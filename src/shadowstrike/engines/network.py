from __future__ import annotations

import ipaddress

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence
from shadowstrike.network.lan import ShadowLAN
from shadowstrike.network.service import NetworkDiscoveryService


class InternalNetworkEngine(Engine):
    """Discover authorised internal assets and always expose locally detected network coverage.

    Local interface/route discovery is passive. Active host/service probing remains limited to
    CIDRs explicitly present in the engagement scope.
    """

    name = "ShadowLAN"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        del targets
        assets: list[Asset] = []
        evidence: list[Evidence] = []

        allowed = [ipaddress.ip_network(c, strict=False) for c in context.scope.policy.allowed_cidrs]
        detected = ShadowLAN.detected_networks()
        for network in detected:
            net = ipaddress.ip_network(network.cidr, strict=False)
            authorised = any(net.subnet_of(a) or a.subnet_of(net) or net.overlaps(a) for a in allowed if a.version == net.version)
            asset = Asset(
                kind="internal-network", value=network.cidr, source=self.name,
                attributes={**network.as_dict(), "authorised_for_active_scan": authorised},
            )
            assets.append(asset)
            evidence.append(Evidence(
                asset_id=asset.id, engine=self.name, category="internal-network-detected",
                summary=f"Detected local/routed network {network.cidr} ({'authorised' if authorised else 'not in active scope'})",
                raw={**network.as_dict(), "authorised_for_active_scan": authorised},
            ))

        if not allowed:
            evidence.append(Evidence(
                engine=self.name, category="discovery-coverage-gap",
                summary="Internal networks were detected passively but no CIDR is authorised for active discovery",
                raw={"reason": "allowed_cidrs-empty", "detected_networks": [n.cidr for n in detected]},
            ))
            return EngineOutput(assets=assets, evidence=evidence, findings=[])

        port_profile = "adaptive" if context.profile in {"full", "deep"} else "standard"
        for cidr in context.scope.policy.allowed_cidrs:
            lan = ShadowLAN(cidr)
            try:
                devices = await lan.discover(
                    ports=None,
                    port_profile=port_profile,
                    concurrency=min(context.scope.policy.max_concurrency, 256),
                    verify_services=True,
                )
            except ValueError as exc:
                evidence.append(Evidence(
                    engine=self.name, category="discovery-coverage-gap",
                    summary=f"Internal CIDR {cidr} was not scanned completely",
                    raw={"cidr": cidr, "reason": str(exc), "port_profile": port_profile},
                ))
                continue
            evidence.append(Evidence(
                engine=self.name, category="internal-scan-coverage",
                summary=f"Completed {port_profile} internal discovery for {cidr}",
                raw={"cidr": cidr, "device_count": len(devices), "port_profile": port_profile},
            ))
            for device in devices:
                a, e = NetworkDiscoveryService._device_assets(device, str(cidr), lan.gateway)
                assets.extend(a)
                evidence.extend(e)
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
