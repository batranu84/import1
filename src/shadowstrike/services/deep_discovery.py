from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


class DeepDiscoveryEngine(Engine):
    """Synthesize discovery artifacts and make missing coverage explicit.

    This stage performs no new intrusive action. It turns certificates, services, OS hints,
    networks and software fingerprints already observed by earlier stages into searchable
    assets and produces coverage-gap evidence when expected categories are absent.
    """

    name = "ShadowDeepDiscovery"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        del targets
        existing = context.assets or []
        evidence_in = context.evidence or []
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        seen = {(a.kind, a.value.lower()) for a in existing}

        # Promote certificate SANs to scoped hostname assets and certificate fingerprints to assets.
        for ev in evidence_in:
            if ev.category != "tls-certificate":
                continue
            raw = ev.raw or {}
            fp = str(raw.get("sha256") or "").strip()
            if fp and ("tls-certificate", fp.lower()) not in seen:
                a = Asset(kind="tls-certificate", value=fp, source=self.name, attributes=raw)
                assets.append(a); seen.add((a.kind, a.value.lower()))
            for name in raw.get("san_dns_names", []) or []:
                host = str(name).lower().rstrip(".")
                if host.startswith("*."):
                    host = host[2:]
                if host and context.scope.allows(host) and ("hostname", host) not in seen:
                    a = Asset(kind="hostname", value=host, source=self.name, attributes={"source": "certificate-san", "certificate_sha256": fp})
                    assets.append(a); seen.add((a.kind, a.value.lower()))

        # Promote direct OS hints and software banners so the UI does not hide them in nested metadata.
        for asset in existing:
            attrs = asset.attributes or {}
            os_hint = attrs.get("os_hint")
            if os_hint and ("operating-system", f"{asset.value}|{os_hint}".lower()) not in seen:
                value = f"{asset.value} -> {os_hint}"
                a = Asset(kind="operating-system", value=value, source=self.name, attributes={"host": asset.value, "os": os_hint, "confidence": attrs.get("identity_confidence", "observed")})
                assets.append(a); seen.add((a.kind, value.lower()))

        counts = Counter(a.kind for a in [*existing, *assets])
        ev_counts = Counter(e.category for e in evidence_in)
        expected = {
            "certificates": counts.get("tls-certificate", 0) or ev_counts.get("tls-certificate", 0),
            "network_devices": counts.get("network-device", 0),
            "internal_networks": counts.get("internal-network", 0),
            "operating_systems": counts.get("operating-system", 0),
            "services": counts.get("network-service", 0),
            "transport_observations": counts.get("transport-endpoint", 0) + counts.get("transport-surface", 0),
            "cve_candidates": ev_counts.get("cve-candidate", 0),
        }
        gaps = [name for name, count in expected.items() if count == 0 and name != "transport_observations"]
        evidence.append(Evidence(
            engine=self.name, category="deep-discovery-summary",
            summary=f"Deep discovery synthesized {len(assets)} additional inventory assets; {len(gaps)} coverage categories remain empty",
            raw={"inventory_counts": dict(sorted(counts.items())), "evidence_counts": dict(sorted(ev_counts.items())), "coverage_gaps": gaps},
        ))
        if gaps:
            evidence.append(Evidence(
                engine=self.name, category="discovery-coverage-gap",
                summary="One or more discovery categories could not be verified",
                raw={"missing_categories": gaps, "note": "An empty category is reported as a coverage gap, not as proof that the asset class does not exist."},
            ))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
