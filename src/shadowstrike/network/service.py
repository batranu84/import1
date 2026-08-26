from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Iterable

from shadowstrike.core.scope import ScopeViolation
from shadowstrike.models.domain import Asset, AssessmentRequest, AssessmentResult, Evidence
from shadowstrike.network.agent import local_firmware_inventory
from shadowstrike.network.device import ShadowDevice, service_name
from shadowstrike.network.intelligence import DeviceProfile, NetworkRisk
from shadowstrike.network.lan import ShadowLAN
from shadowstrike.network.snmp import ShadowSNMP
from shadowstrike.network.topology import ShadowTopology
from shadowstrike.services.assessment_truth import valid_host_address


class NetworkDiscoveryService:
    SOURCE = "ShadowLAN"

    @staticmethod
    def require_cidr(request: AssessmentRequest, cidr: str) -> ipaddress._BaseNetwork:
        try:
            candidate = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ScopeViolation(f"Invalid CIDR: {cidr}") from exc
        if candidate.is_loopback or candidate.is_multicast or candidate.is_unspecified or str(candidate.network_address) == "255.255.255.255":
            raise ScopeViolation(f"CIDR is not a usable discovery network: {candidate}")
        allowed = [ipaddress.ip_network(x, strict=False) for x in request.scope.allowed_cidrs]
        excluded = [ipaddress.ip_network(x, strict=False) for x in request.scope.excluded_cidrs]
        if not allowed or not any(candidate.subnet_of(net) for net in allowed if candidate.version == net.version):
            raise ScopeViolation(f"CIDR is outside authorized scope: {candidate}")
        if any(candidate.overlaps(net) for net in excluded if candidate.version == net.version):
            raise ScopeViolation(f"CIDR overlaps excluded scope: {candidate}")
        return candidate

    @staticmethod
    def _device_assets(
        device: ShadowDevice,
        cidr: str,
        gateway: str | None,
        sensor_id: str | None = None,
    ) -> tuple[list[Asset], list[Evidence]]:
        attrs = device.as_dict()
        attrs.update({"cidr": cidr, "gateway": gateway, "sensor_id": sensor_id})
        confirmed_service_identities = [
            str(s.get("name") or "").strip().lower() for s in device.services
            if str(s.get("service_state") or "").lower() == "confirmed"
            and str(s.get("name") or "").strip()
            and str(s.get("name") or "").strip().lower() != "unknown"
        ]
        profile = DeviceProfile(
            address=device.ip,
            vendor=device.vendor,
            device_type=device.device_type if device.identity_confidence == "confirmed" else "unknown",
            services=confirmed_service_identities,
        )
        attrs["network_risk_score"] = NetworkRisk.score(profile)
        attrs["risk_basis"] = "protocol-confirmed service identities only; conventional port candidates do not add protocol-specific risk"

        device_asset = Asset(kind="network-device", value=device.ip, source="ShadowLAN", attributes=attrs)
        assets: list[Asset] = [device_asset]
        evidence: list[Evidence] = [
            Evidence(
                asset_id=device_asset.id,
                engine="ShadowLAN",
                category="network-device",
                summary=f"Positive internal network observation for {device.ip} ({device.device_type})",
                raw={
                    **attrs,
                    "state": device.observation_state,
                    "identity_confidence": device.identity_confidence,
                    "evidence_types": device.evidence_types,
                },
            )
        ]

        if device.os_hint:
            os_fp = dict(device.metadata.get("os_fingerprint") or {})
            os_asset = Asset(
                kind="operating-system",
                value=f"{device.ip}:{device.os_hint}",
                source="ShadowLAN",
                attributes={
                    "host": device.ip,
                    "os": device.os_hint,
                    "fingerprint": os_fp,
                    "confidence": os_fp.get("state") or "observed",
                    "cidr": cidr,
                    "sensor_id": sensor_id,
                },
            )
            assets.append(os_asset)
            evidence.append(Evidence(
                asset_id=os_asset.id,
                engine="ShadowFingerprint",
                category="os-fingerprint",
                summary=f"OS fingerprint evidence for {device.ip}: {device.os_hint}",
                raw={"host": device.ip, "os": device.os_hint, "fingerprint": os_fp},
            ))

        service_map = {int(s.get("port")): s for s in device.services if s.get("port") is not None}
        latency_map = device.metadata.get("connect_latency_ms", {}) if device.metadata else {}
        for port in device.open_ports:
            verified = service_map.get(int(port), {})
            service_state = str(verified.get("service_state") or "unconfirmed")
            candidate = str(verified.get("service_candidate") or service_name(int(port)))
            confirmed_name = str(verified.get("name") or "unknown") if service_state == "confirmed" else "unknown"
            service_attrs = {
                "host": device.ip,
                "port": int(port),
                "transport": "tcp",
                "state": "open",
                "port_state": "confirmed-open",
                "service_candidate": candidate,
                "service_name": confirmed_name,
                "service_state": service_state,
                "identity_basis": verified.get("identity_basis") or "conventional-port-candidate",
                "application_evidence": verified.get("application_evidence"),
                "server": verified.get("server"),
                "tls_version": verified.get("tls_version"),
                "product": verified.get("product"),
                "version": verified.get("version"),
                "cpe": verified.get("cpe") or [],
                "ostype": verified.get("ostype"),
                "devicetype": verified.get("devicetype"),
                "nmap": verified.get("nmap"),
                "connect_latency_ms": latency_map.get(str(port)),
                "cidr": cidr,
                "network_device_type": device.device_type,
                "sensor_id": sensor_id,
            }
            service_asset = Asset(
                kind="network-service" if service_state == "confirmed" else "transport-endpoint",
                value=f"{device.ip}:{int(port)}/tcp",
                source="ShadowLAN",
                attributes={
                    **service_attrs,
                    "inventory_class": "protocol-confirmed-service" if service_state == "confirmed" else "unverified-transport-endpoint",
                    "service_promotion_suppressed": service_state != "confirmed",
                },
            )
            assets.append(service_asset)
            evidence.append(
                Evidence(
                    asset_id=service_asset.id,
                    engine="ShadowLAN",
                    category="port",
                    summary=(
                        f"TCP/{int(port)} confirmed open on {device.ip}; "
                        f"service identity {service_attrs['service_state']}"
                    ),
                    raw=service_attrs,
                )
            )

        if device.snmp:
            evidence.append(
                Evidence(
                    asset_id=device_asset.id,
                    engine="ShadowSNMP",
                    category="snmp-inventory",
                    summary=f"Authenticated/configured SNMP read response collected from {device.ip}",
                    raw={**device.snmp, "state": "confirmed"},
                )
            )
        if device.bios:
            evidence.append(
                Evidence(
                    asset_id=device_asset.id,
                    engine="ShadowAgent",
                    category="firmware-inventory",
                    summary=f"Local sensor firmware/BIOS inventory collected for {device.ip}",
                    raw={**device.bios, "state": "confirmed", "source": "local-agent"},
                )
            )
        return assets, evidence

    @staticmethod
    def _replace_network_snapshot(
        result: AssessmentResult,
        cidr: str,
        assets: Iterable[Asset],
        evidence: Iterable[Evidence],
        sensor_id: str | None = None,
    ) -> None:
        removable_ids = {
            str(asset.id)
            for asset in result.assets
            if asset.source == "ShadowLAN"
            and str(asset.attributes.get("cidr", "")) == cidr
            and (sensor_id is None or asset.attributes.get("sensor_id") == sensor_id)
        }
        result.assets = [
            asset for asset in result.assets
            if not (
                asset.source == "ShadowLAN"
                and str(asset.attributes.get("cidr", "")) == cidr
                and (sensor_id is None or asset.attributes.get("sensor_id") == sensor_id)
            )
        ]
        result.evidence = [e for e in result.evidence if not (e.asset_id and str(e.asset_id) in removable_ids)]
        result.assets.extend(list(assets))
        result.evidence.extend(list(evidence))

    async def scan(
        self,
        request: AssessmentRequest,
        result: AssessmentResult,
        cidr: str,
        ports: list[int] | None = None,
        snmp_community: str | None = None,
        sensor_id: str | None = None,
        port_profile: str = "adaptive",
    ) -> dict[str, Any]:
        network = self.require_cidr(request, cidr)
        if port_profile not in {"discovery", "standard", "adaptive", "full", "exhaustive"}:
            raise ValueError("port_profile must be discovery, standard, adaptive, full, or exhaustive")
        lan = ShadowLAN(str(network))
        devices = await lan.discover(
            ports=ports,
            timeout=0.4,
            concurrency=min(request.scope.max_concurrency, 256),
            port_profile=port_profile,
            verify_services=True,
        )

        local_ips = {interface.address for interface in ShadowLAN.local_interfaces()}
        local_firmware = None
        for device in devices:
            if device.ip in local_ips:
                if local_firmware is None:
                    local_firmware = await asyncio.to_thread(local_firmware_inventory)
                device.bios = local_firmware
                device.metadata["sensor_host"] = True
                if "local-agent-inventory" not in device.evidence_types:
                    device.evidence_types.append("local-agent-inventory")
                device.normalize()

        if snmp_community:
            semaphore = asyncio.Semaphore(min(32, max(1, request.scope.max_concurrency)))
            known = {d.ip: d for d in devices}

            async def probe_snmp(ip: str) -> tuple[str, dict[str, Any] | None]:
                async with semaphore:
                    snmp = ShadowSNMP(host=ip, community=snmp_community, timeout=0.3)
                    descr = await asyncio.to_thread(snmp.get, "1.3.6.1.2.1.1.1.0")
                    if descr in (None, ""):
                        return ip, None
                    snmp.timeout = 0.7
                    inventory = await asyncio.to_thread(snmp.inventory)
                    if "sys_descr" not in inventory:
                        inventory["sys_descr"] = descr
                    return ip, inventory

            snmp_results = await asyncio.gather(*(probe_snmp(str(ip)) for ip in network.hosts()))
            for ip, inventory in snmp_results:
                if not inventory:
                    continue
                device = known.get(ip)
                if device is None:
                    device = ShadowDevice(
                        ip=ip,
                        open_ports=[],
                        metadata={"discovery": "snmp-positive-response"},
                        evidence_types=["snmp-response"],
                    )
                    devices.append(device)
                    known[ip] = device
                device.snmp = inventory
                device.vendor = inventory.get("vendor") or device.vendor
                device.firmware = inventory.get("firmware") or device.firmware
                lldp_links = []
                for neighbor in inventory.get("lldp_neighbors", []) or []:
                    target_id = str(neighbor.get("chassis_id") or neighbor.get("system_name") or "").strip()
                    if not target_id:
                        continue
                    lldp_links.append({
                        "source": device.ip,
                        "target": f"lldp:{target_id}",
                        "target_label": neighbor.get("system_name") or target_id,
                        "target_description": neighbor.get("system_description"),
                        "relation": "lldp-neighbor",
                        "local_port": neighbor.get("local_port_num"),
                        "remote_port": neighbor.get("port_id") or neighbor.get("port_description"),
                        "evidence": "snmp-lldp-mib",
                        "confidence": "confirmed",
                    })
                if lldp_links:
                    device.metadata["topology_links"] = lldp_links
                    device.metadata["lldp_role"] = "managed-network-device"
                    if "snmp-lldp" not in device.evidence_types:
                        device.evidence_types.append("snmp-lldp")
                if "snmp-response" not in device.evidence_types:
                    device.evidence_types.append("snmp-response")
                device.normalize()
            devices.sort(key=lambda d: ipaddress.ip_address(d.ip))

        assets: list[Asset] = []
        evidence: list[Evidence] = []
        for device in devices:
            a, e = self._device_assets(device, str(network), lan.gateway, sensor_id=sensor_id)
            assets.extend(a)
            evidence.extend(e)
        self._replace_network_snapshot(result, str(network), assets, evidence, sensor_id=sensor_id)
        topology = ShadowTopology.from_devices(devices, lan.gateway).export()
        return {
            "cidr": str(network),
            "gateway": lan.gateway,
            "port_profile": port_profile,
            "devices": [d.as_dict() for d in devices],
            "device_count": len(devices),
            "service_count": sum(1 for d in devices for svc in d.services if str(svc.get("service_state") or "").lower() == "confirmed" and str(svc.get("name") or "").lower() != "unknown"),
            "transport_endpoint_count": sum(len(d.open_ports) for d in devices),
            "confirmed_devices": sum(1 for d in devices if d.observation_state == "confirmed"),
            "observed_devices": sum(1 for d in devices if d.observation_state == "observed"),
            "topology": topology,
        }

    @staticmethod
    def ingest_payload(
        request: AssessmentRequest,
        result: AssessmentResult,
        payload: dict[str, Any],
        sensor_id: str,
    ) -> dict[str, Any]:
        cidr = str(NetworkDiscoveryService.require_cidr(request, str(payload.get("cidr", ""))))
        gateway = payload.get("gateway")
        network = ipaddress.ip_network(cidr, strict=False)
        devices: list[ShadowDevice] = []
        for raw in payload.get("devices", []):
            ip = str(raw.get("ip", ""))
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address not in network or not valid_host_address(ip):
                continue
            if network.version == 4 and network.prefixlen < 31 and address in {network.network_address, network.broadcast_address}:
                continue
            device = ShadowDevice(
                ip=ip,
                mac=raw.get("mac"),
                vendor=raw.get("vendor"),
                hostname=raw.get("hostname"),
                device_type=raw.get("device_type", "unknown"),
                open_ports=[int(p) for p in raw.get("open_ports", [])],
                services=list(raw.get("services", [])),
                os_hint=raw.get("os_hint"),
                firmware=raw.get("firmware"),
                bios=raw.get("bios"),
                is_gateway=bool(raw.get("is_gateway", False)),
                snmp=raw.get("snmp"),
                metadata=dict(raw.get("metadata", {})),
                observation_state=str(raw.get("observation_state", "observed")),
                identity_confidence=str(raw.get("identity_confidence", "observed")),
                evidence_types=list(raw.get("evidence_types", [])),
                candidate_types=list(raw.get("candidate_types", [])),
            ).normalize()
            devices.append(device)

        assets: list[Asset] = []
        evidence: list[Evidence] = []
        for device in devices:
            a, e = NetworkDiscoveryService._device_assets(device, cidr, gateway, sensor_id=sensor_id)
            assets.extend(a)
            evidence.extend(e)
        NetworkDiscoveryService._replace_network_snapshot(result, cidr, assets, evidence, sensor_id=sensor_id)
        return {
            "cidr": cidr,
            "gateway": gateway,
            "port_profile": payload.get("port_profile", "unknown"),
            "devices": [d.as_dict() for d in devices],
            "device_count": len(devices),
            "service_count": sum(1 for d in devices for svc in d.services if str(svc.get("service_state") or "").lower() == "confirmed"),
            "transport_endpoint_count": sum(len(d.open_ports) for d in devices),
            "topology": ShadowTopology.from_devices(devices, gateway).export(),
        }

    @staticmethod
    def summary(result: AssessmentResult) -> dict[str, Any]:
        devices = [a for a in result.assets if a.kind == "network-device" and valid_host_address(a.value)]
        services = [a for a in result.assets if a.kind == "network-service" and a.source == "ShadowLAN"]
        transport_endpoints = [a for a in result.assets if a.kind == "transport-endpoint" and a.source == "ShadowLAN"]
        by_type: dict[str, int] = {}
        by_state: dict[str, int] = {}
        risk: list[dict[str, Any]] = []
        for asset in devices:
            dtype = str(asset.attributes.get("device_type", "unknown"))
            state = str(asset.attributes.get("observation_state", "observed"))
            by_type[dtype] = by_type.get(dtype, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1
            risk.append({
                "ip": asset.value,
                "device_type": dtype,
                "identity_confidence": asset.attributes.get("identity_confidence", "observed"),
                "observation_state": state,
                "candidate_types": asset.attributes.get("candidate_types", []),
                "evidence_types": asset.attributes.get("evidence_types", []),
                "vendor": asset.attributes.get("vendor"),
                "hostname": asset.attributes.get("hostname"),
                "score": asset.attributes.get("network_risk_score", 0),
                "open_ports": asset.attributes.get("open_ports", []),
                "services": asset.attributes.get("services", []),
                "firmware": asset.attributes.get("firmware"),
                "bios": asset.attributes.get("bios"),
                "snmp": asset.attributes.get("snmp"),
                "sensor_id": asset.attributes.get("sensor_id"),
            })
        risk.sort(key=lambda x: float(x.get("score", 0)), reverse=True)

        topology_devices = []
        for asset in devices:
            raw = asset.attributes
            topology_devices.append(ShadowDevice(
                ip=asset.value,
                mac=raw.get("mac"),
                vendor=raw.get("vendor"),
                hostname=raw.get("hostname"),
                device_type=raw.get("device_type", "unknown"),
                open_ports=raw.get("open_ports", []),
                services=raw.get("services", []),
                is_gateway=bool(raw.get("is_gateway", False)),
                snmp=raw.get("snmp"),
                metadata=raw.get("metadata", {}),
                observation_state=raw.get("observation_state", "observed"),
                identity_confidence=raw.get("identity_confidence", "observed"),
                evidence_types=raw.get("evidence_types", []),
                candidate_types=raw.get("candidate_types", []),
            ).normalize())
        gateway = next((d.ip for d in topology_devices if d.is_gateway), None)
        return {
            "device_count": len(devices),
            "service_count": len(services),
            "transport_endpoint_count": len(transport_endpoints),
            "by_type": by_type,
            "by_state": by_state,
            "devices": risk,
            "topology": ShadowTopology.from_devices(topology_devices, gateway).export(),
        }
