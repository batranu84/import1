from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from uuid import UUID

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


class InternalInfrastructureService:
    """Passive infrastructure intelligence built from existing internal observations.

    The service never probes a target. It correlates ShadowLAN device/service assets,
    SNMP inventory already collected by an authorized scan, sensor topology links, and
    physical-pipeline classifications. Port-only hints stay candidates unless direct
    application/SNMP metadata confirms the role.
    """

    NETWORK_ROLES = {"switch", "gateway/router", "firewall", "wireless-ap", "access-point"}
    PLATFORM_ROLES = {"nas", "virtualization-host", "container-host", "nvr", "camera"}
    ROLE_PORT_HINTS = {
        8006: "virtualization-host",
        2375: "container-host",
        2376: "container-host",
        2049: "nas",
        554: "camera/streaming-device",
    }
    MANAGEMENT_PORTS = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 161: "SNMP", 443: "HTTPS",
        445: "SMB", 3389: "RDP", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
        8006: "Proxmox", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    }

    @staticmethod
    def _devices(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-device" and a.source == "ShadowLAN"]

    @staticmethod
    def _services(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-service" and a.source == "ShadowLAN"]

    @staticmethod
    def _host(service: Asset) -> str:
        host = str(service.attributes.get("host") or service.attributes.get("ip") or "")
        if not host and ":" in service.value:
            host = service.value.rsplit(":", 1)[0]
        return host

    @staticmethod
    def _port(service: Asset) -> int | None:
        raw = service.attributes.get("port")
        if raw is None and ":" in service.value:
            raw = service.value.rsplit(":", 1)[-1]
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _evidence_for_asset(evidence: list[Evidence], asset_id: UUID) -> list[Evidence]:
        return [e for e in evidence if e.asset_id == asset_id]

    @staticmethod
    def _snmp_interfaces(device: Asset) -> list[dict[str, Any]]:
        snmp = device.attributes.get("snmp") or {}
        rows = snmp.get("interfaces") if isinstance(snmp, dict) else None
        return [dict(x) for x in rows or [] if isinstance(x, dict)]

    @classmethod
    def summarize(cls, assets: list[Asset], evidence: list[Evidence]) -> dict[str, Any]:
        devices = cls._devices(assets)
        services = cls._services(assets)
        device_by_ip = {d.value: d for d in devices}

        roles: Counter[str] = Counter()
        confirmed_infrastructure: list[dict[str, Any]] = []
        platform_inventory: list[dict[str, Any]] = []
        candidate_platforms: defaultdict[str, set[str]] = defaultdict(set)
        interface_inventory: list[dict[str, Any]] = []
        management_by_host: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        candidate_management_by_host: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        topology_edges: list[dict[str, Any]] = []
        snmp_devices = 0

        for device in devices:
            attrs = device.attributes
            role = str(attrs.get("device_type") or "unknown")
            confidence = str(attrs.get("identity_confidence") or "observed")
            roles[role] += 1
            row = {
                "ip": device.value,
                "hostname": attrs.get("hostname"),
                "vendor": attrs.get("vendor"),
                "role": role,
                "identity_confidence": confidence,
                "firmware": attrs.get("firmware"),
                "candidate_types": list(attrs.get("candidate_types") or []),
            }
            if role in cls.NETWORK_ROLES and confidence == "confirmed":
                confirmed_infrastructure.append(row)
            if role in cls.PLATFORM_ROLES and confidence == "confirmed":
                platform_inventory.append(row)
            for candidate in attrs.get("candidate_types") or []:
                candidate_platforms[device.value].add(str(candidate))

            snmp = attrs.get("snmp") or {}
            if isinstance(snmp, dict) and snmp:
                snmp_devices += 1
                for iface in cls._snmp_interfaces(device):
                    interface_inventory.append({
                        "ip": device.value,
                        "hostname": attrs.get("hostname"),
                        **iface,
                    })

            metadata = attrs.get("metadata") or {}
            for link in metadata.get("topology_links", []) if isinstance(metadata, dict) else []:
                if not isinstance(link, dict):
                    continue
                target = str(link.get("target") or "")
                if not target:
                    continue
                edge = {
                    "source": str(link.get("source") or device.value),
                    "target": target,
                    "relation": str(link.get("relation") or "connected"),
                    "evidence": str(link.get("evidence") or "sensor"),
                    "confidence": str(link.get("confidence") or "confirmed"),
                }
                if edge not in topology_edges:
                    topology_edges.append(edge)

        for service in services:
            port = cls._port(service)
            if port is None:
                continue
            host = cls._host(service)
            attrs = service.attributes
            service_state = str(attrs.get("service_state") or "unconfirmed")
            service_name = str(attrs.get("service_name") or attrs.get("service") or "unknown")
            if port in cls.MANAGEMENT_PORTS:
                row = {
                    "port": port,
                    "protocol": service_name if service_state == "confirmed" and service_name != "unknown" else "unknown",
                    "service_candidate": cls.MANAGEMENT_PORTS[port],
                    "service_name": service_name,
                    "service_state": service_state,
                    "identity_basis": attrs.get("identity_basis") or "conventional-port-candidate",
                    "asset_id": str(service.id),
                }
                (management_by_host if service_state == "confirmed" and service_name != "unknown" else candidate_management_by_host)[host].append(row)
            hint = cls.ROLE_PORT_HINTS.get(port)
            if hint and host:
                candidate_platforms[host].add(hint)

        # A gateway relationship is a routed-LAN observation, not a physical switch edge.
        for device in devices:
            gateway = str(device.attributes.get("gateway") or "")
            if gateway and device.value != gateway:
                edge = {
                    "source": gateway,
                    "target": device.value,
                    "relation": "same-routed-lan",
                    "evidence": "route+positive-host-observation",
                    "confidence": "observed",
                }
                if edge not in topology_edges:
                    topology_edges.append(edge)

        physical = [a for a in assets if a.source == "physical_pipeline"]
        cctv = [
            {
                "ip": a.value,
                "category": a.kind,
                "vendor": a.attributes.get("vendor"),
                "classification": a.attributes.get("classification") or a.attributes.get("device_type"),
                "confidence": a.attributes.get("confidence"),
            }
            for a in physical
            if str(a.kind).lower() in {"cctv", "camera", "nvr", "dvr"}
            or "camera" in str(a.attributes).lower()
            or "nvr" in str(a.attributes).lower()
        ]

        return {
            "device_count": len(devices),
            "service_count": len(services),
            "role_counts": dict(roles),
            "confirmed_network_infrastructure": confirmed_infrastructure,
            "confirmed_platforms": platform_inventory,
            "candidate_platforms": {k: sorted(v) for k, v in sorted(candidate_platforms.items())},
            "snmp_device_count": snmp_devices,
            "interface_inventory": interface_inventory,
            "interface_count": len(interface_inventory),
            "management_surfaces": {k: v for k, v in sorted(management_by_host.items())},
            "candidate_management_surfaces": {k: v for k, v in sorted(candidate_management_by_host.items())},
            "cctv_nvr_inventory": cctv,
            "topology": {
                "nodes": [
                    {
                        "id": d.value,
                        "label": d.attributes.get("hostname") or d.value,
                        "kind": d.attributes.get("device_type") or "unknown",
                        "confidence": d.attributes.get("identity_confidence") or "observed",
                    }
                    for d in devices
                ],
                "edges": topology_edges,
            },
            "evidence_count": len(evidence),
            "basis": "passive correlation of existing authorized internal observations",
        }

    @classmethod
    def derive(cls, assets: list[Asset], evidence: list[Evidence]) -> tuple[list[Evidence], list[Finding]]:
        summary = cls.summarize(assets, evidence)
        derived: list[Evidence] = [Evidence(
            engine="ShadowInfrastructure",
            category="internal-infrastructure-summary",
            summary=(
                f"Correlated {summary['device_count']} device(s), {summary['service_count']} service(s), "
                f"{summary['interface_count']} SNMP interface row(s), and "
                f"{len(summary['topology']['edges'])} topology relationship(s)"
            ),
            raw=summary,
        )]
        findings: list[Finding] = []

        # TCP/2375 is the non-TLS Docker API transport. We report the observed transport
        # exposure only; no claim is made about authentication or command execution.
        for service in cls._services(assets):
            port = cls._port(service)
            if port != 2375:
                continue
            attrs = service.attributes or {}
            service_state = str(attrs.get("service_state") or "unconfirmed").lower()
            service_name = str(attrs.get("service_name") or "unknown").lower()
            if service_state != "confirmed" or service_name not in {"docker", "docker-http", "docker-api"}:
                continue
            host = cls._host(service)
            supporting = cls._evidence_for_asset(evidence, service.id)
            ev = Evidence(
                asset_id=service.id,
                engine="ShadowInfrastructure",
                category="container-management-surface",
                summary=f"Non-TLS Docker API transport observed on {host}:2375",
                raw={
                    "host": host,
                    "port": 2375,
                    "transport": "tcp",
                    "claim": "protocol-confirmed Docker HTTP management transport",
                    "supporting_evidence_ids": [str(x.id) for x in supporting],
                },
            )
            derived.append(ev)
            findings.append(Finding(
                title="Non-TLS Docker management transport exposed internally",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                affected_asset=f"{host}:2375",
                description=(
                    "Docker HTTP management protocol evidence was confirmed on TCP/2375 on the authorized internal "
                    "network. This establishes a non-TLS Docker management transport; it does not establish that "
                    "the API is unauthenticated or that commands can be executed."
                ),
                remediation=(
                    "Disable the TCP/2375 listener where it is not required. Prefer a local Unix socket or "
                    "mutually authenticated TLS on TCP/2376, and restrict management access to dedicated "
                    "administrative segments."
                ),
                evidence_ids=[x.id for x in supporting] + [ev.id],
                tags=["internal", "container", "docker", "management-surface"],
                validation_status="observed-service",
                technical_impact="An unencrypted container-management transport is reachable from the assessed network segment.",
                business_impact="Compromise risk increases if the management service is weakly authenticated or otherwise misconfigured.",
                remediation_priority="P2 - high",
                retest_status="not-retested",
                attack_path=["Internal network", host, "TCP/2375", "Docker management surface"],
            ))

        return derived, findings


class InternalInfrastructureEngine(Engine):
    name = "ShadowInfrastructure"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        assets = list(context.assets or [])
        evidence = list(context.evidence or [])
        derived, findings = InternalInfrastructureService.derive(assets, evidence)
        return EngineOutput(assets=[], evidence=derived, findings=findings)
