from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from uuid import UUID

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


class InternalPostureService:
    """Evidence-first synthesis of already observed internal-network assets.

    This service does not probe targets. It turns ShadowLAN/physical-pipeline observations
    into an auditable internal inventory, management-surface summary, and conservative
    configuration findings. Candidate device classifications are never promoted to confirmed
    identity without direct evidence from the discovery layer.
    """

    CLEAR_TEXT_PORTS = {
        21: ("FTP", Severity.LOW),
        23: ("Telnet", Severity.MEDIUM),
        110: ("POP3", Severity.LOW),
        143: ("IMAP", Severity.LOW),
    }
    MANAGEMENT_PORTS = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 161: "SNMP", 443: "HTTPS",
        445: "SMB", 3389: "RDP", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
        8006: "Proxmox", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    }
    DATA_SERVICE_PORTS = {
        1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    }
    INFRA_TYPES = {"switch", "firewall", "gateway/router", "access-point", "wireless-ap"}
    CONFIRMED_BY_PORT = {
        21: {"ftp"}, 23: {"telnet"}, 80: {"http"}, 110: {"pop3"}, 143: {"imap"},
        22: {"ssh"}, 161: {"snmp"}, 443: {"https"}, 445: {"smb"},
        3389: {"rdp"}, 5985: {"winrm-http", "winrm"}, 5986: {"winrm-https", "winrm"},
        1433: {"mssql", "ms-sql-s"}, 3306: {"mysql"}, 5432: {"postgresql", "postgres"},
        6379: {"redis"}, 9200: {"elasticsearch"}, 11211: {"memcached"}, 27017: {"mongodb", "mongo"},
    }

    @staticmethod
    def _network_devices(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-device" and a.source == "ShadowLAN"]

    @staticmethod
    def _network_services(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-service" and a.source == "ShadowLAN"]

    @staticmethod
    def _physical_assets(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.source == "physical_pipeline"]

    @staticmethod
    def _evidence_for_asset(evidence: list[Evidence], asset_id: UUID) -> list[Evidence]:
        return [e for e in evidence if e.asset_id == asset_id]

    @staticmethod
    def _port(asset: Asset) -> int | None:
        raw = asset.attributes.get("port")
        if raw is None:
            try:
                if ":" in asset.value:
                    raw = asset.value.rsplit(":", 1)[-1]
            except Exception:
                raw = None
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    @classmethod
    def summarize(cls, assets: list[Asset], evidence: list[Evidence]) -> dict[str, Any]:
        devices = cls._network_devices(assets)
        services = cls._network_services(assets)
        physical = cls._physical_assets(assets)

        by_type: Counter[str] = Counter()
        by_vendor: Counter[str] = Counter()
        by_network: Counter[str] = Counter()
        by_sensor: Counter[str] = Counter()
        identity: Counter[str] = Counter()
        observation: Counter[str] = Counter()
        management: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        candidate_management: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        data_services: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        candidate_data_services: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        clear_text: list[dict[str, Any]] = []
        candidate_clear_text: list[dict[str, Any]] = []
        infrastructure: list[dict[str, Any]] = []
        snmp_confirmed: list[dict[str, Any]] = []

        device_by_ip = {d.value: d for d in devices}
        for device in devices:
            attrs = device.attributes
            dtype = str(attrs.get("device_type") or "unknown")
            confidence = str(attrs.get("identity_confidence") or "observed")
            state = str(attrs.get("observation_state") or "observed")
            by_type[dtype] += 1
            identity[confidence] += 1
            observation[state] += 1
            vendor = str(attrs.get("vendor") or "").strip()
            if vendor:
                by_vendor[vendor] += 1
            cidr = str(attrs.get("cidr") or "").strip()
            if cidr:
                by_network[cidr] += 1
            sensor = str(attrs.get("sensor_id") or "local").strip() or "local"
            by_sensor[sensor] += 1
            if dtype in cls.INFRA_TYPES and confidence == "confirmed":
                infrastructure.append({
                    "ip": device.value, "device_type": dtype, "vendor": attrs.get("vendor"),
                    "hostname": attrs.get("hostname"), "firmware": attrs.get("firmware"),
                })
            if attrs.get("snmp"):
                snmp_confirmed.append({
                    "ip": device.value, "vendor": attrs.get("vendor"),
                    "hostname": attrs.get("hostname"), "snmp": attrs.get("snmp"),
                })

        for service in services:
            port = cls._port(service)
            if port is None:
                continue
            host = str(service.attributes.get("ip") or service.attributes.get("host") or "")
            if not host and ":" in service.value:
                host = service.value.rsplit(":", 1)[0]
            attrs = service.attributes or {}
            state = str(attrs.get("service_state") or "unconfirmed").lower()
            confirmed_name = str(attrs.get("service_name") or "unknown").lower() if state == "confirmed" else "unknown"
            candidate_name = str(attrs.get("service_candidate") or attrs.get("service") or attrs.get("name") or "unknown")
            identity_matches = confirmed_name in cls.CONFIRMED_BY_PORT.get(port, set())
            row = {
                "ip": host, "port": port,
                "service": confirmed_name if identity_matches else "unknown",
                "service_candidate": candidate_name,
                "service_state": "confirmed" if identity_matches else state,
                "identity_basis": attrs.get("identity_basis") or "conventional-port-candidate",
                "asset_id": str(service.id),
            }
            if port in cls.MANAGEMENT_PORTS:
                bucket = management if identity_matches else candidate_management
                bucket[cls.MANAGEMENT_PORTS[port]].append(row)
            if port in cls.DATA_SERVICE_PORTS:
                bucket = data_services if identity_matches else candidate_data_services
                bucket[cls.DATA_SERVICE_PORTS[port]].append(row)
            if port in cls.CLEAR_TEXT_PORTS:
                name, _ = cls.CLEAR_TEXT_PORTS[port]
                (clear_text if identity_matches else candidate_clear_text).append({**row, "protocol": name})

        physical_by_category = Counter(str(a.kind) for a in physical)
        unknown_devices = [
            d.value for d in devices
            if str(d.attributes.get("identity_confidence") or "observed") != "confirmed"
        ]
        gateways = [d.value for d in devices if bool(d.attributes.get("is_gateway"))]

        return {
            "device_count": len(devices),
            "service_count": len(services),
            "network_count": len(by_network),
            "sensor_count": len(by_sensor),
            "by_type": dict(by_type),
            "by_vendor": dict(by_vendor),
            "by_network": dict(by_network),
            "by_sensor": dict(by_sensor),
            "identity_confidence": dict(identity),
            "observation_state": dict(observation),
            "confirmed_infrastructure": infrastructure,
            "unknown_identity_devices": unknown_devices,
            "gateways": gateways,
            "management_surface": dict(management),
            "candidate_management_surface": dict(candidate_management),
            "data_services": dict(data_services),
            "candidate_data_services": dict(candidate_data_services),
            "clear_text_services": clear_text,
            "candidate_clear_text_services": candidate_clear_text,
            "snmp_confirmed": snmp_confirmed,
            "physical_assets": {
                "count": len(physical),
                "by_category": dict(physical_by_category),
            },
            "evidence_count": len(evidence),
            "basis": "observed ShadowLAN and physical-pipeline evidence only",
        }

    @classmethod
    def derive(cls, assets: list[Asset], evidence: list[Evidence]) -> tuple[list[Evidence], list[Finding]]:
        summary = cls.summarize(assets, evidence)
        devices = cls._network_devices(assets)
        services = cls._network_services(assets)
        device_by_ip = {d.value: d for d in devices}
        derived_evidence: list[Evidence] = []
        findings: list[Finding] = []

        inventory_evidence = Evidence(
            engine="ShadowInternal",
            category="internal-posture-summary",
            summary=(
                f"Observed {summary['device_count']} internal devices and {summary['service_count']} "
                f"services across {summary['network_count']} authorized network(s)"
            ),
            raw=summary,
        )
        derived_evidence.append(inventory_evidence)

        for service in services:
            port = cls._port(service)
            if port not in cls.CLEAR_TEXT_PORTS:
                continue
            attrs = service.attributes or {}
            service_state = str(attrs.get("service_state") or "unconfirmed").lower()
            service_name_value = str(attrs.get("service_name") or "").lower()
            if service_state != "confirmed" or service_name_value not in cls.CONFIRMED_BY_PORT.get(port, set()):
                continue
            protocol, severity = cls.CLEAR_TEXT_PORTS[port]
            host = str(service.attributes.get("ip") or service.attributes.get("host") or "")
            if not host and ":" in service.value:
                host = service.value.rsplit(":", 1)[0]
            supporting = cls._evidence_for_asset(evidence, service.id)
            ev = Evidence(
                asset_id=service.id,
                engine="ShadowInternal",
                category="clear-text-service",
                summary=f"{protocol} service observed on {host}:{port}",
                raw={
                    "host": host, "port": port, "protocol": protocol,
                    "source_asset_id": str(service.id),
                    "supporting_evidence_ids": [str(x.id) for x in supporting],
                },
            )
            derived_evidence.append(ev)
            ids = [x.id for x in supporting] + [ev.id]
            findings.append(Finding(
                title=f"Clear-text {protocol} service accessible on internal network",
                severity=severity,
                confidence=Confidence.CONFIRMED,
                affected_asset=f"{host}:{port}",
                description=(
                    f"ShadowStrike confirmed the {protocol} application protocol on the authorized internal "
                    "network. The finding does not assume credentials, sensitive data, or successful authentication."
                ),
                remediation=(
                    f"Disable {protocol} where it is not required. Where a service is required, migrate "
                    "to an encrypted alternative and restrict access to the smallest necessary management segment."
                ),
                evidence_ids=ids,
                tags=["internal", "clear-text", protocol.lower()],
                validation_status="observed-service",
                evidence_quality="corroborated" if supporting else "single-observation",
                technical_impact="Network traffic for the observed service may lack transport encryption.",
                business_impact="Unencrypted internal protocols can increase exposure if network traffic is intercepted or a trusted segment is compromised.",
                remediation_priority="P2" if severity == Severity.MEDIUM else "P3",
                priority_score=65 if severity == Severity.MEDIUM else 45,
                attack_path=["Internal network", host, f"{protocol}/{port}", "Clear-text service exposure"],
            ))

        if summary["snmp_confirmed"]:
            ev = Evidence(
                engine="ShadowInternal",
                category="snmp-inventory",
                summary=f"SNMP inventory confirmed on {len(summary['snmp_confirmed'])} device(s)",
                raw={"devices": summary["snmp_confirmed"]},
            )
            derived_evidence.append(ev)

        if summary["physical_assets"]["count"]:
            ev = Evidence(
                engine="ShadowInternal",
                category="physical-asset-inventory",
                summary=f"Classified {summary['physical_assets']['count']} physical/IoT asset observation(s)",
                raw=summary["physical_assets"],
            )
            derived_evidence.append(ev)

        return derived_evidence, findings


class InternalPostureEngine(Engine):
    """Passive internal assessment synthesis; performs no additional target I/O."""

    name = "ShadowInternal"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if context.profile not in {"internal", "full"}:
            return EngineOutput(assets=[], evidence=[], findings=[])
        derived_evidence, findings = InternalPostureService.derive(context.assets, context.evidence)
        return EngineOutput(assets=[], evidence=derived_evidence, findings=findings)
