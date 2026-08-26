from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from uuid import UUID

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


class InternalSegmentationService:
    """Passive segmentation and trust-boundary correlation.

    This stage performs no additional target I/O. It relies on explicit zone/VLAN/subnet
    metadata, previously observed service reachability, and topology relationships from
    authorized sensors. Cross-zone reachability is inventory unless direct policy metadata
    marks it as a segmentation violation.
    """

    MANAGEMENT_PORTS = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 161: "SNMP", 443: "HTTPS",
        445: "SMB", 3389: "RDP", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
        8006: "Proxmox", 8443: "HTTPS-alt",
    }
    TRUST_PORTS = {
        22: "SSH", 88: "Kerberos", 135: "MS RPC", 389: "LDAP", 445: "SMB",
        636: "LDAPS", 1433: "MSSQL", 2049: "NFS", 3268: "LDAP GC",
        3269: "LDAPS GC", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6379: "Redis",
    }

    @staticmethod
    def _devices(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-device" and a.source == "ShadowLAN"]

    @staticmethod
    def _services(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-service" and a.source == "ShadowLAN"]

    @staticmethod
    def _port(asset: Asset) -> int | None:
        raw = asset.attributes.get("port")
        if raw is None and ":" in asset.value:
            raw = asset.value.rsplit(":", 1)[-1]
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _host(asset: Asset) -> str:
        host = str(asset.attributes.get("host") or asset.attributes.get("ip") or "").strip()
        if host:
            return host
        if ":" in asset.value:
            return asset.value.rsplit(":", 1)[0]
        return asset.value

    @staticmethod
    def _zone(asset: Asset) -> str:
        attrs = asset.attributes
        for key in ("network_zone", "security_zone", "zone", "vlan_name", "subnet", "network", "cidr"):
            value = str(attrs.get(key) or "").strip()
            if value:
                return value
        vlan = attrs.get("vlan_id")
        if vlan is not None and str(vlan).strip():
            return f"VLAN-{vlan}"
        return "unclassified"

    @staticmethod
    def _evidence_for_asset(evidence: list[Evidence], asset_id: UUID) -> list[Evidence]:
        return [e for e in evidence if e.asset_id == asset_id]

    @classmethod
    def summarize(cls, assets: list[Asset], evidence: list[Evidence]) -> dict[str, Any]:
        devices = cls._devices(assets)
        services = cls._services(assets)
        device_by_ip = {d.value: d for d in devices}
        zone_by_host = {d.value: cls._zone(d) for d in devices}

        zones: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for device in devices:
            zone = cls._zone(device)
            zones[zone].append({
                "ip": device.value,
                "hostname": device.attributes.get("hostname"),
                "device_type": device.attributes.get("device_type") or "unknown",
                "identity_confidence": device.attributes.get("identity_confidence") or "observed",
                "vlan_id": device.attributes.get("vlan_id"),
            })

        management_by_zone: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        candidate_management_by_zone: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        trust_by_zone: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        candidate_trust_by_zone: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        lateral_paths: list[dict[str, Any]] = []
        explicit_violations: list[dict[str, Any]] = []

        for service in services:
            port = cls._port(service)
            if port is None:
                continue
            host = cls._host(service)
            target_zone = zone_by_host.get(host) or cls._zone(service)
            attrs = service.attributes
            state = str(attrs.get("service_state") or "unconfirmed").lower()
            confirmed_name = str(attrs.get("service_name") or "unknown") if state == "confirmed" else "unknown"
            candidate_name = str(attrs.get("service_candidate") or attrs.get("service") or "unknown")
            row = {
                "host": host,
                "target_zone": target_zone,
                "port": port,
                "service": confirmed_name,
                "service_candidate": candidate_name,
                "asset_id": str(service.id),
                "service_state": state,
                "identity_basis": attrs.get("identity_basis") or "conventional-port-candidate",
            }
            if port in cls.MANAGEMENT_PORTS:
                target = management_by_zone if state == "confirmed" and confirmed_name != "unknown" else candidate_management_by_zone
                target[target_zone].append({**row, "protocol": confirmed_name if state == "confirmed" else "unknown", "protocol_candidate": cls.MANAGEMENT_PORTS[port]})
            if port in cls.TRUST_PORTS:
                target = trust_by_zone if state == "confirmed" and confirmed_name != "unknown" else candidate_trust_by_zone
                target[target_zone].append({**row, "protocol": confirmed_name if state == "confirmed" else "unknown", "protocol_candidate": cls.TRUST_PORTS[port]})

            reachable = attrs.get("reachable_from_zones") or attrs.get("source_zones") or []
            if isinstance(reachable, str):
                reachable = [reachable]
            allowed = attrs.get("allowed_source_zones") or []
            if isinstance(allowed, str):
                allowed = [allowed]
            for source_zone in [str(x) for x in reachable if str(x).strip()]:
                if source_zone == target_zone:
                    continue
                path = {
                    "source_zone": source_zone,
                    "target_zone": target_zone,
                    "target": host,
                    "port": port,
                    "service": confirmed_name,
                    "service_candidate": cls.TRUST_PORTS.get(port, candidate_name),
                    "service_state": state,
                    "identity_basis": attrs.get("identity_basis") or "conventional-port-candidate",
                    "evidence": "observed reachability metadata",
                    "policy_violation": bool(attrs.get("segmentation_violation") or attrs.get("policy_violation")),
                }
                if allowed and source_zone not in {str(x) for x in allowed}:
                    path["policy_violation"] = True
                    path["policy_basis"] = "source zone is absent from allowed_source_zones"
                lateral_paths.append(path)
                if path["policy_violation"]:
                    explicit_violations.append({**path, "service_asset_id": str(service.id)})

        boundary_edges: list[dict[str, Any]] = []
        relation_counts: Counter[str] = Counter()
        for device in devices:
            metadata = device.attributes.get("metadata") or {}
            links = metadata.get("topology_links", []) if isinstance(metadata, dict) else []
            for link in links:
                if not isinstance(link, dict):
                    continue
                source = str(link.get("source") or device.value)
                target = str(link.get("target") or "")
                if not target:
                    continue
                source_zone = zone_by_host.get(source, cls._zone(device) if source == device.value else "unclassified")
                target_zone = zone_by_host.get(target, "unclassified")
                if source_zone == target_zone:
                    continue
                relation = str(link.get("relation") or "connected")
                edge = {
                    "source": source,
                    "target": target,
                    "source_zone": source_zone,
                    "target_zone": target_zone,
                    "relation": relation,
                    "evidence": str(link.get("evidence") or "sensor"),
                    "confidence": str(link.get("confidence") or "observed"),
                    "policy_violation": bool(link.get("segmentation_violation") or link.get("policy_violation")),
                }
                if edge not in boundary_edges:
                    boundary_edges.append(edge)
                    relation_counts[relation] += 1
                if edge["policy_violation"]:
                    explicit_violations.append(edge)

        identity_hosts = []
        infrastructure_hosts = []
        for device in devices:
            role = str(device.attributes.get("device_type") or "unknown")
            row = {"ip": device.value, "zone": cls._zone(device), "role": role}
            if role in {"domain-controller", "server", "active-directory"} or device.attributes.get("is_domain_controller"):
                identity_hosts.append(row)
            if role in {"switch", "gateway/router", "firewall", "wireless-ap", "access-point", "virtualization-host", "container-host", "nas"}:
                infrastructure_hosts.append(row)

        return {
            "zone_count": len(zones),
            "zones": {k: v for k, v in sorted(zones.items())},
            "unclassified_device_count": len(zones.get("unclassified", [])),
            "management_surfaces_by_zone": {k: v for k, v in sorted(management_by_zone.items())},
            "candidate_management_surfaces_by_zone": {k: v for k, v in sorted(candidate_management_by_zone.items())},
            "trust_services_by_zone": {k: v for k, v in sorted(trust_by_zone.items())},
            "candidate_trust_services_by_zone": {k: v for k, v in sorted(candidate_trust_by_zone.items())},
            "boundary_relationships": boundary_edges,
            "boundary_relation_counts": dict(relation_counts),
            "cross_zone_exposure_paths": lateral_paths,
            "explicit_policy_violations": explicit_violations,
            "identity_zone_map": identity_hosts,
            "infrastructure_zone_map": infrastructure_hosts,
            "evidence_count": len(evidence),
            "basis": "passive correlation of explicit zone/VLAN metadata, sensor topology, and observed service reachability",
            "limitations": (
                "Cross-zone TCP reachability is not treated as a segmentation failure unless supplied policy metadata "
                "or sensor evidence explicitly identifies a policy violation. Conventional port mappings are candidates only; "
                "application protocols require independent confirmation. No lateral movement or credential use is performed."
            ),
        }

    @classmethod
    def derive(cls, assets: list[Asset], evidence: list[Evidence]) -> tuple[list[Evidence], list[Finding]]:
        summary = cls.summarize(assets, evidence)
        derived = [Evidence(
            engine="ShadowTrust",
            category="internal-segmentation-summary",
            summary=(
                f"Correlated {summary['zone_count']} zone(s), {len(summary['boundary_relationships'])} trust-boundary "
                f"relationship(s), and {len(summary['cross_zone_exposure_paths'])} cross-zone exposure path(s)"
            ),
            raw=summary,
        )]
        findings: list[Finding] = []

        service_by_id = {str(a.id): a for a in cls._services(assets)}
        seen: set[tuple[str, str, int]] = set()
        for violation in summary["explicit_policy_violations"]:
            service_id = violation.get("service_asset_id")
            if not service_id:
                continue
            service = service_by_id.get(str(service_id))
            if service is None:
                continue
            host = cls._host(service)
            port = cls._port(service) or 0
            source_zone = str(violation.get("source_zone") or "unknown")
            key = (source_zone, host, port)
            if key in seen:
                continue
            seen.add(key)
            supporting = cls._evidence_for_asset(evidence, service.id)
            ev = Evidence(
                asset_id=service.id,
                engine="ShadowTrust",
                category="segmentation-policy-violation",
                summary=f"Observed policy-marked cross-zone reachability from {source_zone} to {host}:{port}",
                raw=violation,
            )
            derived.append(ev)
            findings.append(Finding(
                title="Observed cross-zone access conflicts with segmentation policy",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                affected_asset=f"{host}:{port}",
                description=(
                    "Authorized sensor/service metadata explicitly marks this observed cross-zone reachability as a "
                    "segmentation or policy violation. ShadowStrike did not attempt lateral movement or authenticate to the service."
                ),
                remediation=(
                    "Review the documented zone-to-zone policy and restrict the observed path at the appropriate firewall, ACL, "
                    "security group, host firewall, or network access-control layer. Retest the exact path after the change."
                ),
                evidence_ids=[x.id for x in supporting] + [ev.id],
                tags=["internal", "segmentation", "trust-boundary", "policy-violation"],
                validation_status="observed-policy-violation",
                evidence_quality="corroborated" if supporting else "single-observation",
                technical_impact="A path exists across an intended trust boundary according to supplied policy evidence.",
                business_impact="Unexpected cross-zone reachability can weaken containment and increase the blast radius of a compromised internal host.",
                remediation_priority="P2 - high",
                priority_score=68,
                retest_status="not-retested",
                attack_path=[source_zone, "Trust boundary", violation.get("target_zone") or "target zone", f"{host}:{port}"],
            ))

        return derived, findings


class InternalSegmentationEngine(Engine):
    """Passive segmentation/trust synthesis; performs no additional target I/O."""

    name = "ShadowTrust"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if context.profile not in {"internal", "full"}:
            return EngineOutput(assets=[], evidence=[], findings=[])
        derived, findings = InternalSegmentationService.derive(
            list(context.assets or []), list(context.evidence or [])
        )
        return EngineOutput(assets=[], evidence=derived, findings=findings)
