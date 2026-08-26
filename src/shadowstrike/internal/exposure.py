from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.internal.segmentation import InternalSegmentationService
from shadowstrike.models.domain import Asset, Evidence, Finding, Severity


class InternalExposureService:
    """Passive internal exposure/attack-path correlation.

    The service creates defensible path records from already-observed assets, explicit
    cross-zone reachability, identity/infrastructure roles and existing findings. It
    performs no authentication, lateral movement or exploit execution and does not infer
    successful compromise from service visibility alone.
    """

    SEVERITY_WEIGHT = {
        Severity.INFO.value: 5,
        Severity.LOW.value: 20,
        Severity.MEDIUM.value: 45,
        Severity.HIGH.value: 70,
        Severity.CRITICAL.value: 90,
    }

    @staticmethod
    def _devices(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-device" and a.source == "ShadowLAN"]

    @staticmethod
    def _host_from_finding(finding: Finding) -> str:
        affected = str(finding.affected_asset or "").strip()
        if not affected:
            return ""
        if affected.startswith("[") and "]:" in affected:
            return affected[1:].split("]:", 1)[0]
        if affected.count(":") == 1:
            host, port = affected.rsplit(":", 1)
            if port.isdigit():
                return host
        return affected

    @staticmethod
    def _role(device: Asset | None) -> str:
        if device is None:
            return "unknown"
        return str(device.attributes.get("device_type") or "unknown")

    @classmethod
    def summarize(cls, assets: list[Asset], evidence: list[Evidence], findings: list[Finding]) -> dict[str, Any]:
        devices = cls._devices(assets)
        device_by_ip = {d.value: d for d in devices}
        zone_by_ip = {d.value: InternalSegmentationService._zone(d) for d in devices}
        trust = InternalSegmentationService.summarize(assets, evidence)

        findings_by_host: defaultdict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            host = cls._host_from_finding(finding)
            if host:
                findings_by_host[host].append(finding)

        paths: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int, str]] = set()
        for exposure in trust.get("cross_zone_exposure_paths", []):
            host = str(exposure.get("target") or "")
            source_zone = str(exposure.get("source_zone") or "unknown")
            target_zone = str(exposure.get("target_zone") or zone_by_ip.get(host) or "unclassified")
            port = int(exposure.get("port") or 0)
            service_state = str(exposure.get("service_state") or "unconfirmed").lower()
            service = str(exposure.get("service") or "unknown") if service_state == "confirmed" else "unknown"
            service_candidate = str(exposure.get("service_candidate") or "unknown")
            endpoint_label = service if service != "unknown" else f"candidate: {service_candidate}" if service_candidate != "unknown" else "unidentified service"
            device = device_by_ip.get(host)
            role = cls._role(device)
            related = findings_by_host.get(host, [])

            if not related:
                key = (source_zone, host, port, "inventory")
                if key in seen:
                    continue
                seen.add(key)
                score = 25 + (20 if exposure.get("policy_violation") else 0)
                paths.append({
                    "source_zone": source_zone,
                    "target_zone": target_zone,
                    "target": host,
                    "target_role": role,
                    "service": service,
                    "service_candidate": service_candidate,
                    "service_state": service_state,
                    "port": port,
                    "finding_id": None,
                    "finding_title": None,
                    "finding_severity": None,
                    "validation_status": "observed-reachability",
                    "policy_violation": bool(exposure.get("policy_violation")),
                    "path_score": min(score, 100),
                    "path": [source_zone, "Trust boundary", target_zone, f"{host}:{port} ({endpoint_label})"],
                    "basis": "observed cross-zone transport reachability; application identity is separate and no compromise is inferred",
                })
                continue

            for finding in related:
                key = (source_zone, host, port, str(finding.id))
                if key in seen:
                    continue
                seen.add(key)
                sev = cls.SEVERITY_WEIGHT.get(finding.severity.value, 20)
                score = sev
                if exposure.get("policy_violation"):
                    score += 15
                if finding.confidence.value in {"high", "confirmed"}:
                    score += 10
                if role in {"domain-controller", "firewall", "gateway/router", "switch", "virtualization-host", "container-host", "nas"}:
                    score += 5
                score = min(score, 100)
                paths.append({
                    "source_zone": source_zone,
                    "target_zone": target_zone,
                    "target": host,
                    "target_role": role,
                    "service": service,
                    "service_candidate": service_candidate,
                    "service_state": service_state,
                    "port": port,
                    "finding_id": str(finding.id),
                    "finding_title": finding.title,
                    "finding_severity": finding.severity.value,
                    "validation_status": finding.validation_status,
                    "evidence_quality": finding.evidence_quality,
                    "policy_violation": bool(exposure.get("policy_violation")),
                    "path_score": score,
                    "path": [
                        source_zone,
                        "Trust boundary",
                        target_zone,
                        f"{host}:{port} ({endpoint_label})",
                        finding.title,
                    ],
                    "basis": "existing finding correlated with observed cross-zone transport reachability; protocol identity is not inferred from port number and no exploitation is performed",
                })

        # Existing findings on sensitive infrastructure remain useful exposure paths even
        # when no cross-zone source metadata is available.
        sensitive_roles = {"domain-controller", "firewall", "gateway/router", "switch", "virtualization-host", "container-host", "nas"}
        for host, host_findings in findings_by_host.items():
            device = device_by_ip.get(host)
            role = cls._role(device)
            if role not in sensitive_roles:
                continue
            zone = zone_by_ip.get(host, "unclassified")
            for finding in host_findings:
                key = ("local/unknown", host, 0, str(finding.id))
                if key in seen:
                    continue
                seen.add(key)
                score = min(cls.SEVERITY_WEIGHT.get(finding.severity.value, 20) + 5, 100)
                paths.append({
                    "source_zone": "local/unknown",
                    "target_zone": zone,
                    "target": host,
                    "target_role": role,
                    "service": None,
                    "port": None,
                    "finding_id": str(finding.id),
                    "finding_title": finding.title,
                    "finding_severity": finding.severity.value,
                    "validation_status": finding.validation_status,
                    "evidence_quality": finding.evidence_quality,
                    "policy_violation": False,
                    "path_score": score,
                    "path": [zone, f"{host} ({role})", finding.title],
                    "basis": "existing finding on sensitive infrastructure; reachability origin not established",
                })

        paths.sort(key=lambda p: (-int(p["path_score"]), str(p["target"]), str(p.get("finding_title") or "")))
        score_bands = Counter(
            "critical" if p["path_score"] >= 90 else
            "high" if p["path_score"] >= 70 else
            "medium" if p["path_score"] >= 40 else "low"
            for p in paths
        )
        role_counts = Counter(str(p.get("target_role") or "unknown") for p in paths)
        return {
            "path_count": len(paths),
            "paths": paths,
            "score_bands": dict(score_bands),
            "target_role_counts": dict(role_counts),
            "policy_violation_path_count": sum(1 for p in paths if p.get("policy_violation")),
            "finding_correlated_path_count": sum(1 for p in paths if p.get("finding_id")),
            "basis": "passive correlation of explicit reachability, trust boundaries, asset roles, evidence and existing findings",
            "limitations": (
                "Path records describe observed or evidence-supported exposure relationships. They do not demonstrate lateral movement, "
                "credential validity, privilege escalation, exploitability, or successful compromise unless those outcomes are separately validated."
            ),
        }

    @classmethod
    def derive(cls, assets: list[Asset], evidence: list[Evidence], findings: list[Finding]) -> list[Evidence]:
        summary = cls.summarize(assets, evidence, findings)
        return [Evidence(
            engine="ShadowPath",
            category="internal-exposure-path-summary",
            summary=(
                f"Correlated {summary['path_count']} internal exposure path(s), including "
                f"{summary['finding_correlated_path_count']} path(s) linked to existing findings"
            ),
            raw=summary,
        )]


class InternalExposureEngine(Engine):
    """Passive internal exposure-path synthesis; performs no additional target I/O."""

    name = "ShadowPath"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if context.profile not in {"internal", "full"}:
            return EngineOutput(assets=[], evidence=[], findings=[])
        derived = InternalExposureService.derive(
            list(context.assets or []), list(context.evidence or []), list(context.findings or [])
        )
        return EngineOutput(assets=[], evidence=derived, findings=[])
