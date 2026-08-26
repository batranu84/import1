from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity


SEVERITY_WEIGHT = {
    Severity.INFO: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}
CONFIDENCE_WEIGHT = {
    Confidence.INFORMATIONAL: 0,
    Confidence.PROBABLE: 3,
    Confidence.HIGH: 7,
    Confidence.CONFIRMED: 10,
}


class FindingIntelligenceService:
    """Enrich findings for consultancy delivery without inventing exploitability.

    The service is deliberately deterministic. It only uses captured evidence and the
    finding's existing metadata. A CVE candidate remains a candidate until a separate,
    authorised validation step proves more.
    """

    def enrich(self, findings: list[Finding], evidence: list[Evidence]) -> list[Finding]:
        evidence_by_id = {item.id: item for item in evidence}
        by_asset: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            linked = [evidence_by_id[eid] for eid in finding.evidence_ids if eid in evidence_by_id]
            finding.validation_status = self._validation_status(finding, linked)
            finding.evidence_quality = self._evidence_quality(linked)
            finding.technical_impact = finding.technical_impact or self._technical_impact(finding)
            finding.business_impact = finding.business_impact or self._business_impact(finding)
            finding.priority_score = self._priority_score(finding, linked)
            finding.remediation_priority = self._priority_band(finding.priority_score)
            finding.attack_path = finding.attack_path or self._exposure_path(finding)
            by_asset[finding.affected_asset.lower()].append(finding)

        # Correlate co-located findings as related observations, not causal exploit chains.
        for group in by_asset.values():
            if len(group) < 2:
                continue
            ids = [item.id for item in group]
            for item in group:
                item.related_finding_ids = [fid for fid in ids if fid != item.id]
                item.tags = list(dict.fromkeys([*item.tags, "related-observations" ]))

        return findings

    @staticmethod
    def _validation_status(finding: Finding, linked: list[Evidence]) -> str:
        tags = set(finding.tags)
        if finding.cve_ids and "needs-validation" in tags:
            if "applicability-supported" in tags:
                return "applicability-supported-not-exploit-validated"
            return "candidate-needs-validation"
        if finding.confidence == Confidence.CONFIRMED and linked:
            return "evidence-confirmed"
        if finding.confidence == Confidence.HIGH and linked:
            return "high-confidence-evidence-backed"
        if linked:
            return "evidence-backed-review"
        return "insufficient-evidence-for-promotion"

    @staticmethod
    def _evidence_quality(linked: list[Evidence]) -> str:
        if not linked:
            return "none"
        engines = {item.engine for item in linked}
        categories = {item.category for item in linked}
        if len(engines) >= 2 or len(categories) >= 3:
            return "corroborated"
        if len(linked) >= 2 or len(categories) >= 2:
            return "multi-signal"
        return "single-observation"

    @staticmethod
    def _technical_impact(finding: Finding) -> str:
        tags = {tag.lower() for tag in finding.tags}
        if "cleartext" in tags:
            return "An externally reachable clear-text protocol may expose authentication or session data if encryption is not enforced at the protocol layer."
        if "remote-access" in tags or "management" in tags:
            return "The observation increases the externally reachable administrative attack surface and warrants strict access control and authentication review."
        if "database" in tags or "file-sharing" in tags:
            return "The service exposes a data-bearing interface to the assessed network boundary; security depends on network restriction, authentication, transport protection, and configuration."
        if "transport-security" in tags or "tls" in tags:
            return "The observation weakens transport-security assurance or client-side enforcement and should be reviewed against the intended security policy."
        if finding.cve_ids:
            return "The detected software identity is associated with published vulnerability intelligence. Applicability evidence does not by itself prove exploitability on this target."
        if "api" in tags:
            return "The observation increases externally visible application/API surface area and may disclose implementation structure or reachable operations."
        return "The observation increases or documents the reachable attack surface and should be reviewed against the intended architecture and exposure policy."

    @staticmethod
    def _business_impact(finding: Finding) -> str:
        tags = {tag.lower() for tag in finding.tags}
        if finding.severity in {Severity.CRITICAL, Severity.HIGH}:
            prefix = "If the underlying weakness is abused, potential business consequences may include material service, data, or administrative impact. "
        elif finding.severity == Severity.MEDIUM:
            prefix = "If security controls around this exposure are weak, the issue could contribute to unauthorised access, data exposure, or operational disruption. "
        else:
            prefix = "This is primarily a security-hardening or attack-surface concern. "
        if "remote-access" in tags or "management" in tags:
            return prefix + "Administrative interfaces deserve priority because compromise could provide broad control over affected systems."
        if "database" in tags or "file-sharing" in tags:
            return prefix + "Data-bearing services may affect confidentiality, integrity, or availability of business information."
        if "mail" in tags:
            return prefix + "Mail-service weaknesses can affect credential confidentiality and business communications."
        if "api" in tags or "web" in tags:
            return prefix + "Web/API exposure can affect customer-facing services, application data, and trust if combined with exploitable application weaknesses."
        return prefix + "Remediation should be prioritised according to asset criticality and whether the exposure is intentional."

    @staticmethod
    def _priority_score(finding: Finding, linked: list[Evidence]) -> int:
        score = SEVERITY_WEIGHT[finding.severity] + CONFIDENCE_WEIGHT[finding.confidence]
        tags = set(finding.tags)
        if "external" in tags:
            score += 4
        if "remote-access" in tags or "management" in tags:
            score += 4
        if "applicability-supported" in tags:
            score += 2
        if len({item.engine for item in linked}) >= 2:
            score += 2
        if finding.validation_status.startswith("candidate"):
            score -= 5
        return max(0, min(100, score))

    @staticmethod
    def _priority_band(score: int) -> str:
        if score >= 85:
            return "P1-immediate"
        if score >= 65:
            return "P2-high"
        if score >= 40:
            return "P3-planned"
        return "P4-hardening"

    @staticmethod
    def _exposure_path(finding: Finding) -> list[str]:
        asset = finding.affected_asset.strip()
        host = asset
        service = None
        if "://" in asset:
            parsed = urlparse(asset)
            host = parsed.hostname or asset
            service = parsed.scheme.upper() if parsed.scheme else None
        elif asset.count(":") == 1:
            maybe_host, maybe_port = asset.rsplit(":", 1)
            if maybe_port.isdigit():
                host = maybe_host
                service = f"TCP/{maybe_port}"
        path = ["Internet", host]
        if service:
            path.append(service)
        path.append(finding.title)
        return list(dict.fromkeys(item for item in path if item))
