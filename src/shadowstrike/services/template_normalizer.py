from __future__ import annotations

from typing import Any, Iterable

from shadowstrike.core.scope import ScopeGuard
from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity

_SEVERITY = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


class TemplateResultNormalizer:
    """Normalize pre-produced template scanner results into ShadowStrike evidence.

    This component does not execute templates or commands; adapters provide structured
    observations which are then scope-filtered and normalized.
    """

    def normalize(self, records: Iterable[dict[str, Any]], scope: ScopeGuard) -> tuple[list[Evidence], list[Finding]]:
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        for record in records:
            target = str(record.get("host") or record.get("matched-at") or record.get("url") or "")
            if not target or not scope.allows(target):
                continue
            name = str(record.get("name") or record.get("template-id") or "Template observation")
            sev = _SEVERITY.get(str(record.get("severity", "info")).lower(), Severity.INFO)
            ev = Evidence(engine="ShadowTemplate", category="template-observation", summary=name, raw=dict(record))
            evidence.append(ev)
            findings.append(Finding(
                title=name,
                severity=sev,
                confidence=Confidence.PROBABLE,
                affected_asset=target,
                description=str(record.get("description") or "Template-derived observation requiring ShadowVerify review."),
                remediation=str(record.get("remediation") or "Review the affected configuration and validate the condition."),
                evidence_ids=[ev.id],
                tags=["template", str(record.get("template-id") or "unknown")],
            ))
        return evidence, findings
