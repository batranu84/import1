from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional
from uuid import UUID

from shadowstrike.models.domain import Finding, RetestRecord


REMEDIATION_STATES = {
    "open",
    "remediation-planned",
    "remediation-in-progress",
    "ready-for-retest",
    "remediated",
    "partially-remediated",
    "risk-accepted",
}
RETEST_RESULTS = {"fixed", "partially-fixed", "not-fixed"}


class RemediationRetestService:
    """Manage remediation and retest state without performing target-side actions.

    The service records operator decisions and evidence relationships. It never infers a
    successful fix from a scan result: a retest must be completed explicitly and linked
    to after-evidence captured by the assessment workflow.
    """

    @staticmethod
    def find(findings: Iterable[Finding], finding_id: UUID | str) -> Finding:
        wanted = str(finding_id)
        for finding in findings:
            if str(finding.id) == wanted:
                return finding
        raise KeyError(f"finding {wanted} was not found")

    def update_remediation(
        self,
        finding: Finding,
        *,
        status: str,
        owner: Optional[str] = None,
        due_at: Optional[datetime] = None,
        notes: Optional[str] = None,
        risk_acceptance_reference: Optional[str] = None,
    ) -> Finding:
        if status not in REMEDIATION_STATES:
            raise ValueError(f"unsupported remediation status: {status}")
        if status == "risk-accepted" and not (risk_acceptance_reference or "").strip():
            raise ValueError("risk_acceptance_reference is required for risk-accepted findings")
        finding.remediation_status = status
        finding.remediation_owner = owner
        finding.remediation_due_at = due_at
        finding.remediation_notes = notes
        finding.risk_acceptance_reference = risk_acceptance_reference
        if status == "risk-accepted":
            finding.retest_status = "risk-accepted"
        return finding

    def request_retest(
        self,
        finding: Finding,
        *,
        operator: Optional[str] = None,
        notes: Optional[str] = None,
        before_evidence_ids: Optional[list[UUID]] = None,
    ) -> RetestRecord:
        if finding.remediation_status == "risk-accepted":
            raise ValueError("risk-accepted findings cannot enter retest without reopening remediation")
        if finding.retest_history and finding.retest_history[-1].status == "pending":
            raise ValueError("a retest is already pending for this finding")
        record = RetestRecord(
            status="pending",
            operator=operator,
            notes=notes,
            before_evidence_ids=list(before_evidence_ids or finding.evidence_ids),
        )
        finding.retest_history.append(record)
        finding.retest_status = "pending"
        finding.remediation_status = "ready-for-retest"
        return record

    def complete_retest(
        self,
        finding: Finding,
        *,
        status: str,
        after_evidence_ids: list[UUID],
        operator: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> RetestRecord:
        if status not in RETEST_RESULTS:
            raise ValueError(f"unsupported retest result: {status}")
        if not after_evidence_ids:
            raise ValueError("after_evidence_ids are required to complete a retest")
        if not finding.retest_history or finding.retest_history[-1].status != "pending":
            raise ValueError("no pending retest exists for this finding")
        record = finding.retest_history[-1]
        record.status = status
        record.completed_at = datetime.now(timezone.utc)
        record.operator = operator or record.operator
        if notes:
            record.notes = notes
        record.after_evidence_ids = list(after_evidence_ids)
        finding.retest_status = status
        if status == "fixed":
            finding.remediation_status = "remediated"
        elif status == "partially-fixed":
            finding.remediation_status = "partially-remediated"
        else:
            finding.remediation_status = "open"
        return record
