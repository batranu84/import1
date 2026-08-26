from __future__ import annotations

from shadowstrike.utils.compat import StrEnum

from pydantic import BaseModel

from shadowstrike.models.domain import Confidence, Finding


class VerificationState(StrEnum):
    OBSERVATION = "observation"
    CANDIDATE = "candidate"
    CORRELATED = "correlated"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    MANUAL = "manual_review"


class VerificationRecord(BaseModel):
    finding_id: str
    state: VerificationState
    reason: str
    evidence_count: int


class VerificationService:
    """Conservative finding-state classifier.

    This service never performs exploit actions. It only upgrades confidence when the
    existing evidence is sufficiently direct or independently corroborated.
    """

    def classify(self, finding: Finding) -> VerificationRecord:
        count = len(set(finding.evidence_ids))
        if finding.confidence == Confidence.CONFIRMED and count >= 1:
            state = VerificationState.CONFIRMED
            reason = "Finding is backed by direct observed evidence."
        elif count >= 2 and finding.confidence in {Confidence.HIGH, Confidence.CONFIRMED}:
            state = VerificationState.VALIDATED
            reason = "Multiple evidence objects support a high-confidence finding."
        elif count >= 2:
            state = VerificationState.CORRELATED
            reason = "Multiple evidence objects correlate to the same candidate condition."
        elif count == 1:
            state = VerificationState.CANDIDATE
            reason = "A single evidence object supports this candidate finding."
        else:
            state = VerificationState.MANUAL
            reason = "No linked evidence is available; manual review is required."
        return VerificationRecord(
            finding_id=str(finding.id), state=state, reason=reason, evidence_count=count
        )

    def summarize(self, findings: list[Finding]) -> dict[str, object]:
        records = [self.classify(f) for f in findings]
        counts: dict[str, int] = {}
        for record in records:
            counts[record.state.value] = counts.get(record.state.value, 0) + 1
        return {"counts": counts, "records": [r.model_dump(mode="json") for r in records]}
