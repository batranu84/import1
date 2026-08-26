from __future__ import annotations

from datetime import datetime, timezone
import secrets
from typing import Iterable, Optional
from uuid import UUID

from shadowstrike.models.domain import Finding, PocArtifact, ProofObjective, ValidationSession, ValidationState


FINAL_STATES = {
    ValidationState.CLEANUP_CONFIRMED,
    ValidationState.VALIDATION_FAILED,
}
VALID_VERDICTS = {
    "not-confirmed",
    "exploit-confirmed",
    "access-confirmed",
    "proof-objective-achieved",
}


class ControlledValidationService:
    """Record tightly scoped exploit validation without executing target-side payloads.

    ShadowStrike generates proof markers, enforces authorization metadata, stores safe
    proof-of-concept artifacts supplied by the operator, validates evidence references,
    and records the final verdict. Actual exploitation remains an explicit operator
    action performed only under the engagement's Rules of Engagement.
    """

    @staticmethod
    def find(findings: Iterable[Finding], finding_id: UUID | str) -> Finding:
        wanted = str(finding_id)
        for finding in findings:
            if str(finding.id) == wanted:
                return finding
        raise KeyError(f"finding {wanted} was not found")

    @staticmethod
    def find_session(finding: Finding, session_id: UUID | str) -> ValidationSession:
        wanted = str(session_id)
        for session in finding.validation_sessions:
            if str(session.id) == wanted:
                return session
        raise KeyError(f"validation session {wanted} was not found")

    @staticmethod
    def validate_evidence_ids(evidence_ids: Iterable[UUID], available_ids: set[str]) -> None:
        missing = [str(item) for item in evidence_ids if str(item) not in available_ids]
        if missing:
            raise ValueError(f"evidence IDs are not present in this assessment: {', '.join(missing)}")

    def authorize(
        self,
        finding: Finding,
        *,
        assessment_authorization_reference: str,
        validation_authorization_reference: str,
        operator: Optional[str],
        technique: str,
        objective_description: str,
        expected_access_level: Optional[str] = None,
        expected_effect: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ValidationSession:
        if not assessment_authorization_reference.strip():
            raise ValueError("assessment authorization reference is required")
        if not validation_authorization_reference.strip():
            raise ValueError("validation authorization reference is required")
        if not technique.strip():
            raise ValueError("validation technique is required")
        if not objective_description.strip():
            raise ValueError("proof objective is required")
        if finding.validation_sessions and finding.validation_sessions[-1].state not in FINAL_STATES:
            raise ValueError("an active validation session already exists for this finding")

        marker = f"SS-PROOF-{secrets.token_hex(8).upper()}"
        session = ValidationSession(
            state=ValidationState.AUTHORIZED,
            authorization_reference=validation_authorization_reference.strip(),
            operator=operator,
            technique=technique.strip(),
            expected_effect=expected_effect,
            proof_objective=ProofObjective(
                description=objective_description.strip(),
                marker=marker,
                expected_access_level=expected_access_level,
            ),
            safety_constraints=[
                "No persistence unless separately and explicitly authorized.",
                "No credential collection unless separately and explicitly authorized.",
                "No destructive action or denial of service.",
                "Stop when the agreed proof objective is achieved.",
                "Capture evidence and verify cleanup before closing validation.",
            ],
            notes=notes,
        )
        finding.validation_sessions.append(session)
        finding.validation_status = ValidationState.AUTHORIZED.value
        return session

    def add_poc(
        self,
        finding: Finding,
        session: ValidationSession,
        *,
        artifact_type: str,
        title: str,
        content: str,
        safety_notes: Optional[str] = None,
        non_persistent: bool = True,
        credential_access: bool = False,
        destructive: bool = False,
    ) -> PocArtifact:
        if session.state not in {ValidationState.AUTHORIZED, ValidationState.POC_PREPARED}:
            raise ValueError("PoC artifacts can only be prepared before execution")
        if not non_persistent or credential_access or destructive:
            raise ValueError("ShadowStrike client PoC artifacts must be non-persistent, non-destructive, and not collect credentials")
        if not content.strip():
            raise ValueError("PoC content is required")
        artifact = PocArtifact(
            artifact_type=artifact_type.strip() or "reproduction",
            title=title.strip() or "Controlled validation PoC",
            content=content,
            safety_notes=safety_notes,
            non_persistent=True,
            credential_access=False,
            destructive=False,
        )
        session.poc_artifacts.append(artifact)
        session.state = ValidationState.POC_PREPARED
        finding.validation_status = session.state.value
        return artifact

    def record_attempt(
        self,
        finding: Finding,
        session: ValidationSession,
        *,
        evidence_ids: list[UUID],
        available_evidence_ids: set[str],
        operator: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ValidationSession:
        if session.state not in {ValidationState.AUTHORIZED, ValidationState.POC_PREPARED}:
            raise ValueError("validation attempt is not allowed from the current state")
        if not evidence_ids:
            raise ValueError("attempt evidence is required")
        self.validate_evidence_ids(evidence_ids, available_evidence_ids)
        session.attempt_evidence_ids = list(evidence_ids)
        session.operator = operator or session.operator
        if notes:
            session.notes = notes
        session.state = ValidationState.EXECUTION_ATTEMPTED
        finding.validation_status = session.state.value
        return session

    def complete(
        self,
        finding: Finding,
        session: ValidationSession,
        *,
        verdict: str,
        proof_evidence_ids: list[UUID],
        available_evidence_ids: set[str],
        proof_marker_observed: Optional[str] = None,
        access_level_achieved: Optional[str] = None,
        operator: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ValidationSession:
        if session.state != ValidationState.EXECUTION_ATTEMPTED:
            raise ValueError("a validation attempt must be recorded before completion")
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"unsupported validation verdict: {verdict}")
        if not proof_evidence_ids:
            raise ValueError("proof evidence is required to complete validation")
        self.validate_evidence_ids(proof_evidence_ids, available_evidence_ids)
        if verdict == "proof-objective-achieved":
            if proof_marker_observed != session.proof_objective.marker:
                raise ValueError("observed proof marker does not match the engagement proof objective")
        if verdict in {"access-confirmed", "proof-objective-achieved"} and not (access_level_achieved or "").strip():
            raise ValueError("access_level_achieved is required for access-confirmed verdicts")

        session.proof_evidence_ids = list(proof_evidence_ids)
        session.proof_marker_observed = proof_marker_observed
        session.access_level_achieved = access_level_achieved
        session.operator = operator or session.operator
        session.verdict = verdict
        if notes:
            session.notes = notes
        if verdict == "not-confirmed":
            session.state = ValidationState.VALIDATION_FAILED
            session.completed_at = datetime.now(timezone.utc)
        elif verdict == "exploit-confirmed":
            session.state = ValidationState.EXPLOIT_CONFIRMED
        elif verdict == "access-confirmed":
            session.state = ValidationState.ACCESS_CONFIRMED
        else:
            session.state = ValidationState.PROOF_ACHIEVED
        finding.validation_status = session.state.value
        return session

    def confirm_cleanup(
        self,
        finding: Finding,
        session: ValidationSession,
        *,
        cleanup_evidence_ids: list[UUID],
        available_evidence_ids: set[str],
        operator: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ValidationSession:
        if session.state not in {
            ValidationState.EXPLOIT_CONFIRMED,
            ValidationState.ACCESS_CONFIRMED,
            ValidationState.PROOF_ACHIEVED,
        }:
            raise ValueError("cleanup can only be confirmed after successful validation")
        if not cleanup_evidence_ids:
            raise ValueError("cleanup evidence is required")
        self.validate_evidence_ids(cleanup_evidence_ids, available_evidence_ids)
        session.cleanup_evidence_ids = list(cleanup_evidence_ids)
        session.cleanup_confirmed = True
        session.operator = operator or session.operator
        if notes:
            session.notes = notes
        session.state = ValidationState.CLEANUP_CONFIRMED
        session.completed_at = datetime.now(timezone.utc)
        finding.validation_status = session.state.value
        return session
