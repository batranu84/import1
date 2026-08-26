from pathlib import Path

from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.models.domain import (
    AssessmentRequest,
    AssessmentResult,
    Confidence,
    Evidence,
    Finding,
    ScopePolicy,
    Severity,
    ValidationState,
)
from shadowstrike.reporting.validation import ValidationReport
from shadowstrike.services.validation import ControlledValidationService
from shadowstrike.storage.repository import AssessmentRepository


def make_finding(evidence: Evidence) -> Finding:
    return Finding(
        title="Controlled validation fixture",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_asset="example.test:443",
        description="A weakness requiring explicit controlled validation.",
        remediation="Apply the approved fix and retest.",
        evidence_ids=[evidence.id],
    )


def test_validation_lifecycle_requires_matching_proof_and_cleanup() -> None:
    attempt = Evidence(engine="operator", category="validation-attempt", summary="attempt", raw={})
    proof = Evidence(engine="operator", category="proof", summary="proof", raw={})
    cleanup = Evidence(engine="operator", category="cleanup", summary="cleanup", raw={})
    finding = make_finding(attempt)
    service = ControlledValidationService()
    available = {str(attempt.id), str(proof.id), str(cleanup.id)}

    session = service.authorize(
        finding,
        assessment_authorization_reference="AUTH-1",
        validation_authorization_reference="AUTH-VAL-1",
        operator="analyst",
        technique="controlled reproduction",
        objective_description="Reach the harmless assessment marker only",
        expected_access_level="application service account",
    )
    assert session.state == ValidationState.AUTHORIZED
    assert session.proof_objective.marker.startswith("SS-PROOF-")

    artifact = service.add_poc(
        finding,
        session,
        artifact_type="http-request",
        title="Minimal reproduction",
        content="POST /test HTTP/1.1\nX-Assessment-Proof: <engagement marker>",
    )
    assert artifact.non_persistent is True
    assert session.state == ValidationState.POC_PREPARED

    service.record_attempt(
        finding,
        session,
        evidence_ids=[attempt.id],
        available_evidence_ids=available,
    )
    assert session.state == ValidationState.EXECUTION_ATTEMPTED

    try:
        service.complete(
            finding,
            session,
            verdict="proof-objective-achieved",
            proof_evidence_ids=[proof.id],
            available_evidence_ids=available,
            proof_marker_observed="WRONG",
            access_level_achieved="application service account",
        )
        raise AssertionError("wrong proof marker should fail")
    except ValueError:
        pass

    service.complete(
        finding,
        session,
        verdict="proof-objective-achieved",
        proof_evidence_ids=[proof.id],
        available_evidence_ids=available,
        proof_marker_observed=session.proof_objective.marker,
        access_level_achieved="application service account",
    )
    assert session.state == ValidationState.PROOF_ACHIEVED

    service.confirm_cleanup(
        finding,
        session,
        cleanup_evidence_ids=[cleanup.id],
        available_evidence_ids=available,
    )
    assert session.state == ValidationState.CLEANUP_CONFIRMED
    assert session.cleanup_confirmed is True
    assert session.completed_at is not None


def test_client_poc_rejects_persistence_credentials_and_destructive_flags() -> None:
    evidence = Evidence(engine="operator", category="validation", summary="fixture", raw={})
    finding = make_finding(evidence)
    service = ControlledValidationService()
    session = service.authorize(
        finding,
        assessment_authorization_reference="AUTH-1",
        validation_authorization_reference="AUTH-VAL-1",
        operator=None,
        technique="manual",
        objective_description="harmless proof",
    )
    for kwargs in (
        {"non_persistent": False},
        {"credential_access": True},
        {"destructive": True},
    ):
        try:
            service.add_poc(
                finding,
                session,
                artifact_type="script",
                title="unsafe",
                content="fixture",
                **kwargs,
            )
            raise AssertionError("unsafe PoC declaration should fail")
        except ValueError:
            pass


def test_validation_report_contains_proof_chain() -> None:
    attempt = Evidence(engine="operator", category="validation-attempt", summary="attempt", raw={})
    proof = Evidence(engine="operator", category="proof", summary="proof", raw={})
    cleanup = Evidence(engine="operator", category="cleanup", summary="cleanup", raw={})
    finding = make_finding(attempt)
    service = ControlledValidationService()
    available = {str(attempt.id), str(proof.id), str(cleanup.id)}
    session = service.authorize(
        finding,
        assessment_authorization_reference="AUTH-1",
        validation_authorization_reference="AUTH-VAL-1",
        operator="analyst",
        technique="controlled reproduction",
        objective_description="Reach harmless marker",
        expected_access_level="service account",
    )
    service.add_poc(finding, session, artifact_type="curl", title="Reproduction", content="curl https://example.test/proof")
    service.record_attempt(finding, session, evidence_ids=[attempt.id], available_evidence_ids=available)
    service.complete(
        finding, session, verdict="proof-objective-achieved", proof_evidence_ids=[proof.id],
        available_evidence_ids=available, proof_marker_observed=session.proof_objective.marker,
        access_level_achieved="service account",
    )
    service.confirm_cleanup(finding, session, cleanup_evidence_ids=[cleanup.id], available_evidence_ids=available)
    result = AssessmentResult(name="fixture", profile="full", evidence=[attempt, proof, cleanup], findings=[finding])
    html = ValidationReport().render(result)
    assert "Controlled Validation &amp; Proof-of-Access Report" in html
    assert session.proof_objective.marker in html
    assert "cleanup-confirmed" in html
    assert "curl https://example.test/proof" in html


def test_validation_api_is_explicitly_gated_and_persists(tmp_path: Path, monkeypatch) -> None:
    repo = AssessmentRepository(tmp_path / "validation.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    attempt = Evidence(engine="operator", category="validation-attempt", summary="attempt", raw={})
    proof = Evidence(engine="operator", category="proof", summary="proof", raw={})
    cleanup = Evidence(engine="operator", category="cleanup", summary="cleanup", raw={})
    finding = make_finding(attempt)
    request = AssessmentRequest(
        name="validation-api",
        targets=["example.test"],
        authorization_reference="ENGAGEMENT-AUTH-1",
        scope=ScopePolicy(
            allowed_domains=["example.test"],
            allow_controlled_validation=True,
            validation_authorization_reference="ROE-VALIDATION-1",
        ),
    )
    result = AssessmentResult(name=request.name, profile=request.profile, evidence=[attempt, proof, cleanup], findings=[finding])
    repo.save(request, result)
    client = TestClient(app)

    auth = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/validation/authorize",
        json={"operator": "analyst", "technique": "controlled reproduction", "proof_objective": "Read the harmless engagement marker", "expected_access_level": "service account"},
    )
    assert auth.status_code == 200
    session_id = auth.json()["id"]
    marker = auth.json()["proof_objective"]["marker"]

    poc = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/validation/{session_id}/poc",
        json={"artifact_type": "http-request", "title": "Minimal PoC", "content": "GET /proof HTTP/1.1"},
    )
    assert poc.status_code == 200

    attempt_resp = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/validation/{session_id}/attempt",
        json={"evidence_ids": [str(attempt.id)], "operator": "analyst"},
    )
    assert attempt_resp.status_code == 200

    complete = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/validation/{session_id}/complete",
        json={"verdict": "proof-objective-achieved", "proof_evidence_ids": [str(proof.id)], "proof_marker_observed": marker, "access_level_achieved": "service account"},
    )
    assert complete.status_code == 200
    assert complete.json()["state"] == "proof-objective-achieved"

    cleanup_resp = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/validation/{session_id}/cleanup",
        json={"cleanup_evidence_ids": [str(cleanup.id)]},
    )
    assert cleanup_resp.status_code == 200
    assert cleanup_resp.json()["state"] == "cleanup-confirmed"

    report = client.get(f"/assessments/{result.id}/validation-report")
    assert report.status_code == 200
    assert marker in report.text

    loaded = repo.load(result.id)
    assert loaded is not None
    saved = loaded[1].findings[0].validation_sessions[0]
    assert saved.cleanup_confirmed is True
    assert saved.verdict == "proof-objective-achieved"


def test_validation_api_denies_when_scope_does_not_authorize(tmp_path: Path, monkeypatch) -> None:
    repo = AssessmentRepository(tmp_path / "validation-denied.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    evidence = Evidence(engine="operator", category="validation", summary="fixture", raw={})
    finding = make_finding(evidence)
    request = AssessmentRequest(
        name="validation-denied",
        targets=["example.test"],
        authorization_reference="AUTH-1",
        scope=ScopePolicy(allowed_domains=["example.test"], allow_controlled_validation=False),
    )
    result = AssessmentResult(name=request.name, profile=request.profile, evidence=[evidence], findings=[finding])
    repo.save(request, result)
    client = TestClient(app)
    response = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/validation/authorize",
        json={"technique": "controlled reproduction", "proof_objective": "harmless marker"},
    )
    assert response.status_code == 403
