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
)
from shadowstrike.reporting.retest import RetestReport
from shadowstrike.services.remediation import RemediationRetestService
from shadowstrike.storage.repository import AssessmentRepository


def make_finding(evidence: Evidence) -> Finding:
    return Finding(
        title="Example exposure",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        affected_asset="example.test:443",
        description="Observed exposure",
        remediation="Apply the approved configuration change.",
        evidence_ids=[evidence.id],
    )


def test_remediation_and_retest_lifecycle_requires_after_evidence() -> None:
    before = Evidence(engine="ShadowHTTP", category="http", summary="before", raw={})
    after = Evidence(engine="ShadowHTTP", category="http", summary="after", raw={})
    finding = make_finding(before)
    service = RemediationRetestService()

    service.update_remediation(
        finding,
        status="remediation-in-progress",
        owner="client-ops",
        notes="Change scheduled",
    )
    assert finding.remediation_status == "remediation-in-progress"
    assert finding.remediation_owner == "client-ops"

    record = service.request_retest(finding, operator="analyst")
    assert record.before_evidence_ids == [before.id]
    assert finding.retest_status == "pending"
    assert finding.remediation_status == "ready-for-retest"

    try:
        service.complete_retest(finding, status="fixed", after_evidence_ids=[])
        raise AssertionError("empty after evidence should have failed")
    except ValueError:
        pass

    completed = service.complete_retest(
        finding,
        status="fixed",
        after_evidence_ids=[after.id],
        notes="Control verified",
    )
    assert completed.status == "fixed"
    assert completed.completed_at is not None
    assert completed.after_evidence_ids == [after.id]
    assert finding.retest_status == "fixed"
    assert finding.remediation_status == "remediated"


def test_risk_acceptance_requires_reference() -> None:
    evidence = Evidence(engine="ShadowScan", category="port", summary="open", raw={})
    finding = make_finding(evidence)
    service = RemediationRetestService()
    try:
        service.update_remediation(finding, status="risk-accepted")
        raise AssertionError("missing reference should fail")
    except ValueError:
        pass
    service.update_remediation(
        finding,
        status="risk-accepted",
        risk_acceptance_reference="RISK-2026-004",
    )
    assert finding.retest_status == "risk-accepted"


def test_retest_report_renders_before_after_evidence() -> None:
    before = Evidence(engine="ShadowHTTP", category="http", summary="before", raw={})
    after = Evidence(engine="ShadowHTTP", category="http", summary="after", raw={})
    finding = make_finding(before)
    service = RemediationRetestService()
    service.request_retest(finding, operator="analyst")
    service.complete_retest(finding, status="partially-fixed", after_evidence_ids=[after.id])
    result = AssessmentResult(name="fixture", profile="full", evidence=[before, after], findings=[finding])
    html = RetestReport().render(result)
    assert "Remediation & Retest Report" in html
    assert "partially-fixed" in html
    assert str(before.id) in html
    assert str(after.id) in html


def test_retest_api_persists_workflow_and_validates_evidence(tmp_path: Path, monkeypatch) -> None:
    repo = AssessmentRepository(tmp_path / "retest.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    before = Evidence(engine="ShadowHTTP", category="http", summary="before", raw={})
    after = Evidence(engine="ShadowHTTP", category="http", summary="after", raw={})
    finding = make_finding(before)
    request = AssessmentRequest(
        name="retest-api",
        targets=["example.test"],
        authorization_reference="LAB-RETEST",
        scope=ScopePolicy(allowed_domains=["example.test"]),
    )
    result = AssessmentResult(name=request.name, profile=request.profile, evidence=[before, after], findings=[finding])
    repo.save(request, result)

    client = TestClient(app)
    remediation = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/remediation",
        json={"status": "remediation-in-progress", "owner": "client-ops"},
    )
    assert remediation.status_code == 200
    assert remediation.json()["remediation_status"] == "remediation-in-progress"

    requested = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/retest/request",
        json={"operator": "analyst"},
    )
    assert requested.status_code == 200
    assert requested.json()["status"] == "pending"

    invalid = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/retest/complete",
        json={"status": "fixed", "after_evidence_ids": ["00000000-0000-0000-0000-000000000000"]},
    )
    assert invalid.status_code == 400

    completed = client.post(
        f"/assessments/{result.id}/findings/{finding.id}/retest/complete",
        json={"status": "fixed", "after_evidence_ids": [str(after.id)], "operator": "analyst"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "fixed"

    report = client.get(f"/assessments/{result.id}/retest-report")
    assert report.status_code == 200
    assert "Fixed" in report.text

    loaded = repo.load(result.id)
    assert loaded is not None
    saved = loaded[1].findings[0]
    assert saved.retest_status == "fixed"
    assert saved.remediation_status == "remediated"
    assert len(saved.retest_history) == 1
