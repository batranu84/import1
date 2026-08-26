from shadowstrike.models.domain import AssessmentResult, Asset, Finding, Severity, Confidence, ValidationSession, ValidationState, ProofObjective
from shadowstrike.risk.assessment import AssessmentRiskService


def test_validated_critical_finding_scores_above_unvalidated_low():
    result = AssessmentResult(name="risk", profile="full")
    result.assets.append(Asset(kind="network-device", value="10.0.0.10", source="test", attributes={"role": "domain controller", "criticality": "critical"}))
    low = Finding(title="Low", severity=Severity.LOW, confidence=Confidence.PROBABLE, affected_asset="10.0.0.20", description="x", remediation="x")
    high = Finding(title="Critical", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, affected_asset="10.0.0.10", description="x", remediation="x", priority_score=95)
    high.validation_sessions.append(ValidationSession(
        state=ValidationState.PROOF_ACHIEVED,
        authorization_reference="AUTH-1",
        technique="safe poc",
        proof_objective=ProofObjective(description="marker", marker="SS-PROOF-1"),
        verdict="proof-objective-achieved",
    ))
    result.findings = [low, high]
    summary = AssessmentRiskService.summarize(result)
    scores = {x["title"]: x["score"] for x in summary["finding_risk"]}
    assert scores["Critical"] > scores["Low"]
    assert summary["validated_finding_count"] == 1


def test_successful_retest_reduces_residual_risk():
    result = AssessmentResult(name="risk", profile="full")
    finding = Finding(title="High", severity=Severity.HIGH, confidence=Confidence.HIGH, affected_asset="host", description="x", remediation="x", priority_score=80)
    result.findings = [finding]
    before = AssessmentRiskService.summarize(result)["finding_risk"][0]["score"]
    finding.remediation_status = "remediated"
    finding.retest_status = "fixed"
    after = AssessmentRiskService.summarize(result)["finding_risk"][0]["score"]
    assert after < before


def test_no_findings_yields_low_zero_risk():
    summary = AssessmentRiskService.summarize(AssessmentResult(name="empty", profile="full"))
    assert summary["overall_score"] == 0
    assert summary["overall_level"] == "low"


def test_failed_module_marks_risk_not_final():
    from shadowstrike.models.domain import ModuleStatus, ModuleState
    result = AssessmentResult(name="broken", profile="full", status="completed_with_errors", modules=[ModuleStatus(name="ShadowUDP", state=ModuleState.FAILED, message="NotImplementedError")])
    summary = AssessmentRiskService.summarize(result)
    assert summary["risk_final"] is False
    assert summary["assessment_complete"] is False
    assert summary["failed_modules"] == ["ShadowUDP"]
