from shadowstrike.models.domain import AssessmentResult, Finding, Severity, Confidence
from shadowstrike.reporting.executive import ExecutiveRiskReport


def test_executive_report_renders_risk_and_priorities():
    result = AssessmentResult(name="Executive", profile="full", status="completed")
    result.findings = [Finding(title="Observed high risk", severity=Severity.HIGH, confidence=Confidence.HIGH, affected_asset="host", description="x", remediation="patch", priority_score=90)]
    html = ExecutiveRiskReport().render(result)
    assert "Executive Risk Report" in html
    assert "Observed high risk" in html
    assert "Priority remediation view" in html
    assert "probability of compromise" in html
