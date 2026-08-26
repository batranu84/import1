from shadowstrike.models.domain import AssessmentResult, Confidence, Finding, Severity
from shadowstrike.reporting.html import HtmlReport


def test_report_renders_finding_intelligence_fields():
    finding = Finding(
        title="Example exposure", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
        affected_asset="example.com:443", description="Observed exposure", remediation="Restrict access",
        validation_status="evidence-confirmed", evidence_quality="corroborated",
        business_impact="Business impact text", technical_impact="Technical impact text",
        remediation_priority="P2-high", priority_score=72, retest_status="not-retested",
        attack_path=["Internet", "example.com", "TCP/443", "Example exposure"],
    )
    html = HtmlReport().render(AssessmentResult(name="fixture", profile="full", findings=[finding]), "technical")
    assert "evidence-confirmed" in html
    assert "corroborated" in html
    assert "P2-high" in html
    assert "Business impact text" in html
    assert "Technical impact text" in html
    assert "Internet" in html and "TCP/443" in html
