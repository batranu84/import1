from shadowstrike.models.domain import AssessmentResult
from shadowstrike.reporting.html import HtmlReport


def test_report_profiles():
    result = AssessmentResult(name="fixture", profile="full")
    assert "Technical Report" in HtmlReport().render(result, "technical")
    assert "Bug Bounty Report" in HtmlReport().render(result, "bug-bounty")
