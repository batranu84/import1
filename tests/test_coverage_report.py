from shadowstrike.models.domain import AssessmentResult, ModuleState, ModuleStatus
from shadowstrike.reporting.html import HtmlReport
from shadowstrike.services.coverage import CoverageService


def test_coverage_and_report():
    result = AssessmentResult(
        name="fixture",
        profile="full",
        status="completed_with_errors",
        modules=[
            ModuleStatus(name="one", state=ModuleState.COMPLETED, completed_units=2),
            ModuleStatus(name="two", state=ModuleState.FAILED, message="fixture"),
        ],
    )
    summary = CoverageService().summarize(result)
    assert summary["modules"]["completion_percent"] == 50.0
    html = HtmlReport().render(result)
    assert "ShadowStrike" in html
    assert "fixture" in html
    assert "50.0%" in html
