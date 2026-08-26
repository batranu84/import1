from shadowstrike.engines.base import EngineContext
from shadowstrike.models.domain import Finding, Severity, Confidence


def test_engine_context_exposes_findings_for_validation_stage():
    finding = Finding(
        title="candidate",
        severity=Severity.INFO,
        confidence=Confidence.PROBABLE,
        affected_asset="example.test:443",
        description="candidate",
        remediation="review",
        tags=["needs-validation"],
    )
    assert "findings" in EngineContext.__dataclass_fields__

