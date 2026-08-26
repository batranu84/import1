from shadowstrike.models.domain import AssessmentResult, Asset, Confidence, Evidence, Finding, Severity
from shadowstrike.services.delta import DeltaService


def test_delta_tracks_new_assets_findings_and_evidence_categories():
    previous = AssessmentResult(
        name="fixture",
        profile="full",
        assets=[Asset(kind="host", value="a.example.test", source="x")],
        evidence=[Evidence(engine="x", category="dns", summary="old")],
    )
    current = AssessmentResult(
        name="fixture",
        profile="full",
        assets=[
            Asset(kind="host", value="a.example.test", source="x"),
            Asset(kind="host", value="b.example.test", source="x"),
        ],
        evidence=[
            Evidence(engine="x", category="dns", summary="one"),
            Evidence(engine="x", category="dns", summary="two"),
        ],
        findings=[
            Finding(
                title="New finding",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                affected_asset="b.example.test",
                description="fixture",
                remediation="fixture",
            )
        ],
    )
    delta = DeltaService().compare(previous, current)
    assert ["host", "b.example.test"] in delta["assets"]["added"]
    assert any(item[:2] == ["New finding", "b.example.test"] for item in delta["findings"]["added"])
    assert delta["evidence_category_delta"]["dns"] == 1
