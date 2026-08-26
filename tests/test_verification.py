from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity
from shadowstrike.services.verification import VerificationService, VerificationState


def test_confirmed_finding_is_confirmed():
    evidence = Evidence(engine="fixture", category="x", summary="observed")
    finding = Finding(
        title="fixture",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        affected_asset="example.test",
        description="fixture",
        remediation="fixture",
        evidence_ids=[evidence.id],
    )
    record = VerificationService().classify(finding)
    assert record.state == VerificationState.CONFIRMED
    assert record.evidence_count == 1


def test_unlinked_finding_requires_review():
    finding = Finding(
        title="fixture",
        severity=Severity.INFO,
        confidence=Confidence.PROBABLE,
        affected_asset="example.test",
        description="fixture",
        remediation="fixture",
    )
    assert VerificationService().classify(finding).state == VerificationState.MANUAL
