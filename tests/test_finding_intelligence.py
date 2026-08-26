from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity
from shadowstrike.services.finding_intelligence import FindingIntelligenceService


def test_confirmed_finding_gets_delivery_metadata():
    ev = Evidence(engine="ShadowScan", category="port", summary="open", raw={"host":"example.com", "port":3389})
    finding = Finding(
        title="Remote Desktop service exposed", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
        affected_asset="example.com:3389", description="RDP reachable", remediation="Restrict access",
        evidence_ids=[ev.id], tags=["external", "remote-access", "rdp"],
    )
    out = FindingIntelligenceService().enrich([finding], [ev])[0]
    assert out.validation_status == "evidence-confirmed"
    assert out.evidence_quality == "single-observation"
    assert out.business_impact
    assert out.technical_impact
    assert out.remediation_priority == "P3-planned"
    assert out.retest_status == "not-retested"
    assert out.attack_path == ["Internet", "example.com", "TCP/3389", "Remote Desktop service exposed"]


def test_cve_candidate_is_not_promoted_to_exploit_validated():
    ev1 = Evidence(engine="ShadowScan", category="port", summary="open", raw={})
    ev2 = Evidence(engine="ShadowValidate", category="service-identity-correlation", summary="corroborated", raw={})
    finding = Finding(
        title="Candidate CVE", severity=Severity.HIGH, confidence=Confidence.HIGH,
        affected_asset="example.com:443", description="candidate", remediation="Patch after validation",
        evidence_ids=[ev1.id, ev2.id], tags=["external", "cve", "needs-validation", "applicability-supported"],
        cve_ids=["CVE-2099-0001"],
    )
    out = FindingIntelligenceService().enrich([finding], [ev1, ev2])[0]
    assert out.validation_status == "applicability-supported-not-exploit-validated"
    assert out.evidence_quality == "corroborated"
    assert "exploit" not in out.validation_status.replace("not-exploit-validated", "")


def test_related_findings_are_correlated_by_same_asset_only():
    e = Evidence(engine="ShadowHTTP", category="http", summary="response", raw={})
    f1 = Finding(title="A", severity=Severity.LOW, confidence=Confidence.CONFIRMED, affected_asset="https://example.com", description="a", remediation="a", evidence_ids=[e.id])
    f2 = Finding(title="B", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, affected_asset="https://example.com", description="b", remediation="b", evidence_ids=[e.id])
    f3 = Finding(title="C", severity=Severity.LOW, confidence=Confidence.CONFIRMED, affected_asset="https://other.example.com", description="c", remediation="c", evidence_ids=[e.id])
    out = FindingIntelligenceService().enrich([f1, f2, f3], [e])
    assert out[1].id in out[0].related_finding_ids
    assert out[2].id not in out[0].related_finding_ids
    assert "related-observations" in out[0].tags
