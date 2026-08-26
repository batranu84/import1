from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.internal.exposure import InternalExposureService
from shadowstrike.models.domain import Asset, AssessmentRequest, AssessmentResult, Confidence, Evidence, Finding, ScopePolicy, Severity
from shadowstrike.storage.repository import AssessmentRepository


def _exposure_fixture():
    user = Asset(kind="network-device", value="10.70.10.20", source="ShadowLAN", attributes={"device_type": "workstation", "network_zone": "Users"})
    dc = Asset(kind="network-device", value="10.70.20.10", source="ShadowLAN", attributes={"device_type": "domain-controller", "network_zone": "Servers", "is_domain_controller": True})
    smb = Asset(kind="network-service", value="10.70.20.10:445", source="ShadowLAN", attributes={
        "host": "10.70.20.10", "port": 445, "service_name": "smb", "network_zone": "Servers",
        "reachable_from_zones": ["Users"], "allowed_source_zones": ["Admin"], "service_state": "confirmed",
    })
    ev = Evidence(asset_id=smb.id, engine="Sensor", category="reachability", summary="Users can reach DC SMB")
    finding = Finding(
        title="Observed cross-zone access conflicts with segmentation policy",
        severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, affected_asset="10.70.20.10:445",
        description="Observed policy violation", remediation="Restrict the path", evidence_ids=[ev.id],
        validation_status="observed-policy-violation", evidence_quality="corroborated",
    )
    return [user, dc, smb], [ev], [finding]


def test_exposure_paths_correlate_reachability_and_existing_finding():
    assets, evidence, findings = _exposure_fixture()
    data = InternalExposureService.summarize(assets, evidence, findings)
    correlated = next(p for p in data["paths"] if p.get("finding_id"))
    assert correlated["source_zone"] == "Users"
    assert correlated["target_role"] == "domain-controller"
    assert correlated["policy_violation"] is True
    assert correlated["path"][-1] == findings[0].title
    assert data["finding_correlated_path_count"] >= 1


def test_exposure_paths_do_not_claim_compromise():
    assets, evidence, findings = _exposure_fixture()
    data = InternalExposureService.summarize(assets, evidence, findings)
    assert "no exploitation" in next(p for p in data["paths"] if p.get("finding_id"))["basis"]
    assert "do not demonstrate lateral movement" in data["limitations"]


def test_internal_exposure_api(tmp_path, monkeypatch):
    repo = AssessmentRepository(tmp_path / "exposure-api.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    request = AssessmentRequest(
        name="internal", targets=["10.70.20.10"], profile="internal", mode="internal",
        authorization_reference="LAB-PATH", scope=ScopePolicy(allowed_cidrs=["10.70.0.0/16"]),
    )
    result = AssessmentResult(name="internal", profile="internal", status="completed")
    result.assets, result.evidence, result.findings = _exposure_fixture()
    repo.save(request, result)
    response = TestClient(app).get(f"/assessments/{result.id}/internal-exposure-paths")
    assert response.status_code == 200
    assert response.json()["path_count"] >= 1


def test_orchestrator_routes_shadowpath_after_shadowtrust():
    names = [e.name for e in app_module.orchestrator.internal_engines]
    assert names[-2:] == ["ShadowTrust", "ShadowPath"]


def test_report_contains_internal_exposure_intelligence():
    from shadowstrike.reporting.html import HtmlReport
    assets, evidence, findings = _exposure_fixture()
    result = AssessmentResult(name="internal", profile="internal", status="completed", assets=assets, evidence=evidence, findings=findings)
    rendered = HtmlReport().render(result)
    assert "Internal exposure &amp; attack-path intelligence" in rendered
    assert "finding_correlated_path_count" in rendered
