from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.internal.posture import InternalPostureEngine, InternalPostureService
from shadowstrike.models.domain import Asset, AssessmentRequest, AssessmentResult, Evidence, ScopePolicy
from shadowstrike.services.orchestrator import AssessmentOrchestrator
from shadowstrike.storage.repository import AssessmentRepository


def _sample_assets():
    device = Asset(
        kind="network-device", value="10.20.0.10", source="ShadowLAN",
        attributes={
            "cidr": "10.20.0.0/24", "hostname": "edge-switch", "vendor": "Cisco",
            "device_type": "switch", "identity_confidence": "confirmed",
            "observation_state": "confirmed", "is_gateway": False,
            "snmp": {"sys_descr": "Cisco Catalyst"},
        },
    )
    telnet = Asset(
        kind="network-service", value="10.20.0.10:23", source="ShadowLAN",
        attributes={
            "ip": "10.20.0.10", "port": 23,
            "service_candidate": "telnet", "service_name": "telnet",
            "service_state": "confirmed", "identity_basis": "telnet-iac-negotiation",
        },
    )
    camera = Asset(
        kind="CCTV", value="10.20.0.50", source="physical_pipeline",
        attributes={"category": "CCTV", "confidence": "High"},
    )
    evidence = Evidence(
        asset_id=telnet.id, engine="ShadowLAN", category="tcp-service",
        summary="Telnet protocol confirmed on TCP/23",
        raw={"port": 23, "service_candidate": "telnet", "service_name": "telnet", "service_state": "confirmed", "identity_basis": "telnet-iac-negotiation"},
    )
    return [device, telnet, camera], [evidence]


def test_internal_posture_inventory_is_evidence_first():
    assets, evidence = _sample_assets()
    data = InternalPostureService.summarize(assets, evidence)
    assert data["device_count"] == 1
    assert data["service_count"] == 1
    assert data["by_type"]["switch"] == 1
    assert data["confirmed_infrastructure"][0]["ip"] == "10.20.0.10"
    assert data["physical_assets"]["by_category"]["CCTV"] == 1
    assert data["clear_text_services"][0]["protocol"] == "Telnet"


def test_internal_posture_promotes_only_observed_cleartext_service():
    assets, evidence = _sample_assets()
    derived, findings = InternalPostureService.derive(assets, evidence)
    assert any(e.category == "internal-posture-summary" for e in derived)
    assert len(findings) == 1
    finding = findings[0]
    assert "Telnet" in finding.title
    assert finding.validation_status == "observed-service"
    assert evidence[0].id in finding.evidence_ids
    assert finding.retest_status == "not-retested"



def test_unconfirmed_telnet_port_is_candidate_only():
    assets, evidence = _sample_assets()
    service = next(a for a in assets if a.kind == "network-service")
    service.attributes.update({
        "service_name": "unknown",
        "service_state": "unconfirmed",
        "identity_basis": "conventional-port-candidate",
    })
    data = InternalPostureService.summarize(assets, evidence)
    assert data["clear_text_services"] == []
    assert data["candidate_clear_text_services"][0]["port"] == 23
    _, findings = InternalPostureService.derive(assets, evidence)
    assert not any("Telnet" in f.title for f in findings)

def test_candidate_device_identity_is_not_promoted_to_infrastructure():
    candidate = Asset(
        kind="network-device", value="10.20.0.60", source="ShadowLAN",
        attributes={
            "device_type": "host", "candidate_types": ["printer"],
            "identity_confidence": "observed", "observation_state": "observed",
            "cidr": "10.20.0.0/24",
        },
    )
    data = InternalPostureService.summarize([candidate], [])
    assert data["confirmed_infrastructure"] == []
    assert data["unknown_identity_devices"] == ["10.20.0.60"]


def test_internal_orchestrator_includes_passive_posture_stage(tmp_path):
    orchestrator = AssessmentOrchestrator(AssessmentRepository(tmp_path / "internal.db"))
    request = AssessmentRequest(
        name="internal", targets=["10.20.0.1"], profile="internal", mode="internal",
        authorization_reference="LAB-INTERNAL",
        scope=ScopePolicy(allowed_cidrs=["10.20.0.0/24"]),
    )
    names = [engine.name for engine in orchestrator._engines_for(request)]
    assert InternalPostureEngine.name in names
    assert names[-1] == "ShadowPath"
    assert "ShadowLAN" in names


def test_internal_posture_api(tmp_path, monkeypatch):
    repo = AssessmentRepository(tmp_path / "api.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    request = AssessmentRequest(
        name="internal", targets=["10.20.0.1"], profile="internal", mode="internal",
        authorization_reference="LAB-INTERNAL",
        scope=ScopePolicy(allowed_cidrs=["10.20.0.0/24"]),
    )
    result = AssessmentResult(name="internal", profile="internal", status="completed")
    result.assets, result.evidence = _sample_assets()
    repo.save(request, result)
    response = TestClient(app).get(f"/assessments/{result.id}/internal-posture")
    assert response.status_code == 200
    assert response.json()["device_count"] == 1
    assert response.json()["management_surface"]["Telnet"][0]["port"] == 23


def test_internal_posture_is_rendered_in_technical_report():
    from shadowstrike.reporting.html import HtmlReport
    result = AssessmentResult(name="internal-report", profile="internal", status="completed")
    result.assets, result.evidence = _sample_assets()
    html = HtmlReport().render(result)
    assert "Internal posture" in html
    assert "clear_text_services" in html
    assert "confirmed_infrastructure" in html
