from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.internal.segmentation import InternalSegmentationService
from shadowstrike.models.domain import Asset, AssessmentRequest, AssessmentResult, Evidence, ScopePolicy
from shadowstrike.storage.repository import AssessmentRepository


def _segmentation_assets():
    user = Asset(
        kind="network-device", value="10.50.10.20", source="ShadowLAN",
        attributes={"hostname": "user-20", "device_type": "workstation", "network_zone": "Users", "vlan_id": 10},
    )
    server = Asset(
        kind="network-device", value="10.50.20.10", source="ShadowLAN",
        attributes={
            "hostname": "filesrv", "device_type": "server", "network_zone": "Servers", "vlan_id": 20,
            "metadata": {"topology_links": [{"target": "10.50.10.20", "relation": "routed-neighbor", "evidence": "sensor", "confidence": "observed"}]},
        },
    )
    service = Asset(
        kind="network-service", value="10.50.20.10:445", source="ShadowLAN",
        attributes={
            "host": "10.50.20.10", "port": 445, "service_name": "smb", "network_zone": "Servers",
            "reachable_from_zones": ["Users"], "allowed_source_zones": ["Admin"],
            "service_state": "confirmed",
        },
    )
    ev = Evidence(asset_id=service.id, engine="Sensor", category="reachability", summary="Users zone can reach SMB on filesrv")
    return [user, server, service], [ev]


def test_segmentation_summary_maps_zones_and_cross_zone_paths():
    assets, evidence = _segmentation_assets()
    data = InternalSegmentationService.summarize(assets, evidence)
    assert data["zone_count"] == 2
    assert len(data["cross_zone_exposure_paths"]) == 1
    assert data["cross_zone_exposure_paths"][0]["source_zone"] == "Users"
    assert data["explicit_policy_violations"][0]["policy_violation"] is True


def test_segmentation_finding_requires_explicit_policy_basis():
    assets, evidence = _segmentation_assets()
    derived, findings = InternalSegmentationService.derive(assets, evidence)
    assert any(e.category == "internal-segmentation-summary" for e in derived)
    finding = next(f for f in findings if "segmentation policy" in f.title)
    assert finding.validation_status == "observed-policy-violation"
    assert evidence[0].id in finding.evidence_ids
    assert finding.attack_path[0] == "Users"


def test_cross_zone_visibility_without_policy_marker_is_inventory_only():
    assets, evidence = _segmentation_assets()
    service = next(a for a in assets if a.kind == "network-service")
    service.attributes.pop("allowed_source_zones")
    service.attributes["segmentation_violation"] = False
    _, findings = InternalSegmentationService.derive(assets, evidence)
    assert findings == []


def test_internal_trust_api(tmp_path, monkeypatch):
    repo = AssessmentRepository(tmp_path / "trust-api.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    request = AssessmentRequest(
        name="internal", targets=["10.50.10.20"], profile="internal", mode="internal",
        authorization_reference="LAB-TRUST",
        scope=ScopePolicy(allowed_cidrs=["10.50.0.0/16"]),
    )
    result = AssessmentResult(name="internal", profile="internal", status="completed")
    result.assets, result.evidence = _segmentation_assets()
    repo.save(request, result)
    response = TestClient(app).get(f"/assessments/{result.id}/internal-trust")
    assert response.status_code == 200
    assert response.json()["zone_count"] == 2


def test_orchestrator_routes_shadowtrust_after_identity():
    names = [e.name for e in app_module.orchestrator.internal_engines]
    assert names[-3:-1] == ["ShadowIdentity", "ShadowTrust"]
    assert names[-1] == "ShadowPath"


def test_unconfirmed_cross_zone_port_keeps_protocol_as_candidate():
    assets, evidence = _segmentation_assets()
    service = next(a for a in assets if a.kind == "network-service")
    service.attributes.update({
        "service_name": "unknown",
        "service_candidate": "smb",
        "service_state": "unconfirmed",
        "identity_basis": "conventional-port-candidate",
    })
    data = InternalSegmentationService.summarize(assets, evidence)
    path = data["cross_zone_exposure_paths"][0]
    assert path["service"] == "unknown"
    assert path["service_candidate"] == "SMB"
    assert path["service_state"] == "unconfirmed"
    assert data["trust_services_by_zone"].get("Servers") is None
    assert data["candidate_trust_services_by_zone"]["Servers"][0]["protocol_candidate"] == "SMB"
