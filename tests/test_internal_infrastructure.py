from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.internal.infrastructure import InternalInfrastructureService
from shadowstrike.models.domain import Asset, AssessmentRequest, AssessmentResult, Evidence, ScopePolicy
from shadowstrike.network.device import ShadowDevice
from shadowstrike.network.snmp import ShadowSNMP
from shadowstrike.storage.repository import AssessmentRepository


def _infra_assets():
    switch = Asset(
        kind="network-device", value="10.30.0.2", source="ShadowLAN",
        attributes={
            "hostname": "core-sw", "device_type": "switch", "identity_confidence": "confirmed",
            "observation_state": "confirmed", "gateway": "10.30.0.1", "candidate_types": [],
            "snmp": {
                "sys_descr": "Cisco Catalyst",
                "interfaces": [
                    {"index": 1, "name": "Gi1/0/1", "alias": "uplink", "admin_status": 1, "oper_status": 1},
                    {"index": 2, "name": "Gi1/0/2", "alias": "camera", "admin_status": 1, "oper_status": 1},
                ],
            },
            "metadata": {"topology_links": [{"target": "10.30.0.50", "relation": "lldp-neighbor", "evidence": "LLDP", "confidence": "confirmed"}]},
        },
    )
    docker = Asset(
        kind="network-service", value="10.30.0.20:2375", source="ShadowLAN",
        attributes={"host": "10.30.0.20", "port": 2375, "service_name": "docker", "service_state": "unconfirmed"},
    )
    camera = Asset(
        kind="CCTV", value="10.30.0.50", source="physical_pipeline",
        attributes={"classification": "IP Camera", "vendor": "Axis", "confidence": "High"},
    )
    ev = Evidence(asset_id=docker.id, engine="ShadowLAN", category="port", summary="TCP/2375 confirmed open")
    return [switch, docker, camera], [ev]


def test_infrastructure_summary_correlates_interfaces_topology_and_cctv():
    assets, evidence = _infra_assets()
    data = InternalInfrastructureService.summarize(assets, evidence)
    assert data["confirmed_network_infrastructure"][0]["role"] == "switch"
    assert data["snmp_device_count"] == 1
    assert data["interface_count"] == 2
    assert any(edge["relation"] == "lldp-neighbor" for edge in data["topology"]["edges"])
    assert data["cctv_nvr_inventory"][0]["vendor"] == "Axis"
    assert "container-host" in data["candidate_platforms"]["10.30.0.20"]


def test_docker_2375_finding_is_transport_only_claim():
    assets, evidence = _infra_assets()
    docker = next(a for a in assets if a.kind == "network-service")
    docker.attributes.update({
        "service_name": "docker-http",
        "service_state": "confirmed",
        "identity_basis": "docker-ping-response",
    })
    derived, findings = InternalInfrastructureService.derive(assets, evidence)
    assert any(e.category == "internal-infrastructure-summary" for e in derived)
    finding = next(f for f in findings if "Docker" in f.title)
    assert finding.validation_status == "observed-service"
    assert "does not establish" in finding.description
    assert evidence[0].id in finding.evidence_ids



def test_docker_2375_port_candidate_does_not_create_docker_finding():
    assets, evidence = _infra_assets()
    data = InternalInfrastructureService.summarize(assets, evidence)
    assert data["management_surfaces"].get("10.30.0.20") is None
    assert "container-host" in data["candidate_platforms"]["10.30.0.20"]
    _, findings = InternalInfrastructureService.derive(assets, evidence)
    assert not any("Docker" in f.title for f in findings)

def test_direct_device_metadata_confirms_new_platform_roles():
    nvr = ShadowDevice(ip="10.0.0.5", snmp={"sys_descr": "Hikvision Network Video Recorder NVR"}).normalize()
    container = ShadowDevice(ip="10.0.0.6", snmp={"sys_descr": "Linux Docker Engine appliance"}).normalize()
    hypervisor = ShadowDevice(ip="10.0.0.7", snmp={"sys_descr": "VMware ESXi 8.0"}).normalize()
    assert nvr.device_type == "nvr" and nvr.identity_confidence == "confirmed"
    assert container.device_type == "container-host" and container.identity_confidence == "confirmed"
    assert hypervisor.device_type == "virtualization-host" and hypervisor.identity_confidence == "confirmed"


def test_snmp_inventory_joins_if_mib_columns(monkeypatch):
    snmp = ShadowSNMP(host="10.0.0.2", community="public")
    values = {
        "1.3.6.1.2.1.1.1.0": "Cisco IOS XE Software",
    }
    monkeypatch.setattr(snmp, "get", lambda oid: values.get(oid))
    walks = {
        "1.3.6.1.2.1.2.2.1.2": [("1.3.6.1.2.1.2.2.1.2.1", "GigabitEthernet1")],
        "1.3.6.1.2.1.2.2.1.3": [("1.3.6.1.2.1.2.2.1.3.1", 6)],
        "1.3.6.1.2.1.2.2.1.5": [("1.3.6.1.2.1.2.2.1.5.1", 1000000000)],
        "1.3.6.1.2.1.2.2.1.7": [("1.3.6.1.2.1.2.2.1.7.1", 1)],
        "1.3.6.1.2.1.2.2.1.8": [("1.3.6.1.2.1.2.2.1.8.1", 1)],
        "1.3.6.1.2.1.31.1.1.1.1": [("1.3.6.1.2.1.31.1.1.1.1.1", "Gi1")],
        "1.3.6.1.2.1.31.1.1.1.18": [("1.3.6.1.2.1.31.1.1.1.18.1", "uplink")],
        "1.3.6.1.2.1.31.1.1.1.15": [("1.3.6.1.2.1.31.1.1.1.15.1", 1000)],
    }
    monkeypatch.setattr(snmp, "walk", lambda oid, max_rows=512: walks.get(oid, []))
    data = snmp.inventory()
    iface = data["interfaces"][0]
    assert iface["name"] == "Gi1"
    assert iface["alias"] == "uplink"
    assert iface["oper_status"] == 1
    assert iface["high_speed_mbps"] == 1000


def test_internal_infrastructure_api(tmp_path, monkeypatch):
    repo = AssessmentRepository(tmp_path / "infra-api.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    request = AssessmentRequest(
        name="internal", targets=["10.30.0.1"], profile="internal", mode="internal",
        authorization_reference="LAB-INTERNAL",
        scope=ScopePolicy(allowed_cidrs=["10.30.0.0/24"]),
    )
    result = AssessmentResult(name="internal", profile="internal", status="completed")
    result.assets, result.evidence = _infra_assets()
    repo.save(request, result)
    response = TestClient(app).get(f"/assessments/{result.id}/internal-infrastructure")
    assert response.status_code == 200
    assert response.json()["interface_count"] == 2
