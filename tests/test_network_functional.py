import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.engines.contacts import ContactDiscoveryEngine, _classify_role
from shadowstrike.models.domain import AssessmentRequest, AssessmentResult, ScopePolicy
from shadowstrike.network.agent import SensorRegistry, ShadowAgent
from shadowstrike.network.device import ShadowDevice, classify_device
from shadowstrike.network.lan import ShadowLAN
from shadowstrike.network.service import NetworkDiscoveryService
from shadowstrike.network.topology import ShadowTopology
from shadowstrike.storage.repository import AssessmentRepository


def test_device_classification_switch_from_snmp() -> None:
    device = ShadowDevice(
        ip="10.0.0.2",
        open_ports=[22, 80, 443],
        snmp={"sys_descr": "Cisco Catalyst 9300 Switch IOS XE"},
    ).normalize()
    assert classify_device(device) == "switch"
    assert device.os_hint == "Cisco network OS"


def test_device_classification_printer_is_candidate_without_direct_identity_evidence() -> None:
    device = ShadowDevice(ip="10.0.0.50", open_ports=[80, 9100]).normalize()
    assert device.device_type == "host"
    assert "printer" in device.candidate_types
    assert device.identity_confidence == "observed"


def test_topology_gateway_links_devices() -> None:
    devices = [
        ShadowDevice(ip="10.0.0.1", is_gateway=True).normalize(),
        ShadowDevice(ip="10.0.0.2", open_ports=[443]).normalize(),
    ]
    topology = ShadowTopology.from_devices(devices, "10.0.0.1").export()
    assert {n["id"] for n in topology["nodes"]} == {"10.0.0.1", "10.0.0.2"}
    assert {e["target"] for e in topology["edges"]} == {"10.0.0.2"}


def test_cidr_scope_rejects_unapproved_network() -> None:
    request = AssessmentRequest(
        name="lan",
        targets=["10.0.0.1"],
        authorization_reference="LAB",
        scope=ScopePolicy(allowed_cidrs=["10.0.0.0/24"]),
    )
    assert str(NetworkDiscoveryService.require_cidr(request, "10.0.0.0/25")) == "10.0.0.0/25"
    with pytest.raises(ValueError):
        NetworkDiscoveryService.require_cidr(request, "10.0.1.0/24")


@pytest.mark.asyncio
async def test_lan_discovery_uses_tcp_and_neighbor_evidence(monkeypatch) -> None:
    lan = ShadowLAN("10.0.0.0/30")
    monkeypatch.setattr(ShadowLAN, "default_gateway", staticmethod(lambda: "10.0.0.1"))
    neighbor_calls = {"count": 0}

    def neighbors():
        neighbor_calls["count"] += 1
        return {"10.0.0.1": "00:11:22:33:44:55", "10.0.0.2": "00:24:e8:00:00:01"}

    monkeypatch.setattr(ShadowLAN, "arp_neighbors", staticmethod(neighbors))

    async def fake_probe(ip, ports, timeout, semaphore):
        if ip == "10.0.0.2":
            return [80, 443], {80: 1.1, 443: 1.3}
        return [], {}

    monkeypatch.setattr(ShadowLAN, "_probe", staticmethod(fake_probe))
    monkeypatch.setattr("socket.gethostbyaddr", lambda ip: (f"host-{ip}", [], [ip]))
    devices = await lan.discover(ports=[80, 443])
    assert [d.ip for d in devices] == ["10.0.0.1", "10.0.0.2"]
    assert devices[0].is_gateway is True
    assert devices[1].open_ports == [80, 443]
    assert devices[1].vendor == "Dell"


def test_sensor_registry_token_auth(tmp_path: Path) -> None:
    registry = SensorRegistry(tmp_path / "sensors.json")
    record, token = registry.create("hq", "assessment-1")
    raw = registry.get(record["agent_id"])
    assert raw is not None
    assert ShadowAgent.verify_token(token, raw["token_hash"])
    assert not ShadowAgent.verify_token("wrong", raw["token_hash"])


def test_contact_expansion_defaults_and_roles() -> None:
    engine = ContactDiscoveryEngine()
    assert engine.max_pages_per_target >= 500
    assert engine.max_contacts_per_target >= 5000
    assert _classify_role("security@example.com") == "security"
    assert _classify_role("jane.doe@example.com") == "personal/public"


def test_dashboard_contains_network_pages() -> None:
    page = TestClient(app).get("/")
    assert page.status_code == 200
    for label in ("Internal Devices", "Internal Topology", "Remote Sensors", "Network Risk"):
        assert label in page.text
    assert "Discover devices + ports" in page.text
    assert "Approve detected CIDR" in page.text


def test_network_summary_api_and_sensor_ingest(tmp_path: Path, monkeypatch) -> None:
    repo = AssessmentRepository(tmp_path / "network.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    registry = SensorRegistry(tmp_path / "sensors.json")
    monkeypatch.setattr(app_module, "sensor_registry", registry)
    request = AssessmentRequest(
        name="remote-network",
        targets=["10.10.10.1"],
        profile="internal",
        authorization_reference="LAB-NET",
        scope=ScopePolicy(allowed_cidrs=["10.10.10.0/24"]),
    )
    result = AssessmentResult(name=request.name, profile=request.profile, status="completed")
    repo.save(request, result)
    client = TestClient(app)
    created = client.post(f"/assessments/{result.id}/sensors/register", json={"site": "branch"})
    assert created.status_code == 200
    sensor = created.json()
    payload = {
        "assessment_id": str(result.id),
        "cidr": "10.10.10.0/24",
        "gateway": "10.10.10.1",
        "devices": [
            {
                "ip": "10.10.10.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "edge-router",
                "device_type": "gateway/router",
                "open_ports": [22, 443],
                "is_gateway": True,
                "snmp": {"sys_descr": "Cisco IOS XE", "vendor": "Cisco"},
                "firmware": "IOS XE 17.x",
            },
            {
                "ip": "10.10.10.20",
                "hostname": "office-printer",
                "open_ports": [80, 9100],
            },
        ],
    }
    ingest = client.post(
        f"/sensors/{sensor['agent_id']}/ingest",
        headers={"X-ShadowStrike-Sensor-Token": sensor["token"]},
        json=payload,
    )
    assert ingest.status_code == 200
    summary = client.get(f"/assessments/{result.id}/network")
    assert summary.status_code == 200
    data = summary.json()
    assert data["device_count"] == 2
    assert data["service_count"] == 0
    assert data["transport_endpoint_count"] == 4
    printer = next(d for d in data["devices"] if d["ip"] == "10.10.10.20")
    assert printer["device_type"] == "host"
    assert "printer" in printer["candidate_types"]
    assert data["topology"]["edges"]


def test_snmp_response_parser_and_switch_fingerprint() -> None:
    from shadowstrike.network.snmp import _integer, _oid, _parse_get_response, _tlv, ShadowSNMP

    oid = "1.3.6.1.2.1.1.1.0"
    value = b"Cisco Catalyst 9300 Switch IOS XE Version 17.9"
    varbind = _tlv(0x30, _oid(oid) + _tlv(0x04, value))
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xA2, _integer(1) + _integer(0) + _integer(0) + varbinds)
    packet = _tlv(0x30, _integer(1) + _tlv(0x04, b"public") + pdu)
    parsed = _parse_get_response(packet)
    assert parsed == (oid, value.decode())
    vendor, model, firmware = ShadowSNMP._fingerprint(value.decode())
    assert vendor == "Cisco"
    assert "Catalyst" in model
    assert firmware and "Version" in firmware


def test_network_report_contains_internal_inventory() -> None:
    from shadowstrike.models.domain import Asset
    from shadowstrike.reporting.html import HtmlReport

    result = AssessmentResult(name="report", profile="internal", status="completed")
    result.assets.append(
        Asset(
            kind="network-device",
            value="10.0.0.2",
            source="ShadowLAN",
            attributes={"hostname": "switch-1", "device_type": "switch", "vendor": "Cisco", "open_ports": [22, 443], "firmware": "IOS XE"},
        )
    )
    html = HtmlReport().render(result)
    assert "Internal network inventory" in html
    assert "switch-1" in html
    assert "IOS XE" in html


@pytest.mark.asyncio
async def test_snmp_only_device_is_added_to_network_snapshot(monkeypatch) -> None:
    request = AssessmentRequest(
        name="snmp",
        targets=["10.0.0.1"],
        profile="internal",
        authorization_reference="LAB-SNMP",
        scope=ScopePolicy(allowed_cidrs=["10.0.0.0/30"]),
    )
    result = AssessmentResult(name="snmp", profile="internal", status="completed")

    async def fake_discover(self, **kwargs):
        self.gateway = "10.0.0.1"
        return [ShadowDevice(ip="10.0.0.1", is_gateway=True, open_ports=[443]).normalize()]

    monkeypatch.setattr(ShadowLAN, "discover", fake_discover)

    def fake_get(self, oid):
        return "Cisco Catalyst 1000 Switch IOS" if self.host == "10.0.0.2" else None

    def fake_inventory(self):
        if self.host == "10.0.0.2":
            return {
                "sys_descr": "Cisco Catalyst 1000 Switch IOS",
                "sys_name": "access-switch",
                "vendor": "Cisco",
                "firmware": "IOS 15.x",
                "interfaces": [],
            }
        return {"vendor": None, "model": None, "firmware": None, "interfaces": []}

    monkeypatch.setattr("shadowstrike.network.service.ShadowSNMP.get", fake_get)
    monkeypatch.setattr("shadowstrike.network.service.ShadowSNMP.inventory", fake_inventory)
    data = await NetworkDiscoveryService().scan(request, result, "10.0.0.0/30", snmp_community="lab-read")
    assert data["device_count"] == 2
    switch = next(d for d in data["devices"] if d["ip"] == "10.0.0.2")
    assert switch["device_type"] == "switch"
    assert switch["vendor"] == "Cisco"
