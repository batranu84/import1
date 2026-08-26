from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.models.domain import AssessmentRequest, AssessmentResult, ScopePolicy
from shadowstrike.network.agent import SensorRegistry
from shadowstrike.network.device import ShadowDevice
from shadowstrike.network.lan import DetectedNetwork, NetworkInterface, ShadowLAN
from shadowstrike.network.topology import ShadowTopology
from shadowstrike.storage.repository import AssessmentRepository


def test_scope_normalizes_full_url_to_hostname() -> None:
    scope = ScopePolicy(allowed_domains=["https://www.example.com/path?q=1", "*.api.example.com"])
    assert scope.allowed_domains == ["www.example.com", "*.api.example.com"]


def test_sensor_registry_persists_detected_networks(tmp_path: Path) -> None:
    registry = SensorRegistry(tmp_path / "sensors.json")
    record, _token = registry.create("hq", "assessment-1")
    updated = registry.heartbeat(
        record["agent_id"],
        capabilities={"route_inventory": True},
        detected_networks=[{"cidr": "10.20.30.0/24", "interface": "en0"}],
        health={"interfaces": 1},
    )
    assert updated is not None
    assert updated["detected_networks"][0]["cidr"] == "10.20.30.0/24"
    assert updated["health"]["interfaces"] == 1


def test_sensor_detected_network_requires_operator_approval(tmp_path: Path, monkeypatch) -> None:
    repo = AssessmentRepository(tmp_path / "approval.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    registry = SensorRegistry(tmp_path / "sensors.json")
    monkeypatch.setattr(app_module, "sensor_registry", registry)

    request = AssessmentRequest(
        name="approval",
        targets=["example.test"],
        profile="full",
        authorization_reference="AUTH-1",
        scope=ScopePolicy(allowed_domains=["example.test"]),
    )
    result = AssessmentResult(name=request.name, profile=request.profile, status="completed")
    repo.save(request, result)
    client = TestClient(app)

    created = client.post(f"/assessments/{result.id}/sensors/register", json={"site": "hq"}).json()
    heartbeat = client.post(
        f"/sensors/{created['agent_id']}/heartbeat",
        headers={"X-ShadowStrike-Sensor-Token": created["token"]},
        json={
            "status": "online",
            "capabilities": {"automatic_network_detection": True},
            "detected_networks": [{"cidr": "10.20.30.0/24", "interface": "eth0", "directly_connected": True}],
            "health": {"interfaces": 1},
        },
    )
    assert heartbeat.status_code == 200

    before = client.get(
        f"/sensors/{created['agent_id']}/assignment",
        headers={"X-ShadowStrike-Sensor-Token": created["token"]},
    ).json()
    assert before["allowed_cidrs"] == []

    approved = client.post(
        f"/assessments/{result.id}/sensors/{created['agent_id']}/approve-network",
        json={"cidr": "10.20.30.0/24"},
    )
    assert approved.status_code == 200
    assert approved.json()["cidr"] == "10.20.30.0/24"

    after = client.get(
        f"/sensors/{created['agent_id']}/assignment",
        headers={"X-ShadowStrike-Sensor-Token": created["token"]},
    ).json()
    assert after["allowed_cidrs"] == ["10.20.30.0/24"]


def test_topology_edges_are_labeled_as_observed_not_physical_guess() -> None:
    devices = [
        ShadowDevice(ip="10.0.0.1", is_gateway=True, evidence_types=["default-gateway"]).normalize(),
        ShadowDevice(ip="10.0.0.2", open_ports=[443], evidence_types=["tcp-connect"]).normalize(),
    ]
    topology = ShadowTopology.from_devices(devices, "10.0.0.1").export()
    edge = topology["edges"][0]
    assert edge["relation"] == "same-routed-lan"
    assert edge["confidence"] == "observed"
    assert "route" in edge["evidence"]


@pytest.mark.asyncio
async def test_automatic_full_port_profile_runs_only_after_positive_host_observation(monkeypatch) -> None:
    lan = ShadowLAN("10.0.0.0/30")
    monkeypatch.setattr(ShadowLAN, "default_gateway", staticmethod(lambda: None))
    monkeypatch.setattr(ShadowLAN, "arp_neighbors", staticmethod(lambda: {}))

    async def fake_probe(ip, ports, timeout, semaphore):
        # Only .2 is positively observed during the liveness pass.
        return ([80], {80: 1.0}) if ip == "10.0.0.2" else ([], {})

    async def fake_ping(ip, timeout, semaphore):
        return False

    calls: list[tuple[str, int, int]] = []

    async def fake_chunked(cls, ip, ports, timeout, semaphore, chunk_size=512):
        values = list(ports)
        calls.append((ip, values[0], values[-1]))
        return [80, 65000], {80: 1.0, 65000: 1.2}

    monkeypatch.setattr(ShadowLAN, "_probe", staticmethod(fake_probe))
    monkeypatch.setattr(ShadowLAN, "_ping", staticmethod(fake_ping))
    monkeypatch.setattr(ShadowLAN, "_probe_chunked", classmethod(fake_chunked))

    devices = await lan.discover(ports=None, port_profile="full", verify_services=False)
    assert [d.ip for d in devices] == ["10.0.0.2"]
    assert devices[0].open_ports == [80, 65000]
    # Legacy "full" now maps to adaptive deep discovery so every live endpoint is not
    # subjected to a 65k sweep. Exhaustive remains an explicit profile.
    assert len(calls) == 1 and calls[0][0] == "10.0.0.2"
    assert calls[0][2] < 65535
    assert devices[0].metadata["effective_port_profile"] == "adaptive"


def test_snmp_switch_identity_is_confirmed() -> None:
    device = ShadowDevice(
        ip="10.0.0.10",
        snmp={"sys_descr": "Cisco Catalyst 9300 Switch IOS XE"},
        evidence_types=["snmp-response"],
    ).normalize()
    assert device.device_type == "switch"
    assert device.identity_confidence == "confirmed"
    assert device.observation_state == "confirmed"

@pytest.mark.asyncio
async def test_exhaustive_profile_retains_1_to_65535_explicit_scan(monkeypatch) -> None:
    lan = ShadowLAN("10.0.0.0/30")
    monkeypatch.setattr(ShadowLAN, "default_gateway", staticmethod(lambda: None))
    monkeypatch.setattr(ShadowLAN, "arp_neighbors", staticmethod(lambda: {}))

    async def fake_probe(ip, ports, timeout, semaphore):
        return ([80], {80: 1.0}) if ip == "10.0.0.2" else ([], {})

    async def fake_ping(ip, timeout, semaphore):
        return False

    calls = []

    async def fake_chunked(cls, ip, ports, timeout, semaphore, chunk_size=512):
        values = list(ports)
        calls.append((values[0], values[-1], len(values)))
        return [80], {80: 1.0}

    monkeypatch.setattr(ShadowLAN, "_probe", staticmethod(fake_probe))
    monkeypatch.setattr(ShadowLAN, "_ping", staticmethod(fake_ping))
    monkeypatch.setattr(ShadowLAN, "_probe_chunked", classmethod(fake_chunked))

    devices = await lan.discover(ports=None, port_profile="exhaustive", verify_services=False)
    assert calls == [(1, 65535, 65535)]
    assert devices[0].metadata["effective_port_profile"] == "exhaustive"
