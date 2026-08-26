from __future__ import annotations

import pytest

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.tcp import TcpDiscoveryEngine, _acceptance_profile, _banner_service
from shadowstrike.external.posture import ExternalPostureEngine
from shadowstrike.external.validation import ExternalValidationEngine
from shadowstrike.models.domain import Asset, Evidence, ScopePolicy
from shadowstrike.network.device import ShadowDevice
from shadowstrike.services.findings import FindingsEngine
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine


def _context(assets, evidence):
    policy = ScopePolicy(allowed_domains=["example.com"], allowed_cidrs=["203.0.113.0/24"])
    return EngineContext(
        scope=ScopeGuard(policy),
        limiter=RateLimiter(100),
        timeout=1.0,
        user_agent="test",
        assets=assets,
        evidence=evidence,
    )


def _candidate_endpoint(host: str, port: int, candidate: str, latency: float):
    asset = Asset(
        kind="transport-endpoint",
        value=f"{host}:{port}/tcp",
        source="ShadowScan",
        attributes={
            "host": host,
            "port": port,
            "transport": "tcp",
            "port_state": "confirmed-open",
            "service_candidate": candidate,
            "service_hint": candidate,
            "service_name": "unknown",
            "service_state": "candidate",
            "identity_basis": "conventional-port-candidate",
            "connect_latency_ms": latency,
            "banner": None,
        },
    )
    evidence = Evidence(
        asset_id=asset.id,
        engine="ShadowScan",
        category="port",
        summary=f"TCP/{port} accepted a connection on {host}",
        raw={
            "host": host,
            "resolved_ip": "203.0.113.10",
            "port": port,
            "state": "open",
            "port_state": "confirmed-open",
            "service_candidate": candidate,
            "service_name": "unknown",
            "service_state": "candidate",
            "identity_basis": "conventional-port-candidate",
            "connect_latency_ms": latency,
            "banner": None,
        },
    )
    return asset, evidence


def test_conventional_port_does_not_become_banner_identity() -> None:
    assert _banner_service(1433, "") == "unknown"
    assert _banner_service(3306, "") == "unknown"
    assert _banner_service(22, "SSH-2.0-OpenSSH_9.8") == "ssh"


@pytest.mark.asyncio
async def test_database_port_candidates_do_not_create_database_finding() -> None:
    ports = [(1433, "mssql"), (1521, "oracle"), (3306, "mysql"), (5432, "postgresql"), (6379, "redis"), (9200, "elasticsearch"), (11211, "memcached"), (27017, "mongodb")]
    pairs = [_candidate_endpoint("example.com", p, name, 28.0 + i * 0.5) for i, (p, name) in enumerate(ports)]
    assets = [a for a, _ in pairs]
    evidence = [e for _, e in pairs]
    output = await ExternalPostureEngine().run([], _context(assets, evidence))

    assert not any("database or data service confirmed" in finding.title.lower() for finding in output.findings)
    candidates = [e for e in output.evidence if e.category == "service-candidate-surface" and e.raw.get("group") == "database/data services"]
    assert len(candidates) == 1
    assert candidates[0].raw["service_identity"] == "unverified"
    assert candidates[0].raw["promotion_to_finding"] is False


@pytest.mark.asyncio
async def test_similar_open_port_pattern_is_flagged_for_validation_not_promoted() -> None:
    ports = [(1433, "mssql", 29), (1521, "oracle", 28), (3306, "mysql", 26), (5432, "postgresql", 29), (6379, "redis", 26), (9200, "elasticsearch", 30), (11211, "memcached", 26), (27017, "mongodb", 33)]
    pairs = [_candidate_endpoint("example.com", p, name, latency) for p, name, latency in ports]
    assets = [a for a, _ in pairs]
    evidence = [e for _, e in pairs]
    output = await ExternalValidationEngine().run([], _context(assets, evidence))

    assert not [e for e in output.evidence if e.category == "service-identity-correlation"]
    anomalies = [e for e in output.evidence if e.category == "tcp-reachability-pattern-anomaly"]
    assert len(anomalies) == 1
    assert anomalies[0].raw["finding_created"] is False
    assert "protocol validation required" in anomalies[0].raw["interpretation"]



def test_broad_acceptance_profile_marks_intermediary_pattern() -> None:
    observations = [
        {
            "host": "example.com",
            "port": port,
            "connect_latency_ms": 28.0 + (port % 3) * 0.2,
            "banner": None,
            "service_candidate": {1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgresql", 6379: "redis", 9200: "elasticsearch"}.get(port, "unknown"),
        }
        for port in range(1, 1025)
    ]
    profile = _acceptance_profile(observations, attempted_ports=1024)
    assert profile["accepted_ports"] == 1024
    assert profile["acceptance_ratio"] == 1.0
    assert profile["suspected_intermediary_or_tarpit"] is True
    assert "high-port-acceptance-ratio" in profile["signals"]


def test_anomalous_transport_finding_does_not_dump_all_ports() -> None:
    anomaly = Evidence(
        engine="ShadowScan",
        category="tcp-acceptance-anomaly",
        summary="broad accept",
        raw={"host": "example.com", "attempted_ports": 1056, "accepted_ports": 1056},
    )
    port_evidence = [
        Evidence(engine="ShadowScan", category="port", summary="accepted", raw={"host": "example.com", "port": p, "state": "open", "service_state": "candidate"})
        for p in range(1, 80)
    ]
    findings = FindingsEngine().analyze([anomaly, *port_evidence])
    finding = next(f for f in findings if f.title == "Anomalous broad TCP acceptance pattern")
    assert finding.severity.value == "info"
    assert "1, 2, 3" not in finding.description
    assert finding.evidence_ids == [anomaly.id]


@pytest.mark.asyncio
async def test_tcp_engine_collapses_mass_acceptance_instead_of_creating_services(monkeypatch) -> None:
    import socket

    class DummyReader:
        async def read(self, _size: int) -> bytes:
            return b""

    class DummySocket:
        family = socket.AF_INET

    class DummyWriter:
        def __init__(self, host: str, port: int) -> None:
            self.host = host
            self.port = port

        def get_extra_info(self, name: str):
            if name == "peername":
                return ("203.0.113.10", self.port)
            if name == "socket":
                return DummySocket()
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def fake_open_connection(host: str, port: int, **_kwargs):
        return DummyReader(), DummyWriter(host, port)

    monkeypatch.setattr("shadowstrike.engines.tcp.asyncio.open_connection", fake_open_connection)
    policy = ScopePolicy(allowed_domains=["example.com"], max_concurrency=64, max_requests_per_second=10000)
    context = EngineContext(scope=ScopeGuard(policy), limiter=RateLimiter(10000), timeout=0.1, user_agent="test", profile="full")
    output = await TcpDiscoveryEngine(ports=list(range(1, 65)), batch_size=64).run(["example.com"], context)

    assert not [a for a in output.assets if a.kind == "network-service"]
    assert not [a for a in output.assets if a.kind == "transport-endpoint"]
    surfaces = [a for a in output.assets if a.kind == "transport-surface"]
    assert len(surfaces) == 1
    assert surfaces[0].attributes["accepted_ports"] == 64
    assert surfaces[0].attributes["service_promotion_suppressed"] is True
    assert len([e for e in output.evidence if e.category == "port"]) == 64
    assert len([e for e in output.evidence if e.category == "tcp-acceptance-anomaly"]) == 1


@pytest.mark.asyncio
async def test_external_posture_suppresses_candidate_groups_for_mass_acceptance() -> None:
    ports = [(1433, "mssql"), (1521, "oracle"), (3306, "mysql"), (5432, "postgresql"), (6379, "redis"), (9200, "elasticsearch"), (11211, "memcached"), (27017, "mongodb")]
    pairs = [_candidate_endpoint("example.com", port, candidate, 28.0) for port, candidate in ports]
    anomaly = Evidence(engine="ShadowScan", category="tcp-acceptance-anomaly", summary="mass accept", raw={"host": "example.com", "accepted_ports": 1056, "attempted_ports": 1056})
    output = await ExternalPostureEngine().run([], _context([a for a, _ in pairs], [e for _, e in pairs] + [anomaly]))
    assert not [e for e in output.evidence if e.category == "service-candidate-surface"]
    assert not [f for f in output.findings if "database" in f.title.lower()]

def test_confirmed_state_with_mismatched_identity_cannot_fire_port_rule() -> None:
    evidence = Evidence(
        engine="ShadowScan",
        category="port",
        summary="TCP/1433 open",
        raw={
            "host": "example.com",
            "port": 1433,
            "state": "open",
            "service_state": "confirmed",
            "service_name": "ssh",
        },
    )
    findings = FindingsEngine().analyze([evidence])
    assert not any("SQL Server" in finding.title for finding in findings)


def test_nmap_identity_requires_high_tool_confidence() -> None:
    low = '''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="203.0.113.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="1433"><state state="open"/><service name="ms-sql-s" product="Microsoft SQL Server" version="15.0" conf="3"/></port></ports></host></nmaprun>'''
    assets, _evidence = SpecialistToolBridgeEngine._parse_nmap_xml(low)
    service = next(a for a in assets if a.kind == "transport-endpoint")
    assert service.attributes["service_state"] == "candidate"
    assert service.attributes["service_name"] == "unknown"
    assert service.attributes["product"] is None
    assert service.attributes["version"] is None

    high = low.replace('conf="3"', 'conf="10"')
    assets, _evidence = SpecialistToolBridgeEngine._parse_nmap_xml(high)
    service = next(a for a in assets if a.kind == "network-service")
    assert service.attributes["service_state"] == "confirmed"
    assert service.attributes["service_name"] == "ms-sql-s"
    assert service.attributes["product"] == "Microsoft SQL Server"
    assert service.attributes["version"] == "15.0"


def test_internal_device_port_mapping_remains_candidate_only() -> None:
    device = ShadowDevice(ip="10.0.0.20", open_ports=[2375, 445]).normalize()
    by_port = {int(row["port"]): row for row in device.services}
    assert by_port[2375]["service_candidate"] == "docker"
    assert by_port[2375]["name"] == "unknown"
    assert by_port[2375]["service_state"] == "unconfirmed"
    assert by_port[445]["service_candidate"] == "smb"
    assert by_port[445]["name"] == "unknown"
