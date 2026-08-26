from __future__ import annotations

import struct
from unittest.mock import AsyncMock, patch

import pytest

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.udp import UdpProtocolDiscoveryEngine
from shadowstrike.models.domain import Asset, ScopePolicy


def context(**kwargs):
    policy = ScopePolicy(allowed_cidrs=["10.10.10.0/24"], **kwargs)
    return EngineContext(scope=ScopeGuard(policy), limiter=RateLimiter(100), timeout=0.2, user_agent="test", assets=[Asset(kind="network-device", value="10.10.10.5", source="test", attributes={"host": "10.10.10.5"})])


@pytest.mark.asyncio
async def test_udp_engine_reports_only_positive_protocol_responses():
    engine = UdpProtocolDiscoveryEngine()

    async def fake_dns(host, timeout):
        return {"service": "dns", "port": 53, "answers": 1}

    with patch.object(engine, "_probe_dns", side_effect=fake_dns), \
         patch.object(engine, "_probe_ntp", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_nbns", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_ssdp", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_mdns", new=AsyncMock(return_value=None)):
        output = await engine.run([], context())
    assert len(output.assets) == 1
    assert output.assets[0].value == "10.10.10.5:53/udp"
    assert output.assets[0].attributes["state"] == "positive-response"
    assert any(e.category == "udp-discovery-summary" and e.raw["silent_udp_ports_are_not_reported_open"] for e in output.evidence)


@pytest.mark.asyncio
async def test_udp_engine_can_be_disabled_by_scope():
    output = await UdpProtocolDiscoveryEngine().run([], context(allow_udp_discovery=False))
    assert output.assets == []
    assert output.evidence[0].category == "udp-discovery-skipped"

@pytest.mark.asyncio
async def test_udp_engine_promotes_in_scope_passive_arp_neighbors():
    engine = UdpProtocolDiscoveryEngine()
    with patch("shadowstrike.engines.udp.ShadowLAN.arp_neighbors", return_value={"10.10.10.8": "aa:bb:cc:dd:ee:ff", "192.168.1.9": "11:22:33:44:55:66"}), \
         patch.object(engine, "_probe_dns", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_ntp", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_nbns", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_ssdp", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_probe_mdns", new=AsyncMock(return_value=None)), \
         patch.object(engine, "_passive_dhcp_observations", return_value=[]):
        output = await engine.run([], context())
    neighbors = [a for a in output.assets if a.kind == "arp-neighbor"]
    assert [a.value for a in neighbors] == ["10.10.10.8"]
    assert neighbors[0].attributes["mac"] == "aa:bb:cc:dd:ee:ff"


def test_ssdp_parser_extracts_device_metadata():
    data = (b"HTTP/1.1 200 OK\r\nSERVER: Linux/6 UPnP/1.1 Camera/2.0\r\n"
            b"LOCATION: http://10.10.10.9/device.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:test::upnp:rootdevice\r\n\r\n")
    parsed = UdpProtocolDiscoveryEngine._parse_ssdp_response(data)
    assert parsed["service"] == "ssdp/upnp"
    assert "Camera" in parsed["server"]
    assert parsed["location"].startswith("http://10.10.10.9")


def test_mdns_parser_extracts_service_hints():
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    parsed = UdpProtocolDiscoveryEngine._parse_mdns_response(header + b"_http._tcp.local\x00")
    assert parsed["service"] == "mdns/dns-sd"
    assert any("_http._tcp.local" in item for item in parsed["service_hints"])
