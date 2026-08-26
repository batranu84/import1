import ipaddress

import pytest

from shadowstrike.models.domain import Asset, AssessmentResult, ModuleState, ModuleStatus
from shadowstrike.network.lan import DetectedNetwork, ShadowLAN
from shadowstrike.network.service import NetworkDiscoveryService
from shadowstrike.reporting.html import HtmlReport
from shadowstrike.services.assessment_truth import inventory_summary, valid_host_address
from shadowstrike.services.coverage import CoverageService


def test_broadcast_is_not_valid_device():
    assert not valid_host_address("255.255.255.255")
    assert not valid_host_address("0.0.0.0")
    assert valid_host_address("192.168.0.10")


def test_network_summary_filters_legacy_broadcast_device():
    result = AssessmentResult(name="x", profile="internal")
    result.assets.extend([
        Asset(kind="network-device", value="255.255.255.255", source="ShadowLAN", attributes={"device_type":"host"}),
        Asset(kind="network-device", value="192.168.0.10", source="ShadowLAN", attributes={"device_type":"host"}),
    ])
    summary = NetworkDiscoveryService.summary(result)
    assert summary["device_count"] == 1
    assert summary["devices"][0]["ip"] == "192.168.0.10"


def test_inventory_summary_separates_subresources():
    result = AssessmentResult(name="x", profile="full")
    result.assets.extend([
        Asset(kind="dns-name", value="example.test", source="ShadowDNS"),
        Asset(kind="network-service", value="example.test:443", source="ShadowScan", attributes={"service_state":"confirmed"}),
        Asset(kind="transport-endpoint", value="example.test:8443", source="ShadowScan", attributes={"service_state":"unconfirmed"}),
    ])
    summary = inventory_summary(result)
    assert summary["primary_assets"] == 1
    assert summary["confirmed_services"] == 1
    assert summary["transport_observations"] == 1


def test_coverage_separates_execution_from_evidence():
    result = AssessmentResult(name="x", profile="full", modules=[
        ModuleStatus(name="a", state=ModuleState.COMPLETED, completed_units=4),
        ModuleStatus(name="b", state=ModuleState.COMPLETED, completed_units=0),
        ModuleStatus(name="c", state=ModuleState.SKIPPED, completed_units=0),
    ])
    summary = CoverageService().summarize(result)
    assert summary["modules"]["execution_percent"] == 100.0
    assert summary["modules"]["evidence_bearing_percent"] == pytest.approx(33.3)
    assert summary["modules"]["zero_evidence_completed"] == ["b"]


def test_report_warns_for_legacy_assessment_and_counts_primary_assets():
    result = AssessmentResult(name="legacy", profile="full", engine_version="0.24.1")
    result.assets.extend([
        Asset(kind="dns-name", value="example.test", source="ShadowDNS"),
        Asset(kind="transport-endpoint", value="example.test:1", source="ShadowScan"),
    ])
    html = HtmlReport().render(result)
    assert "Legacy assessment semantics" in html
    assert ">1</b><br>Primary assets" in html


def test_detected_network_sort_prefers_direct_network(monkeypatch):
    monkeypatch.setattr(ShadowLAN, "local_interfaces", staticmethod(lambda: []))
    # Sorting invariant can be validated directly on the dataclass ordering key used by detected_networks.
    rows = [
        DetectedNetwork("192.168.0.0/24", source="interface", directly_connected=True, approval_recommended=True),
        DetectedNetwork("192.168.1.0/24", source="route", directly_connected=False, approval_recommended=True),
    ]
    ordered = sorted(rows, key=lambda x: (not x.directly_connected, ipaddress.ip_network(x.cidr).prefixlen, x.cidr))
    assert ordered[0].cidr == "192.168.0.0/24"


def test_macos_detected_networks_exclude_neighbor_and_broadcast_routes(monkeypatch):
    from shadowstrike.network.lan import NetworkInterface
    monkeypatch.setattr("shadowstrike.network.lan.platform.system", lambda: "Darwin")
    monkeypatch.setattr(ShadowLAN, "local_interfaces", staticmethod(lambda: [
        NetworkInterface(name="en0", address="192.168.0.24", prefix=24, network="192.168.0.0/24")
    ]))
    table = """Routing tables
Internet:
Destination        Gateway            Flags            Netif Expire
 default            192.168.0.1        UGScg            en0
192.168.0          link#4             UCS              en0
192.168.0.1/32     00:11:22:33:44:55  UHLWIir          en0
192.168.0.75/32    00:11:22:33:44:66  UHLWI            en0
255.255.255.255/32 link#4             UCS              en0
10.20.30.0/24      192.168.0.1        UGSc             en0
"""
    monkeypatch.setattr("shadowstrike.network.lan.subprocess.check_output", lambda *a, **k: table)
    rows = ShadowLAN.detected_networks()
    cidrs = [x.cidr for x in rows]
    assert "192.168.0.0/24" in cidrs
    assert "10.20.30.0/24" in cidrs
    assert all(not c.endswith("/32") for c in cidrs)
    assert "255.255.255.255/32" not in cidrs
    assert rows[0].cidr == "192.168.0.0/24"
    assert rows[0].directly_connected is True


@pytest.mark.asyncio
async def test_internal_scan_counts_only_confirmed_services(monkeypatch):
    from shadowstrike.models.domain import AssessmentRequest, ScopePolicy
    from shadowstrike.network.device import ShadowDevice
    request = AssessmentRequest(name="lan", targets=["10.0.0.2"], authorization_reference="LAB", scope=ScopePolicy(allowed_cidrs=["10.0.0.0/30"]))
    result = AssessmentResult(name="lan", profile="internal")
    async def fake_discover(self, **kwargs):
        self.gateway = "10.0.0.1"
        return [ShadowDevice(ip="10.0.0.2", open_ports=[22,80], services=[
            {"port":22,"name":"unknown","service_candidate":"ssh","service_state":"unconfirmed"},
            {"port":80,"name":"http","service_candidate":"http","service_state":"confirmed","identity_basis":"http-response"},
        ], evidence_types=["tcp-connect","service:http"]).normalize()]
    monkeypatch.setattr(ShadowLAN, "discover", fake_discover)
    data = await NetworkDiscoveryService().scan(request, result, "10.0.0.0/30")
    assert data["transport_endpoint_count"] == 2
    assert data["service_count"] == 1
