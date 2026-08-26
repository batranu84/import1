import pytest

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.cve import CveIntelligenceEngine, parse_product_version
from shadowstrike.engines.network import InternalNetworkEngine
from shadowstrike.engines.tls import _candidate_endpoints
from shadowstrike.models.domain import Asset, Evidence, ScopePolicy
from shadowstrike.network.device import ShadowDevice
from shadowstrike.network.lan import DetectedNetwork, ShadowLAN
from shadowstrike.services.deep_discovery import DeepDiscoveryEngine


def _context(policy: ScopePolicy, *, profile: str = "full", assets=None, evidence=None):
    return EngineContext(
        scope=ScopeGuard(policy), limiter=RateLimiter(10000), timeout=0.01,
        user_agent="tests", profile=profile, assets=assets or [], evidence=evidence or [], findings=[]
    )


def test_bare_domain_is_tls_candidate_and_service_value_fallback():
    assets = [Asset(kind="network-service", value="example.com:443", source="ShadowScan", attributes={"port": 443, "service_hint": "https"})]
    candidates = _candidate_endpoints(["example.com"], assets)
    assert ("example.com", 443, "example.com:443") in candidates


def test_tcp_service_version_patterns_are_broader():
    assert parse_product_version("Server: Microsoft-IIS/10.0") == ("Microsoft IIS", "10.0")
    assert parse_product_version("Docker 27.1.2") == ("Docker", "27.1.2")


def test_os_hint_uses_direct_service_banner():
    device = ShadowDevice(
        ip="10.0.0.10", open_ports=[22],
        services=[{"port": 22, "service_state": "confirmed", "application_evidence": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}],
    ).normalize()
    assert device.os_hint == "Linux"


@pytest.mark.asyncio
async def test_internal_networks_visible_even_without_active_cidr_authorization(monkeypatch):
    monkeypatch.setattr(ShadowLAN, "detected_networks", classmethod(lambda cls: [DetectedNetwork("192.168.50.0/24", interface="en0", directly_connected=True)]))
    out = await InternalNetworkEngine().run([], _context(ScopePolicy()))
    assert any(a.kind == "internal-network" and a.value == "192.168.50.0/24" for a in out.assets)
    assert any(e.category == "discovery-coverage-gap" for e in out.evidence)


@pytest.mark.asyncio
async def test_deep_discovery_promotes_certificate_and_reports_gaps():
    cert_ev = Evidence(engine="ShadowTLS", category="tls-certificate", summary="cert", raw={
        "sha256": "abc123", "san_dns_names": ["example.com", "www.example.com"]
    })
    ctx = _context(ScopePolicy(allowed_domains=["example.com", "www.example.com"]), evidence=[cert_ev])
    out = await DeepDiscoveryEngine().run([], ctx)
    assert any(a.kind == "tls-certificate" for a in out.assets)
    assert any(a.kind == "hostname" and a.value == "www.example.com" for a in out.assets)
    summary = next(e for e in out.evidence if e.category == "deep-discovery-summary")
    assert "coverage_gaps" in summary.raw


def test_cve_fingerprints_use_application_evidence():
    asset = Asset(kind="network-service", value="10.0.0.10:22", source="ShadowLAN", attributes={
        "application_evidence": "SSH-2.0-OpenSSH_9.6p1 Ubuntu"
    })
    ctx = _context(ScopePolicy(allowed_cidrs=["10.0.0.0/24"]), assets=[asset])
    fps = CveIntelligenceEngine()._fingerprints(ctx)
    assert fps and fps[0].product == "OpenSSH" and fps[0].version == "9.6p1"
