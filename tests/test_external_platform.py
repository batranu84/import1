from pathlib import Path

import pytest

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.external.inventory import build_external_inventory
from shadowstrike.external.posture import ExternalPostureEngine
from shadowstrike.models.domain import (
    AssessmentMode,
    AssessmentRequest,
    Asset,
    Evidence,
    ScopePolicy,
)
from shadowstrike.services.orchestrator import AssessmentOrchestrator
from shadowstrike.storage.repository import AssessmentRepository


def _context(assets, evidence):
    policy = ScopePolicy(allowed_domains=["example.com"], allowed_cidrs=["203.0.113.0/24"])
    return EngineContext(
        scope=ScopeGuard(policy),
        limiter=RateLimiter(100),
        timeout=1.0,
        user_agent="ShadowStrike-Test",
        assets=assets,
        evidence=evidence,
    )


def test_external_inventory_deduplicates_assets_and_services():
    assets = [
        Asset(kind="network-service", value="203.0.113.10:443", source="a", attributes={"host": "203.0.113.10", "port": 443}),
        Asset(kind="network-service", value="203.0.113.10:443", source="b", attributes={"host": "203.0.113.10", "port": 443}),
        Asset(kind="web-application", value="https://Example.com/", source="http"),
        Asset(kind="network-device", value="10.0.0.5", source="lan"),
    ]
    inventory = build_external_inventory(assets, [])
    assert inventory.asset_count == 2
    assert inventory.service_ports == {"203.0.113.10": [443]}
    assert inventory.web_origins == ["https://example.com"]


@pytest.mark.asyncio
async def test_external_posture_synthesizes_exposure_without_probing():
    service = Asset(kind="network-service", value="203.0.113.10:3389", source="ShadowScan", attributes={"host": "203.0.113.10", "port": 3389, "service_name": "rdp", "service_state": "confirmed"})
    web = Asset(kind="web-application", value="http://example.com", source="ShadowHTTP")
    port_ev = Evidence(
        asset_id=service.id,
        engine="ShadowScan",
        category="port",
        summary="203.0.113.10:3389 open",
        raw={"host": "203.0.113.10", "port": 3389, "state": "open", "service_name": "rdp", "service_state": "confirmed"},
    )
    http_ev = Evidence(
        asset_id=web.id,
        engine="ShadowHTTP",
        category="http",
        summary="HTTP 200 from http://example.com",
        raw={"status_code": 200},
    )
    output = await ExternalPostureEngine().run([], _context([service, web], [port_ev, http_ev]))
    titles = {finding.title for finding in output.findings}
    assert "Internet-reachable administrative service confirmed" in titles
    assert "Externally reachable web application observed over HTTP" in titles
    assert len(output.evidence) == 1
    assert output.evidence[0].category == "external-inventory-summary"


def test_orchestrator_routes_external_and_internal_modes(tmp_path: Path):
    repo = AssessmentRepository(tmp_path / "shadowstrike.db")
    orchestrator = AssessmentOrchestrator(repo)
    external = AssessmentRequest(
        name="ext",
        targets=["example.com"],
        mode=AssessmentMode.EXTERNAL,
        authorization_reference="AUTH-1",
        scope=ScopePolicy(allowed_domains=["example.com"]),
    )
    internal = AssessmentRequest(
        name="int",
        targets=["10.10.10.1"],
        mode=AssessmentMode.INTERNAL,
        authorization_reference="AUTH-2",
        scope=ScopePolicy(allowed_cidrs=["10.10.10.0/24"]),
    )
    ext_names = [engine.name for engine in orchestrator._engines_for(external)]
    int_names = [engine.name for engine in orchestrator._engines_for(internal)]
    assert "ShadowExternal" in ext_names
    assert "ShadowNetwork" not in ext_names
    assert int_names == ["ShadowLAN", "ShadowUDP", "ShadowTLS", "ShadowCerts", "ShadowDeepDiscovery", "ShadowAdaptive", "ShadowToolBridge", "ShadowGraphIntel", "ShadowCVE", "ShadowInternal", "ShadowInfrastructure", "ShadowIdentity", "ShadowTrust", "ShadowPath"]
    hybrid = AssessmentRequest(name="hyb", targets=["example.com"], mode=AssessmentMode.HYBRID, authorization_reference="AUTH-3", scope=ScopePolicy(allowed_domains=["example.com"], allowed_cidrs=["10.10.10.0/24"]))
    hyb_names = [engine.name for engine in orchestrator._engines_for(hybrid)]
    assert len(hyb_names) == len(set(hyb_names))
    assert hyb_names.count("ShadowToolBridge") == 1
    assert hyb_names.count("ShadowTLS") == 1
