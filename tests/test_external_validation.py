from pathlib import Path

import pytest

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.external.validation import ExternalValidationEngine
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, ScopePolicy, Severity


def _context(assets, evidence, findings=None):
    policy = ScopePolicy(allowed_domains=["example.com"], allowed_cidrs=["203.0.113.0/24"])
    ctx = EngineContext(scope=ScopeGuard(policy), limiter=RateLimiter(100), timeout=1.0, user_agent="test", assets=assets, evidence=evidence)
    ctx.findings = findings or []
    return ctx


@pytest.mark.asyncio
async def test_service_identity_correlation_requires_multiple_signals():
    asset = Asset(kind="network-service", value="203.0.113.10:22", source="ShadowScan", attributes={"host":"203.0.113.10", "port":22, "service_hint":"ssh", "banner":"SSH-2.0-OpenSSH_9.6"})
    port = Evidence(asset_id=asset.id, engine="ShadowScan", category="port", summary="open", raw={"host":"203.0.113.10", "port":22, "state":"open", "service_hint":"ssh"})
    output = await ExternalValidationEngine().run([], _context([asset], [port]))
    records = [e for e in output.evidence if e.category == "service-identity-correlation"]
    assert len(records) == 1
    assert set(records[0].raw["signals"]) >= {"tcp-connect", "protocol/product-confirmation"}
    assert "service-hint" not in records[0].raw["signals"]


@pytest.mark.asyncio
async def test_https_hsts_posture_is_evidence_backed():
    asset = Asset(kind="web-application", value="https://example.com", source="ShadowHTTP")
    http = Evidence(asset_id=asset.id, engine="ShadowHTTP", category="http", summary="HTTP 200 from https://example.com", raw={"url":"https://example.com", "status_code":200, "headers":{"content-security-policy":"default-src 'self'", "x-content-type-options":"nosniff", "referrer-policy":"strict-origin"}})
    output = await ExternalValidationEngine().run([], _context([asset], [http]))
    assert any(e.category == "http-security-posture" for e in output.evidence)
    finding = next(f for f in output.findings if f.title == "HSTS not observed on HTTPS application")
    assert finding.confidence == Confidence.CONFIRMED
    assert http.id in finding.evidence_ids


@pytest.mark.asyncio
async def test_api_schema_exposure_is_inventory_not_vulnerability_claim():
    schema = Asset(kind="api-schema", value="https://example.com/openapi.json", source="ShadowAPI", attributes={"format":"openapi"})
    op = Asset(kind="api-operation", value="GET /users", source="ShadowAPI", attributes={"schema_url":"https://example.com/openapi.json"})
    ev = Evidence(asset_id=schema.id, engine="ShadowAPI", category="api-schema", summary="schema", raw={"url":"https://example.com/openapi.json", "operation_count":1})
    output = await ExternalValidationEngine().run([], _context([schema, op], [ev]))
    finding = next(f for f in output.findings if f.title == "Externally reachable API schema documentation")
    assert finding.severity == Severity.INFO
    assert "attack-surface" in finding.tags


@pytest.mark.asyncio
async def test_cve_candidate_confidence_increases_only_with_identity_corroboration():
    asset = Asset(kind="network-service", value="203.0.113.10:22", source="ShadowScan", attributes={"host":"203.0.113.10", "port":22, "service_hint":"ssh", "banner":"SSH-2.0-OpenSSH_9.6"})
    port = Evidence(asset_id=asset.id, engine="ShadowScan", category="port", summary="open", raw={"host":"203.0.113.10", "port":22, "state":"open"})
    candidate = Finding(title="Candidate CVE-TEST", severity=Severity.HIGH, confidence=Confidence.PROBABLE, affected_asset="203.0.113.10:22", description="candidate", remediation="review", evidence_ids=[port.id], tags=["cve", "needs-validation"], cve_ids=["CVE-TEST"])
    output = await ExternalValidationEngine().run([], _context([asset], [port], [candidate]))
    assert candidate.confidence == Confidence.HIGH
    assert "applicability-supported" in candidate.tags
    applicability = [e for e in output.evidence if e.category == "vulnerability-applicability"]
    assert len(applicability) == 1
    assert applicability[0].raw["status"] == "applicability-supported-not-exploit-validated"
