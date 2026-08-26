import pytest
from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.models.domain import Asset, Evidence, ScopePolicy
from shadowstrike.services.adaptive_assessment import AdaptiveAssessmentEngine
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine


def context(assets=None, evidence=None):
    scope = ScopePolicy(allowed_domains=["example.com"], allowed_cidrs=["10.0.0.0/8"])
    return EngineContext(scope=ScopeGuard(scope), limiter=RateLimiter(1000), timeout=0.1, user_agent="test", assets=assets or [], evidence=evidence or [], findings=[])


@pytest.mark.asyncio
async def test_adaptive_planner_activates_ad_branch_without_probing():
    asset = Asset(kind="service", value="10.0.0.10:389", source="test", attributes={"service": "ldap"})
    output = await AdaptiveAssessmentEngine().run(["10.0.0.10"], context([asset]))
    branches = [e.raw for e in output.evidence if e.category == "adaptive-assessment-branch"]
    ad = next(x for x in branches if x["branch"] == "active-directory")
    assert ad["state"] == "activated"
    assert ad["additional_probe_performed"] is False


@pytest.mark.asyncio
async def test_candidate_is_scope_gated_not_contacted():
    ev = Evidence(engine="ShadowTLS", category="certificate", summary="cert", raw={"sans": ["api.example.com", "outside.invalid"]})
    output = await AdaptiveAssessmentEngine().run(["example.com"], context(evidence=[ev]))
    decisions = {e.raw["candidate"]: e.raw for e in output.evidence if e.category == "candidate-scope-decision"}
    assert decisions["api.example.com"]["authorized"] is True
    assert decisions["outside.invalid"]["authorized"] is False
    assert all(x["contacted"] is False for x in decisions.values())


@pytest.mark.asyncio
async def test_tool_bridge_only_inventories_capabilities():
    output = await SpecialistToolBridgeEngine().run(["example.com"], context())
    records = [e.raw for e in output.evidence if e.category == "specialist-tool-capability"]
    assert records
    assert all(r["execution"] == "not-invoked" for r in records)
