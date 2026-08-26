from __future__ import annotations

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.models.domain import ScopePolicy
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine


def context(**kwargs):
    return EngineContext(scope=ScopeGuard(ScopePolicy(allowed_cidrs=["10.0.0.0/24"], **kwargs)), limiter=RateLimiter(100), timeout=0.2, user_agent="test")


def test_nmap_xml_normalizer_preserves_service_identity_without_creating_findings():
    xml = '''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="server.lab"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.24.0" conf="10"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service></port></ports></host></nmaprun>'''
    assets, evidence = SpecialistToolBridgeEngine._parse_nmap_xml(xml)
    service = next(a for a in assets if a.kind == "network-service")
    assert service.attributes["product"] == "nginx"
    assert service.attributes["version"] == "1.24.0"
    assert service.attributes["cpe"] == ["cpe:/a:nginx:nginx:1.24.0"]
    assert any(e.category == "specialist-service-observation" for e in evidence)


def test_specialist_tools_are_opt_in():
    ctx = context()
    assert ctx.scope.policy.allow_specialist_tools is False
    assert ctx.scope.policy.specialist_tools == []
