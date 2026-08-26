import asyncio
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine
from shadowstrike.services.intelligence_graph import IntelligenceGraphEngine
from shadowstrike.engines.base import EngineContext
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.core.rate import RateLimiter
from shadowstrike.models.domain import Asset, Evidence, ScopePolicy


def ctx(assets=None,evidence=None):
    return EngineContext(scope=ScopeGuard(ScopePolicy(allowed_domains=['example.com','*.example.com'],allowed_cidrs=['203.0.113.0/24'])),limiter=RateLimiter(1000),timeout=1,user_agent='test',profile='full',assessment_id='x',assets=assets or [],evidence=evidence or [],findings=[])


def test_nmap_tcpwrapped_never_promoted_and_scripts_preserved():
    xml='''<nmaprun><host><status state="up"/><address addr="203.0.113.5" addrtype="ipv4"/><hostscript><script id="uptime" output="123"/></hostscript><ports><port protocol="tcp" portid="443"><state state="open"/><service name="tcpwrapped" conf="10"/><script id="ssl-cert" output="cert data"/></port></ports></host></nmaprun>'''
    assets,evidence=SpecialistToolBridgeEngine._parse_nmap_xml(xml)
    ep=[a for a in assets if a.value=='203.0.113.5:443/tcp'][0]
    assert ep.kind=='transport-endpoint'
    assert ep.attributes['service_state']=='candidate'
    assert ep.attributes['service_name']=='unknown'
    assert any(e.category=='nmap-port-script' and e.raw.get('id')=='ssl-cert' for e in evidence)
    assert any(e.category=='nmap-host-script' and e.raw.get('id')=='uptime' for e in evidence)


def test_graph_transforms_product_cpe_ct_and_parent_domain():
    assets=[Asset(kind='network-service',value='api.example.com:443/tcp',source='t',attributes={'host':'api.example.com','port':443,'transport':'tcp','service_name':'https','service_state':'confirmed','product':'nginx','version':'1.25','cpe':['cpe:/a:nginx:nginx:1.25']})]
    evidence=[Evidence(engine='ShadowCerts',category='certificate-transparency-summary',summary='ct',raw={'base_domain':'example.com','names':['api.example.com','www.example.com']})]
    out=asyncio.run(IntelligenceGraphEngine().run(['example.com'],ctx(assets,evidence)))
    rels=[e.raw for e in out.evidence if e.category=='intelligence-relationship']
    assert any(r.get('relationship')=='subdomain-of' for r in rels)
    assert any(r.get('relationship')=='identified-as' for r in rels)
    assert any(r.get('relationship')=='maps-to-cpe' for r in rels)
    assert any(r.get('transform')=='certificate-transparency' for r in rels)


def test_dashboard_exposes_deep_profile():
    from shadowstrike.web.dashboard import DASHBOARD_HTML
    assert 'value="deep"' in DASHBOARD_HTML
    assert 'Deep / exhaustive' in DASHBOARD_HTML
