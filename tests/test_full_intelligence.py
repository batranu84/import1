import asyncio
from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.certificates import CertificateIntelligenceEngine
from shadowstrike.models.domain import Asset, Evidence, ScopePolicy
from shadowstrike.services.intelligence_graph import IntelligenceGraphEngine


def ctx(assets=None,evidence=None):
    return EngineContext(scope=ScopeGuard(ScopePolicy(allowed_domains=['example.com','*.example.com'])), limiter=RateLimiter(1000), timeout=1, user_agent='test', profile='full', assessment_id='x', assets=assets or [], evidence=evidence or [], findings=[])


def test_intelligence_graph_builds_typed_relationships():
    assets=[Asset(kind='web-endpoint',value='https://example.com/login',source='t'), Asset(kind='email-address',value='admin@example.com',source='t')]
    out=asyncio.run(IntelligenceGraphEngine().run(['example.com'],ctx(assets=assets)))
    assert any(e.category=='intelligence-relationship' for e in out.evidence)
    assert any(a.kind=='intel-host' and a.value=='example.com' for a in out.assets)


def test_certificate_engine_reuses_tls_evidence_without_network_probe():
    ev=Evidence(engine='ShadowTLS',category='tls-certificate',summary='x',raw={'host':'example.com','port':443,'sha256':'a'*64,'san_dns_names':['example.com','www.example.com'],'issuer':'CN=CA','subject':'CN=example.com','days_remaining':90,'public_key':{'type':'RSA','bits':2048}})
    out=asyncio.run(CertificateIntelligenceEngine().run(['example.com'],ctx(evidence=[ev])))
    assert any(a.kind=='certificate' for a in out.assets)
    assert any(e.category=='certificate-posture' for e in out.evidence)
    assert not out.findings
