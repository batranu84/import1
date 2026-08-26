from shadowstrike.engines.cve import CveIntelligenceEngine, _exact_version_cpe, parse_product_version


def test_parse_observed_versions() -> None:
    assert parse_product_version("SSH-2.0-OpenSSH_9.6p1 Ubuntu") == ("OpenSSH", "9.6p1")
    assert parse_product_version("220 mx ESMTP Exim 4.99.5") == ("Exim", "4.99.5")
    assert parse_product_version("nginx/1.26.2") == ("nginx", "1.26.2")
    assert parse_product_version("generic smtp service") is None


def test_cve_requires_exact_version_cpe() -> None:
    wrapper = {
        "cve": {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{"criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"}]
                }]
            }]
        }
    }
    assert _exact_version_cpe(wrapper, "OpenSSH", "9.6p1") is True
    assert _exact_version_cpe(wrapper, "OpenSSH", "9.7") is False


def test_cve_fingerprint_accepts_normalized_product_and_version_fields():
    from shadowstrike.core.rate import RateLimiter
    from shadowstrike.core.scope import ScopeGuard
    from shadowstrike.engines.base import EngineContext
    from shadowstrike.models.domain import Asset, ScopePolicy
    asset = Asset(kind="network-service", value="10.0.0.5:443/tcp", source="test", attributes={"host":"10.0.0.5","product":"nginx","version":"1.24.0","service_state":"confirmed","service_name":"https"})
    ctx = EngineContext(scope=ScopeGuard(ScopePolicy(allowed_cidrs=["10.0.0.0/24"])), limiter=RateLimiter(100), timeout=0.2, user_agent="test", assets=[asset], evidence=[])
    fps = CveIntelligenceEngine()._fingerprints(ctx)
    assert [(fp.product, fp.version) for fp in fps] == [("nginx", "1.24.0")]


def test_cve_product_match_does_not_use_vendor_word_substring():
    tomcat = {
        "cve": {"configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:apache:tomcat:2.4.58:*:*:*:*:*:*:*"}
        ]}]}]}
    }
    httpd = {
        "cve": {"configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"}
        ]}]}]}
    }
    assert _exact_version_cpe(tomcat, "Apache HTTP Server", "2.4.58") is False
    assert _exact_version_cpe(httpd, "Apache HTTP Server", "2.4.58") is True


def test_unconfirmed_network_service_product_version_is_not_cve_fingerprint():
    from shadowstrike.core.rate import RateLimiter
    from shadowstrike.core.scope import ScopeGuard
    from shadowstrike.engines.base import EngineContext
    from shadowstrike.models.domain import Asset, ScopePolicy
    asset = Asset(
        kind="network-service", value="10.0.0.5:1433", source="test",
        attributes={"host":"10.0.0.5", "product":"Microsoft SQL Server", "version":"15.0", "service_state":"candidate"},
    )
    ctx = EngineContext(scope=ScopeGuard(ScopePolicy(allowed_cidrs=["10.0.0.0/24"])), limiter=RateLimiter(100), timeout=0.2, user_agent="test", assets=[asset], evidence=[])
    assert CveIntelligenceEngine()._fingerprints(ctx) == []
