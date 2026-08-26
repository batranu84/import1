from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.contacts import ContactDiscoveryEngine
from shadowstrike.models.domain import ScopePolicy


def _context() -> EngineContext:
    policy = ScopePolicy(allowed_domains=["example.co.uk", "*.example.co.uk"])
    return EngineContext(scope=ScopeGuard(policy), limiter=RateLimiter(10), timeout=1.0, user_agent="test")


def test_contact_domain_scope() -> None:
    context = _context()
    assert ContactDiscoveryEngine._allowed_email_domain("security@example.co.uk", context, "example.co.uk")
    assert ContactDiscoveryEngine._allowed_email_domain("ops@sub.example.co.uk", context, "example.co.uk")
    assert not ContactDiscoveryEngine._allowed_email_domain("person@gmail.com", context, "example.co.uk")
    assert not ContactDiscoveryEngine._allowed_email_domain("security@127.0.0.1", context, "127.0.0.1")


def test_cfemail_decoder() -> None:
    from shadowstrike.engines.contacts import _decode_cfemail

    email = "security@example.co.uk"
    key = 0x42
    encoded = bytes([key]) + bytes(ord(c) ^ key for c in email)
    assert _decode_cfemail(encoded.hex()) == email


def test_contact_seeds_reuse_crawler_assets() -> None:
    from shadowstrike.models.domain import Asset

    context = _context()
    context.assets = [
        Asset(kind="web-endpoint", value="https://example.co.uk/team", source="ShadowCrawler"),
        Asset(kind="web-endpoint", value="https://outside.invalid/contact", source="ShadowCrawler"),
    ]
    seeds = ContactDiscoveryEngine._seed_urls("example.co.uk", context)
    assert "https://example.co.uk/team" in seeds
    assert all("outside.invalid" not in item for item in seeds)
