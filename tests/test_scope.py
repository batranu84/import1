import pytest

from shadowstrike.core.scope import ScopeGuard, ScopeViolation
from shadowstrike.models.domain import ScopePolicy


def test_domain_scope():
    guard = ScopeGuard(ScopePolicy(allowed_domains=["example.com"]))
    assert guard.allows("example.com")
    assert guard.allows("api.example.com")
    assert not guard.allows("example.net")


def test_exclusion_wins():
    guard = ScopeGuard(ScopePolicy(allowed_domains=["example.com"], excluded_domains=["admin.example.com"]))
    assert not guard.allows("admin.example.com")


def test_require_raises():
    guard = ScopeGuard(ScopePolicy(allowed_domains=["example.com"]))
    with pytest.raises(ScopeViolation):
        guard.require("openai.com")
