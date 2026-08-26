from shadowstrike.core.scope import ScopeGuard
from shadowstrike.models.domain import ScopePolicy
from shadowstrike.services.template_normalizer import TemplateResultNormalizer


def test_template_normalizer_filters_scope():
    scope = ScopeGuard(ScopePolicy(allowed_domains=["example.test"]))
    evidence, findings = TemplateResultNormalizer().normalize([
        {"host": "https://api.example.test", "name": "fixture", "severity": "high"},
        {"host": "https://outside.test", "name": "outside", "severity": "critical"},
    ], scope)
    assert len(evidence) == 1
    assert len(findings) == 1
    assert findings[0].affected_asset == "https://api.example.test"
