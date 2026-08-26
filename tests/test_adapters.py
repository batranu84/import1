from shadowstrike.adapters import AdapterRegistry, AdapterResult, SecurityToolAdapter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.models.domain import Asset, ScopePolicy


class FixtureAdapter(SecurityToolAdapter):
    name = "fixture"

    async def collect(self, targets, scope):
        return AdapterResult()


def test_registry_and_scope_filter():
    registry = AdapterRegistry()
    registry.register(FixtureAdapter())
    assert registry.names() == ["fixture"]
    scope = ScopeGuard(ScopePolicy(allowed_domains=["example.test"]))
    result = AdapterResult(assets=[
        Asset(kind="host", value="api.example.test", source="fixture"),
        Asset(kind="host", value="outside.test", source="fixture"),
    ])
    filtered = SecurityToolAdapter.filter_scoped(result, scope)
    assert [a.value for a in filtered.assets] == ["api.example.test"]
