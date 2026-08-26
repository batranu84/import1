from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from shadowstrike.core.scope import ScopeGuard
from shadowstrike.models.domain import Asset, Evidence, Finding


@dataclass
class AdapterResult:
    assets: list[Asset] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class SecurityToolAdapter(ABC):
    """Stable normalization boundary for optional third-party assessment tools.

    Adapters must scope-filter every returned asset before it enters ShadowStrike. The
    core intentionally does not shell out to arbitrary tools through this interface.
    """

    name: str
    version: str = "1"

    @abstractmethod
    async def collect(self, targets: list[str], scope: ScopeGuard) -> AdapterResult:
        raise NotImplementedError

    @staticmethod
    def filter_scoped(result: AdapterResult, scope: ScopeGuard) -> AdapterResult:
        assets = [a for a in result.assets if scope.allows(a.value)]
        allowed_ids = {a.id for a in assets}
        evidence = [e for e in result.evidence if e.asset_id is None or e.asset_id in allowed_ids]
        evidence_ids = {e.id for e in evidence}
        findings = [
            f for f in result.findings
            if scope.allows(f.affected_asset)
            and (not f.evidence_ids or any(eid in evidence_ids for eid in f.evidence_ids))
        ]
        return AdapterResult(assets=assets, evidence=evidence, findings=findings, metadata=result.metadata)


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, SecurityToolAdapter] = {}

    def register(self, adapter: SecurityToolAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"adapter already registered: {adapter.name}")
        self._adapters[adapter.name] = adapter

    def names(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, name: str) -> SecurityToolAdapter:
        return self._adapters[name]

class PassiveProviderAdapter(SecurityToolAdapter):
    """Marker base class for passive providers. Implementations must not actively probe targets."""
    passive_only: bool = True


class CachedAdapter:
    """Persistent TTL cache for structured passive adapter payloads."""

    def __init__(self, repository, ttl_seconds: int = 3600) -> None:
        self.repository = repository
        self.ttl_seconds = max(1, ttl_seconds)

    def get(self, key: str):
        import time
        return self.repository.cache_get(key, time.time())

    def put(self, key: str, payload: dict) -> None:
        import time
        self.repository.cache_put(key, payload, time.time() + self.ttl_seconds)
