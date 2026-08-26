from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Optional

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.models.domain import Asset, Evidence, Finding


@dataclass
class EngineContext:
    scope: ScopeGuard
    limiter: RateLimiter
    timeout: float
    user_agent: str
    profile: str = "full"
    assessment_id: Optional[str] = None
    engine_name: Optional[str] = None
    load_checkpoint: Optional[Callable[[str], Optional[dict[str, Any]]]] = None
    save_checkpoint: Optional[Callable[[str, dict[str, Any]], None]] = None
    clear_checkpoint: Optional[Callable[[str], None]] = None
    assets: Optional[list[Asset]] = None
    evidence: Optional[list[Evidence]] = None
    findings: Optional[list[Finding]] = None

    def checkpoint_get(self) -> Optional[dict[str, Any]]:
        if self.engine_name and self.load_checkpoint:
            return self.load_checkpoint(self.engine_name)
        return None

    def checkpoint_save(self, state: dict[str, Any]) -> None:
        if self.engine_name and self.save_checkpoint:
            self.save_checkpoint(self.engine_name, state)

    def checkpoint_clear(self) -> None:
        if self.engine_name and self.clear_checkpoint:
            self.clear_checkpoint(self.engine_name)


@dataclass
class EngineOutput:
    assets: list[Asset]
    evidence: list[Evidence]
    findings: list[Finding]


class Engine(ABC):
    name: str

    @abstractmethod
    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        raise NotImplementedError
