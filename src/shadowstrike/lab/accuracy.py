from __future__ import annotations

from dataclasses import dataclass

from shadowstrike.core.scope import ScopeGuard
from shadowstrike.models.domain import ScopePolicy
from shadowstrike.services.template_normalizer import TemplateResultNormalizer
from shadowstrike.utils.endpoints import normalize_url


@dataclass
class AccuracyResult:
    known_conditions: int
    detected: int
    false_positives: int

    @property
    def recall_percent(self) -> float:
        return round(100.0 * self.detected / self.known_conditions, 2) if self.known_conditions else 0.0

    def as_dict(self) -> dict:
        return {
            "known_conditions": self.known_conditions,
            "detected": self.detected,
            "false_positives": self.false_positives,
            "recall_percent": self.recall_percent,
        }


def run_accuracy_fixtures() -> AccuracyResult:
    known = detected = false_positives = 0

    known += 2
    detected += int(normalize_url("https://example.test/users/123?x=1") == "https://example.test/users/{id}")
    detected += int(normalize_url("https://example.test/a/550e8400-e29b-41d4-a716-446655440000") == "https://example.test/a/{uuid}")

    scope = ScopeGuard(ScopePolicy(allowed_domains=["example.test"]))
    records = [
        {"host": "https://api.example.test", "name": "Known in-scope observation", "severity": "low"},
        {"host": "https://outside.test", "name": "Out-of-scope observation", "severity": "critical"},
    ]
    evidence, findings = TemplateResultNormalizer().normalize(records, scope)
    known += 1
    detected += int(len(evidence) == 1 and len(findings) == 1)
    false_positives += int(any(f.affected_asset == "https://outside.test" for f in findings))
    return AccuracyResult(known_conditions=known, detected=detected, false_positives=false_positives)
