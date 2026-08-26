from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Union


@dataclass
class AdaptiveConcurrency:
    """Small AIMD-style concurrency controller bounded by the engagement policy.

    Engines may use this to decide the next batch size. It never exceeds max_limit and
    only increases after a healthy window; error/timeout pressure reduces concurrency.
    """

    max_limit: int
    initial: int = 16
    min_limit: int = 1
    healthy_error_rate: float = 0.05
    high_error_rate: float = 0.20
    latency_ceiling_ms: float = 1500.0
    window: int = 64
    current: int = field(init=False)
    _samples: deque[tuple[bool, float]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.current = max(self.min_limit, min(self.initial, self.max_limit))
        self._samples = deque(maxlen=max(8, self.window))

    def observe(self, success: bool, latency_ms: float) -> None:
        self._samples.append((success, max(0.0, latency_ms)))
        if len(self._samples) < min(8, self._samples.maxlen or 8):
            return
        error_rate = sum(1 for ok, _ in self._samples if not ok) / len(self._samples)
        successful_latencies = [lat for ok, lat in self._samples if ok]
        mean_latency = (
            sum(successful_latencies) / len(successful_latencies)
            if successful_latencies
            else self.latency_ceiling_ms * 2
        )
        if error_rate >= self.high_error_rate or mean_latency >= self.latency_ceiling_ms:
            self.current = max(self.min_limit, self.current // 2)
            self._samples.clear()
        elif error_rate <= self.healthy_error_rate and self.current < self.max_limit:
            self.current = min(self.max_limit, self.current + max(1, self.current // 4))
            self._samples.clear()

    def snapshot(self) -> dict[str, Union[float, int]]:
        errors = sum(1 for ok, _ in self._samples if not ok)
        latencies = [lat for ok, lat in self._samples if ok]
        return {
            "current_concurrency": self.current,
            "sample_count": len(self._samples),
            "window_error_rate": round(errors / len(self._samples), 4) if self._samples else 0.0,
            "mean_success_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        }
