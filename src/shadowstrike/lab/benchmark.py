from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.tcp import TcpDiscoveryEngine
from shadowstrike.models.domain import ScopePolicy


@dataclass
class LabBenchmark:
    attempts: int
    open_detected: int
    duration_seconds: float
    attempts_per_second: float
    expected_open_detected: bool

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


async def run_local_tcp_benchmark(iterations: int = 64) -> LabBenchmark:
    """Benchmark ShadowScan against an ephemeral localhost server only."""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    policy = ScopePolicy(
        allowed_cidrs=["127.0.0.1/32"],
        max_requests_per_second=10000,
        max_concurrency=64,
    )
    context = EngineContext(
        scope=ScopeGuard(policy),
        limiter=RateLimiter(policy.max_requests_per_second),
        timeout=0.5,
        user_agent="ShadowStrike-Lab/0.4",
        profile="lab",
    )
    # Include one open fixture and deterministic closed ports for repeatable error pressure.
    closed = [max(1, port - i - 1) for i in range(max(1, iterations - 1))]
    ports = [port, *closed]
    engine = TcpDiscoveryEngine(ports=ports, batch_size=64)
    started = time.monotonic()
    try:
        output = await engine.run(["127.0.0.1"], context)
    finally:
        server.close()
        await server.wait_closed()
    duration = max(time.monotonic() - started, 1e-9)
    telemetry = next((e.raw for e in output.evidence if e.category == "scan-telemetry"), {})
    open_detected = len([a for a in output.assets if a.attributes.get("port") == port])
    return LabBenchmark(
        attempts=int(telemetry.get("attempted_connections", len(ports))),
        open_detected=open_detected,
        duration_seconds=round(duration, 4),
        attempts_per_second=round(len(ports) / duration, 2),
        expected_open_detected=open_detected >= 1,
    )
