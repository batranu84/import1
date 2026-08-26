from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, rate_per_second: int):
        self.rate = max(1, rate_per_second)
        self._interval = 1.0 / self.rate
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._interval - (now - self._last)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = time.monotonic()
