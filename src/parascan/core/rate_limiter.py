"""configurable requests-per-second throttling using a token bucket."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """async token-bucket rate limiter."""

    def __init__(self, rate: int = 10) -> None:
        self._rate = max(rate, 1)
        self._tokens = float(self._rate)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """wait until a token is available."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                # wait for the next token
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
