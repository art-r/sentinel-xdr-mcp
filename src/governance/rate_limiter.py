"""Per-caller sliding-window rate limiter and concurrency guard (in-memory).

Both are bounded: entries are swept on expiry and the window map is capped, so
memory is not a monotonically increasing function of distinct caller IDs.
In-memory means per-replica - keep min=max=1 replicas or move to a shared store.
"""
from __future__ import annotations

import asyncio
import time
from threading import Lock


class RateLimitExceeded(Exception):
    pass


class ConcurrencyLimitExceeded(Exception):
    pass


class SlidingWindowRateLimiter:
    def __init__(self, maxsize: int = 10_000) -> None:
        self._windows: dict[str, list[float]] = {}
        self._lock = Lock()
        self._maxsize = maxsize

    def check_or_raise(self, key: str, limit: int, window_seconds: int = 60) -> None:
        now = time.monotonic()
        with self._lock:
            # Plain dict + explicit get: a defaultdict would create an entry on
            # every lookup, including for callers that are then rejected.
            window = [t for t in self._windows.get(key, ()) if now - t < window_seconds]
            if len(window) >= limit:
                if window:
                    self._windows[key] = window  # keep the pruned list
                    wait = window_seconds - (now - window[0])
                else:
                    # limit <= 0: never store a row for a caller we always reject
                    self._windows.pop(key, None)
                    wait = window_seconds
                raise RateLimitExceeded(
                    f"Rate limit exceeded: {limit} requests per {window_seconds}s. "
                    f"Wait {wait:.0f}s before retrying."
                )
            window.append(now)
            self._windows[key] = window
            if len(self._windows) > self._maxsize:
                self._sweep(now, window_seconds)

    def _sweep(self, now: float, window_seconds: int) -> None:
        stale = [k for k, v in self._windows.items() if not v or now - v[-1] >= window_seconds]
        for k in stale:
            self._windows.pop(k, None)


class ConcurrencyLimiter:
    def __init__(self) -> None:
        self._active: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def slot(self, caller_id: str, limit: int) -> "_Slot":
        return _Slot(self, caller_id, limit)

    async def _acquire(self, caller_id: str, limit: int) -> None:
        async with self._lock:
            current = self._active.get(caller_id, 0)
            if current >= limit:
                raise ConcurrencyLimitExceeded(
                    f"Too many concurrent requests (limit {limit}). "
                    "Retry when your other request finishes."
                )
            self._active[caller_id] = current + 1

    async def _release(self, caller_id: str) -> None:
        async with self._lock:
            remaining = self._active.get(caller_id, 1) - 1
            if remaining > 0:
                self._active[caller_id] = remaining
            else:
                self._active.pop(caller_id, None)  # keeps the map bounded


class _Slot:
    def __init__(self, limiter: ConcurrencyLimiter, caller_id: str, limit: int) -> None:
        self._limiter, self._caller_id, self._limit = limiter, caller_id, limit

    async def __aenter__(self) -> "_Slot":
        await self._limiter._acquire(self._caller_id, self._limit)
        return self

    async def __aexit__(self, *exc) -> None:
        await self._limiter._release(self._caller_id)
