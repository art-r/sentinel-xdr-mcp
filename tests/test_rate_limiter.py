import asyncio

from src.governance.rate_limiter import (
    ConcurrencyLimitExceeded,
    ConcurrencyLimiter,
    RateLimitExceeded,
    SlidingWindowRateLimiter,
)


def test_allows_under_limit():
    rl = SlidingWindowRateLimiter()
    for _ in range(5):
        rl.check_or_raise("u1", 5)


def test_blocks_over_limit():
    rl = SlidingWindowRateLimiter()
    for _ in range(5):
        rl.check_or_raise("u2", 5)
    try:
        rl.check_or_raise("u2", 5)
    except RateLimitExceeded:
        return
    raise AssertionError("expected RateLimitExceeded")


def test_callers_and_tools_are_isolated():
    rl = SlidingWindowRateLimiter()
    for _ in range(5):
        rl.check_or_raise("a:query_sentinel_logs", 5)
    rl.check_or_raise("b:query_sentinel_logs", 5)
    rl.check_or_raise("a:get_incident", 5)


def test_rejected_lookups_do_not_create_entries():
    """A defaultdict created a row on every lookup, including for rejections."""
    rl = SlidingWindowRateLimiter()
    for _ in range(3):
        rl.check_or_raise("real", 3)
    before = len(rl._windows)
    for _ in range(20):
        try:
            rl.check_or_raise("other", 0)
        except RateLimitExceeded:
            pass
    assert len(rl._windows) == before


def test_window_map_is_bounded():
    rl = SlidingWindowRateLimiter(maxsize=50)
    for i in range(500):
        rl.check_or_raise(f"caller-{i}", 10, window_seconds=0)
    assert len(rl._windows) <= 51


def test_concurrency_limit_and_release():
    async def main():
        cl = ConcurrencyLimiter()
        async with cl.slot("u", 1):
            try:
                async with cl.slot("u", 1):
                    raise AssertionError("expected ConcurrencyLimitExceeded")
            except ConcurrencyLimitExceeded:
                pass
        assert cl._active == {}  # released, and the key is gone
        async with cl.slot("u", 1):
            pass

    asyncio.run(main())
