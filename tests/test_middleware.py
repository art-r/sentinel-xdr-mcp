"""Protocol middleware: tool scoping, limits, deny-by-default.

This file exists because nothing previously imported fastmcp, so the entire
security-critical wiring - middleware and caller propagation - was unverified
(report C-2). It drives the hooks directly with synthetic contexts; the token is
faked at `src.auth.current.get_access_token`, which is the only place the code
reads it.
"""
import asyncio

import pytest
from fastmcp.exceptions import ToolError

from src.auth import current as current_mod
from src.auth.middleware import AuthorizationMiddleware
from src.governance.rate_limiter import ConcurrencyLimiter, SlidingWindowRateLimiter
from src.logging_setup import AuditLogger

from ._support import CollectingLogger, agent_claims, config, human_claims


class _Token:
    def __init__(self, claims):
        self.claims = claims


class _Message:
    def __init__(self, name):
        self.name = name


class _Ctx:
    def __init__(self, tool=None, method=None):
        self.message = _Message(tool)
        self.method = method


class _Tool:
    def __init__(self, name):
        self.name = name


ALL_TOOLS = [_Tool(n) for n in (
    "query_sentinel_logs", "get_incident", "get_incident_entities",
    "list_available_tables", "get_table_schema", "add_incident_comment")]


class _Deps:
    def __init__(self):
        self.config = config()
        self.log = CollectingLogger()
        self.audit = AuditLogger(self.config, logger=self.log)
        self.rate_limiter = SlidingWindowRateLimiter()
        self.concurrency = ConcurrencyLimiter()
        self.global_concurrency = ConcurrencyLimiter()


@pytest.fixture
def mw(monkeypatch):
    deps = _Deps()
    middleware = AuthorizationMiddleware(deps)
    middleware._test_deps = deps

    def _set(claims):
        monkeypatch.setattr(current_mod, "get_access_token",
                            lambda: None if claims is None else _Token(claims))

    middleware._set_token = _set
    _set(None)
    return middleware


async def _passthrough(context):
    return "OK"


async def _list_all(context):
    return list(ALL_TOOLS)


# ---- tools/list --------------------------------------------------------

def test_list_tools_is_scoped_to_the_human_tier(mw):
    mw._set_token(human_claims())
    names = {t.name for t in asyncio.run(mw.on_list_tools(_Ctx(), _list_all))}
    assert names == set(config().governance["human"].allowed_tools)
    assert "add_incident_comment" not in names


def test_list_tools_is_scoped_to_the_agent_tier(mw):
    mw._set_token(agent_claims())
    names = {t.name for t in asyncio.run(mw.on_list_tools(_Ctx(), _list_all))}
    assert names == set(config().governance["agent"].allowed_tools)
    assert "add_incident_comment" in names


def test_list_tools_denies_when_unauthenticated(mw):
    with pytest.raises(ToolError):
        asyncio.run(mw.on_list_tools(_Ctx(), _list_all))


# ---- tools/call --------------------------------------------------------

def test_authorized_call_passes_through(mw):
    mw._set_token(human_claims())
    assert asyncio.run(mw.on_call_tool(_Ctx("get_incident"), _passthrough)) == "OK"


def test_unauthenticated_call_is_denied_and_audited(mw):
    with pytest.raises(ToolError):
        asyncio.run(mw.on_call_tool(_Ctx("get_incident"), _passthrough))
    assert mw._test_deps.log.of("access_denied")[0]["reason"] == "unauthenticated"


def test_human_cannot_call_the_agent_write_tool(mw):
    """Filtering tools/list does not block tools/call - both must enforce."""
    mw._set_token(human_claims())
    with pytest.raises(ToolError):
        asyncio.run(mw.on_call_tool(_Ctx("add_incident_comment"), _passthrough))
    assert mw._test_deps.log.of("access_denied")[0]["reason"] == "tool_not_allowed"


def test_unknown_tool_name_is_denied(mw):
    mw._set_token(human_claims())
    with pytest.raises(ToolError):
        asyncio.run(mw.on_call_tool(_Ctx("delete_everything"), _passthrough))


def test_rate_limit_applies_to_every_tool_and_is_audited(mw):
    mw._set_token(human_claims())
    limit = config().governance["human"].rate_limit_queries_per_minute

    async def hammer():
        for _ in range(limit):
            await mw.on_call_tool(_Ctx("get_incident"), _passthrough)
        with pytest.raises(ToolError):
            await mw.on_call_tool(_Ctx("get_incident"), _passthrough)

    asyncio.run(hammer())
    assert mw._test_deps.log.of("access_denied")[0]["reason"] == "rate_limited"


def test_write_tool_has_its_own_smaller_budget(mw):
    mw._set_token(agent_claims())
    writes = config().governance["agent"].rate_limit_writes_per_minute

    async def hammer():
        for _ in range(writes):
            await mw.on_call_tool(_Ctx("add_incident_comment"), _passthrough)
        with pytest.raises(ToolError):
            await mw.on_call_tool(_Ctx("add_incident_comment"), _passthrough)
        # Read budget is separate and untouched.
        await mw.on_call_tool(_Ctx("get_incident"), _passthrough)

    asyncio.run(hammer())


def test_global_concurrency_limit_is_enforced_and_audited(mw):
    mw._set_token(human_claims())
    original_limit = mw.config.server.max_concurrent_requests
    mw.config.server.max_concurrent_requests = 1
    release = asyncio.Event()

    async def slow(_context):
        await release.wait()
        return "OK"

    async def main():
        running = asyncio.create_task(mw.on_call_tool(_Ctx("get_incident"), slow))
        await asyncio.sleep(0)
        with pytest.raises(ToolError):
            await mw.on_call_tool(_Ctx("get_table_schema"), _passthrough)
        release.set()
        await running

    try:
        asyncio.run(main())
    finally:
        mw.config.server.max_concurrent_requests = original_limit

    reasons = [event["reason"] for event in mw._test_deps.log.of("access_denied")]
    assert "global_concurrency_limited" in reasons


def test_request_deadline_is_enforced_and_audited(mw):
    mw._set_token(human_claims())
    original_timeout = mw.config.server.max_request_timeout_seconds
    mw.config.server.max_request_timeout_seconds = 0.01

    async def slow(_context):
        await asyncio.sleep(1)

    try:
        with pytest.raises(ToolError, match="timed out"):
            asyncio.run(mw.on_call_tool(_Ctx("get_incident"), slow))
    finally:
        mw.config.server.max_request_timeout_seconds = original_timeout

    reasons = [event["reason"] for event in mw._test_deps.log.of("access_denied")]
    assert "request_timed_out" in reasons


def test_concurrency_limit_is_enforced_and_audited(mw):
    mw._set_token(agent_claims())
    limit = config().governance["agent"].max_concurrent_queries
    release = asyncio.Event()

    async def slow(_context):
        await release.wait()
        return "OK"

    async def main():
        running = [asyncio.create_task(mw.on_call_tool(_Ctx("get_incident"), slow))
                   for _ in range(limit)]
        await asyncio.sleep(0)
        with pytest.raises(ToolError):
            await mw.on_call_tool(_Ctx("get_incident"), _passthrough)
        release.set()
        await asyncio.gather(*running)

    asyncio.run(main())
    reasons = [e["reason"] for e in mw._test_deps.log.of("access_denied")]
    assert "concurrency_limited" in reasons


# ---- deny by default ---------------------------------------------------

def test_on_request_denies_unauthenticated_non_handshake_methods(mw):
    with pytest.raises(ToolError):
        asyncio.run(mw.on_request(_Ctx(method="resources/list"), _passthrough))


def test_on_request_allows_the_handshake(mw):
    """initialize/ping must stay reachable or no session can be established.
    Neither returns workspace data."""
    assert asyncio.run(mw.on_request(_Ctx(method="initialize"), _passthrough)) == "OK"
    assert asyncio.run(mw.on_request(_Ctx(method="ping"), _passthrough)) == "OK"


def test_on_request_allows_an_authorized_caller(mw):
    mw._set_token(human_claims())
    assert asyncio.run(mw.on_request(_Ctx(method="tools/list"), _passthrough)) == "OK"


def test_resources_and_prompts_are_denied_unconditionally(mw):
    mw._set_token(agent_claims())
    with pytest.raises(ToolError):
        asyncio.run(mw.on_read_resource(_Ctx(), _passthrough))
    with pytest.raises(ToolError):
        asyncio.run(mw.on_get_prompt(_Ctx(), _passthrough))


# ---- caller resolution -------------------------------------------------

def test_a_raising_token_lookup_fails_closed(mw, monkeypatch):
    """Some FastMCP builds raise instead of returning None when there is no
    auth context. That must be a denial, not a 500."""
    def _boom():
        raise RuntimeError("no auth context")

    monkeypatch.setattr(current_mod, "get_access_token", _boom)
    assert mw._caller() is None


def test_claims_without_a_role_are_denied(mw):
    mw._set_token(human_claims(roles=[]))
    with pytest.raises(ToolError):
        asyncio.run(mw.on_call_tool(_Ctx("get_incident"), _passthrough))


def test_delegated_token_with_the_agent_role_gets_the_human_tier(mw):
    """A user mis-assigned MCP.Agent must not reach the write tool."""
    mw._set_token(human_claims(roles=[config().identity.required_human_role,
                                      config().identity.required_agent_role]))
    with pytest.raises(ToolError):
        asyncio.run(mw.on_call_tool(_Ctx("add_incident_comment"), _passthrough))
