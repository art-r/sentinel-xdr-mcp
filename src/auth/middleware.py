"""Protocol-level enforcement: tool scoping, rate limits, concurrency.

The verifier (auth/setup.py) has already rejected any token that is not a valid,
authorised caller, so anything reaching here is authenticated. This layer decides
*what* that caller may do.

Rate and concurrency limits live HERE, once, for every tool - not inside
individual tool functions. That is how five of six tools previously ended up
unmetered (report.md H-3), and it is how tool number seven would too.

The caller is re-derived from the verified token on each hook via
`current_caller()` rather than being passed through `Context` state; see
`auth/current.py` for why.

Rejections are raised as ToolError: FastMCP masks other exception types into a
generic internal error, so a plain PermissionError tells the caller nothing and
cannot trigger re-authentication.
"""
from __future__ import annotations

import asyncio

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from src.governance.rate_limiter import ConcurrencyLimitExceeded, RateLimitExceeded

from .current import current_caller

#: Protocol methods that carry no workspace data and must stay reachable for a
#: session to be established at all. Everything else is denied by `on_request`
#: unless a caller resolves. Keeping this list explicit (rather than exempting
#: whole component types) is what makes the deny-by-default real.
_HANDSHAKE_METHODS = frozenset({"initialize", "ping"})


class AuthorizationMiddleware(Middleware):
    def __init__(self, deps) -> None:
        self.deps = deps
        self.config = deps.config
        self.audit = deps.audit

    # ---- hooks ---------------------------------------------------------

    async def on_request(self, context, call_next):
        """Deny-by-default catch-all: no component type is reachable without an
        authorised caller, including ones added after this was written."""
        method = getattr(context, "method", None)
        if method in _HANDSHAKE_METHODS:
            return await call_next(context)
        if self._caller() is None:
            self.audit.log_denied("unauthenticated", tool=method)
            raise ToolError("Unauthorized")
        return await call_next(context)

    async def on_list_tools(self, context, call_next):
        caller = self._caller()
        if caller is None:
            raise ToolError("Unauthorized")
        allowed = set(self.config.governance[caller.type].allowed_tools)
        tools = await call_next(context)
        return [t for t in tools if t.name in allowed]

    async def on_call_tool(self, context, call_next):
        caller = self._caller()
        tool_name = getattr(context.message, "name", None)
        if caller is None:
            self.audit.log_denied("unauthenticated", tool=tool_name)
            raise ToolError("Unauthorized")

        gov = self.config.governance[caller.type]
        if tool_name not in set(gov.allowed_tools):
            self.audit.log_denied("tool_not_allowed", tool=tool_name, caller=caller)
            raise ToolError(f"Tool '{tool_name}' is not available for your role")

        try:
            self.deps.rate_limiter.check_or_raise(
                f"{caller.id}:{tool_name}", gov.rate_limit_for(tool_name))
        except RateLimitExceeded as exc:
            self.audit.log_denied("rate_limited", tool=tool_name, caller=caller)
            raise ToolError(str(exc)) from None

        try:
            async with self.deps.concurrency.slot(caller.id, gov.max_concurrent_queries):
                try:
                    async with self.deps.global_concurrency.slot(
                        "__server__", self.config.server.max_concurrent_requests
                    ):
                        try:
                            async with asyncio.timeout(self.config.server.max_request_timeout_seconds):
                                return await call_next(context)
                        except TimeoutError:
                            self.audit.log_denied("request_timed_out", tool=tool_name, caller=caller)
                            raise ToolError(
                                "Request timed out. Narrow the query or retry with fewer concurrent requests."
                            ) from None
                except ConcurrencyLimitExceeded as exc:
                    self.audit.log_denied("global_concurrency_limited", tool=tool_name, caller=caller)
                    raise ToolError("Server is at its concurrent-request limit. Retry shortly.") from None
        except ConcurrencyLimitExceeded as exc:
            self.audit.log_denied("concurrency_limited", tool=tool_name, caller=caller)
            raise ToolError(str(exc)) from None

    # Deny by default for component types this server does not expose. If
    # someone adds @mcp.resource or @mcp.prompt later, it is guarded from the
    # first commit instead of shipping unprotected.
    async def on_read_resource(self, context, call_next):
        raise ToolError("This server exposes no resources")

    async def on_get_prompt(self, context, call_next):
        raise ToolError("This server exposes no prompts")

    # ---- internals -----------------------------------------------------

    def _caller(self):
        return current_caller(self.config)
