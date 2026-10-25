"""Single source of truth for "who is calling this request?".

Both the protocol middleware and the tools resolve the caller through this
function. It re-derives the identity from the verified access token on every
call, which is cheap - `authorize()` is a pure set-membership test over claims
that FastMCP has already validated (signature, iss, aud, exp).

Why not stash the CallerContext in `Context` state:

  * in FastMCP 3 `set_state`/`get_state` are coroutines, and the previous code
    called them synchronously - the write was never awaited and the read
    returned a coroutine object that passed a `is None` check (report C-1);
  * state in FastMCP 3 is SESSION-scoped and backed by a pluggable store keyed
    by a session id the client supplies. An authorisation identity must never
    live in a store keyed by a client-controlled value.

Re-deriving has neither problem and cannot drift from the middleware's view.
"""
from __future__ import annotations

from fastmcp.server.dependencies import get_access_token

from .authorization import authorize
from .caller import CallerContext


def current_claims() -> dict | None:
    """Verified JWT claims for the in-flight request, or None."""
    try:
        token = get_access_token()
    except Exception:
        # No auth context (or a FastMCP build that raises instead of returning
        # None). Fail closed.
        return None
    if token is None:
        return None
    return getattr(token, "claims", None) or {}


def current_caller(config) -> CallerContext | None:
    claims = current_claims()
    if claims is None:
        return None
    return authorize(claims, config)
