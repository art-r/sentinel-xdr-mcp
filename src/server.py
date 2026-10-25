from __future__ import annotations

import asyncio
import inspect
import time
from contextlib import asynccontextmanager

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from src.auth.current import current_caller
from src.auth.middleware import AuthorizationMiddleware
from src.auth.setup import apply_oauth_resource_override, create_auth_provider
from src.clients.law_client import LAWClient
from src.clients.sentinel_client import SentinelClient
from src.clients.defender_client import DefenderHuntingClient
from src.config import load_config
from src.governance.kql_validator import KQLValidator
from src.governance.rate_limiter import ConcurrencyLimiter, SlidingWindowRateLimiter
from src.logging_setup import AuditLogger, get_logger, setup_logging


class Deps:
    """Process-wide singletons.

    The Azure clients are built lazily. Constructing them at import time made
    the module impossible to import in a test process, and pointlessly created
    credential objects in a replica that had not served a request yet.
    """

    def __init__(self, config) -> None:
        self.config = config
        self.audit = AuditLogger(config)
        self.kql_validator = KQLValidator(config)
        # Second profile, same implementation. Built only when configured, so a
        # deployment with defender absent cannot construct one by accident.
        self.defender_kql_validator = (
            KQLValidator(config, source="defender")
            if config.defender is not None and config.defender.enabled
            else None
        )
        self._defender_client: DefenderHuntingClient | None = None
        self.rate_limiter = SlidingWindowRateLimiter()
        self.concurrency = ConcurrencyLimiter()
        # Separate from per-caller limits: prevents aggregate exhaustion of the
        # one-worker process by otherwise valid callers.
        self.global_concurrency = ConcurrencyLimiter()
        self._law_client: LAWClient | None = None
        self._sentinel_client: SentinelClient | None = None
        self._ready: tuple[float | None, bool, str] = (None, False, "not checked")
        # Single-flight: without this, every request arriving on a cold or
        # just-expired cache fires its own LAW query. The 30s TTL bounds the
        # steady state; only a lock bounds the herd.
        self._ready_lock = asyncio.Lock()
        # Live table list for discovery under table_policy: workspace. Cached
        # and single-flighted for the same reason as the readiness probe.
        self._tables: tuple[float | None, tuple[str, ...]] = (None, ())
        self._tables_lock = asyncio.Lock()

    @property
    def law_client(self) -> LAWClient:
        if self._law_client is None:
            self._law_client = LAWClient(self.config)
        return self._law_client

    @property
    def sentinel_client(self) -> SentinelClient:
        if self._sentinel_client is None:
            self._sentinel_client = SentinelClient(self.config)
        return self._sentinel_client

    @property
    def defender_client(self):
        from src.clients.defender_client import DefenderHuntingClient

        if self._defender_client is None:
            self._defender_client = DefenderHuntingClient(self.config)
        return self._defender_client

    def require_caller(self, ctx=None):
        """Resolve the caller for the in-flight request.

        Re-derived from the verified access token rather than read out of
        Context state - see src/auth/current.py. `ctx` is accepted (and
        ignored) so tool signatures keep the injected Context that FastMCP
        needs for logging/progress.
        """
        caller = current_caller(self.config)
        if caller is None:
            raise ToolError("Unauthorized: no authenticated caller for this request")
        return caller

    async def check_ready(self, ttl: float = 30.0) -> tuple[bool, str]:
        """Readiness: can the service query its configured LAW workspace?

        Cached so probes do not generate continuous LAW traffic. The LAW client
        executes a minimal `print 1` query, validating both token acquisition
        and LAW workspace RBAC. Optional Sentinel write access is not probed.
        """
        checked_at, ok, detail = self._ready
        now = time.monotonic()
        if checked_at is not None and now - checked_at < ttl:
            return ok, detail
        async with self._ready_lock:
            # Re-check: a concurrent caller may have refreshed it while we waited.
            checked_at, ok, detail = self._ready
            now = time.monotonic()
            if checked_at is not None and now - checked_at < ttl:
                return ok, detail
            try:
                await self.law_client.check_workspace_access()
                ok, detail = True, "ok"
            except Exception as exc:  # pragma: no cover - depends on Azure
                ok, detail = False, type(exc).__name__
                log.warning("readiness_check_failed", error=type(exc).__name__, exc_info=True)
            self._ready = (time.monotonic(), ok, detail)
            return ok, detail

    async def workspace_tables(self, ttl: float = 900.0) -> tuple[str, ...]:
        """Cached workspace table names for discovery. () when unavailable.

        Discovery only - `config.is_table_allowed` is the gate and never calls
        this. A 15-minute TTL is well inside the rate at which tables appear.
        """
        fetched_at, tables = self._tables
        if fetched_at is not None and time.monotonic() - fetched_at < ttl:
            return tables
        async with self._tables_lock:
            fetched_at, tables = self._tables
            if fetched_at is not None and time.monotonic() - fetched_at < ttl:
                return tables
            try:
                names = await self.law_client.list_workspace_tables()
            except Exception as exc:  # pragma: no cover - depends on Azure
                # Broad on purpose: discovery must never fail a tool call. But
                # log the class - an AttributeError or TypeError here is a code
                # defect that would otherwise be indistinguishable from a
                # workspace outage, and would silently pin discovery to the
                # configured fallback list for the life of the revision.
                log.warning(
                    "workspace_table_discovery_failed", error=type(exc).__name__, exc_info=True
                )
                return tables
            self._tables = (time.monotonic(), tuple(sorted(set(names))))
            return self._tables[1]

    async def aclose(self) -> None:
        for client in (self._law_client, self._sentinel_client, self._defender_client):
            if client is None:
                continue
            try:
                await client.close()
            except Exception:  # pragma: no cover
                log.warning("client_close_failed", client=type(client).__name__)
        self._law_client = None
        self._sentinel_client = None
        self._defender_client = None


config = load_config()
setup_logging(config)
log = get_logger()
deps = Deps(config)


@asynccontextmanager
async def _lifespan(_server):
    log.info(
        "server_starting", base_url=str(config.server.base_url), dev_mode=config.server.dev_mode
    )
    try:
        yield
    finally:
        await deps.aclose()
        log.info("server_stopped")


_kwargs = {}
if "lifespan" in inspect.signature(FastMCP.__init__).parameters:
    _kwargs["lifespan"] = _lifespan
else:  # pragma: no cover - FastMCP build without lifespan support
    log.warning("fastmcp_lifespan_unsupported_clients_not_closed_on_shutdown")

mcp = FastMCP(
    name="Sentinel MCP Server",
    auth=create_auth_provider(config, audit=deps.audit),
    **_kwargs,
)
mcp.add_middleware(AuthorizationMiddleware(deps))


@mcp.custom_route("/health", methods=["GET"])
async def health(request):
    """Liveness only: the process is up. Deliberately unauthenticated -
    platform probes cannot present a token. Returns a constant."""
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/ready", methods=["GET"])
async def ready(request):
    """Readiness for monitoring, NOT for the platform probe. `detail` is
    withheld from the response: an exception class name distinguishes a missing
    role from an unreachable workspace, which is not an unauthenticated
    caller's business. It is in the logs."""
    if not config.server.expose_ready_probe:
        return JSONResponse({"status": "disabled"}, status_code=404)
    ok, _detail = await deps.check_ready()
    return JSONResponse({"status": "ready" if ok else "unready"}, status_code=200 if ok else 503)


from src.tools import comments, defender, incidents, query_logs, schema_discovery  # noqa: E402,F401

_allowed_hosts = list(config.server.host_header_allowlist)
if config.server.dev_mode:
    _allowed_hosts += ["localhost", "127.0.0.1"]

# Middleware is passed INTO http_app so that `uvicorn src.main:app` and the
# __main__ path in main.py serve an identical stack. Adding it to only one of
# them is how a dev entrypoint ends up weaker than production.
app = mcp.http_app(middleware=[ASGIMiddleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)])
apply_oauth_resource_override(app, config)
