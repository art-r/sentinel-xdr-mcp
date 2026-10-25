"""Entra ID bearer-token authentication.

Four things here are deliberate and load-bearing.

1. `required_scopes` is NOT set.
   FastMCP's JWTVerifier extracts scopes from the `scope`/`scp` claims only -
   never from `roles`. An Entra client-credentials token carries `roles` and has
   no `scp`, so `required_scopes=["user_impersonation"]` rejects **every**
   app-only token with a 401 before any middleware runs, making the agent unable
   to authenticate at all (report.md C-1). "Delegated OR app-only" cannot be
   expressed as a scope list, so it is expressed in code below.

2. The authorisation gate hangs off `verify_token`, and off NOTHING ELSE.
   mcp's BearerAuthBackend.authenticate calls `verify_token`. An earlier version
   overrode only `load_access_token`, which that SDK never calls: the base JWT
   check ran, `authorize()` did not, and every signature-valid token from the
   tenant authenticated without a role or client-application check.

   Do NOT "defensively" also override `load_access_token` to delegate here.
   The two names are aliases of each other inside the base class, and which one
   wraps which has changed between releases. Overriding exactly one is correct
   in both directions: if the base implements the work in `verify_token`, the
   super() call below does it; if the base implements it in `load_access_token`,
   the base `verify_token` alias reaches it. Overriding both closes that loop
   into infinite recursion, which the except-clause then hides as a 401.

3. Authorisation happens here, in the verifier, not only in middleware.
   Returning None yields a proper 401 with WWW-Authenticate, so a compliant MCP
   client can re-authenticate, and no code path can reach a tool without having
   passed the role and client-application checks.

4. Every rejection is audited AND logged with a traceback. The audit record
   carries a coarse reason only (report H-4) - deliberately non-leaky, but
   useless for operations: a JWKS fetch failure, clock skew and a forged
   signature all collapse to "token_validation_error". The server log gets the
   exception type and stack; the audit trail does not. The token itself is
   never written to either.

JWTVerifier is used explicitly rather than AzureJWTVerifier (which does exist in
fastmcp.server.auth.providers.azure and would derive these values from
tenant_id/client_id) so that issuer and audience are pinned to exactly what this
tenant issues. Swap it in if you prefer the derived configuration.
"""
from __future__ import annotations

import json

from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

from src.logging_setup import get_logger

from .authorization import authorize, denial_reason

log = get_logger("auth")


class EntraCallerVerifier(JWTVerifier):
    """Validates the token, then applies the delegated-OR-app-only rule."""

    def __init__(self, config, audit=None) -> None:
        tenant = config.identity.tenant_id
        super().__init__(
            jwks_uri=f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
            issuer=f"https://login.microsoftonline.com/{tenant}/v2.0",
            audience=config.identity.mcp_app_client_id,
            # Intentionally empty - see module docstring.
            required_scopes=[],
        )
        self._config = config
        self._audit = audit

    def _deny(self, reason: str, claims: dict | None = None) -> None:
        log.warning("authentication_denied", reason=reason)
        if self._audit is not None:
            try:
                self._audit.log_auth_denied(reason, claims)
            except Exception:
                # Auditing must never block authn, but a silent failure here
                # means the 401-spike alert has no source. Say so.
                log.warning("audit_hook_failed", hook="log_auth_denied", exc_info=True)

    async def verify_token(self, token: str):
        """The hook BearerAuthBackend calls. Every check lives here."""
        try:
            access_token = await super().verify_token(token)  # signature, iss, aud, exp
        except Exception as exc:
            # A verifier that raises must still fail closed, not 500. The
            # traceback stays in the server log and never reaches the caller.
            log.warning("token_validation_error", error=type(exc).__name__, exc_info=True)
            self._deny("token_validation_error")
            return None
        if access_token is None:
            # Base verifier rejected it without raising: bad signature, wrong
            # aud/iss, expired, or an unusable JWKS document.
            self._deny("token_invalid")
            return None

        claims = getattr(access_token, "claims", None) or {}
        if authorize(claims, self._config) is None:
            self._deny(denial_reason(claims, self._config), claims)
            return None
        return access_token


def create_auth_provider(config, audit=None) -> RemoteAuthProvider:
    """Entra ID JWT validation.

    IMPORTANT - Entra token versions: set `requestedAccessTokenVersion = 2` on
    the MCP app registration so access tokens carry iss=.../v2.0 and
    aud=<mcp_app_client_id> (a GUID). Otherwise Entra issues
    iss=https://sts.windows.net/<tenant>/ and aud=api://<client_id>, and both
    checks above fail with an uninformative 401. Decode a real token first.

    IMPORTANT - egress: JWT validation fetches the tenant JWKS from
    login.microsoftonline.com on first use. That is a different FQDN from the
    Log Analytics data plane and from the IMDS endpoint the Managed Identity
    uses, so `/ready` passing does NOT prove this host is reachable. On a
    VNet-integrated environment with a firewall, allow it explicitly or every
    token fails with token_validation_error.

    IMPORTANT - clock: after this verifier returns, the SDK re-checks
    `expires_at` against the container's own clock and drops the request with a
    bare 401 that no code here can log. A skewed clock therefore looks like a
    silent auth failure.

    `scopes_supported` is advertised in the protected-resource metadata so a
    compliant MCP client knows which scope to request. It is metadata only -
    enforcement stays in `authorize()`, which also covers the app-only path that
    has no scope at all.
    """
    tenant = config.identity.tenant_id
    return RemoteAuthProvider(
        token_verifier=EntraCallerVerifier(config, audit=audit),
        authorization_servers=[AnyHttpUrl(f"https://login.microsoftonline.com/{tenant}/v2.0")],
        base_url=str(config.server.base_url),
        scopes_supported=[config.identity.delegated_scope_uri],
        resource_name="Sentinel MCP Server",
    )

#: RFC 9728 inserts the resource's path after the well-known segment, so the
#: generated document is served at /.well-known/oauth-protected-resource/mcp,
#: not at the root form.
PRM_PATH_PREFIX = "/.well-known/oauth-protected-resource"


def _find_metadata_routes(routes, found=None):
    """Routes at or under the protected-resource metadata prefix.

    Recurses into Mounts so a FastMCP version that nests the auth routes is
    DETECTED rather than silently missed - a missed route means the override
    does nothing while the config claims it is on.
    """
    found = [] if found is None else found
    for route in routes:
        path = getattr(route, "path", None)
        if isinstance(path, str) and path.startswith(PRM_PATH_PREFIX):
            found.append(route)
        nested = getattr(route, "routes", None)
        if nested:
            _find_metadata_routes(nested, found)
    return found


class _MetadataResourceOverride:
    """ASGI wrapper that rewrites `resource` in the metadata document.

    Wraps at the ASGI layer, not the endpoint layer: the MCP SDK registers this
    route with a CORSMiddleware instance as the endpoint, which takes
    (scope, receive, send) rather than a Request. Wrapping the route's ASGI app
    is agnostic to that, and leaves the CORS headers - emitted inside the app
    being wrapped - untouched.

    The response is buffered because the body length changes and content-length
    must be recomputed. The document is a few hundred bytes and is served once
    per client per discovery, so buffering costs nothing.
    """

    def __init__(self, app, resource: str) -> None:
        self._app = app
        self._resource = resource

    async def __call__(self, scope, receive, send) -> None:
        state: dict = {"start": None, "chunks": []}

        async def _send(message):
            if message["type"] == "http.response.start":
                # Held back: content-length is not known until the body is.
                state["start"] = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            state["chunks"].append(message.get("body", b""))
            if message.get("more_body"):
                return
            await self._flush(scope, state["start"], b"".join(state["chunks"]), send)

        await self._app(scope, receive, _send)

    async def _flush(self, scope, start, body: bytes, send) -> None:
        if start is None:  # pragma: no cover - not reachable over HTTP/1.1
            raise RuntimeError("metadata response ended without a start message")

        headers = list(start["headers"])
        content_type = next(
            (v.decode("latin-1") for k, v in headers if k.lower() == b"content-type"), ""
        )

        # Only the GET that returns the document is rewritten. A CORS preflight
        # (OPTIONS -> text/plain) and any error status pass through untouched.
        if scope.get("method") == "GET" and start["status"] == 200:
            if not content_type.startswith("application/json"):
                raise RuntimeError(
                    "protected-resource metadata returned "
                    f"content-type {content_type!r}; the override cannot rewrite it."
                )
            document = json.loads(body)
            if not isinstance(document, dict) or "resource" not in document:
                raise RuntimeError(
                    "protected-resource metadata has no 'resource' field; "
                    "FastMCP's document shape changed."
                )
            document["resource"] = self._resource
            body = json.dumps(document).encode()
            headers = [(k, v) for k, v in headers if k.lower() != b"content-length"]
            headers.append((b"content-length", str(len(body)).encode()))

        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})


def apply_oauth_resource_override(app, config) -> None:
    """Rewrite `resource` in the protected-resource metadata document.

    FastMCP offers no hook to set that value independently of the route path:
    both are derived from `base_url`, which is typed AnyHttpUrl and therefore
    cannot hold an `api://` URI. This wraps the generated route's ASGI app and
    patches exactly one field, leaving the path, every other field and the
    response headers as FastMCP produced them.

    No-op unless identity.advertise_app_id_uri_as_oauth_resource is set.

    Raises at import time - before the process serves anything - if the route is
    not where it is expected. A FastMCP upgrade that moves it is a startup
    failure, not a server that quietly advertises the wrong identifier.
    """
    resource = config.identity.oauth_resource_id
    if resource is None:
        return

    found = _find_metadata_routes(app.routes)
    if len(found) != 1:
        raise RuntimeError(
            "identity.advertise_app_id_uri_as_oauth_resource is set, but "
            f"{len(found)} protected-resource metadata route(s) were found: "
            f"{[getattr(r, 'path', r) for r in found]}. FastMCP's auth routing "
            "changed - re-verify the override before deploying."
        )

    route = found[0]
    inner = getattr(route, "app", None)
    if inner is None:
        raise RuntimeError(
            f"protected-resource metadata route {getattr(route, 'path', route)!r} "
            "has no ASGI app to wrap."
        )

    # Mutated in place rather than rebuilt: reconstructing the Route would drop
    # name, path_regex, include_in_schema and the derived method set.
    route.app = _MetadataResourceOverride(inner, resource)
    log.warning("oauth_resource_override_applied", path=route.path, resource=resource)