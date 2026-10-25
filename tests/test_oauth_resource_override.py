"""The override rewrites exactly one field, and the route it wraps is where
FastMCP puts it.

The second property is the one that matters operationally: if a FastMCP upgrade
moves the metadata route or changes the document shape, this must fail loudly
rather than serve an unmodified document while the config claims otherwise.

The routes are driven over raw ASGI. FastMCP registers this endpoint as a
CORSMiddleware instance, so it cannot be called as `endpoint(request)`, and a
hand-rolled driver keeps the test free of an HTTP-client dependency.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest

from src.auth.setup import _find_metadata_routes, apply_oauth_resource_override

from ._support import config

PRM_PATH = "/.well-known/oauth-protected-resource/mcp"


def _metadata_route(app):
    found = _find_metadata_routes(app.routes)
    assert len(found) == 1, f"expected exactly one metadata route, got {found}"
    return found[0]


def _call(route, method="GET", host=None):
    """Drive the route's ASGI app; return (status, headers, body bytes)."""
    host = host or config().server.base_url.host
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": route.path,
        "raw_path": route.path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", host.encode())],
        "server": (host, 443),
        "client": ("127.0.0.1", 0),
    }
    asyncio.run(route.handle(scope, receive, send))

    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    headers = {k.decode().lower(): v.decode("latin-1") for k, v in start["headers"]}
    return start["status"], headers, body


def _document(app):
    status, headers, body = _call(_metadata_route(app))
    assert status == 200
    assert headers["content-type"].startswith("application/json")
    # A stale content-length breaks the document for any client that honours it.
    assert headers["content-length"] == str(len(body))
    return json.loads(body)


def test_metadata_route_is_where_we_patch_it():
    """Canary for a FastMCP upgrade moving the well-known route."""
    from src.server import app

    assert _metadata_route(app).path == PRM_PATH


def test_served_resource_matches_the_configured_override():
    from src.server import app

    cfg = config()
    expected = cfg.identity.oauth_resource_id or f"{cfg.server.base_url}mcp"
    assert _document(app)["resource"] == expected


def test_advertised_resource_is_the_scope_prefix():
    """The whole point: Entra compares the RFC 8707 resource indicator against
    the prefix of the requested scope."""
    cfg = config()
    if cfg.identity.oauth_resource_id is None:
        pytest.skip("override disabled in the shipped config")
    assert cfg.identity.delegated_scope_uri.startswith(cfg.identity.oauth_resource_id + "/")


def test_override_preserves_every_other_field():
    from src.server import app

    cfg = config()
    document = _document(app)
    assert document["scopes_supported"] == [cfg.identity.delegated_scope_uri]
    assert document["authorization_servers"] == [
        f"https://login.microsoftonline.com/{cfg.identity.tenant_id}/v2.0"
    ]
    assert document["resource_name"] == "Sentinel MCP Server"
    assert document["bearer_methods_supported"] == ["header"]


def test_cors_preflight_is_not_rewritten():
    """The wrapper must only touch the GET that returns the document; the SDK
    wraps this route in CORSMiddleware and its preflight is not JSON."""
    from src.server import app

    route = _metadata_route(app)
    if "OPTIONS" not in (route.methods or set()):
        pytest.skip("route does not advertise OPTIONS")
    status, _, _ = _call(route, method="OPTIONS")
    assert status < 400


def test_override_is_a_noop_when_disabled():
    identity = SimpleNamespace(oauth_resource_id=None)
    app = SimpleNamespace(routes=[])
    apply_oauth_resource_override(app, SimpleNamespace(identity=identity))
    assert app.routes == []


def test_override_raises_when_the_route_is_missing():
    identity = SimpleNamespace(oauth_resource_id="api://x")
    app = SimpleNamespace(routes=[])
    with pytest.raises(RuntimeError, match="0 protected-resource metadata"):
        apply_oauth_resource_override(app, SimpleNamespace(identity=identity))
