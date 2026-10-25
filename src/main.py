"""Entrypoint. `app` is the ASGI app uvicorn serves (Dockerfile CMD).

Note: FastMCP exposes the ASGI app via http_app(), not get_app(). The __main__
path runs the *same* `app` object rather than mcp.run(), so a locally started
server has exactly the same middleware stack (host-header validation included)
as the container.
"""

from src.server import app, config, mcp  # noqa: F401

UVICORN_OPTIONS = dict(
    host=config.server.host,
    port=config.server.port,
    # Rate, concurrency and readiness-cache state is process-local. Explicit,
    # so a stray WEB_CONCURRENCY in the environment cannot fan this out.
    workers=1,
    access_log=False,
    # Do not advertise the ASGI server to unauthenticated callers.
    server_header=False,
    # ACA terminates TLS at Envoy and forwards over plain HTTP from a pod IP,
    # which uvicorn does not trust by default. Without this the request scope
    # says scheme="http" and every generated absolute URL - notably the
    # /mcp/ -> /mcp trailing-slash redirect - points at http://. A client that
    # follows it either strips the Authorization header (httpx: silent 401) or
    # sends the bearer token in cleartext (curl -L). The container is only
    # reachable through ingress, so trusting the forwarded scheme is sound.
    proxy_headers=True,
    forwarded_allow_ips="*",
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, **UVICORN_OPTIONS)
