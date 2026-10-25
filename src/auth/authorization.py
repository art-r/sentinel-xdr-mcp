"""Caller authorisation - a pure function over already-verified JWT claims.

Design change vs the original spec (see report.md H-1 / H-2b): authorisation is
an Entra **app role**, not an OBO exchange plus a Graph group lookup.

  * humans    -> app role `Sentinel.Read`, assigned to the SOC security group
  * the agent -> app role `MCP.Agent`, assigned directly to its managed identity
                 (Entra does NOT emit a roles claim for a service principal that
                  gains a role via group membership - assign it directly)

Consequences: no confidential client, no certificate or Key Vault secret, no
Graph permission, no network call in the request path, no cache to poison or
lock an analyst out of, and no failure mode to fail-closed around. The decision
is a set membership test on a signature-verified token.

Token-type discrimination is explicit and must stay that way: a delegated token
that happens to carry `roles: ["MCP.Agent"]` must never be treated as the agent,
otherwise a user assigned the wrong role gains write access.
"""

from __future__ import annotations

from .caller import CallerContext


def is_app_only(claims: dict) -> bool:
    """True for a client-credentials (app-only) token.

    Entra sets `idtyp=app` on v2 app-only tokens, but ONLY if `idtyp` has been
    added to the app registration's optional claims (README section 2.10). The
    fallback covers tenants where it has not: app-only tokens never carry `scp`,
    delegated tokens always do.
    """
    if claims.get("idtyp") == "app":
        return True
    return "scp" not in claims and bool(claims.get("roles"))


def _scopes(claims: dict) -> set[str]:
    raw = claims.get("scp") or claims.get("scope") or ""
    if isinstance(raw, (list, tuple)):
        return set(raw)
    return set(raw.split())


def authorize(claims: dict, config) -> CallerContext | None:
    """Return the caller, or None if the token must be rejected (401)."""
    ident = config.identity
    roles = set(claims.get("roles") or [])
    app_id = claims.get("azp") or claims.get("appid")
    if not app_id:
        return None

    if is_app_only(claims):
        if ident.required_agent_role not in roles:
            return None
        if app_id not in ident.allowed_agent_app_ids:
            return None
        return CallerContext(
            type="agent",
            id=app_id,
            name="investigation-agent",
            client_app_id=app_id,
            claims=claims,
        )

    oid = claims.get("oid")
    if not oid:
        return None
    if ident.required_delegated_scope not in _scopes(claims):
        return None
    if ident.required_human_role not in roles:
        return None
    # Pre-authorisation in Entra only suppresses the consent prompt; it does not
    # restrict which client applications may request the scope. Check azp.
    if app_id not in ident.allowed_client_app_ids:
        return None
    return CallerContext(
        type="human",
        id=oid,
        name=claims.get("preferred_username") or claims.get("upn") or "unknown",
        client_app_id=app_id,
        claims=claims,
    )


def denial_reason(claims: dict, config) -> str:
    """Coarse, non-leaky reason for the audit log. Never returned to the caller.

    Mirrors `authorize()` check-for-check and in the same order, so the reason
    always names the first failing condition rather than falling through to a
    catch-all.
    """
    ident = config.identity
    roles = set(claims.get("roles") or [])
    app_id = claims.get("azp") or claims.get("appid")
    if not app_id:
        return "no_client_app_id"

    if is_app_only(claims):
        if ident.required_agent_role not in roles:
            return "missing_agent_role"
        if app_id not in ident.allowed_agent_app_ids:
            return "agent_app_not_allowlisted"
        return "authorized"

    if not claims.get("oid"):
        return "no_oid"
    if ident.required_delegated_scope not in _scopes(claims):
        return "missing_scope"
    if ident.required_human_role not in roles:
        return "missing_role"
    if app_id not in ident.allowed_client_app_ids:
        return "client_app_not_allowlisted"
    return "authorized"
