"""Authorisation matrix. This is the highest-value test file in the repo:
the C-1 defect (app-only tokens rejected outright) would have been caught by
test_agent_token_is_authorized alone.
"""
from src.auth.authorization import authorize, is_app_only

from ._support import OMIT, agent_claims, config, human_claims


# verify the sdk and function flow
def test_verifier_hook_matches_sdk():
    """The bearer backend must call a method EntraCallerVerifier overrides."""
    import inspect
    import mcp.server.auth.middleware.bearer_auth as backend
    src = inspect.getsource(backend.BearerAuthBackend.authenticate)
    assert "verify_token" in src, "MCP SDK changed the token-verifier hook name"


def test_only_one_hook_is_overridden():
    """Overriding both names closes the base class's internal alias into
    infinite recursion. See src/auth/setup.py docstring point 2."""
    from src.auth.setup import EntraCallerVerifier
    assert "verify_token" in vars(EntraCallerVerifier)
    assert "load_access_token" not in vars(EntraCallerVerifier)

# ---- app-only (agent) --------------------------------------------------

def test_agent_token_is_authorized():
    caller = authorize(agent_claims(), config())
    assert caller is not None, "app-only token with the agent role must authenticate"
    assert caller.type == "agent"


def test_agent_without_idtyp_still_detected():
    """Not every tenant emits idtyp; absence of scp + presence of roles is the fallback."""
    claims = agent_claims(idtyp=OMIT)
    assert is_app_only(claims)
    assert authorize(claims, config()).type == "agent"


def test_agent_with_wrong_app_id_denied():
    assert authorize(agent_claims(appid="99999999-9999-9999-9999-999999999999",
                                  azp="99999999-9999-9999-9999-999999999999"), config()) is None


def test_agent_without_role_denied():
    assert authorize(agent_claims(roles=[]), config()) is None


# ---- delegated (human) -------------------------------------------------

def test_human_token_is_authorized():
    caller = authorize(human_claims(), config())
    assert caller is not None and caller.type == "human"
    assert caller.name == "analyst@corp.example"


def test_human_without_role_denied():
    assert authorize(human_claims(roles=[]), config()) is None


def test_human_without_scope_denied():
    assert authorize(human_claims(scp="openid profile"), config()) is None


def test_human_from_unlisted_client_app_denied():
    """Entra pre-authorisation is consent suppression, not access control."""
    assert authorize(human_claims(azp="99999999-9999-9999-9999-999999999999"), config()) is None


def test_human_without_oid_denied():
    assert authorize(human_claims(oid=OMIT), config()) is None


# ---- privilege escalation ---------------------------------------------

def test_delegated_token_with_agent_role_is_not_the_agent():
    """A user mis-assigned MCP.Agent must not gain the agent's write access."""
    cfg = config()
    caller = authorize(human_claims(roles=[cfg.identity.required_agent_role]), cfg)
    assert caller is None or caller.type != "agent"


def test_agent_role_alongside_human_role_stays_human():
    cfg = config()
    claims = human_claims(roles=[cfg.identity.required_human_role, cfg.identity.required_agent_role])
    caller = authorize(claims, cfg)
    assert caller is not None and caller.type == "human"


def test_no_client_app_id_denied():
    assert authorize(human_claims(azp=OMIT), config()) is None
    assert authorize({}, config()) is None


# ---- tool scoping ------------------------------------------------------

def test_tool_scoping_matches_tier():
    cfg = config()
    assert "add_incident_comment" in cfg.governance["agent"].allowed_tools
    assert "add_incident_comment" not in cfg.governance["human"].allowed_tools


def test_write_tools_get_a_smaller_budget():
    agent = config().governance["agent"]
    assert agent.rate_limit_for("add_incident_comment") < agent.rate_limit_for("query_sentinel_logs")


# ---- the verifier itself ----------------------------------------------

def _run_verifier(claims):
    """Drive EntraCallerVerifier with a base class that returns `claims`.

    Patches and calls `verify_token` - the hook BearerAuthBackend uses, and the
    only one EntraCallerVerifier overrides. Patching `load_access_token` here
    worked by accident; when the override moved, the patched base answered
    directly and these tests stopped exercising any of our code at all.
    """
    import asyncio
    from unittest.mock import patch

    from fastmcp.server.auth.providers.jwt import JWTVerifier

    from src.auth.setup import EntraCallerVerifier
    from src.logging_setup import AuditLogger

    from ._support import CollectingLogger

    assert "verify_token" in vars(EntraCallerVerifier), \
        "harness patches a hook the verifier does not override"

    log = CollectingLogger()
    cfg = config()
    verifier = EntraCallerVerifier(cfg, audit=AuditLogger(cfg, logger=log))

    class _AccessToken:
        def __init__(self, c):
            self.claims = c

    reached_base = []

    async def _fake(self, token):
        reached_base.append(token)
        return _AccessToken(claims)

    with patch.object(JWTVerifier, "verify_token", _fake):
        result = asyncio.run(verifier.verify_token("the-raw-token"))

    # Without this, a harness that bypasses the override reports four passes.
    assert reached_base == ["the-raw-token"], "base verifier not reached via super()"
    return result, log


def test_verifier_denies_and_audits_an_unauthorized_token():
    """Authorisation runs inside the verifier, so an unauthorised token gets a
    real 401 and leaves an audit trail. `denial_reason()` used to be dead code
    (report round 2, H-4)."""
    claims = human_claims(roles=[])          # signature-valid, but no app role
    result, log = _run_verifier(claims)
    assert result is None
    denial = log.of("authentication_denied")[0]
    assert denial["reason"] == "missing_role"
    assert denial["client_app_id"] == claims["azp"]
    assert "the-raw-token" not in log.dumps()   # the token is never logged


def test_verifier_denies_an_unlisted_client_app():
    claims = human_claims(azp="99999999-9999-9999-9999-999999999999")
    result, log = _run_verifier(claims)
    assert result is None
    assert log.of("authentication_denied")[0]["reason"] == "client_app_not_allowlisted"


def test_verifier_admits_an_authorized_agent_token():
    result, log = _run_verifier(agent_claims())
    assert result is not None
    assert log.of("authentication_denied") == []


def test_verifier_admits_an_authorized_human_token():
    result, log = _run_verifier(human_claims())
    assert result is not None
    assert log.of("authentication_denied") == []
