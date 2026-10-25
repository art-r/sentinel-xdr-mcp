"""Tool behaviour, end to end from the tool function down to a stubbed client.

Importing this module imports `src.server`, which builds the real FastMCP
instance, the real auth provider and registers the real tools - so a wiring
error (a bad decorator, a missing import, a tool that cannot resolve its caller)
fails here rather than in production.
"""
import asyncio
import copy

import pytest
from fastmcp.exceptions import ToolError

from src import server as srv
from src.tools.comments import add_incident_comment
from src.tools.incidents import get_incident, get_incident_entities
from src.tools.query_logs import query_sentinel_logs
from src.tools.schema_discovery import get_table_schema, list_available_tables

from ._support import (
    FakeLAW, FakeSentinel, agent_claims, config, human_claims,
    defender_human_claims, defender_config
)

# ---- caller resolution (the C-1 regression) ----------------------------

def test_tools_refuse_to_run_without_an_authenticated_caller(env):
    for call in (
        lambda: list_available_tables(ctx=None),
        lambda: get_incident(incident_id="1", ctx=None),
        lambda: query_sentinel_logs(kql="SecurityAlert | take 1", ctx=None),
    ):
        with pytest.raises(ToolError):
            asyncio.run(call())


def test_list_available_tables_is_audited(env):
    env.act_as(human_claims())
    tables = asyncio.run(list_available_tables(ctx=None))["sentinel"]
    event = env.log.of("tool_invocation")[0]
    assert event["tool"] == "list_available_tables"
    assert event["result_row_count"] == len(tables)


def test_tool_sees_the_right_caller(env):
    """Regression for C-1: the caller reached the tool as an unawaited
    coroutine, so every tool failed with AttributeError."""
    env.act_as(human_claims())
    human = asyncio.run(list_available_tables(ctx=None))["sentinel"]
    env.act_as(agent_claims())
    agent = asyncio.run(list_available_tables(ctx=None))["sentinel"]
    assert human and agent
    assert set(human) == config().allowed_tables_for("human")
    assert set(agent) == config().allowed_tables_for("agent")


def test_readiness_checks_workspace_query_access(env, monkeypatch):
    monkeypatch.setattr(srv.deps, "_ready", (None, False, "not checked"))
    ok, detail = asyncio.run(srv.deps.check_ready(ttl=0))
    assert ok is True and detail == "ok"
    assert env.law.ready_calls == 1


# ---- query_sentinel_logs ----------------------------------------------

def test_query_runs_and_applies_the_row_cap(env):
    env.act_as(human_claims())
    out = asyncio.run(query_sentinel_logs(kql="SecurityAlert", ctx=None, timespan="P1D"))
    assert out["row_count"] == 1
    assert "content_warning" in out
    assert env.law.last_kql.rstrip().endswith("| take 5001")


def test_query_rejects_invalid_kql_before_touching_the_client(env):
    env.act_as(human_claims())
    with pytest.raises(ToolError):
        asyncio.run(query_sentinel_logs(kql="Heartbeat | take 5", ctx=None))
    assert env.law.last_kql is None


def test_query_timespan_is_capped_at_the_tier_ceiling(env):
    from datetime import timedelta
    env.act_as(agent_claims())
    asyncio.run(query_sentinel_logs(kql="SecurityAlert | take 5", ctx=None, timespan="P365D"))
    assert env.law.last_timespan == timedelta(days=config().governance["agent"].max_timespan_days)


def test_query_failure_is_audited_and_the_message_is_generic(env, monkeypatch):
    env.act_as(human_claims())
    monkeypatch.setattr(srv.deps, "_law_client",
                        FakeLAW(exc=RuntimeError("BadRequest: 'secret-host' not found")))
    with pytest.raises(ToolError) as err:
        asyncio.run(query_sentinel_logs(kql="SecurityAlert | take 5", ctx=None))
    assert "secret-host" not in str(err.value)
    assert "secret-host" not in env.log.dumps()
    assert env.log.of("tool_failed")[0]["error_class"] == "RuntimeError"


def test_query_results_are_never_logged(env):
    env.act_as(agent_claims())
    env.law.result = {"columns": ["Cmd"], "rows": [["powershell -enc SECRETPAYLOAD"]],
                      "partial": False, "partial_error": None}
    out = asyncio.run(query_sentinel_logs(kql="SecurityAlert | take 5", ctx=None))
    assert out["rows"][0][0] == "powershell -enc SECRETPAYLOAD"
    assert "SECRETPAYLOAD" not in env.log.dumps()


def test_partial_results_are_reported(env):
    env.act_as(human_claims())
    env.law.result = {"columns": ["C"], "rows": [["v"]], "partial": True,
                      "partial_error": "HttpResponseError"}
    out = asyncio.run(query_sentinel_logs(kql="SecurityAlert | take 5", ctx=None))
    assert out["partial"] is True and "partial_note" in out


# ---- incidents ---------------------------------------------------------

def test_get_incident_scrubs_and_labels(env):
    env.act_as(human_claims())
    out = asyncio.run(get_incident(incident_id="42", ctx=None))
    assert out["title"] == "title"          # zero-width stripped
    assert "content_warning" in out


def test_get_incident_not_found_keeps_its_message(env, monkeypatch):
    env.act_as(human_claims())
    monkeypatch.setattr(srv.deps, "_sentinel_client",
                        FakeSentinel(exc=ValueError("Incident 42 not found")))
    with pytest.raises(ToolError) as err:
        asyncio.run(get_incident(incident_id="42", ctx=None))
    assert "not found" in str(err.value)


def test_get_incident_backend_error_is_generic(env, monkeypatch):
    env.act_as(human_claims())
    monkeypatch.setattr(srv.deps, "_sentinel_client",
                        FakeSentinel(exc=RuntimeError("subscription /subs/abc denied")))
    with pytest.raises(ToolError) as err:
        asyncio.run(get_incident(incident_id="42", ctx=None))
    assert "/subs/abc" not in str(err.value)
    assert "/subs/abc" not in env.log.dumps()


def test_get_incident_entities_is_capped(env):
    env.act_as(human_claims())
    out = asyncio.run(get_incident_entities(incident_id="42", ctx=None))
    assert out["count"] == 1 and out["truncated"] is False


# ---- schema ------------------------------------------------------------

def test_get_table_schema_refuses_a_table_outside_the_tier(env):
    env.act_as(human_claims())
    with pytest.raises(ToolError):
        asyncio.run(get_table_schema(table_name="Heartbeat", ctx=None))


def test_get_table_schema_returns_columns(env):
    env.act_as(human_claims())
    out = asyncio.run(get_table_schema(table_name="SigninLogs", ctx=None))
    assert out["count"] == 1 and out["items"][0]["ColumnName"] == "TimeGenerated"

def test_schema_of_a_defender_table_routes_to_defender(defender_env):
    defender_env.act_as(defender_human_claims())
    defender_env.defender.payload = {
        "columns": ["ColumnName", "ColumnType"],
        "rows": [["DeviceId", "string"]],
        "partial": False, "partial_error": None,
    }
    out = asyncio.run(get_table_schema(
        table_name="DeviceTvmSoftwareVulnerabilities", ctx=None, source="defender"))
    assert out["count"] == 1
    assert defender_env.defender.last_kql.startswith("DeviceTvmSoftwareVulnerabilities")
    assert defender_env.law.last_kql is None


# ---- add_incident_comment ---------------------------------------------

def test_comment_is_refused_for_a_human_even_if_middleware_is_bypassed(env):
    """Defence in depth: the tool re-checks what middleware already enforced."""
    env.act_as(human_claims())
    with pytest.raises(ToolError):
        asyncio.run(add_incident_comment(incident_id="42", comment="hi", ctx=None))
    assert env.sentinel.comments == []
    assert env.log.of("access_denied")[0]["reason"] == "human_called_agent_tool"


def test_comment_is_written_with_attribution_and_neutralised_markdown(env):
    env.act_as(agent_claims())
    out = asyncio.run(add_incident_comment(
        incident_id="42",
        comment="found ![](https://attacker.example/?q=x) and <https://attacker.example>",
        ctx=None))
    number, message = env.sentinel.comments[0]
    assert number == "42"
    assert out["correlation_id"] in message
    assert "![](" not in message
    assert "<https" not in message
    assert "attacker.example" in message  # content preserved, rendering neutralised

def test_discovery_returns_the_live_table_list_under_workspace_policy(env):
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    env.law.result = {
        "columns": ["DataType"],
        "rows": [["AzureDiagnostics"], ["SecurityAlert"], ["Heartbeat"]],
        "partial": False,
        "partial_error": None,
    }
    tables = asyncio.run(list_available_tables(ctx=None))["sentinel"]
    assert "AzureDiagnostics" in tables      # not in any tier
    assert "Heartbeat" not in tables         # blocked wins


def test_discovery_falls_back_to_config_when_enumeration_fails(env):
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    env.law.result = {"columns": ["C"], "rows": [["v"]], "partial": False,
                      "partial_error": None}
    tables = asyncio.run(list_available_tables(ctx=None))["sentinel"]
    assert set(tables) == config().allowed_tables_for("human")


def test_query_against_an_unlisted_table_is_accepted_for_a_human(env):
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    asyncio.run(query_sentinel_logs(kql="AzureDiagnostics | take 5", ctx=None))
    assert env.law.last_kql.startswith("AzureDiagnostics")


def test_query_against_an_unlisted_table_is_refused_for_the_agent(env):
    env.act_as(agent_claims())
    with pytest.raises(ToolError):
        asyncio.run(query_sentinel_logs(kql="AzureDiagnostics | take 5", ctx=None))
    assert env.law.last_kql is None

def test_zero_rows_from_a_schema_only_table_is_explained(env):
    """A schema-only table (e.g. DeviceTvmSoftwareVulnerabilities) returns zero
    rows with no error. Without the note the model reports 'no findings'."""
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    monkeypatch_result = {"columns": ["DataType"],
                          "rows": [["SecurityAlert"], ["SigninLogs"]],
                          "partial": False, "partial_error": None}
    env.law.result = monkeypatch_result          # discovery call
    asyncio.run(srv.deps.workspace_tables(ttl=0))  # prime the cache
    env.law.result = {"columns": ["C"], "rows": [], "partial": False, "partial_error": None}
    out = asyncio.run(query_sentinel_logs(kql="DeviceTvmSoftwareVulnerabilities", ctx=None))
    assert out["row_count"] == 0
    assert "schema-only" in out["note"] or "advanced hunting" in out["note"]

def test_zero_rows_from_a_schema_only_table_is_explained_query_defender(env):
    """A schema-only table returns zero rows with no error. Without the note
    the model reports 'no findings' on a security question."""
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    env.law.result = {"columns": ["DataType"],
                      "rows": [["SecurityAlert"], ["SigninLogs"]],
                      "partial": False, "partial_error": None}
    asyncio.run(srv.deps.workspace_tables(ttl=0))   # prime the discovery cache

    env.law.result = {"columns": ["C"], "rows": [], "partial": False,
                      "partial_error": None}
    out = asyncio.run(query_sentinel_logs(
        kql="DeviceTvmSoftwareVulnerabilities", ctx=None))
    assert out["row_count"] == 0
    assert "query_defender_hunting" in out["note"]


def test_zero_rows_from_a_live_table_gets_no_note(env):
    """The note must not fire on an ordinary empty result, or it trains the
    model to distrust every zero-row answer."""
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    env.law.result = {"columns": ["DataType"], "rows": [["SecurityAlert"]],
                      "partial": False, "partial_error": None}
    asyncio.run(srv.deps.workspace_tables(ttl=0))

    env.law.result = {"columns": ["C"], "rows": [], "partial": False,
                      "partial_error": None}
    out = asyncio.run(query_sentinel_logs(
        kql="SecurityAlert | where Computer == 'nope'", ctx=None))
    assert "note" not in out


def test_no_note_when_discovery_is_unavailable(env):
    """An empty discovery result must not be read as 'every table is absent'."""
    if config().table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    env.act_as(human_claims())
    env.law.result = {"columns": ["C"], "rows": [], "partial": False,
                      "partial_error": None}
    out = asyncio.run(query_sentinel_logs(kql="SecurityAlert", ctx=None))
    assert "note" not in out

def test_discovery_returns_both_stores_by_default(defender_env):
    """The model must see the Defender store without being told to ask for it."""
    defender_env.act_as(defender_human_claims())
    defender_env.law.result = {"columns": ["DataType"], "rows": [["SecurityAlert"]],
                               "partial": False, "partial_error": None}
    out = asyncio.run(list_available_tables(ctx=None))
    assert set(out) == {"sentinel", "defender"}
    assert "DeviceTvmSoftwareVulnerabilities" in out["defender"]


def test_discovery_omits_defender_without_the_role(defender_env):
    defender_env.act_as(
        defender_human_claims(roles=[config().identity.required_human_role]))
    defender_env.law.result = {"columns": ["DataType"], "rows": [["SecurityAlert"]],
                               "partial": False, "partial_error": None}
    out = asyncio.run(list_available_tables(ctx=None))
    assert "defender" not in out
    assert "sentinel" in out

def test_defender_store_is_not_advertised_without_the_query_tool(defender_env,
                                                                 monkeypatch):
    """Advertising a store the caller cannot query is what produced the
    'discoverable but not queryable' report."""

    data = copy.deepcopy(defender_config().model_dump(mode="json"))
    tools = data["governance"]["human"]["allowed_tools"]
    data["governance"]["human"]["allowed_tools"] = [
        t for t in tools if t != "query_defender_hunting"
    ]
    # Bypass Config._check via construction from an already-validated dict is
    # not possible - the rule in section 2 rejects this state. Patch the tier
    # list on the live object instead, which is what a stale image looks like.
    cfg = defender_config()
    monkeypatch.setattr(cfg.governance["human"], "allowed_tools",
                        data["governance"]["human"]["allowed_tools"])
    monkeypatch.setattr(srv.deps, "config", cfg)

    defender_env.act_as(defender_human_claims())
    defender_env.law.result = {"columns": ["DataType"], "rows": [["SecurityAlert"]],
                               "partial": False, "partial_error": None}
    out = asyncio.run(list_available_tables(ctx=None))
    assert "defender" not in out
    assert "sentinel" in out
