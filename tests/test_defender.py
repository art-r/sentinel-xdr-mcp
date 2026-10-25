"""Defender advanced hunting: the second app role, the second validator
profile, and the tenant-wide-access guards in config.

Uses `defender_env` rather than `env`: the shipped example config has
defender.enabled false, which is the right default for a new tenant and the
wrong default for a test suite.
"""
import asyncio

import pytest
from fastmcp.exceptions import ToolError

from src import server as srv
from src.clients.defender_client import (
    HuntingQuotaExhausted,
    HuntingUnavailable,
    _to_table,
)
from src.governance.kql_validator import KQLValidator

from ._support import agent_claims, config, defender_config, defender_human_claims


def _tool():
    from src.tools.defender import query_defender_hunting

    return query_defender_hunting


class _RaisingDefender:
    def __init__(self, exc):
        self.exc = exc
        self.last_kql = None

    async def run_query(self, kql):
        raise self.exc

    async def close(self):
        pass


# ---- happy path --------------------------------------------------------

def test_tvm_table_is_reachable(defender_env):
    """The reason this integration exists: TVM tables hold no data in Sentinel."""
    defender_env.act_as(defender_human_claims())
    out = asyncio.run(_tool()(kql="DeviceTvmSoftwareVulnerabilities | take 5", ctx=None))
    assert out["row_count"] == 1
    assert defender_env.defender.last_kql.startswith("DeviceTvmSoftwareVulnerabilities")


def test_row_cap_is_compiled_in(defender_env):
    defender_env.act_as(defender_human_claims())
    asyncio.run(_tool()(kql="DeviceInfo", ctx=None))
    cap = defender_config().defender.max_result_rows + 1
    assert defender_env.defender.last_kql.rstrip().endswith(f"| take {cap}")


def test_audit_record_names_the_source(defender_env):
    """Two query tools write to one audit stream; without `source` they are
    indistinguishable."""
    defender_env.act_as(defender_human_claims())
    asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    event = defender_env.log.of("tool_invocation")[0]
    assert event["tool"] == "query_defender_hunting"
    assert event["source"] == "defender"


# ---- authorisation -----------------------------------------------------

def test_missing_defender_role_is_denied(defender_env):
    """Sentinel.Read alone must not reach the hunting corpus."""
    defender_env.act_as(
        defender_human_claims(roles=[config().identity.required_human_role]))
    with pytest.raises(ToolError):
        asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert defender_env.defender.last_kql is None
    assert defender_env.log.of("access_denied")[0]["reason"] == "missing_defender_role"


def test_agent_cannot_hunt(defender_env):
    """Config._check forbids the pairing; the tool refuses independently."""
    defender_env.act_as(agent_claims())
    with pytest.raises(ToolError):
        asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert defender_env.defender.last_kql is None


def test_unauthenticated_caller_is_refused(defender_env):
    defender_env.act_as(None)
    with pytest.raises(ToolError):
        asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert defender_env.defender.last_kql is None


# ---- validator profile -------------------------------------------------

def test_enrichment_functions_are_rejected(defender_env):
    """They return data beyond the named tables, which would make
    `extracted_tables` in the audit record untrue."""
    defender_env.act_as(defender_human_claims())
    for query in (
        "DeviceFileEvents | invoke FileProfile(SHA1, 100)",
        "DeviceInfo | extend x = SeenBy(DeviceId)",
        "DeviceInfo | extend ip = AssignedIPAddresses(DeviceId)",
        "DeviceNetworkInfo | extend d = DeviceFromIP(RemoteIP)",
    ):
        with pytest.raises(ToolError):
            asyncio.run(_tool()(kql=query, ctx=None))
    assert defender_env.defender.last_kql is None


def test_unlisted_defender_table_is_rejected(defender_env):
    defender_env.act_as(defender_human_claims())
    with pytest.raises(ToolError):
        asyncio.run(_tool()(kql="EmailAttachmentInfo | take 5", ctx=None))
    assert defender_env.defender.last_kql is None


def test_the_two_validator_profiles_do_not_bleed():
    """A Sentinel table is not reachable through the Defender profile."""
    cfg = defender_config()
    defender = KQLValidator(cfg, source="defender")
    assert not defender.validate("SecurityIncident | take 5", "human").is_valid
    assert defender.validate("DeviceInfo | take 5", "human").is_valid


def test_defender_tables_are_an_explicit_allowlist():
    cfg = defender_config()
    assert cfg.is_defender_table_allowed("DeviceTvmSoftwareVulnerabilities")
    assert not cfg.is_defender_table_allowed("SomeUnlistedTable")
    assert not cfg.is_defender_table_allowed("SecurityIncident")


# ---- failure paths -----------------------------------------------------

def test_upstream_error_text_never_escapes(defender_env, monkeypatch):
    defender_env.act_as(defender_human_claims())
    monkeypatch.setattr(srv.deps, "_defender_client",
                        _RaisingDefender(HuntingUnavailable("HTTPStatusError")))
    with pytest.raises(ToolError) as err:
        asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert "HTTPStatusError" not in str(err.value)
    assert "HTTPStatusError" not in defender_env.log.dumps()
    assert defender_env.log.of("tool_failed")[0]["error_class"] == "HuntingUnavailable"


def test_quota_exhaustion_is_audited(defender_env, monkeypatch):
    defender_env.act_as(defender_human_claims())
    monkeypatch.setattr(srv.deps, "_defender_client",
                        _RaisingDefender(HuntingQuotaExhausted("budget gone")))
    with pytest.raises(ToolError):
        asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert defender_env.log.of("access_denied")[0]["reason"] == "defender_quota_exhausted"


def test_results_are_never_logged(defender_env):
    defender_env.act_as(defender_human_claims())
    defender_env.defender.payload = {
        "columns": ["Cve"], "rows": [["CVE-SECRETPAYLOAD"]],
        "partial": False, "partial_error": None,
    }
    out = asyncio.run(_tool()(kql="DeviceTvmSoftwareVulnerabilities | take 5", ctx=None))
    assert out["rows"][0][0] == "CVE-SECRETPAYLOAD"
    assert "SECRETPAYLOAD" not in defender_env.log.dumps()


def test_output_is_labelled_untrusted(defender_env):
    defender_env.act_as(defender_human_claims())
    out = asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert "content_warning" in out


# ---- disabled path -----------------------------------------------------

def test_tool_refuses_when_defender_is_disabled(env):
    """Plain `env`: the shipped example config has defender disabled."""
    if config().defender is not None and config().defender.enabled:
        pytest.skip("defender is enabled in this checkout's config")
    env.act_as(defender_human_claims())
    with pytest.raises(ToolError):
        asyncio.run(_tool()(kql="DeviceInfo | take 5", ctx=None))
    assert env.defender.last_kql is None


# ---- graph response shape ----------------------------------------------

def test_graph_response_shape_is_converted():
    """Column order comes from `schema`, so a row missing a key still aligns."""
    out = _to_table({
        "schema": [{"Name": "A", "Type": "String"}, {"Name": "B", "Type": "Int"}],
        "results": [{"A": "x", "B": 1}, {"B": 2}],
    })
    assert out["columns"] == ["A", "B"]
    assert out["rows"] == [["x", 1], [None, 2]]


def test_graph_empty_response_is_safe():
    out = _to_table({})
    assert out["columns"] == [] and out["rows"] == []