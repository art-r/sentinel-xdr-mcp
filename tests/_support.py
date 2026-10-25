"""Shared test helpers. No cloud dependencies."""

from __future__ import annotations

import copy
import os
from functools import lru_cache

from src.config import load_config, Config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, "config", "mcp-server-config.example.yaml")
AGENT_APP_ID = "11111111-2222-3333-4444-555555555555"  # test-only, not policy


class _Omit:
    def __repr__(self):
        return "<omit>"


OMIT = _Omit()


@lru_cache(maxsize=1)
def config():
    """The real shipped config - so the tests also validate the YAML."""
    return load_config(CONFIG_PATH)


def _merge(base: dict, overrides: dict) -> dict:
    base.update(overrides)
    return {k: v for k, v in base.items() if not isinstance(v, _Omit)}


def human_claims(**overrides) -> dict:
    cfg = config()
    roles = [cfg.identity.required_human_role]
    if cfg.defender is not None:
        roles.append(cfg.defender.required_role)
    return _merge(
        {
            "oid": "aaaaaaaa-0000-0000-0000-000000000001",
            "azp": cfg.identity.allowed_client_app_ids[0],
            "scp": cfg.identity.required_delegated_scope,
            "roles": roles,
            "preferred_username": "analyst@corp.example",
        },
        overrides,
    )


def agent_claims(**overrides) -> dict:
    cfg = config()
    return _merge(
        {
            "idtyp": "app",
            "appid": AGENT_APP_ID,
            "azp": cfg.identity.allowed_agent_app_ids[0],
            "roles": [cfg.identity.required_agent_role],
        },
        overrides,
    )


class CollectingLogger:
    """Stands in for a structlog logger so tests can assert on what was
    actually emitted - including what was NOT emitted."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def _record(self, level, event, **kw):
        self.events.append((level, event, kw))

    def info(self, event, **kw):
        self._record("info", event, **kw)

    def warning(self, event, **kw):
        self._record("warning", event, **kw)

    def error(self, event, **kw):
        self._record("error", event, **kw)

    def of(self, event: str) -> list[dict]:
        return [kw for _, name, kw in self.events if name == event]

    def dumps(self) -> str:
        import json

        return json.dumps(self.events, default=str)


# --- config variants ----------------------------------------------------

#: Defender block used by the hunting tests. The example config ships
#: `defender.enabled: false` - the correct default for a new tenant - so
#: without this the entire Defender suite would silently skip, in CI too.
#: Built from the shipped policy rather than a hand-made stub, so the block
#: still has to satisfy every Config validator.
_DEFENDER_OVERLAY = {
    "enabled": True,
    "graph_base_url": "https://graph.microsoft.com/v1.0",
    "timeout_seconds": 170,
    "max_result_rows": 5000,
    "max_result_size_mb": 10,
    "max_cell_chars": 4096,
    "calls_per_minute": 10,
    "daily_call_budget": 500,
    "required_role": "Defender.Hunt",
    "allowed_tables": [
        "DeviceTvmSoftwareInventory",
        "DeviceTvmSoftwareVulnerabilities",
        "DeviceTvmSoftwareVulnerabilitiesKB",
        "DeviceTvmSecureConfigurationAssessment",
        "DeviceTvmSecureConfigurationAssessmentKB",
        "DeviceTvmBrowserExtensions",
        "DeviceInfo",
        "DeviceNetworkInfo",
        "AlertInfo",
        "AlertEvidence",
    ],
    "blocked_tables": [],
    "kql": {
        "max_query_length": 4000,
        "banned_functions": [
            "FileProfile",
            "SeenBy",
            "AssignedIPAddresses",
            "DeviceFromIP",
            "workspace",
            "cluster",
            "app",
            "database",
            "externaldata",
            "toscalar",
            "materialize",
            "datatable",
        ],
        "banned_operators": [
            "let",
            "search",
            "find",
            "lookup",
            "evaluate",
            "invoke",
            "externaldata",
            "datatable",
            "range",
            "print",
            "partition",
            "facet",
            "fork",
        ],
    },
}


@lru_cache(maxsize=1)
def defender_config():
    """The shipped policy with Defender hunting enabled on the human tier."""
    data = copy.deepcopy(config().model_dump(mode="json"))
    data["defender"] = copy.deepcopy(_DEFENDER_OVERLAY)
    tools = data["governance"]["human"]["allowed_tools"]
    if "query_defender_hunting" not in tools:
        tools.append("query_defender_hunting")
    return Config.model_validate(data)


def defender_human_claims(**overrides) -> dict:
    """A human caller holding both required roles."""
    cfg = defender_config()
    claims = human_claims(**overrides)
    if "roles" not in overrides:
        claims["roles"] = [cfg.identity.required_human_role, cfg.defender.required_role]
    return claims


# --- fakes --------------------------------------------------------------
#
# No test performs network I/O. CI has no Azure credentials and no egress, and
# that is a property to defend, not a limitation to work around.


class _Token:
    def __init__(self, claims):
        self.claims = claims


class FakeLAW:
    def __init__(self, result=None, exc=None):
        self.result = result or {
            "columns": ["C"],
            "rows": [["v"]],
            "partial": False,
            "partial_error": None,
        }
        self.exc = exc
        self.last_kql = None
        self.last_timespan = None
        self.ready_calls = 0

    async def query(self, kql, timespan, server_timeout):
        self.last_kql = kql
        self.last_timespan = timespan
        if self.exc:
            raise self.exc
        return self.result

    async def get_table_schema(self, table_name):
        if self.exc:
            raise self.exc
        return [{"ColumnName": "TimeGenerated", "ColumnType": "datetime"}]

    async def list_workspace_tables(self, days: int = 7):
        # Same parse as the real client, so a response-shape change breaks both.
        from src.clients.law_client import parse_datatype_names

        if self.exc:
            raise self.exc
        return parse_datatype_names(await self.query("Usage | summarize by DataType", None, 60))

    async def check_workspace_access(self):
        self.ready_calls += 1
        if self.exc:
            raise self.exc

    async def close(self):
        pass


class FakeSentinel:
    def __init__(self, exc=None):
        self.exc = exc
        self.comments = []

    async def get_incident(self, number):
        if self.exc:
            raise self.exc
        return {"id": "guid", "incident_number": int(number), "title": "t\u200bitle"}

    async def get_incident_entities(self, number):
        if self.exc:
            raise self.exc
        return [{"entity_type": "Ip", "properties": {"address": "10.0.0.1"}}]

    async def add_comment(self, number, message):
        if self.exc:
            raise self.exc
        self.comments.append((number, message))
        return {"success": True, "comment_id": "cid"}

    async def close(self):
        pass


class FakeDefender:
    def __init__(self, payload=None, exc=None):
        self.payload = payload or {
            "columns": ["DeviceName"],
            "rows": [["host1"]],
            "partial": False,
            "partial_error": None,
        }
        self.exc = exc
        self.last_kql = None

    async def run_query(self, kql):
        self.last_kql = kql
        if self.exc:
            raise self.exc
        return self.payload

    async def close(self):
        pass
