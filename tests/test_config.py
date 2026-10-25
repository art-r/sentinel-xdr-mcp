"""Config must fail CLOSED and fail at STARTUP."""
import copy
import glob
import os
import subprocess
import ast
import asyncio
import inspect
import pathlib

import pytest
from pydantic import ValidationError

from src.config import Config, load_config

from ._support import AGENT_APP_ID, config, defender_config

CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config"
)
TOOLS_DIR = pathlib.Path(__file__).resolve().parent.parent / "src" / "tools"


#: Every per-tenant config in this checkout. Each is a deployable policy, and a
#: typo in one is a crash-looping container in that tenant. Collected at import
#: time so each file is a named test rather than one opaque loop.
#:
#: MUST come after CONFIG_DIR - this is module level, not a function body.
_LOCAL_CONFIGS = sorted(
    p for p in glob.glob(os.path.join(CONFIG_DIR, "*.yaml"))
    if not p.endswith(".example.yaml")
)


def _raw() -> dict:
    return copy.deepcopy(config().model_dump(mode="json"))


def _defender_raw() -> dict:
    """The shipped policy with Defender hunting ENABLED.

    Rules guarded on `defender.enabled` are inert against the example config, so
    a test that mutates the example and expects a rejection passes or fails for
    reasons unrelated to the rule it names.
    """
    return copy.deepcopy(defender_config().model_dump(mode="json"))


def _expect_invalid(mutate, base=None) -> None:
    """Mutate a valid config and assert it is rejected.

    `base` defaults to the shipped example. Pass `_defender_raw()` for any rule
    that only applies when Defender hunting is enabled.
    """
    data = _raw() if base is None else base
    mutate(data)
    try:
        Config.model_validate(data)
    except ValidationError:
        return
    raise AssertionError("config should have been rejected")

@pytest.mark.parametrize(
    "path", _LOCAL_CONFIGS or [None],
    ids=[os.path.basename(p) for p in _LOCAL_CONFIGS] or ["none-present"],
)
def test_local_configs_are_valid(path):
    """The example is what CI validates. Every per-tenant config present in the
    working tree must also load, or the build produces an image for that tenant
    which cannot start."""
    if path is None:
        pytest.skip("no per-tenant config in this checkout")
    load_config(path)


def test_only_the_example_config_is_tracked_by_git():
    """Per-tenant configs name the tenant, subscription, workspace and app
    registrations. `.gitignore` allowlists exactly one file; this asserts the
    allowlist is doing its job in THIS checkout, which CI also checks."""
    import subprocess

    try:
        tracked = subprocess.run(
            ["git", "ls-files", "config/"],
            capture_output=True, text=True, timeout=10,
            cwd=os.path.dirname(CONFIG_DIR),
        ).stdout.split()
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git not available")
    if not tracked:
        pytest.skip("not a git checkout")
    leaked = [p for p in tracked
              if p.endswith((".yaml", ".yml"))
              and not p.endswith("mcp-server-config.example.yaml")]
    assert not leaked, f"per-tenant config(s) tracked by git: {leaked}"

CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config"
)


def _raw() -> dict:
    return copy.deepcopy(config().model_dump(mode="json"))


def _defender_raw() -> dict:
    """The shipped policy with Defender hunting ENABLED.

    Rules guarded on `defender.enabled` are inert against the example config,
    so a test that mutates the example and expects a rejection passes or fails
    for reasons unrelated to the rule it names.
    """
    return copy.deepcopy(defender_config().model_dump(mode="json"))


def _expect_invalid(mutate, base=None) -> None:
    """Mutate a valid config and assert it is rejected.

    `base` defaults to the shipped example. Pass `_defender_raw()` for any rule
    that only applies when Defender hunting is enabled.
    """
    data = _raw() if base is None else base
    mutate(data)
    try:
        Config.model_validate(data)
    except ValidationError:
        return
    raise AssertionError("config should have been rejected")


def test_shipped_config_loads():
    c = config()
    assert set(c.governance) == {"human", "agent"}
    assert c.server.base_url.scheme == "https"
    assert c.server.dev_mode is False


def test_allowed_tables_excludes_blocked():
    h = config().allowed_tables_for("human")
    assert "SecurityAlert" in h and "DeviceEvents" in h
    assert "Heartbeat" not in h and "Usage" not in h


def test_table_checks_are_case_insensitive():
    c = config()
    assert c.is_table_allowed("human", "securityalert")
    assert c.is_table_blocked("heartbeat")


def test_typo_in_a_blocklist_key_is_rejected():
    """The original model silently accepted this and ran with an empty blocklist."""
    def mutate(d):
        d["kql"]["banned_function"] = d["kql"].pop("banned_functions")
    _expect_invalid(mutate)


def test_empty_banned_lists_rejected():
    _expect_invalid(lambda d: d["kql"].update(banned_functions=[]))
    _expect_invalid(lambda d: d["kql"].update(banned_operators=[]))


def test_empty_blocked_tables_rejected():
    _expect_invalid(lambda d: d["tables"].update(blocked=[]))


def test_unknown_tool_name_rejected():
    _expect_invalid(lambda d: d["governance"]["human"]["allowed_tools"].append("query_sentinal_logs"))


def test_unknown_tier_rejected():
    _expect_invalid(lambda d: d["governance"]["human"]["allowed_tables"].append("tier9"))


def test_missing_tier_rejected():
    _expect_invalid(lambda d: d["governance"].pop("agent"))


def test_human_may_not_hold_a_write_tool():
    _expect_invalid(lambda d: d["governance"]["human"]["allowed_tools"].append("add_incident_comment"))


def test_http_base_url_rejected():
    _expect_invalid(lambda d: d["server"].update(base_url="http://example.com"))


def test_host_allowlist_must_match_the_canonical_base_url_host():
    _expect_invalid(lambda d: d["server"].update(host_header_allowlist=["other.example"]))
    _expect_invalid(lambda d: d["server"].update(host_header_allowlist=["*"]))
    _expect_invalid(lambda d: d["server"].update(host_header_allowlist=["localhost"]))
    _expect_invalid(lambda d: d["server"].update(host_header_allowlist=["https://example.com"]))
    _expect_invalid(lambda d: d["server"].update(host_header_allowlist=["example.com:443"]))


def test_global_request_timeout_must_exceed_query_timeout():
    _expect_invalid(lambda d: d["server"].update(max_request_timeout_seconds=180))


def test_non_uuid_identity_rejected():
    _expect_invalid(lambda d: d["identity"].update(tenant_id="not-a-uuid"))


def test_empty_client_allowlist_rejected():
    _expect_invalid(lambda d: d["identity"].update(allowed_client_app_ids=[]))


def test_unknown_top_level_key_rejected():
    _expect_invalid(lambda d: d.update(oauth={"client_secret": "oops"}))


def test_unknown_logging_level_rejected():
    _expect_invalid(lambda d: d["logging"].update(level="TRACE"))


def test_unknown_caller_tier_in_log_policy_rejected():
    _expect_invalid(lambda d: d["logging"].update(log_query_text_for=["human", "robot"]))


def test_human_query_text_is_not_logged_by_default():
    """The shipped policy must exclude humans - the whole point of H-2."""
    assert config().logging.log_query_text_for == ["agent"]


def test_per_tier_caps_are_present_and_positive():
    for tier in config().governance.values():
        assert tier.max_entities > 0
        assert tier.max_schema_columns > 0
        assert tier.max_cell_chars > 0
        assert tier.max_result_size_bytes == tier.max_result_size_mb * 1024 * 1024

def test_workspace_policy_allows_an_unlisted_table():
    c = config()
    if c.table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    assert c.is_table_allowed("human", "AzureDiagnostics")
    assert c.is_table_allowed("human", "SomeCustomTable_CL")


def test_workspace_policy_still_refuses_blocked_tables():
    c = config()
    if c.table_policy_for("human") != "workspace":
        pytest.skip("human tier is on the allowlist in the shipped config")
    for name in c.tables.blocked:
        assert not c.is_table_allowed("human", name)
        assert not c.is_table_allowed("human", name.lower())


def test_agent_tier_is_not_open():
    """The agent holds a write tool; an open read surface widens the
    indirect-injection chain in trust-model.md."""
    c = config()
    assert c.table_policy_for("agent") == "allowlist"
    assert not c.is_table_allowed("agent", "AzureDiagnostics")


def test_workspace_policy_with_a_write_tool_is_rejected():
    _expect_invalid(lambda d: d["governance"]["agent"].update(table_policy="workspace"))


def test_unknown_table_policy_rejected():
    _expect_invalid(lambda d: d["governance"]["human"].update(table_policy="everything"))

def test_testing_agent_not_in_identity_allowed():
    c = config()
    assert AGENT_APP_ID not in c.identity.allowed_agent_app_ids

def test_all_http_client_loggers_are_pinned():
    """Any HTTP client in the image must be pinned to WARNING (report M-7)."""
    from src.logging_setup import _NOISY_LOGGERS
    for name in ("httpx", "httpcore", "httpx2", "httpcore2", "urllib3"):
        assert name in _NOISY_LOGGERS, f"{name} would log request URLs at DEBUG"

def test_hunting_tool_requires_defender_enabled():
    _expect_invalid(lambda d: (
        d["governance"]["human"]["allowed_tools"].append("query_defender_hunting"),
        d.setdefault("defender", {}).update(enabled=False),
    ))


def test_hunting_tool_cannot_coexist_with_a_write_tool():
    def mutate(d):
        d["governance"]["agent"]["allowed_tools"].append("query_defender_hunting")
    _expect_invalid(mutate)

# ---- Defender hunting ---------------------------------------------------
#
# Rules guarded on defender.enabled are tested against _defender_raw(), not the
# example config, or they pass without exercising the rule.


def test_example_config_ships_defender_disabled():
    """A fresh tenant must not inherit a tenant-wide Graph permission from a
    template. Enabling it is a recorded decision - see trust-model.md."""
    cfg = config()
    assert cfg.defender is None or cfg.defender.enabled is False


def test_defender_overlay_used_by_the_tests_is_a_valid_policy():
    """The Defender suite forces the feature on. If that overlay could not pass
    the validators, those tests would exercise a policy that can never ship."""
    cfg = defender_config()
    assert cfg.defender is not None and cfg.defender.enabled
    assert "query_defender_hunting" in cfg.governance["human"].allowed_tools
    assert "query_defender_hunting" not in cfg.governance["agent"].allowed_tools


def test_hunting_tool_requires_defender_enabled():
    """The failure an operator hits when they flip enabled to false and forget
    the tool entry. Enabling/disabling is two edits."""
    def mutate(d):
        d["governance"]["human"]["allowed_tools"].append("query_defender_hunting")
        d["defender"]["enabled"] = False
    _expect_invalid(mutate)


def test_hunting_tool_cannot_coexist_with_a_write_tool():
    """Tenant-wide read plus a write path closes the indirect-injection loop in
    trust-model.md across the whole XDR corpus.

    Runs against the ENABLED overlay: against the example it would trip the
    'defender disabled' branch first and never reach this rule.
    """
    def mutate(d):
        tools = d["governance"]["agent"]["allowed_tools"]
        assert "add_incident_comment" in tools, "agent tier lost its write tool"
        tools.append("query_defender_hunting")
    _expect_invalid(mutate, base=_defender_raw())


def test_hunting_tool_is_human_tier_only():
    """The human-tier restriction, isolated from the write-tool rule: strip the
    agent's write tool first, so the rejection can only come from the tier
    check. Unscoped tenant-wide access requires an accountable named caller."""
    def mutate(d):
        agent = d["governance"]["agent"]
        agent["allowed_tools"] = [t for t in agent["allowed_tools"]
                                  if t != "add_incident_comment"]
        agent["allowed_tools"].append("query_defender_hunting")
    _expect_invalid(mutate, base=_defender_raw())


def test_defender_timeout_must_be_under_the_request_deadline():
    """A hunting call that outlives the global deadline is cancelled mid-flight
    and the quota is spent for nothing."""
    _expect_invalid(lambda d: d["defender"].update(timeout_seconds=500),
                    base=_defender_raw())


def test_defender_cannot_resolve_to_zero_tables():
    def mutate(d):
        d["defender"]["blocked_tables"] = list(d["defender"]["allowed_tables"])
    _expect_invalid(mutate, base=_defender_raw())


def test_defender_empty_allowed_tables_rejected():
    _expect_invalid(lambda d: d["defender"].update(allowed_tables=[]),
                    base=_defender_raw())


def test_defender_empty_banned_lists_rejected():
    _expect_invalid(lambda d: d["defender"]["kql"].update(banned_functions=[]),
                    base=_defender_raw())
    _expect_invalid(lambda d: d["defender"]["kql"].update(banned_operators=[]),
                    base=_defender_raw())


def test_defender_typo_in_a_key_is_rejected():
    """extra='forbid' must hold inside the nested Defender models too."""
    def mutate(d):
        d["defender"]["banned_function"] = d["defender"]["kql"].pop("banned_functions")
    _expect_invalid(mutate, base=_defender_raw())


def test_enrichment_functions_are_banned_in_the_shipped_defender_profile():
    """They return data beyond the tables named in the query, which makes
    `extracted_tables` in the audit record untrue. Banned for audit integrity,
    independently of the RBAC regime - see trust-model.md."""
    cfg = defender_config()
    banned = {f.lower() for f in cfg.defender.kql.banned_functions}
    for fn in ("fileprofile", "seenby", "assignedipaddresses", "devicefromip"):
        assert fn in banned, f"{fn} must stay banned"

def test_async_azure_transport_is_installed():
    """azure-core has no built-in async transport - AioHttpTransport imports
    aiohttp lazily. Without it every .aio client raises ImportError at call
    time, with duration_ms=0 and no network I/O. Not transitive: neither
    azure-identity nor azure-monitor-query requests the [aio] extra."""
    from azure.core.pipeline.transport import AioHttpTransport  # noqa: F401

def _is_registered(name: str) -> bool:
    """True when FastMCP will serve a tool under `name`.

    Uses get_tool(name) rather than an enumeration API: FastMCP's introspection
    surface has changed across 3.x releases (get_tools() does not exist in
    3.4.x), and a test that guards tool registration must not itself break on a
    dependency bump. Tolerates a sync or async implementation.
    """
    from src.server import mcp

    try:
        result = mcp.get_tool(name)
        if inspect.isawaitable(result):
            result = asyncio.run(result)
    except Exception:
        # FastMCP raises rather than returning None for an unknown tool.
        return False
    return result is not None


def _mcp_tool_registrations() -> dict:
    """{tool name: source file} for every mcp.tool(...) under src/tools/.

    A static scan, so it sees registrations in modules that src/server.py never
    imports - which is one of the two ways a tool silently fails to appear in
    tools/list. Recognises this repo's `mcp.tool(fn)` call form, the `@mcp.tool`
    decorator form, and an explicit `name=` override.
    """
    found: dict = {}

    def _record(default_name, keywords, path):
        for kw in keywords or ():
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                found[str(kw.value.value)] = path.name
                return
        found[default_name] = path.name

    def _is_mcp_tool(node) -> bool:
        return (isinstance(node, ast.Attribute) and node.attr == "tool"
                and isinstance(node.value, ast.Name) and node.value.id == "mcp")

    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            # mcp.tool(some_function)
            if isinstance(node, ast.Call) and _is_mcp_tool(node.func):
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        _record(arg.id, node.keywords, path)
            # @mcp.tool  /  @mcp.tool(...)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    target, keywords = (
                        (dec.func, dec.keywords) if isinstance(dec, ast.Call)
                        else (dec, ())
                    )
                    if _is_mcp_tool(target):
                        _record(node.name, keywords, path)

    return found


def test_every_known_tool_is_registered():
    """A name in KNOWN_TOOLS with no live registration passes config validation
    and is then invisible to every client: allowed_tools names it,
    AuthorizationMiddleware.on_list_tools filters it out of tools/list, and
    nothing logs anything. The model reports the tool does not exist, which is
    accurate and unactionable."""
    from src.config import KNOWN_TOOLS

    missing = sorted(name for name in KNOWN_TOOLS if not _is_registered(name))
    assert not missing, (
        f"declared in KNOWN_TOOLS but not served by FastMCP: {missing}. "
        "Check for a missing mcp.tool(...) call at the bottom of the tool "
        "module, and that the module appears in the import line at the bottom "
        "of src/server.py."
    )


def test_every_registration_is_a_known_tool():
    """The reverse: a registered tool absent from KNOWN_TOOLS can never appear
    in allowed_tools, so no caller can ever reach it."""
    from src.config import KNOWN_TOOLS

    extra = {n: f for n, f in _mcp_tool_registrations().items()
             if n not in KNOWN_TOOLS}
    assert not extra, (
        f"registered with FastMCP but absent from KNOWN_TOOLS: {extra}. "
        "Config validation rejects unknown names in allowed_tools, so this tool "
        "is unreachable."
    )


def test_source_registrations_all_reach_the_live_server():
    """Bridges the static scan and the runtime.

    A registration in a module that src/server.py never imports is visible to
    the AST scan and absent from the server. That failure mode produces no
    error anywhere - the tool simply does not exist.
    """
    dead = sorted(
        f"{name} ({file})" for name, file in _mcp_tool_registrations().items()
        if not _is_registered(name)
    )
    assert not dead, (
        f"registered in source but not served: {dead}. The module is almost "
        "certainly missing from the `from src.tools import ...` line at the "
        "bottom of src/server.py."
    )

@pytest.mark.parametrize(
    "path", _LOCAL_CONFIGS or [None],
    ids=[os.path.basename(p) for p in _LOCAL_CONFIGS] or ["none-present"],
)
def test_local_config_tools_are_all_registered(path):
    """A per-tenant config naming a tool this build does not serve is a
    deployment that silently offers fewer tools than its policy claims."""
    if path is None:
        pytest.skip("no per-tenant config in this checkout")
    cfg = load_config(path)
    for tier, gov in cfg.governance.items():
        missing = sorted(t for t in gov.allowed_tools if not _is_registered(t))
        assert not missing, (
            f"{os.path.basename(path)} [{tier}]: allowed_tools names {missing}, "
            "which this build does not serve"
        )