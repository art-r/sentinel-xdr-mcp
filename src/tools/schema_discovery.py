from __future__ import annotations

import time
from typing import Annotated, Literal

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import Field

from src.governance.result_truncation import truncate_list
from src.server import deps, mcp
from src.config import TENANT_WIDE_TOOLS


async def list_available_tables(
    ctx: Context,
    source: Annotated[Literal["all", "sentinel", "defender"], Field(
        description="Which data store to list. 'all' (default) returns both.")] = "all",
) -> dict:
    """List the tables you may query, per data store. Call this before writing KQL.

    Returns a mapping of store name to table list:

      "sentinel" - the Log Analytics workspace. Query with query_sentinel_logs.
      "defender" - Defender XDR advanced hunting. Query with
                   query_defender_hunting. This is where Vulnerability
                   Management data (DeviceTvmSoftwareVulnerabilities,
                   DeviceTvmSoftwareInventory and related) actually lives -
                   those tables appear in the Sentinel schema but hold no data
                   there, so a Sentinel query against them returns zero rows.

    A store is absent from the response when it is not enabled on this server
    or this caller lacks the role for it. Absent means unavailable, not empty.
    """
    caller = deps.require_caller(ctx)
    start = time.monotonic()
    cfg = deps.config
    out: dict[str, list[str]] = {}

    if source in ("all", "sentinel"):
        tables = sorted(cfg.allowed_tables_for(caller.type))
        if cfg.table_policy_for(caller.type) == "workspace":
            discovered = [t for t in await deps.workspace_tables()
                          if not cfg.is_table_blocked(t)]
            if discovered:
                tables = sorted(discovered)
        out["sentinel"] = tables

    if source in ("all", "defender"):
        enabled = cfg.defender is not None and cfg.defender.enabled
        has_role = enabled and cfg.defender.required_role in set(
            caller.claims.get("roles") or [])
        # A store with no query tool for THIS caller must not be advertised.
        # on_list_tools filters query_defender_hunting out of tools/list when it
        # is absent from the tier's allowed_tools, so advertising the store here
        # tells the model about data it has no mechanism to fetch.
        has_tool = bool(
            TENANT_WIDE_TOOLS & set(cfg.governance[caller.type].allowed_tools))

        if enabled and has_role and has_tool:
            # No `Usage` equivalent in advanced hunting: the configured list is
            # authoritative, not a fallback.
            out["defender"] = sorted(cfg.defender_tables())
        elif source == "defender":
            # Explicitly asked for a store that is unavailable - name the
            # reason. Under "all" it is silently omitted.
            if not enabled:
                raise ToolError(
                    "Defender advanced hunting is not enabled on this server.")
            if not has_role:
                deps.audit.log_denied("missing_defender_role",
                                      tool="list_available_tables", caller=caller)
                raise ToolError(
                    "Defender advanced hunting requires an additional role that "
                    "this account does not hold."
                )
            deps.audit.log_denied("defender_tool_not_in_tier",
                                  tool="list_available_tables", caller=caller)
            raise ToolError(
                "Defender advanced hunting is enabled but no query tool is "
                "available to this caller. This is a server configuration error - "
                "report it to the operator."
            )

    deps.audit.log_tool_call(
        caller, "list_available_tables", {"source": source},
        source=source,
        result_row_count=sum(len(v) for v in out.values()),
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    return out


async def get_table_schema(
    table_name: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{1,63}$",
                                     description="Exact table name, e.g. 'SigninLogs'")],
    ctx: Context,
    source: Annotated[Literal["sentinel", "defender"], Field(
        description="Which store the table belongs to. Use the key it appeared "
                    "under in list_available_tables.")] = "sentinel",
) -> dict:
    """Return column names and types for one table in one data store.

    The table must be one this caller may query in that store; call
    list_available_tables first and use the key the table appeared under.
    """
    caller = deps.require_caller(ctx)
    cfg = deps.config
    gov = cfg.governance[caller.type]
    args = {"table_name": table_name, "source": source}
    start = time.monotonic()

    if source == "defender":
        if not (TENANT_WIDE_TOOLS & set(cfg.governance[caller.type].allowed_tools)):
            raise ToolError(
                "Defender advanced hunting is enabled but no query tool is "
                "available to this caller. This is a server configuration error."
            )
        if cfg.defender is None or not cfg.defender.enabled:
            raise ToolError("Defender advanced hunting is not enabled on this server.")
        if cfg.defender.required_role not in set(caller.claims.get("roles") or []):
            deps.audit.log_denied("missing_defender_role", tool="get_table_schema",
                                  caller=caller)
            raise ToolError(
                "Defender advanced hunting requires an additional role that this "
                "account does not hold."
            )
        if not cfg.is_defender_table_allowed(table_name):
            raise ToolError(
                f"Table '{table_name}' is not available in Defender advanced hunting. "
                "Call list_available_tables first."
            )
        try:
            # `| getschema` is a normal operator; it passes the Defender
            # validator profile and costs one hunting call.
            raw = await deps.defender_client.run_query(f"{table_name} | getschema")
        except Exception as exc:
            deps.audit.log_tool_failure(caller, "get_table_schema", args, error=exc,
                                        duration_ms=int((time.monotonic() - start) * 1000))
            raise ToolError("Could not read the table schema from advanced hunting "
                            "(the service is unavailable or refused the query).") from None
        schema = [dict(zip(raw["columns"], row, strict=False)) for row in raw["rows"]]
        max_columns = gov.max_schema_columns
        max_bytes = cfg.defender.max_result_size_bytes
        max_cell = cfg.defender.max_cell_chars
    else:
        if not cfg.is_table_allowed(caller.type, table_name):
            raise ToolError(
                f"Table '{table_name}' is not available. Call list_available_tables first."
            )
        try:
            schema = await deps.law_client.get_table_schema(table_name)
        except Exception as exc:
            deps.audit.log_tool_failure(caller, "get_table_schema", args, error=exc,
                                        duration_ms=int((time.monotonic() - start) * 1000))
            raise ToolError("Could not read the table schema (the workspace is "
                            "unavailable or the table has no data).") from None
        max_columns = gov.max_schema_columns
        max_bytes = gov.max_result_size_bytes
        max_cell = gov.max_cell_chars

    out = truncate_list(schema, max_columns, max_bytes, max_cell)
    deps.audit.log_tool_call(caller, "get_table_schema", args, source=source,
                             result_row_count=out["count"], truncated=out["truncated"],
                             duration_ms=int((time.monotonic() - start) * 1000))
    return out


mcp.tool(list_available_tables)
mcp.tool(get_table_schema)
