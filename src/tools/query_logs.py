from __future__ import annotations

import time
from typing import Annotated

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import Field

from src.governance.result_truncation import truncate
from src.server import deps, mcp
from src.util import TIMESPAN_PATTERN, parse_and_cap_timespan

#: Driven by config so there is exactly one place to change it (report M-8).
_MAX_KQL_CHARS = deps.config.kql.max_query_length


async def query_sentinel_logs(
    kql: Annotated[str, Field(min_length=1, max_length=_MAX_KQL_CHARS,
                              description="KQL query to run against the Log Analytics Workspace")],
    ctx: Context,
    timespan: Annotated[str, Field(
        pattern=TIMESPAN_PATTERN,
        description="ISO-8601 duration ceiling, e.g. P1D, P7D, PT6H (default P1D)")] = "P1D",
) -> dict:
    """Execute a KQL query against the Log Analytics Workspace.

    Returns columns, rows, row_count and truncated. When truncated, a note
    explains why; total_row_count is present only when the exact total is
    known (size-capped results), never when the row cap was hit.
    Always filter by time; the timespan parameter is a hard ceiling.
    Prefer aggregations (summarize/count) before pulling raw events; limit raw
    event queries with `| take N`.

    The query must be a single statement starting with a table name. `let`,
    `search`, `find`, cross-workspace/cluster references and plugin operators
    (`evaluate`, `externaldata`) are not permitted.
    """
    caller = deps.require_caller(ctx)
    gov = deps.config.governance[caller.type]
    args = {"kql": kql, "timespan": timespan}

    result = deps.kql_validator.validate(kql, caller.type)
    if not result.is_valid:
        deps.audit.log_tool_call(caller, "query_sentinel_logs", args,
                                 validation_result=f"rejected: {result.error}")
        raise ToolError(f"KQL validation failed: {result.error}")

    try:
        span = parse_and_cap_timespan(timespan, gov.max_timespan_days)
    except ValueError as exc:
        deps.audit.log_tool_call(caller, "query_sentinel_logs", args,
                                 validation_result=f"rejected: {exc}")
        raise ToolError(str(exc)) from None

    # Rate and concurrency limits are enforced by AuthorizationMiddleware for
    # every tool - deliberately not repeated here.
    start = time.monotonic()
    try:
        raw = await deps.law_client.query(result.sanitized_kql, span, gov.max_query_timeout_seconds)
    except Exception as exc:
        deps.audit.log_tool_failure(caller, "query_sentinel_logs", args, error=exc,
                                    duration_ms=int((time.monotonic() - start) * 1000))
        # Generic message on purpose: an Azure error string commonly echoes the
        # failing query fragment back to the caller and into the logs.
        raise ToolError(
            "Query execution failed (the workspace rejected it, timed out, or is unavailable). "
            "Simplify the query or narrow the timespan and retry."
        ) from None

    out = truncate(raw, gov.max_result_rows, gov.max_result_size_bytes, gov.max_cell_chars)
    if raw.get("partial"):
        out["partial"] = True
        out["partial_note"] = (
            "The workspace returned only partial results (timeout or resource limit). "
            "Narrow the timespan or add filters."
        )
    if raw.get("additional_tables_dropped"):
        out["additional_tables_dropped"] = raw["additional_tables_dropped"]

    # A table present in the workspace SCHEMA but never ingested returns zero
    # rows, indistinguishable from a filter that matched nothing. Defender
    # Vulnerability Management (DeviceTvm*) is the common case: Sentinel exposes
    # those tables for query validation and autocomplete only. Without this note
    # the model reports "no vulnerabilities found", which is a false negative
    # on a security question.
    #
    # Guarded three ways:
    #   * `not out.get("note")` - truncate() owns that key when a cap fired;
    #   * non-empty `live` - workspace_tables() returns () when discovery
    #     failed, and claiming every table is absent would be worse than silence;
    #   * workspace policy only - an allowlist tier would otherwise pay for a
    #     Usage query it has no other use for.
    if out["row_count"] == 0 and not out.get("note"):
        if deps.config.table_policy_for(caller.type) == "workspace":
            live = {name.lower() for name in await deps.workspace_tables()}
            if live:
                absent = sorted(t for t in result.extracted_tables
                                if t.lower() not in live)
                if absent:
                    out["note"] = (
                        f"No rows returned. Table(s) {absent} exist in the workspace "
                        "schema but have no ingested data here. Defender XDR "
                        "Vulnerability Management tables (DeviceTvm*) in particular "
                        "are schema-only in Sentinel - query them with "
                        "query_defender_hunting instead, and call "
                        "list_available_tables(source=\"defender\") to see what is "
                        "reachable there. Do not report this as 'no findings'."
                    )

    deps.audit.log_tool_call(caller, "query_sentinel_logs", args,
                             executed_kql=result.sanitized_kql,
                             tables=result.extracted_tables,
                             result_row_count=out["row_count"], truncated=out["truncated"],
                             duration_ms=int((time.monotonic() - start) * 1000))
    return out


mcp.tool(query_sentinel_logs)
