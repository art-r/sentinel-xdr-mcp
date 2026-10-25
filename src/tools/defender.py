from __future__ import annotations

import time
from typing import Annotated

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import Field

from src.clients.defender_client import HuntingQuotaExhausted, HuntingUnavailable
from src.governance.result_truncation import truncate
from src.server import deps, mcp

_MAX_KQL_CHARS = (
    deps.config.defender.kql.max_query_length if deps.config.defender is not None else 4000
)


async def query_defender_hunting(
    kql: Annotated[
        str,
        Field(
            min_length=1,
            max_length=_MAX_KQL_CHARS,
            description="Defender advanced-hunting KQL query",
        ),
    ],
    ctx: Context,
) -> dict:
    """Run a Microsoft Defender XDR advanced-hunting query.

    Use this for data that is NOT in the Sentinel workspace - above all
    Vulnerability Management: DeviceTvmSoftwareInventory,
    DeviceTvmSoftwareVulnerabilities, DeviceTvmSecureConfigurationAssessment and
    related tables. Those exist in the Sentinel schema but never hold data.

    When a table is available in BOTH sources (DeviceProcessEvents, EmailEvents,
    IdentityLogonEvents and similar), prefer query_sentinel_logs: it is not
    bounded by a tenant-wide hunting quota. Call list_available_tables with
    source="defender" to see what is reachable here.

    The hunting corpus covers roughly the last 30 days. There is no timespan
    parameter - always include an explicit filter, e.g.
    `| where Timestamp > ago(7d)`.

    Single statement starting with a table name. `let`, `search`, `find`,
    `externaldata`, plugin operators, and the enrichment functions FileProfile,
    SeenBy, AssignedIPAddresses and DeviceFromIP are not permitted.
    """
    caller = deps.require_caller(ctx)
    cfg = deps.config.defender
    if cfg is None or not cfg.enabled or deps.defender_kql_validator is None:
        raise ToolError("Defender advanced hunting is not enabled on this server.")

    # Second app role, checked here rather than in authorize(). Defender access
    # is additive to Sentinel.Read and must be separately assignable and
    # separately reviewable. Same defence-in-depth pattern as the caller.type
    # check in add_incident_comment.
    if cfg.required_role not in set(caller.claims.get("roles") or []):
        deps.audit.log_denied("missing_defender_role", tool="query_defender_hunting", caller=caller)
        raise ToolError(
            "Defender advanced hunting requires an additional role that this account does not hold."
        )

    args = {"kql": kql}
    result = deps.defender_kql_validator.validate(kql, caller.type)
    if not result.is_valid:
        deps.audit.log_tool_call(
            caller,
            "query_defender_hunting",
            args,
            source="defender",
            validation_result=f"rejected: {result.error}",
        )
        raise ToolError(f"KQL validation failed: {result.error}")

    start = time.monotonic()
    try:
        raw = await deps.defender_client.run_query(result.sanitized_kql)
    except HuntingQuotaExhausted as exc:
        deps.audit.log_denied(
            "defender_quota_exhausted", tool="query_defender_hunting", caller=caller
        )
        raise ToolError(str(exc)) from None
    except HuntingUnavailable as exc:
        deps.audit.log_tool_failure(
            caller,
            "query_defender_hunting",
            args,
            error=exc,
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        raise ToolError(
            "Advanced hunting failed (the service rejected the query, timed out, "
            "or is unavailable). Simplify the query or narrow the time filter."
        ) from None

    out = truncate(raw, cfg.max_result_rows, cfg.max_result_size_bytes, cfg.max_cell_chars)
    deps.audit.log_tool_call(
        caller,
        "query_defender_hunting",
        args,
        source="defender",
        executed_kql=result.sanitized_kql,
        tables=result.extracted_tables,
        result_row_count=out["row_count"],
        truncated=out["truncated"],
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    return out


mcp.tool(query_defender_hunting)
