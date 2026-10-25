from __future__ import annotations

import time
from typing import Annotated

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import Field

from src.governance.result_truncation import truncate_list
from src.governance.sanitize import UNTRUSTED_NOTE, scrub_value
from src.server import deps, mcp

_ID = Field(pattern=r"^\d{1,10}$", description="Sentinel incident number (numeric)")

_GENERIC_ERROR = "Could not retrieve the incident (Sentinel is unavailable or refused the request)."


async def get_incident(incident_id: Annotated[str, _ID], ctx: Context) -> dict:
    """Retrieve full details of a Microsoft Sentinel incident: title, severity,
    status, owner, labels, timestamps, alert count and alert product names."""
    caller = deps.require_caller(ctx)
    gov = deps.config.governance[caller.type]
    args = {"incident_id": incident_id}
    start = time.monotonic()
    try:
        incident = await deps.sentinel_client.get_incident(incident_id)
    except ValueError as exc:
        # "Incident N not found" - safe, caller-supplied number only.
        deps.audit.log_tool_call(caller, "get_incident", args, validation_result="not_found")
        raise ToolError(str(exc)) from None
    except Exception as exc:
        deps.audit.log_tool_failure(
            caller,
            "get_incident",
            args,
            error=exc,
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        raise ToolError(_GENERIC_ERROR) from None
    deps.audit.log_tool_call(
        caller, "get_incident", args, duration_ms=int((time.monotonic() - start) * 1000)
    )
    return {**scrub_value(incident, gov.max_cell_chars), "content_warning": UNTRUSTED_NOTE}


async def get_incident_entities(incident_id: Annotated[str, _ID], ctx: Context) -> dict:
    """Retrieve entities (accounts, IPs, hosts, file hashes, URLs) associated
    with a Sentinel incident. Each item has entity_type and properties."""
    caller = deps.require_caller(ctx)
    gov = deps.config.governance[caller.type]
    args = {"incident_id": incident_id}
    start = time.monotonic()
    try:
        entities = await deps.sentinel_client.get_incident_entities(incident_id)
    except ValueError as exc:
        deps.audit.log_tool_call(
            caller, "get_incident_entities", args, validation_result="not_found"
        )
        raise ToolError(str(exc)) from None
    except Exception as exc:
        deps.audit.log_tool_failure(
            caller,
            "get_incident_entities",
            args,
            error=exc,
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        raise ToolError(_GENERIC_ERROR) from None
    out = truncate_list(entities, gov.max_entities, gov.max_result_size_bytes, gov.max_cell_chars)
    deps.audit.log_tool_call(
        caller,
        "get_incident_entities",
        args,
        result_row_count=out["count"],
        truncated=out["truncated"],
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    return out


mcp.tool(get_incident)
mcp.tool(get_incident_entities)
