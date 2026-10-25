from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import Field

from src.governance.sanitize import sanitize_comment
from src.server import deps, mcp

#: Upper bound accepted at the API surface. The per-tier cap from config is
#: applied on top, after the attribution header is accounted for.
_MAX_COMMENT_CHARS = max(tier.max_comment_chars for tier in deps.config.governance.values())


async def add_incident_comment(
    incident_id: Annotated[str, Field(pattern=r"^\d{1,10}$", description="Sentinel incident number")],
    comment: Annotated[str, Field(min_length=1, max_length=_MAX_COMMENT_CHARS,
                                  description="Markdown-formatted comment text")],
    ctx: Context,
) -> dict:
    """Write a Markdown-formatted comment to a Sentinel incident.

    Only available to the automated investigation agent - not for interactive
    human use. Enforced in middleware (tool scoping) AND here (defence in depth).

    Markdown image syntax and autolinks are escaped: the comment is rendered in
    the Sentinel portal, where an embedded remote image is an exfiltration
    channel. A machine-generated attribution header is prepended - the Sentinel
    comment author is the server's Managed Identity, so without it there is no
    attribution outside the audit log.
    """
    caller = deps.require_caller(ctx)
    if caller.type != "agent":
        deps.audit.log_denied("human_called_agent_tool", tool="add_incident_comment", caller=caller)
        raise ToolError("add_incident_comment is only available to the agent")

    gov = deps.config.governance[caller.type]
    correlation_id = str(uuid.uuid4())
    header = (
        f"> Posted by the Sentinel MCP investigation agent "
        f"(caller `{caller.id}`, correlation `{correlation_id}`, "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}). "
        f"Automated content - verify before acting.\n\n"
    )
    body = sanitize_comment(comment, max(1, gov.max_comment_chars - len(header)))
    args = {"incident_id": incident_id, "comment": comment, "comment_len": len(body),
            "correlation_id": correlation_id}

    start = time.monotonic()
    try:
        result = await deps.sentinel_client.add_comment(incident_id, header + body)
    except ValueError as exc:
        deps.audit.log_tool_call(caller, "add_incident_comment", args, validation_result="not_found")
        raise ToolError(str(exc)) from None
    except Exception as exc:
        deps.audit.log_tool_failure(caller, "add_incident_comment", args, error=exc,
                                    duration_ms=int((time.monotonic() - start) * 1000))
        raise ToolError("Could not write the comment (Sentinel is unavailable or refused "
                        "the request).") from None

    deps.audit.log_tool_call(caller, "add_incident_comment", args,
                             duration_ms=int((time.monotonic() - start) * 1000))
    return {**result, "correlation_id": correlation_id}


mcp.tool(add_incident_comment)
