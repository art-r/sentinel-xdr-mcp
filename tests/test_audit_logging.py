"""Audit redaction.

The requirement: query RESULTS are never logged, and a HUMAN analyst's KQL text
is never logged either (it embeds the subject of the investigation). Agent KQL
is logged verbatim so agent behaviour stays reviewable.
"""
from src.auth.caller import CallerContext
from src.logging_setup import AuditLogger, digest

from ._support import CollectingLogger, config

HUMAN = CallerContext(type="human", id="oid-1", name="analyst@corp.example",
                      client_app_id="app-1")
AGENT = CallerContext(type="agent", id="app-2", name="investigation-agent",
                      client_app_id="app-2")

KQL = "SigninLogs | where UserPrincipalName == 'victim@corp.example' | take 5"


def _audit():
    log = CollectingLogger()
    return AuditLogger(config(), logger=log), log


def test_human_query_text_is_never_logged():
    audit, log = _audit()
    audit.log_tool_call(HUMAN, "query_sentinel_logs", {"kql": KQL, "timespan": "P1D"},
                        executed_kql=KQL + "\n| take 5000", tables={"SigninLogs"})
    blob = log.dumps()
    assert "victim@corp.example" not in blob
    assert "SigninLogs |" not in blob
    args = log.of("tool_invocation")[0]["arguments"]
    assert args["kql_sha256"] == digest(KQL)
    assert args["kql_len"] == len(KQL)
    assert "kql" not in args and "executed_kql" not in args
    # Non-sensitive metadata survives, so the trail is still useful.
    assert args["timespan"] == "P1D"
    assert log.of("tool_invocation")[0]["tables"] == ["SigninLogs"]


def test_agent_query_text_is_logged():
    audit, log = _audit()
    audit.log_tool_call(AGENT, "query_sentinel_logs", {"kql": KQL, "timespan": "P1D"},
                        executed_kql=KQL)
    args = log.of("tool_invocation")[0]["arguments"]
    assert args["kql"] == KQL
    assert args["executed_kql"] == KQL


def test_human_rejection_path_is_also_redacted():
    audit, log = _audit()
    audit.log_tool_call(HUMAN, "query_sentinel_logs", {"kql": KQL, "timespan": "P1D"},
                        validation_result="rejected: Table 'X' is blocked")
    assert "victim@corp.example" not in log.dumps()


def test_failure_path_is_redacted_and_carries_no_error_message():
    audit, log = _audit()
    audit.log_tool_failure(HUMAN, "query_sentinel_logs", {"kql": KQL},
                           error=RuntimeError("BadRequest: syntax error near 'victim@corp.example'"))
    blob = log.dumps()
    assert "victim@corp.example" not in blob
    assert "syntax error" not in blob
    assert log.of("tool_failed")[0]["error_class"] == "RuntimeError"


def test_comment_text_is_redacted_for_a_human_caller():
    """add_incident_comment is agent-only, but the redaction must not depend on
    that being enforced elsewhere."""
    audit, log = _audit()
    audit.log_tool_call(HUMAN, "add_incident_comment",
                        {"incident_id": "42", "comment": "secret finding"})
    assert "secret finding" not in log.dumps()


def test_auth_denial_never_carries_a_token():
    audit, log = _audit()
    audit.log_auth_denied("missing_role", {"azp": "app-9", "oid": "oid-9", "tid": "t-1",
                                           "scp": "user_impersonation"})
    event = log.of("authentication_denied")[0]
    assert event["reason"] == "missing_role"
    assert event["client_app_id"] == "app-9"
    assert "token" not in log.dumps().lower() or "token_type" in log.dumps()


def test_upn_can_be_switched_off():
    cfg = config().model_copy(deep=True)
    cfg.logging.log_caller_upn = False
    log = CollectingLogger()
    AuditLogger(cfg, logger=log).log_tool_call(HUMAN, "get_incident", {"incident_id": "1"})
    assert "analyst@corp.example" not in log.dumps()
    assert log.of("tool_invocation")[0]["caller_id"] == "oid-1"
