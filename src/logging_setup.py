"""Structured JSON logging + audit logger.

Two things here are load-bearing.

1. structlog is routed THROUGH the stdlib logging module
   (`structlog.stdlib.LoggerFactory` + `ProcessorFormatter`). The Azure Monitor
   OpenTelemetry exporter works by attaching a handler to the stdlib root
   logger, so a `PrintLoggerFactory` writing straight to stdout means the audit
   trail never reaches Application Insights at all (report H-3).

2. Query text is redacted per caller tier. A human analyst's KQL embeds the
   subject of an investigation; the agent's is machine-generated and is kept
   verbatim for reviewability (report H-2). Query RESULTS are never logged by
   anything, at any tier.
"""

from __future__ import annotations

import hashlib
import logging
import sys

import structlog

#: Libraries that log request URLs, headers or resource ids at DEBUG/INFO.
#: Pinned to WARNING regardless of our own level so raising `logging.level` to
#: DEBUG during an incident cannot start emitting Azure request metadata
#: (report M-7). Bodies are never logged by azure-core unless logging_enable is
#: set, which this code never does.
_NOISY_LOGGERS = (
    "azure",
    "azure.core.pipeline.policies.http_logging_policy",
    "azure.identity",
    "azure.monitor",
    "msal",
    "urllib3",
    # httpx/httpcore stay: the MCP SDK hard-depends on them and they are in
    # the image regardless of what this codebase imports.
    "httpx",
    "httpcore",
    # httpx2/httpcore2 are DIFFERENT logger names, not aliases. Without these
    # two lines, raising logging.level to DEBUG emits Graph request URLs -
    # exactly the regression M-7 was raised for.
    "httpx2",
    "httpcore2",
    "uvicorn.access",
)

#: Argument keys whose value is free-form text supplied by the caller.
_SENSITIVE_ARGS = frozenset({"kql", "executed_kql", "comment"})


def _shared_processors() -> list:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]


def setup_logging(config) -> None:
    level = getattr(logging, config.logging.level.upper(), logging.INFO)
    shared = _shared_processors()

    structlog.configure(
        processors=shared + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        )
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(max(level, logging.WARNING))

    # Attach the OTel handler AFTER the stdout handler is installed, so both
    # receive every record.
    if config.logging.application_insights_connection_string:
        _try_azure_monitor(config.logging.application_insights_connection_string)


def _try_azure_monitor(connection_string: str) -> None:
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor

        configure_azure_monitor(connection_string=connection_string, logger_name=None)
    except Exception:  # pragma: no cover - depends on the deployed environment
        logging.getLogger(__name__).warning("azure_monitor_otel_export_not_configured")


def get_logger(name: str = "sentinel-mcp"):
    return structlog.get_logger(name)


def digest(text: str) -> str:
    """Short, stable fingerprint - lets you correlate repeated queries in the
    audit log without storing the query itself."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


class AuditLogger:
    """Central audit trail. All redaction happens HERE, not in the tools, so a
    tool added later cannot forget it."""

    def __init__(self, config=None, logger=None) -> None:
        self._log = logger if logger is not None else structlog.get_logger("audit")
        log_cfg = getattr(config, "logging", None)
        self._text_tiers = frozenset(getattr(log_cfg, "log_query_text_for", ["agent"]))
        self._log_upn = bool(getattr(log_cfg, "log_caller_upn", True))

    # ---- redaction -----------------------------------------------------

    def _may_log_text(self, caller_type: str | None) -> bool:
        return caller_type in self._text_tiers

    def _redact(self, caller_type: str | None, arguments: dict | None) -> dict:
        out: dict = {}
        allow = self._may_log_text(caller_type)
        for key, value in (arguments or {}).items():
            if key in _SENSITIVE_ARGS and isinstance(value, str):
                if allow:
                    out[key] = value
                else:
                    out[f"{key}_sha256"] = digest(value)
                    out[f"{key}_len"] = len(value)
            else:
                out[key] = value
        return out

    def _caller_fields(self, caller) -> dict:
        caller_type = getattr(caller, "type", None)
        fields = {
            "caller_type": caller_type,
            "caller_id": getattr(caller, "id", None),
            "client_app_id": getattr(caller, "client_app_id", None),
        }
        if self._log_upn:
            fields["caller_name"] = getattr(caller, "name", None)
        return fields

    # ---- events --------------------------------------------------------

    def log_tool_call(
        self,
        caller,
        tool,
        arguments=None,
        result_row_count=None,
        truncated=None,
        duration_ms=None,
        validation_result="passed",
        executed_kql=None,
        tables=None,
        **extra,
    ) -> None:
        caller_type = getattr(caller, "type", None)
        payload = self._redact(caller_type, arguments)
        if executed_kql is not None:
            payload.update(self._redact(caller_type, {"executed_kql": executed_kql}))
        self._log.info(
            "tool_invocation",
            tool=tool,
            arguments=payload,
            tables=sorted(tables) if tables else None,
            result_row_count=result_row_count,
            truncated=truncated,
            duration_ms=duration_ms,
            validation_result=validation_result,
            **self._caller_fields(caller),
            **extra,
        )

    def log_tool_failure(self, caller, tool, arguments=None, error=None, duration_ms=None) -> None:
        """Failure path. Only the exception CLASS is recorded - Azure error
        messages routinely echo the failing query fragment (report H-5)."""
        self._log.warning(
            "tool_failed",
            tool=tool,
            arguments=self._redact(getattr(caller, "type", None), arguments),
            error_class=type(error).__name__ if error is not None else None,
            duration_ms=duration_ms,
            validation_result="failed",
            **self._caller_fields(caller),
        )

    def log_denied(self, reason, tool=None, caller=None) -> None:
        self._log.warning(
            "access_denied",
            reason=reason,
            tool=tool,
            **self._caller_fields(caller),
        )

    def log_auth_denied(self, reason, claims=None) -> None:
        """Authentication/authorisation rejection at the verifier.

        Never receives the token. Only the coarse reason plus the identifiers
        needed to investigate a 401 spike (report H-4).
        """
        claims = claims or {}
        self._log.warning(
            "authentication_denied",
            reason=reason,
            client_app_id=claims.get("azp") or claims.get("appid"),
            caller_id=claims.get("oid"),
            tenant_id=claims.get("tid"),
            token_type="app" if claims.get("idtyp") == "app" else None,
        )
