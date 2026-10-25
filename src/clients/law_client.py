from __future__ import annotations

from datetime import timedelta

from azure.identity.aio import ManagedIdentityCredential
from azure.monitor.query import LogsQueryStatus
from azure.monitor.query.aio import LogsQueryClient

def parse_datatype_names(result: dict) -> list[str]:
    """Table names from a `Usage | summarize by DataType` result.

    Module-level and pure so the test fake can use the same parse as the real
    client. Returns [] on an unexpected shape rather than raising - the caller
    falls back to the configured list.
    """
    columns = result.get("columns") or []
    if "DataType" not in columns:
        return []
    index = columns.index("DataType")
    return [str(row[index]) for row in result.get("rows") or [] if row[index]]

class LAWClient:
    """Async wrapper over the Logs Query API. Always uses the server's own
    user-assigned Managed Identity - never the caller's token.

    Correction vs spec: query_workspace expects a timedelta for `timespan`
    (not an ISO-8601 string) and `server_timeout` in seconds.
    """

    def __init__(self, config) -> None:
        self.config = config
        self._credential = ManagedIdentityCredential(client_id=config.identity.mcp_mi_client_id)
        self._client = LogsQueryClient(self._credential)
        self._workspace_id = config.law.workspace_id

    async def query(self, kql: str, timespan: timedelta, server_timeout: int) -> dict:
        resp = await self._client.query_workspace(
            self._workspace_id, kql, timespan=timespan, server_timeout=server_timeout
        )
        partial = resp.status != LogsQueryStatus.SUCCESS
        if partial:
            tables = resp.partial_data or []
            # Class name only: the partial-error MESSAGE routinely echoes the
            # failing query fragment, which must not reach a log or the caller
            # (report L-3 / H-5).
            partial_error = type(resp.partial_error).__name__ if resp.partial_error else "PartialError"
        else:
            tables = resp.tables
            partial_error = None

        out = {"columns": [], "rows": [], "partial": partial, "partial_error": partial_error}
        if not tables:
            return out
        # Only the first table is returned; report the rest rather than
        # dropping them silently.
        table = tables[0]
        out["columns"] = [getattr(c, "name", c) for c in table.columns]
        out["rows"] = [list(r) for r in table.rows]
        out["additional_tables_dropped"] = max(0, len(tables) - 1)
        return out

    async def get_table_schema(self, table_name: str) -> list[dict]:
        result = await self.query(f"{table_name} | getschema", timedelta(minutes=5), 60)
        cols = result["columns"]
        return [dict(zip(cols, row)) for row in result["rows"]]

    async def check_workspace_access(self) -> None:
        """Readiness probe: prove the MI can query the configured workspace.

        Token acquisition alone cannot detect a removed Log Analytics Reader
        assignment. `print 1` is a constant, low-cost data-plane query that
        still requires access to this workspace.
        """
        response = await self._client.query_workspace(
            self._workspace_id,
            "print 1",
            timespan=timedelta(minutes=1),
            server_timeout=10,
        )
        if response.status != LogsQueryStatus.SUCCESS:
            raise RuntimeError("Log Analytics readiness query did not succeed")

        # tables = response.tables or []
        # if not tables:
        #     return {"tables": 0, "columns": [], "rows": []}
        # table = tables[0]
        # return {
        #     "tables": len(tables),
        #     "columns": [getattr(c, "name", c) for c in table.columns],
        #     "rows": [list(r) for r in table.rows],
        # }

    async def close(self) -> None:
        await self._client.close()
        await self._credential.close()

    async def list_workspace_tables(self, days: int = 7) -> list[str]:
        """Tables that ingested data recently. DISCOVERY ONLY - never a gate.

        `Usage` is the metering table: cheap, and the standard way to enumerate
        tables without a `union *` scan. It lists only tables with recent
        ingestion, which is the useful set for discovery.
        """
        result = await self.query("Usage | summarize by DataType", timedelta(days=days), 60)
        return parse_datatype_names(result)
