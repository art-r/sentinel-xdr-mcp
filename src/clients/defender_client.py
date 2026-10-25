"""Defender XDR advanced hunting via Microsoft Graph.

WARNING - this client's access is TENANT-WIDE and cannot be scoped. The managed
identity holds the Graph application permission ThreatHunting.Read.All, which
grants read of the entire Defender XDR hunting corpus: every device, every
mailbox, every identity, with no device-group or resource scoping available.
See trust-model.md, "Regime A extended".

Deliberately separate from LAWClient: different endpoint, different token
audience, different KQL dialect, different quota model. Do not merge them.
"""
from __future__ import annotations

import asyncio
import time

import httpx2
from azure.identity.aio import ManagedIdentityCredential

#: Graph, not api.loganalytics.io. A token for one is useless for the other.
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class HuntingUnavailable(Exception):
    """Upstream failure. The message stays in the server log, never the caller."""


class HuntingQuotaExhausted(Exception):
    pass


def _to_table(payload: dict) -> dict:
    """Graph returns a schema list plus row objects; the rest of the server
    works on {columns, rows}.

    Column order comes from `schema`, never from dict iteration order, so a row
    with a missing key still lines up with its header.
    """
    schema = payload.get("schema") or []
    columns = [c.get("Name") for c in schema if c.get("Name")]
    results = payload.get("results") or []
    if not columns and results:
        columns = sorted({k for row in results for k in row})
    rows = [[row.get(c) for c in columns] for row in results]
    return {"columns": columns, "rows": rows, "partial": False, "partial_error": None}


class DefenderHuntingClient:
    def __init__(self, config) -> None:
        self._cfg = config.defender
        self._credential = ManagedIdentityCredential(
            client_id=config.identity.mcp_mi_client_id)
        self._client = httpx2.AsyncClient(
            base_url=str(self._cfg.graph_base_url).rstrip("/"),
            timeout=httpx2.Timeout(self._cfg.timeout_seconds),
        )
        self._minute: tuple[int, int] = (-1, 0)
        self._day: tuple[str, int] = ("", 0)
        self._quota_lock = asyncio.Lock()

    async def _spend_quota(self) -> None:
        """Client-side budget. The real quota is tenant-wide and shared, so
        this bounds THIS server's contribution, not the tenant's consumption."""
        async with self._quota_lock:
            minute = int(time.monotonic() // 60)
            slot, used = self._minute
            if slot != minute:
                slot, used = minute, 0
            if used >= self._cfg.calls_per_minute:
                raise HuntingQuotaExhausted(
                    "Advanced-hunting rate limit reached. Retry in under a minute.")

            today = time.strftime("%Y-%m-%d", time.gmtime())
            day, spent = self._day
            if day != today:
                day, spent = today, 0
            if spent >= self._cfg.daily_call_budget:
                raise HuntingQuotaExhausted(
                    "Daily advanced-hunting budget exhausted. Retry tomorrow.")

            self._minute = (slot, used + 1)
            self._day = (day, spent + 1)

    async def run_query(self, kql: str) -> dict:
        await self._spend_quota()
        try:
            token = await self._credential.get_token(_GRAPH_SCOPE)
            response = await self._client.post(
                "/security/runHuntingQuery",
                json={"Query": kql},
                headers={"Authorization": f"Bearer {token.token}",
                         "Content-Type": "application/json"},
            )
            if response.status_code == 429:
                # Tenant-wide throttle: another consumer is spending the budget.
                raise HuntingQuotaExhausted(
                    "Advanced hunting is throttled tenant-wide. Retry shortly.")
            response.raise_for_status()
            payload = response.json()
        except HuntingQuotaExhausted:
            raise
        except Exception as exc:
            # Class name only: a Graph error body echoes the submitted query.
            raise HuntingUnavailable(type(exc).__name__) from exc
        return _to_table(payload)

    async def close(self) -> None:
        await self._client.aclose()
        await self._credential.close()