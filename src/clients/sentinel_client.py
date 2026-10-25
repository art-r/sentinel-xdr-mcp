from __future__ import annotations

import asyncio
import uuid

#: Generated name for the incident-comment write, newest first. The REST
#: operation is "Create Or Update" (PUT .../comments/{id}); 1.x generates
#: `create_or_update`, older generations used `create_comment` / `create`.
COMMENT_CREATE_METHODS = ("create_or_update", "create_comment", "create")


def _resolve(operations, candidates: tuple[str, ...], label: str):
    """First callable among `candidates`, or a loud error naming what is there."""
    for name in candidates:
        fn = getattr(operations, name, None)
        if callable(fn):
            return fn
    available = sorted(n for n in dir(operations) if not n.startswith("_"))
    raise RuntimeError(
        f"azure-mgmt-securityinsight: none of {candidates} exist on {label}. "
        f"Your installed SDK version is incompatible. Available: {available}"
    )


class SentinelClient:
    """Security Insights (Sentinel) wrapper. Sync SDK calls run in worker
    threads. Uses the server's Managed Identity.

    Correction vs spec: an incident's SDK resource identity is a GUID (resource
    *name*), not the human 'incident number'. Tools accept the number; we resolve
    it to the GUID via an OData filter on properties/incidentNumber.

    Pinned to azure-mgmt-securityinsight 1.x. Do NOT move to 2.0.0bN: those are
    pre-releases, and 2.0.0b3 renames the client to SecurityInsightsMgmtClient
    and moves model fields under `.properties` (hybrid models). Both break the
    code below.
    """

    def __init__(self, config) -> None:
        from azure.identity import ManagedIdentityCredential
        from azure.mgmt.securityinsight import SecurityInsights

        self.config = config
        self._rg = config.law.resource_group
        self._ws = config.law.workspace_name
        self._credential = ManagedIdentityCredential(client_id=config.identity.mcp_mi_client_id)
        self._client = SecurityInsights(self._credential, config.law.subscription_id)
        # Resolve the write method NOW, not on first use. The underlying REST
        # operation is "Create Or Update"; the generated method name has moved
        # across SDK generations. Failing here means a bad SDK pin surfaces on
        # the first Sentinel call, not silently at 3am on the one write path.
        self._create_comment = _resolve(
            self._client.incident_comments, COMMENT_CREATE_METHODS, "incident_comments")

    async def _guid_for_number(self, number: str) -> str:
        def _list():
            return list(self._client.incidents.list(
                self._rg, self._ws, filter=f"properties/incidentNumber eq {int(number)}"))

        items = await asyncio.to_thread(_list)
        if not items:
            raise ValueError(f"Incident {number} not found")
        return items[0].name

    async def get_incident(self, number: str) -> dict:
        guid = await self._guid_for_number(number)
        inc = await asyncio.to_thread(self._client.incidents.get, self._rg, self._ws, guid)
        return _incident_to_dict(inc)

    async def get_incident_entities(self, number: str) -> list[dict]:
        guid = await self._guid_for_number(number)
        resp = await asyncio.to_thread(self._client.incidents.list_entities, self._rg, self._ws, guid)
        entities = getattr(resp, "entities", None) or []
        return [{"entity_type": getattr(e, "kind", None),
                 "properties": e.as_dict() if hasattr(e, "as_dict") else {}} for e in entities]

    async def add_comment(self, number: str, message: str) -> dict:
        from azure.mgmt.securityinsight.models import IncidentComment

        guid = await self._guid_for_number(number)
        comment_id = str(uuid.uuid4())

        def _create():
            return self._create_comment(
                self._rg, self._ws, guid, comment_id, IncidentComment(message=message))

        res = await asyncio.to_thread(_create)
        return {"success": True, "comment_id": getattr(res, "name", comment_id)}

    async def close(self) -> None:
        await asyncio.to_thread(self._client.close)
        await asyncio.to_thread(self._credential.close)


def _incident_to_dict(inc) -> dict:
    ad = getattr(inc, "additional_data", None)
    owner = getattr(inc, "owner", None)
    labels = getattr(inc, "labels", None) or []
    return {
        "id": getattr(inc, "name", None),
        "incident_number": getattr(inc, "incident_number", None),
        "title": getattr(inc, "title", None),
        "severity": getattr(inc, "severity", None),
        "status": getattr(inc, "status", None),
        "description": getattr(inc, "description", None),
        "owner": owner.as_dict() if hasattr(owner, "as_dict") else None,
        "labels": [l.as_dict() if hasattr(l, "as_dict") else l for l in labels],
        "created_time_utc": str(getattr(inc, "created_time_utc", None)),
        "last_modified_time_utc": str(getattr(inc, "last_modified_time_utc", None)),
        "alerts_count": getattr(ad, "alerts_count", None) if ad else None,
        "alert_product_names": getattr(ad, "alert_product_names", None) if ad else None,
    }
