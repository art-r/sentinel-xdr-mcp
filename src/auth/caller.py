from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CallerContext:
    type: str          # "human" | "agent"
    id: str            # oid for humans, application id for the agent
    name: str
    client_app_id: str | None = None
    claims: dict = field(default_factory=dict)
