"""Typed configuration, loaded from YAML and validated with Pydantic.

Security-relevant config MUST fail closed and fail at startup:
  * every model sets extra="forbid" - a typo cannot silently disable a control
  * explicit validators reject empty blocklists, unknown tool names, bad tiers
Secrets never live here or in the YAML.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Literal

import yaml
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator, model_validator

DEFAULT_CONFIG_PATH = "/app/config/mcp-server-config.yaml"

#: Every tool the server registers. `allowed_tools` is validated against this,
#: so a typo in config is a startup error rather than a silently denied tool.
KNOWN_TOOLS: frozenset[str] = frozenset({
    "list_available_tables",
    "get_table_schema",
    "query_sentinel_logs",
    "get_incident",
    "get_incident_entities",
    "add_incident_comment",
    "query_defender_hunting",
})

#: Tools that mutate Sentinel. They get their own (much smaller) rate budget.
WRITE_TOOLS: frozenset[str] = frozenset({"add_incident_comment"})

#: Tools reaching data beyond the single Log Analytics workspace the managed
#: identity is scoped to. Their backing credential is tenant-wide and cannot be
#: resource-scoped, so there is no per-caller RBAC backstop for them at all.
#: See trust-model.md, "Regime A extended".
TENANT_WIDE_TOOLS: frozenset[str] = frozenset({"query_defender_hunting"})

#: The only recognised caller tiers. Used by governance and by the audit policy.
CALLER_TYPES: frozenset[str] = frozenset({"human", "agent"})


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _uuid_list(values: list[str]) -> list[str]:
    for v in values:
        uuid.UUID(v)
    return values


class ServerConfig(_Base):
    base_url: AnyHttpUrl
    host: str = "0.0.0.0"
    port: int = 8000
    transport: str = "streamable-http"
    #: Must contain exactly the canonical host from base_url. Local development
    #: hosts are added in code only when dev_mode is true.
    host_header_allowlist: list[str] = Field(min_length=1)
    #: Bound all in-flight tool calls in this process, across every caller.
    max_concurrent_requests: int = Field(default=4, gt=0)
    #: End-to-end ceiling around a tool call. It must exceed every LAW server
    #: timeout so cancellation leaves time for transport cleanup.
    max_request_timeout_seconds: int = Field(default=200, gt=0)
    #: Only in dev_mode may localhost be added to the host allowlist.
    dev_mode: bool = False
    #: expose the unauthenticated /ready endpoint, therefore default is False
    expose_ready_probe: bool = False

    @field_validator("base_url")
    @classmethod
    def _https(cls, v: AnyHttpUrl) -> AnyHttpUrl:
        if v.scheme != "https":
            raise ValueError("server.base_url must be https (it is published in OAuth metadata)")
        return v

    @field_validator("host_header_allowlist")
    @classmethod
    def _canonical_hosts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            host = value.strip().lower().rstrip(".")
            if not host or "://" in host or "/" in host or ":" in host or "*" in host:
                raise ValueError("host_header_allowlist entries must be plain, non-wildcard host names")
            normalized.append(host)
        return normalized

    @model_validator(mode="after")
    def _host_allowlist_matches_base_url(self) -> "ServerConfig":
        base_host = (self.base_url.host or "").lower().rstrip(".")
        if self.host_header_allowlist != [base_host]:
            raise ValueError(
                "server.host_header_allowlist must contain exactly server.base_url.host; "
                "localhost is added automatically only when dev_mode is true"
            )
        return self


class IdentityConfig(_Base):
    tenant_id: str
    mcp_app_client_id: str
    mcp_mi_client_id: str
    #: Client applications allowed to present DELEGATED tokens. Required:
    #: pre-authorisation in Entra only suppresses the consent prompt, it does
    #: not restrict which apps may request the scope.
    allowed_client_app_ids: list[str] = Field(min_length=1)
    #: Applications allowed to present APP-ONLY tokens (the agent's MI).
    #: May be empty until the agent exists.
    allowed_agent_app_ids: list[str] = Field(default_factory=list)
    required_delegated_scope: str = "user_impersonation"
    required_human_role: str = "Sentinel.Read"
    required_agent_role: str = "MCP.Agent"
    #: RFC 9728 defines the metadata `resource` value as this server's canonical
    #: URL, and FastMCP derives it from server.base_url. Entra rejects the
    #: RFC 8707 `resource` parameter a client copies from that value
    #: (AADSTS9010010 invalid_target) unless it equals the prefix of the
    #: requested scope - i.e. `api://<mcp_app_client_id>`. The ACA-generated
    #: hostname cannot be registered as an Entra identifier URI, so the two
    #: strings cannot be reconciled in Entra.
    #:
    #: True advertises the App ID URI instead. This is a deliberate deviation
    #: from RFC 9728 section 3.3, NOT a relaxation of authentication: both
    #: strings name the same application, the issued token still carries
    #: aud=<mcp_app_client_id>, and EntraCallerVerifier still pins that
    #: audience. What it costs is interoperability - a client that validates
    #: the advertised resource against the URL it fetched the document from
    #: will refuse to connect.
    #:
    #: Revert to false once server.base_url is a custom domain registered as an
    #: identifier URI on the app registration, which removes the mismatch.
    advertise_app_id_uri_as_oauth_resource: bool = False

    @field_validator("tenant_id", "mcp_app_client_id", "mcp_mi_client_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        uuid.UUID(v)
        return v

    @field_validator("allowed_client_app_ids", "allowed_agent_app_ids")
    @classmethod
    def _uuids(cls, v: list[str]) -> list[str]:
        return _uuid_list(v)

    @property
    def delegated_scope_uri(self) -> str:
        """Fully-qualified scope, published in the protected-resource metadata.

        Enforcement still lives in `authorize()`; this only tells a compliant
        MCP client which scope to request (report M-4).
        """
        return f"api://{self.mcp_app_client_id}/{self.required_delegated_scope}"

    @property
    def oauth_resource_id(self) -> str | None:
        """Override for the metadata `resource` value, or None to keep the
        canonical server URL FastMCP derives from server.base_url.

        Derived, never configured as a free string: the flag cannot be pointed
        at an arbitrary URI by a config edit, and the value is guaranteed to be
        the prefix of `delegated_scope_uri`.
        """
        if not self.advertise_app_id_uri_as_oauth_resource:
            return None
        return f"api://{self.mcp_app_client_id}"


class LawConfig(_Base):
    workspace_id: str
    subscription_id: str
    resource_group: str
    workspace_name: str

    @field_validator("workspace_id", "subscription_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        uuid.UUID(v)
        return v

    @property
    def resource_id(self) -> str:
        """Derived, never configured: the previous YAML key was hand-written and
        had law.workspace_id pasted into the subscription segment."""
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )


class GovernanceTier(_Base):
    max_timespan_days: int = Field(gt=0)
    max_result_rows: int = Field(gt=0)
    max_query_timeout_seconds: int = Field(gt=0)
    max_concurrent_queries: int = Field(gt=0)
    rate_limit_queries_per_minute: int = Field(gt=0)
    #: Separate, deliberately small budget for mutating tools.
    rate_limit_writes_per_minute: int = Field(default=3, gt=0)
    max_result_size_mb: int = Field(gt=0)
    #: Caps that used to be hardcoded in the tool modules (report M-8). Keeping
    #: them in config means extra="forbid" and the startup validators cover
    #: them too.
    max_entities: int = Field(default=500, gt=0)
    max_schema_columns: int = Field(default=500, gt=0)
    max_comment_chars: int = Field(default=30_000, gt=0)
    max_cell_chars: int = Field(default=4096, gt=0)
    allowed_tables: list[str] = Field(min_length=1)
    allowed_tools: list[str] = Field(min_length=1)
    #: How `allowed_tables` is interpreted.
    #:
    #:   "allowlist" - only the tables in the listed tiers are queryable.
    #:   "workspace" - every table in the workspace is queryable except
    #:                 `tables.blocked`, and `allowed_tables` degrades to a
    #:                 discovery hint used when live enumeration fails.
    #:
    #: "workspace" is defensible only where the caller already holds equivalent
    #: Azure RBAC on the workspace directly, so the allowlist is friction rather
    #: than a boundary (see trust-model.md). It is NOT defensible for a caller
    #: holding a write tool - see the validator in Config._check.
    #:
    #: Under "workspace", `tables.blocked` IS the access policy. Review it as
    #: one: it is an exact-name list with no wildcards, so a custom table added
    #: to the workspace later is readable from the day it appears.
    table_policy: Literal["allowlist", "workspace"] = "allowlist"

    def rate_limit_for(self, tool_name: str) -> int:
        if tool_name in WRITE_TOOLS:
            return self.rate_limit_writes_per_minute
        return self.rate_limit_queries_per_minute

    @property
    def max_result_size_bytes(self) -> int:
        return self.max_result_size_mb * 1024 * 1024


class TablesConfig(_Base):
    tier1: list[str] = Field(min_length=1)
    tier2: list[str] = Field(default_factory=list)
    blocked: list[str] = Field(min_length=1)


class KqlConfig(_Base):
    max_query_length: int = Field(default=4000, gt=0)
    #: Rejected when used as a FUNCTION - i.e. the next token is "(".
    #: The check is token-based, so "workspace ('other')" is caught whatever the
    #: spacing, while a column named `app` is not a false positive.
    banned_functions: list[str] = Field(min_length=1)
    #: Rejected when used as an OPERATOR - at the start of the query or straight
    #: after a "|". So `search`/`find`/`let` are blocked, but `extend range = 1`
    #: is fine.
    banned_operators: list[str] = Field(min_length=1)


class LoggingConfig(_Base):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    application_insights_connection_string: str | None = None
    #: Caller tiers whose raw query/comment text may be written to the audit
    #: log. Humans are excluded by default: an analyst's KQL embeds the subject
    #: of the investigation (UPNs, hosts, IPs, hashes) and must not be mirrored
    #: into a second log store (report H-2). Agent KQL is machine-generated and
    #: is logged verbatim so agent behaviour stays reviewable.
    log_query_text_for: list[str] = Field(default_factory=lambda: ["agent"])
    #: Log the human caller's UPN alongside their immutable object id. Keep on
    #: for SOC accountability; turn off if your retention policy forbids it.
    log_caller_upn: bool = True

    @field_validator("log_query_text_for")
    @classmethod
    def _known_tiers(cls, v: list[str]) -> list[str]:
        unknown = set(v) - CALLER_TYPES
        if unknown:
            raise ValueError(f"logging.log_query_text_for: unknown caller type(s) {sorted(unknown)}")
        return v

class DefenderKqlConfig(_Base):
    """KQL restrictions for the Defender advanced-hunting dialect.

    A SEPARATE profile from `kql`, not a copy. Advanced hunting has enrichment
    functions that return data beyond the tables named in the query, which the
    Sentinel profile has never needed to know about.
    """
    max_query_length: int = Field(default=4000, gt=0)
    banned_functions: list[str] = Field(min_length=1)
    banned_operators: list[str] = Field(min_length=1)


class DefenderConfig(_Base):
    """Defender XDR advanced hunting via Microsoft Graph.

    Disabled by default. Enabling it grants this server tenant-wide read of the
    XDR hunting corpus through a Graph application permission that cannot be
    scoped to device groups. Do not enable without reading trust-model.md,
    "Regime A extended", and confirming the precondition recorded there.
    """
    enabled: bool = False
    graph_base_url: AnyHttpUrl = "https://graph.microsoft.com/v1.0"  # type: ignore[assignment]
    #: Must stay below server.max_request_timeout_seconds - enforced in _check.
    timeout_seconds: int = Field(default=170, gt=0)
    max_result_rows: int = Field(default=5000, gt=0)
    max_result_size_mb: int = Field(default=10, gt=0)
    max_cell_chars: int = Field(default=4096, gt=0)
    #: Microsoft's advanced-hunting quota is TENANT-WIDE and shared with every
    #: other consumer of the API. These counters are per replica, so with
    #: min == max == 1 they are exact for this server but say nothing about
    #: what else in the tenant is spending the same budget. Keep them well
    #: under the documented ceiling; verify the current limits in Microsoft's
    #: documentation before raising them.
    calls_per_minute: int = Field(default=10, gt=0)
    daily_call_budget: int = Field(default=500, gt=0)
    #: Additional app role required ON TOP of identity.required_human_role.
    #: Checked by the tool, so it is a second, independently reviewable
    #: assignment list rather than a widening of the existing role.
    required_role: str = "Defender.Hunt"
    #: Advanced hunting has no `Usage` table, so live discovery is impossible
    #: and this list is authoritative. Adding a table here is an access
    #: decision.
    allowed_tables: list[str] = Field(min_length=1)
    #: Blocked wins over allowed, mirroring tables.blocked. Defence in depth
    #: against a careless edit to the list above.
    blocked_tables: list[str] = Field(default_factory=list)
    kql: DefenderKqlConfig

    @property
    def max_result_size_bytes(self) -> int:
        return self.max_result_size_mb * 1024 * 1024

class Config(_Base):
    server: ServerConfig
    identity: IdentityConfig
    law: LawConfig
    tables: TablesConfig
    governance: dict[str, GovernanceTier]
    kql: KqlConfig
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    defender: DefenderConfig | None = None

    @model_validator(mode="after")
    def _check(self) -> "Config":
        if set(self.governance) != CALLER_TYPES:
            raise ValueError("governance must define exactly 'human' and 'agent'")
        tiers = self.tier_map()
        for name, gov in self.governance.items():
            # An open read surface plus a write tool is the indirect-injection
            # chain in trust-model.md: attacker-planted content is read, then
            # written back to an incident with no human in the loop. Widening
            # what can be read widens the input side of that chain.
            if gov.table_policy == "workspace" and WRITE_TOOLS & set(gov.allowed_tools):
                raise ValueError(
                    f"governance.{name}: table_policy 'workspace' must not be combined "
                    f"with write tools {sorted(WRITE_TOOLS & set(gov.allowed_tools))}"
                )
            hunting = TENANT_WIDE_TOOLS & set(gov.allowed_tools)
            if hunting:
                if self.defender is None or not self.defender.enabled:
                    raise ValueError(
                        f"governance.{name}.allowed_tools contains {sorted(hunting)} "
                        "but defender.enabled is false. Enabling or disabling Defender "
                        "hunting is TWO edits: the defender.enabled flag AND the tool "
                        "entry in allowed_tools. Remove the tool, or enable the feature."
                    )
                if WRITE_TOOLS & set(gov.allowed_tools):
                    raise ValueError(
                        f"governance.{name}: {sorted(hunting)} must not be combined with "
                        f"write tool(s) {sorted(WRITE_TOOLS & set(gov.allowed_tools))}. "
                        "Tenant-wide read plus a write path closes the indirect-injection "
                        "loop in trust-model.md across the whole XDR corpus."
                    )
                if name != "human":
                    raise ValueError(
                        f"governance.{name}: {sorted(hunting)} is restricted to the human "
                        "tier. Tenant-wide unscoped access requires an accountable, "
                        "named caller."
                    )
            unknown_tiers = set(gov.allowed_tables) - set(tiers)
            if unknown_tiers:
                raise ValueError(f"governance.{name}.allowed_tables: unknown tier(s) {sorted(unknown_tiers)}")
            unknown_tools = set(gov.allowed_tools) - KNOWN_TOOLS
            if unknown_tools:
                raise ValueError(f"governance.{name}.allowed_tools: unknown tool(s) {sorted(unknown_tools)}")
        if WRITE_TOOLS & set(self.governance["human"].allowed_tools):
            raise ValueError("human tier must not be granted write tools")
        if self.defender is not None and self.defender.enabled:
            if self.server.max_request_timeout_seconds <= self.defender.timeout_seconds:
                raise ValueError(
                    "server.max_request_timeout_seconds must exceed "
                    "defender.timeout_seconds"
                )
            if not self.defender_tables():
                raise ValueError("defender resolves to zero allowed tables")
        if not self.allowed_tables_for("human"):
            raise ValueError("human tier resolves to zero allowed tables")
        if self.defender is not None and self.defender.enabled:
            users = [name for name, gov in self.governance.items()
                     if TENANT_WIDE_TOOLS & set(gov.allowed_tools)]
            if not users:
                raise ValueError(
                    "defender.enabled is true but no tier lists "
                    f"{sorted(TENANT_WIDE_TOOLS)} in allowed_tools. The store would "
                    "be discoverable through list_available_tables while the query "
                    "tool is filtered out of tools/list - a data source the caller "
                    "can see and cannot use. Enabling Defender hunting is TWO edits."
                )
        longest_query_timeout = max(tier.max_query_timeout_seconds for tier in self.governance.values())
        if self.server.max_request_timeout_seconds <= longest_query_timeout:
            raise ValueError(
                "server.max_request_timeout_seconds must exceed every tier's "
                "max_query_timeout_seconds"
            )
        return self

    # ---- table helpers -------------------------------------------------

    def tier_map(self) -> dict[str, list[str]]:
        return {"tier1": self.tables.tier1, "tier2": self.tables.tier2}

    def allowed_tables_for(self, caller_type: str) -> set[str]:
        gov = self.governance[caller_type]
        tiers = self.tier_map()
        tables: set[str] = set()
        for tier in gov.allowed_tables:
            tables.update(tiers.get(tier, []))
        blocked = {b.lower() for b in self.tables.blocked}
        return {t for t in tables if t.lower() not in blocked}

    def is_table_blocked(self, name: str) -> bool:
        """Case-insensitive: KQL table names are case-insensitive at the engine."""
        return name.lower() in {b.lower() for b in self.tables.blocked}

    def table_policy_for(self, caller_type: str) -> str:
        return self.governance[caller_type].table_policy

    def is_table_allowed(self, caller_type: str, name: str) -> bool:
        # Blocked wins under every policy, checked first so the rule holds even
        # if a blocked table is also listed in a tier.
        if self.is_table_blocked(name):
            return False
        if self.table_policy_for(caller_type) == "workspace":
            return True
        return name.lower() in {t.lower() for t in self.allowed_tables_for(caller_type)}

    def is_defender_table_blocked(self, name: str) -> bool:
        if self.defender is None:
            return True
        return name.lower() in {t.lower() for t in self.defender.blocked_tables}

    def is_defender_table_allowed(self, name: str) -> bool:
        """Always an explicit allowlist. There is no `workspace` policy for
        Defender: advanced hunting has no table-enumeration endpoint, so
        "everything except the blocklist" could not be bounded or reviewed."""
        if self.defender is None or not self.defender.enabled:
            return False
        if self.is_defender_table_blocked(name):
            return False
        return name.lower() in {t.lower() for t in self.defender.allowed_tables}

    def defender_tables(self) -> set[str]:
        if self.defender is None:
            return set()
        blocked = {t.lower() for t in self.defender.blocked_tables}
        return {t for t in self.defender.allowed_tables if t.lower() not in blocked}


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("CONFIG_PATH", DEFAULT_CONFIG_PATH)
    data = yaml.safe_load(Path(path).read_text())
    log = data.setdefault("logging", {})
    if cs := os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING"):
        log["application_insights_connection_string"] = cs
    return Config.model_validate(data)
