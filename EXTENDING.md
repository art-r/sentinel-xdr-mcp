# Extending the server

How to add a tool or an integration without breaking the properties the rest of
the repo exists to hold. Written to be followed by a human or an AI coding
agent; the machine-readable procedure is in the last section.

Read [trust-model.md](trust-model.md) first. Read
[ai-instructions.md](ai-instructions.md) second. This document assumes both.

---

## 0. The decision gate

Three questions, in order. A "no" at any of them stops the work.

**Does it need to be a tool at all?** Tools cost context window on every
`tools/list`, and a model that sees eleven tools chooses worse than one that
sees six. Anything the model can do itself — parse a timestamp, reformat JSON,
compute a ratio — is not a tool. Anything that is one KQL query away is a
*prompt*, not a tool.

**Does data leave the tenant?** If yes, this is a Class C change (below) and it
modifies the trust model. It needs the same review as a change to
`src/auth/` — not a feature review.

**Does it write anything?** Write tools are agent-only, get their own rate
budget, and force `table_policy: "allowlist"` on the tier holding them. A second
write tool roughly doubles the blast radius described in trust-model.md; the
single-write-tool design is load-bearing, not incidental.

---

## 1. Three classes of extension

| Class | Example | What it touches |
|---|---|---|
| **A** — new tool over existing clients | `get_incident_alerts`, `list_incidents` | tool module, `KNOWN_TOOLS`, config, tests |
| **B** — new Azure data source | Defender XDR advanced hunting, Entra risk detections | + new client, + MI RBAC, + egress destination |
| **C** — external third-party API | AbuseIPDB, VirusTotal, GreyNoise, MISP | + a secret, + egress, + **tenant data leaves**, + a new untrusted-content source |

Class A is an afternoon. Class B is a day plus an RBAC review. **Class C is a
trust-model change** and the rest of this document is mostly about doing it
safely.

---

## 2. Invariants you may not break

These are not style preferences. Each one exists because its absence caused a
defect that is recorded in `sec-findings-report.md`.

| Rule | Why |
|---|---|
| Resolve the caller with `deps.require_caller(ctx)` | Re-derived from the verified token every call. Never `Context` state — that is session-scoped and keyed by a client-supplied value. |
| **No** rate limiting, concurrency limiting or timeouts inside a tool | They live in `AuthorizationMiddleware`, once, for every tool. Five of six tools were once unmetered because they were expected to do it themselves. |
| Raise `ToolError` for every rejection | FastMCP masks other exception types into a generic internal error. A `PermissionError` tells the caller nothing. |
| Audit through `deps.audit`, never a bare logger | Redaction lives in `AuditLogger`. A tool that logs directly bypasses it. |
| Never log query results, response bodies, or exception **messages** | Azure and third-party errors routinely echo the failing input. Log `type(exc).__name__`. |
| Every data-returning tool scrubs and labels | `scrub_value(payload, gov.max_cell_chars)` plus `content_warning: UNTRUSTED_NOTE`, or use `truncate` / `truncate_list` which do both. |
| Every new tool name goes in `KNOWN_TOOLS` | Otherwise `extra="forbid"` config validation rejects it as a typo and the server will not boot. |
| Free-text tool arguments go in `_SENSITIVE_ARGS` | `src/logging_setup.py`. Otherwise an analyst's investigation subject is written verbatim to a second log store. |
| `Field(pattern=...)` must be **anchored** and Rust-regex-safe | pydantic-core uses the Rust `regex` crate: no look-around, no backreferences, and it *searches* rather than full-matches. `tests/test_tool_patterns.py` enforces both. |
| New clients are lazy properties on `Deps` and are closed in `aclose()` | Construction at import time makes the module unimportable in a test process. |
| Nothing external goes in `check_ready()` | Readiness means "can this server query its workspace". A third-party outage must not make the whole server unready. |
| One worker, one replica | Every limit is process-local. |

---

## 3. Class A — a new tool over existing clients

Six edits. `get_incident_alerts` as the shape:

1. **`src/config.py`** — add the name to `KNOWN_TOOLS`.
2. **`src/tools/<module>.py`** — write the function, register with
   `mcp.tool(fn)` at the bottom of the module.
3. **`src/server.py`** — add the module to the bottom import line, or it is
   never registered.
4. **`config/mcp-server-config.example.yaml`** and your per-tenant config — add
   the name to `allowed_tools` for each tier that should have it. A tool absent
   from `allowed_tools` is filtered out of `tools/list` and denied by
   `on_call_tool`; it is invisible, not broken.
5. **`src/clients/…`** — a new method if needed. Keep the Azure SDK shape
   confined to the client; tools receive plain dicts.
6. **Tests** — see §6.

The canonical tool body, copied from `src/tools/incidents.py`:

```python
async def get_incident_alerts(incident_id: Annotated[str, _ID], ctx: Context) -> dict:
    """One-line summary the model reads. Say what it returns and when to use it."""
    caller = deps.require_caller(ctx)
    gov = deps.config.governance[caller.type]
    args = {"incident_id": incident_id}
    start = time.monotonic()
    try:
        alerts = await deps.sentinel_client.get_incident_alerts(incident_id)
    except ValueError as exc:
        # Caller-supplied identifier only - safe to echo.
        deps.audit.log_tool_call(caller, "get_incident_alerts", args,
                                 validation_result="not_found")
        raise ToolError(str(exc)) from None
    except Exception as exc:
        deps.audit.log_tool_failure(caller, "get_incident_alerts", args, error=exc,
                                    duration_ms=int((time.monotonic() - start) * 1000))
        raise ToolError("Could not retrieve alerts (Sentinel is unavailable or "
                        "refused the request).") from None
    out = truncate_list(alerts, gov.max_entities, gov.max_result_size_bytes,
                        gov.max_cell_chars)
    deps.audit.log_tool_call(caller, "get_incident_alerts", args,
                             result_row_count=out["count"], truncated=out["truncated"],
                             duration_ms=int((time.monotonic() - start) * 1000))
    return out
```

Note the two-branch `except`: `ValueError` carries a caller-supplied identifier
and is safe to return; everything else is generic. Do not collapse them.

The docstring is a prompt. It is the only thing the model reads before deciding
to call the tool. Write it for the model, not for a developer.

---

## 4. Class C — an external integration

### 4.1 What changes, before any code

| Change | Consequence |
|---|---|
| Tenant data leaves | Every lookup discloses what your SOC is investigating. Check the vendor's retention and data-sharing terms; some resell submitted indicators. |
| Attacker-authored content arrives | Free-text vendor fields are a *targeted* injection channel: an attacker can plant content and then trigger the lookup. |
| A secret exists | Rotation, expiry, storage, and a new thing that can leak in a log line. |
| A new egress destination | A firewall or VNet rule; a new way for the container to fail. |
| A new availability dependency | The vendor's outage is now your tool's outage. |
| A vendor-side quota | Account-wide, not per-caller. Your per-caller limiter cannot bound it. |

### 4.2 Reconciling with the "no secrets" invariant

`ai-instructions.md` bans secrets. That ban is about the **identity path** — no
client secret, no certificate, no Key Vault fetch, no OBO. Its purpose is that
*authorization decisions require no credential the server holds*, so there is
nothing to steal that grants access to Sentinel.

An **outbound data-source API key** is a different category: it authenticates
this server to a third party, grants nothing in this tenant, and cannot
influence any authorization decision. It is permitted under the conditions
below. Amend §1/§3 of `ai-instructions.md` before merging, or the invariant and
the code disagree.

Conditions:

- Delivered as an environment variable from an ACA secret, ideally a Key Vault
  reference resolved by the platform. **Never** in YAML — `config.py` states
  "Secrets never live here", and that stays true.
- Injected in `load_config()`, the same way
  `APPLICATIONINSIGHTS_CONNECTION_STRING` already is.
- Absent at startup with the integration enabled ⇒ **startup failure**, not a
  runtime surprise.
- Never logged. `httpx2` is already pinned to WARNING in `_NOISY_LOGGERS`; keep
  it that way, and never log a request object.

```bash
# Platform-resolved Key Vault reference: the key is not in the ACA config,
# not in the image, and rotates without a redeploy.
az containerapp secret set -g "$RG" -n sentinel-mcp \
  --secrets abuseipdb-key=keyvaultref:https://<vault>.vault.azure.net/secrets/abuseipdb-key,identityref:$MI_RESOURCE_ID

az containerapp update -g "$RG" -n sentinel-mcp \
  --set-env-vars ABUSEIPDB_API_KEY=secretref:abuseipdb-key
```

The MI needs `Key Vault Secrets User` on the vault. The application code never
talks to Key Vault — the platform resolves the reference — so the invariant
against a Key Vault client in `src/` holds.

### 4.3 The five controls that make Class C survivable

**1. Constrain the parameter, hard.** A free-form string parameter on an
outbound tool is an exfiltration channel: an injected instruction can put
arbitrary tenant data into it and the vendor's access log becomes the
attacker's dead drop. Accept one narrow indicator type, validated twice.

```python
# Shape gate only. Rust-regex-safe and anchored (tests/test_tool_patterns.py).
# Real validation is ipaddress.ip_address() in the client - do not attempt a
# full IP grammar here, it needs look-around that pydantic-core cannot compile.
_IP = Field(pattern=r"^[0-9A-Fa-f:.]{3,45}$",
            description="A single public IPv4 or IPv6 address")
```

**2. Refuse non-routable addresses before the call.** RFC1918, loopback,
link-local, CGNAT and reserved space are useless to a reputation service and
leaking them discloses your internal topology. `ipaddress.ip_address(x).is_global`
is one check that covers all of them.

**3. Project a field allowlist. Never pass the response through.** This is the
strongest control available and it costs nothing. Do not request verbose
output; take the score and the structured metadata, drop everything else. A
vendor adding a free-text field next quarter then cannot reach the model.

**4. Bound the vendor quota in-process.** A daily counter in the client. It is
per-replica like everything else — with `min == max == 1` that is exact; if the
key is shared with other consumers it is advisory, so say so in config.

**5. Fail closed on the tier that can write.** A tier holding both an external
tool and a write tool closes the injection loop. Default deny, explicit opt-in
named after the risk.

### 4.4 Worked example — AbuseIPDB

#### `src/config.py`

Add near `WRITE_TOOLS`:

```python
#: Tools that call a service outside this tenant. Tenant data leaves and
#: third-party content comes back; both are trust-model events. See
#: EXTENDING.md section 4.
EXTERNAL_TOOLS: frozenset[str] = frozenset({"get_ip_reputation"})
```

Add `"get_ip_reputation"` to `KNOWN_TOOLS`.

New models:

```python
class AbuseIPDBConfig(_Base):
    enabled: bool = False
    base_url: AnyHttpUrl = "https://api.abuseipdb.com/api/v2"  # type: ignore[assignment]
    max_age_days: int = Field(default=90, gt=0, le=365)
    timeout_seconds: int = Field(default=10, gt=0)
    cache_ttl_seconds: int = Field(default=3600, ge=0)
    #: Vendor-side quota is account-wide; this counter is per replica. Exact at
    #: one replica, advisory if the key is shared with other consumers.
    daily_quota: int = Field(default=1000, gt=0)
    #: Permit a tier that holds a write tool to call this. That closes the loop
    #: in trust-model.md: attacker-planted text is read, a lookup returns more
    #: third-party text, and the result can be written back to an incident with
    #: no human in the path. Default deny.
    permit_for_write_tiers: bool = False
    #: Injected from ABUSEIPDB_API_KEY by load_config. Never present in YAML.
    api_key: str | None = Field(default=None, exclude=True)


class IntegrationsConfig(_Base):
    abuseipdb: AbuseIPDBConfig = Field(default_factory=AbuseIPDBConfig)
```

Add to `Config`:

```python
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)
```

Add to `Config._check`, inside the existing per-tier loop:

```python
            external = EXTERNAL_TOOLS & set(gov.allowed_tools)
            if external:
                if not self.integrations.abuseipdb.enabled:
                    raise ValueError(
                        f"governance.{name}.allowed_tools contains external tool(s) "
                        f"{sorted(external)} but integrations.abuseipdb.enabled is false"
                    )
                if (WRITE_TOOLS & set(gov.allowed_tools)
                        and not self.integrations.abuseipdb.permit_for_write_tiers):
                    raise ValueError(
                        f"governance.{name}: external tool(s) {sorted(external)} combined "
                        f"with write tool(s) {sorted(WRITE_TOOLS & set(gov.allowed_tools))}. "
                        "Set integrations.abuseipdb.permit_for_write_tiers to accept the "
                        "injection-amplification risk in trust-model.md."
                    )
```

And in the same method, after the tier loop:

```python
        if self.integrations.abuseipdb.enabled and not self.integrations.abuseipdb.api_key:
            raise ValueError(
                "integrations.abuseipdb.enabled is true but ABUSEIPDB_API_KEY is not set"
            )
```

Extend `load_config`, mirroring the App Insights injection exactly:

```python
    if key := os.environ.get("ABUSEIPDB_API_KEY"):
        data.setdefault("integrations", {}).setdefault("abuseipdb", {})["api_key"] = key
```

`exclude=True` on `api_key` keeps it out of `model_dump()`, which
`tests/test_config.py::_raw()` round-trips.

#### `src/logging_setup.py`

```python
_SENSITIVE_ARGS = frozenset({"kql", "executed_kql", "comment", "ip"})
```

An indicator under investigation is the same class of data as an analyst's KQL:
it names the subject. This hashes it for humans and logs it verbatim for the
agent, per the existing `log_query_text_for` policy. Reuse the policy; do not
invent a second one.

#### `src/clients/abuseipdb_client.py`

```python
"""AbuseIPDB reputation lookup.

WARNING: this client sends tenant data to a third party. Every address passed
here discloses to AbuseIPDB which IPs this SOC is investigating.

Two controls are load-bearing and must not be relaxed:

  * non-routable addresses are refused BEFORE the request - private space is
    useless to a reputation service and leaks internal topology;
  * the response is PROJECTED through a field allowlist, and `verbose` is never
    requested. Verbose returns user-submitted report comments: free text written
    by anyone, about an address an attacker can choose, which is a targeted
    prompt-injection channel into an analyst's context.
"""
from __future__ import annotations

import ipaddress
import time

import httpx

#: Response fields copied to the caller. Everything else is dropped, so a
#: vendor-side schema addition cannot reach the model. Extending this list is a
#: trust-model decision, not a bug fix.
_FIELDS = (
    "ipAddress", "isPublic", "ipVersion", "abuseConfidenceScore", "countryCode",
    "usageType", "isp", "domain", "totalReports", "numDistinctUsers", "lastReportedAt",
)

_MAX_CACHE = 4096


class EnrichmentUnavailable(Exception):
    """Upstream failure. The message stays in the server log."""


class QuotaExhausted(Exception):
    pass


class NonRoutableAddress(ValueError):
    """Refused before the request: this address must not leave the tenant."""


class AbuseIPDBClient:
    def __init__(self, config) -> None:
        self._cfg = config.integrations.abuseipdb
        self._client = httpx.AsyncClient(
            base_url=str(self._cfg.base_url),
            timeout=httpx.Timeout(self._cfg.timeout_seconds),
            headers={"Accept": "application/json"},
        )
        self._cache: dict[str, tuple[float, dict]] = {}
        self._day: tuple[str, int] = ("", 0)

    @staticmethod
    def assert_routable(ip: str) -> None:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise NonRoutableAddress("Not a valid IP address") from None
        # is_global is False for RFC1918, loopback, link-local, CGNAT,
        # multicast, documentation and reserved ranges - one check, all of them.
        if not address.is_global:
            raise NonRoutableAddress(
                "Private, reserved or non-routable addresses are not sent to "
                "external reputation services."
            )

    def _spend_quota(self) -> None:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        day, used = self._day
        if day != today:
            day, used = today, 0
        if used >= self._cfg.daily_quota:
            raise QuotaExhausted("Daily reputation-lookup quota exhausted.")
        self._day = (day, used + 1)

    async def check_ip(self, ip: str) -> dict:
        self.assert_routable(ip)

        cached = self._cache.get(ip)
        now = time.monotonic()
        if cached and now - cached[0] < self._cfg.cache_ttl_seconds:
            return cached[1]

        self._spend_quota()
        try:
            response = await self._client.get(
                "/check",
                params={"ipAddress": ip, "maxAgeInDays": self._cfg.max_age_days},
                headers={"Key": self._cfg.api_key},
            )
            response.raise_for_status()
            payload = response.json().get("data") or {}
        except Exception as exc:
            # Class name only: an upstream error body can echo the request.
            raise EnrichmentUnavailable(type(exc).__name__) from exc

        projected = {k: payload.get(k) for k in _FIELDS if k in payload}
        if len(self._cache) >= _MAX_CACHE:
            self._cache.clear()
        self._cache[ip] = (now, projected)
        return projected

    async def close(self) -> None:
        await self._client.aclose()
```

#### `src/server.py`

```python
        self._abuseipdb_client: "AbuseIPDBClient | None" = None

    @property
    def abuseipdb_client(self):
        from src.clients.abuseipdb_client import AbuseIPDBClient
        if self._abuseipdb_client is None:
            self._abuseipdb_client = AbuseIPDBClient(self.config)
        return self._abuseipdb_client
```

Add it to the tuple in `aclose()`, and add the module to the bottom import line:

```python
from src.tools import comments, enrichment, incidents, query_logs, schema_discovery  # noqa
```

#### `src/tools/enrichment.py`

```python
from __future__ import annotations

import time
from typing import Annotated

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import Field

from src.clients.abuseipdb_client import (
    EnrichmentUnavailable, NonRoutableAddress, QuotaExhausted,
)
from src.governance.sanitize import UNTRUSTED_NOTE, scrub_value
from src.server import deps, mcp

#: Shape gate only. Anchored and Rust-regex-safe (tests/test_tool_patterns.py);
#: real validation is ipaddress.ip_address() inside the client.
_IP = Field(pattern=r"^[0-9A-Fa-f:.]{3,45}$",
            description="A single public IPv4 or IPv6 address")


async def get_ip_reputation(ip: Annotated[str, _IP], ctx: Context) -> dict:
    """Look up the abuse reputation of a single PUBLIC IP address in AbuseIPDB.

    Returns an abuse confidence score (0-100), report counts, and network
    metadata (ISP, country, usage type). Private and reserved addresses are
    refused. This query is sent to a third party: only look up addresses that
    are already external indicators in an investigation.
    """
    caller = deps.require_caller(ctx)
    gov = deps.config.governance[caller.type]
    args = {"ip": ip}
    start = time.monotonic()

    try:
        data = await deps.abuseipdb_client.check_ip(ip)
    except NonRoutableAddress as exc:
        # Caller-supplied address only - safe to echo, and the caller needs to
        # know this was policy rather than an outage.
        deps.audit.log_tool_call(caller, "get_ip_reputation", args,
                                 validation_result="non_routable")
        raise ToolError(str(exc)) from None
    except QuotaExhausted:
        deps.audit.log_denied("enrichment_quota_exhausted", tool="get_ip_reputation",
                              caller=caller)
        raise ToolError("Reputation lookups are exhausted for today. Retry tomorrow "
                        "or continue without enrichment.") from None
    except EnrichmentUnavailable as exc:
        deps.audit.log_tool_failure(caller, "get_ip_reputation", args, error=exc,
                                    duration_ms=int((time.monotonic() - start) * 1000))
        raise ToolError("The reputation service is unavailable. Continue without "
                        "enrichment.") from None

    deps.audit.log_tool_call(caller, "get_ip_reputation", args,
                             duration_ms=int((time.monotonic() - start) * 1000))
    return {**scrub_value(data, gov.max_cell_chars), "content_warning": UNTRUSTED_NOTE}


mcp.tool(get_ip_reputation)
```

`isp` and `domain` are third-party strings, so the payload is still scrubbed and
labelled even though the field allowlist removed the free-text reports. Two
layers, cheap.

#### Config

```yaml
integrations:
  abuseipdb:
    enabled: true
    max_age_days: 90
    timeout_seconds: 10
    cache_ttl_seconds: 3600
    daily_quota: 1000
    # Deny the agent: it also holds add_incident_comment. See trust-model.md.
    permit_for_write_tiers: false
```

Add `get_ip_reputation` to the human tier's `allowed_tools` only.

#### Deployment

- Egress allowlist: `api.abuseipdb.com:443`.
- ACA secret + env var as in §4.2.
- Note the vendor dependency in the README egress table.

#### Dependency

`httpx` becomes a **direct** dependency — it is currently transitive via
`fastmcp`. Add it to `pyproject.toml` with a real constraint, run `poetry lock`,
regenerate `requirements.lock`. Relying on another package's transitive dep is
how a minor upgrade elsewhere breaks your code.

---

## 5. Documentation you must update

A change is not done when the tests pass.

| File | What |
|---|---|
| `README.md` | Tool-surface table; egress table; any new config block; setup step for the secret |
| `trust-model.md` | Class B/C only: what is now trusted, what data leaves, which mitigations apply and how far |
| `ai-instructions.md` | Any new invariant; any amendment to an existing one (see §4.2) |
| `EXTENDING.md` | Add the integration to §7 if it becomes a second worked example |
| `config/…example.yaml` | Must stay policy-identical to your per-tenant config |

---

## 6. Definition of done

A tool is finished when all of these are true.

**Wiring**
- [ ] Name in `KNOWN_TOOLS`; in `WRITE_TOOLS` if it mutates; in `EXTERNAL_TOOLS` if it leaves the tenant
- [ ] Module imported in `src/server.py`; `mcp.tool(fn)` at the bottom of the module
- [ ] Present in `allowed_tools` for the intended tiers in both config files
- [ ] Any new client is a lazy `Deps` property and is closed in `aclose()`

**Safety**
- [ ] Caller from `deps.require_caller(ctx)`
- [ ] No rate limiting, concurrency or timeout logic in the tool
- [ ] Every rejection is a `ToolError`
- [ ] Output passes through `scrub_value`/`truncate*` and carries `content_warning`
- [ ] Generic error messages; exception **class** only in logs
- [ ] Free-text arguments added to `_SENSITIVE_ARGS`
- [ ] `Field(pattern=…)` anchored and free of look-around
- [ ] Nothing external added to `check_ready()`

**Tests** — each must fail if the corresponding control is removed
- [ ] Unauthenticated call raises
- [ ] Caller without the tool in `allowed_tools` is denied by middleware
- [ ] Success path audits with the right tool name and counts
- [ ] Upstream failure ⇒ generic `ToolError`, and the upstream text appears in
      neither the message nor the log (`assert "…" not in env.log.dumps()`)
- [ ] Output is scrubbed and labelled
- [ ] Config: tool in `allowed_tools` with the integration disabled ⇒ startup error
- [ ] Config: external + write on one tier without the opt-in ⇒ startup error
- [ ] Class C: non-routable input refused **before** any request is attempted
- [ ] Class C: response projection drops an unexpected field
- [ ] Class C: quota exhaustion raises rather than calling out
- [ ] Class C: a cache hit performs no second request

Test fakes go on the `env` fixture in `tests/test_tools.py`, alongside `FakeLAW`
and `FakeSentinel`. **No test may perform network I/O.** CI has no egress and no
Azure credentials, and that is deliberate.

```python
class FakeAbuseIPDB:
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result or {}, exc, []

    async def check_ip(self, ip):
        from src.clients.abuseipdb_client import AbuseIPDBClient
        AbuseIPDBClient.assert_routable(ip)   # same gate as production
        self.calls.append(ip)
        if self.exc:
            raise self.exc
        return self.result

    async def close(self):
        pass
```

---

## 7. Candidate extensions, ranked

**Class A — do these first.** High value, no trust-model change.

| Tool | Why |
|---|---|
| `list_incidents` | Filtered by status/severity/time. Analysts currently need the incident number already. The largest usability gap. |
| `get_incident_alerts` | Alerts behind an incident; today only entities are reachable. |
| `get_entity_timeline` | Server-composed KQL across allowed tables for one entity. Removes the most error-prone hand-written query. |
| `get_watchlist_items` | Read a named Sentinel watchlist. Read-only, workspace-scoped. |

**Class B — real value, real review.**

| Source | Note |
|---|---|
| Defender XDR advanced hunting | **Implemented.** `src/tools/defender.py`, disabled by default. A worked Class B example: second client, second validator profile, second app role, trust-model amendment. Read that amendment before extending it. |
| Entra ID Protection risk detections | Requires Microsoft Graph. Graph is banned for *authorization*; as a read-only data source it is a separate decision. Amend `ai-instructions.md` explicitly if you take it. |

**Class C — highest injection risk, lowest marginal value.** An LLM can reason
about a reputation score, but the score rarely changes the triage outcome by
itself. Add at most one, learn from it, then decide about the next.

| Vendor | Specific hazard |
|---|---|
| AbuseIPDB | User-submitted report comments — do not request `verbose` |
| VirusTotal | Community comments, YARA rule names, submitted filenames: all attacker-writable |
| GreyNoise | Structured; comparatively low free-text surface |
| urlscan.io | Returns page **content**. Effectively fetching attacker HTML into an LLM context. Do not add without a dedicated review. |
| MISP | Internal, so no data leaves — but event comments are free text |

**Deliberately out of scope.** Any tool that fetches an arbitrary URL, executes
code, or takes a free-form string that reaches an external service. Those are
not enrichment; they are a remote-content channel with your credentials on it.

---

## 8. Procedure for an AI coding agent

Follow in order. Do not reorder, do not skip, do not batch.

**Before writing code**
1. Read `trust-model.md`, `ai-instructions.md` and §2 of this document in full.
2. Classify the change as A, B or C (§1). State the classification in your first
   response.
3. If C: state explicitly what tenant data leaves, what attacker-authored
   content can return, and which of the five controls in §4.3 you will apply.
   **Stop and ask the operator to confirm** before writing code.
4. Read the nearest existing analogue in `src/tools/` and copy its structure.
   `incidents.py` for reads, `comments.py` for writes.

**MUST**
- Use `deps.require_caller(ctx)`, `deps.audit`, `ToolError`, and
  `scrub_value`/`truncate*`.
- Add the tool name to `KNOWN_TOOLS`, and to `WRITE_TOOLS` / `EXTERNAL_TOOLS`
  where applicable.
- Add the tool to `allowed_tools` in **both** config files.
- Add the module to the import line at the bottom of `src/server.py`.
- Add free-text argument names to `_SENSITIVE_ARGS`.
- Write every test in the §6 checklist, and verify each one fails when its
  control is removed.
- Run `pytest -q` and report the full result before claiming completion.

**MUST NOT**
- Add rate limiting, concurrency control or timeouts inside a tool.
- Log a result payload, a response body, or an exception message.
- Put a secret in YAML, in a default value, or in a log line.
- Add a network call to `check_ready()`.
- Write a `Field(pattern=…)` with look-around, a backreference, or missing
  anchors.
- Store anything in FastMCP `Context` state.
- Add a dependency without updating `pyproject.toml`, `poetry.lock` and
  `requirements.lock` together.
- Weaken, skip or delete an existing test to make a new one pass. If an existing
  test now fails, that is a finding — report it and stop.
- Claim the work is done before §6 is fully checked.

**Report on completion**
- Classification (A/B/C) and files changed.
- Which §6 boxes are checked, and any that are not, with the reason.
- For Class C: the exact data that leaves the tenant, and the projection
  allowlist you applied.
- Any invariant in `ai-instructions.md` that the change contradicts, quoted, with
  the proposed amendment. **Never silently violate one.**
