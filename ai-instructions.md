# AI Coding Instructions — Sentinel MCP Server

This is the engineering contract for the **current implementation**. Do not preserve historical alternatives that conflict with it. If code, tests, configuration, or documentation disagree, resolve the discrepancy deliberately and add regression coverage.

## 1. Purpose and boundaries

This is a Python 3.12 FastMCP server using Streamable HTTP. It exposes a fixed set of Microsoft Sentinel and Log Analytics Workspace (LAW) tools to **ChatGNpt** and a future trusted investigation agent.

It does:

- validate Entra access tokens;
- authorize humans and the agent from verified app-role and client-app claims;
- access LAW/Sentinel only through the server's user-assigned Managed Identity;
- govern KQL, result sizes, rate, concurrency, and request duration;
- audit tool activity; and
- label data returned from LAW/Sentinel as untrusted.

It does not:

- host or orchestrate an LLM;
- forward, exchange, or log caller tokens for data-plane access;
- use OBO, Microsoft Graph membership checks, Key Vault secrets, client secrets,
  or certificates **in the identity path**. Authorization is an app role read
  from a verified token; no credential the server holds can influence an
  authorization decision, and there is nothing to steal that grants access to
  Sentinel.
  
  A Microsoft Graph call as a read-only DATA source (Defender advanced hunting) is
permitted and is not an identity-path use. Graph for membership, consent or
authorization decisions remains banned.

  An outbound API key for an external *data source* is a separate category and
  is permitted under EXTENDING.md section 4.2: environment variable from an ACA
  secret, never in YAML, startup failure if absent, never logged. It
  authenticates this server to a third party and grants nothing in this tenant.
  A Key Vault *reference* resolved by the platform is preferred; a Key Vault
  *client* in `src/` remains banned.- expose MCP resources or prompts; or
- store a caller identity in MCP session state.

## 2. Identity invariants

### Caller authentication

`src/auth/setup.py` uses FastMCP's raw `JWTVerifier`, pinned to:

- `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`;
- issuer `https://login.microsoftonline.com/{tenant}/v2.0`;
- audience equal to the MCP app registration client ID; and
- normal JWT temporal validation.

The MCP app registration requires `requestedAccessTokenVersion = 2`.

Never configure non-empty `required_scopes` on the verifier. App-only Entra access tokens use `roles`, not `scp`; a delegated-scope requirement rejects the agent before the authorization layer runs.

### Caller authorization

`src/auth/authorization.py` is a pure check over verified claims.

| Caller | Required claims |
|---|---|
| Human | delegated token with `oid`, `user_impersonation`, `Sentinel.Read`, and allowlisted `azp`/`appid` |
| Agent | app-only token with `MCP.Agent` and allowlisted `appid`/`azp` |

`identity.advertise_app_id_uri_as_oauth_resource` is an **accepted deviation
from RFC 9728 §3.3**, not an oversight. Entra rejects an RFC 8707 resource
indicator that is not the prefix of the requested scope, and a
platform-generated hostname cannot be an Entra identifier URI. The override
changes only the advertised identifier: `aud` pinning in `EntraCallerVerifier`
is untouched. Retirement condition: `server.base_url` becomes a custom domain
registered as an identifier URI on the API app registration. Do not "fix" it
by removing the flag while that condition is unmet.

`apply_oauth_resource_override` must keep raising at startup when the metadata
route is not exactly where it expects. A FastMCP upgrade that moves it is a
deployment failure, never a server that quietly advertises the wrong identifier.

`idtyp == "app"` is the preferred app-only discriminator. A roles claim without `scp` is the fallback. A delegated token that also has `MCP.Agent` must remain a human token.

The Entra app registration must require app-role assignment. `Sentinel.Read` is assigned to the SOC group; `MCP.Agent` is assigned directly to the agent MI service principal. Pre-authorized applications only suppress consent prompts; they do not authorize callers.

### Data-plane access

`LAWClient` and `SentinelClient` use the server MI and never receive caller tokens. Assign its Azure RBAC only on the individual LAW workspace resource:

- `Log Analytics Reader`;
- `Microsoft Sentinel Reader`; and
- `Microsoft Sentinel Responder` only for the comment-write tool.

The MI's workspace RBAC scope is the real boundary. KQL controls are defense in depth and cost governance.

## 3. Technology constraints

| Component | Requirement |
|---|---|
| Python | `>=3.12,<3.14` |
| MCP SDK | `fastmcp>=3.0,<4.0` |
| Auth | `RemoteAuthProvider` and `JWTVerifier` |
| LAW | `azure-monitor-query>=1.4,<2.0` |
| Sentinel | `azure-mgmt-securityinsight>=1.0,<2.0` |
| Identity | `azure-identity>=1.17,<2.0` |
| Validation | Pydantic v2 + PyYAML |
| Logging | structlog + Azure Monitor OpenTelemetry |

Do not add FastAPI, Flask, SSE, the Anthropic `mcp` SDK, an Azure OAuth proxy, OBO, Graph, secrets, or certificates. Do not upgrade `azure-mgmt-securityinsight` to 2.x pre-release without migrating `SentinelClient` and its SDK-shape test.

Adding an external integration is governed by EXTENDING.md. Class C changes
(tenant data leaves the tenant) require a trust-model update and the same review
as a change to `src/auth/`.

## 4. Configuration and container policy

`config/mcp-server-config.example.yaml` is committed and is what the test suite
loads. `config/mcp-server-config.yaml` is per-tenant, gitignored, and copied
into the image by name — a missing file is a build failure, not an image that
ships the example.

The two must stay **policy-identical**: same tiers, tools, tables, KQL rules,
limits and logging policy, differing only in tenant/app/workspace identifiers
and hostname. Several tests assert against the shipped policy, so a divergence
means CI is validating something you do not deploy.
The release Dockerfile copies configuration into `/app/config`. Do not mount mutable production policy over it or point `CONFIG_PATH` at mutable storage. Policy changes need source review, a new image, scanning/signing, and revision rollout.

Every Pydantic config model must use `extra="forbid"`. Startup must fail if a security list is empty, a configured tool or table tier is unknown, the host policy is weak, or request timeout is not greater than every configured LAW query timeout.

`server.host_header_allowlist` must contain exactly one value: the canonical hostname from HTTPS `server.base_url`. Reject wildcards, URLs, ports, and alternate hosts. Code adds `localhost` and `127.0.0.1` only when `dev_mode` is true.

The container must run non-root, emit unbuffered structured logs, use one Uvicorn worker, and omit an image `HEALTHCHECK`; the platform owns probes. `poetry.lock` is the source of truth. `requirements.lock` is generated from it
(`poetry export --only main`) and is what the image installs with
`--require-hashes --no-deps`. Regenerate both in the same commit; CI fails on
drift. Do not hand-edit `requirements.lock`.

`fastmcp` is pinned to `~3.4`, not a major range: `src/auth/setup.py` wraps a
route FastMCP generates, and that route's construction has already changed once
within 3.x.

## 5. Middleware and caller resolution

Do not store `CallerContext` in FastMCP `Context` state. It is session-scoped and client-session-keyed, which is wrong for authorization identity.

Middleware and tools re-derive the caller from the verified access token:

```python
caller = deps.require_caller(ctx)
```

`AuthorizationMiddleware` must:

1. deny unauthenticated non-handshake requests;
2. filter `tools/list` by caller tier;
3. enforce tool access again for `tools/call`;
4. deny resources and prompts by default;
5. enforce per-caller/per-tool rate limits;
6. enforce per-caller concurrency;
7. enforce global process concurrency; and
8. wrap every tool call in the configured end-to-end deadline.

Use `ToolError` for caller-visible denials. Audit rate, concurrency, and timeout rejections as `access_denied` events. Global limits are process-local; maintain one replica and one worker until shared enforcement exists.

## 6. Tool requirements

Every tool must:

- use bounded typed arguments;
- use Rust-regex-compatible Pydantic patterns only: no look-around or backreferences;
- anchor every Pydantic argument pattern with `^` and `$`;
- call `deps.require_caller(ctx)`;
- route all audit events through `AuditLogger`;
- never log output rows, JWTs, tokens, or Azure exception messages;
- return structured data; and
- treat caller strings and returned LAW/Sentinel values as untrusted.

Every successful invocation emits `tool_invocation`; failures emit `tool_failed`; access denials emit `access_denied` or `authentication_denied`. Human KQL/comment text is hashed and length-recorded. Agent text is only logged when allowed by `logging.log_query_text_for`.

Data-returning tools must scrub control, zero-width, and bidi characters; cap string cells; apply row/byte caps where relevant; and return a clear untrusted-content warning.

`add_incident_comment` is agent-only in middleware and tool code. It must use the separate write budget, neutralize Markdown images/autolinks, enforce its text cap, and prepend server-generated attribution with caller ID, correlation ID, and UTC timestamp.

## 7. KQL governance

`src/governance/kql_validator.py` is intentionally a small tokenizer and positional scan. It is not a full parser.

It must continue to:

- reject semicolons and `let`;
- reject banned functions when an identifier is followed by `(`, regardless of whitespace;
- reject banned operators only at query head or after `|`;
- compare table names through case-insensitive configuration helpers;
- enforce outer `take`/`limit` only at nesting depth zero;
- use API `timespan` as the time ceiling rather than heuristic `ago()` parsing; and
- insert a cap before terminal `render`.

### Tabular `in (...)` operands

A nested tabular `in (...)` operand may begin only with one direct allowed table:

```kql
SecurityAlert | where Computer in (SigninLogs | project Location)
```

Reject nested source-hiding forms such as:

```kql
SecurityAlert | where Computer in (union * | project Computer)
SecurityAlert | where Computer in (search * | project Computer)
SecurityAlert | where Computer in (find where true | project Computer)
SecurityAlert | where Computer in (SomeStoredFunction())
SecurityAlert | where Computer in (materialized_view('view'))
```

Scalar value lists remain valid, including `in ('a', 'b')` and `in (dynamic(['a', 'b']))`.

This narrow restriction closes a material nested-source blind spot without turning this repository into a KQL parser project. Do not broaden it without a concrete use case and a test corpus.

Required KQL regression coverage includes whitespace variants of cross-workspace functions, blocked tables at top level/join/union/tabular `in`, union branches after piped branches, nested `union`/`search`/`find`/`range`/`print`/stored function/materialized-view attempts, string/comment false positives, allowed nested pipelines, outer row caps, and `render` placement.

## 8. Limits and readiness

| Limit | Human | Agent |
|---|---:|---:|
| Maximum timespan | 90 days | 30 days |
| Maximum rows | 5,000 | 3,000 |
| LAW server timeout | 180 seconds | 120 seconds |
| Per-caller concurrency | 3 | 2 |
| Rate limit per caller/tool | 10/minute | 15/minute |
| Comment-write limit | n/a | 3/minute |
| Global in-flight tool calls | 4/process | 4/process |
| Tool-call deadline | 200 seconds/process | 200 seconds/process |

`/health` is unauthenticated liveness only. `/ready` is unauthenticated, cached for 30 seconds, and executes a minimal LAW `print 1` query through the MI. It checks LAW data-plane access, not merely token minting. It does not validate optional Sentinel write permission. Note that by default it is disabled via config!

## 9. Mandatory test coverage

Maintain tests for:

- the human/agent authorization matrix and escalation resistance;
- FastMCP middleware hooks, scoped tool lists, and tool-call enforcement;
- rate limits, per-caller concurrency, global concurrency, and deadlines;
- fail-closed config validation including canonical host rules and timeout consistency;
- audit paths for every tool, including `list_available_tables`;
- readiness calling the LAW workspace-access probe;
- KQL accepted/rejected corpus;
- result/string sanitization; and
- Sentinel SDK-shape assumptions.

Use the same lock file and Python base image in CI, tests, and Docker once supply-chain pinning is introduced.

## 10. Intentional limitations

- No complete KQL parser or Kusto.Language sidecar.
- No `let`, `search`, or `find` support.
- No OBO or Graph fallback.
- Table allowlists are best-effort inside the one workspace available to the MI.
- Prompt-injection mitigation is not a complete defense.
- Enforcement limits are process-local until moved to shared infrastructure.
- `tables.blocked` is exact-name matching with no wildcard support. Under
  `table_policy: "workspace"` this is the access policy, and a table added to
  the workspace later is readable immediately.
- The protected-resource metadata deviates from RFC 9728 §3.3 when
  `advertise_app_id_uri_as_oauth_resource` is set.
- Defender XDR advanced hunting is reachable via `query_defender_hunting` when
  `defender.enabled` is true. Its Graph permission (`ThreatHunting.Read.All`) is
  tenant-wide and cannot be scoped; the `Defender.Hunt` app role plus an
  operator-verified precondition is the only boundary. Never add it to a tier
  holding a write tool, and never to the agent tier — `Config._check` rejects
  both.
- `KQLValidator` has two profiles, selected by `source`. They must not be
  merged: advanced hunting has enrichment functions (`FileProfile`, `SeenBy`,
  `AssignedIPAddresses`, `DeviceFromIP`) that return data beyond the tables
  named in the query. They are banned to keep `extracted_tables` in the audit
  record truthful, not for RBAC reasons. Do not unban them.
- `LAWClient.list_workspace_tables()` queries `Usage`, which is in
  `tables.blocked`. This is correct and deliberate: the blocklist constrains
  caller-supplied KQL through `KQLValidator`, not server-issued queries. Do not
  reconcile them.

Do not describe these limitations as solved or hide them in documentation.

## 11. Test corpus invariants

`tests/test_kql_validator.py` carries two rejection corpora and they are not
interchangeable:

- `REJECT` — syntax-level rejections. Must fail for **every** tier regardless of
  table policy.
- `REJECT_UNLISTED_TABLE` — rejections that depend on the table not being in the
  caller's tier. This is the regression suite for source extraction (H-1): every
  entry proves the validator finds a table reference in a union branch, a join
  operand or the head of an `in (...)` operand.

Setting a tier to `table_policy: "workspace"` makes the second corpus pass for
that tier. It must keep running against a tier that still enforces an allowlist,
or opening a tier silently deletes that coverage.
`test_unlisted_tables_are_accepted_for_workspace_tiers` asserts the widening is
real, so reverting the policy fails loudly instead of passing quietly.
