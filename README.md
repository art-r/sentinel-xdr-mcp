# (Non-Data-Lake) Sentinel and XDR MCP Server 

A governed [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes an optionally restricted set of Microsoft Sentinel and Log
Analytics tools, as well as Microsoft XDR data to an LLM client, with Entra ID authentication, app-role
authorization, KQL validation, per-caller rate limits and a redacting audit
trail. Microsoft XDR integration is optional and can be turned off.\
It exposes the direct tables inside LAW and XDR and does not use Data Lake.

Licensed under Apache-2.0.

> Microsoft affiliation:\
> This is an independent, community-developed project and is not affiliated with, endorsed by, or supported by Microsoft. Microsoft Sentinel, Microsoft Defender XDR, Microsoft Entra ID, and related product names are trademarks of their respective owners.

> Development and maintenance\
> This project was developed primarily in my spare time and is maintained on a best-effort basis. There is no guarantee of ongoing development, timely updates, bug fixes, or support. Contributions and feedback are welcome, but maintenance and future development depend on available time and resources.

---

## What this is

A MCP server exposing (optionally restricted on table level) data from a Log Analytics Workspace and additionally (also optional) data from XDR to a LLM through a set of tools.\
It includes call logging (either kql hash based or full kql queries) and basic operator restrictions (e.g. blocking let statements).\
It respects existing RBAC permissions (see also the [trust model.md](trust-model.md)) and does not implement its own identity management but rather fully relies on Entra ID.\
No hard-coded credentials and no tokens or api keys involved.\
It supports two identity configurations, 1x for human operators (interactive chatting with a LLM) and 1x for agents (automated agents, allowing for example for automated incident analysis with write-back of results to an incident by using the comments feature).\
This explicitly does not incorporate any action-oriented features. **Human operator capabilities are read-only and the only write tool is limited to writing results into a Sentinel incident comment for the agent identity.**

A SOC analyst asks an LLM a question. The LLM calls this server. This server
decides whether that caller may run that tool, validates the KQL, executes it
against one Log Analytics workspace or Microsoft XDR using **its own Managed Identity**, caps and
scrubs the result, and writes an audit record.

```
 Analyst ──► MCP client ──Entra OAuth──► Sentinel MCP Server ──Managed Identity──► Log Analytics
                                              │                                     Sentinel/XDR
                                              └──► audit ──► Application Insights
```

**Caller tokens never reach the data plane.** The token authorizes the *call*;
the server's own Managed Identity performs the *access*. That is a deliberate
privilege-escalation path and it comes with a precondition — see
[trust-model.md](trust-model.md).

## What it is not

- Not an LLM host. It exposes tools; something else does the reasoning.
- Not a general Sentinel API. Six tools, one workspace, read-heavy.
- Not a replacement for Azure RBAC. It is a governance layer *on top of* RBAC.
- Not a defence against prompt injection. It contains the blast radius; it does
  not prevent it.

## Why

In my job in a security function I saw a gap of allowing in-house LLM models access security relevant data to speed up investigations and assist with in-depth incident analysis or threat hunting etc.\
Microsoft's security copilot feature only supports data living in Data lake, but I wanted direct access, similar to manual hunting. Hence this MCP.\
To not build a loophole for RBAC/URBAC this MCP was built from the ground-up with relevant considerations in mind. See [trust-model.md](trust-model.md). 

We now use this MCP daily with state-of-the-art LLM models through enterprise agreements, and his already sped up daily incident handling, threat hunting etc. by a significant factor.


## Tool surface

| Tool | Human | Agent | Purpose |
|---|:---:|:---:|---|
| `list_available_tables` | ✅ | ✅ | Which LAW tables this caller may query |
| `get_table_schema` | ✅ | ✅ | Column names and types for one table |
| `query_sentinel_logs` | ✅ | ✅ | Run validated, capped KQL |
| `get_incident` | ✅ | ✅ | Read a Sentinel incident by incident number |
| `get_incident_entities` | ✅ | ✅ | Read incident entities |
| `add_incident_comment` | ❌ | ✅ | Add one sanitised, attributed comment |
| `query_defender_hunting` | ✅¹ | ❌ | Defender XDR advanced hunting (Vulnerability Management) |

¹ Requires the additional `Defender.Hunt` app role. Disabled by default.

Two caller tiers with independent policy:

- **human** — a delegated (user) token. No write tools, by config validator.
- **agent** — an app-only token from a trusted automation's managed identity.
  Smaller limits, narrower table policy, holds the single write tool.

The agent tier is fully implemented and tested but is **not required**. Leave
`allowed_agent_app_ids` at a placeholder GUID until you deploy one.

---

## Security model in one page

### Authentication

Every request carries an Entra access token for this API. FastMCP's
`JWTVerifier` validates signature against the tenant JWKS, `iss`, `aud`, `exp`
and `nbf`. Failure returns 401 with a `WWW-Authenticate` challenge pointing at
the protected-resource metadata, so a compliant MCP client can start the OAuth
flow.

### Authorization

A pure function over verified claims — `src/auth/authorization.py`. No network
call, no cache, no Graph lookup, nothing to poison.

| Caller | Required claims |
|---|---|
| Human | `oid`, `scp` contains `user_impersonation`, `roles` contains `Sentinel.Read`, `azp`/`appid` in `allowed_client_app_ids` |
| Agent | app-only (`idtyp=app`, or no `scp` + has `roles`), `roles` contains `MCP.Agent`, `azp`/`appid` in `allowed_agent_app_ids` |

Token-type discrimination is explicit: a delegated token carrying
`roles: ["MCP.Agent"]` is never treated as the agent.

> **Entra pre-authorization does not authorize anything.** It suppresses the
> consent prompt. The `allowed_client_app_ids` list in config is the actual
> restriction on which client applications may present a delegated token.

### Data access

The server's user-assigned Managed Identity needs roles **at the individual
workspace resource**, never at resource-group or subscription scope:

| Role | Needed for |
|---|---|
| `Log Analytics Reader` | all queries, `/ready` |
| `Microsoft Sentinel Reader` | incidents and entities |
| `Microsoft Sentinel Responder` | only if `add_incident_comment` is enabled |

Additionally for XDR integration (if enabled) the service principal of the managed identity needs the following two roles: `ThreatHunting.Read.All` and `ThreatIntelligence.Read.All`.

### Configuration is security policy

`config/mcp-server-config.yaml` contains no credentials but controls which
client apps are accepted, which roles authorize, which tools each tier gets,
which tables are reachable, which KQL constructs are banned, and whether caller
query text is written to a second log store.

It is **baked into the image** and validated at startup with `extra="forbid"` —
a typo refuses to boot rather than silently disabling a control. Do not mount
over `/app/config` and do not point `CONFIG_PATH` at mutable storage. A policy
change is a source change: review, build, scan, new revision. `git log` on that
file is your policy history.

---

## Prerequisites

- An Entra tenant where you can create app registrations and grant admin consent
- A Log Analytics workspace with Microsoft Sentinel enabled, and optionally Microsoft XDR
- Azure CLI ≥ 2.60 with the `containerapp` extension, if you deploy and configure everything via cli
- Python 3.12 or 3.13, Poetry 2.x
- Docker, or Azure Container Registry with `az acr build`

Everything below is per-tenant and reproducible from a clean clone.

---

## 1. Configuration

```bash
git clone <this-repo> && cd sentinel-mcp-server
cp config/mcp-server-config.example.yaml config/mcp-server-config.yaml
```

`config/mcp-server-config.yaml` is gitignored. The example is committed, is
policy-identical, and is what the test suite validates — so `pytest` passes on a
clean checkout before you have a tenant.

Fill in the `identity` and `law` blocks as you work through the steps below.
`server.base_url` comes last, once you know your hostname (step 5).

Collect your workspace facts now:

```bash
LAW_RG="<resource-group-of-the-workspace>"
LAW_NAME="<workspace-name>"

az monitor log-analytics workspace show -g "$LAW_RG" -n "$LAW_NAME" \
  --query "{workspace_id:customerId, resource_id:id}" -o json
```

`law.workspace_id` is the **customerId** GUID, not the ARM resource ID. The ARM
resource ID is assembled from `subscription_id` / `resource_group` /
`workspace_name` by the config model.

### Derive your table list from your own workspace

`tables.tier1` / `tables.tier2` in the example config are one tenant's
selection. Table availability differs per tenant — connectors, licensing and
retention all vary. Before your first deployment:

```kql
Usage
| where TimeGenerated > ago(30d)
| summarize GB = round(sum(Quantity)/1024, 2) by DataType
| order by GB desc
```

Only tables that appear here have data. A table listed in config but absent
from this result is queryable and always returns zero rows.

## 2. Entra: the API app registration

This is the resource your tokens are audienced to.

```bash
TENANT_ID=$(az account show --query tenantId -o tsv)

API_APP_ID=$(az ad app create \
  --display-name "sentinel-mcp-server" \
  --sign-in-audience AzureADMyOrg \
  --query appId -o tsv)
API_APP_OBJ=$(az ad app show --id "$API_APP_ID" --query id -o tsv)

SCOPE_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
HUMAN_ROLE_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
AGENT_ROLE_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
```

Patch the manifest in one call. Four things here are load-bearing:

```bash
cat > /tmp/api-app.json <<JSON
{
  "identifierUris": ["api://$API_APP_ID"],
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [{
      "id": "$SCOPE_ID",
      "value": "user_impersonation",
      "type": "Admin",
      "isEnabled": true,
      "adminConsentDisplayName": "Access Sentinel MCP Server as the signed-in user",
      "adminConsentDescription": "Allows the app to call the Sentinel MCP Server on behalf of the signed-in user.",
      "userConsentDisplayName": "Access Sentinel MCP Server on your behalf",
      "userConsentDescription": "Allows the app to call the Sentinel MCP Server on your behalf."
    }]
  },
  "appRoles": [
    {
      "id": "$HUMAN_ROLE_ID",
      "value": "Sentinel.Read",
      "displayName": "Sentinel.Read",
      "description": "Read Sentinel incidents and query the workspace.",
      "allowedMemberTypes": ["User"],
      "isEnabled": true
    },
    {
      "id": "$AGENT_ROLE_ID",
      "value": "MCP.Agent",
      "displayName": "MCP.Agent",
      "description": "Investigation agent: read plus add incident comments.",
      "allowedMemberTypes": ["Application"],
      "isEnabled": true
    }
  ],
  "optionalClaims": {
    "accessToken": [{ "name": "idtyp", "essential": false, "additionalProperties": [] }]
  }
}
JSON

az rest --method PATCH \
  --url "https://graph.microsoft.com/v1.0/applications/$API_APP_OBJ" \
  --headers "Content-Type=application/json" \
  --body @/tmp/api-app.json
```

| Setting | Why it matters |
|---|---|
| `requestedAccessTokenVersion: 2` | Without it Entra issues v1 tokens with `iss=https://sts.windows.net/<tid>/` and `aud=api://<guid>`. The verifier pins the v2 forms and every request 401s. |
| `allowedMemberTypes` | `["User"]` cannot be assigned to a service principal; `["Application"]` cannot be assigned to a user. Getting this wrong yields a token with no `roles` claim. |
| `optionalClaims: idtyp` | Makes app-only detection explicit. There is a fallback (`no scp` + `has roles`), but set it. |
| `type: "Admin"` on the scope | Users cannot self-consent to a SOC data API. |

Create the service principal and require assignment:

```bash
az ad sp create --id "$API_APP_ID"
API_SP_OBJ=$(az ad sp show --id "$API_APP_ID" --query id -o tsv)

az rest --method PATCH \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$API_SP_OBJ" \
  --headers "Content-Type=application/json" \
  --body '{"appRoleAssignmentRequired": true}'
```

Assign `Sentinel.Read` and if you want to give access to XDR `Defender.Hunt` to your security users group:

```bash
SOC_GROUP_ID="<soc-security-group-object-id>"

az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/groups/$SOC_GROUP_ID/appRoleAssignments" \
  --headers "Content-Type=application/json" \
  --body "{\"principalId\":\"$SOC_GROUP_ID\",\"resourceId\":\"$API_SP_OBJ\",\"appRoleId\":\"$HUMAN_ROLE_ID\"}"
```

> Group assignment works for **users**. It does **not** work for the agent:
> Entra does not emit `roles` for a service principal that gained the role
> through group membership. Assign `MCP.Agent` directly to the agent's managed
> identity service principal.

## 3. Entra: the client app registration

One per MCP client. Do not share one registration across clients — `azp` in the
token is how you tell them apart in the audit log, and how you revoke one
without breaking the others.

```bash
REDIRECT_URI="<callback URL your MCP client publishes>"

CLIENT_APP_ID=$(az ad app create \
  --display-name "sentinel-mcp-client" \
  --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "$REDIRECT_URI" \
  --query appId -o tsv)

az ad sp create --id "$CLIENT_APP_ID"

az ad app credential reset --id "$CLIENT_APP_ID" \
  --display-name "mcp-client-secret" --years 1 \
  --query password -o tsv
```

The redirect URI must be registered on the **Web** platform. A registration
created as a public client (`allowPublicClient: true`, e.g. for device-code
testing) ignores the client secret and the authorization-code flow fails.

Record the secret expiry somewhere with an owner and an alert — see
[Operations](#operations).

Pre-authorize the client for the scope, so analysts see no consent prompt:

```bash
az rest --method PATCH \
  --url "https://graph.microsoft.com/v1.0/applications/$API_APP_OBJ" \
  --headers "Content-Type=application/json" \
  --body "{\"api\":{\"preAuthorizedApplications\":[{\"appId\":\"$CLIENT_APP_ID\",\"delegatedPermissionIds\":[\"$SCOPE_ID\"]}]}}"
```

Put `CLIENT_APP_ID` in `identity.allowed_client_app_ids`. Pre-authorization is a
consent convenience; that list is the enforcement.

If you set `assignment required` to Yes for the service principal, then you have another gateway of controling which users have access to even attempt the authentication.

## 4. Managed identity and workspace RBAC

```bash
RG="rg-sentinel-mcp"
LOCATION="westeurope"
MI_NAME="mi-sentinel-mcp"

az group create -n "$RG" -l "$LOCATION"
az identity create -g "$RG" -n "$MI_NAME"

MI_RESOURCE_ID=$(az identity show -g "$RG" -n "$MI_NAME" --query id -o tsv)
MI_CLIENT_ID=$(az identity show -g "$RG" -n "$MI_NAME" --query clientId -o tsv)
MI_PRINCIPAL_ID=$(az identity show -g "$RG" -n "$MI_NAME" --query principalId -o tsv)

LAW_ID=$(az monitor log-analytics workspace show -g "$LAW_RG" -n "$LAW_NAME" --query id -o tsv)

for ROLE in "Log Analytics Reader" "Microsoft Sentinel Reader"; do
  az role assignment create \
    --assignee-object-id "$MI_PRINCIPAL_ID" --assignee-principal-type ServicePrincipal \
    --role "$ROLE" --scope "$LAW_ID"
done

# Only when the agent and its comment tool are deployed:
# az role assignment create \
#   --assignee-object-id "$MI_PRINCIPAL_ID" --assignee-principal-type ServicePrincipal \
#   --role "Microsoft Sentinel Responder" --scope "$LAW_ID"
```

Put `MI_CLIENT_ID` in `identity.mcp_mi_client_id`.

## 5. Hostname

`server.base_url` and `server.host_header_allowlist` must hold exactly the same
hostname, and it is published in the OAuth metadata every client discovers.

**Strongly preferred: a custom domain on a tenant-verified DNS zone.** It
survives Container Apps environment rebuilds, and it is the only way to retire
the RFC 9728 deviation described below.

If you must use a platform-generated FQDN, it changes whenever the environment
is recreated, and every change rewrites `base_url`, the host allowlist, the
metadata document and every client's configuration. Bootstrap it with a
no-traffic revision, read the FQDN, update config, rebuild.

## 6. Build

```bash
poetry install --with dev
poetry run pytest -q

poetry export --only main -f requirements.txt -o requirements.lock
az acr build -r "<your-acr>" -t "sentinel-mcp:1.0.0" .
```

The image installs from `requirements.lock` with `--require-hashes --no-deps`,
runs as non-root, and uses **one uvicorn worker**. One worker is deliberate:
rate limiting, concurrency limiting and the readiness cache are process-local.

## 7. Deploy

```bash
APP="sentinel-mcp"
ACR="<your-acr>"

az containerapp create -g "$RG" -n "$APP" \
  --environment "<aca-environment>" \
  --image "$ACR.azurecr.io/sentinel-mcp:1.0.0" \
  --registry-server "$ACR.azurecr.io" \
  --registry-identity "$MI_RESOURCE_ID" \
  --user-assigned "$MI_RESOURCE_ID" \
  --target-port 8000 --transport auto \
  --min-replicas 1 --max-replicas 1 \
  --cpu 1.0 --memory 2.0Gi \
  --secrets appinsights-cs="<connection-string>" \
  --env-vars AZURE_CLIENT_ID="$MI_CLIENT_ID" \
             APPLICATIONINSIGHTS_CONNECTION_STRING=secretref:appinsights-cs
```

- `--min-replicas 1 --max-replicas 1` is **not** a performance setting. Every
  configured limit is per process; N replicas multiply them all by N.
- `--transport auto` — uvicorn is h11-only and cannot speak h2c.
- Configure a **Liveness** probe on `GET /health` only. `/ready` is disabled by
  default (`expose_ready_probe: false`) and returns 404; wiring an ACA readiness
  probe to it makes the replica permanently unhealthy and traffic never routes.

### Required egress

VNet integration or a firewall will break the server unless these are reachable:

| Destination | Used by | Symptom if blocked |
|---|---|---|
| `login.microsoftonline.com` | JWKS fetch | every request 401s with `token_validation_error` |
| `api.loganalytics.io` | all queries | every tool call fails |
| `management.azure.com` | Sentinel/ARM | incident tools fail |
| ACR + `*.blob.core.windows.net` | image pull | revision never starts |
| Azure Monitor ingestion | audit export | silent audit loss |
| graph.microsoft.com | Defender advanced hunting | query_defender_hunting fails; nothing else affected |

The JWKS host is the one people forget. It is a different FQDN from the Log
Analytics data plane and from IMDS, so a working query proves nothing about it.

### Verify

```bash
BASE="https://<your-hostname>"

curl -is "$BASE/health"
curl -s "$BASE/.well-known/oauth-protected-resource/mcp" | python3 -m json.tool

# Unauthenticated probe: must be 401 WITH a WWW-Authenticate challenge.
curl -is -X POST "$BASE/mcp/" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

## 8. Connect an MCP client

| Field | Value |
|---|---|
| Server URL | `https://<your-hostname>/mcp` |
| Transport | Streamable HTTP |
| Authentication | OAuth 2.0 authorization code |
| Client ID | the client app registration's application ID |
| Client secret | from step 3 |
| Authorization URL | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize` |
| Token URL | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` |
| Scope | `api://<API_APP_ID>/user_impersonation offline_access` |
| Token exchange | POST body (`client_secret_post`) |

The scope prefix is the **API's** application ID, never the client's. That is
the single most common configuration mistake.

Without the trailing slash, Starlette issues a 307 to `/mcp/`. Clients that do
not follow it — or that drop `Authorization` when they do — fail with an opaque
connection error and produce no server logs.

`offline_access` buys a refresh token so analysts do not re-authenticate hourly.
Do not add Microsoft Graph scopes: the v2 endpoint issues one token per
resource.

---

## Known deviation: RFC 9728 `resource` vs. Entra

**Symptom:** the browser sign-in succeeds, the client then fails, and the Entra
sign-in log shows a non-interactive failure —
`AADSTS9010010: The resource parameter provided in the request doesn't match
with the requested scopes` (`invalid_target`).

**Cause.** MCP 2025-06-18 requires clients to send an RFC 8707 `resource`
indicator, and they take it from this server's protected-resource metadata,
where RFC 9728 says it must be the server's own URL:

```
resource = https://<your-hostname>/mcp
scope    = api://<API_APP_ID>/user_impersonation
```

Entra compares `resource` against the **prefix of the requested scope**, byte
for byte. They differ, so redemption fails. Changing the scope cannot fix it —
`.default` changes the suffix, not the prefix.

**Fix A — custom domain (preferred, permanent).** Register the server URL as an
identifier URI on the API app registration, which requires a tenant-verified
domain. Platform-generated hostnames such as `*.azurecontainerapps.io` can never
qualify.

```bash
az ad app update --id "$API_APP_ID" \
  --identifier-uris "api://$API_APP_ID" "https://<your-hostname>/mcp"
```

The scope then becomes `https://<your-hostname>/mcp/user_impersonation`, both
sides match, and the metadata stays spec-compliant.

**Fix B — advertise the App ID URI.** When a custom domain is not available:

```yaml
identity:
  advertise_app_id_uri_as_oauth_resource: true
```

The metadata then advertises `api://<API_APP_ID>` as `resource`, so the prefixes
match. This is a deliberate deviation from RFC 9728 §3.3 and is **not** a
relaxation of authentication: both strings name the same Entra application, the
issued token still carries `aud=<API_APP_ID>`, and the verifier still pins that
audience.

What it costs: a client that validates the advertised resource against the URL
it fetched the document from will refuse to connect. Retire it as soon as
Fix A is available.

`src/auth/setup.py::apply_oauth_resource_override` raises at startup if FastMCP
moves the metadata route, so a dependency upgrade cannot silently turn the
override off while config still claims it is on.

---

## Table policy

Each tier chooses how `allowed_tables` is interpreted:

```yaml
governance:
  human:
    table_policy: "workspace"    # every table except tables.blocked
  agent:
    table_policy: "allowlist"    # only the listed tiers
```

- **`allowlist`** (default) — only tables in the named tiers are queryable.
- **`workspace`** — every table in the workspace is queryable except
  `tables.blocked`, and `allowed_tables` degrades to a discovery fallback used
  when live enumeration is unavailable.

`workspace` is defensible only where the caller already holds equivalent Azure
RBAC on the workspace directly, so the allowlist is friction rather than a
boundary. **Under `workspace`, `tables.blocked` is the access policy — review it
as one.** It is exact-name matching with no wildcards, so a custom table added
to the workspace later is readable from the day it appears.

A startup validator rejects `table_policy: "workspace"` on any tier holding a
write tool. Widening what a caller can read widens the input side of the
indirect-injection chain in [trust-model.md](trust-model.md), and the agent has
no human in the loop.

Before enabling it, look at what you are opening up:

```kql
Usage
| where TimeGenerated > ago(30d)
| summarize GB = round(sum(Quantity)/1024, 2) by DataType
| order by GB desc
```

### Schema-only tables

Some tables resolve in Sentinel but never contain data. Microsoft Defender
Vulnerability Management tables (`DeviceTvmSoftwareInventory`,
`DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSecureConfigurationAssessment`
and related) are exposed in the Sentinel schema for autocomplete and query
validation only. Queries against them succeed and return zero rows. The data
lives in **Defender advanced hunting**, behind a different API
(`https://graph.microsoft.com/v1.0/security/runHuntingQuery`), a different token
audience, and a different permission model.

This server reaches that data through `query_defender_hunting`, which is
**disabled by default**. Enabling it grants the managed identity a tenant-wide
Graph permission that cannot be scoped to device groups. Read
[trust-model.md](trust-model.md), "Regime A extended", and confirm the recorded
precondition before enabling it.

Enabling or disabling Defender hunting is **two edits**: `defender.enabled`, and
the `query_defender_hunting` entry in `governance.human.allowed_tools`. A config
with one but not the other is rejected at startup — a tool listed as available
that cannot work is a config lie, not a convenience.

The `note` on zero-row Sentinel results now points at a tool that exists: call
`list_available_tables(source="defender")`, then `query_defender_hunting`.

Live table discovery queries `Usage` through `LAWClient` directly, not through
`KQLValidator`, which is why it works even though `Usage` is in
`tables.blocked`. The blocklist governs **caller-supplied** KQL. Do not "fix"
this by removing `Usage` from the blocklist.

---

## Governance behaviour

### KQL validation

A tokeniser and positional scan, **not** a KQL parser. It fails closed on
anything it does not understand, which means some legitimate queries are
rejected. That trade is deliberate.

Rejected: multi-statement queries and `let`; cross-workspace, cross-cluster,
`app()` and `database()` references; `externaldata`; fan-out operators
`search`/`find`; plugin operators (`evaluate`, `invoke`); subquery-introducing
operators the source scan cannot cover (`partition`, `facet`, `fork`); control
commands; and any table not permitted for the caller in a position the scanner
understands.

Allowed, with every source checked: `union` with explicit branches, `join`, and
a tabular `in (...)` operand headed by one direct table.

```kql
SecurityAlert | where Computer in (SigninLogs | project Location) | take 5
```

Every query gets an outer `| take N+1` compiled in. The extra row is a probe: it
is what allows a truncated result to be honestly labelled incomplete. Inserted
before a trailing `| render`, because Kusto requires `render` to be last.

### Limits (per process)

| Control | Human | Agent |
|---|---:|---:|
| Max timespan | 90 days | 30 days |
| Max result rows | 5,000 | 3,000 |
| LAW server timeout | 180 s | 120 s |
| Concurrent tool calls per caller | 3 | 2 |
| Requests/minute/caller/tool | 10 | 15 |
| Comment writes/minute | — | 3 |
| Global concurrent tool calls | 4 | 4 |
| End-to-end tool deadline | 200 s | 200 s |

### Audit and redaction

Every successful tool call, failure and denial is audited to stdout as
structured JSON, exported to Application Insights.

Never logged, by anything: query **results**, and Azure exception **messages**
(they routinely echo the failing query fragment). Failures record the exception
class only.

Human KQL and comment text are recorded as a SHA-256 prefix plus length —
an analyst's query embeds the subject of the investigation. Agent text is logged
verbatim, because it is machine-generated and must stay reviewable.
`logging.log_query_text_for` controls this per tier.

Returned Sentinel/LAW content is labelled untrusted, stripped of C0/C1,
zero-width, bidi-override and Unicode-tag characters, and size-capped. Comment
text has markdown image syntax and autolinks neutralised.

---

## Operations

### Audit events

| Event | Meaning |
|---|---|
| `tool_invocation` | successful call, with caller, tool, tables, row count, duration |
| `tool_failed` | exception class only, never the message |
| `access_denied` | authorized caller, refused action — tool scoping, rate limit, timeout |
| `authentication_denied` | token rejected, with a coarse `reason` and the calling app ID |

`authentication_denied` reasons: `token_validation_error`, `token_invalid`,
`no_client_app_id`, `missing_agent_role`, `agent_app_not_allowlisted`, `no_oid`,
`missing_scope`, `missing_role`, `client_app_not_allowlisted`.

### Recommended alerts

```kusto
// 401 spike - misconfigured client, expired secret, or credential probing
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(15m)
| where Log_s has "authentication_denied"
| summarize count() by bin(TimeGenerated, 5m)
```

```kusto
// A code defect masquerading as an outage: discovery failing with anything
// other than an Azure transport error means the call path is broken.
ContainerAppConsoleLogs_CL
| where Log_s has "workspace_table_discovery_failed"
| where Log_s !has "HttpResponseError" and Log_s !has "ServiceRequestError"
```

Also alert on Entra **application credential expiry** for the client app
registration. An expired secret is a scheduled, silent outage.

### Rotating the client secret

```bash
az ad app credential reset --id "$CLIENT_APP_ID" \
  --display-name "rotated-$(date +%Y%m)" --years 1 --append
```

Update the MCP client, verify a fresh sign-in, then remove the old credential.
No server change and no redeploy: the server never sees the secret.

### Reading logs

```kusto
ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "sentinel-mcp"
| where TimeGenerated > ago(1h)
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

Send Container Apps diagnostics to a workspace **other than** the one this
server queries.

---

## Troubleshooting

Ordered by how often each one bites. "No logs" below means *the container
produced no output*, which is itself diagnostic: a token that reaches the
verifier and is rejected always logs `authentication_denied`.

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS9010010 invalid_target` after sign-in | RFC 8707 `resource` ≠ scope prefix | [Known deviation](#known-deviation-rfc-9728-resource-vs-entra) |
| `AADSTS900144: ... 'scope'` | client sent no scope | fill the scope field; v2 has no default |
| `AADSTS65001` consent required | client not pre-authorized for that exact scope | pre-authorization is per scope ID, not per app |
| `AADSTS501051 not assigned to a role` | client-credentials token, no application app role | expected — this server's human path is authorization-code; do **not** grant an application role to make it go away |
| `AADSTS700016` app not found | wrong tenant in the authority URL | check the tenant GUID |
| Connection error, container started, no logs | client aborted during cold start | `--min-replicas 1`; retry warm |
| Connection error, no logs, no Entra entry | request never reached the app | check ingress restrictions, then TLS interception on the client's egress |
| Client fails immediately, never opens sign-in | 401 without `WWW-Authenticate`, or 307 on `/mcp` | use `/mcp/`; verify the challenge header is present |
| HTTP 400 "Invalid host header" | `Host` not in `host_header_allowlist` | allowlist must equal exactly `[base_url.host]` |
| 401, log `reason=missing_role` | signed-in user has no `Sentinel.Read` | assign the app role to the user or their group |
| 401, log `reason=missing_scope` | client requested the wrong scope | `api://<API_APP_ID>/user_impersonation` |
| 401, log `reason=client_app_not_allowlisted` | `azp` not in config | add the client app ID to `allowed_client_app_ids` |
| 401, log `reason=token_validation_error` | JWKS unreachable, clock skew, or v1 token | check egress to `login.microsoftonline.com`; confirm `requestedAccessTokenVersion: 2` |
| 401, **no log at all** | no `Authorization` header — rejected before the verifier | the client is not attaching the token |
| `GET /ready` returns 404 | `expose_ready_probe: false` (the default) | expected; do not wire an ACA readiness probe to it |
| `ValidationError` at startup | config typo — `extra="forbid"` | the message names the field |
| `RuntimeError: ... protected-resource metadata route(s) were found` | a FastMCP upgrade moved the metadata route | re-verify `apply_oauth_resource_override` before deploying |
| Every limit appears doubled | more than one replica | limits are per process; pin `min == max == 1` |
| Query succeeds, returns 0 rows, table is a `DeviceTvm*` or other Defender table | Schema-only in Sentinel; no data is ingested | Query it in Defender advanced hunting. Not an RBAC problem — no role assignment changes this. |
| A table in `allowed_tables` always returns 0 rows | Not ingested in this tenant | Check `Usage | summarize by DataType`; remove it from the tier list |
| `Defender advanced hunting is not enabled` | `defender.enabled: false` | Intentional default. See trust-model.md before changing. |
| `requires an additional role` | `Defender.Hunt` not assigned to the signed-in user | Assign it — and verify the user holds unrestricted Defender XDR access first |
| Hunting returns 403 from Graph | MI lacks `ThreatHunting.Read.All`, or consent was never granted | Re-run the grant; it needs Privileged Role Administrator |
| Hunting 429s while Sentinel queries work | tenant-wide hunting quota, shared with other consumers | Lower `calls_per_minute`; find the other consumer |

Decode a token to see what actually arrived:

```bash
python3 -c "
import base64,json,sys
p=sys.argv[1].split('.')[1]
c=json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4)))
for k in ('aud','iss','ver','appid','azp','scp','roles','oid','idtyp'):
    print(f'{k:8} {c.get(k)}')
" "<access-token>"
```

Want: `ver=2`, `iss=https://login.microsoftonline.com/<tid>/v2.0`, `aud` = the
API application ID, `roles` containing `Sentinel.Read`.

---

## Deliberate limitations

These are design positions, not backlog items. Do not describe them as solved.

- The KQL validator is a guard rail, not a parser. `let`, `search` and `find`
  are unsupported by choice.
- No On-Behalf-Of, no Microsoft Graph, no Key Vault, no client secrets or
  certificates in the server. Authorization is an app role read from a verified
  token.
- The table allowlist is best-effort inside the one workspace the MI can reach.
  Workspace-scoped Azure RBAC is the real boundary.
- Incident tools expose **every** incident in the workspace to every caller
  holding the app role. No filter by owner, severity or label.
- Prompt-injection mitigation is containment, not prevention.
- All limits are process-local. Do not scale out.
- Bearer tokens are not sender-constrained. A stolen token is valid until expiry
  from any network location — mitigate with Conditional Access on the client
  app.
- Defender XDR advanced hunting is reachable but **unscopeable**: the backing
  Graph permission is tenant-wide with no device-group restriction. Access is
  gated by a second app role and an operator-verified precondition, not by a
  technical boundary.

## Repository layout

```text
.github/workflows/ci.yml           tests, hygiene, image build (see CI.md)
src/
  auth/          token verification, claim authorization, MCP middleware
  clients/       Log Analytics and Sentinel wrappers (Managed Identity only)
  governance/    KQL validation, rate/concurrency limits, truncation, sanitising
  tools/         the six MCP tools
  config.py      strict Pydantic configuration model
  server.py      FastMCP app, dependency container, probes
config/
  mcp-server-config.example.yaml   committed template; what the tests validate
  mcp-server-config.yaml           per-tenant, gitignored, baked into the image
tests/                             ~150 tests, no cloud dependencies, no network
poetry.lock                        dependency source of truth
requirements.lock                  generated from it; what the image installs
trust-model.md                     what is trusted, what is not, and why
ai-instructions.md                 engineering invariants for maintainers
EXTENDING.md                       how to add tools and integrations safely
CI.md                              what the pipeline checks and why
SECURITY.md                        vulnerability reporting
```

## Contributing

Read [ai-instructions.md](ai-instructions.md) first — it records invariants that
look like arbitrary style until you know why they exist.

`pytest` must pass on a clean clone with no Azure access. Security-relevant
changes need a test that fails without the change. Changes to
`src/governance/kql_validator.py` or `src/auth/` require review against
[trust-model.md](trust-model.md).

Adding a tool or an integration: follow [EXTENDING.md](EXTENDING.md). It has a definition-of-done checklist and a procedure for AI coding agents.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open a public
issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).
