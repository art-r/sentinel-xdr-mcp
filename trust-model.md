# Trust model

Two things are trusted in this system, and they are not the same thing. Most
security mistakes here come from collapsing them.

**Trusted principals** — *who* is calling. Established by Entra token validation
and the app-role check in `src/auth/authorization.py`. Both the Security team members / SOC analysts and
the investigation agent are trusted principals.

**Untrusted content** — *what* flows through. Every byte returned by Log
Analytics or Sentinel. Never trusted, at any tier, for any caller.

A trusted principal handling untrusted content is the normal case, not an
anomaly. The server is designed around it.

## What is trusted

| | Trusted | Basis |
|---|---|---|
| Caller identity | Yes | Entra JWT: signature, `iss`, `aud`, `exp`, `nbf`; then `roles` + `azp` allowlist |
| Caller intent | Yes | The human holds `Sentinel.Read` and optionally `Defender.Hunt`; the agent holds `MCP.Agent`. Neither is assumed hostile. |
| `config/mcp-server-config.yaml` | Yes | Reviewed, baked into the image, `extra="forbid"` at startup |
| The server's own MI credentials | Yes | Platform-issued, never leaves the process |
| **The MCP client platform** | **Partially** | See "The client is in the trust boundary" |
| **LAW/XDR query results** | **No** | See below |
| **Sentinel incident fields** | **No** | See below |
| **Agent-authored comment text** | **No** | Derived from the two rows above |

---

## The access boundary, and which regime we are in

The server queries LAW, Sentinel and XDR with **its own user-assigned Managed
Identity**, never the caller's token. The caller's token authorises the *call*;
the MI performs the *access*.

That makes the server a deliberate privilege-escalation path. Which controls are
load-bearing depends entirely on one operational fact, so it is recorded here
rather than left implicit.

> ### Recorded decision: Regime A
>
> **`Sentinel.Read` is only assigned to principals who already hold
> `Log Analytics Reader` on this workspace directly.** The app role grants no
> data the analyst could not already read in the portal.
>
> Consequences:
>
> - **Azure RBAC is the data boundary.** The table policy and the KQL validator
>   are governance, usability and cost control — a defect in them widens what a
>   caller can reach through this server but grants nothing they did not already
>   have.
> - This is why the human tier runs `table_policy: "workspace"`. An enumerated
>   allowlist would be friction, not a boundary.
> - **This is a standing operator obligation, not a one-time check.** It is
>   verified at each access review.
>
> If you inherit this deployment, verify it before trusting this paragraph:
>
> ```bash
> az rest --method get \
>   --url "https://graph.microsoft.com/v1.0/servicePrincipals/$API_SP_OBJ/appRoleAssignedTo" \
>   --query "value[].principalDisplayName" -o tsv
>
> az role assignment list --scope "$LAW_ID" \
>   --query "[?roleDefinitionName=='Log Analytics Reader'].principalName" -o tsv
> ```
>
> **If the precondition ever breaks** — a role holder with no direct workspace
> RBAC — the deployment moves to **Regime B**: the table policy and KQL
> validator become the access-control perimeter. In Regime B,
> `table_policy: "workspace"` is indefensible and must revert to `"allowlist"`,
> and every change to `src/governance/kql_validator.py` becomes a change to a
> security boundary requiring review as one. Update this section if that
> happens. Do not leave it implicit.

### What `table_policy: "workspace"` actually widens

Under Regime A the analyst can already read every table. What changes is not
*who can read* but *where the data goes*: rows now flow into an LLM context
window, and into whatever the client platform logs, retains and forwards.

`tables.blocked` is therefore the human tier's entire access policy, and it must
be reviewed as one. Two known gaps:

- It is **exact-name matching with no wildcards**. A custom `*_CL` table
  onboarded by a non-security team is readable the day it appears, with no
  review. If this workspace ingests custom logs from outside the security org,
  that is a standing review obligation.
- The shipped blocklist was written to suppress *noise and cost* tables, not
  sensitive ones. Re-derive it against a live `Usage | summarize by DataType`
  before enabling this policy in a new tenant.

The agent tier stays on `"allowlist"`, enforced by a startup validator that
rejects `"workspace"` on any tier holding a write tool. See the injection chain
below for why.

### Incidents have no scoping at all

`get_incident` and `get_incident_entities` expose **every** incident in the
workspace to every caller holding the app role. No filter by owner, severity,
classification or label. If this workspace carries incidents with restricted
readership — insider threat, HR, legal hold — this server exposes them. Use a
separate workspace, or accept it explicitly.

### Regime A extended: Defender XDR advanced hunting

`query_defender_hunting` reads the Defender XDR hunting corpus through the Graph
application permission `ThreatHunting.Read.All`, held by the server's managed
identity.

**That permission has no resource scope and no device-group scope.** It grants
read of every device, every mailbox and every identity in the tenant. There is
no Defender equivalent of "Log Analytics Reader on one workspace"; the
permission is all-or-nothing.

The integration is nevertheless in Regime A, on the same reasoning as the
workspace, extended to a second store:

> #### Recorded decision: Regime A, extended
>
> **`Defender.Hunt` is only assigned to principals who already hold
> unrestricted Defender XDR access** — no device-group scoping, no Unified RBAC
> scope restriction. For those principals the server grants no data they could
> not already read in the Defender portal.
>
> Access to this server is deliberately narrower than SOC membership. The
> broader SOC does not hold `Sentinel.Read` and therefore cannot reach this
> server at all. That is the design, not a consequence.
>
> Consequences:
>
> - Azure and Defender RBAC remain the data boundary for their respective
>   stores. The table policy and both KQL profiles are governance and cost
>   control.
> - A defect in the validator widens what a caller can reach *through this
>   server*, but grants nothing they did not already have.

#### What makes this harder than the workspace half

The workspace precondition is one command against one scope. The Defender
precondition is neither.

**It cannot be verified from Azure RBAC.** Defender scoping lives in device
groups (legacy) or Microsoft Defender XDR Unified RBAC. Neither appears in
`az role assignment list`. Looking at the workspace, or at the Entra app role
assignments, tells you nothing about whether a given holder is device-group
restricted.

**The failure mode is a silent privilege escalation.** A SOC analyst restricted
away from Tier-0 devices in Defender, who is added to the group holding
`Defender.Hunt`, sees Tier-0 device data through this server. Nothing in this
server can detect that, because from its point of view the token is valid and
the role is present.

**Group drift is the likely cause.** If the role is assigned to a group used for
anything else, one membership change breaks the precondition with no signal.

#### Standing operator obligation

Both roles are assigned to a **dedicated group used for nothing else**, and both
halves are verified at each access review:

```bash
# Half 1 - Entra: who holds the roles
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$API_SP_OBJ/appRoleAssignedTo" \
  --query "value[].{principal:principalDisplayName,type:principalType}" -o table

# Half 2 - workspace RBAC
az role assignment list --scope "$LAW_ID" \
  --query "[?roleDefinitionName=='Log Analytics Reader'].principalName" -o tsv
```

**Half 3 has no CLI.** In the Defender portal, under
Settings → Microsoft Defender XDR → Permissions and roles, confirm that every
member of the group carrying `Defender.Hunt`:

- holds a role with **no device-group restriction** (or, under Unified RBAC, a
  role assignment with an unrestricted scope); and
- is not also a member of any scoped SOC role that the unrestricted assignment
  would be silently overriding.

Record the date and the reviewer. This is the only control standing between the
design and a bypass of Defender's own scoping model.

An Entra **access review** on both app role assignments is required, not
optional.

#### If the precondition breaks

Remove `query_defender_hunting` from `allowed_tools` and set
`defender.enabled: false`. Do not attempt to compensate with a narrower table
list: the Defender allowlist is governance, and turning it into a security
perimeter is Regime B for a store whose backing credential cannot be scoped at
all — a materially worse position than Regime B for the workspace, where the
managed identity is at least bounded to one resource.

#### Why enrichment functions are banned

`FileProfile()`, `SeenBy()`, `AssignedIPAddresses()` and `DeviceFromIP()` return
data beyond the tables named in the query. Under Regime A that is not an access
problem — the caller already holds the access.

It is an **audit** problem. `extracted_tables` in every audit record is what
makes "a malicious analyst with legitimate credentials" a detection case rather
than an unmitigated one. A query whose real data sources are not in the audit
record defeats that control. They are banned in
`defender.kql.banned_functions` for that reason, independently of the RBAC
regime, and must stay banned if the regime ever changes.

#### Blast radius of container compromise

Compromise of the ACA environment or the container image remains **out of
scope**, as recorded below. Its consequence is now larger: an attacker holding
the managed identity's token reaches the entire tenant XDR hunting corpus, not
one Log Analytics workspace.

This does not change the classification — no control in this server addresses
its own compromise — but it raises the value of the controls that live outside
it: image signing, digest-pinned base images, hash-pinned dependencies,
restricted egress, and Conditional Access on the client app registration.

#### Quota is a shared, tenant-wide resource

The advanced-hunting API quota is consumed tenant-wide and shared with every
other consumer. `defender.calls_per_minute` and `defender.daily_call_budget`
bound this server's contribution; they cannot bound the tenant's consumption,
and they are per replica like every other limit here. A misbehaving caller can
degrade hunting for other tools in the tenant before this server's own limits
bite.

#### Two stores, one server

| | Sentinel / Log Analytics | Defender XDR advanced hunting |
|---|---|---|
| Credential | MI, `Log Analytics Reader` on **one workspace** | MI, `ThreatHunting.Read.All`, **tenant-wide** |
| Scope available | resource-scoped | none |
| Caller role | `Sentinel.Read` | `Sentinel.Read` **and** `Defender.Hunt` |
| Table authority | live `Usage` discovery, `tables.blocked` | static allowlist in config |
| Table policy | `workspace` for the human tier | always an explicit allowlist |
| Validator profile | `kql` | `defender.kql`, plus enrichment-function bans |
| Write path | `add_incident_comment` (agent only) | none, and none permitted |
| Available to the agent | yes | **no** — rejected at startup |
| Verifiable precondition | `az` one-liner | Defender portal, manual |

---

## The client is in the trust boundary

The MCP client platform is not a passive pipe. It:

- holds a client secret for a pre-authorized application in this tenant;
- performs the analyst's interactive sign-in and holds the resulting access and
  refresh tokens;
- composes every prompt that reaches these tools; and
- **renders untrusted Sentinel content back to a human.**

The last one is the least obvious and matters most. `sanitize_comment` escapes
markdown image syntax and autolinks specifically because the Sentinel portal
renders markdown — a beacon-on-view or one-click exfiltration primitive. The
same class of issue applies wherever tool output is rendered.

Before onboarding a client platform, establish:

| Question | Why |
|---|---|
| Does it render markdown or HTML from tool output? | Beacon-on-view via remote images |
| Does it fetch remote URLs (image previews, link unfurling)? | Exfiltration without a click |
| Where do tool results go — logs, retention, training, third-party models? | Sentinel data leaving its intended boundary |
| Can it be configured to send tool output to another tenant or vendor? | Cross-tenant data flow |
| Who administers it, and can they read another analyst's session? | Effective read access beyond the app role |

Record the answers per platform. A client that fails these questions is a data
exfiltration path with valid credentials, and no control in this server can see
it happening.

---

## Why Log Analytics data is untrusted input

An attacker does not need access to this server, this tenant, or any Azure
resource to place text inside it. They need only to cause a log to be written:

- send a phishing email — subject, sender display name and attachment filename
  reach `EmailEvents` and the resulting `SecurityAlert`;
- name a file, process or scheduled task — reaches `DeviceProcessEvents`,
  `DeviceFileEvents`;
- set a User-Agent, hostname or TLS SNI — reaches `CommonSecurityLog`;
- register a display name in a federated directory — reaches `SigninLogs`.

All of these are copied verbatim into incident titles, descriptions and entity
properties, and returned by `get_incident`, `get_incident_entities` and
`query_sentinel_logs`. This is not hypothetical: it is the ordinary operation of
a SIEM. **A SIEM is an attacker-writable data store by design.**

### The injection chain this creates

1. Attacker plants instruction-shaped text in a source that Sentinel ingests.
2. It surfaces in an incident field or query result.
3. The agent reads it while investigating.
4. The agent holds `add_incident_comment`.
5. Attacker-authored analysis appears on the SOC's own incident record,
   attributed to an automated system the analyst is inclined to believe.

Step 4 is why the write tool is scoped as narrowly as it is, and why an open
table policy is forbidden on any tier holding it: widening step 2 widens the
input side of the chain, and the agent has no human in the loop.

### What actually mitigates it, and how far

| Control | Stops | Does not stop |
|---|---|---|
| `scrub_text` — strips C0/C1, zero-width, bidi overrides, Unicode tag block | Hidden and invisible injection | Plain-text instructions |
| `UNTRUSTED_NOTE` on every data-returning tool | Naive model compliance | A determined injection; models do not reliably obey |
| `max_cell_chars` (4096), row and byte caps | Payload-volume attacks, context flooding | Short, well-crafted instructions |
| `sanitize_comment` — escapes `![` and autolinks | Beacon-on-view and one-click exfiltration from the Sentinel portal | Text content manipulation |
| Attribution header on every comment | Deniability; loss of provenance | The comment being wrong |
| `rate_limit_writes_per_minute: 3` | Bulk incident pollution | A single well-placed comment |
| Tool scoping — comment is the **only** write | Status changes, reassignment, severity edits, closure, playbook triggers | Comment content |
| `table_policy: "allowlist"` on the write-holding tier | Reach into unreviewed data sources | Injection via already-allowed tables |

**Prompt injection is not solved here and cannot be solved here.** The design
position is blast-radius containment: assume the agent will eventually be
influenced by content it reads, and ensure the worst outcome is one attributed,
rate-limited, human-reviewed comment — never a state change to an incident,
never a query outside the policy, never an action outside this workspace.

Consequences for operators:

- **Never auto-close or auto-triage on agent output.** A comment is an input to
  an analyst, not a decision.
- **Treat agent comments as untrusted when they are read back.** They are
  derived from untrusted content.
- Audit logs contain agent comment text verbatim (`log_query_text_for:
  ["agent"]`), so attacker-influenced text reaches your log store. Escape it
  before rendering in any dashboard.

---

## Network exposure

The server is deployed with **public Container Apps ingress**. That is an
accepted risk, on this reasoning:

- Authentication is real and unconditional — JWT signature, `iss`, `aud`, `exp`,
  `nbf` — followed by an app-role and client-application check. There is no
  unauthenticated path to any tool.
- The only unauthenticated endpoints are `GET /health` (constant response) and
  the OAuth protected-resource metadata, which is required to be public.
- The primary client is a server-side platform, so network-layer geo-filtering
  would filter a datacentre, not an analyst desk. The correct place for a
  location control is the Entra sign-in.

What public ingress costs, stated plainly:

| Exposure | Compensating control |
|---|---|
| A stolen bearer token is valid until expiry (~75 min) from any network location | **Conditional Access on the client app registration** — named locations and/or device compliance. Required, not optional; ACA ingress restricted to the client platform's egress range, so a stolen token must be replayed from inside that infrastructure. |
| Rate and concurrency limits live at the MCP protocol layer, so unauthenticated traffic reaches uvicorn on a single replica with nothing in front of it | Availability only. Mitigate with ACA ingress IP restrictions scoped to the client platform's egress range. |
| The metadata document publishes the tenant ID and API application ID | Not secret. Accepted. |

The stronger posture — internal-only ingress reachable through a zero-trust
access proxy — removes the first two entirely and is the recommended target for
deployments that can absorb the operational cost. It requires a custom domain
first: the environment must be recreated, which changes any
platform-generated hostname.

---

## Threats explicitly out of scope

- **A malicious SOC analyst with legitimate credentials.** Detection, not
  prevention: every call is audited with caller id, UPN, tool, resolved tables
  and a query fingerprint.
- **Compromise of the Azure control plane, the ACA environment, or the container
  image supply chain.** This must be handled through proper usage of dependency scanning. Reasonable measures were taken to harden the container environment itself and package dependencies are pinned (`requirements.lock`).
- **Compromise of the tenant's Entra signing keys.**
- **Bearer-token theft.** No DPoP, no sender constraint, no CAE. An issued
  access token is valid for its full lifetime (~60–90 min, not configurable)
  from any location. **Conditional Access does not mitigate this** — it is
  evaluated at issuance and this server never consults Entra again. CA reduces
  the likelihood of a token being issued to an attacker (phishing-resistant MFA,
  compliant device) and supplies replay detections (Identity Protection), which
  is a different property. The control that actually constrains *use* is
  network: ACA ingress restricted to the client platform's egress range, so a
  stolen token must be replayed from inside that infrastructure. See
  `conditional-access.md`.
- **Compromise of the MCP client platform.** It holds a valid client secret and
  live analyst tokens. Nothing in this server can distinguish a compromised
  client from a working one.
- **Denial of service by an authenticated caller** beyond the per-caller and
  global limits, which are **per replica**. Pin
  `minReplicas == maxReplicas == 1` or the configured numbers are wrong by that
  factor.
