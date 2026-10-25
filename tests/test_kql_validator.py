"""KQL validator, including the regression corpus of bypasses that earlier
implementations accepted (report.md section 3, and finding H-1). Every REJECT
entry below was empirically verified as ACCEPTED by the implementation that
preceded the fix for it.
"""

import pytest

from src.governance.kql_validator import KQLValidator, clean_query, tokenize

from ._support import config


def _v() -> KQLValidator:
    return KQLValidator(config())


VALID = [
    "SecurityAlert | take 10",
    "SigninLogs | where TimeGenerated > ago(1h) | summarize count() by UserPrincipalName",
    "DeviceEvents | where DeviceName == 'WORKSTATION01' | project TimeGenerated, ActionType",
    # Blocked-table names used as COLUMN names must not be false positives.
    "AzureActivity | project OperationName | take 5",
    "AzureActivity | extend Operation = 1 | take 5",
    "SigninLogs | summarize Usage = count()",
    # Source keywords used as column names / aliases: matching is positional.
    "SecurityAlert | project union = 1 | take 5",
    "SecurityAlert | extend join = 1 | take 5",
    "SecurityAlert | extend app = 1 | take 5",
    "SecurityAlert | extend range = 1 | take 5",
    "SecurityAlert | project print = 1 | take 5",
    # Long inline ranges are harmless: the API timespan is the authoritative cap.
    "SecurityAlert | where TimeGenerated > ago(365d) | take 5",
    # Legitimate multi-table work is still allowed, with every source checked.
    "SecurityAlert | join kind=inner (SigninLogs | take 10) on $left.X == $right.Y",
    "SecurityAlert | join hint.strategy=broadcast (SigninLogs) on Y",
    "union SecurityAlert, SecurityIncident | take 5",
    "union isfuzzy=true (SecurityAlert), (SecurityIncident) | take 5",
    "union (SecurityAlert | take 5), (SigninLogs) | take 10",
    "SecurityAlert | union (SigninLogs | take 5), (AuditLogs) | take 10",
    # Strings containing scary words are blanked before analysis.
    "SecurityAlert | where Description has 'workspace(\"other\").Table' | take 5",
    "SecurityAlert | where Entities contains 'a let externaldata' | take 5",
    "// leading comment\nSecurityAlert | take 5",
    "(SecurityAlert) | take 5",
    "SigninLogs | summarize c = count() by bin(TimeGenerated, 1h) | take 5",
    "SecurityAlert | where (Severity == 'High') | take 5",
    # Allowed tables inside a subquery / as an `in` operand.
    "SecurityAlert | where Computer in (SigninLogs | project Location) | take 5",
    "SecurityAlert | where Computer in ((SigninLogs | project Location)) | take 5",
    "SecurityAlert | where Computer in (SigninLogs) | take 5",
    "SecurityAlert | where Severity in ('High', 'Medium') | take 5",
    "SecurityAlert | where Severity in (dynamic(['High', 'Medium'])) | take 5",
    # render is a legal terminal operator.
    "SecurityAlert | summarize count() by Severity | render barchart",
]

REJECT = [
    # --- cross-workspace / cross-cluster (one space defeated the old check)
    "workspace ('other').SecurityAlert | take 10",
    "workspace('other').SecurityAlert | take 10",
    "cluster ('other').database('db').SecurityAlert | take 5",
    "app ('other').requests | take 5",
    # --- let / multi-statement bindings
    "let t = SecurityEvent | take 5; t",
    "let x = 1; SecurityEvent | take 5",
    "let t = heartbeat; t | take 5",
    # --- unqualified fan-out across every table in the workspace
    "search 'password' | take 10",
    "search in (SecurityEvent) 'x'",
    "find in (SecurityEvent, SecurityAlert) where Computer != ''",
    # --- hidden data sources
    "SecurityAlert | extend z = toscalar(SecurityEvent | count)",
    "let d = materialize(SecurityEvent | take 5); d",
    "externaldata(col:string)['https://evil.com/data.csv']",
    "SecurityAlert | lookup SecurityEvent on Computer",
    # --- plugins, including via the hint that bypassed 'evaluate python'
    "SecurityAlert | evaluate python(typeof(x:int), 'x=1')",
    "SecurityAlert | evaluate hint.distribution=per_node python(typeof(x:int),'x=1')",
    "SecurityAlert | evaluate r('1+1')",
    # --- subquery-introducing operators the source scan cannot cover, in both
    #     the paren and the legacy brace form (report M-2)
    "SecurityAlert | partition by Computer (SecurityEvent | take 5)",
    "SecurityAlert | partition by Computer {SecurityEvent | take 5}",
    "SecurityAlert | facet by Type with (SecurityEvent | take 5)",
    "SecurityAlert | fork (SecurityEvent | take 5) (SigninLogs | take 5)",
    # --- control commands
    ".set MyTable <| SecurityAlert",
    # --- disallowed / blocked tables, in every position and casing
    "Heartbeat | take 10",
    "heartbeat | take 10",
    "HeArTbEaT | take 10",
    "Usage | summarize count()",
    "union * | where TimeGenerated > ago(1h)",
    "union withsource=T * | take 5",
    "SecurityAlert | join (Heartbeat | project Computer) on Computer",
    "print 1",
    "datatable(x:int)[1,2]",
    # --- union branches AFTER a pipeline branch were silently unscanned (H-1)
    "union (SecurityAlert | take 5), (Heartbeat)",
    "union isfuzzy=true (SecurityAlert | take 1), (Usage)",
    "union (union SecurityEvent, SigninLogs), (SecurityAlert)",
    "SecurityAlert | join (union SecurityEvent, SigninLogs) on Computer",
    # --- a disallowed / blocked table in a subquery or as an `in` operand
    "SecurityAlert | where Computer in (Heartbeat | project Computer) | take 5",
    "SecurityAlert | where Computer !in (Heartbeat) | take 5",
    # --- operators/functions hidden at the head of a tabular in() operand
    "SecurityAlert | where Computer in (union * | project Computer)",
    "SecurityAlert | where Computer in (union SigninLogs, Heartbeat | project Computer)",
    "SecurityAlert | where Computer in (search * | project Computer)",
    "SecurityAlert | where Computer in (find where true | project Computer)",
    "SecurityAlert | where Computer in (range x from 1 to 3 step 1 | project x)",
    "SecurityAlert | where Computer in (print x = 1 | project x)",
    "SecurityAlert | where Computer in (SomeStoredFunction() | project Computer)",
    "SecurityAlert | where Computer in (SomeStoredFunction())",
    "SecurityAlert | where Computer in (materialized_view('view') | project Computer)",
    "SecurityAlert | where Computer in (materialized_view('view'))",
    "SecurityAlert | where Computer in ((union Heartbeat | project Computer))",
]

#: Rejected because the table is not in the caller's tier - NOT because of
#: syntax. SecurityEvent is a real Sentinel table that is absent from tier1 and
#: tier2 and is not in `tables.blocked`, so these are accepted under
#: table_policy "workspace" and rejected under "allowlist".
#:
#: This is the regression corpus for SOURCE EXTRACTION (report H-1): every
#: entry proves the validator finds a table reference in a union branch, a join
#: operand or the head of an `in (...)` operand. It must keep running against a
#: tier that still enforces an allowlist, or opening the human tier silently
#: deletes that coverage.
REJECT_UNLISTED_TABLE = [
    "SecurityEvent | take 5",
    "(SecurityEvent) | take 5",
    "// hi\nSecurityEvent | take 5",
    "union (SecurityEvent), (SecurityAlert) | take 5",
    "union SecurityAlert, SecurityEvent | take 5",
    "SecurityAlert | join kind=inner (SecurityEvent | take 5) on Computer",
    "union (SecurityAlert | take 5), (SecurityEvent)",
    "union (SecurityAlert | take 5), SecurityEvent",
    "union (SecurityAlert | take 1), (SigninLogs), (SecurityEvent)",
    "SecurityAlert | union (SigninLogs | take 5), (SecurityEvent)",
    "SecurityAlert | where Computer in (SecurityEvent | project Computer) | take 5",
    "SecurityAlert | where Computer in (SecurityEvent) | take 5",
]

#: Tiers whose table_policy is "allowlist" in the shipped config.
ALLOWLIST_TIERS = [t for t in ("human", "agent") if config().table_policy_for(t) == "allowlist"]


def test_valid_queries_are_accepted():
    v = _v()
    for tier in ("human", "agent"):
        for q in VALID:
            r = v.validate(q, tier)
            assert r.is_valid, f"should accept for {tier}: {q!r} -> {r.error}"


def test_bypass_corpus_is_rejected():
    """Syntax-level rejections. Tier-independent: these must fail for every
    caller regardless of table policy."""
    v = _v()
    for tier in ("human", "agent"):
        for q in REJECT:
            assert not v.validate(q, tier).is_valid, f"should reject for {tier}: {q!r}"


def test_unlisted_tables_are_rejected_for_allowlist_tiers():
    """Source extraction still works. Runs against whichever tiers enforce an
    allowlist; skips only if the shipped config has opened every tier, which
    would itself be worth noticing."""
    if not ALLOWLIST_TIERS:
        pytest.skip("no tier uses table_policy 'allowlist' in the shipped config")
    v = _v()
    for tier in ALLOWLIST_TIERS:
        for q in REJECT_UNLISTED_TABLE:
            assert not v.validate(q, tier).is_valid, f"should reject for {tier}: {q!r}"


def test_unlisted_tables_are_accepted_for_workspace_tiers():
    """The deliberate widening, asserted rather than assumed - so that turning
    table_policy back to 'allowlist' fails here instead of passing quietly."""
    c = config()
    open_tiers = [t for t in ("human", "agent") if c.table_policy_for(t) == "workspace"]
    if not open_tiers:
        pytest.skip("no tier uses table_policy 'workspace' in the shipped config")
    v = _v()
    for tier in open_tiers:
        for q in REJECT_UNLISTED_TABLE:
            r = v.validate(q, tier)
            assert r.is_valid, f"should accept for {tier}: {q!r} -> {r.error}"


def test_blocked_tables_are_rejected_for_every_tier():
    """`tables.blocked` is the access policy under 'workspace'. It must hold
    for the open tier too."""
    v = _v()
    for tier in ("human", "agent"):
        for q in (
            "Heartbeat | take 10",
            "heartbeat | take 10",
            "HeArTbEaT | take 10",
            "Usage | summarize count()",
            "union (SecurityAlert | take 5), (Heartbeat)",
            "SecurityAlert | where Computer in (Heartbeat) | take 5",
        ):
            assert not v.validate(q, tier).is_valid, f"should reject for {tier}: {q!r}"


def test_empty_and_oversized():
    v = _v()
    assert not v.validate("   ", "human").is_valid
    assert not v.validate("SecurityAlert | where X == '" + "a" * 5000 + "'", "human").is_valid


def test_row_limit_appended():
    r = _v().validate("SecurityAlert", "human")
    assert r.is_valid and "take 5001" in r.sanitized_kql


def test_row_limit_capped():
    r = _v().validate("SecurityAlert | take 999999", "human")
    assert r.is_valid and "take 5001" in r.sanitized_kql and "999999" not in r.sanitized_kql


def test_row_limit_left_alone_when_under_cap():
    r = _v().validate("SecurityAlert | take 10", "human")
    assert r.sanitized_kql.strip() == "SecurityAlert | take 10"


def test_inner_take_does_not_satisfy_the_outer_limit():
    """A take inside a subquery limits the subquery, not the result set."""
    r = _v().validate("SecurityAlert | join (SigninLogs | take 10) on $left.A == $right.B", "human")
    assert r.is_valid
    assert r.sanitized_kql.rstrip().endswith("| take 5001")
    assert "take 10" in r.sanitized_kql  # the inner limit is preserved


def test_braces_count_towards_nesting_depth():
    """A `take` inside braces must not be mistaken for the outer cap."""
    toks = tokenize(clean_query("SecurityAlert | mv-apply x = 1 to typeof(int) on {take 5}"))
    inner = [t for t in toks if t.text == "5"]
    assert inner and inner[0].depth > 0


def test_agent_row_limit_is_lower():
    r = _v().validate("SecurityAlert", "agent")
    assert "take 3001" in r.sanitized_kql


def test_take_inside_a_string_is_not_rewritten():
    r = _v().validate("SecurityAlert | where Msg == '| take 999999' | take 10", "human")
    assert r.is_valid and "999999" in r.sanitized_kql


def test_take_is_inserted_before_render_not_after():
    """`render` must be the last operator in a Kusto query, so appending the
    row cap after it produced an invalid query (report M-1)."""
    r = _v().validate("SecurityAlert | summarize count() by Severity | render barchart", "human")
    assert r.is_valid
    assert r.sanitized_kql.rstrip().endswith("| render barchart")
    assert "| take 5001" in r.sanitized_kql
    assert r.sanitized_kql.index("take 5001") < r.sanitized_kql.index("render")


def test_existing_take_before_render_is_left_alone():
    r = _v().validate("SecurityAlert | take 5 | render table", "human")
    assert r.is_valid and r.sanitized_kql.strip() == "SecurityAlert | take 5 | render table"


def test_extracted_tables_reported():
    r = _v().validate("union SecurityAlert, SecurityIncident | take 5", "human")
    assert r.is_valid
    assert {t.lower() for t in r.extracted_tables} == {"securityalert", "securityincident"}


def test_every_union_branch_is_reported():
    r = _v().validate("union (SecurityAlert | take 5), (SigninLogs), (AuditLogs) | take 5", "human")
    assert r.is_valid
    assert {t.lower() for t in r.extracted_tables} == {"securityalert", "signinlogs", "auditlogs"}


def test_take_exactly_at_the_cap_is_bumped_to_the_probe():
    """`take 5000` must not return a full page flagged complete (report D-5)."""
    r = _v().validate("SecurityAlert | take 5000", "human")
    assert r.is_valid and "take 5001" in r.sanitized_kql
