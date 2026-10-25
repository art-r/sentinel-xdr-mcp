"""KQL validation and sanitisation. Fail-closed: anything not understood is rejected.

Design notes (deliberate - see report.md section 3)
---------------------------------------------------
This is NOT a KQL parser and does not try to be. It is a small tokeniser plus a
positional scan, which is both simpler and strictly stronger than the previous
pile of substring regexes:

  * the query is cleaned length-preservingly (comments and string literals are
    blanked), so token offsets still map onto the original text;
  * multi-statement queries and `let` are rejected outright - that removes the
    entire class of "bind a table to a name, then use the name" bypasses;
  * constructs that reach outside the workspace or introduce an invisible data
    source are matched POSITIONALLY on the token stream: as a function when the
    next token is "(" - so `workspace ('other')` is caught whatever the spacing,
    which a "workspace(" substring match is not - or as an operator at the query
    start / straight after a "|". Position is what lets `extend app = 1` and
    `project range` through while still blocking `app ('other')`;
  * table names are collected only from positions where KQL can actually take a
    data source: query start, after `union` (every comma-separated branch, at
    the union's own nesting depth), after `join`, the head of a parenthesised
    or braced pipeline, and the operand of `in (...)`. Everything else - column
    names, aliases - is never compared against the table lists, so
    `| project Operation` is not a false positive.

`union` and `join` are only treated as source-introducing at a real operator
position (query start, or straight after `|`), so a column or alias named
`union` is not a false positive either.

The Managed Identity's RBAC scope (Log Analytics Reader on ONE workspace) is
still the authoritative boundary. This layer is a usability guard rail and a
second line of defence, not the security perimeter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple


@dataclass
class ValidationResult:
    is_valid: bool
    error: str | None = None
    sanitized_kql: str | None = None
    extracted_tables: frozenset = field(default_factory=frozenset)


def _banned_message(word: str) -> str:
    return (
        f"'{word}' is not allowed here. Query this workspace's own tables directly; "
        "cross-workspace/cluster references, dynamic sources and plugin operators "
        "are disabled."
    )


class _Tok(NamedTuple):
    text: str
    kind: str  # "ident" | "num" | "punc"
    start: int
    end: int
    depth: int


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|\S")

#: Identifiers that introduce a data source and are handled explicitly.
_SOURCE_KEYWORDS = {"union", "join"}

#: All bracket kinds count towards nesting depth. Braces matter because the
#: legacy `partition by X {subquery}` form uses them, and a `| take` inside one
#: must not satisfy the OUTER row cap (report M-2).
_OPENERS = {"(", "[", "{"}
_CLOSERS = {")", "]", "}"}


def clean_query(kql: str) -> str:
    """Blank comments and string literals, preserving length and offsets."""
    out = list(kql)
    i, n = 0, len(kql)
    while i < n:
        c = kql[i]
        if c == "/" and i + 1 < n and kql[i + 1] == "/":
            while i < n and kql[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "@" and i + 1 < n and kql[i + 1] in "'\"":
            quote = kql[i + 1]
            out[i] = out[i + 1] = " "
            i += 2
            while i < n:
                if kql[i] == quote:
                    if i + 1 < n and kql[i + 1] == quote:  # doubled-quote escape
                        out[i] = out[i + 1] = " "
                        i += 2
                        continue
                    out[i] = " "
                    i += 1
                    break
                out[i] = " "
                i += 1
            continue
        if c in "'\"":
            quote = c
            out[i] = " "
            i += 1
            while i < n:
                if kql[i] == "\\" and i + 1 < n:
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if kql[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def tokenize(cleaned: str) -> list[_Tok]:
    toks: list[_Tok] = []
    depth = 0
    for m in _TOKEN_RE.finditer(cleaned):
        text = m.group(0)
        if text[0].isalpha() or text[0] == "_":
            kind = "ident"
        elif text[0].isdigit():
            kind = "num"
        else:
            kind = "punc"
        if text in _CLOSERS:
            depth = max(0, depth - 1)
        toks.append(_Tok(text, kind, m.start(), m.end(), depth))
        if text in _OPENERS:
            depth += 1
    return toks


def _read_source(toks: list[_Tok], i: int) -> tuple[str | None, int]:
    """Read one data source starting at token index `i`.

    Skips `kind=inner`, `isfuzzy=true`, `hint.strategy=shuffle`-style modifiers
    and any opening parentheses, then expects a bare identifier.
    Returns (name, index_after) or (None, i) when the position is not a plain
    table reference - which the caller treats as a rejection.
    """
    n = len(toks)
    while i < n and toks[i].kind == "ident":
        j = i + 1
        while j + 1 < n and toks[j].text == "." and toks[j + 1].kind == "ident":
            j += 2
        if j < n and toks[j].text == "=" and j + 1 < n and toks[j + 1].kind in ("ident", "num"):
            i = j + 2
            continue
        break
    while i < n and toks[i].text == "(":
        i += 1
    if i < n and toks[i].kind == "ident" and toks[i].text.lower() not in _SOURCE_KEYWORDS:
        return toks[i].text, i + 1
    return None, i


def _at_operator_position(toks: list[_Tok], idx: int) -> bool:
    """True when the token starts a pipeline stage: query start, or after `|`."""
    return idx == 0 or toks[idx - 1].text == "|"


def _preceded_by_in(toks: list[_Tok], open_idx: int) -> bool:
    """True when the bracket at `open_idx` is the operand of in / !in / in~."""
    j = open_idx - 1
    while j >= 0 and toks[j].text in ("~", "!"):
        j -= 1
    return j >= 0 and toks[j].kind == "ident" and toks[j].text.lower() == "in"


def _matching_bracket(toks: list[_Tok], open_idx: int) -> int | None:
    """Return the matching close token for a bracket, or None if malformed.

    Token depth alone is insufficient here because an `in (...)` operand may
    contain nested `()`, `[]` and `{}`. This deliberately small stack is used
    only to bound the operand scan; it is not an attempt to parse KQL.
    """
    expected = {"(": ")", "[": "]", "{": "}"}
    opener = toks[open_idx].text
    if opener not in expected:
        return None
    stack = [expected[opener]]
    for idx in range(open_idx + 1, len(toks)):
        text = toks[idx].text
        if text in expected:
            stack.append(expected[text])
        elif stack and text == stack[-1]:
            stack.pop()
            if not stack:
                return idx
    return None


class KQLValidator:
    def __init__(self, config, source: str = "law") -> None:
        """`source` selects the dialect profile and the table authority.

        "law"      - Log Analytics, tables from config.governance / config.tables
        "defender" - Defender advanced hunting, tables from config.defender

        Two instances, not two classes: the tokeniser and the positional scan
        are dialect-independent. Only the banned lists, the table authority and
        the row cap differ.
        """
        if source not in ("law", "defender"):
            raise ValueError(f"unknown KQL source {source!r}")
        self.config = config
        self.source = source
        self.kql = config.kql if source == "law" else config.defender.kql
        self._banned_fn = {b.lower() for b in self.kql.banned_functions}
        self._banned_op = {b.lower() for b in self.kql.banned_operators}

    def _is_blocked(self, name: str) -> bool:
        if self.source == "law":
            return self.config.is_table_blocked(name)
        return self.config.is_defender_table_blocked(name)

    def _is_allowed(self, caller_type: str, name: str) -> bool:
        if self.source == "law":
            return self.config.is_table_allowed(caller_type, name)
        return self.config.is_defender_table_allowed(name)

    def _max_rows(self, caller_type: str) -> int:
        if self.source == "law":
            return self.config.governance[caller_type].max_result_rows
        return self.config.defender.max_result_rows

    # ---- public API ----------------------------------------------------

    def validate(self, kql: str, caller_type: str) -> ValidationResult:
        kql = kql.strip()
        if not kql:
            return ValidationResult(False, "Empty query")
        if len(kql) > self.kql.max_query_length:
            return ValidationResult(
                False,
                f"Query exceeds the maximum length of {self.kql.max_query_length} characters",
            )

        cleaned = clean_query(kql)
        if cleaned.lstrip().startswith("."):
            return ValidationResult(False, "Control commands (queries starting with '.') are not allowed")

        toks = tokenize(cleaned)
        if not toks:
            return ValidationResult(False, "Empty query")

        for idx, t in enumerate(toks):
            if t.text == ";":
                return ValidationResult(
                    False, "Only a single statement is allowed (';' and 'let' are not permitted)"
                )
            if t.kind != "ident":
                continue
            word = t.text.lower()
            prev = toks[idx - 1].text if idx else None
            nxt = toks[idx + 1].text if idx + 1 < len(toks) else None
            if prev == ".":
                continue  # property access such as x.app, not the operator
            # Function form: `name (` - the token stream ignores the whitespace
            # that defeated the old "workspace(" substring match.
            if word in self._banned_fn and nxt == "(":
                return ValidationResult(False, _banned_message(t.text))
            # Operator form: at the query start or immediately after a pipe.
            if word in self._banned_op and _at_operator_position(toks, idx):
                return ValidationResult(False, _banned_message(t.text))

        tables, err = self._extract_tables(toks)
        if err:
            return ValidationResult(False, err)

        for tbl in sorted(tables):
            if self._is_blocked(tbl):
                return ValidationResult(False, f"Table '{tbl}' is blocked")
            if not self._is_allowed(caller_type, tbl):
                return ValidationResult(
                    False,
                    f"Table '{tbl}' is not in your allowed list. "
                    "Call list_available_tables to see what you can query.",
                )

        sanitized = self._enforce_row_limit(kql, toks, caller_type)
        return ValidationResult(True, sanitized_kql=sanitized, extracted_tables=frozenset(tables))

    # ---- internals -----------------------------------------------------

    def _collect_union_sources(self, toks: list[_Tok], idx: int, tables: set[str]) -> str | None:
        """Collect every branch of a `union`; return an error string or None.

        The previous implementation advanced only over `)` tokens looking for
        the separating comma, so a branch that was itself a pipeline -
        `union (SecurityAlert | take 5), (Heartbeat)` - stopped the walk at the
        inner `|` and left every later branch unscanned (report H-1). The walk
        is now depth-aware: separators count only at the union's own depth.
        """
        n = len(toks)
        base_depth = toks[idx].depth
        j = idx + 1
        while j < n:
            name, after = _read_source(toks, j)
            if name is None:
                return ("Could not determine the tables used in 'union'. "
                        "List each source table explicitly; wildcards, nested unions "
                        "and computed sources are not allowed.")
            tables.add(name)

            k = after
            while k < n:
                tok = toks[k]
                if tok.depth == base_depth and tok.text in (",", "|", ";"):
                    break
                k += 1
            if k < n and toks[k].text == "," and toks[k].depth == base_depth:
                j = k + 1
                continue
            return None
        return None

    def _extract_tables(self, toks: list[_Tok]) -> tuple[set[str], str | None]:
        tables: set[str] = set()
        n = len(toks)

        if toks[0].text.lower() != "union":
            name, _ = _read_source(toks, 0)
            if name is None:
                return tables, (
                    "Could not determine the data source. A query must start with a table name, "
                    "for example: SecurityAlert | where ... | take 100"
                )
            tables.add(name)

        for idx, t in enumerate(toks):
            if t.kind != "ident" or not _at_operator_position(toks, idx):
                continue
            word = t.text.lower()
            if word == "join":
                name, _ = _read_source(toks, idx + 1)
                if name is None:
                    return tables, "Could not determine the table used in 'join'"
                tables.add(name)
            elif word == "union":
                err = self._collect_union_sources(toks, idx, tables)
                if err:
                    return tables, err

        # A tabular `in (...)` operand is a source position too. It is the one
        # nested form that is both common in SOC queries and easy to make safe:
        # permit a pipeline headed by one direct table, reject union/search/find,
        # stored functions and computed sources. This closes the previous blind
        # spot without turning the validator into a KQL parser.
        for open_idx, opener in enumerate(toks):
            if opener.text != "(" or not _preceded_by_in(toks, open_idx):
                continue
            close_idx = _matching_bracket(toks, open_idx)
            if close_idx is None:
                return tables, "Unbalanced parentheses in 'in (...)' expression"

            head_idx = open_idx + 1
            while head_idx < close_idx and toks[head_idx].text == "(":
                head_idx += 1  # allow harmless grouping around a direct table
            if head_idx >= close_idx or toks[head_idx].kind != "ident":
                continue  # scalar list such as ('a', 'b')

            head = toks[head_idx]
            next_text = toks[head_idx + 1].text if head_idx + 1 < close_idx else None
            word = head.text.lower()
            contains_pipe = any(t.text == "|" for t in toks[open_idx + 1:close_idx])

            # dynamic([...]) is a scalar list, not a tabular source. Every other
            # function-form head is rejected: it might resolve to a stored
            # tabular function and hide its source tables, even with no pipe.
            if next_text == "(":
                if word == "dynamic":
                    continue
                return tables, (
                    "A tabular 'in (...)' expression must start with one direct table name; "
                    "unions and functions are not allowed there."
                )
            if word in self._banned_op:
                return tables, _banned_message(head.text)
            if word in _SOURCE_KEYWORDS:
                return tables, (
                    "A tabular 'in (...)' expression must start with one direct table name; "
                    "unions and functions are not allowed there."
                )
            if contains_pipe:
                tables.add(head.text)
                continue

            # A single bare identifier (possibly wrapped in grouping parentheses)
            # is a tabular operand in Kusto and must be checked as a table. Comma-
            # separated identifier lists remain scalar lists and are left alone.
            if next_text == ")":
                tables.add(head.text)

        # Head of other bracketed pipelines, e.g. a join operand. `in (...)`
        # has been handled above because it needs the stricter direct-table rule.
        for idx in range(1, n - 1):
            prev, cur, nxt = toks[idx - 1], toks[idx], toks[idx + 1]
            if cur.kind != "ident" or prev.text not in ("(", "{"):
                continue
            if nxt.text == "|":
                tables.add(cur.text)
            elif nxt.text in (")", "}") and _preceded_by_in(toks, idx - 1):
                tables.add(cur.text)
        return tables, None

    def _enforce_row_limit(self, kql: str, toks: list[_Tok], caller_type: str) -> str:
        """Cap or append an OUTER `| take N`.

        A `take` inside a subquery limits the subquery, not the result set, so
        only depth-0 pipes satisfy the outer limit. When the query ends in
        `| render ...` the cap is inserted BEFORE it: Kusto requires `render`
        to be the last operator, so appending after it produces an invalid
        query (report M-1).

        The compiled limit is max_rows + 1, not max_rows. The extra row is a
        probe: `truncate()` reports truncation as `len(rows) > max_rows`, so a
        query capped at exactly max_rows returns a full result set flagged
        `truncated: false` and the caller is told the data is complete when it
        is not (report D-5). The probe row is discarded before the result is
        returned; it only ever answers "was there more?".
        """
        max_rows = self._max_rows(caller_type)
        probe = max_rows + 1
        edits: list[tuple[int, int, str]] = []
        found_outer = False
        render_at: int | None = None
        for i, t in enumerate(toks):
            if t.text != "|" or t.depth != 0:
                continue
            if i + 1 >= len(toks):
                continue
            op = toks[i + 1]
            if op.kind == "ident" and op.text.lower() == "render" and render_at is None:
                render_at = t.start
            if i + 2 >= len(toks):
                continue
            num = toks[i + 2]
            if op.kind == "ident" and op.text.lower() in ("take", "limit") and num.kind == "num":
                found_outer = True
                # >= not >: a caller-supplied `take max_rows` is exactly the
                # case that silently loses the truncation signal.
                if int(num.text) >= max_rows:
                    edits.append((num.start, num.end, str(probe)))

        if not found_outer:
            if render_at is not None:
                return f"{kql[:render_at]}| take {probe}\n{kql[render_at:]}"
            return f"{kql}\n| take {probe}"

        out = kql
        for start, end, repl in sorted(edits, reverse=True):
            out = out[:start] + repl + out[end:]
        return out
