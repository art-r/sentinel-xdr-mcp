"""Result-size enforcement. Truncation is always reported explicitly.

Byte capping is linear: estimate the per-row cost once from a sample and slice,
rather than re-serialising the whole payload in a shrink loop.
"""

from __future__ import annotations

import json

from .sanitize import MAX_CELL_CHARS, UNTRUSTED_NOTE, scrub_text, scrub_value


def _json_len(obj) -> int:
    return len(json.dumps(obj, default=str).encode())


def _cap_rows_by_size(rows: list, max_size_bytes: int, overhead: int) -> list:
    if not rows:
        return rows
    budget = max_size_bytes - overhead
    if budget <= 0:
        return []
    sample = rows[: min(len(rows), 50)]
    per_row = max(1.0, _json_len(sample) / len(sample))
    keep = int(budget // per_row)
    if keep >= len(rows):
        # The estimate says it fits; confirm once, and fall back to a
        # proportional shrink if the estimate was optimistic (wide tail rows).
        actual = _json_len(rows)
        if actual <= budget:
            return rows
        keep = max(0, int(len(rows) * budget / actual))
    return rows[:keep]


def truncate(
    result: dict,
    max_rows: int,
    max_size_bytes: int | None = None,
    max_cell_chars: int = MAX_CELL_CHARS,
) -> dict:
    """Apply the row cap, the byte cap and cell scrubbing, reporting each one.

    `max_rows` must be the same ceiling KQLValidator._enforce_row_limit compiled
    into the query, which asks the workspace for max_rows + 1. That extra row is
    a probe: if it came back, more data matched than the caller may see, the
    exact total is unknown, and the row is dropped here rather than returned.

    The two truncation causes are reported differently on purpose. A byte cap
    knows the real total; a row cap does not, and publishing max_rows + 1 as
    `total_row_count` would be a precise-looking lie.
    """
    # Column names come from the workspace schema and are attacker-influenced in
    # custom tables, so they are scrubbed too.
    columns = [scrub_text(str(c), max_cell_chars) for c in result["columns"]]
    rows = result["rows"]
    actual = len(rows)

    row_capped = actual > max_rows
    kept = rows[:max_rows]

    size_capped = False
    if max_size_bytes is not None:
        before = len(kept)
        kept = _cap_rows_by_size(kept, max_size_bytes, overhead=_json_len(columns) + 512)
        size_capped = len(kept) < before

    out: dict = {
        "columns": columns,
        "rows": scrub_value(kept, max_cell_chars),
        "row_count": len(kept),
        "truncated": row_capped or size_capped,
        "content_warning": UNTRUSTED_NOTE,
    }
    if row_capped:
        out["note"] = (
            f"More than {max_rows} rows matched; returning the first {len(kept)}. "
            "The exact total is not available. Refine your query with filters or "
            "aggregations (summarize/count) to get a complete answer."
        )
    elif size_capped:
        out["total_row_count"] = actual
        out["note"] = (
            f"Results truncated from {actual} to {len(kept)} rows by the result "
            "size limit. Refine your query with filters, fewer columns, or "
            "aggregations (summarize/count)."
        )
    return out


def truncate_list(
    items: list,
    max_items: int,
    max_size_bytes: int | None = None,
    max_cell_chars: int = MAX_CELL_CHARS,
) -> dict:
    """Row/byte caps for the non-tabular tools (entities, schema)."""
    actual = len(items)
    kept = items[:max_items]
    truncated = actual > max_items
    if max_size_bytes is not None:
        before = len(kept)
        kept = _cap_rows_by_size(kept, max_size_bytes, overhead=512)
        truncated = truncated or len(kept) < before
    out: dict = {
        "items": scrub_value(kept, max_cell_chars),
        "count": len(kept),
        "truncated": truncated,
        "content_warning": UNTRUSTED_NOTE,
    }
    if truncated:
        out["total_count"] = actual
    return out
