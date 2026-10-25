"""Pure helpers, no cloud/framework deps (unit-testable)."""
from __future__ import annotations

import re
from datetime import timedelta

_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")

#: Time component of an ISO-8601 duration with AT LEAST one field present.
_TIME = r"(\d+H(\d+M)?(\d+S)?|\d+M(\d+S)?|\d+S)"

#: Pattern for tool arguments - i.e. handed to `pydantic.Field(pattern=...)`.
#:
#: MUST be expressible in the Rust `regex` crate, which pydantic-core uses:
#: **no look-ahead, no look-behind, no backreferences**. An earlier version read
#:     ^P(?=\d|T\d)(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$
#: which is valid Python `re` but makes pydantic raise SchemaError at import
#: time - i.e. the server does not start and the test suite cannot even be
#: collected. Python's `re` accepting a pattern proves nothing about pydantic.
#:
#: The alternation below expresses "at least one component" structurally
#: instead of with a look-ahead: either a day part (with an optional, non-empty
#: time part) or a time part on its own. Rejects the degenerate "P", "PT" and
#: also the dangling "P1DT", which the look-ahead version accepted.
TIMESPAN_PATTERN = rf"^P(\d+D(T{_TIME})?|T{_TIME})$"


def parse_iso8601_duration(value: str) -> timedelta:
    m = _DURATION.match(value or "")
    if not m or not any(m.groups()):
        raise ValueError(f"Invalid ISO 8601 duration: {value!r}")
    days, hours, minutes, seconds = (int(x) if x else 0 for x in m.groups())
    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def parse_and_cap_timespan(value: str, max_days: int) -> timedelta:
    """Parse an ISO-8601 duration and cap it at the tier ceiling.

    A zero-length span is an error, not a silent expansion to the maximum.
    """
    span = parse_iso8601_duration(value)
    if span <= timedelta(0):
        raise ValueError("timespan must be greater than zero")
    return min(span, timedelta(days=max_days))
