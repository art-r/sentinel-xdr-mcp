from datetime import timedelta
from typing import Annotated

import pytest
from pydantic import Field, TypeAdapter

from src.util import TIMESPAN_PATTERN, parse_and_cap_timespan, parse_iso8601_duration

#: Validate through PYDANTIC, not `re`. The pattern is consumed by pydantic-core,
#: which uses the Rust `regex` crate - a strictly smaller language than Python's
#: `re` (no look-around, no backreferences) with slightly different `$`
#: semantics. A previous version of this file compiled the pattern with `re`,
#: which happily accepted a look-ahead that made pydantic raise SchemaError on
#: import and stopped the whole suite from being collected.
_timespan = TypeAdapter(Annotated[str, Field(pattern=TIMESPAN_PATTERN)])


def _accepted(value: str) -> bool:
    try:
        _timespan.validate_python(value)
        return True
    except Exception:
        return False


ACCEPT = ["P1D", "P7D", "P365D", "PT6H", "PT30M", "PT0S", "P0D",
          "P7DT12H", "P7DT12H30M", "P7DT12H30M45S", "PT1H1M1S"]

REJECT = ["", "P", "PT", "1D", "banana", "p1d", "D1P", "P1H", "PTS",
          # dangling time designator - the look-ahead version accepted these
          "P1DT", "P0DT",
          # surrounding whitespace / newline: Python `re` "$" would allow the
          # trailing newline, the Rust engine does not. We want the Rust answer.
          " P1D", "P1D ", "P1D\n"]


def test_pattern_builds_under_pydantic():
    """The regression test for the SchemaError: constructing the adapter at
    import time is exactly what FastMCP does when registering the tool."""
    assert _timespan is not None


def test_pattern_accepts_real_durations():
    for value in ACCEPT:
        assert _accepted(value), f"pydantic should accept {value!r}"


def test_pattern_rejects_degenerate_values():
    for value in REJECT:
        assert not _accepted(value), f"pydantic should reject {value!r}"


def test_everything_the_pattern_accepts_can_be_parsed():
    """A value that passes the tool signature but blows up in the parser is a
    500. The two must not drift apart."""
    for value in ACCEPT:
        parse_iso8601_duration(value)


def test_parse():
    assert parse_iso8601_duration("P1D") == timedelta(days=1)
    assert parse_iso8601_duration("PT6H") == timedelta(hours=6)
    assert parse_iso8601_duration("P7DT12H") == timedelta(days=7, hours=12)


def test_cap():
    assert parse_and_cap_timespan("P1D", 90) == timedelta(days=1)
    assert parse_and_cap_timespan("P365D", 90) == timedelta(days=90)


def test_invalid():
    for bad in ("1D", "", "P", "PT", "banana"):
        with pytest.raises(ValueError):
            parse_iso8601_duration(bad)


def test_zero_is_an_error_not_the_maximum():
    """P0D previously expanded silently to the 90-day ceiling."""
    for zero in ("P0D", "PT0S"):
        with pytest.raises(ValueError):
            parse_and_cap_timespan(zero, 90)
