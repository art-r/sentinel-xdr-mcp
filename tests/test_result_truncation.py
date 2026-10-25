import time

from src.governance.result_truncation import truncate, truncate_list


def test_no_truncation():
    r = truncate({"columns": ["c"], "rows": [[1], [2], [3]]}, 5)
    assert r["truncated"] is False and r["row_count"] == 3


def test_row_truncation_reports_no_exact_total():
    """The row cap is enforced by a `take max_rows + 1` probe, so the real
    total is unknown and must not be invented (report D-5)."""
    rows = [[i] for i in range(10)]
    r = truncate({"columns": ["c"], "rows": rows}, 5)
    assert r["truncated"] is True and r["row_count"] == 5
    assert "total_row_count" not in r
    assert "More than 5 rows" in r["note"]


def test_exactly_at_the_cap_is_not_truncated():
    """Only the probe row proves there was more."""
    r = truncate({"columns": ["c"], "rows": [[i] for i in range(5)]}, 5)
    assert r["truncated"] is False and "note" not in r


def test_one_over_the_cap_is_truncated():
    r = truncate({"columns": ["c"], "rows": [[i] for i in range(6)]}, 5)
    assert r["truncated"] is True and r["row_count"] == 5


def test_byte_cap_still_reports_an_exact_total():
    rows = [["x" * 1000] for _ in range(1000)]
    r = truncate({"columns": ["c"], "rows": rows}, 5000, max_size_bytes=50_000)
    assert r["truncated"] is True and r["total_row_count"] == 1000


def test_byte_cap():
    rows = [["x" * 1000] for _ in range(1000)]
    r = truncate({"columns": ["c"], "rows": rows}, 5000, max_size_bytes=50_000)
    assert r["truncated"] is True
    assert 0 < r["row_count"] < 1000


def test_byte_cap_is_not_quadratic():
    """The old shrink loop re-serialised the whole payload on every iteration."""
    rows = [["y" * 200] for _ in range(50_000)]
    start = time.monotonic()
    r = truncate({"columns": ["c"], "rows": rows}, 50_000, max_size_bytes=100_000)
    elapsed = time.monotonic() - start
    assert r["truncated"] is True
    assert elapsed < 2.0, f"byte capping took {elapsed:.1f}s"


def test_untrusted_marker_present():
    r = truncate({"columns": ["c"], "rows": [["v"]]}, 5)
    assert "content_warning" in r and "untrusted" in r["content_warning"].lower()


def test_cells_are_scrubbed():
    r = truncate({"columns": ["c"], "rows": [["a\u200bb\x07c"]]}, 5)
    assert r["rows"][0][0] == "abc"


def test_truncate_list():
    out = truncate_list([{"i": i} for i in range(100)], 10)
    assert out["count"] == 10 and out["truncated"] is True and out["total_count"] == 100
