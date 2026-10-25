"""Every `pattern=` in src/ must be buildable by pydantic-core.

pydantic validates with the Rust `regex` crate, not Python's `re`. The Rust
crate has no look-around and no backreferences, so a pattern that compiles
happily under `re` can still make pydantic raise `SchemaError` - and because
FastMCP builds a `TypeAdapter` per tool at *registration* time, that error
fires on import: the server does not start and pytest cannot even collect.

This scans the source rather than testing one known pattern, so the next one
someone adds is covered too.
"""

import ast
import importlib
import pathlib
from typing import Annotated

import pytest
from pydantic import Field, TypeAdapter

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"


def _module_name(path: pathlib.Path) -> str:
    return ".".join(path.relative_to(SRC.parent).with_suffix("").parts)


def _patterns() -> list[tuple[str, str, str]]:
    """(source_file, description, pattern) for every `pattern=` in src/.

    Handles both a literal (`Field(pattern=r"^\\d+$")`) and a reference to a
    module-level constant (`Field(pattern=TIMESPAN_PATTERN)`), which is resolved
    by importing the module that uses it.
    """
    found: list[tuple[str, str, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.keyword) or node.arg != "pattern":
                continue
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                found.append((path.name, f"line {value.lineno}", value.value))
            elif isinstance(value, ast.Name):
                module = importlib.import_module(_module_name(path))
                resolved = getattr(module, value.id, None)
                assert isinstance(resolved, str), (
                    f"{path.name}: could not resolve pattern={value.id} to a string"
                )
                found.append((path.name, value.id, resolved))
            else:  # pragma: no cover - a computed pattern would be a smell
                raise AssertionError(
                    f"{path.name} line {value.lineno}: pattern= must be a literal "
                    "or a module-level constant so it can be checked here"
                )
    return found


PATTERNS = _patterns()


def test_some_patterns_were_found():
    """Guards the guard: if the scan silently finds nothing it proves nothing."""
    assert len(PATTERNS) >= 4, PATTERNS


@pytest.mark.parametrize("source,label,pattern", PATTERNS)
def test_pattern_is_buildable_by_pydantic_core(source, label, pattern):
    try:
        TypeAdapter(Annotated[str, Field(pattern=pattern)])
    except Exception as exc:  # pragma: no cover - only on a regression
        pytest.fail(
            f"{source} ({label}) is not a valid pydantic-core pattern: {pattern!r}\n"
            f"{exc}\n"
            "The Rust regex crate has no look-around and no backreferences - "
            "express the constraint structurally instead."
        )


@pytest.mark.parametrize("source,label,pattern", PATTERNS)
def test_pattern_is_anchored(source, label, pattern):
    """pydantic uses a SEARCH, not a full match: an unanchored `\\d{1,10}` would
    accept 'abc123def'. Every pattern here is an input allowlist, so all of them
    must be anchored at both ends."""
    assert pattern.startswith("^") and pattern.endswith("$"), (
        f"{source} ({label}): {pattern!r} is not anchored; pydantic would accept "
        "any string merely CONTAINING a match"
    )
