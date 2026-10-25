"""Shared pytest configuration and fixtures.

CONFIG_PATH is set BEFORE anything under src/ is imported: src.server calls
load_config() at import time, so the order of the statements in this file is
load-bearing.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Forced, not setdefault: a CONFIG_PATH exported in the developer's shell would
# otherwise silently change what the suite validates, and the same commit would
# pass locally and fail in CI. Per-tenant configs are validated separately by
# test_config.test_local_configs_are_valid.
os.environ["CONFIG_PATH"] = os.path.join(
    ROOT, "config", "mcp-server-config.example.yaml"
)

import pytest  # noqa: E402

from src import server as srv  # noqa: E402
from src.auth import current as current_mod  # noqa: E402
from src.governance.kql_validator import KQLValidator  # noqa: E402
from src.logging_setup import AuditLogger  # noqa: E402

from ._support import (  # noqa: E402
    CollectingLogger,
    FakeDefender,
    FakeLAW,
    FakeSentinel,
    _Token,
    config,
    defender_config,
)


class _Env:
    """Handle onto the stubbed dependencies for one test."""

    log = None
    law = None
    sentinel = None
    defender = None
    act_as = None


@pytest.fixture
def env(monkeypatch):
    """Stubbed clients and a capturing audit logger on the real Deps object.

    `Deps` is a module-level singleton, so every mutation here must go through
    monkeypatch - including the caches, which would otherwise leak between
    tests and make ordering significant.
    """
    log = CollectingLogger()
    monkeypatch.setattr(srv.deps, "audit", AuditLogger(config(), logger=log))

    law, sentinel, defender = FakeLAW(), FakeSentinel(), FakeDefender()
    monkeypatch.setattr(srv.deps, "_law_client", law)
    monkeypatch.setattr(srv.deps, "_sentinel_client", sentinel)
    monkeypatch.setattr(srv.deps, "_defender_client", defender)

    monkeypatch.setattr(srv.deps, "_tables", (None, ()))
    monkeypatch.setattr(srv.deps, "_ready", (None, False, "not checked"))

    env = _Env()
    env.log, env.law, env.sentinel, env.defender = log, law, sentinel, defender

    def _as(claims):
        monkeypatch.setattr(
            current_mod, "get_access_token",
            lambda: None if claims is None else _Token(claims),
        )

    env.act_as = _as
    _as(None)
    return env


@pytest.fixture
def defender_env(env, monkeypatch):
    """`env`, with Defender hunting enabled.

    The example config ships `defender.enabled: false`. Skipping the Defender
    suite on that basis would mean a green CI run proves nothing about the
    tool, so the policy is overridden here instead.

    `deps.config` is what every tool reads at call time, and
    `deps.defender_kql_validator` is built once in Deps.__init__ - both must be
    replaced together or the validator and the policy disagree.
    """
    cfg = defender_config()
    monkeypatch.setattr(srv.deps, "config", cfg)
    monkeypatch.setattr(srv.deps, "defender_kql_validator",
                        KQLValidator(cfg, source="defender"))
    monkeypatch.setattr(srv.deps, "kql_validator", KQLValidator(cfg, source="law"))
    monkeypatch.setattr(srv.deps, "audit", AuditLogger(cfg, logger=env.log))
    return env