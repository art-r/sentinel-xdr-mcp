"""SDK-shape contract for azure-mgmt-securityinsight.

The package's newest non-prerelease is 1.0.0 (2022) and the generated method
names have moved across SDK generations - `incident_comments.create` did not
exist in 1.x, and the only code path that used it was the single write path,
so a wrong guess would have surfaced in production and nowhere else.
"""

import pytest

from src.clients.sentinel_client import COMMENT_CREATE_METHODS, _resolve, _incident_to_dict


class _Ops:
    def create_or_update(self, *a, **k):
        return "created"


class _LegacyOps:
    def create_comment(self, *a, **k):
        return "created"


class _WrongOps:
    def delete(self, *a, **k):
        return None


def test_resolve_prefers_the_current_name():
    assert _resolve(_Ops(), COMMENT_CREATE_METHODS, "x")() == "created"


def test_resolve_falls_back_to_an_older_generation():
    assert _resolve(_LegacyOps(), COMMENT_CREATE_METHODS, "x")() == "created"


def test_resolve_fails_loudly_and_names_what_it_found():
    with pytest.raises(RuntimeError) as err:
        _resolve(_WrongOps(), COMMENT_CREATE_METHODS, "incident_comments")
    msg = str(err.value)
    assert "incident_comments" in msg and "delete" in msg


def test_installed_sdk_actually_has_the_operations_we_call():
    """Runs only when the SDK is installed. This is the test that catches a bad
    version pin - the mocks above cannot."""
    securityinsight = pytest.importorskip("azure.mgmt.securityinsight")

    assert hasattr(securityinsight, "SecurityInsights"), (
        "SecurityInsights is missing - you are probably on a 2.0.0bN pre-release, "
        "which renamed it to SecurityInsightsMgmtClient. Pin >=1.0,<2.0."
    )
    from azure.mgmt.securityinsight.models import IncidentComment
    from azure.mgmt.securityinsight.operations import (
        IncidentCommentsOperations,
        IncidentsOperations,
    )

    for name in ("get", "list", "list_entities"):
        assert hasattr(IncidentsOperations, name), f"IncidentsOperations.{name} missing"
    assert any(hasattr(IncidentCommentsOperations, n) for n in COMMENT_CREATE_METHODS), (
        f"IncidentCommentsOperations has none of {COMMENT_CREATE_METHODS}"
    )
    IncidentComment(message="probe")  # constructor signature we rely on


def test_incident_mapping_tolerates_missing_optional_fields():
    """Model attributes vary by SDK version; the mapper must degrade to None
    rather than raise."""

    class _Bare:
        name = "guid"

    out = _incident_to_dict(_Bare())
    assert out["id"] == "guid"
    assert out["title"] is None and out["owner"] is None and out["labels"] == []
    assert out["alerts_count"] is None
