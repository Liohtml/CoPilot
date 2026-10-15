"""The notification hand-off from the Rust service (``POST /notifications/events``).

The route is reachable by analysts, so the bridge must never trust what the
caller computed: only the two AI-analyst triggers, only alert events whose
customer is the alert's, and the dedupe key and link are re-derived.

Unit tests — no DB, no network.

Run with: cd backend && python -m pytest tests/test_notification_rust_bridge.py
"""

import os

import pytest

os.environ.setdefault("JWT_SECRET", "test-only-secret-not-the-compromised-default")

from app.notifications.schema.events import NotificationEvent  # noqa: E402
from app.notifications.schema.notifications import NotificationSeverity  # noqa: E402
from app.notifications.schema.notifications import NotificationTrigger  # noqa: E402
from app.notifications.services.bridge import BridgeRejected  # noqa: E402
from app.notifications.services.bridge import sanitize_bridged_event  # noqa: E402
from app.notifications.services.event_builders import (  # noqa: E402
    investigation_complete_event,
)


def _event(**overrides):
    base = dict(
        customer_code="TENANT_A",
        trigger=NotificationTrigger.INVESTIGATION_COMPLETE,
        severity=NotificationSeverity.HIGH,
        subject="Mimikatz signature",
        summary="Credential dumping observed.",
        entity_type="alert",
        entity_id=42,
        dedupe_key="anything-the-caller-likes",
        link_url="https://evil.invalid/phish",
        context={"alert_name": "Mimikatz signature", "asset_name": "dc01"},
    )
    base.update(overrides)
    return NotificationEvent(**base)


def test_rust_built_event_matches_the_python_builder(monkeypatch):
    """The JSON the Rust service sends (copilot_core::notify) parses into the
    same envelope the Python builder produces for the same alert."""
    monkeypatch.setenv("COPILOT_URL", "https://copilot.example.com/")
    rust_json = {
        "customer_code": "TENANT_A",
        "trigger": "investigation_complete",
        "severity": "Medium",
        "subject": "Alert #14",
        "summary": "done",
        "entity_type": "alert",
        "entity_id": 14,
        "dedupe_key": "alert:14:investigation_complete",
        "link_url": "https://copilot.example.com/alerts/14",
        "assignee_username": None,
        "actor_username": None,
        "context": {"alert_name": None, "asset_name": "dc01"},
    }
    python = investigation_complete_event(
        alert_id=14,
        customer_code="TENANT_A",
        severity="Medium",
        summary="done",
        alert_name=None,
        asset_name="dc01",
    )
    assert NotificationEvent(**rust_json) == python


def test_server_owned_fields_are_rederived(monkeypatch):
    monkeypatch.setenv("COPILOT_URL", "https://copilot.example.com")
    out = sanitize_bridged_event(_event(), "TENANT_A")
    assert out.dedupe_key == "alert:42:investigation_complete"
    assert out.link_url == "https://copilot.example.com/alerts/42"
    assert out.summary == "Credential dumping observed."


def test_link_is_dropped_without_copilot_url(monkeypatch):
    monkeypatch.delenv("COPILOT_URL", raising=False)
    assert sanitize_bridged_event(_event(), "TENANT_A").link_url is None


def test_customer_must_be_the_alerts():
    with pytest.raises(BridgeRejected, match="customer_code mismatch"):
        sanitize_bridged_event(_event(customer_code="TENANT_B"), "TENANT_A")


def test_missing_alert_is_a_lookup_error():
    with pytest.raises(LookupError, match="Alert 42 not found"):
        sanitize_bridged_event(_event(), None)


def test_only_ai_analyst_triggers():
    with pytest.raises(BridgeRejected):
        sanitize_bridged_event(_event(trigger=NotificationTrigger.ALERT_ASSIGNED), "TENANT_A")
    assert sanitize_bridged_event(_event(trigger=NotificationTrigger.AI_REPORT_REVIEWED), "TENANT_A")


def test_only_alert_entities():
    with pytest.raises(BridgeRejected):
        sanitize_bridged_event(_event(entity_type="case"), "TENANT_A")
