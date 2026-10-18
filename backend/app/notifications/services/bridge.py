"""Notification hand-off from the Rust service (`crates/copilot-gateway`).

While the backend is migrated to Rust module by module, the notification
pipeline (routes, channel providers, dispatch log) stays here. Ported modules
build the exact ``NotificationEvent`` the Python builders build and POST it
to ``/api/notifications/events``; this module decides whether to accept it.

The endpoint is analyst-reachable, so nothing the caller sends is trusted
beyond what a builder would have computed from the same alert:

* only the triggers the Rust service emits are accepted;
* the event must be about an alert, and its ``customer_code`` must be that
  alert's (the route has already checked the caller may see that customer);
* ``dedupe_key`` and ``link_url`` are re-derived here, so a caller can neither
  dodge the dispatch log's idempotency nor put a foreign link in a message.

See docs/architecture/RUST_MIGRATION.md.
"""

from __future__ import annotations

from typing import Optional

from app.notifications.schema.events import EntityType
from app.notifications.schema.events import NotificationEvent
from app.notifications.schema.notifications import NotificationTrigger
from app.notifications.services.event_builders import _copilot_link

BRIDGED_TRIGGERS = frozenset(
    {
        NotificationTrigger.INVESTIGATION_COMPLETE,
        NotificationTrigger.AI_REPORT_REVIEWED,
    },
)


class BridgeRejected(ValueError):
    """The event is not one the bridge forwards (answered as a 400)."""


def sanitize_bridged_event(event: NotificationEvent, alert_customer_code: Optional[str]) -> NotificationEvent:
    """Validate a bridged event against its alert and re-derive server-owned fields.

    ``alert_customer_code`` is the owner of ``event.entity_id`` as stored in
    ``incident_management_alert``; ``None`` means the alert does not exist.
    Raises ``LookupError`` for a missing alert and ``BridgeRejected`` otherwise.
    """
    if event.trigger not in BRIDGED_TRIGGERS:
        raise BridgeRejected(f"Trigger {event.trigger.value} cannot be emitted through the bridge")
    if event.entity_type != EntityType.ALERT:
        raise BridgeRejected("Only alert events can be emitted through the bridge")
    if alert_customer_code is None:
        raise LookupError(f"Alert {event.entity_id} not found")
    if event.customer_code != alert_customer_code:
        raise BridgeRejected(
            f"customer_code mismatch: alert {event.entity_id} belongs to {alert_customer_code}, got {event.customer_code}",
        )
    return event.model_copy(
        update={
            "dedupe_key": f"{EntityType.ALERT}:{event.entity_id}:{event.trigger.value}",
            "link_url": _copilot_link(f"/alerts/{event.entity_id}"),
        },
    )
