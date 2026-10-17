"""Regenerate the vectors that pin the monitoring-alert port (`copilot-monitoring-alerts`) to the
Python module it ports (`app/integrations/monitoring_alert/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-monitoring-alert-vectors.py

Writes `crates/copilot-monitoring-alerts/src/monitoring_alert_vectors.json`:

* `catalog` — `AvailableMonitoringAlerts` (member names and values, in declaration order) and the
  bytes `GET /available` answers (the route function, serialized as FastAPI's `dump_json`);
* `definitions` — the event definition every provisioning function of `PROVISION_FUNCTIONS` but
  the two WAF alerts sends (`json.dumps` of the entity `send_post_request_create_entity` receives,
  which is what `requests` puts on the wire), for several windows and intervals, and for Graylog
  versions below `"5.2"` as a string compares (`event_limit` deleted);
* `requests` — `ProvisionMonitoringAlertRequest` and `CustomMonitoringAlertProvisionModel`
  validated as FastAPI validates a body (`validate_python(…, from_attributes=True)`, errors under
  `("body",)`): the JSON-mode dump, the 422 `exception_handlers.validation_exception_handler`
  answers, or the `HTTPException` a validator raises;
* `custom` — the event definition `provision_custom_alert` sends for a validated custom alert, or
  the `ValidationError` it raises;
* `testing` — `EventShipperPayload(customer_code="00002", integration="testing", version="1.0",
  **request).to_dict()` and the GELF frame asyncgelf writes for it (to a local socket, with
  `socket.getfqdn()` fixed), or the `TypeError` of a key given twice;
* `ports` — the port `asyncio.open_connection(host, port_text)` connects to
  (`base_events._ipaddr_info`, else `socket.getaddrinfo`), or `null` when it raises.

Re-run after a change to the module, a Pydantic or FastAPI upgrade, or a Python upgrade.
"""

import asyncio
import json
import pathlib
import socket
import threading
from asyncio import base_events

from fastapi import HTTPException
from pydantic import TypeAdapter
from pydantic import ValidationError

import app.connectors.event_shipper.utils.universal as shipper
from app.integrations.monitoring_alert.routes import provision as routes
from app.integrations.monitoring_alert.schema.provision import AvailableMonitoringAlerts
from app.integrations.monitoring_alert.schema.provision import (
    AvailableMonitoringAlertsResponse,
)
from app.integrations.monitoring_alert.schema.provision import (
    CustomMonitoringAlertProvisionModel,
)
from app.integrations.monitoring_alert.schema.provision import (
    ProvisionMonitoringAlertRequest,
)
from app.integrations.monitoring_alert.services import provision as services
from app.integrations.utils.schema import EventShipperPayload
from app.middleware.exception_handlers import _describe
from app.utils import ErrorType
from app.utils import ValidationErrorItem
from app.utils import ValidationErrorResponse

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-monitoring-alerts" / "src" / "monitoring_alert_vectors.json"

SENT = []
VERSION = ["6.1.4"]


async def fake_create_entity(endpoint, entity, share_request=None, connector_name=None):
    SENT.append((endpoint, entity))
    return {"success": True, "data": {"id": "x"}}


async def fake_version():
    return VERSION[0]


services.send_post_request_create_entity = fake_create_entity
services.get_graylog_version = fake_version


def json_response(content):
    """The bytes of Starlette's `JSONResponse(content)`."""
    return json.dumps(content, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))


def body_outcome(model, text):
    """What FastAPI makes of `text` as the body of a route whose body parameter is `model`."""
    value = json.loads(text)
    try:
        dump = TypeAdapter(model).validate_python(value, from_attributes=True).model_dump(mode="json")
    except HTTPException as e:
        return {"status": e.status_code, "body": json_response({"success": False, "message": e.detail})}
    except ValidationError as e:
        details = []
        for error in e.errors(include_url=False):
            loc = ("body",) + tuple(error["loc"])
            field = str(loc[-1]) if loc else "body"
            try:
                error_type = ErrorType(error["type"])
            except ValueError:
                error_type = ErrorType.GENERAL
            message = _describe(error, loc) if error_type is ErrorType.GENERAL else None
            details.append(ValidationErrorItem(field=field, error_type=error_type, message=message))
        main = details[0].message if details else "Validation Error"
        return {"status": 422, "body": json_response(ValidationErrorResponse(message=main, details=details).model_dump())}
    return {"status": 200, "dump": json.dumps(dump)}


PROVISION_BODIES = [
    {"search_within_last": 60, "execute_every": 120},
    {"search_within_last": 60, "execute_every": 120, "alert_name": "suricata alert severity 1"},
    {"search_within_last": "60", "execute_every": 1.0, "alert_name": "Fortinet system", "graylog_instance": "network"},
    {"search_within_last": -5, "execute_every": True, "alert_name": "SOCFORTRESS_WAF_BLOCKED"},
    {"search_within_last": 100000000000000000000, "execute_every": 1, "alert_name": "MIMECAST_PHISHING_EMAIL_DELIVERED"},
    {"search_within_last": 0, "execute_every": 1},
    {"search_within_last": 1, "execute_every": 0},
    {"search_within_last": 1, "execute_every": False},
    {"search_within_last": "x", "execute_every": 0},
    {"search_within_last": 0.0, "execute_every": "x"},
    {"search_within_last": 1.5, "execute_every": 1},
    {"search_within_last": None, "execute_every": [], "alert_name": 5, "graylog_instance": "graylog02"},
    {"alert_name": "nope"},
    {"search_within_last": 1, "execute_every": 1, "alert_name": "nope"},
    {"search_within_last": "x", "execute_every": 1, "alert_name": "nope", "graylog_instance": 1},
    {"search_within_last": 1, "execute_every": 1, "alert_name": "custom"},
    {"search_within_last": 1, "execute_every": 1, "alert_name": "straße"},
    {"search_within_last": 1, "execute_every": 1, "alert_name": "wazuh\tsyslog level alert"},
    {"search_within_last": 1, "execute_every": 1, "alert_name": " wazuh syslog level alert"},
    {"search_within_last": 1, "execute_every": 1, "alert_name": "Wazuh_Syslog_Level_Alert", "graylog_instance": "DEFAULT"},
    {"search_within_last": 1, "execute_every": 1, "graylog_instance": None},
    {"search_within_last": "1_000", "execute_every": " 2 ", "graylog_instance": "network"},
    {"search_within_last": 1e300, "execute_every": 1},
    {},
    [],
    "x",
    {"search_within_last": {"a": 1}, "execute_every": [1]},
]

CUSTOM_BASE = {
    "alert_name": "MY_CUSTOM ALERT",
    "alert_description": "Custom",
    "alert_priority": 2,
    "search_query": "syslog_type:wazuh AND rule_level:>10",
    "search_within_ms": 300000,
    "execute_every_ms": 60000,
}
CUSTOM_BODIES = [
    CUSTOM_BASE,
    {**CUSTOM_BASE, "streams": ["s1", "s2"], "custom_fields": [{"name": "CUSTOMER CODE", "value": "00001"}]},
    {**CUSTOM_BASE, "alert_priority": 3.0, "graylog_instance": "network", "streams": []},
    {**CUSTOM_BASE, "alert_priority": True, "custom_fields": None},
    {**CUSTOM_BASE, "streams": None},
    {**CUSTOM_BASE, "search_within_ms": 0, "execute_every_ms": -1},
    {**CUSTOM_BASE, "search_within_ms": "100000000000000000000000"},
    {**CUSTOM_BASE, "alert_priority": "2"},
    {**CUSTOM_BASE, "alert_priority": 4, "streams": [1], "custom_fields": [{"name": 1}, "x"]},
    {**CUSTOM_BASE, "custom_fields": {"name": "a", "value": "b"}},
    {**CUSTOM_BASE, "alert_name": None, "search_query": 5, "graylog_instance": "x"},
    {"alert_name": "x"},
    {},
    [CUSTOM_BASE],
]

TESTING_BODIES = [
    {},
    {"message": "hello", "level": 3},
    {"a": None, "b": {"c": None}, "c": [1, 2.5, "é"], "d": True},
    {"customer_code": "00001"},
    {"integration": None},
    {"version": "2"},
    {"syslog_type": "wazuh", "agent_labels_customer": "00001", "n": 100000000000000000000},
    {"x": ' \u0000\u007f"\\'},
]

PORT_CASES = [
    (host, port)
    for host in ("127.0.0.1", "::1", "localhost")
    for port in (
        "12201",
        " 12201 ",
        "+12201",
        "-1",
        "1_2201",
        "77737",
        "12201.0",
        "",
        "None",
        "0",
        "65535",
        "65536",
        " 12201",
        "-4294967296",
        "4294979497",
    )
]


async def definitions():
    out = []
    windows = [(11, 7), (-5, 3), (100000000000000000000, 1)]
    for name, fn in routes.PROVISION_FUNCTIONS.items():
        if name == "CUSTOM" or name.startswith("SOCFORTRESS_WAF"):
            continue
        for within, every in windows:
            for version in ("6.1.4",) if (within, every) != (11, 7) else ("6.1.4", "5.1.9", "10.0.0"):
                VERSION[0] = version
                SENT.clear()
                await fn(ProvisionMonitoringAlertRequest(search_within_last=within, execute_every=every, alert_name=name))
                assert len(SENT) == 1 and SENT[0][0] == "/api/events/definitions", name
                out.append(
                    {
                        "name": name,
                        "search_within_last": str(within),
                        "execute_every": str(every),
                        "version": version,
                        "body": json.dumps(SENT[0][1], allow_nan=False),
                    },
                )
    VERSION[0] = "6.1.4"
    return out


async def custom():
    out = []
    for body in CUSTOM_BODIES:
        text = json.dumps(body)
        try:
            model = TypeAdapter(CustomMonitoringAlertProvisionModel).validate_python(json.loads(text), from_attributes=True)
        except (ValidationError, HTTPException):
            continue
        SENT.clear()
        try:
            await services.provision_custom_alert(model)
            out.append({"input": text, "body": json.dumps(SENT[0][1], allow_nan=False)})
        except ValidationError as e:
            out.append({"input": text, "error": str(e)})
    return out


def capture_server():
    """A one-connection TCP server on 127.0.0.1 collecting what it receives."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    received = []

    def accept():
        conn, _ = server.accept()
        chunks = []
        while True:
            data = conn.recv(65536)
            if not data:
                break
            chunks.append(data)
        received.append(b"".join(chunks))
        conn.close()

    t = threading.Thread(target=accept)
    t.start()
    return t, server, received


async def testing():
    out = []
    original = socket.getfqdn
    socket.getfqdn = lambda name="": "parity.host"
    try:
        for body in TESTING_BODIES:
            text = json.dumps(body)
            request = json.loads(text)
            try:
                message = EventShipperPayload(customer_code="00002", integration="testing", version="1.0", **request)
            except TypeError as e:
                out.append({"input": text, "error": f"TypeError: {e}"})
                continue
            t, server, received = capture_server()
            # The Event Shipper connector row's host and port, as `create_gelf_logger` reads them.
            logger = shipper.GelfLogger(host="127.0.0.1", port=str(server.getsockname()[1]))
            await logger.tcp_handler(message=message)
            await asyncio.sleep(0.05)
            t.join(5)
            server.close()
            out.append({"input": text, "message": json.dumps(message.to_dict()), "frame": received[0].decode("utf-8")})
    finally:
        socket.getfqdn = original
    return out


def ports():
    out = []
    for host, port in PORT_CASES:
        info = base_events._ipaddr_info(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0)
        if info is not None:
            number = info[4][1]
            resolved = number if 0 <= number <= 65535 else None
        else:
            try:
                resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][1]
            except OSError:
                resolved = None
        out.append({"host": host, "port": port, "resolved": resolved})
    return out


async def main():
    available = await routes.get_available_monitoring_alerts_route()
    doc = {
        "catalog": {
            "members": [{"name": m.name, "value": m.value} for m in AvailableMonitoringAlerts],
            "available": TypeAdapter(AvailableMonitoringAlertsResponse).dump_json(available).decode(),
        },
        "definitions": await definitions(),
        "requests": {
            "provision": [
                {"input": json.dumps(b), **body_outcome(ProvisionMonitoringAlertRequest, json.dumps(b))} for b in PROVISION_BODIES
            ],
            "custom": [{"input": json.dumps(b), **body_outcome(CustomMonitoringAlertProvisionModel, json.dumps(b))} for b in CUSTOM_BODIES],
        },
        "custom": await custom(),
        "testing": await testing(),
        "ports": ports(),
    }
    OUT.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}: {len(doc['definitions'])} definitions, {len(doc['testing'])} test events")


if __name__ == "__main__":
    asyncio.run(main())
