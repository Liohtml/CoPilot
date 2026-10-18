"""Regenerate the vectors that pin the Sublime port (`copilot-sublime`) to the Python module it ports
(`app/connectors/sublime/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-sublime-vectors.py

Writes `crates/copilot-sublime/src/sublime_vectors.json`:

* `requests` — `AlertRequestBody` on webhook bodies, as FastAPI validates a body
  (`from_attributes=True`): the dump or Pydantic's errors (`type`, `loc`, `msg`);
* `schemas` — `SublimeAlertsSchema` on stored alerts: the dump or the `ValidationError`'s
  `str()`, which the listing's 500 carries;
* `tags` — `json.dumps(rule.tags)`, the flagged rule's stored tags;
* `emails` — `collect_sender` / `collect_recipient` on Sublime's message answers:
  `data["sender"]["email"]` and `data["recipients"][0]["email"]`, or the exception (class and
  `str()`);
* `params` — SQLAlchemy's `_repr_params` of one row's values, as a database error prints them;
* `literals` — pymysql's `escape_item` of the JSON values an email may be (no strings: those
  are bound parameters in the port), or what it raises.

Re-run after a change to the module or a Pydantic, SQLAlchemy or PyMySQL upgrade.
"""

import datetime
import json
import pathlib

from pydantic import ValidationError
from pymysql.converters import escape_item
from sqlalchemy.sql.util import _repr_params

from app.connectors.sublime.schema.alerts import AlertRequestBody
from app.connectors.sublime.schema.alerts import SublimeAlertsSchema

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-sublime" / "src" / "sublime_vectors.json"


def message(**over):
    base = {
        "canonical_id": "canon-1",
        "external_id": "ext-1",
        "id": "msg-1",
        "mailbox": {"external_id": "mbx-ext", "id": "mbx-1"},
        "message_source_id": "src-1",
    }
    base.update(over)
    return base


def body(**over):
    base = {
        "api_version": "v0",
        "created_at": "2026-10-17T10:00:00Z",
        "data": {
            "flagged_rules": [{"id": "r1", "name": "Rule one", "severity": "high", "tags": ["a", "b"]}],
            "message": message(),
            "triggered_actions": [{"id": "a1", "name": "Notify", "type": "webhook"}],
        },
        "id": "evt-1",
        "type": "message.flagged",
    }
    base.update(over)
    return base


REQUESTS = [
    body(),
    body(api_version=1, created_at=None, id=["x"], type=True),
    {},
    {"api_version": "v0"},
    body(data={"flagged_rules": "r", "message": {}, "triggered_actions": [{}]}),
    body(
        data={
            "flagged_rules": [{"id": 1, "name": "n", "tags": "t"}, {"id": "r", "name": "n", "tags": [1, None]}],
            "message": message(external_id=None, mailbox={"id": 5}),
            "triggered_actions": [],
        },
    ),
    body(data={"flagged_rules": [], "message": message(mailbox=None), "triggered_actions": None}),
    body(data=[]),
    body(data={"flagged_rules": [{"id": "r", "name": "n", "severity": 3, "tags": []}], "message": "m", "triggered_actions": []}),
    body(extra="kept?", data={"flagged_rules": [], "message": {**message(), "extra": 1}, "triggered_actions": []}),
    body(created_at=1.5, api_version="ü ✓"),
]


def request_outcome(b):
    try:
        # FastAPI validates a body with `from_attributes=True`.
        return {"ok": AlertRequestBody.model_validate(b, from_attributes=True).model_dump(mode="json", by_alias=True)}
    except ValidationError as e:
        return {"errors": [{"type": x["type"], "loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}


def alert_row(**over):
    base = {
        "api_version": "v0",
        "created_at": "2026-10-17T10:00:00Z",
        "event_id": "evt-1",
        "type": "message.flagged",
        "message_id": "msg-1",
        "canonical_id": "canon-1",
        "external_id": "ext-1",
        "message_source_id": "src-1",
        "timestamp": "2026-10-17T10:00:01",
        "flagged_rules": [{"rule_id": "r1", "name": "Rule", "severity": None, "tags": '["a"]'}],
        "mailbox": [{"external_id": None, "mailbox_id": "mbx-1"}],
        "triggered_actions": [],
        "sender": [{"email": "s@example.com", "name": "n/a"}],
        "recipients": [{"email": "r@example.com", "name": "n/a"}],
    }
    base.update(over)
    return base


SCHEMAS = [
    alert_row(),
    alert_row(sender=[{"email": "s@example.com", "name": None}]),
    alert_row(sender=[{"email": "s@example.com", "name": None}], recipients=[{"email": "x", "name": "n/a"}, {"email": "y", "name": None}]),
    alert_row(timestamp="2026-10-17T10:00:01.250000", flagged_rules=[], mailbox=[], sender=[], recipients=[]),
]


def schema_outcome(row):
    try:
        return {"ok": SublimeAlertsSchema.model_validate(row).model_dump(mode="json")}
    except ValidationError as e:
        return {"error": str(e)}


TAGS = [[], ["a", "b"], ["ü", 'q"uote', "back\\slash", "\n", "✓ 😀"]]

DATA = [
    {"sender": {"email": "s@example.com"}, "recipients": [{"email": "r@example.com"}, {"email": "r2"}]},
    {"sender": {"email": None}, "recipients": [{"email": 5}]},
    {"sender": {"email": [1, "a"]}, "recipients": [{"email": {"x": 1}}]},
    {"sender": {}, "recipients": []},
    {"sender": "s", "recipients": "r"},
    {"sender": ["s"], "recipients": ""},
    {"sender": None, "recipients": {"0": {"email": "x"}}},
    {"recipients": [None]},
    {"sender": {"email": 1}, "recipients": [["x"]]},
    {"sender": {"email": True}, "recipients": [5]},
    [],
    "text",
    None,
    7,
]


def email_outcome(data, recipient):
    try:
        if recipient:
            return {"ok": data["recipients"][0]["email"]}
        return {"ok": data["sender"]["email"]}
    except Exception as e:  # noqa: BLE001 - the exception is the vector
        return {"error": {"class": type(e).__name__, "text": str(e)}}


def typed(value):
    if isinstance(value, datetime.datetime):
        return {"time": value.isoformat(sep=" ")}
    if value is None:
        return {"text": None}
    if isinstance(value, bool):
        return {"json": json.dumps(value)}
    if isinstance(value, int):
        return {"id": value}
    if isinstance(value, str):
        return {"text": value}
    return {"json": json.dumps(value)}


PARAMS = [
    ("v0", "2026-10-17T10:00:00Z", "evt-1", None, datetime.datetime(2026, 10, 17, 16, 59, 2, 756315)),
    (["a", []], "n/a", 7),
    ("x" * 400, "y'" * 200, None, '["a", "b"]', 1234567),
    ("ü✓😀" * 120, datetime.datetime(2026, 1, 7, 0, 0), datetime.datetime(2026, 1, 7, 0, 0, 5)),
    (["z" * 500], "n/a", 3),
    (7,),
]

LITERALS = [
    None,
    True,
    False,
    0,
    -5,
    12345678901234567890123,
    1.5,
    0.1,
    -0.0,
    1e100,
    1e-7,
    123456789012345680.0,
    [],
    [1],
    [[]],
    [1, [True, None, 2.5]],
    {"a": 1},
    [1, {}],
    [float("nan")],
    float("inf"),
    float("-inf"),
    [2, float("nan"), {}],
]


def literal_outcome(value):
    try:
        return {"ok": escape_item(value, "utf8mb4")}
    except Exception as e:  # noqa: BLE001 - the exception is the vector
        return {"error": {"class": type(e).__name__, "text": str(e)}}


def json_value(value):
    return json.dumps(value, allow_nan=True)


def main():
    out = {
        "requests": [{"body": b, "outcome": request_outcome(b)} for b in REQUESTS],
        "schemas": [{"row": r, "outcome": schema_outcome(r)} for r in SCHEMAS],
        "tags": [{"tags": t, "dumps": json.dumps(t)} for t in TAGS],
        "emails": [{"data": json_value(d), "sender": email_outcome(d, False), "recipient": email_outcome(d, True)} for d in DATA],
        "params": [{"values": [typed(v) for v in p], "repr": repr(_repr_params(p, batches=10, ismulti=False))} for p in PARAMS],
        "literals": [{"value": json_value(v), "outcome": literal_outcome(v)} for v in LITERALS],
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
