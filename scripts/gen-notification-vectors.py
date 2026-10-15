"""Regenerate the vectors that pin `crates/copilot-notifications` to the Python
notification module.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-notification-vectors.py

Writes:

* `crates/copilot-notifications/src/channel_catalog.json` — what
  `GET /notification_channels` lists for each channel (`model_json_schema()` of
  each provider's config model, which carries its docstring);
* `crates/copilot-notifications/src/config_vectors.json` — channel configs
  through each provider's Pydantic `config_schema`: the normalized
  `model_dump()`, or the `ValidationError` text CoPilot puts into a 400/422;
* `crates/copilot-notifications/src/pyjson_vectors.json` — `json.dumps` with
  the default and the compact separators, ASCII-escaped or not;
* `crates/copilot-notifications/src/teams_vectors.json` — the Adaptive Card the
  Teams provider posts (`_build_card` + `_fit_within_size_limit`), as
  `json.dumps` text, for events, bodies and both body modes (the parity suite
  cannot capture Teams traffic: its URL must be `https://`).

Re-run after a Pydantic upgrade or a change to a channel's config model.
"""

import hashlib
import json
import pathlib

from pydantic import ValidationError

from app.notifications.channels import CHANNEL_REGISTRY
from app.notifications.schema.notifications import ChannelDescriptor

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-notifications" / "src"


def catalog():
    channels = []
    for provider in CHANNEL_REGISTRY.values():
        channels.append(
            ChannelDescriptor(
                key=provider.key,
                display_name=provider.display_name,
                config_schema=provider.config_schema.model_json_schema(),
                supports_recipient_modes=sorted(provider.supports_recipient_modes),
                supports_internal_scope=provider.supports_internal_scope,
                secret_fields=sorted(provider.secret_fields),
                template_formats=sorted(provider.template_formats),
            ).model_dump(),
        )
    return channels


LONG = "y" * 100
CONFIG_CASES = {
    "webhook": [
        {},
        {"url": "https://hooks.example.com/a", "method": "put", "headers": {"X-Key": "s"}, "include_full_report": True},
        {"url": 5},
        {"url": None},
        {"url": "é" * 30},
        {"method": "get"},
        {"method": "DELETE"},
        {"method": None},
        {"method": ""},
        {"method": "ß"},
        {"method": " post"},
        {"headers": {"a": 1}},
        {"headers": "x"},
        {"headers": None},
        {"headers": {"k": None, "j": [1]}},
        {"headers": []},
        {"bogus": 1, "x" * 80: LONG},
        {"z": 1, "url": 5},
        {"url": 5, "z": 1, "method": 3},
        {"include_full_report": "yes"},
        {"include_full_report": "maybe"},
        {"include_full_report": 1},
        {"include_full_report": 2},
        {"include_full_report": 0.0},
        {"include_full_report": None},
        {"url": "a" * 200},
        {"url": "a" * 47},
        {"url": "a" * 48},
        {"url": "a" * 49},
        {"url": {"nested": {"deep": [1, 2.5, True, None, "s"]}}},
        {"url": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]},
        {"url": "it's"},
        {"url": 'say "hi"'},
        {"url": "both ' and \""},
        {"url": "tab\there\nnewline\\"},
        {"url": "\x00\x1f\x7f\u0085  "},
        {"url": "emoji 😀 and ퟿"},
        {"url": 1.5},
        {"url": 1e100},
        {"url": -0.0},
        {"url": False},
        {"headers": "x" * 48},
        {"headers": "x" * 49},
        {"url": ["é" * 60]},
        {"url": ["😀" * 30]},
        {"include_full_report": " YES "},
        {"include_full_report": "Yes"},
        {"include_full_report": [True]},
        {"include_full_report": 1.0},
        {"include_full_report": -1},
    ],
    "resend": [
        {},
        {"to": "a@b.c"},
        {"to": ""},
        {"to": "   "},
        {"to": [1]},
        {"to": ["a@b.c", 2, None]},
        {"cc": None},
        {"cc": "c@d.e"},
        {"to": {"a": 1}},
        {"to": 7},
        {"max_per_hour": 0},
        {"max_per_hour": -3},
        {"max_per_hour": 1},
        {"max_per_hour": "3"},
        {"max_per_hour": " 4 "},
        {"max_per_hour": "x"},
        {"max_per_hour": 2.5},
        {"max_per_hour": 2.0},
        {"max_per_hour": True},
        {"max_per_hour": None},
        {"max_per_hour": "0"},
        {"max_per_hour": "+5"},
        {"max_per_hour": "007"},
        {"max_per_hour": "1_0"},
        {"max_per_hour": " -2 "},
        {"max_per_hour": 1e20},
        {"max_per_hour": []},
        {"max_per_hour": False},
        {"subject_prefix": None},
        {"subject_prefix": ""},
        {"from_address": 3, "reply_to": [], "subject_prefix": 1},
        {"to": ["x@y.z"], "cc": ["c@y.z"], "from_address": "f@y.z", "reply_to": "r@y.z", "subject_prefix": "[ACME]", "max_per_hour": 5},
        {"extra": True},
    ],
    "teams": [
        {},
        {"webhook_url": " https://x "},
        {"webhook_url": "HTTPS://Example.com"},
        {"webhook_url": "http://x"},
        {"webhook_url": ""},
        {"webhook_url": "   "},
        {"webhook_url": 3},
        {"webhook_url": None},
        {"webhook_url": "https://x", "other": "y"},
    ],
    "shuffle": [
        {},
        {"app_id": 1},
        {"app_id": "x", "app_name": "y", "z": [1, 2]},
        {"app_id": "abc", "app_name": None},
    ],
}


def config_vectors():
    out = []
    for channel, inputs in CONFIG_CASES.items():
        model = CHANNEL_REGISTRY[channel].config_schema
        for value in inputs:
            try:
                out.append({"channel": channel, "input": value, "ok": model.model_validate(value).model_dump()})
            except ValidationError as e:
                out.append({"channel": channel, "input": value, "error": str(e)})
    return out


DUMPS_CASES = [
    {},
    [],
    {"a": 1, "b": [True, False, None], "c": {"d": "e"}},
    {"text": 'é ü 😀   \x00 \x1f \x7f "q" \\ / \t\n\r\b\f'},
    [1.0, 1.5, 1e16, 1e-7, 123456789.0, 0.1, -0.0, 1e22, 12345678901234567890],
    "plain",
]


def dumps_vectors():
    out = []
    for value in DUMPS_CASES:
        out.append(
            {
                "input": value,
                "default": json.dumps(value),
                "compact": json.dumps(value, ensure_ascii=False, separators=(",", ":")),
            },
        )
    return out


TEAMS_EVENTS = [
    {
        "customer_code": "ACME",
        "trigger": "investigation_complete",
        "severity": "Critical",
        "subject": "Mimikatz on dc01",
        "summary": "s",
        "entity_type": "alert",
        "entity_id": 14,
        "dedupe_key": "k",
        "link_url": "https://copilot.example.com/alerts/14",
    },
    {
        "customer_code": None,
        "trigger": "case_task_assigned",
        "severity": "Informational",
        "subject": "Task \u00e9t\u00e9 \U0001f389",
        "summary": "s",
        "entity_type": "case_task",
        "entity_id": 7,
        "dedupe_key": "k",
        "assignee_username": "bob",
        "actor_username": "alice",
    },
    {
        "customer_code": "B",
        "trigger": "sla_breached",
        "severity": "Medium",
        "subject": 'Quote " and \\ backslash',
        "summary": "s",
        "entity_type": "case",
        "entity_id": 3,
        "dedupe_key": "k",
        "link_url": "https://c/x?a=1&b=<2>",
        "actor_username": "carol",
    },
]
#: (text, repeat): the body is `text * repeat`, so the file need not carry it.
TEAMS_BODIES = [
    ("short body", 1),
    ("*bold* \u2014 \u00fcnicode \U0001f600\nline two\ttab", 1),
    ('Report line with \u00e9 and "quotes" and \\ backslashes. ', 600),
    ("\U0001f600", 9000),
]


def teams_vectors():
    from app.notifications.channels.teams import TeamsChannel
    from app.notifications.schema.events import NotificationEvent

    channel = TeamsChannel()
    out = []
    for raw in TEAMS_EVENTS:
        event = NotificationEvent(**raw)
        for text, repeat in TEAMS_BODIES:
            body = text * repeat
            for raw_body in (False, True):
                card = channel._fit_within_size_limit(channel._build_card(event, body, raw_body=raw_body), event, body)
                dumped = json.dumps(card)
                out.append(
                    {
                        "event": raw,
                        "body": text,
                        "repeat": repeat,
                        "raw_body": raw_body,
                        # Long cards are pinned by length and digest only.
                        "card": dumped if len(dumped) < 4000 else None,
                        "length": len(dumped),
                        "sha256": hashlib.sha256(dumped.encode()).hexdigest(),
                    },
                )
    return out


def write(name, data):
    path = OUT / name
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    write("channel_catalog.json", catalog())
    write("config_vectors.json", config_vectors())
    write("pyjson_vectors.json", dumps_vectors())
    write("teams_vectors.json", teams_vectors())
