"""Parity of the Rust SOC Management port (`crates/copilot-soc-management`, `crates/copilot-sla`)
with this backend — NOT collected by pytest (needs a live MySQL and a running Rust binary; run by
scripts/rust-parity.sh, or alone with PARITY_SUITES=tests/e2e/rust_parity_soc_e2e.py).

Sends the same requests to the real FastAPI routers (`soc_management_router`,
`customer_portal_sla_router`, in-process) and to the Rust service over HTTP, on one disposable
database, and compares status codes and **raw response bytes** (field order and CPython's float
rendering included). The seed is a realistic SLA history written straight to the tables, the way
`soc_management_seed.py` writes it (every lifecycle action through the API would be stamped
"now"): five customers, a business-hours calendar in Europe/Rome with items across the March DST
change and open clocks running across the October one, a New York calendar for the write twins,
customer overrides, paused, breached, at-risk, reopened, untracked and customer-closed items,
verdicts, case links, tags, and every kind of user (admin, scoped analysts, a tag-restricted
analyst, a responder, portal users, an analyst with no customer).

"Now" is part of every figure. Each dashboard-like read goes to Rust first, and the Python
service's clock (`metrics.utc_now`) is frozen at the instant Rust evaluated (`generated_at`, or the
`now` an attention item's `overdue_seconds` implies), so the comparison is exact even for items of
other suites whose clocks move during the run. The seeded open items are shifted until their
states are stable for twenty minutes, so the portal overview (which reports no "now") compares too.

Writes run once per backend on twin customers (P for Python, R for Rust) with identical items, and
the rows they leave — policy cells, calendars, re-targeted due times — are compared; the global
policy and calendar writes are compared with the database restored in between. The notifier runs
once in Python and once in Rust (a second binary opted in to `notify_sla_transitions`, the job
handed over), against one webhook recorder: stamps, deliveries and dispatch-log rows are compared.

Deliberate differences are asserted as such (DIFF_BY_DESIGN) and listed in
docs/architecture/RUST_MIGRATION.md §4.
"""

import asyncio
import datetime
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from rust_parity_e2e import RUST  # noqa: E402  (sets the environment defaults first)
from rust_parity_e2e import check  # noqa: E402
from rust_parity_e2e import results  # noqa: E402
from rust_parity_e2e import token  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

import app.soc_management.services.metrics as metrics_module  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402
from app.soc_management.clock import utc_now as real_utc_now  # noqa: E402
from app.soc_management.domain.analytics import ItemFact  # noqa: E402
from app.soc_management.domain.calendar import BusinessCalendar  # noqa: E402
from app.soc_management.domain.calendar import CalendarBook  # noqa: E402
from app.soc_management.domain.policy import PolicyRow  # noqa: E402
from app.soc_management.domain.policy import SlaEntity  # noqa: E402
from app.soc_management.domain.policy import resolve_targets  # noqa: E402

SFX = uuid.uuid4().hex[:6]
A, B, C, D, P, R = (f"SOC_{k}{SFX}" for k in "ABCDPR")
NAMES = {A: "Acme Industries", B: "Globex Retail", C: "Initech Health", D: "Tie Breakers", P: "Twin Python", R: "Twin Rust"}
ADMIN, ANALYST, ANA_A, TAGGED = f"soc_admin{SFX}", f"soc_ana{SFX}", f"soc_anaa{SFX}", f"soc_tag{SFX}"
RESPONDER, PORTAL, PORTAL_B, NOBODY = f"soc_resp{SFX}", f"soc_portal{SFX}", f"soc_portalb{SFX}", f"soc_nobody{SFX}"
BOB, CLEO = f"soc_bob{SFX}", f"soc_cleo{SFX}"
# Whole minutes: every seeded opening, hence every 24/7 due time, sits on :00 seconds.
T0 = datetime.datetime.utcnow().replace(second=0, microsecond=0)
SO = "/api/soc_management"
CP = "/api/customer_portal/sla"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# --- frozen clock for the Python side ------------------------------------------------
CLOCK = [None]
metrics_module.utc_now = lambda: CLOCK[0] or real_utc_now()

WEEK_ROME = {d: [["08:00", "12:00"], ["13:00", "18:00"]] for d in ("mon", "tue", "wed", "thu", "fri")}
WEEK_NY = {d: [["09:00", "17:00"]] for d in ("mon", "tue", "wed", "thu", "fri")}
CALENDARS = {
    A: ("Europe/Rome", WEEK_ROME, ["2026-04-06", "2026-10-19", "2025-12-25"]),
    P: ("America/New_York", WEEK_NY, ["2026-11-26"]),
    R: ("America/New_York", WEEK_NY, ["2026-11-26"]),
}
# (customer, entity, severity, ack, resolve, business hours)
POLICY = [
    (A, "alert", "High", 45, 300, True),
    (A, "alert", "Critical", 15, 120, True),
    (A, "case", "High", 60, 1440, True),
    (B, "alert", "High", 30, 240, False),
    (B, "case", "High", 30, 1440, False),
    (B, "alert", "Informational", None, 2880, False),
    *[(t, "alert", "Medium", 120, 600, True) for t in (P, R)],
    *[(t, "case", "Critical", 30, 480, True) for t in (P, R)],
]
POLICY_ROWS = [PolicyRow(c, SlaEntity(e), s, a, r, bh) for c, e, s, a, r, bh in POLICY]

# (title, source, severity, false-positive share)
RULES = [
    ("Brute force SSH login", "wazuh", "Medium", 0.65),
    ("Impossible travel sign-in", "office365", "High", 0.3),
    ("Malware detected by EDR", "crowdstrike", "Critical", 0.05),
    ("Suspicious PowerShell execution", "wazuh", "High", 0.2),
    ("Port scan from external host", "graylog", "Low", 0.75),
    ("Phishing link clicked", "Office365", "Medium", 0.25),
    ("DNS tunneling suspected", "graylog", "Informational", 0.5),
]
WEIGHTS = [18, 10, 3, 8, 14, 9, 5]
ACK_MEDIAN = {"Critical": 9, "High": 28, "Medium": 95, "Low": 240, "Informational": 600}
RESOLVE_MEDIAN = {"Critical": 150, "High": 300, "Medium": 900, "Low": 2400, "Informational": 4000}


def calendar_book():
    cals = {c: BusinessCalendar.from_dict({"timezone": tz, "week": w, "holidays": h}) for c, (tz, w, h) in CALENDARS.items()}
    return CalendarBook(global_calendar=None, by_customer=cals)


def minutes(rng, median, spread=0.9):
    return datetime.timedelta(minutes=round(max(1.0, rng.lognormvariate(0, spread) * median)))


def fact_of(item, code, book):
    return ItemFact(
        entity=SlaEntity(item["entity"]),
        id=0,
        title="",
        customer_code=code,
        severity=item["severity"],
        status=item["status"],
        assigned_to=None,
        opened_at=item["opened"],
        tracked=item["tracked"],
        ack_due_at=item["ack_due"],
        resolve_due_at=item["resolve_due"],
        first_ack_at=item["ack_at"],
        resolved_at=item["resolved_at"],
        paused_at=item["paused_at"],
        clock=book.clock(code, item["bh"]),
    )


def place(item, code, book):
    """Due times from the policy in force; then, for an open item, shift its history back until no
    clock changes state within twenty minutes of T0 (the run must not race a boundary)."""
    for _ in range(200):
        targets = resolve_targets(SlaEntity(item["entity"]), item["severity"], code, POLICY_ROWS)
        clock = book.clock(code, targets.business_hours)
        item["bh"] = targets.business_hours
        if item["tracked"]:
            item["ack_due"] = targets.ack_due(item["opened"], clock)
            item["resolve_due"] = targets.resolve_due(item["opened"], clock)
        else:
            item["ack_due"] = item["resolve_due"] = None
        if item["status"] == "CLOSED" or not item["tracked"]:
            return item
        fact = fact_of(item, code, book)
        later = T0 + datetime.timedelta(minutes=20)
        if fact.ack_state(T0) == fact.ack_state(later) and fact.resolve_state(T0) == fact.resolve_state(later):
            return item
        step = datetime.timedelta(minutes=37)
        for k in ("opened", "ack_at", "resolved_at", "paused_at"):
            if item[k] is not None:
                item[k] -= step
    raise RuntimeError("could not place an item away from its SLA boundaries")


def gen_alerts(code, n, seed, start, end):
    rng = random.Random(seed)
    book = calendar_book()
    team = [BOB, CLEO, ANALYST, ADMIN, RESPONDER]
    span = int((end - start).total_seconds()) // 60
    out = []
    for i in range(n):
        title, source, severity, fp = rng.choices(RULES, weights=WEIGHTS)[0]
        opened = start + datetime.timedelta(minutes=rng.randint(0, span))
        if i % 9 == 0:  # some fresh ones, close to their response clock
            opened = T0 - datetime.timedelta(minutes=rng.choice([4, 12, 40, 55, 95, 170, 400]))
        actor = rng.choice(team)
        ack = opened + minutes(rng, ACK_MEDIAN[severity])
        acked = ack <= T0 and rng.random() < 0.9
        resolve = (ack if acked else opened) + minutes(rng, RESOLVE_MEDIAN[severity], 1.1)
        resolved = resolve <= T0 and rng.random() < 0.75
        if resolved and not acked and rng.random() < 0.5:
            resolved_by = PORTAL  # a customer closed it before the SOC answered
        else:
            resolved_by = rng.choice([actor, actor, BOB, PORTAL])
        verdict = None
        if resolved and rng.random() < 0.8:
            verdict = "FALSE_POSITIVE" if rng.random() < fp else "TRUE_POSITIVE"
        waiting = acked and not resolved and rng.random() < 0.2
        status = "PENDING_CUSTOMER" if waiting else ("CLOSED" if resolved else rng.choice(["OPEN", "IN_PROGRESS"]))
        item = {
            "entity": "alert",
            "title": title,
            "source": source,
            "severity": severity,
            "status": status,
            "opened": opened,
            "tracked": rng.random() > 0.08,
            "ack_at": ack if acked else None,
            "ack_by": actor if acked else None,
            "ack_action": rng.choice(["assigned", "status_changed", "commented"]) if acked else None,
            "resolved_at": resolve if resolved else None,
            "resolved_by": resolved_by if resolved else None,
            "reopen_count": 1 if resolved and rng.random() < 0.1 else 0,
            "paused_at": min(T0 - datetime.timedelta(minutes=5), ack + minutes(rng, 90)) if waiting else None,
            "paused_seconds": rng.choice([0, 0, 0, 1800, 7260]) if resolved else 0,
            "credit": 0,
            "assigned": actor if acked and rng.random() < 0.8 else rng.choice([None, None, ""]),
            "escalated": severity == "Critical" and rng.random() < 0.5,
            "verdict": verdict,
            "tag": rng.choice([None, "t1", "t2", "t1"]),
        }
        if item["paused_seconds"]:
            item["credit"] = item["paused_seconds"]
        out.append(place(item, code, book))
    return out


def gen_cases(code, alert_ids, items, seed):
    rng = random.Random(seed)
    book = calendar_book()
    out = []
    candidates = [(aid, it) for aid, it in zip(alert_ids, items) if it["severity"] in ("Critical", "High", "Medium")]
    for k, (aid, it) in enumerate(candidates[:6]):
        created = (it["ack_at"] or it["opened"]) + datetime.timedelta(minutes=7)
        if created > T0:
            created = T0 - datetime.timedelta(hours=3)
        closed = created + minutes(rng, 900)
        resolved = closed <= T0 and rng.random() < 0.5
        severity = rng.choice([None, "Critical", it["severity"]])
        case = {
            "entity": "case",
            "title": f"[INC] {it['title']}",
            "severity": severity or it["severity"],
            "explicit": severity,
            "status": "CLOSED" if resolved else rng.choice(["OPEN", "IN_PROGRESS", "PENDING_CUSTOMER"]),
            "opened": created,
            "tracked": k != 3,
            "ack_at": created,
            "ack_by": ANALYST,
            "ack_action": "created",
            "resolved_at": closed if resolved else None,
            "resolved_by": ANALYST if resolved else None,
            "reopen_count": 0,
            "paused_at": None,
            "paused_seconds": 0,
            "credit": 0,
            "assigned": rng.choice([ANALYST, BOB, None]),
            "escalated": rng.random() < 0.3,
            "links": [aid],
        }
        if case["status"] == "PENDING_CUSTOMER":
            case["paused_at"] = T0 - datetime.timedelta(minutes=30)
        out.append(place(case, code, book))
    return out


async def seed():
    ids = {"alerts": {}, "cases": {}}
    async with AsyncSession(async_engine) as s:

        async def ins(sql, **params):
            return (await s.execute(text(sql), params)).lastrowid

        for code, name in NAMES.items():
            await ins("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
        users = {}
        for name, role in (
            (ADMIN, 1),
            (ANALYST, 2),
            (ANA_A, 2),
            (TAGGED, 2),
            (RESPONDER, 5),
            (PORTAL, 4),
            (PORTAL_B, 4),
            (NOBODY, 2),
            (BOB, 2),
            (CLEO, 2),
        ):
            users[name] = await ins(
                "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 's@example.com', UTC_TIMESTAMP(), :r)",
                n=name,
                r=role,
            )
        for name, codes in (
            (ANALYST, (A, B, C)),
            (ANA_A, (A,)),
            (TAGGED, (A, B)),
            (RESPONDER, (A,)),
            (PORTAL, (A, C)),
            (PORTAL_B, (B,)),
            (BOB, (A, B, C, D, P, R)),
        ):
            for code in codes:
                await ins(
                    "INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (:u, :c, UTC_TIMESTAMP())",
                    u=users[name],
                    c=code,
                )
        for code, (tz, week, holidays) in CALENDARS.items():
            await ins(
                "INSERT INTO soc_sla_calendar (customer_code, timezone, week, holidays, updated_at, updated_by) "
                "VALUES (:c, :tz, :w, :h, '2026-01-02 03:04:05', 'seed')",
                c=code,
                tz=tz,
                w=json.dumps(week),
                h=json.dumps(holidays),
            )
        for i, (code, entity, severity, ack, resolve, bh) in enumerate(POLICY):
            await ins(
                "INSERT INTO soc_sla_policy (customer_code, entity_type, severity, ack_minutes, resolve_minutes, business_hours, "
                "updated_at, updated_by) VALUES (:c, :e, :s, :a, :r, :bh, :t, :by)",
                c=code,
                e=entity,
                s=severity,
                a=ack,
                r=resolve,
                bh=bh,
                t=f"2026-02-0{1 + i % 3} 10:00:00",
                by=f"seed{i % 2}",
            )
        for code, enabled in ((A, 1), (C, 0)):
            await ins(
                "INSERT INTO customer_portal_sla_settings (customer_code, enabled, updated_at, updated_by) VALUES (:c, :e, "
                "'2026-03-04 05:06:07', :u)",
                c=code,
                e=enabled,
                u=users[ADMIN],
            )
        tags = {t: await ins("INSERT INTO incident_management_alerttag (tag) VALUES (:t)", t=f"{t}-{SFX}") for t in ("t1", "t2")}
        ids["tags"] = tags
        ids["users"] = users

        dst_start, dst_end = datetime.datetime(2026, 3, 24), datetime.datetime(2026, 4, 3)
        recent = T0 - datetime.timedelta(days=40), T0
        plan = [
            (A, 70, 11, *recent),
            (A, 25, 12, dst_start, dst_end),
            (B, 45, 21, *recent),
            (C, 30, 31, *recent),
            (P, 24, 41, *recent),
            (R, 24, 41, *recent),
        ]
        for code, n, seed_, start, end in plan:
            items = gen_alerts(code, n, seed_, start, end)
            alert_ids = []
            for it in items:
                aid = await ins(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, customer_code, "
                    "source, escalated, assigned_to, severity, verdict, time_closed) VALUES (:n, 'd', :s, :t, :c, :src, :e, :a, :sev, :v, :tc)",
                    n=it["title"],
                    s=it["status"],
                    t=it["opened"],
                    c=code,
                    src=it["source"],
                    e=it["escalated"],
                    a=it["assigned"],
                    sev=it["severity"],
                    v=it["verdict"],
                    tc=it["resolved_at"],
                )
                alert_ids.append(aid)
                await insert_tracking(s, "soc_sla_alert_tracking", "alert_id", aid, it)
                if it["tag"] and code in (A, B):
                    await ins("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)", a=aid, t=tags[it["tag"]])
            ids["alerts"].setdefault(code, []).extend(zip(alert_ids, items))
            cases = gen_cases(code, alert_ids, items, seed_ + 100)
            for case in cases:
                cid = await ins(
                    "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, case_status, assigned_to, "
                    "customer_code, escalated, case_closed_time, severity) VALUES (:n, 'cd', :t, :s, :a, :c, :e, :tc, :sev)",
                    n=case["title"],
                    t=case["opened"],
                    s=case["status"],
                    a=case["assigned"],
                    c=code,
                    e=case["escalated"],
                    tc=case["resolved_at"],
                    sev=case["explicit"],
                )
                for aid in case["links"]:
                    await ins("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=cid, a=aid)
                await insert_tracking(s, "soc_sla_case_tracking", "case_id", cid, case)
                ids["cases"].setdefault(code, []).append((cid, case))
        # Clocks the notifier owes on (C runs 24/7 on the built-in targets).
        notices = [
            ("Medium", 20 * 60, None),  # acknowledge breached 16 h ago (sent), resolve at risk (sent)
            ("Low", 60 * 60, 30),  # acknowledged; resolve at risk
            ("Critical", 30 * 60, None),  # both clocks breached over a day ago: stamped silently
            ("High", 3 * 60, None),  # acknowledge breached 2 h ago
        ]
        for severity, age, acked_after in notices:
            opened = T0 - datetime.timedelta(minutes=age)
            item = {
                "entity": "alert",
                "title": f"Notice {severity}",
                "source": "wazuh",
                "severity": severity,
                "status": "OPEN",
                "opened": opened,
                "tracked": True,
                "ack_at": opened + datetime.timedelta(minutes=acked_after) if acked_after else None,
                "ack_by": BOB if acked_after else None,
                "ack_action": "assigned" if acked_after else None,
                "resolved_at": None,
                "resolved_by": None,
                "reopen_count": 0,
                "paused_at": None,
                "paused_seconds": 0,
                "credit": 0,
                "assigned": BOB if acked_after else None,
                "escalated": False,
                "verdict": None,
            }
            place(item, C, calendar_book())
            aid = await ins(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, customer_code, "
                "source, escalated, assigned_to, severity) VALUES (:n, 'd', 'OPEN', :t, :c, 'wazuh', 0, :a, :sev)",
                n=item["title"],
                t=item["opened"],
                c=C,
                a=item["assigned"],
                sev=severity,
            )
            await insert_tracking(s, "soc_sla_alert_tracking", "alert_id", aid, item)
            ids["alerts"][C].append((aid, item))
        # A top-rule tie for D: two titles with the same count, which MySQL's row order breaks.
        for title in ("Tie rule Y", "Tie rule X", "Tie rule X", "Tie rule Y"):
            item = {
                "entity": "alert",
                "title": title,
                "source": "wazuh",
                "severity": "Low",
                "status": "CLOSED",
                "opened": T0 - datetime.timedelta(days=2),
                "tracked": True,
                "ack_at": T0 - datetime.timedelta(days=2) + datetime.timedelta(minutes=30),
                "ack_by": BOB,
                "ack_action": "assigned",
                "resolved_at": T0 - datetime.timedelta(days=1),
                "resolved_by": BOB,
                "reopen_count": 0,
                "paused_at": None,
                "paused_seconds": 0,
                "credit": 0,
                "assigned": BOB,
                "escalated": False,
                "verdict": None,
            }
            place(item, D, calendar_book())
            aid = await ins(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, customer_code, "
                "source, escalated, assigned_to, severity) VALUES (:n, 'd', 'CLOSED', :t, :c, 'wazuh', 0, :a, 'Low')",
                n=title,
                t=item["opened"],
                c=D,
                a=BOB,
            )
            await insert_tracking(s, "soc_sla_alert_tracking", "alert_id", aid, item)
        await s.commit()
    return ids


async def insert_tracking(s, table, key, item_id, it):
    await s.execute(
        text(
            f"INSERT INTO {table} ({key}, severity, opened_at, ack_due_at, resolve_due_at, first_ack_at, first_ack_by, first_ack_action, "
            "first_assigned_at, resolved_at, resolved_by, first_resolved_at, reopen_count, tracked, updated_at, business_hours, "
            "paused_at, paused_seconds, pause_credit_seconds) VALUES (:id, :sev, :o, :ad, :rd, :aa, :ab, :act, :fa, :ra, :rb, :fr, "
            ":rc, :tr, :o, :bh, :pa, :ps, :pc)",
        ),
        {
            "id": item_id,
            "sev": it["severity"],
            "o": it["opened"],
            "ad": it["ack_due"],
            "rd": it["resolve_due"],
            "aa": it["ack_at"],
            "ab": it["ack_by"],
            "act": it["ack_action"],
            "fa": it["ack_at"] if it.get("assigned") else None,
            "ra": it["resolved_at"],
            "rb": it["resolved_by"],
            "fr": it["resolved_at"],
            "rc": it["reopen_count"],
            "tr": it["tracked"],
            "bh": it["bh"],
            "pa": it["paused_at"],
            "ps": it["paused_seconds"],
            "pc": it["credit"],
        },
    )


def build_python_app():
    from app.customer_portal.routes.sla import customer_portal_sla_router
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.soc_management.routes.soc_management import soc_management_router

    api = APIRouter(prefix="/api")
    api.include_router(soc_management_router, prefix="/soc_management")
    api.include_router(customer_portal_sla_router, prefix="/customer_portal")
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def frozen_at(resp, how):
    """The instant the Rust answer was evaluated at, for the Python side."""
    try:
        data = resp.json()
    except ValueError:
        return None
    if how == "generated_at" and isinstance(data, dict) and data.get("generated_at"):
        return datetime.datetime.fromisoformat(data["generated_at"])
    if how == "attention" and isinstance(data, dict) and data.get("items"):
        first = data["items"][0]
        return datetime.datetime.fromisoformat(first["due_at"]) + datetime.timedelta(seconds=first["overdue_seconds"])
    if how == "dashboard" and isinstance(data, dict) and data.get("generated_at"):
        return datetime.datetime.fromisoformat(data["generated_at"])
    return None


async def sql(statement, **params):
    async with AsyncSession(async_engine) as s:
        result = await s.execute(text(statement), params)
        await s.commit()
        return result


async def rows(statement, **params):
    async with AsyncSession(async_engine) as s:
        return [tuple(r) for r in (await s.execute(text(statement), params)).all()]


async def main():
    ids = await seed()
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=60)
    tok = {
        "admin": token(ADMIN, ["admin"]),
        "analyst": token(ANALYST, ["analyst"]),
        "ana_a": token(ANA_A, ["analyst"]),
        "tagged": token(TAGGED, ["analyst"]),
        "responder": token(RESPONDER, ["responder", "analyst"]),
        "portal": token(PORTAL, ["customer_user"], customer_codes=[A, C]),
        "portal_b": token(PORTAL_B, ["customer_user"], customer_codes=[B]),
        "nobody": token(NOBODY, ["analyst"]),
        "bob": token(BOB, ["analyst"]),
    }
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    async def same(name, method, path, t=None, body=None, freeze=None, raw=None, ctype=None):
        kw = {"headers": H(t)}
        if body is not None:
            kw["json"] = body
        if raw is not None:
            kw["content"] = raw
            kw["headers"] = {**kw["headers"], "Content-Type": ctype or "application/json"}
        r2 = await rs.request(method, path, **kw)
        CLOCK[0] = frozen_at(r2, freeze) if freeze else None
        try:
            r1 = await py.request(method, path, **kw)
        finally:
            CLOCK[0] = None
        ok = r1.status_code == r2.status_code and r1.content == r2.content
        detail = f"python {r1.status_code} {r1.content[:900]!r}\n        rust   {r2.status_code} {r2.content[:900]!r}"
        if not ok and r1.status_code == r2.status_code:
            detail += "\n        " + first_difference(r1.content, r2.content)
        check(f"{name} [{r1.status_code}]", ok, detail)
        return r1, r2

    # ======================================================================
    print("\n=== A. auth and validation ===")
    d = f"date_from={(T0 - datetime.timedelta(days=7)).isoformat()}&date_to={T0.isoformat()}"
    await same("dashboard: no token", "GET", f"{SO}/dashboard?{d}")
    await same("dashboard: portal token", "GET", f"{SO}/dashboard?{d}", tok["portal"])
    await same("dashboard: missing dates", "GET", f"{SO}/dashboard", tok["admin"])
    await same("dashboard: bad date, bad bucket", "GET", f"{SO}/dashboard?date_from=nope&date_to=2026-13-01&bucket=year", tok["admin"])
    await same("dashboard: reversed period", "GET", f"{SO}/dashboard?date_from=2026-02-01&date_to=2026-01-01", tok["admin"])
    await same("dashboard: too long", "GET", f"{SO}/dashboard?date_from=2025-01-01&date_to=2026-01-03", tok["admin"])
    await same("attention: bad state", "GET", f"{SO}/attention?state=met", tok["admin"])
    await same("attention: bad limit/entity", "GET", f"{SO}/attention?limit=0&entity=x&state=y", tok["admin"])
    await same("attention: limit too large", "GET", f"{SO}/attention?limit=501", tok["admin"])
    await same("item: bad path", "GET", f"{SO}/items/bogus/abc/sla", tok["admin"])
    await same("item: missing", "GET", f"{SO}/items/alert/999999999/sla", tok["admin"])
    await same("item: case missing", "GET", f"{SO}/items/case/999999999/sla", tok["admin"])
    await same("policies: other tenant", "GET", f"{SO}/policies?customer_code={C}", tok["ana_a"])
    await same("calendars: other tenant", "GET", f"{SO}/calendars?customer_code={P}", tok["ana_a"])
    await same("policies put: analyst", "PUT", f"{SO}/policies", tok["analyst"], {"customer_code": P, "cells": []})
    await same("calendars delete: analyst", "DELETE", f"{SO}/calendars/{P}", tok["analyst"])
    await same("policy put: malformed json", "PUT", f"{SO}/policies", None, raw=b'{"cells": [}')
    await same("policy put: no body", "PUT", f"{SO}/policies", tok["admin"])
    await same(
        "policy put: invalid cells",
        "PUT",
        f"{SO}/policies",
        tok["admin"],
        {
            "customer_code": 5,
            "cells": [{"entity": "x", "severity": "y", "ack_minutes": 0, "resolve_minutes": "abc"}, 7],
            "apply_to_open": "maybe",
        },
    )
    await same(
        "policy put: ack longer than resolve",
        "PUT",
        f"{SO}/policies",
        tok["admin"],
        {"customer_code": P, "cells": [{"entity": "case", "severity": "Low", "ack_minutes": 600, "resolve_minutes": 60}]},
    )
    await same(
        "policy put: duplicate cell",
        "PUT",
        f"{SO}/policies",
        tok["admin"],
        {"customer_code": P, "cells": [{"entity": "alert", "severity": "High"}, {"entity": "alert", "severity": "High", "inherit": True}]},
    )
    await same(
        "policy put: too long, fractional",
        "PUT",
        f"{SO}/policies",
        tok["admin"],
        {"cells": [{"entity": "alert", "severity": "High", "ack_minutes": 600000, "resolve_minutes": 1.5}]},
    )
    for label, body in (
        ("timezone", {"customer_code": P, "timezone": "Mars/Base", "week": WEEK_NY}),
        ("quoted timezone", {"customer_code": P, "timezone": "O'Brien", "week": WEEK_NY}),
        ("weekday", {"customer_code": P, "week": {"xyz": [["09:00", "17:00"]]}}),
        ("time", {"customer_code": P, "week": {"mon": [["9", "17:00"]]}}),
        ("hour range", {"customer_code": P, "week": {"mon": [["24:00", "25:00"]]}}),
        ("pair", {"customer_code": P, "week": {"mon": [["09:00"]]}}),
        ("backwards", {"customer_code": P, "week": {"mon": [["17:00", "09:00"]]}}),
        ("overlap", {"customer_code": P, "week": {"mon": [["09:00", "12:00"], ["11:00", "17:00"]]}}),
        ("empty", {"customer_code": P, "week": {}}),
        (
            "types",
            {"customer_code": P, "week": {"mon": "x", "tue": [[9, "17:00"]]}, "holidays": ["2026-13-01", "2026-01-01T00:00:00", 1.5, True]},
        ),
        ("null timezone", {"customer_code": P, "week": WEEK_NY, "timezone": None}),
    ):
        await same(f"calendar put: {label}", "PUT", f"{SO}/calendars", tok["admin"], body)
    await same("calendar delete: bad flag", "DELETE", f"{SO}/calendars/{P}?apply_to_open=maybe", tok["admin"])
    await same("portal settings: unknown customer", "PUT", f"{CP}/settings/NOPE{SFX}", tok["admin"], {"enabled": True})
    await same("portal settings: missing field", "PUT", f"{CP}/settings/{P}", tok["admin"], {})
    await same("portal settings: analyst put", "PUT", f"{CP}/settings/{P}", tok["analyst"], {"enabled": True})
    await same("portal settings: other tenant", "GET", f"{CP}/settings/{C}", tok["ana_a"])
    await same("portal availability: other tenant", "GET", f"{CP}/availability?customer_code={B}", tok["portal"])
    await same("portal overview: missing dates", "GET", f"{CP}/overview", tok["portal"])
    await same("portal overview: invalid period", "GET", f"{CP}/overview?date_from=2026-02-01&date_to=2026-01-01", tok["portal"])
    await same("portal overview: too long", "GET", f"{CP}/overview?date_from=2025-01-01&date_to=2026-06-01", tok["portal"])

    # ======================================================================
    print("\n=== B. dashboard ===")
    periods = {
        "7d": (T0 - datetime.timedelta(days=7), T0),
        "30d": (T0 - datetime.timedelta(days=30), T0 + datetime.timedelta(hours=1)),
        "2d": (T0 - datetime.timedelta(days=2), T0),
        "DST March": (datetime.datetime(2026, 3, 20), datetime.datetime(2026, 4, 10)),
        "100d": (T0 - datetime.timedelta(days=100), T0),
        "200d": (T0 - datetime.timedelta(days=200), T0 + datetime.timedelta(days=1)),
    }
    for label, (start, end) in periods.items():
        q = f"date_from={start.isoformat()}&date_to={end.isoformat()}"
        for who in ("admin", "analyst", "ana_a", "responder", "nobody"):
            await same(f"dashboard {label} ({who})", "GET", f"{SO}/dashboard?{q}", tok[who], freeze="generated_at")
    q7 = f"date_from={periods['7d'][0].isoformat()}&date_to={periods['7d'][1].isoformat()}"
    q30 = f"date_from={periods['30d'][0].isoformat()}&date_to={periods['30d'][1].isoformat()}"
    for label, extra in (
        ("one customer", f"&customer_codes={A}"),
        ("one customer, B", f"&customer_codes={B}"),
        ("two customers", f"&customer_codes={A}&customer_codes={C}"),
        ("bracket form", f"&customer_codes%5B%5D={B}"),
        ("legacy customer_code", f"&customer_code={C}"),
        ("tie customer", f"&customer_codes={D}&customer_codes={C}"),
        ("unknown customer", f"&customer_codes=NOPE{SFX}"),
        ("star", "&customer_codes=*"),
        ("severities", "&severities=High&severities%5B%5D=Critical&severities=High"),
        ("sources", "&sources=wazuh&sources=office365"),
        ("bucket hour", "&bucket=hour"),
        ("bucket month", "&bucket=month"),
        ("bucket week", "&bucket=week"),
    ):
        for who in ("admin", "ana_a"):
            await same(f"dashboard 30d {label} ({who})", "GET", f"{SO}/dashboard?{q30}{extra}", tok[who], freeze="generated_at")
    await same(
        "dashboard: aware dates",
        "GET",
        f"{SO}/dashboard?date_from=2026-03-20T00:00:00%2B02:00&date_to=2026-04-10T12:30:00Z&customer_codes={A}",
        tok["admin"],
        freeze="generated_at",
    )
    await same(
        "dashboard: unix timestamps",
        "GET",
        f"{SO}/dashboard?date_from=1773964800&date_to=1775779200",
        tok["admin"],
        freeze="generated_at",
    )
    await same(
        "dashboard: micro dates",
        "GET",
        f"{SO}/dashboard?date_from=2026-03-20T00:00:00.123456&date_to=2026-04-10T00:00:00.5",
        tok["admin"],
        freeze="generated_at",
    )

    # ======================================================================
    print("\n=== C. sources, attention, items ===")
    for who in ("admin", "analyst", "ana_a", "nobody"):
        await same(f"sources ({who})", "GET", f"{SO}/sources", tok[who])
    await same("sources: customer", "GET", f"{SO}/sources?customer_codes={C}", tok["admin"])
    for label, qs in (
        ("all", ""),
        ("alerts", "?entity=alert"),
        ("cases", "?entity=case"),
        ("breached", "?state=breached"),
        ("at risk", "?state=at_risk"),
        ("limited", "?limit=3"),
        ("customer", f"?customer_codes={A}&severities=High"),
    ):
        for who in ("admin", "ana_a"):
            await same(f"attention {label} ({who})", "GET", f"{SO}/attention{qs}", tok[who], freeze="attention")
    sample = []
    for code in (A, B, P):
        picked = ids["alerts"][code]
        sample += [aid for aid, it in picked if it["status"] == "PENDING_CUSTOMER"][:2]
        sample += [aid for aid, it in picked if not it["tracked"]][:1]
        sample += [aid for aid, it in picked if it["status"] == "CLOSED" and it["paused_seconds"]][:1]
        sample += [aid for aid, it in picked if it["status"] in ("OPEN", "IN_PROGRESS")][:3]
    for aid in sample:
        for who in ("admin", "ana_a"):
            await same(f"item alert {aid} ({who})", "GET", f"{SO}/items/alert/{aid}/sla", tok[who], freeze="generated_at")
    for code in (A, B, P):
        for cid, _ in ids["cases"].get(code, [])[:4]:
            for who in ("admin", "ana_a"):
                await same(f"item case {cid} ({who})", "GET", f"{SO}/items/case/{cid}/sla", tok[who], freeze="generated_at")

    # ======================================================================
    print("\n=== D. policies and calendars (reads) ===")
    for code in (None, A, B, C, P, f"NOPE{SFX}", ""):
        qs = "" if code is None else f"?customer_code={code}"
        await same(f"policies {code!r}", "GET", f"{SO}/policies{qs}", tok["admin"])
        await same(f"calendars {code!r}", "GET", f"{SO}/calendars{qs}", tok["admin"])
    for who in ("admin", "analyst", "ana_a", "nobody"):
        await same(f"policy overrides ({who})", "GET", f"{SO}/policies/overrides", tok[who])
        await same(f"calendars ({who})", "GET", f"{SO}/calendars", tok[who])
    await same("policies A (analyst)", "GET", f"{SO}/policies?customer_code={A}", tok["ana_a"])
    await same("get /policies/{code}: method", "GET", f"{SO}/policies/{A}", tok["admin"])

    # ======================================================================
    print("\n=== E. portal SLA (reads) ===")
    await same("portal settings A", "GET", f"{CP}/settings/{A}", tok["analyst"])
    await same("portal settings C (disabled row)", "GET", f"{CP}/settings/{C}", tok["admin"])
    await same("portal settings B (no row)", "GET", f"{CP}/settings/{B}", tok["admin"])
    await same("portal settings: case-insensitive code", "GET", f"{CP}/settings/{A.lower()}", tok["admin"])
    for who in ("portal", "portal_b", "analyst", "admin", "nobody"):
        await same(f"portal availability ({who})", "GET", f"{CP}/availability", tok[who])
    await same("portal availability: own customer", "GET", f"{CP}/availability?customer_code={A}", tok["portal"])
    await same("portal availability: disabled customer", "GET", f"{CP}/availability?customer_code={C}", tok["portal"])
    await same("portal availability: empty code", "GET", f"{CP}/availability?customer_code=", tok["portal"])
    for label, (start, end) in periods.items():
        q = f"date_from={start.isoformat()}&date_to={end.isoformat()}"
        for who in ("portal", "portal_b", "admin"):
            await same(f"portal overview {label} ({who})", "GET", f"{CP}/overview?{q}", tok[who], freeze="now")
    await same("portal overview: narrowed", "GET", f"{CP}/overview?{q7}&customer_codes={A}", tok["portal"], freeze="now")
    await same("portal overview: narrowed away", "GET", f"{CP}/overview?{q7}&customer_codes={C}", tok["portal"], freeze="now")
    await same("portal overview: bracket form ignored", "GET", f"{CP}/overview?{q7}&customer_codes%5B%5D={C}", tok["portal"], freeze="now")

    await edge_section(same, tok, q7)
    await tag_rbac_section(same, tok, q30, ids)
    await writes_section(py, rs, tok, H, ids)
    await notifier_section(py, rs, tok, H, ids)
    await by_design_section(rs, tok, H)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    await py.aclose()
    await rs.aclose()
    sys.exit(1 if failed else 0)


def first_difference(a: bytes, b: bytes) -> str:
    n = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    return f"first difference at byte {n}: python …{a[max(0, n - 80):n + 80]!r}\n        rust   …{b[max(0, n - 80):n + 80]!r}"


# ==========================================================================
async def edge_section(same, tok, q7):
    print("\n=== J. edge cases: failed writes, Python's date range, unreadable stored rows ===")
    one = [{"entity": "alert", "severity": "High", "ack_minutes": 30, "resolve_minutes": 300}]
    nope = f"NOPE{SFX}"
    # No such customer: the foreign key refuses the row inside the route's try block.
    await same(
        "policy put: unknown customer",
        "PUT",
        f"{SO}/policies",
        tok["admin"],
        {"customer_code": nope, "cells": one, "apply_to_open": True},
    )
    await same(
        "policy put: unknown customer, every cell inherits",
        "PUT",
        f"{SO}/policies",
        tok["admin"],
        {"customer_code": nope, "cells": [{"entity": "alert", "severity": "High", "inherit": True}]},
    )
    await same("calendar put: unknown customer", "PUT", f"{SO}/calendars", tok["admin"], {"customer_code": nope, "week": WEEK_NY})
    await same("policy delete: unknown customer", "DELETE", f"{SO}/policies/{nope}?apply_to_open=true", tok["admin"])
    await same("calendar delete: unknown customer", "DELETE", f"{SO}/calendars/{nope}", tok["admin"])
    # GET /policies/overrides is a route, DELETE of the same path removes customer "overrides".
    await same("policy delete: the literal 'overrides'", "DELETE", f"{SO}/policies/overrides", tok["admin"])
    # Past Python's datetime range: `datetime - timedelta` raises OverflowError (a bare 500),
    # a monthly bucket past 9999 `replace(year=10000)`, a ValueError (the 400 with its text).
    for label, qs in (
        ("before year 1", "date_from=0001-01-01&date_to=0001-02-01"),
        ("month bucket past 9999", "date_from=9999-11-15&date_to=9999-12-31&bucket=month"),
        ("auto month bucket past 9999", "date_from=9999-01-15&date_to=9999-12-31"),
    ):
        await same(f"dashboard: {label}", "GET", f"{SO}/dashboard?{qs}", tok["admin"])
        await same(f"portal overview: {label}", "GET", f"{CP}/overview?{qs}", tok["portal"])
    # Stored rows the API never writes (manual SQL): read with Python's semantics, a ValueError
    # answered with its text, a TypeError as a bare 500 — and a write that has to read them fails
    # inside its try block.
    d_alert = (await rows("SELECT id FROM incident_management_alert WHERE customer_code = :c ORDER BY id LIMIT 1", c=D))[0][0]
    for label, tz, week, holidays in (
        ("week is a string", "UTC", '"ab"', "[]"),
        ("week holds a number", "UTC", "[5]", "[]"),
        ("week as pairs", "UTC", '[["mon", [["08:00", "16:00"]]], ["fri", [["\u0660\u0669:00", "12:00"]]]]', '[20261225, "2026-W53-5"]'),
        ("week is null", "UTC", "null", "[]"),
        ("weekday", "UTC", '{"mon": [["09:00", "17:00"]], "xyz": []}', "[]"),
        ("time", "UTC", '{"mon": [["9", "17:00"]]}', "[]"),
        ("number time", "UTC", '{"mon": [[9, 17]]}', "[]"),
        ("short window", "UTC", '{"mon": ["ab", "09:00"]}', "[]"),
        ("holiday", "UTC", '{"mon": [["09:00", "17:00"]]}', '["2026-02-30"]'),
        ("holiday year 10000", "UTC", '{"mon": [["09:00", "17:00"]]}', '["9999-W52-7"]'),
        ("timezone", "Mars/Base", '{"mon": [["09:00", "17:00"]]}', "[]"),
        ("holidays is a string", "UTC", '{"mon": [["09:00", "17:00"]]}', '"0"'),
        ("empty timezone", "", '{"mon": [["09:00", "17:00"]]}', "[]"),
    ):
        await sql(
            "INSERT INTO soc_sla_calendar (customer_code, timezone, week, holidays, updated_at, updated_by) VALUES (:c, :tz, :w, :h, UTC_TIMESTAMP(), 'sql')",
            c=D,
            tz=tz,
            w=week,
            h=holidays,
        )
        try:
            await same(f"stored calendar, {label}: read", "GET", f"{SO}/calendars?customer_code={D}", tok["admin"])
            await same(
                f"stored calendar, {label}: dashboard",
                "GET",
                f"{SO}/dashboard?{q7}&customer_codes={D}",
                tok["admin"],
                freeze="generated_at",
            )
            await same(f"stored calendar, {label}: item", "GET", f"{SO}/items/alert/{d_alert}/sla", tok["admin"], freeze="generated_at")
            await same(
                f"stored calendar, {label}: policy put re-targets",
                "PUT",
                f"{SO}/policies",
                tok["admin"],
                {"customer_code": D, "cells": [{"entity": "alert", "severity": "Low", "inherit": True}], "apply_to_open": True},
            )
        finally:
            await sql("DELETE FROM soc_sla_calendar WHERE customer_code = :c", c=D)
    for entity in ("bogus", "it's"):
        await sql(
            "INSERT INTO soc_sla_policy (customer_code, entity_type, severity, ack_minutes, resolve_minutes, business_hours, updated_at, updated_by) "
            "VALUES (:c, :e, 'Low', 10, 20, 0, UTC_TIMESTAMP(), 'sql')",
            c=D,
            e=entity,
        )
        try:
            await same(f"stored policy entity {entity!r}: read", "GET", f"{SO}/policies?customer_code={D}", tok["admin"])
            await same(
                f"stored policy entity {entity!r}: dashboard",
                "GET",
                f"{SO}/dashboard?{q7}&customer_codes={D}",
                tok["admin"],
                freeze="generated_at",
            )
            await same(f"stored policy entity {entity!r}: overrides", "GET", f"{SO}/policies/overrides", tok["admin"])
        finally:
            await sql("DELETE FROM soc_sla_policy WHERE customer_code = :c", c=D)


async def by_design_section(rs, tok, H):
    print("\n=== K. differences by design ===")
    # Timezone names: Rust reads the IANA database compiled into chrono-tz (every canonical and
    # backward name, nothing else); Python reads the host's zoneinfo files (or the tzdata
    # package), so what it accepts depends on the host — this one, for instance, has no
    # backward names but serves its `localtime` link. Only the Rust side is asserted.
    for tz, status, message in (
        ("US/Eastern", 200, None),
        ("Asia/Calcutta", 200, None),
        ("localtime", 422, "Unknown timezone 'localtime'"),
        ("posixrules", 422, "Unknown timezone 'posixrules'"),
    ):
        r = await rs.put(f"{SO}/calendars", json={"customer_code": R, "timezone": tz, "week": WEEK_NY}, headers=H(tok["admin"]))
        body = r.json()
        ok = r.status_code == status and (body["calendar"]["timezone"] == tz if status == 200 else body["message"] == message)
        check(f"DIFF_BY_DESIGN calendar timezone {tz!r}: Rust answers {status}", ok, f"rust {r.status_code} {r.content[:400]!r}")
    await rs.delete(f"{SO}/calendars/{R}", headers=H(tok["admin"]))


async def tag_rbac_section(same, tok, q30, ids):
    print("\n=== F. tag RBAC ===")
    if (await rows("SELECT COUNT(*) FROM incident_management_tag_access_settings"))[0][0]:
        print("  SKIP  tag RBAC: incident_management_tag_access_settings already configured")
        return
    t1 = ids["tags"]["t1"]
    await sql("INSERT INTO user_tag_access (user_id, tag_id, created_at) VALUES (:u, :t, UTC_TIMESTAMP())", u=ids["users"][TAGGED], t=t1)
    settings_id = (
        await sql(
            "INSERT INTO incident_management_tag_access_settings (enabled, untagged_alert_behavior, updated_at) "
            "VALUES (1, 'admin_only', UTC_TIMESTAMP())",
        )
    ).lastrowid
    try:
        for behavior in ("admin_only", "visible_to_all", "default_tag"):
            await sql(
                "UPDATE incident_management_tag_access_settings SET untagged_alert_behavior = :b, default_tag_id = :t WHERE id = :i",
                b=behavior,
                t=t1 if behavior == "default_tag" else None,
                i=settings_id,
            )
            await same(f"dashboard 30d tagged ({behavior})", "GET", f"{SO}/dashboard?{q30}", tok["tagged"], freeze="generated_at")
            await same(f"sources tagged ({behavior})", "GET", f"{SO}/sources", tok["tagged"])
            await same(f"attention tagged ({behavior})", "GET", f"{SO}/attention", tok["tagged"], freeze="attention")
            await same(f"portal overview with tag RBAC ({behavior})", "GET", f"{CP}/overview?{q30}", tok["portal"], freeze="now")
            untagged = [aid for aid, it in ids["alerts"][A] if not it["tag"]][:1]
            t2 = [aid for aid, it in ids["alerts"][A] if it["tag"] == "t2"][:1]
            for aid in untagged + t2:
                await same(f"item {aid} tagged ({behavior})", "GET", f"{SO}/items/alert/{aid}/sla", tok["tagged"], freeze="generated_at")
    finally:
        await sql("DELETE FROM incident_management_tag_access_settings WHERE id = :i", i=settings_id)
        await sql("DELETE FROM user_tag_access WHERE tag_id = :t", t=t1)


# ==========================================================================
def sub(value, old, new):
    return json.loads(json.dumps(value).replace(old, new))


TRACKING_COLS = "t.severity, t.opened_at, t.ack_due_at, t.resolve_due_at, t.business_hours, t.pause_credit_seconds"


async def tracking_of(code):
    alerts = await rows(
        f"SELECT {TRACKING_COLS} FROM soc_sla_alert_tracking t JOIN incident_management_alert a ON a.id = t.alert_id "
        "WHERE a.customer_code = :c ORDER BY t.alert_id",
        c=code,
    )
    cases = await rows(
        f"SELECT {TRACKING_COLS} FROM soc_sla_case_tracking t JOIN incident_management_case a ON a.id = t.case_id "
        "WHERE a.customer_code = :c ORDER BY t.case_id",
        c=code,
    )
    return alerts + cases


async def writes_section(py, rs, tok, H, ids):
    print("\n=== G. writes on twin customers (P: Python, R: Rust) ===")

    async def twin(name, method, path_of, body_of=None, t=None):
        t = t or tok["admin"]
        out = {}
        for code, client in ((P, py), (R, rs)):
            kw = {"headers": H(t)}
            if body_of is not None:
                kw["json"] = body_of(code)
            out[code] = await client.request(method, path_of(code), **kw)

        def norm(raw, own):
            text_ = raw.decode()
            try:
                data = json.loads(text_)
            except ValueError:
                return text_
            if isinstance(data, dict) and isinstance(data.get("customers_with_calendar"), list):
                # The twin written second is listed only in the second answer: compare the rest.
                data["customers_with_calendar"] = [c for c in data["customers_with_calendar"] if c not in (P, R)]
                text_ = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            text_ = re.sub(r'"updated_at":"[^"]*"', '"updated_at":"<v>"', text_)
            return text_.replace(own, "<twin>")

        b1, b2 = norm(out[P].content, P), norm(out[R].content, R)
        ok = out[P].status_code == out[R].status_code and b1 == b2
        check(f"{name} [{out[P].status_code}]", ok, f"python {b1[:900]}\n        rust   {b2[:900]}")
        return out

    def same_rows(name, a, b):
        check(name, a == b, f"python {a[:6]}\n        rust   {b[:6]}")

    cells = [
        {"entity": "alert", "severity": "High", "ack_minutes": 20, "resolve_minutes": 180, "business_hours": True},
        {"entity": "alert", "severity": "Medium", "inherit": True},
        {"entity": "alert", "severity": "Low", "ack_minutes": None, "resolve_minutes": 2880},
        {"entity": "case", "severity": "Critical", "ack_minutes": 15, "resolve_minutes": 240, "business_hours": False},
        {"entity": "case", "severity": "High", "ack_minutes": "45", "resolve_minutes": 960.0, "business_hours": "yes"},
    ]
    await twin(
        "policy put (customer, apply)",
        "PUT",
        lambda c: f"{SO}/policies",
        lambda c: {"customer_code": c, "cells": cells, "apply_to_open": True},
    )
    same_rows("policy put: re-targeted rows", await tracking_of(P), await tracking_of(R))
    pol = "SELECT entity_type, severity, ack_minutes, resolve_minutes, business_hours, updated_by FROM soc_sla_policy WHERE customer_code = :c ORDER BY id"
    same_rows("policy put: stored cells", await rows(pol, c=P), await rows(pol, c=R))
    await twin("policies read back", "GET", lambda c: f"{SO}/policies?customer_code={c}")
    await asyncio.sleep(1.1)
    await twin("policy put (customer, no apply)", "PUT", lambda c: f"{SO}/policies", lambda c: {"customer_code": c, "cells": cells[:2]})
    same_rows("policy put (no apply): rows untouched", await tracking_of(P), await tracking_of(R))
    r1 = await py.get(f"{SO}/policies/overrides", headers=H(tok["admin"]))
    r2 = await rs.get(f"{SO}/policies/overrides", headers=H(tok["admin"]))
    check(
        "policy overrides after writes",
        (r1.status_code, r1.content) == (r2.status_code, r2.content),
        f"{r1.content[:600]!r}\n        {r2.content[:600]!r}",
    )
    await twin("policy delete (apply)", "DELETE", lambda c: f"{SO}/policies/{c}?apply_to_open=true")
    same_rows("policy delete: re-targeted rows", await tracking_of(P), await tracking_of(R))
    await twin("policy delete again (nothing left)", "DELETE", lambda c: f"{SO}/policies/{c}?apply_to_open=1")
    cal = {
        "timezone": "Europe/Berlin",
        "week": {"fri": [["13:00", "17:30"], ["08:00", "12:00"]], "mon": [["08:00", "16:00"]], "sat": []},
        "holidays": ["2026-12-25", "2026-10-26", "2026-12-25T00:00:00"],
        "apply_to_open": True,
    }
    await twin("policy put (bh cells for the calendar)", "PUT", lambda c: f"{SO}/policies", lambda c: {"customer_code": c, "cells": cells})
    await twin("calendar put (apply)", "PUT", lambda c: f"{SO}/calendars", lambda c: {**cal, "customer_code": c})
    same_rows("calendar put: re-targeted rows", await tracking_of(P), await tracking_of(R))
    cq = "SELECT timezone, week, holidays, updated_by FROM soc_sla_calendar WHERE customer_code = :c"
    same_rows("calendar put: stored", await rows(cq, c=P), await rows(cq, c=R))
    await twin("calendar read back", "GET", lambda c: f"{SO}/calendars?customer_code={c}")
    await twin("calendar delete (apply)", "DELETE", lambda c: f"{SO}/calendars/{c}?apply_to_open=true")
    same_rows("calendar delete: re-targeted rows (default calendar)", await tracking_of(P), await tracking_of(R))
    await twin("calendar delete again", "DELETE", lambda c: f"{SO}/calendars/{c}")
    await twin("portal settings put (new row)", "PUT", lambda c: f"{CP}/settings/{c}", lambda c: {"enabled": True})
    await twin("portal settings put (update)", "PUT", lambda c: f"{CP}/settings/{c}", lambda c: {"enabled": "false"})
    await twin("portal settings read", "GET", lambda c: f"{CP}/settings/{c}")
    sq = "SELECT enabled, updated_by FROM customer_portal_sla_settings WHERE customer_code = :c"
    same_rows("portal settings: stored", await rows(sq, c=P), await rows(sq, c=R))

    # --- global writes: Python, restore, Rust; compare what each leaves ----------
    print("\n=== H. global policy and calendar writes (database restored in between) ===")
    open_alerts = (
        "SELECT alert_id, ack_due_at, resolve_due_at, business_hours FROM soc_sla_alert_tracking "
        "WHERE tracked IS true AND resolved_at IS NULL ORDER BY alert_id"
    )
    open_cases = (
        "SELECT case_id, ack_due_at, resolve_due_at, business_hours FROM soc_sla_case_tracking "
        "WHERE tracked IS true AND resolved_at IS NULL ORDER BY case_id"
    )
    global_pol = "SELECT customer_code, entity_type, severity, ack_minutes, resolve_minutes, business_hours, updated_at, updated_by FROM soc_sla_policy WHERE customer_code IS NULL ORDER BY id"
    global_cal = "SELECT customer_code, timezone, week, holidays, updated_at, updated_by FROM soc_sla_calendar WHERE customer_code IS NULL ORDER BY id"
    before = {
        "alerts": await rows(open_alerts),
        "cases": await rows(open_cases),
        "pol": await rows(global_pol),
        "cal": await rows(global_cal),
    }

    async def restore():
        for table, key, snap in (
            ("soc_sla_alert_tracking", "alert_id", before["alerts"]),
            ("soc_sla_case_tracking", "case_id", before["cases"]),
        ):
            async with AsyncSession(async_engine) as s:
                for row in snap:
                    await s.execute(
                        text(f"UPDATE {table} SET ack_due_at = :a, resolve_due_at = :r, business_hours = :b WHERE {key} = :k"),
                        {"a": row[1], "r": row[2], "b": row[3], "k": row[0]},
                    )
                await s.commit()
        await sql("DELETE FROM soc_sla_policy WHERE customer_code IS NULL")
        for row in before["pol"]:
            await sql(
                "INSERT INTO soc_sla_policy (customer_code, entity_type, severity, ack_minutes, resolve_minutes, business_hours, updated_at, "
                "updated_by) VALUES (NULL, :e, :s, :a, :r, :b, :u, :by)",
                e=row[1],
                s=row[2],
                a=row[3],
                r=row[4],
                b=row[5],
                u=row[6],
                by=row[7],
            )
        await sql("DELETE FROM soc_sla_calendar WHERE customer_code IS NULL")
        for row in before["cal"]:
            await sql(
                "INSERT INTO soc_sla_calendar (customer_code, timezone, week, holidays, updated_at, updated_by) VALUES (NULL, :tz, :w, :h, :u, :by)",
                tz=row[1],
                w=row[2],
                h=row[3],
                u=row[4],
                by=row[5],
            )

    global_cells = [
        {"entity": "alert", "severity": "Critical", "ack_minutes": 10, "resolve_minutes": 200, "business_hours": True},
        {"entity": "alert", "severity": "Medium", "ack_minutes": 300, "resolve_minutes": 1500},
        {"entity": "case", "severity": "Low", "inherit": True},
    ]
    global_calendar = {
        "timezone": "Asia/Kolkata",
        "week": {"mon": [["10:00", "18:00"]], "wed": [["10:00", "18:00"]]},
        "apply_to_open": True,
    }
    steps = [
        ("global policy put (apply)", "PUT", f"{SO}/policies", {"customer_code": None, "cells": global_cells, "apply_to_open": True}),
        ("global calendar put (apply)", "PUT", f"{SO}/calendars", global_calendar),
    ]
    try:
        for name, method, path, body in steps:
            answers, states = {}, {}
            for tag, client in (("py", py), ("rs", rs)):
                await restore()
                answers[tag] = await client.request(method, path, json=body, headers=H(tok["admin"]))
                states[tag] = (
                    await rows(open_alerts),
                    await rows(open_cases),
                    [r[:6] + (r[7],) for r in await rows(global_pol)],
                    [r[:4] + (r[5],) for r in await rows(global_cal)],
                )
            ok = answers["py"].status_code == answers["rs"].status_code and answers["py"].content == answers["rs"].content
            check(
                f"{name} [{answers['py'].status_code}]",
                ok,
                f"python {answers['py'].content[:900]!r}\n        rust   {answers['rs'].content[:900]!r}",
            )
            for i, label in enumerate(("open alerts", "open cases", "global policy", "global calendar")):
                diff = [(a, b) for a, b in zip(states["py"][i], states["rs"][i]) if a != b]
                check(
                    f"{name}: {label} rows",
                    states["py"][i] == states["rs"][i],
                    f"{len(states['py'][i])} vs {len(states['rs'][i])} rows; first differences {diff[:3]}",
                )
    finally:
        await restore()


# ==========================================================================
CAPTURED = []


class _Recorder(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        CAPTURED.append({"path": self.path, "body": self.rfile.read(length) if length else b""})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def start_recorder():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_rust_with_job(port):
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        "COPILOT_PORT": str(port),
        "COPILOT_URL": os.environ.get("COPILOT_URL", "https://copilot.parity.test/"),
        "COPILOT_RS_JOBS": "notify_sla_transitions",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the second Rust binary did not start")


def in_list(values):
    return "(" + ", ".join(f"'{v}'" if isinstance(v, str) else str(int(v)) for v in values) + ")"


STAMPS = "ack_at_risk_notified_at, ack_breached_notified_at, resolve_at_risk_notified_at, resolve_breached_notified_at"


async def notifier_section(py, rs, tok, H, ids):
    print("\n=== I. notify_sla_transitions (Python pass, then the Rust job) ===")
    from app.notifications.services import emit as emit_module
    from app.soc_management.services.notifier import SlaNotifier

    mine = (A, B, C, D, P, R)
    # Foreign rows owe nothing during this section: their NULL stamps are set to a sentinel and
    # restored afterwards, so only this suite's clocks (placed away from every boundary) count.
    sentinel = "1970-01-02 00:00:00"
    neutralised = {}
    for table, key, owner in (
        ("soc_sla_alert_tracking", "alert_id", "incident_management_alert"),
        ("soc_sla_case_tracking", "case_id", "incident_management_case"),
    ):
        neutralised[table] = await rows(
            f"SELECT t.{key}, {STAMPS} FROM {table} t JOIN {owner} o ON o.id = t.{key} "
            f"WHERE o.customer_code IS NULL OR o.customer_code NOT IN {in_list(mine)}",
        )
        for col in STAMPS.split(", "):
            await sql(
                f"UPDATE {table} t JOIN {owner} o ON o.id = t.{key} SET t.{col} = :s "
                f"WHERE t.{col} IS NULL AND (o.customer_code IS NULL OR o.customer_code NOT IN {in_list(mine)})",
                s=sentinel,
            )
    stub = start_recorder()
    routes = []
    for trigger in ("sla_at_risk", "sla_breached"):
        r = await rs.post(
            "/api/internal_notification_routes",
            json={
                "name": f"SLA {trigger} {SFX}",
                "trigger": trigger,
                "channel": "webhook",
                "scope": "internal",
                "min_severity": "Informational",
                "config": {"url": f"{stub}/hook/{trigger}"},
            },
            headers=H(tok["admin"]),
        )
        check(f"internal route {trigger} created [{r.status_code}]", r.status_code == 200, r.text)
        routes.append(r.json()["route"]["id"])
    my_rows = (
        f"SELECT t.alert_id, {STAMPS} FROM soc_sla_alert_tracking t JOIN incident_management_alert o ON o.id = t.alert_id "
        f"WHERE o.customer_code IN {in_list(mine)} ORDER BY t.alert_id"
    )
    my_case_rows = (
        f"SELECT t.case_id, {STAMPS} FROM soc_sla_case_tracking t JOIN incident_management_case o ON o.id = t.case_id "
        f"WHERE o.customer_code IN {in_list(mine)} ORDER BY t.case_id"
    )

    def log_q():
        return (
            "SELECT customer_code, alert_id, route_id, `trigger`, status, entity_type, entity_id, dedupe_key, triggered_by, "
            "trigger_source, payload_preview, error_message, provider_reference FROM notification_dispatch_log "
            f"WHERE route_id IN {in_list(routes)} ORDER BY route_id, dedupe_key"
        )

    async def reset_stamps():
        for table, key in (("soc_sla_alert_tracking", "alert_id"), ("soc_sla_case_tracking", "case_id")):
            owner = "incident_management_alert" if key == "alert_id" else "incident_management_case"
            await sql(
                f"UPDATE {table} t JOIN {owner} o ON o.id = t.{key} SET "
                + ", ".join(f"t.{c} = NULL" for c in STAMPS.split(", "))
                + f" WHERE o.customer_code IN {in_list(mine)}",
            )
        await sql(f"DELETE FROM notification_dispatch_log WHERE route_id IN {in_list(routes)}")

    meta = await rows("SELECT id, enabled, last_success FROM scheduled_job_metadata WHERE job_id = 'notify_sla_transitions' ORDER BY id")
    created_meta = not meta
    if created_meta:
        await sql(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, enabled, job_description) "
            "VALUES ('notify_sla_transitions', NULL, 2, 1, 'SLA notices (parity)')",
        )
        meta = await rows(
            "SELECT id, enabled, last_success FROM scheduled_job_metadata WHERE job_id = 'notify_sla_transitions' ORDER BY id",
        )
    meta_id = meta[0][0]

    async def settled():
        """Wait until the deliveries stop arriving (both sides dispatch on tasks of their own)."""
        seen, quiet = -1, 0
        while quiet < 8:
            await asyncio.sleep(0.25)
            quiet = quiet + 1 if len(CAPTURED) == seen else 0
            seen = len(CAPTURED)

    # The Rust run is a real scheduled tick: the job handed over (row disabled, opt-in set), its
    # first tick one interval after `last_success`. Owed clocks are due on whole minutes, so the
    # tick is placed a few seconds past a minute: "N min left/overdue" cannot sit on a rounding
    # edge between the Rust tick and the Python pass (frozen at the instant the tick stamped).
    wall = datetime.datetime.utcnow()
    target = wall.replace(second=4, microsecond=0) + datetime.timedelta(minutes=1 if wall.second < 45 else 2)
    last = target - datetime.timedelta(minutes=2)
    await sql(
        "UPDATE scheduled_job_metadata SET enabled = 0, time_interval = 2, last_success = :l WHERE id = :i",
        l=last,
        i=meta_id,
    )
    proc = start_rust_with_job(free_port())
    try:
        CAPTURED.clear()
        ran = False
        for _ in range(900):
            await asyncio.sleep(0.2)
            stamp_now = (await rows("SELECT last_success FROM scheduled_job_metadata WHERE id = :i", i=meta_id))[0][0]
            if stamp_now and stamp_now > last:
                ran = True
                break
        # Back to APScheduler's side (not running here): the binary's next ticks skip.
        await sql("UPDATE scheduled_job_metadata SET enabled = 1 WHERE id = :i", i=meta_id)
        check("Rust tick ran and stamped last_success", ran, f"last_success {stamp_now}")
        await settled()
        rust_captured = list(CAPTURED)
        rust_stamps = await rows(my_rows) + await rows(my_case_rows)
        rust_log = await rows(log_q())
        stamped = [v for row in rust_stamps for v in row[1:] if v is not None]
        now = max(stamped) if stamped else datetime.datetime.utcnow().replace(microsecond=0)
        check(
            "Rust pass stamped and sent something",
            bool(stamped) and bool(rust_captured),
            f"{len(stamped)} stamps, {len(rust_captured)} deliveries",
        )

        await reset_stamps()
        CAPTURED.clear()
        counts = await SlaNotifier(clock=lambda: now).run()
        await asyncio.gather(*list(emit_module._IN_FLIGHT), return_exceptions=True)
        await settled()
        py_captured = list(CAPTURED)
        py_stamps = await rows(my_rows) + await rows(my_case_rows)
        py_log = await rows(log_q())
        print(f"        python pass: {counts}")
        check(
            "notifier: stamps",
            py_stamps == rust_stamps,
            f"{[r for r in py_stamps if r not in rust_stamps][:4]} / {[r for r in rust_stamps if r not in py_stamps][:4]}",
        )
        key = lambda c: (c["path"], c["body"])  # noqa: E731
        check(
            f"notifier: deliveries ({len(py_captured)})",
            sorted(map(key, py_captured)) == sorted(map(key, rust_captured)),
            f"python {sorted(map(key, py_captured))[:2]}\n        rust   {sorted(map(key, rust_captured))[:2]}",
        )
        check("notifier: dispatch log", py_log == rust_log, f"{py_log[:3]} / {rust_log[:3]}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if created_meta:
            await sql("DELETE FROM scheduled_job_metadata WHERE id = :i", i=meta_id)
        else:
            await sql(
                "UPDATE scheduled_job_metadata SET enabled = :e, last_success = :l WHERE id = :i",
                e=meta[0][1],
                l=meta[0][2],
                i=meta_id,
            )
        for route in routes:
            await rs.delete(f"/api/internal_notification_routes/{route}", headers=H(tok["admin"]))
        for table, snap in neutralised.items():
            key = "alert_id" if "alert" in table else "case_id"
            async with AsyncSession(async_engine) as s:
                for row in snap:
                    await s.execute(
                        text(
                            f"UPDATE {table} SET ack_at_risk_notified_at = :a, ack_breached_notified_at = :b, "
                            f"resolve_at_risk_notified_at = :c, resolve_breached_notified_at = :d WHERE {key} = :k",
                        ),
                        {"a": row[1], "b": row[2], "c": row[3], "d": row[4], "k": row[0]},
                    )
                await s.commit()


if __name__ == "__main__":
    asyncio.run(main())
