"""Parity of the Rust incidents module with this backend — NOT collected by pytest (needs a live
MySQL and a running Rust binary).

Sends the same requests to the real FastAPI incidents routers (in-process) and to the Rust
service over HTTP, on one disposable database, and compares status codes and JSON bodies. Reads
must be equal byte for byte; writes are compared with ids and timestamps masked, and the rows they
leave behind are compared too. Deliberate differences are asserted as such (DIFF_BY_DESIGN) and
listed in docs/architecture/RUST_MIGRATION.md §4.

    scripts/rust-parity.sh                       # every suite
    PARITY_SUITES=tests/e2e/rust_parity_incidents_e2e.py scripts/rust-parity.sh
"""

import asyncio
import datetime
import json
import re
import sys
import uuid

import httpx  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from rust_parity_e2e import RUST  # noqa: E402  (sets the environment defaults first)
from rust_parity_e2e import check
from rust_parity_e2e import mask
from rust_parity_e2e import results
from rust_parity_e2e import token
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.db.db_session import async_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"INC_A{SFX}", f"INC_B{SFX}"
# Twins for the settings writes: Python writes P's rows, Rust R's.
CUST_P, CUST_R = f"INC_P{SFX}", f"INC_R{SFX}"
ADMIN, ANALYST, PORTAL = f"inc_admin{SFX}", f"inc_analyst{SFX}", f"inc_portal{SFX}"
NOBODY, TAGGED, RESPONDER = f"inc_nobody{SFX}", f"inc_tagged{SFX}", f"inc_resp{SFX}"
# Twin users for the tag-access writes.
USER_P, USER_R = f"inc_tp{SFX}", f"inc_tr{SFX}"
SOURCE = f"src{SFX}"
P = "/api/incidents/db_operations"


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import incidents

    api = APIRouter(prefix="/api")
    api.include_router(incidents.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


async def seed():
    """Two customers, six users, alerts with every relationship, cases, tasks, events, files."""
    ids = {}
    async with AsyncSession(async_engine) as s:

        async def ins(sql, **params):
            return (await s.execute(text(sql), params)).lastrowid

        for c in (CUST_A, CUST_B, CUST_P, CUST_R):
            await ins("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())", c=c)
        for c in (CUST_A, CUST_B):
            await ins("INSERT INTO custom_alert_creation_settings (customer_code, customer_name) VALUES (:c, :c)", c=c)
        # Case templates: a customer+source default with a mandatory task, and a field-match one (its raw
        # event cannot be fetched here, so both backends fall back to the tier picker).
        for name, cust, src, default, field, created in (
            (f"tmpl-cs-{SFX}", CUST_A, SOURCE, 1, None, "2026-01-02 00:00:00"),
            (f"tmpl-c-{SFX}", CUST_A, None, 0, None, "2026-01-01 00:00:00"),
            (f"tmpl-fm-{SFX}", CUST_A, SOURCE, 0, "data_win_system_eventID", "2026-01-03 00:00:00"),
            (f"tmpl-b-{SFX}", CUST_B, None, 0, None, "2026-01-04 00:00:00"),
        ):
            ids[name] = await ins(
                "INSERT INTO incident_management_case_template (name, customer_code, source, is_default, match_field, match_value, "
                "created_by, created_at, updated_at) VALUES (:n, :c, :s, :d, :f, IF(:f IS NULL, NULL, '1'), 'seed', :t, :t)",
                n=name,
                c=cust,
                s=src,
                d=default,
                f=field,
                t=created,
            )
            for title, mandatory, order in (("Triage", 1, 1), ("Contain", 0, 0)):
                await ins(
                    "INSERT INTO incident_management_case_template_task (template_id, title, description, guidelines, mandatory, "
                    "order_index) VALUES (:t, :ti, 'd', 'g', :m, :o)",
                    t=ids[name],
                    ti=f"{title} ({name})",
                    m=mandatory,
                    o=order,
                )
        # SLA: customer A's High alerts and High/Critical cases run on business hours of its own calendar.
        for entity, severity, ack, resolve in (("alert", "High", 45, 300), ("case", "High", 60, 1440), ("case", "Critical", 30, 600)):
            await ins(
                "INSERT INTO soc_sla_policy (customer_code, entity_type, severity, ack_minutes, resolve_minutes, updated_at, "
                "business_hours) VALUES (:c, :e, :s, :a, :r, UTC_TIMESTAMP(), 1)",
                c=CUST_A,
                e=entity,
                s=severity,
                a=ack,
                r=resolve,
            )
        await ins(
            "INSERT INTO soc_sla_calendar (customer_code, timezone, week, holidays, updated_at) VALUES (:c, 'Europe/Rome', :w, '[]', "
            "UTC_TIMESTAMP())",
            c=CUST_A,
            w=json.dumps({d: [["08:00", "12:00"], ["13:00", "18:00"]] for d in ("mon", "tue", "wed", "thu", "fri")}),
        )
        for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (NOBODY, 2), (TAGGED, 2), (RESPONDER, 5), (USER_P, 2), (USER_R, 2)):
            ids[name] = await ins(
                "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'i@example.com', UTC_TIMESTAMP(), :r)",
                n=name,
                r=role,
            )
        for name in (ANALYST, PORTAL, TAGGED, RESPONDER):
            await ins(
                "INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (:u, :c, UTC_TIMESTAMP())",
                u=ids[name],
                c=CUST_A,
            )

        async def alert(name, cust, status, source, when, **kw):
            return await ins(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, customer_code, "
                "source, escalated, assigned_to, time_closed, severity, verdict, verdict_reason, verdict_note, verdict_by, verdict_at) "
                "VALUES (:n, 'desc', :s, :t, :c, :src, :e, :a, :tc, :sev, :v, :vr, :vn, :vb, :va)",
                n=name,
                s=status,
                t=when,
                c=cust,
                src=source,
                e=kw.get("escalated", 0),
                a=kw.get("assigned_to"),
                tc=kw.get("time_closed"),
                sev=kw.get("severity"),
                v=kw.get("verdict"),
                vr=kw.get("verdict_reason"),
                vn=kw.get("verdict_note"),
                vb=kw.get("verdict_by"),
                va=kw.get("verdict_at"),
            )

        ids["a1"] = await alert(
            f"Mimikatz {SFX}",
            CUST_A,
            "OPEN",
            SOURCE,
            "2026-03-01 10:00:00",
            assigned_to=ANALYST,
            severity="High",
            verdict="FALSE_POSITIVE",
            verdict_reason="EXPECTED_ACTIVITY",
            verdict_note="admin tool",
            verdict_by=ANALYST,
            verdict_at="2026-03-01 11:00:00",
        )
        ids["a2"] = await alert(
            f"Phish {SFX}",
            CUST_A,
            "IN_PROGRESS",
            "sublime",
            "2026-03-02 10:00:00",
            verdict="TRUE_POSITIVE",
            verdict_by=ANALYST,
            verdict_at="2026-03-02 11:00:00",
        )
        ids["a3"] = await alert(f"Old {SFX}", CUST_A, "CLOSED", SOURCE, "2026-02-01 10:00:00", time_closed="2026-02-02 10:00:00")
        ids["a4"] = await alert(f"Waiting {SFX}", CUST_A, "PENDING_CUSTOMER", SOURCE, "2026-03-03 10:00:00", escalated=1)
        ids["b1"] = await alert(f"Mimikatz {SFX}", CUST_B, "OPEN", SOURCE, "2026-03-01 12:00:00", assigned_to=ANALYST)
        ids["b2"] = await alert(f"Closed B {SFX}", CUST_B, "CLOSED", "sublime", "2026-01-15 10:00:00", verdict="FALSE_POSITIVE")

        ctx = {}
        for key, cust in (("a1", CUST_A), ("b1", CUST_B)):
            ctx[key] = await ins(
                "INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', :j)",
                j=json.dumps({"rule_level": 12, "agent_name": f"host-{key}", "nested": {"z": 1, "a": [1, 2]}}),
            )
        ids["ctx_a1"], ids["ctx_b1"] = ctx["a1"], ctx["b1"]
        for key, name, cust in (
            ("a1", "dc01", CUST_A),
            ("a1", "web-01", CUST_A),
            ("a2", "web-01", CUST_A),
            ("a3", "dc01", CUST_A),
            ("a3", "dc01", CUST_A),
            ("b1", "dc01", CUST_B),
        ):
            await ins(
                "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, customer_code, index_name, index_id, "
                "agent_id) VALUES (:a, :n, :ctx, :c, 'wazuh-alerts-1', :doc, '007')",
                a=ids[key],
                n=f"{name}-{SFX}",
                ctx=ctx.get(key, ctx["a1"]),
                c=cust,
                doc=f"doc-{key}",
            )
        for key, text_, user in (
            ("a1", "first look", ANALYST),
            ("a1", "escalating", ADMIN),
            ("b1", "b note", ADMIN),
            ("a4", "waiting", ANALYST),
        ):
            await ins(
                "INSERT INTO incident_management_comment (alert_id, comment, user_name, created_at) VALUES (:a, :t, :u, '2026-03-01 10:30:00')",
                a=ids[key],
                t=text_,
                u=user,
            )
        tags = {}
        for t in ("t1", "t2"):
            tags[t] = await ins("INSERT INTO incident_management_alerttag (tag) VALUES (:t)", t=f"{t}-{SFX}")
        ids["tag_t1"], ids["tag_t2"] = tags["t1"], tags["t2"]
        for key, t in (("a1", "t2"), ("a1", "t1"), ("a2", "t2"), ("b1", "t1")):
            await ins("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)", a=ids[key], t=tags[t])
        for key, value, kind in (
            ("a1", f"10.0.0.{SFX[:2]}", "IP"),
            ("a2", f"evil-{SFX}.test", "DOMAIN"),
            ("b1", f"10.0.0.{SFX[:2]}", "IP"),
        ):
            ioc = await ins("INSERT INTO incident_management_ioc (value, type, description) VALUES (:v, :t, 'seen')", v=value, t=kind)
            await ins("INSERT INTO incident_management_alert_to_ioc (alert_id, ioc_id) VALUES (:a, :i)", a=ids[key], i=ioc)

        async def case(name, cust, status, **kw):
            return await ins(
                "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, case_status, assigned_to, "
                "customer_code, notification_invoked_number, escalated, severity) VALUES (:n, 'cd', '2026-03-04 09:00:00', :s, :a, :c, "
                ":nn, 0, :sev)",
                n=name,
                s=status,
                a=kw.get("assigned_to"),
                c=cust,
                nn=kw.get("notified"),
                sev=kw.get("severity"),
            )

        ids["ca1"] = await case(f"Case A1 {SFX}", CUST_A, "OPEN", notified=2, severity="High")
        ids["ca2"] = await case(f"Case A2 {SFX}", CUST_A, "CLOSED", assigned_to=ANALYST)
        ids["cb1"] = await case(f"Case B1 {SFX}", CUST_B, "OPEN", assigned_to=ANALYST)
        ids["cn"] = await case(f"Case none {SFX}", None, "IN_PROGRESS")
        for c, a in (("ca1", "a2"), ("ca1", "a1"), ("ca2", "a3"), ("cb1", "b1")):
            await ins("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=ids[c], a=ids[a])
        for c, t in (("ca1", "case note"), ("ca1", "second"), ("cb1", "b case note")):
            await ins(
                "INSERT INTO incident_management_case_comment (case_id, comment, user_name, created_at) VALUES (:c, :t, :u, '2026-03-04 09:30:00')",
                c=ids[c],
                t=t,
                u=ANALYST,
            )
        for c, title, order, status in (("ca1", "Isolate", 1, "TODO"), ("ca1", "Collect", 0, "DONE"), ("cb1", "B task", 0, "TODO")):
            await ins(
                "INSERT INTO incident_management_case_task (case_id, title, description, mandatory, order_index, status, created_by, "
                "created_at, updated_at, completed_at) VALUES (:c, :t, 'd', 1, :o, :s, 'seed', '2026-03-04 09:00:00', '2026-03-04 09:10:00', "
                "IF(:s = 'DONE', '2026-03-04 09:10:00', NULL))",
                c=ids[c],
                t=title,
                o=order,
                s=status,
            )
        for c, ev, payload, ts in (
            ("ca1", "case_created", {"source": "manual", "template_id": None}, "2026-03-04 09:00:00"),
            ("ca1", "alert_linked", {"alert_id": ids["a1"]}, "2026-03-04 09:00:00"),
            ("ca1", "comment_added", {"snippet": "case note", "comment_id": 1}, "2026-03-04 09:30:00"),
            ("cb1", "case_created", None, "2026-03-04 09:00:00"),
        ):
            await ins(
                "INSERT INTO incident_management_case_event (case_id, event_type, actor, timestamp, payload) VALUES (:c, :e, 'seed', :t, :p)",
                c=ids[c],
                e=ev,
                t=ts,
                p=json.dumps(payload) if payload is not None else None,
            )
        for c in ("ca1", "cb1"):
            await ins(
                "INSERT INTO incident_management_case_datastore (case_id, bucket_name, object_key, file_name, content_type, file_size, "
                "upload_time, file_hash) VALUES (:c, 'copilot-cases', :k, :f, 'text/plain', 12, '2026-03-04 10:00:00', 'abc')",
                c=ids[c],
                k=f"{ids[c]}/notes-{SFX}.txt",
                f=f"notes-{SFX}.txt",
            )
        for table, names in (
            ("incident_management_fieldname", ("rule_id", "agent_ip", "rule_id")),
            ("incident_management_assetfieldname", ("agent_name",)),
            ("incident_management_timestampfieldname", ("timestamp_utc",)),
            ("incident_management_alerttitlefieldname", ("rule_description",)),
            ("incident_management_iocfieldname", ("src_ip", "dst_ip")),
        ):
            for n in names:
                await ins(f"INSERT INTO {table} (source, field_name) VALUES (:s, :n)", s=SOURCE, n=n)
        await ins(f"INSERT INTO incident_management_fieldname (source, field_name) VALUES ('half{SFX}', 'x')")
        await ins("INSERT INTO incident_management_ai_analyst_trigger_enabled (customer_code, enabled) VALUES (:c, 1)", c=CUST_A)
        await ins(
            "INSERT INTO incident_management_notification (customer_code, shuffle_workflow_id, enabled) VALUES (:c, 'wf-1', 1)",
            c=CUST_A,
        )
        await s.commit()
    return ids


async def main():
    ids = await seed()
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=60)
    tok = {
        "admin": token(ADMIN, ["admin"]),
        "analyst": token(ANALYST, ["analyst"]),
        "portal": token(PORTAL, ["customer_user"]),
        "nobody": token(NOBODY, ["analyst"]),
        "tagged": token(TAGGED, ["analyst"]),
        "responder": token(RESPONDER, ["responder", "analyst"]),
    }
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    async def both(method, path, t=None, body=None):
        kw = {"headers": H(t)}
        if body is not None:
            kw["json"] = body
        return await py.request(method, path, **kw), await rs.request(method, path, **kw)

    def body_of(r):
        try:
            return r.json()
        except ValueError:
            return r.text

    async def same(name, method, path, t=None, body=None, masked=False):
        r1, r2 = await both(method, path, t, body)
        b1, b2 = body_of(r1), body_of(r2)
        if masked:
            b1, b2 = mask(b1), mask(b2)
        ok = r1.status_code == r2.status_code and b1 == b2
        check(
            f"{name} [{r1.status_code}]",
            ok,
            f"python {r1.status_code} {json.dumps(b1)[:900]}\n        rust   {r2.status_code} {json.dumps(b2)[:900]}",
        )
        return r1, r2

    a1, a2, a3, b1 = ids["a1"], ids["a2"], ids["a3"], ids["b1"]
    ca1, cb1, cn = ids["ca1"], ids["cb1"], ids["cn"]

    print("\n=== incidents: auth and validation ===")
    await same("no token", "GET", f"{P}/alerts")
    await same("bad token", "GET", f"{P}/alerts", "x.y.z")
    await same("portal on an admin/analyst route", "GET", f"{P}/alert/available-users", tok["portal"])
    await same("alert id not an int", "GET", f"{P}/alert/abc", tok["admin"])
    await same("paging errors in one 422", "GET", f"{P}/alerts?page=0&page_size=x&order=up", tok["admin"])
    await same("status enum + paging", "GET", f"{P}/alerts/status/BOGUS?page_size=0", tok["admin"])
    await same("timeline limits", "GET", f"{P}/case/{ca1}/timeline?limit=0&offset=-1", tok["admin"])
    await same("timeline path + query", "GET", f"{P}/case/x/timeline?limit=3000", tok["admin"])
    await same("fields: source missing", "GET", f"{P}/fields-assets-title-and-timefield", tok["admin"])
    await same("filter: bad date", "GET", f"{P}/alerts/filter?date_from=nope", tok["admin"])
    await same("filter: reversed range", "GET", f"{P}/alerts/filter?date_from=2026-03-02&date_to=2026-03-01", tok["admin"])
    await same("verdict-stats: reversed range", "GET", f"{P}/alerts/verdict-stats?date_from=2026-03-02&date_to=2026-03-01", tok["admin"])
    await same("verdict-stats: limit bound", "GET", f"{P}/alerts/verdict-stats?alert_name_limit=101", tok["admin"])
    await same("filter-options: include_assets not a bool", "GET", f"{P}/alerts/filter-options?include_assets=maybe", tok["admin"])
    await same("asset options: limit bound", "GET", f"{P}/alerts/filter-options/assets?limit=0", tok["admin"])

    print("\n=== incidents: settings and dictionaries ===")
    for who in ("admin", "analyst"):
        await same(f"ai_trigger A ({who})", "GET", f"{P}/ai_trigger/{CUST_A}", tok[who])
        await same(f"ai_trigger B ({who})", "GET", f"{P}/ai_trigger/{CUST_B}", tok[who])
        await same(f"notification A ({who})", "GET", f"{P}/notification/{CUST_A}", tok[who])
        await same(f"notification B ({who})", "GET", f"{P}/notification/{CUST_B}", tok[who])
    await same("ai_trigger unknown customer", "GET", f"{P}/ai_trigger/nope{SFX}", tok["admin"])
    await same("recommends", "GET", f"{P}/socfortress/recommends/wazuh", tok["analyst"])
    await same("configured sources", "GET", f"{P}/configured/sources", tok["admin"])
    await same("fields of a source", "GET", f"{P}/fields-assets-title-and-timefield?source={SOURCE}", tok["admin"])
    await same("fields of a half-configured source", "GET", f"{P}/fields-assets-title-and-timefield?source=half{SFX}", tok["admin"])
    await same("available users", "GET", f"{P}/alert/available-users", tok["analyst"])
    await same("alert context (admin)", "GET", f"{P}/alert/context/{ids['ctx_a1']}", tok["admin"])
    await same("alert context, own (analyst)", "GET", f"{P}/alert/context/{ids['ctx_a1']}", tok["analyst"])
    await same("alert context missing (admin)", "GET", f"{P}/alert/context/999999999", tok["admin"])
    r1, r2 = await both("GET", f"{P}/alert/context/{ids['ctx_b1']}", tok["analyst"])
    check(
        f"DIFF_BY_DESIGN alert context of another tenant: Python {r1.status_code}, Rust 403",
        r1.status_code == 200 and r2.status_code == 403,
        f"{r1.text[:200]} / {r2.text[:200]}",
    )

    print("\n=== incidents: alerts ===")
    for who in ("admin", "analyst", "portal", "nobody", "responder"):
        await same(f"alerts list ({who})", "GET", f"{P}/alerts?page_size=5", tok[who])
        await same(f"alert a1 ({who})", "GET", f"{P}/alert/{a1}", tok[who])
        await same(f"alert b1 ({who})", "GET", f"{P}/alert/{b1}", tok[who])
        await same(f"filter options ({who})", "GET", f"{P}/alerts/filter-options", tok[who])
        await same(f"asset options ({who})", "GET", f"{P}/alerts/filter-options/assets?search=-{SFX}", tok[who])
        await same(f"case filter options ({who})", "GET", f"{P}/cases/filter-options", tok[who])
    await same("alerts list asc, scoped", "GET", f"{P}/alerts?order=asc&customer_codes={CUST_A}&customer_codes={CUST_B}", tok["admin"])
    await same("alerts list, analyst asks for B", "GET", f"{P}/alerts?customer_codes={CUST_B}", tok["analyst"])
    await same("alert missing", "GET", f"{P}/alert/999999999", tok["admin"])
    await same("filter options without assets", "GET", f"{P}/alerts/filter-options?include_assets=false", tok["admin"])
    await same("asset options, search and limit", "GET", f"{P}/alerts/filter-options/assets?search=%20WEB&limit=1", tok["analyst"])
    q_cust = f"customer_codes={CUST_A}&customer_codes={CUST_B}"
    for who in ("admin", "analyst", "portal"):
        await same(f"filter: everything ({who})", "GET", f"{P}/alerts/filter?{q_cust}&page_size=50", tok[who])
        await same(f"filter: title + status ({who})", "GET", f"{P}/alerts/filter?{q_cust}&alert_title=mimi&status=OPEN", tok[who])
        await same(f"filter: asset dup ({who})", "GET", f"{P}/alerts/filter?{q_cust}&asset_name=dc01-{SFX}", tok[who])
        await same(f"filter: tags any ({who})", "GET", f"{P}/alerts/filter?{q_cust}&tags=t1-{SFX}&tags=t2-{SFX}", tok[who])
        await same(f"filter: ioc ({who})", "GET", f"{P}/alerts/filter?{q_cust}&ioc_value=10.0.0.{SFX[:2]}", tok[who])
        await same(f"filter: untriaged ({who})", "GET", f"{P}/alerts/filter?{q_cust}&verdict=UNTRIAGED", tok[who])
        await same(
            f"filter: verdict + reason ({who})",
            "GET",
            f"{P}/alerts/filter?{q_cust}&verdict=FALSE_POSITIVE&verdict_reason=EXPECTED_ACTIVITY",
            tok[who],
        )
        await same(
            f"filter: date window, aware ({who})",
            "GET",
            f"{P}/alerts/filter?{q_cust}&date_from=2026-03-01T11:00:00%2B01:00&date_to=2026-03-02T23:59:59Z",
            tok[who],
        )
        await same(
            f"filter: assignee + source ({who})",
            "GET",
            f"{P}/alerts/filter?{q_cust}&assigned_to={ANALYST}&source={SOURCE}",
            tok[who],
        )
        await same(f"filter: legacy customer_code ({who})", "GET", f"{P}/alerts/filter?customer_code={CUST_B}", tok[who])
        await same(f"filter: empty criteria ignored ({who})", "GET", f"{P}/alerts/filter?{q_cust}&alert_title=&status=", tok[who])
    await same("filter: nobody (sees nothing)", "GET", f"{P}/alerts/filter?{q_cust}", tok["nobody"])

    print("\n=== incidents: per-key alert listings ===")
    keys = {
        "status": f"/alerts/status/OPEN?page_size=3&{q_cust}",
        "status, no subset": "/alerts/status/CLOSED?page_size=3",
        "assigned-to": f"/alerts/assigned-to/{ANALYST}",
        "asset": f"/alerts/asset/dc01-{SFX}?{q_cust}",
        "asset, no subset": f"/alerts/asset/dc01-{SFX}",
        "title": f"/alerts/title/{SFX}?order=asc",
        "customer A": f"/alerts/customer/{CUST_A}",
        "customer B": f"/alerts/customer/{CUST_B}",
        "source": f"/alerts/source/{SOURCE}?{q_cust}",
        "source, no subset": f"/alerts/source/{SOURCE}",
        "ioc": f"/alert/ioc/10.0.0.{SFX[:2]}",
        "tag": f"/alert/tag/t1-{SFX}?{q_cust}",
        "tag, no subset": f"/alert/tag/t2-{SFX}",
    }
    for label, path in keys.items():
        for who in ("admin", "analyst", "portal"):
            await same(f"{label} ({who})", "GET", f"{P}{path}", tok[who])
    # DIFF_BY_DESIGN: an analyst whose scope resolves to no customer. Python's scoped branch
    # passed `customer_codes=[]` on, which the filter reads as "no filter": every tenant's
    # alerts. Rust lists none; the counts (zeros) agree.
    for label in ("status, no subset", "source, no subset", "asset, no subset"):
        r1, r2 = await both("GET", f"{P}{keys[label]}", tok["nobody"])
        j1, j2 = r1.json(), r2.json()
        check(
            f"DIFF_BY_DESIGN {label} (unassigned analyst): Python lists other tenants, Rust nothing",
            r1.status_code == r2.status_code == 200
            and j1["alerts"]
            and j2["alerts"] == []
            and {k: v for k, v in j1.items() if k != "alerts"} == {k: v for k, v in j2.items() if k != "alerts"},
            f"{json.dumps(j1)[:300]} / {json.dumps(j2)[:300]}",
        )

    print("\n=== incidents: cases ===")
    for who in ("admin", "analyst", "portal", "nobody"):
        await same(f"cases list ({who})", "GET", f"{P}/cases?page_size=5", tok[who])
        await same(f"case A1 ({who})", "GET", f"{P}/case/{ca1}", tok[who])
        await same(f"case B1 ({who})", "GET", f"{P}/case/{cb1}", tok[who])
        await same(f"case without customer ({who})", "GET", f"{P}/case/{cn}", tok[who])
        await same(f"case status OPEN ({who})", "GET", f"{P}/case/status/OPEN?page_size=50&{q_cust}", tok[who])
        await same(f"case name ({who})", "GET", f"{P}/case/name/{SFX}?order=asc", tok[who])
        await same(f"case assignee ({who})", "GET", f"{P}/case/assigned-to/{ANALYST}?customer_codes={CUST_A}", tok[who])
        await same(f"case asset ({who})", "GET", f"{P}/case/asset/dc01-{SFX}", tok[who])
        await same(f"case customer A ({who})", "GET", f"{P}/case/customer/{CUST_A}", tok[who])
        await same(f"case customer B ({who})", "GET", f"{P}/case/customer/{CUST_B}", tok[who])
        await same(f"case files A1 ({who})", "GET", f"{P}/case/data-store/{ca1}", tok[who])
        await same(f"case files B1 ({who})", "GET", f"{P}/case/data-store/{cb1}", tok[who])
        await same(f"case tasks A1 ({who})", "GET", f"{P}/case/{ca1}/tasks", tok[who])
        await same(f"case tasks B1 ({who})", "GET", f"{P}/case/{cb1}/tasks", tok[who])
        await same(f"case timeline A1 ({who})", "GET", f"{P}/case/{ca1}/timeline", tok[who])
        await same(f"case timeline B1, paged ({who})", "GET", f"{P}/case/{cb1}/timeline?limit=1&offset=0", tok[who])
    await same("cases list, asc, subset", "GET", f"{P}/cases?order=asc&customer_codes={CUST_B}", tok["admin"])
    await same("case missing", "GET", f"{P}/case/999999999", tok["admin"])
    await same("case timeline, missing case", "GET", f"{P}/case/999999999/timeline", tok["admin"])
    await same("default report template exists", "GET", f"{P}/case-report-template/do-default-template-exists", tok["admin"])
    await same("all case files (admin)", "GET", f"{P}/case/data-store", tok["admin"])
    r1, r2 = await both("GET", f"{P}/case/data-store", tok["analyst"])
    py_cases = {f["case_id"] for f in r1.json()["case_data_store"]}
    rs_cases = {f["case_id"] for f in r2.json()["case_data_store"]}
    check(
        "DIFF_BY_DESIGN all case files (analyst): Python lists every tenant's, Rust only A's",
        cb1 in py_cases and cb1 not in rs_cases and ca1 in rs_cases,
        f"{sorted(py_cases)[:20]} / {sorted(rs_cases)[:20]}",
    )

    print("\n=== incidents: verdict statistics ===")
    for who in ("admin", "analyst"):
        await same(
            f"verdict-stats subset ({who})",
            "GET",
            f"{P}/alerts/verdict-stats?{q_cust}&date_from=2026-01-01&date_to=2026-04-01",
            tok[who],
        )
        await same(
            f"verdict-stats legacy customer_code ({who})",
            "GET",
            f"{P}/alerts/verdict-stats?customer_code={CUST_A}&date_from=2026-01-01T00:00:00&date_to=2026-04-01",
            tok[who],
        )
    await same("verdict-stats, nobody", "GET", f"{P}/alerts/verdict-stats?customer_codes={CUST_A}", tok["nobody"])
    await same("verdict-stats, whole deployment", "GET", f"{P}/alerts/verdict-stats?date_from=2026-01-01&alert_name_limit=3", tok["admin"])

    # Tag RBAC (global settings: only when this database has none, restored afterwards).
    async with AsyncSession(async_engine) as s_:
        configured = (await s_.execute(text("SELECT COUNT(*) FROM incident_management_tag_access_settings"))).scalar_one()
    if configured:
        print("  SKIP  tag RBAC: incident_management_tag_access_settings already configured")
    else:
        print("\n=== incidents: tag RBAC ===")
        async with AsyncSession(async_engine) as s_:
            settings_id = (
                await s_.execute(
                    text(
                        "INSERT INTO incident_management_tag_access_settings (enabled, untagged_alert_behavior, updated_at) "
                        "VALUES (1, 'admin_only', UTC_TIMESTAMP())",
                    ),
                )
            ).lastrowid
            await s_.execute(
                text(
                    "INSERT INTO user_tag_access (user_id, tag_id, created_at) SELECT id, :t, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                ),
                {"t": ids["tag_t1"], "n": TAGGED},
            )
            await s_.commit()
        try:
            for behavior in ("admin_only", "visible_to_all", "default_tag"):
                async with AsyncSession(async_engine) as s_:
                    await s_.execute(
                        text("UPDATE incident_management_tag_access_settings SET untagged_alert_behavior = :b WHERE id = :i"),
                        {"b": behavior, "i": settings_id},
                    )
                    await s_.commit()
                for who in ("tagged", "analyst", "portal"):
                    await same(f"tags {behavior}: alerts ({who})", "GET", f"{P}/alerts?page_size=50", tok[who])
                    await same(f"tags {behavior}: alert a1 ({who})", "GET", f"{P}/alert/{a1}", tok[who])
                    await same(f"tags {behavior}: alert a2 ({who})", "GET", f"{P}/alert/{a2}", tok[who])
                    await same(f"tags {behavior}: untagged a3 ({who})", "GET", f"{P}/alert/{a3}", tok[who])
                    await same(f"tags {behavior}: filter ({who})", "GET", f"{P}/alerts/filter?{q_cust}", tok[who])
                    await same(f"tags {behavior}: filter options ({who})", "GET", f"{P}/alerts/filter-options", tok[who])
                    await same(f"tags {behavior}: case A1 ({who})", "GET", f"{P}/case/{ca1}", tok[who])
            # DIFF_BY_DESIGN: the per-key listings' scoped branch filtered on customers only.
            r1, r2 = await both("GET", f"{P}/alerts/source/{SOURCE}", tok["tagged"])
            py_ids = [a["id"] for a in r1.json()["alerts"]]
            rs_ids = [a["id"] for a in r2.json()["alerts"]]
            check(
                "DIFF_BY_DESIGN per-key listing (tag-restricted analyst): Python ignores tag RBAC, Rust applies it",
                a3 in py_ids and a3 not in rs_ids and a1 in rs_ids,
                f"{py_ids} / {rs_ids}",
            )
        finally:
            async with AsyncSession(async_engine) as s_:
                await s_.execute(text("DELETE FROM incident_management_tag_access_settings WHERE id = :i"), {"i": settings_id})
                await s_.execute(text("DELETE FROM user_tag_access WHERE tag_id = :t"), {"t": ids["tag_t1"]})
                await s_.commit()

    await writes(py, rs, tok, ids, body_of)

    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


# ── writes ─────────────────────────────────────────────────────────────────────
#
# Every write runs twice: Python on one twin, Rust on the other (created the same way), and the
# answers are compared once each side's ids are replaced by shared labels and the timestamps a write
# stamps with `utcnow()` are masked. The rows a write leaves behind (SLA tracking, case timeline,
# tasks, audit) are compared the same way.

# Which kind of object an id key names; `None`: always a new row ("<new>"). `id` takes the kind
# of the object it sits in (`_kind_of`).
ID_KINDS = {
    "alert_id": "alert",
    "alert_linked": "alert",
    "case_id": "case",
    "ioc_id": "ioc",
    "tag_id": "tag",
    "comment_id": "comment",
    "alert_context_id": "ctx",
    "task_id": None,
    "entity_id": None,
    "template_id": "template",
    "user_id": "user",
    "source_alert_id": "alert",
    "source_case_id": "case",
}
LIST_ID_KEYS = {"updated_alert_ids", "not_updated_alert_ids", "deleted_alert_ids", "not_deleted_alert_ids", "missing", "alert_ids"}
TIME_KEYS = {"time_closed", "verdict_at", "created_at", "updated_at", "timestamp", "case_closed_time", "completed_at"}


def _kind_of(obj):
    if "match_count" in obj and "field_matches" in obj:
        return "excl"
    if "alert_name" in obj:
        return "alert"
    if "case_name" in obj:
        return "case"
    if "is_default" in obj and "tasks" in obj:
        return "template"
    if "template_id" in obj and "title" in obj:
        return "ttask"
    if "title" in obj and "mandatory" in obj and "status" in obj:
        return "task"
    if "comment" in obj:
        return "comment"
    if "context" in obj:
        return "ctx"
    if set(obj) == {"id", "tag"}:
        return "tag"
    return None


def norm(value, labels, keep=(), key=None, owner=None):
    """`labels`: {kind: {id: label}} plus {"str": {text: label}}."""
    if isinstance(value, dict):
        kind = _kind_of(value)
        return {k: norm(v, labels, keep, k, kind) for k, v in value.items()}
    if isinstance(value, list):
        if key in LIST_ID_KEYS:
            return [labels.get("alert", {}).get(v, "<new>") if isinstance(v, int) else v for v in value]
        return [norm(v, labels, keep, key, owner) for v in value]
    if key in TIME_KEYS and key not in keep and value is not None:
        return "<t>"
    if isinstance(value, int) and not isinstance(value, bool) and (key == "id" or key in ID_KINDS):
        kind = owner if key == "id" else ID_KINDS[key]
        return labels.get(kind, {}).get(value, "<new>") if kind else "<new>"
    if isinstance(value, str):
        for text_, label in labels.get("str", {}).items():
            value = value.replace(text_, label)
        if key in ("message", "detail"):
            # "alert 5", "Alert id=5", "case id=7", "Case task 9", "template id=3": the id after
            # its kind's word, labelled (or "<new>").
            for kind in ("alert", "case", "task", "template"):

                def sub(m, kind=kind):
                    return f"{m.group(1)}{labels.get(kind, {}).get(int(m.group(2)), '<new>')}"

                value = re.sub(rf"(?i)(\b{kind}(?: id=| ))(\d+)\b", sub, value)
    return value


def mask_keys(value, keys):
    if not keys:
        return value
    if isinstance(value, dict):
        return {k: ("<m>" if k in keys and v is not None else mask_keys(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_keys(v, keys) for v in value]
    return value


async def rows(sql, **params):
    async with AsyncSession(async_engine) as s:
        return [dict(r._mapping) for r in (await s.execute(text(sql), params)).all()]


async def tracking(entity, item_id):
    table, key = ("soc_sla_alert_tracking", "alert_id") if entity == "alert" else ("soc_sla_case_tracking", "case_id")
    found = await rows(f"SELECT * FROM {table} WHERE {key} = :i", i=item_id)
    if not found:
        return None
    t = found[0]
    out = {k: ("set" if isinstance(v, datetime.datetime) else v) for k, v in t.items() if k != key}
    out["paused_seconds"] = "n" if t["paused_seconds"] is not None else None
    out["pause_credit_seconds"] = "n" if t["pause_credit_seconds"] is not None else None
    dues = {k: t[k] for k in ("ack_due_at", "resolve_due_at")}
    return out, t["opened_at"], dues


async def events_of(case_id, labels):
    found = await rows("SELECT event_type, actor, payload FROM incident_management_case_event WHERE case_id = :c ORDER BY id", c=case_id)
    return [(e["event_type"], e["actor"], norm(json.loads(e["payload"]) if e["payload"] else None, labels)) for e in found]


async def tasks_of(case_id, labels):
    found = await rows(
        "SELECT alert_id, template_task_id, title, mandatory, order_index, status, created_by FROM incident_management_case_task "
        "WHERE case_id = :c ORDER BY id",
        c=case_id,
    )
    return [norm(t, labels) for t in found]


async def audit_of(entity_type, entity_id, labels, want=1):
    for _ in range(40):
        found = await rows(
            "SELECT action, actor_username, customer_code, result, old_value, new_value FROM audit_log "
            "WHERE entity_type = :t AND entity_id = :i ORDER BY id",
            t=entity_type,
            i=str(entity_id),
        )
        if len(found) >= want:
            break
        await asyncio.sleep(0.1)
    return [
        norm(
            {
                **a,
                "old_value": json.loads(a["old_value"]) if a["old_value"] else None,
                "new_value": json.loads(a["new_value"]) if a["new_value"] else None,
            },
            labels,
        )
        for a in found
    ]


async def writes(py, rs, tok, ids, body_of):
    L = {"p": {"str": {}}, "r": {"str": {}}}  # {kind: {id: label}}, {"str": {text: label}}
    ID = {"p": {}, "r": {}}  # name -> this side's id
    client = {"p": py, "r": rs}

    def H(t):
        return {"Authorization": f"Bearer {t}"} if t else {}

    async def call(side, method, path, t, body=None, raw=None):
        kw = {"headers": H(t)}
        if body is not None:
            kw["json"] = body
        if raw is not None:
            kw["content"] = raw
            kw["headers"] = {**kw["headers"], "Content-Type": "application/json"}
        return await client[side].request(method, path, **kw)

    async def pair(name, method, path, t, body=None, keep=(), raw=None, exact=False, extra=(), order=("p", "r")):
        """`path` and `body` are callables of the side ("p" / "r") or plain values. `exact`: the
        same request on both sides, compared without labels; `extra`: keys masked as well;
        `order`: which side goes first."""
        out = {}
        for side in order:
            p = path(side) if callable(path) else path
            b = body(side) if callable(body) else body
            out[side] = await call(side, method, p, t, b, raw)
        if exact:
            n1, n2 = body_of(out["p"]), body_of(out["r"])
        else:
            n1 = mask_keys(norm(body_of(out["p"]), L["p"], keep), extra)
            n2 = mask_keys(norm(body_of(out["r"]), L["r"], keep), extra)
        check(
            f"{name} [{out['p'].status_code}]",
            out["p"].status_code == out["r"].status_code and n1 == n2,
            f"python {out['p'].status_code} {json.dumps(n1)[:900]}\n        rust   {out['r'].status_code} {json.dumps(n2)[:900]}",
        )
        return out["p"], out["r"]

    async def same_rows(name, fetch):
        a, b = await fetch("p"), await fetch("r")
        check(name, a == b, f"python {a}\n        rust   {b}")

    async def same_tracking(name, entity, key):
        tp, tr = await tracking(entity, ID["p"][key]), await tracking(entity, ID["r"][key])
        ok = (tp is None) == (tr is None)
        detail = f"python {tp}\n        rust   {tr}"
        if ok and tp is not None:
            ok = tp[0] == tr[0]
            for col in ("ack_due_at", "resolve_due_at"):
                dp, dr = tp[2][col], tr[2][col]
                if (dp is None) != (dr is None):
                    ok = False
                elif dp is not None:
                    by_delta = abs(((dp - tp[1]) - (dr - tr[1])).total_seconds()) <= 2
                    by_value = abs((dp - dr).total_seconds()) <= 2
                    ok = ok and (by_delta or by_value)
        check(f"{name}: SLA tracking", ok, detail)

    def label(key, rp, rr, kind):
        L["p"].setdefault(kind, {})[rp] = f"<{key}>"
        L["r"].setdefault(kind, {})[rr] = f"<{key}>"
        ID["p"][key] = rp
        ID["r"][key] = rr

    def label_str(text_p, text_r, lab):
        L["p"]["str"][text_p] = lab
        L["r"]["str"][text_r] = lab

    def lid(side, key):
        return ID[side][key]

    adm, ana, portal, nobody = tok["admin"], tok["analyst"], tok["portal"], tok["nobody"]
    b1 = ids["b1"]

    print("\n=== incidents writes: alert creation ===")
    await pair("create alert: empty body", "POST", f"{P}/alert", adm, {})
    await pair("create alert: malformed JSON", "POST", f"{P}/alert", None, raw=b'{"alert_name": ')
    await pair("create alert: no token", "POST", f"{P}/alert", None, {"alert_name": "x"})
    await pair("create alert: portal scope", "POST", f"{P}/alert", portal, {"alert_name": "x"})

    def alert_body(title, cust=CUST_A, **kw):
        return {
            "alert_name": title,
            "alert_description": "made by the parity suite",
            "status": kw.get("status", "OPEN"),
            "alert_creation_time": kw.get("when", "2026-03-05T10:00:00+02:00"),
            "customer_code": cust,
            "source": kw.get("source", SOURCE),
            "assigned_to": kw.get("assigned_to", ANALYST),
            **({"time_closed": kw["time_closed"]} if "time_closed" in kw else {}),
        }

    await pair(
        "create alert: bad datetime + types",
        "POST",
        f"{P}/alert",
        adm,
        {**alert_body("x"), "alert_creation_time": "soon", "status": 5},
    )
    await pair("create alert: another tenant (analyst)", "POST", f"{P}/alert", ana, alert_body("x", CUST_B))
    created = {}
    for key, title, who in (("w1", f"Write one {SFX}", adm), ("w2", f"Write two {SFX}", ana), ("w3", f"Write three {SFX}", ana)):
        rp = await call("p", "POST", f"{P}/alert", who, alert_body(title, when="1767225600"))
        rr = await call("r", "POST", f"{P}/alert", who, alert_body(title, when="1767225600"))
        if rp.status_code == 200 and rr.status_code == 200:
            label(key, rp.json()["id"], rr.json()["id"], "alert")
        n1, n2 = norm(rp.json(), L["p"]), norm(rr.json(), L["r"])
        check(f"create alert {key} [{rp.status_code}]", rp.status_code == rr.status_code and n1 == n2, f"{n1}\n        {n2}")
        created[key] = (rp, rr)
        if key in ID["p"]:
            await same_tracking(f"create alert {key}", "alert", key)
    await pair(
        "create alert: aware creation time, closed",
        "POST",
        f"{P}/alert",
        adm,
        alert_body(f"Write aware {SFX}", when="2026-03-05T10:00:00.6+02:00", time_closed="2026-03-05T11:00:00Z", status="CLOSED"),
    )

    W1 = lambda s: lid(s, "w1")  # noqa: E731
    W2 = lambda s: lid(s, "w2")  # noqa: E731

    print("\n=== incidents writes: alert status, verdict, escalation ===")
    await pair("status: body errors", "PUT", f"{P}/alert/status", ana, {"alert_id": "x", "status": "DONE"})
    await pair("status: missing alert", "PUT", f"{P}/alert/status", ana, {"alert_id": 999999999, "status": "OPEN"})
    await pair("status: another tenant", "PUT", f"{P}/alert/status", ana, {"alert_id": b1, "status": "OPEN"})
    await pair(
        "status: portal cannot wait",
        "PUT",
        f"{P}/alert/status",
        portal,
        lambda s: {"alert_id": W1(s), "status": "PENDING_CUSTOMER"},
    )
    for status in ("IN_PROGRESS", "CLOSED", "OPEN", "PENDING_CUSTOMER"):
        await pair(f"status -> {status}", "PUT", f"{P}/alert/status", ana, lambda s, st=status: {"alert_id": W1(s), "status": st})
        await same_tracking(f"status -> {status}", "alert", "w1")
    await pair(
        "portal reply on a waiting alert",
        "POST",
        f"{P}/alert/comment",
        portal,
        lambda s: {"alert_id": W1(s), "comment": "here you go", "user_name": "spoofed"},
    )
    await pair("alert after the reply", "GET", lambda s: f"{P}/alert/{W1(s)}", ana)
    await same_tracking("after the portal reply", "alert", "w1")
    await pair("status by portal on own alert", "PUT", f"{P}/alert/status", portal, lambda s: {"alert_id": W1(s), "status": "CLOSED"})
    await same_tracking("closed by the customer", "alert", "w1")

    await pair(
        "verdict: reason without FP",
        "PUT",
        f"{P}/alert/verdict",
        ana,
        lambda s: {"alert_id": W2(s), "verdict": "TRUE_POSITIVE", "verdict_reason": "OTHER"},
    )
    await pair("verdict: FP without reason", "PUT", f"{P}/alert/verdict", ana, lambda s: {"alert_id": W2(s), "verdict": "FALSE_POSITIVE"})
    await pair(
        "verdict: bad enum + long note",
        "PUT",
        f"{P}/alert/verdict",
        ana,
        {"alert_id": 1, "verdict": "MAYBE", "verdict_note": "x" * 1025},
    )
    await pair("verdict: portal scope", "PUT", f"{P}/alert/verdict", portal, {"alert_id": 1})
    await pair("verdict: another tenant", "PUT", f"{P}/alert/verdict", ana, {"alert_id": b1, "verdict": "TRUE_POSITIVE"})
    await pair(
        "verdict: set FP",
        "PUT",
        f"{P}/alert/verdict",
        ana,
        lambda s: {"alert_id": W2(s), "verdict": "FALSE_POSITIVE", "verdict_reason": "AUTHORIZED_USER", "verdict_note": "known"},
    )
    await pair("verdict: clear", "PUT", f"{P}/alert/verdict", ana, lambda s: {"alert_id": W2(s)})
    await same_rows("verdict: audit rows", lambda s: audit_of("alert", W2(s), L[s], want=2))
    await same_tracking("verdict", "alert", "w2")
    await pair("escalate", "PUT", f"{P}/alert/escalated", ana, lambda s: {"alert_id": W2(s), "escalated": True})
    await pair("escalate: bool parse error", "PUT", f"{P}/alert/escalated", ana, {"alert_id": 1, "escalated": "perhaps"})

    print("\n=== incidents writes: comments ===")
    await pair("comment: missing fields", "POST", f"{P}/alert/comment", ana, {"alert_id": 1})
    await pair("comment: another tenant", "POST", f"{P}/alert/comment", ana, {"alert_id": b1, "comment": "x", "user_name": "x"})
    rp, rr = await pair(
        "comment: create with an aware time",
        "POST",
        f"{P}/alert/comment",
        ana,
        lambda s: {"alert_id": W2(s), "comment": "looked at it", "user_name": "spoofed", "created_at": "2026-03-05T10:00:00.5+02:00"},
        keep=("created_at",),
    )
    if rp.status_code == rr.status_code == 200:
        label("cm", rp.json()["comment"]["id"], rr.json()["comment"]["id"], "comment")
        CM = lambda s: lid(s, "cm")  # noqa: E731
        await pair(
            "comment: edit",
            "PUT",
            f"{P}/alert/comment",
            ana,
            lambda s: {"alert_id": W2(s), "comment_id": CM(s), "comment": "edited", "user_name": "z", "created_at": "2026-01-01"},
        )
        await pair(
            "comment: edit, wrong alert",
            "PUT",
            f"{P}/alert/comment",
            ana,
            lambda s: {"alert_id": ids["a1"], "comment_id": CM(s), "comment": "e", "user_name": "z", "created_at": "2026-01-01"},
        )
        await pair(
            "comment: edit by portal (not theirs)",
            "PUT",
            f"{P}/alert/comment",
            portal,
            lambda s: {"alert_id": W2(s), "comment_id": CM(s), "comment": "e", "user_name": "z", "created_at": "2026-01-01"},
        )
        await pair("comment: delete by portal (not theirs)", "DELETE", lambda s: f"{P}/alert/comment/{CM(s)}", portal)
        await pair("comment: delete", "DELETE", lambda s: f"{P}/alert/comment/{CM(s)}", ana)
        await pair("comment: delete again", "DELETE", lambda s: f"{P}/alert/comment/{CM(s)}", ana)
    await pair("comment: delete, path not an int", "DELETE", f"{P}/alert/comment/abc", ana)
    await pair(
        "comment: delete b1's (analyst)",
        "DELETE",
        f"{P}/alert/comment/{(await rows('SELECT id FROM incident_management_comment WHERE alert_id = :a', a=b1))[0]['id']}",
        ana,
    )

    print("\n=== incidents writes: assignment ===")
    await pair("assign: unknown user", "PUT", f"{P}/alert/assigned-to", ana, lambda s: {"alert_id": W2(s), "assigned_to": f"ghost{SFX}"})
    await pair(
        "assign: case-different user",
        "PUT",
        f"{P}/alert/assigned-to",
        ana,
        lambda s: {"alert_id": W2(s), "assigned_to": ANALYST.upper()},
    )
    await pair("assign: another tenant", "PUT", f"{P}/alert/assigned-to", ana, {"alert_id": b1, "assigned_to": ADMIN})
    await pair("assign", "PUT", f"{P}/alert/assigned-to", ana, lambda s: {"alert_id": W2(s), "assigned_to": ADMIN})
    await same_tracking("assign", "alert", "w2")
    await pair("bulk assign: unknown user", "PUT", f"{P}/alerts/assigned-to", ana, {"alert_ids": [1], "assigned_to": f"ghost{SFX}"})
    await pair(
        "bulk assign",
        "PUT",
        f"{P}/alerts/assigned-to",
        ana,
        lambda s: {"alert_ids": [W2(s), b1, 999999999, W2(s)], "assigned_to": ANALYST},
    )
    await pair("bulk status", "PUT", f"{P}/alerts/status", ana, lambda s: {"alert_ids": [W2(s), b1, 999999999], "status": "IN_PROGRESS"})
    await pair(
        "bulk status: portal waiting",
        "PUT",
        f"{P}/alerts/status",
        portal,
        lambda s: {"alert_ids": [W2(s)], "status": "PENDING_CUSTOMER"},
    )
    await pair("bulk status: errors", "PUT", f"{P}/alerts/status", ana, {"alert_ids": ["x", 2], "status": "NOPE"})
    await same_tracking("bulk", "alert", "w2")

    print("\n=== incidents writes: contexts, assets, IoCs, tags ===")
    rp, rr = await pair(
        "context: create",
        "POST",
        f"{P}/alert/context",
        ana,
        {"source": "wazuh", "context": {"b": 1, "a": {"zz": [1, 2.5, None], "y": "x"}}},
    )
    if rp.status_code == rr.status_code == 200:
        label("ctx", rp.json()["alert_context"]["id"], rr.json()["alert_context"]["id"], "ctx")
    await pair("context: not a dict", "POST", f"{P}/alert/context", ana, {"source": "wazuh", "context": [1]})
    await pair(
        "asset: missing context",
        "POST",
        f"{P}/alert/asset",
        ana,
        lambda s: {
            "alert_linked": W2(s),
            "asset_name": "h",
            "alert_context_id": 999999999,
            "customer_code": CUST_A,
            "index_name": "i",
            "index_id": "d",
        },
    )
    await pair(
        "asset: create",
        "POST",
        f"{P}/alert/asset",
        ana,
        lambda s: {
            "alert_linked": W2(s),
            "asset_name": f"host-{SFX}",
            "alert_context_id": lid(s, "ctx"),
            "customer_code": CUST_A,
            "index_name": "wazuh-alerts-x",
            "index_id": "doc",
            "agent_id": "001",
        },
    )
    await pair(
        "asset: another tenant",
        "POST",
        f"{P}/alert/asset",
        ana,
        {"alert_linked": b1, "asset_name": "h", "alert_context_id": 1, "customer_code": CUST_A, "index_name": "i", "index_id": "d"},
    )
    await pair("ioc: bad type", "POST", f"{P}/alert/ioc", ana, {"alert_id": 1, "ioc_value": "x", "ioc_type": "ip"})
    rp, rr = await pair(
        "ioc: create",
        "POST",
        f"{P}/alert/ioc",
        ana,
        lambda s: {"alert_id": W2(s), "ioc_value": f"9.9.9.{SFX[:1]}", "ioc_type": "IP"},
    )
    if rp.status_code == rr.status_code == 200:
        label("ioc", rp.json()["alert_ioc"]["ioc_id"], rr.json()["alert_ioc"]["ioc_id"], "ioc")
        await pair("alert with its new children", "GET", lambda s: f"{P}/alert/{W2(s)}", ana)
        await pair("ioc: delete", "DELETE", f"{P}/alert/ioc", ana, lambda s: {"alert_id": W2(s), "ioc_id": lid(s, "ioc")})
        await pair("ioc: delete again", "DELETE", f"{P}/alert/ioc", ana, lambda s: {"alert_id": W2(s), "ioc_id": lid(s, "ioc")})
    rp, rr = await pair("tag: create", "POST", f"{P}/alert/tag", ana, lambda s: {"alert_id": W2(s), "tag": f"w-{SFX}"})
    if rp.status_code == rr.status_code == 200:
        label("tag", rp.json()["alert_tag"]["id"], rr.json()["alert_tag"]["id"], "tag")
        await pair("tag: link missing", "DELETE", f"{P}/alert/tag", ana, lambda s: {"alert_id": ids["a1"], "tag_id": lid(s, "tag")})
        await pair("tag: delete", "DELETE", f"{P}/alert/tag", ana, lambda s: {"alert_id": W2(s), "tag_id": lid(s, "tag")})
        await pair("tag: delete again", "DELETE", f"{P}/alert/tag", ana, lambda s: {"alert_id": W2(s), "tag_id": lid(s, "tag")})
    await pair("tag: shared tag still linked elsewhere", "DELETE", f"{P}/alert/tag", adm, {"alert_id": ids["a2"], "tag_id": ids["tag_t2"]})

    print("\n=== incidents writes: verdict state ===")
    both_ids = [lid("p", "w2"), lid("r", "w2"), b1, 999999999, lid("p", "w2")]
    for who in ("admin", "analyst", "nobody"):
        await pair(f"verdict-state ({who})", "POST", f"{P}/alerts/verdict-state", tok[who], {"alert_ids": both_ids}, exact=True)
    await pair("verdict-state: empty", "POST", f"{P}/alerts/verdict-state", adm, {"alert_ids": []})
    await pair("verdict-state: too many", "POST", f"{P}/alerts/verdict-state", adm, {"alert_ids": list(range(501))})

    print("\n=== incidents writes: cases ===")
    await pair("case create: errors (query + body)", "POST", f"{P}/case/create?template_id=abc", ana, {"case_name": 1})
    await pair(
        "case create: another tenant",
        "POST",
        f"{P}/case/create",
        ana,
        {"case_name": "c", "case_description": "d", "case_creation_time": "2026-03-05", "case_status": "OPEN", "customer_code": CUST_B},
    )
    await pair(
        "case create: portal, no customer",
        "POST",
        f"{P}/case/create",
        portal,
        {"case_name": "c", "case_description": "d", "case_creation_time": "2026-03-05", "case_status": "OPEN"},
    )
    tmpl = ids[f"tmpl-cs-{SFX}"]
    for key, query, body in (
        ("c1", f"?template_id={tmpl}", {"severity": "High"}),
        ("c2", "", {}),
        ("c3", "?template_id=999999999", {}),
    ):
        b = {
            "case_name": f"Write case {key} {SFX}",
            "case_description": "d",
            "case_creation_time": "2026-03-05T09:00:00+01:00",
            "case_status": "OPEN",
            "customer_code": CUST_A,
            "assigned_to": ANALYST,
            **body,
        }
        rp = await call("p", "POST", f"{P}/case/create{query}", ana, b)
        rr = await call("r", "POST", f"{P}/case/create{query}", ana, b)
        if rp.status_code == rr.status_code == 200:
            label(key, rp.json()["case"]["id"], rr.json()["case"]["id"], "case")
        n1, n2 = norm(body_of(rp), L["p"]), norm(body_of(rr), L["r"])
        check(f"case create {key} [{rp.status_code}]", rp.status_code == rr.status_code and n1 == n2, f"{n1}\n        {n2}")
        if key in ID["p"]:
            await same_rows(f"case create {key}: timeline", lambda s, k=key: events_of(lid(s, k), L[s]))
            await same_rows(f"case create {key}: tasks", lambda s, k=key: tasks_of(lid(s, k), L[s]))
            await same_rows(f"case create {key}: audit", lambda s, k=key: audit_of("case", lid(s, k), L[s]))
            await same_tracking(f"case create {key}", "case", key)
    C1 = lambda s: lid(s, "c1")  # noqa: E731
    C2 = lambda s: lid(s, "c2")  # noqa: E731

    await pair(
        "case comment: create",
        "POST",
        f"{P}/case/comment",
        ana,
        lambda s: {"case_id": C1(s), "comment": "x" * 150, "user_name": "spoof"},
    )
    found = await rows("SELECT id FROM incident_management_case_comment WHERE case_id = :c ORDER BY id DESC LIMIT 1", c=lid("p", "c1"))
    found_r = await rows("SELECT id FROM incident_management_case_comment WHERE case_id = :c ORDER BY id DESC LIMIT 1", c=lid("r", "c1"))
    if found and found_r:
        label("ccm", found[0]["id"], found_r[0]["id"], "comment")
        await pair(
            "case comment: edit",
            "PUT",
            f"{P}/case/comment",
            ana,
            lambda s: {"case_id": C1(s), "comment_id": lid(s, "ccm"), "comment": "new", "user_name": "x", "created_at": "2026-01-01"},
        )
        await pair(
            "case comment: edit, wrong case",
            "PUT",
            f"{P}/case/comment",
            ana,
            lambda s: {"case_id": C2(s), "comment_id": lid(s, "ccm"), "comment": "new", "user_name": "x", "created_at": "2026-01-01"},
        )
        await pair("case comment: delete by portal", "DELETE", lambda s: f"{P}/case/comment/{lid(s, 'ccm')}", portal)
        await pair("case comment: delete", "DELETE", lambda s: f"{P}/case/comment/{lid(s, 'ccm')}", ana)
    await pair("case comment: another tenant", "POST", f"{P}/case/comment", ana, {"case_id": ids["cb1"], "comment": "x", "user_name": "x"})

    print("\n=== incidents writes: links ===")
    await pair("link: another tenant's alert", "POST", f"{P}/case/alert-link", ana, lambda s: {"case_id": C1(s), "alert_id": b1})
    await pair("link w2", "POST", f"{P}/case/alert-link", ana, lambda s: {"case_id": C1(s), "alert_id": W2(s)})
    await pair("link w2 again", "POST", f"{P}/case/alert-link", ana, lambda s: {"case_id": C1(s), "alert_id": W2(s)})
    await same_rows("link: tasks", lambda s: tasks_of(C1(s), L[s]))
    await same_tracking("link: case re-targeted", "case", "c1")
    await pair("links: bulk", "POST", f"{P}/case/alert-links", ana, lambda s: {"case_id": C2(s), "alert_ids": [lid(s, "w3"), W1(s)]})
    await pair("links: bulk, already linked", "POST", f"{P}/case/alert-links", ana, lambda s: {"case_id": C2(s), "alert_ids": [W1(s)]})
    await pair("links: bulk, another tenant", "POST", f"{P}/case/alert-links", ana, lambda s: {"case_id": C2(s), "alert_ids": [b1]})
    await pair("links: portal scope", "POST", f"{P}/case/alert-links", portal, {"case_id": 1, "alert_ids": []})
    await same_rows("links: tasks", lambda s: tasks_of(C2(s), L[s]))
    await same_rows("links: timeline", lambda s: events_of(C2(s), L[s]))
    await same_tracking("links: case re-targeted", "case", "c2")
    await pair("unlink: missing link", "POST", f"{P}/case/alert-unlink", ana, lambda s: {"case_id": C1(s), "alert_id": b1})
    await pair("unlink w3", "POST", f"{P}/case/alert-unlink", ana, lambda s: {"case_id": C2(s), "alert_id": lid(s, "w3")})
    await same_rows("unlink: tasks orphaned", lambda s: tasks_of(C2(s), L[s]))
    await same_rows("unlink: timeline", lambda s: events_of(C2(s), L[s]))

    print("\n=== incidents writes: case status cascade ===")
    await pair("case status: query + body errors", "PUT", f"{P}/case/status?force=maybe", ana, {"case_id": "x"})
    await pair(
        "case status: close with mandatory tasks open",
        "PUT",
        f"{P}/case/status",
        ana,
        lambda s: {"case_id": C1(s), "status": "CLOSED"},
    )
    await pair("case status: force close", "PUT", f"{P}/case/status?force=true", ana, lambda s: {"case_id": C1(s), "status": "CLOSED"})
    await same_tracking("case closed", "case", "c1")
    await same_tracking("case closed: alert", "alert", "w2")
    await pair("case status: reopen", "PUT", f"{P}/case/status", ana, lambda s: {"case_id": C1(s), "status": "OPEN"})
    await pair("case status: wait on customer", "PUT", f"{P}/case/status", ana, lambda s: {"case_id": C1(s), "status": "PENDING_CUSTOMER"})
    await pair(
        "case status: portal cannot wait",
        "PUT",
        f"{P}/case/status",
        portal,
        lambda s: {"case_id": C1(s), "status": "PENDING_CUSTOMER"},
    )
    await pair(
        "case: portal reply",
        "POST",
        f"{P}/case/comment",
        portal,
        lambda s: {"case_id": C1(s), "comment": "answer", "user_name": "x"},
    )
    await pair("case after the reply", "GET", lambda s: f"{P}/case/{C1(s)}", ana)
    await same_rows("case status: timeline", lambda s: events_of(C1(s), L[s]))
    await same_tracking("case after the reply", "case", "c1")
    await same_tracking("case after the reply: alert", "alert", "w2")

    print("\n=== incidents writes: case escalation, severity, assignment, customer ===")
    await pair("case escalate", "PUT", f"{P}/case/escalated", ana, lambda s: {"case_id": C2(s), "escalated": True})
    await pair("case escalate: portal scope", "PUT", f"{P}/case/escalated", portal, {"case_id": 1, "escalated": True})
    await pair("case severity: bad enum", "PUT", f"{P}/case/severity", ana, {"case_id": 1, "severity": "critical"})
    for sev in ("Critical", None):
        await pair(f"case severity {sev}", "PUT", f"{P}/case/severity", ana, lambda s, v=sev: {"case_id": C2(s), "severity": v})
        await same_tracking(f"case severity {sev}", "case", "c2")
    await pair("case assign: unknown user", "PUT", f"{P}/case/assigned-to", ana, lambda s: {"case_id": C2(s), "assigned_to": f"ghost{SFX}"})
    await pair("case assign", "PUT", f"{P}/case/assigned-to", ana, lambda s: {"case_id": C2(s), "assigned_to": ADMIN})
    await pair("case assign (portal)", "PUT", f"{P}/case/assigned-to", portal, lambda s: {"case_id": C2(s), "assigned_to": PORTAL})
    await same_rows("case assign: timeline", lambda s: events_of(C2(s), L[s]))
    await pair("case customer: params missing", "PUT", f"{P}/case/customer-code", adm)
    await pair("case customer: no settings", "PUT", lambda s: f"{P}/case/customer-code?case_id={C2(s)}&customer_code={CUST_P}", adm)
    await pair("case customer: analyst to B", "PUT", lambda s: f"{P}/case/customer-code?case_id={C2(s)}&customer_code={CUST_B}", ana)
    await pair("case customer: admin to B", "PUT", lambda s: f"{P}/case/customer-code?case_id={C2(s)}&customer_code={CUST_B}", adm)
    await pair("case customer: analyst cannot see it now", "GET", lambda s: f"{P}/case/{C2(s)}", ana)

    print("\n=== incidents writes: case from alert ===")
    rp = await call("p", "POST", f"{P}/alert", ana, alert_body(f"Write four {SFX}"))
    rr = await call("r", "POST", f"{P}/alert", ana, alert_body(f"Write four {SFX}"))
    if rp.status_code == rr.status_code == 200:
        label("w4", rp.json()["id"], rr.json()["id"], "alert")
        rp, rr = await pair("from alert", "POST", f"{P}/case/from-alert", ana, lambda s: {"alert_id": lid(s, "w4")})
        if rp.status_code == rr.status_code == 200:
            label("c4", rp.json()["case_alert_link"]["case_id"], rr.json()["case_alert_link"]["case_id"], "case")
            await pair("from alert: the case", "GET", lambda s: f"{P}/case/{lid(s, 'c4')}", ana, extra=("case_creation_time",))
            await same_rows("from alert: tasks", lambda s: tasks_of(lid(s, "c4"), L[s]))
            await same_rows("from alert: timeline", lambda s: events_of(lid(s, "c4"), L[s]))
            await same_tracking("from alert: case", "case", "c4")
        await pair("from alert: errors", "POST", f"{P}/case/from-alert?template_id=x", ana, {"alert_id": "y"})
        await pair("from alert: another tenant", "POST", f"{P}/case/from-alert", ana, {"alert_id": b1})
        await pair(
            "from alert, explicit template",
            "POST",
            f"{P}/case/from-alert?template_id={ids[f'tmpl-c-{SFX}']}",
            ana,
            lambda s: {"alert_id": lid(s, "w4")},
        )

    print("\n=== incidents writes: deletion ===")
    await pair("delete alert: linked to a case", "DELETE", lambda s: f"{P}/alert/{W2(s)}", ana)
    await pair("delete alert: another tenant", "DELETE", f"{P}/alert/{b1}", ana)
    await pair("delete alert: not an int", "DELETE", f"{P}/alert/x", ana)
    await pair("delete alert", "DELETE", lambda s: f"{P}/alert/{lid(s, 'w3')}", ana)
    await pair("delete alert again", "DELETE", lambda s: f"{P}/alert/{lid(s, 'w3')}", ana)
    for key in ("d1", "d2"):
        rp = await call("p", "POST", f"{P}/alert", ana, alert_body(f"Del {key} P{SFX}"))
        rr = await call("r", "POST", f"{P}/alert", ana, alert_body(f"Del {key} R{SFX}"))
        label(key, rp.json()["id"], rr.json()["id"], "alert")
        label_str(f"Del {key} P{SFX}", f"Del {key} R{SFX}", f"<{key} title>")
    await pair("bulk delete", "DELETE", f"{P}/alerts", ana, lambda s: {"alert_ids": [lid(s, "d1"), W2(s), b1, 999999999]})
    await pair("delete by title", "DELETE", lambda s: f"{P}/alerts/by-title/Del d2 {s.upper()}{SFX}", ana)
    await pair("delete by title: nothing", "DELETE", f"{P}/alerts/by-title/nothing-{SFX}", ana)
    await pair("delete by title: nobody", "DELETE", f"{P}/alerts/by-title/{SFX}", nobody)

    print("\n=== incidents writes: settings ===")
    TWIN = {"p": CUST_P, "r": CUST_R}
    label_str(CUST_P, CUST_R, "<CUST>")
    await pair("ai_trigger: query + body errors", "PUT", f"{P}/ai_trigger", adm, {"enabled": "x"})
    await pair("ai_trigger: unknown customer", "PUT", f"{P}/ai_trigger?customer_code=nope{SFX}", adm, {"customer_code": "x"})
    for enabled in (True, False):
        await pair(
            f"ai_trigger: put {enabled}",
            "PUT",
            lambda s: f"{P}/ai_trigger?customer_code={TWIN[s]}",
            adm,
            lambda s, e=enabled: {"customer_code": TWIN[s], "enabled": e},
        )
        await pair(
            f"notification: put {enabled}",
            "PUT",
            lambda s: f"{P}/notification?customer_code={TWIN[s]}",
            adm,
            lambda s, e=enabled: {"customer_code": TWIN[s], "shuffle_workflow_id": f"wf-{e}", "enabled": e},
        )
    r1, r2 = await call("p", "PUT", f"{P}/ai_trigger?customer_code={CUST_A}", ana, {"customer_code": CUST_B, "enabled": True}), None
    r2 = await call("r", "PUT", f"{P}/ai_trigger?customer_code={CUST_A}", ana, {"customer_code": CUST_B, "enabled": True})
    check(
        "DIFF_BY_DESIGN ai_trigger for another tenant (analyst): Python 200, Rust 403",
        r1.status_code == 200 and r2.status_code == 403,
        f"{r1.text[:200]} / {r2.text[:200]}",
    )
    r1 = await call(
        "p",
        "PUT",
        f"{P}/notification?customer_code={CUST_A}",
        ana,
        {"customer_code": CUST_B, "shuffle_workflow_id": "x", "enabled": True},
    )
    r2 = await call(
        "r",
        "PUT",
        f"{P}/notification?customer_code={CUST_A}",
        ana,
        {"customer_code": CUST_B, "shuffle_workflow_id": "x", "enabled": True},
    )
    check(
        "DIFF_BY_DESIGN notification for another tenant (analyst): Python 200, Rust 403",
        r1.status_code == 200 and r2.status_code == 403,
        f"{r1.text[:200]} / {r2.text[:200]}",
    )

    SRC = {"p": f"srcP{SFX}", "r": f"srcR{SFX}"}
    label_str(SRC["p"], SRC["r"], "<SRC>")

    def names(s, **kw):
        return {
            "field_names": ["f1", "f2", "f1"],
            "asset_name": "agent",
            "timefield_name": "ts",
            "alert_title_name": "title",
            "source": SRC[s],
            **kw,
        }

    await pair("dictionary: body errors", "POST", f"{P}/fields-assets-title-and-timefield", adm, {"field_names": "x"})
    await pair(
        "dictionary: create",
        "POST",
        f"{P}/fields-assets-title-and-timefield",
        adm,
        lambda s: names(s, ioc_field_names=["ip", "ip"]),
    )
    await pair("dictionary: read back", "GET", lambda s: f"{P}/fields-assets-title-and-timefield?source={SRC[s]}", adm)
    await pair(
        "dictionary: replace without IoCs (500)",
        "PUT",
        f"{P}/fields-assets-title-and-timefield",
        adm,
        lambda s: names(s, field_names=["f3"], asset_name="host"),
    )
    await pair("dictionary: after the failed replace", "GET", lambda s: f"{P}/fields-assets-title-and-timefield?source={SRC[s]}", adm)
    await pair(
        "dictionary: replace",
        "PUT",
        f"{P}/fields-assets-title-and-timefield",
        adm,
        lambda s: names(s, field_names=["f4", "f5"], ioc_field_names=["dst"]),
    )
    await pair("dictionary: after replace", "GET", lambda s: f"{P}/fields-assets-title-and-timefield?source={SRC[s]}", adm)
    await pair(
        "dictionary: delete with IoCs (500)",
        "DELETE",
        f"{P}/delete-fields-assets-title-and-timefield",
        adm,
        lambda s: names(s, field_names=["f4"], ioc_field_names=["dst"]),
    )
    await pair("dictionary: deprecated delete", "DELETE", lambda s: f"{P}/field_name/f4/{SRC[s]}", adm)
    await pair(
        "dictionary: delete",
        "DELETE",
        f"{P}/delete-fields-assets-title-and-timefield",
        adm,
        lambda s: names(s, field_names=["f4"], asset_name="host"),
    )
    await pair("dictionary: after delete", "GET", lambda s: f"{P}/fields-assets-title-and-timefield?source={SRC[s]}", adm)
    await pair("dictionary: configured source delete", "DELETE", lambda s: f"{P}/configured/sources/{SRC[s]}", adm)
    await pair("dictionary: after source delete", "GET", lambda s: f"{P}/fields-assets-title-and-timefield?source={SRC[s]}", adm)
    await pair("dictionary: duplicate rows (500)", "DELETE", f"{P}/field_name/rule_id/{SOURCE}", adm)
    await pair("dictionary: duplicate rows, configured source (500)", "DELETE", f"{P}/configured/sources/{SOURCE}", adm)

    await tasks_templates_tags(pair, call, label, label_str, lid, L, ID, tok, ids, body_of)
    await exclusions(pair, call, label, lid, L, ID, tok, ids, same_rows)


async def tasks_templates_tags(pair, call, label, label_str, lid, L, ID, tok, ids, body_of):
    adm, ana, portal = tok["admin"], tok["analyst"], tok["portal"]
    C1 = lambda s: lid(s, "c1")  # noqa: E731
    C3 = lambda s: lid(s, "c3")  # noqa: E731
    W2 = lambda s: lid(s, "w2")  # noqa: E731

    print("\n=== incidents writes: case tasks ===")
    await pair("task add: errors", "POST", f"{P}/case/x/tasks", ana, {"order_index": -1, "mandatory": "maybe"})
    await pair("task add: portal scope", "POST", lambda s: f"{P}/case/{C3(s)}/tasks", portal, {"title": "t"})
    await pair("task add: another tenant", "POST", f"{P}/case/{ids['cb1']}/tasks", ana, {"title": "t"})
    await pair("task add: alert not linked", "POST", lambda s: f"{P}/case/{C3(s)}/tasks", ana, lambda s: {"title": "t", "alert_id": W2(s)})
    rp, rr = await pair(
        "task add: case-wide",
        "POST",
        lambda s: f"{P}/case/{C3(s)}/tasks",
        ana,
        {"title": "Interview the user", "description": "d", "mandatory": True, "order_index": 3},
    )
    if rp.status_code == rr.status_code == 200 and rp.json()["task"] and rr.json()["task"]:
        label("t1", rp.json()["task"]["id"], rr.json()["task"]["id"], "task")
    await pair(
        "task add: on a linked alert",
        "POST",
        lambda s: f"{P}/case/{C1(s)}/tasks",
        ana,
        lambda s: {"title": "Check host", "alert_id": W2(s)},
    )
    T1 = lambda s: lid(s, "t1")  # noqa: E731
    await pair("task update: missing", "PATCH", f"{P}/case/tasks/999999999", ana, {"status": "DONE"})
    await pair("task update: bad status", "PATCH", lambda s: f"{P}/case/tasks/{T1(s)}", ana, {"status": "done"})
    await pair("task update: mandatory not necessary", "PATCH", lambda s: f"{P}/case/tasks/{T1(s)}", ana, {"status": "NOT_NECESSARY"})
    await pair(
        "task update: unknown assignee after a status change",
        "PATCH",
        lambda s: f"{P}/case/tasks/{T1(s)}",
        ana,
        {"status": "DONE", "evidence_comment": "e", "assigned_to": f" ghost{SFX} "},
    )
    await pair(
        "task update: done, evidence, assignee",
        "PATCH",
        lambda s: f"{P}/case/tasks/{T1(s)}",
        ana,
        {"status": "DONE", "evidence_comment": "y" * 150, "assigned_to": f" {ADMIN} "},
    )
    await pair(
        "task update: back to TODO, unassign",
        "PATCH",
        lambda s: f"{P}/case/tasks/{T1(s)}",
        ana,
        {"status": "TODO", "assigned_to": None, "evidence_comment": None},
    )
    await pair("task update: nothing sent", "PATCH", lambda s: f"{P}/case/tasks/{T1(s)}", ana, {})
    await pair("task update: portal scope", "PATCH", lambda s: f"{P}/case/tasks/{T1(s)}", portal, {})
    await pair("case tasks after updates", "GET", lambda s: f"{P}/case/{C3(s)}/tasks", ana)
    await pair(
        "apply template: alert not linked",
        "POST",
        lambda s: f"{P}/case/{C3(s)}/apply-template/{ids[f'tmpl-c-{SFX}']}?alert_id={W2(s)}",
        ana,
    )
    await pair("apply template: errors", "POST", f"{P}/case/x/apply-template/y?alert_id=z", ana)
    await pair("apply template", "POST", lambda s: f"{P}/case/{C3(s)}/apply-template/{ids[f'tmpl-c-{SFX}']}", ana)
    await pair(
        "apply template: on a linked alert",
        "POST",
        lambda s: f"{P}/case/{C1(s)}/apply-template/{ids[f'tmpl-c-{SFX}']}?alert_id={W2(s)}",
        ana,
    )
    await pair("apply template: missing template", "POST", lambda s: f"{P}/case/{C3(s)}/apply-template/999999999", ana)
    await pair("case tasks after the templates", "GET", lambda s: f"{P}/case/{C3(s)}/tasks", ana)
    await pair("case timeline after the tasks", "GET", lambda s: f"{P}/case/{C3(s)}/timeline", ana)
    await pair("task delete", "DELETE", lambda s: f"{P}/case/tasks/{T1(s)}", ana)
    await pair("task delete again", "DELETE", lambda s: f"{P}/case/tasks/{T1(s)}", ana)

    print("\n=== incidents writes: case templates ===")
    CT = "/api/incidents/case_templates"
    TW = {"p": f"srcP{SFX}", "r": f"srcR{SFX}"}  # labelled "<SRC>" by the dictionary section

    def tmpl(s, **kw):
        return {
            "name": f"Twin template {SFX}",
            "description": "playbook",
            "customer_code": CUST_A,
            "source": TW[s],
            "is_default": True,
            "tasks": [{"title": "Second", "order_index": 2, "mandatory": True}, {"title": "First", "guidelines": "g"}],
            **kw,
        }

    await pair("templates: portal scope", "GET", CT, portal)
    await pair("templates: list, bad bool", "GET", f"{CT}?include_global=maybe", adm)
    await pair("template create: errors", "POST", CT, ana, {"name": "x" * 256, "tasks": [{"order_index": -1}, 5]})
    await pair("template create: half a match pair", "POST", CT, ana, lambda s: tmpl(s, match_field="f"))
    rp, rr = await pair("template create", "POST", CT, ana, tmpl)
    if rp.status_code == rr.status_code == 200 and rp.json()["template"] and rr.json()["template"]:
        label("tp1", rp.json()["template"]["id"], rr.json()["template"]["id"], "template")
    rp, rr = await pair("template create: second default of the scope", "POST", CT, ana, lambda s: tmpl(s, tasks=[]))
    if rp.status_code == rr.status_code == 200 and rp.json()["template"] and rr.json()["template"]:
        label("tp2", rp.json()["template"]["id"], rr.json()["template"]["id"], "template")
    TP1 = lambda s: lid(s, "tp1")  # noqa: E731
    await pair("template: first one demoted", "GET", lambda s: f"{CT}/{TP1(s)}", ana)
    await pair("template: missing", "GET", f"{CT}/999999999", ana)
    await pair("template: not an int", "GET", f"{CT}/abc", ana)
    for q in (f"customer_code={CUST_A}", f"customer_code={CUST_A}&source={SOURCE}&include_global=false", f"source=nope{SFX}"):
        await pair(f"templates: list {q}", "GET", f"{CT}?{q}", adm, exact=True)
    await pair("templates: list everything", "GET", CT, adm, exact=True)
    # DIFF_BY_DESIGN: a template scoped to another customer is that tenant's.
    tb = ids[f"tmpl-b-{SFX}"]
    r1, r2 = await call("p", "GET", f"{CT}/{tb}", ana), await call("r", "GET", f"{CT}/{tb}", ana)
    check(
        "DIFF_BY_DESIGN another tenant's template (analyst): Python returns it, Rust as missing",
        r1.json()["success"] and r2.json() == {"template": None, "success": False, "message": f"Template id={tb} not found"},
        f"{r1.text[:200]} / {r2.text[:200]}",
    )
    r1, r2 = await call("p", "GET", CT, ana), await call("r", "GET", CT, ana)
    py_ids = [t["id"] for t in r1.json()["templates"]]
    rs_ids = [t["id"] for t in r2.json()["templates"]]
    check(
        "DIFF_BY_DESIGN template list (analyst): Python lists other tenants', Rust drops them, order kept",
        tb in py_ids and tb not in rs_ids and rs_ids == [i for i in py_ids if i in rs_ids],
        f"{py_ids} / {rs_ids}",
    )
    r2 = await call("r", "POST", CT, ana, {"name": "x", "customer_code": CUST_B})
    check(
        "DIFF_BY_DESIGN template for another tenant (analyst): Rust 403",
        r2.status_code == 403,
        r2.text[:200],
    )
    r2 = await call("r", "PATCH", f"{CT}/{tb}", ana, {"name": "x"})
    check("DIFF_BY_DESIGN edit another tenant's template (analyst): Rust as missing", r2.json()["success"] is False, r2.text[:200])
    r2 = await call("r", "POST", f"{P}/case/{C3('r')}/apply-template/{tb}", ana)
    check(
        "DIFF_BY_DESIGN apply another tenant's template (analyst): Rust copies nothing",
        r2.status_code == 200 and r2.json()["tasks_added"] == 0,
        r2.text[:200],
    )
    await pair("template update: half a match pair", "PATCH", lambda s: f"{CT}/{TP1(s)}", ana, {"match_value": "1"})
    await pair("template update: errors", "PATCH", lambda s: f"{CT}/{TP1(s)}", ana, {"is_default": "x", "name": 5})
    await pair(
        "template update",
        "PATCH",
        lambda s: f"{CT}/{TP1(s)}",
        ana,
        {"name": f"Renamed {SFX}", "description": None, "is_default": True, "match_field": "rule_id", "match_value": "5"},
    )
    await pair("template update: missing", "PATCH", f"{CT}/999999999", ana, {"name": "x"})
    await pair("template: second one demoted", "GET", lambda s: f"{CT}/{lid(s, 'tp2')}", ana)
    rp, rr = await pair("template task add", "POST", lambda s: f"{CT}/{TP1(s)}/tasks", ana, {"title": "Third", "order_index": 1})
    if rp.status_code == rr.status_code == 200 and rp.json()["task"] and rr.json()["task"]:
        label("tt1", rp.json()["task"]["id"], rr.json()["task"]["id"], "ttask")
    await pair("template task add: missing template", "POST", f"{CT}/999999999/tasks", ana, {"title": "x"})
    await pair(
        "template task update",
        "PATCH",
        lambda s: f"{CT}/tasks/{lid(s, 'tt1')}",
        ana,
        {"title": "Third!", "mandatory": True, "description": None},
    )
    await pair("template task update: missing", "PATCH", f"{CT}/tasks/999999999", ana, {"title": "x"})
    tasks_p = (await call("p", "GET", f"{CT}/{TP1('p')}", ana)).json()["template"]["tasks"]
    tasks_r = (await call("r", "GET", f"{CT}/{TP1('r')}", ana)).json()["template"]["tasks"]
    for i, (tp, tr) in enumerate(zip(tasks_p, tasks_r)):
        label(f"tt{i}x", tp["id"], tr["id"], "ttask")
    await pair("template reorder: foreign ids", "POST", lambda s: f"{CT}/{TP1(s)}/tasks/reorder", ana, [999999999, 5])
    await pair("template reorder: not a list", "POST", lambda s: f"{CT}/{TP1(s)}/tasks/reorder", ana, {"ids": []})
    await pair(
        "template reorder",
        "POST",
        lambda s: f"{CT}/{TP1(s)}/tasks/reorder",
        ana,
        lambda s: [lid(s, "tt2x"), lid(s, "tt0x"), lid(s, "tt2x")],
    )
    await pair("template reorder: missing", "POST", f"{CT}/999999999/tasks/reorder", ana, [])
    # A case built from the template keeps its tasks when the template goes.
    await pair("apply the twin template", "POST", lambda s: f"{P}/case/{C3(s)}/apply-template/{TP1(s)}", ana)
    await pair("template task delete", "DELETE", lambda s: f"{CT}/tasks/{lid(s, 'tt1')}", ana)
    await pair("template task delete: missing", "DELETE", f"{CT}/tasks/999999999", ana)
    await pair("template delete", "DELETE", lambda s: f"{CT}/{TP1(s)}", ana)
    await pair("template delete: missing", "DELETE", f"{CT}/999999999", ana)
    await pair("case tasks keep their snapshots", "GET", lambda s: f"{P}/case/{C3(s)}/tasks", ana)

    print("\n=== incidents writes: tag access ===")
    TA = "/api/incidents/tag_access"
    async with AsyncSession(async_engine) as s_:
        configured = (await s_.execute(text("SELECT COUNT(*) FROM incident_management_tag_access_settings"))).scalar_one()
    if configured:
        print("  SKIP  tag access writes: incident_management_tag_access_settings already configured")
        return
    users = {"p": USER_P, "r": USER_R}
    uid = {}
    async with AsyncSession(async_engine) as s_:
        for side, name in users.items():
            uid[side] = (await s_.execute(text("SELECT id FROM `user` WHERE username = :n"), {"n": name})).scalar_one()
    label("user", uid["p"], uid["r"], "user")
    label_str(USER_P, USER_R, "<user>")
    t1, t2 = ids["tag_t1"], ids["tag_t2"]
    try:
        await pair("settings: analyst", "GET", f"{TA}/settings", ana)
        await pair("settings: created on first read (Rust first)", "GET", f"{TA}/settings", adm, order=("r", "p"))
        await pair(
            "settings: default_tag without id (analyst: 400 first)",
            "PUT",
            f"{TA}/settings",
            ana,
            {"enabled": True, "untagged_alert_behavior": "default_tag"},
        )
        await pair("settings: errors", "PUT", f"{TA}/settings", adm, {"untagged_alert_behavior": "never"})
        await pair("settings: analyst", "PUT", f"{TA}/settings", ana, {"enabled": True})
        await pair(
            "settings: unknown tag",
            "PUT",
            f"{TA}/settings",
            adm,
            {"enabled": True, "untagged_alert_behavior": "default_tag", "default_tag_id": 999999999},
        )
        await pair(
            "settings: put",
            "PUT",
            f"{TA}/settings",
            adm,
            {"enabled": False, "untagged_alert_behavior": "default_tag", "default_tag_id": t1},
        )
        await pair("tags (portal)", "GET", f"{TA}/tags", portal, exact=True)
        await pair("tags: no token", "GET", f"{TA}/tags", None)
        await pair("user access: analyst", "GET", lambda s: f"{TA}/user/{uid[s]}", ana)
        await pair("user access: missing user", "GET", f"{TA}/user/999999999", adm)
        await pair("user access: errors", "PUT", f"{TA}/user/x", adm, {"tag_ids": ["y"]})
        await pair("user access: unknown tag", "PUT", lambda s: f"{TA}/user/{uid[s]}", adm, {"tag_ids": [t1, 999999999]})
        await pair("user access: set", "PUT", lambda s: f"{TA}/user/{uid[s]}", adm, {"tag_ids": [t2, t1, t2]})
        await pair("user access: add", "POST", lambda s: f"{TA}/user/{uid[s]}/add", adm, {"tag_ids": [t1, t1]})
        await pair("user access: get", "GET", lambda s: f"{TA}/user/{uid[s]}", adm)
        await pair("user access: remove", "POST", lambda s: f"{TA}/user/{uid[s]}/remove", adm, {"tag_ids": [t2]})
        await pair("user access: remove nothing", "POST", lambda s: f"{TA}/user/{uid[s]}/remove", adm, {"tag_ids": []})
        await pair("user access: set empty", "PUT", lambda s: f"{TA}/user/{uid[s]}", adm, {"tag_ids": []})
        await pair("role access: missing role", "GET", f"{TA}/role/999", adm)
        for step, method, path_, body in (
            ("set", "PUT", f"{TA}/role/3", {"tag_ids": [t2, t1]}),
            ("add", "POST", f"{TA}/role/3/add", {"tag_ids": [t1]}),
            ("get", "GET", f"{TA}/role/3", None),
            ("remove", "POST", f"{TA}/role/3/remove", {"tag_ids": [t1]}),
        ):
            await pair(f"role access: {step}", method, path_, adm, body, exact=True)
        for enabled in (False, True):
            await pair(
                f"settings: enabled={enabled}",
                "PUT",
                f"{TA}/settings",
                adm,
                {"enabled": enabled, "untagged_alert_behavior": "admin_only"},
            )
            for who in ("admin", "analyst", "portal", "tagged", "responder", "nobody"):
                await pair(f"me ({who}, rbac={enabled})", "GET", f"{TA}/me", tok[who], exact=True)
    finally:
        async with AsyncSession(async_engine) as s_:
            await s_.execute(text("DELETE FROM incident_management_tag_access_settings"))
            await s_.execute(text("DELETE FROM role_tag_access WHERE role_id = 3 AND tag_id IN (:a, :b)"), {"a": t1, "b": t2})
            await s_.execute(text("DELETE FROM user_tag_access WHERE tag_id IN (:a, :b)"), {"a": t1, "b": t2})
            await s_.commit()


async def exclusions(pair, call, label, lid, L, ID, tok, ids, same_rows):
    """The Velociraptor Sigma exclusion rules of /api/incidents/alerts (CRUD and toggle)."""
    adm, ana, portal, nobody = tok["admin"], tok["analyst"], tok["portal"], tok["nobody"]
    A = "/api/incidents/alerts"
    X = f"{A}/create/velo-sigma/exclusion"
    T = lambda i: f"{A}/velo-sigma/exclusion/{i}/toggle"  # noqa: E731
    E = lambda key: lambda s: lid(s, key)  # noqa: E731

    async def row_of(side, key):
        found = await rows(
            "SELECT name, description, channel, title, field_matches IS NULL AS sql_null, CAST(field_matches AS CHAR) AS fm, "
            "customer_code, created_by, last_matched_at, match_count, enabled, source_alert_id, source_case_id "
            "FROM incident_management_velo_sigma_exclusion WHERE id = :i",
            i=lid(side, key),
        )
        return [norm(r, L[side]) for r in found]

    async def link_comments(side, alert_key):
        found = await rows(
            "SELECT comment, user_name FROM incident_management_comment WHERE alert_id = :a AND comment LIKE 'Exclusion rule created%' "
            "ORDER BY id",
            a=lid(side, alert_key),
        )
        out = []
        for c in found:
            text_ = c["comment"]
            for excl_id, lab in L[side].get("excl", {}).items():
                text_ = text_.replace(f"#{excl_id} ", f"#{lab} ")
            out.append((text_, c["user_name"]))
        return out

    print("\n=== incidents alerts: Velociraptor Sigma exclusion rules ===")
    await pair("exclusions: no token", "GET", X, None, exact=True)
    await pair("exclusions: portal scope", "GET", X, portal, exact=True)
    await pair("exclusions: query errors", "GET", f"{X}?skip=x&limit=1.5&enabled_only=maybe&source_alert_id=z", ana, exact=True)
    await pair("exclusion create: malformed JSON, no token", "POST", X, None, raw=b'{"name": ', exact=True)
    await pair("exclusion create: empty body", "POST", X, ana, {}, exact=True)
    await pair(
        "exclusion create: body errors",
        "POST",
        X,
        ana,
        {"name": 5, "field_matches": [1], "enabled": "x", "source_alert_id": "y", "created_by": 3},
        exact=True,
    )
    await pair("exclusion create: not an object", "POST", X, ana, [1], exact=True)
    await pair("exclusion create: missing source alert", "POST", X, ana, {"name": "x", "source_alert_id": 999999999}, exact=True)
    await pair("exclusion create: another tenant's alert", "POST", X, ana, {"name": "x", "source_alert_id": ids["b1"]}, exact=True)
    await pair("exclusion create: missing source case", "POST", X, ana, {"name": "x", "source_case_id": 999999999}, exact=True)
    await pair("exclusion create: another tenant's case", "POST", X, ana, {"name": "x", "source_case_id": ids["cb1"]}, exact=True)
    await pair("exclusion: not an int", "GET", f"{X}/abc", ana, exact=True)
    await pair("exclusion: missing", "GET", f"{X}/999999999", ana, exact=True)
    await pair("exclusion update: path and body errors", "PATCH", f"{X}/abc", ana, {"enabled": "x", "field_matches": "s"}, exact=True)
    await pair("exclusion update: missing", "PATCH", f"{X}/999999999", ana, {"name": "x"}, exact=True)
    await pair("exclusion delete: missing", "DELETE", f"{X}/999999999", ana, exact=True)
    await pair("exclusion toggle: missing", "POST", T(999999999), ana, exact=True)
    await pair("exclusion toggle: not an int", "POST", T("x"), ana, exact=True)

    has_w4 = "w4" in ID["p"] and "c4" in ID["p"]
    first = {
        "name": f"Excl one {SFX}",
        "description": "benign updater",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "title": "Proc Access",
        "field_matches": {"Image": "C:\\u.exe", "CommandLine": "u --check", "zeta": 1, "a": {"b": [1, 2.5, None]}},
        "customer_code": CUST_A,
        "created_by": "spoofed",
    }
    rp, rr = await pair(
        "exclusion create (in context)",
        "POST",
        X,
        ana,
        lambda s: {**first, **({"source_alert_id": lid(s, "w4"), "source_case_id": lid(s, "c4")} if has_w4 else {})},
    )
    if not (rp.status_code == rr.status_code == 200):
        return
    label("x1", rp.json()["exclusion_response"]["id"], rr.json()["exclusion_response"]["id"], "excl")
    await same_rows("exclusion create: stored row", lambda s: row_of(s, "x1"))
    if has_w4:
        await same_rows("exclusion create: link comment on the alert", lambda s: link_comments(s, "w4"))
    rp, rr = await pair("exclusion create: minimal (admin)", "POST", X, adm, {"name": f"Excl two {SFX}"})
    label("x2", rp.json()["exclusion_response"]["id"], rr.json()["exclusion_response"]["id"], "excl")
    await same_rows("exclusion create: minimal, stored row (JSON null)", lambda s: row_of(s, "x2"))
    rp, rr = await pair(
        "exclusion create: empty dict, disabled, empty customer",
        "POST",
        X,
        ana,
        {"name": f"Excl three {SFX}", "field_matches": {}, "enabled": False, "customer_code": ""},
    )
    label("x3", rp.json()["exclusion_response"]["id"], rr.json()["exclusion_response"]["id"], "excl")
    await same_rows("exclusion create: empty dict, stored row", lambda s: row_of(s, "x3"))
    await pair("exclusion: get", "GET", lambda s: f"{X}/{E('x1')(s)}", ana)
    if has_w4:
        await pair("exclusions: by source alert", "GET", lambda s: f"{X}?source_alert_id={lid(s, 'w4')}", ana)
        await pair("exclusions: by source case", "GET", lambda s: f"{X}?source_case_id={lid(s, 'c4')}&enabled_only=true", ana)
    await pair("exclusions: list (admin)", "GET", f"{X}?limit=1000", adm, exact=True)
    await pair("exclusions: enabled only, paged", "GET", f"{X}?enabled_only=yes&skip=1&limit=2", adm, exact=True)
    await pair("exclusions: limit 0", "GET", f"{X}?limit=0", adm, exact=True)
    await pair("exclusions: negative skip (500)", "GET", f"{X}?skip=-1", adm, exact=True)
    await pair(
        "exclusion update",
        "PATCH",
        lambda s: f"{X}/{E('x1')(s)}",
        ana,
        {"name": f"Excl one renamed {SFX}", "description": None, "field_matches": {"Image": "C:\\v.exe"}, "enabled": False},
    )
    await same_rows("exclusion update: stored row", lambda s: row_of(s, "x1"))
    await pair("exclusion update: field_matches null", "PATCH", lambda s: f"{X}/{E('x1')(s)}", ana, {"field_matches": None})
    await same_rows("exclusion update: JSON null stored", lambda s: row_of(s, "x1"))
    await pair("exclusion update: nothing", "PATCH", lambda s: f"{X}/{E('x1')(s)}", ana, {})
    await pair("exclusion update: name null (500)", "PATCH", lambda s: f"{X}/{E('x1')(s)}", ana, {"name": None})
    await pair("exclusion update: same values", "PATCH", lambda s: f"{X}/{E('x3')(s)}", ana, {"field_matches": {}, "enabled": False})
    await same_rows("exclusion update: same values, stored row", lambda s: row_of(s, "x3"))
    await pair("exclusion toggle", "POST", lambda s: T(E("x1")(s)), ana)
    await pair("exclusion toggle back", "POST", lambda s: T(E("x1")(s)), ana)
    await pair("exclusion delete", "DELETE", lambda s: f"{X}/{E('x3')(s)}", ana)
    await pair("exclusion delete again", "DELETE", lambda s: f"{X}/{E('x3')(s)}", ana)

    # DIFF_BY_DESIGN: a rule scoped to a customer is that tenant's.
    async with AsyncSession(async_engine) as s_:
        rule_b = (
            await s_.execute(
                text(
                    "INSERT INTO incident_management_velo_sigma_exclusion (name, customer_code, created_by, created_at, match_count, "
                    "enabled, field_matches) VALUES (:n, :c, 'admin', UTC_TIMESTAMP(), 0, 1, 'null')",
                ),
                {"n": f"Excl B {SFX}", "c": CUST_B},
            )
        ).lastrowid
        await s_.commit()
    r1, r2 = await call("p", "GET", f"{X}/{rule_b}", ana), await call("r", "GET", f"{X}/{rule_b}", ana)
    check(
        "DIFF_BY_DESIGN another tenant's exclusion rule (analyst): Python returns it, Rust 404",
        r1.status_code == 200 and r2.status_code == 404 and r2.json() == {"success": False, "message": "Exclusion rule not found"},
        f"{r1.status_code} {r1.text[:200]} / {r2.status_code} {r2.text[:200]}",
    )
    r1, r2 = await call("p", "GET", f"{X}?limit=1000", ana), await call("r", "GET", f"{X}?limit=1000", ana)
    py_ids = [e["id"] for e in r1.json()["exclusions"]]
    rs_ids = [e["id"] for e in r2.json()["exclusions"]]
    check(
        "DIFF_BY_DESIGN exclusion list (analyst): Python lists other tenants', Rust drops them, order and total follow",
        rule_b in py_ids
        and rule_b not in rs_ids
        and lid("r", "x2") in rs_ids
        and rs_ids == [i for i in py_ids if i in rs_ids]
        and r2.json()["pagination"]["total"] == len(rs_ids),
        f"{py_ids} / {rs_ids}",
    )
    r2 = await call("r", "GET", f"{X}?limit=1000", nobody)
    check(
        "DIFF_BY_DESIGN exclusion list (unassigned analyst): Rust only the shared rules",
        r2.status_code == 200 and all(e["customer_code"] in (None, "") for e in r2.json()["exclusions"]),
        r2.text[:300],
    )
    for name, method, path_, body in (
        ("edit", "PATCH", f"{X}/{rule_b}", {"enabled": False}),
        ("toggle", "POST", T(rule_b), None),
        ("delete", "DELETE", f"{X}/{rule_b}", None),
    ):
        r2 = await call("r", method, path_, ana, body)
        check(f"DIFF_BY_DESIGN {name} another tenant's exclusion rule (analyst): Rust 404", r2.status_code == 404, r2.text[:200])
    left = await rows("SELECT enabled FROM incident_management_velo_sigma_exclusion WHERE id = :i", i=rule_b)
    check("DIFF_BY_DESIGN another tenant's exclusion rule is untouched by Rust", left == [{"enabled": 1}], str(left))
    r2 = await call("r", "POST", X, ana, {"name": "x", "customer_code": CUST_B})
    check(
        "DIFF_BY_DESIGN exclusion rule for another tenant (analyst): Python 200, Rust 403",
        r2.status_code == 403
        and r2.json() == {"success": False, "message": f"Access denied to customer {CUST_B} - insufficient customer permissions"},
        r2.text[:200],
    )
    r2 = await call("r", "PATCH", f"{X}/{lid('r', 'x1')}", ana, {"customer_code": CUST_B})
    check("DIFF_BY_DESIGN move an exclusion rule to another tenant (analyst): Rust 403", r2.status_code == 403, r2.text[:200])


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
