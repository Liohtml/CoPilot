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
import json
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
ADMIN, ANALYST, PORTAL = f"inc_admin{SFX}", f"inc_analyst{SFX}", f"inc_portal{SFX}"
NOBODY, TAGGED, RESPONDER = f"inc_nobody{SFX}", f"inc_tagged{SFX}", f"inc_resp{SFX}"
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

        for c in (CUST_A, CUST_B):
            await ins("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())", c=c)
        for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (NOBODY, 2), (TAGGED, 2), (RESPONDER, 5)):
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

    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
