"""Parity of the Rust notification module with this backend — NOT collected by pytest
(needs a live MySQL and a running Rust binary; run by scripts/rust-parity.sh).

Sends the same requests to the real FastAPI notification router (in-process) and to
the Rust service (`crates/copilot-notifications`) over HTTP, both on the same
disposable database, and compares status codes, JSON bodies (key order included),
the rows each write leaves, and every outbound request a delivery makes: webhook,
Resend and Shuffle all point at one recorder, so the bytes, headers and URLs each
backend sends are compared too. Teams URLs must be `https://`, so its deliveries are
compared through their failure (a closed port) and the card itself is pinned by
`crates/copilot-notifications/src/teams_vectors.json`.

Writes that create rows run once per backend (masked ids and timestamps); a dispatch
uses one alert per backend (alert ids are normalised) so the two never share a
dispatch-log key. Deliberate differences are asserted as such (DIFF_BY_DESIGN).

    PARITY_SUITES=tests/e2e/rust_parity_notifications_e2e.py scripts/rust-parity.sh
"""

import asyncio
import datetime
import json
import os
import re
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ.setdefault("COPILOT_URL", "https://copilot.parity.test/")

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.db.db_session import async_engine  # noqa: E402

RUST = os.environ.get("RUST_BASE_URL", "http://127.0.0.1:5199")
SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"NOT_A{SFX}", f"NOT_B{SFX}"
ADMIN, ANALYST, PORTAL = f"not_admin{SFX}", f"not_analyst{SFX}", f"not_portal{SFX}"
VOLATILE = {
    "id",
    "created_at",
    "updated_at",
    "last_dispatched_at",
    "last_used_at",
    "dispatched_at",
    "latency_ms",
}
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def mask(value, extra=()):
    """Volatile values replaced; dicts become key-ordered pair lists so the
    comparison covers field order too."""
    keys = VOLATILE | set(extra)
    if isinstance(value, dict):
        return [[k, "<v>" if k in keys and v is not None else mask(v, extra)] for k, v in value.items()]
    if isinstance(value, list):
        return [mask(v, extra) for v in value]
    return value


# --- The outbound recorder ---------------------------------------------------------
# Webhook URLs, the Resend connector and the Shuffle connector all point here. Every
# request is kept; RESPONSES picks the answer by (method, path prefix).
CAPTURED = []
RESPONSES = {
    ("POST", "/hook/fail"): (500, "text/plain", b"upstream exploded"),
    ("POST", "/hook/"): (200, "text/plain", b"ok"),
    ("POST", "/emails"): (200, "application/json", b'{"id": "msg-parity", "object": "email"}'),
    (
        "GET",
        "/api/v1/orgs",
    ): (
        200,
        "application/json",
        json.dumps(
            [
                {"id": "org-1", "name": "Acme", "role": "admin", "creator_org": "", "description": "Main"},
                {"id": "org-2", "name": "Sub", "creator_org": "org-1"},
                {"id": "", "name": "no id"},
                {"id": "org-3", "name": "Parent", "creator_org": "PARENT_ORG_ID", "role": None},
            ],
        ).encode(),
    ),
    (
        "GET",
        "/api/v1/apps",
    ): (
        200,
        "application/json",
        json.dumps(
            [
                {"id": "app-1", "name": "Slack", "description": "chat", "large_image": "data:x"},
                {"id": "app-2", "name": "Teams"},
                {"id": "app-3"},
            ],
        ).encode(),
    ),
    ("POST", "/api/v1/apps/app-fail/mcp"): (200, "application/json", b'{"success": false, "reason": "app error"}'),
    ("POST", "/api/v1/apps/app-401/mcp"): (401, "text/plain", b"bad key"),
    ("POST", "/api/v1/apps/"): (200, "application/json", b'{"success": true, "execution_id": "ex-parity"}'),
}
#: Headers a client adds on its own (and the stub's port).
TRANSPORT_HEADERS = {"host", "user-agent", "accept-encoding", "connection", "content-length", "transfer-encoding"}


class _Recorder(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items() if k.lower() not in TRANSPORT_HEADERS}
        CAPTURED.append({"method": self.command, "path": self.path, "headers": headers, "body": body})
        status, ctype, payload = 404, "text/plain", b"no stub"
        for (m, prefix), answer in RESPONSES.items():
            if m == self.command and self.path.startswith(prefix):
                status, ctype, payload = answer
                break
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = _handle  # noqa: N815 - http.server API

    def log_message(self, *args):
        pass


def start_recorder():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


#: An id inside text: not part of a longer number, a dotted quad, a ratio or a word (the
#: random hex suffix of a customer code holds digits too).
ID_PATTERN = r"(?<![0-9A-Za-z_.]){}(?![0-9A-Za-z_./])"


def normalised(captures, subs):
    """Captured requests with backend-specific values (alert ids) replaced."""
    out = []
    for c in captures:
        body = c["body"].decode("utf-8", "replace")
        path = c["path"]
        for old, new in subs:
            body = re.sub(ID_PATTERN.format(re.escape(str(old))), new, body)
            path = re.sub(ID_PATTERN.format(re.escape(str(old))), new, path)
        out.append({"method": c["method"], "path": path, "headers": dict(sorted(c["headers"].items())), "body": body})
    return out


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.notifications.routes.notifications import notifications_router

    api = APIRouter(prefix="/api")
    api.include_router(notifications_router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


async def sql(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        await s.commit()
        return r


async def rows(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        return [dict(m) for m in r.mappings().all()]


async def seed():
    for c in (CUST_A, CUST_B):
        await sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=c, n=f"{c} Corp")
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        await sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r)",
            n=name,
            e=f"{name}@parity.test",
            r=role,
        )
    for name in (ANALYST, PORTAL):
        await sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
            "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )
    alerts = {}
    for key, code, severity in (
        ("py", CUST_A, "High"),
        ("rs", CUST_A, "High"),
        ("b", CUST_B, "Low"),
        ("odd_py", CUST_A, "critical "),
        ("odd_rs", CUST_A, "critical "),
    ):
        r = await sql(
            "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
            "customer_code, source, escalated, severity) VALUES (:n, 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0, :s)",
            n="Mimikatz <on> dc01 & é" if code == CUST_A else "Beta alert",
            c=code,
            s=severity,
        )
        alerts[key] = r.lastrowid
    # Case ids well clear of every other number in a message, so substituting them
    # never touches anything else.
    top = (await rows("SELECT COALESCE(MAX(id), 0) AS n FROM incident_management_case"))[0]["n"]
    cases = {}
    for i, (key, code) in enumerate((("py", CUST_A), ("rs", CUST_A), ("b", CUST_B))):
        cases[key] = top + 50000 + i
        await sql(
            "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, "
            "customer_code, escalated) VALUES (:i, 'Case \"quoted\"', 'd', '2026-01-02 03:04:05', 'OPEN', :c, 0)",
            i=cases[key],
            c=code,
        )
    # An AI report per backend alert: a GFM table, an IOC, a newline-heavy summary.
    for key in ("py", "rs"):
        job = f"copilot-inv-{alerts[key]}-not{SFX}"
        await sql(
            "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, triggered_by, created_at) "
            "VALUES (:j, :a, :c, 'completed', 'webhook', '2026-01-02 03:04:05')",
            j=job,
            a=alerts[key],
            c=CUST_A,
        )
        r = report = await sql(
            "INSERT INTO ai_analyst_report (job_id, alert_id, customer_code, severity_assessment, summary, report_markdown, "
            "recommended_actions, created_at) VALUES (:j, :a, :c, 'High', 'Dumped creds.\nTwice.', :m, 'Isolate', "
            "'2026-01-02 03:04:05')",
            j=job,
            a=alerts[key],
            c=CUST_A,
            m="# Findings\n\n| IOC | Verdict |\n|:--|--:|\n| 203.0.113.7 | *bad* |\n\n> note <b>x</b>\n\n```\ncode & more\n```",
        )
        await sql(
            "INSERT INTO ai_analyst_ioc (report_id, alert_id, customer_code, ioc_value, ioc_type, vt_verdict, vt_score, "
            "details, created_at) VALUES (:r, :a, :c, '203.0.113.7', 'ip', 'malicious', '12/90', NULL, '2026-01-02 03:04:05')",
            r=r.lastrowid,
            a=alerts[key],
            c=CUST_A,
        )
        alerts["report_" + key] = report.lastrowid
    # The Resend and Shuffle connectors are global: absent until section E, before
    # either backend has read them (misses are never cached, hits are).
    await sql("DELETE FROM connectors WHERE connector_name IN ('Resend', 'Shuffle')")
    return alerts, cases


async def add_connector(name, url, key, extra=None):
    await sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_api_key, "
        "connector_configured, connector_verified, connector_accepts_host_only, connector_accepts_api_key, "
        "connector_accepts_username_password, connector_accepts_file, connector_accepts_extra_data, connector_extra_data, "
        "connector_enabled) VALUES (:n, '3', :u, UTC_TIMESTAMP(), :k, 1, 1, 0, 1, 0, 0, 1, :x, 1)",
        n=name,
        u=url,
        k=key,
        x=extra,
    )


ROUTE_COLUMNS = (
    "customer_code, name, `trigger`, channel, destination, min_severity, format_template, template_id, enabled, scope, "
    "recipient_mode, notify_on_self_assign, shuffle_integration_id, config, dispatch_count, created_by"
)
LOG_COLUMNS = (
    "customer_code, alert_id, `trigger`, status, error_message, payload_preview, provider_reference, entity_type, "
    "entity_id, dedupe_key, triggered_by, trigger_source"
)


async def main():
    stub = start_recorder()
    alerts, cases = await seed()
    a_py, a_rs = alerts["py"], alerts["rs"]
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=60)
    t_admin = token(ADMIN, ["admin"])
    t_analyst = token(ANALYST, ["analyst"])
    t_portal = token(PORTAL, ["customer_user"])
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731
    clients = {"py": py, "rs": rs}

    def body_of(r):
        try:
            return r.json()
        except ValueError:
            return r.text

    async def call(client, method, path, tok=None, body=None, raw=None, ctype="application/json"):
        kw = {"headers": H(tok)}
        if raw is not None:
            kw["content"] = raw
            kw["headers"] = {**kw["headers"], "Content-Type": ctype}
        elif body is not None:
            kw["json"] = body
        return await client.request(method, path, **kw)

    async def same(name, method, path, tok=None, body=None, raw=None, masked=False, extra=(), py_path=None):
        r1 = await call(py, method, py_path or path, tok, body, raw)
        r2 = await call(rs, method, path, tok, body, raw)
        b1, b2 = body_of(r1), body_of(r2)
        if masked:
            b1, b2 = mask(b1, extra), mask(b2, extra)
        else:
            b1, b2 = json.dumps(b1), json.dumps(b2)  # key order counts
        ok = r1.status_code == r2.status_code and b1 == b2
        check(
            f"{name} [{r1.status_code}]",
            ok,
            f"python {r1.status_code} {str(b1)[:900]}\n        rust   {r2.status_code} {str(b2)[:900]}",
        )
        return r1, r2

    async def each(method, path_of, tok=None, body_of_tag=None):
        """One request per backend (its own rows); returns both responses."""
        out = {}
        for tag, client in clients.items():
            body = body_of_tag(tag) if callable(body_of_tag) else body_of_tag
            out[tag] = await call(client, method, path_of(tag) if callable(path_of) else path_of, tok, body)
        return out

    def subst(v, subs):
        """Backend-specific ids (alerts, cases, integrations) replaced by markers."""
        if isinstance(v, dict):
            return {k: subst(x, subs) for k, x in v.items()}
        if isinstance(v, list):
            return [subst(x, subs) for x in v]
        if isinstance(v, int) and not isinstance(v, bool):
            return next((new for old, new in subs if old == v), v)
        if isinstance(v, str):
            return sub_text(v, subs)
        return v

    def same_each(name, out, extra=("route_id", "template_id", "shuffle_integration_id"), subs=None):
        b = {}
        for tag, r in out.items():
            v = body_of(r)
            if subs:
                v = subst(v, subs[tag])
            b[tag] = mask(v, extra)
        ok = out["py"].status_code == out["rs"].status_code and b["py"] == b["rs"]
        check(
            f"{name} [{out['py'].status_code}]",
            ok,
            f"python {out['py'].status_code} {json.dumps(b['py'])[:900]}\n        rust   {out['rs'].status_code} {json.dumps(b['rs'])[:900]}",
        )

    def sub_text(s, subs):
        for old, new in subs:
            s = re.sub(ID_PATTERN.format(re.escape(str(old))), new, s)
        return s

    async def outbound(name, run, subs=None, settle=None):
        """Run `run(tag, client)` per backend and compare what each sent."""
        got = {}
        responses = {}
        for tag, client in clients.items():
            CAPTURED.clear()
            responses[tag] = await run(tag, client)
            if settle:
                await settle(tag)
            got[tag] = normalised(list(CAPTURED), (subs or {}).get(tag, []))
        first = next((i for i, (x, y) in enumerate(zip(got["py"], got["rs"])) if x != y), None)
        check(
            f"{name}: outbound requests ({len(got['py'])})",
            got["py"] == got["rs"],
            f"paths python {[g['path'] for g in got['py']]}\n        paths rust   {[g['path'] for g in got['rs']]}"
            + (
                f"\n        first difference #{first}:\n        python {json.dumps(got['py'][first])[:2500]}\n        rust   {json.dumps(got['rs'][first])[:2500]}"
                if first is not None
                else ""
            ),
        )
        return responses

    async def log_rows(where, subs=None, **params):
        found = await rows(f"SELECT {LOG_COLUMNS} FROM notification_dispatch_log WHERE {where} ORDER BY dedupe_key, route_id", **params)
        out = []
        for row in found:
            row = {
                k: (v if not isinstance(v, str) else re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", v))
                for k, v in row.items()
            }
            text_ = json.dumps(row, default=str, sort_keys=True)
            out.append(sub_text(text_, subs or []))
        return out

    alert_subs = {
        tag: [(alerts[tag], "<ALERT>"), (alerts["odd_" + tag], "<ODD>"), (cases[tag], "<CASE>"), (alerts["report_" + tag], "<REPORT>")]
        for tag in ("py", "rs")
    }
    A = f"/api/customers/{CUST_A}"
    B = f"/api/customers/{CUST_B}"

    # ======================================================================
    print("\n=== A. auth, scopes, tenancy (exact) ===")
    await same("channels: no token", "GET", "/api/notification_channels")
    await same("channels: garbage token", "GET", "/api/notification_channels", "garbage")
    await same("channels: portal user", "GET", "/api/notification_channels", t_portal)
    await same("channels: 2fa temp token", "GET", "/api/notification_channels", token(ADMIN, [], type="2fa_pending"))
    await same("channels (analyst)", "GET", "/api/notification_channels", t_analyst)
    await same("routes: other tenant", "GET", f"{B}/notification_routes", t_analyst)
    await same("routes: portal", "GET", f"{A}/notification_routes", t_portal)
    await same("routes: empty list", "GET", f"{A}/notification_routes", t_analyst)
    await same("dispatch log: empty", "GET", f"{A}/notification_dispatch_log", t_analyst)
    await same("dispatch log: other tenant", "GET", f"{B}/notification_dispatch_log", t_analyst)
    await same("internal routes: analyst", "GET", "/api/internal_notification_routes", t_analyst)
    await same("internal route: analyst", "GET", "/api/internal_notification_routes/1", t_analyst)
    await same("internal route: path int", "GET", "/api/internal_notification_routes/abc", t_admin)
    await same("internal route: missing", "GET", "/api/internal_notification_routes/999999999", t_admin)
    await same("shuffle integrations: other tenant", "GET", f"{B}/shuffle_integrations", t_analyst)
    await same("templates: analyst, other tenant", "GET", f"/api/notifications/templates?customer_code={CUST_B}", t_analyst)
    await same("malformed JSON before the token", "POST", f"{A}/notification_routes", raw=b"{")
    await same("non-JSON body", "POST", f"{A}/notification_routes", t_admin, raw=b"name=x")
    await same("JSON body, no token", "POST", f"{A}/notification_routes", body={})
    await same("JSON null body", "POST", f"{A}/notification_routes", t_admin, raw=b"null")
    await same("body, other tenant (tenancy before body)", "POST", f"{B}/notification_routes", t_analyst, {})
    await same("route delete: path int after tenancy", "DELETE", f"{B}/notification_routes/abc", t_analyst)
    await same("route delete: path int", "DELETE", f"{A}/notification_routes/abc", t_analyst)
    await same("route patch: path + body errors", "PATCH", f"{A}/notification_routes/abc", t_admin, {"enabled": "maybe", "trigger": "x"})
    await same("route test: missing route", "POST", f"{A}/notification_routes/999999999/test", t_admin)
    await same("templates: create as analyst", "POST", "/api/notifications/templates", t_analyst, {"name": "x", "body_template": "y"})
    await same("templates: patch as analyst", "PATCH", "/api/notifications/templates/1", t_analyst, {"name": "x"})
    await same("templates: get path int", "GET", "/api/notifications/templates/abc", t_analyst)
    await same("templates: get missing", "GET", "/api/notifications/templates/999999999", t_analyst)
    await same("send: portal user", "POST", "/api/notifications/send", t_portal, {"entity_type": "alert", "entity_id": 1, "route_id": 1})
    await same("events: portal user", "POST", "/api/notifications/events", t_portal, {})
    await same("quota (unconfigured)", "GET", "/api/notification_channels/resend/quota", t_analyst)
    await same("quota: other tenant", "GET", f"/api/notification_channels/resend/quota?customer_code={CUST_B}", t_analyst)
    await same("quota: empty customer_code", "GET", "/api/notification_channels/resend/quota?customer_code=", t_analyst)
    await same("quota: own tenant", "GET", f"/api/notification_channels/resend/quota?customer_code={CUST_A}", t_analyst)
    await same("shuffle orgs (unconfigured)", "GET", "/api/notifications/shuffle/orgs", t_analyst)

    # ======================================================================
    print("\n=== B. route validation (exact) ===")
    hook = f"{stub}/hook/ok"
    invalid = [
        ("empty body", {}),
        ("name too long", {"name": "n" * 129, "trigger": "alert_created", "channel": "webhook", "config": {"url": hook}}),
        ("empty name", {"name": "", "trigger": "alert_created", "channel": "webhook", "config": {"url": hook}}),
        ("bad trigger", {"name": "x", "trigger": "bogus", "channel": "webhook", "config": {"url": hook}}),
        ("temp_password_issued", {"name": "x", "trigger": "temp_password_issued", "channel": "webhook", "config": {"url": hook}}),
        ("bad channel", {"name": "x", "trigger": "alert_created", "channel": "sms"}),
        (
            "bad severity",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "min_severity": "Severe", "config": {"url": hook}},
        ),
        ("bad scope", {"name": "x", "trigger": "alert_created", "channel": "webhook", "scope": "global", "config": {"url": hook}}),
        ("bad enabled", {"name": "x", "trigger": "alert_created", "channel": "webhook", "enabled": "maybe", "config": {"url": hook}}),
        (
            "template_id text",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "template_id": "abc", "config": {"url": hook}},
        ),
        ("webhook method GET", {"name": "x", "trigger": "alert_created", "channel": "webhook", "config": {"url": hook, "method": "GET"}}),
        ("webhook extra key", {"name": "x", "trigger": "alert_created", "channel": "webhook", "config": {"url": hook, "nope": 1}}),
        (
            "webhook headers not str",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "config": {"url": hook, "headers": {"a": 1}}},
        ),
        ("webhook no url", {"name": "x", "trigger": "alert_created", "channel": "webhook", "config": {}}),
        ("teams http url", {"name": "x", "trigger": "alert_created", "channel": "teams", "config": {"webhook_url": "http://x"}}),
        (
            "resend max_per_hour 0",
            {"name": "x", "trigger": "alert_created", "channel": "resend", "config": {"to": ["a@b.c"], "max_per_hour": 0}},
        ),
        ("resend to int", {"name": "x", "trigger": "alert_created", "channel": "resend", "config": {"to": 5}}),
        ("resend no recipients", {"name": "x", "trigger": "alert_created", "channel": "resend", "config": {}}),
        (
            "assignee on webhook",
            {"name": "x", "trigger": "alert_assigned", "channel": "webhook", "recipient_mode": "assignee", "config": {"url": hook}},
        ),
        (
            "bad recipient mode",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "recipient_mode": "all", "config": {"url": hook}},
        ),
        (
            "shuffle without integration",
            {"name": "x", "trigger": "alert_created", "channel": "shuffle", "destination": "#a", "config": {"app_id": "a"}},
        ),
        (
            "shuffle without destination",
            {"name": "x", "trigger": "alert_created", "channel": "shuffle", "shuffle_integration_id": 1, "config": {"app_id": "a"}},
        ),
        (
            "template syntax error",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "format_template": "{{ x ", "config": {"url": hook}},
        ),
        (
            "template unknown filter",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "format_template": "{{ x | nope }}", "config": {"url": hook}},
        ),
        ("config not an object", {"name": "x", "trigger": "alert_created", "channel": "webhook", "config": [1]}),
        ("config bad JSON string", {"name": "x", "trigger": "alert_created", "channel": "webhook", "config": "{nope"}),
        (
            "internal scope on customer endpoint",
            {"name": "x", "trigger": "alert_assigned", "channel": "webhook", "scope": "internal", "config": {"url": hook}},
        ),
        (
            "missing template",
            {"name": "x", "trigger": "alert_created", "channel": "webhook", "template_id": 999999999, "config": {"url": hook}},
        ),
    ]
    for name, body in invalid:
        await same(f"create: {name}", "POST", f"{A}/notification_routes", t_admin, body)
    await same(
        "internal create: shuffle refused",
        "POST",
        "/api/internal_notification_routes",
        t_admin,
        {
            "name": "x",
            "trigger": "alert_assigned",
            "channel": "shuffle",
            "scope": "internal",
            "destination": "#a",
            "shuffle_integration_id": 1,
            "config": {"app_id": "a"},
        },
    )
    await same(
        "internal create: customer scope refused",
        "POST",
        "/api/internal_notification_routes",
        t_admin,
        {"name": "x", "trigger": "alert_assigned", "channel": "webhook", "config": {"url": hook}},
    )
    await same(
        "internal create: analyst",
        "POST",
        "/api/internal_notification_routes",
        t_analyst,
        {"name": "x", "trigger": "alert_assigned", "channel": "webhook", "scope": "internal", "config": {"url": hook}},
    )

    # ======================================================================
    print("\n=== C. routes: create, read, update (masked writes, exact reads) ===")
    route_bodies = {
        "webhook": {
            "name": "SOC webhook é",
            "trigger": "severity_critical_or_high",
            "channel": "webhook",
            "destination": "  #soc  ",
            "min_severity": "High",
            "config": json.dumps({"url": f"{stub}/hook/ok/main", "headers": {"X-Key": "s3cret"}, "method": "put"}),
        },
        "template": {
            "name": "Templated webhook",
            "trigger": "investigation_complete",
            "channel": "webhook",
            "min_severity": "Low",
            "format_template": '{"alert": "{{ alert_name }}", "sev": "{{ severity }}", "report": {{report}}, "ai": {{ (context.ai_report.summary or "") | tojson }}}',
            "config": {"url": f"{stub}/hook/ok/tpl"},
        },
        "full": {
            "name": "Full report webhook",
            "trigger": "investigation_complete",
            "channel": "webhook",
            "min_severity": "Low",
            "config": {"url": f"{stub}/hook/ok/full", "include_full_report": True},
        },
        "failing": {
            "name": "Failing webhook",
            "trigger": "alert_created",
            "channel": "webhook",
            "min_severity": "Informational",
            "config": {"url": f"{stub}/hook/fail"},
        },
        "teams": {
            "name": "Teams",
            "trigger": "alert_created",
            "channel": "teams",
            "min_severity": "Informational",
            "config": {"webhook_url": " https://127.0.0.1:1/teams "},
        },
        "resend": {
            "name": "Email",
            "trigger": "investigation_complete",
            "channel": "resend",
            "min_severity": "Low",
            "format_template": "**{{ subject }}**\n\n{{ context.ai_report.markdown }}\n\n| a | b |\n|---|:-:|\n| <x> | &amp; |",
            "config": {"to": "ops@parity.test", "cc": ["lead@parity.test"], "reply_to": "soc@parity.test", "max_per_hour": "20"},
        },
    }
    routes = {}
    for key, body in route_bodies.items():
        out = await each("POST", f"{A}/notification_routes", t_admin, body)
        same_each(f"create route: {key}", out)
        routes[key] = {tag: r.json()["route"]["id"] for tag, r in out.items() if r.status_code == 200}
        await asyncio.sleep(1.1)  # distinct created_at: the list's order has no tie to break
    ids = [i for r in routes.values() for i in r.values()]
    stored = await rows(
        f"SELECT id, {ROUTE_COLUMNS} FROM customer_notification_route WHERE id IN :ids".replace(
            ":ids",
            "(" + ",".join(map(str, ids)) + ")",
        ),
    )
    by_id = {r.pop("id"): r for r in stored}
    for key, r in routes.items():
        check(
            f"route row: {key}",
            by_id.get(r.get("py")) == by_id.get(r.get("rs")),
            f"{by_id.get(r.get('py'))}\n        {by_id.get(r.get('rs'))}",
        )
    await same("list routes (both backends' rows)", "GET", f"{A}/notification_routes", t_analyst)

    updates = [
        ("rename", {"name": "Renamed"}),
        ("disable", {"enabled": False}),
        ("re-enable + severity", {"enabled": True, "min_severity": "Critical"}),
        ("null name refused", {"name": None}),
        ("bad trigger", {"trigger": "temp_password_issued"}),
        ("legacy trigger", {"trigger": "severity_critical_or_high"}),
        ("config replaced", {"config": {"url": f"{stub}/hook/ok/main", "include_full_report": False}}),
        ("bad config for channel", {"config": {"webhook_url": "https://x"}}),
        ("switch to resend without config", {"channel": "resend"}),
        ("assignee mode on webhook", {"recipient_mode": "assignee"}),
        ("template syntax error", {"format_template": "{% if %}"}),
        ("clear template", {"format_template": None}),
        ("missing template_id", {"template_id": 999999999}),
        ("scope change", {"scope": "internal"}),
        ("destination stripped", {"destination": "  x  "}),
    ]
    for name, body in updates:
        out = await each("PATCH", lambda tag: f"{A}/notification_routes/{routes['webhook'][tag]}", t_analyst, body)
        same_each(f"update: {name}", out)
    await same(
        "update: other tenant's id",
        "PATCH",
        f"{A}/notification_routes/{routes['webhook']['py']}",
        t_analyst,
        {"name": "x"},
        py_path=f"{A}/notification_routes/{routes['webhook']['py']}",
    )
    await same("update: id under the wrong customer", "PATCH", f"{B}/notification_routes/{routes['webhook']['py']}", t_admin, {"name": "x"})
    stored = await rows(
        f"SELECT {ROUTE_COLUMNS} FROM customer_notification_route WHERE id IN ({routes['webhook']['py']}, {routes['webhook']['rs']}) ORDER BY id",
    )
    check("route rows after the updates", len(stored) == 2 and stored[0] == stored[1], f"{stored}")

    # ======================================================================
    print("\n=== D. templates ===")
    await same("templates (admin)", "GET", "/api/notifications/templates", t_admin)
    await same("templates (analyst, scoped)", "GET", "/api/notifications/templates", t_analyst)
    await same(
        "templates ?customer_code&trigger",
        "GET",
        f"/api/notifications/templates?customer_code={CUST_A}&trigger=alert_created",
        t_analyst,
    )
    await same("templates ?trigger=", "GET", "/api/notifications/templates?trigger=", t_analyst)
    template_invalid = [
        ("empty", {}),
        ("blank name", {"name": "   ", "body_template": "x"}),
        ("blank body", {"name": "x", "body_template": "   "}),
        ("bad format", {"name": "x", "body_template": "x", "format": "pdf"}),
        ("bad trigger", {"name": "x", "body_template": "x", "trigger": "nope"}),
        ("syntax error", {"name": "x", "body_template": "{% for %}"}),
        ("subject syntax error", {"name": "x", "body_template": "ok", "subject_template": "{{"}),
        ("description too long", {"name": "x", "body_template": "x", "description": "d" * 513}),
    ]
    for name, body in template_invalid:
        await same(f"template create: {name}", "POST", "/api/notifications/templates", t_admin, body)
    templates = {}
    for key, body in {
        "shared": {
            "name": "  Shared html ",
            "format": "html",
            "trigger": "alert_created",
            "subject_template": "{{ severity }}: {{ subject }}",
            "body_template": "<p>{{ summary }}</p>{{ branding.title if branding else '' }}",
        },
        "scoped": {"name": "Scoped md", "format": "markdown", "customer_code": CUST_A, "body_template": "*{{ alert_name }}*"},
        "other": {"name": "Other tenant", "format": "text", "customer_code": CUST_B, "body_template": "x"},
    }.items():
        out = await each("POST", "/api/notifications/templates", t_admin, body)
        same_each(f"template create: {key}", out)
        templates[key] = {tag: r.json()["template"]["id"] for tag, r in out.items()}
        await asyncio.sleep(1.1)
    await same("template get (shared)", "GET", f"/api/notifications/templates/{templates['shared']['py']}", t_analyst)
    await same("template get (other tenant)", "GET", f"/api/notifications/templates/{templates['other']['py']}", t_analyst)
    await same("templates ?customer_code (both rows)", "GET", f"/api/notifications/templates?customer_code={CUST_A}", t_analyst)
    builtin = await rows("SELECT id FROM notification_template WHERE is_default = 1 ORDER BY id LIMIT 1")
    if builtin:
        await same("template patch: built-in refused", "PATCH", f"/api/notifications/templates/{builtin[0]['id']}", t_admin, {"name": "x"})
        await same("template delete: built-in refused", "DELETE", f"/api/notifications/templates/{builtin[0]['id']}", t_admin)
    # Attach the scoped markdown template to each backend's resend route, then try
    # edits that would break it.
    out = await each(
        "PATCH",
        lambda tag: f"{A}/notification_routes/{routes['resend'][tag]}",
        t_admin,
        lambda tag: {"template_id": templates["scoped"][tag]},
    )
    same_each("attach template to route", out)
    out = await each(
        "PATCH",
        lambda tag: f"{A}/notification_routes/{routes['template'][tag]}",
        t_admin,
        lambda tag: {"template_id": templates["shared"][tag]},
    )
    same_each("attach html template to a webhook route (incompatible)", out)
    out = await each(
        "PATCH",
        lambda tag: f"{A}/notification_routes/{routes['template'][tag]}",
        t_admin,
        lambda tag: {"template_id": templates["other"][tag]},
    )
    same_each("attach another tenant's template", out)
    for name, body in (
        ("format json breaks the route", {"format": "json"}),
        ("customer change breaks the route", {"customer_code": CUST_B}),
        ("trigger change breaks the route", {"trigger": "sla_breached"}),
        ("valid edit", {"description": "Used by the email route", "body_template": "*{{ alert_name }}* — {{ severity }}"}),
        ("null body refused", {"body_template": None}),
        ("syntax error", {"body_template": "{{"}),
    ):
        out = await each("PATCH", lambda tag: f"/api/notifications/templates/{templates['scoped'][tag]}", t_admin, body)
        same_each(f"template patch: {name}", out)

    previews = [
        ("default", {"body_template": "{{ severity }} {{ alert_name }} {{ context.iocs | length }} {{ assignee }}"}),
        (
            "html autoescape",
            {"body_template": "<b>{{ summary }}</b> {{ '<i>' }}", "format": "html", "subject_template": "  {{ subject }}\n  x  "},
        ),
        ("render failure", {"body_template": "{{ nope.attr }}"}),
        ("subject failure", {"body_template": "ok", "subject_template": "{{ 1/0 }}"}),
        ("sla trigger", {"body_template": "{{ context.overdue_minutes }}|{{ context.clock }}", "trigger": "sla_breached"}),
        ("case task trigger", {"body_template": "{{ entity_type }} {{ event.entity_id }}", "trigger": "case_task_assigned"}),
        ("branding", {"body_template": "{{ branding | dictsort }}", "customer_code": CUST_A}),
        (
            "temp password",
            {
                "body_template": "{{ user_name }} {{ temp_password }} {{ login_url }} {{ customer_name }}",
                "trigger": "temp_password_issued",
                "customer_code": CUST_A,
            },
        ),
        ("bad trigger", {"body_template": "x", "trigger": "nope"}),
        ("sandbox", {"body_template": "{{ ''.__class__ }}"}),
        ("too big", {"body_template": "{% for i in range(70000) %}x{% endfor %}"}),
        ("json format", {"body_template": '{"a": {{ alert_id }}}', "format": "json"}),
    ]
    for name, body in previews:
        await same(f"template preview: {name}", "POST", "/api/notifications/templates/preview", t_analyst, body)

    # ======================================================================
    print("\n=== E. connectors absent, then present ===")
    out = await each("POST", lambda tag: f"{A}/notification_routes/{routes['resend'][tag]}/test", t_admin)
    same_each("resend test send, connector absent", out)
    await same("shuffle apps without the connector", "GET", f"{A}/shuffle_integrations/999999999/apps", t_analyst)
    await add_connector("Resend", stub, "re_parity", "CoPilot <soc@parity.test>")
    await add_connector("Shuffle", stub, "sh_parity")
    await same("quota (configured)", "GET", f"/api/notification_channels/resend/quota?customer_code={CUST_A}", t_analyst)
    orgs = await outbound("shuffle orgs", lambda tag, c: call(c, "GET", "/api/notifications/shuffle/orgs", t_analyst))
    same_each("shuffle orgs", orgs)

    # ======================================================================
    print("\n=== F. Shuffle integrations ===")
    await same("integration create: empty", "POST", f"{A}/shuffle_integrations", t_analyst, {})
    await same(
        "integration create: too long",
        "POST",
        f"{A}/shuffle_integrations",
        t_analyst,
        {"display_name": "x", "shuffle_org_id": "o" * 65},
    )
    out = await each(
        "POST",
        f"{A}/shuffle_integrations",
        t_analyst,
        {"display_name": "Acme é", "shuffle_org_id": "  org-1 ", "enabled": "true"},
    )
    same_each("integration create", out)
    integ = {tag: r.json()["integration"]["id"] for tag, r in out.items()}
    out_b = await each("POST", f"{B}/shuffle_integrations", t_admin, {"display_name": "Beta", "shuffle_org_id": "org-b"})
    integ_b = {tag: r.json()["integration"]["id"] for tag, r in out_b.items()}
    await asyncio.sleep(1.1)
    await same("integrations list", "GET", f"{A}/shuffle_integrations", t_analyst)
    out = await each(
        "PATCH",
        lambda tag: f"{A}/shuffle_integrations/{integ[tag]}",
        t_analyst,
        {"display_name": "Renamed", "shuffle_org_id": " org-1"},
    )
    same_each("integration patch", out)
    integ_subs = {tag: [(integ[tag], "<INTEG>"), (integ_b[tag], "<INTEG_B>")] for tag in clients}
    out = await each("PATCH", lambda tag: f"{A}/shuffle_integrations/{integ_b[tag]}", t_admin, {"display_name": "x"})
    same_each("integration patch: other customer's id", out, subs=integ_subs)
    apps = await outbound("integration apps", lambda tag, c: call(c, "GET", f"{A}/shuffle_integrations/{integ[tag]}/apps", t_analyst))
    same_each("integration apps", apps)
    verify = await outbound("integration verify", lambda tag, c: call(c, "GET", f"{A}/shuffle_integrations/{integ[tag]}/verify", t_analyst))
    same_each("integration verify", verify)
    shuffle_routes = {}
    for key, app_id in (("ok", "app-1"), ("fail", "app-fail"), ("401", "app-401")):
        out = await each(
            "POST",
            f"{A}/notification_routes",
            t_admin,
            lambda tag, app_id=app_id: {
                "name": f"Shuffle {app_id}",
                "trigger": "alert_created",
                "channel": "shuffle",
                "destination": "#soc",
                "min_severity": "Informational",
                "shuffle_integration_id": integ[tag],
                "config": {"app_id": app_id, "app_name": "Slack"},
            },
        )
        same_each(f"shuffle route create: {key}", out)
        shuffle_routes[key] = {tag: r.json()["route"]["id"] for tag, r in out.items()}
    out = await each(
        "POST",
        f"{A}/notification_routes",
        t_admin,
        lambda tag: {
            "name": "x",
            "trigger": "alert_created",
            "channel": "shuffle",
            "destination": "#soc",
            "shuffle_integration_id": integ_b[tag],
            "config": {"app_id": "a"},
        },
    )
    same_each("shuffle route on another customer's integration", out, subs=integ_subs)
    out = await each("DELETE", lambda tag: f"{A}/shuffle_integrations/{integ[tag]}", t_admin)
    same_each("integration delete: referenced", out)
    out = await each("DELETE", lambda tag: f"{B}/shuffle_integrations/{integ_b[tag]}", t_admin)
    same_each("integration delete", out)

    # ======================================================================
    print("\n=== G. test sends (outbound + outcome + log) ===")
    for key in ("webhook", "template", "full", "failing", "teams", "resend"):
        resp = await outbound(
            f"test send: {key}",
            lambda tag, c, key=key: call(c, "POST", f"{A}/notification_routes/{routes[key][tag]}/test", t_analyst),
        )
        same_each(f"test send outcome: {key}", resp)
    for key in ("ok", "fail", "401"):
        resp = await outbound(
            f"test send: shuffle {key}",
            lambda tag, c, key=key: call(c, "POST", f"{A}/notification_routes/{shuffle_routes[key][tag]}/test", t_admin),
        )
        same_each(f"test send outcome: shuffle {key}", resp)
    py_logs = await log_rows(
        "trigger_source = 'test' AND route_id IN ("
        + ",".join(str(r["py"]) for r in list(routes.values()) + list(shuffle_routes.values()))
        + ")",
    )
    rs_logs = await log_rows(
        "trigger_source = 'test' AND route_id IN ("
        + ",".join(str(r["rs"]) for r in list(routes.values()) + list(shuffle_routes.values()))
        + ")",
    )

    def strip_route(xs):
        """Log rows with the route id (each backend's own) and the test key's route masked."""
        return sorted(re.sub(r'"route_id": [0-9]+', '"route_id": 0', re.sub(r"test:[0-9]+:", "test:N:", x)) for x in xs)

    check(
        "test sends: dispatch log rows",
        strip_route(py_logs) == strip_route(rs_logs),
        f"{strip_route(py_logs)}\n        {strip_route(rs_logs)}",
    )
    await same(
        "dispatch log (both backends' rows)",
        "GET",
        f"{A}/notification_dispatch_log",
        t_analyst,
        masked=True,
        extra=("route_id", "dedupe_key"),
    )

    # ======================================================================
    print("\n=== H. Talon dispatch ===")

    def dispatch_body(tag, **over):
        body = {
            "customer_code": CUST_A,
            "alert_id": alerts[tag],
            "trigger": "investigation_complete",
            "severity_assessment": "High",
            "summary": "Credential dumping on dc01.",
            "report_url": "https://copilot.parity.test/alerts/x",
            "alert_name": "Mimikatz",
        }
        body.update(over)
        return body

    for name, body in (
        ("empty", {}),
        (
            "bad severity",
            {"customer_code": CUST_A, "alert_id": 1, "trigger": "investigation_complete", "severity_assessment": "high", "summary": "s"},
        ),
        (
            "bad alert id",
            {"customer_code": CUST_A, "alert_id": "x", "trigger": "investigation_complete", "severity_assessment": "High", "summary": "s"},
        ),
    ):
        await same(f"dispatch: {name}", "POST", "/api/notifications/dispatch", t_admin, body)
    # The customer has not opted in to AI reports: every customer route is skipped.
    resp = await outbound(
        "dispatch, AI reports off",
        lambda tag, c: call(c, "POST", "/api/notifications/dispatch", t_admin, dispatch_body(tag)),
        subs=alert_subs,
    )
    same_each("dispatch, AI reports off", resp, subs=alert_subs)
    await sql(
        "INSERT INTO customer_portal_ai_report_settings (customer_code, enabled, updated_at) VALUES (:c, 1, UTC_TIMESTAMP())",
        c=CUST_A,
    )
    resp = await outbound(
        "dispatch",
        lambda tag, c: call(c, "POST", "/api/notifications/dispatch", t_admin, dispatch_body(tag)),
        subs=alert_subs,
    )
    same_each("dispatch", resp, subs=alert_subs)
    resp = await outbound(
        "dispatch again (sent again, then refused by the log)",
        lambda tag, c: call(c, "POST", "/api/notifications/dispatch", t_admin, dispatch_body(tag)),
        subs=alert_subs,
    )
    same_each("dispatch again", resp, subs=alert_subs)
    resp = await outbound(
        "dispatch with the legacy trigger, Critical, no name",
        lambda tag, c: call(
            c,
            "POST",
            "/api/notifications/dispatch",
            t_admin,
            dispatch_body(tag, trigger="severity_critical_or_high", severity_assessment="Critical", alert_name=None, report_url=None),
        ),
        subs=alert_subs,
    )
    same_each("dispatch (legacy trigger)", resp, subs=alert_subs)
    resp = await outbound(
        "dispatch below every floor",
        lambda tag, c: call(c, "POST", "/api/notifications/dispatch", t_admin, dispatch_body(tag, severity_assessment="Informational")),
        subs=alert_subs,
    )
    same_each("dispatch below every floor", resp, subs=alert_subs)
    resp = await outbound(
        "dispatch alert_created (failing webhook, Teams, Shuffle)",
        lambda tag, c: call(
            c,
            "POST",
            "/api/notifications/dispatch",
            t_admin,
            dispatch_body(tag, trigger="alert_created", severity_assessment="Low"),
        ),
        subs=alert_subs,
    )
    same_each("dispatch alert_created", resp, subs=alert_subs, extra=("route_id",))
    py_logs = await log_rows("customer_code = :c AND alert_id = :a", subs=alert_subs["py"], c=CUST_A, a=a_py)
    rs_logs = await log_rows("customer_code = :c AND alert_id = :a", subs=alert_subs["rs"], c=CUST_A, a=a_rs)
    check("dispatch log rows", strip_route(py_logs) == strip_route(rs_logs), f"{strip_route(py_logs)}\n        {strip_route(rs_logs)}")
    r1 = await call(py, "POST", "/api/notifications/dispatch", t_analyst, dispatch_body("b", customer_code=CUST_B))
    r2 = await call(rs, "POST", "/api/notifications/dispatch", t_analyst, dispatch_body("b", customer_code=CUST_B))
    # DIFF_BY_DESIGN: Python dispatches for any customer the body names; Rust checks
    # the caller may see that customer first.
    check(
        "dispatch for another tenant: Python 200, Rust 403",
        r1.status_code == 200
        and (r2.status_code, r2.json()) == (403, {"success": False, "message": f"Access denied to customer {CUST_B}"}),
        f"python {r1.status_code} {r1.text}\n        rust   {r2.status_code} {r2.text}",
    )

    # ======================================================================
    print("\n=== I. manual send ===")
    internal = {}
    out = await each(
        "POST",
        "/api/internal_notification_routes",
        t_admin,
        {
            "name": "SOC internal",
            "trigger": "alert_assigned",
            "channel": "webhook",
            "scope": "internal",
            "min_severity": "Informational",
            "config": {"url": f"{stub}/hook/ok/internal"},
        },
    )
    same_each("internal route create", out)
    internal = {tag: r.json()["route"]["id"] for tag, r in out.items()}
    await asyncio.sleep(1.1)
    await same("internal routes list", "GET", "/api/internal_notification_routes", t_admin)
    out = await each("GET", lambda tag: f"/api/internal_notification_routes/{internal[tag]}", t_admin)
    same_each("internal route get", out)
    out = await each(
        "PATCH",
        lambda tag: f"/api/internal_notification_routes/{internal[tag]}",
        t_admin,
        {"notify_on_self_assign": True, "name": "SOC internal é"},
    )
    same_each("internal route patch", out)
    out = await each("GET", lambda tag: f"/api/internal_notification_routes/{routes['webhook'][tag]}", t_admin)
    same_each("internal route get: a customer route's id", out)

    def send_body(tag, **over):
        body = {"entity_type": "alert", "entity_id": alerts[tag], "route_id": internal[tag]}
        body.update(over)
        return body

    manual_errors = [
        ("unknown entity type", lambda tag: send_body(tag, entity_type="task")),
        ("missing alert", lambda tag: send_body(tag, entity_id=999999999)),
        ("missing route", lambda tag: send_body(tag, route_id=999999999)),
        ("customer route needs admin", lambda tag: send_body(tag, route_id=routes["webhook"][tag])),
        ("other tenant's alert", lambda tag: send_body(tag, entity_id=alerts["b"])),
        (
            "case with an AI report",
            lambda tag: {"entity_type": "case", "entity_id": cases[tag], "route_id": internal[tag], "include_ai_report": True},
        ),
        ("bad body", lambda tag: {"entity_type": "alert"}),
    ]
    for name, body in manual_errors:
        out = await each("POST", "/api/notifications/send", t_analyst, body)
        same_each(f"send: {name}", out, subs=alert_subs)
    out = await each(
        "POST",
        "/api/notifications/send",
        t_admin,
        lambda tag: send_body(tag, entity_id=alerts["b"], route_id=routes["webhook"][tag]),
    )
    same_each("send: route of another customer than the item", out, subs=alert_subs)
    for name, body in (
        ("alert, internal route", lambda tag: send_body(tag)),
        ("alert with AI report", lambda tag: send_body(tag, include_ai_report=True)),
        ("odd severity", lambda tag: send_body(tag, entity_id=alerts["odd_" + tag])),
        ("case", lambda tag: {"entity_type": "case", "entity_id": cases[tag], "route_id": internal[tag]}),
    ):
        out = await each("POST", "/api/notifications/send/preview", t_analyst, body)
        same_each(f"send preview: {name}", out, subs=alert_subs)
        resp = await outbound(
            f"send: {name}",
            lambda tag, c, body=body: call(c, "POST", "/api/notifications/send", t_analyst, body(tag)),
            subs=alert_subs,
        )
        same_each(f"send outcome: {name}", resp, subs=alert_subs)
    for key in ("resend", "full", "template"):
        resp = await outbound(
            f"admin send to customer route: {key}",
            lambda tag, c, key=key: call(
                c,
                "POST",
                "/api/notifications/send",
                t_admin,
                send_body(tag, route_id=routes[key][tag], include_ai_report=True),
            ),
            subs=alert_subs,
        )
        same_each(f"admin send outcome: {key}", resp, subs=alert_subs)
    # Every send so far reached both backends' email routes alike (a dispatch walks
    # all of the customer's routes): one an hour throttles both the same way.
    out = await each(
        "PATCH",
        lambda tag: f"{A}/notification_routes/{routes['resend'][tag]}",
        t_admin,
        {"config": {"to": ["ops@parity.test"], "max_per_hour": 1}},
    )
    same_each("resend route: one an hour", out)
    resp = await outbound(
        "admin send: resend over its hourly limit",
        lambda tag, c: call(c, "POST", "/api/notifications/send", t_admin, send_body(tag, route_id=routes["resend"][tag])),
        subs=alert_subs,
    )
    same_each("admin send outcome: resend throttled", resp, subs=alert_subs)
    py_logs = await log_rows("trigger_source = 'manual' AND customer_code = :c AND alert_id = :a", subs=alert_subs["py"], c=CUST_A, a=a_py)
    rs_logs = await log_rows("trigger_source = 'manual' AND customer_code = :c AND alert_id = :a", subs=alert_subs["rs"], c=CUST_A, a=a_rs)
    check(
        "manual sends: dispatch log rows",
        strip_route(py_logs) == strip_route(rs_logs),
        f"{strip_route(py_logs)}\n        {strip_route(rs_logs)}",
    )
    await same("quota after the sends", "GET", f"/api/notification_channels/resend/quota?customer_code={CUST_A}", t_admin)

    # ======================================================================
    print("\n=== J. the events endpoint (former bridge) ===")

    def event_body(tag, **over):
        body = {
            "customer_code": CUST_A,
            "trigger": "ai_report_reviewed",
            "severity": "High",
            "subject": "Reviewed: Mimikatz",
            "summary": "Thumbs up.",
            "entity_id": alerts[tag],
            "dedupe_key": "forged",
            "link_url": "https://evil.example",
            "actor_username": ANALYST,
            "context": {"report_id": 1, "verdict": "up"},
        }
        body.update(over)
        return body

    for name, over in (
        ("not an AI trigger", {"trigger": "alert_created"}),
        ("not an alert", {"entity_type": "case"}),
        ("missing alert", {"entity_id": 999999999}),
        ("customer mismatch (admin)", {"customer_code": CUST_B}),
        ("bad context", {"context": [1]}),
    ):
        out = await each("POST", "/api/notifications/events", t_admin, lambda tag, over=over: event_body(tag, **over))
        same_each(f"events: {name}", out, subs=alert_subs)
    out = await each("POST", "/api/notifications/events", t_analyst, lambda tag: event_body("b", customer_code=CUST_B))
    same_each("events: other tenant's alert", out)
    await sql(
        "INSERT INTO customer_notification_route (customer_code, name, `trigger`, channel, min_severity, enabled, dispatch_count, "
        "created_by, created_at, config, scope, recipient_mode, notify_on_self_assign) VALUES (:c, 'Reviewed hook', "
        "'ai_report_reviewed', 'webhook', 'Low', 1, 0, 'par', UTC_TIMESTAMP(), :cfg, 'customer', 'static', 0)",
        c=CUST_A,
        cfg=json.dumps({"url": f"{stub}/hook/ok/reviewed"}),
    )

    async def settle(tag):
        alert = alerts[tag]
        for _ in range(100):
            done = await rows(
                "SELECT COUNT(*) AS n FROM notification_dispatch_log WHERE alert_id = :a AND `trigger` = 'ai_report_reviewed'",
                a=alert,
            )
            if done[0]["n"]:
                return
            await asyncio.sleep(0.1)

    resp = await outbound(
        "events: accepted, dispatched in the background",
        lambda tag, c: call(c, "POST", "/api/notifications/events", t_analyst, event_body(tag)),
        subs=alert_subs,
        settle=settle,
    )
    same_each("events: accepted", resp)
    py_logs = await log_rows("`trigger` = 'ai_report_reviewed' AND alert_id = :a", subs=alert_subs["py"], a=a_py)
    rs_logs = await log_rows("`trigger` = 'ai_report_reviewed' AND alert_id = :a", subs=alert_subs["rs"], a=a_rs)
    check(
        "events: dispatch log rows (dedupe key re-derived)",
        strip_route(py_logs) == strip_route(rs_logs) and len(py_logs) == 1,
        f"{py_logs}\n        {rs_logs}",
    )

    # ======================================================================
    print("\n=== L. more deliveries: headers, {{report}}, html, SLA, assignee ===")
    extra_routes = {}
    for key, body in {
        "bad_header": {
            "name": "Bad header",
            "trigger": "alert_created",
            "channel": "webhook",
            "config": {"url": f"{stub}/hook/ok/bad", "headers": {"X-Key": " leading"}},
        },
        "non_ascii_header": {
            "name": "Non-ASCII header",
            "trigger": "alert_created",
            "channel": "webhook",
            "config": {"url": f"{stub}/hook/ok/na", "headers": {"X-Who": "Zo\u00eb\u00eb"}},
        },
        "report_token": {
            "name": "Report token",
            "trigger": "investigation_complete",
            "channel": "webhook",
            "min_severity": "Low",
            "format_template": '{"text": {{ summary | tojson }}, "report": {{ "{{report}}" }}}',
            "config": {"url": f"{stub}/hook/ok/report"},
        },
        "plain_template": {
            "name": "Plain template",
            "trigger": "investigation_complete",
            "channel": "webhook",
            "min_severity": "Low",
            "format_template": "{{ alert_name }} / {{ severity }} / {{ report_url }} / {{ context.ai_report.ioc_count }}",
            "config": {"url": f"{stub}/hook/ok/plain", "method": "PUT"},
        },
    }.items():
        out = await each("POST", f"{A}/notification_routes", t_admin, body)
        same_each(f"create route: {key}", out)
        extra_routes[key] = {tag: r.json()["route"]["id"] for tag, r in out.items()}
    html_tpl = {}
    out = await each(
        "POST",
        "/api/notifications/templates",
        t_admin,
        {
            "name": "AI html",
            "format": "html",
            "trigger": "investigation_complete",
            "customer_code": CUST_A,
            "subject_template": "{{ subject }} <{{ severity }}>",
            "body_template": "<h1>{{ subject }}</h1>{{ context.ai_report.html }}<p>{{ '<i>' }}</p>",
        },
    )
    same_each("template create: AI html", out)
    html_tpl = {tag: r.json()["template"]["id"] for tag, r in out.items()}
    out = await each(
        "POST",
        f"{A}/notification_routes",
        t_admin,
        lambda tag: {
            "name": "AI html mail",
            "trigger": "investigation_complete",
            "channel": "resend",
            "min_severity": "Low",
            "template_id": html_tpl[tag],
            "config": {"to": ["ai@parity.test"], "subject_prefix": ""},
        },
    )
    same_each("create route: AI html mail", out)
    extra_routes["html_mail"] = {tag: r.json()["route"]["id"] for tag, r in out.items()}
    for key in ("bad_header", "non_ascii_header"):
        resp = await outbound(
            f"test send: {key}",
            lambda tag, c, key=key: call(c, "POST", f"{A}/notification_routes/{extra_routes[key][tag]}/test", t_admin),
        )
        same_each(f"test send outcome: {key}", resp)
    for key in ("report_token", "plain_template", "html_mail"):
        resp = await outbound(
            f"admin send with AI report: {key}",
            lambda tag, c, key=key: call(
                c,
                "POST",
                "/api/notifications/send",
                t_admin,
                send_body(tag, route_id=extra_routes[key][tag], include_ai_report=True),
            ),
            subs=alert_subs,
        )
        same_each(f"admin send outcome: {key}", resp, subs=alert_subs)
    sla = {}
    for key, body in {
        "sla": {
            "name": "SLA",
            "trigger": "sla_breached",
            "channel": "webhook",
            "scope": "internal",
            "min_severity": "Informational",
            "config": {"url": f"{stub}/hook/ok/sla"},
        },
        "assignee_mail": {
            "name": "Assignee mail",
            "trigger": "alert_assigned",
            "channel": "resend",
            "scope": "internal",
            "recipient_mode": "assignee",
            "min_severity": "Informational",
            "config": {},
        },
        "reviewed_internal": {
            "name": "Reviewed (SOC)",
            "trigger": "ai_report_reviewed",
            "channel": "webhook",
            "scope": "internal",
            "min_severity": "Informational",
            "config": {"url": f"{stub}/hook/ok/reviewed-soc"},
        },
    }.items():
        out = await each("POST", "/api/internal_notification_routes", t_admin, body)
        same_each(f"internal route create: {key}", out)
        sla[key] = {tag: r.json()["route"]["id"] for tag, r in out.items()}
    for trigger in ("sla_breached", "alert_assigned", "ai_report_reviewed"):
        resp = await outbound(
            f"dispatch {trigger}",
            lambda tag, c, trigger=trigger: call(c, "POST", "/api/notifications/dispatch", t_admin, dispatch_body(tag, trigger=trigger)),
            subs=alert_subs,
        )
        same_each(f"dispatch {trigger}", resp, subs=alert_subs)
    for key in ("sla", "assignee_mail", "reviewed_internal"):
        out = await each("DELETE", lambda tag, key=key: f"/api/internal_notification_routes/{sla[key][tag]}", t_admin)
        same_each(f"internal route delete: {key}", out)
    for key in ("bad_header", "non_ascii_header", "report_token", "plain_template", "html_mail"):
        out = await each("DELETE", lambda tag, key=key: f"{A}/notification_routes/{extra_routes[key][tag]}", t_admin)
        same_each(f"route delete: {key}", out)

    # ======================================================================
    print("\n=== K. deletes ===")
    out = await each("DELETE", lambda tag: f"{B}/notification_routes/{routes['teams'][tag]}", t_admin)
    same_each("route delete: wrong customer", out)
    for key in ("teams", "failing"):
        out = await each("DELETE", lambda tag, key=key: f"{A}/notification_routes/{routes[key][tag]}", t_analyst)
        same_each(f"route delete: {key}", out)
    out = await each("DELETE", lambda tag: f"/api/internal_notification_routes/{internal[tag]}", t_admin)
    same_each("internal route delete", out)
    out = await each("DELETE", lambda tag: f"/api/internal_notification_routes/{internal[tag]}", t_admin)
    same_each("internal route delete again", out)
    out = await each("DELETE", lambda tag: f"/api/notifications/templates/{templates['scoped'][tag]}", t_admin)
    same_each("template delete (detaches its route)", out)
    out = await each("DELETE", lambda tag: f"/api/notifications/templates/{templates['other'][tag]}", t_admin)
    same_each("template delete (unused)", out)
    stored = await rows(
        f"SELECT template_id FROM customer_notification_route WHERE id IN ({routes['resend']['py']}, {routes['resend']['rs']})",
    )
    check("detached routes", stored == [{"template_id": None}, {"template_id": None}], f"{stored}")
    for key in ("ok", "fail", "401"):
        await each("DELETE", lambda tag, key=key: f"{A}/notification_routes/{shuffle_routes[key][tag]}", t_admin)
    out = await each("DELETE", lambda tag: f"{A}/shuffle_integrations/{integ[tag]}", t_admin)
    same_each("integration delete once unreferenced", out)
    await same("routes after the deletes", "GET", f"{A}/notification_routes", t_analyst)

    await sql("DELETE FROM connectors WHERE connector_name IN ('Resend', 'Shuffle')")
    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
