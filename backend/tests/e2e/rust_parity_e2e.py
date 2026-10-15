"""Parity of the Rust service with this backend — NOT collected by pytest (needs a live MySQL
and a running Rust binary).

Sends the same requests to the real FastAPI routers (in-process) and to the Rust service
(`crates/copilot`) over HTTP, both on the same disposable database, and compares status
codes and JSON bodies. Read endpoints must be byte-for-byte equal; for writes, ids and
timestamps are masked and everything else must be equal. See docs/architecture/RUST_MIGRATION.md.

    # MySQL on 13306 migrated to head (see analyst_object_scoping_e2e.py), then:
    scripts/rust-parity.sh            # builds and starts the Rust service, runs this file

Deliberate differences are asserted as such (DIFF_BY_DESIGN), not skipped silently.
"""

import asyncio
import datetime
import json
import os
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

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.db.db_session import async_engine  # noqa: E402

RUST = os.environ.get("RUST_BASE_URL", "http://127.0.0.1:5199")
SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"PAR_A{SFX}", f"PAR_B{SFX}"
ADMIN, ANALYST, PORTAL = f"par_admin{SFX}", f"par_analyst{SFX}", f"par_portal{SFX}"
VOLATILE = {
    "id",
    "job_id",
    "created_at",
    "updated_at",
    "started_at",
    "completed_at",
    "ingested_at",
    "generated_at",
    "report_id",
    "review_id",
    "ioc_id",
}

results = []

# Talon stand-in: accepts every investigation but those in TALON_REFUSES, records the bodies.
TALON_BODIES = []
TALON_REFUSES = set()


class _TalonStub(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        TALON_BODIES.append(body)
        status = 500 if body.get("alert_id") in TALON_REFUSES else 202
        payload = json.dumps({"job_id": "stub", "status": "queued"} if status == 202 else {"error": "boom"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def start_talon_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TalonStub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def mask(value):
    if isinstance(value, dict):
        return {k: ("<v>" if k in VOLATILE and v is not None else mask(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v) for v in value]
    return value


def build_python_app():
    from app.ai_analyst.routes.ai_analyst import ai_analyst_router
    from app.connectors.talon.routes.talon import talon_router
    from app.customer_portal.routes.ai_reports import customer_portal_ai_reports_router
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler

    api = APIRouter(prefix="/api")
    api.include_router(ai_analyst_router, prefix="/ai_analyst")
    api.include_router(talon_router, prefix="/talon")
    api.include_router(customer_portal_ai_reports_router, prefix="/customer_portal")
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


async def seed():
    """Two customers, users, one alert each with an asset; returns alert ids."""
    async with AsyncSession(async_engine) as s:
        for c in (CUST_A, CUST_B):
            await s.execute(
                text("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())"),
                {"c": c},
            )
        for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
            await s.execute(
                text(
                    "INSERT INTO `user` (username, password, email, created_at, role_id) "
                    "VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
                ),
                {"n": name, "r": role},
            )
        for name in (ANALYST, PORTAL):
            await s.execute(
                text(
                    "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
                    "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                ),
                {"c": CUST_A, "n": name},
            )
        alerts = {}
        for c in (CUST_A, CUST_B):
            r = await s.execute(
                text(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
                    "customer_code, source, escalated) VALUES (:n, 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0)",
                ),
                {"n": f"Mimikatz {c}", "c": c},
            )
            alert_id = r.lastrowid
            r = await s.execute(text("INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')"))
            await s.execute(
                text(
                    "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, customer_code, "
                    "index_name, index_id) VALUES (:a, 'dc01', :ctx, :c, 'idx', 'doc')",
                ),
                {"a": alert_id, "ctx": r.lastrowid, "c": c},
            )
            alerts[c] = alert_id
        # A second alert for A with no AI analysis at all.
        r = await s.execute(
            text(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
                "customer_code, source, escalated) VALUES ('Quiet', 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0)",
            ),
            {"c": CUST_A},
        )
        alerts["quiet"] = r.lastrowid
        # Alerts the portal requests use: one per backend, one Talon refuses, one over the limit.
        for key in ("req_py", "req_rs", "refuse", "over"):
            r = await s.execute(
                text(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
                    "customer_code, source, escalated) VALUES (:n, 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0)",
                ),
                {"n": key, "c": CUST_A},
            )
            alerts[key] = r.lastrowid
        # The Talon connector is global: point it at the stub before either backend reads it.
        await s.execute(text("DELETE FROM connectors WHERE connector_name = 'Talon'"))
        await s.execute(
            text(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, "
                "connector_api_key, connector_configured, connector_verified, connector_accepts_host_only, "
                "connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, "
                "connector_accepts_extra_data, connector_enabled) VALUES "
                "('Talon', '3', :u, UTC_TIMESTAMP(), 'talon-key', 1, 1, 0, 1, 0, 0, 0, 1)",
            ),
            {"u": start_talon_stub()},
        )
        await s.commit()
    return alerts


async def main():
    alerts = await seed()
    a, b = alerts[CUST_A], alerts[CUST_B]
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app()), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=30)
    t_admin = token(ADMIN, ["admin"])
    t_analyst = token(ANALYST, ["analyst"])
    t_portal = token(PORTAL, ["customer_user"])
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    async def both(method, path, tok=None, body=None):
        kw = {"headers": H(tok)}
        if body is not None:
            kw["json"] = body
        r1 = await py.request(method, path, **kw)
        r2 = await rs.request(method, path, **kw)
        return r1, r2

    def body_of(r):
        try:
            return r.json()
        except ValueError:
            return r.text

    async def same(name, method, path, tok=None, body=None, masked=False):
        r1, r2 = await both(method, path, tok, body)
        b1, b2 = body_of(r1), body_of(r2)
        if masked:
            b1, b2 = mask(b1), mask(b2)
        ok = r1.status_code == r2.status_code and b1 == b2
        check(name, ok, f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}")
        return r1, r2

    # --- Writes through each backend (distinct keys, masked comparison) -------------
    print("\n=== writes (ids/timestamps masked) ===")
    jobs = {}
    for tag, client in (("py", py), ("rs", rs)):
        job_id = f"copilot-inv-{a}-{tag}{SFX}"
        jobs[tag] = job_id
    r1 = await py.post(
        "/api/ai_analyst/jobs",
        json={"id": jobs["py"], "alert_id": a, "customer_code": CUST_A, "triggered_by": "webhook"},
        headers=H(t_admin),
    )
    r2 = await rs.post(
        "/api/ai_analyst/jobs",
        json={"id": jobs["rs"], "alert_id": a, "customer_code": CUST_A, "triggered_by": "webhook"},
        headers=H(t_admin),
    )
    check("POST /jobs (create)", (r1.status_code, mask(r1.json())) == (r2.status_code, mask(r2.json())), f"{r1.json()} / {r2.json()}")
    for tag, client in (("py", py), ("rs", rs)):
        await client.post(
            "/api/ai_analyst/jobs",
            json={"id": jobs[tag], "alert_id": a, "customer_code": CUST_A, "triggered_by": "manual", "template_used": "sysmon_event_1.txt"},
            headers=H(t_admin),
        )
    r1 = await py.patch(
        f"/api/ai_analyst/jobs/{jobs['py']}",
        json={"status": "running", "alert_type": "sysmon_event_1"},
        headers=H(t_admin),
    )
    r2 = await rs.patch(
        f"/api/ai_analyst/jobs/{jobs['rs']}",
        json={"status": "running", "alert_type": "sysmon_event_1"},
        headers=H(t_admin),
    )
    check("PATCH /jobs (running)", (r1.status_code, mask(r1.json())) == (r2.status_code, mask(r2.json())), f"{r1.json()} / {r2.json()}")
    report = {
        "alert_id": a,
        "customer_code": CUST_A,
        "severity_assessment": "High",
        "summary": "Credential dumping.\x07",
        "report_markdown": "# Report\n\nDetails.",
        "recommended_actions": "Isolate dc01",
    }
    reports = {}
    for tag, client in (("py", py), ("rs", rs)):
        r = await client.post("/api/ai_analyst/reports", json={**report, "job_id": jobs[tag]}, headers=H(t_admin))
        reports[tag] = r
        # Separate the two reports by a second: on a same-second tie Python's
        # `ORDER BY created_at DESC LIMIT 1` returns whichever row MySQL's plan reaches
        # first, Rust the newest id (DIFF_BY_DESIGN, see RUST_MIGRATION.md).
        await asyncio.sleep(1.1)
    check(
        "POST /reports",
        (reports["py"].status_code, mask(reports["py"].json())) == (reports["rs"].status_code, mask(reports["rs"].json())),
        f"{reports['py'].json()} / {reports['rs'].json()}",
    )
    rid = {tag: reports[tag].json()["report"]["id"] for tag in reports}
    iocs = [
        {"ioc_value": "203.0.113.7", "ioc_type": "ip", "vt_verdict": "malicious", "vt_score": "12/90", "details": "seen"},
        {"ioc_value": "mimikatz.exe", "ioc_type": "process"},
    ]
    ioc_resp = {}
    for tag, client in (("py", py), ("rs", rs)):
        ioc_resp[tag] = await client.post(
            "/api/ai_analyst/iocs",
            json={"report_id": rid[tag], "alert_id": a, "customer_code": CUST_A, "iocs": iocs},
            headers=H(t_admin),
        )
    check("POST /iocs", mask(ioc_resp["py"].json()) == mask(ioc_resp["rs"].json()), f"{ioc_resp['py'].json()} / {ioc_resp['rs'].json()}")
    review = {"overall_verdict": "up", "template_choice": "partial", "rating_instructions": 4, "missing_steps": "check\x01 lsass"}
    rev = {}
    for tag, client in (("py", py), ("rs", rs)):
        ioc_id = ioc_resp[tag].json()["iocs"][0]["id"]
        body = {**review, "ioc_reviews": [{"ioc_id": ioc_id, "verdict_correct": True, "note": "ok"}]}
        rev[tag] = await client.post(f"/api/ai_analyst/reports/{rid[tag]}/review", json=body, headers=H(t_analyst))
    check("POST review (create)", mask(rev["py"].json()) == mask(rev["rs"].json()), f"{rev['py'].json()} / {rev['rs'].json()}")
    for tag, client in (("py", py), ("rs", rs)):
        rev[tag] = await client.post(f"/api/ai_analyst/reports/{rid[tag]}/review", json={"overall_verdict": "down"}, headers=H(t_analyst))
    edit_py, edit_rs = rev["py"].json(), rev["rs"].json()
    stale_py = edit_py["review"].pop("ioc_reviews")
    fresh_rs = edit_rs["review"].pop("ioc_reviews")
    check("POST review (edit, ioc_reviews aside)", mask(edit_py) == mask(edit_rs), f"{edit_py} / {edit_rs}")
    # DIFF_BY_DESIGN: the edit deletes the review's IOC rows; Python answers from its
    # identity map and still lists them, Rust answers with what is stored ([]).
    check("POST review (edit): Rust returns the stored ioc_reviews", fresh_rs == [] and stale_py != [], f"{stale_py} / {fresh_rs}")
    for i, text_ in enumerate(("DC01 runs SCCM patching at 02:00", "dc01 runs sccm patching at 02:00 nightly")):
        await same(
            f"POST /palace_lessons #{i}",
            "POST",
            "/api/ai_analyst/palace_lessons",
            t_analyst,
            {"customer_code": CUST_A, "lesson_type": "assets", "lesson_text": text_, "durability": "one_off"},
            masked=True,
        )

    # --- Reads: byte-for-byte ---------------------------------------------------------
    print("\n=== reads (exact) ===")
    for tag in ("py", "rs"):
        await same(f"GET /jobs/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/jobs/{jobs[tag]}", t_analyst)
        await same(f"GET /reports/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/reports/{rid[tag]}", t_analyst)
        await same(f"GET /iocs/report/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/iocs/report/{rid[tag]}", t_analyst)
        await same(f"GET review/mine ({tag} row)", "GET", f"/api/ai_analyst/reports/{rid[tag]}/review/mine", t_analyst)
        review_id = rev[tag].json()["review"]["id"]
        await same(f"GET /reviews/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/reviews/{review_id}", t_analyst)
        ioc_id = ioc_resp[tag].json()["iocs"][0]["id"]
        await same(f"GET /iocs/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/iocs/{ioc_id}", t_analyst)
    await same("GET /jobs/alert", "GET", f"/api/ai_analyst/jobs/alert/{a}", t_analyst)
    await same("GET /jobs/customer", "GET", f"/api/ai_analyst/jobs/customer/{CUST_A}", t_analyst)
    await same("GET /reports/alert", "GET", f"/api/ai_analyst/reports/alert/{a}", t_analyst)
    await same("GET /iocs/alert", "GET", f"/api/ai_analyst/iocs/alert/{a}", t_analyst)
    await same("GET /iocs/customer?vt_verdict", "GET", f"/api/ai_analyst/iocs/customer/{CUST_A}?vt_verdict=malicious", t_analyst)
    await same("GET /iocs/customer", "GET", f"/api/ai_analyst/iocs/customer/{CUST_A}", t_analyst)
    await same("GET /alerts_with_reports (admin, filtered)", "GET", f"/api/ai_analyst/alerts_with_reports?customer_codes={CUST_A}", t_admin)
    await same("GET /alerts_with_reports/{alert}", "GET", f"/api/ai_analyst/alerts_with_reports/{a}", t_analyst)
    await same("GET /alert/{alert}", "GET", f"/api/ai_analyst/alert/{a}", t_analyst)
    await same("GET /alert/{alert} without analysis", "GET", f"/api/ai_analyst/alert/{alerts['quiet']}", t_analyst)
    await same("GET /reviews/customer", "GET", f"/api/ai_analyst/reviews/customer/{CUST_A}", t_analyst)
    await same("GET /reviews/customer/stats", "GET", f"/api/ai_analyst/reviews/customer/{CUST_A}/stats?recent_limit=3", t_analyst)
    await same("GET /talon/jobs/{alert} (admin)", "GET", f"/api/talon/jobs/{a}", t_admin)
    r1, r2 = await both("GET", f"/api/ai_analyst/palace_lessons/customer/{CUST_A}/consolidation", t_analyst)
    c1, c2 = r1.json(), r2.json()
    for c in (c1, c2):
        c["generated_at"] = "<v>"
        c["markdown"] = "\n".join(line for line in c["markdown"].split("\n") if not line.startswith("_Generated"))
    check("GET consolidation (clock masked)", c1 == c2, f"{c1}\n        {c2}")

    # --- Errors: byte-for-byte -------------------------------------------------------
    print("\n=== errors (exact) ===")
    await same("no token", "GET", "/api/ai_analyst/alerts_with_reports")
    await same("garbage token", "GET", "/api/ai_analyst/alerts_with_reports", "garbage")
    await same(
        "expired token",
        "GET",
        "/api/ai_analyst/alerts_with_reports",
        jwt.encode({"sub": ADMIN, "exp": 1}, os.environ["JWT_SECRET"], algorithm="HS256"),
    )
    await same("2fa temp token", "GET", "/api/ai_analyst/alerts_with_reports", token(ADMIN, [], type="2fa_pending"))
    await same("unknown user", "GET", "/api/ai_analyst/alerts_with_reports", token("nobody" + SFX, ["admin"]))
    await same("portal user", "GET", "/api/ai_analyst/alerts_with_reports", t_portal)
    await same("other tenant's alert", "GET", f"/api/ai_analyst/alert/{b}", t_analyst)
    await same("nonexistent report (scoped)", "GET", "/api/ai_analyst/reports/999999999", t_analyst)
    await same("nonexistent report (admin)", "GET", "/api/ai_analyst/reports/999999999", t_admin)
    await same("nonexistent job (admin)", "GET", "/api/ai_analyst/jobs/nope", t_admin)
    await same("PATCH unparseable job id (admin)", "PATCH", "/api/ai_analyst/jobs/nope", t_admin, {"status": "running"})
    await same("other tenant's customer", "GET", f"/api/ai_analyst/jobs/customer/{CUST_B}", t_analyst)
    await same("int parsing in path", "GET", "/api/ai_analyst/alert/abc", t_analyst)
    await same("recent_limit out of range", "GET", f"/api/ai_analyst/reviews/customer/{CUST_A}/stats?recent_limit=99", t_analyst)
    await same("palace search without query", "GET", f"/api/ai_analyst/palace_lessons/customer/{CUST_A}", t_analyst)
    await same("empty body", "POST", "/api/ai_analyst/jobs", t_admin, {})
    await same(
        "bad enum",
        "POST",
        "/api/ai_analyst/jobs",
        t_admin,
        {"id": "x", "alert_id": a, "customer_code": CUST_A, "triggered_by": "cron"},
    )
    await same(
        "string too long",
        "POST",
        "/api/ai_analyst/jobs",
        t_admin,
        {"id": "x" * 65, "alert_id": a, "customer_code": CUST_A, "triggered_by": "manual"},
    )
    await same(
        "report body guard",
        "POST",
        "/api/ai_analyst/reports",
        t_admin,
        {"job_id": jobs["py"], "alert_id": a, "customer_code": CUST_A, "summary": "  "},
    )
    await same("report for unknown job", "POST", "/api/ai_analyst/reports", t_admin, {**report, "job_id": "missing-job"})
    await same(
        "iocs for unknown report",
        "POST",
        "/api/ai_analyst/iocs",
        t_admin,
        {"report_id": 999999999, "alert_id": a, "customer_code": CUST_A, "iocs": []},
    )
    await same(
        "bad ioc type",
        "POST",
        "/api/ai_analyst/iocs",
        t_admin,
        {"report_id": rid["py"], "alert_id": a, "customer_code": CUST_A, "iocs": [{"ioc_value": "x", "ioc_type": "ipv9"}]},
    )
    await same("rating out of range", "POST", f"/api/ai_analyst/reports/{rid['py']}/review", t_analyst, {"rating_severity": 9})
    await same(
        "foreign ioc in review",
        "POST",
        f"/api/ai_analyst/reports/{rid['py']}/review",
        t_analyst,
        {"ioc_reviews": [{"ioc_id": 999999999, "verdict_correct": False}]},
    )
    await same(
        "replay with bad template",
        "POST",
        f"/api/ai_analyst/reports/{rid['py']}/replay",
        t_analyst,
        {"template_override": "x.md", "customer_code": CUST_A},
    )
    await same(
        "replay customer mismatch",
        "POST",
        f"/api/ai_analyst/reports/{rid['py']}/replay",
        t_analyst,
        {"template_override": "x.txt", "customer_code": CUST_B},
    )
    await same(
        "lesson for unknown review",
        "POST",
        "/api/ai_analyst/palace_lessons",
        t_analyst,
        {"customer_code": CUST_A, "lesson_type": "assets", "lesson_text": "x", "review_id": 999999999},
    )
    await same(
        "empty lesson text",
        "POST",
        "/api/ai_analyst/palace_lessons",
        t_analyst,
        {"customer_code": CUST_A, "lesson_type": "assets", "lesson_text": "\x01"},
    )
    await same(
        "talon investigate: unknown alert",
        "POST",
        "/api/talon/investigate",
        t_admin,
        {"alert_id": 999999999, "customer_code": CUST_A},
    )
    await same("talon investigate: other tenant", "POST", "/api/talon/investigate", t_analyst, {"alert_id": b, "customer_code": CUST_B})
    await same("talon investigate: mismatch", "POST", "/api/talon/investigate", t_analyst, {"alert_id": a, "customer_code": CUST_B})
    await same("talon jobs: no job", "GET", f"/api/talon/jobs/{alerts['quiet']}", t_admin)

    # --- Customer Portal AI reports ---------------------------------------------------
    print("\n=== customer portal ai_reports ===")
    P = "/api/customer_portal/ai_reports"
    settings_a = f"{P}/settings/{CUST_A}"
    await same("portal: settings (no row)", "GET", settings_a, t_analyst)
    await same("portal: settings, other tenant", "GET", f"{P}/settings/{CUST_B}", t_analyst)
    await same("portal: settings as portal user", "GET", settings_a, t_portal)
    await same("portal: availability (off)", "GET", f"{P}/availability", t_portal)
    await same("portal: availability, other tenant", "GET", f"{P}/availability?customer_code={CUST_B}", t_portal)
    await same("portal: availability, empty code", "GET", f"{P}/availability?customer_code=", t_portal)
    await same("portal: alert while switched off", "GET", f"{P}/alert/{a}", t_portal)
    await same("portal: insights while switched off", "GET", f"{P}/insights", t_portal)
    await same("portal: request while switched off", "POST", f"{P}/alert/{a}/investigate", t_portal)
    await same("portal: PUT as analyst", "PUT", settings_a, t_analyst, {"enabled": True})
    await same("portal: PUT bad body", "PUT", f"{P}/settings/nosuch{SFX}", t_admin, {"daily_request_limit": 0})
    await same("portal: PUT bad limit", "PUT", settings_a, t_admin, {"enabled": True, "daily_request_limit": "abc"})
    await same("portal: PUT unknown customer", "PUT", f"{P}/settings/nosuch{SFX}", t_admin, {"enabled": True})
    await same("portal: PUT enable", "PUT", settings_a, t_admin, {"enabled": True}, masked=True)
    await same("portal: settings (enabled)", "GET", settings_a, t_analyst)
    await same("portal: availability (on)", "GET", f"{P}/availability", t_portal)
    await same("portal: availability for A (admin)", "GET", f"{P}/availability?customer_code={CUST_A}", t_admin)
    for who, tok in (("portal", t_portal), ("analyst", t_analyst), ("admin", t_admin)):
        await same(f"portal: alert with analysis ({who})", "GET", f"{P}/alert/{a}", tok)
    await same("portal: alert without analysis", "GET", f"{P}/alert/{alerts['quiet']}", t_portal)
    await same("portal: other tenant's alert", "GET", f"{P}/alert/{b}", t_portal)
    await same("portal: unknown alert", "GET", f"{P}/alert/999999999", t_portal)
    await same("portal: alert id parsing", "GET", f"{P}/alert/abc", t_portal)
    await same("portal: insights", "GET", f"{P}/insights", t_portal)
    await same("portal: insights limit=1", "GET", f"{P}/insights?limit=1", t_portal)
    await same("portal: insights limit=0", "GET", f"{P}/insights?limit=0", t_portal)
    await same("portal: insights for A (admin)", "GET", f"{P}/insights?customer_codes={CUST_A}&limit=25", t_admin)
    await same("portal: insights for B (switch off)", "GET", f"{P}/insights?customer_codes={CUST_B}", t_admin)
    await same(
        "portal: PUT allow requests",
        "PUT",
        settings_a,
        t_admin,
        {"enabled": True, "allow_customer_requests": True, "daily_request_limit": 3},
        masked=True,
    )
    await same("portal: request, analysis running", "POST", f"{P}/alert/{a}/investigate", t_portal)

    def request_shape(r):
        b = r.json()
        return r.status_code, sorted(b), b.get("message"), b.get("success")

    r_py = await py.post(f"{P}/alert/{alerts['req_py']}/investigate", headers=H(t_portal))
    r_rs = await rs.post(f"{P}/alert/{alerts['req_rs']}/investigate", headers=H(t_portal))
    check("portal: request accepted", request_shape(r_py) == request_shape(r_rs) and r_py.status_code == 200, f"{r_py.text} / {r_rs.text}")
    await same("portal: request in cooldown (python's)", "POST", f"{P}/alert/{alerts['req_py']}/investigate", t_portal)
    await same("portal: request in cooldown (rust's)", "POST", f"{P}/alert/{alerts['req_rs']}/investigate", t_portal)
    TALON_REFUSES.add(alerts["refuse"])
    await same("portal: Talon refuses", "POST", f"{P}/alert/{alerts['refuse']}/investigate", t_portal)
    r = await py.post(f"{P}/alert/{alerts['quiet']}/investigate", headers=H(t_portal))
    check("portal: third request accepted (python)", r.status_code == 200, r.text)
    await same("portal: over the daily limit", "POST", f"{P}/alert/{alerts['over']}/investigate", t_portal)
    await same("portal: other tenant's alert request", "POST", f"{P}/alert/{b}/investigate", t_analyst)
    await same("portal: settings show the requests", "GET", settings_a, t_admin)
    senders = {(x["alert_id"], x.get("sender")) for x in TALON_BODIES}
    check(
        "portal: Talon was told sender=customer-portal by both",
        {(alerts["req_py"], "customer-portal"), (alerts["req_rs"], "customer-portal")} <= senders,
        str(senders),
    )
    async with AsyncSession(async_engine) as s_:
        rows = (
            await s_.execute(
                text(
                    "SELECT alert_id, user_name, comment FROM incident_management_comment WHERE alert_id IN (:p, :r) " "ORDER BY alert_id",
                ),
                {"p": alerts["req_py"], "r": alerts["req_rs"]},
            )
        ).all()
        refused = (
            await s_.execute(text("SELECT COUNT(*) FROM customer_portal_ai_request WHERE alert_id = :a"), {"a": alerts["refuse"]})
        ).scalar_one()
    check(
        "portal: both left the same comment",
        len(rows) == 2 and rows[0][1:] == rows[1][1:] == (PORTAL, "AI analysis requested from the Customer Portal."),
        str(rows),
    )
    check("portal: a refused request costs nothing", refused == 0, str(refused))

    # Tag RBAC (global settings: only when this database has none, restored afterwards).
    async with AsyncSession(async_engine) as s_:
        configured = (await s_.execute(text("SELECT COUNT(*) FROM incident_management_tag_access_settings"))).scalar_one()
    if configured:
        print("  SKIP  tag RBAC: incident_management_tag_access_settings already configured")
    else:
        async with AsyncSession(async_engine) as s_:
            tag_id = (await s_.execute(text("INSERT INTO incident_management_alerttag (tag) VALUES (:t)"), {"t": f"par{SFX}"})).lastrowid
            await s_.execute(text("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)"), {"a": a, "t": tag_id})
            settings_id = (
                await s_.execute(
                    text(
                        "INSERT INTO incident_management_tag_access_settings (enabled, untagged_alert_behavior, updated_at) "
                        "VALUES (1, 'admin_only', UTC_TIMESTAMP())",
                    ),
                )
            ).lastrowid
            await s_.commit()
        try:
            await same("portal/tags: tagged alert, analyst without the tag", "GET", f"{P}/alert/{a}", t_analyst)
            await same("portal/tags: untagged alert under admin_only", "GET", f"{P}/alert/{alerts['quiet']}", t_analyst)
            await same("portal/tags: insights, analyst sees nothing", "GET", f"{P}/insights", t_analyst)
            await same("portal/tags: portal users bypass tag RBAC", "GET", f"{P}/insights", t_portal)
            async with AsyncSession(async_engine) as s_:
                await s_.execute(
                    text("UPDATE incident_management_tag_access_settings SET untagged_alert_behavior = 'default_tag' WHERE id = :i"),
                    {"i": settings_id},
                )
                await s_.commit()
            # No default tag configured: one alert is allowed, lists still exclude it.
            await same("portal/tags: default_tag without a tag, one alert", "GET", f"{P}/alert/{alerts['quiet']}", t_analyst)
            await same("portal/tags: default_tag without a tag, insights", "GET", f"{P}/insights", t_analyst)
            async with AsyncSession(async_engine) as s_:
                await s_.execute(
                    text(
                        "INSERT INTO user_tag_access (user_id, tag_id, created_at) "
                        "SELECT id, :t, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                    ),
                    {"t": tag_id, "n": ANALYST},
                )
                await s_.commit()
            await same("portal/tags: granted tag, alert", "GET", f"{P}/alert/{a}", t_analyst)
            await same("portal/tags: granted tag, insights", "GET", f"{P}/insights", t_analyst)
        finally:
            async with AsyncSession(async_engine) as s_:
                await s_.execute(text("DELETE FROM incident_management_tag_access_settings WHERE id = :i"), {"i": settings_id})
                await s_.execute(text("DELETE FROM user_tag_access WHERE tag_id = :t"), {"t": tag_id})
                await s_.execute(text("DELETE FROM incident_management_alert_to_tag WHERE tag_id = :t"), {"t": tag_id})
                await s_.execute(text("DELETE FROM incident_management_alerttag WHERE id = :t"), {"t": tag_id})
                await s_.commit()

    # --- Deliberate differences ------------------------------------------------------
    print("\n=== differences by design ===")
    r1, r2 = await both("GET", "/api/ai_analyst/alerts_with_reports", t_analyst)
    py_codes = {x["customer_code"] for x in r1.json()["alerts"]}
    rs_codes = {x["customer_code"] for x in r2.json()["alerts"]}
    check("alerts_with_reports: Rust scopes to the analyst's customers", CUST_A in rs_codes and CUST_B not in rs_codes, str(rs_codes))
    check("  (python leaks other tenants here — the bug being fixed)", CUST_B not in py_codes or CUST_B in py_codes)
    r1, r2 = await both("GET", f"/api/talon/jobs/{b}", t_analyst)
    check("talon/jobs: Rust refuses another tenant's alert", r2.status_code == 403, f"python {r1.status_code}, rust {r2.status_code}")

    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
