"""Parity of the Rust Customer Portal module with this backend — NOT collected by pytest
(needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

Sends the same requests to the real FastAPI routers (`app/routers/customer_portal.py`,
in-process, behind the production app's `GZipMiddleware(minimum_size=1000)`) and to a Rust
instance this suite starts (`crates/copilot-customer-portal`), both on the same disposable
database, and compares status codes, bodies (key order included), the bytes and headers of
the logos and the CSV export, and the rows each write leaves. None of these routes calls an
upstream, so there is no stand-in.

Seeded like `portal_overview_seed.py`, with explicit ids (7_810_000…7_819_999): two tenants
with tagged alerts, cases, agents and AI reports, a portal user per tenant and one with both,
analysts (assigned, unassigned, tag-restricted), a responder, an admin, a scheduler-role user
and a user without a role.

Also checked here:

* the branding caches of the two processes (`services/branding_cache.py`, the Rust
  `BrandingCache`): a write through either backend, and one made in MySQL directly, is served
  by the other within `BRANDING_CACHE_CHECK_SECONDS` (1 s here, both sides) — two writes in
  one second included;
* the Overview's statement budget (`customer_portal_overview_e2e.py`, 12): Python's counted
  with SQLAlchemy's `before_cursor_execute`, Rust's with MySQL's `Questions`;
* the differences by design (RUST_MIGRATION.md §4): `GET /branding` narrowed to a scoped
  analyst's customers; a PATCH naming several empty fields.

Masked, each with a check of its own: the clocks each backend stamps (`updated_at` of a
default row or a write, the CSV file name), and a gzipped body's `Content-Length` (zlib and
the Rust deflate encoder compress the same bytes differently; the decoded bodies are
compared). `X-Frame-Options`, the CORS `Vary` values and `X-Content-Type-Options` outside the
logos come from the Rust service's global layers and are not compared.

Ports (overridable): CUSTOMER_PORTAL_PARITY_RUST_PORT.

    PARITY_SUITES=tests/e2e/rust_parity_customer_portal_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
import json
import os
import re
import subprocess
import sys
import time
import uuid

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# Both processes check the branding tables every second (read at import).
os.environ["BRANDING_CACHE_CHECK_SECONDS"] = "1"
os.environ.pop("BRANDING_CACHE_TTL_SECONDS", None)

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.db.db_session import async_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("CUSTOMER_PORTAL_PARITY_RUST_PORT", "6810"))
RUST = f"http://127.0.0.1:{RS_PORT}"
CHECK_SECONDS = 1.0
#: Python's budget for the Overview (`customer_portal_overview_e2e.py`).
MAX_OVERVIEW_STATEMENTS = 12

SFX = uuid.uuid4().hex[:6]
BASE = 7_810_000
CUST_A, CUST_B = f"CpA{SFX}", f"CpB{SFX}"
USERS = {
    # name: (id, role id, customers)
    "admin": (BASE + 11, 1, []),
    "analyst": (BASE + 12, 2, [CUST_A]),
    "unassigned": (BASE + 13, 2, []),
    "tagged": (BASE + 14, 2, [CUST_A, CUST_B]),
    "responder": (BASE + 15, 5, [CUST_A]),
    "portal_a": (BASE + 16, 4, [CUST_A]),
    "portal_b": (BASE + 17, 4, [CUST_B]),
    "portal_ab": (BASE + 18, 4, [CUST_B, CUST_A]),
    "scheduler": (BASE + 19, 3, []),
    "norole": (BASE + 20, None, [CUST_A]),
}
SCOPES = {
    "admin": ["admin"],
    "analyst": ["analyst"],
    "unassigned": ["analyst"],
    "tagged": ["analyst"],
    "responder": ["responder", "analyst"],
    "portal_a": ["customer_user"],
    "portal_b": ["customer_user"],
    "portal_ab": ["customer_user"],
    "scheduler": ["scheduler"],
    "norole": ["customer_user"],
}
TAGS = {"phishing": BASE + 101, "vip": BASE + 102}
NOW = datetime.datetime(2026, 9, 1, 12, 0, 0)
# (customer, status, source, days before NOW, tags), like portal_overview_seed.ALERT_ROWS_*.
ALERTS = [
    (CUST_A, "OPEN", "wazuh", 10, ["phishing"]),
    (CUST_A, "OPEN", "office365", 8, ["phishing", "vip"]),
    (CUST_A, "OPEN", "wazuh", 5, []),
    (CUST_A, "IN_PROGRESS", "office365", 3, ["vip"]),
    (CUST_A, "PENDING_CUSTOMER", "wazuh", 1, []),
    (CUST_A, "CLOSED", "wazuh", 0, ["phishing"]),
    (CUST_B, "OPEN", "wazuh", 6, []),
    (CUST_B, "OPEN", "office365", 4, ["phishing"]),
    (CUST_B, "CLOSED", "wazuh", 2, []),
    (CUST_B, "CLOSED", "wazuh", 0, []),
]
ALERT_ID = {i: BASE + 201 + i for i in range(len(ALERTS))}
# Asset names per alert index: two on one alert, a hostname shared across tenants.
ASSETS = {0: ["host-a1", "host-a2"], 1: ["host-a3", f"ov-{SFX}-0"], 6: ["host-b1", f"ov-{SFX}-0"]}
CASES = [(CUST_A, "OPEN", [0, 1]), (CUST_A, "PENDING_CUSTOMER", [2]), (CUST_A, "CLOSED", []), (CUST_B, "OPEN", [6])]
CASE_ID = {i: BASE + 501 + i for i in range(len(CASES))}
# (customer, hostname, status, critical, os)
AGENTS = [
    (CUST_A, f"ov-{SFX}-0", "active", 1, "Linux"),
    (CUST_A, f"ov-{SFX}-1", "active", 0, "Windows"),
    (CUST_A, f'desk,"{SFX}"', "disconnected", 0, "linux"),
    (CUST_A, f"ov-{SFX}-3", "never_connected", 0, ""),
    (CUST_B, f"ov-{SFX}-b", "active", 0, "Linux"),
]
AGENT_ID = {i: BASE + 601 + i for i in range(len(AGENTS))}
# Latest report per alert counts: alert 0 has two (the newest Medium), alert 3 one, B's alert 6 one.
REPORTS = [(0, "High", 1), (0, "Medium", 2), (3, None, 3), (6, "Low", 4)]
REPORT_ID = {i: BASE + 701 + i for i in range(len(REPORTS))}
P = "/api/customer_portal"
PNG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + bytes(range(256)) * 6
SMALL_PNG = PNG[:300]

results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def uname(key):
    return f"cp_{key}{SFX}"


# --- the database ---------------------------------------------------------------------------
async def sql(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        await s.commit()
        return r


async def rows(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        return [dict(m) for m in r.mappings().all()]


SAVED = {}


async def seed():
    # The singletons this suite changes, put back by `cleanup`.
    SAVED["settings"] = await rows("SELECT * FROM customer_portal_settings ORDER BY id")
    SAVED["tag_settings"] = await rows("SELECT * FROM incident_management_tag_access_settings ORDER BY id")
    await sql("DELETE FROM customer_portal_settings")
    for i, (code, name) in enumerate(((CUST_A, "Acme Rome"), (CUST_B, "  "))):
        await sql(
            "INSERT INTO customers (id, customer_code, customer_name, created_at) VALUES (:id, :c, :n, :t)",
            id=BASE + 1 + i,
            c=code,
            n=name,
            t=NOW,
        )
    for key, (uid, role, customers) in USERS.items():
        await sql(
            "INSERT INTO `user` (id, username, password, email, created_at, role_id) VALUES (:id, :u, 'x', :e, :t, :r)",
            id=uid,
            u=uname(key),
            e=f"{key}@parity.test",
            t=NOW,
            r=role,
        )
        for j, code in enumerate(customers):
            await sql(
                "INSERT INTO user_customer_access (id, user_id, customer_code, created_at) VALUES (:id, :u, :c, :t)",
                id=BASE + 1000 + (uid - BASE) * 10 + j,
                u=uid,
                c=code,
                t=NOW,
            )
    for name, tid in TAGS.items():
        await sql("INSERT INTO incident_management_alerttag (id, tag) VALUES (:id, :t)", id=tid, t=f"cp-{name}-{SFX}")
    await sql(
        "INSERT INTO user_tag_access (id, user_id, tag_id, created_at) VALUES (:id, :u, :t, :n)",
        id=BASE + 901,
        u=USERS["tagged"][0],
        t=TAGS["vip"],
        n=NOW,
    )
    await sql("INSERT INTO incident_management_alertcontext (id, source, context) VALUES (:id, 'wazuh', '{}')", id=BASE + 301)
    for i, (code, status, source, days, tags) in enumerate(ALERTS):
        await sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, "
            "customer_code, source, escalated) VALUES (:id, :n, :d, :s, :t, :c, :src, 0)",
            id=ALERT_ID[i],
            n=f"{code} alert {i}",
            d=f"description {i}",
            s=status,
            t=NOW - datetime.timedelta(days=days) + datetime.timedelta(minutes=i),
            c=code,
            src=source,
        )
        for tag in tags:
            await sql("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)", a=ALERT_ID[i], t=TAGS[tag])
    asset = BASE + 401
    for i, names in ASSETS.items():
        for name in names:
            await sql(
                "INSERT INTO incident_management_asset (id, alert_linked, asset_name, alert_context_id, customer_code, "
                "index_name, index_id) VALUES (:id, :a, :n, :ctx, :c, 'idx', 'doc')",
                id=asset,
                a=ALERT_ID[i],
                n=name,
                ctx=BASE + 301,
                c=ALERTS[i][0],
            )
            asset += 1
    for i, (code, status, linked) in enumerate(CASES):
        await sql(
            "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, "
            "assigned_to, customer_code, escalated) VALUES (:id, :n, 'cd', :t, :s, :a, :c, 0)",
            id=CASE_ID[i],
            n=f"{code} case {i}",
            t=NOW - datetime.timedelta(days=5 - i),
            s=status,
            a=uname("analyst") if i == 0 else None,
            c=code,
        )
        for a in linked:
            await sql("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=CASE_ID[i], a=ALERT_ID[a])
    for i, (code, host, status, critical, os_name) in enumerate(AGENTS):
        await sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
            "wazuh_agent_version, wazuh_agent_status, customer_code, quarantined, velociraptor_id_pinned) VALUES "
            "(:id, :aid, :ip, :os, :h, 'grp', :crit, :seen, :v, :s, :c, 0, 0)",
            id=AGENT_ID[i],
            aid=f"{SFX}{i:03d}",
            ip=f"10.9.0.{i}",
            os=os_name,
            h=host,
            crit=critical,
            seen=NOW + datetime.timedelta(seconds=i),
            v=f"Wazuh v4.9.{i}",
            s=status,
            c=code,
        )
    for i, (alert, severity, minute) in enumerate(REPORTS):
        job = f"cp-{SFX}-{i}"
        code = ALERTS[alert][0]
        await sql(
            "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, triggered_by, created_at) "
            "VALUES (:id, :a, :c, 'completed', 'webhook', :t)",
            id=job,
            a=ALERT_ID[alert],
            c=code,
            t=NOW + datetime.timedelta(minutes=minute),
        )
        await sql(
            "INSERT INTO ai_analyst_report (id, job_id, alert_id, customer_code, severity_assessment, summary, created_at) "
            "VALUES (:id, :j, :a, :c, :s, :sum, :t)",
            id=REPORT_ID[i],
            j=job,
            a=ALERT_ID[alert],
            c=code,
            s=severity,
            sum=f"summary {i}",
            t=NOW + datetime.timedelta(minutes=minute),
        )
    await sql(
        "INSERT INTO customer_portal_ai_report_settings (id, customer_code, enabled, updated_at) VALUES (:id, :c, 1, :t)",
        id=BASE + 801,
        c=CUST_A,
        t=NOW,
    )


async def cleanup():
    codes = {"a": CUST_A, "b": CUST_B}
    for query in (
        "DELETE FROM customer_portal_branding WHERE customer_code IN (:a, :b)",
        "DELETE FROM customer_portal_ai_report_settings WHERE customer_code IN (:a, :b)",
        "DELETE FROM ai_analyst_report WHERE customer_code IN (:a, :b)",
        "DELETE FROM ai_analyst_job WHERE customer_code IN (:a, :b)",
        "DELETE FROM incident_management_casealertlink WHERE case_id IN (SELECT id FROM incident_management_case "
        "WHERE customer_code IN (:a, :b))",
        "DELETE FROM incident_management_case WHERE customer_code IN (:a, :b)",
        "DELETE FROM incident_management_asset WHERE customer_code IN (:a, :b)",
        "DELETE FROM incident_management_alert_to_tag WHERE alert_id IN (SELECT id FROM incident_management_alert "
        "WHERE customer_code IN (:a, :b))",
        "DELETE FROM incident_management_alert WHERE customer_code IN (:a, :b)",
        "DELETE FROM agents WHERE customer_code IN (:a, :b)",
    ):
        await sql(query, **codes)
    await sql("DELETE FROM incident_management_alertcontext WHERE id = :id", id=BASE + 301)
    await sql("DELETE FROM user_tag_access WHERE id = :id", id=BASE + 901)
    await sql("DELETE FROM incident_management_alerttag WHERE id IN :ids", ids=tuple(TAGS.values()))
    ids = tuple(u[0] for u in USERS.values())
    await sql("DELETE FROM user_customer_access WHERE user_id IN :ids", ids=ids)
    await sql("DELETE FROM log_entries WHERE user_id IN :ids", ids=ids)
    await sql("DELETE FROM `user` WHERE id IN :ids", ids=ids)
    await sql("DELETE FROM customers WHERE customer_code IN (:a, :b)", **codes)
    await restore_settings(SAVED.get("settings", []))
    await sql("DELETE FROM incident_management_tag_access_settings")
    for row in SAVED.get("tag_settings", []):
        await sql(
            "INSERT INTO incident_management_tag_access_settings ({}) VALUES ({})".format(
                ", ".join(row),
                ", ".join(f":{k}" for k in row),
            ),
            **row,
        )


async def restore_settings(saved):
    await sql("DELETE FROM customer_portal_settings")
    for row in saved:
        await sql(
            "INSERT INTO customer_portal_settings ({}) VALUES ({})".format(", ".join(row), ", ".join(f":{k}" for k in row)),
            **row,
        )


async def settings_rows():
    return await rows(
        "SELECT id, title, logo_base64, logo_mime_type, brand_color, updated_at, updated_by FROM customer_portal_settings ORDER BY id",
    )


async def override_rows():
    return await rows(
        "SELECT id, customer_code, enabled, title, logo_base64, logo_mime_type, brand_color, updated_at, updated_by "
        "FROM customer_portal_branding WHERE customer_code IN (:a, :b) ORDER BY customer_code",
        a=CUST_A,
        b=CUST_B,
    )


def settings_state(state):
    """A reset putting the global settings table in `state` (None: no row), with its counter."""

    async def reset():
        await sql("DELETE FROM customer_portal_settings")
        if state is not None:
            await sql(
                "INSERT INTO customer_portal_settings (id, title, logo_base64, logo_mime_type, brand_color, updated_at, "
                "updated_by) VALUES (:id, :title, :logo, :mime, :color, :t, NULL)",
                id=BASE + 50,
                title=state.get("title", "CoPilot"),
                logo=state.get("logo"),
                mime=state.get("mime"),
                color=state.get("color"),
                t=state.get("updated_at", NOW),
            )
        await sql(f"ALTER TABLE customer_portal_settings AUTO_INCREMENT = {BASE + 51}")

    return reset


def overrides_state(**state):
    """A reset putting the two customers' overrides in `state` (customer → fields), with the counter."""

    async def reset():
        await sql("DELETE FROM customer_portal_branding WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
        for i, (code, fields) in enumerate(state.items()):
            await sql(
                "INSERT INTO customer_portal_branding (id, customer_code, enabled, title, logo_base64, logo_mime_type, "
                "brand_color, updated_at, updated_by) VALUES (:id, :c, :e, :t, :l, :m, :col, :u, NULL)",
                id=BASE + 60 + i,
                c={"a": CUST_A, "b": CUST_B}[code],
                e=fields.get("enabled", 1),
                t=fields.get("title"),
                l=fields.get("logo"),
                m=fields.get("mime"),
                col=fields.get("color"),
                u=NOW,
            )
        await sql(f"ALTER TABLE customer_portal_branding AUTO_INCREMENT = {BASE + 70}")

    return reset


# --- the two backends ---------------------------------------------------------------------
def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import customer_portal

    api = APIRouter(prefix="/api")
    api.include_router(customer_portal.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust():
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        "COPILOT_PORT": str(RS_PORT),
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "BRANDING_CACHE_CHECK_SECONDS": "1",
        "TZ": os.environ.get("TZ", "UTC"),
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"{RUST}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


#: Stamps the two backends write at their own instant.
CLOCK_KEYS = {"updated_at"}


def same_instant(a, b, slack=10):
    try:
        ta = datetime.datetime.fromisoformat(str(a).replace("Z", "+00:00").replace(" ", "T"))
        tb = datetime.datetime.fromisoformat(str(b).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return False
    if (ta.tzinfo is None) != (tb.tzinfo is None):
        return False
    return abs((ta - tb).total_seconds()) <= slack


def mask_clocks(p, q):
    """`updated_at` written by each backend at its own instant: masked where the two are within
    seconds of each other (anything else stays a difference)."""
    if isinstance(p, dict) and isinstance(q, dict):
        out_p, out_q = {}, {}
        for k in p:
            if k in CLOCK_KEYS and k in q and p[k] != q[k] and same_instant(p[k], q[k]):
                out_p[k] = out_q[k] = "<now>"
            elif k in q:
                out_p[k], out_q[k] = mask_clocks(p[k], q[k])
            else:
                out_p[k] = p[k]
        for k in q:
            if k not in out_q:
                out_q[k] = q[k]
        return {k: out_p[k] for k in p}, {k: out_q[k] for k in q}
    if isinstance(p, list) and isinstance(q, list) and len(p) == len(q):
        pairs = [mask_clocks(a, b) for a, b in zip(p, q)]
        return [a for a, _ in pairs], [b for _, b in pairs]
    return p, q


#: Response headers of the byte routes worth comparing (the rest come from the servers or,
#: on the Rust side, from its global layers).
GLOBAL_LAYER_VARY = {"origin", "access-control-request-method", "access-control-request-headers"}
STAMP = re.compile(r"assets-export-\d{4}-\d\d-\d\d-\d\d-\d\d-\d\d\.csv")


def byte_headers(r, keep_nosniff):
    out = []
    gzipped = r.headers.get("content-encoding") == "gzip"
    for k, v in r.headers.multi_items():
        k = k.lower()
        if k in ("date", "server", "x-frame-options") or k.startswith("access-control-"):
            continue
        if k == "x-content-type-options" and not keep_nosniff:
            continue
        if k == "content-length" and gzipped:
            continue
        if k == "vary":
            tokens = [t.strip() for t in v.split(",") if t.strip().lower() not in GLOBAL_LAYER_VARY]
            if not tokens:
                continue
            v = ", ".join(tokens)
        if k == "content-disposition":
            v = STAMP.sub("assets-export-<now>.csv", v)
        out.append([k, v])
    return sorted(out)


#: `Agents`' columns in declaration order: the order Rust sends a row in. Python's follows
#: the order SQLAlchemy loaded the attributes in, which changes between processes (§4).
AGENT_FIELDS = [
    "id",
    "agent_id",
    "ip_address",
    "os",
    "hostname",
    "label",
    "critical_asset",
    "wazuh_last_seen",
    "velociraptor_id",
    "velociraptor_last_seen",
    "wazuh_agent_version",
    "wazuh_agent_status",
    "velociraptor_agent_version",
    "customer_code",
    "quarantined",
    "velociraptor_org",
    "velociraptor_id_pinned",
]


def agent_rows_by_key(body):
    """The agent rows with their keys sorted (compared key by key)."""
    if isinstance(body, dict) and isinstance(body.get("agents"), list):
        return {**body, "agents": [dict(sorted(a.items())) for a in body["agents"]]}
    return body


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


class Statements:
    """SQL statements Python sends (SQLAlchemy's `before_cursor_execute`)."""

    def __init__(self):
        self.seen = []
        event.listen(async_engine.sync_engine, "before_cursor_execute", self._record)

    def _record(self, conn, cursor, statement, *args):
        self.seen.append(statement)


async def questions():
    """MySQL's `Questions`: statements from every client."""
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text("SHOW GLOBAL STATUS LIKE 'Questions'"))
        return int(r.all()[0][1])


async def main():  # noqa: C901 - one scenario after the other
    await seed()
    rust = start_rust()
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=60)
    T = {key: token(uname(key), SCOPES[key]) for key in USERS}
    A, B = CUST_A, CUST_B

    async def settle():
        """Past both caches' change-check interval."""
        await asyncio.sleep(CHECK_SECONDS + 0.4)

    async def send(client, method, path, tok, body, raw, headers):
        kw = {"headers": {**({"Authorization": f"Bearer {tok}"} if tok else {}), **(headers or {})}}
        if raw is not None:
            kw["content"] = raw
            kw["headers"].setdefault("Content-Type", "application/json")
        elif body is not None:
            kw["json"] = body
        return await client.request(method, path, **kw)

    async def both(name, method, path, tok=None, body=None, raw=None, headers=None, reset=None, snapshot=None, kind="json"):
        """The responses and (`snapshot`) the rows each backend left; `reset` runs before each call."""
        got = {}
        for tag, client in (("py", py), ("rs", rs)):
            if reset is not None:
                await reset()
                await settle()
            r = await send(client, method, path, tok, body, raw, headers)
            got[tag] = {
                "status": r.status_code,
                "type": r.headers.get("content-type"),
                "body": body_of(r) if kind == "json" else r.content,
                # The logos set `X-Content-Type-Options` themselves; elsewhere it is the Rust
                # service's global layer.
                "headers": byte_headers(r, keep_nosniff=kind == "logo" and r.status_code in (200, 304)) if kind != "json" else None,
                "disposition": r.headers.get("content-disposition"),
                "rows": await snapshot() if snapshot else None,
            }
        p, q = got["py"], got["rs"]
        if kind == "json":
            if isinstance(q["body"], dict) and isinstance(q["body"].get("agents"), list) and q["body"]["agents"]:
                check(
                    f"{name}: Rust sends agent rows in declaration order",
                    all(list(a) == AGENT_FIELDS for a in q["body"]["agents"]),
                    str([list(a) for a in q["body"]["agents"]][:1]),
                )
            p["body"], q["body"] = agent_rows_by_key(p["body"]), agent_rows_by_key(q["body"])
            p["body"], q["body"] = mask_clocks(p["body"], q["body"])
            same = p["status"] == q["status"] and p["type"] == q["type"] and json.dumps(p["body"]) == json.dumps(q["body"])
            detail = f"python {p['status']} {p['type']} {json.dumps(p['body'])[:2500]}\n        rust   {q['status']} {q['type']} {json.dumps(q['body'])[:2500]}"
        else:
            same = p["status"] == q["status"] and p["body"] == q["body"] and p["headers"] == q["headers"]
            detail = (
                f"python {p['status']} {p['headers']} {p['body'][:200]!r}\n        rust   {q['status']} {q['headers']} {q['body'][:200]!r}"
            )
        check(f"{name} [{p['status']}]", same, detail)
        if p["disposition"] or q["disposition"]:
            stamps = [STAMP.search(x["disposition"] or "") for x in (p, q)]
            when = [datetime.datetime.strptime(m.group(0)[14:-4], "%Y-%m-%d-%H-%M-%S") if m else None for m in stamps]
            check(
                f"{name}: the file names are stamped within seconds of each other",
                None not in when and abs((when[0] - when[1]).total_seconds()) <= 10,
                f"python {p['disposition']}\n        rust   {q['disposition']}",
            )
        if snapshot:
            pr, qr = mask_clocks(p["rows"], q["rows"])
            check(
                f"{name}: rows",
                json.dumps(pr, default=str) == json.dumps(qr, default=str),
                f"python {json.dumps(pr, default=str)[:3000]}\n        rust   {json.dumps(qr, default=str)[:3000]}",
            )
        return p, q

    t_2fa = token(uname("admin"), [], type="2fa_pending")
    try:
        # ==================================================================
        print("\n=== A. the global settings (no row yet) ===")
        await settings_state(None)()
        S = P + "/settings"
        for label, tok in (("no token", None), ("garbage token", "garbage"), ("portal user", T["portal_a"])):
            await both(f"public settings: {label}", "GET", S, tok)
        await both("public logo: no row", "GET", S + "/logo")
        for label, tok in (
            ("no token", None),
            ("garbage token", "garbage"),
            ("2fa temp token", t_2fa),
            ("portal user", T["portal_a"]),
            ("analyst", T["analyst"]),
            ("responder", T["responder"]),
            ("admin", T["admin"]),
        ):
            await both(f"global settings: {label}", "GET", S + "/global", tok)
        check(
            "no request wrote a default row",
            await settings_rows() == [],
        )

        print("\n=== B. replacing and patching the global settings ===")
        logo = base64.b64encode(PNG).decode()
        no_row = settings_state(None)
        a_row = settings_state({"title": "Before", "logo": base64.b64encode(SMALL_PNG).decode(), "mime": "image/gif", "color": "#111111"})
        await both("POST: malformed JSON, no token", "POST", S, raw=b"{")
        await both("POST: no token", "POST", S, body={"title": "x"})
        await both("POST: 2fa temp token", "POST", S, t_2fa, {"title": "x"})
        await both("POST: analyst", "POST", S, T["analyst"], {"title": "x"})
        await both("POST: no body", "POST", S, T["admin"])
        await both("POST: a list", "POST", S, T["admin"], [])
        await both("POST: a text body", "POST", S, T["admin"], raw=b"title=x", headers={"Content-Type": "text/plain"})
        for label, body in (
            ("a bad colour", {"brand_color": "red"}),
            ("a long colour", {"brand_color": "   #abcdef   "}),
            ("bad base64", {"logo_base64": "QQ="}),
            ("not base64", {"logo_base64": "not base64!"}),
            ("a newline after the padding", {"logo_base64": "QQ==\n"}),
            ("a PDF", {"logo_mime_type": "application/pdf"}),
            ("a long title", {"title": "x" * 256}),
            ("a number as title", {"title": 5}),
            ("three errors", {"title": 5, "logo_base64": "x", "brand_color": "nope"}),
        ):
            await both(f"POST: {label}", "POST", S, T["admin"], body, reset=no_row, snapshot=settings_rows)
        for label, reset in (("no row", no_row), ("a row", a_row)):
            await both(
                f"POST: everything ({label})",
                "POST",
                S,
                T["admin"],
                {
                    "title": "Acme SOC",
                    "logo_base64": f"data:image/png;base64,{logo}",
                    "logo_mime_type": "image/png",
                    "brand_color": " #ABC ",
                },
                reset=reset,
                snapshot=settings_rows,
            )
            await both(f"POST: nothing ({label})", "POST", S, T["admin"], {}, reset=reset, snapshot=settings_rows)
            await both(
                f"POST: nulls ({label})",
                "POST",
                S,
                T["admin"],
                {"title": None, "brand_color": None},
                reset=reset,
                snapshot=settings_rows,
            )
            await both(f"POST: an empty title ({label})", "POST", S, T["admin"], {"title": ""}, reset=reset, snapshot=settings_rows)
        for label, body in (
            ("nothing", {}),
            ("a null title", {"title": None}),
            ("an empty title", {"title": ""}),
            ("a blank colour", {"brand_color": "  "}),
            ("the logo alone", {"logo_base64": logo}),
            ("an empty logo", {"logo_base64": "", "logo_mime_type": "image/png"}),
            ("set and reset", {"title": "x", "reset": ["title"]}),
            (
                "set and reset the logo",
                {"logo_base64": logo, "logo_mime_type": "image/png", "title": "x", "reset": ["logo", "title", "brand_color"]},
            ),
            ("an unknown reset", {"reset": ["x", 5]}),
            ("reset not a list", {"reset": "title"}),
            ("field errors before the model's", {"title": "", "brand_color": "zz", "reset": ["x"]}),
        ):
            await both(f"PATCH: {label}", "PATCH", S, T["admin"], body, reset=a_row, snapshot=settings_rows)
        await both("PATCH: analyst", "PATCH", S, T["analyst"], {"title": "x"})
        for label, reset in (("no row", no_row), ("a row", a_row)):
            for what, body in (
                ("the title", {"title": "Patched"}),
                ("the colour", {"brand_color": "#ABCDEF"}),
                ("the logo", {"logo_base64": logo, "logo_mime_type": "image/png"}),
                ("resets", {"reset": ["logo", "title", "brand_color", "logo"]}),
                ("a reset and a colour", {"reset": ["logo"], "brand_color": "#123"}),
            ):
                await both(f"PATCH {what} ({label})", "PATCH", S, T["admin"], body, reset=reset, snapshot=settings_rows)

        # Several empty fields: Python names whichever its set iterates first (string
        # hashes, per process); Rust the first in declaration order (§4).
        body = {"brand_color": None, "title": None, "logo_mime_type": None, "logo_base64": None}
        r_py = await py.patch(S, json=body, headers={"Authorization": f"Bearer {T['admin']}"})
        r_rs = await rs.patch(S, json=body, headers={"Authorization": f"Bearer {T['admin']}"})
        names = {f'{f} cannot be empty; to restore its default send reset: ["{"logo" if f.startswith("logo_") else f}"]' for f in body}
        check(
            "PATCH: several empty fields: Python names one of them [422]",
            r_py.status_code == 422 and r_py.json()["message"] in names,
            r_py.text,
        )
        check(
            "PATCH: several empty fields: Rust names the first declared [422]",
            r_rs.status_code == 422 and r_rs.json()["message"] == 'title cannot be empty; to restore its default send reset: ["title"]',
            r_rs.text,
        )

        print("\n=== C. the global logo ===")
        with_logo = settings_state(
            {"title": "Logo", "logo": logo, "mime": "image/png", "updated_at": datetime.datetime(2026, 9, 1, 12, 0, 7)},
        )
        await with_logo()
        await settle()
        await both("public settings with a logo", "GET", S)
        await both("global settings with a logo", "GET", S + "/global", T["analyst"])
        version = str(int(datetime.datetime(2026, 9, 1, 12, 0, 7, tzinfo=datetime.timezone.utc).timestamp() * 1000))
        for label, headers in (
            ("identity", {"Accept-Encoding": "identity"}),
            ("gzip", {"Accept-Encoding": "gzip, deflate"}),
            ("If-None-Match, matching", {"If-None-Match": f'"{version}"'}),
            ("If-None-Match, in a list", {"If-None-Match": f'W/"x",  "{version}"'}),
            ("If-None-Match, weak", {"If-None-Match": f'W/"{version}"'}),
            ("If-None-Match, another", {"If-None-Match": '"1"'}),
            ("If-None-Match, empty", {"If-None-Match": ""}),
        ):
            await both(f"public logo: {label}", "GET", S + "/logo", headers=headers, kind="logo")
        for label, state in (
            ("small, no MIME type", {"logo": base64.b64encode(SMALL_PNG).decode(), "mime": None}),
            ("an empty MIME type", {"logo": base64.b64encode(SMALL_PNG).decode(), "mime": ""}),
            ("a text MIME type", {"logo": base64.b64encode(PNG).decode(), "mime": "text/plain"}),
            ("stored with spaces", {"logo": " " + logo, "mime": "image/png"}),
            ("not base64", {"logo": "!!!", "mime": "image/png"}),
            ("a MIME type that is not latin-1", {"logo": logo, "mime": "image/Ā"}),
            ("an empty logo", {"logo": "", "mime": "image/png"}),
        ):
            await settings_state({"title": "Odd", **state})()
            await both(f"public logo: {label}", "GET", S + "/logo", headers={"Accept-Encoding": "gzip"}, kind="logo")
            await both(f"public settings: {label}", "GET", S)

        # ==================================================================
        print("\n=== D. per-customer branding ===")
        await settings_state({"title": "Global", "logo": logo, "mime": "image/png", "color": "#222222"})()
        BR = P + "/branding"
        none = overrides_state()
        some = overrides_state(a={"title": "Acme Portal", "color": "#abcdef"}, b={"enabled": 0, "title": "Beta", "logo": "QQ=="})
        await some()
        await settle()
        for label, tok in (
            ("no token", None),
            ("portal user", T["portal_a"]),
            ("analyst", T["analyst"]),
            ("admin", T["admin"]),
            ("responder", T["responder"]),
        ):
            await both(f"branding of A: {label}", "GET", f"{BR}/{A}", tok)
        for label, tok in (("analyst", T["analyst"]), ("admin", T["admin"]), ("unassigned analyst", T["unassigned"])):
            await both(f"branding of B: {label}", "GET", f"{BR}/{B}", tok)
        await both("branding of an unknown customer: admin", "GET", f"{BR}/NOPE{SFX}", T["admin"])
        await both("branding of A, other casing: admin", "GET", f"{BR}/{A.lower()}", T["admin"])
        for label, tok in (("no token", None), ("portal user", T["portal_a"]), ("admin", T["admin"])):
            p, _ = await both(f"branding list: {label}", "GET", BR, tok)
        # A scoped analyst: Python lists every tenant's overrides, Rust theirs only (§4).
        r_py = await py.get(BR, headers={"Authorization": f"Bearer {T['analyst']}"})
        r_rs = await rs.get(BR, headers={"Authorization": f"Bearer {T['analyst']}"})
        mine = lambda r: [o["customer_code"] for o in r.json()["overrides"] if o["customer_code"] in (A, B)]  # noqa: E731
        check(
            "branding list: analyst: Python lists B's override too [200]",
            r_py.status_code == 200 and mine(r_py) == [A, B],
            r_py.text[:500],
        )
        check(
            "branding list: analyst: Rust lists A's only, the rest as Python [200]",
            r_rs.status_code == 200
            and mine(r_rs) == [A]
            and [o for o in r_rs.json()["overrides"] if o["customer_code"] != A] == []
            and [o for o in r_py.json()["overrides"] if o["customer_code"] == A] == r_rs.json()["overrides"],
            r_rs.text[:500],
        )
        r_rs = await rs.get(BR, headers={"Authorization": f"Bearer {T['unassigned']}"})
        check("branding list: unassigned analyst: Rust lists nothing", r_rs.json()["overrides"] == [], r_rs.text[:300])

        for label, body in (
            ("malformed JSON, no token", None),
            ("no token", {"title": "x"}),
            ("analyst", {"title": "x"}),
        ):
            await both(
                f"PUT branding: {label}",
                "PUT",
                f"{BR}/{A}",
                T["analyst"] if label == "analyst" else None,
                body,
                raw=b"{" if body is None else None,
            )
        await both(
            "PUT branding: an unknown customer",
            "PUT",
            f"{BR}/NOPE{SFX}",
            T["admin"],
            {"title": "x"},
            reset=none,
            snapshot=override_rows,
        )
        await both("PUT branding: an unknown customer, bad body", "PUT", f"{BR}/NOPE{SFX}", T["admin"], {"enabled": 2}, reset=none)
        for label, body in (
            ("enabled 2", {"enabled": 2}),
            ("enabled 0.5", {"enabled": 0.5}),
            ("enabled ' true'", {"enabled": " true"}),
            ("a bad colour", {"brand_color": "#12345"}),
            ("a long MIME type", {"logo_mime_type": "x" * 51}),
            ("not an object", ["x"]),
        ):
            await both(f"PUT branding: {label}", "PUT", f"{BR}/{A}", T["admin"], body, reset=none, snapshot=override_rows)
        for label, reset in (("new", none), ("existing", some)):
            for what, body in (
                (
                    "everything",
                    {
                        "enabled": "yes",
                        "title": "  Acme  ",
                        "logo_base64": "data:image/png;base64,QQ==",
                        "logo_mime_type": "image/gif",
                        "brand_color": " #ABC ",
                    },
                ),
                ("nothing", {}),
                ("blanks", {"title": "  ", "logo_base64": "", "logo_mime_type": "image/png", "brand_color": ""}),
                ("disabled", {"enabled": False, "title": "Off", "logo_base64": logo}),
                ("only the MIME type", {"logo_mime_type": "image/gif"}),
                ("enabled 1.0", {"enabled": 1.0, "title": "One"}),
            ):
                await both(
                    f"PUT branding of A: {what} ({label})",
                    "PUT",
                    f"{BR}/{A}",
                    T["admin"],
                    body,
                    reset=reset,
                    snapshot=override_rows,
                )
        await both(
            "PUT branding of A, other casing",
            "PUT",
            f"{BR}/{A.lower()}",
            T["admin"],
            {"title": "Lower"},
            reset=some,
            snapshot=override_rows,
        )
        for label, reset in (("none", none), ("one", some)):
            await both(f"DELETE branding of A ({label})", "DELETE", f"{BR}/{A}", T["admin"], reset=reset, snapshot=override_rows)
        await both("DELETE branding: analyst", "DELETE", f"{BR}/{A}", T["analyst"])
        await both("DELETE branding: no token", "DELETE", f"{BR}/{A}")

        print("\n=== E. the branding a user resolves to, and its logo ===")
        await some()
        await settle()
        E = S + "/effective"
        for label, tok in (
            ("no token", None),
            ("garbage token", "garbage"),
            ("2fa temp token", t_2fa),
            ("portal user of A", T["portal_a"]),
            ("portal user of B (disabled)", T["portal_b"]),
            ("portal user of both", T["portal_ab"]),
            ("analyst of A", T["analyst"]),
            ("unassigned analyst", T["unassigned"]),
            ("admin", T["admin"]),
            ("scheduler", T["scheduler"]),
        ):
            await both(f"effective: {label}", "GET", E, tok)
            await both(f"effective logo: {label}", "GET", E + "/logo", tok, headers={"Accept-Encoding": "gzip"}, kind="logo")
        await overrides_state(a={"title": "Acme", "logo": logo, "mime": "image/webp"})()
        await settle()
        p, _ = await both("effective with a custom logo: portal user of A", "GET", E, T["portal_a"])
        tag = '"{}"'.format(p["body"]["settings"]["logo_url"].rsplit("=", 1)[-1])
        for label, headers in (
            ("identity", {"Accept-Encoding": "identity"}),
            ("gzip", {"Accept-Encoding": "gzip"}),
            ("If-None-Match", {"If-None-Match": tag}),
        ):
            await both(f"effective logo, custom: {label}", "GET", E + "/logo", T["portal_a"], headers=headers, kind="logo")
        await overrides_state(a={"title": "Acme", "logo": "!!", "mime": None})()
        await settle()
        await both("effective logo: a custom logo that is not base64", "GET", E + "/logo", T["portal_a"], kind="logo")
        await both("effective: a custom logo that is not base64", "GET", E, T["portal_a"])

        print("\n=== F. the branding caches of the two processes ===")

        async def title(client, tok=T["portal_a"]):
            r = await client.get(E, headers={"Authorization": f"Bearer {tok}"})
            return r.json()["settings"]["title"]

        async def put(client, value):
            r = await client.put(f"{BR}/{A}", json={"title": value}, headers={"Authorization": f"Bearer {T['admin']}"})
            assert r.status_code == 200, r.text

        await put(py, "Zero")
        await settle()
        check("both serve the saved branding", (await title(py), await title(rs)) == ("Zero", "Zero"))
        await put(rs, "From Rust")
        check("the writer (Rust) forgets at once", await title(rs) == "From Rust")
        await settle()
        check("Python serves Rust's write within the interval", await title(py) == "From Rust")
        await put(py, "From Python")
        check("the writer (Python) forgets at once", await title(py) == "From Python")
        await settle()
        check("Rust serves Python's write within the interval", await title(rs) == "From Python")
        # Two writes within one second: the save times may be equal, the values are not.
        await put(rs, "Fast one")
        await title(py)
        await put(rs, "Fast two")
        await settle()
        check("Python sees the second of two writes in one second", await title(py) == "Fast two")
        await sql("UPDATE customer_portal_branding SET title = 'Direct' WHERE customer_code = :c", c=A)
        await settle()
        check("an edit made in MySQL reaches both", (await title(py), await title(rs)) == ("Direct", "Direct"))
        r = await rs.delete(f"{BR}/{A}", headers={"Authorization": f"Bearer {T['admin']}"})
        await settle()
        check("Python serves the global branding after Rust's delete", await title(py) == "Global")
        r = await rs.patch(S, json={"title": "Global 2"}, headers={"Authorization": f"Bearer {T['admin']}"})
        await settle()
        check("Python serves Rust's global settings change", await title(py) == "Global 2", r.text)
        r = await py.post(S, json={"title": "Global 3"}, headers={"Authorization": f"Bearer {T['admin']}"})
        await settle()
        check("Rust serves Python's global settings change", await title(rs) == "Global 3", r.text)

        # ==================================================================
        print("\n=== G. the Overview and the dashboard counters ===")
        await sql("DELETE FROM incident_management_tag_access_settings")
        OV = P + "/overview"
        users = ("portal_a", "portal_b", "portal_ab", "analyst", "unassigned", "tagged", "responder", "admin", "scheduler")
        for key in users:
            await both(f"overview: {key}", "GET", OV, T[key])
        for label, query in (
            ("B (portal user of A)", f"customer_codes={B}"),
            ("B and A", f"customer_codes={B}&customer_codes={A}"),
            ("an empty code", "customer_codes="),
            ("the wildcard", "customer_codes=*"),
            ("bracketed (not read)", f"customer_codes[]={B}"),
            ("limits", "recent_limit=1&ai_limit=25"),
            ("limits as Pydantic reads them", "recent_limit=+2.0&ai_limit= 1_0 "),
            ("bad limits", "recent_limit=0&ai_limit=26"),
            ("unparsable limits", "recent_limit=x&ai_limit=1e3"),
            ("a huge limit", "recent_limit=" + "9" * 40),
        ):
            for key in ("portal_a", "admin"):
                await both(f"overview: {key}: {label}", "GET", f"{OV}?{query}", T[key])
        await both("overview: no token", "GET", OV)
        await both("overview: garbage token", "GET", OV, "garbage")
        for route in ("stats", "alert-stats", "case-stats"):
            D = f"{P}/dashboard/{route}"
            await both(f"dashboard {route}: no token", "GET", D)
            for key in users:
                await both(f"dashboard {route}: {key}", "GET", D, T[key])
            await both(f"dashboard {route}: admin, B", "GET", f"{D}?customer_codes={B}", T["admin"])
            await both(f"dashboard {route}: admin, the wildcard", "GET", f"{D}?customer_codes=*", T["admin"])
            await both(f"dashboard {route}: portal user of both, A", "GET", f"{D}?customer_codes={A}", T["portal_ab"])
        # Tag RBAC on: the tag-restricted analyst sees the vip-tagged alerts (and per the
        # untagged behaviour), the counters and the AI findings with them.
        for i, behaviour in enumerate(("admin_only", "visible_to_all")):
            await sql("DELETE FROM incident_management_tag_access_settings")
            await sql(
                "INSERT INTO incident_management_tag_access_settings (id, enabled, untagged_alert_behavior, default_tag_id, "
                "updated_at) VALUES (:id, 1, :b, NULL, :t)",
                id=BASE + 950 + i,
                b=behaviour,
                t=NOW,
            )
            for key in ("tagged", "analyst", "portal_a", "admin"):
                await both(f"overview with tag RBAC ({behaviour}): {key}", "GET", OV, T[key])
                await both(f"alert-stats with tag RBAC ({behaviour}): {key}", "GET", f"{P}/dashboard/alert-stats", T[key])
                await both(f"stats with tag RBAC ({behaviour}): {key}", "GET", f"{P}/dashboard/stats", T[key])
        await sql("DELETE FROM incident_management_tag_access_settings")

        print("\n=== H. the Overview's statement budget ===")
        counter = Statements()
        for key in ("portal_a", "analyst"):
            await py.get(OV, headers={"Authorization": f"Bearer {T[key]}"})  # warm
            counter.seen.clear()
            await py.get(OV, headers={"Authorization": f"Bearer {T[key]}"})
            py_count = len(counter.seen)
            access_reads = sum("user_customer_access" in s and s.lstrip().upper().startswith("SELECT") for s in counter.seen)
            check(
                f"Python: the Overview of {key} within {MAX_OVERVIEW_STATEMENTS} statements",
                py_count <= MAX_OVERVIEW_STATEMENTS,
                str(py_count),
            )
            check(f"Python: user_customer_access read once ({key})", access_reads == 1, str(access_reads))
            best = None
            for _ in range(3):
                a = await questions()
                idle = await questions() - a
                a = await questions()
                await rs.get(OV, headers={"Authorization": f"Bearer {T[key]}"})
                used = await questions() - a - idle
                best = used if best is None else min(best, used)
            check(
                f"Rust: the Overview of {key} within {MAX_OVERVIEW_STATEMENTS} statements (Python {py_count})",
                best is not None and 5 <= best <= MAX_OVERVIEW_STATEMENTS,
                str(best),
            )
            print(f"        statements for {key}: python {py_count}, rust {best}")
        event.remove(async_engine.sync_engine, "before_cursor_execute", counter._record)

        # ==================================================================
        print("\n=== I. agents and their CSV ===")
        AG = P + "/agents"
        for key in ("portal_a", "portal_b", "portal_ab", "analyst", "unassigned", "responder", "admin", "scheduler"):
            await both(f"agents: {key}", "GET", AG, T[key])
        await both("agents: no token", "GET", AG)
        await both("agents: garbage token", "GET", AG, "garbage")
        for label, query in (
            ("page 2 of 2", "page=2&page_size=2"),
            ("past the end", "page=9"),
            ("search", "search=OV-"),
            ("search with spaces", "search=%20%20"),
            ("search an IP", "search=10.9.0.1"),
            ("search a wildcard", "search=_"),
            ("status", "status=active"),
            ("OS", "os=LINUX"),
            ("critical", "critical=TRUE"),
            ("critical off", "critical=off"),
            ("empty filters", "search=&status=&os="),
            ("B", f"customer_codes={B}"),
            ("bracketed B", f"customer_codes[]={B}"),
            ("legacy B", f"customer_code={B}"),
            ("legacy empty", "customer_code="),
            ("the wildcard", "customer_codes=*"),
            ("bad values", "page=0&page_size=101&critical=%20true"),
            ("Pydantic ints", "page=1.0&page_size=+5"),
            ("unparsable", "page=x&page_size=1e2&critical=2"),
            ("a huge page", "page=" + "9" * 30),
        ):
            for key in ("portal_a", "admin"):
                await both(f"agents: {key}: {label}", "GET", f"{AG}?{query}", T[key])
        X = AG + "/export"
        for key in ("portal_a", "portal_ab", "unassigned", "admin"):
            await both(f"CSV: {key}", "GET", X, T[key], headers={"Accept-Encoding": "identity"}, kind="csv")
        for label, query in (
            ("status", "status=active"),
            ("B", f"customer_codes={B}"),
            ("search", "search=desk"),
            ("bad critical", "critical=x"),
        ):
            await both(f"CSV: admin: {label}", "GET", f"{X}?{query}", T["admin"], headers={"Accept-Encoding": "gzip"}, kind="csv")
        await both("CSV: no token", "GET", X)

        # ==================================================================
        print("\n=== J. /me ===")
        M = P + "/me"
        for key in ("portal_a", "portal_b", "portal_ab", "norole", "analyst", "admin"):
            await both(f"me: {key}", "GET", M, T[key])
        await both("me: no token", "GET", M)
        await sql("DELETE FROM user_customer_access WHERE user_id = :u AND customer_code = :c", u=USERS["portal_ab"][0], c=B)
        await both("me: portal user of both, after losing B", "GET", M, T["portal_ab"])
    finally:
        await cleanup()
        rust.terminate()
        rust.wait(timeout=10)
        await py.aclose()
        await rs.aclose()
    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
