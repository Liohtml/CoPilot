"""Parity of the Rust platform-status modules with this backend — NOT collected by pytest (needs a
live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process: `app/routers/logs.py`, `license.py`, `status.py`,
`performance.py`, with the backend's exception handlers) and Rust instances this suite starts
(`crates/copilot-status`, `crates/copilot-license`; no legacy backend) answer the same requests on
one database. Compared: status codes, content types, bodies (key order included), the rows each
call leaves (`license`, `license_cache`, `log_entries` — the error rows the handlers write
included) and every request each backend sends upstream, **every header in the order it was
sent**. The upstreams are local stand-ins that record what arrives:

* the SOCFortress licence server (`requests`): every licence route, its failure shapes (a 5xx
  with and without JSON, a non-JSON 200, a 204, odd JSON, a closed port);
* for the sidebar: InfluxDB (the Flux query of the health indicator), the Wazuh indexer
  (`_cluster/health`), MinIO (`list_buckets`), GitHub's latest release, the Wazuh manager (the
  catalog indicator's ruleset load).

Python reaches the stand-ins because `requests.Session.request` and `httpx.AsyncClient`'s
`build_request` are patched here to rewrite the public hosts; Rust because its instances are
started with the `COPILOT_*_URL` overrides (parity harness only).

The deployment-wide sidebar indicators are process state (refreshed off the request path in both
backends): each sidebar scenario sets the database up, refreshes Python's set in-process and
starts a fresh Rust instance whose warm-up computes its own.

`/api/performance` describes each backend's own process: only the shapes, units, ordering rules,
the guards and the reset behaviour are compared (RUST_MIGRATION.md §4).

Ports (all overridable, defaults in this suite's range): PLATFORM_PARITY_RUST_PORT,
PLATFORM_PARITY_RUST_DOWN_PORT, PLATFORM_LICENSE_STUB_PORT, PLATFORM_INFLUX_STUB_PORT,
PLATFORM_INDEXER_STUB_PORT, PLATFORM_S3_STUB_PORT, PLATFORM_RELEASE_STUB_PORT,
PLATFORM_MANAGER_STUB_PORT, PLATFORM_PARITY_RUST_SIDEBAR_PORT.

    PARITY_SUITES=tests/e2e/rust_parity_platform_e2e.py scripts/rust-parity.sh
"""

import asyncio
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# `send_post_request` reads it per call (`os.getenv`); the Rust instances get the same.
os.environ["COPILOT_API_KEY"] = "parity-platform-api-key"
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

import httpx  # noqa: E402
import jwt  # noqa: E402
import requests  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.connectors import cache as connector_cache  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("PLATFORM_PARITY_RUST_PORT", "6210"))
RS_DOWN_PORT = int(os.environ.get("PLATFORM_PARITY_RUST_DOWN_PORT", "6211"))
LICENSE_PORT = int(os.environ.get("PLATFORM_LICENSE_STUB_PORT", "6212"))
INFLUX_PORT = int(os.environ.get("PLATFORM_INFLUX_STUB_PORT", "6213"))
INDEXER_PORT = int(os.environ.get("PLATFORM_INDEXER_STUB_PORT", "6214"))
S3_PORT = int(os.environ.get("PLATFORM_S3_STUB_PORT", "6215"))
RELEASE_PORT = int(os.environ.get("PLATFORM_RELEASE_STUB_PORT", "6216"))
MANAGER_PORT = int(os.environ.get("PLATFORM_MANAGER_STUB_PORT", "6217"))
RS_SIDEBAR_PORT = int(os.environ.get("PLATFORM_PARITY_RUST_SIDEBAR_PORT", "6218"))
#: A port nothing listens on (an upstream that is down).
CLOSED_PORT = 1
RUST = f"http://127.0.0.1:{RS_PORT}"

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"PlA{SFX}", f"PlB{SFX}"
ADMIN, ANALYST, PORTAL = f"pl_admin{SFX}", f"pl_analyst{SFX}", f"pl_portal{SFX}"
USERS = (ADMIN, ANALYST, PORTAL)
LICENSE_KEY = f"PARITY-{SFX}"
results = []
#: Every stand-in (`main` fills it): each call takes and compares what all of them received.
RECS = []
#: State saved at the start and put back at the end.
SAVED = {}


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


# --- HTTP stand-ins -------------------------------------------------------------------
class Recorder:
    """Records every request — method, target, every header in the order it came (names
    lower-cased: hyper writes no other spelling), body — and answers with
    `answer(rec, method, path, headers, body)`."""

    def __init__(self, answer, port, name):
        self.answer = answer
        self.name = name
        self.captured = []
        self.mode = {}
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                ordered = [(k.lower(), v) for k, v in self.headers.items()]
                with recorder.lock:
                    recorder.captured.append({"method": self.command, "path": self.path, "headers": ordered, "body": body})
                answer = recorder.answer(recorder, self.command, self.path, dict(ordered), body)
                if answer is None:
                    self.close_connection = True
                    return
                status, ctype, payload, extra = answer
                self.send_response(status)
                if ctype:
                    self.send_header("Content-Type", ctype)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle  # noqa: N815 - http.server API

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{port}"

    def take(self):
        with self.lock:
            out, self.captured[:] = list(self.captured), []
        return out

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def normalised(captures):
    out = []
    for c in captures:
        out.append({"method": c["method"], "path": c["path"], "headers": c["headers"], "body": c["body"].decode("utf-8", "replace")})
    return out


def jbody(obj):
    return json.dumps(obj).encode()


def ok(obj, status=200, ctype="application/json"):
    return status, ctype, jbody(obj), {}


# --- the licence server -------------------------------------------------------------------
FEATURE = {
    "id": 1,
    "subscription_price_id": "price_1",
    "name": "THREAT INTEL",
    "price": 100,
    "currency": "usd",
    "info": "i",
    "short_description": "s",
    "full_description": "f",
}
LICENSE_OBJ = {
    "productId": 1,
    "id": 7,
    "key": LICENSE_KEY,
    "created": "2026-01-02T03:04:05.123",
    "expires": "2027-01-02T03:04:05",
    "period": 365,
    "f1": True,
    "f2": False,
    "f3": "yes",
    "f4": 0,
    "f5": False,
    "f6": False,
    "f7": False,
    "f8": False,
    "notes": "",
    "block": False,
    "globalId": 9,
    "customer": {"id": 3, "name": "Parity", "email": "p@parity.test", "companyName": "Parity Co", "created": "2025-06-01T00:00:00Z"},
    "activatedMachines": [],
    "trialActivation": False,
    "maxNoOfMachines": 0,
    "allowedMachines": None,
    "dataObjects": [{"name": "THREAT INTEL", "intValue": 1}, {"name": "SOCFORTRESS AI", "intValue": 0}, {"intValue": 1}],
    "signDate": "2026-01-02T03:04:05+02:00",
    "reseller": None,
}
SESSION = {
    "amount_subtotal": 100,
    "amount_total": 100,
    "automatic_tax": {"enabled": False},
    "cancel_url": "https://x/cancel",
    "created": 1700000000,
    "currency": "usd",
    "custom_text": {},
    "expires_at": 1700086400,
    "id": "cs_test_1",
    "livemode": False,
    "metadata": {"a": "b"},
    "mode": "subscription",
    "object": "checkout.session",
    "payment_method_collection": "always",
    "payment_method_options": {"card": {"request_three_d_secure": "automatic"}},
    "payment_method_types": ["card"],
    "payment_status": "unpaid",
    "phone_number_collection": {"enabled": False},
    "status": "open",
    "success_url": "https://x/success",
    "total_details": {"amount_discount": 0, "amount_shipping": 0, "amount_tax": 0},
    "ui_mode": "hosted",
    "url": "https://checkout.stripe.test/c/1",
    "invoice_creation": {"enabled": False, "invoice_data": {"metadata": {}}},
}
LICENSE_DEFAULTS = {
    "/features": ok({"data": {"features": [FEATURE, {**FEATURE, "id": 2, "mssp_seats": 5}]}, "success": True, "message": "ok"}),
    "/verify-license": ok({"data": {"license": LICENSE_OBJ, "success": True, "message": "License is valid"}, "success": True}),
    "/retrieve-license-by-email": ok(
        {"data": {"success": True, "message": "found", "license": {"key": f"EMAIL-{SFX}", "customer": LICENSE_OBJ["customer"]}}},
    ),
    "/create-checkout-session": ok({"data": {"success": True, "message": "created", "session": SESSION}}),
    "/trial-license": ok({"data": {"success": True, "message": "trial created", "license_key": f"TRIAL-{SFX}"}}),
    "/cancel-subscription": ok({"data": {"success": True, "message": "cancelled"}}),
    "/license-features": ok({"success": True, "features": ["THREAT INTEL", "MSSP 5"], "message": "features"}),
    "/retrieve-docker-compose": ok({"success": True, "docker_compose": "version: '3'", "message": "compose"}),
}


def license_answer(rec, method, raw_path, headers, body):
    path = raw_path.split("?")[0]
    if path in rec.mode:
        return rec.mode[path]
    return LICENSE_DEFAULTS.get(path, ok({"detail": "Not Found"}, 404))


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


def in_list(values):
    return "(" + ",".join(repr(str(v)) if not isinstance(v, int) else str(v) for v in values) + ")"


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
    ids = await rows("SELECT id, username FROM `user` WHERE username IN " + in_list(USERS))
    SAVED["user_ids"] = {r["username"]: r["id"] for r in ids}
    # The licence and the error log are deployment-wide: put aside, restored at the end.
    SAVED["license"] = await rows("SELECT * FROM license ORDER BY id")
    SAVED["license_cache"] = await rows("SELECT * FROM license_cache ORDER BY id")
    SAVED["log_entries"] = await rows("SELECT * FROM log_entries ORDER BY id")
    await sql("DELETE FROM license_cache")
    await sql("DELETE FROM license")


async def restore_table(table, saved):
    await sql(f"DELETE FROM {table}")
    if not saved:
        return
    cols = list(saved[0].keys())
    stmt = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(':' + c for c in cols)})"
    async with AsyncSession(async_engine) as s:
        for i in range(0, len(saved), 2000):
            await s.execute(text(stmt), saved[i : i + 2000])
        await s.commit()


async def cleanup():
    await restore_table("license_cache", SAVED.get("license_cache", []))
    await restore_table("license", SAVED.get("license", []))
    if "log_entries" in SAVED:
        # Rows the Rust instances write after their answers land late: let them, then restore.
        await asyncio.sleep(0.5)
        await restore_table("log_entries", SAVED["log_entries"])
    await sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username IN " + in_list(USERS) + ")")
    await sql("DELETE FROM `user` WHERE username IN " + in_list(USERS))
    await sql("DELETE FROM customers WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    connector_cache.invalidate_all()


# --- the two backends -----------------------------------------------------------------------
def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import license as license_router
    from app.routers import logs

    api = APIRouter(prefix="/api")
    api.include_router(logs.router)
    api.include_router(license_router.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


#: The public hosts the Python services call, and the stand-ins they reach here.
REWRITES = {
    "https://license.socfortress.co": f"http://127.0.0.1:{LICENSE_PORT}",
}


def rewrite(url):
    text_url = str(url)
    for public, local in REWRITES.items():
        if text_url.startswith(public):
            return local + text_url[len(public) :]
    return url


def patch_python_clients():
    original_build = httpx.AsyncClient.build_request

    def build_request(self, method, url, *args, **kwargs):
        return original_build(self, method, rewrite(url), *args, **kwargs)

    httpx.AsyncClient.build_request = build_request
    original_request = requests.Session.request

    def session_request(self, method, url, *args, **kwargs):
        return original_request(self, method, rewrite(url), *args, **kwargs)

    requests.Session.request = session_request


def start_rust(port, extra=None):
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_PORT": str(port),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "COPILOT_API_KEY": os.environ["COPILOT_API_KEY"],
        "COPILOT_LICENSE_URL": f"http://127.0.0.1:{LICENSE_PORT}/",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        **(extra or {}),
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(150):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


def stop_rust(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


#: Stamps the two backends write at their own instant.
CLOCK_KEYS = {"timestamp", "cached_at", "expires_at", "started_at", "reset_at"}


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
    """Stamps written by each backend at its own instant: masked where the two are within
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


#: urllib3 prints the connection object's address, which differs between any two processes.
ADDRESS = re.compile(r"object at 0x[0-9a-f]+")


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


def unaddress(value):
    return json.loads(ADDRESS.sub("object at 0x…", json.dumps(value)))


async def log_rows_after(mark):
    """The `log_entries` rows written after `mark` (the URL's host masked: `http://py` in-process,
    `127.0.0.1:port` for Rust)."""
    out = await rows(
        "SELECT event_type, user_id, route, method, status_code, message, additional_info FROM log_entries WHERE id > :m ORDER BY id",
        m=mark,
    )
    for r in out:
        r["route"] = re.sub(r"^http://[^/]+", "http://<host>", r["route"] or "")
        r["message"] = ADDRESS.sub("object at 0x…", r["message"] or "")
    return out


async def max_log_id():
    r = await rows("SELECT COALESCE(MAX(id), 0) AS m FROM log_entries")
    return r[0]["m"]


async def main():  # noqa: C901 - one scenario after the other
    lic = Recorder(license_answer, LICENSE_PORT, "license")
    RECS[:] = [lic]
    await seed()
    patch_python_clients()
    rust = start_rust(RS_PORT)
    procs = [rust]
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    clients = {"rs": rs}
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    uid = SAVED["user_ids"]

    async def send(client, method, path, tok, body, raw, headers):
        kw = {"headers": {**({"Authorization": f"Bearer {tok}"} if tok else {}), **(headers or {})}}
        if raw is not None:
            kw["content"] = raw
            kw["headers"].setdefault("Content-Type", "application/json")
        elif body is not None:
            kw["json"] = body
        return await client.request(method, path, **kw)

    async def both(name, method, path, tok=None, body=None, raw=None, headers=None, reset=None, snapshot=None, rust="rs"):
        """The responses, every request each backend sent upstream, the error rows it logged and
        (`snapshot`) the rows it left; `reset` runs before each backend's call."""
        got = {}
        for tag, client in (("py", py), ("rs", clients[rust])):
            if reset is not None:
                await reset()
            for rec in RECS:
                rec.take()
            mark = await max_log_id()
            r = await send(client, method, path, tok, body, raw, headers)
            if tag == "rs":
                # Rust writes its `log_entries` row after the answer (a task of its own).
                await asyncio.sleep(0.3 if r.status_code >= 400 else 0.05)
            upstream = {rec.name: normalised(rec.take()) for rec in RECS}
            got[tag] = {
                "status": r.status_code,
                "type": r.headers.get("content-type"),
                "body": unaddress(body_of(r)),
                "upstream": upstream,
                "logged": await log_rows_after(mark),
                "rows": await snapshot() if snapshot else None,
            }
        p, q = got["py"], got["rs"]
        p["body"], q["body"] = mask_clocks(p["body"], q["body"])
        same = p["status"] == q["status"] and p["type"] == q["type"] and json.dumps(p["body"]) == json.dumps(q["body"])
        check(
            f"{name} [{p['status']}]",
            same,
            f"python {p['status']} {p['type']} {json.dumps(p['body'])[:2500]}\n        rust   {q['status']} {q['type']} {json.dumps(q['body'])[:2500]}",
        )
        for upstream in p["upstream"]:
            a, b = p["upstream"][upstream], q["upstream"][upstream]
            if not (a or b):
                continue
            first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), None)
            check(
                f"{name}: requests to {upstream} ({len(a)})",
                a == b,
                f"python {[x['method'] + ' ' + x['path'] for x in a]}\n        rust   {[x['method'] + ' ' + x['path'] for x in b]}"
                + (
                    f"\n        first difference #{first}:\n        python {json.dumps(a[first])}\n        rust   {json.dumps(b[first])}"
                    if first is not None
                    else ""
                ),
            )
        check(
            f"{name}: error rows logged",
            p["logged"] == q["logged"],
            f"python {json.dumps(p['logged'], default=str)[:1500]}\n        rust   {json.dumps(q['logged'], default=str)[:1500]}",
        )
        if snapshot:
            pr, qr = mask_clocks(p["rows"], q["rows"])
            check(
                f"{name}: rows",
                json.dumps(pr, default=str) == json.dumps(qr, default=str),
                f"python {json.dumps(pr, default=str)[:3000]}\n        rust   {json.dumps(qr, default=str)[:3000]}",
            )
        return p, q

    try:
        # ==================================================================
        print("\n=== A. /api/logs ===")
        L = "/api/logs"

        def logs_state(seeded=True):
            async def reset():
                await sql("DELETE FROM log_entries")
                if not seeded:
                    return
                for event, user, route, method, status, message, extra, hours in (
                    ("Info", uid[ADMIN], "http://h/api/a", "GET", 200, "seed info", None, 2),
                    ("Error", None, "http://h/api/b", "POST", 500, "seed error é", "extra", 30),
                    ("Info", uid[ADMIN], None, None, 201, None, None, 72),
                    ("Error", uid[ANALYST], "http://h/api/c", "DELETE", 404, "old", None, 240),
                    ("info", uid[PORTAL], "http://h/api/d", "GET", 200, "lower-case type", None, 1),
                ):
                    await sql(
                        "INSERT INTO log_entries (timestamp, event_type, user_id, route, method, status_code, message, additional_info) "
                        "VALUES (UTC_TIMESTAMP() - INTERVAL :h HOUR, :e, :u, :r, :m, :s, :msg, :x)",
                        h=hours,
                        e=event,
                        u=user,
                        r=route,
                        m=method,
                        s=status,
                        msg=message,
                        x=extra,
                    )

            return reset

        async def log_table():
            out = await rows("SELECT event_type, user_id, route, method, status_code, message FROM log_entries ORDER BY id")
            for r in out:
                r["route"] = re.sub(r"^http://(py|127\.0\.0\.1:\d+)/", "http://<host>/", r["route"] or "")
            return out

        seeded, empty = logs_state(), logs_state(False)
        await both("logs: no token", "GET", L, reset=seeded)
        await both("logs: garbage token", "GET", L, "garbage", reset=seeded)
        await both("logs: 2fa temp token", "GET", L, token(ADMIN, [], type="2fa_pending"), reset=seeded)
        await both("logs: analyst", "GET", L, t_analyst, reset=seeded)
        await both("logs: portal user", "GET", L, t_portal, reset=seeded)
        await both("logs: admin", "GET", L, t_admin, reset=seeded)
        await both("logs: admin, empty table", "GET", L, t_admin, reset=empty)
        await both("logs: trailing slash", "GET", L + "/", t_admin, reset=seeded)
        await both("logs: POST without a segment", "POST", L, t_admin, reset=seeded)
        for label, segment in (
            ("an admin's id", str(uid[ADMIN])),
            ("an id with no rows", "0"),
            ("text", "abc"),
            ("spaces", f"%20{uid[ADMIN]}%20"),
            ("underscores", "1_0"),
            ("a float", f"{uid[ADMIN]}.0"),
            ("a fraction", "1.5"),
            ("negative zero", "-0"),
            ("beyond 64 bits", "99999999999999999999"),
            ("the static segment", "timerange"),
        ):
            await both(f"logs by user: {label}", "GET", f"{L}/{segment}", t_admin, reset=seeded)
        await both("logs by user: analyst", "GET", f"{L}/{uid[ADMIN]}", t_analyst, reset=seeded)
        await both("logs by user: no token", "GET", f"{L}/{uid[ADMIN]}", reset=seeded)

        TR = L + "/timerange"
        for label, body in (
            ("1d", {"time_range": "1d"}),
            ("3d", {"time_range": "3d"}),
            ("1h is a day", {"time_range": "1h"}),
            ("1w is a day", {"time_range": "1w"}),
            ("an int", {"time_range": 3}),
            ("an int float", {"time_range": 3.0}),
            ("true", {"time_range": True}),
            ("the default", {}),
            ("extra keys", {"time_range": "2d", "other": 1}),
            ("Arabic-Indic digit", {"time_range": "١d"}),
            ("underscored", {"time_range": "1_0d"}),
            ("signed", {"time_range": "+2d"}),
            ("2w", {"time_range": "2w"}),
            ("0h", {"time_range": "0h"}),
            ("-1d", {"time_range": "-1d"}),
            ("no unit", {"time_range": "5"}),
            ("a bad unit", {"time_range": "5m"}),
            ("text", {"time_range": "abc"}),
            ("an empty string", {"time_range": ""}),
            ("8", {"time_range": 8}),
            ("0", {"time_range": 0}),
            ("a fraction", {"time_range": 1.5}),
            ("null", {"time_range": None}),
            ("a list", {"time_range": ["1d"]}),
            ("a huge window", {"time_range": "9999999999d"}),
            ("a window before year 1", {"time_range": "999999999d"}),
        ):
            await both(f"logs by time range: {label}", "POST", TR, t_admin, body, reset=seeded)
        await both("logs by time range: empty table", "POST", TR, t_admin, {"time_range": "1d"}, reset=empty)
        await both("logs by time range: no body", "POST", TR, t_admin, reset=seeded)
        await both("logs by time range: a list body", "POST", TR, t_admin, ["1d"], reset=seeded)
        await both("logs by time range: malformed JSON, no token", "POST", TR, raw=b"{", reset=seeded)
        await both("logs by time range: analyst", "POST", TR, t_analyst, {"time_range": "1d"}, reset=seeded)
        await both("logs by time range: invalid, analyst", "POST", TR, t_analyst, {"time_range": "x"}, reset=seeded)

        async def only_old():
            await sql("DELETE FROM log_entries")
            await sql(
                "INSERT INTO log_entries (timestamp, event_type, status_code, message) VALUES (UTC_TIMESTAMP() - INTERVAL 20 DAY, 'Info', 200, 'old')",
            )

        await both("logs by time range: nothing inside", "POST", TR, t_admin, {"time_range": "1d"}, reset=only_old)
        for label, segment in (("Info", "Info"), ("Error", "Error"), ("lower case", "info"), ("unknown", "Warning")):
            await both(f"logs by event type: {label}", "POST", f"{L}/{segment}", t_admin, reset=seeded)
        await both("logs by event type: none of the type", "POST", f"{L}/Error", t_admin, reset=only_old)
        await both("logs by event type: analyst", "POST", f"{L}/Info", t_analyst, reset=seeded)
        await both("logs: DELETE of a segment", "DELETE", f"{L}/Info", t_admin, reset=seeded)
        await both("purge: analyst", "DELETE", L, t_analyst, reset=seeded, snapshot=log_table)
        await both("purge: admin", "DELETE", L, t_admin, reset=seeded, snapshot=log_table)
        await both("purge: empty table", "DELETE", L, t_admin, reset=empty, snapshot=log_table)
        for label, body in (("1d", {"time_range": "1d"}), ("2d", {"time_range": "2d"}), ("invalid", {"time_range": "9w"})):
            await both(f"purge by time range: {label}", "DELETE", TR, t_admin, body, reset=seeded, snapshot=log_table)
        await both("purge by time range: nothing inside", "DELETE", TR, t_admin, {"time_range": "1d"}, reset=only_old, snapshot=log_table)

        # ==================================================================
        print("\n=== B. /api/license ===")
        LI = "/api/license"

        def license_state(licensed=True, cache=(), data=None, mode=None):
            """A reset: the licence row (or none), the feature cache as given — `(feature,
            enabled, fresh)` with `data` as their `license_data` — and the stand-in's answers."""

            async def reset():
                await sql("DELETE FROM license_cache")
                await sql("DELETE FROM license")
                if licensed:
                    await sql(
                        "INSERT INTO license (license_key, customer_name, customer_email, company_name) VALUES "
                        "(:k, 'Parity', 'p@parity.test', 'Parity Co')",
                        k=LICENSE_KEY,
                    )
                for feature, enabled, fresh in cache:
                    await sql(
                        "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, expires_at, license_data) VALUES "
                        "(:k, :f, :e, UTC_TIMESTAMP() - INTERVAL 2 HOUR, UTC_TIMESTAMP() + INTERVAL :h HOUR, :d)",
                        k=LICENSE_KEY,
                        f=feature,
                        e=enabled,
                        h=1 if fresh else -1,
                        d=data,
                    )
                lic.mode.clear()
                lic.mode.update(mode or {})

            return reset

        async def license_rows():
            licenses = await rows("SELECT license_key, customer_name, customer_email, company_name FROM license ORDER BY id")
            cache = await rows(
                "SELECT license_key, feature_name, is_enabled, cached_at, expires_at, license_data FROM license_cache ORDER BY id",
            )
            return {"licenses": licenses, "cache": cache}

        none, bare = license_state(False), license_state()
        await both("licence: no token", "GET", LI + "/get_license", reset=bare)
        await both("licence: portal user", "GET", LI + "/get_license", t_portal, reset=bare)
        await both("licence: no licence", "GET", LI + "/get_license", t_analyst, reset=none)
        await both("licence: get", "GET", LI + "/get_license", t_analyst, reset=bare)
        await both("invalidate: no licence", "POST", LI + "/invalidate_cache", t_admin, reset=none, snapshot=license_rows)
        await both(
            "invalidate: cached features",
            "POST",
            LI + "/invalidate_cache",
            t_admin,
            reset=license_state(cache=[("THREAT INTEL", 1, True), ("X", 0, False)]),
            snapshot=license_rows,
        )

        F = LI + "/is_feature_enabled"
        await both("feature: no licence", "GET", F + "/THREAT%20INTEL", t_analyst, reset=none)
        await both("feature: cached on", "GET", F + "/THREAT%20INTEL", t_analyst, reset=license_state(cache=[("THREAT INTEL", 1, True)]))
        await both("feature: cached off", "GET", F + "/THREAT%20INTEL", t_analyst, reset=license_state(cache=[("THREAT INTEL", 0, True)]))
        await both(
            "feature: expired cache, enabled upstream",
            "GET",
            F + "/THREAT%20INTEL",
            t_analyst,
            reset=license_state(cache=[("THREAT INTEL", 0, False)]),
            snapshot=license_rows,
        )
        await both("feature: not enabled upstream", "GET", F + "/SOCFORTRESS%20AI", t_analyst, reset=bare, snapshot=license_rows)
        await both("feature: unknown upstream", "GET", F + "/NOPE", t_analyst, reset=bare, snapshot=license_rows)
        for label, answer in (
            ("a 500 with JSON", ok({"message": "Cryptolens down"}, 500)),
            ("a 500 with detail", ok({"detail": "boom"}, 503)),
            ("a 500 without JSON", (500, "text/plain", b"upstream exploded", {})),
            ("a 500 with an empty body", (502, "text/plain", b"", {})),
            ("a 500 with a list", ok([1, 2], 500)),
            ("an error body at 200", ok({"message": "Internal server error"})),
            ("a non-JSON 200", (200, "text/html", b"<html>hi</html>", {})),
            ("a 204", (204, None, b"", {})),
            ("a list", ok(["data"])),
            ("a number", ok(5)),
            ("a string", ok("metadata")),
            ("no dataObjects", ok({"data": {"license": {"key": LICENSE_KEY}}})),
            ("odd data objects", ok({"data": {"license": {"dataObjects": [{"name": "X"}, 5]}}})),
            ("a 404", ok({"detail": "missing"}, 404)),
        ):
            await both(
                f"feature: {label}",
                "GET",
                F + "/THREAT%20INTEL",
                t_analyst,
                reset=license_state(mode={"/verify-license": answer}),
                snapshot=license_rows,
            )

        V = LI + "/verify_license"
        good_cache = json.dumps({"data": {"license": LICENSE_OBJ, "success": True}})
        await both("verify: no licence", "GET", V, t_analyst, reset=none)
        await both(
            "verify: from the cache",
            "GET",
            V,
            t_analyst,
            reset=license_state(cache=[("THREAT INTEL", 1, True)], data=good_cache),
            snapshot=license_rows,
        )
        for label, data in (
            ("unwrapped", json.dumps({"license": LICENSE_OBJ})),
            ("not JSON", "{oops"),
            ("an empty string", ""),
            ("no licence", json.dumps({"other": 1})),
            ("a bad licence", json.dumps({"data": {"license": {**LICENSE_OBJ, "productId": "x"}, "success": True}})),
            ("no success", json.dumps({"data": {"license": LICENSE_OBJ}})),
            ("a number as data", json.dumps({"data": 5})),
        ):
            await both(
                f"verify: cache {label}",
                "GET",
                V,
                t_analyst,
                reset=license_state(cache=[("THREAT INTEL", 1, True)], data=data),
                snapshot=license_rows,
            )
        await both("verify: from the server", "GET", V, t_analyst, reset=bare, snapshot=license_rows)
        for label, answer in (
            ("unwrapped", ok({"license": LICENSE_OBJ, "success": True, "message": "direct"})),
            ("not successful", ok({"success": False, "message": "License blocked"})),
            ("not successful, no message", ok({"success": 0})),
            ("an error body", ok({"message": "Internal server error"})),
            ("a bad licence", ok({"data": {"license": {**LICENSE_OBJ, "expires": "soon", "customer": 5}}})),
            ("a 500", ok({"message": "down"}, 500)),
            ("a list", ok([1])),
        ):
            await both(
                f"verify: {label}",
                "GET",
                V,
                t_analyst,
                reset=license_state(mode={"/verify-license": answer}),
                snapshot=license_rows,
            )

        G = LI + "/get_license_features"
        await both("features: no licence", "GET", G, t_analyst, reset=none)
        await both(
            "features: cached",
            "GET",
            G,
            t_analyst,
            reset=license_state(cache=[("B", 1, True), ("A", 1, True), ("C", 0, True), ("D", 1, False)]),
        )
        await both("features: from the server", "GET", G, t_analyst, reset=bare, snapshot=license_rows)
        for label, answer in (
            ("not successful", ok({"success": False, "message": {"why": "expired"}})),
            ("not successful, no message", ok({"success": ""})),
            ("a dict of features", ok({"features": {"A": 1}})),
            ("numbers", ok({"features": [1, "B"]})),
            ("no features", ok({"message": "nothing"})),
            ("a list", ok([1])),
        ):
            await both(
                f"features: {label}",
                "GET",
                G,
                t_analyst,
                reset=license_state(mode={"/license-features": answer}),
                snapshot=license_rows,
            )

        S = LI + "/subscription_features"
        await both("catalog", "GET", S, t_analyst, reset=bare)
        for label, answer in (
            ("unwrapped", ok({"features": [FEATURE]})),
            ("no features", ok({"other": 1})),
            ("a 500 with JSON", ok({"data": {"features": []}, "success": False, "message": "down"}, 500)),
            ("not JSON", (200, "text/plain", b"nope", {})),
            ("a 204", (204, None, b"", {})),
            ("a bad feature", ok({"features": [{**FEATURE, "price": "x"}, {"id": 2}]})),
            ("a list", ok([1])),
        ):
            await both(f"catalog: {label}", "GET", S, t_analyst, reset=license_state(mode={"/features": answer}))

        E = LI + "/retrieve_license_by_email"
        await both("by email: no body", "POST", E, t_analyst, reset=none)
        await both("by email: a number", "POST", E, t_analyst, {"email": 5}, reset=none)
        await both("by email: malformed JSON", "POST", E, raw=b"{", reset=none)
        await both("by email: portal user", "POST", E, t_portal, {"email": "p@parity.test"}, reset=none)
        await both("by email: already stored", "POST", E, t_analyst, {"email": "p@parity.test"}, reset=bare, snapshot=license_rows)
        await both("by email: from the server", "POST", E, t_analyst, {"email": "new@parity.test"}, reset=none, snapshot=license_rows)
        for label, answer in (
            ("not found", ok({"data": {"success": False, "message": "No licence for that email"}})),
            ("not found, structured", ok({"data": {"success": False, "message": {"code": 4, "text": "é"}}})),
            ("not found, no message", ok({"data": {"success": False, "message": None}})),
            ("no customer", ok({"data": {"success": True, "message": "x", "license": {"key": "K"}}})),
            (
                "a bad customer",
                ok({"data": {"success": True, "message": "x", "license": {"key": 5, "customer": {"email": 1, "name": "n"}}}}),
            ),
            ("a numeric key", ok({"data": {"success": True, "message": "m", "license": {"key": 77, "customer": LICENSE_OBJ["customer"]}}})),
            ("a 500", ok({"message": "down"}, 500)),
        ):
            await both(
                f"by email: {label}",
                "POST",
                E,
                t_analyst,
                {"email": "new@parity.test"},
                reset=license_state(False, mode={"/retrieve-license-by-email": answer}),
                snapshot=license_rows,
            )

        C = LI + "/create_checkout_session"
        order = {
            "feature_id": "3",
            "cancel_url": "https://x/c",
            "success_url": "https://x/s",
            "customer_email": "p@parity.test",
            "company_name": "Parity",
        }
        await both("checkout", "POST", C, t_analyst, order, reset=bare)
        await both("checkout: missing fields", "POST", C, t_analyst, {"feature_id": "x"}, reset=bare)
        for label, answer in (
            ("refused", ok({"data": {"success": False, "message": "Stripe says no"}})),
            ("a bad session", ok({"data": {"success": True, "message": "m", "session": {**SESSION, "created": "x", "metadata": None}}})),
            ("no session", ok({"data": {"success": True, "message": "m"}})),
            ("unwrapped", ok({"success": True, "message": "m", "session": SESSION})),
        ):
            await both(f"checkout: {label}", "POST", C, t_analyst, order, reset=license_state(mode={"/create-checkout-session": answer}))

        T = LI + "/trial_license"
        trial = {"email": "t@parity.test", "feature_name": "THREAT INTEL", "customer_name": "Trial", "company_name": "Trial Co"}
        await both("trial: a licence exists", "POST", T, t_analyst, trial, reset=bare, snapshot=license_rows)
        await both("trial: created", "POST", T, t_analyst, trial, reset=none, snapshot=license_rows)
        await both("trial: period null", "POST", T, t_analyst, {**trial, "period": None}, reset=none, snapshot=license_rows)
        await both("trial: invalid body", "POST", T, t_analyst, {"period": "x"}, reset=bare, snapshot=license_rows)
        await both(
            "trial: refused",
            "POST",
            T,
            t_analyst,
            trial,
            reset=license_state(False, mode={"/trial-license": ok({"data": {"success": False, "message": "No trial"}})}),
            snapshot=license_rows,
        )
        await both(
            "trial: no key",
            "POST",
            T,
            t_analyst,
            trial,
            reset=license_state(False, mode={"/trial-license": ok({"data": {"success": True, "message": "m"}})}),
            snapshot=license_rows,
        )

        X = LI + "/cancel_subscription"
        cancel = {"customer_email": "p@parity.test", "subscription_price_id": "price_1", "feature_name": "THREAT INTEL"}
        await both("cancel", "POST", X, t_analyst, cancel, reset=bare)
        await both(
            "cancel: refused",
            "POST",
            X,
            t_analyst,
            cancel,
            reset=license_state(mode={"/cancel-subscription": ok({"data": {"success": False, "message": "no"}})}),
        )
        await both(
            "cancel: odd answer",
            "POST",
            X,
            t_analyst,
            cancel,
            reset=license_state(mode={"/cancel-subscription": ok({"data": {"success": "yes", "message": 3}})}),
        )

        R = LI + "/replace_license_in_db"
        await both(
            "replace: existing",
            "POST",
            R,
            t_admin,
            {"license_key": f"NEW-{SFX}"},
            reset=license_state(cache=[("A", 1, True)]),
            snapshot=license_rows,
        )
        await both("replace: none, verified", "POST", R, t_admin, {"license_key": f"NEW-{SFX}"}, reset=none, snapshot=license_rows)
        await both(
            "replace: none, refused",
            "POST",
            R,
            t_admin,
            {"license_key": f"NEW-{SFX}"},
            reset=license_state(False, mode={"/verify-license": ok({"success": False})}),
            snapshot=license_rows,
        )
        await both("replace: no body", "POST", R, t_admin, reset=none)

        D = LI + "/retrieve-docker-compose"
        await both("compose", "POST", D, t_analyst, reset=bare)
        await both("compose: no licence", "POST", D, t_analyst, reset=none)
        for label, answer in (
            ("refused", ok({"success": False, "message": "not entitled"})),
            ("no compose", ok({"message": "Internal server error"})),
            ("no compose, no message", ok({})),
            ("a number", ok({"docker_compose": 5})),
        ):
            await both(f"compose: {label}", "POST", D, t_analyst, reset=license_state(mode={"/retrieve-docker-compose": answer}))

        # The licence server down: a second Rust instance pointed at a closed port.
        down = start_rust(RS_DOWN_PORT, {"COPILOT_LICENSE_URL": f"http://127.0.0.1:{CLOSED_PORT}/"})
        procs.append(down)
        clients["down"] = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_DOWN_PORT}", timeout=120)
        REWRITES["https://license.socfortress.co"] = f"http://127.0.0.1:{CLOSED_PORT}"
        await both("down: feature", "GET", F + "/THREAT%20INTEL", t_analyst, reset=bare, rust="down")
        await both("down: catalog", "GET", S, t_analyst, reset=bare, rust="down")
        await both("down: verify", "GET", V, t_analyst, reset=bare, rust="down")
        await both("down: compose", "POST", D, t_analyst, reset=bare, rust="down")
        REWRITES["https://license.socfortress.co"] = f"http://127.0.0.1:{LICENSE_PORT}"
    finally:
        await cleanup()
        for rec in RECS:
            rec.stop()
        for proc in procs:
            stop_rust(proc)
        await py.aclose()
        for c in clients.values():
            await c.aclose()
    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
