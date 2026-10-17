"""Parity of the core leftovers ported to Rust with this backend — NOT collected by pytest
(needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

Sends the same requests to the real FastAPI routers (in-process) and to a Rust instance this
suite starts, both on the same disposable database, and compares status codes, bodies (key
order included), the rows each write leaves and every request each backend sends upstream —
method, path, query, body and every header, `Content-Length` included. The upstreams are local
stand-ins that record what arrives:

* the SOCFortress licence server (the MSSP seat check on customer creation).

Python reaches the stand-ins because `requests.Session.request` (and the other clients, as
sections need them) are patched here to rewrite the public hosts; Rust because its instance is
started with the `COPILOT_*_URL` overrides (parity harness only).

The `license` and `license_cache` rows are deployment-wide: put aside first, restored at the
end. Rows created by both backends are twins (a `py`/`rs` pair of keys) compared column by
column.

Ports (all overridable): CORE_LEFTOVERS_PARITY_RUST_PORT, CORE_LEFTOVERS_LICENSE_STUB_PORT.

    PARITY_SUITES=tests/e2e/rust_parity_core_leftovers_e2e.py scripts/rust-parity.sh
"""

import asyncio
import datetime
import json
import os
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
# `send_post_request` reads it per call (`os.getenv`); the Rust instance gets the same.
os.environ["COPILOT_API_KEY"] = "parity-core-leftovers-key"
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
RS_PORT = int(os.environ.get("CORE_LEFTOVERS_PARITY_RUST_PORT", "6440"))
LICENSE_PORT = int(os.environ.get("CORE_LEFTOVERS_LICENSE_STUB_PORT", "6441"))
RUST = f"http://127.0.0.1:{RS_PORT}"

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"ClA{SFX}", f"ClB{SFX}"
ADMIN, ANALYST, PORTAL = f"cl_admin{SFX}", f"cl_analyst{SFX}", f"cl_portal{SFX}"
USERS = (ADMIN, ANALYST, PORTAL)
LICENSE_KEY = f"CL-PARITY-{SFX}"
results = []
#: Every stand-in (`main` fills it): each call takes and compares what all of them received.
RECS = []
SAVED = {}


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


async def sql(stmt, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(stmt), params)
        await s.commit()
        return r


async def rows(stmt, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(stmt), params)
        return [dict(m) for m in r.mappings().all()]


def in_list(values):
    return "(" + ", ".join("'" + v.replace("'", "''") + "'" for v in values) + ")"


# --- HTTP stand-ins -------------------------------------------------------------------
class Recorder:
    """Records every request — method, path, every header as sent, body — and answers
    with `answer(rec, method, path, headers, body)`."""

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
                headers = [(k.lower(), v) for k, v in self.headers.items()]
                with recorder.lock:
                    recorder.captured.append({"method": self.command, "path": self.path, "headers": headers, "body": body})
                answer = recorder.answer(recorder, self.command, self.path, dict(headers), body)
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

            do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815 - http.server API

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


def jbody(obj):
    return json.dumps(obj).encode()


def ok(obj, status=200, ctype="application/json", extra=None):
    return status, ctype, jbody(obj), extra or {}


def normalised(captures):
    """Every request as it arrived: headers in the order sent (names lower-cased), body text."""
    return [
        {"method": c["method"], "path": c["path"], "headers": c["headers"], "body": c["body"].decode("utf-8", "replace")} for c in captures
    ]


# --- the licence server ---------------------------------------------------------------
#: What `/verify-license` answers next (`set_licence_answer`).
LICENSE_ANSWER = {}


def licence_object(objects):
    return {"key": LICENSE_KEY, "dataObjects": objects, "customer": {"name": "Parity"}}


def license_answer(rec, method, path, headers, body):
    if method == "POST" and path == "/verify-license":
        return LICENSE_ANSWER.get("answer") or ok({"data": {"license": licence_object([]), "success": True}, "success": True})
    return ok({"detail": "Not Found"}, 404)


def set_licence_answer(answer):
    LICENSE_ANSWER["answer"] = answer


# --- seed and cleanup -----------------------------------------------------------------
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
    # The licence is deployment-wide: put aside, restored at the end.
    SAVED["license"] = await rows("SELECT * FROM license ORDER BY id")
    SAVED["license_cache"] = await rows("SELECT * FROM license_cache ORDER BY id")
    await sql("DELETE FROM license_cache")
    await sql("DELETE FROM license")
    await sql(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) VALUES (:k, 'n', 'e@parity.test', 'c')",
        k=LICENSE_KEY,
    )


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
    if "license" in SAVED:
        await restore_table("license_cache", SAVED.get("license_cache", []))
        await restore_table("license", SAVED.get("license", []))
    like = f"%{SFX}%"
    await sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username IN " + in_list(USERS) + ")")
    await sql("DELETE FROM user_customer_access WHERE customer_code LIKE :l", l=like)
    await sql("DELETE FROM `user` WHERE username IN " + in_list(USERS))
    await sql("DELETE FROM agents WHERE hostname LIKE :l", l=like)
    await sql("DELETE FROM customersmeta WHERE customer_code LIKE :l", l=like)
    await sql("DELETE FROM customers WHERE customer_code LIKE :l", l=like)
    connector_cache.invalidate_all()


# --- the two backends -----------------------------------------------------------------
def build_python_app():
    from app.customers.routes.customers import customers_router
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler

    api = APIRouter(prefix="/api")
    api.include_router(customers_router, prefix="/customers")
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


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


class Pair:
    """Sends a request to both backends and compares what came back and what went out."""

    def __init__(self, py, rs):
        self.py = py
        self.rs = rs

    async def send(self, client, method, path, tok, body, raw, headers, files=None, data=None):
        kw = {"headers": {**({"Authorization": f"Bearer {tok}"} if tok else {}), **(headers or {})}}
        if raw is not None:
            kw["content"] = raw
            kw["headers"].setdefault("Content-Type", "application/json")
        elif body is not None:
            kw["json"] = body
        if files is not None:
            kw["files"] = files
        if data is not None:
            kw["data"] = data
        return await client.request(method, path, **kw)

    async def both(self, method, path, tok=None, body=None, raw=None, headers=None, reset=None, snapshot=None, **kw):
        """The two responses and the requests each backend sent upstream; `reset` runs before each
        backend's call, `snapshot` after it (what it returns is kept as `self.snapshots`)."""
        got = {}
        self.snapshots = {}
        for tag, client in (("py", self.py), ("rs", self.rs)):
            if reset is not None:
                await reset()
            for rec in RECS:
                rec.take()
            r = await self.send(client, method, path, tok, body, raw, headers, **kw)
            # A request a background task sends lands after the answer: let it.
            await asyncio.sleep(0.05)
            got[tag] = (r, {rec.name: normalised(rec.take()) for rec in RECS})
            if snapshot is not None:
                self.snapshots[tag] = await snapshot()
        return got["py"], got["rs"]

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        body=None,
        raw=None,
        headers=None,
        reset=None,
        outbound=True,
        adjust=None,
        snapshot=None,
        **kw,
    ):
        (p, pout), (q, qout) = await self.both(method, path, tok, body, raw, headers, reset, snapshot, **kw)
        b1, b2 = body_of(p), body_of(q)
        if adjust is not None:
            b1, b2 = adjust(b1), adjust(b2)
        passed = p.status_code == q.status_code and b1 == b2
        check(
            f"{name} [{p.status_code}]",
            passed,
            f"python {p.status_code} {json.dumps(b1)[:700]}\n        rust   {q.status_code} {json.dumps(b2)[:700]}",
        )
        if outbound:
            check(
                f"{name}: the same upstream requests",
                pout == qout,
                f"python {json.dumps(pout)[:1500]}\n        rust   {json.dumps(qout)[:1500]}",
            )
        if snapshot is not None:
            sp, sq = self.snapshots["py"], self.snapshots["rs"]
            check(f"{name}: the same rows", sp == sq, f"python {sp}\n        rust   {sq}")
        return p, q


# --- 1. customers ----------------------------------------------------------------------
CUSTOMER_COLS = (
    "customer_code, parent_customer_code, customer_name, contact_last_name, contact_first_name, phone, address_line1, "
    "address_line2, city, state, postal_code, country, customer_type, logo_file"
)
META_COLS = (
    "customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, customer_meta_grafana_org_id, "
    "customer_meta_wazuh_group, customer_meta_index_retention, customer_meta_wazuh_registration_port, "
    "customer_meta_wazuh_log_ingestion_port, customer_meta_wazuh_api_port, customer_meta_wazuh_auth_password, "
    "customer_meta_iris_customer_id, customer_meta_office365_organization_id, customer_meta_portainer_stack_id"
)


def twin(value, tag):
    """The `py`/`rs` twin of a code or value carrying `{t}`."""
    return value.replace("{t}", tag)


def untwin(value, tag):
    """`value` with the twin's tag put back as `{t}` (for comparing twin rows and answers)."""
    if isinstance(value, dict):
        return {k: untwin(v, tag) for k, v in value.items()}
    if isinstance(value, list):
        return [untwin(v, tag) for v in value]
    if isinstance(value, str):
        return value.replace(f"Tw{tag}{SFX}", "Tw{t}" + SFX).replace(f"tw{tag}{SFX}", "tw{t}" + SFX)
    return value


async def customer_rows(code):
    return await rows(f"SELECT {CUSTOMER_COLS} FROM customers WHERE customer_code = :c ORDER BY id", c=code)


async def meta_rows(code):
    return await rows(f"SELECT {META_COLS} FROM customersmeta WHERE customer_code = :c ORDER BY id", c=code)


async def customers_section(pair):
    print("\n=== 1. /api/customers writes ===")
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    C = "/api/customers"

    async def no_cache():
        await sql("DELETE FROM license_cache")

    async def licence_cache():
        """What the ladder cached (the stamps are each backend's own instant)."""
        return await rows(
            "SELECT license_key, feature_name, is_enabled, license_data, TIMESTAMPDIFF(MINUTE, cached_at, expires_at) AS ttl "
            "FROM license_cache ORDER BY id",
        )

    def body(code, **extra):
        out = {
            "customer_code": code,
            "customer_name": "Twin Co",
            "contact_last_name": "Doe",
            "contact_first_name": "Jane",
            "parent_customer_code": "PAR",
            "phone": "+1 555",
            "address_line1": "1 Main St",
            "city": "Anytown",
            "country": "US",
            "customer_type": "MSSP",
            "logo_file": "logo.png",
        }
        out.update(extra)
        return out

    async def twins(name, method, path, payload=None, tok=t_admin, reset=no_cache, rows_of=None, outbound=True):
        """The same request for the `py` and `rs` twin of a customer; answers, upstream requests
        and (`rows_of`) the rows each left compared with the twin's tag put back."""
        (p, pout), (q, qout) = await both_twin_bodies(pair, method, path, payload, tok, reset)
        b1, b2 = untwin(body_of(p), "py"), untwin(body_of(q), "rs")
        check(
            f"{name} [{p.status_code}]",
            p.status_code == q.status_code and b1 == b2,
            f"python {p.status_code} {json.dumps(b1)[:700]}\n        rust   {q.status_code} {json.dumps(b2)[:700]}",
        )
        if outbound:
            pout_t, qout_t = untwin(pout, "py"), untwin(qout, "rs")
            check(f"{name}: the same upstream requests", pout_t == qout_t, f"python {pout_t}\n        rust   {qout_t}")
        if rows_of is not None:
            r1 = untwin(await rows_of(twin(rows_of.code, "py")), "py")
            r2 = untwin(await rows_of(twin(rows_of.code, "rs")), "rs")
            check(f"{name}: the same rows", r1 == r2, f"python {r1}\n        rust   {r2}")
        return p, q

    # Guards and validation (FastAPI's order: JSON → token → body).
    seats = ok({"data": {"license": licence_object([{"name": "MSSP Seats", "intValue": 100000}]), "success": True}, "success": True})
    set_licence_answer(seats)
    await pair.same("create: no token", "POST", C, None, body(f"n{SFX}"), reset=no_cache)
    await pair.same("create: analyst", "POST", C, t_analyst, body(f"n{SFX}"), reset=no_cache)
    await pair.same("create: portal user", "POST", C, t_portal, body(f"n{SFX}"), reset=no_cache)
    await pair.same("create: malformed JSON without a token", "POST", C, None, raw=b'{"customer_code": ')
    await pair.same("create: missing fields", "POST", C, t_admin, {"customer_code": f"n{SFX}"}, reset=no_cache)
    await pair.same(
        "create: wrong types",
        "POST",
        C,
        t_admin,
        {"customer_code": 5, "customer_name": None, "contact_last_name": [], "contact_first_name": "x", "is_provisioned": "maybe"},
        reset=no_cache,
    )
    await pair.same("create: not an object", "POST", C, t_admin, ["x"], reset=no_cache)
    await pair.same("create: no body", "POST", C, t_admin, reset=no_cache)

    # Created: the answer is the body as sent; the rows are twins.
    for label, extra in (("a full body", {"is_provisioned": "yes"}), ("only the required fields", None)):
        code = f"Tw{{t}}{SFX}{len(label)}"
        payload = (
            body(code, **(extra or {}))
            if extra is not None
            else {
                "customer_code": code,
                "customer_name": "Bare",
                "contact_last_name": "L",
                "contact_first_name": "F",
            }
        )

        async def created(c, code=code):
            return await customer_rows(c)

        created.code = code
        await twins(f"create: {label}", "POST", C, payload, rows_of=created)

    # Seats: the count of customers against the allowance (nothing written on a refusal).
    for label, objects, status in (
        ("one seat", [{"name": "MSSP Seats", "intValue": 1}], 200),
        ("seats as a float", [{"name": "MSSP Seats", "intValue": 2.0}], 200),
        ("seats as text", [{"name": "MSSP Seats", "intValue": "100"}], 200),
        ("seats null: the legacy ladder", [{"name": "MSSP Seats", "intValue": None}], 200),
        ("unlimited but 0, seats 1", [{"name": "MSSP Unlimited", "intValue": 0}, {"name": "MSSP Seats", "intValue": 1}], 200),
        ("unlimited as text", [{"name": "MSSP Unlimited", "intValue": "1"}], 200),
        ("a data object that is no dict", ["MSSP Seats"], 200),
        ("no data objects: the ladder, MSSP 5 only", [{"name": "MSSP 5", "intValue": 1}], 200),
        ("no data objects: nothing enabled", [{"name": "AI", "intValue": 1}], 200),
    ):
        set_licence_answer(ok({"data": {"license": licence_object(objects), "success": True}, "success": True}, status))
        await pair.same(f"create, license {label}", "POST", C, t_admin, body(f"lic{SFX}"), reset=no_cache, snapshot=licence_cache)
    check("  (no refused customer was written)", await customer_rows(f"lic{SFX}") == [])
    # The licence server failing: no seat allowance, then the ladder's own failure.
    set_licence_answer(ok({"message": "down"}, 503))
    await pair.same("create, the licence server failing", "POST", C, t_admin, body(f"lic{SFX}"), reset=no_cache)
    set_licence_answer(ok({"data": {"message": "no licence here"}, "success": True}))
    await pair.same("create, an answer without a licence", "POST", C, t_admin, body(f"lic{SFX}"), reset=no_cache)
    # The ladder's cache: a disabled "MSSP Unlimited" cached, the API for the next tier.
    set_licence_answer(ok({"data": {"license": licence_object([{"name": "MSSP 10", "intValue": 1}]), "success": True}, "success": True}))

    async def cached_unlimited_off():
        await sql("DELETE FROM license_cache")
        await sql(
            "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, expires_at) "
            "VALUES (:k, 'MSSP Unlimited', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 HOUR)",
            k=LICENSE_KEY,
        )

    await pair.same(
        "create, the ladder with a cached tier",
        "POST",
        C,
        t_admin,
        body(f"lic{SFX}"),
        reset=cached_unlimited_off,
        snapshot=licence_cache,
    )
    # No licence row at all: the 404 of `get_license`.
    set_licence_answer(seats)
    await sql("DELETE FROM license")
    await pair.same("create without a licence", "POST", C, t_admin, body(f"lic{SFX}"), reset=no_cache)
    await sql(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) VALUES (:k, 'n', 'e@parity.test', 'c')",
        k=LICENSE_KEY,
    )

    # The code is unique as MySQL's collation compares it; too long for the column.
    await pair.same("create: an existing code (another case)", "POST", C, t_admin, body(CUST_A.lower()), reset=no_cache)
    await pair.same("create: a code longer than its column", "POST", C, t_admin, body("x" * 60 + SFX), reset=no_cache)
    await pair.same(
        "create: a parent code longer than its column",
        "POST",
        C,
        t_admin,
        body(f"pl{SFX}", parent_customer_code="P" * 12),
        reset=no_cache,
    )
    check("  (neither was written)", await customer_rows(f"pl{SFX}") == [])

    # Update.
    base = f"Tw{{t}}{SFX}"
    for tag in ("py", "rs"):
        await sql(
            "INSERT INTO customers (customer_code, customer_name, contact_last_name, contact_first_name, phone, created_at) "
            "VALUES (:c, 'Old', 'L', 'F', '1', UTC_TIMESTAMP())",
            c=twin(base, tag),
        )

    async def updated(c):
        return await customer_rows(c)

    updated.code = base
    await twins("update: every field set, an omitted one cleared", "PUT", f"{C}/{base}", body(base, customer_name="New"), rows_of=updated)
    await twins("update: nothing changed", "PUT", f"{C}/{base}", body(base, customer_name="New"), rows_of=updated)
    await twins("update: by another case of the code", "PUT", f"{C}/{base.lower()}", body(base, city="Elsewhere"), rows_of=updated)
    await pair.same("update: unknown customer", "PUT", f"{C}/nosuch{SFX}", t_admin, body("x"))
    await pair.same("update: analyst", "PUT", f"{C}/{CUST_A}", t_analyst, body(CUST_A))
    await pair.same("update: bad body", "PUT", f"{C}/{CUST_A}", t_admin, {"customer_code": CUST_A})
    await pair.same("update: malformed JSON", "PUT", f"{C}/{CUST_A}", t_admin, raw=b"{")
    await twins("update: a value too long for its column", "PUT", f"{C}/{base}", body(base, state="S" * 51), rows_of=updated)

    # Meta (deprecated in Python).
    def meta(index, **extra):
        out = {
            "customer_meta_graylog_index": index,
            "customer_meta_graylog_stream": "stream",
            "customer_meta_grafana_org_id": "7",
            "customer_meta_wazuh_group": "grp",
            "customer_meta_index_retention": "30",
            "customer_meta_wazuh_registration_port": "1515",
            "customer_meta_wazuh_log_ingestion_port": "1514",
            "customer_meta_wazuh_api_port": "55000",
            "customer_meta_wazuh_auth_password": "pw",
        }
        out.update(extra)
        return out

    async def metas(c):
        return await meta_rows(c)

    metas.code = base
    await twins("meta: create", "POST", f"{C}/{base}/meta", meta("idx", customer_meta_portainer_stack_id="12"), rows_of=metas)
    await twins("meta: update without a stack id (exclude_unset)", "PUT", f"{C}/{base}/meta", meta("idx2"), rows_of=metas)
    await twins(
        "meta: update with an explicit null stack id",
        "PUT",
        f"{C}/{base}/meta",
        meta("idx2", customer_meta_portainer_stack_id=None),
        rows_of=metas,
    )
    await pair.same("meta: create for an unknown customer", "POST", f"{C}/nosuch{SFX}/meta", t_admin, meta("i"))
    await pair.same("meta: update unknown", "PUT", f"{C}/nosuch{SFX}/meta", t_admin, meta("i"))
    await pair.same(
        "meta: bad body",
        "POST",
        f"{C}/{CUST_A}/meta",
        t_admin,
        {"customer_meta_graylog_index": 5, "customer_meta_portainer_stack_id": "x"},
    )
    await pair.same("meta: analyst", "DELETE", f"{C}/{CUST_A}/meta", t_analyst)

    # Delete: a meta row (its NOT NULL code), an assigned user, agents nulled, then gone.
    await twins("delete: a customer with a meta row", "DELETE", f"{C}/{base}", rows_of=updated)
    await twins("meta: delete", "DELETE", f"{C}/{base}/meta", rows_of=metas)
    await twins("meta: delete again", "DELETE", f"{C}/{base}/meta", rows_of=metas)
    for tag in ("py", "rs"):
        await sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=twin(base, tag),
            n=ANALYST,
        )
    await twins("delete: users still assigned", "DELETE", f"{C}/{base}", rows_of=updated)
    await sql("DELETE FROM user_customer_access WHERE customer_code LIKE :l", l=f"Tw%{SFX}")
    for tag in ("py", "rs"):
        for n in (1, 2):
            await sql(
                "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, wazuh_agent_version, "
                "wazuh_agent_status, customer_code, quarantined) VALUES (:a, '1', 'l', :h, 'l', 0, UTC_TIMESTAMP(), '1', 'active', :c, 0)",
                a=f"{tag}{n}{SFX}",
                h=f"host-{tag}{n}-{SFX}",
                c=twin(base, tag),
            )
    await twins("delete: a customer with agents", "DELETE", f"{C}/{base}", rows_of=updated)
    agents = {
        tag: await rows("SELECT agent_id, customer_code FROM agents WHERE hostname LIKE :h ORDER BY agent_id", h=f"host-{tag}%-{SFX}")
        for tag in ("py", "rs")
    }
    check(
        "  (both left the agents with a NULL customer code)",
        [r["customer_code"] for r in agents["py"]] == [r["customer_code"] for r in agents["rs"]] == [None, None],
        str(agents),
    )
    await pair.same("delete: unknown customer", "DELETE", f"{C}/nosuch{SFX}", t_admin)
    await pair.same("delete: analyst", "DELETE", f"{C}/{CUST_A}", t_analyst)
    # A tenant's other references (here a notification route) refuse the delete.
    await pair.same("delete: no token", "DELETE", f"{C}/{CUST_A}")


async def both_twin_bodies(pair, method, path, payload, tok, reset):
    """`Pair.both` for twins: each backend gets its own twin's path and body."""
    got = {}
    for tag, client in (("py", pair.py), ("rs", pair.rs)):
        if reset is not None:
            await reset()
        for rec in RECS:
            rec.take()
        body = None if payload is None else json.loads(json.dumps(payload).replace("{t}", tag))
        r = await pair.send(client, method, twin(path, tag), tok, body, None, None)
        await asyncio.sleep(0.05)
        got[tag] = (r, {rec.name: normalised(rec.take()) for rec in RECS})
    return got["py"], got["rs"]


async def main():
    RECS[:] = [Recorder(license_answer, LICENSE_PORT, "license")]
    await seed()
    patch_python_clients()
    rust = start_rust(RS_PORT)
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    pair = Pair(py, rs)
    try:
        await customers_section(pair)
    finally:
        await py.aclose()
        await rs.aclose()
        stop_rust(rust)
        for rec in RECS:
            rec.stop()
        await cleanup()
    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
