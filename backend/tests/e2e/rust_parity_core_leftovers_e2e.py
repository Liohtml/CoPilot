"""Parity of the core leftovers ported to Rust with this backend — NOT collected by pytest
(needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

Sends the same requests to the real FastAPI routers (in-process) and to a Rust instance this
suite starts, both on the same disposable database, and compares status codes, bodies (key
order included), the rows each write leaves and every request each backend sends upstream —
method, path, query, body and every header, `Content-Length` included. The upstreams are local
stand-ins that record what arrives:

* the SOCFortress licence server (the MSSP seat check on customer creation);
* the Wazuh manager (the rule switches: `GET /rules`, the rule file, its upload, the restart),
  stateful — an upload changes the level the next read shows;
* the AI module (`POST /copilot-ai-module/wazuh-rule-exclusion`, as COPILOT_INTEGRATION_MODULES_URL
  addresses it);
* GitHub (`/raw/…` for raw.githubusercontent.com, `/api/…` for api.github.com): the Atomic Red
  Team index, the folder listing, each technique's YAML and markdown;
* the Wazuh indexer (the host logs: `_alias`, then one `_search` per index);
* the CarbonBlack module (`POST /copilot-carbonblack-module/collect`, on the AI module's stand-in).

Python reaches the stand-ins because `requests.Session.request` (and the other clients, as
sections need them) are patched here to rewrite the public hosts; Rust because its instance is
started with the `COPILOT_*_URL` overrides (parity harness only).

The `license`, `license_cache` and `disabledrule` rows, the `Wazuh-Manager`, `Wazuh-Indexer` and
`Event Shipper` connectors and the CarbonBlack job's `scheduled_job_metadata` rows are
deployment-wide: put aside first, restored at the end. Two things are masked in the indexer's
requests: the time window's start (each backend reads its own clock) and the patch version
elasticsearch-py names in its `User-Agent`. Rows created by both backends are twins (a `py`/`rs` pair of keys) compared column by
column.

Ports (all overridable): CORE_LEFTOVERS_PARITY_RUST_PORT, CORE_LEFTOVERS_LICENSE_STUB_PORT,
CORE_LEFTOVERS_MANAGER_STUB_PORT, CORE_LEFTOVERS_AI_STUB_PORT, CORE_LEFTOVERS_GITHUB_STUB_PORT,
CORE_LEFTOVERS_INDEXER_STUB_PORT.

    PARITY_SUITES=tests/e2e/rust_parity_core_leftovers_e2e.py scripts/rust-parity.sh
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
import types
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs

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
MANAGER_PORT = int(os.environ.get("CORE_LEFTOVERS_MANAGER_STUB_PORT", "6442"))
AI_PORT = int(os.environ.get("CORE_LEFTOVERS_AI_STUB_PORT", "6443"))
GITHUB_PORT = int(os.environ.get("CORE_LEFTOVERS_GITHUB_STUB_PORT", "6444"))
INDEXER_PORT = int(os.environ.get("CORE_LEFTOVERS_INDEXER_STUB_PORT", "6445"))
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
    # The indexer and the Event Shipper connectors, the CarbonBlack job's rows: put aside.
    SAVED["indexer"] = await rows("SELECT * FROM connectors WHERE connector_name IN ('Wazuh-Indexer', 'Event Shipper')")
    await sql("DELETE FROM connectors WHERE connector_name IN ('Wazuh-Indexer', 'Event Shipper')")
    for name, url, extra in (("Wazuh-Indexer", f"http://127.0.0.1:{INDEXER_PORT}", None), ("Event Shipper", "10.0.0.5", "12201")):
        await sql(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
            "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
            "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
            "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
            "(:n, '4.8', :u, '2026-01-02 03:04:05', 'indexer', 'pw', NULL, 'desc', 'supports', 1, 1, 0, 0, 1, 0, 0, :x, 1)",
            n=name,
            u=url,
            x=extra,
        )
    SAVED["cb_jobs"] = await rows("SELECT * FROM scheduled_job_metadata WHERE job_id = :j ORDER BY id", j=CB_JOB)
    await sql("DELETE FROM scheduled_job_metadata WHERE job_id = :j", j=CB_JOB)
    for i, (code, host) in enumerate(((CUST_B, HL_DUP), (CUST_A, HL_OK), (CUST_A, HL_SICK), (CUST_B, HL_OTHER), (CUST_A, HL_DUP))):
        await sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
            "wazuh_agent_version, wazuh_agent_status, customer_code, quarantined) VALUES "
            "(:i, :a, '1', 'l', :h, 'l', 0, UTC_TIMESTAMP(), '1', 'active', :c, 0)",
            i=7731001 + i,
            a=f"hl{i}{SFX}",
            h=host,
            c=code,
        )
    await sql("INSERT INTO integration_services (id, service_name, auth_type) VALUES (7731100, 'CarbonBlack', 'API Key')")
    await sql(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, integration_service_id, integration_service_name, "
        "instance_name, deployed) VALUES (7731000, :c, 'cl', 1, 'CarbonBlack', NULL, 0)",
        c=CUST_A,
    )
    await sql("INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES (7731200, 7731000, 7731100)")
    for i, (k, v) in enumerate((("API_URL", "https://cb.example"), ("API_KEY", "cbk"), ("API_ID", "cbid"), ("ORGANIZATION_KEY", "org"))):
        await sql(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, 7731200, :k, :v)",
            i=7731300 + i,
            k=k,
            v=v,
        )
    # The disabled rules and the manager's connector: put aside, restored at the end.
    SAVED["disabledrule"] = await rows("SELECT * FROM disabledrule ORDER BY id")
    await sql("DELETE FROM disabledrule")
    SAVED["manager"] = await rows("SELECT * FROM connectors WHERE connector_name = 'Wazuh-Manager'")
    await sql("DELETE FROM connectors WHERE connector_name = 'Wazuh-Manager'")
    await sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
        "('Wazuh-Manager', '4.8', :u, '2026-01-02 03:04:05', 'wazuh', 'pw', NULL, 'desc', 'supports', 1, 1, 0, 0, 1, 0, 0, "
        "NULL, 1)",
        u=f"http://127.0.0.1:{MANAGER_PORT}",
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
    if "disabledrule" in SAVED:
        await restore_table("disabledrule", SAVED["disabledrule"])
    await sql("DELETE FROM integration_auth_keys WHERE id BETWEEN 7731300 AND 7731399")
    await sql("DELETE FROM integration_subscriptions WHERE id BETWEEN 7731200 AND 7731299")
    await sql("DELETE FROM customer_integrations WHERE id BETWEEN 7731000 AND 7731099")
    await sql("DELETE FROM integration_services WHERE id BETWEEN 7731100 AND 7731199")
    await sql("DELETE FROM agents WHERE id BETWEEN 7731001 AND 7731099")
    if "cb_jobs" in SAVED:
        await sql("DELETE FROM scheduled_job_metadata WHERE job_id = :j", j=CB_JOB)
        for row in SAVED["cb_jobs"]:
            cols = [c for c in row if c != "id"]
            await sql(f"INSERT INTO scheduled_job_metadata ({', '.join(cols)}) VALUES ({', '.join(':' + c for c in cols)})", **row)
    if "indexer" in SAVED:
        await sql("DELETE FROM connectors WHERE connector_name IN ('Wazuh-Indexer', 'Event Shipper')")
        for row in SAVED["indexer"]:
            cols = list(row.keys())
            await sql(f"INSERT INTO connectors ({', '.join(cols)}) VALUES ({', '.join(':' + c for c in cols)})", **row)
    if "manager" in SAVED:
        await sql("DELETE FROM connectors WHERE connector_name = 'Wazuh-Manager'")
        for row in SAVED["manager"]:
            cols = list(row.keys())
            await sql(f"INSERT INTO connectors ({', '.join(cols)}) VALUES ({', '.join(':' + c for c in cols)})", **row)
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
    from app.routers.carbonblack import router as carbonblack_router
    from app.routers.healthcheck import router as healthcheck_router
    from app.routers.wazuh_manager import router as wazuh_manager_router

    api = APIRouter(prefix="/api")
    api.include_router(customers_router, prefix="/customers")
    api.include_router(wazuh_manager_router)
    api.include_router(healthcheck_router)
    api.include_router(carbonblack_router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


#: The public hosts the Python services call, and the stand-ins they reach here.
REWRITES = {
    "https://license.socfortress.co": f"http://127.0.0.1:{LICENSE_PORT}",
    "https://raw.githubusercontent.com": f"http://127.0.0.1:{GITHUB_PORT}/raw",
    "https://api.github.com": f"http://127.0.0.1:{GITHUB_PORT}/api",
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
    redirect_python_httpx()
    redirect_python_aiohttp()


class _ModuleRedirect(httpx.AsyncBaseTransport):
    """What COPILOT_INTEGRATION_MODULES_URL does for the Rust service: `{base}/{host}{path}`."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        base = f"http://127.0.0.1:{AI_PORT}"
        rest = str(request.url).split("://", 1)[1]
        request.url = httpx.URL(f"{base}/{rest}")
        request.headers["Host"] = base.split("://", 1)[1]
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


def redirect_python_httpx():
    """The rule exclusion's `httpx.AsyncClient()` reaches the AI module stand-in."""
    from app.connectors.wazuh_manager.services import rules

    real = httpx.AsyncClient
    shim = types.SimpleNamespace(**{k: getattr(httpx, k) for k in dir(httpx) if not k.startswith("_")})
    shim.AsyncClient = lambda *a, **kw: real(*a, transport=_ModuleRedirect(), **kw)
    rules.httpx = shim
    from app.integrations.modules.services import carbonblack

    carbonblack.httpx = shim


def redirect_python_aiohttp():
    """The Atomic Red Team service's `aiohttp.ClientSession()` reaches the GitHub stand-in (the
    URL rewritten before yarl reads it, as the Rust overrides replace the host)."""
    import warnings

    import aiohttp

    from app.connectors.wazuh_manager.services import mitre

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        class Session(aiohttp.ClientSession):
            def _request(self, method, str_or_url, *a, **kw):
                return super()._request(method, rewrite(str(str_or_url)), *a, **kw)

    shim = types.SimpleNamespace(**{k: getattr(aiohttp, k) for k in dir(aiohttp) if not k.startswith("_")})
    shim.ClientSession = Session
    mitre.aiohttp = shim


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
        "COPILOT_INTEGRATION_MODULES_URL": f"http://127.0.0.1:{AI_PORT}",
        "COPILOT_GITHUB_RAW_URL": f"http://127.0.0.1:{GITHUB_PORT}/raw",
        "COPILOT_GITHUB_API_URL": f"http://127.0.0.1:{GITHUB_PORT}/api",
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
    # The disabled rules and the manager's connector: put aside, restored at the end.
    SAVED["disabledrule"] = await rows("SELECT * FROM disabledrule ORDER BY id")
    await sql("DELETE FROM disabledrule")
    SAVED["manager"] = await rows("SELECT * FROM connectors WHERE connector_name = 'Wazuh-Manager'")
    await sql("DELETE FROM connectors WHERE connector_name = 'Wazuh-Manager'")
    await sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
        "('Wazuh-Manager', '4.8', :u, '2026-01-02 03:04:05', 'wazuh', 'pw', NULL, 'desc', 'supports', 1, 1, 0, 0, 1, 0, 0, "
        "NULL, 1)",
        u=f"http://127.0.0.1:{MANAGER_PORT}",
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


# --- 2. the Wazuh manager's rule switches, the exclusion, Atomic Red Team ------------------
RULE_ID = f"77{int(SFX, 16) % 10000:04d}"
HL_OK, HL_SICK, HL_OTHER, HL_DUP = (f"hl-{n}-{SFX}" for n in ("ok", "sick", "other", "dup"))
CB_JOB = "invoke_carbonblack_integration_collection"
RULE_FILE = "0095-sshd_rules.xml"


def rule_group(level):
    return {
        "@name": "syslog,sshd,",
        "rule": [
            {"@id": "5700", "@level": "0", "decoded_as": "sshd", "description": "SSHD messages grouped."},
            {
                "@id": RULE_ID,
                "@level": level,
                "if_sid": "5700",
                "match": "illegal user|invalid user",
                "description": "sshd: Attempt <x> & y",
            },
        ],
    }


def manager_answer(rec, method, path, headers, body):
    """The Wazuh API as the rule switches use it; the rule's level is what the last upload wrote."""
    p, _, q = path.partition("?")
    if p == "/security/user/authenticate":
        return ok({"data": {"token": "tok"}, "error": 0})
    if method == "GET" and p == "/rules":
        if parse_qs(q).get("rule_ids") == [RULE_ID]:
            return ok({"data": {"affected_items": [{"filename": RULE_FILE, "id": int(RULE_ID)}], "total_affected_items": 1}, "error": 0})
        return ok({"data": {"affected_items": [], "total_affected_items": 0}, "error": 0})
    if method == "GET" and p == f"/rules/files/{RULE_FILE}":
        group = rule_group(rec.mode.get("level", "5"))
        return ok({"data": {"affected_items": [{"group": group}], "total_affected_items": 1}, "error": 0})
    if method == "PUT" and p == f"/rules/files/{RULE_FILE}":
        if headers.get("content-type") != "application/octet-stream":
            return ok({"title": "Unsupported Media Type", "detail": "Invalid content-type"}, 415)
        found = re.search(rf'<rule id="{RULE_ID}" level="([^"]*)"', body.decode())
        if found:
            rec.mode["level"] = found.group(1)
        return ok({"data": {"affected_items": [RULE_FILE], "total_affected_items": 1}, "error": 0})
    if method == "PUT" and p == "/manager/restart":
        return ok({"data": {"affected_items": ["node01"], "total_affected_items": 1}, "error": 0})
    return ok({"title": "Not Found"}, 404)


#: What the AI module answers next.
AI_ANSWER = {}


def ai_answer(rec, method, path, headers, body):
    if method == "POST" and path == "/copilot-ai-module/wazuh-rule-exclusion":
        return AI_ANSWER.get("answer") or ok({"wazuh_rule": "<rule id='1'/>", "explanation": "e", "message": "m", "success": True})
    if method == "POST" and path == "/copilot-carbonblack-module/collect":
        return ok({"success": True, "message": "collected"})
    return ok({"detail": "Not Found"}, 404)


ART = "/raw/redcanaryco/atomic-red-team/refs/heads/master/atomics"
INDEX_PATH = f"{ART}/Indexes/Indexes-Markdown/atomic-red-team-index.md"
CONTENTS_PATH = "/api/repos/redcanaryco/atomic-red-team/contents/atomics"
INDEX_TEXT = (
    "# Atomic Red Team\n\n| Technique | ID | Tests |\n|---|---|---|\n"
    "| [OS Credential Dumping](../../T1003/T1003.md) | T1003 | 12 |\n"
    "| [LSASS Memory](../../T1003.001/T1003.001.md) | T1003.001 | 7 |\n"
    "|[Command and Scripting Interpreter](x)|T1059|  3  |\n"
    "| [Bad count](y) | T1 | x |\n"
)
TECHNIQUE_FILES = {
    "T1001.yaml": "display_name: Data Obfuscation\natomic_tests:\n- name: a\n  supported_platforms: [windows, linux]\n"
    "  dependencies:\n  - description: x\n- name: b\n  supported_platforms: [linux, macos]\n",
    "T1002.md": "# Data Compressed - T1002\n## Atomic Test #1\n## Atomic Test #2\nRuns on Windows.\n",
    "T1003.yaml": "atomic_tests: [unclosed\n",
    "T1003.md": "# OS Credential Dumping\n## Atomic Test #1 - linux dependencies\n",
    "T1006.yaml": "- a list\n",
    "T1006.md": "no header, no tests\n",
}
TEXT = "text/plain; charset=utf-8"


def github_answer(rec, method, path, headers, body):
    mode = rec.mode
    if path == INDEX_PATH:
        index = mode.get("index", "ok")
        if index == "close":
            return None
        if index == "404":
            return 404, TEXT, b"404: Not Found", {}
        if index == "bad-utf8":
            return 200, TEXT, b"| [x](y) | T1 | 1 |\n\xff\xfe", {}
        return 200, TEXT, INDEX_TEXT.encode(), {}
    if path == CONTENTS_PATH:
        contents = mode.get("contents", "ok")
        if contents == "403":
            return ok({"message": "API rate limit exceeded"}, 403)
        if contents == "html":
            return 200, "text/html; charset=utf-8", b"<html></html>", {}
        if contents == "no-type":
            return ok([{"name": "T1001"}])
        if contents == "dict":
            return ok({"name": "T1001", "type": "dir"})
        folders = [
            {"name": "T1001", "type": "dir"},
            {"name": "T1002", "type": "dir"},
            {"name": "T1003", "type": "dir"},
            {"name": "T1004", "type": "dir"},
            {"name": "T1006", "type": "dir"},
            {"name": "Indexes", "type": "dir"},
            {"name": "T1005", "type": "file"},
        ]
        return ok(folders)
    if path.startswith(ART + "/"):
        name = path[len(ART) + 1 :].split("/")[-1]
        if name == "T7777.md":
            return 200, TEXT, b"# x\n\xff", {}
        if name in TECHNIQUE_FILES:
            return 200, TEXT, TECHNIQUE_FILES[name].encode(), {}
        if name == "T1059.md":
            return 200, TEXT, b"# Command and Scripting Interpreter\n", {}
    return 404, TEXT, b"404: Not Found", {}


def masked_listing(body):
    """`last_updated` is a clock reading (checked for its form, then masked); a technique's YAML
    platforms are a Python `set`, whose order follows per-process string hashes."""
    if isinstance(body, dict) and isinstance(body.get("last_updated"), str):
        stamp = body["last_updated"]
        body = dict(body)
        body["last_updated"] = "<iso>" if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?", stamp) else stamp
        body["tests"] = [{**t, "categories": sorted(t.get("categories") or [])} for t in body.get("tests", [])]
    return body


async def disabled_rows():
    return await rows(
        "SELECT rule_id, previous_level, new_level, reason_for_disabling, length_of_time, disabled_by FROM disabledrule "
        "WHERE rule_id = :a OR rule_id = :b ORDER BY id",
        a=RULE_ID,
        b="404404",
    )


def bare_500(r):
    return r.status_code == 500 and r.text == "Internal Server Error"


async def wazuh_rules_section(pair, holder):
    from app.connectors.wazuh_manager.services.mitre import AtomicRedTeamService
    from app.connectors.wazuh_manager.services.rules import convert_to_xml
    from app.connectors.wazuh_manager.services.rules import set_rule_level

    print("\n== 2. /api/wazuh_manager rule switches, exclusion, Atomic Red Team ==")
    W = "/api/wazuh_manager"
    t_admin = token(ADMIN, ["admin"])
    t_analyst = token(ANALYST, ["analyst"])
    t_portal = token(PORTAL, ["customer_user"])
    manager, ai, github = RECS[1], RECS[2], RECS[3]
    disable = {"rule_id": RULE_ID, "reason_for_disabling": "noisy", "length_of_time": "1 week"}
    enable = {"rule_id": RULE_ID, "reason_for_enabling": "tuned"}

    # Guards and bodies, in FastAPI's order (nothing reaches the manager).
    for route, payload in (("/rule/disable", disable), ("/rule/enable", enable)):
        await pair.same(f"POST {route}: no token", "POST", W + route, body=payload)
        await pair.same(f"POST {route}: analyst", "POST", W + route, t_analyst, payload)
        await pair.same(f"POST {route}: malformed JSON, no token", "POST", W + route, raw=b"{")
        await pair.same(f"POST {route}: no body", "POST", W + route, t_admin)
        await pair.same(f"POST {route}: a list", "POST", W + route, t_admin, [1])
        await pair.same(f"POST {route}: wrong types", "POST", W + route, t_admin, {"rule_id": 5, "reason_for_disabling": None})
    await pair.same("GET /rule/disabled: no token", "GET", W + "/rule/disabled")
    await pair.same("GET /rule/disabled: analyst", "GET", W + "/rule/disabled", t_analyst)
    await pair.same("GET /rule/disabled: none", "GET", W + "/rule/disabled", t_admin)
    await pair.same("POST /rule/enable: not disabled", "POST", W + "/rule/enable", t_admin, enable, snapshot=disabled_rows)

    # Disable. Python's endpoints lack their `/` (`{url}rules`: a malformed URL, then the KeyError of
    # the failure answer) — a bare 500 on any connector URL that ends without one, which is every
    # working one; and its upload is `application/json`, which the manager refuses. Rust works.
    manager.mode.clear()
    (p, pout), (q, qout) = await pair.both("POST", W + "/rule/disable", t_admin, disable, snapshot=disabled_rows)
    _, expected_xml = await set_rule_level([rule_group("5")], RULE_ID, "1")
    expected_xml = await convert_to_xml(expected_xml)
    rust_calls = [(c["method"], c["path"]) for c in qout["manager"] if c["path"] != "/security/user/authenticate"]
    upload = [c for c in qout["manager"] if c["method"] == "PUT" and c["path"].startswith("/rules/files/")]
    check(
        "POST /rule/disable: Python fails (bare 500, nothing written), Rust works",
        bare_500(p)
        and pair.snapshots["py"] == []
        and q.status_code == 200
        and body_of(q)
        == {"previous_level": "5", "message": f"Rule {RULE_ID} successfully processed in file {RULE_FILE}.", "success": True},
        f"python {p.status_code} {p.text[:200]}\n        rust   {q.status_code} {q.text[:300]}",
    )
    check(
        "POST /rule/disable: Rust's manager calls are Python's chain, with the `/` and the rule file's type",
        rust_calls
        == [
            ("GET", f"/rules?rule_ids={RULE_ID}"),
            ("GET", f"/rules/files/{RULE_FILE}"),
            ("PUT", f"/rules/files/{RULE_FILE}?overwrite=true"),
            ("PUT", "/manager/restart"),
        ]
        and len(upload) == 1
        and upload[0]["body"] == expected_xml
        and dict(upload[0]["headers"]).get("content-type") == "application/octet-stream",
        f"{json.dumps(qout['manager'])[:1500]}\n        expected body {expected_xml!r}",
    )
    check(
        "POST /rule/disable: the row Rust writes (the previous level, the caller)",
        pair.snapshots["rs"]
        == [
            {
                "rule_id": RULE_ID,
                "previous_level": "5",
                "new_level": "1",
                "reason_for_disabling": "noisy",
                "length_of_time": "1 week",
                "disabled_by": ADMIN,
            },
        ],
        str(pair.snapshots["rs"]),
    )
    # Listing a stored row: Python validates the ORM rows without `from_attributes` (its 400).
    (p, _), (q, _) = await pair.both("GET", W + "/rule/disabled", t_admin)
    listed = body_of(q)
    check(
        "GET /rule/disabled with a row: Python fails (the response model's 400), Rust lists it",
        p.status_code == 400
        and "validation error for AllDisabledRuleResponse" in str(body_of(p))
        and q.status_code == 200
        and listed["message"] == "Successfully fetched all disabled rules"
        and [r for r in listed["disabled_rules"] if r["rule_id"] == RULE_ID]
        == [
            {
                "rule_id": RULE_ID,
                "previous_level": "5",
                "new_level": "1",
                "reason_for_disabling": "noisy",
                "length_of_time": "1 week",
                "disabled_by": ADMIN,
            },
        ],
        f"python {p.status_code} {p.text[:300]}\n        rust   {q.status_code} {q.text[:300]}",
    )
    await pair.same("POST /rule/disable: already disabled", "POST", W + "/rule/disable", t_admin, disable)
    # Enable: the recorded level goes back, the row goes.
    (p, _), (q, qout) = await pair.both("POST", W + "/rule/enable", t_admin, enable, snapshot=disabled_rows)
    _, expected_xml = await set_rule_level([rule_group("1")], RULE_ID, "5")
    expected_xml = await convert_to_xml(expected_xml)
    upload = [c for c in qout["manager"] if c["method"] == "PUT" and c["path"].startswith("/rules/files/")]
    check(
        "POST /rule/enable: Python fails (bare 500, the row kept), Rust works and deletes the row",
        bare_500(p)
        and len(pair.snapshots["py"]) == 1
        and q.status_code == 200
        and body_of(q) == {"new_level": None, "message": f"Rule {RULE_ID} successfully processed in file {RULE_FILE}.", "success": True}
        and pair.snapshots["rs"] == []
        and len(upload) == 1
        and upload[0]["body"] == expected_xml,
        f"python {p.status_code} {p.text[:200]}\n        rust   {q.status_code} {q.text[:300]} {json.dumps(upload)[:600]}",
    )
    await pair.same("POST /rule/enable: enabled again", "POST", W + "/rule/enable", t_admin, enable)
    unknown = {"rule_id": "404404", "reason_for_disabling": "x", "length_of_time": "x"}
    (p, _), (q, _) = await pair.both("POST", W + "/rule/disable", t_admin, unknown, snapshot=disabled_rows)
    check(
        "POST /rule/disable: a rule the manager does not know (Python's bare 500, Rust's 404)",
        bare_500(p)
        and q.status_code == 404
        and body_of(q) == {"message": "Rule 404404 not found. Make sure the rule ID is correct within the Wazuh Manager.", "success": False}
        and pair.snapshots["rs"] == [],
        f"python {p.status_code} {p.text[:200]}\n        rust   {q.status_code} {q.text[:300]}",
    )

    # The exclusion: the AI module's answer, whatever its status.
    X = W + "/rule/exclude"
    good = {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "windows", "n": 10**20, "f": 1.5, "u": "é"}}
    await pair.same("POST /rule/exclude: no token", "POST", X, body=good)
    await pair.same("POST /rule/exclude: analyst", "POST", X, t_analyst, good)
    await pair.same("POST /rule/exclude: malformed JSON", "POST", X, t_admin, raw=b"{")
    for name, payload in (
        ("no body", None),
        ("integration not a str", {"integration": 5, "prompt": {"rule_group1": "windows"}}),
        ("another integration", {"integration": "x", "prompt": {"rule_group1": "windows"}}),
        ("integration wrong, prompt not a dict", {"integration": "x", "prompt": 5}),
        ("integration not a str, prompt refused", {"integration": 5, "prompt": {}}),
        ("prompt not a dict", {"integration": "wazuh-rule-exclusion", "prompt": [1]}),
        ("no rule_group1", {"integration": "wazuh-rule-exclusion", "prompt": {"x": 1}}),
        ("rule_group1 not windows", {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "linux"}}),
        ("rule_group3, neither windows", {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "a", "rule_group3": "b"}}),
        ("rule_group3 alone", {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group3": "b"}}),
        ("rule_group3 windows", {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "a", "rule_group3": "windows"}}),
        ("a valid body", good),
    ):
        await pair.same(f"POST /rule/exclude: {name}", "POST", X, t_admin, payload)
    await pair.same(
        "POST /rule/exclude: NaN in the prompt (httpx refuses it)",
        "POST",
        X,
        t_admin,
        raw=b'{"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "windows", "x": NaN}}',
    )
    for name, answer in (
        ("the module's 500 with a valid answer", ok({"wazuh_rule": "r", "explanation": "e", "message": "m", "success": False}, 500)),
        ("not JSON", (502, "text/html", b"<html>bad gateway</html>", {})),
        ("a list", ok([1, 2])),
        ("fields missing or wrong", ok({"wazuh_rule": 5, "success": "maybe"})),
        ("the connection dropped", None),
    ):
        AI_ANSWER["answer"] = answer
        if answer is None:
            AI_ANSWER["answer"] = None
            ai.answer = lambda *a: None
        await pair.same(f"POST /rule/exclude: {name}", "POST", X, t_admin, good)
        ai.answer = ai_answer
    AI_ANSWER.clear()

    # Atomic Red Team. Both processes cache the listing for a day once it loads: the failures first.
    A = W + "/mitre/atomic-tests"
    AtomicRedTeamService._tests_cache.clear()
    AtomicRedTeamService._cache.clear()
    await pair.same("GET /atomic-tests: no token", "GET", A)
    await pair.same("GET /atomic-tests: portal user", "GET", A, t_portal)
    for q in ("page=0", "page=-1&size=x", "size=1.5", "page=1.0&size=2_0&os_category="):
        github.mode.update({"index": "close"})
        await pair.same(f"GET /atomic-tests?{q}", "GET", f"{A}?{q}", t_analyst)
    for name, mode in (
        ("the index fetch dropped", {"index": "close"}),
        ("the index not UTF-8", {"index": "bad-utf8"}),
        ("no index, the API refuses", {"index": "404", "contents": "403"}),
        ("no index, the API answers HTML", {"index": "404", "contents": "html"}),
        ("no index, a folder without its type", {"index": "404", "contents": "no-type"}),
        ("no index, the API answers a dict", {"index": "404", "contents": "dict"}),
    ):
        github.mode.clear()
        github.mode.update(mode)
        await pair.same(f"GET /atomic-tests: {name}", "GET", A, t_analyst)
    # The fallback: each technique's YAML (then its markdown), five at a time — so the requests are
    # compared as a set.
    github.mode.clear()
    github.mode.update({"index": "404"})
    (p, pout), (q, qout) = await pair.both("GET", f"{A}?size=10", t_analyst)
    key = lambda c: (c["method"], c["path"])  # noqa: E731
    check(
        "GET /atomic-tests: the fallback (folders, YAML, markdown) [200]",
        p.status_code == q.status_code == 200 and masked_listing(body_of(p)) == masked_listing(body_of(q)),
        f"python {p.status_code} {json.dumps(body_of(p))[:900]}\n        rust   {q.status_code} {json.dumps(body_of(q))[:900]}",
    )
    check(
        "GET /atomic-tests: the fallback's requests (as a set)",
        sorted(pout["github"], key=key) == sorted(qout["github"], key=key) and pout["manager"] == qout["manager"] == [],
        f"python {json.dumps(sorted(pout['github'], key=key))[:1500]}\n        rust   {json.dumps(sorted(qout['github'], key=key))[:1500]}",
    )
    for q in (
        "",
        "?size=2&page=2",
        "?os_category=WINDOWS",
        "?os_category=linux&size=1&page=2",
        "?size=0",
        "?size=-1&page=3",
        "?size=3&page=-1",
    ):
        await pair.same(f"GET /atomic-tests{q} (cached)", "GET", A + q, t_analyst, adjust=masked_listing)
    # A fresh start of both: the index.
    AtomicRedTeamService._tests_cache.clear()
    stop_rust(holder["rust"])
    holder["rust"] = start_rust(RS_PORT)
    await pair.rs.aclose()
    pair.rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    github.mode.clear()
    await pair.same("GET /atomic-tests: the index", "GET", f"{A}?size=2", t_analyst, adjust=masked_listing)
    await pair.same("GET /atomic-tests: the index, cached", "GET", f"{A}?page=2&size=2", t_analyst, adjust=masked_listing)
    await pair.same(
        "GET /atomic-tests: os_category on the index (no categories)",
        "GET",
        f"{A}?os_category=windows",
        t_analyst,
        adjust=masked_listing,
    )

    T = W + "/mitre/techniques"
    await pair.same("GET /techniques/{id}/atomic-tests: no token", "GET", f"{T}/T1003/atomic-tests")
    for tid in ("T1003", "T1003", "T9998", "attack-pattern-T1059", "T7777", "T1003%20x", "T1%3Fx", "T%C3%A9", "%2E%2E", "a-b-"):
        await pair.same(f"GET /techniques/{tid}/atomic-tests", "GET", f"{T}/{tid}/atomic-tests", t_analyst)


# --- 3. the host logs, the CarbonBlack test ---------------------------------------------
INDICES = {
    "wazuh-alerts-a": {"aliases": {}},
    "graylog_deflector": {"aliases": {}},
    "wazuh-alerts-b": {"aliases": {}},
    "wazuh-alerts-c": {"aliases": {}},
}


def indexer_answer(rec, method, path, headers, body):
    p = path.partition("?")[0]
    if method == "GET" and p == "/*/_alias":
        if rec.mode.get("alias") == "fail":
            return ok({"error": "boom"}, 500)
        return ok(INDICES)
    if method == "POST" and p.endswith("/_search"):
        text_body = body.decode()
        index = p.split("/")[1]
        hits = rec.mode.get("hits", "list")
        if HL_SICK in text_body:
            return ok({"error": {"type": "boom"}}, 500)
        if index == "wazuh-alerts-b":
            if hits == "list":
                return ok({"hits": {"hits": [{"_index": index, "_source": {"x": 1}}]}})
            if hits == "ints":
                return ok({"hits": {"hits": [1, 2]}})
            if hits == "str":
                return ok({"hits": {"hits": "abc"}})
        return ok({"hits": {"hits": []}})
    return ok({"error": "no route"}, 404)


STAMP = re.compile(r'"gte":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z"')


ES_AGENT = re.compile(r"\(Python 3\.11(?:\.\d+)?\)")


def masked_searches(out):
    """The indexer requests with the window's start (a clock reading) masked, and the
    interpreter's patch version elasticsearch-py names in its `User-Agent` (the Rust port names
    the minor one)."""
    return [
        {
            **c,
            "headers": [(k, ES_AGENT.sub("(Python 3.11)", v) if k == "user-agent" else v) for k, v in c["headers"]],
            "body": STAMP.sub('"gte":"<start>"', c["body"]),
        }
        for c in out
    ]


async def same_masked(pair, name, method, path, tok=None, body=None, raw=None):
    (p, pout), (q, qout) = await pair.both(method, path, tok, body, raw)
    check(
        f"{name} [{p.status_code}]",
        p.status_code == q.status_code and body_of(p) == body_of(q),
        f"python {p.status_code} {json.dumps(body_of(p))[:700]}\n        rust   {q.status_code} {json.dumps(body_of(q))[:700]}",
    )
    pout = {k: masked_searches(v) for k, v in pout.items()}
    qout = {k: masked_searches(v) for k, v in qout.items()}
    check(
        f"{name}: the same upstream requests",
        pout == qout,
        f"python {json.dumps(pout)[:2000]}\n        rust   {json.dumps(qout)[:2000]}",
    )


async def cb_rows():
    return [
        {"enabled": r["enabled"], "stamped": r["last_success"] is not None}
        for r in await rows("SELECT enabled, last_success FROM scheduled_job_metadata WHERE job_id = :j ORDER BY id", j=CB_JOB)
    ]


async def logs_and_carbonblack_section(pair):
    print("\n== 3. /api/healthcheck/logs, /api/carbonblack/test ==")
    t_admin = token(ADMIN, ["admin"])
    t_analyst = token(ANALYST, ["analyst"])
    t_portal = token(PORTAL, ["customer_user"])
    indexer = RECS[4]
    L = "/api/healthcheck/logs"
    await pair.same("POST /logs: no token", "POST", L, body={"agent_name": HL_OK})
    await pair.same("POST /logs: portal user", "POST", L, t_portal, {"agent_name": HL_OK})
    await pair.same("POST /logs: malformed JSON, no token", "POST", L, raw=b"{")
    for name, payload in (
        ("no body", None),
        ("a list", [1]),
        ("no agent_name", {}),
        ("wrong types", {"agent_name": 5, "size": "x", "log_field": None}),
        ("a timerange in another unit", {"agent_name": HL_OK, "timerange": "5x"}),
        ("a timerange without a number", {"agent_name": HL_OK, "timerange": "h"}),
        ("a timerange that is not a str", {"agent_name": HL_OK, "timerange": 5}),
        ("an empty timerange (IndexError)", {"agent_name": HL_OK, "timerange": "", "size": "x"}),
    ):
        await pair.same(f"POST /logs: {name}", "POST", L, t_admin, payload)
    await pair.same("POST /logs: another tenant's host", "POST", L, t_analyst, {"agent_name": HL_OTHER})
    await pair.same("POST /logs: a hostname whose first agent is another tenant's", "POST", L, t_analyst, {"agent_name": HL_DUP})
    await pair.same("POST /logs: an unknown host (scoped)", "POST", L, t_analyst, {"agent_name": f"nosuch-{SFX}"})
    await pair.same("POST /logs: an unknown host (admin)", "POST", L, t_admin, {"agent_name": f"nosuch-{SFX}"})
    for name, payload, mode in (
        ("healthy (the first index with a hit ends it)", {"agent_name": HL_OK}, {}),
        (
            "healthy, every field set",
            {
                "agent_name": HL_OK,
                "timerange": "15m",
                "size": 3,
                "log_field": "rule_level",
                "log_value": "3",
                "timestamp_field": "timestamp",
            },
            {},
        ),
        ("weeks and a size of 0", {"agent_name": HL_OK, "timerange": "2w", "size": 0}, {}),
        ("days, a negative size", {"agent_name": HL_OK, "timerange": "1d", "size": -1}, {}),
        ("hits that are not documents", {"agent_name": HL_OK}, {"hits": "ints"}),
        ("hits that are a string", {"agent_name": HL_OK}, {"hits": "str"}),
        ("every search fails: unhealthy", {"agent_name": HL_SICK}, {}),
        ("the analyst's own host", {"agent_name": HL_OK}, {}),
        ("a digit int() refuses", {"agent_name": HL_OK, "timerange": "\u00b2h"}, {}),
        ("days timedelta refuses", {"agent_name": HL_OK, "timerange": "1000000000d"}, {}),
        ("an int too large for C", {"agent_name": HL_OK, "timerange": "99999999999999999999h"}, {}),
        ("the index listing fails", {"agent_name": HL_OK}, {"alias": "fail"}),
    ):
        indexer.mode.clear()
        indexer.mode.update(mode)
        tok = t_analyst if "analyst" in name else t_admin
        await same_masked(pair, f"POST /logs: {name}", "POST", L, tok, payload)
    indexer.mode.clear()

    C = "/api/carbonblack/test"
    await pair.same("GET /carbonblack/test: no token", "GET", C)
    await pair.same("GET /carbonblack/test: portal user", "GET", C, t_portal)

    async def no_row():
        await sql("DELETE FROM scheduled_job_metadata WHERE job_id = :j", j=CB_JOB)

    async def row(enabled, n=1):
        await no_row()
        for _ in range(n):
            await sql("INSERT INTO scheduled_job_metadata (job_id, time_interval, enabled) VALUES (:j, 5, :e)", j=CB_JOB, e=enabled)

    await pair.same("GET /carbonblack/test: no job row (runs, nothing to stamp)", "GET", C, t_analyst, reset=no_row, snapshot=cb_rows)
    await pair.same("GET /carbonblack/test: the row disabled (skipped)", "GET", C, t_admin, reset=lambda: row(0), snapshot=cb_rows)
    await pair.same("GET /carbonblack/test: the row enabled (runs, stamped)", "GET", C, t_admin, reset=lambda: row(1), snapshot=cb_rows)
    (p, pout), (q, qout) = await pair.both("GET", C, t_admin, reset=lambda: row(1))
    posts = [c for c in pout["ai"] if c["path"] == "/copilot-carbonblack-module/collect"]
    check(
        "GET /carbonblack/test: the seeded customer's collection reaches the module, the same request from both",
        p.status_code == q.status_code == 200 and len(posts) >= 1 and pout["ai"] == qout["ai"],
        f"python {json.dumps(pout['ai'])[:1200]}\n        rust   {json.dumps(qout['ai'])[:1200]}",
    )
    await pair.same(
        "GET /carbonblack/test: two rows (one_or_none raises after the run)",
        "GET",
        C,
        t_admin,
        reset=lambda: row(1, 2),
        snapshot=cb_rows,
    )
    await no_row()


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
    RECS[:] = [
        Recorder(license_answer, LICENSE_PORT, "license"),
        Recorder(manager_answer, MANAGER_PORT, "manager"),
        Recorder(ai_answer, AI_PORT, "ai"),
        Recorder(github_answer, GITHUB_PORT, "github"),
        Recorder(indexer_answer, INDEXER_PORT, "indexer"),
    ]
    await seed()
    patch_python_clients()
    holder = {"rust": start_rust(RS_PORT)}
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    pair = Pair(py, rs)
    try:
        await customers_section(pair)
        await wazuh_rules_section(pair, holder)
        await logs_and_carbonblack_section(pair)
    finally:
        await py.aclose()
        await rs.aclose()
        await pair.rs.aclose()
        stop_rust(holder["rust"])
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
