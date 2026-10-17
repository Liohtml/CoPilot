"""Parity of the Rust Grafana dashboard, network-connector and integration provisioning
(`copilot-grafana-dashboards`, `copilot-integration-provisioning`) with this backend — NOT collected
by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process) and Rust instances this suite starts answer the same requests
on one database: `POST /api/grafana/dashboards`, `POST /api/customer_provisioning/provision/dashboards`,
the Fortinet / SonicWall / SentinelOne stack provisioning and the integrations' `/provision` routes.
One Rust instance meets Graylog 6, a second Graylog 7 (both backends cache the version, Python's is
pinned to the instance in use); the Rust instances' legacy backend is the same routers served by
uvicorn in a subprocess, which registers the APScheduler jobs the integration routes add (Rust hands
that step to Python). The tools are local stand-ins recording every request — method, target, every
header the client sent and the body bytes (a dashboard is compared as it was sent, never
re-serialised): Graylog and Graylog-Network (`/graylog`, `/graylog-net`), Grafana (`/grafanaapi`,
the root `grafana_client` builds from a connector URL ending in `/grafana`) on one port, the Wazuh
indexer on another. For each request the suite compares the status, the body, every outbound request
and the rows the request left. Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_grafana_provisioning_e2e.py scripts/rust-parity.sh

Ports (all overridable): GRAFANA_PROV_PARITY_RUST_PORT (6420), GRAFANA_PROV_PARITY_RUST7_PORT (6421),
GRAFANA_PROV_PARITY_PY_PORT (6422, the uvicorn legacy backend), GRAFANA_PROV_STUB_PORT (6423, Graylog
and Grafana), GRAFANA_PROV_INDEXER_STUB_PORT (6424), GRAFANA_PROV_CLOSED_PORT (6425, nothing listens).
Seeded ids are seven digits in 7650000-7659999. `GRAFANA_PROV_PARITY_SECTIONS=dashboards,network,
integrations` picks the sections.
"""

import asyncio
import copy
import datetime
import fnmatch
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(BACKEND, ".."))
sys.path.insert(0, HERE)

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import bindparam  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = os.environ.get("GRAFANA_PROV_PARITY_SFX") or uuid.uuid4().hex[:6]
RS_PORT = int(os.environ.get("GRAFANA_PROV_PARITY_RUST_PORT", "6420"))
RS7_PORT = int(os.environ.get("GRAFANA_PROV_PARITY_RUST7_PORT", "6421"))
PY_PORT = int(os.environ.get("GRAFANA_PROV_PARITY_PY_PORT", "6422"))
STUB_PORT = int(os.environ.get("GRAFANA_PROV_STUB_PORT", "6423"))
INDEXER_PORT = int(os.environ.get("GRAFANA_PROV_INDEXER_STUB_PORT", "6424"))
CLOSED_PORT = int(os.environ.get("GRAFANA_PROV_CLOSED_PORT", "6425"))
SEED_LO, SEED_HI = 7_650_000, 7_659_999

CUST_A, CUST_B, CUST_C = f"GPA{SFX}", f"GPB{SFX}", f"GPC{SFX}"
CUSTOMERS = (CUST_A, CUST_B, CUST_C)
NAME_A, NAME_B, NAME_C = f"Alpha {SFX}", f"Beta {SFX}", f"Gamma {SFX}"
ADMIN, ANALYST, ANALYST_B, UNASSIGNED = (f"gp_admin{SFX}", f"gp_analyst{SFX}", f"gp_analyst_b{SFX}", f"gp_unassigned{SFX}")
USERS = (ADMIN, ANALYST, ANALYST_B, UNASSIGNED)
OUR_CONNECTORS = ("Graylog", "Graylog-Network", "Grafana", "Wazuh-Indexer")
GRAFANA_URL = f"http://127.0.0.1:{STUB_PORT}/grafana"
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def _bind(statement, params):
    stmt = text(statement)
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    return stmt


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(_bind(statement, params), params)


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(_bind(statement, params), params)]


def _json(value):
    return json.dumps(value).encode()


# --- The stand-ins ------------------------------------------------------------------------------------


class Grafana:
    """Grafana 11 for provisioning: the org switch, datasources, folders, dashboards. Per-test
    overrides by (method, path glob): one answer, or a list answered in turn (the last repeated)."""

    def __init__(self):
        self.reset()

    def reset(self, overrides=None):
        self.overrides = copy.deepcopy(overrides or {})
        self.counter = 0

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix("/grafanaapi")
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(path, pattern):
                if isinstance(reply, list):
                    return reply.pop(0) if len(reply) > 1 else reply[0]
                return reply
        j = "application/json"
        if method == "POST" and re.fullmatch(r"/user/using/[^/]+", path):
            return 200, j, _json({"message": "Active organization changed"})
        if method == "POST" and path == "/dashboards/db":
            self.counter += 1
            title = json.loads(body).get("dashboard", {}).get("title", "x")
            slug = re.sub(r"[^a-z0-9]+", "-", str(title).lower()).strip("-")
            return (
                200,
                j,
                _json(
                    {
                        "id": 500 + self.counter,
                        "slug": slug,
                        "status": "success",
                        "uid": f"uid{self.counter}",
                        "url": f"/d/uid{self.counter}/{slug}",
                        "version": 1,
                        "folderUid": "fold",
                    },
                ),
            )
        if method == "POST" and path == "/folders":
            data = json.loads(body)
            return (
                200,
                j,
                _json(
                    {
                        "id": 77,
                        "uid": "fold-77",
                        "orgId": 7,
                        "title": data.get("title"),
                        "url": "/dashboards/f/fold-77/",
                        "hasAcl": False,
                        "canSave": True,
                        "canEdit": True,
                        "canAdmin": True,
                        "canDelete": True,
                        "createdBy": "admin",
                        "created": "2026-10-16T00:00:00Z",
                        "updatedBy": "admin",
                        "updated": "2026-10-16T00:00:00Z",
                        "version": 1,
                    },
                ),
            )
        if method == "POST" and path == "/datasources":
            data = json.loads(body)
            ds = {
                "id": 9,
                "uid": "ds-uid-9",
                "orgId": 7,
                "name": data.get("name"),
                "type": data.get("type"),
                "typeLogoUrl": "public/plugins/grafana-opensearch-datasource/img/logo.svg",
                "access": data.get("access"),
                "url": data.get("url"),
                "user": "",
                "database": data.get("database"),
                "basicAuth": data.get("basicAuth"),
                "basicAuthUser": data.get("basicAuthUser"),
                "withCredentials": False,
                "isDefault": data.get("isDefault"),
                "jsonData": data.get("jsonData"),
                "secureJsonFields": {"basicAuthPassword": True},
                "version": 1,
                "readOnly": data.get("readOnly"),
            }
            return 200, j, _json({"datasource": ds, "id": 9, "message": "Datasource added", "name": data.get("name")})
        return 404, j, _json({"message": "Not found"})


class Recorder:
    """Every request a stand-in was sent: (method, target, every header sorted, body)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, method, target, headers, body):
        with self.lock:
            self.requests.append((method, target, headers, body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


GRAFANA = Grafana()
RECORDER = Recorder()


class ByPrefix:
    def __init__(self, routes):
        self.routes = routes

    def answer(self, method, target, body):
        for prefix, tool in self.routes:
            if target.startswith(prefix):
                return tool.answer(method, target, body)
        return 404, "application/json", _json({"message": "no such stand-in route"})


TOOLS = ByPrefix((("/grafanaapi", GRAFANA),))


def start_stub(port, tool):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            # Every header the client sent, Content-Length included.
            headers = sorted((k.lower(), v) for k, v in self.headers.items())
            RECORDER.add(self.command, self.path, headers, body)
            status, ctype, payload = tool.answer(self.command, self.path, body)
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- Seed --------------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, username="parity-user", password="pässword"):
    """Point connector `name` at `url`, keeping its id when it exists."""
    found = rows("SELECT id FROM connectors WHERE connector_name = :n ORDER BY id LIMIT 1", n=name)
    if found:
        sql(
            "UPDATE connectors SET connector_url = :u, connector_username = :user, connector_password = :pw WHERE id = :i",
            u=url,
            user=username,
            pw=password,
            i=found[0]["id"],
        )
        return
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (:n, '3', :u, "
        "UTC_TIMESTAMP(), :user, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
    )


def save_connectors():
    SAVED_CONNECTORS.extend(rows("SELECT * FROM connectors WHERE connector_name IN :n OR id = 1", n=list(OUR_CONNECTORS)))


def restore_connectors():
    ids = [r["id"] for r in SAVED_CONNECTORS]
    sql("DELETE FROM connectors WHERE connector_name IN :n OR id = 1", n=list(OUR_CONNECTORS))
    for row in SAVED_CONNECTORS:
        sql(f"INSERT INTO connectors ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    del ids


def seed():
    cleanup()
    save_connectors()
    set_connector("Grafana", GRAFANA_URL)
    for code, name in ((CUST_A, NAME_A), (CUST_B, NAME_B), (CUST_C, NAME_C)):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (ANALYST_B, 2), (UNASSIGNED, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name, code in ((ANALYST, CUST_A), (ANALYST_B, CUST_B)):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=code,
            n=name,
        )


def cleanup():
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for code in CUSTOMERS:
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)


# --- The backends ------------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import customer_provisioning
    from app.routers import grafana

    api = APIRouter(prefix="/api")
    api.include_router(grafana.router)
    api.include_router(customer_provisioning.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def wait_port(port, proc):
    for _ in range(150):
        if proc.poll() is not None:
            raise RuntimeError(f"the process for port {port} exited")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"nothing listens on {port}")


def start_rust(port):
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
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}",
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
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
    raise RuntimeError("the Rust instance did not start")


ADDRESS = re.compile(rb"object at 0x[0-9a-f]+")


def norm_body(raw):
    return ADDRESS.sub(b"object at 0x...", raw)


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)
        self.rs7 = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS7_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        RECORDER.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, RECORDER.take()

    async def same(self, name, method, path, tok=None, before=None, state=None, expect=None, rust=None, **kw):
        """Python, then Rust, each after `before()`; `state()` returns what the request left.
        `expect=(python, rust)`: the statuses of a deliberate difference (bodies not compared)."""
        sides = []
        for client in (self.py, rust or self.rs):
            if before:
                before()
            r, out = await self.call(client, method, path, tok, **kw)
            sides.append((r, out, state() if state else None))
        (r1, o1, s1), (r2, o2, s2) = sides
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2
        b1, b2 = norm_body(r1.content), norm_body(r2.content)
        ok = r1.status_code == r2.status_code and b1 == b2
        at = next((i for i, (x, y) in enumerate(zip(b1, b2)) if x != y), min(len(b1), len(b2)))
        start = max(0, at - 300)
        detail = (
            f"bodies differ at byte {at}\n        python {r1.status_code} {b1[start : at + 600]!r}\n"
            f"        rust   {r2.status_code} {b2[start : at + 600]!r}"
        )
        if o1 != o2:
            ok = False
            for i, (x, y) in enumerate(zip(o1, o2)):
                if x != y:
                    detail += f"\n        outbound #{i} python {x[:3]} {x[3][:400]!r}\n        outbound #{i} rust   {y[:3]} {y[3][:400]!r}"
                    break
            else:
                detail += f"\n        outbound python {[o[:2] for o in o1]}\n        outbound rust   {[o[:2] for o in o2]}"
        if s1 != s2:
            ok = False
            detail += f"\n        state python {s1}\n        state rust   {s2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {[(m, p, b[:200]) for m, p, h, b in o1]}")
        return r1, r2

    async def close(self):
        for c in (self.py, self.rs, self.rs7):
            await c.aclose()


# --- Dashboards ----------------------------------------------------------------------------------------

DASH = "/api/grafana/dashboards"
CPDASH = "/api/customer_provisioning/provision/dashboards"


def grafana(overrides=None):
    return lambda: GRAFANA.reset(overrides)


async def dashboard_checks(p, t_admin, t_analyst, t_unassigned):
    ok = grafana()
    await p.same("dashboards: no token", "POST", DASH, json={"dashboards": []})
    await p.same("dashboards: malformed JSON, no token", "POST", DASH, content=b"{", headers={"Content-Type": "application/json"})
    await p.same("dashboards: no body", "POST", DASH, t_admin)
    await p.same("dashboards: a list body", "POST", DASH, t_admin, json=[])
    await p.same("dashboards: not JSON", "POST", DASH, t_admin, content=b"x=1", headers={"Content-Type": "text/plain"})
    await p.same("dashboards: unknown name", "POST", DASH, t_admin, json={"dashboards": ["WAZUH_SUMMARY", "NOPE"]})
    await p.same("dashboards: commented-out member", "POST", DASH, t_admin, json={"dashboards": ["EDR_WAZUH_INVENOTRY"]})
    await p.same(
        "dashboards: bad fields",
        "POST",
        DASH,
        t_admin,
        json={"dashboards": [1], "organizationId": "x", "folderId": 1.5, "datasourceUid": 5, "grafana_url": None},
    )
    await p.same("dashboards: empty list asks nothing", "POST", DASH, t_analyst, before=ok, json={"dashboards": []})
    await p.same(
        "dashboards: defaults (org 0, folder 0, the template URL)",
        "POST",
        DASH,
        t_admin,
        before=ok,
        json={"dashboards": ["HUNTRESS_SUMMARY"]},
    )
    await p.same(
        "dashboards: several, the datasource and URL replaced",
        "POST",
        DASH,
        t_unassigned,
        before=ok,
        json={
            "dashboards": ["WAZUH_SUMMARY", "OFFICE365_SUMMARY", "SONICWALL_VPN", "WAZUH_SUMMARY", "MIMECAST_SUMMARY"],
            "organizationId": "44",
            "folderId": 7.0,
            "datasourceUid": 'ds-ü"\\x',
            "grafana_url": "https://grafana.company.local/sub",
        },
    )
    await p.same(
        "dashboards: every Fortinet and SentinelOne dashboard",
        "POST",
        DASH,
        t_admin,
        before=ok,
        json={
            "dashboards": [
                "FORTINET_SYSTEM_LOGS",
                "FORTINET_UTM_ANOMALIES",
                "FOTINET_UTM_DLP",
                "FORTINET_VPN",
                "SENTINELONE_EPP_SUMMARY",
                "SENTINELONE_EPP_MALWARE",
                "EDR_AGENT_INVENTORY",
                "EDR_OPEN_AUDIT",
            ],
            "organizationId": 100000000000000000000,
            "folderId": -3,
            "grafana_url": "http://g:3000",
        },
    )
    body = {"dashboards": ["DUO_AUTH", "CATO_SUMMARY"], "organizationId": 7, "folderId": 3}
    await p.same(
        "dashboards: the switch refused",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/user/using/*"): (404, "application/json", _json({"message": "User not found"}))}),
        json=body,
    )
    await p.same(
        "dashboards: the second upload refused (the first stays)",
        "POST",
        DASH,
        t_admin,
        before=grafana(
            {
                ("POST", "/dashboards/db"): [
                    (200, "application/json", _json({"id": 1, "slug": "s", "status": "success", "uid": "u", "url": "/d/u", "version": 1})),
                    (412, "application/json", _json({"message": "version-mismatch", "status": "version-mismatch"})),
                ],
            },
        ),
        json=body,
    )
    await p.same(
        "dashboards: Grafana 400",
        "POST",
        DASH,
        t_admin,
        before=grafana(
            {("POST", "/dashboards/db"): (400, "application/json", _json({"message": "Dashboard title cannot be empty", "x": [1]}))},
        ),
        json=body,
    )
    await p.same(
        "dashboards: Grafana 401",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (401, "application/json", _json({"message": "Unauthorized"}))}),
        json=body,
    )
    await p.same(
        "dashboards: Grafana 500 text",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (500, "text/html", b"<h1>boom</h1>")}),
        json=body,
    )
    await p.same(
        "dashboards: an answer missing fields (the model's 400)",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (200, "application/json", _json({"id": 1, "uid": 5}))}),
        json=body,
    )
    await p.same(
        "dashboards: a text answer (the TypeError's 500)",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (200, "text/plain", b"ok")}),
        json=body,
    )
    await p.same(
        "dashboards: a 204 answer",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (204, None, b"")}),
        json=body,
    )
    await p.same(
        "dashboards: an answer that is not JSON",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (200, "application/json", b"{nope")}),
        json=body,
    )

    def grafana_down():
        GRAFANA.reset()
        set_connector("Grafana", f"http://127.0.0.1:{CLOSED_PORT}")

    def grafana_back():
        GRAFANA.reset()
        set_connector("Grafana", GRAFANA_URL)

    await p.same("dashboards: Grafana unreachable", "POST", DASH, t_admin, before=grafana_down, json=body)

    def grafana_gone():
        GRAFANA.reset()
        sql("DELETE FROM connectors WHERE connector_name = 'Grafana'")

    await p.same("dashboards: no Grafana connector", "POST", DASH, t_admin, before=grafana_gone, json=body)

    def grafana_bad_url():
        GRAFANA.reset()
        set_connector("Grafana", "grafana.local:3000")

    await p.same("dashboards: a connector URL without a scheme", "POST", DASH, t_admin, before=grafana_bad_url, json=body)
    grafana_back()

    full = {
        "customer_name": "Acme",
        "dashboards_to_include": {"dashboards": ["HUNTRESS_SUMMARY", "CROWDSTRIKE_SUMMARY"], "organizationId": 99, "folderId": 98},
        "grafana_org_id": 7,
        "grafana_datasource_uid": "ds-2",
        "grafana_folder_id": 3,
        "grafana_url": "https://grafana.example.com",
    }
    await p.same("customer dashboards: no token", "POST", CPDASH, json=full)
    await p.same("customer dashboards: provisioned", "POST", CPDASH, t_analyst, before=ok, json=full)
    await p.same(
        "customer dashboards: missing fields",
        "POST",
        CPDASH,
        t_admin,
        json={"dashboards_to_include": {"dashboards": ["DUO_AUTH"]}},
    )
    await p.same(
        "customer dashboards: unknown dashboard and a bad org",
        "POST",
        CPDASH,
        t_admin,
        json={**full, "dashboards_to_include": {"dashboards": ["NOPE"]}, "grafana_org_id": "x"},
    )
    await p.same("customer dashboards: nested not an object", "POST", CPDASH, t_admin, json={**full, "dashboards_to_include": []})
    await p.same(
        "customer dashboards: Grafana refuses",
        "POST",
        CPDASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (403, "application/json", _json({"message": "Permission denied"}))}),
        json=full,
    )
    # The GET of the same path stays the customer router's.
    await p.same("customer dashboards: the GET list", "GET", CPDASH, t_admin)


async def main():
    servers = [start_stub(STUB_PORT, TOOLS)]
    procs = []
    try:
        seed()
        procs.append(start_rust(RS_PORT))
        procs.append(start_rust(RS7_PORT))
        p = Pair()
        t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
        t_unassigned = token(UNASSIGNED, ["analyst"])
        try:
            sections = os.environ.get("GRAFANA_PROV_PARITY_SECTIONS", "dashboards,network,integrations").split(",")
            if "dashboards" in sections:
                await dashboard_checks(p, t_admin, t_analyst, t_unassigned)
        finally:
            await p.close()
            from app.db.db_session import async_engine

            await async_engine.dispose()
    finally:
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            cleanup()
        finally:
            restore_connectors()
            for server in servers:
                server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
