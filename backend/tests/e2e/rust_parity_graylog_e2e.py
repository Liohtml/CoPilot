"""Parity of the Rust Graylog, InfluxDB, Grafana and Portainer connectors with this backend —
NOT collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts (no legacy backend,
connector cache off, so a connector row changed between checks is seen at once by both) answer
the same requests on one database. The tools themselves are local stand-ins that record every
request: Graylog with a 6.x and a 7.x personality, and the Event Shipper's GELF TCP input. For
each request the suite compares the status, the response **bytes**, and every request each
backend sent to the tool (method, target, the headers that matter, body bytes). urllib3 prints
an object's memory address in a connection error, which differs between any two processes; it
is masked. Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_graylog_e2e.py scripts/rust-parity.sh
"""

import asyncio
import copy
import datetime
import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs
from urllib.parse import urlsplit

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# Read at import by app.connectors.cache: every request re-reads the connector row, as the
# Rust instance below does.
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import connector_samples as samples  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
ADMIN, ANALYST, PORTAL = f"gl_admin{SFX}", f"gl_analyst{SFX}", f"gl_portal{SFX}"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
# Ports: the Rust instance and the stand-ins (5690-5695; 5696-5699 belong to the shared harness).
RS_PORT = int(os.environ.get("GRAYLOG_PARITY_RUST_PORT", "5695"))
GRAYLOG_PORT = int(os.environ.get("GRAYLOG_STUB_PORT", "5690"))
GELF_PORT = int(os.environ.get("GELF_STUB_PORT", "5694"))
CLOSED_PORT = 1
OUR_CONNECTORS = ("Graylog", "Event Shipper")
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(text(statement), params)


# --- The tool stand-ins ---------------------------------------------------------------------------


class Recorder:
    """What a stand-in was asked: (method, target, selected headers, body)."""

    HEADERS = ("authorization", "x-requested-by", "content-type", "content-length")

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, method, target, headers, body):
        kept = {k: headers.get(k) for k in self.HEADERS if headers.get(k) is not None}
        with self.lock:
            self.requests.append((method, target, kept, body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


def _json(value):
    return json.dumps(value).encode()


class Graylog:
    """Graylog 6.1 or 7.0, with per-test overrides."""

    def __init__(self):
        self.version = 6
        self.overrides = {}
        self.deleted_indices = set()
        self.delete_removes = True
        self.page_size = 500

    def reset(self, version=6):
        self.version = version
        self.overrides = {}
        self.deleted_indices = set()
        self.delete_removes = True
        self.page_size = 500

    def answer(self, method, target, body):
        parts = urlsplit(target)
        path, query = parts.path, parse_qs(parts.query)
        key = (method, path)
        if key in self.overrides:
            return self.overrides[key]
        not_found = (404, "application/json", _json({"type": "ApiError", "message": "HTTP 404 Not Found"}))
        if method == "GET" and path == "/api/system":
            return 200, "application/json", _json(samples.GRAYLOG_SYSTEM_7 if self.version == 7 else samples.GRAYLOG_SYSTEM_6)
        if method == "GET" and path == "/api/system/indexer/indices":
            data = copy.deepcopy(samples.GRAYLOG_INDICES)
            for name in self.deleted_indices:
                data["all"]["indices"].pop(name, None)
            return 200, "application/json", _json(data)
        if method == "DELETE" and path.startswith("/api/system/indexer/indices/"):
            if self.delete_removes:
                self.deleted_indices.add(path.rsplit("/", 1)[1])
            return 204, None, b""
        if method == "GET" and path == "/api/system/inputs":
            return 200, "application/json", _json(samples.graylog_inputs(self.version))
        if method == "GET" and path == "/api/system/inputstates":
            return 200, "application/json", _json(samples.graylog_input_states(self.version))
        if method in ("DELETE", "PUT") and path.startswith("/api/system/inputstates/"):
            return 200, "application/json", _json({"id": path.rsplit("/", 1)[1]})
        if method == "GET" and path == "/api/events/definitions":
            page = int(query.get("page", ["1"])[0])
            size = self.page_size
            defs = samples.GRAYLOG_EVENT_DEFINITIONS
            batch = defs[(page - 1) * size : page * size]
            return 200, "application/json", _json({"event_definitions": batch, "total": len(defs), "page": page, "per_page": size})
        if method == "POST" and path == "/api/events/search":
            return 200, "application/json", _json(samples.GRAYLOG_EVENTS_SEARCH)
        if method == "GET" and path == "/api/system/urlallowlist":
            return (200, "application/json", _json(samples.GRAYLOG_URL_ALLOWLIST)) if self.version == 7 else not_found
        if method == "GET" and path == "/api/system/urlwhitelist":
            return (200, "application/json", _json(samples.GRAYLOG_URL_ALLOWLIST)) if self.version == 6 else not_found
        if method == "POST" and re.fullmatch(r"/api/streams/[^/]+/(pause|resume)", path):
            return 204, None, b""
        if method == "GET" and path == "/api/system/messages":
            return 200, "application/json", _json(samples.GRAYLOG_MESSAGES)
        if method == "GET" and path == "/api/system/metrics":
            return 200, "application/json", _json(samples.GRAYLOG_METRICS)
        if method == "GET" and path == "/api/system/journal":
            return 200, "application/json", _json(samples.GRAYLOG_JOURNAL)
        if method == "GET" and path == "/api/events/notifications":
            return 200, "application/json", _json(samples.GRAYLOG_EVENT_NOTIFICATIONS)
        if method == "GET" and path == "/api/streams":
            return 200, "application/json", _json(samples.GRAYLOG_STREAMS)
        if method == "GET" and path == "/api/system/pipelines/pipeline":
            return 200, "application/json", _json(samples.GRAYLOG_PIPELINES)
        if method == "GET" and path == "/api/system/pipelines/rule":
            return 200, "application/json", _json(samples.GRAYLOG_PIPELINE_RULES)
        if method == "GET" and path.startswith("/api/system/pipelines/rule/"):
            rule_id = path.rsplit("/", 1)[1]
            for rule in samples.GRAYLOG_PIPELINE_RULES:
                if rule["id"] == rule_id:
                    return 200, "application/json", _json(rule)
            return 404, "application/json", _json({"type": "ApiError", "message": f"Couldn't find rule {rule_id}"})
        return not_found


GRAYLOG = Graylog()
RECORDER = Recorder()


def make_handler(tool, recorder):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            recorder.add(self.command, self.path, headers, body)
            status, ctype, payload = tool.answer(self.command, self.path, body)
            self.send_response_only(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _serve  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    return Handler


def start_http_stub(port, tool, recorder):
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(tool, recorder))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


GELF_FRAMES = []
GELF_LOCK = threading.Lock()


class _GelfHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.read()
        with GELF_LOCK:
            GELF_FRAMES.append(data)


def start_gelf_stub(port):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), _GelfHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def take_gelf(expected, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with GELF_LOCK:
            if len(GELF_FRAMES) >= expected:
                break
        time.sleep(0.02)
    time.sleep(0.05)
    with GELF_LOCK:
        out, GELF_FRAMES[:] = list(GELF_FRAMES), []
    return out


# --- Database ---------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, username=None, password=None, api_key=None, extra=None):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    if url is None:
        return
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) "
        "VALUES (:n, '3', :u, UTC_TIMESTAMP(), :un, :pw, :key, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 1, :x, 1)",
        n=name,
        u=url,
        un=username,
        pw=password,
        key=api_key,
        x=extra,
    )


def seed():
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(names=list(OUR_CONNECTORS)))
    SAVED_CONNECTORS.extend(dict(r._mapping) for r in rows)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    set_connector("Graylog", f"http://127.0.0.1:{GRAYLOG_PORT}", "admin", "pässword")
    set_connector("Event Shipper", "127.0.0.1", extra=str(GELF_PORT))


def cleanup():
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in (ADMIN, ANALYST, PORTAL):
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)


# --- The two backends -------------------------------------------------------------------------------


def build_python_app():
    # First, as in copilot.py's import order: `typing` caches `Dict[str, Union[...]]` by set
    # equality, so whichever module spells `Union[List[str], str]` first decides the member
    # order of AlertQuery.filter — and with it the order of its union errors in a 422.
    from app.connectors.graylog.schema import events  # noqa: F401
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import graylog

    api = APIRouter(prefix="/api")
    api.include_router(graylog.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
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
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{RS_PORT}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


ADDRESS = re.compile(rb"object at 0x[0-9a-f]+")


def normalize(body):
    return ADDRESS.sub(b"object at 0x...", body)


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        RECORDER.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, RECORDER.take()

    async def same(self, name, method, path, tok=None, before=None, outbound=True, concurrent=False, **kw):
        """Python, then Rust, with the stand-in reset by `before` for each.

        `concurrent`: the route sends its requests at once (`asyncio.gather`), so their order
        is not compared, and when both fail Python reports whichever failed first — the
        other request's error is accepted too (RUST_MIGRATION.md §4)."""
        if before:
            before()
        r1, out1 = await self.call(self.py, method, path, tok, **kw)
        if before:
            before()
        r2, out2 = await self.call(self.rs, method, path, tok, **kw)
        b1, b2 = normalize(r1.content), normalize(r2.content)
        ok = r1.status_code == r2.status_code and b1 == b2
        if concurrent and not ok and r1.status_code == r2.status_code:
            swapped = b1.replace(b"/journal", b"/__swap__").replace(b"/metrics", b"/journal").replace(b"/__swap__", b"/metrics")
            ok = swapped == b2
        detail = f"python {r1.status_code} {b1[:900]!r}\n        rust   {r2.status_code} {b2[:900]!r}"
        if outbound:
            o1 = [(m, t, h, normalize(b)) for m, t, h, b in out1]
            o2 = [(m, t, h, normalize(b)) for m, t, h, b in out2]
            if concurrent:
                o1, o2 = sorted(o1, key=repr), sorted(o2, key=repr)
            if o1 != o2:
                ok = False
                detail += f"\n        outbound python {o1}\n        outbound rust   {o2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- The checks -------------------------------------------------------------------------------------


async def graylog_checks(p, t_admin, t_analyst, t_portal):
    G = "/api/graylog"
    reads = [
        "/indices",
        "/inputs",
        "/inputs/running",
        "/inputs/configured",
        "/event/definitions",
        "/messages",
        "/metrics",
        "/event_notifications",
        "/streams",
        "/pipelines",
        "/pipeline/full",
        "/pipeline/rules",
        "/pipeline/rules/65a0000000000000000000e1",
    ]
    for version in (6, 7):
        print(f"\n=== Graylog {version}.x: reads ===")
        for path in reads:
            await p.same(
                f"GET {path} (Graylog {version})",
                "GET",
                G + path,
                t_analyst,
                before=lambda v=version: GRAYLOG.reset(v),
                concurrent=path == "/metrics",
            )
        await p.same(
            f"GET /url_whitelist (Graylog {version})",
            "GET",
            G + "/url_whitelist",
            t_admin,
            before=lambda v=version: GRAYLOG.reset(v),
        )

    print("\n=== Graylog: auth ===")
    for path in ("/indices", "/streams", "/pipeline/rules/x"):
        await p.same(f"GET {path}, no token", "GET", G + path)
        await p.same(f"GET {path}, bad token", "GET", G + path, "not-a-jwt")
        await p.same(f"GET {path}, portal user", "GET", G + path, t_portal)
    await p.same("GET /url_whitelist, analyst", "GET", G + "/url_whitelist", t_analyst)
    await p.same("GET /url_whitelist, no token", "GET", G + "/url_whitelist")
    await p.same("GET /url_whitelist, bad token", "GET", G + "/url_whitelist", "not-a-jwt")
    await p.same("POST /input/stop, analyst", "POST", G + "/input/stop", t_analyst, json={"input_id": "x"})
    await p.same("POST /receiver, analyst", "POST", G + "/receiver", t_analyst, json={"integration": "x", "customer_code": "c"})
    await p.same(
        "POST /event/alerts, malformed JSON, no token",
        "POST",
        G + "/event/alerts",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    print("\n=== Graylog: query and path parameters ===")
    for raw in ("2", " 3 ", "007", "1.0", "x", "", "1.5", "99999999999999999999"):
        await p.same(
            f"GET /messages?page_number={raw!r}",
            "GET",
            G + "/messages",
            t_analyst,
            params={"page_number": raw},
            before=GRAYLOG.reset,
        )
    await p.same("GET /pipeline/rules/{unknown}", "GET", G + "/pipeline/rules/nope", t_analyst, before=GRAYLOG.reset)
    await p.same("GET /pipeline/rules/{id with space}", "GET", G + "/pipeline/rules/a%20b", t_analyst, before=GRAYLOG.reset)
    await p.same("GET /pipeline/rules/{encoded slash}", "GET", G + "/pipeline/rules/a%2Fb", t_analyst, before=GRAYLOG.reset)

    print("\n=== Graylog: event search bodies ===")
    bodies = [
        {},
        {"query": "rule_level:>10", "page": 2, "per_page": "25", "filter": {"alerts": "include", "event_definitions": ["a"]}},
        {"timerange": {"range": 3600, "type": "relative"}},
        {"timerange": {"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z", "type": "absolute"}},
        {"query": None, "filter": None, "timerange": None},
        {"page": "x"},
        {"filter": {"alerts": 5}},
        {"timerange": {"range": 1.5}},
        [],
    ]
    for body in bodies:
        await p.same(f"POST /event/alerts {json.dumps(body)[:60]}", "POST", G + "/event/alerts", t_analyst, json=body, before=GRAYLOG.reset)
    await p.same("POST /event/alerts, no body", "POST", G + "/event/alerts", t_analyst, before=GRAYLOG.reset)
    await p.same(
        "POST /event/alerts, text body",
        "POST",
        G + "/event/alerts",
        t_analyst,
        content=b"{}",
        headers={"Content-Type": "text/plain"},
    )

    print("\n=== Graylog: management ===")
    await p.same(
        "DELETE /index (removed)",
        "DELETE",
        G + "/index",
        t_admin,
        json={"index_name": " wazuh-alerts-3x_1 "},
        before=GRAYLOG.reset,
    )

    def keeps():
        GRAYLOG.reset()
        GRAYLOG.delete_removes = False

    await p.same("DELETE /index (still there)", "DELETE", G + "/index", t_admin, json={"index_name": "gl-events_0"}, before=keeps)
    await p.same("DELETE /index (unknown)", "DELETE", G + "/index", t_admin, json={"index_name": "nope"}, before=GRAYLOG.reset)
    await p.same("DELETE /index (bad body)", "DELETE", G + "/index", t_admin, json={"index": 1}, before=GRAYLOG.reset)

    def delete_fails():
        GRAYLOG.reset()
        GRAYLOG.overrides[("DELETE", "/api/system/indexer/indices/gl-events_0")] = (
            400,
            "application/json",
            _json({"message": "Index is the write index"}),
        )

    await p.same(
        "DELETE /index (Graylog refuses)",
        "DELETE",
        G + "/index",
        t_admin,
        json={"index_name": "gl-events_0"},
        before=delete_fails,
    )
    for action in ("stop", "start"):
        await p.same(
            f"POST /input/{action}",
            "POST",
            f"{G}/input/{action}",
            t_admin,
            json={"input_id": "65a000000000000000000001 "},
            before=GRAYLOG.reset,
        )
        await p.same(
            f"POST /input/{action} (unknown)",
            "POST",
            f"{G}/input/{action}",
            t_admin,
            json={"input_id": "nope"},
            before=GRAYLOG.reset,
        )
        await p.same(
            f"POST /stream/{action}",
            "POST",
            f"{G}/stream/{action}",
            t_admin,
            json={"stream_id": "65a0000000000000000000a1"},
            before=GRAYLOG.reset,
        )
        await p.same(
            f"POST /stream/{action} (unknown)",
            "POST",
            f"{G}/stream/{action}",
            t_admin,
            json={"stream_id": "nope"},
            before=GRAYLOG.reset,
        )
        await p.same(f"POST /stream/{action} (no body)", "POST", f"{G}/stream/{action}", t_admin, before=GRAYLOG.reset)

    def input_errors():
        GRAYLOG.reset()
        GRAYLOG.overrides[("DELETE", "/api/system/inputstates/65a000000000000000000001")] = (500, "text/html", b"<html>boom</html>")
        GRAYLOG.overrides[("PUT", "/api/system/inputstates/65a000000000000000000001")] = (
            404,
            "application/json",
            _json({"message": "gone"}),
        )

    await p.same(
        "POST /input/stop (Graylog 500, not JSON)",
        "POST",
        G + "/input/stop",
        t_admin,
        json={"input_id": "65a000000000000000000001"},
        before=input_errors,
    )
    await p.same(
        "POST /input/start (Graylog 404)",
        "POST",
        G + "/input/start",
        t_admin,
        json={"input_id": "65a000000000000000000001"},
        before=input_errors,
    )

    def pause_fails():
        GRAYLOG.reset()
        GRAYLOG.overrides[("POST", "/api/streams/65a0000000000000000000a1/pause")] = (403, "application/json", _json({"message": ""}))
        GRAYLOG.overrides[("POST", "/api/streams/65a0000000000000000000a1/resume")] = (500, "application/json", _json([1]))

    await p.same(
        "POST /stream/stop (Graylog 403, empty message)",
        "POST",
        G + "/stream/stop",
        t_admin,
        json={"stream_id": "65a0000000000000000000a1"},
        before=pause_fails,
    )
    await p.same(
        "POST /stream/start (Graylog 500, a list)",
        "POST",
        G + "/stream/start",
        t_admin,
        json={"stream_id": "65a0000000000000000000a1"},
        before=pause_fails,
    )

    print("\n=== Graylog: what the tool answers ===")
    weird = [
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {"indices": [{"index_name": "x", **samples._index_info(1)}]}})),
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {}})),
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {"indices": "x"}})),
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {"indices": {"x": {"routing": []}}}})),
        ("GET", "/api/system/indexer/indices", 200, _json([])),
        ("GET", "/api/system/indexer/indices", 500, _json({"message": "OpenSearch down"})),
        ("GET", "/api/system/indexer/indices", 404, b"<html>not here</html>"),
        ("GET", "/api/system/indexer/indices", 404, _json({"nope": 1})),
        ("GET", "/api/system/indexer/indices", 200, b"not json"),
        ("GET", "/api/system/indexer/indices", 200, b""),
        ("GET", "/api/system/inputs", 200, _json({"inputs": [{"title": 5}]})),
        ("GET", "/api/system/inputs", 200, _json({"inputs": ["x"]})),
        ("GET", "/api/system/inputs", 200, _json({"inputs": {"a": 1}})),
        ("GET", "/api/system/inputs", 200, _json({})),
        ("GET", "/api/system/inputstates", 200, _json({"states": None})),
        ("GET", "/api/events/definitions", 200, _json({"event_definitions": [{"id": "x"}], "total": 1})),
        ("GET", "/api/events/definitions", 200, _json({"total": 1})),
        ("GET", "/api/events/definitions", 200, _json({"event_definitions": [], "total": "3"})),
        ("GET", "/api/events/definitions", 200, _json({"event_definitions": []})),
        ("GET", "/api/system/messages", 200, _json({"messages": [{"caller": "a"}], "total": 1})),
        ("GET", "/api/system/messages", 200, _json({"messages": ["x"], "total": 1})),
        ("GET", "/api/system/messages", 200, _json({"messages": [], "total": "many"})),
        ("GET", "/api/system/messages", 200, _json({"messages": []})),
        ("GET", "/api/system/metrics", 200, _json({"gauges": {}, "counters": []})),
        ("GET", "/api/system/metrics", 200, _json({"gauges": {"org.graylog2.throughput.input": 5}, "counters": {}})),
        ("GET", "/api/system/metrics", 200, _json({"gauges": {"org.graylog2.throughput.input": {"value": "x"}}, "counters": {}})),
        ("GET", "/api/system/metrics", 200, _json({"counters": {}})),
        ("GET", "/api/system/journal", 200, _json({})),
        ("GET", "/api/events/notifications", 200, _json({"total": 1})),
        ("GET", "/api/events/notifications", 200, _json(None)),
        ("GET", "/api/streams", 200, _json({"streams": [], "total": "two"})),
        ("GET", "/api/streams", 200, _json({"streams": ["x"], "total": 1})),
        ("GET", "/api/streams", 200, _json({"streams": [{"id": "x"}], "total": 1})),
        ("GET", "/api/streams", 200, _json({"total": 1})),
        ("GET", "/api/system/pipelines/pipeline", 200, _json({"a": 1})),
        ("GET", "/api/system/pipelines/pipeline", 200, _json([{"id": "x", "errors": "boom"}])),
        ("GET", "/api/system/pipelines/pipeline", 200, _json(None)),
        ("GET", "/api/system/pipelines/rule", 200, _json([{"title": "t"}])),
        ("GET", "/api/system/urlallowlist", 200, _json({"entries": [{}], "disabled": "maybe"})),
        ("GET", "/api/system/urlallowlist", 500, b"oops"),
    ]
    routes_for = {
        "/api/system/indexer/indices": ["/indices"],
        "/api/system/inputs": ["/inputs", "/inputs/configured"],
        "/api/system/inputstates": ["/inputs/running"],
        "/api/events/definitions": ["/event/definitions"],
        "/api/system/messages": ["/messages"],
        "/api/system/metrics": ["/metrics"],
        "/api/system/journal": ["/metrics"],
        "/api/events/notifications": ["/event_notifications"],
        "/api/streams": ["/streams"],
        "/api/system/pipelines/pipeline": ["/pipelines", "/pipeline/full"],
        "/api/system/pipelines/rule": ["/pipeline/rules", "/pipeline/full"],
        "/api/system/urlallowlist": ["/url_whitelist"],
    }
    for method, path, status, payload in weird:
        for route in routes_for[path]:

            def before(m=method, pa=path, s=status, b=payload):
                GRAYLOG.reset(7 if pa == "/api/system/urlallowlist" else 6)
                GRAYLOG.overrides[(m, pa)] = (s, "application/json" if b[:1] in (b"{", b"[", b"n") else "text/html", b)

            tok = t_admin if route == "/url_whitelist" else t_analyst
            await p.same(f"GET {route} ← {status} {payload[:50]!r}", "GET", G + route, tok, before=before, concurrent=route == "/metrics")

    def two_pages():
        GRAYLOG.reset()
        GRAYLOG.page_size = 2

    await p.same("GET /event/definitions over two pages", "GET", G + "/event/definitions", t_analyst, before=two_pages)

    def search(payload, status=200):
        def before():
            GRAYLOG.reset()
            GRAYLOG.overrides[("POST", "/api/events/search")] = (status, "application/json", payload)

        return before

    for payload, status in (
        (_json({**samples.GRAYLOG_EVENTS_SEARCH, "events": [{"index_name": "x"}]}), 200),
        (_json({**samples.GRAYLOG_EVENTS_SEARCH, "duration": "slow"}), 200),
        (_json({k: v for k, v in samples.GRAYLOG_EVENTS_SEARCH.items() if k != "context"}), 200),
        (_json({"message": "Search failed"}), 400),
        (b"", 204),
        (b"", 202),
        (b"not json", 200),
    ):
        await p.same(
            f"POST /event/alerts ← {status} {payload[:40]!r}",
            "POST",
            G + "/event/alerts",
            t_analyst,
            json={},
            before=search(payload, status),
        )

    print("\n=== Graylog: connector problems ===")
    for label, url, user in (
        ("connection refused", f"http://127.0.0.1:{CLOSED_PORT}", "admin"),
        ("no scheme", f"127.0.0.1:{GRAYLOG_PORT}", "admin"),
        ("empty URL", "", "admin"),
        ("no host", "http://", "admin"),
        ("bad port", "http://127.0.0.1:99999", "admin"),
        ("ftp", "ftp://127.0.0.1", "admin"),
        ("trailing slash", f"http://127.0.0.1:{GRAYLOG_PORT}/", None),
        ("non-latin-1 user", f"http://127.0.0.1:{GRAYLOG_PORT}", "€uro"),
    ):
        set_connector("Graylog", url, user, "pw")
        for route in ("/indices", "/streams", "/pipeline/rules/x"):
            await p.same(f"GET {route} ({label})", "GET", G + route, t_analyst, before=GRAYLOG.reset)
        await p.same(f"POST /event/alerts ({label})", "POST", G + "/event/alerts", t_analyst, json={}, before=GRAYLOG.reset)
        if label != "connection refused":
            await p.same(f"GET /metrics ({label})", "GET", G + "/metrics", t_analyst, before=GRAYLOG.reset, concurrent=True)
    set_connector("Graylog", None)
    for route in ("/indices", "/inputs", "/metrics", "/url_whitelist"):
        await p.same(f"GET {route} (no connector)", "GET", G + route, t_admin, before=GRAYLOG.reset, concurrent=route == "/metrics")
    await p.same("POST /input/stop (no connector)", "POST", G + "/input/stop", t_admin, json={"input_id": "x"})
    set_connector("Graylog", f"http://127.0.0.1:{GRAYLOG_PORT}", "admin", "pässword")

    print("\n=== Event Shipper (/receiver) ===")
    payloads = [
        {"integration": "mimecast", "customer_code": "acme", "message": "hello", "n": None, "nested": {"a": None, "é": [1, 2.5]}},
        {"integration": "x", "customer_code": "y"},
    ]
    for payload in payloads:
        GELF_FRAMES.clear()
        r1, _ = await p.call(p.py, "POST", G + "/receiver", t_admin, json=payload)
        f1 = take_gelf(1)
        r2, _ = await p.call(p.rs, "POST", G + "/receiver", t_admin, json=payload)
        f2 = take_gelf(1)
        check(
            f"POST /receiver {json.dumps(payload)[:50]} [{r1.status_code}]",
            (r1.status_code, r1.content, f1) == (r2.status_code, r2.content, f2),
            f"python {r1.status_code} {r1.content!r} {f1}\n        rust   {r2.status_code} {r2.content!r} {f2}",
        )
    for body in ({"integration": "x"}, {"integration": 1, "customer_code": None}, [], "x"):
        await p.same(f"POST /receiver {json.dumps(body)}", "POST", G + "/receiver", t_admin, json=body, outbound=False)
    await p.same("POST /receiver, no body", "POST", G + "/receiver", t_admin, outbound=False)
    set_connector("Event Shipper", "127.0.0.1", extra=str(CLOSED_PORT))
    await p.same("POST /receiver (shipper unreachable)", "POST", G + "/receiver", t_admin, json=payloads[1], outbound=False)
    set_connector("Event Shipper", None)
    await p.same("POST /receiver (no shipper connector)", "POST", G + "/receiver", t_admin, json=payloads[1], outbound=False)
    set_connector("Event Shipper", "127.0.0.1", extra=str(GELF_PORT))


async def main():
    graylog_server = start_http_stub(GRAYLOG_PORT, GRAYLOG, RECORDER)
    gelf_server = start_gelf_stub(GELF_PORT)
    seed()
    proc = start_rust()
    p = Pair()
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    try:
        await graylog_checks(p, t_admin, t_analyst, t_portal)
    finally:
        await p.close()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        graylog_server.shutdown()
        gelf_server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
