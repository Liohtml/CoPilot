"""Parity of the Rust response routes (`crates/copilot-response`) and the Shuffle connector
(`crates/copilot-shuffle`) with this backend — NOT collected by pytest (needs a live MySQL and the
Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process) and the Rust instances this suite starts (no legacy backend,
connector cache off) answer the same requests on one database. Every tool is a local stand-in that
records each request it receives — method, target, **every header** (Content-Length included) and
the body bytes — and both backends' requests are compared one by one:

* the Wazuh manager (token flow, `PUT /active-response`);

For each request the suite compares the status, the response bytes and the outbound requests.
urllib3 prints an object's memory address in a connection error, which differs between any two
processes; it is masked. Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_response_e2e.py scripts/rust-parity.sh

Ports (all overridable): RESPONSE_PARITY_RUST_PORT and RESPONSE_PARITY_RUST_BARE_PORT (a second
Rust instance without GRAYLOG_API_HEADER_VALUE / COPILOT_API_KEY), RESPONSE_MANAGER_STUB_PORT.
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
# Read at import by app.connectors.cache: every request re-reads the connector row, as the Rust
# instances below do.
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
GRAYLOG_HEADER = "parity-response-graylog-header"
os.environ["GRAYLOG_API_HEADER_VALUE"] = GRAYLOG_HEADER

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("RESPONSE_PARITY_RUST_PORT", "5787"))
RS_BARE_PORT = int(os.environ.get("RESPONSE_PARITY_RUST_BARE_PORT", "5788"))
MANAGER_PORT = int(os.environ.get("RESPONSE_MANAGER_STUB_PORT", "5789"))
CLOSED_PORT = 1
OUR_CONNECTORS = ("Wazuh-Manager",)
CUST_A, CUST_B = f"RsA{SFX}", f"RsB{SFX}"
ADMIN, ANALYST, PORTAL, RESP = f"rs_admin{SFX}", f"rs_analyst{SFX}", f"rs_portal{SFX}", f"rs_resp{SFX}"
USERS = (ADMIN, ANALYST, PORTAL, RESP)
#: Explicit agent row ids (7 digits, this suite's range).
AGENT_ID_BASE = 7_640_000
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
    """What a stand-in was asked: (method, target, every header, body). Header names are
    lower-cased and sorted (the two HTTP stacks write them in different orders); none is
    dropped."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, method, target, headers, body):
        kept = sorted((k.lower(), v) for k, v in headers.items())
        with self.lock:
            self.requests.append((method, target, kept, body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


def start_http_stub(port, answer, recorder):
    """A threaded HTTP/1.1 server; `answer(method, target, headers, body)` returns
    (status, content_type, body bytes)."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            recorder.add(self.command, self.path, self.headers, body)
            status, ctype, payload = answer(self.command, self.path, self.headers, body)
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Manager:
    """The Wazuh manager: the token flow, and `PUT /active-response` answered per `mode`."""

    def __init__(self):
        self.mode = "ok"

    def __call__(self, method, target, headers, body):
        if target.startswith("/security/user/authenticate"):
            return 200, "application/json", json.dumps({"data": {"token": "parity-token"}, "error": 0}).encode()
        if method == "PUT" and target.startswith("/active-response"):
            if self.mode == "ok":
                return 200, "application/json", json.dumps({"data": {"affected_items": ["001"]}, "error": 0}).encode()
            if self.mode == "detail":
                return 400, "application/json", json.dumps({"title": "Bad Request", "detail": "bad agents_list"}).encode()
            if self.mode == "message":
                return 500, "application/json", json.dumps({"message": {"why": ["down"]}}).encode()
            if self.mode == "data-detail":
                return 404, "application/json", json.dumps({"data": {"detail": "no such agent"}}).encode()
            if self.mode == "text":
                return 503, "text/plain", b"upstream unavailable"
            if self.mode == "empty-detail":
                return 400, "application/json", json.dumps({"detail": ""}).encode()
            if self.mode == "not-json":
                return 200, "text/html", b"<html>ok</html>"
        return 404, "application/json", b'{"detail": "not found"}'


MANAGER = Manager()
MANAGER_RECORDER = Recorder()
RECORDERS = [MANAGER_RECORDER]


# --- Database -------------------------------------------------------------------------------------

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


AGENTS = [
    # (row offset, agent_id, hostname, os, customer)
    (0, f"a{SFX}w", f"win-a-{SFX}", "Microsoft Windows 11 Pro", CUST_A),
    (1, f"a{SFX}l", f"lin-a-{SFX}", "Ubuntu 24.04 LTS", CUST_A),
    (2, f"a{SFX}n", f"nos-a-{SFX}", "", CUST_A),
    (3, f"b{SFX}w", f"win-b-{SFX}", "Microsoft Windows Server 2022", CUST_B),
]
AGENT_A_WIN, AGENT_A_LIN, AGENT_A_NOOS, AGENT_B_WIN = (a[1] for a in AGENTS)


def seed():
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(names=list(OUR_CONNECTORS)))
    SAVED_CONNECTORS.extend(dict(r._mapping) for r in rows)
    for code in (CUST_A, CUST_B):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())", c=code)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (RESP, 5)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name in (ANALYST, PORTAL, RESP):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
            "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )
    for offset, agent_id, hostname, os_name, customer in AGENTS:
        sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
            "velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, velociraptor_agent_version, "
            "customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) VALUES (:id, :a, '10.0.0.1', :os, :h, "
            "'grp', 0, '2026-10-15 08:00:00', NULL, NULL, 'Wazuh v4.9.0', 'active', NULL, :c, 0, NULL, 0)",
            id=AGENT_ID_BASE + offset,
            a=agent_id,
            os=os_name,
            h=hostname,
            c=customer,
        )
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")


def cleanup():
    sql("DELETE FROM agents WHERE id BETWEEN :lo AND :hi", lo=AGENT_ID_BASE, hi=AGENT_ID_BASE + 9999)
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM audit_log WHERE actor_username = :n", n=name)
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for code in (CUST_A, CUST_B):
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)


# --- The two backends -----------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import active_response

    api = APIRouter(prefix="/api")
    api.include_router(active_response.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port, bare=False):
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        "COPILOT_PORT": str(port),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    if not bare:
        env["GRAYLOG_API_HEADER_VALUE"] = GRAYLOG_HEADER
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


def normalize(body):
    return ADDRESS.sub(b"object at 0x...", body)


def reset_python_caches():
    """Forget the manager token Python caches per process (the Rust instance keys its own by the
    connector row, which the checks below never change while a token is held)."""
    from app.connectors.wazuh_manager.utils import universal

    universal._token_cache._cache.clear()


class Pair:
    def __init__(self, rust_port):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{rust_port}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        for recorder in RECORDERS:
            recorder.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, [request for recorder in RECORDERS for request in recorder.take()]

    async def same(self, name, method, path, tok=None, before=None, outbound=True, expect=None, **kw):
        """Python, then Rust, with the stand-ins reset by `before` for each. `expect` is a
        status both must answer."""
        if before:
            before()
        r1, out1 = await self.call(self.py, method, path, tok, **kw)
        if before:
            before()
        r2, out2 = await self.call(self.rs, method, path, tok, **kw)
        b1, b2 = normalize(r1.content), normalize(r2.content)
        ok = r1.status_code == r2.status_code and b1 == b2
        if expect is not None and r1.status_code != expect:
            ok = False
        detail = f"python {r1.status_code} {b1[:900]!r}\n        rust   {r2.status_code} {b2[:900]!r}"
        if outbound:
            o1 = [(m, t, h, normalize(b)) for m, t, h, b in out1]
            o2 = [(m, t, h, normalize(b)) for m, t, h, b in out2]
            if o1 != o2:
                ok = False
                detail += f"\n        outbound python {o1}\n        outbound rust   {o2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:400]!r}\n        outbound {[(m, t, b[:300]) for m, t, h, b in out1]}")
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- Active response ------------------------------------------------------------------------------


def mode(m):
    def set_mode():
        MANAGER.mode = m

    return set_mode


def firewall(agents=..., **extra):
    body = {"command": "windows_firewall", "alert": {"action": "block", "ip": "1.1.1.1"}, "params": {"wait_for_complete": True}}
    if agents is not ...:
        body["params"]["agents_list"] = agents
    body.update(extra)
    return body


INVALID_BODIES = [
    {"command": "nope", "alert": {}, "params": {}},
    {"command": True, "alert": {}, "params": {}},
    {"command": [1], "alert": {}, "params": {}},
    {"command": {"a": 1.5}, "alert": {}, "params": {}},
    {"command": 1.0, "alert": {}, "params": {}},
    {"command": "", "alert": {}, "params": {}},
    {"alert": {}, "params": {}},
    {"command": None, "alert": 5, "params": {"wait_for_complete": True}},
    {"command": "windows_firewall", "alert": [], "params": {}},
    {"command": "windows_firewall", "alert": 5, "params": {}},
    {"command": "nope", "alert": 5},
    {"command": "windows_firewall", "alert": {"action": "block", "ip": "x"}, "params": {}},
    {"command": "windows_firewall", "alert": {"action": "nuke"}, "params": {}},
    {"command": "linux_firewall", "alert": {"action": "BLOCK", "ip": 5}, "params": {}},
    {"command": "linux_firewall", "alert": {"action": "block", "ip": "1.1.1.01"}, "params": {}},
    {"command": "windows_firewall", "alert": {"action": "block", "ip": None}, "params": {}},
    {"command": "sysmon_config_reload", "alert": {"action": "block"}, "params": {}},
    {"command": "sysmon_config_reload", "alert": {"action": None}, "params": {}},
    {
        "command": "linux_firewall",
        "alert": {"action": "unblock", "ip": "::1"},
        "params": {"wait_for_complete": True},
        "custom": False,
        "endpoint": "/x",
        "arguments": [1],
    },
    {"command": "linux_firewall", "alert": {"action": "unblock", "ip": "::1"}, "params": {"wait_for_complete": True}, "custom": "true"},
    {"command": "sysmon_config_reload", "alert": {}, "params": "x"},
    {"command": "sysmon_config_reload", "alert": {}, "params": {"agents_list": "001"}},
    {"command": "sysmon_config_reload", "alert": {}, "params": {"wait_for_complete": "maybe", "agents_list": [1, "a", None]}},
    {"command": "sysmon_config_reload", "alert": {}, "params": {"wait_for_complete": True}, "arguments": "x"},
    [],
    "str",
]

VALID_BODIES = [
    firewall([AGENT_A_WIN]),
    {
        "command": "WINDOWS_FIREWALL",
        "alert": {"action": "block", "ip": " 1.1.1.1 ", "x": 1},
        "params": {"wait_for_complete": "yes", "agents_list": [AGENT_A_WIN]},
    },
    {"command": "Sysmon_Config_Reload", "alert": {}, "params": {"wait_for_complete": 1, "agents_list": [AGENT_A_WIN, AGENT_A_LIN]}},
    {
        "command": "linux_firewall",
        "alert": {"action": "unblock", "ip": "fe80::1%eth0"},
        "custom": 1.0,
        "params": {"wait_for_complete": False, "agents_list": [AGENT_A_LIN]},
        "arguments": ["a", "ü"],
        "endpoint": "/active-response",
    },
    {
        "command": "windows_firewall",
        "alert": {"action": "sysmon_config_reload", "ip": "10.0.0.1"},
        "params": {"wait_for_complete": True, "agents_list": [AGENT_A_WIN]},
    },
]


async def active_response_checks(p, t_admin, t_analyst, t_portal, t_resp):
    A = "/api/active_response"
    print("\n=== Active response: auth ===")
    for method, path, body in (
        ("GET", "/supported", None),
        ("GET", f"/supported/{AGENT_A_WIN}", None),
        ("GET", "/describe/windows_firewall", None),
        ("POST", "/invoke", firewall([AGENT_A_WIN])),
    ):
        kw = {"json": body} if body is not None else {}
        await p.same(f"{method} {path}, no token", method, A + path, **kw)
        await p.same(f"{method} {path}, bad token", method, A + path, "not-a-jwt", **kw)
        await p.same(f"{method} {path}, portal user", method, A + path, t_portal, **kw)
        await p.same(f"{method} {path}, ghost user", method, A + path, token(f"ghost{SFX}", ["admin"]), **kw)
    await p.same(
        "POST /invoke, malformed JSON, no token",
        "POST",
        A + "/invoke",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    print("\n=== Active response: reads ===")
    await p.same("GET /supported", "GET", A + "/supported", t_analyst, expect=200)
    await p.same("GET /supported, responder", "GET", A + "/supported", t_resp, expect=200)
    for name in ("windows_firewall", "WINDOWS_FIREWALL", "Windows_Firewall", "nope", "linux_firewall", "windows"):
        await p.same(f"GET /describe/{name}", "GET", f"{A}/describe/{name}", t_analyst)
    for agent in (AGENT_A_WIN, AGENT_A_LIN, AGENT_A_NOOS, AGENT_B_WIN, f"missing{SFX}"):
        await p.same(f"GET /supported/{agent}, analyst", "GET", f"{A}/supported/{agent}", t_analyst)
    await p.same("GET /supported/{other tenant}, admin", "GET", f"{A}/supported/{AGENT_B_WIN}", t_admin, expect=200)

    print("\n=== Active response: invoke, validation ===")
    for i, body in enumerate(INVALID_BODIES):
        await p.same(f"POST /invoke invalid #{i} {json.dumps(body)[:80]}", "POST", A + "/invoke", t_admin, json=body)
    for raw in (b"null", b"", b"{"):
        await p.same(f"POST /invoke raw {raw!r}", "POST", A + "/invoke", t_admin, content=raw, headers={"Content-Type": "application/json"})
    await p.same("POST /invoke, no content type", "POST", A + "/invoke", t_admin, content=json.dumps(firewall()).encode())

    print("\n=== Active response: invoke, tenancy ===")
    for agents in (["*"], [], None, ...):
        await p.same(f"POST /invoke analyst agents_list={agents!r}", "POST", A + "/invoke", t_analyst, json=firewall(agents), expect=403)
    await p.same(
        "POST /invoke analyst, a foreign agent",
        "POST",
        A + "/invoke",
        t_analyst,
        json=firewall([AGENT_A_WIN, AGENT_B_WIN]),
        expect=403,
    )
    await p.same("POST /invoke analyst, an unknown agent", "POST", A + "/invoke", t_analyst, json=firewall([f"x{SFX}"]), expect=403)
    await p.same("POST /invoke portal user", "POST", A + "/invoke", t_portal, json=firewall([AGENT_A_WIN]), expect=403)

    print("\n=== Active response: invoke, Wazuh ===")
    reset_python_caches()
    for i, body in enumerate(VALID_BODIES):
        await p.same(f"POST /invoke valid #{i}", "POST", A + "/invoke", t_analyst, json=body, before=mode("ok"), expect=200)
    await p.same("POST /invoke admin ['*'] (every agent)", "POST", A + "/invoke", t_admin, json=firewall(["*"]), before=mode("ok"))
    await p.same("POST /invoke admin, no agents_list", "POST", A + "/invoke", t_admin, json=firewall(), before=mode("ok"))
    await p.same("POST /invoke responder", "POST", A + "/invoke", t_resp, json=firewall([AGENT_A_WIN]), before=mode("ok"))
    for m in ("detail", "message", "data-detail", "text", "empty-detail", "not-json"):
        await p.same(f"POST /invoke, Wazuh answers {m}", "POST", A + "/invoke", t_admin, json=firewall(["001", "002"]), before=mode(m))
    # The manager unreachable: the token fetch fails first.
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{CLOSED_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()
    await p.same("POST /invoke, manager unreachable", "POST", A + "/invoke", t_admin, json=firewall(["001"]))
    set_connector("Wazuh-Manager", None)
    await p.same("POST /invoke, no manager connector", "POST", A + "/invoke", t_admin, json=firewall(["001"]), expect=503)
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()


def notification(fields=None, **event_extra):
    event = {
        "id": "01JNHQP35THD48VH8601F6EMHE",
        "event_definition_type": "aggregation-v1",
        "event_definition_id": "67c78b93cf26aa2045bdc2ea",
        "origin_context": "urn:graylog:message:es:graylog-01_3:766b70b4",
        "timestamp": "2025-03-04T23:21:55.840Z",
        "timestamp_processing": "2025-03-04T23:26:03.450Z",
        "timerange_start": None,
        "timerange_end": None,
        "streams": [],
        "source_streams": ["679945aa7c4dd06afcef5feb"],
        "message": "ACTIVE RESPONSE WEBSERVER THREAT INTEL",
        "source": "soc-grlog01",
        "key_tuple": [],
        "key": "",
        "priority": 2,
        "scores": {},
        "associated_assets": [],
        "alert": True,
        "fields": fields
        if fields is not None
        else {"COMMAND": "domain_sinkhole", "AGENT_ID": "032", "ACTION": "sinkhole", "VALUE": "example.com"},
        "group_by_fields": {},
        "replay_info": {
            "timerange_start": "2025-03-04T23:21:03.360Z",
            "timerange_end": "2025-03-04T23:26:03.360Z",
            "query": "_exists_:threat_intel_score",
            "streams": ["679945aa7c4dd06afcef5feb"],
            "filters": [],
        },
    }
    event.update(event_extra)
    return {
        "event_definition_id": "67c78b93cf26aa2045bdc2ea",
        "event_definition_type": "aggregation-v1",
        "event_definition_title": "ACTIVE RESPONSE WEBSERVER THREAT INTEL",
        "event_definition_description": "",
        "job_definition_id": "67c78befcf26aa2045bdc4e9",
        "job_trigger_id": "67c78c0bcf26aa2045bdc5b5",
        "event": event,
        "backlog": [],
    }


async def graylog_webhook_checks(p, bare):
    G = "/api/graylog/invoke"
    ok = {"graylog": GRAYLOG_HEADER}
    print("\n=== Graylog webhook: header ===")
    await p.same("POST /invoke, no header", "POST", G, json=notification(), expect=403)
    await p.same("POST /invoke, wrong header", "POST", G, json=notification(), headers={"graylog": "nope"}, expect=403)
    await p.same("POST /invoke, a token is not the header", "POST", G, token(ADMIN, ["admin"]), json=notification(), expect=403)
    await p.same("POST /invoke, malformed JSON", "POST", G, content=b"{", headers={"Content-Type": "application/json", **ok})
    await p.same("POST /invoke, wrong header and invalid body", "POST", G, json={}, headers={"graylog": "nope"}, expect=403)

    print("\n=== Graylog webhook: body ===")
    fields = {"COMMAND": "domain_sinkhole", "AGENT_ID": "032", "ACTION": "sinkhole", "VALUE": "example.com"}
    bad = [
        ("COMMAND with a space", notification({**fields, "COMMAND": "rm -rf /"})),
        ("COMMAND too long", notification({**fields, "COMMAND": "a" * 65, "AGENT_ID": 32})),
        ("COMMAND not ASCII", notification({**fields, "COMMAND": "dömain"})),
        ("additional_fields not a dict", notification({**fields, "additional_fields": 5})),
        ("__extra__ not a dict", notification({**fields, "__extra__": 5})),
        ("both spellings", notification({**fields, "__extra__": 5, "additional_fields": 6})),
        ("bad datetime, int, bool", notification(None, timestamp="nope", priority="x", alert="maybe")),
        ("no fields", {**notification(), "event": {k: v for k, v in notification()["event"].items() if k != "fields"}}),
        ("fields a list", notification([])),
        ("event null", {**notification(), "event": None}),
        ("origin_context null", notification(None, origin_context=None)),
        ("empty object", {}),
        ("a list", []),
    ]
    for name, body in bad:
        await p.same(f"POST /invoke, {name}", "POST", G, json=body, headers=ok)
    print("\n=== Graylog webhook: forwarded ===")
    reset_python_caches()
    good = [
        ("as sent by Graylog", notification()),
        ("extra fields", notification({**fields, "OTHER": [1, 2], "__extra__": {"k": "v"}})),
        ("timestamps as numbers", notification(None, timestamp=1741130515, timestamp_processing=1741130515840.5)),
        ("non-ASCII value", notification({**fields, "VALUE": "exämple.com", "ACTION": "tab\there"})),
    ]
    for name, body in good:
        await p.same(f"POST /invoke, {name}", "POST", G, json=body, headers=ok, before=mode("ok"), expect=200)
    for m in ("detail", "text"):
        await p.same(
            f"POST /invoke, Wazuh answers {m} (still a success)",
            "POST",
            G,
            json=notification(),
            headers=ok,
            before=mode(m),
            expect=200,
        )
    set_connector("Wazuh-Manager", None)
    await p.same("POST /invoke, no manager connector (still a success)", "POST", G, json=notification(), headers=ok, expect=200)
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()

    print("\n=== Graylog webhook: GRAYLOG_API_HEADER_VALUE unset ===")
    del os.environ["GRAYLOG_API_HEADER_VALUE"]
    try:
        await bare.same("POST /invoke, header not configured", "POST", G, json=notification(), headers=ok, expect=403)
        await bare.same("POST /invoke, header not configured, none sent", "POST", G, json=notification(), expect=403)
    finally:
        os.environ["GRAYLOG_API_HEADER_VALUE"] = GRAYLOG_HEADER


async def main():
    manager_server = start_http_stub(MANAGER_PORT, MANAGER, MANAGER_RECORDER)
    seed()
    proc = start_rust(RS_PORT)
    bare_proc = start_rust(RS_BARE_PORT, bare=True)
    p, bare = Pair(RS_PORT), Pair(RS_BARE_PORT)
    t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
    t_portal, t_resp = token(PORTAL, ["customer_user"]), token(RESP, ["responder", "analyst"])
    try:
        sections = os.environ.get("RESPONSE_PARITY_SECTIONS", "active_response,graylog").split(",")
        if "active_response" in sections:
            await active_response_checks(p, t_admin, t_analyst, t_portal, t_resp)
        if "graylog" in sections:
            await graylog_webhook_checks(p, bare)
    finally:
        await p.close()
        await bare.close()
        for proc_ in (proc, bare_proc):
            proc_.terminate()
            try:
                proc_.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc_.kill()
        cleanup()
        manager_server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
