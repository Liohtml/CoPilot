"""Parity of the Rust monitoring-alert catalog (`copilot-monitoring-alerts`) with this backend —
NOT collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI router of `/api/monitoring_alert` (in-process) and a Rust instance this suite
starts (no legacy backend, connector cache off) answer the same requests on one database. The
tools are local stand-ins that record everything they receive: on one port, by path prefix, the
default Graylog (`Graylog`, a 6.x — `/graylog`) and the network one (`Graylog-Network`, a 7.x —
`/graylog-net`), every header and the body bytes of each request; and the Event Shipper's GELF TCP
input, the bytes of each connection. For each request the suite compares the status, the response
bytes, every request sent to Graylog (method, target, all headers, body), every GELF frame, and the
`log_entries` row an error leaves.

Both backends cache the Graylog major version per connector for five minutes (`GET /api/system`):
Python's cache is pinned before each request (6 for `Graylog`, 7 for `Graylog-Network`), the Rust
instance probes once per five minutes. `provision_alert_definition` reads `GET /api/system` itself
too (`get_system_info`), so a probe shows up as a second `GET /api/system` right after it: the
first request compares both backends cold, the others drop a `GET /api/system` that repeats the one
before it.

    PARITY_SUITES=tests/e2e/rust_parity_monitoring_alert_e2e.py scripts/rust-parity.sh

Ports: MONITORING_ALERT_PARITY_RUST_PORT (6280), MONITORING_ALERT_STUB_PORT (6282, Graylog),
MONITORING_ALERT_GELF_PORT (6283). Seeded user ids are seven digits in 7642000-7642999.
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
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
# The WAF brute-force alert's webhook settings (both backends read them).
ENV = {"ALERT_FORWARDING_IP": "10.9.8.7", "GRAYLOG_API_HEADER_VALUE": "parity-header-secret"}
os.environ.update(ENV)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)

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
RS_PORT = int(os.environ.get("MONITORING_ALERT_PARITY_RUST_PORT", "6280"))
STUB_PORT = int(os.environ.get("MONITORING_ALERT_STUB_PORT", "6282"))
GELF_PORT = int(os.environ.get("MONITORING_ALERT_GELF_PORT", "6283"))
CLOSED_PORT = 1
USER_IDS = {"admin": 7642001, "analyst": 7642002, "portal": 7642003}
USERS = {kind: f"ma_{kind}{SFX}" for kind in USER_IDS}
OUR_CONNECTORS = ("Graylog", "Graylog-Network", "Event Shipper")
P = "/api/monitoring_alert"
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(text(statement), params)


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(text(statement), params)]


def _json(value):
    return json.dumps(value).encode()


# --- Graylog ----------------------------------------------------------------------------------------


class Graylog:
    """One Graylog personality: what the monitoring alerts read and create."""

    def __init__(self, version):
        self.default_version = version
        self.reset()

    def reset(self, system=None, definitions=None, notifications=None, allowlist=None, overrides=None):
        self.system = copy.deepcopy(system if system is not None else self._system(self.default_version))
        self.definitions = copy.deepcopy(definitions if definitions is not None else samples.GRAYLOG_EVENT_DEFINITIONS)
        self.notifications = copy.deepcopy(notifications or [])
        self.allowlist = copy.deepcopy(allowlist if allowlist is not None else {"entries": [], "disabled": False})
        self.overrides = dict(overrides or {})
        self.counter = 0

    @staticmethod
    def _system(version):
        return {**samples.GRAYLOG_SYSTEM_6, "version": version}

    def answer(self, method, path, query, body):
        if (method, path) in self.overrides:
            return self.overrides[(method, path)]
        major = int(str(self.system.get("version", "6") if isinstance(self.system, dict) else "6").split(".")[0] or 6)
        if method == "GET" and path == "/api/system":
            return 200, "application/json", _json(self.system)
        if method == "GET" and path == "/api/events/definitions":
            page = int(query.get("page", ["1"])[0])
            size = int(query.get("per_page", ["50"])[0])
            batch = self.definitions[(page - 1) * size : page * size]
            return (
                200,
                "application/json",
                _json({"event_definitions": batch, "total": len(self.definitions), "page": page, "per_page": size}),
            )
        if method == "POST" and path == "/api/events/definitions":
            entity = json.loads(body)
            if major >= 7:
                if "entity" not in entity:
                    return 400, "application/json", _json({"type": "ApiError", "message": "entity cannot be null"})
                entity = entity["entity"]
            self.counter += 1
            return 200, "application/json", _json({"id": f"ed{self.counter:022d}", "title": entity.get("title")})
        if method == "GET" and path == "/api/events/notifications":
            return 200, "application/json", _json({"notifications": self.notifications, "total": len(self.notifications)})
        if method == "POST" and path == "/api/events/notifications":
            entity = json.loads(body)
            if major >= 7:
                entity = entity.get("entity") or {}
            self.counter += 1
            new = {"id": f"nt{self.counter:022d}", "title": entity.get("title")}
            self.notifications.append(new)
            return 200, "application/json", _json(new)
        allow = "/api/system/urlallowlist" if major >= 7 else "/api/system/urlwhitelist"
        if path == allow and method == "GET":
            return 200, "application/json", _json(self.allowlist)
        if path == allow and method == "PUT":
            self.allowlist = json.loads(body)
            return 204, None, b""
        return 404, "application/json", _json({"type": "ApiError", "message": "HTTP 404 Not Found"})


DEFAULT = Graylog("6.1.4+d7b6e3c")
NETWORK = Graylog("7.0.1+abc1234")
PREFIXES = (("/graylog-net", NETWORK), ("/graylog", DEFAULT))
CAPTURED = []
CAPTURE_LOCK = threading.Lock()


def start_stub():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            # Every header the client sent, Content-Length included.
            headers = sorted((k.lower(), v) for k, v in self.headers.items())
            with CAPTURE_LOCK:
                CAPTURED.append((self.command, self.path, headers, body))
            parts = urlsplit(self.path)
            for prefix, graylog in PREFIXES:
                if parts.path.startswith(prefix + "/"):
                    status, ctype, payload = graylog.answer(self.command, parts.path[len(prefix) :], parse_qs(parts.query), body)
                    break
            else:
                status, ctype, payload = 404, "application/json", _json({"message": "no such stand-in"})
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

    server = Server(("127.0.0.1", STUB_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def take_captured():
    with CAPTURE_LOCK:
        out, CAPTURED[:] = list(CAPTURED), []
    return out


# --- The Event Shipper's GELF input -----------------------------------------------------------------

GELF_FRAMES = []
GELF_LOCK = threading.Lock()


class _GelfHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.read()
        with GELF_LOCK:
            GELF_FRAMES.append(data)


def start_gelf_stub():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("127.0.0.1", GELF_PORT), _GelfHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def take_gelf(settle=0.3, timeout=5.0):
    """The frames received so far, once no new connection came for `settle` seconds."""
    deadline = time.time() + timeout
    seen = -1
    while time.time() < deadline:
        with GELF_LOCK:
            n = len(GELF_FRAMES)
        if n == seen:
            break
        seen = n
        time.sleep(settle)
    with GELF_LOCK:
        out, GELF_FRAMES[:] = list(GELF_FRAMES), []
    return out


# --- Seed -------------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, username="admin", password="pässword", extra=None):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    if url is None:
        return
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (:n, '3', :u, "
        "UTC_TIMESTAMP(), :user, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, :extra, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
        extra=extra,
    )


def connectors_default():
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog")
    set_connector("Graylog-Network", f"http://127.0.0.1:{STUB_PORT}/graylog-net", "net", "net-pw")
    set_connector("Event Shipper", "127.0.0.1", extra=str(GELF_PORT))


def seed():
    with sync_engine.connect() as conn:
        found = conn.execute(text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(names=list(OUR_CONNECTORS)))
    SAVED_CONNECTORS.extend(dict(r._mapping) for r in found)
    for kind, role in (("admin", 1), ("analyst", 2), ("portal", 4)):
        sql(
            "INSERT INTO `user` (id, username, password, email, created_at, role_id) VALUES "
            "(:i, :n, 'x', 'ma@example.com', UTC_TIMESTAMP(), :r)",
            i=USER_IDS[kind],
            n=USERS[kind],
            r=role,
        )
    connectors_default()


def waf_field_rows():
    """`waf` in the five field-mapping tables (the WAF alerts register it)."""
    out = {}
    for table in ("fieldname", "assetfieldname", "timestampfieldname", "alerttitlefieldname", "iocfieldname"):
        cols = [
            c["COLUMN_NAME"]
            for c in rows(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME != 'id' "
                "ORDER BY ORDINAL_POSITION",
                t=f"incident_management_{table}",
            )
        ]
        out[table] = sorted(
            json.dumps(r, sort_keys=True, default=str)
            for r in rows(
                f"SELECT {', '.join(cols)} FROM incident_management_{table} WHERE source = 'waf'",
            )
        )
    return out


def clear_waf_rows():
    for table in ("fieldname", "assetfieldname", "timestampfieldname", "alerttitlefieldname", "iocfieldname"):
        sql(f"DELETE FROM incident_management_{table} WHERE source = 'waf'")


def cleanup():
    clear_waf_rows()
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for kind, user_id in USER_IDS.items():
        sql("DELETE FROM log_entries WHERE user_id = :i", i=user_id)
        sql("DELETE FROM `user` WHERE id = :i", i=user_id)
    sql("DELETE FROM log_entries WHERE user_id IS NULL AND route LIKE '%/api/monitoring_alert/%'")


# --- The backends -----------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import monitoring_alert

    api = APIRouter(prefix="/api")
    api.include_router(monitoring_alert.router)
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
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_STARTUP_TASKS": "false",  # the startup seeds no row of the shared database
        "COPILOT_PORT": str(RS_PORT),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        **ENV,
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


def pin_python_versions():
    """Python's cached Graylog major versions, as the Rust instance has them after its probes."""
    from app.connectors.graylog.utils import universal

    universal._GRAYLOG_VERSION_CACHE["Graylog"] = (6, time.monotonic())
    universal._GRAYLOG_VERSION_CACHE["Graylog-Network"] = (7, time.monotonic())


def clear_python_versions():
    from app.connectors.graylog.utils import universal

    universal._GRAYLOG_VERSION_CACHE.clear()


# The URL allowlist entry the WAF brute-force alert adds is named by `secrets.token_hex(12)`.
OUT_MASKS = [(re.compile(rb'"id": "[0-9a-f]{24}", "title": "\\"SEND TO COPILOT'), b'"id": "<hex>", "title": "\\"SEND TO COPILOT')]


def out_norm(requests, cold=False):
    """The requests a backend sent; without `cold`, a `GET …/api/system` repeating the one just
    before it (the version probe after `get_system_info`) is dropped."""
    out = []
    for method, target, headers, body in requests:
        if not cold and out and method == "GET" and target.endswith("/api/system") and out[-1][:2] == (method, target):
            continue
        for pattern, repl in OUT_MASKS:
            body = pattern.sub(repl, body)
        out.append((method, target, headers, body))
    return out


def log_rows(after_id):
    return [
        {**r, "route": urlsplit(r["route"]).path + ("?" + urlsplit(r["route"]).query if urlsplit(r["route"]).query else "")}
        for r in rows(
            "SELECT event_type, user_id, route, method, status_code, message, additional_info FROM log_entries "
            "WHERE id > :i AND route LIKE '%/api/monitoring_alert/%' ORDER BY id",
            i=after_id,
        )
    ]


def max_log_id():
    return rows("SELECT COALESCE(MAX(id), 0) AS m FROM log_entries")[0]["m"]


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, expect_logs=0, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        take_captured()
        take_gelf(settle=0.0, timeout=0.0)
        before = max_log_id()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        out = take_captured()
        frames = take_gelf(settle=0.15) if path.endswith("/testing") else []
        # The Rust log row is written by a task after the answer: wait for as many rows as
        # Python wrote, and a little longer for one more.
        logs = log_rows(before)
        if client is self.rs:
            for _ in range(60):
                if len(logs) >= expect_logs:
                    break
                await asyncio.sleep(0.05)
                logs = log_rows(before)
            await asyncio.sleep(0.1)
            logs = log_rows(before)
        return r, out, frames, logs

    async def same(self, name, method, path, tok=None, before=None, after=None, cold=False, **kw):
        """Python, then Rust, each after `before(side)`; `after(side)` returns the state the
        request left. `cold`: compare every request, version probes included."""
        sides = []
        for side, client in (("py", self.py), ("rs", self.rs)):
            DEFAULT.reset()
            NETWORK.reset()
            if not cold:
                pin_python_versions()
            if before:
                before(side)
            expect = len(sides[0][3]) if sides else 0
            r, out, frames, logs = await self.call(client, method, path, tok, expect_logs=expect, **kw)
            state = after(side) if after else None
            sides.append((r, out_norm(out, cold), frames, logs, state))
        (r1, o1, f1, l1, s1), (r2, o2, f2, l2, s2) = sides
        b1, b2 = ADDRESS.sub(b"object at 0x...", r1.content), ADDRESS.sub(b"object at 0x...", r2.content)
        ok = r1.status_code == r2.status_code and b1 == b2
        detail = f"python {r1.status_code} {b1[:1200]!r}\n        rust   {r2.status_code} {b2[:1200]!r}"
        if o1 != o2:
            ok = False
            detail += f"\n        outbound python {o1}\n        outbound rust   {o2}"
        if f1 != f2:
            ok = False
            detail += f"\n        gelf python {f1}\n        gelf rust   {f2}"
        m1 = [{**r, "message": ADDRESS.sub(b"object at 0x...", (r["message"] or "").encode()).decode()} for r in l1]
        m2 = [{**r, "message": ADDRESS.sub(b"object at 0x...", (r["message"] or "").encode()).decode()} for r in l2]
        if m1 != m2:
            ok = False
            detail += f"\n        log python {m1}\n        log rust   {m2}"
        if s1 != s2:
            ok = False
            detail += f"\n        state python {s1}\n        state rust   {s2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {[(m, t, b[:300]) for m, t, h, b in o1]}\n        gelf {f1}")
        return r1, r2, o1, f1

    async def close(self):
        for c in (self.py, self.rs):
            await c.aclose()


# --- The checks -------------------------------------------------------------------------------------


def catalog_names():
    from app.integrations.monitoring_alert.schema.provision import (
        AvailableMonitoringAlerts,
    )

    return [m.name for m in AvailableMonitoringAlerts]


async def first_checks(p, t_analyst):
    # Both processes cold: `get_system_info`, then the version probe, then the definition.
    def cold(side):
        clear_python_versions()

    body = {"search_within_last": 60, "execute_every": 120, "alert_name": "SURICATA_ALERT_SEVERITY_1"}
    _, _, out, _ = await p.same(
        "provision, cold caches (info + probe)",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=body,
        before=cold,
        cold=True,
    )
    systems = [o for o in out if o[0] == "GET" and o[1].endswith("/api/system")]
    check("provision, cold caches: two GET /api/system", len(systems) == 2, f"{[o[:2] for o in out]}")
    body = {**body, "graylog_instance": "network"}
    _, _, out, _ = await p.same(
        "provision on the network Graylog, cold",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=body,
        before=cold,
        cold=True,
    )
    check("network, cold: every request to Graylog-Network", all(o[1].startswith("/graylog-net/") for o in out), f"{[o[:2] for o in out]}")


async def available_checks(p, t_admin, t_analyst, t_portal):
    await p.same("available: analyst", "GET", f"{P}/available", t_analyst)
    await p.same("available: admin", "GET", f"{P}/available", t_admin)
    await p.same("available: no token", "GET", f"{P}/available")
    await p.same("available: portal user", "GET", f"{P}/available", t_portal)
    await p.same("available: bad token", "GET", f"{P}/available", "not-a-token")
    await p.same("available: POST", "POST", f"{P}/available", t_analyst)
    await p.same("provision: GET", "GET", f"{P}/provision", t_analyst)


async def catalog_checks(p, t_analyst):
    names = [n for n in catalog_names() if not n.startswith("SOCFORTRESS_WAF")]
    check("49 catalog functions", len(names) == 49, str(len(names)))
    for i, name in enumerate(names):
        body = {"search_within_last": 60 + i, "execute_every": 300, "alert_name": name.lower().replace("_", " ")}
        await p.same(f"provision {name} (Graylog 6)", "POST", f"{P}/provision", t_analyst, json=body)
    for i, name in enumerate(names):
        body = {"search_within_last": "1", "execute_every": 2.0 + i, "alert_name": name, "graylog_instance": "network"}
        await p.same(f"provision {name} (network, Graylog 7)", "POST", f"{P}/provision", t_analyst, json=body)


async def graylog_checks(p, t_analyst):
    body = {"search_within_last": 60, "execute_every": 60, "alert_name": "WAZUH_SYSLOG_LEVEL_ALERT"}

    def gl(target=DEFAULT, **kw):
        return lambda side: target.reset(**kw)

    await p.same("exists (the name with spaces)", "POST", f"{P}/provision", t_analyst, json=body)
    many = [samples.graylog_event_definition(f"66000000000000000{i:07d}", f"DEF {i}") for i in range(600)]
    await p.same(
        "exists on page 2 of the definitions",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "CROWDSTRIKE_ALERT"},
        before=gl(definitions=many + [samples.graylog_event_definition("6600000000000000000000e9", "CROWDSTRIKE ALERT")]),
    )
    await p.same(
        "600 definitions, created",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "CROWDSTRIKE_ALERT"},
        before=gl(definitions=many),
    )
    await p.same(
        "the title differs from the checked name (PALOALTO ALERT)",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "PALOALTO_ALERT"},
        before=gl(definitions=[samples.graylog_event_definition("6600000000000000000000e8", "PALO ALTO - HIGH SEVERITY EVENTS")]),
    )
    for version in ("5.1.9", "5.10.0", "10.0.0", "5.2"):
        await p.same(
            f"Graylog {version} (event_limit as a string compare)",
            "POST",
            f"{P}/provision",
            t_analyst,
            json={**body, "alert_name": "SURICATA_ALERT_SEVERITY_1"},
            before=gl(system={**samples.GRAYLOG_SYSTEM_6, "version": version}),
        )
    await p.same(
        "network Graylog 10.0.0",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "FORTINET_UTM", "graylog_instance": "network"},
        before=gl(NETWORK, system={**samples.GRAYLOG_SYSTEM_7, "version": "10.0.0"}),
    )
    bad_system = {k: v for k, v in samples.GRAYLOG_SYSTEM_6.items() if k not in ("node_id", "is_processing")}
    await p.same(
        "system info missing fields (ValidationError)",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "SURICATA_ALERT_SEVERITY_1"},
        before=gl(system=bad_system),
    )
    await p.same(
        "system info a list (TypeError)",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "SURICATA_ALERT_SEVERITY_1"},
        before=gl(system=[1]),
    )
    await p.same(
        "definitions answer 404",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=body,
        before=gl(overrides={("GET", "/api/events/definitions"): (404, "application/json", _json({"message": "gone"}))}),
    )
    await p.same(
        "definitions answer without the key",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=body,
        before=gl(overrides={("GET", "/api/events/definitions"): (200, "application/json", _json({"total": 0}))}),
    )
    await p.same(
        "definitions answer HTML",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=body,
        before=gl(overrides={("GET", "/api/events/definitions"): (200, "text/html", b"<html>")}),
    )
    await p.same(
        "a definition Graylog refuses",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "SURICATA_ALERT_SEVERITY_1"},
        before=gl(
            overrides={("POST", "/api/events/definitions"): (400, "application/json", _json({"type": "ApiError", "message": "nope"}))},
        ),
    )
    await p.same(
        "a definition Graylog refuses without a message",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "alert_name": "SURICATA_ALERT_SEVERITY_1"},
        before=gl(overrides={("POST", "/api/events/definitions"): (500, "text/plain", b"")}),
    )

    def unreachable(side):
        set_connector("Graylog", f"http://127.0.0.1:{CLOSED_PORT}")

    await p.same("Graylog unreachable", "POST", f"{P}/provision", t_analyst, json=body, before=unreachable)

    def no_network(side):
        set_connector("Graylog-Network", None)

    await p.same(
        "no Graylog-Network connector",
        "POST",
        f"{P}/provision",
        t_analyst,
        json={**body, "graylog_instance": "network"},
        before=no_network,
    )
    connectors_default()


async def waf_checks(p, t_analyst):
    # The WAF alerts are pinned to the default Graylog: a network request goes there.
    defs = [d for d in samples.GRAYLOG_EVENT_DEFINITIONS if "WAF" not in d["title"]]

    def fresh(side):
        clear_waf_rows()
        DEFAULT.reset(definitions=defs)

    blocked = {
        "search_within_last": 100000000000000000000,
        "execute_every": 30,
        "alert_name": "socfortress waf blocked",
        "graylog_instance": "network",
    }
    await p.same(
        "WAF blocked on network → default Graylog",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=blocked,
        before=fresh,
        after=lambda s: waf_field_rows(),
    )
    brute = {"search_within_last": 1, "execute_every": 1, "alert_name": "SOCFORTRESS_WAF_BRUTE_FORCE", "graylog_instance": "network"}
    await p.same(
        "WAF brute force on network → default Graylog",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=brute,
        before=fresh,
        after=lambda s: waf_field_rows(),
    )
    await p.same(
        "WAF brute force exists on the default Graylog",
        "POST",
        f"{P}/provision",
        t_analyst,
        json=brute,
        before=lambda s: (clear_waf_rows(), DEFAULT.reset()),
        after=lambda s: waf_field_rows(),
    )
    clear_waf_rows()


async def validation_checks(p, t_analyst):
    from app.integrations.monitoring_alert.schema.provision import (  # noqa: F401
        AvailableMonitoringAlerts,
    )

    bodies = [
        {"search_within_last": 0, "execute_every": 1},
        {"search_within_last": 1, "execute_every": False},
        {"search_within_last": "x", "execute_every": 0},
        {"search_within_last": 1.5, "execute_every": 1, "graylog_instance": "graylog02"},
        {"search_within_last": None, "execute_every": [], "alert_name": 5},
        {"alert_name": "nope"},
        {"search_within_last": 1, "execute_every": 1, "alert_name": "custom"},
        {"search_within_last": 1, "execute_every": 1, "alert_name": "straße"},
        {"search_within_last": 1, "execute_every": 1, "alert_name": "Wazuh_Syslog_Level_Alert", "graylog_instance": "DEFAULT"},
        {"search_within_last": 1e300, "execute_every": 1},
        {"search_within_last": "1_000", "execute_every": " 2 ", "alert_name": "ﬁ"},
        {},
        [],
        "x",
    ]
    for body in bodies:
        await p.same(f"provision body {json.dumps(body, ensure_ascii=False)[:70]}", "POST", f"{P}/provision", t_analyst, json=body)
    for label, kw in (
        ("malformed JSON, no token", {"content": b"{", "headers": {"Content-Type": "application/json"}, "tok": None}),
        ("not UTF-8", {"content": b"\xff", "headers": {"Content-Type": "application/json"}}),
        ("text body", {"content": b"{}", "headers": {"Content-Type": "text/plain"}}),
        ("no body", {}),
        ("JSON null", {"content": b"null", "headers": {"Content-Type": "application/json"}}),
        ("NaN window", {"content": b'{"search_within_last": NaN, "execute_every": 1}', "headers": {"Content-Type": "application/json"}}),
        ("no token", {"json": {"search_within_last": 1, "execute_every": 1}, "tok": None}),
    ):
        kw = dict(kw)
        tok = kw.pop("tok", t_analyst)
        for route in ("/provision", "/provision/custom", "/provision/testing"):
            await p.same(f"{route}: {label}", "POST", f"{P}{route}", tok, **kw)


CUSTOM = {
    "alert_name": "MY_CUSTOM ALERT",
    "alert_description": "Custom — é",
    "alert_priority": 2,
    "search_query": "syslog_type:wazuh AND rule_level:>10",
    "search_within_ms": 300000,
    "execute_every_ms": 60000,
}


async def custom_checks(p, t_admin, t_analyst):
    C = f"{P}/provision/custom"
    for label, body in (
        ("base", CUSTOM),
        ("streams and custom fields", {**CUSTOM, "streams": ["s1", "s2"], "custom_fields": [{"name": "CUSTOMER CODE", "value": "00001"}]}),
        ("network, priority 3.0", {**CUSTOM, "alert_priority": 3.0, "graylog_instance": "network"}),
        ("priority true", {**CUSTOM, "alert_priority": True}),
        ("a WAF name is not pinned", {**CUSTOM, "alert_name": "SOCFORTRESS_WAF_BLOCKED", "graylog_instance": "network"}),
        ("big timings", {**CUSTOM, "search_within_ms": "100000000000000000000000", "execute_every_ms": -1}),
        ("null streams (after the check)", {**CUSTOM, "streams": None}),
        ("priority as text", {**CUSTOM, "alert_priority": "2"}),
        ("bad fields", {**CUSTOM, "alert_priority": 4, "streams": [1], "custom_fields": [{"name": 1}, "x"]}),
        ("custom_fields not a list", {**CUSTOM, "custom_fields": {"name": "a", "value": "b"}}),
        ("bad instance", {**CUSTOM, "graylog_instance": "x"}),
        ("missing fields", {"alert_name": "x"}),
    ):
        await p.same(f"custom: {label}", "POST", C, t_analyst, json=body)
    await p.same(
        "custom: exists (underscores checked as spaces)",
        "POST",
        C,
        t_admin,
        json={**CUSTOM, "alert_name": "WAZUH_SYSLOG_LEVEL_ALERT"},
    )
    await p.same(
        "custom: Graylog 5.1.9",
        "POST",
        C,
        t_admin,
        json=CUSTOM,
        before=lambda s: DEFAULT.reset(system={**samples.GRAYLOG_SYSTEM_6, "version": "5.1.9"}),
    )


async def testing_checks(p, t_analyst, t_portal):
    T = f"{P}/provision/testing"
    for body in (
        {},
        {"message": "hello", "level": 3},
        {"a": None, "b": {"c": None}, "c": [1, 2.5, "é"], "d": True},
        {"syslog_type": "wazuh", "agent_labels_customer": "00001", "n": 100000000000000000000},
        {"x": ' \u0000\u007f"\\'},
        {"customer_code": "00001"},
        {"integration": None},
        {"version": "2"},
        [1],
        "x",
    ):
        await p.same(f"testing {json.dumps(body)[:60]}", "POST", T, t_analyst, json=body)
    await p.same(
        "testing NaN and Infinity",
        "POST",
        T,
        t_analyst,
        content=b'{"f": NaN, "g": -Infinity, "h": 1e400}',
        headers={"Content-Type": "application/json"},
    )
    await p.same("testing: portal user", "POST", T, t_portal, json={})
    for label, extra in (
        (" port with blanks", f" {GELF_PORT} "),
        ("port +n", f"+{GELF_PORT}"),
        ("closed port", str(CLOSED_PORT)),
        ("port None", None),
        ("port text", "gelf"),
    ):

        def shipper(side, extra=extra):
            set_connector("Event Shipper", "127.0.0.1", extra=extra)

        await p.same(f"testing: {label}", "POST", T, t_analyst, json={"m": 1}, before=shipper)

    def localhost(side):
        set_connector("Event Shipper", "localhost", extra=str(GELF_PORT + 65536))

    await p.same("testing: localhost, port beyond 65535 (htons)", "POST", T, t_analyst, json={"m": 1}, before=localhost)

    def no_shipper(side):
        set_connector("Event Shipper", None)

    await p.same("testing: no Event Shipper connector", "POST", T, t_analyst, json={}, before=no_shipper)
    connectors_default()


async def main():
    servers = [start_stub(), start_gelf_stub()]
    seed()
    procs = [start_rust()]
    p = Pair()
    t_admin, t_analyst = token(USERS["admin"], ["admin"]), token(USERS["analyst"], ["analyst"])
    t_portal = token(USERS["portal"], ["customer_user"])
    try:
        sections = os.environ.get(
            "MONITORING_ALERT_PARITY_SECTIONS",
            "first,available,catalog,graylog,waf,validation,custom,testing",
        ).split(",")
        if "first" in sections:
            await first_checks(p, t_analyst)
        if "available" in sections:
            await available_checks(p, t_admin, t_analyst, t_portal)
        if "catalog" in sections:
            await catalog_checks(p, t_analyst)
        if "graylog" in sections:
            await graylog_checks(p, t_analyst)
        if "waf" in sections:
            await waf_checks(p, t_analyst)
        if "validation" in sections:
            await validation_checks(p, t_analyst)
        if "custom" in sections:
            await custom_checks(p, t_admin, t_analyst)
        if "testing" in sections:
            await testing_checks(p, t_analyst, t_portal)
    finally:
        await p.close()
        from app.db.db_session import async_engine

        await async_engine.dispose()
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        cleanup()
        for s in servers:
            s.shutdown()
            s.server_close()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
