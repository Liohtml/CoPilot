"""Parity of the Rust SOCFortress UBA connector (`copilot-uba`) with this backend — NOT collected
by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers of `/api/uba` and `/api/connectors` (in-process) and a Rust instance
answer the same requests on one database. The Rust instance's legacy backend is the same routers
served by uvicorn in a subprocess, so what Rust hands over is answered by Python too. One local
stand-in records every request either backend sends — method, path and query, every header, the
body bytes — as SOCFortress UBA (`/uba`), Graylog 6 (`/graylog`), Graylog 7 (`/graylog7`) and the
Wazuh manager (`/wazuh`); Graylog is stateful (streams, pipelines, rules, connections, outputs,
inputs, event definitions), so setup and rollback run end to end on both backends. A second UBA
stand-in serves HTTPS with a certificate nobody trusts (TLS is verified).

For each request the suite compares the status, the body (byte for byte, or with the fields named
in `masked` replaced), every request sent to the stand-ins, and the rows the request left (audit
events, incident alert verdicts, `uba_provisioned_resource`, `uba_rollback`, the connector's
`connector_verified`). Each side starts from the same seeded rows and the same stand-in state.
Twin customers (A, B) and an analyst of A check the tenancy. Deliberate differences are asserted
as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_uba_e2e.py scripts/rust-parity.sh

Ports: UBA_PARITY_RUST_PORT (6380), UBA_PARITY_PY_PORT (6381, the uvicorn legacy backend),
UBA_STUB_PORT (6382), UBA_TLS_STUB_PORT (6383), UBA_CLOSED_PORT (6384, nothing listens). Seeded
incident alert ids are seven digits in 7682000-7682999.
"""

import asyncio
import datetime
import fnmatch
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qsl
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

SFX = os.environ.get("UBA_PARITY_SFX") or uuid.uuid4().hex[:6]
RS_PORT = int(os.environ.get("UBA_PARITY_RUST_PORT", "6380"))
PY_PORT = int(os.environ.get("UBA_PARITY_PY_PORT", "6381"))
STUB_PORT = int(os.environ.get("UBA_STUB_PORT", "6382"))
TLS_PORT = int(os.environ.get("UBA_TLS_STUB_PORT", "6383"))
CLOSED_PORT = int(os.environ.get("UBA_CLOSED_PORT", "6384"))
SEED_LO, SEED_HI = 7_682_000, 7_682_999

CUST_A, CUST_B = f"UA{SFX}", f"UB{SFX}"
CUSTOMERS = (CUST_A, CUST_B)
ADMIN, ANALYST, ANALYST_B, PORTAL, UNICODE = (
    f"uba_admin{SFX}",
    f"uba_analyst{SFX}",
    f"uba_analyst_b{SFX}",
    f"uba_portal{SFX}",
    f"uba_é{SFX}",
)
USERS = (ADMIN, ANALYST, ANALYST_B, PORTAL, UNICODE)
OUR_CONNECTORS = ("SOCFortress UBA", "Graylog", "Wazuh-Manager")
UBA_KEY = "uba_parity_key"
FORWARDED = {"X-Forwarded-For": "10.9.8.7"}
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def _bind(stmt, params):
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    return stmt


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(_bind(text(statement), params), params)


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(_bind(text(statement), params), params)]


# --- The stand-ins ----------------------------------------------------------------------------------


def jbody(value):
    return json.dumps(value).encode()


class Stub:
    """UBA, Graylog 6 and 7 and the Wazuh manager on one port, by path prefix."""

    def __init__(self):
        self.lock = threading.Lock()
        self.captured = []
        self.reset()

    def reset(self, overrides=None, uba_info=None):
        # (method, glob on the path after the prefix, query included) -> (status, content type, body)
        # or a callable(method, path, query, body) returning that triple.
        self.overrides = dict(overrides or {})
        self.uba_info = uba_info

    def take(self):
        with self.lock:
            out, self.captured = self.captured, []
        return out

    def answer(self, method, raw_path, body):
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(raw_path, pattern):
                if callable(reply):
                    return reply(method, raw_path, body)
                return reply
        split = urlsplit(raw_path)
        path, query = split.path, split.query
        j = "application/json"
        if path.startswith("/uba/"):
            return self.uba(method, path[len("/uba") :], query, body)
        if path.startswith("/wazuh/"):
            p = path[len("/wazuh") :]
            if p.startswith("/security/user/authenticate"):
                return 200, j, jbody({"data": {"token": "parity-token"}, "error": 0})
            if p.startswith("/rules/files/"):
                return 200, j, jbody({"data": {"affected_items": [p], "total_affected_items": 1}, "error": 0})
            if p.startswith("/manager/restart"):
                return 200, j, jbody({"data": {"affected_items": ["manager"]}, "message": "Restart requested", "error": 0})
            return 404, j, jbody({"title": "Not Found"})
        return 404, j, jbody({"message": "no such stand-in route"})

    def uba(self, method, p, query, body):
        j = "application/json"
        if p == "/v1/status":
            return (
                200,
                j,
                jbody(
                    {
                        "version": "1.4.6",
                        "tenants": [
                            {"tenant": "elsewhere", "alerts_24h": 1},
                            {
                                "tenant": CUST_A,
                                "processed_until": "2026-10-17T10:00:00.123456+00:00",
                                "lag_seconds": 12,
                                "alerts_24h": "3",
                                "open_alerts": 2.0,
                                "onboarding": "live",
                                "workers": {"lag": [1, 2.5, None]},
                            },
                        ],
                    },
                ),
            )
        if p == "/v1/about":
            return 200, j, jbody({"policy": {"alert_threshold": 60, "decay": 0.5}, "categories": ["auth", "é"], "message": "about"})
        if p == "/v1/rules":
            return 200, j, jbody([{"id": "r1", "score": 10}, {"id": "r2", "mitre": ["T1110"]}])
        parsed = None
        if body:
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = body.decode("latin-1")
        return (
            200,
            j,
            jbody(
                {
                    "message": f"{method} {p}",
                    "query": sorted(parse_qsl(query, keep_blank_values=True)),
                    "sent": parsed,
                    "n": 1.5,
                    "big": 12345678901234567890,
                    "tiny": 1e-7,
                    "u": "é ",
                    "nested": {"a": [1, 2.5, None, True], "z": {}},
                    "success": True,
                },
            ),
        )


STUB = Stub()


def handler_class(stub):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            # Every header the client sent, Content-Length included.
            headers = sorted((k.lower(), v) for k, v in self.headers.items())
            with stub.lock:
                stub.captured.append((self.command, self.path, headers, body))
            status, ctype, payload = stub.answer(self.command, self.path, body)
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_stub():
    server = Server(("127.0.0.1", STUB_PORT), handler_class(STUB))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def self_signed():
    """A certificate for 127.0.0.1 no client trusts."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "uba.parity.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    folder = tempfile.mkdtemp(prefix="uba-parity-")
    cert_path, key_path = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def start_tls_stub():
    cert, key = self_signed()
    server = Server(("127.0.0.1", TLS_PORT), handler_class(STUB))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def outbound(requests):
    """What a backend sent, the Wazuh token fetch left out (each process caches its own)."""
    return [r for r in requests if not r[1].startswith("/wazuh/security/user/authenticate")]


# --- Seed ------------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, username=None, password=None, api_key=None, verified=1):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (:n, '3', :u, "
        "UTC_TIMESTAMP(), :user, :pw, :key, 'parity', 'parity', 1, :v, 0, 1, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
        key=api_key,
        v=verified,
    )


def uba_connector(url=None, key=UBA_KEY):
    set_connector("SOCFortress UBA", url if url is not None else f"http://127.0.0.1:{STUB_PORT}/uba/v1", api_key=key)


# Incident alerts (id, customer, verdict, tag): UBA alerts link to them by `copilot_alert_id`.
ALERT_A1, ALERT_A2, ALERT_A3, ALERT_B1, ALERT_GONE = 7_682_001, 7_682_002, 7_682_003, 7_682_011, 7_682_099
INCIDENTS = (
    (ALERT_A1, CUST_A, None, None),
    (ALERT_A2, CUST_A, "TRUE_POSITIVE", None),
    (ALERT_A3, CUST_A, None, 7_682_502),
    (ALERT_B1, CUST_B, None, None),
)
TAG_SEEN, TAG_HIDDEN = 7_682_501, 7_682_502


def wipe_incidents():
    ids = [i[0] for i in INCIDENTS]
    sql("DELETE FROM soc_sla_alert_tracking WHERE alert_id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM incident_management_alert_to_tag WHERE alert_id IN :i", i=ids)
    sql("DELETE FROM incident_management_alert WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)


def seed_rows(extra=None):
    """The rows every request starts from; `extra()` adjusts them."""
    uba_connector()
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog", "admin", "gl-pass")
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{STUB_PORT}/wazuh", "wazuh-wui", "wazuh-pass")
    sql("DELETE FROM audit_log WHERE actor_username IN :u", u=list(USERS))
    wipe_incidents()
    for alert_id, code, verdict, tag in INCIDENTS:
        sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
            "source, escalated, severity, verdict, verdict_by, verdict_at) VALUES (:i, :n, 'd', 'OPEN', '2026-10-01 00:00:00', :c, "
            "'uba', 0, 'High', :v, :by, :at)",
            i=alert_id,
            n=f"UBA alert {alert_id}",
            c=code,
            v=verdict,
            by="someone" if verdict else None,
            at="2026-10-02 00:00:00" if verdict else None,
        )
        if tag:
            sql("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)", a=alert_id, t=tag)
        sql(
            "INSERT INTO soc_sla_alert_tracking (alert_id, severity, opened_at, ack_due_at, resolve_due_at, tracked, updated_at, "
            "business_hours, reopen_count, paused_seconds, pause_credit_seconds) VALUES (:a, 'High', '2026-10-01 00:00:00', "
            "'2099-01-01 00:00:00', '2099-01-02 00:00:00', 1, '2026-10-01 00:00:00', 0, 0, 0, 0)",
            a=alert_id,
        )
    if extra:
        extra()


def seed():
    with sync_engine.connect() as conn:
        found = conn.execute(
            text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(bindparam("names", expanding=True)),
            {"names": list(OUR_CONNECTORS)},
        )
        SAVED_CONNECTORS.extend(dict(r._mapping) for r in found)
    SAVED_TAG_SETTINGS.extend(rows("SELECT * FROM incident_management_tag_access_settings"))
    for code in CUSTOMERS:
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=f"Name {code}")
    for name, role in ((ADMIN, 1), (ANALYST, 2), (ANALYST_B, 2), (PORTAL, 4), (UNICODE, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'u@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name, code in ((ANALYST, CUST_A), (ANALYST_B, CUST_B), (PORTAL, CUST_A), (UNICODE, CUST_A)):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=code,
            n=name,
        )
    for tag_id, name in ((TAG_SEEN, f"uba-seen-{SFX}"), (TAG_HIDDEN, f"uba-hidden-{SFX}")):
        sql("INSERT INTO incident_management_alerttag (id, tag) VALUES (:i, :t)", i=tag_id, t=name)
    sql(
        "INSERT INTO user_tag_access (user_id, tag_id, created_at) SELECT id, :t, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
        t=TAG_SEEN,
        n=ANALYST,
    )
    seed_rows()


SAVED_TAG_SETTINGS = []


def restrict_tags():
    """Tag RBAC on: the analyst sees untagged alerts and TAG_SEEN's."""
    sql("DELETE FROM incident_management_tag_access_settings")
    sql(
        "INSERT INTO incident_management_tag_access_settings (id, enabled, untagged_alert_behavior, default_tag_id, updated_at, "
        "updated_by) VALUES (1, 1, 'visible_to_all', NULL, UTC_TIMESTAMP(), 'parity')",
    )


def unrestrict_tags():
    sql("DELETE FROM incident_management_tag_access_settings")
    for row in SAVED_TAG_SETTINGS:
        sql(
            f"INSERT INTO incident_management_tag_access_settings ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})",
            **row,
        )


def cleanup():
    wipe_incidents()
    unrestrict_tags()
    sql("DELETE FROM user_tag_access WHERE tag_id IN :t", t=[TAG_SEEN, TAG_HIDDEN])
    sql("DELETE FROM incident_management_alerttag WHERE id IN :t", t=[TAG_SEEN, TAG_HIDDEN])
    sql("DELETE FROM audit_log WHERE actor_username IN :u", u=list(USERS))
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    sql("DELETE FROM customers WHERE customer_code IN :c", c=list(CUSTOMERS))
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)


def state():
    """The rows a request may have changed (ids and times masked)."""
    return {
        "audit": [
            {k: v for k, v in r.items() if k not in ("id", "timestamp")}
            for r in rows(
                "SELECT * FROM audit_log WHERE actor_username IN :u ORDER BY id",
                u=list(USERS),
            )
        ],
        "uba_connector": rows("SELECT connector_verified FROM connectors WHERE connector_name = 'SOCFortress UBA'"),
        "incidents": [
            {**r, "verdict_at": r["verdict_at"] is not None}
            for r in rows(
                "SELECT id, verdict, verdict_reason, verdict_note, verdict_by, verdict_at FROM incident_management_alert "
                "WHERE id BETWEEN :lo AND :hi ORDER BY id",
                lo=SEED_LO,
                hi=SEED_HI,
            )
        ],
        "sla": [
            {**r, "first_ack_at": r["first_ack_at"] is not None}
            for r in rows(
                "SELECT alert_id, first_ack_at, first_ack_by, first_ack_action FROM soc_sla_alert_tracking "
                "WHERE alert_id BETWEEN :lo AND :hi ORDER BY alert_id",
                lo=SEED_LO,
                hi=SEED_HI,
            )
        ],
    }


# --- The backends ------------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors
    from app.routers import uba

    api = APIRouter(prefix="/api")
    api.include_router(uba.router)
    api.include_router(connectors.router)
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


def start_python_legacy():
    code = (
        "import sys; sys.path.insert(0, %r); import rust_parity_uba_e2e as m; import uvicorn; "
        "uvicorn.run(m.build_python_app(), host='127.0.0.1', port=%d, log_level='warning')" % (HERE, PY_PORT)
    )
    env = {**os.environ, "PYTHONPATH": BACKEND}
    proc = subprocess.Popen([sys.executable, "-c", code], env=env, cwd=BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(PY_PORT, proc)
    return proc


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
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}",
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


def mask(value, keys):
    if isinstance(value, dict):
        return {k: ("<masked>" if k in keys and v is not None else mask(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, keys) for v in value]
    return value


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = {**FORWARDED, **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        STUB.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, outbound(STUB.take())

    async def same(self, name, method, path, tok=None, seed=True, before=None, stub=None, masked=(), view=None, expect=None, **kw):
        """Python, then Rust, each from the same rows (`seed`, then `before()`) and the same
        stand-in (`stub`: the keyword arguments of `Stub.reset`). `view` turns either side's state
        into what is compared; `expect=(python, rust)` statuses of a deliberate difference."""
        sides = []
        for client in (self.py, self.rs):
            if seed:
                seed_rows(before)
            elif before:
                before()
            STUB.reset(**(stub or {}))
            r, out = await self.call(client, method, path, tok, **kw)
            st = state()
            sides.append((r, out, view(st) if view else st))
        (r1, o1, s1), (r2, o2, s2) = sides
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2

        def norm(r):
            raw = r.content
            if not masked:
                return raw
            try:
                return json.dumps(mask(json.loads(raw), set(masked))).encode()
            except ValueError:
                return raw

        b1, b2 = norm(r1), norm(r2)
        ok = r1.status_code == r2.status_code and b1 == b2
        at = next((i for i, (x, y) in enumerate(zip(b1, b2)) if x != y), min(len(b1), len(b2)))
        start = max(0, at - 300)
        detail = (
            f"bodies differ at byte {at}\n        python {r1.status_code} {b1[start : at + 600]!r}\n"
            f"        rust   {r2.status_code} {b2[start : at + 600]!r}"
        )
        if o1 != o2:
            ok = False
            first = next((i for i, (x, y) in enumerate(zip(o1, o2)) if x != y), min(len(o1), len(o2)))
            detail += f"\n        outbound differ at {first} of {len(o1)}/{len(o2)}\n        python {o1[first:first + 2]}\n        rust   {o2[first:first + 2]}"
        if s1 != s2:
            ok = False
            diff = {k: (s1[k], s2[k]) for k in s1 if s1[k] != s2.get(k)}
            detail += f"\n        state differs: {diff}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:800]!r}\n        outbound {[(m, p, b[:300]) for m, p, h, b in o1]}")
        return r1, r2

    async def close(self):
        for c in (self.py, self.rs):
            await c.aclose()


# --- A: the proxy routes -----------------------------------------------------------------------------

U = "/api/uba"


def reply(status, payload, ctype="application/json"):
    """A stand-in answer: JSON unless `payload` is bytes already."""
    return status, ctype, payload if isinstance(payload, bytes) else jbody(payload)


def connector_id():
    return rows("SELECT id FROM connectors WHERE connector_name = 'SOCFortress UBA'")[0]["id"]


async def proxy_checks(p, t):
    a, b = f"{U}/{CUST_A}", f"{U}/{CUST_B}"

    # Availability: the connector row only.
    await p.same("availability", "GET", f"{U}/availability", t["analyst"])
    await p.same("availability without a token", "GET", f"{U}/availability")
    await p.same("availability for a portal user", "GET", f"{U}/availability", t["portal"])
    await p.same("availability, no key", "GET", f"{U}/availability", t["admin"], before=lambda: uba_connector(key="  "))
    await p.same(
        "availability, not installed",
        "GET",
        f"{U}/availability",
        t["admin"],
        before=lambda: sql("DELETE FROM connectors WHERE connector_name = 'SOCFortress UBA'"),
    )

    # Status: UBA's row for the tenant, lazily found.
    await p.same("status", "GET", f"{a}/status", t["analyst"])
    await p.same("status of another tenant", "GET", f"{b}/status", t["analyst"])
    await p.same("status of an unknown tenant", "GET", f"{b}/status", t["admin"])
    await p.same(
        "status, a non-dict tenant after the match",
        "GET",
        f"{a}/status",
        t["admin"],
        stub={"overrides": {("GET", "/uba/v1/status"): reply(200, {"tenants": [{"tenant": CUST_A}, 5]})}},
    )
    await p.same(
        "status, a non-dict tenant before the match",
        "GET",
        f"{a}/status",
        t["admin"],
        stub={"overrides": {("GET", "/uba/v1/status"): reply(200, {"tenants": [5, {"tenant": CUST_A}]})}},
    )
    await p.same(
        "status, a version Pydantic refuses",
        "GET",
        f"{a}/status",
        t["admin"],
        stub={"overrides": {("GET", "/uba/v1/status"): reply(200, {"version": 1.5, "tenants": []})}},
    )
    await p.same(
        "status, a tenant row Pydantic refuses",
        "GET",
        f"{a}/status",
        t["admin"],
        stub={
            "overrides": {("GET", "/uba/v1/status"): reply(200, {"tenants": [{"tenant": CUST_A, "alerts_24h": 1.5, "lag_seconds": "x"}]})},
        },
    )
    await p.same(
        "status, a list answer",
        "GET",
        f"{a}/status",
        t["admin"],
        stub={"overrides": {("GET", "/uba/v1/status"): reply(200, [])}},
    )

    # Entities and their query.
    await p.same("entities", "GET", f"{a}/entities", t["analyst"])
    await p.same(
        "entities, every parameter",
        "GET",
        f"{a}/entities?entity_type=actor&q=j%C3%A9+d&min_risk=1e-5&native=OFF&page=2&page_size=500",
        t["analyst"],
    )
    await p.same("entities, inf risk", "GET", f"{a}/entities?min_risk=inf&q=", t["analyst"])
    # (Python's log writer fails on a URL over 256 characters: kept short.)
    await p.same("entities, invalid query", "GET", f"{a}/entities?min_risk=nan&native=%20true&page=0&page_size=501", t["analyst"])
    await p.same("entities, a long q", "GET", f"{a}/entities?q={'x' * 201}", t["analyst"])
    await p.same("entities of another tenant, invalid query", "GET", f"{b}/entities?page=0", t["analyst"])
    for key in ("upn:jane@contoso.com", "windows-demo\\jdoe", "é/ü ?#&", ".."):
        await p.same(f"entity {key!r}", "GET", f"{a}/entity", t["analyst"], params={"entity_key": key})
    await p.same("entity, no key", "GET", f"{a}/entity", t["analyst"])
    await p.same(
        "risk history",
        "GET",
        f"{a}/entity/risk-history",
        t["analyst"],
        params={"entity_key": "upn:jane", "since": "7d", "step": "6h"},
    )
    await p.same("risk history, bad step", "GET", f"{a}/entity/risk-history?entity_key=&step=2h", t["analyst"])
    await p.same(
        "timeline",
        "GET",
        f"{a}/entity/timeline",
        t["analyst"],
        params={"entity_key": "k", "page": " 3 ", "page_size": "5.0"},
    )
    await p.same(
        "signals",
        "GET",
        f"{a}/signals",
        t["analyst"],
        params=[("rule_id", "r1"), ("entity_key", "k"), ("since", "1h"), ("until", ""), ("include_native", "yes"), ("page", "1_0")],
    )
    await p.same("alerts", "GET", f"{a}/alerts?status=open&entity_key=k&since=1d&page_size=2", t["analyst"])
    await p.same("alerts, bad status", "GET", f"{a}/alerts?status=OPEN", t["analyst"])
    for alert_id in ("42", "a b", "é", "%2E%2E"):
        await p.same(f"alert {alert_id!r}", "GET", f"{a}/alerts/{alert_id}", t["analyst"])
    await p.same("evidence", "GET", f"{a}/signals/sig%3A1/evidence", t["analyst"])

    # Suppressions.
    await p.same("suppressions", "GET", f"{a}/suppressions?include_expired=1", t["analyst"])
    await p.same(
        "suppress",
        "POST",
        f"{a}/suppressions",
        t["analyst"],
        json={"entity_key": "upn:jane@contoso.com", "rule_ids": ["r1", "r2"], "days": "7", "reason": "é"},
    )
    await p.same("suppress, defaults", "POST", f"{a}/suppressions", t["admin"], json={"entity_key": "k", "rule_ids": ["r1"]})
    await p.same(
        "suppress, invalid body",
        "POST",
        f"{a}/suppressions",
        t["analyst"],
        json={"entity_key": "", "rule_ids": [1, None], "days": 366, "reason": "r" * 501},
    )
    await p.same("suppress, empty rules", "POST", f"{a}/suppressions", t["analyst"], json={"entity_key": "k", "rule_ids": []})
    await p.same("suppress, no body", "POST", f"{a}/suppressions", t["analyst"])
    await p.same("suppress, a list body", "POST", f"{a}/suppressions", t["analyst"], json=[1])
    await p.same(
        "suppress, not JSON",
        "POST",
        f"{a}/suppressions",
        t["analyst"],
        content=b"entity_key=k",
        headers={"Content-Type": "text/plain"},
    )
    await p.same(
        "suppress, malformed JSON without a token",
        "POST",
        f"{a}/suppressions",
        None,
        content=b"{",
        headers={"Content-Type": "application/json"},
    )
    await p.same("suppress for another tenant", "POST", f"{b}/suppressions", t["analyst"], json={"entity_key": "k"})
    await p.same("unsuppress", "DELETE", f"{a}/suppressions?entity_key=upn%3Aj&rule_id=r1", t["analyst"])
    await p.same("unsuppress all", "DELETE", f"{a}/suppressions?entity_key=k", t["analyst"])
    await p.same("unsuppress, no key", "DELETE", f"{a}/suppressions", t["analyst"])
    await p.same("suppress, a non-ASCII actor", "POST", f"{a}/suppressions", t["unicode"], json={"entity_key": "k", "rule_ids": ["r"]})

    # Identities.
    await p.same("identity review", "GET", f"{a}/identities/review?include_reviewed=true", t["analyst"])
    await p.same("identity search", "GET", f"{a}/identities?q=ja", t["analyst"])
    await p.same("identity search, short", "GET", f"{a}/identities?q=j", t["analyst"])
    await p.same("merge", "POST", f"{a}/identities/merge?identity_id=id%2F1", t["admin"], json={"into": "id-2"})
    await p.same("merge by an analyst", "POST", f"{a}/identities/merge?identity_id=1", t["analyst"], json={"into": "x"})
    await p.same("merge, invalid", "POST", f"{a}/identities/merge?identity_id=", t["admin"], json={"into": "x" * 65})
    await p.same("reviewed", "POST", f"{a}/identities/reviewed?identity_id=i1&reviewed=false", t["admin"])
    await p.same("reviewed, default", "POST", f"{a}/identities/reviewed?identity_id=i1", t["admin"], json={"ignored": True})
    await p.same("dismiss", "POST", f"{a}/identity-candidates/0042/dismiss", t["admin"])
    await p.same("dismiss, not an int", "POST", f"{a}/identity-candidates/4.5/dismiss", t["admin"])
    await p.same("dismiss, a huge int", "POST", f"{a}/identity-candidates/123456789012345678901234/dismiss", t["admin"])
    await p.same("dismiss, another tenant", "POST", f"{b}/identity-candidates/x/dismiss", t["analyst"])
    await p.same("identity sources", "GET", f"{a}/identity-sources", t["analyst"])
    await p.same("identity source test", "POST", f"{a}/identity-sources/src%201/test", t["admin"])
    await p.same("identity source sync", "POST", f"{a}/identity-sources/src-1/sync", t["admin"])
    await p.same("identity source sync by an analyst", "POST", f"{a}/identity-sources/src-1/sync", t["analyst"])

    # About, rules, backtests, settings.
    await p.same("about", "GET", f"{a}/about", t["analyst"])
    await p.same(
        "about, a list answer",
        "GET",
        f"{a}/about",
        t["analyst"],
        stub={"overrides": {("GET", "/uba/v1/about"): reply(200, [1, 2])}},
    )
    await p.same("rule catalog", "GET", f"{a}/rules/catalog", t["analyst"])
    await p.same(
        "rule catalog, a dict answer",
        "GET",
        f"{a}/rules/catalog",
        t["analyst"],
        stub={"overrides": {("GET", "/uba/v1/rules"): reply(200, {"rules": []})}},
    )
    await p.same("backtest, defaults", "POST", f"{a}/backtests", t["analyst"], json={})
    await p.same(
        "backtest",
        "POST",
        f"{a}/backtests",
        t["analyst"],
        json={"days": 2, "warmup_days": "1.5", "rules": ["r1"], "filter": "user:é"},
    )
    await p.same(
        "backtest, invalid",
        "POST",
        f"{a}/backtests",
        t["analyst"],
        json={"days": 0, "warmup_days": 15, "rules": "r1", "filter": None},
    )
    await p.same("backtests", "GET", f"{a}/backtests?limit=100", t["analyst"])
    await p.same("backtests, limit", "GET", f"{a}/backtests?limit=101", t["analyst"])
    await p.same("backtest one", "GET", f"{a}/backtests/job%201", t["analyst"])
    await p.same("backtest cancel", "POST", f"{a}/backtests/job-1/cancel", t["analyst"])
    await p.same("rule stats", "GET", f"{a}/rules/stats", t["analyst"])
    await p.same("rule stats since", "GET", f"{a}/rules/stats?since=2026-10-01T00:00:00Z", t["analyst"])
    await p.same("rule settings", "GET", f"{a}/rule-settings", t["analyst"])
    await p.same("rule setting", "PUT", f"{a}/rule-settings/r%2F1", t["admin"], json={"enabled": "off", "score": "12.5"})
    await p.same("rule setting, unset", "PUT", f"{a}/rule-settings/r1", t["admin"], json={"score": None})
    await p.same("rule setting, empty", "PUT", f"{a}/rule-settings/r1", t["admin"], json={})
    await p.same("rule setting, invalid", "PUT", f"{a}/rule-settings/r1", t["admin"], json={"enabled": "maybe", "score": 101})
    await p.same("rule setting reset", "DELETE", f"{a}/rule-settings/r1", t["admin"])
    await p.same("risk policy", "PUT", f"{a}/risk-policy", t["admin"], json={"alert_threshold": True})
    await p.same("risk policy, too low", "PUT", f"{a}/risk-policy", t["admin"], json={"alert_threshold": 19.99})
    await p.same("risk policy reset", "DELETE", f"{a}/risk-policy", t["admin"])
    await p.same("native overrides", "GET", f"{a}/native-overrides?integration=office365", t["analyst"])
    await p.same("native override", "PUT", f"{a}/native-overrides/100002", t["admin"], json={"score": 0})
    await p.same("native override, invalid", "PUT", f"{a}/native-overrides/100002?integration=x", t["admin"], json={"score": -1})
    await p.same("native override delete", "DELETE", f"{a}/native-overrides/100002?integration=wazuh", t["admin"])
    await p.same("native override delete by an analyst", "DELETE", f"{a}/native-overrides/1", t["analyst"])
    await p.same("a method the route does not take", "PATCH", f"{a}/risk-policy", t["admin"], json={})

    # UBA's failures.
    alert = "/uba/v1/tenants/" + CUST_A + "/alerts/x"
    for label, answer in (
        ("401", reply(401, {"detail": "bad key"})),
        ("403 detail", reply(403, {"detail": "scope é"})),
        ("403 no body", reply(403, b"")),
        ("404 detail list", reply(404, {"detail": [{"loc": ["path", 1, None, 1.5, True], "msg": {"m": 1}}]})),
        ("404 detail list, loc a string", reply(404, {"detail": [{"loc": "abc"}]})),
        ("404 detail list, not a dict", reply(404, {"detail": ["x"]})),
        ("404 detail list, loc an int", reply(404, {"detail": [{"loc": 5}]})),
        ("404 detail dict", reply(404, {"detail": {"a": 1}})),
        ("404 text", reply(404, b"not json", "text/plain")),
        ("422", reply(422, {"detail": "bad"})),
        ("422 empty list", reply(422, {"detail": []})),
        ("500", reply(500, {"detail": "boom"})),
        ("302", reply(302, b"")),
        ("not JSON", reply(200, b"<html>", "text/html")),
        ("JSON null", reply(200, b"null")),
        ("JSON NaN", reply(200, b'{"n": NaN, "i": Infinity}')),
        ("success a string", reply(200, {"success": "nope"})),
        ("message an int", reply(200, {"message": 5, "success": 0})),
        ("a list", reply(200, [1])),
        ("UTF-16", reply(200, json.dumps({"u": "é"}).encode("utf-16"))),
    ):
        await p.same(f"UBA answers {label}", "GET", f"{a}/alerts/x", t["analyst"], stub={"overrides": {("GET", alert): answer}})
    await p.same(
        "UBA unreachable",
        "GET",
        f"{a}/alerts/x",
        t["analyst"],
        before=lambda: uba_connector(url=f"http://127.0.0.1:{CLOSED_PORT}/"),
    )
    await p.same(
        "UBA over HTTPS with an untrusted certificate",
        "GET",
        f"{a}/alerts/x",
        t["analyst"],
        before=lambda: uba_connector(url=f"https://127.0.0.1:{TLS_PORT}/uba"),
    )
    await p.same(
        "UBA URL without a scheme",
        "GET",
        f"{a}/rules/catalog",
        t["analyst"],
        before=lambda: uba_connector(url="uba.local:8010"),
    )
    await p.same(
        "UBA URL with a bad port",
        "GET",
        f"{a}/rules/catalog",
        t["analyst"],
        before=lambda: uba_connector(url="http://127.0.0.1:x/"),
    )
    await p.same(
        "no connector",
        "GET",
        f"{a}/about",
        t["analyst"],
        before=lambda: sql("DELETE FROM connectors WHERE connector_name = 'SOCFortress UBA'"),
    )
    await p.same("no URL", "GET", f"{a}/about", t["analyst"], before=lambda: uba_connector(url=" /v1"))

    # The connector check (/api/connectors/verify/{id}).
    def verify(name, stub=None, before=None):
        return p.same(name, "POST", f"/api/connectors/verify/{connector_id()}", t["admin"], stub=stub, before=before)

    await verify("connector check")
    await verify("connector check, UBA refuses", stub={"overrides": {("GET", "/uba/v1/status"): reply(401, b"")}})
    await verify(
        "connector check, a non-string tenant",
        stub={"overrides": {("GET", "/uba/v1/status"): reply(200, {"tenants": [{"tenant": 1}]})}},
    )
    await verify("connector check, unreachable", before=lambda: uba_connector(url=f"http://127.0.0.1:{CLOSED_PORT}"))


# --- B: the verdict on the incident alert (#1239) -----------------------------------------------------


def uba_alert(alert_id, linked, entity_key="upn:jane@contoso.com", **extra):
    path = f"/uba/v1/tenants/{CUST_A}/alerts/{alert_id}"
    payload = {"alert": {"id": alert_id, "copilot_alert_id": linked, "entity_key": entity_key, **extra}}
    return ("GET", path), reply(200, payload)


def open_alerts(*alerts):
    return ("GET", f"/uba/v1/tenants/{CUST_A}/alerts?*"), reply(200, {"alerts": list(alerts), "total": len(alerts)})


async def verdict_checks(p, t):
    def fb(alert_id):
        return f"{U}/{CUST_A}/alerts/{alert_id}/feedback"

    tp, fp = {"verdict": "TRUE_POSITIVE", "note": "seen"}, {"verdict": "FALSE_POSITIVE", "reason": "AUTHORIZED_USER"}
    unsuppressed = {"verdict": "FALSE_POSITIVE", "suppress": False, "reason": "made up"}

    def stub(*overrides):
        return {"overrides": dict(overrides)}

    await p.same("verdict recorded", "POST", fb("u1"), t["analyst"], json=tp, stub=stub(uba_alert("u1", ALERT_A1)))
    await p.same("verdict recorded by an admin", "POST", fb("u1"), t["admin"], json=fp, stub=stub(uba_alert("u1", ALERT_A1)))
    await p.same(
        "false positive, a reason CoPilot does not know",
        "POST",
        fb("u1"),
        t["analyst"],
        json={"verdict": "FALSE_POSITIVE", "reason": "noise", "suppress_days": 5},
        stub=stub(uba_alert("u1", ALERT_A1)),
    )
    await p.same(
        "unsuppressed false positive, an open sibling",
        "POST",
        fb("u1"),
        t["analyst"],
        json=unsuppressed,
        stub=stub(
            uba_alert("u1", ALERT_A1),
            open_alerts(
                {"id": "u1", "copilot_alert_id": ALERT_A1},
                {"id": "u2", "copilot_alert_id": float(ALERT_A1)},
                {"id": "u3", "copilot_alert_id": 1},
            ),
        ),
    )
    await p.same(
        "unsuppressed false positive, the only open one listed",
        "POST",
        fb("u1"),
        t["analyst"],
        json=unsuppressed,
        stub=stub(uba_alert("u1", ALERT_A1), open_alerts({"id": "u1", "copilot_alert_id": ALERT_A1})),
    )
    await p.same(
        "unsuppressed false positive, no entity key",
        "POST",
        fb("u1"),
        t["analyst"],
        json=unsuppressed,
        stub=stub(uba_alert("u1", ALERT_A1, entity_key=None), open_alerts()),
    )
    await p.same(
        "unsuppressed false positive, a non-dict sibling",
        "POST",
        fb("u1"),
        t["analyst"],
        json=unsuppressed,
        stub=stub(uba_alert("u1", ALERT_A1), open_alerts(5)),
    )
    await p.same(
        "unsuppressed false positive, UBA's list fails",
        "POST",
        fb("u1"),
        t["analyst"],
        json=unsuppressed,
        stub=stub(uba_alert("u1", ALERT_A1), (("GET", f"/uba/v1/tenants/{CUST_A}/alerts?*"), reply(503, b""))),
    )
    await p.same("not linked", "POST", fb("u1"), t["analyst"], json=tp, stub=stub(uba_alert("u1", None)))
    await p.same(
        "no alert in UBA's answer",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        stub=stub((("GET", f"/uba/v1/tenants/{CUST_A}/alerts/u1"), reply(200, {"other": 1}))),
    )
    await p.same(
        "UBA's alert is a list",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        stub=stub((("GET", f"/uba/v1/tenants/{CUST_A}/alerts/u1"), reply(200, {"alert": [1]}))),
    )
    await p.same("the incident alert is gone", "POST", fb("u1"), t["analyst"], json=tp, stub=stub(uba_alert("u1", ALERT_GONE)))
    await p.same("already has a verdict", "POST", fb("u1"), t["analyst"], json=fp, stub=stub(uba_alert("u1", ALERT_A2)))
    await p.same("another customer's incident alert", "POST", fb("u1"), t["admin"], json=tp, stub=stub(uba_alert("u1", ALERT_B1)))
    await p.same(
        "an incident alert the analyst's tags do not reach",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        before=restrict_tags,
        stub=stub(uba_alert("u1", ALERT_A3)),
    )
    unrestrict_tags()
    await p.same(
        "an incident alert reached by tags",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        before=restrict_tags,
        stub=stub(uba_alert("u1", ALERT_A1)),
    )
    unrestrict_tags()
    for label, linked in (
        ("a string id", str(ALERT_A1)),
        ("a padded string id", f" {ALERT_A1} "),
        ("a string id MySQL reads as a number", f"{ALERT_A1}abc"),
        ("a float id", float(ALERT_A1)),
        ("a fractional id", ALERT_A1 + 0.5),
        ("a list id", [ALERT_A1]),
        ("a nested list id", [[str(ALERT_A1)]]),
        ("a list of two ids", [ALERT_A1, ALERT_A2]),
        ("a list of null", [None]),
        ("a dict id", {"id": ALERT_A1}),
        ("a huge id", 10**30),
        ("true", True),
    ):
        await p.same(f"copilot_alert_id {label}", "POST", fb("u1"), t["admin"], json=tp, stub=stub(uba_alert("u1", linked)))
    await p.same(
        "UBA refuses the verdict",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        stub=stub((("POST", f"/uba/v1/tenants/{CUST_A}/alerts/u1/feedback"), reply(401, b""))),
    )
    await p.same(
        "UBA answers the verdict with an incident field",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        stub=stub(
            uba_alert("u1", ALERT_A1),
            (("POST", f"/uba/v1/tenants/{CUST_A}/alerts/u1/feedback"), reply(200, {"incident": "mine"})),
        ),
    )
    await p.same(
        "UBA's alert lookup fails",
        "POST",
        fb("u1"),
        t["analyst"],
        json=tp,
        stub=stub((("GET", f"/uba/v1/tenants/{CUST_A}/alerts/u1"), reply(404, {"detail": "gone"}))),
    )
    await p.same("verdict, invalid body", "POST", fb("u1"), t["analyst"], json={"verdict": "maybe", "suppress_days": 0})
    await p.same("verdict for another tenant", "POST", f"{U}/{CUST_B}/alerts/u1/feedback", t["analyst"], json=tp)
    await p.same("verdict without a token", "POST", fb("u1"), json=tp)


async def main():
    server = start_stub()
    tls = start_tls_stub()
    procs = []
    try:
        seed()
        procs.append(start_python_legacy())
        procs.append(start_rust())
        p = Pair()
        t = {
            "admin": token(ADMIN, ["admin"]),
            "analyst": token(ANALYST, ["analyst"]),
            "analyst_b": token(ANALYST_B, ["analyst"]),
            "portal": token(PORTAL, ["customer_user"]),
            "unicode": token(UNICODE, ["analyst"]),
        }
        try:
            sections = os.environ.get("UBA_PARITY_SECTIONS", "proxy,verdict").split(",")
            if "proxy" in sections:
                await proxy_checks(p, t)
            if "verdict" in sections:
                await verdict_checks(p, t)
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
            server.shutdown()
            tls.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
