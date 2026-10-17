"""Parity of the OpenCTI and Cortex connectors (`crates/copilot-intel-connectors`) with this
backend — NOT collected by pytest (needs a live MySQL and the Rust binary; run by
scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts (no legacy backend,
connector cache off) answer the same requests on one database. OpenCTI and Cortex are local
stand-ins that record every request — method, target, **every header in the order it was sent**
(Content-Length and Host included) and the body bytes — and both backends' requests are compared
one by one:

* OpenCTI (GraphQL over httpx): the platform info, the IOC lookups, a multi-page indicator walk,
  entities, and every failure shape — `errors` at HTTP 200 (a revoked token), an HTTP error, a
  non-JSON or non-object answer, a closed port, a URL httpx refuses, an API key h11 refuses — over
  HTTP and over HTTPS with a self-signed certificate (`verify=False`);
* Cortex (cortex4py over requests): the analyzer list and a run with its job polling (one 5 s
  poll), odd answers the library's objects choke on, every HTTP error class, a closed port, URLs
  requests refuses;
* the two connectors' verification through `POST /api/connectors/verify/{id}` (the row it writes).

Sublime stays in Python (its tables are not created by Alembic); one check here confirms what
Python answers for it today.

    PARITY_SUITES=tests/e2e/rust_parity_intel_connectors_e2e.py scripts/rust-parity.sh

Ports (all overridable, defaults in the suite's own range): INTEL_PARITY_RUST_PORT,
INTEL_OPENCTI_STUB_PORT, INTEL_OPENCTI_TLS_STUB_PORT, INTEL_CORTEX_STUB_PORT,
INTEL_CORTEX_TLS_STUB_PORT.
"""

import asyncio
import copy
import datetime
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
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
# instance below does.
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

import httpx  # noqa: E402
import jwt  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("INTEL_PARITY_RUST_PORT", "6470"))
OPENCTI_PORT = int(os.environ.get("INTEL_OPENCTI_STUB_PORT", "6471"))
OPENCTI_TLS_PORT = int(os.environ.get("INTEL_OPENCTI_TLS_STUB_PORT", "6472"))
CORTEX_PORT = int(os.environ.get("INTEL_CORTEX_STUB_PORT", "6473"))
CORTEX_TLS_PORT = int(os.environ.get("INTEL_CORTEX_TLS_STUB_PORT", "6474"))
#: A port nothing listens on.
CLOSED_PORT = 1
OUR_CONNECTORS = ("OpenCTI", "Cortex")

SFX = uuid.uuid4().hex[:6]
ADMIN, ANALYST, PORTAL = f"ic_admin{SFX}", f"ic_analyst{SFX}", f"ic_portal{SFX}"
USERS = (ADMIN, ANALYST, PORTAL)
OPENCTI_KEY = f"opencti-key-{SFX}"
CORTEX_KEY = f"cortex-key-{SFX}"
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


# --- The stand-ins -----------------------------------------------------------------------------------


class Recorder:
    """What a stand-in was asked: (method, target, [(header, value), …] in the order they came,
    body). Nothing is dropped or normalized."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.connections = 0

    def add(self, method, target, headers, body):
        with self.lock:
            self.requests.append((method, target, list(headers), body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
            self.connections = 0
        return out


def make_tls():
    """A self-signed certificate for `localhost` (not the 127.0.0.1 the clients dial): neither the
    issuer nor the name verifies, which `verify=False` must not mind."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    workdir = tempfile.mkdtemp(prefix="intel-parity-")
    cert_path, key_path = os.path.join(workdir, "cert.pem"), os.path.join(workdir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def start_stub(port, answer, recorder, tls=None):
    """A threaded HTTP/1.1 server; `answer(method, target, headers, body)` returns
    (status, content_type, body bytes)."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            with recorder.lock:
                recorder.connections += 1

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            recorder.add(self.command, self.path, self.headers.items(), body)
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
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def as_json(status, value):
    return status, "application/json", json.dumps(value).encode()


# --- OpenCTI -----------------------------------------------------------------------------------------

LABELS = [{"value": "malware", "color": "#ff0000"}, {"value": "", "color": "#00ff00"}, None, {"value": "c2"}]
MARKINGS = [{"definition": "TLP:CLEAR"}, {"definition": None}, {}, None, {"definition": "PAP:GREEN"}]


def indicator_node(n, **over):
    node = {
        "id": f"ind-{n}",
        "standard_id": f"indicator--{n}",
        "entity_type": "Indicator",
        "created_at": "2026-01-02T03:04:05.000Z",
        "updated_at": "2026-01-03T03:04:05.000Z",
        "createdBy": {"name": "SOCFortress"},
        "objectLabel": LABELS,
        "objectMarking": MARKINGS,
        "name": f"bad{n}.example",
        "description": "A bad domain",
        "pattern": f"[domain-name:value = 'bad{n}.example']",
        "pattern_type": "stix",
        "x_opencti_main_observable_type": "Domain-Name",
        "x_opencti_score": 80,
        "confidence": 75,
        "valid_from": "2026-01-01T00:00:00.000Z",
        "valid_until": None,
        "revoked": False,
    }
    node.update(over)
    return node


SHA = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"


def observable_node(value="bad.example", **over):
    node = {
        "id": f"obs-{value}",
        "standard_id": f"domain-name--{value}",
        "entity_type": "Domain-Name",
        "created_at": "2026-01-02T03:04:05.000Z",
        "updated_at": None,
        "createdBy": None,
        "objectLabel": LABELS,
        "objectMarking": MARKINGS,
        "observable_value": value,
        "x_opencti_description": None,
        "x_opencti_score": "50",
        "name": "evil.exe",
        "hashes": [{"algorithm": "SHA-256", "hash": SHA}, {"algorithm": "MD5", "hash": ""}, None],
        "indicators": {"pageInfo": {"globalCount": 3}, "edges": [{"node": indicator_node(1)}, {"node": None}, None]},
        "reports": {"pageInfo": {"globalCount": 1}, "edges": [{"node": {"id": "rep-1", "name": "A report", "published": "2026-01-01"}}]},
    }
    node.update(over)
    return node


def entity_node(**over):
    node = {
        "id": "rep-1",
        "standard_id": "report--1",
        "entity_type": "Report",
        "created_at": "2026-01-02T03:04:05.000Z",
        "updated_at": "2026-01-02T03:04:05.000Z",
        "createdBy": {"name": "CERT"},
        "objectLabel": [],
        "objectMarking": [{"definition": "TLP:AMBER"}],
        "parent_types": ["Basic-Object", "Stix-Object", "Stix-Domain-Object"],
        "representative": {"main": "A report", "secondary": "What it says"},
        "externalReferences": {
            "edges": [{"node": {"source_name": "cert", "url": "https://cert.example/1", "external_id": "X-1", "description": None}}],
        },
        "confidence": 90,
    }
    node.update(over)
    return node


INDICATOR_PAGES = [indicator_node(n) for n in range(1, 6)]


class OpenCti:
    """GraphQL by operation name; `override(op, variables)` (when set) answers first: a tuple
    (status, content_type, bytes) or None for the default."""

    def __init__(self):
        self.override = None

    def __call__(self, method, target, headers, body):
        try:
            doc = json.loads(body)
        except ValueError:
            return as_json(400, {"errors": [{"message": "not JSON"}]})
        query, variables = doc.get("query", ""), doc.get("variables") or {}
        op = re.search(r"(?:query|mutation)\s+(\w+)", query)
        op = op.group(1) if op else ""
        if self.override:
            answer = self.override(op, variables)
            if answer is not None:
                return answer
        if op in ("CoPilotAbout", "CoPilotVerify"):
            return as_json(
                200,
                {
                    "data": {
                        "about": {"version": "6.4.2", "dependencies": [{"name": "Elasticsearch", "version": "8.13"}, {"name": "RabbitMQ"}]},
                        "me": {"name": "copilot", "user_email": "copilot@example.com"},
                    },
                },
            )
        if op == "CoPilotObservableLookup":
            values = variables["filters"]["filters"][0]["values"]
            nodes = []
            for v in values:
                if v.lower() in ("bad.example", SHA.lower()):
                    nodes.append(observable_node())
                elif v == "twin.example":
                    nodes.append(observable_node("twin.example", entity_type="Hostname", id="obs-twin-host"))
                    nodes.append(observable_node("TWIN.example", id="obs-twin-domain"))
            return as_json(
                200,
                {"data": {"stixCyberObservables": {"pageInfo": {"globalCount": len(nodes)}, "edges": [{"node": n} for n in nodes]}}},
            )
        if op == "CoPilotIndicators":
            first, after = variables.get("first") or 25, variables.get("after")
            start = int(after[1:]) if after else 0
            page = INDICATOR_PAGES[start : start + first]
            end = start + len(page)
            info = {"globalCount": len(INDICATOR_PAGES), "hasNextPage": end < len(INDICATOR_PAGES), "endCursor": f"c{end}" if page else ""}
            return as_json(200, {"data": {"indicators": {"pageInfo": info, "edges": [{"node": n} for n in page]}}})
        if op == "CoPilotEntity":
            node = entity_node(id=variables["id"]) if variables.get("id") != "missing" else None
            return as_json(200, {"data": {"stixCoreObject": node}})
        return as_json(
            200,
            {"errors": [{"message": f"Unknown operation {op}", "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}}], "data": None},
        )


OPENCTI = OpenCti()
OPENCTI_RECORDER = Recorder()


# --- Cortex ------------------------------------------------------------------------------------------


class Cortex:
    """cortex4py's endpoints, answered from `mode` (reset before each backend's call)."""

    def __init__(self):
        self.reset()

    def reset(self, **mode):
        self.mode = {
            "list": [{"id": "an-1", "name": "VirusTotal_GetReport_3_1", "_secret": "x"}, {"id": "an 2/x", "name": "Abuse_Finder_3_0"}],
            "run": {"id": "job-1", "status": "Success", "_type": "job"},
            "polls": [],
            "report": {
                "id": "job-1",
                "status": "Success",
                "report": {"full": {"verdict": "malicious", "score": 8.5, "items": [1, None]}, "summary": {}},
            },
            # Each backend gets its own copy: the polls are consumed.
            **copy.deepcopy(mode),
        }

    def __call__(self, method, target, headers, body):
        m = self.mode
        if "status" in m:
            return m["status"]
        path, _, query = target.partition("?")
        path = path.replace("//", "/")
        if method == "POST" and path == "/api/analyzer/_search" and query == "range=all":
            return self._answer(m["list"])
        if method == "POST" and path == "/api/analyzer/_search":
            if "by_name" in m:
                return self._answer(m["by_name"])
            wanted = json.loads(body)["query"]["_value"]
            return self._answer([a for a in m["list"] if isinstance(a, dict) and a.get("name") == wanted][:1])
        if method == "POST" and path.endswith("/run"):
            return self._answer(m["run"])
        if method == "GET" and path.endswith("/report"):
            return self._answer(m["report"])
        if method == "GET" and path.startswith("/api/job/"):
            polls = m["polls"]
            return self._answer(polls.pop(0) if polls else {"id": "job-1", "status": "Success"})
        return as_json(404, {"type": "NotFound"})

    @staticmethod
    def _answer(value):
        if isinstance(value, tuple):
            return value
        return as_json(200, value)


CORTEX = Cortex()
CORTEX_RECORDER = Recorder()
RECORDERS = (OPENCTI_RECORDER, CORTEX_RECORDER)


# --- Database ----------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, api_key=None, extra=None, verified=1):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    if url is None:
        return
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) "
        "VALUES (:n, '3', :u, UTC_TIMESTAMP(), NULL, NULL, :key, 'parity', 'parity', 1, :v, 0, 1, 0, 0, 1, :x, 1)",
        n=name,
        u=url,
        key=api_key,
        x=extra,
        v=verified,
    )


def connector_id(name):
    with sync_engine.connect() as conn:
        return conn.execute(text("SELECT id FROM connectors WHERE connector_name = :n"), {"n": name}).scalar()


def connector_verified(name):
    with sync_engine.connect() as conn:
        return conn.execute(text("SELECT connector_verified FROM connectors WHERE connector_name = :n"), {"n": name}).scalar()


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


def cleanup():
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)


# --- The two backends --------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors
    from app.routers import cortex
    from app.routers import opencti
    from app.routers import sublime

    api = APIRouter(prefix="/api")
    api.include_router(opencti.router)
    api.include_router(cortex.router)
    api.include_router(sublime.router)
    api.include_router(connectors.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port):
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


RESPONSE_HEADERS = ("content-type", "content-length")


def outbound(requests_):
    """Every request, the headers in the order they were sent."""
    return [(m, t, h, b) for m, t, h, b in requests_]


class Pair:
    def __init__(self, rust_port):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{rust_port}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = {"Accept-Encoding": "identity", **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        for recorder in RECORDERS:
            recorder.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0.05)
        out = [(rec_name, req) for rec_name, recorder in zip(("opencti", "cortex"), RECORDERS) for req in recorder.take()]
        return r, out

    async def same(self, name, method, path, tok=None, before=None, expect=None, table=None, **kw):
        """Python, then Rust, with the stand-ins reset by `before` for each. `expect` is a status
        both must answer; `table` returns a value both must leave alike."""
        if before:
            before()
        r1, out1 = await self.call(self.py, method, path, tok, **kw)
        t1 = table() if table else None
        if before:
            before()
        r2, out2 = await self.call(self.rs, method, path, tok, **kw)
        t2 = table() if table else None
        b1, b2 = r1.content, r2.content
        ok = r1.status_code == r2.status_code and b1 == b2
        if expect is not None and r1.status_code != expect:
            ok = False
        detail = f"python {r1.status_code} {b1[:1200]!r}\n        rust   {r2.status_code} {b2[:1200]!r}"
        h1 = {k: r1.headers.get(k) for k in RESPONSE_HEADERS}
        h2 = {k: r2.headers.get(k) for k in RESPONSE_HEADERS}
        if h1 != h2:
            ok = False
            detail += f"\n        headers python {h1}\n        headers rust   {h2}"
        if out1 != out2:
            ok = False
            detail += f"\n        outbound python {out1}\n        outbound rust   {out2}"
        if table and t1 != t2:
            ok = False
            detail += f"\n        table python {t1}\n        table rust   {t2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {out1}")
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- OpenCTI checks ----------------------------------------------------------------------------------

OCTI_URL = f"http://127.0.0.1:{OPENCTI_PORT}"
OP = "/api/opencti"


def octi(url=OCTI_URL, key=OPENCTI_KEY, extra=None, verified=1, override=None):
    def go():
        set_connector("OpenCTI", url, api_key=key, extra=extra, verified=verified)
        OPENCTI.override = override

    return go


def answering(value, status=200, op=None):
    """An override answering `value` (JSON) to every operation, or only to `op`."""

    def override(operation, variables):
        if op and operation != op:
            return None
        if isinstance(value, bytes):
            return status, "text/html", value
        return as_json(status, value)

    return override


def lookup_answer(nodes, count=None):
    conn = {"pageInfo": {"globalCount": len(nodes) if count is None else count}, "edges": [{"node": n} for n in nodes]}
    return answering({"data": {"stixCyberObservables": conn}})


AUTH_REQUIRED = {
    "errors": [{"message": "You must be logged in to do this.", "extensions": {"code": "AUTH_REQUIRED"}}],
    "data": {"about": None, "me": None},
}


async def opencti_checks(p, t_admin, t_analyst, t_portal):
    print("\n== OpenCTI: auth and availability")
    await p.same("availability, no token", "GET", f"{OP}/availability", before=octi(), expect=401)
    await p.same("availability, portal user", "GET", f"{OP}/availability", t_portal, before=octi(), expect=403)
    await p.same("availability, no connector row", "GET", f"{OP}/availability", t_analyst, before=octi(url=None), expect=200)
    await p.same("availability, verified", "GET", f"{OP}/availability", t_admin, before=octi(), expect=200)
    await p.same(
        "availability, the public URL",
        "GET",
        f"{OP}/availability",
        t_analyst,
        before=octi(url=OCTI_URL + "/graphql/", extra=" https://cti.example.com/graphql/ "),
        expect=200,
    )
    await p.same(
        "availability, a public URL that is not http(s)",
        "GET",
        f"{OP}/availability",
        t_analyst,
        before=octi(extra="ftp://cti.example.com"),
    )
    await p.same("availability, a relative public URL", "GET", f"{OP}/availability", t_analyst, before=octi(extra="cti.example.com"))
    await p.same(
        "availability, urlparse's ValueError",
        "GET",
        f"{OP}/availability",
        t_analyst,
        before=octi(extra="http://[::1"),
        expect=400,
    )
    await p.same("availability, not verified", "GET", f"{OP}/availability", t_analyst, before=octi(verified=0, extra="https://x.example"))
    await p.same("availability, a blank key", "GET", f"{OP}/availability", t_analyst, before=octi(key="  "))
    await p.same("availability, no key", "GET", f"{OP}/availability", t_analyst, before=octi(key=None))

    print("\n== OpenCTI: about and the transport's failures")
    await p.same("about, no connector row", "GET", f"{OP}/about", t_analyst, before=octi(url=None), expect=500)
    await p.same("about", "GET", f"{OP}/about", t_analyst, before=octi(), expect=200)
    await p.same("about, the /graphql URL", "GET", f"{OP}/about", t_analyst, before=octi(url=OCTI_URL + "/graphql"), expect=200)
    await p.same(
        "about, errors at HTTP 200 (a revoked token)",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(override=answering(AUTH_REQUIRED)),
        expect=500,
    )
    many = {
        "errors": [{"message": "a", "name": "FORBIDDEN_ACCESS"}, {"extensions": {}}, {"message": {"x": 1}, "extensions": {"code": 7}}],
        "data": None,
    }
    await p.same("about, several errors", "GET", f"{OP}/about", t_analyst, before=octi(override=answering(many)), expect=500)
    await p.same(
        "about, an error that is no object",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(override=answering({"errors": ["boom"]})),
        expect=500,
    )
    await p.same(
        "about, a message that is no str",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(override=answering({"errors": [{"message": 5}]})),
        expect=500,
    )
    await p.same(
        "about, HTTP 503 with JSON",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(override=answering({"data": None}, 503)),
        expect=500,
    )
    await p.same(
        "about, HTTP 502 not JSON",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(override=answering(b"<html>bad gateway</html>", 502)),
        expect=500,
    )
    await p.same("about, a JSON list", "GET", f"{OP}/about", t_analyst, before=octi(override=answering([1, 2])), expect=500)
    await p.same("about, data null", "GET", f"{OP}/about", t_analyst, before=octi(override=answering({"data": None})), expect=200)
    await p.same("about, data not an object", "GET", f"{OP}/about", t_analyst, before=octi(override=answering({"data": [1]})), expect=500)
    bad_deps = {"data": {"about": {"version": "6", "dependencies": [{"version": 1}, "x"]}, "me": {"name": 5}}}
    await p.same(
        "about, models refusing the answer",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(override=answering(bad_deps)),
        expect=400,
    )
    await p.same("about, a closed port", "GET", f"{OP}/about", t_analyst, before=octi(url=f"http://127.0.0.1:{CLOSED_PORT}"), expect=500)
    await p.same("about, a URL httpx refuses", "GET", f"{OP}/about", t_analyst, before=octi(url="http://127.0.0.1:x"), expect=500)
    await p.same("about, an unsupported scheme", "GET", f"{OP}/about", t_analyst, before=octi(url="opencti.local:8080"), expect=500)
    await p.same("about, an empty URL", "GET", f"{OP}/about", t_analyst, before=octi(url=""), expect=500)
    await p.same("about, no API key (h11 refuses 'Bearer ')", "GET", f"{OP}/about", t_analyst, before=octi(key=None), expect=500)
    await p.same(
        "about, no API key and a closed port",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(url=f"http://127.0.0.1:{CLOSED_PORT}", key=None),
        expect=500,
    )
    await p.same("about, a key with a trailing space", "GET", f"{OP}/about", t_analyst, before=octi(key="abc "), expect=500)
    await p.same("about, a non-ASCII key", "GET", f"{OP}/about", t_analyst, before=octi(key="kéy"), expect=400)
    await p.same(
        "about, HTTPS with a self-signed certificate",
        "GET",
        f"{OP}/about",
        t_analyst,
        before=octi(url=f"https://127.0.0.1:{OPENCTI_TLS_PORT}"),
        expect=200,
    )

    print("\n== OpenCTI: one IOC")
    S = f"{OP}/observables/search"
    await p.same("search, no value", "GET", S, t_analyst, before=octi(), expect=422)
    await p.same("search, an empty value", "GET", f"{S}?value=", t_analyst, before=octi(), expect=422)
    # The 422's log_entries row cannot hold a URL this long: Python's handler fails (a bare 500).
    await p.same("search, a value too long", "GET", f"{S}?value={'x' * 2049}", t_analyst, before=octi(), expect=500)
    await p.same("search, first out of range and value missing", "GET", f"{S}?first=0", t_analyst, before=octi(), expect=422)
    await p.same("search, first 101", "GET", f"{S}?value=a&first=101", t_analyst, before=octi(), expect=422)
    await p.same("search, first not an int", "GET", f"{S}?value=a&first=abc", t_analyst, before=octi(), expect=422)
    await p.same(
        "search, first '1.0' (Pydantic's lax int)",
        "GET",
        f"{S}?value=bad.example&first=1.0",
        t_analyst,
        before=octi(),
        expect=200,
    )
    await p.same("search, a blank value", "GET", f"{S}?value=%20%20", t_analyst, before=octi(), expect=400)
    await p.same("search, found", "GET", f"{S}?value=%20bad.example%20&first=5", t_analyst, before=octi(), expect=200)
    await p.same("search, by an upper-case hash", "GET", f"{S}?value={SHA}", t_analyst, before=octi(), expect=200)
    await p.same("search, not found", "GET", f"{S}?value=nothing.example", t_analyst, before=octi(), expect=200)
    await p.same("search, two observables", "GET", f"{S}?value=twin.example", t_analyst, before=octi(), expect=200)
    await p.same(
        "search, a node without id",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([{"entity_type": "x"}])),
        expect=500,
    )
    await p.same(
        "search, a fractional score",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([observable_node(x_opencti_score=5.5)])),
        expect=400,
    )
    bad_indicator = observable_node(indicators={"edges": [{"node": indicator_node(2, id=7, revoked="maybe")}]})
    await p.same(
        "search, an indicator the model refuses",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([bad_indicator])),
        expect=400,
    )
    await p.same(
        "search, labels as an object",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([observable_node(objectLabel={"a": 1})])),
        expect=500,
    )
    odd = observable_node(
        objectMarking=[{"definition": 5}],
        hashes=[{"algorithm": "MD5", "hash": 5}],
        reports={"edges": [{"node": {"name": "no id"}}]},
    )
    await p.same(
        "search, markings, hashes and reports the model refuses",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([odd])),
        expect=400,
    )
    await p.same(
        "search, a string globalCount",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([observable_node()], count="7")),
        expect=200,
    )
    await p.same(
        "search, connections missing",
        "GET",
        f"{S}?value=x",
        t_analyst,
        before=octi(override=lookup_answer([observable_node(indicators=None, reports={}, hashes=None, objectLabel=None, createdBy={})])),
        expect=200,
    )
    await p.same("search, errors at HTTP 200", "GET", f"{S}?value=x", t_analyst, before=octi(override=answering(AUTH_REQUIRED)), expect=500)

    print("\n== OpenCTI: many IOCs")
    L = f"{OP}/observables/lookup"
    await p.same(
        "lookup, malformed JSON without a token",
        "POST",
        L,
        content=b'{"values": [',
        headers={"Content-Type": "application/json"},
        before=octi(),
        expect=422,
    )
    await p.same("lookup, no token", "POST", L, json={"values": ["a"]}, before=octi(), expect=401)
    await p.same("lookup, no body", "POST", L, t_analyst, before=octi(), expect=422)
    await p.same(
        "lookup, not JSON",
        "POST",
        L,
        t_analyst,
        content=b"values",
        headers={"Content-Type": "text/plain"},
        before=octi(),
        expect=422,
    )
    await p.same("lookup, a list body", "POST", L, t_analyst, json=["a"], before=octi(), expect=422)
    await p.same("lookup, values missing", "POST", L, t_analyst, json={}, before=octi(), expect=422)
    await p.same("lookup, no values", "POST", L, t_analyst, json={"values": []}, before=octi(), expect=422)
    await p.same("lookup, values not a list", "POST", L, t_analyst, json={"values": "a"}, before=octi(), expect=422)
    await p.same("lookup, 101 values", "POST", L, t_analyst, json={"values": [1] * 101}, before=octi(), expect=422)
    await p.same("lookup, values that are no strings", "POST", L, t_analyst, json={"values": [1, None, "x"]}, before=octi(), expect=422)
    await p.same("lookup, only blanks", "POST", L, t_analyst, json={"values": ["  ", ""]}, before=octi(), expect=422)
    await p.same("lookup, a value too long", "POST", L, t_analyst, json={"values": ["a", " " + "x" * 2049]}, before=octi(), expect=422)
    values = ["Bad.Example", SHA, "nothing.example", "bad.example", " twin.example ", "İstanbul.example", "i̇stanbul.example"]
    await p.same("lookup, found, de-duplicated and mapped back", "POST", L, t_analyst, json={"values": values}, before=octi(), expect=200)
    await p.same(
        "lookup, truncated",
        "POST",
        L,
        t_analyst,
        json={"values": ["bad.example"]},
        before=octi(override=lookup_answer([observable_node()], count=99)),
        expect=200,
    )
    await p.same(
        "lookup, a string globalCount",
        "POST",
        L,
        t_analyst,
        json={"values": ["bad.example"]},
        before=octi(override=lookup_answer([observable_node()], count="5")),
        expect=500,
    )
    await p.same(
        "lookup, 60 values (first=300)",
        "POST",
        L,
        t_analyst,
        json={"values": [f"v{n}.example" for n in range(60)]},
        before=octi(),
        expect=200,
    )
    await p.same(
        "lookup, errors at HTTP 200",
        "POST",
        L,
        t_analyst,
        json={"values": ["a"]},
        before=octi(override=answering(AUTH_REQUIRED)),
        expect=500,
    )

    print("\n== OpenCTI: indicators, page by page")
    IND = f"{OP}/indicators"
    await p.same("indicators", "GET", IND, t_analyst, before=octi(), expect=200)
    cursor = None
    for page in range(1, 4):
        path = f"{IND}?first=2" + (f"&after={cursor}" if cursor else "")
        r1, _ = await p.same(f"indicators, page {page}", "GET", path, t_analyst, before=octi(), expect=200)
        cursor = r1.json()["page_info"]["end_cursor"]
    await p.same(
        "indicators, every filter",
        "GET",
        f"{IND}?search=bad.example&min_score=50&main_observable_type=Domain-Name&after=c1&first=500",
        t_analyst,
        before=octi(),
        expect=200,
    )
    await p.same("indicators, empty filters", "GET", f"{IND}?search=&main_observable_type=&after=", t_analyst, before=octi(), expect=200)
    await p.same("indicators, min_score 0", "GET", f"{IND}?min_score=0", t_analyst, before=octi(), expect=200)
    await p.same(
        "indicators, every parameter refused",
        "GET",
        f"{IND}?search={'s' * 513}&first=501&after={'a' * 1025}&min_score=101&main_observable_type={'t' * 65}",
        t_analyst,
        before=octi(),
        expect=500,
    )
    await p.same("indicators, min_score below 0", "GET", f"{IND}?min_score=-1", t_analyst, before=octi(), expect=422)
    await p.same("indicators, an empty min_score", "GET", f"{IND}?min_score=", t_analyst, before=octi(), expect=422)
    no_info = answering({"data": {"indicators": {"edges": [{"node": indicator_node(9)}]}}})
    await p.same("indicators, no pageInfo", "GET", IND, t_analyst, before=octi(override=no_info), expect=200)
    await p.same(
        "indicators, an empty cursor",
        "GET",
        IND,
        t_analyst,
        before=octi(override=answering({"data": {"indicators": {"pageInfo": {"endCursor": "", "hasNextPage": 1}}}})),
        expect=200,
    )
    await p.same(
        "indicators, a string globalCount",
        "GET",
        IND,
        t_analyst,
        before=octi(override=answering({"data": {"indicators": {"pageInfo": {"globalCount": "x"}}}})),
        expect=400,
    )
    await p.same("indicators, no data", "GET", IND, t_analyst, before=octi(override=answering({"data": None})), expect=200)
    await p.same("indicators, errors at HTTP 200", "GET", IND, t_analyst, before=octi(override=answering(AUTH_REQUIRED)), expect=500)

    print("\n== OpenCTI: entities")
    E = f"{OP}/entities"
    await p.same("entity", "GET", f"{E}/report--1", t_analyst, before=octi(), expect=200)
    await p.same("entity, not found", "GET", f"{E}/missing", t_analyst, before=octi(), expect=404)
    await p.same(
        "entity, an id too long (and a URL too long for log_entries)",
        "GET",
        f"{E}/{'r' * 257}",
        t_analyst,
        before=octi(),
        expect=500,
    )
    # The raw URL is longer than log_entries.route, the decoded one Starlette logs is not.
    await p.same(
        "entity, a long percent-encoded id that is not found",
        "GET",
        f"{E}/{'r' * 10}{'%20' * 80}",
        t_analyst,
        before=octi(override=answering({"data": {"stixCoreObject": None}})),
        expect=404,
    )
    await p.same("entity, an id with spaces and accents", "GET", f"{E}/r%C3%A9port%201", t_analyst, before=octi(), expect=200)
    await p.same("entity, an encoded slash", "GET", f"{E}/a%2Fb", t_analyst, before=octi(), expect=404)
    await p.same("entity, an id that is no UTF-8 once decoded", "GET", f"{E}/a%FFb", t_analyst, before=octi(), expect=200)
    await p.same("entity, an encoded percent", "GET", f"{E}/a%2541", t_analyst, before=octi(), expect=200)
    await p.same(
        "entity, representative not an object",
        "GET",
        f"{E}/report--1",
        t_analyst,
        before=octi(override=answering({"data": {"stixCoreObject": entity_node(representative=[1])}})),
        expect=500,
    )
    await p.same(
        "entity, a confidence the model refuses",
        "GET",
        f"{E}/report--1",
        t_analyst,
        before=octi(override=answering({"data": {"stixCoreObject": entity_node(confidence="high", parent_types=None)}})),
        expect=400,
    )
    await p.same("entity, no token", "GET", f"{E}/report--1", before=octi(), expect=401)

    print("\n== OpenCTI: the connector check")
    octi()()
    cid = connector_id("OpenCTI")

    def verify_with(url=OCTI_URL, key=OPENCTI_KEY, override=None):
        def go():
            sql(
                "UPDATE connectors SET connector_url = :u, connector_api_key = :k, connector_verified = 0 WHERE connector_name = 'OpenCTI'",
                u=url,
                k=key,
            )
            OPENCTI.override = override

        return go

    V = f"/api/connectors/verify/{cid}"
    table = lambda: connector_verified("OpenCTI")  # noqa: E731
    await p.same("verify OpenCTI", "POST", V, t_admin, before=verify_with(), table=table, expect=200)
    await p.same(
        "verify OpenCTI, errors at HTTP 200",
        "POST",
        V,
        t_admin,
        before=verify_with(override=answering(AUTH_REQUIRED)),
        table=table,
        expect=500,
    )
    await p.same(
        "verify OpenCTI, no version",
        "POST",
        V,
        t_admin,
        before=verify_with(override=answering({"data": {"about": {}, "me": None}})),
        table=table,
        expect=500,
    )
    await p.same("verify OpenCTI, a blank URL", "POST", V, t_admin, before=verify_with(url="  "), table=table, expect=500)
    await p.same(
        "verify OpenCTI, a closed port",
        "POST",
        V,
        t_admin,
        before=verify_with(url=f"http://127.0.0.1:{CLOSED_PORT}"),
        table=table,
        expect=500,
    )
    await p.same(
        "verify OpenCTI, a URL httpx refuses",
        "POST",
        V,
        t_admin,
        before=verify_with(url="http://127.0.0.1:x"),
        table=table,
        expect=404,
    )
    await p.same(
        "verify OpenCTI, data not an object",
        "POST",
        V,
        t_admin,
        before=verify_with(override=answering({"data": [1]})),
        table=table,
        expect=404,
    )
    await p.same(
        "verify OpenCTI, HTTPS self-signed",
        "POST",
        V,
        t_admin,
        before=verify_with(url=f"https://127.0.0.1:{OPENCTI_TLS_PORT}/"),
        table=table,
        expect=200,
    )


# --- Cortex checks -----------------------------------------------------------------------------------

CTX_URL = f"http://127.0.0.1:{CORTEX_PORT}"
A = "/api/analyzers"


def ctx(url=CTX_URL, key=CORTEX_KEY, **mode):
    def go():
        set_connector("Cortex", url, api_key=key)
        CORTEX.reset(**mode)

    return go


def run_body(name="VirusTotal_GetReport_3_1", data="1.2.3.4", **extra):
    return {"analyzer_name": name, "analyzer_data": data, **extra}


async def cortex_checks(p, t_admin, t_analyst, t_portal):
    print("\n== Cortex: the analyzers")
    await p.same("analyzers, no token", "GET", A, before=ctx(), expect=401)
    await p.same("analyzers, portal user", "GET", A, t_portal, before=ctx(), expect=403)
    await p.same("analyzers, no connector row", "GET", A, t_analyst, before=ctx(url=None), expect=500)
    await p.same("analyzers, no API key (Api's TypeError)", "GET", A, t_analyst, before=ctx(key=None), expect=500)
    await p.same("analyzers", "GET", A, t_analyst, before=ctx(), expect=200)
    await p.same("analyzers, a URL ending in /", "GET", A, t_analyst, before=ctx(url=CTX_URL + "/"), expect=200)
    await p.same("analyzers, none", "GET", A, t_analyst, before=ctx(list=[]), expect=200)
    await p.same("analyzers, one without a name", "GET", A, t_analyst, before=ctx(list=[{"id": "x"}]), expect=500)
    await p.same("analyzers, an object", "GET", A, t_analyst, before=ctx(list={"name": "x"}), expect=500)
    await p.same("analyzers, null", "GET", A, t_analyst, before=ctx(list=None), expect=500)
    await p.same("analyzers, a string", "GET", A, t_analyst, before=ctx(list="ab"), expect=500)
    await p.same("analyzers, an empty string", "GET", A, t_analyst, before=ctx(list=""), expect=200)
    await p.same("analyzers, a null item (the class defaults)", "GET", A, t_analyst, before=ctx(list=[None, {"name": 5}]), expect=400)
    await p.same("analyzers, an item that is no object", "GET", A, t_analyst, before=ctx(list=[1]), expect=500)
    for status in (401, 403, 404, 500):
        await p.same(f"analyzers, HTTP {status}", "GET", A, t_analyst, before=ctx(status=as_json(status, {"message": "no"})), expect=500)
    await p.same("analyzers, not JSON", "GET", A, t_analyst, before=ctx(status=(200, "text/html", b"<html>")), expect=500)
    await p.same("analyzers, a closed port", "GET", A, t_analyst, before=ctx(url=f"http://127.0.0.1:{CLOSED_PORT}"), expect=500)
    await p.same("analyzers, no scheme (InvalidSchema)", "GET", A, t_analyst, before=ctx(url=f"127.0.0.1:{CORTEX_PORT}"), expect=500)
    await p.same("analyzers, no scheme nor port (MissingSchema)", "GET", A, t_analyst, before=ctx(url="cortex"), expect=500)
    await p.same(
        "analyzers, HTTPS with a self-signed certificate",
        "GET",
        A,
        t_analyst,
        before=ctx(url=f"https://127.0.0.1:{CORTEX_TLS_PORT}"),
        expect=200,
    )

    print("\n== Cortex: running an analyzer")
    R = f"{A}/run"
    await p.same(
        "run, malformed JSON without a token",
        "POST",
        R,
        content=b"{",
        headers={"Content-Type": "application/json"},
        before=ctx(),
        expect=422,
    )
    await p.same("run, no token", "POST", R, json=run_body(), before=ctx(), expect=401)
    await p.same("run, no fields", "POST", R, t_analyst, json={}, before=ctx(), expect=422)
    await p.same("run, a data_type that is no string", "POST", R, t_analyst, json=run_body(data_type=5), before=ctx(), expect=422)
    await p.same("run, data that is no IoC", "POST", R, t_analyst, json=run_body(data="not an ioc"), before=ctx(), expect=422)
    await p.same("run, an upper-case domain", "POST", R, t_analyst, json=run_body(data="Example.com"), before=ctx(), expect=422)
    await p.same("run, an unknown analyzer", "POST", R, t_analyst, json=run_body(name="Nope"), before=ctx(), expect=400)
    await p.same("run, no connector row", "POST", R, t_analyst, json=run_body(), before=ctx(url=None), expect=500)
    await p.same("run, an IPv4 address", "POST", R, t_analyst, json=run_body(data_type="ignored"), before=ctx(), expect=200)
    await p.same("run, a hash", "POST", R, t_analyst, json=run_body(data="d41d8cd98f00b204e9800998ecf8427e"), before=ctx(), expect=200)
    await p.same(
        "run, a domain (an id needing quoting)",
        "POST",
        R,
        t_analyst,
        json=run_body(name="Abuse_Finder_3_0", data="example.com\n"),
        before=ctx(),
        expect=200,
    )
    await p.same(
        "run, the job fails at once",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(run={"id": 7, "status": "Failure", "errorMessage": "quota"}),
        expect=200,
    )
    await p.same(
        "run, one poll (5 s), then success",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(run={"id": "job 2", "status": "Waiting"}, polls=[{"id": "job 2", "status": "Success"}]),
        expect=200,
    )
    await p.same(
        "run, one poll (5 s), then failure without a message",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(run={"id": "job-3", "status": "InProgress"}, polls=[{"status": "Failure"}]),
        expect=500,
    )
    await p.same("run, the analyzer is not found by name", "POST", R, t_analyst, json=run_body(), before=ctx(by_name=[]), expect=500)
    await p.same(
        "run, the analyzer has no id",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(by_name=[{"name": "VirusTotal_GetReport_3_1"}]),
        expect=500,
    )
    await p.same("run, the search answers an object", "POST", R, t_analyst, json=run_body(), before=ctx(by_name={"a": 1}), expect=500)
    await p.same("run, the search answers null", "POST", R, t_analyst, json=run_body(), before=ctx(by_name=None), expect=500)
    await p.same("run, the search answers a string", "POST", R, t_analyst, json=run_body(), before=ctx(by_name="x"), expect=500)
    await p.same("run, the search answers [null]", "POST", R, t_analyst, json=run_body(), before=ctx(by_name=[None]), expect=500)
    await p.same(
        "run, the run is refused",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(run=as_json(400, {"message": "bad"})),
        expect=500,
    )
    await p.same("run, the run answers a list", "POST", R, t_analyst, json=run_body(), before=ctx(run=[{"id": "j"}]), expect=500)
    await p.same("run, a job without id", "POST", R, t_analyst, json=run_body(), before=ctx(run={"status": "Success"}), expect=500)
    await p.same("run, a job without status", "POST", R, t_analyst, json=run_body(), before=ctx(run={"id": "j"}), expect=500)
    await p.same(
        "run, a job with a 'json' key",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(run={"id": "j", "status": "Success", "json": 1}),
        expect=500,
    )
    await p.same("run, a report without report", "POST", R, t_analyst, json=run_body(), before=ctx(report={"id": "j"}), expect=500)
    await p.same(
        "run, a report without full",
        "POST",
        R,
        t_analyst,
        json=run_body(),
        before=ctx(report={"report": {"summary": {}}}),
        expect=500,
    )
    await p.same("run, a report that is a string", "POST", R, t_analyst, json=run_body(), before=ctx(report={"report": "x"}), expect=500)
    await p.same("run, Cortex answers 503 to the run", "POST", R, t_analyst, json=run_body(), before=ctx(run=as_json(503, {})), expect=500)

    print("\n== Cortex: the connector check")
    ctx()()
    cid = connector_id("Cortex")

    def verify_with(key=CORTEX_KEY):
        def go():
            sql("UPDATE connectors SET connector_api_key = :k, connector_verified = 0 WHERE connector_name = 'Cortex'", k=key)

        return go

    V = f"/api/connectors/verify/{cid}"
    table = lambda: connector_verified("Cortex")  # noqa: E731
    await p.same("verify Cortex", "POST", V, t_admin, before=verify_with(), table=table, expect=200)
    await p.same("verify Cortex, no API key", "POST", V, t_admin, before=verify_with(key=None), table=table, expect=500)


async def sublime_checks():
    """Sublime stays in Python: its tables are not created by Alembic, so its routes fail."""
    print("\n== Sublime (Python only)")
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    try:
        r = await client.get("/api/sublime/alerts", headers={"Authorization": f"Bearer {token(ANALYST, ['analyst'])}"})
        check(
            "sublime: GET /alerts is a 500 in Python (no sublimealerts table)",
            r.status_code == 500,
            f"{r.status_code} {r.content[:300]!r}",
        )
    finally:
        await client.aclose()


async def main():
    tls = make_tls()
    servers = [
        start_stub(OPENCTI_PORT, OPENCTI, OPENCTI_RECORDER),
        start_stub(OPENCTI_TLS_PORT, OPENCTI, OPENCTI_RECORDER, tls=tls),
        start_stub(CORTEX_PORT, CORTEX, CORTEX_RECORDER),
        start_stub(CORTEX_TLS_PORT, CORTEX, CORTEX_RECORDER, tls=tls),
    ]
    proc = None
    try:
        seed()
        proc = start_rust(RS_PORT)
    except BaseException:
        if proc:
            proc.kill()
        cleanup()
        raise
    p = Pair(RS_PORT)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    try:
        sections = os.environ.get("INTEL_PARITY_SECTIONS", "opencti,cortex,sublime").split(",")
        if "opencti" in sections:
            await opencti_checks(p, t_admin, t_analyst, t_portal)
        if "cortex" in sections:
            await cortex_checks(p, t_admin, t_analyst, t_portal)
        if "sublime" in sections:
            await sublime_checks()
    finally:
        await p.close()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        for server in servers:
            server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
