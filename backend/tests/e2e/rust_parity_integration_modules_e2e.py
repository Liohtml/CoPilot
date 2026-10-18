"""Parity of the Rust integration modules (`copilot-integration-modules`) with this backend — NOT
collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers of `/api/integrations/modules/*` (Huntress, Mimecast, Duo, Cato, SAP SIEM
and its seven analyses) and of `/api/mimecast` (in-process) and Rust instances answer the same
requests on one database. Their module containers (`http://copilot-<name>-module`) and Mimecast's
region discovery (`https://api.mimecast.com`) are one recording stand-in: Rust reaches it through
`COPILOT_INTEGRATION_MODULES_URL`, Python's httpx clients through a transport that rewrites the
URL (and its `Host`) the same way, so both send the same bytes. Every request either backend sends
is compared — method, path, every header in order (names lower-cased: hyper writes them so when
httpx's are mixed-case), body —, the request id and date of Mimecast's signature headers and the
SAP collection's `utcnow()` bounds checked for their shape, then masked.

A legacy Python (uvicorn, a process of its own) serves the scheduler routes over a paused APScheduler on the
real store; a second Rust instance opted in to the collection jobs (`COPILOT_RS_JOBS`) runs them
from `/api/scheduler/jobs/run/{id}` while their rows are disabled, compared with Python's manual
run, the `last_success` stamp included; the Python guard is checked to skip a handed-over tick and
to run one whose row is enabled. A third Rust instance reaches the modules on a closed port.

Deliberate differences are asserted as such (RUST_MIGRATION.md §4): a body naming another tenant's
customer, or an IRIS id none of the caller's customers carries, is refused. Two features Python never
runs work in Rust ("Python fails, Rust works"): Mimecast's SIEM download and TTP URL pages (Python's
`HttpUrl + str` is a `TypeError` on every run) and the SAP SIEM collection with one API key
(`get_customer_meta_attribute`'s `Depends` default). Each is shown twice: Python as it is against Rust
(the two answers), then Python patched to do what its code says past the crash — the region's URL as
the string Mimecast sent, the one key sent down the several-keys path — compared request by request,
with the checkpoint and log files (one directory both backends write, laid out as Python lays it out)
and every GELF frame the Event Shipper stand-in receives.

    PARITY_SUITES=tests/e2e/rust_parity_integration_modules_e2e.py scripts/rust-parity.sh

Ports: INTEGRATION_MODULES_STUB_PORT (6610), INTEGRATION_MODULES_PARITY_RUST_PORT (6611),
INTEGRATION_MODULES_PARITY_PY_PORT (6612, the legacy Python), INTEGRATION_MODULES_RUST_JOBS_PORT
(6613), INTEGRATION_MODULES_CLOSED_PORT (6614, nothing listens), INTEGRATION_MODULES_PARITY_RUST_CLOSED_PORT
(6615), INTEGRATION_MODULES_GELF_PORT (6900, the Event Shipper's GELF input). Seeded ids are seven digits in
7725000-7725999.
"""

import asyncio
import contextlib
import datetime
import fnmatch
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import types
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
# The stand-in is reached directly, never through a proxy from the environment.
for _var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(_var, None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(BACKEND, ".."))
sys.path.insert(0, HERE)

import httpx  # noqa: E402
import jwt  # noqa: E402
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore  # noqa: E402
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import bindparam  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = os.environ.get("INTEGRATION_MODULES_PARITY_SFX") or uuid.uuid4().hex[:6]
STUB_PORT = int(os.environ.get("INTEGRATION_MODULES_STUB_PORT", "6610"))
RS_PORT = int(os.environ.get("INTEGRATION_MODULES_PARITY_RUST_PORT", "6611"))
PY_PORT = int(os.environ.get("INTEGRATION_MODULES_PARITY_PY_PORT", "6612"))
JOBS_PORT = int(os.environ.get("INTEGRATION_MODULES_RUST_JOBS_PORT", "6613"))
CLOSED_PORT = int(os.environ.get("INTEGRATION_MODULES_CLOSED_PORT", "6614"))
RS_CLOSED_PORT = int(os.environ.get("INTEGRATION_MODULES_PARITY_RUST_CLOSED_PORT", "6615"))
GELF_PORT = int(os.environ.get("INTEGRATION_MODULES_GELF_PORT", "6900"))
STUB = f"http://127.0.0.1:{STUB_PORT}"
# The Mimecast module directory both backends keep their files in (Rust's COPILOT_MIMECAST_DIR;
# Python's `__file__` is pointed at `services/mimecast.py` under it).
MIMECAST_DIR = os.environ.get("INTEGRATION_MODULES_MIMECAST_DIR") or tempfile.mkdtemp(prefix="parity-mimecast-")
os.environ["INTEGRATION_MODULES_MIMECAST_DIR"] = MIMECAST_DIR
CLOSED = f"http://127.0.0.1:{CLOSED_PORT}"

CUST_A, CUST_B, CUST_C, CUST_D, CUST_E = (f"IMA{SFX}", f"IMB{SFX}", f"IMC{SFX}", f"IMD{SFX}", f"IME{SFX}")
CUSTOMERS = (CUST_A, CUST_B, CUST_C, CUST_D, CUST_E)
ADMIN, ANALYST, ANALYST_B, UNASSIGNED = (f"im_admin{SFX}", f"im_analyst{SFX}", f"im_analyst_b{SFX}", f"im_unassigned{SFX}")
USERS = (ADMIN, ANALYST, ANALYST_B, UNASSIGNED)
IRIS_A, IRIS_B, IRIS_E, IRIS_UNKNOWN = 7725101, 7725102, 7725103, 7725999
CONNECTOR_IDS = {1: f"IM Indexer {SFX}", 10: f"IM Graylog10 {SFX}", 14: f"IM Graylog14 {SFX}"}
JOB_DESCRIPTION = f"parity-im{SFX}"
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def sql(statement, **params):
    stmt = text(statement)
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    with sync_engine.begin() as conn:
        return conn.execute(stmt, params)


def rows(statement, **params):
    stmt = text(statement)
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(stmt, params)]


# --- The stand-in -------------------------------------------------------------------------------------

DISCOVERY_OK = {
    "meta": {"status": 200},
    "data": [
        {
            "emailAddress": "admin@a.example",
            "emailToken": "token",
            "authenticate": ["Basic-AD"],
            "region": {
                "code": "us",
                # Mimecast's API is the URL its discovery names: the stand-in, for both backends.
                "api": f"{STUB}/us-api.mimecast.com",
                "mpp": "https://us-mpp.mimecast.com",
                "adminConsole": "https://us-console.mimecast.com",
                "name": "USA",
            },
        },
    ],
    "fail": [],
}


class Stub:
    """The module containers and Mimecast's API, by the first path segment (the host)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.captured = []
        self.reset()

    def reset(self, overrides=None):
        # (method, glob on the path) -> a reply, or a list of replies used in turn.
        # A reply is (status, content type, body bytes, extra headers) or "close".
        self.overrides = {k: (list(v) if isinstance(v, list) else v) for k, v in (overrides or {}).items()}

    def take(self):
        with self.lock:
            out, self.captured = self.captured, []
        return out

    def answer(self, method, path):
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(path, pattern):
                if isinstance(reply, list):
                    return reply.pop(0) if len(reply) > 1 else reply[0]
                return reply
        j = "application/json"
        if path.startswith("/api.mimecast.com/"):
            return 200, j, json.dumps(DISCOVERY_OK).encode(), []
        if path.startswith("/us-api.mimecast.com/api/audit/get-siem-logs"):
            return 200, j, json.dumps({"meta": {"status": 200}, "data": [], "fail": []}).encode(), []
        if path.startswith("/us-api.mimecast.com/api/ttp/url/get-logs"):
            return 200, j, json.dumps(ttp_page([])).encode(), []
        if path.startswith("/copilot-"):
            return 200, j, json.dumps({"message": "collected"}).encode(), []
        return 404, j, b'{"detail": "no such stand-in route"}', []


STUB_STATE = Stub()


def start_stub():
    stub = STUB_STATE

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            # Every header the client sent, in order (names lower-cased).
            headers = [(k.lower(), v) for k, v in self.headers.items()]
            with stub.lock:
                stub.captured.append((self.command, self.path, headers, body))
            reply = stub.answer(self.command, self.path)
            if reply == "close":
                self.close_connection = True
                return
            status, ctype, payload, extra = reply
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            for k, v in extra:
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

    server = Server(("127.0.0.1", STUB_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def ttp_page(clicks, next_token=None):
    """One page of `/api/ttp/url/get-logs`."""
    pagination = {"pageSize": len(clicks), "totalCount": len(clicks)}
    if next_token is not None:
        pagination["next"] = next_token
    return {"meta": {"pagination": pagination, "status": 200}, "data": [{"clickLogs": clicks}], "fail": []}


def click_log(n):
    return {
        "userEmailAddress": f"user{n}@a.example",
        "fromUserEmailAddress": "x@evil.example",
        "url": f"https://evil.example/{n}",
        "ttpDefinition": "Default",
        "subject": "hello",
        "action": "block",
        "adminOverride": "N/A",
        "userOverride": "None",
        "scanResult": "malicious",
        "category": "phishing",
        "sendingIp": "198.51.100.7",
        "userAwarenessAction": "n/a",
        "date": "2026-10-17T10:00:00+0000",
        "actions": "Blocked",
        "route": "inbound",
        "creationMethod": "User Click",
        "emailPartsDescription": ["Body"],
        "messageId": f"<m{n}@a.example>",
        "notInTheModel": "dropped",
    }


# --- The Event Shipper's GELF input -------------------------------------------------------------------

GELF_FRAMES = []
GELF_LOCK = threading.Lock()


class _GelfHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.read()
        with GELF_LOCK:
            GELF_FRAMES.extend(f for f in data.split(b"\0") if f)


def start_gelf_stub():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("127.0.0.1", GELF_PORT), _GelfHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def take_gelf(settle=0.3, timeout=8.0):
    """The frames received so far (sorted: each event is a connection of its own, which a threaded
    input may finish in any order), once no new one came for `settle` seconds."""
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
    return sorted(f.decode("utf-8", "replace") for f in out)


def mimecast_files():
    """Every file under the Mimecast directory (Python's `services/` stand-in aside), with its bytes."""
    out = {}
    for root, dirs, files in os.walk(MIMECAST_DIR):
        rel = os.path.relpath(root, MIMECAST_DIR)
        if rel.split(os.sep)[0] == "services":
            continue
        for d in dirs:
            if rel == "." and d == "services":
                continue
            out[os.path.normpath(os.path.join(rel, d)) + "/"] = None
        for f in files:
            with open(os.path.join(root, f), "rb") as fh:
                out[os.path.normpath(os.path.join(rel, f))] = fh.read().decode("utf-8", "replace")
    return out


def reset_mimecast_files(checkpoints=None):
    """An empty Mimecast directory, but for `services/` and the given `{customer: token}` checkpoints."""
    for name in os.listdir(MIMECAST_DIR):
        if name != "services":
            shutil.rmtree(os.path.join(MIMECAST_DIR, name), ignore_errors=True)
    os.makedirs(os.path.join(MIMECAST_DIR, "services"), exist_ok=True)
    for code, token in (checkpoints or {}).items():
        os.makedirs(os.path.join(MIMECAST_DIR, "checkpoint"), exist_ok=True)
        with open(os.path.join(MIMECAST_DIR, "checkpoint", f"mimecast_{code}.checkpoint"), "w") as fh:
            fh.write(token)


# --- Python as its code reads past its crashes -------------------------------------------------------

PATCHED = {"mimecast": False, "sap_one_key": False}


class _OneKey(str):
    """A key without a comma that takes the several-keys path: `"," in key`, `key.split(",") == [key]`."""

    def __contains__(self, sub):
        return sub == "," or str.__contains__(self, sub)

    def split(self, sep=None, maxsplit=-1):
        if sep == ",":
            return [str(self)]
        return str.split(self, sep, maxsplit)


def install_python_patches(always=False):
    """`always=False`: only while `PATCHED[...]` says so (this process); `True`: for good (the legacy
    process). Both point the Mimecast module's files at MIMECAST_DIR."""
    from app.integrations.mimecast.schema import mimecast as mimecast_schema
    from app.integrations.mimecast.services import mimecast as mimecast_service
    from app.integrations.modules.routes import sap_siem as sap_route
    from app.integrations.modules.schema import sap_siem as sap_schema

    original_response = mimecast_schema.MimecastAPIEndpointResponse

    def endpoint_response(**kwargs):
        # The same validation (the `HttpUrl`s still have to be URLs), then the region's `api` as the
        # string Mimecast sent: `HttpUrl + str` is the `TypeError` every Python run ends in.
        model = original_response(**kwargs)
        if always or PATCHED["mimecast"]:
            for item, raw in zip(model.data.data, kwargs["data"]["data"]):
                object.__setattr__(item.region, "api", raw["region"]["api"])
        return model

    mimecast_service.MimecastAPIEndpointResponse = endpoint_response
    mimecast_service.__file__ = os.path.join(MIMECAST_DIR, "services", "mimecast.py")
    os.makedirs(os.path.join(MIMECAST_DIR, "services"), exist_ok=True)

    original_keys = sap_schema.SapSiemAuthKeys

    def sap_keys(**kwargs):
        # A key without a comma takes the several-keys branch (a list of one): Python's own
        # one-key branch calls `get_customer_meta_attribute` without its session and never sends.
        # (The keys the loop builds are wrapped too, which their dump does not show.)
        model = original_keys(**kwargs)
        if (always or PATCHED["sap_one_key"]) and isinstance(model.API_KEY, str) and "," not in model.API_KEY:
            object.__setattr__(model, "API_KEY", _OneKey(model.API_KEY))
        return model

    sap_route.SapSiemAuthKeys = sap_keys


@contextlib.contextmanager
def python_patched(*names):
    for name in names:
        PATCHED[name] = True
    try:
        yield
    finally:
        for name in names:
            PATCHED[name] = False


APP_KEYS = {"acc-a": ("appkey-a", b"secret-a"), "acc-b": ("appkey-b", None)}
TTP_TIME_RE = re.compile(r"'(from|to)': '(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\+0000'")


def mimecast_signature_ok(headers, path):
    """`MC <access>:<b64 hmac-sha1(date:req_id:uri:app_key)>` with the decoded secret."""
    import base64
    import hashlib
    import hmac

    h = dict(headers)
    auth = h.get("authorization", "")
    access, _, sig = auth[3:].partition(":")
    app_key, secret = APP_KEYS.get(access, (None, None))
    if secret is None:
        return False
    uri = "/api/ttp/url/get-logs" if "/ttp/" in path else "/api/audit/get-siem-logs"
    unsigned = f"{h.get('x-mc-date')}:{h.get('x-mc-req-id')}:{uri}:{app_key}"
    want = base64.b64encode(hmac.new(secret, unsigned.encode(), hashlib.sha1).digest()).decode()
    return sig == want


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DATE_RE = re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d UTC$")
BOUND_RE = re.compile(rb'"(lower_bound|upper_bound)":"(\d{1,4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)"')


def normalised(captured):
    """The requests with their per-run values checked and masked."""
    out = []
    for method, path, headers, body in captured:
        hs = []
        for k, v in headers:
            if k == "authorization" and v.startswith("MC "):
                v = "<MC signature ok>" if mimecast_signature_ok(headers, path) else f"<bad MC signature {v}>"
            elif k == "x-mc-req-id":
                v = "<uuid>" if UUID_RE.match(v) else f"<bad uuid {v}>"
            elif k == "x-mc-date":
                ok = (
                    DATE_RE.match(v)
                    and abs(datetime.datetime.strptime(v, "%a, %d %b %Y %H:%M:%S UTC") - datetime.datetime.utcnow()).total_seconds() < 120
                )
                v = "<date>" if ok else f"<bad date {v}>"
            hs.append((k, v))
        bounds = {m.group(1): m.group(2).decode() for m in BOUND_RE.finditer(body)}
        if "upper_bound" in bounds:
            upper = datetime.datetime.strptime(bounds["upper_bound"], "%Y-%m-%dT%H:%M:%S.%fZ")
            if abs((upper - datetime.datetime.utcnow()).total_seconds()) > 120:
                body = body + b" <upper bound not now>"
        body = BOUND_RE.sub(lambda m: b'"' + m.group(1) + b'":"<' + m.group(1) + b'>"', body)
        times = TTP_TIME_RE.findall(body.decode("utf-8", "replace"))
        if times:
            stale = [
                t
                for _, t in times
                if abs((datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S") - datetime.datetime.utcnow()).total_seconds()) > 3 * 86400
            ]
            body = TTP_TIME_RE.sub(lambda m: f"'{m.group(1)}': '<time>'", body.decode("utf-8", "replace")).encode()
            if stale:
                body += b" <ttp time not near now>"
        out.append({"method": method, "path": path, "headers": hs, "body": body.decode("utf-8", "replace"), "bounds": sorted(bounds)})
    return out


# --- Python's httpx, redirected to the stand-in -------------------------------------------------------

REDIRECT = {"base": STUB}


class _Redirect(httpx.AsyncBaseTransport):
    """What COPILOT_INTEGRATION_MODULES_URL does for the Rust service: `{base}/{host}{path}`."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        base = REDIRECT["base"]
        rest = str(request.url).split("://", 1)[1]
        request.url = httpx.URL(f"{base}/{rest}")
        request.headers["Host"] = base.split("://", 1)[1]
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


def redirect_python_httpx():
    import importlib

    real = httpx.AsyncClient
    shim = types.SimpleNamespace(**{k: getattr(httpx, k) for k in dir(httpx) if not k.startswith("_")})
    shim.AsyncClient = lambda *a, **kw: real(*a, transport=_Redirect(), **kw)
    for name in (
        "app.integrations.modules.services.huntress",
        "app.integrations.modules.services.mimecast",
        "app.integrations.modules.services.duo",
        "app.integrations.modules.services.cato",
        "app.integrations.modules.services.carbonblack",
        "app.integrations.modules.services.darktrace",
        "app.integrations.modules.services.sap_siem.collect",
        "app.integrations.utils.collection",
    ):
        importlib.import_module(name).httpx = shim


# --- Seed ---------------------------------------------------------------------------------------------

SAVED = {"connectors": [], "license": [], "apscheduler": []}
B64_SECRET = "c2VjcmV0LWE="  # base64("secret-a")

# (ci id, customer, service name, [(key, value)])
INTEGRATIONS = (
    (7725001, CUST_A, "Huntress", (("API_KEY", "hk-a"), ("API_SECRET", "hs-a"))),
    (
        7725002,
        CUST_A,
        "Mimecast",
        (
            ("APP_ID", "app-a"),
            ("APP_KEY", "appkey-a"),
            ("EMAIL_ADDRESS", "admin@a.example"),
            ("ACCESS_KEY", "acc-a"),
            ("SECRET_KEY", B64_SECRET),
        ),
    ),
    (7725003, CUST_A, "DUO", (("API_HOSTNAME", "api-a.duosecurity.com"), ("INTEGRATION_KEY", "ik-a"), ("SECRET_KEY", "sk-a"))),
    (
        7725004,
        CUST_A,
        "CATO",
        (("API_KEY", "ck-a"), ("ACCOUNT_ID", " 42 "), ("EVENT_TYPES", "Security"), ("EVENT_SUB_TYPES", "NG Anti Malware,IPS")),
    ),
    (
        7725005,
        CUST_A,
        "SAP SIEM",
        (("API_KEY", "k1,k2"), ("SECRET_KEY", "s-a"), ("USER_KEY", "u-a"), ("API_DOMAIN", "audit.eu1.gigya.com")),
    ),
    (
        7725006,
        CUST_A,
        "CarbonBlack",
        (("API_URL", "https://cb.example"), ("API_KEY", "cbk"), ("API_ID", "cbid"), ("ORGANIZATION_KEY", "org-a")),
    ),
    (7725007, CUST_A, "Darktrace", (("PUBLIC_TOKEN", "pub"), ("PRIVATE_TOKEN", "priv"), ("HOST", "dt.example"), ("PORT", "443"))),
    (7725011, CUST_B, "Huntress", (("API_KEY", "hk-b"),)),
    (7725012, CUST_B, "Mimecast", (("APP_ID", "app-b"), ("APP_KEY", "appkey-b"), ("ACCESS_KEY", "acc-b"), ("SECRET_KEY", "abc"))),
    (7725014, CUST_B, "CATO", (("API_KEY", "ck-b"), ("ACCOUNT_ID", "abc"), ("EVENT_TYPES", "Security"), ("EVENT_SUB_TYPES", "IPS"))),
    (7725015, CUST_B, "SAP SIEM", (("API_KEY", "single"), ("SECRET_KEY", "s-b"), ("API_DOMAIN", "audit.eu1.gigya.com"))),
    (7725016, CUST_B, "CarbonBlack", (("API_URL", "https://cb.example"), ("API_KEY", "cbk"), ("ORGANIZATION_KEY", "org-b"))),
    (7725017, CUST_B, "Darktrace", (("PUBLIC_TOKEN", "pub-b"),)),
    (7725025, CUST_D, "SAP SIEM", (("API_KEY", "d1,d2"), ("SECRET_KEY", "s-d"), ("API_DOMAIN", "audit.eu1.gigya.com"))),
    (
        7725026,
        CUST_E,
        "SAP SIEM",
        (("API_KEY", "e-single"), ("SECRET_KEY", "s-e"), ("USER_KEY", "u-e"), ("API_DOMAIN", "audit.eu1.gigya.com")),
    ),
)

JOB_IDS = (
    "invoke_huntress_integration_collect",
    "invoke_duo_integration_collect",
    "invoke_darktrace_integration_collect",
    "invoke_carbonblack_integration_collection",
    "invoke_mimecast_integration",
    "invoke_mimecast_integration_ttp",
    "invoke_sap_siem_integration_collection",
    "invoke_sap_siem_integration_suspicious_logins_analysis",
    "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
    "invoke_sap_siem_integration_successful_user_login_with_different_ip",
    "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
    "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location",
    "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location",
    "invoke_sap_siem_integration_brute_force_failed_logins",
    "invoke_sap_siem_integration_brute_force_failed_logins_same_ip",
    "invoke_sap_siem_integration_successful_login_after_multiple_failed_logins",
)


def insert_connector(cid, name, url, extra=None, username=None, password=None):
    columns = (
        "connector_name, connector_type, connector_url, connector_last_updated, connector_username, connector_password, "
        "connector_api_key, connector_description, connector_supports, connector_configured, connector_verified, "
        "connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, "
        "connector_accepts_extra_data, connector_extra_data, connector_enabled"
    )
    values = ":n, '3', :u, UTC_TIMESTAMP(), :user, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 1, :x, 1"
    if cid is None:
        sql(f"INSERT INTO connectors ({columns}) VALUES ({values})", n=name, u=url, user=username, pw=password, x=extra)
    else:
        sql(f"INSERT INTO connectors (id, {columns}) VALUES (:i, {values})", i=cid, n=name, u=url, user=username, pw=password, x=extra)


def seed_connectors():
    saved = rows("SELECT * FROM connectors WHERE id IN :i OR connector_name = 'Event Shipper'", i=list(CONNECTOR_IDS))
    SAVED["connectors"].extend(saved)
    sql("DELETE FROM connectors WHERE id IN :i OR connector_name = 'Event Shipper'", i=list(CONNECTOR_IDS))
    insert_connector(1, CONNECTOR_IDS[1], "https://indexer.example:9200", username="indexer-user", password="indexer-pw")
    insert_connector(10, CONNECTOR_IDS[10], "10.0.0.10", extra="12210")
    insert_connector(14, CONNECTOR_IDS[14], "10.0.0.14", extra="12214")
    insert_connector(None, "Event Shipper", "10.0.0.5", extra="12201")


def restore_connectors():
    sql("DELETE FROM connectors WHERE id IN :i OR connector_name = 'Event Shipper'", i=list(CONNECTOR_IDS))
    for row in SAVED["connectors"]:
        sql(f"INSERT INTO connectors ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)


def wipe_integrations():
    cis = list(range(7_725_000, 7_725_100))
    cis += [r["id"] for r in rows("SELECT id FROM customer_integrations WHERE customer_code IN :c", c=list(CUSTOMERS))]
    subs = [r["id"] for r in rows("SELECT id FROM integration_subscriptions WHERE customer_id IN :c", c=cis)]
    subs += list(range(7_725_200, 7_725_300))
    sql("DELETE FROM integration_auth_keys WHERE subscription_id IN :s OR id BETWEEN 7725300 AND 7725499", s=subs)
    sql("DELETE FROM integration_subscriptions WHERE id IN :s", s=subs)
    sql("DELETE FROM customer_integrations WHERE id IN :c", c=cis)
    sql("DELETE FROM integration_services WHERE id BETWEEN 7725100 AND 7725199")


def seed_integrations():
    wipe_integrations()
    key_id = 7_725_300
    for n, (ci, code, service, keys) in enumerate(INTEGRATIONS):
        svc, sub = 7_725_100 + n, 7_725_200 + n
        sql("INSERT INTO integration_services (id, service_name, auth_type) VALUES (:i, :n, 'API Key')", i=svc, n=service)
        sql(
            "INSERT INTO customer_integrations (id, customer_code, customer_name, integration_service_id, integration_service_name, "
            "instance_name, deployed) VALUES (:i, :c, :cn, 1, :n, NULL, 0)",
            i=ci,
            c=code,
            cn=f"{code} name",
            n=service,
        )
        sql("INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES (:i, :c, :s)", i=sub, c=ci, s=svc)
        for k, v in keys:
            sql(
                "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, :s, :k, :v)",
                i=key_id,
                s=sub,
                k=k,
                v=v,
            )
            key_id += 1
    sql("ANALYZE TABLE customer_integrations, integration_subscriptions, integration_services, integration_auth_keys")


def seed_jobs():
    sql("DELETE FROM scheduled_job_metadata WHERE job_id IN :j", j=list(JOB_IDS))
    for job_id in JOB_IDS:
        extra = None
        if job_id.endswith("successful_user_login_with_different_ip"):
            extra = "threshold=2,time_range=10"
        elif job_id.endswith("brute_force_failed_logins_same_ip"):
            extra = "time_range=7,other=x,threshold=4"
        sql(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, enabled, job_description) "
            "VALUES (:j, NULL, 1440, :x, 0, :d)",
            j=job_id,
            x=extra,
            d=JOB_DESCRIPTION,
        )


def seed():
    SAVED["apscheduler"].extend(
        rows("SELECT * FROM apscheduler_jobs WHERE id IN :j", j=list(JOB_IDS)) if table_exists("apscheduler_jobs") else [],
    )
    SAVED["license"].extend(rows("SELECT * FROM license"))
    if not SAVED["license"]:
        sql(
            "INSERT INTO license (license_key, customer_name, customer_email, company_name) VALUES (:k, 'p', 'p@example.com', 'p')",
            k=f"lic-{SFX}",
        )
    seed_connectors()
    for code in CUSTOMERS:
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=f"{code} name")
    for code, iris in ((CUST_A, IRIS_A), (CUST_B, None), (CUST_C, IRIS_B), (CUST_E, IRIS_E)):
        sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group, customer_meta_iris_customer_id) VALUES (:c, :n, 'i', 's', '1', 'g', :r)",
            c=code,
            n=f"{code} name",
            r=iris,
        )
    for name, role in ((ADMIN, 1), (ANALYST, 2), (ANALYST_B, 2), (UNASSIGNED, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'im@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name, codes in ((ANALYST, (CUST_A, CUST_C)), (ANALYST_B, (CUST_B,))):
        for code in codes:
            sql(
                "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` "
                "WHERE username = :n",
                c=code,
                n=name,
            )
    seed_integrations()
    seed_jobs()


def table_exists(name):
    return bool(rows("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :t", t=name))


def cleanup():
    wipe_integrations()
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    sql("DELETE FROM customersmeta WHERE customer_code IN :c", c=list(CUSTOMERS))
    sql("DELETE FROM customers WHERE customer_code IN :c", c=list(CUSTOMERS))
    sql("DELETE FROM scheduled_job_metadata WHERE job_description = :d", d=JOB_DESCRIPTION)
    if table_exists("apscheduler_jobs"):
        sql("DELETE FROM apscheduler_jobs WHERE id IN :j", j=list(JOB_IDS))
        for row in SAVED["apscheduler"]:
            sql(f"INSERT INTO apscheduler_jobs ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    sql("DELETE FROM license WHERE license_key = :k", k=f"lic-{SFX}")
    present = {r["id"] for r in rows("SELECT id FROM license")}
    for row in SAVED["license"]:
        if row["id"] not in present:
            sql(f"INSERT INTO license ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    restore_connectors()


def without_license():
    sql("DELETE FROM license")


def with_license():
    present = {r["id"] for r in rows("SELECT id FROM license")}
    if not SAVED["license"]:
        if not rows("SELECT 1 FROM license WHERE license_key = :k", k=f"lic-{SFX}"):
            sql(
                "INSERT INTO license (license_key, customer_name, customer_email, company_name) VALUES (:k, 'p', 'p@example.com', 'p')",
                k=f"lic-{SFX}",
            )
        return
    for row in SAVED["license"]:
        if row["id"] not in present:
            sql(f"INSERT INTO license ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)


def log_rows(after):
    """The handled errors each side logged (`log_entries`), for the test users."""
    return [
        {
            **{k: r[k] for k in ("event_type", "method", "status_code", "message", "additional_info")},
            # The URL as each side saw it: the in-process client's base differs.
            "route": re.sub(r"^https?://[^/]*", "", r["route"] or ""),
        }
        for r in rows(
            "SELECT * FROM log_entries WHERE id > :a AND user_id IN (SELECT id FROM `user` WHERE username IN :u) ORDER BY id",
            a=after,
            u=list(USERS),
        )
    ]


def last_log_id():
    return rows("SELECT COALESCE(MAX(id), 0) AS m FROM log_entries")[0]["m"]


# --- The backends -------------------------------------------------------------------------------------


def build_python_app(with_scheduler=False):
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import mimecast
    from app.routers import modules
    from app.schedulers import scheduler as scheduler_module
    from app.schedulers.routes.scheduler import scheduler_router

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        if not with_scheduler:
            yield
            return
        # The real scheduler on the real store, paused: the jobs are stored, none fires.
        scheduler = AsyncIOScheduler(event_loop=asyncio.get_running_loop())
        scheduler.configure(jobstores={"default": SQLAlchemyJobStore(engine=sync_engine)})
        scheduler.start(paused=True)
        scheduler_module.scheduler_instance = scheduler
        for job_id in JOB_IDS:
            scheduler.add_job(
                scheduler_module.get_function_by_name(job_id),
                "interval",
                minutes=1440,
                id=job_id,
                replace_existing=True,
                coalesce=True,
                max_instances=1,
            )
        yield
        scheduler.shutdown(wait=False)

    test_router = APIRouter()

    @test_router.post("/__test/tick/{job_id}")
    async def scheduled_tick(job_id: str):
        """What APScheduler does on a fire: call the function (outside a manual run)."""
        from app.schedulers.handover import JOB_SKIPPED

        try:
            result = await scheduler_module.get_function_by_name(job_id)()
        except Exception as e:  # noqa: BLE001
            return {"outcome": "raised", "error": str(e)}
        return {"outcome": "skipped" if result is JOB_SKIPPED else "ran"}

    api = APIRouter(prefix="/api")
    api.include_router(modules.router)
    api.include_router(mimecast.router)
    if with_scheduler:
        api.include_router(scheduler_router, prefix="/scheduler")
    app = FastAPI(redirect_slashes=False, lifespan=lifespan)
    app.include_router(api)
    if with_scheduler:
        app.include_router(test_router)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def wait_port(port, proc):
    import socket

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
    """The legacy backend the Rust instances fall back to: the same routers and the scheduler
    routes over a paused APScheduler, its httpx redirected like this process's, in a process of
    its own (its event loop owns its database connections)."""
    code = (
        "import sys; sys.path.insert(0, %r); import rust_parity_integration_modules_e2e as m; m.redirect_python_httpx(); "
        "m.install_python_patches(always=True); "
        "import uvicorn; uvicorn.run(m.build_python_app(with_scheduler=True), host='127.0.0.1', port=%d, log_level='warning')"
    ) % (HERE, PY_PORT)
    env = {**os.environ, "PYTHONPATH": BACKEND, "INTEGRATION_MODULES_PARITY_SFX": SFX}
    proc = subprocess.Popen([sys.executable, "-c", code], env=env, cwd=BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(PY_PORT, proc)
    return proc


def start_rust(port, modules_url, rs_jobs=None):
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
        "COPILOT_PORT": str(port),
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}",
        "COPILOT_INTEGRATION_MODULES_URL": modules_url,
        "COPILOT_MIMECAST_DIR": MIMECAST_DIR,
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    if rs_jobs:
        env["COPILOT_RS_JOBS"] = rs_jobs
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"the Rust instance on {port} did not start")


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)
        self.rs_closed = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_CLOSED_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        STUB_STATE.take()
        mark = last_log_id()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0.05)
        logs = log_rows(mark)
        # The Rust service writes a handled error's row on a task of its own.
        handled = r.status_code >= 400 and r.headers.get("content-type", "").startswith("application/json")
        for _ in range(40):
            if logs or not handled:
                break
            await asyncio.sleep(0.05)
            logs = log_rows(mark)
        return r, normalised(STUB_STATE.take()), logs

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        before=None,
        stub=None,
        closed=False,
        expect=None,
        patched=(),
        files=None,
        **kw,
    ):
        """Python, then Rust, each from the same seed (`before()` on top) and stand-in (`stub`).
        `closed`: the modules are on a port nothing listens on. `expect=(python, rust)`: the
        statuses of a deliberate difference. `patched`: Python runs as its code reads past its
        crash (`python_patched`). `files`: the Mimecast checkpoints each side starts from; the
        Mimecast directory and the GELF frames are compared too."""
        sides = []
        for client in (self.py, self.rs_closed if closed else self.rs):
            seed_integrations()
            with_license()
            if files is not None:
                reset_mimecast_files(files)
                take_gelf(settle=0.0, timeout=0.0)
            if before:
                before()
            STUB_STATE.reset(stub)
            REDIRECT["base"] = CLOSED if closed else STUB
            with python_patched(*(patched if client is self.py else ())):
                r, out, logs = await self.call(client, method, path, tok, **kw)
            extra = (mimecast_files(), take_gelf()) if files is not None else None
            sides.append((r, out, logs, extra))
        REDIRECT["base"] = STUB
        (r1, o1, l1, x1), (r2, o2, l2, x2) = sides
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2
        ok = r1.status_code == r2.status_code and r1.content == r2.content and o1 == o2 and l1 == l2 and x1 == x2
        detail = f"python {r1.status_code} {r1.content[:900]!r}\n        rust   {r2.status_code} {r2.content[:900]!r}"
        if o1 != o2:
            detail += f"\n        outbound python {o1}\n        outbound rust   {o2}"
        if l1 != l2:
            detail += f"\n        log_entries python {l1}\n        log_entries rust   {l2}"
        if x1 != x2:
            detail += f"\n        files+gelf python {x1}\n        files+gelf rust   {x2}"
        if r1.headers.get("content-type") != r2.headers.get("content-type"):
            ok = False
            detail += f"\n        content-type {r1.headers.get('content-type')} / {r2.headers.get('content-type')}"
        suffix = f", {len(x1[0])} files, {len(x1[1])} gelf" if x1 else ""
        check(f"{name} [{r1.status_code}, {len(o1)} out{suffix}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {r1.content[:600]!r}\n        outbound {o1}\n        extra {x1}")
        return r1, r2

    async def close(self):
        for c in (self.py, self.rs, self.rs_closed):
            await c.aclose()


# --- The checks ---------------------------------------------------------------------------------------

M = "/api/integrations/modules"
J = "application/json"


def no_event_shipper():
    sql("UPDATE connectors SET connector_name = :n WHERE connector_name = 'Event Shipper'", n=f"Event Shipper off {SFX}")


def event_shipper_back():
    sql("UPDATE connectors SET connector_name = 'Event Shipper' WHERE connector_name = :n", n=f"Event Shipper off {SFX}")


def no_indexer_password():
    sql("UPDATE connectors SET connector_password = NULL WHERE id = 1")


def indexer_password_back():
    sql("UPDATE connectors SET connector_password = 'indexer-pw' WHERE id = 1")


async def module_checks(p, t):
    for name, model_name in (("huntress", "Huntress"), ("mimecast", "Mimecast"), ("duo", "Duo"), ("cato", "Cato")):
        path = f"{M}/{name}"
        await p.same(f"{name}: no token", "POST", path, json={"customer_code": CUST_A})
        await p.same(f"{name}: malformed JSON, no token", "POST", path, content=b"{", headers={"Content-Type": J})
        await p.same(f"{name}: no body", "POST", path, t["admin"])
        await p.same(f"{name}: empty object", "POST", path, t["admin"], json={})
        await p.same(f"{name}: a list", "POST", path, t["admin"], json=[1])
        await p.same(f"{name}: raw bytes", "POST", path, t["admin"], content=b"x")
        await p.same(f"{name}: an int customer", "POST", path, t["admin"], json={"customer_code": 7})
        await p.same(f"{name}: collected for A", "POST", path, t["analyst"], json={"customer_code": CUST_A})
        await p.same(f"{name}: A, admin", "POST", path, t["admin"], json={"customer_code": CUST_A, "extra": 1})
        await p.same(f"{name}: B's broken keys or none", "POST", path, t["admin"], json={"customer_code": CUST_B})
        await p.same(f"{name}: no integrations at all", "POST", path, t["admin"], json={"customer_code": CUST_C})
        await p.same(
            f"{name}: unknown integration name",
            "POST",
            path,
            t["admin"],
            json={"customer_code": CUST_A, "integration_name": "Nope"},
        )
        await p.same(
            f"{name}: the module answers 500",
            "POST",
            path,
            t["admin"],
            json={"customer_code": CUST_A},
            stub={("POST", "/copilot-*"): (500, J, b'{"detail":"boom"}', [])},
        )
        await p.same(
            f"{name}: the module answers 404",
            "POST",
            path,
            t["admin"],
            json={"customer_code": CUST_A},
            stub={("POST", "/copilot-*"): (404, "text/plain", b"nope", [])},
        )
        await p.same(
            f"{name}: the module hangs up",
            "POST",
            path,
            t["admin"],
            json={"customer_code": CUST_A},
            stub={("POST", "/copilot-*"): "close"},
        )
        await p.same(f"{name}: the module is not there", "POST", path, t["admin"], json={"customer_code": CUST_A}, closed=True)
        await p.same(f"{name}: GET (405 from Python)", "GET", path, t["admin"])
        await p.same(f"{name}: analyst of B for A", "POST", path, t["analyst_b"], json={"customer_code": CUST_A}, expect=(200, 403))
        await p.same(f"{name}: unassigned analyst", "POST", path, t["unassigned"], json={"customer_code": CUST_A}, expect=(200, 403))
        await p.same(
            f"{name}: analyst of A, unknown customer",
            "POST",
            path,
            t["analyst"],
            json={"customer_code": f"ZZ{SFX}"},
            expect=(200, 403),
        )
        await p.same(f"{name}: admin, unknown customer", "POST", path, t["admin"], json={"customer_code": f"ZZ{SFX}"})
        await p.same(
            f"{name}: no Event Shipper connector",
            "POST",
            path,
            t["admin"],
            json={"customer_code": CUST_A},
            before=no_event_shipper,
        )
        event_shipper_back()
    await p.same(
        "huntress: the indexer password unset",
        "POST",
        f"{M}/huntress",
        t["admin"],
        json={"customer_code": CUST_A},
        before=no_indexer_password,
    )
    indexer_password_back()
    await p.same("mimecast: no licence", "POST", f"{M}/mimecast", t["admin"], json={"customer_code": CUST_A}, before=without_license)
    await p.same(
        "duo: the body's integration name is ignored",
        "POST",
        f"{M}/duo",
        t["admin"],
        json={"customer_code": CUST_A, "integration_name": "x"},
    )
    await p.same(
        "cato: the name is case-sensitive",
        "POST",
        f"{M}/cato",
        t["admin"],
        json={"customer_code": CUST_A, "integration_name": "Cato"},
    )
    await p.same("huntress: a non-ASCII customer code", "POST", f"{M}/huntress", t["admin"], json={"customer_code": "IMä"})


async def sap_checks(p, t):
    path = f"{M}/sap_siem"
    await p.same("sap: no token", "POST", path, json={"customer_code": CUST_A})
    await p.same("sap: malformed JSON", "POST", path, t["admin"], content=b"[", headers={"Content-Type": J})
    await p.same("sap: no body", "POST", path, t["admin"])
    await p.same("sap: raw bytes (bytes.get)", "POST", path, t["admin"], content=b"abc")
    await p.same("sap: a list body (list.get)", "POST", path, t["admin"], json=[1, 2])
    await p.same("sap: a string body", "POST", path, t["admin"], json="x")
    await p.same("sap: empty object", "POST", path, t["admin"], json={})
    await p.same("sap: two keys, two posts", "POST", path, t["analyst"], json={"customer_code": CUST_A})
    await p.same(
        "sap: two keys, 2h, threshold as text",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A, "time_range": "2h", "threshold": "7"},
    )
    await p.same(
        "sap: two keys, no window",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A, "time_range": None, "threshold": None},
    )
    # One key: Python's `get_customer_meta_attribute` without its session (a bare 500 on every run);
    # Rust POSTs it as the several-keys path POSTs each key — compared with Python taking that path.
    await p.same("sap: one key, Python's Depends.execute", "POST", path, t["admin"], json={"customer_code": CUST_E}, expect=(500, 200))
    await p.same(
        "sap: one key, as the several-keys path",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_E},
        patched=("sap_one_key",),
    )
    await p.same(
        "sap: one key, 1h, threshold 9",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_E, "time_range": "1h", "threshold": 9},
        patched=("sap_one_key",),
    )
    await p.same(
        "sap: one key, no IRIS id (CustomerDetails)",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_B},
        patched=("sap_one_key",),
    )
    await p.same(
        "sap: one key, the module is not there (swallowed)",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_E},
        patched=("sap_one_key",),
        closed=True,
    )
    await p.same("sap: no IRIS id (CustomerDetails)", "POST", path, t["admin"], json={"customer_code": CUST_D})
    await p.same("sap: no integrations", "POST", path, t["admin"], json={"customer_code": CUST_C})
    await p.same("sap: another name", "POST", path, t["admin"], json={"customer_code": CUST_A, "integration_name": "Huntress"})
    await p.same(
        "sap: the module answers text",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A},
        stub={("POST", "/copilot-sap-module/*"): (200, "text/plain", b"ok", [])},
    )
    await p.same(
        "sap: the module answers an empty 500",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A},
        stub={("POST", "/copilot-sap-module/*"): (500, None, b"", [])},
    )
    await p.same(
        "sap: the module hangs up (swallowed)",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A},
        stub={("POST", "/copilot-sap-module/*"): "close"},
    )
    await p.same("sap: the module is not there (swallowed)", "POST", path, t["admin"], json={"customer_code": CUST_A}, closed=True)
    for label, window in (
        ("5x (lower_bound unbound)", "5x"),
        ("ab (int())", "ab"),
        ("5 (int subscript)", 5),
        ("0m (pattern)", "0m"),
        ("-5m (pattern after the bounds)", "-5m"),
        ("empty (pattern)", ""),
        ("[] (falsy, string_type)", []),
        ('["5","m"] (int(list))', ["5", "m"]),
        ("a dict (KeyError)", {"a": 1}),
        ("true (bool subscript)", True),
        ("99999999999w (overflow)", "99999999999w"),
        ("60000w (a year below 1000)", "60000w"),
        (" 5m (int strips, pattern does not)", " 5m"),
        ("1_0m", "1_0m"),
    ):
        await p.same(f"sap: time_range {label}", "POST", path, t["admin"], json={"customer_code": CUST_A, "time_range": window})
    await p.same(
        "sap: a bound sent with no window",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A, "time_range": None, "lower_bound": 5},
    )
    await p.same(
        "sap: a bound overwritten",
        "POST",
        path,
        t["admin"],
        json={"customer_code": CUST_A, "lower_bound": 5, "upper_bound": None},
    )
    await p.same("sap: analyst of B for A", "POST", path, t["analyst_b"], json={"customer_code": CUST_A}, expect=(200, 403))
    for route in (
        "successful_user_login_with_different_ip",
        "same_user_failed_login_from_different_ip",
        "same_user_failed_login_from_different_geo_location",
        "same_user_successful_login_from_different_geo_location",
        "brute_force_failed_logins_multiple_ips",
        "brute_force_failed_logins_same_ip",
        "successful_login_after_multiple_failed_logins",
    ):
        await p.same(
            f"sap {route}: A's IRIS id",
            "POST",
            f"{path}/{route}",
            t["analyst"],
            json={"iris_customer_id": IRIS_A, "threshold": 3, "time_range": 20},
        )
        await p.same(f"sap {route}: the defaults", "POST", f"{path}/{route}", t["admin"], json={"iris_customer_id": IRIS_A})
    a = f"{path}/same_user_failed_login_from_different_ip"
    await p.same("sap analysis: no token", "POST", a, json={"iris_customer_id": IRIS_A})
    await p.same("sap analysis: no IRIS id", "POST", a, t["admin"], json={})
    await p.same("sap analysis: IRIS id as text", "POST", a, t["admin"], json={"iris_customer_id": "7725101", "threshold": "2"})
    await p.same("sap analysis: not ints", "POST", a, t["admin"], json={"iris_customer_id": "x", "threshold": 1.5, "time_range": "y"})
    await p.same("sap analysis: an unknown IRIS id, admin", "POST", a, t["admin"], json={"iris_customer_id": IRIS_UNKNOWN})
    await p.same(
        "sap analysis: the module answers text",
        "POST",
        a,
        t["admin"],
        json={"iris_customer_id": IRIS_A},
        stub={("POST", "/copilot-sap-module/*"): (200, "text/html", b"<p>", [])},
    )
    await p.same("sap analysis: the module is not there", "POST", a, t["admin"], json={"iris_customer_id": IRIS_A}, closed=True)
    await p.same("sap analysis: analyst of A, C's IRIS id", "POST", a, t["analyst"], json={"iris_customer_id": IRIS_B})
    await p.same("sap analysis: analyst of B, A's IRIS id", "POST", a, t["analyst_b"], json={"iris_customer_id": IRIS_A}, expect=(200, 403))
    await p.same(
        "sap analysis: analyst, an unknown IRIS id",
        "POST",
        a,
        t["analyst"],
        json={"iris_customer_id": IRIS_UNKNOWN},
        expect=(200, 403),
    )
    await p.same("sap analysis: GET (405 from Python)", "GET", a, t["admin"])


def discovery(body, status=200, ctype=J, extra=()):
    return {
        ("POST", "/api.mimecast.com/*"): (status, ctype, json.dumps(body).encode() if not isinstance(body, bytes) else body, list(extra)),
    }


def mimecast_zip(members):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


SIEM = "/us-api.mimecast.com/api/audit/get-siem-logs"
TTP = "/us-api.mimecast.com/api/ttp/url/get-logs"
OCTET = "application/octet-stream"


def siem_page(name, body, token="token-1", disposition=None, extra=()):
    headers = [("Content-Disposition", disposition or f'attachment; filename="{name}"')]
    if token is not None:
        headers.append(("mc-siem-token", token))
    return (200, OCTET, body, headers + list(extra))


def event_shipper_at_gelf():
    sql(
        "UPDATE connectors SET connector_url = '127.0.0.1', connector_extra_data = :p WHERE connector_name = 'Event Shipper'",
        p=str(GELF_PORT),
    )


def event_shipper_back_to_seed():
    sql("UPDATE connectors SET connector_url = '10.0.0.5', connector_extra_data = '12201' WHERE connector_name = 'Event Shipper'")


async def mimecast_checks(p, t):
    region = DISCOVERY_OK["data"][0]["region"]
    bad_url = {**DISCOVERY_OK, "data": [{**DISCOVERY_OK["data"][0], "region": {**region, "mpp": "ftp://x"}}]}
    no_data = {**DISCOVERY_OK, "data": []}
    event_shipper_at_gelf()
    mc = {"patched": ("mimecast",), "files": {}}
    try:
        for route in ("invoke", "ttp/urls"):
            path = f"/api/mimecast/{route}"
            # Python as it is: the region's `HttpUrl + str` (/invoke's 400, /ttp/urls' bare 500).
            await p.same(
                f"mimecast {route}: A, Python's HttpUrl + str",
                "POST",
                path,
                t["analyst"],
                json={"customer_code": CUST_A},
                expect=(400 if route == "invoke" else 500, 200),
            )
            await p.same(f"mimecast {route}: no token", "POST", path, json={"customer_code": CUST_A}, **mc)
            await p.same(f"mimecast {route}: no body", "POST", path, t["admin"], **mc)
            await p.same(f"mimecast {route}: a list", "POST", path, t["admin"], json=[], **mc)
            await p.same(
                f"mimecast {route}: time_range 0m",
                "POST",
                path,
                t["admin"],
                json={"customer_code": CUST_A, "time_range": "0m"},
                **mc,
            )
            await p.same(f"mimecast {route}: time_range 5", "POST", path, t["admin"], json={"customer_code": 5, "time_range": 5}, **mc)
            await p.same(f"mimecast {route}: A", "POST", path, t["analyst"], json={"customer_code": CUST_A}, **mc)
            await p.same(f"mimecast {route}: A, 2d", "POST", path, t["admin"], json={"customer_code": CUST_A, "time_range": "2d"}, **mc)
            await p.same(
                f"mimecast {route}: A, no window",
                "POST",
                path,
                t["admin"],
                json={"customer_code": CUST_A, "time_range": None},
                **mc,
            )
            await p.same(f"mimecast {route}: B (no email, a bad secret)", "POST", path, t["admin"], json={"customer_code": CUST_B}, **mc)
            await p.same(f"mimecast {route}: no integrations", "POST", path, t["admin"], json={"customer_code": CUST_C}, **mc)
            await p.same(
                f"mimecast {route}: another name",
                "POST",
                path,
                t["admin"],
                json={"customer_code": CUST_A, "integration_name": "DUO"},
                **mc,
            )
            for label, stub in (
                ("discovery 500", discovery({"x": 1}, 500)),
                ("discovery, an ftp URL", discovery(bad_url)),
                ("discovery, no region", discovery(no_data)),
                ("discovery, not JSON", discovery(b"<html>", 200, "text/html")),
                ("discovery, broken JSON", discovery(b"{", 200, J)),
                (
                    "discovery 429, then fine",
                    {
                        ("POST", "/api.mimecast.com/*"): [
                            (429, J, b"{}", [("X-RateLimit-Reset", "0")]),
                            (200, J, json.dumps(DISCOVERY_OK).encode(), []),
                        ],
                    },
                ),
                ("discovery 429, an unreadable reset", {("POST", "/api.mimecast.com/*"): (429, J, b"{}", [("X-RateLimit-Reset", "soon")])}),
                ("discovery hangs up", {("POST", "/api.mimecast.com/*"): "close"}),
            ):
                await p.same(f"mimecast {route}: {label}", "POST", path, t["admin"], json={"customer_code": CUST_A}, stub=stub, **mc)
            await p.same(
                f"mimecast {route}: Mimecast is not there",
                "POST",
                path,
                t["admin"],
                json={"customer_code": CUST_A},
                closed=True,
                **mc,
            )
            await p.same(
                f"mimecast {route}: analyst of B for A",
                "POST",
                path,
                t["analyst_b"],
                json={"customer_code": CUST_A},
                expect=(200, 403),
                patched=("mimecast",),
            )
            await p.same(f"mimecast {route}: GET (405 from Python)", "GET", path, t["admin"])

        # The SIEM download: a zip of log files, each line an event, the next token kept.
        inv = "/api/mimecast/invoke"
        a = {"customer_code": CUST_A}
        logs = mimecast_zip(
            [
                ("mta_1.log", b"datetime=2026-10-17T10:00:00+0000|aCode=a1|acc=C0A0|Sender=x@evil.example\nAct=Acc | Dir = in | x==y\n"),
                ("mta_2.log", "aCode=a2|Subject=caf\u00e9|junk\r\nlast=1".encode()),
            ],
        )
        for label, stub, files in (
            ("a zip of two files", {("POST", SIEM): siem_page("mta_1.zip", logs)}, {}),
            ("a zip, the stored token sent", {("POST", SIEM): siem_page("mta_2.zip", logs, token="token-2")}, {CUST_A: "token-1"}),
            ("an empty zip", {("POST", SIEM): siem_page("e.zip", mimecast_zip([]))}, {}),
            ("a zip holding a directory", {("POST", SIEM): siem_page("d.zip", mimecast_zip([("sub/x.log", b"a=1")]))}, {}),
            ("a broken zip", {("POST", SIEM): siem_page("bad.zip", b"PK not really")}, {}),
            ("not a zip (bytes to a text file)", {("POST", SIEM): siem_page("mta.log", b"a=1")}, {}),
            ("no Content-Disposition", {("POST", SIEM): (200, OCTET, logs, [("mc-siem-token", "t")])}, {}),
            ('a Content-Disposition without ="', {("POST", SIEM): siem_page("x", logs, disposition="attachment")}, {}),
            ("no mc-siem-token", {("POST", SIEM): siem_page("m.zip", logs, token=None)}, {}),
            ("no Content-Type", {("POST", SIEM): (200, None, b"x", [])}, {}),
            ("text/plain (nothing to do)", {("POST", SIEM): (200, "text/plain", b"x", [])}, {}),
            ("JSON with a charset (nothing to do)", {("POST", SIEM): (200, "application/json; charset=utf-8", b"{}", [])}, {}),
            ("a 500 in JSON (no more logs)", {("POST", SIEM): (500, J, b'{"fail": []}', [])}, {}),
            ("Mimecast hangs up", {("POST", SIEM): "close"}, {}),
            ("a line that is not UTF-8", {("POST", SIEM): siem_page("u.zip", mimecast_zip([("u.log", b"a=1\nb=\xff\n")]))}, {}),
            (
                "a line naming customer_code",
                {("POST", SIEM): siem_page("c.zip", mimecast_zip([("c.log", b"x=1\ncustomer_code=evil\n")]))},
                {},
            ),
        ):
            await p.same(f"mimecast siem: {label}", "POST", inv, t["admin"], json=a, stub=stub, patched=("mimecast",), files=files)
        # A plain file left in the log directory by an earlier run is Python's crash on the walk.
        await p.same(
            "mimecast siem: a leftover plain file",
            "POST",
            inv,
            t["admin"],
            json=a,
            before=lambda: (
                os.makedirs(os.path.join(MIMECAST_DIR, "logs", CUST_A), exist_ok=True),
                open(os.path.join(MIMECAST_DIR, "logs", CUST_A, "left.log"), "w").close(),
            ),
            patched=("mimecast",),
            files={CUST_A: "token-9"},
        )
        await p.same(
            "mimecast siem: no Event Shipper",
            "POST",
            inv,
            t["admin"],
            json=a,
            before=no_event_shipper,
            stub={("POST", SIEM): siem_page("m.zip", logs)},
            patched=("mimecast",),
            files={},
        )
        event_shipper_back()

        # The TTP URL pages: the page token carried, the same signed headers on every page.
        ttp = "/api/mimecast/ttp/urls"
        for label, stub in (
            ("one page", {("POST", TTP): (200, J, json.dumps(ttp_page([click_log(1), click_log(2)])).encode(), [])}),
            (
                "two pages",
                {
                    ("POST", TTP): [
                        (200, J, json.dumps(ttp_page([click_log(1)], next_token="p'2\"")).encode(), []),
                        (200, J, json.dumps(ttp_page([click_log(2)], next_token="")).encode(), []),
                    ],
                },
            ),
            ("an empty page", {("POST", TTP): (200, J, json.dumps(ttp_page([])).encode(), [])}),
            ("no data item (IndexError)", {("POST", TTP): (200, J, json.dumps({**ttp_page([]), "data": []}).encode(), [])}),
            ("a click log missing a field", {("POST", TTP): (200, J, json.dumps(ttp_page([{"url": "x"}])).encode(), [])}),
            ("not JSON", {("POST", TTP): (200, "text/html", b"<html>", [])}),
            ("a list (TypeError)", {("POST", TTP): (200, J, b"[1]", [])}),
            ("a 500", {("POST", TTP): (500, J, b'{"meta": {}}', [])}),
            ("Mimecast hangs up", {("POST", TTP): "close"}),
        ):
            await p.same(
                f"mimecast ttp: {label}",
                "POST",
                ttp,
                t["admin"],
                json={"customer_code": CUST_A, "time_range": "1h"},
                stub=stub,
                **mc,
            )
    finally:
        event_shipper_back_to_seed()


# --- The jobs -----------------------------------------------------------------------------------------


def job_state():
    return {
        r["job_id"]: r["last_success"] is not None
        for r in rows("SELECT job_id, last_success FROM scheduled_job_metadata WHERE job_description = :d", d=JOB_DESCRIPTION)
    }


async def job_checks(t):
    py = httpx.AsyncClient(base_url=f"http://127.0.0.1:{PY_PORT}", timeout=120)
    rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{JOBS_PORT}", timeout=120)
    admin = {"Authorization": f"Bearer {t['admin']}"}

    async def both(name, job_id, before=None, stub=None, expect=None):
        got = {}
        for tag, client in (("py", py), ("rs", rs)):
            seed_integrations()
            with_license()
            sql("UPDATE scheduled_job_metadata SET last_success = NULL, enabled = 0 WHERE job_description = :d", d=JOB_DESCRIPTION)
            if before:
                before()
            STUB_STATE.reset(stub)
            STUB_STATE.take()
            reset_mimecast_files()
            take_gelf(settle=0.0, timeout=0.0)
            r = await client.post(f"/api/scheduler/jobs/run/{job_id}", headers=admin)
            await asyncio.sleep(0.05)
            got[tag] = {
                "status": r.status_code,
                "body": r.content.decode(),
                "out": normalised(STUB_STATE.take()),
                "stamped": job_state(),
                "files": mimecast_files(),
                "gelf": take_gelf(),
            }
        check(
            f"job {name} [{got['py']['status']}, {len(got['py']['out'])} out]",
            expect(got) if expect else json.dumps(got["py"], default=str) == json.dumps(got["rs"], default=str),
            f"python {json.dumps(got['py'], default=str)[:3000]}\n        rust   {json.dumps(got['rs'], default=str)[:3000]}",
        )
        return got

    def only(*keep):
        """Leave only these integration rows (by id): the others move to another service name."""

        def apply():
            sql(
                "UPDATE customer_integrations SET integration_service_name = CONCAT('off-', integration_service_name) WHERE id BETWEEN 7725000 AND 7725099 AND id NOT IN :k",
                k=list(keep),
            )

        return apply

    try:
        await both("huntress: one customer fails (RuntimeError, no stamp)", "invoke_huntress_integration_collect")
        await both("huntress: all collected", "invoke_huntress_integration_collect", before=only(7725001))
        await both("huntress: no customer", "invoke_huntress_integration_collect", before=only())
        await both(
            "huntress: the module is down",
            "invoke_huntress_integration_collect",
            before=only(7725001),
            stub={("POST", "/copilot-*"): (503, J, b"{}", [])},
        )
        await both("duo (failures ignored, stamped)", "invoke_duo_integration_collect")
        await both("darktrace", "invoke_darktrace_integration_collect")
        await both(
            "carbonblack: Python's run route cannot find its function (a 500), Rust runs it (§4)",
            "invoke_carbonblack_integration_collection",
            expect=lambda got: got["py"]["status"] == 500
            and "has no entry in get_function_by_name" in got["py"]["body"]
            and not got["py"]["out"]
            and got["rs"]["status"] == 200
            and json.loads(got["rs"]["body"])["result"] == {"success": True, "message": "Carbonblack integration invoked."}
            and len(got["rs"]["out"]) == 1
            and got["rs"]["stamped"]["invoke_carbonblack_integration_collection"] is True,
        )
        # The legacy Python runs Mimecast and SAP SIEM as their code reads past the crash (above, the
        # in-process Python shows the crash itself: `mimecast_job_crash`).
        event_shipper_at_gelf()
        await both("mimecast: A collects, B's secret fails the run", "invoke_mimecast_integration")
        await both(
            "mimecast: A only, a zip downloaded",
            "invoke_mimecast_integration",
            before=only(7725002),
            stub={("POST", SIEM): siem_page("j.zip", mimecast_zip([("j.log", b"a=1|b=2\n")]))},
        )
        await both("mimecast: no customer (stamped)", "invoke_mimecast_integration", before=only())
        await both("mimecast ttp: B fails the run", "invoke_mimecast_integration_ttp")
        await both(
            "mimecast ttp: A only, a page",
            "invoke_mimecast_integration_ttp",
            before=only(7725002),
            stub={("POST", TTP): (200, J, json.dumps(ttp_page([click_log(5)])).encode(), [])},
        )
        event_shipper_back_to_seed()
        await both("sap collection: B's single key (no IRIS id) fails the run", "invoke_sap_siem_integration_collection")
        await both("sap collection: E's single key", "invoke_sap_siem_integration_collection", before=only(7725026))
        await both("sap collection: A only", "invoke_sap_siem_integration_collection", before=only(7725005))
        await both(
            "sap collection: a 0-minute interval (pattern)",
            "invoke_sap_siem_integration_collection",
            before=lambda: (
                only(7725005)(),
                sql("UPDATE scheduled_job_metadata SET time_interval = 0 WHERE job_id = 'invoke_sap_siem_integration_collection'"),
            ),
        )
        sql("UPDATE scheduled_job_metadata SET time_interval = 1440 WHERE job_id = 'invoke_sap_siem_integration_collection'")
        await both("sap suspicious logins (a no-op)", "invoke_sap_siem_integration_suspicious_logins_analysis")
        await both("sap multiple logins (a no-op)", "invoke_sap_siem_integration_multiple_logins_same_ip_analysis")
        for job_id in JOB_IDS[9:]:
            await both(f"{job_id[len('invoke_sap_siem_integration_'):]}: B has no IRIS id", job_id)
            await both(f"{job_id[len('invoke_sap_siem_integration_'):]}: A only", job_id, before=only(7725005))
        await both(
            "an analysis: extra_data without '='",
            "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
            before=lambda: (
                only(7725005)(),
                sql(
                    "UPDATE scheduled_job_metadata SET extra_data = 'threshold' WHERE job_id = 'invoke_sap_siem_integration_same_user_failed_login_from_different_ip'",
                ),
            ),
        )
        await both(
            "an analysis: extra_data without threshold (unbound)",
            "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
            before=lambda: (
                only(7725005)(),
                sql(
                    "UPDATE scheduled_job_metadata SET extra_data = 'time_range=3' WHERE job_id = 'invoke_sap_siem_integration_same_user_failed_login_from_different_ip'",
                ),
            ),
        )
        await both(
            "an analysis: extra_data not an int",
            "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
            before=lambda: (
                only(7725005)(),
                sql(
                    "UPDATE scheduled_job_metadata SET extra_data = 'threshold=x' WHERE job_id = 'invoke_sap_siem_integration_same_user_failed_login_from_different_ip'",
                ),
            ),
        )
        sql(
            "UPDATE scheduled_job_metadata SET extra_data = NULL WHERE job_id = 'invoke_sap_siem_integration_same_user_failed_login_from_different_ip'",
        )

        # The hand-over itself.
        seed_integrations()
        sql("UPDATE scheduled_job_metadata SET last_success = NULL, enabled = 0 WHERE job_description = :d", d=JOB_DESCRIPTION)
        STUB_STATE.reset()
        STUB_STATE.take()
        for job_id in JOB_IDS:
            r = await py.post(f"/__test/tick/{job_id}")
            check(f"python: a handed-over {job_id} tick is skipped", r.json() == {"outcome": "skipped"}, r.text)
        check("  nothing was sent", not STUB_STATE.take())
        sql("UPDATE scheduled_job_metadata SET enabled = 1 WHERE job_id = 'invoke_duo_integration_collect'")
        r = await py.post("/__test/tick/invoke_duo_integration_collect")
        check("python: a tick whose row is enabled runs", r.json() == {"outcome": "ran"} and len(STUB_STATE.take()) == 1, r.text)
        r = await rs.post("/api/scheduler/jobs/run/invoke_duo_integration_collect", headers=admin)
        check(
            "rust: a manual run of a job Python owns is run here, as Python's manual run is",
            r.status_code == 200
            and r.json()["result"] == {"success": True, "message": "Duo integration invoked."}
            and len(STUB_STATE.take()) == 1,
            r.text,
        )

        # The CarbonBlack job has no route and Python's manual run of it fails (a 500: the run
        # route looks its function's name up), so its collection is compared on scheduled ticks:
        # Python's guard with the row enabled, then the Rust runner's once the row is handed over
        # and the interval brought down to a minute (the runner re-reads it every 30 s).
        cb = "invoke_carbonblack_integration_collection"
        got = {}
        seed_integrations()
        sql("UPDATE scheduled_job_metadata SET last_success = NULL, enabled = 1 WHERE job_id = :j", j=cb)
        STUB_STATE.reset()
        STUB_STATE.take()
        r = await py.post(f"/__test/tick/{cb}")
        got["py"] = {"tick": r.json(), "out": normalised(STUB_STATE.take()), "stamped": job_state()[cb]}
        sql("UPDATE scheduled_job_metadata SET last_success = NULL, enabled = 0, time_interval = 1 WHERE job_id = :j", j=cb)
        out = []
        for _ in range(240):
            await asyncio.sleep(0.5)
            out = STUB_STATE.take()
            if out:
                break
        await asyncio.sleep(1)
        sql("UPDATE scheduled_job_metadata SET enabled = 1, time_interval = 1440 WHERE job_id = :j", j=cb)
        got["rs"] = {
            "tick": {"outcome": "ran"} if out else {"outcome": "never"},
            "out": normalised(out + STUB_STATE.take()),
            "stamped": job_state()[cb],
        }
        check(
            f"job carbonblack, scheduled ticks [{len(got['py']['out'])} out]",
            json.dumps(got["py"], default=str) == json.dumps(got["rs"], default=str) and got["py"]["out"],
            f"python {json.dumps(got['py'], default=str)[:3000]}\n        rust   {json.dumps(got['rs'], default=str)[:3000]}",
        )
    finally:
        await py.aclose()
        await rs.aclose()


async def mimecast_job_crash():
    """The Python job as it is: its first customer's `HttpUrl + str` raises out of the job."""
    from app.schedulers.services.invoke_mimecast import invoke_mimecast_integration

    seed_integrations()
    sql("UPDATE scheduled_job_metadata SET enabled = 1 WHERE job_id = 'invoke_mimecast_integration'")
    try:
        await invoke_mimecast_integration()
        outcome = "ran"
    except HTTPException as e:
        outcome = f"{e.status_code}: {e.detail}"
    finally:
        sql("UPDATE scheduled_job_metadata SET enabled = 0, last_success = NULL WHERE job_id = 'invoke_mimecast_integration'")
        reset_mimecast_files()
    check(
        "python's invoke_mimecast_integration raises as it is (HttpUrl + str), Rust's collects",
        outcome == "400: Unable to retrieve MTA SIEM logs from Mimecast integration.",
        outcome,
    )


async def main():
    redirect_python_httpx()
    install_python_patches()
    reset_mimecast_files()
    server = start_stub()
    gelf_server = start_gelf_stub()
    procs = []
    try:
        seed()
        procs.append(start_python_legacy())
        procs.append(start_rust(RS_PORT, STUB))
        procs.append(start_rust(RS_CLOSED_PORT, CLOSED))
        procs.append(start_rust(JOBS_PORT, STUB, rs_jobs=",".join(JOB_IDS)))
        p = Pair()
        t = {
            "admin": token(ADMIN, ["admin"]),
            "analyst": token(ANALYST, ["analyst"]),
            "analyst_b": token(ANALYST_B, ["analyst"]),
            "unassigned": token(UNASSIGNED, ["analyst"]),
        }
        try:
            sections = os.environ.get("INTEGRATION_MODULES_PARITY_SECTIONS", "modules,sap,mimecast,jobs").split(",")
            if "modules" in sections:
                print("\n=== the module collections ===")
                await module_checks(p, t)
            if "sap" in sections:
                print("\n=== SAP SIEM ===")
                await sap_checks(p, t)
            if "mimecast" in sections:
                print("\n=== Mimecast ===")
                await mimecast_checks(p, t)
            if "jobs" in sections:
                print("\n=== the collection jobs, handed over ===")
                await mimecast_job_crash()
                await job_checks(t)
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
            gelf_server.shutdown()
            shutil.rmtree(MIMECAST_DIR, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
