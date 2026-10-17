"""Parity of the external-tool modules of wave 6 with this backend — NOT collected by pytest
(needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts (no legacy backend)
answer the same requests on one database. Every upstream is a local stand-in that records each
request — method, target, **every header in the order it was sent** (`Host` and `Content-Length`
included) and the body bytes — and both backends' requests are compared one by one:

* Microsoft Patch Tuesday (`/api/patch-tuesday`, `crates/copilot-patch-tuesday`): MSRC's CVRF
  documents, FIRST's EPSS API (several chunks, one failing) and CISA's KEV catalog, odd document
  shapes and every failure `fetch_json` words (an HTTP error, XML, invalid JSON, invalid UTF-8,
  a server that hangs up);
* CoPilot MCP (`/api/copilot_mcp`, `crates/copilot-mcp`): the servers and their example questions,
  and the query to the local `copilot-mcp` container and to SOCFortress's cloud (the licence's
  `SOCFORTRESS AI` feature, cached or asked of the licence server) with every answer
  `execute_query` turns into a message. The cloud request's header names are compared
  lower-cased: hyper writes one case per request, httpx a lower-case `x-api-key` among title-case
  names (a §4 row); values and order are compared as sent. So are the licence server's
  (`copilot-license`'s client): `requests` title-cases them over the urllib3-future the backend
  installs, hyper lower-cases them (as `rust_parity_platform_e2e.py` compares them).
* Sublime (`/api/sublime`, `crates/copilot-sublime`), on the tables migration `d6c01a2b3c4d`
  created: the webhook's validation, the store (the rows each backend wrote, column by column
  but the ids and the timestamp; the two message lookups), what fails where — a column MySQL
  refuses, in the unit of work's table order; odd emails pymysql writes as literals; every
  answer of Sublime's the lookups cannot read; no connector row; a closed port —, the listing
  (also with a stored sender MySQL holds without a name) and the connector check. The ids of
  the rows a failed store rolled back differ (Python's attempt takes one first), and so does the
  timestamp each backend stamps: those are masked in the error texts; the timestamp is its own
  check (Python stamps its import time, a §4 row).
* ScoutSuite (`/api/scoutsuite`, `crates/copilot-scoutsuite`): `scout` is a stand-in first on
  both processes' `PATH` that records its arguments, working directory, an environment variable
  both processes hold, and for GCP the credential it was handed and its directory's mode, then
  writes the three report files ScoutSuite writes. Both backends work in one directory (Python's
  working directory for this section, Rust's `COPILOT_SCOUTSUITE_DIR`) and one `TMPDIR`; each
  scan's record is compared (the credential directory's random name masked after a check of its
  shape), and so is the report tree a delete leaves.

Python reaches the stand-ins because the modules' URL constants are patched here (and the
licence server's host rewritten in `requests`); Rust because its instance is started with the
`COPILOT_*_URL` overrides (parity harness only). Each backend
stamps the items with its own clock: those stamps are masked in the bodies after a check that
they are within seconds of each other; everything else is compared byte for byte.

    PARITY_SUITES=tests/e2e/rust_parity_ext_tools_e2e.py scripts/rust-parity.sh

Ports (all overridable, defaults in the suite's own range): EXT_PARITY_RUST_PORT,
EXT_FEEDS_STUB_PORT, EXT_MCP_STUB_PORT, EXT_SUBLIME_STUB_PORT, EXT_CLOSED_PORT (nothing listens).
"""

import asyncio
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qsl

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
# `send_post_request` (the licence server) reads it per call; the Rust instance gets the same.
os.environ["COPILOT_API_KEY"] = "parity-copilot-api-key"

import httpx  # noqa: E402
import jwt  # noqa: E402
import requests  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("EXT_PARITY_RUST_PORT", "6634"))
FEEDS_PORT = int(os.environ.get("EXT_FEEDS_STUB_PORT", "6631"))
FEEDS = f"http://127.0.0.1:{FEEDS_PORT}"
MCP_PORT = int(os.environ.get("EXT_MCP_STUB_PORT", "6632"))
MCP_URL = f"http://127.0.0.1:{MCP_PORT}"
SUBLIME_PORT = int(os.environ.get("EXT_SUBLIME_STUB_PORT", "6633"))
SUBLIME_URL = f"http://127.0.0.1:{SUBLIME_PORT}"
CLOSED_PORT = int(os.environ.get("EXT_CLOSED_PORT", "6635"))
# ScoutSuite: the working directory, the stand-in's records, its directory and the TMPDIR both
# backends write the GCP credential under.
SCOUT_ROOT = tempfile.mkdtemp(prefix="ext-parity-scout-")
SCOUT_WORK = os.path.join(SCOUT_ROOT, "work")
SCOUT_LOG = os.path.join(SCOUT_ROOT, "log")
SCOUT_BIN = os.path.join(SCOUT_ROOT, "bin")
SCOUT_TMP = os.path.join(SCOUT_ROOT, "tmp")
for _d in (SCOUT_WORK, SCOUT_LOG, SCOUT_BIN, SCOUT_TMP):
    os.makedirs(_d)
SCOUT_MARKER = f"scout-marker-{uuid.uuid4().hex[:6]}"

SFX = uuid.uuid4().hex[:6]
ADMIN, ANALYST, PORTAL = f"ext_admin{SFX}", f"ext_analyst{SFX}", f"ext_portal{SFX}"
USERS = (ADMIN, ANALYST, PORTAL)
LICENSE_KEY = f"ext-lic-{SFX}"
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
    """A threaded HTTP/1.1 stand-in recording (method, target, [(header, value), …] in the order
    they came, body); `answer(method, target, headers, body)` returns (status, [(header, value)],
    bytes), or None to hang up without a response. Nothing is dropped or normalized."""

    def __init__(self, name, port, answer, fold=None):
        self.name = name
        self.answer = answer
        #: `fold(target)`: whether this request's header names are recorded lower-cased.
        self.fold = fold or (lambda target: False)
        self.lock = threading.Lock()
        self.requests = []
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = list(self.headers.items())
                if recorder.fold(self.path):
                    headers = [(k.lower(), v) for k, v in headers]
                with recorder.lock:
                    recorder.requests.append((self.command, self.path, headers, body))
                out = recorder.answer(self.command, self.path, self.headers, body)
                if out is None:
                    self.close_connection = True
                    return
                status, headers, payload = out
                self.send_response(status)
                for k, v in headers:
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

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def as_json(status, value, ctype="application/json"):
    return status, [("Content-Type", ctype)], json.dumps(value).encode()


def raw(status, ctype, payload):
    return status, ([("Content-Type", ctype)] if ctype else []), payload


# --- Patch Tuesday: MSRC, EPSS and KEV ---------------------------------------------------------------

CVRF_JAN = {
    "DocumentTitle": {"Value": "January 2026 Security Updates"},
    "ProductTree": {
        "FullProductName": [
            {"ProductID": "11926", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
            {"ProductID": "12001", "Value": "Windows Server 2025"},
            {"ProductID": "11800", "Value": "Microsoft Office LTSC 2021 for 64-bit editions"},
            {"ProductID": "11700", "Value": "Microsoft Exchange Server 2019 Cumulative Update 14"},
            {"ProductID": "11600", "Value": "Microsoft Edge (Chromium-based)"},
            {"ProductID": "11500", "Value": "Azure Connected Machine Agent"},
            {"ProductID": "11400", "Value": "Skype for Business Server 2019"},
            {"ProductID": 11300, "Value": "  .NET 9.0\tinstalled on\nLinux "},
        ],
    },
    "Vulnerability": [
        {
            "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
            "CVE": "CVE-2026-20001",
            "Threats": [{"Type": 0, "Description": {"Value": "Important"}}, {"Type": 3, "Description": {"Value": "Important"}}],
            "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "ProductID": ["11926"]}],
            "ProductStatuses": [{"ProductID": ["11926", "12001"], "Type": 3}],
            "Remediations": [
                {"Description": {"Value": "5034441"}, "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5034441"},
            ],
        },
        {
            "Title": {"Value": "Microsoft Office Remote Code Execution Vulnerability"},
            "CVE": "cve-2026-20002",
            "Severity": "critical",
            "CVSSScoreSets": [{"BaseScore": 8.4, "Vector": "CVSS:3.1/AV:L"}, {"BaseScore": "9.25"}],
            "ProductStatuses": [{"ProductID": ["11800"], "Type": 3}],
            "Remediations": [{"Description": "KB5002500 / kb5002501", "URL": "https://support.microsoft.com/help/5002500"}],
        },
        {
            "Title": "Exchange Server Spoofing",
            "CVE": "CVE-2026-20003",
            "CVSSScoreSets": [{"BaseScore": 6.5}],
            "ProductStatuses": [{"ProductID": ["11700", "99999"]}],
        },
        {"Title": "Edge", "CVE": "CVE-2026-20004", "Threats": [{"Type": "Severity", "Description": "moderate"}], "Products": ["11600"]},
        {
            "Title": "Azure Agent",
            "CVE": "CVE-2026-20005",
            "CVSSScoreSets": [{"BaseScore": 5.0}],
            "ProductStatuses": [{"ProductID": ["11500"]}],
        },
        {"Title": "Unmapped", "CVE": "CVE-2026-20006"},
        {"Title": "Skype", "CVE": "CVE-2026-20007", "Severity": "low", "ProductStatuses": [{"ProductID": "11400"}]},
        {"Title": ".NET", "CVE": "CVE-2026-20008", "Severity": "ǅemo ß", "ProductStatuses": [{"ProductID": [11300]}]},
        {"Title": "Not a CVE", "CVE": "ADV990001"},
        "junk",
    ],
}

#: 159 CVEs: the EPSS query goes out in two chunks of at most 1900 characters.
CVRF_APR = {
    "ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows 10"}, {"ProductID": "2", "Value": "SQL Server 2019"}]},
    "Vulnerability": [
        {"CVE": f"CVE-2026-{n:05d}", "Products": ["1", "2"] if n % 7 == 0 else ["1"], "CVSSScoreSets": [{"BaseScore": (n % 100) / 10}]}
        for n in range(1, 160)
    ],
}

DOCS = {
    "2026-Jan": CVRF_JAN,
    "2026-Apr": CVRF_APR,
    # Odd shapes (Python's operations on them, and their CPython failures).
    "2025-Jan": [1, 2],
    "2025-Feb": {"ProductTree": "s"},
    "2025-Mar": {"Vulnerability": 5},
    "2025-Apr": {"Vulnerability": {"CVE": "CVE-2025-1", "Title": 7, "Threats": "x"}},
    "2025-May": {"Vulnerabilities": [{"cve": "CVE-2025-2", "Threats": 4}]},
    "2025-Jun": {"Vulnerability": [{"CVE": {"Value": "CVE-2025-3"}, "CVSSScoreSets": {"BaseScore": "nan"}, "Remediations": 3}]},
    "2025-Jul": {"Vulnerability": []},
}

EPSS_SCORES = {"CVE-2026-20001": ("0.94321", "0.99"), "CVE-2026-20002": ("0.12345", "0.80000"), "CVE-2026-20005": (0.35, None)}


class Feeds:
    """MSRC (`/cvrf/v3.0/cvrf/{cycle}`), EPSS (`/data/v1/epss?cve=…`) and KEV (`/kev.json`);
    `mode` (reset before each backend's call) overrides one of them."""

    def __init__(self):
        self.mode = {}
        self.epss_calls = 0

    def reset(self, **mode):
        self.mode = dict(mode)
        self.epss_calls = 0

    def __call__(self, method, target, headers, body):
        path, _, query = target.partition("?")
        if path.startswith("/cvrf/v3.0/cvrf/"):
            return self.msrc(path.rsplit("/", 1)[1])
        if path == "/data/v1/epss":
            self.epss_calls += 1
            return self.epss(dict(parse_qsl(query, keep_blank_values=True)).get("cve", ""))
        if path == "/kev.json":
            return self.kev()
        return raw(404, "text/plain", b"no such feed")

    def msrc(self, cycle):
        m = self.mode.get("msrc")
        if m == "hangup":
            return None
        if isinstance(m, tuple):
            return m
        if cycle not in DOCS:
            return raw(404, "application/json", b'{"error":{"code":"NotFound","message":"Not found"}}')
        return as_json(200, DOCS[cycle])

    def epss(self, cves):
        m = self.mode.get("epss")
        if m == "second_fails" and self.epss_calls == 2:
            return raw(503, "text/plain", b"busy")
        if isinstance(m, tuple):
            return m
        if isinstance(m, dict) or isinstance(m, list):
            return as_json(200, m)
        rows = []
        for cve in cves.split(","):
            if cve in EPSS_SCORES:
                score, pct = EPSS_SCORES[cve]
                rows.append({"cve": cve, "epss": score, "percentile": pct, "date": "2026-01-14"})
            elif cve.startswith("CVE-2026-0"):
                rows.append({"cve": cve, "epss": str(int(cve[-5:]) * 37 % 1000 / 1000), "percentile": "0.5", "date": "2026-04-15"})
        return as_json(200, {"status": "OK", "total": len(rows), "data": rows})

    def kev(self):
        m = self.mode.get("kev")
        if m == "hangup":
            return None
        if isinstance(m, tuple):
            return m
        if m is not None:
            return as_json(200, m)
        return as_json(
            200,
            {
                "title": "CISA Catalog of Known Exploited Vulnerabilities",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-20003",
                        "vendorProject": "Microsoft",
                        "product": "Exchange Server",
                        "vulnerabilityName": "Microsoft Exchange Server Spoofing Vulnerability",
                        "dateAdded": "2026-01-13",
                        "shortDescription": "  Exchange   contains\na spoofing vulnerability. ",
                        "requiredAction": "Apply mitigations per vendor instructions.",
                        "dueDate": "2026-02-03",
                        "knownRansomwareCampaignUse": "Unknown",
                        "notes": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20003", ""],
                    },
                    {"cveID": "cve-2026-20007", "vendorProject": {"Value": "MS"}},
                    {"cveID": "CVE-2026-00042"},
                    "junk",
                ],
            },
        )


FEEDS_ANSWER = Feeds()


# --- CoPilot MCP: the local container, SOCFortress's cloud and the licence server ---------------------

FEATURES = [{"name": "SOCFORTRESS AI", "intValue": 1}, {"name": "THREAT INTEL", "intValue": 0}]


class Mcp:
    """`/mcp/{endpoint}` (local), `/query/{endpoint}` (cloud) and `/verify-license`; `mode` (reset
    before each backend's call) chooses the answers."""

    def __init__(self):
        self.mode = {}

    def reset(self, **mode):
        self.mode = dict(mode)

    def __call__(self, method, target, headers, body):
        if target == "/verify-license":
            license_mode = self.mode.get("license", "ok")
            if license_mode == "ok":
                return as_json(200, {"data": {"license": {"key": LICENSE_KEY, "dataObjects": FEATURES}}, "success": True})
            if license_mode == "disabled":
                return as_json(200, {"data": {"license": {"dataObjects": [{"name": "SOCFORTRESS AI", "intValue": 0}]}}})
            return as_json(500, {"message": "licence server down", "detail": "x"})
        answer = self.mode.get("answer", "ok")
        if answer == "ok":
            try:
                sent = json.loads(body)
            except ValueError:
                sent = None
            return as_json(
                200,
                {
                    "message": f"answered {target}",
                    "success": True,
                    "result": {"echo": sent, "rows": [1, 2.5, None, "é ✓"]},
                    "structured_result": {"response": "**Markdown** answer", "thinking_process": None},
                    "execution_time": 1.25,
                },
            )
        return {
            "error500": raw(500, "text/plain", b"boom"),
            "error404": as_json(404, {"detail": "no such tool"}),
            "redirect": (307, [("Location", "http://elsewhere.invalid/x")], b""),
            "notjson": raw(200, "text/html", b"<html>not json</html>"),
            "empty": raw(200, "application/json", b""),
            "list": as_json(200, [1, 2]),
            "string": as_json(200, "text"),
            "invalid": as_json(200, {"message": 5, "success": None}),
            "structured": as_json(200, {"message": "ok", "success": True, "structured_result": {"thinking_process": "t"}}),
            "lax": as_json(200, {"message": "ok", "success": "true", "execution_time": "2.5", "extra": "dropped", "result": [1]}),
            "minimal": as_json(200, {"message": "ok", "success": False}),
            "hangup": None,
        }[answer]


MCP_ANSWER = Mcp()


# --- The two backends --------------------------------------------------------------------------------


def build_python_app():
    from app.integrations.copilot_mcp.services.copilot_mcp import MCPService
    from app.integrations.copilot_mcp.services.copilot_mcp import MCPServiceType
    from app.integrations.microsoft_patch_tuesday.services import (
        microsoft_patch_tuesday as pt_services,
    )
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors
    from app.routers import copilot_mcp
    from app.routers import microsoft_patch_tuesday
    from app.routers import scoutsuite
    from app.routers import sublime

    MCPService._BASE_URLS[MCPServiceType.LOCAL] = f"{MCP_URL}/mcp"
    MCPService._BASE_URLS[MCPServiceType.CLOUD] = f"{MCP_URL}/query"
    original_request = requests.Session.request

    def session_request(self, method, url, *args, **kwargs):
        if url.startswith("https://license.socfortress.co/"):
            url = MCP_URL + url[len("https://license.socfortress.co") :]
        return original_request(self, method, url, *args, **kwargs)

    requests.Session.request = session_request
    pt_services.MSRC_CVRF_BASE = f"{FEEDS}/cvrf/v3.0/cvrf"
    pt_services.EPSS_BASE = f"{FEEDS}/data/v1/epss"
    pt_services.CISA_KEV_JSON = f"{FEEDS}/kev.json"
    api = APIRouter(prefix="/api")
    api.include_router(microsoft_patch_tuesday.router)
    api.include_router(copilot_mcp.router)
    api.include_router(sublime.router)
    api.include_router(scoutsuite.router)
    api.include_router(connectors.router)
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
        "PATH": SCOUT_BIN + os.pathsep + os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_PORT": str(RS_PORT),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        "COPILOT_MSRC_CVRF_URL": f"{FEEDS}/cvrf/v3.0/cvrf",
        "COPILOT_EPSS_URL": f"{FEEDS}/data/v1/epss",
        "COPILOT_CISA_KEV_URL": f"{FEEDS}/kev.json",
        "COPILOT_MCP_LOCAL_URL": f"{MCP_URL}/mcp",
        "COPILOT_SOCFORTRESS_MCP_URL": f"{MCP_URL}/query",
        "COPILOT_LICENSE_URL": f"{MCP_URL}/",
        "COPILOT_API_KEY": os.environ["COPILOT_API_KEY"],
        "COPILOT_SCOUTSUITE_DIR": SCOUT_WORK,
        "TMPDIR": SCOUT_TMP,
        "SCOUT_PARITY_MARKER": SCOUT_MARKER,
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


RESPONSE_HEADERS = ("content-type", "content-length")
#: The stamps each backend writes with its own clock (`…Z`, whole seconds).
STAMPED = re.compile(rb'"(generated_utc|timestamp_utc)":"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)"')


def masked(body):
    """The body with its clock stamps replaced, and the stamps."""
    stamps = [m.group(2).decode() for m in STAMPED.finditer(body)]
    return STAMPED.sub(rb'"\1":"<now>"', body), stamps


def recent(stamps, slack=30):
    now = datetime.datetime.now(datetime.timezone.utc)
    for s in stamps:
        t = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        if abs((now - t).total_seconds()) > slack:
            return False
    return True


class Pair:
    def __init__(self, recorders):
        self.recorders = recorders
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = {"Accept-Encoding": "identity", **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        for recorder in self.recorders:
            recorder.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0.05)
        out = [(rec.name, req) for rec in self.recorders for req in rec.take()]
        return r, out

    async def same(self, name, method, path, tok=None, before=None, expect=None, table=None, masks=(), **kw):
        """Python, then Rust, with the stand-ins reset by `before` for each. `expect` is a status
        both must answer; `table` returns a value both must leave alike; `masks` are
        `(pattern, replacement)` pairs applied to both bodies (the lengths then compare no more)."""
        if before:
            before()
        r1, out1 = await self.call(self.py, method, path, tok, **kw)
        t1 = table() if table else None
        if before:
            before()
        r2, out2 = await self.call(self.rs, method, path, tok, **kw)
        t2 = table() if table else None
        (b1, s1), (b2, s2) = masked(r1.content), masked(r2.content)
        for pattern, replacement in masks:
            b1, b2 = re.sub(pattern, replacement, b1), re.sub(pattern, replacement, b2)
        ok = r1.status_code == r2.status_code and b1 == b2
        if expect is not None and r1.status_code != expect:
            ok = False
        detail = f"python {r1.status_code} {b1[:1500]!r}\n        rust   {r2.status_code} {b2[:1500]!r}"
        h1 = {k: r1.headers.get(k) for k in RESPONSE_HEADERS}
        h2 = {k: r2.headers.get(k) for k in RESPONSE_HEADERS}
        if (s1 != s2 or masks) and h1.get("content-length") and h2.get("content-length"):
            # Stamps of the same length: the lengths still compare.
            h1.pop("content-length")
            h2.pop("content-length")
        if h1 != h2:
            ok = False
            detail += f"\n        headers python {h1}\n        headers rust   {h2}"
        if len(s1) != len(s2) or not recent(s1 + s2):
            ok = False
            detail += f"\n        stamps python {s1[:3]}\n        stamps rust   {s2[:3]}"
        if out1 != out2:
            ok = False
            first = next((i for i, (x, y) in enumerate(zip(out1, out2)) if x != y), min(len(out1), len(out2)))
            detail += f"\n        outbound ({len(out1)} / {len(out2)}), first difference #{first}:"
            detail += f"\n        python {out1[first:first + 1]}\n        rust   {out2[first:first + 1]}"
        if table and t1 != t2:
            ok = False
            detail += f"\n        table python {t1}\n        table rust   {t2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {out1[:3]}")
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- Patch Tuesday checks ----------------------------------------------------------------------------

PT = "/api/patch-tuesday"


def feeds(**mode):
    def go():
        FEEDS_ANSWER.reset(**mode)

    return go


async def patch_tuesday_checks(p, t_admin, t_analyst, t_portal):
    print("\n== Patch Tuesday: auth and validation")
    for route in ("", "/summary", "/cycles", "/search?cve_ids=x", "/priority/P0", "/kev"):
        await p.same(f"{route or '/'}: no token", "GET", PT + route, expect=401)
        await p.same(f"{route or '/'}: portal user", "GET", PT + route, t_portal, expect=403)
    for query in (
        "cycle=2026-jan",
        "cycle=26-Jan",
        "cycle=",
        "cycle=2026-Jan%0A",
        "cycle=2026-Janx",
        "include_epss=maybe",
        "include_epss=",
        "include_kev=2&include_epss=nope&cycle=x",
    ):
        await p.same(f"/: 422 for {query!r}", "GET", f"{PT}?{query}", t_analyst, before=feeds())
    for query in ("top_n=0", "top_n=101", "top_n=abc", "top_n=5.5", "top_n=", "top_n=1e1"):
        await p.same(f"/summary: 422 for {query!r}", "GET", f"{PT}/summary?{query}&cycle=2026-Jan", t_analyst, before=feeds())
    await p.same("/search: no cve_ids", "GET", f"{PT}/search", t_analyst, expect=422)
    await p.same("/search: no cve_ids and a bad cycle", "GET", f"{PT}/search?cycle=2026", t_analyst, expect=422)
    await p.same("/kev: a bad cycle", "GET", f"{PT}/kev?cycle=Jan-2026", t_analyst, expect=422)
    await p.same("/priority: a bad cycle", "GET", f"{PT}/priority/P1?cycle=2026-Foo&include_kev=x", t_analyst, expect=422)

    print("\n== Patch Tuesday: a whole cycle")
    await p.same("/: January, EPSS and KEV", "GET", f"{PT}?cycle=2026-Jan", t_analyst, before=feeds(), expect=200)
    await p.same("/: admin", "GET", f"{PT}?cycle=2026-Jan", t_admin, before=feeds(), expect=200)
    for flags in (
        "include_epss=false&include_kev=False",
        "include_epss=0&include_kev=1",
        "include_epss=off&include_kev=yes",
        "include_epss=t&include_kev=n",
        "include_epss=ON",
    ):
        await p.same(f"/: {flags}", "GET", f"{PT}?cycle=2026-Jan&{flags}", t_analyst, before=feeds(), expect=200)
    await p.same("/: Unicode digits in the cycle", "GET", f"{PT}?cycle=%D9%A2%D9%A0%D9%A2%D9%A6-Jan", t_analyst, before=feeds())
    await p.same("/: year 0", "GET", f"{PT}?cycle=0000-Jan", t_analyst, before=feeds(), expect=200)
    await p.same("/: the current month (no document)", "GET", PT, t_analyst, before=feeds(), expect=200)
    await p.same("/: 159 CVEs, two EPSS chunks", "GET", f"{PT}?cycle=2026-Apr", t_analyst, before=feeds(), expect=200)
    await p.same(
        "/: 159 CVEs, the second EPSS chunk fails",
        "GET",
        f"{PT}?cycle=2026-Apr",
        t_analyst,
        before=feeds(epss="second_fails"),
        expect=200,
    )
    for cycle in ("2025-Jan", "2025-Feb", "2025-Mar", "2025-Apr", "2025-May", "2025-Jun", "2025-Jul"):
        await p.same(f"/: an odd document ({cycle})", "GET", f"{PT}?cycle={cycle}", t_analyst, before=feeds(), expect=200)

    print("\n== Patch Tuesday: what fetch_json refuses")
    long_text = ("ä" * 150 + "x" * 400).encode()
    for label, answer in (
        ("a 404", None),
        ("a 500 with a long body", raw(500, "text/plain; charset=utf-8", long_text)),
        ("a 204", raw(204, None, b"")),
        ("a redirect", (302, [("Location", "https://elsewhere.example/")], b"")),
        ("XML", raw(200, "application/xml", b"  \n<cvrfdoc/>")),
        ("HTML without a type", raw(200, None, b"<html></html>")),
        ("XML said to be JSON", raw(200, "application/json", b"<x/>")),
        ("invalid JSON", raw(200, "application/json", b'{"Vulnerability": [')),
        ("invalid UTF-8", raw(200, "application/json", b'{"a": "\xff"}')),
        ("a BOM", raw(200, "application/json", b'\xef\xbb\xbf{"Vulnerability": []}')),
        ("NaN", raw(200, "application/json", b'{"Vulnerability": [{"CVE": "CVE-2026-9", "CVSSScoreSets": [{"BaseScore": NaN}]}]}')),
        ("a latin-1 text", raw(500, "text/plain; charset=latin-1", b"caf\xe9 " * 80)),
        ("a hang-up", "hangup"),
    ):
        mode = {} if answer is None else {"msrc": answer}
        await p.same(f"/: MSRC answers {label}", "GET", f"{PT}?cycle=2025-Dec", t_analyst, before=feeds(**mode), expect=200)
        await p.same(f"/summary: MSRC answers {label}", "GET", f"{PT}/summary?cycle=2025-Dec", t_analyst, before=feeds(**mode))
    for label, mode in (
        ("EPSS answers a 500", {"epss": raw(500, "text/plain", b"down")}),
        ("EPSS answers XML", {"epss": raw(200, "text/xml", b"<x/>")}),
        ("EPSS answers a list", {"epss": [1, 2]}),
        ("EPSS rows of odd shapes", {"epss": {"data": [{"cve": "CVE-2026-20001", "epss": "0.5"}, "row", {"cve": "CVE-2026-20002"}]}}),
        ("EPSS data not a list", {"epss": {"data": {"cve": "x"}}}),
        ("EPSS with a numeric cve", {"epss": {"data": [{"cve": 7}]}}),
        ("EPSS with an int date", {"epss": {"data": [{"cve": "CVE-2026-20001", "epss": "1e400", "percentile": True, "date": 20260114}]}}),
        ("EPSS with a dict date", {"epss": {"data": [{"cve": "CVE-2026-20001", "epss": "NaN", "date": {"d": 1}}]}}),
        ("KEV hangs up", {"kev": "hangup"}),
        ("KEV answers a 500", {"kev": raw(500, "text/plain", b"down")}),
        ("KEV answers a list", {"kev": [1]}),
        ("KEV vulnerabilities a dict", {"kev": {"vulnerabilities": {"cveID": "CVE-2026-20001", "notes": None}}}),
        ("KEV vulnerabilities an int", {"kev": {"vulnerabilities": 3}}),
    ):
        await p.same(f"/: {label}", "GET", f"{PT}?cycle=2026-Jan", t_analyst, before=feeds(**mode), expect=200)

    print("\n== Patch Tuesday: summary, search, priority, KEV, cycles")
    for top in ("1", "3", "100", " 2", "+4", "1_0"):
        await p.same(f"/summary: top_n={top!r}", "GET", f"{PT}/summary?cycle=2026-Jan&top_n={top}", t_analyst, before=feeds())
    await p.same("/summary: the default top", "GET", f"{PT}/summary?cycle=2026-Apr", t_analyst, before=feeds(), expect=200)
    for query in (
        "cve_ids=cve-2026-20001&cve_ids=CVE-2026-20003&cve_ids=nope",
        "cve_ids=CVE-2026-20001&product=Windows%20Server%202025",
        "cve_ids=CVE-2026-20001&product=",
        "cve_ids=CVE-1999-0001",
        "cve_ids=CVE-2026-20002&cve_ids=CVE-2026-20002",
        "cve_ids=",
    ):
        await p.same(f"/search: {query}", "GET", f"{PT}/search?cycle=2026-Jan&{query}", t_analyst, before=feeds())
    await p.same("/search: MSRC fails", "GET", f"{PT}/search?cycle=2025-Dec&cve_ids=x", t_analyst, before=feeds())
    for level in ("P0", "p1", "P2", "p3", "P9", "%C3%9F", "low", "P%E2%82%80"):
        await p.same(f"/priority/{level}", "GET", f"{PT}/priority/{level}?cycle=2026-Jan", t_analyst, before=feeds())
    await p.same("/priority: MSRC fails", "GET", f"{PT}/priority/P0?cycle=2025-Dec", t_analyst, before=feeds())
    await p.same("/priority: an encoded slash", "GET", f"{PT}/priority/P0%2FP1?cycle=2026-Jan", t_analyst, before=feeds())
    await p.same("/priority: no EPSS", "GET", f"{PT}/priority/P2?cycle=2026-Jan&include_epss=false", t_analyst, before=feeds())
    await p.same("/kev", "GET", f"{PT}/kev?cycle=2026-Jan", t_analyst, before=feeds(), expect=200)
    await p.same("/kev: the April cycle", "GET", f"{PT}/kev?cycle=2026-Apr", t_analyst, before=feeds(), expect=200)
    await p.same("/kev: MSRC fails", "GET", f"{PT}/kev?cycle=2025-Dec", t_analyst, before=feeds())
    await p.same("/cycles", "GET", f"{PT}/cycles", t_analyst, expect=200)
    await p.same("/cycles: admin", "GET", f"{PT}/cycles?x=1", t_admin, expect=200)


# --- CoPilot MCP checks ------------------------------------------------------------------------------

M = "/api/copilot_mcp"
SERVERS = ("wazuh-indexer", "wazuh-manager", "copilot", "velociraptor", "threat-intel", "cyber-news", "knowledgebase", "attack-surface")


def licence(cache=None, licensed=True, **mode):
    """A reset: the suite's licence row (or none), its `SOCFORTRESS AI` cache row as given
    (`enabled`, fresh) or none, and the stand-in's mode."""

    def go():
        sql("DELETE FROM license_cache WHERE license_key = :k", k=LICENSE_KEY)
        sql("DELETE FROM license WHERE license_key = :k", k=LICENSE_KEY)
        if licensed:
            sql(
                "INSERT INTO license (license_key, customer_name, customer_email, company_name) "
                "VALUES (:k, 'Parity', 'p@parity.test', 'Parity Co')",
                k=LICENSE_KEY,
            )
        if cache is not None:
            enabled, fresh = cache
            sql(
                "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, expires_at, license_data) VALUES "
                "(:k, 'SOCFORTRESS AI', :e, UTC_TIMESTAMP() - INTERVAL 2 HOUR, UTC_TIMESTAMP() + INTERVAL :h HOUR, '{}')",
                k=LICENSE_KEY,
                e=enabled,
                h=1 if fresh else -1,
            )
        MCP_ANSWER.reset(**mode)

    return go


def licence_rows():
    with sync_engine.connect() as conn:
        rows = conn.execute(
            text("SELECT feature_name, is_enabled, license_data FROM license_cache WHERE license_key = :k ORDER BY feature_name"),
            {"k": LICENSE_KEY},
        )
        return [tuple(r) for r in rows]


async def mcp_checks(p, t_admin, t_analyst, t_portal):
    print("\n== CoPilot MCP: auth, servers and questions")
    for method, route in (
        ("GET", "/servers"),
        ("GET", "/servers/copilot"),
        ("GET", "/example-questions?mcp_server=copilot"),
        ("GET", "/categories?mcp_server=copilot"),
        ("POST", "/query"),
    ):
        await p.same(f"{route}: no token", method, M + route, expect=401)
        await p.same(f"{route}: portal user", method, M + route, t_portal, expect=403)
    await p.same("/servers", "GET", f"{M}/servers", t_analyst, expect=200)
    await p.same("/servers: admin", "GET", f"{M}/servers", t_admin, expect=200)
    for server in SERVERS + ("nope", "COPILOT", "copilot%20", "%E2%9C%93"):
        await p.same(f"/servers/{server}", "GET", f"{M}/servers/{server}", t_analyst)
    await p.same("/servers: an encoded slash", "GET", f"{M}/servers/copilot%2Fx", t_analyst)
    for server in SERVERS:
        await p.same(f"/example-questions {server}", "GET", f"{M}/example-questions?mcp_server={server}", t_analyst, expect=200)
        await p.same(f"/categories {server}", "GET", f"{M}/categories?mcp_server={server}", t_analyst, expect=200)
    for query in (
        "mcp_server=copilot&category=alerts",
        "mcp_server=wazuh-manager&category=agents",
        "mcp_server=velociraptor&category=persistence",
        "mcp_server=copilot&category=nope",
        "mcp_server=copilot&category=",
        "mcp_server=copilot&category=ALERTS",
        "mcp_server=nope",
        "mcp_server=",
        "category=alerts",
        "",
    ):
        await p.same(f"/example-questions?{query}", "GET", f"{M}/example-questions?{query}", t_analyst)
    for query in ("mcp_server=nope", "", "mcp_server=Copilot"):
        await p.same(f"/categories?{query}", "GET", f"{M}/categories?{query}", t_analyst)

    print("\n== CoPilot MCP: the query's body")
    Q = f"{M}/query"
    for body in (
        {"input": "hello", "mcp_server": "nope"},
        {"input": 5, "mcp_server": "nope"},
        {"mcp_server": ""},
        {"input": "hello", "mcp_server": 5},
        {"input": "hello", "mcp_server": None},
        {"input": "hello"},
        {"mcp_server": "copilot"},
        {"input": 5, "mcp_server": "copilot", "verbose": "x"},
        {"input": None, "mcp_server": 7},
        {"input": "hello", "mcp_server": "copilot", "verbose": 2},
        {},
        [],
        "text",
    ):
        await p.same(f"/query: {json.dumps(body)[:60]}", "POST", Q, t_analyst, before=licence(), json=body)
    await p.same("/query: no body", "POST", Q, t_analyst)
    await p.same("/query: malformed JSON", "POST", Q, t_analyst, content=b'{"input": ', headers={"Content-Type": "application/json"})
    await p.same("/query: malformed JSON, no token", "POST", Q, content=b"{", headers={"Content-Type": "application/json"})

    print("\n== CoPilot MCP: the local servers")
    for server in SERVERS[:4]:
        await p.same(f"/query {server}", "POST", Q, t_analyst, before=licence(), json={"input": "How many alerts?", "mcp_server": server})
    for verbose in (False, None, "yes", 0, "off"):
        await p.same(
            f"/query: verbose {verbose!r}",
            "POST",
            Q,
            t_analyst,
            before=licence(),
            json={"input": "x", "mcp_server": "copilot", "verbose": verbose},
        )
    await p.same(
        "/query: Unicode input",
        "POST",
        Q,
        t_admin,
        before=licence(),
        json={"input": 'é ✓ \u0000 "q"', "mcp_server": "velociraptor"},
    )
    for answer in (
        "error500",
        "error404",
        "redirect",
        "notjson",
        "empty",
        "list",
        "string",
        "invalid",
        "structured",
        "lax",
        "minimal",
        "hangup",
    ):
        await p.same(
            f"/query: the local server answers {answer}",
            "POST",
            Q,
            t_analyst,
            before=licence(answer=answer),
            json={"input": "x", "mcp_server": "wazuh-manager"},
        )

    print("\n== CoPilot MCP: the cloud servers and the licence")
    for server in SERVERS[4:]:
        await p.same(
            f"/query {server}",
            "POST",
            Q,
            t_analyst,
            before=licence(cache=(1, True)),
            json={"input": "What is new?", "mcp_server": server},
            table=licence_rows,
        )
    for answer in ("error500", "notjson", "invalid", "hangup"):
        await p.same(
            f"/query cloud: the server answers {answer}",
            "POST",
            Q,
            t_analyst,
            before=licence(cache=(1, True), answer=answer),
            json={"input": "x", "mcp_server": "knowledgebase"},
        )
    cloud = {"input": "x", "mcp_server": "threat-intel"}
    await p.same("/query cloud: no licence", "POST", Q, t_analyst, before=licence(licensed=False), json=cloud, table=licence_rows)
    await p.same("/query cloud: cached as disabled", "POST", Q, t_analyst, before=licence(cache=(0, True)), json=cloud, table=licence_rows)
    await p.same("/query cloud: the licence verified", "POST", Q, t_analyst, before=licence(), json=cloud, table=licence_rows)
    await p.same("/query cloud: an expired cache", "POST", Q, t_analyst, before=licence(cache=(1, False)), json=cloud, table=licence_rows)
    await p.same(
        "/query cloud: the licence server refuses",
        "POST",
        Q,
        t_analyst,
        before=licence(license="disabled"),
        json=cloud,
        table=licence_rows,
    )
    await p.same(
        "/query cloud: the licence server fails",
        "POST",
        Q,
        t_analyst,
        before=licence(license="error"),
        json=cloud,
        table=licence_rows,
    )
    await p.same(
        "/query local: no licence needed",
        "POST",
        Q,
        t_analyst,
        before=licence(licensed=False),
        json={"input": "x", "mcp_server": "copilot"},
    )


# --- Database ----------------------------------------------------------------------------------------


# --- Sublime: the message lookups and the connector check --------------------------------------------

SUBLIME_KEY = f"sb-key-{SFX}"


def message_answer(sender, recipients):
    return as_json(200, {"id": "m", "sender": sender, "recipients": recipients})


#: Sublime's `GET /v0/messages/{id}` answers, by message id.
MESSAGES = {
    "ok": message_answer({"email": "boss@example.com", "name": "Boss"}, [{"email": "victim@example.com"}, {"email": "cc@example.com"}]),
    "html": raw(502, "text/html", b"<h1>502 Bad Gateway</h1>"),
    "empty": raw(200, "application/json", b""),
    "hangup": None,
    "nosender": as_json(200, {"recipients": [{"email": "x@example.com"}]}),
    "norcpt": message_answer({"email": "a@example.com"}, []),
    "rcptstr": message_answer({"email": "a@example.com"}, ""),
    "rcptchars": message_answer({"email": "a@example.com"}, "ab"),
    "rcptdict": message_answer({"email": "a@example.com"}, {"0": {"email": "x"}}),
    "datalist": as_json(200, [1, 2]),
    "datanull": as_json(200, None),
    "datastr": as_json(200, "text"),
    "emailnull": message_answer({"email": None}, [{"email": "x@example.com"}]),
    "emaillist": message_answer({"email": []}, [{"email": "x@example.com"}]),
    "emailnested": message_answer({"email": ["a", []]}, [{"email": "x@example.com"}]),
    "emailpair": message_answer({"email": "a@example.com"}, [{"email": [1, 2]}]),
    "emaildict": message_answer({"email": {"a": 1}}, [{"email": "x@example.com"}]),
    "emailnan": raw(200, "application/json", b'{"sender": {"email": NaN}, "recipients": [{"email": "x"}]}'),
    "emailnone": message_answer({"email": [None]}, [{"email": "x@example.com"}]),
    "emaillong": message_answer({"email": "s" * 300}, [{"email": "r" * 300}]),
    "emailodd": message_answer({"email": 5}, [{"email": ["only"]}]),
    "emailfloat": message_answer({"email": 1.5}, [{"email": True}]),
    "emailbig": message_answer({"email": 123456789012345678901234567890}, [{"email": -0.0}]),
    "quoted": message_answer({"email": "o'brien\\\"x\\\\y@example.com"}, [{"email": "ü✓😀@example.com"}]),
}


class Sublime:
    """`/v0/messages/{id}` from MESSAGES, `/v0/rules?limit=1` as `rules` says."""

    def __init__(self):
        self.rules = None

    def __call__(self, method, target, headers, body):
        path, _, _ = target.partition("?")
        if path.startswith("/v0/messages/"):
            key = path[len("/v0/messages/") :].split("-", 1)[0]
            return MESSAGES.get(key, raw(404, "application/json", b'{"error": "not found"}'))
        if path == "/v0/rules":
            return self.rules or as_json(200, {"rules": [], "count": 0})
        return raw(404, "text/plain", b"no such path")


SUBLIME_ANSWER = Sublime()
SB = "/api/sublime"


def sublime_connector(url=SUBLIME_URL, key=SUBLIME_KEY):
    sql("DELETE FROM connectors WHERE connector_name = 'Sublime'")
    if url is None:
        return
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) "
        "VALUES ('Sublime', '3', :u, UTC_TIMESTAMP(), NULL, NULL, :key, 'parity', 'parity', 1, 0, 0, 1, 0, 0, 0, NULL, 1)",
        u=url,
        key=key,
    )


def sublime_body(event, message, **over):
    body = {
        "api_version": "v0",
        "created_at": "2026-10-17T10:00:00.123Z",
        "data": {
            "flagged_rules": [
                {"id": "rule-1", "name": "Impersonation of an executive", "severity": "high", "tags": ["bec", "ü", 'q"t']},
                {"id": "rule-2", "name": "Suspicious link", "tags": []},
            ],
            "message": {
                "canonical_id": "canon-1",
                "external_id": "ext-1",
                "id": f"{message}-{SFX}",
                "mailbox": {"external_id": "mbx-ext", "id": "mbx-1"},
                "message_source_id": "src-1",
            },
            "triggered_actions": [{"id": "act-1", "name": "Notify SOC", "type": "webhook"}],
        },
        "id": f"ext-sb-{SFX}-{event}",
        "type": "message.flagged",
    }
    for key, value in over.items():
        target = body
        *path, last = key.split("__")
        for part in path:
            target = target[part] if not part.isdigit() else target[int(part)]
        if value is DROP:
            del target[last]
        else:
            target[last] = value
    return body


DROP = object()
CHILDREN = ("flaggedrule", "mailbox", "recipient", "sender", "triggeredaction")
CHILD_COLUMNS = {
    "flaggedrule": "rule_id, name, severity, tags",
    "mailbox": "external_id, mailbox_id",
    "recipient": "email, name",
    "sender": "email, name",
    "triggeredaction": "action_id, name, type",
}


def latest_alert():
    """The newest alert of the suite, but its id and timestamp, with its child rows."""
    with sync_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, api_version, created_at, event_id, type, message_id, canonical_id, external_id, message_source_id "
                "FROM sublimealerts WHERE event_id LIKE :p ORDER BY id DESC LIMIT 1",
            ),
            {"p": f"ext-sb-{SFX}-%"},
        ).first()
        if row is None:
            return None
        out = {"alert": tuple(row[1:])}
        for child in CHILDREN:
            rows = conn.execute(text(f"SELECT {CHILD_COLUMNS[child]} FROM {child} WHERE sublime_alert_id = :i ORDER BY id"), {"i": row[0]})
            out[child] = [tuple(r) for r in rows]
        return out


def alert_count():
    with sync_engine.connect() as conn:
        return conn.execute(text("SELECT COUNT(*) FROM sublimealerts WHERE event_id LIKE :p"), {"p": f"ext-sb-{SFX}-%"}).scalar()


def stamps(event):
    with sync_engine.connect() as conn:
        return [r[0] for r in conn.execute(text("SELECT timestamp FROM sublimealerts WHERE event_id = :e ORDER BY id"), {"e": event})]


def sublime_cleanup():
    for child in CHILDREN:
        sql(f"DELETE FROM {child} WHERE sublime_alert_id IN (SELECT id FROM sublimealerts WHERE event_id LIKE :p)", p=f"ext-sb-{SFX}-%")
        sql(f"DELETE FROM {child} WHERE id BETWEEN 9300000 AND 9300099")
    sql("DELETE FROM sublimealerts WHERE event_id LIKE :p", p=f"ext-sb-{SFX}-%")
    sql("DELETE FROM sublimealerts WHERE id BETWEEN 9300000 AND 9300099")


#: What differs between the two backends' failed stores: the id of the rolled-back alert (in the
#: parameters and in MySQL's syntax error), the timestamp each stamps and urllib3's object address.
SUBLIME_MASKS = (
    (rb"datetime\.datetime\(\d+(, \d+)*\)", b"datetime.datetime(<now>)"),
    (rb", \d+\)\]\\n\(Background", b", <id>)]\\n(Background"),
    (rb"'n/a', \d+\)' at line", b"'n/a', <id>)' at line"),
    (rb"object at 0x[0-9a-f]+", b"object at 0x<address>"),
)


async def sublime_checks(p, t_admin, t_analyst, t_portal):
    print("\n== Sublime: guards and validation")
    sublime_connector()
    A = f"{SB}/alert"
    await p.same("alert, no token", "POST", A, json={}, expect=401)
    await p.same("alert, a portal user", "POST", A, t_portal, json={}, expect=403)
    await p.same("alert, malformed JSON without a token", "POST", A, content=b"{", headers={"Content-Type": "application/json"}, expect=422)
    await p.same("alerts, no token", "GET", f"{SB}/alerts", expect=401)
    await p.same("alerts, a portal user", "GET", f"{SB}/alerts", t_portal, expect=403)
    for label, body in (
        ("no body", None),
        ("an empty object", {}),
        ("a list", [1]),
        ("a string", "x"),
        ("wrong types", {"api_version": 1, "created_at": None, "data": [], "id": ["x"], "type": True}),
        (
            "nested errors",
            sublime_body("v", "ok", data__flagged_rules__0__tags="t", data__message__mailbox={"id": 5}, data__triggered_actions=[{}]),
        ),
        ("no message", sublime_body("v", "ok", data__message=DROP)),
    ):
        kw = {} if body is None else {"json": body}
        await p.same(f"alert, {label}", "POST", A, t_analyst, table=alert_count, expect=422, **kw)

    print("\n== Sublime: the store")
    await p.same("store an alert", "POST", A, t_analyst, json=sublime_body("ok", "ok"), table=latest_alert, expect=200)
    await p.same(
        "store, no severity, no mailbox id",
        "POST",
        A,
        t_admin,
        json=sublime_body("min", "ok", data__flagged_rules__0__severity=None, data__message__mailbox__external_id=DROP),
        table=latest_alert,
        expect=200,
    )
    await p.same(
        "store, no rules and no actions",
        "POST",
        A,
        t_analyst,
        json=sublime_body("bare", "ok", data__flagged_rules=[], data__triggered_actions=[]),
        table=latest_alert,
        expect=200,
    )
    await p.same(
        "store, quotes and non-ASCII",
        "POST",
        A,
        t_analyst,
        json=sublime_body("quoted", "quoted", api_version="ü'\"\\"),
        table=latest_alert,
        expect=200,
    )
    await p.same(
        "store, a number, a one-item list",
        "POST",
        A,
        t_analyst,
        json=sublime_body("odd", "emailodd"),
        table=latest_alert,
        expect=200,
    )
    await p.same("store, a float, a bool", "POST", A, t_analyst, json=sublime_body("float", "emailfloat"), table=latest_alert, expect=200)
    await p.same("store, a big int, minus zero", "POST", A, t_analyst, json=sublime_body("big", "emailbig"), table=latest_alert, expect=200)
    await p.same(
        "store, a message id to quote",
        "POST",
        A,
        t_analyst,
        json=sublime_body("path", "ok", data__message__id=f"ok-{SFX} a/b?c#d"),
        table=latest_alert,
        expect=200,
    )
    sublime_connector(key=None)
    await p.same("store, a connector without a key", "POST", A, t_analyst, json=sublime_body("nokey", "ok"), table=latest_alert, expect=200)
    sublime_connector()

    print("\n== Sublime: what fails where")
    failing = [
        ("no external id", sublime_body("noext", "ok", data__message__external_id=DROP)),
        ("a long api_version", sublime_body("longapi", "ok", api_version="v" * 300)),
        ("Sublime answers HTML", sublime_body("html", "html")),
        ("Sublime answers nothing", sublime_body("empty", "empty")),
        ("Sublime hangs up", sublime_body("hangup", "hangup")),
        ("an unknown message", sublime_body("unknown", "unknown")),
        ("no sender", sublime_body("nosender", "nosender")),
        ("no recipient", sublime_body("norcpt", "norcpt")),
        ("recipients an empty string", sublime_body("rcptstr", "rcptstr")),
        ("recipients a string", sublime_body("rcptchars", "rcptchars")),
        ("recipients an object", sublime_body("rcptdict", "rcptdict")),
        ("data a list", sublime_body("datalist", "datalist")),
        ("data null", sublime_body("datanull", "datanull")),
        ("data a string", sublime_body("datastr", "datastr")),
        ("an email null", sublime_body("emailnull", "emailnull")),
        ("an email an empty list", sublime_body("emaillist", "emaillist")),
        ("an email a nested empty list", sublime_body("emailnested", "emailnested")),
        ("an email a pair", sublime_body("emailpair", "emailpair")),
        ("an email an object", sublime_body("emaildict", "emaildict")),
        ("an email NaN", sublime_body("emailnan", "emailnan")),
        ("an email [None]", sublime_body("emailnone", "emailnone")),
        ("long emails (the recipient first)", sublime_body("emaillong", "emaillong")),
        ("a long rule name", sublime_body("longrule", "ok", data__flagged_rules__1__name="n" * 300)),
        (
            "a long mailbox id and action (the mailbox first)",
            sublime_body("longmbx", "ok", data__message__mailbox__id="m" * 256, data__triggered_actions__0__type="t" * 400),
        ),
        (
            "a long action and emails (the recipient first)",
            sublime_body("longact", "emaillong", data__triggered_actions__0__name="a" * 300),
        ),
        ("a long action", sublime_body("longact2", "ok", data__triggered_actions__0__id="a" * 300)),
        ("long tags", sublime_body("longtags", "ok", data__flagged_rules__0__tags=["t" * 100] * 3)),
    ]
    for label, body in failing:
        await p.same(f"store, {label}", "POST", A, t_analyst, json=body, table=alert_count, masks=SUBLIME_MASKS, expect=500)
    sublime_connector(url=None)
    await p.same("store, no connector row", "POST", A, t_analyst, json=sublime_body("norow", "ok"), table=alert_count, expect=500)
    sublime_connector(url=f"http://127.0.0.1:{CLOSED_PORT}")
    await p.same(
        "store, a closed port",
        "POST",
        A,
        t_analyst,
        json=sublime_body("closed", "ok"),
        table=alert_count,
        masks=SUBLIME_MASKS,
        expect=500,
    )
    sublime_connector()

    print("\n== Sublime: the listing")
    L = f"{SB}/alerts"
    await p.same("list the alerts", "GET", L, t_analyst, expect=200)
    await p.same("list the alerts (admin)", "GET", L, t_admin, expect=200)
    sql(
        "INSERT INTO sublimealerts (id, api_version, created_at, event_id, type, message_id, canonical_id, external_id, "
        "message_source_id, timestamp) VALUES (9300001, 'v0', 'c', :e, 't', 'm', 'c', 'x', 's', '2026-01-02 03:04:05')",
        e=f"ext-sb-{SFX}-seeded",
    )
    sql("INSERT INTO sender (id, email, name, sublime_alert_id) VALUES (9300001, 's@example.com', NULL, 9300001)")
    sql("INSERT INTO recipient (id, email, name, sublime_alert_id) VALUES (9300001, 'r@example.com', 'n/a', 9300001)")
    sql("INSERT INTO recipient (id, email, name, sublime_alert_id) VALUES (9300002, 'q@example.com', NULL, 9300001)")
    await p.same("list, a sender and a recipient without a name", "GET", L, t_analyst, expect=500)
    sql("DELETE FROM sender WHERE id = 9300001")
    sql("DELETE FROM recipient WHERE id IN (9300001, 9300002)")
    await p.same("list, an alert without child rows", "GET", L, t_analyst, expect=200)
    sql("DELETE FROM sublimealerts WHERE id = 9300001")

    print("\n== Sublime: the timestamp (section 4: Python stamps its import time)")
    for client, who in ((p.py, "python"), (p.rs, "rust")):
        event = f"ext-sb-{SFX}-stamp-{who}"
        before = datetime.datetime.now().replace(microsecond=0)
        for _ in range(2):
            r = await client.post(A, json=sublime_body(f"stamp-{who}", "ok"), headers={"Authorization": f"Bearer {t_analyst}"})
            if r.status_code != 200:
                check(f"timestamp: {who} stores", False, r.text)
            await asyncio.sleep(1.2)
        got = stamps(event)
        if who == "python":
            check(
                "timestamp: Python stamps both alerts with the same time, before them",
                len(got) == 2 and got[0] == got[1] and got[0] < before,
                str(got),
            )
        else:
            check(
                "timestamp: Rust stamps each alert with its arrival",
                len(got) == 2 and got[0] < got[1] and before - datetime.timedelta(seconds=1) <= got[0],
                str(got),
            )

    print("\n== Sublime: the connector check")
    with sync_engine.connect() as conn:
        cid = conn.execute(text("SELECT id FROM connectors WHERE connector_name = 'Sublime'")).scalar()
    V = f"/api/connectors/verify/{cid}"

    def verified():
        with sync_engine.connect() as conn:
            return conn.execute(text("SELECT connector_verified FROM connectors WHERE connector_name = 'Sublime'")).scalar()

    def rules(answer=None, url=SUBLIME_URL, key=SUBLIME_KEY):
        def go():
            sql(
                "UPDATE connectors SET connector_url = :u, connector_api_key = :k, connector_verified = 0 WHERE connector_name = 'Sublime'",
                u=url,
                k=key,
            )
            SUBLIME_ANSWER.rules = answer

        return go

    await p.same("verify Sublime", "POST", V, t_admin, before=rules(), table=verified, expect=200)
    await p.same(
        "verify Sublime, a 401",
        "POST",
        V,
        t_admin,
        before=rules(raw(401, "application/json", b'{"error":"unauthorized"}')),
        table=verified,
    )
    await p.same("verify Sublime, no key", "POST", V, t_admin, before=rules(key=None), table=verified)
    await p.same(
        "verify Sublime, a closed port",
        "POST",
        V,
        t_admin,
        before=rules(url=f"http://127.0.0.1:{CLOSED_PORT}"),
        table=verified,
        masks=SUBLIME_MASKS,
    )
    SUBLIME_ANSWER.rules = None


# --- ScoutSuite: the scout stand-in -------------------------------------------------------------------

SCOUT_STUB = r"""#!/bin/sh
out="__LOG__/$$"
{
  printf 'cwd=%s\n' "$PWD"
  printf 'marker=%s\n' "$SCOUT_PARITY_MARKER"
  for a in "$@"; do printf 'arg=%s\n' "$a"; done
} > "$out.tmp"
prev=""
name=""
for a in "$@"; do
  if [ "$prev" = "--service-account" ]; then
    cat "$a" > "$out.cred"
    stat -c %a "$(dirname "$a")" > "$out.mode"
  fi
  if [ "$prev" = "--report-name" ]; then name="$a"; fi
  prev="$a"
done
mkdir -p scoutsuite-report/scoutsuite-results
echo report > "scoutsuite-report/$name.html"
echo results > "scoutsuite-report/scoutsuite-results/scoutsuite_results_$name.js"
echo exceptions > "scoutsuite-report/scoutsuite-results/scoutsuite_exceptions_$name.js"
mv "$out.tmp" "$out.done"
case "$name" in fail*) echo "stand-in failure" >&2; exit 3;; esac
"""
SC = "/api/scoutsuite"
CRED_PATH = re.compile(r"^" + re.escape(os.path.realpath(SCOUT_TMP)) + r"/scoutsuite-gcp-cred-[a-z0-9_]{8}/gcp-service-account\.json$")


def install_scout_stub():
    path = os.path.join(SCOUT_BIN, "scout")
    with open(path, "w") as f:
        f.write(SCOUT_STUB.replace("__LOG__", SCOUT_LOG))
    os.chmod(path, 0o755)
    # Python's side: the stand-in first on PATH, the TMPDIR and the marker both processes hold.
    os.environ["PATH"] = SCOUT_BIN + os.pathsep + os.environ.get("PATH", "")
    os.environ["TMPDIR"] = SCOUT_TMP
    os.environ["SCOUT_PARITY_MARKER"] = SCOUT_MARKER
    tempfile.tempdir = None


def scout_run(wait=10.0):
    """The next run of the stand-in (waited for: Rust starts it after answering): its record, the
    credential path checked and masked, and whether the credential's directory is gone after."""
    deadline = time.time() + wait
    while time.time() < deadline:
        done = sorted(f for f in os.listdir(SCOUT_LOG) if f.endswith(".done"))
        if done:
            stem = os.path.join(SCOUT_LOG, done[0][: -len(".done")])
            with open(stem + ".done") as f:
                lines = f.read().splitlines()
            record = {"lines": lines}
            for suffix in ("cred", "mode"):
                if os.path.exists(f"{stem}.{suffix}"):
                    with open(f"{stem}.{suffix}", "rb") as f:
                        record[suffix] = f.read()
            for suffix in ("done", "cred", "mode"):
                if os.path.exists(f"{stem}.{suffix}"):
                    os.remove(f"{stem}.{suffix}")
            cred = next((line[4:] for i, line in enumerate(lines) if i and lines[i - 1] == "arg=--service-account"), None)
            if cred is not None:
                record["cred_path_ok"] = bool(CRED_PATH.match(cred))
                for _ in range(100):
                    if not os.path.exists(os.path.dirname(cred)):
                        break
                    time.sleep(0.05)
                record["cred_dir_removed"] = not os.path.exists(os.path.dirname(cred))
                record["lines"] = [("arg=<credential>" if line == f"arg={cred}" else line) for line in lines]
            return record
        time.sleep(0.05)
    return None


def gcp_run():
    """`scout_run` for a GCP scan, its credential checked: under TMPDIR in a private directory of
    `mkdtemp`'s shape, holding the upload, and gone once the scan ended."""
    record = scout_run()
    ok = bool(record) and record.get("cred_path_ok") and record.get("cred_dir_removed") and record.get("mode") == b"700\n"
    check("ScoutSuite: the GCP credential's directory (shape, mode 0700, removed)", bool(ok), str(record)[:600])
    return record


def no_scout_run():
    time.sleep(0.5)
    return sorted(f for f in os.listdir(SCOUT_LOG) if f.endswith(".done"))


def report_tree():
    root = os.path.join(SCOUT_WORK, "scoutsuite-report")
    out = []
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            out.append(os.path.relpath(os.path.join(base, name), root))
    return sorted(out)


def report_files(*names):
    def go():
        results = os.path.join(SCOUT_WORK, "scoutsuite-report", "scoutsuite-results")
        os.makedirs(results, exist_ok=True)
        for name in names:
            base = os.path.splitext(name)[0]
            for path in (
                os.path.join(SCOUT_WORK, "scoutsuite-report", name),
                os.path.join(results, f"scoutsuite_results_{base}.js"),
                os.path.join(results, f"scoutsuite_exceptions_{base}.js"),
            ):
                with open(path, "w") as f:
                    f.write("x")

    return go


GCP_KEY = {
    "type": "service_account",
    "project_id": "parity",
    "private_key_id": "kid",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n",
    "client_email": "sa@parity.iam.gserviceaccount.com",
    "client_id": "123",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa",
    "universe_domain": "googleapis.com",
}


async def scoutsuite_checks(p, t_admin, t_analyst, t_portal):
    cwd = os.getcwd()
    os.chdir(SCOUT_WORK)
    try:
        await _scoutsuite_checks(p, t_admin, t_analyst, t_portal)
    finally:
        os.chdir(cwd)


async def _scoutsuite_checks(p, t_admin, t_analyst, t_portal):
    print("\n== ScoutSuite: guards and the options")
    for method, path in (
        ("GET", "/report-generation-options"),
        ("GET", "/available-reports"),
        ("POST", "/generate-aws-report"),
        ("POST", "/generate-azure-report"),
        ("POST", "/generate-gcp-report"),
        ("DELETE", "/delete-report/x.html"),
    ):
        kw = {"json": {}} if path in ("/generate-aws-report", "/generate-azure-report") else {}
        await p.same(f"{path}, no token", method, f"{SC}{path}", expect=401, **kw)
        await p.same(f"{path}, a portal user", method, f"{SC}{path}", t_portal, expect=403, **kw)
    await p.same("report options", "GET", f"{SC}/report-generation-options", t_analyst, expect=200)

    print("\n== ScoutSuite: the AWS and Azure scans")
    aws = {"report_type": "aws", "access_key_id": "AKIA-PARITY", "secret_access_key": "s3 cr$t'", "report_name": "aws-parity"}
    azure = {"report_type": "azure", "username": "u@example.com", "password": "p w", "tenant_id": "tenant", "report_name": "azure-parity"}
    A, Z = f"{SC}/generate-aws-report", f"{SC}/generate-azure-report"
    await p.same("AWS scan", "POST", A, t_analyst, json=aws, table=scout_run, expect=200)
    await p.same(
        "AWS scan, odd values and an extra field",
        "POST",
        A,
        t_admin,
        json={**aws, "report_name": "ü -x", "access_key_id": "--help", "extra": 1},
        table=scout_run,
        expect=200,
    )
    await p.same("AWS scan, scout fails", "POST", A, t_analyst, json={**aws, "report_name": "fail-aws"}, table=scout_run, expect=200)
    await p.same("Azure scan", "POST", Z, t_analyst, json=azure, table=scout_run, expect=200)
    for label, path, body, status in (
        ("AWS, another report type", A, {**aws, "report_type": "azure"}, 400),
        ("AWS, report type in capitals", A, {**aws, "report_type": "AWS"}, 400),
        ("AWS, a missing field and another type", A, {"report_type": "azure", "access_key_id": "x"}, 422),
        ("AWS, wrong types", A, {"report_type": None, "access_key_id": 1, "secret_access_key": [], "report_name": True}, 422),
        ("AWS, a list", A, [1], 422),
        ("Azure, another report type", Z, {**azure, "report_type": "aws"}, 400),
        ("Azure, no tenant", Z, {k: v for k, v in azure.items() if k != "tenant_id"}, 422),
    ):
        await p.same(label, "POST", path, t_analyst, json=body, expect=status)
    await p.same("AWS, malformed JSON", "POST", A, t_analyst, content=b"{", headers={"Content-Type": "application/json"}, expect=422)
    await p.same("Azure, no body", "POST", Z, t_analyst, expect=422)
    check("ScoutSuite: no scan started by a refused request", no_scout_run() == [])

    print("\n== ScoutSuite: the GCP scan")
    G = f"{SC}/generate-gcp-report"
    key = json.dumps(GCP_KEY).encode()

    def upload(content, name="key.json", ctype="application/json"):
        return {"files": {"file": (name, content, ctype)}}

    await p.same("GCP scan", "POST", G, t_analyst, table=gcp_run, expect=200, **upload(key))
    await p.same("GCP scan, a report name", "POST", f"{G}?report_name=gcp%20parity", t_admin, table=gcp_run, expect=200, **upload(key))
    await p.same(
        "GCP scan, the last of two report names",
        "POST",
        f"{G}?report_name=a&report_name=gcp-last",
        t_analyst,
        table=gcp_run,
        expect=200,
        **upload(key),
    )
    await p.same(
        "GCP scan, a UTF-16 key with a BOM",
        "POST",
        G,
        t_analyst,
        table=gcp_run,
        expect=200,
        **upload(b"\xff\xfe" + json.dumps(GCP_KEY).encode("utf-16-le")),
    )
    await p.same(
        "GCP scan, a UTF-8 BOM and extra keys",
        "POST",
        G,
        t_analyst,
        table=gcp_run,
        expect=200,
        **upload(b"\xef\xbb\xbf" + json.dumps({**GCP_KEY, "x": [1]}).encode()),
    )
    await p.same("GCP scan, a file name to ignore", "POST", G, t_analyst, table=gcp_run, expect=200, **upload(key, name="../../etc/passwd"))
    for label, content, status in (
        ("invalid JSON", b"{bad", 400),
        ("an empty file", b"", 400),
        ("extra data", b'{"a": 1} x', 400),
        ("a list", b"[1, 2]", 400),
        ("null", b"null", 400),
        ("a missing field", json.dumps({k: v for k, v in GCP_KEY.items() if k != "universe_domain"}).encode(), 400),
        ("wrong types", json.dumps({**GCP_KEY, "client_id": 123, "project_id": None}).encode(), 400),
        ("NaN", b'{"type": NaN}', 400),
        ("not UTF-8", b'{"type": "\xe9"}', 400),
    ):
        await p.same(f"GCP, {label}", "POST", G, t_analyst, expect=status, **upload(content))
    await p.same("GCP, no file", "POST", G, t_analyst, data={"other": "x"}, expect=422)
    await p.same("GCP, a text field for the file", "POST", G, t_analyst, data={"file": "text"}, expect=422)
    await p.same("GCP, a JSON body", "POST", G, t_analyst, json=GCP_KEY, expect=422)
    await p.same(
        "GCP, a truncated multipart body",
        "POST",
        G,
        t_analyst,
        content=b'--x\r\nContent-Disposition: form-data; name="file"; filename="k"\r\n\r\nabc',
        headers={"Content-Type": "multipart/form-data; boundary=x"},
        expect=422,
    )
    await p.same(
        "GCP, a multipart body without a boundary",
        "POST",
        G,
        t_analyst,
        content=b"--x--\r\n",
        headers={"Content-Type": "multipart/form-data"},
        expect=400,
    )
    check("ScoutSuite: no GCP scan started by a refused upload", no_scout_run() == [])
    check("ScoutSuite: no credential left behind", os.listdir(SCOUT_TMP) == [], str(os.listdir(SCOUT_TMP)))

    print("\n== ScoutSuite: the reports")
    R = f"{SC}/available-reports"
    await p.same("available reports", "GET", R, t_analyst, expect=200)
    reports = os.path.join(SCOUT_WORK, "scoutsuite-report")
    os.makedirs(os.path.join(reports, "folder.html"))
    os.symlink(os.path.join(SCOUT_ROOT, "nowhere"), os.path.join(reports, "dangling.html"))
    await p.same("available reports, a directory and a dangling link", "GET", R, t_admin, expect=200)
    D = f"{SC}/delete-report"
    await p.same(
        "delete a report",
        "DELETE",
        f"{D}/del-parity.html",
        t_analyst,
        before=report_files("del-parity.html"),
        table=report_tree,
        expect=200,
    )
    await p.same("delete a report without its scripts", "DELETE", f"{D}/aws-parity.html", t_analyst, table=report_tree, expect=200)
    await p.same("delete, nothing there", "DELETE", f"{D}/missing.html", t_analyst, table=report_tree, expect=200)
    await p.same(
        "delete, a quoted name",
        "DELETE",
        f"{D}/x%20y.tar.html",
        t_analyst,
        before=report_files("x y.tar.html"),
        table=report_tree,
        expect=200,
    )
    await p.same(
        "delete, leading dots",
        "DELETE",
        f"{D}/..hidden",
        t_analyst,
        before=report_files("..hidden"),
        table=report_tree,
        expect=200,
    )
    await p.same("delete, a directory of that name", "DELETE", f"{D}/folder.html", t_analyst, table=report_tree, expect=500)
    await p.same("delete, a dangling link", "DELETE", f"{D}/dangling.html", t_analyst, table=report_tree, expect=200)
    shutil.rmtree(os.path.join(reports, "folder.html"))
    os.remove(os.path.join(reports, "dangling.html"))
    hidden = os.path.join(SCOUT_ROOT, "moved")
    os.rename(reports, hidden)
    await p.same("available reports, no directory", "GET", R, t_analyst, expect=404)
    os.rename(hidden, reports)


SAVED_LICENSES = []
SAVED_SUBLIME = []


def seed():
    # `get_license` reads the first row: the suite's is the only one while it runs.
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT id, license_key, customer_name, customer_email, company_name FROM license ORDER BY id"))
        SAVED_LICENSES.extend(dict(r._mapping) for r in rows)
    sql("DELETE FROM license")
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM connectors WHERE connector_name = 'Sublime'"))
        SAVED_SUBLIME.extend(dict(r._mapping) for r in rows)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )


def cleanup():
    sublime_cleanup()
    sql("DELETE FROM connectors WHERE connector_name = 'Sublime'")
    for row in SAVED_SUBLIME:
        sql(f"INSERT INTO connectors ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    sql("DELETE FROM license_cache WHERE license_key = :k", k=LICENSE_KEY)
    sql("DELETE FROM license WHERE license_key = :k", k=LICENSE_KEY)
    for row in SAVED_LICENSES:
        sql(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) "
            "VALUES (:id, :license_key, :customer_name, :customer_email, :company_name)",
            **row,
        )
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    shutil.rmtree(SCOUT_ROOT, ignore_errors=True)


async def main():
    recorders = [
        Recorder("feeds", FEEDS_PORT, FEEDS_ANSWER),
        Recorder("mcp", MCP_PORT, MCP_ANSWER, fold=lambda target: target.startswith("/query/") or target == "/verify-license"),
        Recorder("sublime", SUBLIME_PORT, SUBLIME_ANSWER),
    ]
    proc = None
    try:
        install_scout_stub()
        seed()
        proc = start_rust()
    except BaseException:
        if proc:
            proc.kill()
        cleanup()
        for recorder in recorders:
            recorder.stop()
        raise
    p = Pair(recorders)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    try:
        sections = os.environ.get("EXT_PARITY_SECTIONS", "patch,mcp,sublime,scoutsuite").split(",")
        if "patch" in sections:
            await patch_tuesday_checks(p, t_admin, t_analyst, t_portal)
        if "mcp" in sections:
            await mcp_checks(p, t_admin, t_analyst, t_portal)
        if "sublime" in sections:
            await sublime_checks(p, t_admin, t_analyst, t_portal)
        if "scoutsuite" in sections:
            await scoutsuite_checks(p, t_admin, t_analyst, t_portal)
    finally:
        await p.close()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        for recorder in recorders:
            recorder.stop()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
