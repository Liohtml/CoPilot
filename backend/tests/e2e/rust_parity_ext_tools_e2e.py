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
  (`copilot-license`'s client): `requests` writes the names as given over urllib3 1.26 (the
  backend image) but title-cases them over urllib3-future (a development venv).

Python reaches the stand-ins because the modules' URL constants are patched here (and the
licence server's host rewritten in `requests`); Rust because its instance is started with the
`COPILOT_*_URL` overrides (parity harness only). Each backend
stamps the items with its own clock: those stamps are masked in the bodies after a check that
they are within seconds of each other; everything else is compared byte for byte.

    PARITY_SUITES=tests/e2e/rust_parity_ext_tools_e2e.py scripts/rust-parity.sh

Ports (all overridable, defaults in the suite's own range): EXT_PARITY_RUST_PORT,
EXT_FEEDS_STUB_PORT, EXT_MCP_STUB_PORT.
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
    from app.routers import copilot_mcp
    from app.routers import microsoft_patch_tuesday

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
        (b1, s1), (b2, s2) = masked(r1.content), masked(r2.content)
        ok = r1.status_code == r2.status_code and b1 == b2
        if expect is not None and r1.status_code != expect:
            ok = False
        detail = f"python {r1.status_code} {b1[:1500]!r}\n        rust   {r2.status_code} {b2[:1500]!r}"
        h1 = {k: r1.headers.get(k) for k in RESPONSE_HEADERS}
        h2 = {k: r2.headers.get(k) for k in RESPONSE_HEADERS}
        if s1 != s2 and h1.get("content-length") and h2.get("content-length"):
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


SAVED_LICENSES = []


def seed():
    # `get_license` reads the first row: the suite's is the only one while it runs.
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT id, license_key, customer_name, customer_email, company_name FROM license ORDER BY id"))
        SAVED_LICENSES.extend(dict(r._mapping) for r in rows)
    sql("DELETE FROM license")
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )


def cleanup():
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


async def main():
    recorders = [
        Recorder("feeds", FEEDS_PORT, FEEDS_ANSWER),
        Recorder("mcp", MCP_PORT, MCP_ANSWER, fold=lambda target: target.startswith("/query/") or target == "/verify-license"),
    ]
    proc = None
    try:
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
        sections = os.environ.get("EXT_PARITY_SECTIONS", "patch,mcp").split(",")
        if "patch" in sections:
            await patch_tuesday_checks(p, t_admin, t_analyst, t_portal)
        if "mcp" in sections:
            await mcp_checks(p, t_admin, t_analyst, t_portal)
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
