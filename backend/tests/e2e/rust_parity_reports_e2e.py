"""Parity of the Rust report routes (`crates/copilot-reports`, `crates/copilot-docx`) with this
backend — NOT collected by pytest (needs a live MySQL, wkhtmltopdf and the Rust binary; run by
scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts answer the same requests
on one database: the case DOCX and PDF reports (`/api/incidents/report/generate-report-{docx,pdf}`),
the customer reports' generation (`/api/incidents/customer_reports/generate/background`, every
layout and theme, the SLA section, a customer user, a failing wkhtmltopdf) and the SOC operations
report (`GET /api/soc_management/report`) and the Grafana panel report
(`POST /api/reporting/generate-report`).

wkhtmltopdf is a recording wrapper on both sides (Python's `pdfkit.configuration` is pointed at it,
the Rust instance through `COPILOT_WKHTMLTOPDF`): it keeps every invocation's arguments and the HTML
page it was given, then runs the real `/usr/bin/wkhtmltopdf` (or fails, when told to). The suite
compares the status, the JSON bodies, the headers of the files, a DOCX's members byte for byte, that
a PDF is a PDF, the pages wkhtmltopdf was given (the generation time masked) and its arguments (the
temporary paths masked), the rows the customer reports leave and the objects they store. The charts
are drawn by Rust (§4): each chart's PNG carries the call that drew it, and Python's chart functions
are replaced by recorders writing the same call into a PNG, so the pages are compared with each
chart reduced to its call. MinIO is the objectstore suite's stand-in.

The Grafana report runs a headless Chromium on both sides: Python's Playwright is pointed at a
recording wrapper of the browser (`executable_path`), the Rust instance through `COPILOT_CHROMIUM`.
The wrapper keeps each launch's arguments (the profile directory masked) and the report page the
second launch is given (Python's `report.html` in its working directory, Rust's in its temporary
directory); a Grafana stand-in serves a login page, `/`, and the `d-solo` pages, and records every
request the browser sends it, headers included (the time window masked). The PDFs are compared by
their page count and text (`pdfinfo`, `pdftotext`), the screenshots by their size.

Deliberate differences (RUST_MIGRATION.md §4): the case reports check the case's customer (403 for
a scoped analyst on another tenant's case; Python rendered it); the Grafana report's page is written
into a fresh temporary directory, not the working directory.

    PARITY_SUITES=tests/e2e/rust_parity_reports_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
import http.server
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
import zlib

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")

import httpx  # noqa: E402
import jwt  # noqa: E402
import pdfkit  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from miniopy_async import Minio  # noqa: E402
from rust_parity_objectstore_e2e import S3StandIn  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("REPORTS_PARITY_RUST_PORT", "6300"))
S3_PORT = int(os.environ.get("REPORTS_S3_STUB_PORT", "6301"))
S3_USER, S3_SECRET = "minio-reports", "minio-reports-secret"
CUST_A, CUST_B = f"RPT_A{SFX}", f"RPT_B{SFX}"
ADMIN, ANALYST, PORTAL, ANALYST_B = f"rpt_admin{SFX}", f"rpt_analyst{SFX}", f"rpt_portal{SFX}", f"rpt_analyst_b{SFX}"
BASE = 9_400_000
R = "/api/incidents/report"
CR = "/api/incidents/customer_reports"
SOC = "/api/soc_management/report"
results = []
USERS = {}
SEEDED = {}


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


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(text(statement), params)]


# --- wkhtmltopdf, recorded ----------------------------------------------------------------------------

GRAFANA_PORT = int(os.environ.get("REPORTS_GRAFANA_STUB_PORT", "6302"))
CLOSED_PORT = int(os.environ.get("REPORTS_CLOSED_PORT", "6307"))
CHROME = os.environ.get("REPORTS_CHROMIUM", "/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell")
WORK = tempfile.mkdtemp(prefix="reports-parity-")
RECORDS = os.path.join(WORK, "records")
CONTROL = os.path.join(WORK, "mode")
WRAPPER = os.path.join(WORK, "wkhtmltopdf")
BROWSER_RECORDS = os.path.join(WORK, "browser")
BROWSER = os.path.join(WORK, "chromium")
RUST_TMP = os.path.join(WORK, "rust-tmp")
os.makedirs(RECORDS)
os.makedirs(BROWSER_RECORDS)
os.makedirs(RUST_TMP)

WRAPPER_SOURCE = f"""#!{sys.executable} -I
import json, os, sys, time
argv = sys.argv
page = None
if len(argv) > 2 and os.path.exists(argv[-2]):
    with open(argv[-2], encoding="utf-8") as fh:
        page = fh.read()
with open(os.path.join({RECORDS!r}, "%020d.json" % time.time_ns()), "w") as fh:
    json.dump({{"argv": argv, "html": page}}, fh)
mode = open({CONTROL!r}).read().strip() if os.path.exists({CONTROL!r}) else ""
if mode == "fail":
    sys.stderr.write("Loading pages (1/6)\\nError: simulated wkhtmltopdf failure\\n")
    sys.exit(1)
os.execv("/usr/bin/wkhtmltopdf", ["/usr/bin/wkhtmltopdf"] + argv[1:])
"""
with open(WRAPPER, "w") as fh:
    fh.write(WRAPPER_SOURCE)
os.chmod(WRAPPER, 0o755)


BROWSER_SOURCE = f"""#!{sys.executable} -I
import glob, json, os, sys, time
def read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None
tmp = os.environ.get("TMPDIR") or "/tmp"
record = {{
    "argv": sys.argv[1:],
    "cwd_html": read(os.path.join(os.getcwd(), "report.html")),
    "tmp_html": [read(p) for p in sorted(glob.glob(os.path.join(tmp, "copilot-grafana-report-*", "report.html")))],
}}
with open(os.path.join({BROWSER_RECORDS!r}, "%020d.json" % time.time_ns()), "w") as fh:
    json.dump(record, fh)
os.execv({CHROME!r}, [{CHROME!r}] + sys.argv[1:])
"""
with open(BROWSER, "w") as fh:
    fh.write(BROWSER_SOURCE)
os.chmod(BROWSER, 0o755)


def take_browser_records():
    out = []
    for name in sorted(os.listdir(BROWSER_RECORDS)):
        path = os.path.join(BROWSER_RECORDS, name)
        with open(path) as fh:
            out.append(json.load(fh))
        os.remove(path)
    return out


def set_mode(mode):
    with open(CONTROL, "w") as fh:
        fh.write(mode)


def take_records():
    out = []
    for name in sorted(os.listdir(RECORDS)):
        path = os.path.join(RECORDS, name)
        with open(path) as fh:
            out.append(json.load(fh))
        os.remove(path)
    return out


def patch_python():
    original = pdfkit.configuration

    def configuration(wkhtmltopdf="", **kwargs):
        return original(wkhtmltopdf=WRAPPER, **kwargs)

    pdfkit.configuration = configuration

    from app.data_store import data_store_operations
    from app.data_store import data_store_session

    async def create_session():
        return Minio(f"127.0.0.1:{S3_PORT}", access_key=S3_USER, secret_key=S3_SECRET, secure=False)

    data_store_operations.create_session = create_session
    data_store_session.create_session = create_session

    # The charts: a PNG that carries the call, as the Rust charts do.
    import app.incidents.services.customer_report as customer_report
    import app.soc_management.services.report as soc_report

    def recorder(name):
        def chart(*args, **kwargs):
            return "data:image/png;base64," + base64.b64encode(fake_png({"chart": name, "args": list(args), "kwargs": kwargs})).decode()

        return chart

    for module in (customer_report, soc_report):
        for name in ("donut_png", "hbar_png", "evolution_png", "line_png"):
            if hasattr(module, name):
                setattr(module, name, recorder(name))

    # Playwright's own Chromium revision is not installed here: the same headless shell the Rust
    # instance runs, through the recording wrapper.
    from playwright.async_api._generated import BrowserType

    launch = BrowserType.launch

    async def launch_wrapped(self, **kwargs):
        return await launch(self, **{**kwargs, "executable_path": BROWSER})

    BrowserType.launch = launch_wrapped


def fake_png(call):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    payload = b"copilot-chart\0" + base64.b64encode(json.dumps(call).encode())
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"tEXt", payload)
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
        + chunk(b"IEND", b"")
    )


def integral(value):
    """A chart's numbers compared as numbers (Rust charts plot floats where Python passes ints)."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, list):
        return [integral(v) for v in value]
    if isinstance(value, dict):
        return {k: integral(v) for k, v in value.items()}
    return value


def png_call(b64):
    png = base64.b64decode(b64)
    i = 8
    while i + 8 <= len(png):
        (length,) = struct.unpack(">I", png[i : i + 4])
        kind, data = png[i + 4 : i + 8], png[i + 8 : i + 8 + length]
        if kind == b"tEXt" and data.startswith(b"copilot-chart\0"):
            return integral(json.loads(base64.b64decode(data.split(b"\0", 1)[1])))
        i += 12 + length
    return {"no": "call"}


CHART = re.compile(r"data:image/png;base64,([A-Za-z0-9+/=]+)")
GENERATED = re.compile(r'<div class="v">\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC</div>')
TMP = re.compile(r"/[^\s\"']*/tmp[a-z0-9_]{8}\.(html|pdf)")
TMP_FILE = re.compile(r"/[^\s\"']*/tmp[a-z0-9_]{8}\.docx")


def normalise_page(html):
    if html is None:
        return None
    html = GENERATED.sub('<div class="v">GENERATED UTC</div>', html)
    return CHART.sub(lambda m: "CHART" + json.dumps(png_call(m.group(1)), sort_keys=True), html)


def normalise_records(records):
    out = []
    for r in records:
        argv = [TMP.sub(lambda m: f"<tmp.{m.group(1)}>", a) for a in r["argv"]]
        out.append({"argv": argv, "html": normalise_page(r["html"])})
    return out


# --- The two backends ---------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import grafana
    from app.routers import incidents
    from app.routers import soc_management

    api = APIRouter(prefix="/api")
    api.include_router(incidents.router)
    api.include_router(soc_management.router)
    api.include_router(grafana.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
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
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_STARTUP_TASKS": "false",  # the startup seeds no row of the shared database
        "COPILOT_PORT": str(port),
        "MINIO_ROOT_USER": S3_USER,
        "MINIO_ROOT_PASSWORD": S3_SECRET,
        "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{S3_PORT}",
        "COPILOT_WKHTMLTOPDF": WRAPPER,
        "COPILOT_CHROMIUM": BROWSER,
        "TMPDIR": RUST_TMP,
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


FILE_HEADERS = ("content-type", "content-disposition", "accept-ranges", "cache-control", "vary", "content-encoding")


def body_of(r):
    if r.headers.get("content-type", "").startswith("application/json"):
        return r.json()
    return None


def docx_members(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    return [(i.filename, z.read(i.filename)) for i in z.infolist()]


def file_summary(r):
    if r.status_code != 200 or body_of(r) is not None:
        return None
    ctype = r.headers.get("content-type", "")
    summary = {"headers": {h: r.headers.get(h) for h in FILE_HEADERS}}
    # Rust's CORS layer adds its own tokens to `Vary`; only `Accept-Encoding` is the route's.
    summary["headers"]["vary"] = "Accept-Encoding" in (r.headers.get("vary") or "")
    if "pdf" in ctype:
        summary["pdf"] = r.content.startswith(b"%PDF-")
    elif "wordprocessingml" in ctype:
        summary["members"] = [(n, len(d), hash(d)) for n, d in docx_members(r.content)]
    return summary


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=180,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=180)

    async def call(self, client, method, path, tok, **kw):
        headers = {"Accept-Encoding": "identity", **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        return await client.request(method, path, headers=headers, **kw)

    async def same(self, name, method, path, tok=None, after=None, mask=None, expect=None, **kw):
        """Python, then Rust: `after(side, response)` waits for and reads what the request left
        (rows, objects), `mask` normalises a JSON body."""
        take_records()
        r1 = await self.call(self.py, method, path, tok, **kw)
        left1 = after("p", r1) if after else None
        rec1 = normalise_records(take_records())
        r2 = await self.call(self.rs, method, path, tok, **kw)
        left2 = after("r", r2) if after else None
        rec2 = normalise_records(take_records())
        b1, b2 = body_of(r1), body_of(r2)
        # A temporary file named in a message (python-docx's `ValueError`).
        b1 = json.loads(TMP_FILE.sub("<tmp>", json.dumps(b1))) if b1 is not None else None
        b2 = json.loads(TMP_FILE.sub("<tmp>", json.dumps(b2))) if b2 is not None else None
        if mask:
            b1, b2 = mask(b1), mask(b2)
        ok = r1.status_code == r2.status_code and b1 == b2
        detail = f"python {r1.status_code} {str(b1 if b1 is not None else r1.content[:200])[:600]}\n        rust   {r2.status_code} {str(b2 if b2 is not None else r2.content[:200])[:600]}"
        f1, f2 = file_summary(r1), file_summary(r2)
        if f1 != f2:
            ok = False
            detail += f"\n        file python {f1}\n        file rust   {f2}"
        if left1 != left2:
            ok = False
            detail += f"\n        left python {left1}\n        left rust   {left2}"
        if rec1 != rec2:
            ok = False
            if len(rec1) != len(rec2):
                detail += f"\n        wkhtmltopdf runs python {len(rec1)} rust {len(rec2)}"
            for a, b in zip(rec1, rec2):
                if a["argv"] != b["argv"]:
                    detail += f"\n        argv python {a['argv']}\n        argv rust   {b['argv']}"
                if a["html"] != b["html"]:
                    x, y = a["html"] or "", b["html"] or ""
                    at = next((i for i, (c, d) in enumerate(zip(x, y)) if c != d), min(len(x), len(y)))
                    detail += f"\n        html differs at {at}\n        python …{x[max(0, at - 200):at + 300]!r}\n        rust   …{y[max(0, at - 200):at + 300]!r}"
        if (f1 or {}).get("pdf") and not rec1:
            ok = False
            detail += "\n        the PDF did not go through the wkhtmltopdf wrapper"
        if expect and r1.status_code != expect:
            ok = False
            detail += f"\n        expected {expect}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- Seed ---------------------------------------------------------------------------------------------

ALERT_IDS = []
CASE_IDS = []


def seed():
    sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, 'Acme Reports', UTC_TIMESTAMP())", c=CUST_A)
    sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, 'Beta Reports', UTC_TIMESTAMP())", c=CUST_B)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (ANALYST_B, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'r@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
        USERS[name] = rows("SELECT id FROM `user` WHERE username = :n", n=name)[0]["id"]
    for name, code in ((ANALYST, CUST_A), (PORTAL, CUST_A), (ANALYST_B, CUST_B)):
        sql("INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (:u, :c, UTC_TIMESTAMP())", u=USERS[name], c=code)
    logo = base64.b64encode(fake_png({"logo": True})).decode()
    sql(
        "INSERT INTO customer_portal_branding (customer_code, enabled, title, logo_base64, logo_mime_type, brand_color, updated_at) "
        "VALUES (:c, 1, 'Acme SOC', :l, 'image/png', '#1d4ed8', UTC_TIMESTAMP())",
        c=CUST_A,
        l=logo,
    )
    tags = {"high": BASE + 5001, "malware": BASE + 5002, "phishing": BASE + 5003}
    for tag, tid in tags.items():
        sql("INSERT INTO incident_management_alerttag (id, tag) VALUES (:i, :t)", i=tid, t=tag)
    SEEDED["tags"] = list(tags.values())
    specs = [
        # name, status, source, created, verdict, reason, tags
        ("Brute force <ssh>", "OPEN", "wazuh", "2026-01-05 10:00:00", None, None, ["high", "malware"]),
        ("Brute force <ssh>", "CLOSED", "wazuh", "2026-01-20 11:00:00", "FALSE_POSITIVE", "EXPECTED_ACTIVITY", ["high"]),
        ("Phishing & spoof", "IN_PROGRESS", "graylog", "2026-02-02 12:00:00", "TRUE_POSITIVE", None, ["phishing"]),
        ("Phishing & spoof", "CLOSED", "graylog", "2026-02-10 08:30:00", "FALSE_POSITIVE", None, []),
        ("Malware “dropper”", "OPEN", "velociraptor", "2026-02-15 09:00:00", None, None, ["malware"]),
        ("Lateral movement", "CLOSED", "wazuh", "2026-03-01 07:00:00", "FALSE_POSITIVE", "RULE_TOO_SENSITIVE", []),
        ("Lateral movement", "PENDING_CUSTOMER", "wazuh", "2026-03-03 07:00:00", None, None, ["high"]),
        ("Out of window", "OPEN", "wazuh", "2025-06-01 07:00:00", None, None, []),
    ]
    for i, (name, status, source, created, verdict, reason, alert_tags) in enumerate(specs):
        aid = BASE + 1 + i
        ALERT_IDS.append(aid)
        sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
            "time_closed, source, assigned_to, escalated, severity, verdict, verdict_reason) VALUES (:i, :n, :d, :s, :c, :cc, :tc, :src, "
            ":a, 0, 'High', :v, :vr)",
            i=aid,
            n=name,
            d=f"Description {i}\nwith a second line",
            s=status,
            c=created,
            cc=CUST_A,
            tc=created if status == "CLOSED" else None,
            src=source,
            a="analyst1" if i % 2 else None,
            v=verdict,
            vr=reason,
        )
        for tag in alert_tags:
            sql("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)", a=aid, t=tags[tag])
        ctx_id = BASE + 2001 + i
        sql(
            "INSERT INTO incident_management_alertcontext (id, source, context) VALUES (:i, :s, :c)",
            i=ctx_id,
            s=source,
            c=json.dumps({"rule": {"id": 5710 + i, "level": 5.5}, "user": "o'brien", "ok": True, "nothing": None}),
        )
        sql(
            "INSERT INTO incident_management_asset (id, alert_linked, asset_name, alert_context_id, agent_id, velociraptor_id, "
            "customer_code, index_name, index_id) VALUES (:i, :a, :n, :c, :ag, NULL, :cc, 'idx', :ii)",
            i=BASE + 3001 + i,
            a=aid,
            n=f"host-{i % 3}",
            c=ctx_id,
            ag=f"00{i}" if i % 2 else None,
            cc=CUST_A,
            ii=f"doc{i}",
        )
        sql(
            "INSERT INTO incident_management_ioc (id, value, type, description) VALUES (:i, :v, 'IP', :d)",
            i=BASE + 4001 + i,
            v=f"10.0.0.{i % 4}",
            d=None if i % 2 else "seen <twice>",
        )
        sql("INSERT INTO incident_management_alert_to_ioc (alert_id, ioc_id) VALUES (:a, :i)", a=aid, i=BASE + 4001 + i)
        sql(
            "INSERT INTO incident_management_comment (id, alert_id, comment, user_name, created_at) VALUES (:i, :a, :c, 'admin', :t)",
            i=BASE + 6001 + i,
            a=aid,
            c=f"Comment & note {i}",
            t=created,
        )
    cases = [
        ("[INC] Credential attack", "OPEN", "2026-01-06 09:00:00", None, [0, 1]),
        ("[rfi] Phishing review", "CLOSED", "2026-02-03 10:00:00", "2026-02-20 10:00:00", [2, 3]),
        ("Malware cleanup", "PENDING_CUSTOMER", "2025-12-20 10:00:00", None, [4]),
        ("[CONF] Firewall change", "CLOSED", "2026-03-02 10:00:00", "2026-03-04 10:00:00", [5, 6]),
    ]
    for i, (name, status, created, closed, linked) in enumerate(cases):
        cid = BASE + 1001 + i
        CASE_IDS.append(cid)
        sql(
            "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, assigned_to, "
            "customer_code, notification_invoked_number, escalated, case_closed_time) VALUES (:i, :n, :d, :c, :s, :a, :cc, 0, 0, :cl)",
            i=cid,
            n=name,
            d="" if i == 2 else f"Case description {i}",
            c=created,
            s=status,
            a=None if i == 1 else "analyst1",
            cc=CUST_A,
            cl=closed,
        )
        for k in linked:
            sql("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=cid, a=ALERT_IDS[k])
        for j in range(2):
            sql(
                "INSERT INTO incident_management_case_comment (id, case_id, comment, user_name, created_at) VALUES (:i, :c, :m, 'admin', :t)",
                i=BASE + 7001 + i * 2 + j,
                c=cid,
                m=f"Resolution note {j}",
                t=f"2026-03-0{5 - j} 12:00:00",
            )
    b_case = BASE + 1101
    CASE_IDS.append(b_case)
    sql(
        "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, customer_code, "
        "notification_invoked_number, escalated) VALUES (:i, 'Beta case', 'd', '2026-01-02 03:04:05', 'OPEN', :c, 0, 0)",
        i=b_case,
        c=CUST_B,
    )
    # SLA clocks with outcomes in the past (nothing depends on the time the report runs).
    for i, aid in enumerate(ALERT_IDS[:6]):
        opened = rows("SELECT alert_creation_time AS t FROM incident_management_alert WHERE id = :i", i=aid)[0]["t"]
        sql(
            "INSERT INTO soc_sla_alert_tracking (alert_id, severity, opened_at, ack_due_at, resolve_due_at, first_ack_at, first_ack_by, "
            "resolved_at, resolved_by, reopen_count, tracked, updated_at, business_hours, paused_seconds, pause_credit_seconds) VALUES "
            "(:a, 'High', :o, :ad, :rd, :fa, 'analyst1', :r, 'analyst1', 0, 1, :o, 0, 0, 0)",
            a=aid,
            o=opened,
            ad=opened + datetime.timedelta(minutes=30),
            rd=opened + datetime.timedelta(hours=8),
            fa=opened + datetime.timedelta(minutes=10 + 25 * (i % 3)),
            r=opened + datetime.timedelta(hours=2 + 4 * (i % 3)),
        )


def cleanup():
    for aid in ALERT_IDS:
        sql("DELETE FROM soc_sla_alert_tracking WHERE alert_id = :i", i=aid)
    for cid in CASE_IDS:
        sql("DELETE FROM soc_sla_case_tracking WHERE case_id = :i", i=cid)
        sql("DELETE FROM incident_management_case_comment WHERE case_id = :i", i=cid)
        sql("DELETE FROM incident_management_casealertlink WHERE case_id = :i", i=cid)
        sql("DELETE FROM incident_management_case WHERE id = :i", i=cid)
    for i, aid in enumerate(ALERT_IDS):
        sql("DELETE FROM incident_management_alert_to_tag WHERE alert_id = :i", i=aid)
        sql("DELETE FROM incident_management_alert_to_ioc WHERE alert_id = :i", i=aid)
        sql("DELETE FROM incident_management_comment WHERE id = :i", i=BASE + 6001 + i)
        sql("DELETE FROM incident_management_asset WHERE id = :i", i=BASE + 3001 + i)
        sql("DELETE FROM incident_management_ioc WHERE id = :i", i=BASE + 4001 + i)
        sql("DELETE FROM incident_management_alertcontext WHERE id = :i", i=BASE + 2001 + i)
        sql("DELETE FROM incident_management_alert WHERE id = :i", i=aid)
    for tid in SEEDED.get("tags", []):
        sql("DELETE FROM incident_management_alerttag WHERE id = :i", i=tid)
    sql("DELETE FROM incident_management_customer_reports WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    sql("DELETE FROM customer_portal_branding WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id = :u", u=USERS[name])
        sql("DELETE FROM user_customer_access WHERE user_id = :u", u=USERS[name])
        sql("DELETE FROM `user` WHERE id = :u", u=USERS[name])
    for c in (CUST_A, CUST_B):
        sql("DELETE FROM customers WHERE customer_code = :c", c=c)


# --- The checks ---------------------------------------------------------------------------------------

DOCX_VECTORS = os.path.join(REPO, "crates", "copilot-docx", "src", "docx_vectors.json")
BUNDLED = os.path.join(REPO, "backend", "app", "incidents", "templates")


# Inserted after the bundled template's `<w:body>`: well-formed as a template, broken once rendered —
# a raw `&` from Jinja (after it every predefined entity in content is dropped) and a conditional
# that removes a table's closing tags (the rest of the body ends up in its cell).
RECOVERY_XML = (
    '<w:p><w:r><w:t xml:space="preserve">Raw {{ "&amp;"[0]|safe }} amp, then &amp; and &lt;b&gt;</w:t></w:r></w:p>'
    '<w:tbl><w:tblPr/><w:tblGrid><w:gridCol w:w="2000"/></w:tblGrid><w:tr><w:tc><w:p><w:r>'
    '<w:t xml:space="preserve">Cell {% if False %}</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
    '<w:p><w:r><w:t xml:space="preserve">{% endif %}After &amp; more</w:t></w:r></w:p>'
)


def recovering_template(source):
    """The bundled template with `RECOVERY_XML` at the start of its body."""
    zin = zipfile.ZipFile(io.BytesIO(source))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "word/document.xml":
                data = data.replace(b"<w:body>", b"<w:body>" + RECOVERY_XML.encode(), 1)
            zout.writestr(info, data)
    return out.getvalue()


def put_templates():
    with open(os.path.join(BUNDLED, "case_report_jinja_template.docx"), "rb") as fh:
        bundled = fh.read()
    S3.put("copilot-case-report-templates", "bundled.docx", bundled)
    S3.put("copilot-case-report-templates", "recover.docx", recovering_template(bundled))
    with open(os.path.join(BUNDLED, "case_report_jinja_template.html"), "rb") as fh:
        S3.put("copilot-case-report-templates", "bundled.html", fh.read())
    with open(DOCX_VECTORS) as fh:
        vectors = json.load(fh)
    S3.put("copilot-case-report-templates", "main.docx", base64.b64decode(vectors["templates"]["main"]))
    S3.put("copilot-case-report-templates", "notword.docx", base64.b64decode(vectors["templates"]["not_word"]))
    S3.put("copilot-case-report-templates", "broken.docx", b"not a zip at all")
    S3.put(
        "copilot-case-report-templates",
        "custom.html",
        "<html><body><h1>{{ case.name }}</h1>{% for a in case.alerts %}<p>{{ a.alert_name }} {{ a.context }} {{ a.time_closed }}"
        "{{ a.tags|join(', ') }}</p>{% endfor %}{{ missing }}{{ case.case_creation_time.strftime('%d/%m') }}</body></html>".encode(),
    )
    S3.put("copilot-case-report-templates", "latin1.html", "<p>caf\xe9 {{ case.name }}</p>".encode("latin-1"))
    S3.put("copilot-case-report-templates", "syntax.html", b"<p>{% for %}</p>")
    S3.put("copilot-case-report-templates", "valueerror.html", b"<p>{{ range(1, 2, 0) }}</p>")


async def case_report_checks(p, t):
    print("\n=== case reports: DOCX and PDF ===")
    put_templates()
    case = CASE_IDS[0]
    for kind in ("docx", "pdf"):
        path = f"{R}/generate-report-{kind}"
        await p.same(f"{kind}: no token", "POST", path, json={"case_id": case, "template_name": "bundled.docx"})
        await p.same(f"{kind}: malformed JSON", "POST", path, t["admin"], content=b"{", headers={"Content-Type": "application/json"})
        await p.same(f"{kind}: empty body", "POST", path, t["admin"])
        await p.same(f"{kind}: bad fields", "POST", path, t["admin"], json={"case_id": "x", "file_name": 0})
        await p.same(f"{kind}: file_name a number", "POST", path, t["admin"], json={"case_id": "x", "file_name": 5})
        await p.same(f"{kind}: file_name a list", "POST", path, t["admin"], json={"case_id": case, "template_name": "x", "file_name": [1]})
        await p.same(f"{kind}: portal user", "POST", path, t["portal"], json={"case_id": case, "template_name": "bundled.docx"})
        await p.same(f"{kind}: no case", "POST", path, t["admin"], json={"case_id": BASE + 1999, "template_name": "bundled.docx"})
        await p.same(f"{kind}: no template", "POST", path, t["admin"], json={"case_id": case, "template_name": f"nope{SFX}"})
    docx = f"{R}/generate-report-docx"
    pdf = f"{R}/generate-report-pdf"
    await p.same("docx: bundled template", "POST", docx, t["admin"], json={"case_id": case, "template_name": "bundled.docx"}, expect=200)
    await p.same(
        "docx: bundled template, closed case",
        "POST",
        docx,
        t["analyst"],
        json={"case_id": CASE_IDS[1], "template_name": "bundled.docx", "file_name": "report"},
        expect=200,
    )
    await p.same(
        "docx: generated template, unicode name",
        "POST",
        docx,
        t["admin"],
        json={"case_id": CASE_IDS[3], "template_name": "main.docx", "file_name": "Bericht für Fall"},
    )
    await p.same("docx: no file name", "POST", docx, t["admin"], json={"case_id": case, "template_name": "bundled.docx", "file_name": None})
    await p.same(
        "docx: empty file name",
        "POST",
        docx,
        t["admin"],
        json={"case_id": case, "template_name": "bundled.docx", "file_name": ""},
    )
    await p.same("docx: not a Word file", "POST", docx, t["admin"], json={"case_id": case, "template_name": "notword.docx"})
    await p.same("docx: not a zip", "POST", docx, t["admin"], json={"case_id": case, "template_name": "broken.docx"})
    await p.same(
        "docx: a rendered body only lxml's recovering parser repairs",
        "POST",
        docx,
        t["admin"],
        json={"case_id": case, "template_name": "recover.docx"},
        expect=200,
    )
    await p.same("pdf: bundled template", "POST", pdf, t["admin"], json={"case_id": case, "template_name": "bundled.html"}, expect=200)
    await p.same(
        "pdf: custom template",
        "POST",
        pdf,
        t["analyst"],
        json={"case_id": CASE_IDS[1], "template_name": "custom.html", "file_name": "r.docx"},
    )
    await p.same("pdf: case without assets", "POST", pdf, t["admin"], json={"case_id": CASE_IDS[2], "template_name": "custom.html"})
    await p.same("pdf: file name null", "POST", pdf, t["admin"], json={"case_id": case, "template_name": "bundled.html", "file_name": None})
    await p.same("pdf: latin-1 template", "POST", pdf, t["admin"], json={"case_id": case, "template_name": "latin1.html"})
    await p.same("pdf: syntax error", "POST", pdf, t["admin"], json={"case_id": case, "template_name": "syntax.html"})
    await p.same("pdf: ValueError", "POST", pdf, t["admin"], json={"case_id": case, "template_name": "valueerror.html"})
    set_mode("fail")
    await p.same("pdf: wkhtmltopdf fails", "POST", pdf, t["admin"], json={"case_id": case, "template_name": "bundled.html"})
    set_mode("")
    # §4: Python renders another tenant's case for a scoped analyst; Rust refuses.
    body = {"case_id": CASE_IDS[0], "template_name": "bundled.docx"}
    r1 = await p.call(p.py, "POST", docx, t["analyst_b"], json=body)
    r2 = await p.call(p.rs, "POST", docx, t["analyst_b"], json=body)
    take_records()
    check(
        "docx: another tenant's case (§4: Python 200, Rust 403) [diff]",
        r1.status_code == 200
        and r2.status_code == 403
        and r2.json().get("message") == f"Access denied to case {CASE_IDS[0]} - insufficient customer permissions",
        f"python {r1.status_code} rust {r2.status_code} {r2.text[:200]}",
    )
    r1 = await p.call(p.py, "POST", pdf, t["analyst_b"], json={**body, "template_name": "bundled.html"})
    r2 = await p.call(p.rs, "POST", pdf, t["analyst_b"], json={**body, "template_name": "bundled.html"})
    take_records()
    check(
        "pdf: another tenant's case (§4: Python 200, Rust 403) [diff]",
        r1.status_code == 200 and r2.status_code == 403,
        f"{r1.status_code} {r2.status_code}",
    )


STAMP = re.compile(r"\d{8}_\d{6}")


def mask_background(body):
    if not isinstance(body, dict):
        return body
    out = dict(body)
    for key in ("report_id",):
        if key in out:
            out[key] = "<id>"
    for key in ("report_name", "download_url"):
        if isinstance(out.get(key), str):
            out[key] = STAMP.sub("<ts>", re.sub(r"/\d+/download", "/<id>/download", out[key]))
    return out


def report_rows(side, response):
    """Wait for the report the response queued, then its row and its object (masked)."""
    if response.status_code != 200:
        return None
    report_id = response.json()["report_id"]
    for _ in range(600):
        row = rows("SELECT * FROM incident_management_customer_reports WHERE id = :i", i=report_id)[0]
        if row["status"] != "processing":
            break
        time.sleep(0.1)
    obj = S3.snapshot()[0].get("incident-management-reports", {}).get(row["object_key"])
    row = {k: v for k, v in row.items() if k not in ("id", "generated_at", "file_hash", "file_size")}
    row["object_key"] = STAMP.sub("<ts>", row["object_key"])
    row["report_name"] = STAMP.sub("<ts>", row["report_name"])
    row["file_name"] = STAMP.sub("<ts>", row["file_name"])
    row["generated_by"] = [n for n, u in USERS.items() if u == row["generated_by"]]
    row["object"] = None if obj is None else {"pdf": obj[0].startswith(b"%PDF-"), "type": obj[1]}
    return row


async def customer_report_checks(p, t):
    print("\n=== customer reports: generation ===")
    path = f"{CR}/generate/background"
    window = {"customer_code": CUST_A, "date_from": "2026-01-01T00:00:00", "date_to": "2026-04-01T00:00:00"}
    await p.same("generate: no token", "POST", path, json=window)
    await p.same("generate: malformed JSON", "POST", path, t["admin"], content=b"[", headers={"Content-Type": "application/json"})
    await p.same("generate: empty body", "POST", path, t["admin"])
    await p.same("generate: missing fields", "POST", path, t["admin"], json={"customer_code": CUST_A})
    await p.same(
        "generate: bad literals and types",
        "POST",
        path,
        t["admin"],
        json={**window, "brand_theme": "x", "report_template": "y", "include_sla": "maybe", "date_to": "soon"},
    )
    await p.same("generate: reversed range", "POST", path, t["admin"], json={**window, "date_from": "2026-05-01T00:00:00"})
    await p.same("generate: equal bounds", "POST", path, t["admin"], json={**window, "date_from": window["date_to"]})
    await p.same("generate: naive and aware", "POST", path, t["admin"], json={**window, "date_to": "2026-04-01T00:00:00Z"})
    await p.same("generate: another tenant", "POST", path, t["analyst_b"], json=window)
    await p.same("generate: unknown customer", "POST", path, t["admin"], json={**window, "customer_code": f"NOPE{SFX}"})
    for name, extra, who in (
        ("full, customer theme", {}, "admin"),
        ("executive, SOCFortress theme", {"report_template": "executive", "brand_theme": "socfortress", "report_name": "exec"}, "admin"),
        ("operational", {"report_template": "operational", "visible_to_customer": True}, "analyst"),
        ("analytics with SLA", {"report_template": "analytics", "include_sla": True}, "admin"),
        ("full with SLA", {"include_sla": True, "report_name": "Quarterly Ü"}, "analyst"),
        ("customer user asks for SLA", {"include_sla": True}, "portal"),
        ("empty window", {"date_from": "2020-01-01T00:00:00", "date_to": "2020-02-01T00:00:00"}, "admin"),
        ("aware dates", {"date_from": "2026-01-01T00:00:00+02:00", "date_to": "2026-04-01T00:00:00Z"}, "admin"),
        ("aware dates with SLA", {"date_from": "2026-01-01T00:00:00Z", "date_to": "2026-04-01T00:00:00Z", "include_sla": True}, "admin"),
        ("timestamps", {"date_from": 1767225600, "date_to": 1775001600}, "admin"),
    ):
        await p.same(f"generate: {name}", "POST", path, t[who], json={**window, **extra}, mask=mask_background, after=report_rows)
    set_mode("fail")
    await p.same("generate: wkhtmltopdf fails", "POST", path, t["admin"], json=window, mask=mask_background, after=report_rows)
    set_mode("")


async def soc_report_checks(p, t):
    print("\n=== SOC operations report ===")
    q = {"date_from": "2026-01-01T00:00:00", "date_to": "2026-04-01T00:00:00", "customer_codes": CUST_A}
    await p.same("soc: no token", "GET", SOC, params=q)
    await p.same("soc: portal user", "GET", SOC, t["portal"], params=q)
    await p.same("soc: missing dates", "GET", SOC, t["admin"], params={"customer_codes": CUST_A})
    await p.same("soc: bad date", "GET", SOC, t["admin"], params={**q, "date_from": "yesterday"})
    await p.same("soc: reversed period", "GET", SOC, t["admin"], params={**q, "date_from": "2026-05-01T00:00:00"})
    await p.same("soc: admin, one customer", "GET", SOC, t["admin"], params=q, expect=200)
    await p.same("soc: analyst", "GET", SOC, t["analyst"], params=q, expect=200)
    await p.same("soc: analyst, filters", "GET", SOC, t["analyst"], params={**q, "severities": "High", "sources": "wazuh"})
    await p.same(
        "soc: hourly buckets",
        "GET",
        SOC,
        t["admin"],
        params={**q, "date_from": "2026-03-01T00:00:00", "date_to": "2026-03-02T00:00:00"},
    )
    await p.same("soc: another tenant asked", "GET", SOC, t["analyst_b"], params=q)
    set_mode("fail")
    await p.same("soc: wkhtmltopdf fails", "GET", SOC, t["admin"], params=q)
    set_mode("")


# --- The Grafana report -------------------------------------------------------------------------------

GR = "/api/reporting/generate-report"
LICENSE_ID, GRAFANA_ID, CACHE_ID = BASE + 901, BASE + 902, BASE + 903
LICENSE_KEY = f"rpt-license-{SFX}"
GRAFANA_SAVED = {}

LOGIN_PAGE = b"""<!doctype html><html><head><meta charset="utf-8"><title>Grafana</title></head>
<body class="login-page">
<form onsubmit="return false">
<input name="user" value="prefilled"><input name="password" type="password">
<button data-testid="data-testid Login button" type="submit" id="login">Log in</button>
</form>
<script>
fetch('/api/live/hold').catch(() => {});
document.getElementById('login').addEventListener('click', async () => {
  const body = JSON.stringify({
    user: document.querySelector('input[name="user"]').value,
    password: document.querySelector('input[name="password"]').value,
  });
  const r = await fetch('/login', {method: 'POST', headers: {'content-type': 'application/json'}, body});
  if (r.ok) { window.location.href = '/'; }
});
</script></body></html>"""
HOME_PAGE = b"""<!doctype html><html><head><meta charset="utf-8"><title>Home</title></head>
<body class="app-grafana no-overlay-scrollbar"><p>home</p></body></html>"""
SOLO_PAGE = b"""<!doctype html><html><head><meta charset="utf-8"><title>Panel</title>
<style>body{margin:0;background:#123}div{width:100%;height:100vh;background:linear-gradient(90deg,#f00,#00f)}</style>
</head><body class="app-grafana"><div></div>
<script>fetch('/api/ds/query', {method: 'POST', body: '{"queries":[]}'});</script></body></html>"""


class GrafanaStandIn:
    """Grafana as the browser sees it: the login page (a request held 2.5 s, so that the page
    is not idle before the click), the login, `/`, the `d-solo` pages; every request recorded."""

    def __init__(self):
        self.mode = "ok"
        self.requests = []
        self.lock = threading.Lock()
        self.server = None

    def start(self):
        stand_in = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def record(self, body):
                with stand_in.lock:
                    stand_in.requests.append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "headers": [[k, v] for k, v in self.headers.items()],
                            "body": body.decode("latin-1"),
                        },
                    )

            def reply(self, code, body, ctype="text/html; charset=UTF-8", extra=()):
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    for k, v in extra:
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):
                self.record(b"")
                path = self.path.split("?")[0]
                if path == "/login":
                    self.reply(200, LOGIN_PAGE)
                elif path == "/api/live/hold":
                    time.sleep(2.5)
                    self.reply(200, b"{}", "application/json")
                elif path == "/":
                    self.reply(200, HOME_PAGE)
                elif path.startswith("/d-solo/"):
                    self.reply(200, SOLO_PAGE)
                else:
                    self.reply(404, b"not found", "text/plain")

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                self.record(body)
                if self.path == "/login" and stand_in.mode == "deny":
                    self.reply(401, b'{"message":"Invalid username or password"}', "application/json")
                elif self.path == "/login":
                    self.reply(
                        200,
                        b'{"message":"Logged in","redirectUrl":"/"}',
                        "application/json",
                        [("Set-Cookie", "grafana_session=parity; Path=/; HttpOnly")],
                    )
                else:
                    self.reply(200, b'{"results":{}}', "application/json")

        for attempt in range(50):
            try:
                self.server = http.server.ThreadingHTTPServer(("127.0.0.1", GRAFANA_PORT), Handler)
                break
            except OSError:
                if attempt == 49:
                    raise
                time.sleep(0.1)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


GRAFANA = GrafanaStandIn()
BACKEND_DIR = os.path.join(REPO, "backend")


def clear_report_files():
    """Python's `report.html` / `report.pdf` in its working directory."""
    for name in ("report.html", "report.pdf"):
        for d in (os.getcwd(), BACKEND_DIR):
            try:
                os.remove(os.path.join(d, name))
            except FileNotFoundError:
                pass


def grafana_seed(url=None, user="admin", password="pässword", license_state="enabled"):
    """The `Grafana` connector row (none when `url` is None) and the licence (absent, or cached
    as enabled or disabled), the deployment's own rows put aside first."""
    if not GRAFANA_SAVED:
        GRAFANA_SAVED["connectors"] = rows("SELECT * FROM connectors WHERE connector_name = 'Grafana'")
        GRAFANA_SAVED["license"] = rows("SELECT * FROM license")
        sql("DELETE FROM connectors WHERE connector_name = 'Grafana'")
        sql("DELETE FROM license")
    sql("DELETE FROM connectors WHERE id = :i", i=GRAFANA_ID)
    sql("DELETE FROM license_cache WHERE id = :i", i=CACHE_ID)
    sql("DELETE FROM license WHERE id = :i", i=LICENSE_ID)
    if url is not None:
        sql(
            "INSERT INTO connectors (id, connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
            "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
            "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
            "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (:i, "
            "'Grafana', '3', :u, UTC_TIMESTAMP(), :user, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
            i=GRAFANA_ID,
            u=url,
            user=user,
            pw=password,
        )
    if license_state is not None:
        sql(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) "
            "VALUES (:i, :k, 'Parity', 'p@parity.test', 'Parity Co')",
            i=LICENSE_ID,
            k=LICENSE_KEY,
        )
        sql(
            "INSERT INTO license_cache (id, license_key, feature_name, is_enabled, cached_at, expires_at, license_data) VALUES "
            "(:i, :k, 'REPORTING', :e, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 HOUR, '{}')",
            i=CACHE_ID,
            k=LICENSE_KEY,
            e=1 if license_state == "enabled" else 0,
        )


def grafana_cleanup():
    sql("DELETE FROM connectors WHERE id = :i", i=GRAFANA_ID)
    sql("DELETE FROM license_cache WHERE id = :i", i=CACHE_ID)
    sql("DELETE FROM license WHERE id = :i", i=LICENSE_ID)
    for row in GRAFANA_SAVED.get("connectors", []):
        sql(f"INSERT INTO connectors ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for row in GRAFANA_SAVED.get("license", []):
        sql(f"INSERT INTO license ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    GRAFANA_SAVED.clear()
    clear_report_files()


PNG_DATA = re.compile(r"data:image/png;base64,([A-Za-z0-9+/=]+)")
WINDOW = re.compile(r"from=(\d+)&to=(\d+)")
PROFILE = re.compile(r"^--user-data-dir=.*/playwright_chromiumdev_profile-[A-Za-z0-9]{6}$")


def png_size(match):
    try:
        data = base64.b64decode(match.group(1), validate=True)
    except ValueError:
        return match.group(0)
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 24:
        return match.group(0)
    width, height = struct.unpack(">II", data[16:24])
    return f"<png {width}x{height}>"


def mask_window(text_):
    return WINDOW.sub(lambda m: f"from=<to - {int(m.group(2)) - int(m.group(1))}>&to=<now>", text_)


def grafana_requests(records):
    return [
        {
            "method": r["method"],
            "path": mask_window(r["path"]),
            "headers": [[k, mask_window(v)] for k, v in r["headers"]],
            "body": r["body"],
        }
        for r in records
    ]


def browser_launches(records, side):
    out = []
    for r in records:
        argv = ["--user-data-dir=<profile>" if PROFILE.match(a) else a for a in r["argv"]]
        page = r["cwd_html"] if side == "p" else (r["tmp_html"][0] if r["tmp_html"] else None)
        out.append({"argv": argv, "page": PNG_DATA.sub(png_size, page) if page is not None else None})
    return out


def pdf_summary(b64):
    with tempfile.NamedTemporaryFile(suffix=".pdf", dir=WORK, delete=False) as fh:
        fh.write(base64.b64decode(b64))
        name = fh.name
    try:
        info = subprocess.run(["pdfinfo", name], capture_output=True, text=True).stdout
        pages = next((line.split()[-1] for line in info.splitlines() if line.startswith("Pages:")), None)
        words = subprocess.run(["pdftotext", name, "-"], capture_output=True, text=True).stdout.split()
        return {"pdf": open(name, "rb").read(5) == b"%PDF-", "pages": pages, "text": words}
    finally:
        os.remove(name)


async def grafana_same(p, name, tok, body=None, raw=None, expect=None):
    GRAFANA.take()
    take_browser_records()
    clear_report_files()
    if raw is not None:
        kw = {"content": raw, "headers": {"content-type": "application/json"}}
    elif body is not None:
        kw = {"json": body}
    else:
        kw = {}
    r1 = await p.call(p.py, "POST", GR, tok, **kw)
    g1, l1 = grafana_requests(GRAFANA.take()), browser_launches(take_browser_records(), "p")
    clear_report_files()
    r2 = await p.call(p.rs, "POST", GR, tok, **kw)
    g2, l2 = grafana_requests(GRAFANA.take()), browser_launches(take_browser_records(), "r")
    b1, b2 = body_of(r1), body_of(r2)
    if r1.status_code == 200 and isinstance(b1, dict) and isinstance(b2, dict):
        b1 = {**b1, "base64_result": pdf_summary(b1["base64_result"])}
        b2 = {**b2, "base64_result": pdf_summary(b2["base64_result"])}
    ok = r1.status_code == r2.status_code and b1 == b2 and (b1 is not None or r1.content == r2.content)
    detail = f"python {r1.status_code} {str(b1 if b1 is not None else r1.content[:200])[:800]}\n        rust   {r2.status_code} {str(b2 if b2 is not None else r2.content[:200])[:800]}"
    if g1 != g2:
        ok = False
        detail += f"\n        grafana python {len(g1)} requests, rust {len(g2)}"
        for a, b in zip(g1, g2):
            if a != b:
                detail += f"\n        python {a}\n        rust   {b}"
                break
        if len(g1) != len(g2):
            detail += f"\n        python {[x['method'] + ' ' + x['path'] for x in g1]}\n        rust   {[x['method'] + ' ' + x['path'] for x in g2]}"
    if l1 != l2:
        ok = False
        detail += f"\n        browser launches python {len(l1)} rust {len(l2)}"
        for a, b in zip(l1, l2):
            if a["argv"] != b["argv"]:
                detail += f"\n        argv python {a['argv']}\n        argv rust   {b['argv']}"
            if a["page"] != b["page"]:
                x, y = a["page"] or "", b["page"] or ""
                at = next((i for i, (c, d) in enumerate(zip(x, y)) if c != d), min(len(x), len(y)))
                detail += f"\n        page differs at {at}\n        python …{x[max(0, at - 200):at + 300]!r}\n        rust   …{y[max(0, at - 200):at + 300]!r}"
    if r1.status_code == 200 and (len(l1) != 2 or l1[1]["page"] is None or not g1):
        ok = False
        detail += f"\n        not recorded: {len(l1)} launches, a page {bool(l1 and l1[-1]['page'])}, {len(g1)} requests"
    if expect and r1.status_code != expect:
        ok = False
        detail += f"\n        expected {expect}"
    check(f"{name} [{r1.status_code}]", ok, detail)
    return r1, r2, g1, l1


def report_panel(panel_id, width=400, height=250, theme="light", title="HUNTRESS - _SUMMARY", uid="ab9bab2c"):
    panel = {
        "panel_id": panel_id,
        "org_id": 1,
        "dashboard_title": title,
        "dashboard_uid": uid,
        "panel_width": width,
        "panel_height": height,
    }
    if theme is not None:
        panel["theme"] = theme
    return panel


async def grafana_report_checks(p, t):
    print("\n=== Grafana panel report ===")
    grafana_url = f"http://127.0.0.1:{GRAFANA_PORT}"
    body = {
        "company_name": "Acme <SOC> & Co",
        "timerange_text": "Last 7 days",
        "logo_base64": "data:image/png;base64,iVBORw0KGgo=",
        "timerange": "7d",
        "rows": [
            {"id": 1710437961108, "panels": [report_panel(5), report_panel(5, 300, 200), report_panel(7, 0, 200)]},
            {"id": 1710437961109, "panels": [report_panel(9, theme=None, title="SAP - USERS", uid="a1891b09")]},
            {"id": 1710437961108, "panels": [report_panel(11, 320, 180)]},
        ],
    }
    one = {**body, "rows": [{"id": 1, "panels": [report_panel(5)]}]}
    grafana_seed(grafana_url, license_state=None)
    GRAFANA.mode = "ok"
    await grafana_same(p, "grafana: no token", None, body)
    await grafana_same(p, "grafana: portal user", t["portal"], body)
    await grafana_same(p, "grafana: malformed JSON", t["admin"], raw=b'{"rows": ')
    await grafana_same(p, "grafana: missing fields", t["admin"], {"company_name": "x", "rows": [{"id": "a", "panels": [{}]}]})
    await grafana_same(p, "grafana: rows not a list", t["admin"], {**body, "rows": {"id": 1}})
    await grafana_same(p, "grafana: no licence", t["admin"], body)
    grafana_seed(grafana_url, license_state="disabled")
    await grafana_same(p, "grafana: licence without REPORTING", t["analyst"], body)
    grafana_seed(grafana_url)
    await grafana_same(p, "grafana: timerange not an int", t["admin"], {**body, "timerange": "xd"})
    await grafana_same(p, "grafana: empty timerange", t["admin"], {**body, "timerange": ""})
    await grafana_same(p, "grafana: unit not m, h or d", t["admin"], {**one, "timerange": "7w"})
    await grafana_same(p, "grafana: a timedelta too large", t["admin"], {**one, "timerange": "99999999999d"})
    grafana_seed(None)
    await grafana_same(p, "grafana: no Grafana connector", t["admin"], one)
    grafana_seed(f"http://127.0.0.1:{CLOSED_PORT}")
    await grafana_same(p, "grafana: Grafana unreachable", t["admin"], one)
    grafana_seed(grafana_url)
    GRAFANA.mode = "deny"
    _, _, seen, launches = await grafana_same(p, "grafana: the login refused", t["admin"], one)
    posted = [x["body"] for x in seen if x["method"] == "POST" and x["path"] == "/login"]
    check(
        "grafana: the refused login was filled and sent, in one browser",
        posted == ['{"user":"admin","password":"pässword"}'.encode().decode("latin-1")] and len(launches) == 1,
        f"{posted} {len(launches)}",
    )
    GRAFANA.mode = "ok"
    await grafana_same(p, "grafana: three rows, five panels", t["admin"], body, expect=200)
    await grafana_same(p, "grafana: analyst, hours", t["analyst"], {**one, "timerange": " +1_2h"}, expect=200)
    grafana_seed(grafana_url, user=None, password="")
    await grafana_same(p, "grafana: no rows, no user name, empty password", t["admin"], {**body, "rows": []}, expect=200)
    grafana_seed(f"127.0.0.1:{GRAFANA_PORT}")
    await grafana_same(p, "grafana: a URL without a scheme", t["admin"], {**one, "timerange": "30m"}, expect=200)


S3 = S3StandIn(S3_USER, S3_SECRET)


async def main():
    server = S3.serve(S3_PORT)
    GRAFANA.start()
    patch_python()
    seed()
    proc = start_rust(RS_PORT)
    p = Pair()
    t = {
        "admin": token(ADMIN, ["admin"]),
        "analyst": token(ANALYST, ["analyst"]),
        "portal": token(PORTAL, ["customer_user"], customer_codes=[CUST_A]),
        "analyst_b": token(ANALYST_B, ["analyst"]),
    }
    try:
        sections = os.environ.get("REPORTS_PARITY_SECTIONS", "case,customer,soc,grafana").split(",")
        if "case" in sections:
            await case_report_checks(p, t)
        if "customer" in sections:
            await customer_report_checks(p, t)
        if "soc" in sections:
            await soc_report_checks(p, t)
        if "grafana" in sections:
            await grafana_report_checks(p, t)
    finally:
        await p.close()
        grafana_cleanup()
        GRAFANA.stop()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        server.shutdown()
        shutil.rmtree(WORK, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
