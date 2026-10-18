"""Parity of the Rust File Analysis module (`crates/copilot-file-analysis`) with this backend — NOT
collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI router (in-process, behind copilot.py's `GZipMiddleware`) and the Rust instances
this suite starts (no legacy backend, connector cache off) answer the same requests on one
database and one MinIO. Every tool is a local stand-in that records each request — method,
target, **every header** and the body bytes — and both backends' requests are compared one by
one:

* MinIO (`rust_parity_objectstore_e2e.S3StandIn`: every SigV4 signature verified, the canonical
  requests compared), holding the `file-analysis` bucket — the state store both backends read
  and write: a job, result, summary or preview one backend wrote is read back by the other;
* the inspector (`POST /insp/inspect`, httpx's multipart: the job's JSON and the sample), CAPE's
  REST API (`/apiv2/…`: status, the sha256 search, the submit, the polls, the report and the
  screenshot zip) and VirusTotal (`/api/v3/…`: the hash lookup, the deep intel, the upload and
  the analysis polls; httpx's public URL rewritten here, `COPILOT_VIRUSTOTAL_URL` for Rust) — one
  HTTP stand-in;
* Velociraptor's gRPC API (`rust_parity_agents_e2e.VeloStandIn`, grpcio over mutual TLS: each
  `VQLCollectorArgs` byte for byte and its deadline);
* wkhtmltopdf — a recording script both backends run (pdfkit's configuration patched here,
  `COPILOT_WKHTMLTOPDF` for Rust): its argv and the HTML it was handed, compared (the temporary
  paths and the report's generation time masked), never the PDF bytes of a real renderer.

Python runs a job inside the request (FastAPI's background task, completed before the ASGI
transport answers); Rust runs it on a task of its own after answering: the suite waits for the
job the answer names to settle in MinIO (and for every stand-in to fall quiet) before it compares.
Job ids (`uuid4().hex`) and the ISO timestamps are masked, numbered by first appearance on each
side. The `/history` reads are concurrent on both sides (Python's order comes from a `set`), so
their MinIO requests are compared as sorted lists. Deliberate differences are asserted as such
(RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_file_analysis_e2e.py scripts/rust-parity.sh

Ports (all overridable, 6600-6699 by default): FILE_ANALYSIS_PARITY_RUST_PORT (Rust with the CAPE
sandbox), FILE_ANALYSIS_PARITY_RUST_NONE_PORT (Rust with `SANDBOX_BACKEND=none` and no
wkhtmltopdf), FILE_ANALYSIS_STUB_PORT, FILE_ANALYSIS_S3_STUB_PORT, FILE_ANALYSIS_VELO_STUB_PORT.
"""

import asyncio
import base64
import datetime
import hashlib
import io
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
import zipfile
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
# Read at import by the Velociraptor client; rust-parity.sh hands the Rust binary the same value.
os.environ.setdefault("VELOCIRAPTOR_QUERY_TIMEOUT", "5")

RS_PORT = int(os.environ.get("FILE_ANALYSIS_PARITY_RUST_PORT", "6600"))
RS_NONE_PORT = int(os.environ.get("FILE_ANALYSIS_PARITY_RUST_NONE_PORT", "6604"))
STUB_PORT = int(os.environ.get("FILE_ANALYSIS_STUB_PORT", "6601"))
S3_PORT = int(os.environ.get("FILE_ANALYSIS_S3_STUB_PORT", "6602"))
VELO_PORT = int(os.environ.get("FILE_ANALYSIS_VELO_STUB_PORT", "6603"))
CAPE_TOKEN = "parity-cape-token"
VT_KEY = "parity-vt-key"

#: Read at import by the module (both backends get the same values).
SETTINGS = {
    "INSPECTOR_URL": f"http://127.0.0.1:{STUB_PORT}/insp",
    "INSPECTOR_HTTP_TIMEOUT": "10",
    "SANDBOX_BACKEND": "remote",
    "CAPE_API_URL": f"http://127.0.0.1:{STUB_PORT}/apiv2/",
    "CAPE_API_TOKEN": CAPE_TOKEN,
    "CAPE_POLL_INTERVAL": "1",
    "CAPE_POLL_TIMEOUT": "2",
    "CAPE_HTTP_TIMEOUT": "10",
    "ENRICHMENT_VT_POLL": "1",
    "ENRICHMENT_VT_MAX_WAIT": "2",
    "FILE_ANALYSIS_MINIO_RETRIES": "2",
    "FILE_ANALYSIS_MINIO_BACKOFF": "0.1",
    "FILE_ANALYSIS_COLLECT_TIMEOUT": "2",
    "FILE_ANALYSIS_ENUM_TIMEOUT": "2",
}
os.environ.update(SETTINGS)

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from miniopy_async import Minio  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_parity_agents_e2e as agents_parity  # noqa: E402
import rust_parity_objectstore_e2e as objstore  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
S3_USER, S3_SECRET = "minio-file-analysis", "minio-file-analysis-secret"
BUCKET = "file-analysis"
CUST_A, CUST_B = f"FaA{SFX}", f"FaB{SFX}"
ADMIN, ANALYST, PORTAL = f"fa_admin{SFX}", f"fa_analyst{SFX}", f"fa_portal{SFX}"
USERS = (ADMIN, ANALYST, PORTAL)
OUR_CONNECTORS = ("Velociraptor", "VirusTotal")
SAVED_CONNECTORS = []
#: Explicit agent row ids (7 digits, this suite's range).
AGENT_ID_BASE = 6_660_000
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


# --- The HTTP stand-in: inspector, CAPE, VirusTotal --------------------------------------------


class Recorder:
    """(method, target, every header — names lower-cased and sorted —, body)."""

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

    def count(self):
        with self.lock:
            return len(self.requests)


def zip_of(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def js(value, status=200, ctype="application/json"):
    return status, ctype, json.dumps(value).encode()


NOISE = "antivm_generic_disk"
LOW = "packer_entropy"


class Upstream:
    """The inspector, CAPE and VirusTotal, each answering per its mode."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.inspector = "ok"
        self.inspector_answer = None
        self.busy = 0
        self.cape = "ok"
        self.cape_report = None
        self.vt = {}
        self.vt_mode = "ok"
        self.vt_after_upload = None
        self.analysis = "completed"

    # inspector
    def inspect(self, body):
        if self.busy > 0:
            self.busy -= 1
            return 429, "application/json", b'{"detail": "busy"}'
        m = self.inspector
        if m == "ok":
            return js(self.inspector_answer)
        if m == "error":
            return 500, "text/plain", b"inspector crashed"
        if m == "html":
            return 200, "text/html", b"<html>not json</html>"
        if m == "list":
            return js([1, 2])
        if m == "bad-preview":
            return js({**self.inspector_answer, "previews_b64": {"p.png": "abc"}})
        if m == "previews-list":
            return js({**self.inspector_answer, "previews_b64": ["x"]})
        if m == "bad-hint":
            return js({**self.inspector_answer, "verdict_hint": "terrible"})
        raise AssertionError(m)

    # CAPE
    def cape_api(self, method, path):
        m = self.cape
        if path == "/apiv2/cuckoo/status/":
            if m == "down":
                return 503, "text/plain", b"maintenance"
            if m == "unauthorized":
                return 401, "application/json", b'{"detail": "bad token"}'
            return js({"error": False, "data": {"version": "2.4", "tasks": {"reported": 7}}})
        if path.startswith("/apiv2/tasks/search/sha256/"):
            if m == "reuse":
                return js({"error": False, "data": [{"id": 5, "status": "failed_analysis"}, {"id": 77, "status": "reported"}]})
            return js({"error": False, "data": [{"id": 5, "status": "failed_analysis"}, "x"]})
        if path == "/apiv2/tasks/create/file/":
            if m == "no-task":
                return js({"error": True, "error_value": "Linux binaries analysis isn't enabled", "data": {}})
            return js({"error": False, "data": {"task_ids": [77]}})
        if path == "/apiv2/tasks/view/77/":
            if m == "failed":
                return js({"data": {"status": "failed_analysis"}})
            if m == "pending":
                return js({"data": {"status": "running"}})
            return js({"data": {"status": "reported"}})
        if path == "/apiv2/tasks/get/report/77/json/" or path == "/apiv2/tasks/get/report/9/json/":
            if m == "report-error":
                return 500, "text/plain", b"processing"
            if m == "report-nan":
                return 200, "application/json", b'{"malscore": NaN, "info": {"id": 9}}'
            return js(self.cape_report)
        if path in ("/apiv2/tasks/get/screenshot/77/", "/apiv2/tasks/get/screenshot/9/"):
            if m == "no-shots":
                return 404, "application/json", b'{"error": true}'
            return 200, "application/zip", zip_of([("shots/0002.jpg", b"jpeg-two"), ("shots/0001.jpg", b"jpeg-one"), ("README.txt", b"x")])
        return 404, "application/json", b'{"error": true, "error_value": "no such task"}'

    # VirusTotal
    def vt_api(self, method, path):
        m = self.vt_mode
        if path.startswith("/api/v3/files/"):
            rest = path[len("/api/v3/files/") :]
            behaviour = rest.endswith("/behaviour_summary")
            digest = rest[: -len("/behaviour_summary")] if behaviour else rest
            if m == "error":
                return 500, "text/plain", b"vt down"
            report = self.vt.get(digest)
            if report is None:
                return js({"error": {"code": "NotFoundError", "message": f'File "{digest}" not found'}}, status=404)
            if behaviour:
                if m == "no-behaviour":
                    return js({"error": {"code": "NotFoundError"}}, status=404)
                return js(
                    {
                        "data": {
                            "tags": ["DETECT_DEBUG_ENVIRONMENT"],
                            "mitre_attack_techniques": [{"id": "T1055", "signature_description": "inject"}],
                        },
                    },
                )
            return js({"data": {"id": digest, "type": "file", "attributes": report, "links": {"self": "x"}}})
        if path == "/api/v3/files" and method == "POST":
            if m == "upload-error":
                return 413, "text/plain", b"too large"
            if self.vt_after_upload:
                digest, report = self.vt_after_upload
                self.vt[digest] = report
            return js({"data": {"type": "analysis", "id": "an-parity"}})
        if path == "/api/v3/analyses/an-parity":
            return js(
                {
                    "data": {
                        "id": "an-parity",
                        "type": "analysis",
                        "attributes": {"date": 1700000000, "status": self.analysis, "stats": {"malicious": 3}},
                    },
                },
            )
        return js({"error": {"code": "NotFoundError"}}, status=404)

    def __call__(self, method, target, headers, body):
        path = target.split("?")[0]
        if path == "/insp/inspect":
            return self.inspect(body)
        if path.startswith("/apiv2/"):
            return self.cape_api(method, path)
        if path.startswith("/api/v3/"):
            return self.vt_api(method, path)
        return 404, "text/plain", b"no stand-in"


UPSTREAM = Upstream()
UPSTREAM_REC = Recorder()


def start_http_stub(port, answer, recorder):
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


S3 = objstore.S3StandIn(S3_USER, S3_SECRET)


# --- Velociraptor -------------------------------------------------------------------------------


class Velo:
    """`VeloStandIn`'s answers, per `mode`."""

    def __init__(self):
        self.mode = "ok"

    def __call__(self, stand_in, vql, org):
        m = self.mode
        if vql.startswith("SELECT client_id, last_seen_at FROM clients(search="):
            if "host:fa-a-" in vql:
                return [json.dumps([{"client_id": "C.faaaa", "last_seen_at": 4102444800000000}])], None
            if "host:fa-b-" in vql:
                return [json.dumps([{"client_id": "C.fabbb", "last_seen_at": 4102444800000000}])], None
            return ["[]"], None
        if vql.startswith("SELECT client_id, last_seen_at FROM clients()"):
            rows = [{"client_id": "C.faaaa", "last_seen_at": 4102444800000000}, {"client_id": "C.fabbb", "last_seen_at": 1}]
            return [json.dumps(rows)], None
        if vql.startswith("SELECT os_info.system AS os FROM clients()"):
            return [json.dumps([{"os": "windows" if m == "windows" else "linux"}])], None
        if vql.startswith("SELECT collect_client("):
            if m == "no-flow":
                return [json.dumps([{"Flow": {}}])], None
            flow = "F.GONE" if "/gone" in vql else "F.PARITY"
            return [json.dumps([{"Flow": {"flow_id": flow}}])], None
        if vql.startswith("SELECT * FROM uploads("):
            if "F.GONE" in vql:
                return ["[]"], None
            row = {
                "vfs_path": "/clients/C.faaaa/collections/F.PARITY/uploads/auto/etc/hostname",
                "client_path": "/etc/hostname",
                "file_size": 13,
            }
            if m == "file-store":
                row = {"file_store": ["/x/y/z.bin"], "Name": "C:\\Users\\x\\Desktop\\invoice.docm"}
            return [json.dumps([row])], None
        if vql.startswith("SELECT read_file("):
            if m == "empty-read":
                return [json.dumps([{"Data": ""}])], None
            return [json.dumps([{"Data": "parity-host\u00e9\n"}])], None
        if vql.startswith("SELECT * FROM source("):
            rows = [
                {"OSPath": "/etc/hostname", "Size": 13, "Hash": {"SHA256": "ab" * 32}},
                {"_FullPath": "C:\\x\\y.txt", "Size": "7"},
                {"Path": ""},
                {"Path": 5},
            ]
            return [json.dumps(rows)], None
        return ["[]"], None


VELO = Velo()
VELO_STAND_IN = None


def velo_take():
    if VELO_STAND_IN is None:
        return []
    out = []
    for r in VELO_STAND_IN.take():
        raw = bytes.fromhex(r["request"])
        args = agents_parity.api_pb2.VQLCollectorArgs.FromString(raw)
        out.append((args.org_id, args.max_wait, [(q.Name, q.VQL) for q in args.Query], r["deadline"], base64.b64encode(raw).decode()))
    return out


def velo_count():
    if VELO_STAND_IN is None:
        return 0
    with VELO_STAND_IN.lock:
        return len(VELO_STAND_IN.captured)


# --- wkhtmltopdf ----------------------------------------------------------------------------------

PDF_DIR = tempfile.mkdtemp(prefix="fa-parity-pdf-")
WRAPPER = os.path.join(PDF_DIR, "wkhtmltopdf")
RECORD = os.path.join(PDF_DIR, "record.jsonl")
MODE_FILE = os.path.join(PDF_DIR, "mode")
WRAPPER_SOURCE = f"""#!{sys.executable}
import json, sys
argv = sys.argv[1:]
mode = open({MODE_FILE!r}).read().strip()
html = open(argv[-2], encoding="utf-8").read() if len(argv) >= 2 else ""
with open({RECORD!r}, "a") as f:
    f.write(json.dumps({{"argv": argv, "html": html}}) + "\\n")
out = argv[-1]
if mode == "ok":
    open(out, "wb").write(b"%PDF-1.4\\n%parity report\\n" + b"x" * 400)
elif mode == "big":
    open(out, "wb").write(b"%PDF-1.4\\n" + bytes(range(256)) * 300)
elif mode == "error":
    sys.stderr.write("Loading pages\\nError: Failed loading page file:///x\\n")
    sys.exit(1)
elif mode == "done":
    sys.stderr.write("Loading pages\\nDone\\n")
    open(out, "wb").write(b"%PDF-1.4 done")
    sys.exit(1)
elif mode == "empty":
    open(out, "wb").write(b"")
elif mode == "bad-utf8":
    open(out, "wb").write(b"\\xff\\xfePDF")
elif mode == "no-file":
    pass
"""


def pdf_mode(m):
    with open(MODE_FILE, "w") as f:
        f.write(m)


def pdf_take():
    if not os.path.exists(RECORD):
        return []
    with open(RECORD) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    os.remove(RECORD)
    return rows


def pdf_count():
    if not os.path.exists(RECORD):
        return 0
    with open(RECORD) as f:
        return sum(1 for _ in f)


PDF_PATHS = {"binary": WRAPPER}


# --- Seed --------------------------------------------------------------------------------------

AGENTS = [
    # (row offset, hostname, velociraptor id, customer)
    (0, f"fa-a-{SFX}", "C.faaaa", CUST_A),
    (1, f"fa-b-{SFX}", "C.fabbb", CUST_B),
    (2, f"fa-orphan-{SFX}", "C.fa000-o1", None),
    (3, f"fa-nov-{SFX}", None, CUST_A),
]


def set_connector(name, url, api_key=None):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) "
        "VALUES (:n, '3', :u, UTC_TIMESTAMP(), NULL, NULL, :key, 'parity', 'parity', 1, 1, 0, 1, 0, 1, 0, NULL, 1)",
        n=name,
        u=url,
        key=api_key,
    )


def seed():
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(names=list(OUR_CONNECTORS)))
    SAVED_CONNECTORS.extend(dict(r._mapping) for r in rows)
    for code in (CUST_A, CUST_B):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())", c=code)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name in (ANALYST, PORTAL):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
            "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )
    for offset, hostname, velo_id, customer in AGENTS:
        sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
            "velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, velociraptor_agent_version, "
            "customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) VALUES (:id, :a, '10.0.0.1', 'Ubuntu', :h, "
            "'grp', 0, '2026-10-15 08:00:00', :v, NULL, 'Wazuh v4.9.0', 'active', NULL, :c, 0, NULL, 0)",
            id=AGENT_ID_BASE + offset,
            a=f"fa{SFX}{offset}",
            h=hostname,
            v=velo_id,
            c=customer,
        )
    set_connector("VirusTotal", "https://www.virustotal.com", api_key=VT_KEY)


def cleanup():
    ids = [AGENT_ID_BASE + a[0] for a in AGENTS]
    with sync_engine.begin() as conn:
        conn.execute(text("DELETE FROM agents WHERE id IN :ids").bindparams(ids=ids))
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for code in (CUST_A, CUST_B):
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)


# --- The two backends -----------------------------------------------------------------------------


def patch_python():
    """MinIO, VirusTotal's public URL and wkhtmltopdf, as the Rust instances are configured."""
    import pdfkit

    from app.file_analysis.services import state_store

    async def create_session():
        return Minio(f"127.0.0.1:{S3_PORT}", access_key=S3_USER, secret_key=S3_SECRET, secure=False)

    state_store.create_session = create_session

    original_build = httpx.AsyncClient.build_request
    public = "https://www.virustotal.com"

    def build_request(self, method, url, *args, **kwargs):
        text_url = str(url)
        if text_url.startswith(public):
            url = f"http://127.0.0.1:{STUB_PORT}" + text_url[len(public) :]
        return original_build(self, method, url, *args, **kwargs)

    httpx.AsyncClient.build_request = build_request
    original_configuration = pdfkit.configuration

    def configuration(wkhtmltopdf=""):
        if PDF_PATHS["binary"] is None:
            raise OSError(f"No wkhtmltopdf executable found: {wkhtmltopdf!r}")
        return original_configuration(wkhtmltopdf=PDF_PATHS["binary"])

    pdfkit.configuration = configuration


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import file_analysis

    api = APIRouter(prefix="/api")
    api.include_router(file_analysis.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port, sandbox="remote", wkhtmltopdf=WRAPPER):
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
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        "MINIO_ROOT_USER": S3_USER,
        "MINIO_ROOT_PASSWORD": S3_SECRET,
        "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{S3_PORT}",
        "COPILOT_VIRUSTOTAL_URL": f"http://127.0.0.1:{STUB_PORT}/api/v3",
        "COPILOT_WKHTMLTOPDF": wkhtmltopdf,
        **SETTINGS,
        "SANDBOX_BACKEND": sandbox,
    }
    for name in ("VELOCIRAPTOR_QUERY_TIMEOUT", "VELOCIRAPTOR_FLOW_TIMEOUT", "TMPDIR"):
        if name in os.environ:
            env[name] = os.environ[name]
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


# --- Masking ---------------------------------------------------------------------------------------

JOB_RE = re.compile(r"\b[0-9a-f]{32}\b")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00")
GENERATED_RE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")
TMP_RE = re.compile(r"/[^\s'\"]*?tmp[a-z0-9_]{8}\.(html|pdf)")
BOUNDARY_RE = re.compile(r"boundary=([0-9a-f]{32})")


class Masker:
    """Job ids numbered by first appearance on one side, ISO timestamps masked."""

    def __init__(self):
        self.ids = {}

    def __call__(self, value):
        if isinstance(value, bytes):
            return self(value.decode("utf-8", "surrogateescape")).encode("utf-8", "surrogateescape")

        def job(mo):
            v = mo.group(0)
            if v not in self.ids:
                self.ids[v] = f"<job{len(self.ids)}>"
            return self.ids[v]

        return TMP_RE.sub(r"<tmp>.\1", TS_RE.sub("<ts>", JOB_RE.sub(job, value)))

    def subst(self):
        return list(self.ids.items())


def masked_upstream(records, mask):
    out = []
    for method, target, headers, body in records:
        hdrs = dict(headers)
        b = BOUNDARY_RE.search(hdrs.get("content-type", ""))
        if b:
            body = body.replace(b.group(1).encode(), b"<boundary>")
            hdrs["content-type"] = hdrs["content-type"].replace(b.group(1), "<boundary>")
        out.append((method, mask(target), sorted(hdrs.items()), mask(body)))
    return out


def bucket_state(snap, mask):
    buckets, _ = snap
    out = {}
    for key, (data, ctype, _etag) in sorted(buckets.get(BUCKET, {}).items()):
        k = mask(key)
        if key.endswith(".json"):
            try:
                out[k] = (ctype, mask(data.decode("utf-8")))
            except UnicodeDecodeError:
                out[k] = (ctype, data)
        else:
            out[k] = (ctype, hashlib.sha256(data).hexdigest())
    return out


def json_puts(records):
    """A JSON object's PUT names its own bytes (job ids, timestamps): its payload hash and length
    are compared through the bucket's masked end state instead."""
    out = []
    for method, path, query, headers, signed, body_sha, signature in records:
        if method == "PUT" and path.endswith(".json"):
            headers = tuple((k, "<json>" if k in ("x-amz-content-sha256", "content-length") else v) for k, v in headers)
            body_sha = "<json>"
        out.append((method, path, query, headers, signed, body_sha, signature))
    return out


def masked_pdf(rows):
    return [
        ([GENERATED_RE.sub("<generated>", TMP_RE.sub(r"<tmp>.\1", a)) for a in r["argv"]], GENERATED_RE.sub("<generated>", r["html"]))
        for r in rows
    ]


RESPONSE_HEADERS = ("content-type", "content-disposition", "content-length", "content-encoding", "accept-ranges", "content-range")
BYTERANGES_RE = re.compile(r"multipart/byteranges; boundary=([0-9a-f]+)")


def comparable(r):
    """The body as the client reads it (httpx decodes gzip: Rust's deflate bytes are not zlib's,
    §4), a `multipart/byteranges` boundary (Starlette's `token_hex(13)`) masked."""
    body = r.content
    m = BYTERANGES_RE.search(r.headers.get("content-type", ""))
    if m:
        body = body.replace(m.group(1).encode(), b"<boundary>")
    return body


def response_headers(r):
    out = {k: r.headers.get(k) for k in RESPONSE_HEADERS}
    if out["content-type"]:
        out["content-type"] = BYTERANGES_RE.sub("multipart/byteranges; boundary=<boundary>", out["content-type"])
    if out["content-encoding"] == "gzip" and "json" in (out["content-type"] or ""):
        # The app-wide compression layer streams a JSON answer (Starlette sets its length).
        out["content-length"] = "<gzip>"
    # Present on both, never equal: the file's mtime.
    out["etag"] = "etag" in r.headers
    out["last-modified"] = "last-modified" in r.headers
    return out


# --- The comparison -----------------------------------------------------------------------------


def counts():
    return (len(S3.requests), UPSTREAM_REC.count(), velo_count(), pdf_count())


def job_settled(job_id):
    data = S3.buckets.get(BUCKET, {}).get(f"jobs/{job_id}.json")
    if data is None:
        return True
    try:
        job = json.loads(data.data)
    except ValueError:
        return True
    if not isinstance(job, dict):
        return True
    if job.get("status") not in ("done", "failed") or job.get("dynamic_status") == "running":
        return False
    result = S3.buckets.get(BUCKET, {}).get(f"{job.get('customer_code')}/{job.get('sha256')}/result.json")
    if result is not None:
        try:
            rep = json.loads(result.data).get("reputation") or {}
        except (ValueError, AttributeError):
            rep = {}
        if isinstance(rep, dict) and rep.get("note") == "uploading to VirusTotal — scan in progress…":
            return False
    return True


async def settle(job_ids, timeout=30):
    """Until every job has settled in MinIO and no stand-in has been asked anything for 0.6 s."""
    deadline = time.time() + timeout
    last, quiet = counts(), time.time()
    while time.time() < deadline:
        await asyncio.sleep(0.1)
        now = counts()
        if now != last:
            last, quiet = now, time.time()
            continue
        if time.time() - quiet > 0.6 and all(job_settled(j) for j in job_ids):
            return True
    return False


def take_all():
    UPSTREAM_REC.take()
    S3.take()
    velo_take()
    pdf_take()


class Pair:
    def __init__(self, rust_port):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rust_port = rust_port
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{rust_port}", timeout=120)

    async def side(self, client, method, path, tok, before, sandbox, wait, **kw):
        take_all()
        if before:
            before()
        headers = {"Accept-Encoding": "identity", **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        previous = os.environ.get("SANDBOX_BACKEND")
        if client is self.py and sandbox:
            os.environ["SANDBOX_BACKEND"] = sandbox
        try:
            jobs_before = set(S3.buckets.get(BUCKET, {}))
            r = await client.request(method, path, headers=headers, **kw)
            created = [k[5:-5] for k in S3.buckets.get(BUCKET, {}) if k.startswith("jobs/") and k not in jobs_before]
            try:
                named = r.json().get("job_id")
            except (ValueError, AttributeError):
                named = None
            if wait:
                await settle(created + ([named] if isinstance(named, str) else []))
            else:
                await asyncio.sleep(0.05)
        finally:
            if previous is not None:
                os.environ["SANDBOX_BACKEND"] = previous
        return r, UPSTREAM_REC.take(), S3.take(), velo_take(), pdf_take(), S3.snapshot()

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        *,
        before=None,
        sandbox=None,
        wait=True,
        expect=None,
        s3_sorted=False,
        canon=None,
        start=None,
        keep=False,
        **kw,
    ):
        """Python, then Rust, from the same MinIO state (`start`, else the current one); `keep`
        leaves Rust's end state in MinIO (the next check reads what Rust wrote)."""
        start = start or S3.snapshot()
        out = []
        for client in (self.py, self.rs):
            S3.restore(start)
            out.append(await self.side(client, method, path, tok, before, sandbox, wait, **dict(kw)))
        if not keep:
            S3.restore(start)
        (r1, up1, s31, v1, p1, end1), (r2, up2, s32, v2, p2, end2) = out
        m1, m2 = Masker(), Masker()
        b1, b2 = (m(comparable(r)) for m, r in ((m1, r1), (m2, r2)))
        if canon:
            b1, b2 = (json.dumps(canon(json.loads(b))).encode() for b in (b1, b2))
        ok = r1.status_code == r2.status_code and b1 == b2
        if expect is not None and r1.status_code != expect:
            ok = False
        detail = f"python {r1.status_code} {b1[:1200]!r}\n        rust   {r2.status_code} {b2[:1200]!r}"
        h1, h2 = response_headers(r1), response_headers(r2)
        # `Vary` of the module's own Starlette responses (the stream and the file); a JSON answer
        # goes through the app-wide compression layer, which adds none for an identity request.
        vary1, vary2 = (
            "Accept-Encoding" in (r.headers.get("vary") or "") and "json" not in (r.headers.get("content-type") or "") for r in (r1, r2)
        )
        if h1 != h2 or vary1 != vary2:
            ok = False
            detail += f"\n        headers python {h1} vary={vary1}\n        headers rust   {h2} vary={vary2}"
        u1, u2 = masked_upstream(up1, m1), masked_upstream(up2, m2)
        if u1 != u2:
            ok = False
            detail += f"\n        upstream python {u1}\n        upstream rust   {u2}"
        if v1 != v2:
            ok = False
            detail += f"\n        velociraptor python {v1}\n        velociraptor rust   {v2}"
        if masked_pdf(p1) != masked_pdf(p2):
            ok = False
            detail += f"\n        wkhtmltopdf python {masked_pdf(p1)}\n        wkhtmltopdf rust   {masked_pdf(p2)}"
        o1, o2 = json_puts(objstore.outbound(s31, m1.subst())), json_puts(objstore.outbound(s32, m2.subst()))
        if s3_sorted:
            o1, o2 = sorted(o1, key=repr), sorted(o2, key=repr)
        if o1 != o2:
            ok = False
            detail += f"\n        minio python {o1}\n        minio rust   {o2}"
        if any(o[-1] != "ok" for o in o1 + o2):
            ok = False
            detail += f"\n        signatures python {[o[-1] for o in o1]} rust {[o[-1] for o in o2]}"
        st1, st2 = bucket_state(end1, m1), bucket_state(end2, m2)
        if st1 != st2:
            ok = False
            diff = sorted(set(st1) ^ set(st2)) + [k for k in st1 if k in st2 and st1[k] != st2[k]]
            detail += f"\n        bucket differs at {diff}: python {[st1.get(k) for k in diff]}\n        rust {[st2.get(k) for k in diff]}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:400]!r}")
        self.last = {"python": (r1, up1, v1, p1, end1), "rust": (r2, up2, v2, p2, end2)}
        return r1, r2

    def jobs(self, side):
        """The jobs of the last check's end state on `side`, by id."""
        buckets, _ = self.last[side][4]
        out = {}
        for key, (data, _ctype, _etag) in buckets.get(BUCKET, {}).items():
            if key.startswith("jobs/"):
                try:
                    out[key[5:-5]] = json.loads(data)
                except ValueError:
                    pass
        return out

    def result_of(self, side, job):
        buckets, _ = self.last[side][4]
        obj = buckets.get(BUCKET, {}).get(f"{job.get('customer_code')}/{job.get('sha256')}/result.json")
        return json.loads(obj[0]) if obj else None

    def sanity(self, name, predicate):
        """`predicate(job, result, upstream paths, VQL texts, wkhtmltopdf runs)` on both sides'
        job of the last check (the one its answer names): the two agreeing on a broken run proves
        nothing."""
        for side in ("python", "rust"):
            r, up, velo, pdfs, _ = self.last[side]
            try:
                named = r.json().get("job_id")
            except (ValueError, AttributeError):
                named = None
            job = self.jobs(side).get(named, {}) if named else {}
            result = self.result_of(side, job) if job else None
            paths = [t.split("?")[0] for _m, t, _h, _b in up]
            vql = [q[2][0][1] for q in velo]
            ok = bool(predicate(job, result, paths, vql, pdfs))
            check(f"  sanity {side}: {name}", ok, f"job {job} result {str(result)[:600]} upstream {paths} vql {vql}")

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- Fixtures ---------------------------------------------------------------------------------------


def inspector_answer(digest, filetype="script", hint="suspicious", **extra):
    return {
        "sha256": digest,
        "filename": "evil.ps1",
        "customer_code": "ignored",
        "filetype": filetype,
        "size": 31,
        "hashes": {"md5": "md5-parity", "sha1": "sha1-parity", "sha256": digest},
        "flags": ["encoded_powershell"],
        "verdict_hint": hint,
        "hardened": False,
        "entropy": 4.25,
        "iocs": {"urls": ["http://evil.example.com/<x>"], "ips": ["1.2.3.4"]},
        "content": {
            "behaviors": [
                {
                    "attack_id": "T1490",
                    "technique": "Inhibit System Recovery",
                    "severity": "malicious",
                    "evidence": "vssadmin delete shadows",
                },
            ],
            "deobfuscated": ["layer 1 & <b>"],
            "strings": ["s1", "ü"],
        },
        "previews_b64": {"page-1.png": base64.b64encode(b"\x89PNG-one").decode(), "page-2.png": base64.b64encode(b"\x89PNG-two").decode()},
        **extra,
    }


def vt_report(malicious, total_extra=60):
    return {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 1, "undetected": total_extra, "harmless": 0, "type-unsupported": 2},
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.parity/x",
            "popular_threat_name": [{"value": "parity", "count": 3}],
        },
        "meaningful_name": "evil.ps1",
        "type_description": "Powershell",
        "names": ["evil.ps1", "b.ps1"],
        "last_analysis_results": {
            "EngB": {"method": "blacklist", "engine_name": "EngB", "category": "malicious", "result": "Trojan.X"},
            "engA": {"method": "blacklist", "engine_name": "engA", "category": "malicious", "result": "Y", "engine_update": "20260101"},
            "EngC": {"method": "blacklist", "engine_name": "EngC", "category": "undetected", "result": None},
        },
        "first_submission_date": 1700000000,
        "tags": ["powershell"],
    }


CAPE_REPORT = {
    "info": {"id": 77, "duration": 42, "package": "ps1", "machine": {"name": "capewin", "platform": "windows"}},
    "malscore": 6.5,
    "CAPE": {"configs": [], "payloads": [{"name": "p", "sha256": "cd" * 32, "cape_type": "Shellcode"}]},
    "signatures": [
        {"name": "deletes_shadow_copies", "severity": 4, "description": "Deletes shadow copies", "ttp": [{"attack_id": "T1490"}]},
        {"name": NOISE, "severity": 2, "description": "noise"},
        {"name": LOW, "severity": 1},
    ],
    "network": {
        "hosts": ["1.2.3.4", {"ip": "1.2.3.4"}],
        "domains": [{"domain": "evil.example.com"}],
        "tcp": [{"dst": "1.2.3.4", "dport": 443}],
        "dns": [{"request": "evil.example.com", "type": "A", "answers": [{"data": "1.2.3.4"}]}],
    },
    "behavior": {
        "processes": [{"process_name": "powershell.exe", "process_id": 10, "parent_id": 1, "command_line": "powershell -enc x"}],
        "summary": {"files": ["C:\\a.txt"], "executed_commands": ["vssadmin delete shadows"]},
        "enhanced": [{"event": "delete", "object": "file", "data": {"file": "C:\\b"}}],
    },
    "ttps": [{"ttp": "T1490", "signature": "deletes_shadow_copies"}],
    "dropped": [{"sha256": "ef" * 32, "name": "drop.exe", "type": "PE32"}],
    "debug": {"errors": ["Monitor injection attempted but failed for process 12"]},
}


def put_json(key, value):
    S3.put(BUCKET, key, json.dumps(value, ensure_ascii=False).encode(), "application/json")


def seeded_job(job_id, customer, digest, **extra):
    return {
        "job_id": job_id,
        "sha256": digest,
        "filename": "seeded.ps1",
        "customer_code": customer,
        "source": "upload",
        "status": "done",
        "static_status": "done",
        "dynamic_status": None,
        "sandbox_enabled": False,
        "hardened": True,
        "verdict": "suspicious",
        "created_at": "2026-01-0%sT03:04:05.123456+00:00" % extra.pop("day", 2),
        "updated_at": "2026-01-02T03:05:00+00:00",
        "error": None,
        **extra,
    }


def seeded_result(job, **extra):
    return {
        "job": job,
        "inspector": {
            "filename": job.get("filename"),
            "filetype": "script",
            "verdict_hint": "suspicious",
            "sha256": job.get("sha256"),
            "hashes": {"md5": "m"},
        },
        "sandbox": None,
        "reputation": {"source": "virustotal", "found": True, "malicious": 2, "total": 70, "suspicious": 0},
        "preview_urls": ["page-1.png"],
        "engine_version": 15,
        "verdict_reason": "static inspection: suspicious; VirusTotal 2/70",
        **extra,
    }


def seed_minio():
    """The state the read checks start from (identical for both sides)."""
    S3.make_bucket(BUCKET)
    ids = {}
    for label, customer, day in (("a1", CUST_A, 2), ("a2", CUST_A, 4), ("b1", CUST_B, 3)):
        job_id = uuid.uuid4().hex
        digest = sha(f"{label}{SFX}".encode())
        job = seeded_job(job_id, customer, digest, day=day)
        result = seeded_result(job)
        put_json(f"jobs/{job_id}.json", job)
        put_json(f"{customer}/{digest}/result.json", result)
        if label != "a2":
            # a2 predates the summaries: `/history` reads its result and backfills one.
            from app.file_analysis.services.state_store import _history_item

            put_json(f"{customer}/{digest}/summary.json", _history_item(result))
        S3.put(BUCKET, f"{customer}/{digest}/previews/page-1.png", b"\x89PNG-seeded", "image/png")
        ids[label] = (job_id, digest)
    # A detonated job (task 9 on CAPE).
    job_id, digest = uuid.uuid4().hex, sha(f"det{SFX}".encode())
    job = seeded_job(job_id, CUST_A, digest, day=5, sandbox_enabled=True, dynamic_status="done", verdict="malicious")
    sandbox = {
        "task_id": 9,
        "malscore": 6.5,
        "verdict": "malicious",
        "signatures": CAPE_REPORT["signatures"],
        "connections": [{"proto": "tcp", "dst": "1.2.3.4", "dport": 443}],
    }
    put_json(f"jobs/{job_id}.json", job)
    put_json(f"{CUST_A}/{digest}/result.json", seeded_result(job, sandbox=sandbox))
    ids["det"] = (job_id, digest)
    # Odd stored shapes.
    odd = {
        "list": [1, 2],
        "no-customer": {"job_id": "x"},
        "null-customer": {"job_id": "x", "customer_code": None, "sha256": "f" * 64},
        "int-customer": {"job_id": "x", "customer_code": 5},
        "bad-status": {"job_id": "x", "customer_code": CUST_A, "status": "exploded"},
        "minimal": {"job_id": "x", "customer_code": CUST_A},
        "no-result": {"job_id": "x", "customer_code": CUST_A, "sha256": "e" * 64, "extra": True},
        "bad-result": {"job_id": "x", "customer_code": CUST_A, "sha256": "d" * 64},
        "sha-int": {"job_id": "x", "customer_code": CUST_A, "sha256": 5},
    }
    for label, job in odd.items():
        job_id = uuid.uuid4().hex
        put_json(f"jobs/{job_id}.json", job)
        ids[label] = (job_id, None)
    put_json(f"{CUST_A}/{'d' * 64}/result.json", {"job": {"job_id": 5}, "preview_urls": "page-1.png", "engine_version": "15"})
    S3.put(BUCKET, f"jobs/{'0' * 32}.json", b"{not json", "application/json")
    ids["garbled"] = ("0" * 32, None)
    return ids


# --- Checks -----------------------------------------------------------------------------------------

FA = "/api/file-analysis"


async def read_checks(p, none, ids, t_admin, t_analyst, t_portal):
    a1, _ = ids["a1"]
    b1, _ = ids["b1"]
    det, det_sha = ids["det"]
    for label, tok in (("admin", t_admin), ("analyst", t_analyst), ("portal", t_portal), ("no token", None)):
        await p.same(f"job a1: {label}", "GET", f"{FA}/job/{a1}", tok, wait=False)
        await p.same(f"job b1: {label}", "GET", f"{FA}/job/{b1}", tok, wait=False)
    for label in ids:
        job_id = ids[label][0]
        for route in ("job", "result", "result/{}/cape-report", "result/{}/preview/page-1.png"):
            path = f"{FA}/{route.format(job_id)}" if "{}" in route else f"{FA}/{route}/{job_id}"
            await p.same(f"{route.split('/')[0]} of {label}: admin", "GET", path, t_admin, wait=False)
        await p.same(f"result of {label}: analyst", "GET", f"{FA}/result/{job_id}", t_analyst, wait=False)
    await p.same("job: unknown id", "GET", f"{FA}/job/{uuid.uuid4().hex}", t_admin, wait=False)
    await p.same("preview: not listed", "GET", f"{FA}/result/{a1}/preview/page-2.png", t_admin, wait=False)
    await p.same(
        "preview: gzip asked",
        "GET",
        f"{FA}/result/{a1}/preview/page-1.png",
        t_admin,
        wait=False,
        headers={"Accept-Encoding": "gzip"},
    )

    # History: summaries, a legacy result backfilled, limits.
    for q in ("", "&limit=1", "&limit=0", "&limit=-1", "&limit=500", "&limit=x", "&limit=1.0", "&limit=", "&limit=1&limit=2"):
        await p.same(f"history A{q}", "GET", f"{FA}/history?customer_code={CUST_A}{q}", t_analyst, wait=False, s3_sorted=True)
    await p.same("history: B as analyst", "GET", f"{FA}/history?customer_code={CUST_B}", t_analyst, wait=False)
    await p.same("history: B as admin", "GET", f"{FA}/history?customer_code={CUST_B}", t_admin, wait=False, s3_sorted=True)
    await p.same("history: no customer", "GET", f"{FA}/history", t_analyst, wait=False)
    await p.same("history: empty customer", "GET", f"{FA}/history?customer_code=", t_admin, wait=False)
    await p.same("history: unknown customer", "GET", f"{FA}/history?customer_code=nobody{SFX}", t_admin, wait=False, s3_sorted=True)
    await p.same("history: portal", "GET", f"{FA}/history?customer_code={CUST_A}", t_portal, wait=False)

    # The cache lookup.
    _, a1_sha = ids["a1"]
    for label, path in (
        ("hit", f"{FA}/search/{a1_sha}?customer_code={CUST_A}"),
        ("no customer", f"{FA}/search/{a1_sha}"),
        ("empty customer", f"{FA}/search/{a1_sha}?customer_code="),
        ("other tenant", f"{FA}/search/{a1_sha}?customer_code={CUST_B}"),
        ("unknown", f"{FA}/search/{'9' * 64}?customer_code={CUST_A}"),
        ("stale engine", f"{FA}/search/{'d' * 64}?customer_code={CUST_A}"),
    ):
        await p.same(f"search: {label}", "GET", path, t_analyst, wait=False)

    # The CAPE report and the PDF.
    await p.same("cape-report: from CAPE", "GET", f"{FA}/result/{det}/cape-report", t_analyst, wait=False, before=cape("ok"))
    await p.same(
        "cape-report: gzip asked",
        "GET",
        f"{FA}/result/{det}/cape-report",
        t_analyst,
        wait=False,
        before=cape("ok"),
        headers={"Accept-Encoding": "gzip"},
    )
    await p.same("cape-report: CAPE fails", "GET", f"{FA}/result/{det}/cape-report", t_analyst, wait=False, before=cape("report-error"))
    await p.same("cape-report: a NaN", "GET", f"{FA}/result/{det}/cape-report", t_analyst, wait=False, before=cape("report-nan"))
    await p.same("cape-report: unauthorized", "GET", f"{FA}/result/{det}/cape-report", t_analyst, wait=False, before=cape("unauthorized"))
    await none.same("cape-report: no sandbox", "GET", f"{FA}/result/{det}/cape-report", t_analyst, wait=False, sandbox="none")
    for mode in ("ok", "big", "error", "done", "empty", "bad-utf8", "no-file"):
        await p.same(
            f"report.pdf: {mode}",
            "GET",
            f"{FA}/result/{det}/report.pdf",
            t_analyst,
            wait=False,
            before=both_modes(cape("ok"), pdf(mode)),
            canon=None,
        )
        if mode == "ok":
            for side in ("python", "rust"):
                r, up, _v, pdfs, _ = p.last[side]
                check(
                    f"  sanity {side}: the PDF went through wkhtmltopdf with the screenshots",
                    r.status_code == 200
                    and r.content.startswith(b"%PDF")
                    and len(pdfs) == 1
                    and "data:image/jpeg;base64," + base64.b64encode(b"jpeg-one").decode() in pdfs[0]["html"],
                    f"{r.status_code} {pdfs}",
                )
                html_path, pdf_path = pdfs[0]["argv"][-2:]
                left = [path for path in (html_path, pdf_path) if os.path.exists(path)]
                # §4: Python leaves both temporary files behind; Rust removes them.
                check(
                    f"  §4 {side}: the temporary HTML and PDF are {'left' if side == 'python' else 'removed'}",
                    left == ([html_path, pdf_path] if side == "python" else []),
                    f"{left}",
                )
                for path in left:
                    os.remove(path)
    await p.same(
        "report.pdf: big, gzip asked",
        "GET",
        f"{FA}/result/{det}/report.pdf",
        t_analyst,
        wait=False,
        before=both_modes(cape("ok"), pdf("big")),
        headers={"Accept-Encoding": "gzip"},
    )
    await p.same(
        "report.pdf: no screenshots",
        "GET",
        f"{FA}/result/{det}/report.pdf",
        t_analyst,
        wait=False,
        before=both_modes(cape("no-shots"), pdf("ok")),
    )
    await p.same(
        "report.pdf: a range",
        "GET",
        f"{FA}/result/{det}/report.pdf",
        t_analyst,
        wait=False,
        before=pdf("ok"),
        headers={"Range": "bytes=0-7"},
    )
    await p.same(
        "report.pdf: two ranges",
        "GET",
        f"{FA}/result/{det}/report.pdf",
        t_analyst,
        wait=False,
        before=pdf("ok"),
        headers={"Range": "bytes=0-1,5-6"},
        canon=None,
    )
    await p.same(
        "report.pdf: a bad range",
        "GET",
        f"{FA}/result/{det}/report.pdf",
        t_analyst,
        wait=False,
        before=pdf("ok"),
        headers={"Range": "bytes=9000-"},
    )
    await p.same(
        "report.pdf: not bytes",
        "GET",
        f"{FA}/result/{det}/report.pdf",
        t_analyst,
        wait=False,
        before=pdf("ok"),
        headers={"Range": "items=0-1"},
    )
    await p.same("report.pdf: without a sandbox", "GET", f"{FA}/result/{a1}/report.pdf", t_analyst, wait=False, before=pdf("ok"))
    await p.same("report.pdf: other tenant", "GET", f"{FA}/result/{b1}/report.pdf", t_analyst, wait=False, before=pdf("ok"))
    PDF_PATHS["binary"] = None
    await none.same("report.pdf: no wkhtmltopdf", "GET", f"{FA}/result/{a1}/report.pdf", t_analyst, wait=False, sandbox="none")
    PDF_PATHS["binary"] = WRAPPER

    # Deletes.
    for label in ("a1", "a2", "det", "minimal", "list", "garbled"):
        await p.same(f"delete {label}", "DELETE", f"{FA}/analysis/{ids[label][0]}", t_admin, wait=False)
    await p.same("delete b1: analyst of A", "DELETE", f"{FA}/analysis/{b1}", t_analyst, wait=False)
    await p.same("delete: unknown", "DELETE", f"{FA}/analysis/{uuid.uuid4().hex}", t_admin, wait=False)


def cape(m):
    def set_mode():
        UPSTREAM.cape = m
        UPSTREAM.cape_report = CAPE_REPORT

    return set_mode


def pdf(m):
    def set_mode():
        pdf_mode(m)

    return set_mode


def both_modes(*fns):
    def run():
        for f in fns:
            f()

    return run


def upstream(
    inspector="ok",
    digest=None,
    answer=None,
    vt=None,
    vt_mode="ok",
    busy=0,
    cape_mode="ok",
    after_upload=None,
    analysis="completed",
):
    def set_mode():
        UPSTREAM.reset()
        UPSTREAM.inspector = inspector
        UPSTREAM.inspector_answer = answer if answer is not None else inspector_answer(digest)
        UPSTREAM.vt = dict(vt or {})
        UPSTREAM.vt_mode = vt_mode
        UPSTREAM.busy = busy
        UPSTREAM.cape = cape_mode
        UPSTREAM.cape_report = CAPE_REPORT
        UPSTREAM.vt_after_upload = after_upload
        UPSTREAM.analysis = analysis

    return set_mode


async def upload_checks(p, none, t_admin, t_analyst, t_portal):
    def sample(label):
        return f"{label} {SFX}".encode()

    def form(customer=CUST_A, **fields):
        return {"customer_code": customer, **fields}

    async def up(name, data, fields, before, tok=t_analyst, filename="evil.ps1", runner=None, **kw):
        files = {"file": (filename, data, "application/octet-stream")} if data is not None else None
        return await (runner or p).same(name, "POST", f"{FA}/upload", tok, before=before, files=files, data=fields, **kw)

    s = sample("found")
    await up("upload: VirusTotal knows it", s, form(sandbox="false"), upstream(digest=sha(s), vt={sha(s): vt_report(7)}))
    p.sanity(
        "the job ran, VirusTotal raised it",
        lambda job, result, paths, vql, pdfs: job.get("status") == "done"
        and job.get("verdict") == "malicious"
        and result["reputation"]["intel"]
        and paths.count("/insp/inspect") == 1
        and len([x for x in paths if x.startswith("/api/v3/files/")]) == 3,
    )
    s = sample("found-refused")
    bad = vt_report(5)
    bad["last_analysis_results"] = {"X": {"category": "malicious"}}
    await up("upload: a VT report the model refuses", s, form(sandbox="false"), upstream(digest=sha(s), vt={sha(s): bad}))
    s = sample("found-no-behaviour")
    await up(
        "upload: VT without behaviour",
        s,
        form(sandbox="no"),
        upstream(digest=sha(s), vt={sha(s): vt_report(0)}, vt_mode="no-behaviour"),
    )
    s = sample("unknown")
    await up("upload: VirusTotal does not know it", s, form(sandbox="0"), upstream(digest=sha(s)))
    s = sample("vt-error")
    await up("upload: VirusTotal fails", s, form(sandbox="off"), upstream(digest=sha(s), vt_mode="error"))
    s = sample("off")
    await up("upload: reputation off", s, form(sandbox="false", reputation_mode="off"), upstream(digest=sha(s), vt={sha(s): vt_report(9)}))
    s = sample("detached")
    await up(
        "upload: the detached VirusTotal upload",
        s,
        form(sandbox="false", reputation_mode="upload"),
        upstream(digest=sha(s), after_upload=(sha(s), vt_report(4))),
    )
    p.sanity(
        "the upload patched the result",
        lambda job, result, paths, vql, pdfs: result["reputation"]["found"] is True
        and result["reputation"]["submitted"] is True
        and "/api/v3/files" in paths
        and "/api/v3/analyses/an-parity" in paths,
    )
    s = sample("detached-fails")
    await up(
        "upload: the upload fails",
        s,
        form(sandbox="false", reputation_mode="upload"),
        upstream(digest=sha(s), vt_mode="upload-error"),
    )
    s = sample("detached-pending")
    await up(
        "upload: VirusTotal still scanning",
        s,
        form(sandbox="false", reputation_mode="upload"),
        upstream(digest=sha(s), analysis="queued"),
    )
    s = sample("upload-known")
    await up(
        "upload: mode upload, VT knows it",
        s,
        form(sandbox="false", reputation_mode="upload"),
        upstream(digest=sha(s), vt={sha(s): vt_report(1)}),
    )
    for mode in ("error", "html", "list", "bad-preview", "previews-list", "bad-hint"):
        s = sample(f"inspector-{mode}")
        await up(f"upload: inspector {mode}", s, form(sandbox="false", reputation_mode="off"), upstream(inspector=mode, digest=sha(s)))
    s = sample("busy")
    await up("upload: inspector busy once", s, form(sandbox="false", reputation_mode="off"), upstream(digest=sha(s), busy=1))
    s = sample("other-sha")
    await up(
        "upload: the inspector's own sha256",
        s,
        form(sandbox="false", reputation_mode="off"),
        upstream(answer={**inspector_answer("ab" * 32), "hardened": "yes", "previews_b64": None}),
    )
    s = sample("no-name")
    await up("upload: no file name", s, form(sandbox="false", reputation_mode="off"), upstream(digest=sha(s)), filename="")
    s = sample("unicode-name")
    await up(
        "upload: a unicode file name",
        s,
        form(sandbox="false", reputation_mode="off"),
        upstream(digest=sha(s)),
        filename="rapport é.pdf",
    )
    await up("upload: empty file", b"", form(sandbox="false", reputation_mode="off"), upstream(digest=sha(b"")))

    # Detonation (the Rust instance with the CAPE sandbox, Python with SANDBOX_BACKEND=remote).
    s = sample("detonate")
    await up("upload: detonated", s, form(reputation_mode="off"), upstream(digest=sha(s)))
    p.sanity(
        "CAPE detonated it",
        lambda job, result, paths, vql, pdfs: job.get("dynamic_status") == "done"
        and result["sandbox"]["task_id"] == 77
        and "/apiv2/tasks/create/file/" in paths,
    )
    s = sample("detonate-reuse")
    await up("upload: a reported CAPE task reused", s, form(reputation_mode="off"), upstream(digest=sha(s), cape_mode="reuse"))
    s = sample("detonate-vt")
    await up("upload: detonated, VirusTotal knows it", s, form(sandbox="true"), upstream(digest=sha(s), vt={sha(s): vt_report(12)}))
    for mode in ("no-task", "failed", "pending", "report-error", "report-nan", "down", "unauthorized"):
        s = sample(f"cape-{mode}")
        await up(f"upload: CAPE {mode}", s, form(reputation_mode="off"), upstream(digest=sha(s), cape_mode=mode))
    s = sample("inert")
    await up(
        "upload: text is never detonated",
        s,
        form(reputation_mode="off"),
        upstream(answer=inspector_answer(sha(s), filetype="text", flags=[])),
    )
    s = sample("flagged-image")
    await up(
        "upload: a flagged image is detonated",
        s,
        form(reputation_mode="off"),
        upstream(answer=inspector_answer(sha(s), filetype="image", flags=["html_smuggling"])),
    )
    s = sample("incomplete")
    await up("upload: an incomplete inspection is detonated", s, form(reputation_mode="off"), upstream(inspector="error", digest=sha(s)))
    s = sample("none-backend")
    await up("upload: no sandbox configured", s, form(reputation_mode="off"), upstream(digest=sha(s)), runner=none, sandbox="none")

    # A cached result: the same bytes again, from the state the first upload left.
    s = sample("cached")
    first = S3.snapshot()
    await up("upload: first of two", s, form(sandbox="false"), upstream(digest=sha(s), vt={sha(s): vt_report(3)}), keep=True)
    await up("upload: the cached job", s, form(sandbox="false"), upstream(digest=sha(s), vt={sha(s): vt_report(3)}))
    await up("upload: cached, another customer", s, form(customer=CUST_B, sandbox="false"), upstream(digest=sha(s)), tok=t_admin)
    S3.restore(first)

    # Validation and tenancy.
    s = sample("v")
    await up("upload: no file", None, form(), upstream(digest=sha(s)))
    await up("upload: no customer", s, {}, upstream(digest=sha(s)))
    await up("upload: empty customer", s, form(customer=""), upstream(digest=sha(s)))
    await up("upload: other tenant", s, form(customer=CUST_B), upstream(digest=sha(s)))
    await up("upload: portal user", s, form(), upstream(digest=sha(s)), tok=t_portal)
    await up("upload: no token", s, form(), upstream(digest=sha(s)), tok=None)
    await up("upload: sandbox maybe", s, form(sandbox="maybe"), upstream(digest=sha(s)))
    await up("upload: sandbox TRUE", s, form(sandbox="TRUE", reputation_mode="off"), upstream(digest=sha(s)))
    await up("upload: sandbox ' 1'", s, form(sandbox=" 1"), upstream(digest=sha(s)))
    await up("upload: reputation all", s, form(reputation_mode="all"), upstream(digest=sha(s)))
    await up("upload: reputation empty", s, form(sandbox="false", reputation_mode=""), upstream(digest=sha(s), vt={sha(s): vt_report(0)}))
    big = b"\0" * (100 * 1024 * 1024 + 1)
    await up("upload: over 100 MB", big, form(sandbox="false"), upstream(digest=sha(big)))
    del big
    r1, r2 = None, None
    for client, label in ((p.py, "python"), (p.rs, "rust")):
        resp = await client.post(
            f"{FA}/upload",
            headers={"Authorization": f"Bearer {t_analyst}", "Content-Type": "application/json", "Accept-Encoding": "identity"},
            content=b"{}",
        )
        if label == "python":
            r1 = resp
        else:
            r2 = resp
    check(
        "upload: a JSON body",
        r1.status_code == r2.status_code and r1.content == r2.content,
        f"{r1.status_code} {r1.content!r} / {r2.status_code} {r2.content!r}",
    )


async def submit_checks(p, t_admin, t_analyst, t_portal):
    host_a = AGENTS[0][1]

    def velo(m):
        def set_mode():
            VELO.mode = m
            UPSTREAM.reset()
            data = "parity-host\u00e9\n".encode("latin-1", "replace")
            UPSTREAM.inspector_answer = inspector_answer(sha(data), filetype="text")

        return set_mode

    def body(**kw):
        return {"source": "host_path", "customer_code": CUST_A, "reputation_mode": "off", **kw}

    async def sub(name, b, before=velo("ok"), tok=t_analyst, **kw):
        return await p.same(name, "POST", f"{FA}/submit", tok, before=before, json=b, **kw)

    await sub("submit: by client id", body(client_id="C.faaaa", target_path="/etc/hostname"))
    p.sanity(
        "collected through Velociraptor",
        lambda job, result, paths, vql, pdfs: job.get("status") == "done"
        and job.get("filename") == "hostname"
        and any(q.startswith("SELECT collect_client(") for q in vql)
        and any(q.startswith("SELECT read_file(") for q in vql),
    )
    await sub("submit: by hostname", body(hostname=host_a, target_path="/etc/hostname"))
    await sub("submit: windows client", body(client_id="C.faaaa", target_path="C:\\Users\\x\\a.txt"), before=velo("windows"))
    await sub("submit: the file is gone", body(client_id="C.faaaa", target_path="/gone"))
    p.sanity("the job failed", lambda job, result, paths, vql, pdfs: job.get("status") == "failed" and job.get("error"))
    await sub("submit: no flow id", body(client_id="C.faaaa", target_path="/etc/hostname"), before=velo("no-flow"))
    await sub("submit: a file_store row", body(client_id="C.faaaa", target_path="/etc/hostname"), before=velo("file-store"))
    await sub("submit: nothing read", body(client_id="C.faaaa", target_path="/etc/hostname"), before=velo("empty-read"))
    await sub("submit: unknown hostname", body(hostname=f"nowhere-{SFX}", target_path="/x"), tok=t_admin)
    await sub("submit: tiers", body(client_id="C.faaaa", target_path="/etc/hostname", tiers=["static", "dynamic"]))
    await sub("submit: client and hostname", body(client_id="C.faaaa", hostname=f"fa-b-{SFX}", target_path="/etc/hostname"))
    # Validation.
    await sub("submit: source upload", body(source="upload"))
    await sub("submit: no endpoint", body(target_path="/x"))
    await sub("submit: empty client id", body(client_id="", target_path="/x"))
    await sub("submit: no path", body(client_id="C.faaaa"))
    await sub("submit: other tenant", body(customer_code=CUST_B, client_id="C.fabbb", target_path="/x"))
    await sub("submit: portal", body(client_id="C.faaaa", target_path="/x"), tok=t_portal)
    await sub("submit: bad tier", body(client_id="C.faaaa", target_path="/x", tiers=["static", "x"]))
    await sub("submit: no source", {"customer_code": CUST_A})
    await sub("submit: a list", [1])
    await sub("submit: null client id", body(client_id=None, hostname=None, target_path="/x"))
    r1 = await p.py.post(f"{FA}/submit", headers={"Authorization": f"Bearer {t_analyst}", "Content-Type": "application/json"}, content=b"{")
    r2 = await p.rs.post(f"{FA}/submit", headers={"Authorization": f"Bearer {t_analyst}", "Content-Type": "application/json"}, content=b"{")
    check("submit: malformed JSON", (r1.status_code, r1.content) == (r2.status_code, r2.content), f"{r1.content!r} / {r2.content!r}")

    # The agents list and the file enumeration.
    for label, tok in (("admin", t_admin), ("portal", t_portal)):
        await p.same(f"agents: {label}", "GET", f"{FA}/velociraptor/agents?customer_code={CUST_A}", tok, wait=False, before=velo("ok"))
    await p.same("agents: B as analyst of A", "GET", f"{FA}/velociraptor/agents?customer_code={CUST_B}", t_analyst, wait=False)
    await p.same("agents: no customer", "GET", f"{FA}/velociraptor/agents", t_admin, wait=False)
    await p.same("agents: empty customer", "GET", f"{FA}/velociraptor/agents?customer_code=", t_admin, wait=False)
    await p.same("agents: B as admin", "GET", f"{FA}/velociraptor/agents?customer_code={CUST_B}", t_admin, wait=False, before=velo("ok"))
    for label, b in (
        ("matches", {"customer_code": CUST_A, "client_id": "C.faaaa", "target_path": "/etc/host*"}),
        ("windows", {"customer_code": CUST_A, "client_id": "C.faaaa", "target_path": "C:\\x\\*.txt"}),
        ("empty path", {"customer_code": CUST_A, "client_id": "C.faaaa", "target_path": ""}),
        ("no client", {"customer_code": CUST_A, "target_path": "/x"}),
        ("no flow", {"customer_code": CUST_A, "client_id": "C.faaaa", "target_path": "/x"}),
    ):
        await p.same(
            f"enumerate: {label}",
            "POST",
            f"{FA}/velociraptor/enumerate",
            t_admin,
            wait=False,
            json=b,
            before=velo("no-flow" if label == "no flow" else ("windows" if label == "windows" else "ok")),
        )


async def section4_checks(p, t_admin, t_analyst):
    """The deliberate differences (RUST_MIGRATION.md §4), asserted as such."""

    async def run(client, method, path, tok, **kw):
        take_all()
        r = await client.request(method, path, headers={"Authorization": f"Bearer {tok}", "Accept-Encoding": "identity"}, **kw)
        try:
            named = r.json().get("job_id")
        except (ValueError, AttributeError):
            named = None
        if isinstance(named, str):
            await settle([named])
        return r, velo_take()

    def reset():
        VELO.mode = "ok"
        UPSTREAM.reset()
        UPSTREAM.inspector_answer = inspector_answer("0" * 64, filetype="text")

    start = S3.snapshot()
    # 1. Another tenant's endpoint, by client id or hostname: Python collected from it.
    for label, extra in (
        ("client id", {"client_id": "C.fabbb"}),
        ("hostname", {"hostname": f"fa-b-{SFX}"}),
        ("unassigned", {"client_id": "C.fa000"}),
    ):
        reset()
        body = {"source": "host_path", "customer_code": CUST_A, "target_path": "/etc/hostname", "reputation_mode": "off", **extra}
        S3.restore(start)
        r1, v1 = await run(p.py, "POST", f"{FA}/submit", t_analyst, json=body)
        S3.restore(start)
        reset()
        r2, v2 = await run(p.rs, "POST", f"{FA}/submit", t_analyst, json=body)
        check(
            f"§4 submit: another tenant's endpoint by {label} is refused",
            r1.status_code == 200 and any("collect_client" in q[2][0][1] for q in v1) and r2.status_code == 403 and v2 == [],
            f"python {r1.status_code} {r1.content[:200]!r} {len(v1)} queries / rust {r2.status_code} {r2.content[:200]!r} {v2}",
        )
    # 2. Enumerate checks the body's customer and the client's owner.
    for label, body in (
        ("another customer", {"customer_code": "B", "client_id": "C.faaaa", "target_path": "/x"}),
        ("another tenant's client", {"customer_code": CUST_A, "client_id": "C.fabbb", "target_path": "/x"}),
    ):
        reset()
        body = {**body, "customer_code": CUST_B if body["customer_code"] == "B" else body["customer_code"]}
        r1, v1 = await run(p.py, "POST", f"{FA}/velociraptor/enumerate", t_analyst, json=body)
        r2, v2 = await run(p.rs, "POST", f"{FA}/velociraptor/enumerate", t_analyst, json=body)
        check(
            f"§4 enumerate: {label} is refused",
            r1.status_code == 200 and v1 and r2.status_code == 403 and v2 == [],
            f"python {r1.status_code} {r1.content[:200]!r} / rust {r2.status_code} {r2.content[:200]!r}",
        )
    # 3. A scoped analyst's agent list leaves the unassigned endpoints out.
    reset()
    r1, _ = await run(p.py, "GET", f"{FA}/velociraptor/agents?customer_code={CUST_A}", t_analyst)
    r2, _ = await run(p.rs, "GET", f"{FA}/velociraptor/agents?customer_code={CUST_A}", t_analyst)
    py_agents, rs_agents = r1.json()["agents"], r2.json()["agents"]
    check(
        "§4 agents: a scoped analyst sees no unassigned endpoint",
        [a for a in py_agents if not a["unassigned"]] == rs_agents and any(a["unassigned"] for a in py_agents),
        f"python {py_agents} / rust {rs_agents}",
    )
    # 4. A client id or hostname that is not one never reaches the VQL (admin: no owner check).
    for label, extra in (
        ("client id", {"client_id": "C.1', artifacts=['Evil"}),
        ("hostname", {"hostname": "x') OR 1=1 --"}),
    ):
        reset()
        body = {"source": "host_path", "customer_code": CUST_A, "target_path": "/etc/hostname", "reputation_mode": "off", **extra}
        S3.restore(start)
        r1, v1 = await run(p.py, "POST", f"{FA}/submit", t_admin, json=body)
        S3.restore(start)
        reset()
        r2, v2 = await run(p.rs, "POST", f"{FA}/submit", t_admin, json=body)
        bad = "Evil" if label == "client id" else "OR 1=1"
        injected = [q[2][0][1] for q in v1 if bad in q[2][0][1]]
        reached = [
            q[2][0][1]
            for q in v2
            if bad in q[2][0][1] and (q[2][0][1].startswith("SELECT collect_client(") or "clients(search=" in q[2][0][1])
        ]
        check(
            f"§4 submit: an invalid {label} is not interpolated into VQL",
            r1.status_code == r2.status_code == 200 and injected and not reached,
            f"python {injected} / rust {[q[2][0][1] for q in v2]}",
        )
    S3.restore(start)


async def cross_checks(p, t_analyst):
    """A job written by one backend, read by the other."""
    data = f"cross {SFX}".encode()

    def before():
        UPSTREAM.reset()
        UPSTREAM.inspector_answer = inspector_answer(sha(data))
        UPSTREAM.vt = {sha(data): vt_report(2)}

    start = S3.snapshot()
    for writer, label in ((p.py, "Python"), (p.rs, "Rust")):
        S3.restore(start)
        take_all()
        before()
        r = await writer.post(
            f"{FA}/upload",
            headers={"Authorization": f"Bearer {t_analyst}"},
            files={"file": ("cross.ps1", data, "application/octet-stream")},
            data={"customer_code": CUST_A, "sandbox": "false"},
        )
        job_id = r.json()["job_id"]
        await settle([job_id])
        written = S3.snapshot()
        for route in (
            f"job/{job_id}",
            f"result/{job_id}",
            f"result/{job_id}/preview/page-2.png",
            f"history?customer_code={CUST_A}",
            f"search/{sha(data)}?customer_code={CUST_A}",
        ):
            await p.same(
                f"{label} wrote, both read: {route.split('?')[0].split('/')[0]}",
                "GET",
                f"{FA}/{route}",
                t_analyst,
                wait=False,
                start=written,
                s3_sorted=route.startswith("history"),
            )
        await p.same(f"{label} wrote, both delete", "DELETE", f"{FA}/analysis/{job_id}", t_analyst, wait=False, start=written)
    S3.restore(start)


async def main():
    global VELO_STAND_IN
    with open(WRAPPER, "w") as f:
        f.write(WRAPPER_SOURCE)
    os.chmod(WRAPPER, 0o755)
    pdf_mode("ok")
    upstream_server = start_http_stub(STUB_PORT, UPSTREAM, UPSTREAM_REC)
    s3_server = S3.serve(S3_PORT)
    VELO_STAND_IN = agents_parity.VeloStandIn(VELO_PORT, VELO)
    workdir = tempfile.mkdtemp(prefix="file-analysis-parity-")
    patch_python()
    procs = []
    try:
        seed()
        set_connector("Velociraptor", "https://velo", api_key=agents_parity.api_config(workdir, VELO_STAND_IN.address))
        ids = seed_minio()
        procs.append(start_rust(RS_PORT))
        procs.append(start_rust(RS_NONE_PORT, sandbox="none", wkhtmltopdf="/nonexistent/wkhtmltopdf"))
    except BaseException:
        for proc_ in procs:
            proc_.kill()
        cleanup()
        raise
    p, none = Pair(RS_PORT), Pair(RS_NONE_PORT)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    try:
        # Each process creates the bucket's flag once (`_bucket_ready`): warm both.
        for client in (p.py, p.rs, none.rs):
            await client.get(f"{FA}/history?customer_code={CUST_A}", headers={"Authorization": f"Bearer {t_admin}"})
        take_all()
        sections = os.environ.get("FILE_ANALYSIS_PARITY_SECTIONS", "read,upload,submit,section4,cross").split(",")
        if "read" in sections:
            await read_checks(p, none, ids, t_admin, t_analyst, t_portal)
        if "upload" in sections:
            await upload_checks(p, none, t_admin, t_analyst, t_portal)
        if "submit" in sections:
            await submit_checks(p, t_admin, t_analyst, t_portal)
        if "section4" in sections:
            await section4_checks(p, t_admin, t_analyst)
        if "cross" in sections:
            await cross_checks(p, t_analyst)
    finally:
        await p.close()
        await none.close()
        for proc_ in procs:
            proc_.terminate()
            try:
                proc_.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc_.kill()
        cleanup()
        upstream_server.shutdown()
        s3_server.shutdown()
        VELO_STAND_IN.stop()
        shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(PDF_DIR, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
