"""Parity of the Rust front with the whole Python app — NOT collected by pytest (needs a live
MySQL and the Rust binary; run by scripts/rust-parity.sh).

The probe that no request needs the Python process: every route of `copilot.app` (the routes
in Starlette's order, the documentation routes and the `/scoutsuite-report` mount) is sent to a
Rust instance this suite starts with `COPILOT_LEGACY_URL` pointing at a recorder, and the
recorder must see none of them:

* **A** — every route and method without a token and without a body, its path parameters
  filled by type (an `int` a number no row has, an `Enum` its first value, else a word); the
  answer is compared with the in-process Python app's (`copilot.app` itself, its middleware and
  exception handlers included, without its startup hooks): status, body and every header but
  the transport's (`date`, `server`, the timing pair; a gzipped length);
* **B** — the same request with an encoded `/` in its first text parameter (`a%2Fb`: Starlette
  routes the decoded path, so it is usually another route, or none), compared the same way;
* **C** — every route and method with an admin's token and an empty body, Rust only (the
  handlers run: their lookups miss, their validation refuses, their upstreams are closed ports);
  `DELETE /api/logs` (it purges every log row) goes with an analyst's token instead;
* **D** — what is not a route: a path no router has, a trailing `/`, `HEAD` and `OPTIONS` of an
  API route, a CORS preflight and a simple CORS request, `/docs`, `/docs/oauth2-redirect`,
  `/redoc`, `/openapi.json` (the one value Python computes at import time masked on both
  sides), `GET /`, the documentation routes' `HEAD` and their 405 (Python's `Allow` names a
  `set` in an order that varies per process: compared sorted), and the static mount over the
  same directory (plain, conditional, ranged, refused and escaping requests), compared;
* **E** — the Scheduler's writes on a job that exists, through an instance that owns the
  schedule (`COPILOT_SCHEDULER_OWNER=rust`, as this one is started): nothing reaches Python's
  `apscheduler_ops`; the rows are restored;
* **F** — a path outside every Python router still reaches the legacy backend (the proxy kept
  for a staged rollout): exactly once.

The Rust instance's upstream overrides and every connector row point at a closed port for the
run (the rows restored at the end), so no request leaves the host. The rows the probe's requests
create (log rows, a settings row a read creates, …) are deleted again by their ids, and the tables
without an integer id must hold as many rows as before. Each request carries an
`X-Probe-Id` the recorder files what it receives by.

Ports (overridable): STANDALONE_PARITY_RUST_PORT (6610), STANDALONE_RECORDER_PORT (6611),
STANDALONE_CLOSED_PORT (6612).

    PARITY_SUITES=tests/e2e/rust_parity_standalone_e2e.py scripts/rust-parity.sh
"""

import asyncio
import datetime
import enum
import json
import os
import re
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
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BACKEND = os.path.join(REPO, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

RS_PORT = int(os.environ.get("STANDALONE_PARITY_RUST_PORT", "6610"))
RECORDER_PORT = int(os.environ.get("STANDALONE_RECORDER_PORT", "6611"))
CLOSED_PORT = int(os.environ.get("STANDALONE_CLOSED_PORT", "6612"))
CLOSED = f"http://127.0.0.1:{CLOSED_PORT}"
RUST = f"http://127.0.0.1:{RS_PORT}"

# `copilot.py` mounts `StaticFiles(directory="scoutsuite-report")` relative to the working
# directory: the app is imported from, and served in, a scratch directory both backends share.
SCRATCH = tempfile.mkdtemp(prefix="parity-standalone-")
REPORT_DIR = os.path.join(SCRATCH, "scoutsuite-report")
os.makedirs(os.path.join(REPORT_DIR, "sub"), exist_ok=True)
STATIC_FILES = {
    "index.html": "<html><body>report</body></html>\n",
    "report.js": "var x = 1;\n" * 200,
    "sub/data.json": json.dumps({"k": ["v"] * 300}),
    "plain.txt": "plain text\n",
}
for name, content in STATIC_FILES.items():
    path = os.path.join(REPORT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.utime(path, (1_700_000_000, 1_700_000_000))
with open(os.path.join(SCRATCH, "outside.txt"), "w", encoding="utf-8") as f:
    f.write("outside\n")
os.symlink(os.path.join(SCRATCH, "outside.txt"), os.path.join(REPORT_DIR, "outside-link"))
os.makedirs(os.path.join(SCRATCH, "data"), exist_ok=True)
os.chdir(SCRATCH)

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

import copilot  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402

APP = copilot.app
SFX = uuid.uuid4().hex[:6]
ADMIN, ANALYST = f"sa_admin{SFX}", f"sa_analyst{SFX}"
results = []
# What the transport writes (uvicorn too, which the in-process app skips): the date, the server, a
# streamed body's chunking, and the request timer's pair.
TRANSPORT_HEADERS = {"date", "server", "transfer-encoding", "x-process-time-ms", "x-request-id"}
# Differences by design (§4): the APScheduler hand-off hook is no route through the Rust service.
BY_DESIGN = {("POST", "/api/scheduler/apscheduler_ops")}
# The Rust service's defensive headers on its API answers (§4).
RUST_ONLY_HEADERS = {"x-content-type-options", "x-frame-options"}
BOUNDARY = re.compile(r"boundary=[0-9a-f]+")
NO_ROW_ID = 9_999_917
WORD = "zzprobe"


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


async def sql(stmt, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(stmt), params)
        await s.commit()
        return r


async def rows(stmt, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(stmt), params)
        return [dict(m) for m in r.mappings().all()]


# --- the recorder (the legacy backend) -------------------------------------------------
class Recorder:
    """Answers 599 to anything and files it by `X-Probe-Id`."""

    def __init__(self, port):
        self.captured = []
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with recorder.lock:
                    recorder.captured.append((self.command, self.path, self.headers.get("X-Probe-Id")))
                payload = b'{"detail":"legacy recorder"}'
                self.send_response(599)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle  # noqa: N815

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def take(self):
        with self.lock:
            out, self.captured[:] = list(self.captured), []
        return out

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# --- the Rust instance ----------------------------------------------------------------
UPSTREAM_OVERRIDES = {
    "COPILOT_EPSS_URL": f"{CLOSED}/epss",
    "COPILOT_SOCFORTRESS_INTEL_URL": f"{CLOSED}/intel",
    "COPILOT_SOCFORTRESS_AI_URL": f"{CLOSED}/ai",
    "COPILOT_SOCFORTRESS_MCP_URL": f"{CLOSED}/mcp",
    "COPILOT_LICENSE_URL": f"{CLOSED}/",
    "COPILOT_VIRUSTOTAL_URL": f"{CLOSED}/vt",
    "COPILOT_GITHUB_API_URL": f"{CLOSED}/api",
    "COPILOT_GITHUB_RAW_URL": f"{CLOSED}/raw",
    "COPILOT_GITHUB_AUDIT_API_URL": f"{CLOSED}/gh",
    "COPILOT_MITRE_STIX_URL": f"{CLOSED}/stix",
    "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{CLOSED_PORT}",
    "COPILOT_INTEGRATION_MODULES_URL": f"{CLOSED}/modules",
    "COPILOT_ACTION_URL": f"{CLOSED}/action",
    "COPILOT_MCP_LOCAL_URL": f"{CLOSED}/mcp-local",
    "COPILOT_NUCLEI_MODULE_URL": f"{CLOSED}/nuclei",
    "COPILOT_MSRC_CVRF_URL": f"{CLOSED}/msrc",
    "COPILOT_CISA_KEV_URL": f"{CLOSED}/kev",
    "COPILOT_SCA_REPO_URL": f"{CLOSED}/sca",
    "COPILOT_BITDEFENDER_URL": f"{CLOSED}/gravityzone",
    "COPILOT_PROVISION_WORKER_PORT": str(CLOSED_PORT),
    "COPILOT_SSO_IDP_URL": CLOSED,
    "COPILOT_VERSION_CHECK_URL": f"{CLOSED}/releases/latest",
    "AWS_ENDPOINT_URL": CLOSED,
    "INSPECTOR_URL": CLOSED,
    "MDR_SERVER_URL": CLOSED,
    "SMTP_HOST": "127.0.0.1",
    "SMTP_PORT": str(CLOSED_PORT),
    "CAPE_API_URL": f"{CLOSED}/cape",
    "COPILOT_WKHTMLTOPDF": os.path.join(SCRATCH, "no-wkhtmltopdf"),
    "COPILOT_CHROMIUM": os.path.join(SCRATCH, "no-chromium"),
}


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
        "COPILOT_CATALOG_REFRESH": "false",
        # No startup work on the shared database (once phase 5A's tasks exist).
        "COPILOT_STARTUP_TASKS": "false",
        "COPILOT_RUN_MIGRATIONS": "false",
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{RECORDER_PORT}",
        "COPILOT_SCHEDULER_OWNER": "rust",
        "COPILOT_SCOUTSUITE_DIR": SCRATCH,
        "COPILOT_BACKEND_DATA_DIR": os.path.join(SCRATCH, "data"),
        "COPILOT_MIMECAST_DIR": os.path.join(SCRATCH, "mimecast"),
        "RUST_LOG": os.environ.get("RUST_LOG", "error"),
        # What both backends read from the environment the runner gives them.
        **{
            k: os.environ[k]
            for k in ("GRAFANA_API_HEADER_VALUE", "VELOCIRAPTOR_QUERY_TIMEOUT", "GRAYLOG_API_HEADER_VALUE", "COPILOT_API_KEY")
            if k in os.environ
        },
        **UPSTREAM_OVERRIDES,
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(150):
        try:
            if httpx.get(f"{RUST}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


def stop_rust(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


# --- the requests ---------------------------------------------------------------------
def param_value(route, name):
    """A value for a path parameter by its annotation (a miss for every lookup)."""
    for p in route.dependant.path_params:
        if p.name != name:
            continue
        ann = p.field_info.annotation
        if isinstance(ann, type) and issubclass(ann, enum.Enum):
            return str(next(iter(ann)).value)
        if ann is int:
            return str(NO_ROW_ID)
        return WORD
    return WORD


def text_param(route, name):
    for p in route.dependant.path_params:
        if p.name == name:
            ann = p.field_info.annotation
            return ann is str
    return True


PARAM = re.compile(r"{([^}:]+)(:[^}]+)?}")


def fill(route, encoded=False):
    """The route's path with its parameters filled; `encoded`: the first text parameter is
    `a%2Fb` (`None` when the route has none)."""
    done = {"enc": not encoded}

    def sub(m):
        name = m.group(1)
        if not done["enc"] and text_param(route, name):
            done["enc"] = True
            return "a%2Fb"
        return param_value(route, name)

    out = PARAM.sub(sub, route.path)
    if not done["enc"]:
        return None
    return out


def api_requests():
    """`(method, route, path)` for every API route and method, in the app's order."""
    out = []
    for r in APP.routes:
        if isinstance(r, APIRoute):
            for m in sorted(r.methods):
                out.append((m, r, fill(r)))
    return out


def normal_headers(r):
    gz = r.headers.get("content-encoding") is not None
    out = []
    for k, v in r.headers.multi_items():
        k = k.lower()
        if k in TRANSPORT_HEADERS or k in RUST_ONLY_HEADERS:
            continue
        v = BOUNDARY.sub("boundary=BOUNDARY", v)
        if k == "content-length" and gz:
            v = "*"
        if k == "vary":
            v = ", ".join(sorted(p.strip().lower() for p in v.split(",")))
        if k == "allow":
            v = ", ".join(sorted(p.strip() for p in v.split(",")))
        out.append((k, v))
    return sorted(out)


def answer(r, adjust=None):
    body = r.content.decode("utf-8", "replace")
    if adjust is not None:
        body = adjust(body)
    return (r.status_code, body, normal_headers(r))


class Probe:
    def __init__(self, recorder):
        self.recorder = recorder
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=APP, raise_app_exceptions=False),
            base_url="http://127.0.0.1:5000",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=RUST, timeout=120)
        self.leaks = []
        self.timeouts = []

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()

    async def rust(self, method, path, headers=None, content=None):
        probe_id = uuid.uuid4().hex
        h = {"X-Probe-Id": probe_id, **(headers or {})}
        try:
            r = await self.rs.request(method, path, headers=h, content=content)
        except httpx.TimeoutException:
            self.timeouts.append((method, path))
            r = None
        if r is not None and r.status_code == 599:
            self.leaks.append((method, path, "599"))
        return r

    async def python(self, method, path, headers=None, content=None):
        return await self.py.request(method, path, headers=headers or {}, content=content)

    def leaked(self):
        got = self.recorder.take()
        return got


async def gather_limited(coros, limit):
    sem = asyncio.Semaphore(limit)

    async def run(c):
        async with sem:
            return await c

    return await asyncio.gather(*(run(c) for c in coros))


async def compare_all(probe, label, items):
    """`items`: `(name, method, path, headers, adjust)`; both answers compared."""
    rs = await gather_limited([probe.rust(m, p, h) for _, m, p, h, _ in items], 16)
    py = await gather_limited([probe.python(m, p, h) for _, m, p, h, _ in items], 8)
    mismatched = []
    for (name, _m, _p, _h, adjust), a, b in zip(items, py, rs):
        if b is None:
            mismatched.append((name, "rust timed out"))
            continue
        pa, ra = answer(a, adjust), answer(b, adjust)
        if pa != ra:
            mismatched.append((name, f"python {pa[0]} {pa[1][:300]} {pa[2]}\n          rust   {ra[0]} {ra[1][:300]} {ra[2]}"))
    check(
        f"{label}: {len(items)} requests answered as Python answers them",
        not mismatched,
        "\n        ".join(f"{n}: {d}" for n, d in mismatched[:25])
        + (f"\n        … {len(mismatched)} in all" if len(mismatched) > 25 else ""),
    )
    return mismatched


# --- sections -------------------------------------------------------------------------
async def section_a(probe):
    print("A. every route, without a token")
    items = [(f"{m} {p}", m, p, None, None) for m, r, p in api_requests() if (m, r.path) not in BY_DESIGN]
    await compare_all(probe, "A", items)


async def section_b(probe):
    print("B. every route with an encoded '/' in a parameter, without a token")
    items = []
    for m, r, _p in api_requests():
        enc = fill(r, encoded=True)
        if enc is not None:
            items.append((f"{m} {enc}", m, enc, None, None))
    await compare_all(probe, "B", items)


async def section_c(probe):
    print("C. every route with an admin's token and an empty body (Rust)")
    admin = token(ADMIN, ["admin"])
    analyst = token(ANALYST, ["analyst"])
    reqs = []
    for m, r, p in api_requests():
        tok = analyst if (m == "DELETE" and r.path == "/api/logs") else admin
        reqs.append((m, p, tok))
        enc = fill(r, encoded=True)
        if enc is not None:
            reqs.append((m, enc, tok))
    answers = await gather_limited([probe.rust(m, p, {"Authorization": f"Bearer {t}"}) for m, p, t in reqs], 16)
    statuses = {}
    for a in answers:
        if a is not None:
            statuses[a.status_code] = statuses.get(a.status_code, 0) + 1
    check(f"C: {len(reqs)} requests answered by Rust", all(a is not None for a in answers), f"timeouts: {probe.timeouts[:10]}")
    print(f"        statuses: {dict(sorted(statuses.items()))}")


def mask_openapi(body):
    try:
        doc = json.loads(body)
    except ValueError:
        return body
    try:
        stamp = doc["components"]["schemas"]["LogRetrieveModel"]["properties"]["timestamp"]["examples"][0]
    except (KeyError, IndexError, TypeError):
        return body
    return body.replace(json.dumps(stamp), '"<import time>"')


async def section_d(probe):
    print("D. what is not an API route")
    origin = {"Origin": "https://ui.example"}
    preflight = {
        "Origin": "https://ui.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, x-thing",
    }
    bad_preflight = {"Origin": "https://ui.example", "Access-Control-Request-Method": "BREW"}
    items = [
        ("no route under a router", "GET", "/api/agents/a/b/c/d", None, None),
        ("trailing slash", "GET", "/api/agents/", None, None),
        ("HEAD of an API route", "HEAD", "/api/agents", None, None),
        ("OPTIONS of an API route", "OPTIONS", "/api/agents", None, None),
        ("PATCH of a GET route", "PATCH", "/api/agents", None, None),
        ("CORS preflight", "OPTIONS", "/api/agents", preflight, None),
        ("CORS preflight, refused method", "OPTIONS", "/api/agents", bad_preflight, None),
        ("CORS preflight of no route", "OPTIONS", "/api/agents/a/b/c", preflight, None),
        ("CORS simple request", "GET", "/api/agents", origin, None),
        ("CORS on a 404", "GET", "/api/agents/a/b/c", origin, None),
        ("CORS on a public route", "GET", "/api/customer_portal/settings", origin, None),
        ("/docs", "GET", "/docs", None, None),
        ("HEAD /docs", "HEAD", "/docs", None, None),
        ("POST /docs", "POST", "/docs", None, None),
        ("/docs/oauth2-redirect", "GET", "/docs/oauth2-redirect", None, None),
        ("/redoc", "GET", "/redoc", None, None),
        ("/openapi.json", "GET", "/openapi.json", None, mask_openapi),
        ("/openapi.json gzipped", "GET", "/openapi.json", {"Accept-Encoding": "gzip"}, mask_openapi),
        ("HEAD /openapi.json", "HEAD", "/openapi.json", None, None),
        ("GET /", "GET", "/", None, None),
        ("POST /", "POST", "/", None, None),
        ("/docs/", "GET", "/docs/", None, None),
        ("static index", "GET", "/scoutsuite-report/index.html", None, None),
        ("static js gzipped", "GET", "/scoutsuite-report/report.js", {"Accept-Encoding": "gzip"}, None),
        ("static json", "GET", "/scoutsuite-report/sub/data.json", None, None),
        ("static HEAD", "HEAD", "/scoutsuite-report/plain.txt", None, None),
        ("static POST", "POST", "/scoutsuite-report/plain.txt", None, None),
        ("static missing", "GET", "/scoutsuite-report/missing.txt", None, None),
        ("static directory", "GET", "/scoutsuite-report/sub", None, None),
        ("static root", "GET", "/scoutsuite-report/", None, None),
        ("static mount without slash", "GET", "/scoutsuite-report", None, None),
        ("static escaping, encoded", "GET", "/scoutsuite-report/%2E%2E/outside.txt", None, None),
        ("static escaping, encoded slash", "GET", "/scoutsuite-report/..%2Foutside.txt", None, None),
        ("static escaping through a link", "GET", "/scoutsuite-report/outside-link", None, None),
        ("static encoded slash", "GET", "/scoutsuite-report/sub%2Fdata.json", None, None),
        ("static range", "GET", "/scoutsuite-report/plain.txt", {"Range": "bytes=0-4"}, None),
        (
            "static ranges",
            "GET",
            "/scoutsuite-report/plain.txt",
            {"Range": "bytes=0-1,4-5"},
            lambda b: re.sub(r"[0-9a-f]{20,}", "BOUNDARY", b),
        ),
        ("static bad range", "GET", "/scoutsuite-report/plain.txt", {"Range": "bytes=50-60"}, None),
        ("static modified since", "GET", "/scoutsuite-report/plain.txt", {"If-Modified-Since": "Wed, 15 Nov 2023 00:00:00 GMT"}, None),
        ("static not modified since", "GET", "/scoutsuite-report/plain.txt", {"If-Modified-Since": "Thu, 16 Nov 2023 00:00:00 GMT"}, None),
    ]
    # The etag both answer with: `If-None-Match` then.
    first = await probe.python("GET", "/scoutsuite-report/plain.txt")
    etag = first.headers.get("etag")
    items.append(("static if-none-match", "GET", "/scoutsuite-report/plain.txt", {"If-None-Match": etag or ""}, None))
    items.append(("static if-none-match, other", "GET", "/scoutsuite-report/plain.txt", {"If-None-Match": '"other"'}, None))
    await compare_all(probe, "D", items)


async def section_e(probe):
    print("E. the Scheduler's writes under the ownership (COPILOT_SCHEDULER_OWNER=rust)")
    saved = await rows("SELECT * FROM scheduled_job_metadata")
    store = await rows("SELECT id, next_run_time FROM apscheduler_jobs")
    admin = {"Authorization": f"Bearer {token(ADMIN, ['admin'])}"}
    job = saved[0]["job_id"] if saved else "agent_sync"
    reqs = [
        ("GET", "/api/scheduler"),
        ("GET", f"/api/scheduler/{job}"),
        ("GET", f"/api/scheduler/next_run/{job}"),
        ("POST", f"/api/scheduler/pause/{job}"),
        ("POST", f"/api/scheduler/start/{job}"),
        ("PUT", f"/api/scheduler/update/{job}?time_interval=37"),
        ("POST", f"/api/scheduler/jobs/run/{job}"),
        ("DELETE", f"/api/scheduler/{job}"),
        ("POST", "/api/scheduler/add?job_id=x&time_interval=5"),
        ("POST", "/api/scheduler/provisioning_jobs"),
        ("POST", "/api/scheduler/apscheduler_ops"),
    ]
    statuses = []
    try:
        for m, p in reqs:
            r = await probe.rust(m, p, admin)
            statuses.append((m, p, None if r is None else r.status_code))
    finally:
        await sql("DELETE FROM scheduled_job_metadata")
        for row in saved:
            cols = ", ".join(row)
            await sql(f"INSERT INTO scheduled_job_metadata ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    after = await rows("SELECT id, next_run_time FROM apscheduler_jobs")
    check("E: APScheduler's store untouched", after == store, f"before {store}\n        after  {after}")
    print(f"        statuses: {statuses}")


OUTSIDE = (
    ("GET", "/zz-outside-every-router/x", None),
    ("GET", "/api/zz-no-router/x", None),
    ("GET", "//api/agents", None),
    ("GET", "/api/zz-no-router/x", {"Origin": "https://ui.example"}),
)


async def section_f(probe):
    print("F. a path outside every Python router (the legacy backend, kept for a staged rollout)")
    for m, p, h in OUTSIDE:
        r = await probe.rust(m, p, h)
        got = probe.recorder.take()
        # Its answer is the legacy backend's, CORS included: nothing added here.
        passed = r is not None and r.status_code == 599 and len(got) == 1 and "access-control-allow-origin" not in r.headers
        check(f"F: {m} {p}{' (CORS)' if h else ''} forwarded once, answered as it came back", passed, f"{got}")
    outside = {p for _, p, _ in OUTSIDE}
    probe.leaks = [x for x in probe.leaks if x[1] not in outside]


async def id_tables():
    """The tables with an integer `id` column: `{table: set of ids}`."""
    names = await rows(
        "SELECT TABLE_NAME AS t FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'id' "
        "AND DATA_TYPE IN ('int', 'bigint', 'smallint', 'mediumint', 'tinyint')",
    )
    out = {}
    for r in names:
        t = r["t"]
        out[t] = {x["id"] for x in await rows(f"SELECT id FROM `{t}`")}
    return out


async def plain_counts():
    """The row counts of the tables without an integer `id`."""
    names = await rows(
        "SELECT TABLE_NAME AS t FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' "
        "AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
        "AND COLUMN_NAME = 'id' AND DATA_TYPE IN ('int', 'bigint', 'smallint', 'mediumint', 'tinyint'))",
    )
    return {r["t"]: (await rows(f"SELECT COUNT(*) AS n FROM `{r['t']}`"))[0]["n"] for r in names}


async def drop_new_rows(before):
    """Every row the probe's requests created, by its exact id (a few passes, for the foreign keys)."""
    left = {}
    for _ in range(4):
        left = {}
        for t, ids in before.items():
            now = {x["id"] for x in await rows(f"SELECT id FROM `{t}`")}
            new = sorted(now - ids)
            if not new:
                continue
            try:
                for i in range(0, len(new), 500):
                    chunk = new[i : i + 500]
                    await sql(f"DELETE FROM `{t}` WHERE id IN ({', '.join(str(int(x)) for x in chunk)})")
            except Exception as e:  # noqa: BLE001 - a foreign key: the next pass
                left[t] = (len(new), type(e).__name__)
        if not left:
            break
    return left


async def seed_users():
    for name, role in ((ADMIN, 1), (ANALYST, 2)):
        await sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r)",
            n=name,
            e=f"{name}@parity.test",
            r=role,
        )


async def drop_users():
    for name in (ADMIN, ANALYST):
        await sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        await sql("DELETE FROM `user` WHERE username = :n", n=name)


async def main():
    # What the probe's requests write (log rows, a settings row a read creates, …) is taken out
    # again at the end, by id; the tables without one are only compared.
    before_ids = await id_tables()
    before_counts = await plain_counts()
    await seed_users()
    saved_connectors = await rows("SELECT id, connector_url, connector_api_key FROM connectors")
    saved_defaults = await rows("SELECT * FROM customer_provisioning_default_settings")
    for row in saved_connectors:
        await sql("UPDATE connectors SET connector_url = :u WHERE id = :i", u=f"{CLOSED}/connector-{row['id']}", i=row["id"])
    recorder = Recorder(RECORDER_PORT)
    proc = start_rust()
    probe = Probe(recorder)
    try:
        for section in (section_a, section_b, section_c, section_d):
            await section(probe)
            got = recorder.take()
            check(f"{section.__name__}: the legacy backend received nothing", not got, f"{got[:20]}")
        await section_e(probe)
        got = recorder.take()
        check("section_e: the legacy backend received nothing", not got, f"{got[:20]}")
        await section_f(probe)
        check("no answer came from the legacy backend", not probe.leaks, f"{probe.leaks[:20]}")
    finally:
        await probe.close()
        stop_rust(proc)
        recorder.stop()
        for row in saved_connectors:
            await sql(
                "UPDATE connectors SET connector_url = :u, connector_api_key = :k WHERE id = :i",
                u=row["connector_url"],
                k=row["connector_api_key"],
                i=row["id"],
            )
        await sql("DELETE FROM customer_provisioning_default_settings")
        for row in saved_defaults:
            cols = ", ".join(row)
            await sql(f"INSERT INTO customer_provisioning_default_settings ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
        await drop_users()
        left = await drop_new_rows(before_ids)
        check("the rows the probe's requests created are gone", not left, f"{left}")
        after_counts = await plain_counts()
        changed = {t: (before_counts.get(t), n) for t, n in after_counts.items() if before_counts.get(t) != n}
        check("the tables without an id hold as many rows as before", not changed, f"{changed}")
        await async_engine.dispose()
    passed = sum(1 for _, ok in results if ok)
    print(f"{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
