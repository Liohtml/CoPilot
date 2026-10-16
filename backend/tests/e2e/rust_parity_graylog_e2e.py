"""Parity of the Rust Graylog, InfluxDB, Grafana and Portainer connectors with this backend —
NOT collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts (no legacy backend,
connector cache off, so a connector row changed between checks is seen at once by both) answer
the same requests on one database. The tools themselves are local stand-ins that record every
request: Graylog with a 6.x and a 7.x personality, the Event Shipper's GELF TCP input,
InfluxDB 2.7's query API (annotated CSV from `connector_samples.influx_answer`), Grafana 11's
HTTP API (organizations, search, dashboards, org users) and Portainer 2.21's (JWT login,
endpoints, swarm nodes, stacks). For
each request the suite compares the status, the response **bytes**, and every request each
backend sent to the tool (method, target, the headers that matter, body bytes). urllib3 prints
an object's memory address in a connection error, which differs between any two processes; it
is masked. Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_graylog_e2e.py scripts/rust-parity.sh

`CONNECTOR_PARITY_SECTIONS=graylog,influxdb,grafana,portainer` (the default) picks the connectors
to check.
"""

import asyncio
import copy
import datetime
import gzip
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
# Read at import by app.connectors.cache: every request re-reads the connector row, as the
# Rust instance below does.
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
ADMIN, ANALYST, PORTAL = f"gl_admin{SFX}", f"gl_analyst{SFX}", f"gl_portal{SFX}"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
# Ports: the Rust instance and the stand-ins (5690-5695; 5696-5699 belong to the shared harness).
RS_PORT = int(os.environ.get("GRAYLOG_PARITY_RUST_PORT", "5695"))
GRAYLOG_PORT = int(os.environ.get("GRAYLOG_STUB_PORT", "5690"))
INFLUX_PORT = int(os.environ.get("INFLUX_STUB_PORT", "5691"))
GRAFANA_PORT = int(os.environ.get("GRAFANA_STUB_PORT", "5692"))
PORTAINER_PORT = int(os.environ.get("PORTAINER_STUB_PORT", "5693"))
GELF_PORT = int(os.environ.get("GELF_STUB_PORT", "5694"))
CLOSED_PORT = 1
OUR_CONNECTORS = ("Graylog", "Event Shipper", "InfluxDB", "Grafana", "Portainer")
INFLUX_URL = f"http://127.0.0.1:{INFLUX_PORT}"
INFLUX_TOKEN = "influx-token"
INFLUX_EXTRA = "SOC FORTRESS,telegraf"
GRAFANA_URL = f"http://127.0.0.1:{GRAFANA_PORT}"
GRAFANA_USER, GRAFANA_PASSWORD = "admin", "grafana-pässword"
PORTAINER_URL = f"http://127.0.0.1:{PORTAINER_PORT}"
PORTAINER_USER, PORTAINER_PASSWORD = "admin", "portainer-pw"
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
    """What a stand-in was asked: (method, target, selected headers, body)."""

    HEADERS = ("authorization", "x-requested-by", "content-type", "content-length")

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, method, target, headers, body):
        kept = {k: headers.get(k) for k in self.HEADERS if headers.get(k) is not None}
        with self.lock:
            self.requests.append((method, target, kept, body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


def _json(value):
    return json.dumps(value).encode()


class Graylog:
    """Graylog 6.1 or 7.0, with per-test overrides."""

    def __init__(self):
        self.version = 6
        self.overrides = {}
        self.deleted_indices = set()
        self.delete_removes = True
        self.page_size = 500

    def reset(self, version=6):
        self.version = version
        self.overrides = {}
        self.deleted_indices = set()
        self.delete_removes = True
        self.page_size = 500

    def answer(self, method, target, body):
        parts = urlsplit(target)
        path, query = parts.path, parse_qs(parts.query)
        key = (method, path)
        if key in self.overrides:
            return self.overrides[key]
        not_found = (404, "application/json", _json({"type": "ApiError", "message": "HTTP 404 Not Found"}))
        if method == "GET" and path == "/api/system":
            return 200, "application/json", _json(samples.GRAYLOG_SYSTEM_7 if self.version == 7 else samples.GRAYLOG_SYSTEM_6)
        if method == "GET" and path == "/api/system/indexer/indices":
            data = copy.deepcopy(samples.GRAYLOG_INDICES)
            for name in self.deleted_indices:
                data["all"]["indices"].pop(name, None)
            return 200, "application/json", _json(data)
        if method == "DELETE" and path.startswith("/api/system/indexer/indices/"):
            if self.delete_removes:
                self.deleted_indices.add(path.rsplit("/", 1)[1])
            return 204, None, b""
        if method == "GET" and path == "/api/system/inputs":
            return 200, "application/json", _json(samples.graylog_inputs(self.version))
        if method == "GET" and path == "/api/system/inputstates":
            return 200, "application/json", _json(samples.graylog_input_states(self.version))
        if method in ("DELETE", "PUT") and path.startswith("/api/system/inputstates/"):
            return 200, "application/json", _json({"id": path.rsplit("/", 1)[1]})
        if method == "GET" and path == "/api/events/definitions":
            page = int(query.get("page", ["1"])[0])
            size = self.page_size
            defs = samples.GRAYLOG_EVENT_DEFINITIONS
            batch = defs[(page - 1) * size : page * size]
            return 200, "application/json", _json({"event_definitions": batch, "total": len(defs), "page": page, "per_page": size})
        if method == "POST" and path == "/api/events/search":
            return 200, "application/json", _json(samples.GRAYLOG_EVENTS_SEARCH)
        if method == "GET" and path == "/api/system/urlallowlist":
            return (200, "application/json", _json(samples.GRAYLOG_URL_ALLOWLIST)) if self.version == 7 else not_found
        if method == "GET" and path == "/api/system/urlwhitelist":
            return (200, "application/json", _json(samples.GRAYLOG_URL_ALLOWLIST)) if self.version == 6 else not_found
        if method == "POST" and re.fullmatch(r"/api/streams/[^/]+/(pause|resume)", path):
            return 204, None, b""
        if method == "GET" and path == "/api/system/messages":
            return 200, "application/json", _json(samples.GRAYLOG_MESSAGES)
        if method == "GET" and path == "/api/system/metrics":
            return 200, "application/json", _json(samples.GRAYLOG_METRICS)
        if method == "GET" and path == "/api/system/journal":
            return 200, "application/json", _json(samples.GRAYLOG_JOURNAL)
        if method == "GET" and path == "/api/events/notifications":
            return 200, "application/json", _json(samples.GRAYLOG_EVENT_NOTIFICATIONS)
        if method == "GET" and path == "/api/streams":
            return 200, "application/json", _json(samples.GRAYLOG_STREAMS)
        if method == "GET" and path == "/api/system/pipelines/pipeline":
            return 200, "application/json", _json(samples.GRAYLOG_PIPELINES)
        if method == "GET" and path == "/api/system/pipelines/rule":
            return 200, "application/json", _json(samples.GRAYLOG_PIPELINE_RULES)
        if method == "GET" and path.startswith("/api/system/pipelines/rule/"):
            rule_id = path.rsplit("/", 1)[1]
            for rule in samples.GRAYLOG_PIPELINE_RULES:
                if rule["id"] == rule_id:
                    return 200, "application/json", _json(rule)
            return 404, "application/json", _json({"type": "ApiError", "message": f"Couldn't find rule {rule_id}"})
        return not_found


GRAYLOG = Graylog()
RECORDER = Recorder()


class InfluxRecorder(Recorder):
    HEADERS = ("authorization", "content-type", "content-length", "accept", "user-agent", "accept-encoding")


INFLUX_ERROR_HEADERS = [
    ("Content-Type", "application/json; charset=utf-8"),
    ("X-Influxdb-Build", "OSS"),
    ("X-Influxdb-Version", "v2.7.11"),
]


class InfluxDB:
    """InfluxDB 2.7's `POST /api/v2/query`, with per-test overrides and two broken modes
    (`silent`: never answers; `close`: hangs up without an answer)."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.override = None
        self.csv = None
        self.csv_for = {}
        self.gzip = False
        self.mode = None
        self.statuses = copy.deepcopy(samples.INFLUX_STATUSES)

    def answer(self, method, target, body, headers):
        if (method, urlsplit(target).path) != ("POST", "/api/v2/query"):
            return 404, None, INFLUX_ERROR_HEADERS, _json({"code": "not found", "message": "path not found"})
        if self.override:
            return self.override
        query = json.loads(body)["query"]
        text = self.csv
        for needle, csv_text in self.csv_for.items():
            if needle in query:
                text = csv_text
        if text is None:
            text = samples.influx_answer(query, self.statuses)
        payload = text.encode() if isinstance(text, str) else text
        out = [("Content-Type", "text/csv; charset=utf-8"), ("Vary", "Accept-Encoding"), ("X-Influxdb-Build", "OSS")]
        if self.gzip and "gzip" in (headers.get("accept-encoding") or ""):
            payload = gzip.compress(payload)
            out.append(("Content-Encoding", "gzip"))
        return 200, None, out, payload


INFLUX = InfluxDB()
INFLUX_RECORDER = InfluxRecorder()


class GrafanaRecorder(Recorder):
    HEADERS = ("authorization", "content-type", "content-length", "user-agent", "accept")


def _grafana_auth(user, password):
    import base64

    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Grafana:
    """Grafana 11's API as CoPilot uses it: organizations, the current org of the admin user,
    search, dashboards by uid, org users."""

    USERS = {"a@b.c", "viewer@acme.io", "é@exämple.io"}

    def __init__(self):
        self.reset()

    def reset(self):
        self.overrides = {}
        self.current_org = 1
        self.members = {1: {"a@b.c"}, 44: {"viewer@acme.io"}}

    def answer(self, method, target, body, headers):
        path = urlsplit(target).path
        for (m, prefix), answer in self.overrides.items():
            if m == method and path.startswith(prefix):
                return answer
        if headers.get("authorization") != _grafana_auth(GRAFANA_USER, GRAFANA_PASSWORD):
            return (
                401,
                "application/json",
                _json({"message": "Invalid username or password", "messageId": "password-auth.failed", "statusCode": 401, "traceID": ""}),
            )
        not_found = (404, "application/json", _json({"message": "Not found"}))
        org_ids = {o["id"] for o in samples.GRAFANA_ORGS}
        if method == "GET" and path == "/api/orgs":
            return 200, "application/json", _json(samples.GRAFANA_ORGS)
        m = re.fullmatch(r"/api/user/using/(-?\d+)", path)
        if method == "POST" and m:
            if int(m.group(1)) not in org_ids:
                return 401, "application/json", _json({"message": "Not a valid organization"})
            self.current_org = int(m.group(1))
            return 200, "application/json", _json({"message": "Active organization changed"})
        if method == "GET" and path == "/api/search":
            return 200, "application/json", _json(samples.GRAFANA_SEARCH.get(self.current_org, []))
        if method == "GET" and path.startswith("/api/dashboards/uid/"):
            if path.rsplit("/", 1)[1] == samples.GRAFANA_DASHBOARD["dashboard"]["uid"]:
                return 200, "application/json", _json(samples.GRAFANA_DASHBOARD)
            return 404, "application/json", _json({"message": "Dashboard not found", "traceID": ""})
        m = re.fullmatch(r"/api/orgs/([^/]+)/users", path)
        if method == "POST" and m:
            if not m.group(1).isdigit() or int(m.group(1)) not in org_ids:
                return 404, "application/json", _json({"message": "Organization not found"})
            login = json.loads(body).get("loginorEmail")
            if login not in self.USERS:
                return 404, "application/json", _json({"message": "User not found"})
            if login in self.members.setdefault(int(m.group(1)), set()):
                return 409, "application/json", _json({"message": "User is already member of this organization"})
            self.members[int(m.group(1))].add(login)
            return 200, "application/json", _json({"message": "User added to organization", "userId": 7})
        return not_found


GRAFANA = Grafana()
GRAFANA_RECORDER = GrafanaRecorder()

CLOSE = object()


class Portainer:
    """Portainer 2.21 on a swarm: the JWT login, environments, nodes, stacks."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.overrides = {}
        self.stacks = {s["Id"]: copy.deepcopy(s) for s in samples.PORTAINER_STACKS}

    def answer(self, method, target, body, headers):
        parts = urlsplit(target)
        path, query = parts.path, parse_qs(parts.query)
        key = (method, path)
        if key in self.overrides:
            return self.overrides[key]
        if method == "POST" and path == "/api/auth":
            creds = json.loads(body or b"null") or {}
            if creds.get("username") == PORTAINER_USER and creds.get("password") == PORTAINER_PASSWORD:
                return 200, "application/json", _json({"jwt": samples.PORTAINER_JWT})
            return 422, "application/json", _json({"message": "Invalid credentials", "details": "Unauthorized"})
        if headers.get("authorization") != f"Bearer {samples.PORTAINER_JWT}":
            return 401, "application/json", _json({"message": "Invalid JWT token", "details": "Unauthorized"})
        not_found = (
            404,
            "application/json",
            _json(
                {
                    "message": "Unable to find a stack with the specified identifier inside the database",
                    "details": "Object not found inside the database",
                },
            ),
        )
        if method == "GET" and path == "/api/endpoints":
            return 200, "application/json", _json(samples.PORTAINER_ENDPOINTS)
        if method == "GET" and path == "/api/endpoints/1/docker/nodes":
            return 200, "application/json", _json(samples.PORTAINER_NODES)
        if method == "GET" and path == "/api/stacks":
            return 200, "application/json", _json(list(self.stacks.values()))
        m = re.fullmatch(r"/api/stacks/(\d+)(?:/(start|stop))?", path)
        if m and query.get("endpointId") == ["1"]:
            stack = self.stacks.get(int(m.group(1)))
            if stack is None:
                return not_found
            if method == "GET" and not m.group(2):
                return 200, "application/json", _json(stack)
            if method == "POST" and m.group(2):
                want = 1 if m.group(2) == "start" else 2
                if stack["Status"] == want:
                    return 400, "application/json", _json({"message": f"Stack is already {'active' if want == 1 else 'inactive'}"})
                stack["Status"] = want
                return 200, "application/json", _json(stack)
            if method == "DELETE" and not m.group(2):
                del self.stacks[stack["Id"]]
                return 204, None, b""
        return 404, "application/json", _json({"message": "Not found", "details": "Not found"})


PORTAINER = Portainer()
PORTAINER_RECORDER = Recorder()
RECORDERS = (RECORDER, INFLUX_RECORDER, GRAFANA_RECORDER, PORTAINER_RECORDER)


def make_grafana_handler(tool, recorder):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            recorder.add(self.command, self.path, headers, body)
            answer = tool.answer(self.command, self.path, body, headers)
            if answer is CLOSE:
                return
            status, ctype, payload = answer
            self.send_response_only(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _serve  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    return Handler


def make_influx_handler(tool, recorder):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            recorder.add(self.command, self.path, headers, body)
            if tool.mode == "close":
                return
            if tool.mode == "silent":
                time.sleep(12)
                return
            status, reason, out, payload = tool.answer(self.command, self.path, body, headers)
            self.send_response_only(status, reason)
            for k, v in out:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _serve  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler


def make_handler(tool, recorder):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            recorder.add(self.command, self.path, headers, body)
            status, ctype, payload = tool.answer(self.command, self.path, body)
            self.send_response_only(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _serve  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    return Handler


def start_http_stub(port, tool, recorder, handler=None):
    server = ThreadingHTTPServer(("127.0.0.1", port), (handler or make_handler)(tool, recorder))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


GELF_FRAMES = []
GELF_LOCK = threading.Lock()


class _GelfHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.read()
        with GELF_LOCK:
            GELF_FRAMES.append(data)


def start_gelf_stub(port):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), _GelfHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def take_gelf(expected, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with GELF_LOCK:
            if len(GELF_FRAMES) >= expected:
                break
        time.sleep(0.02)
    time.sleep(0.05)
    with GELF_LOCK:
        out, GELF_FRAMES[:] = list(GELF_FRAMES), []
    return out


# --- Database ---------------------------------------------------------------------------------------

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
    set_connector("Graylog", f"http://127.0.0.1:{GRAYLOG_PORT}", "admin", "pässword")
    set_connector("Event Shipper", "127.0.0.1", extra=str(GELF_PORT))
    set_connector("InfluxDB", INFLUX_URL, api_key=INFLUX_TOKEN, extra=INFLUX_EXTRA)
    set_connector("Grafana", GRAFANA_URL, GRAFANA_USER, GRAFANA_PASSWORD)
    set_connector("Portainer", PORTAINER_URL, PORTAINER_USER, PORTAINER_PASSWORD)
    for i, (name, stack_id) in enumerate(PORTAINER_CUSTOMERS):
        code = f"pt{i}{SFX}"
        sql(
            "INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())",
            c=code,
            n=name[:50],
        )
        sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group, customer_meta_portainer_stack_id) "
            "VALUES (:c, :n, 'i', 's', '1', 'g', :sid)",
            c=code,
            n=name,
            sid=stack_id,
        )


PORTAINER_CUSTOMERS = [
    (f"Portainer Co {SFX}", 5),
    (f"No Stack Co {SFX}", None),
    (f"Zero Stack Co {SFX}", 0),
    (f"Twice Co {SFX}", 8),
    (f"Twice Co {SFX}", 9),
]


def portainer_cleanup():
    for i in range(len(PORTAINER_CUSTOMERS)):
        sql("DELETE FROM customersmeta WHERE customer_code = :c", c=f"pt{i}{SFX}")
        sql("DELETE FROM customers WHERE customer_code = :c", c=f"pt{i}{SFX}")


def cleanup():
    portainer_cleanup()
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in (ADMIN, ANALYST, PORTAL):
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)


# --- The two backends -------------------------------------------------------------------------------


def build_python_app():
    # First, as in copilot.py's import order: `typing` caches `Dict[str, Union[...]]` by set
    # equality, so whichever module spells `Union[List[str], str]` first decides the member
    # order of AlertQuery.filter — and with it the order of its union errors in a 422.
    from app.connectors.graylog.schema import events  # noqa: F401
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import grafana
    from app.routers import graylog
    from app.routers import influxdb
    from app.routers import portainer

    api = APIRouter(prefix="/api")
    api.include_router(graylog.router)
    api.include_router(influxdb.router)
    api.include_router(grafana.router)
    api.include_router(portainer.router)
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
        "COPILOT_PORT": str(RS_PORT),
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


ADDRESS = re.compile(rb"object at 0x[0-9a-f]+")


def normalize(body):
    return ADDRESS.sub(b"object at 0x...", body)


CLOCK = re.compile(rb"from=(-?\d+)&to=(-?\d+)")


def same_clock(b1, b2):
    """The iframe links carry `now` in milliseconds: the two answers may be a second apart, but
    span the same range. Masked once that holds."""
    c1, c2 = CLOCK.findall(b1), CLOCK.findall(b2)
    if len(c1) != len(c2):
        return b1, b2
    for (f1, t1), (f2, t2) in zip(c1, c2):
        if int(t1) - int(f1) != int(t2) - int(f2) or abs(int(t1) - int(t2)) > 5000:
            return b1, b2
    return CLOCK.sub(b"from=F&to=T", b1), CLOCK.sub(b"from=F&to=T", b2)


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        for recorder in RECORDERS:
            recorder.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, [request for recorder in RECORDERS for request in recorder.take()]

    async def same(self, name, method, path, tok=None, before=None, outbound=True, concurrent=False, clock=False, **kw):
        """Python, then Rust, with the stand-in reset by `before` for each.

        `concurrent`: the route sends its requests at once (`asyncio.gather`), so their order
        is not compared, and when both fail Python reports whichever failed first — the
        other request's error is accepted too (RUST_MIGRATION.md §4)."""
        if before:
            before()
        r1, out1 = await self.call(self.py, method, path, tok, **kw)
        if before:
            before()
        r2, out2 = await self.call(self.rs, method, path, tok, **kw)
        b1, b2 = normalize(r1.content), normalize(r2.content)
        if clock:
            b1, b2 = same_clock(b1, b2)
        ok = r1.status_code == r2.status_code and b1 == b2
        if concurrent and not ok and r1.status_code == r2.status_code:
            swapped = b1.replace(b"/journal", b"/__swap__").replace(b"/metrics", b"/journal").replace(b"/__swap__", b"/metrics")
            ok = swapped == b2
        detail = f"python {r1.status_code} {b1[:900]!r}\n        rust   {r2.status_code} {b2[:900]!r}"
        if outbound:
            o1 = [(m, t, h, normalize(b)) for m, t, h, b in out1]
            o2 = [(m, t, h, normalize(b)) for m, t, h, b in out2]
            if concurrent:
                o1, o2 = sorted(o1, key=repr), sorted(o2, key=repr)
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


# --- The checks -------------------------------------------------------------------------------------


async def graylog_checks(p, t_admin, t_analyst, t_portal):
    G = "/api/graylog"
    reads = [
        "/indices",
        "/inputs",
        "/inputs/running",
        "/inputs/configured",
        "/event/definitions",
        "/messages",
        "/metrics",
        "/event_notifications",
        "/streams",
        "/pipelines",
        "/pipeline/full",
        "/pipeline/rules",
        "/pipeline/rules/65a0000000000000000000e1",
    ]
    for version in (6, 7):
        print(f"\n=== Graylog {version}.x: reads ===")
        for path in reads:
            await p.same(
                f"GET {path} (Graylog {version})",
                "GET",
                G + path,
                t_analyst,
                before=lambda v=version: GRAYLOG.reset(v),
                concurrent=path == "/metrics",
            )
        await p.same(
            f"GET /url_whitelist (Graylog {version})",
            "GET",
            G + "/url_whitelist",
            t_admin,
            before=lambda v=version: GRAYLOG.reset(v),
        )

    print("\n=== Graylog: auth ===")
    for path in ("/indices", "/streams", "/pipeline/rules/x"):
        await p.same(f"GET {path}, no token", "GET", G + path)
        await p.same(f"GET {path}, bad token", "GET", G + path, "not-a-jwt")
        await p.same(f"GET {path}, portal user", "GET", G + path, t_portal)
    await p.same("GET /url_whitelist, analyst", "GET", G + "/url_whitelist", t_analyst)
    await p.same("GET /url_whitelist, no token", "GET", G + "/url_whitelist")
    await p.same("GET /url_whitelist, bad token", "GET", G + "/url_whitelist", "not-a-jwt")
    await p.same("POST /input/stop, analyst", "POST", G + "/input/stop", t_analyst, json={"input_id": "x"})
    await p.same("POST /receiver, analyst", "POST", G + "/receiver", t_analyst, json={"integration": "x", "customer_code": "c"})
    await p.same(
        "POST /event/alerts, malformed JSON, no token",
        "POST",
        G + "/event/alerts",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    print("\n=== Graylog: query and path parameters ===")
    for raw in ("2", " 3 ", "007", "1.0", "x", "", "1.5", "99999999999999999999"):
        await p.same(
            f"GET /messages?page_number={raw!r}",
            "GET",
            G + "/messages",
            t_analyst,
            params={"page_number": raw},
            before=GRAYLOG.reset,
        )
    await p.same("GET /pipeline/rules/{unknown}", "GET", G + "/pipeline/rules/nope", t_analyst, before=GRAYLOG.reset)
    await p.same("GET /pipeline/rules/{id with space}", "GET", G + "/pipeline/rules/a%20b", t_analyst, before=GRAYLOG.reset)
    await p.same("GET /pipeline/rules/{encoded slash}", "GET", G + "/pipeline/rules/a%2Fb", t_analyst, before=GRAYLOG.reset)

    print("\n=== Graylog: event search bodies ===")
    bodies = [
        {},
        {"query": "rule_level:>10", "page": 2, "per_page": "25", "filter": {"alerts": "include", "event_definitions": ["a"]}},
        {"timerange": {"range": 3600, "type": "relative"}},
        {"timerange": {"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z", "type": "absolute"}},
        {"query": None, "filter": None, "timerange": None},
        {"page": "x"},
        {"filter": {"alerts": 5}},
        {"timerange": {"range": 1.5}},
        [],
    ]
    for body in bodies:
        await p.same(f"POST /event/alerts {json.dumps(body)[:60]}", "POST", G + "/event/alerts", t_analyst, json=body, before=GRAYLOG.reset)
    await p.same("POST /event/alerts, no body", "POST", G + "/event/alerts", t_analyst, before=GRAYLOG.reset)
    await p.same(
        "POST /event/alerts, text body",
        "POST",
        G + "/event/alerts",
        t_analyst,
        content=b"{}",
        headers={"Content-Type": "text/plain"},
    )

    print("\n=== Graylog: management ===")
    await p.same(
        "DELETE /index (removed)",
        "DELETE",
        G + "/index",
        t_admin,
        json={"index_name": " wazuh-alerts-3x_1 "},
        before=GRAYLOG.reset,
    )

    def keeps():
        GRAYLOG.reset()
        GRAYLOG.delete_removes = False

    await p.same("DELETE /index (still there)", "DELETE", G + "/index", t_admin, json={"index_name": "gl-events_0"}, before=keeps)
    await p.same("DELETE /index (unknown)", "DELETE", G + "/index", t_admin, json={"index_name": "nope"}, before=GRAYLOG.reset)
    await p.same("DELETE /index (bad body)", "DELETE", G + "/index", t_admin, json={"index": 1}, before=GRAYLOG.reset)

    def delete_fails():
        GRAYLOG.reset()
        GRAYLOG.overrides[("DELETE", "/api/system/indexer/indices/gl-events_0")] = (
            400,
            "application/json",
            _json({"message": "Index is the write index"}),
        )

    await p.same(
        "DELETE /index (Graylog refuses)",
        "DELETE",
        G + "/index",
        t_admin,
        json={"index_name": "gl-events_0"},
        before=delete_fails,
    )
    for action in ("stop", "start"):
        await p.same(
            f"POST /input/{action}",
            "POST",
            f"{G}/input/{action}",
            t_admin,
            json={"input_id": "65a000000000000000000001 "},
            before=GRAYLOG.reset,
        )
        await p.same(
            f"POST /input/{action} (unknown)",
            "POST",
            f"{G}/input/{action}",
            t_admin,
            json={"input_id": "nope"},
            before=GRAYLOG.reset,
        )
        await p.same(
            f"POST /stream/{action}",
            "POST",
            f"{G}/stream/{action}",
            t_admin,
            json={"stream_id": "65a0000000000000000000a1"},
            before=GRAYLOG.reset,
        )
        await p.same(
            f"POST /stream/{action} (unknown)",
            "POST",
            f"{G}/stream/{action}",
            t_admin,
            json={"stream_id": "nope"},
            before=GRAYLOG.reset,
        )
        await p.same(f"POST /stream/{action} (no body)", "POST", f"{G}/stream/{action}", t_admin, before=GRAYLOG.reset)

    def input_errors():
        GRAYLOG.reset()
        GRAYLOG.overrides[("DELETE", "/api/system/inputstates/65a000000000000000000001")] = (500, "text/html", b"<html>boom</html>")
        GRAYLOG.overrides[("PUT", "/api/system/inputstates/65a000000000000000000001")] = (
            404,
            "application/json",
            _json({"message": "gone"}),
        )

    await p.same(
        "POST /input/stop (Graylog 500, not JSON)",
        "POST",
        G + "/input/stop",
        t_admin,
        json={"input_id": "65a000000000000000000001"},
        before=input_errors,
    )
    await p.same(
        "POST /input/start (Graylog 404)",
        "POST",
        G + "/input/start",
        t_admin,
        json={"input_id": "65a000000000000000000001"},
        before=input_errors,
    )

    def pause_fails():
        GRAYLOG.reset()
        GRAYLOG.overrides[("POST", "/api/streams/65a0000000000000000000a1/pause")] = (403, "application/json", _json({"message": ""}))
        GRAYLOG.overrides[("POST", "/api/streams/65a0000000000000000000a1/resume")] = (500, "application/json", _json([1]))

    await p.same(
        "POST /stream/stop (Graylog 403, empty message)",
        "POST",
        G + "/stream/stop",
        t_admin,
        json={"stream_id": "65a0000000000000000000a1"},
        before=pause_fails,
    )
    await p.same(
        "POST /stream/start (Graylog 500, a list)",
        "POST",
        G + "/stream/start",
        t_admin,
        json={"stream_id": "65a0000000000000000000a1"},
        before=pause_fails,
    )

    print("\n=== Graylog: what the tool answers ===")
    weird = [
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {"indices": [{"index_name": "x", **samples._index_info(1)}]}})),
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {}})),
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {"indices": "x"}})),
        ("GET", "/api/system/indexer/indices", 200, _json({"all": {"indices": {"x": {"routing": []}}}})),
        ("GET", "/api/system/indexer/indices", 200, _json([])),
        ("GET", "/api/system/indexer/indices", 500, _json({"message": "OpenSearch down"})),
        ("GET", "/api/system/indexer/indices", 404, b"<html>not here</html>"),
        ("GET", "/api/system/indexer/indices", 404, _json({"nope": 1})),
        ("GET", "/api/system/indexer/indices", 200, b"not json"),
        ("GET", "/api/system/indexer/indices", 200, b""),
        ("GET", "/api/system/inputs", 200, _json({"inputs": [{"title": 5}]})),
        ("GET", "/api/system/inputs", 200, _json({"inputs": ["x"]})),
        ("GET", "/api/system/inputs", 200, _json({"inputs": {"a": 1}})),
        ("GET", "/api/system/inputs", 200, _json({})),
        ("GET", "/api/system/inputstates", 200, _json({"states": None})),
        ("GET", "/api/events/definitions", 200, _json({"event_definitions": [{"id": "x"}], "total": 1})),
        ("GET", "/api/events/definitions", 200, _json({"total": 1})),
        ("GET", "/api/events/definitions", 200, _json({"event_definitions": [], "total": "3"})),
        ("GET", "/api/events/definitions", 200, _json({"event_definitions": []})),
        ("GET", "/api/system/messages", 200, _json({"messages": [{"caller": "a"}], "total": 1})),
        ("GET", "/api/system/messages", 200, _json({"messages": ["x"], "total": 1})),
        ("GET", "/api/system/messages", 200, _json({"messages": [], "total": "many"})),
        ("GET", "/api/system/messages", 200, _json({"messages": []})),
        ("GET", "/api/system/metrics", 200, _json({"gauges": {}, "counters": []})),
        ("GET", "/api/system/metrics", 200, _json({"gauges": {"org.graylog2.throughput.input": 5}, "counters": {}})),
        ("GET", "/api/system/metrics", 200, _json({"gauges": {"org.graylog2.throughput.input": {"value": "x"}}, "counters": {}})),
        ("GET", "/api/system/metrics", 200, _json({"counters": {}})),
        ("GET", "/api/system/journal", 200, _json({})),
        ("GET", "/api/events/notifications", 200, _json({"total": 1})),
        ("GET", "/api/events/notifications", 200, _json(None)),
        ("GET", "/api/streams", 200, _json({"streams": [], "total": "two"})),
        ("GET", "/api/streams", 200, _json({"streams": ["x"], "total": 1})),
        ("GET", "/api/streams", 200, _json({"streams": [{"id": "x"}], "total": 1})),
        ("GET", "/api/streams", 200, _json({"total": 1})),
        ("GET", "/api/system/pipelines/pipeline", 200, _json({"a": 1})),
        ("GET", "/api/system/pipelines/pipeline", 200, _json([{"id": "x", "errors": "boom"}])),
        ("GET", "/api/system/pipelines/pipeline", 200, _json(None)),
        ("GET", "/api/system/pipelines/rule", 200, _json([{"title": "t"}])),
        ("GET", "/api/system/urlallowlist", 200, _json({"entries": [{}], "disabled": "maybe"})),
        ("GET", "/api/system/urlallowlist", 500, b"oops"),
    ]
    routes_for = {
        "/api/system/indexer/indices": ["/indices"],
        "/api/system/inputs": ["/inputs", "/inputs/configured"],
        "/api/system/inputstates": ["/inputs/running"],
        "/api/events/definitions": ["/event/definitions"],
        "/api/system/messages": ["/messages"],
        "/api/system/metrics": ["/metrics"],
        "/api/system/journal": ["/metrics"],
        "/api/events/notifications": ["/event_notifications"],
        "/api/streams": ["/streams"],
        "/api/system/pipelines/pipeline": ["/pipelines", "/pipeline/full"],
        "/api/system/pipelines/rule": ["/pipeline/rules", "/pipeline/full"],
        "/api/system/urlallowlist": ["/url_whitelist"],
    }
    for method, path, status, payload in weird:
        for route in routes_for[path]:

            def before(m=method, pa=path, s=status, b=payload):
                GRAYLOG.reset(7 if pa == "/api/system/urlallowlist" else 6)
                GRAYLOG.overrides[(m, pa)] = (s, "application/json" if b[:1] in (b"{", b"[", b"n") else "text/html", b)

            tok = t_admin if route == "/url_whitelist" else t_analyst
            await p.same(f"GET {route} ← {status} {payload[:50]!r}", "GET", G + route, tok, before=before, concurrent=route == "/metrics")

    def two_pages():
        GRAYLOG.reset()
        GRAYLOG.page_size = 2

    await p.same("GET /event/definitions over two pages", "GET", G + "/event/definitions", t_analyst, before=two_pages)

    def search(payload, status=200):
        def before():
            GRAYLOG.reset()
            GRAYLOG.overrides[("POST", "/api/events/search")] = (status, "application/json", payload)

        return before

    for payload, status in (
        (_json({**samples.GRAYLOG_EVENTS_SEARCH, "events": [{"index_name": "x"}]}), 200),
        (_json({**samples.GRAYLOG_EVENTS_SEARCH, "duration": "slow"}), 200),
        (_json({k: v for k, v in samples.GRAYLOG_EVENTS_SEARCH.items() if k != "context"}), 200),
        (_json({"message": "Search failed"}), 400),
        (b"", 204),
        (b"", 202),
        (b"not json", 200),
    ):
        await p.same(
            f"POST /event/alerts ← {status} {payload[:40]!r}",
            "POST",
            G + "/event/alerts",
            t_analyst,
            json={},
            before=search(payload, status),
        )

    print("\n=== Graylog: connector problems ===")
    for label, url, user in (
        ("connection refused", f"http://127.0.0.1:{CLOSED_PORT}", "admin"),
        ("no scheme", f"127.0.0.1:{GRAYLOG_PORT}", "admin"),
        ("empty URL", "", "admin"),
        ("no host", "http://", "admin"),
        ("bad port", "http://127.0.0.1:99999", "admin"),
        ("ftp", "ftp://127.0.0.1", "admin"),
        ("trailing slash", f"http://127.0.0.1:{GRAYLOG_PORT}/", None),
        ("non-latin-1 user", f"http://127.0.0.1:{GRAYLOG_PORT}", "€uro"),
        ("unknown host", "http://nonexistent.invalid:9000", "admin"),
        ("hangs up", INFLUX_URL, "admin"),
    ):
        set_connector("Graylog", url, user, "pw")

        def before():
            GRAYLOG.reset()
            INFLUX.reset()
            INFLUX.mode = "close"

        for route in ("/indices", "/streams", "/pipeline/rules/x"):
            await p.same(f"GET {route} ({label})", "GET", G + route, t_analyst, before=before)
        await p.same(f"POST /event/alerts ({label})", "POST", G + "/event/alerts", t_analyst, json={}, before=before)
        if label not in ("connection refused", "unknown host", "hangs up"):
            await p.same(f"GET /metrics ({label})", "GET", G + "/metrics", t_analyst, before=before, concurrent=True)
    INFLUX.reset()
    set_connector("Graylog", None)
    for route in ("/indices", "/inputs", "/metrics", "/url_whitelist"):
        await p.same(f"GET {route} (no connector)", "GET", G + route, t_admin, before=GRAYLOG.reset, concurrent=route == "/metrics")
    await p.same("POST /input/stop (no connector)", "POST", G + "/input/stop", t_admin, json={"input_id": "x"})
    set_connector("Graylog", f"http://127.0.0.1:{GRAYLOG_PORT}", "admin", "pässword")

    print("\n=== Event Shipper (/receiver) ===")
    payloads = [
        {"integration": "mimecast", "customer_code": "acme", "message": "hello", "n": None, "nested": {"a": None, "é": [1, 2.5]}},
        {"integration": "x", "customer_code": "y"},
    ]
    for payload in payloads:
        GELF_FRAMES.clear()
        r1, _ = await p.call(p.py, "POST", G + "/receiver", t_admin, json=payload)
        f1 = take_gelf(1)
        r2, _ = await p.call(p.rs, "POST", G + "/receiver", t_admin, json=payload)
        f2 = take_gelf(1)
        check(
            f"POST /receiver {json.dumps(payload)[:50]} [{r1.status_code}]",
            (r1.status_code, r1.content, f1) == (r2.status_code, r2.content, f2),
            f"python {r1.status_code} {r1.content!r} {f1}\n        rust   {r2.status_code} {r2.content!r} {f2}",
        )
    for body in ({"integration": "x"}, {"integration": 1, "customer_code": None}, [], "x"):
        await p.same(f"POST /receiver {json.dumps(body)}", "POST", G + "/receiver", t_admin, json=body, outbound=False)
    await p.same("POST /receiver, no body", "POST", G + "/receiver", t_admin, outbound=False)
    set_connector("Event Shipper", "127.0.0.1", extra=str(CLOSED_PORT))
    await p.same("POST /receiver (shipper unreachable)", "POST", G + "/receiver", t_admin, json=payloads[1], outbound=False)
    set_connector("Event Shipper", None)
    await p.same("POST /receiver (no shipper connector)", "POST", G + "/receiver", t_admin, json=payloads[1], outbound=False)
    set_connector("Event Shipper", "127.0.0.1", extra=str(GELF_PORT))


async def influxdb_checks(p, t_admin, t_analyst, t_portal):
    IX = "/api/influxdb"
    M = IX + "/metrics"
    metrics = ("/summary", "/cpu", "/memory", "/kernel", "/disks", "/processes", "/network")

    print("\n=== InfluxDB: alerts ===")
    queries = [
        {},
        {"days": "30"},
        {"severity": ["critical", "ok"]},
        {"severity": "error"},
        {"severity": ["warning", "warning"]},
        {"check_name": "CPU"},
        {"check_name": 'x" ${a} \\'},
        {"check_name": ""},
        {"sensor_type": "Disk"},
        {"status": "active"},
        {"status": "cleared"},
        {"latest_only": "true"},
        {"latest_only": "1", "status": "active"},
        {"exclude_ok": "yes"},
        {"exclude_ok": "on", "latest_only": "t", "severity": "critical"},
        {"limit": "2"},
        {"limit": "3", "status": "cleared"},
        {"days": " 9 ", "limit": "1_0"},
    ]
    for params in queries:
        await p.same(f"GET /alerts {params}", "GET", IX + "/alerts", t_analyst, params=params, before=INFLUX.reset)
    await p.same("GET /check-names", "GET", IX + "/check-names", t_analyst, before=INFLUX.reset)
    await p.same("GET /metrics/hosts", "GET", M + "/hosts", t_admin, before=INFLUX.reset)

    print("\n=== InfluxDB: metrics ===")
    for path in metrics:
        await p.same(f"GET /metrics{path}", "GET", M + path, t_analyst, params={"host": "web-01"}, before=INFLUX.reset)
    for params in ({"host": "db-01", "range_h": "72"}, {"host": "db-01", "range_h": "bogus"}, {"host": "nohost", "range_h": "720"}):
        for path in ("/cpu", "/disks", "/network"):
            await p.same(f"GET /metrics{path} {params}", "GET", M + path, t_analyst, params=params, before=INFLUX.reset)
    await p.same(
        "GET /metrics/summary, injected host",
        "GET",
        M + "/summary",
        t_analyst,
        params={"host": 'a") or true //'},
        before=INFLUX.reset,
    )

    print("\n=== InfluxDB: query parameters and auth ===")
    bad = [
        {"days": "0"},
        {"days": "91"},
        {"days": "x"},
        {"days": ""},
        {"days": "1.0"},
        {"days": "1.5"},
        {"days": "99999999999999999999"},
        {"severity": ["ok", "bad", "CRITICAL"]},
        {"status": "Active"},
        {"latest_only": "maybe"},
        {"exclude_ok": ""},
        {"limit": "0"},
        {"limit": "1001"},
        {"days": "x", "severity": "x", "status": "x", "latest_only": "x", "exclude_ok": "x", "limit": "x"},
    ]
    for params in bad:
        await p.same(f"GET /alerts {params}", "GET", IX + "/alerts", t_analyst, params=params)
    for path in metrics:
        await p.same(f"GET /metrics{path}, no host", "GET", M + path, t_analyst, params={"range_h": "1"})
    for path in ("/alerts", "/check-names", "/metrics/hosts", "/metrics/cpu"):
        await p.same(f"GET {path}, no token", "GET", IX + path)
        await p.same(f"GET {path}, bad token", "GET", IX + path, "not-a-jwt")
        await p.same(f"GET {path}, portal user", "GET", IX + path, t_portal)
    await p.same("GET /alerts?days=0, no token", "GET", IX + "/alerts", params={"days": "0"})

    print("\n=== InfluxDB: what the tool answers ===")
    unauthorized = (
        401,
        None,
        [*INFLUX_ERROR_HEADERS, ("X-Platform-Error-Code", "unauthorized")],
        _json({"code": "unauthorized", "message": "unauthorized access"}),
    )
    error_table = '#datatype,string,string\r\n#group,true,true\r\n#default,,\r\n,error,reference\r\n,"failed to execute query: error @1:1-1:5: undefined identifier x",897\r\n\r\n'
    answers = [
        ("401", {"override": unauthorized}),
        ("500 without body", {"override": (500, "Whatever", [], b"")}),
        ("404 HTML", {"override": (404, None, [("Content-Type", "text/html")], b"<html>\x00'\"</html>")}),
        ("Flux error table", {"csv": error_table}),
        ("no annotations", {"csv": ",result,table,_value\r\n,,0,x\r\n"}),
        ("short rows", {"csv": "#datatype,string\r\nab\r\n"}),
        (
            "bad long",
            {"csv": "#datatype,string,long,string\r\n#group,false,false,false\r\n#default,_result,,\r\n,result,table,_value\r\n,,x,a\r\n"},
        ),
        (
            "bad datetime",
            {
                "csv": "#datatype,string,long,dateTime:RFC3339,string\r\n#group,false,false,false,false\r\n#default,_result,,,\r\n,result,table,_time,_value\r\n,,0,yesterday,a\r\n",
            },
        ),
        (
            "bad double",
            {
                "csv": "#datatype,string,long,double\r\n#group,false,false,false\r\n#default,_result,,\r\n,result,table,_value\r\n,,0,1.5x\r\n",
            },
        ),
        ("not UTF-8", {"csv": b"\xff\xfe"}),
        ("empty", {"csv": ""}),
        ("gzip", {"gzip": True}),
    ]
    for label, setup in answers:

        def before(setup=setup):
            INFLUX.reset()
            for k, v in setup.items():
                setattr(INFLUX, k, v)

        for path, params in (("/alerts", {}), ("/check-names", {}), ("/metrics/hosts", {}), ("/metrics/disks", {"host": "web-01"})):
            await p.same(f"GET {path} ← {label}", "GET", IX + path, t_analyst, params=params, before=before)

    def statuses(change):
        def before():
            INFLUX.reset()
            change(INFLUX.statuses)

        return before

    def drop(key, index=None):
        def change(rows):
            for i, r in enumerate(rows):
                if index is None or i == index:
                    r.pop(key, None)

        return change

    def setkey(key, value, index=0):
        def change(rows):
            rows[index][key] = value

        return change

    status_cases = [
        ("no _time", drop("_time")),
        ("one row without _time", drop("_time", 1)),
        ("no _value", drop("_value")),
        ("no _level", drop("_level")),
        ("no _check_id", drop("_check_id")),
        ("check name of spaces", setkey("_check_name", "   ")),
        ("one-word check name", setkey("_check_name", "Uptime")),
        ("unknown level", setkey("_level", "info")),
        ("no rows", lambda rows: rows.clear()),
    ]
    for label, change in status_cases:
        for params in ({}, {"latest_only": "true"}):
            await p.same(f"GET /alerts ({label}) {params}", "GET", IX + "/alerts", t_analyst, params=params, before=statuses(change))
    await p.same("GET /check-names (no rows)", "GET", IX + "/check-names", t_analyst, before=statuses(lambda rows: rows.clear()))

    def metric_csv(text):
        def before():
            INFLUX.reset()
            INFLUX.csv = text

        return before

    no_time = "#datatype,string,long,double,string\r\n#group,false,false,false,true\r\n#default,_result,,,\r\n,result,table,_value,_field\r\n,,0,1.5,x\r\n\r\n"
    null_time = "#datatype,string,long,dateTime:RFC3339,double,string\r\n#group,false,false,false,false,true\r\n#default,_result,,,,\r\n,result,table,_time,_value,_field\r\n,,0,,1.5,x\r\n\r\n"
    string_values = "#datatype,string,long,dateTime:RFC3339,string,string,string\r\n#group,false,false,false,false,true,true\r\n#default,_result,,,,,\r\n,result,table,_time,_value,_field,path\r\n,,0,2026-10-15T10:00:00Z,12,total,/\r\n,,1,2026-10-15T10:00:00Z,x,total,\r\n,,2,2026-10-15T10:00:00Z,,total,/a\r\n\r\n"
    special = "#datatype,string,long,dateTime:RFC3339,double,string,long\r\n#group,false,false,false,false,true,true\r\n#default,_result,,,,,\r\n,result,table,_time,_value,_field,interface\r\n,,0,2026-10-15T10:00:00+02:00,NaN,x,1\r\n,,1,2026-10-15T10:00:00.5Z,+Inf,x,\r\n,,2,2026-10-15T10:00:00Z,-0,y,1\r\n\r\n"
    for label, csv_text in (
        ("no _time", no_time),
        ("empty _time", null_time),
        ("string values", string_values),
        ("NaN and odd labels", special),
    ):
        for path in ("/summary", "/disks", "/network", "/hosts"):
            await p.same(
                f"GET /metrics{path} ← {label}",
                "GET",
                M + path,
                t_analyst,
                params={"host": "web-01"},
                before=metric_csv(csv_text),
            )

    print("\n=== InfluxDB: connector problems ===")
    connector_cases = [
        ("connection refused", f"http://127.0.0.1:{CLOSED_PORT}", INFLUX_TOKEN, INFLUX_EXTRA),
        ("no scheme", f"127.0.0.1:{INFLUX_PORT}", INFLUX_TOKEN, INFLUX_EXTRA),
        ("empty URL", "", INFLUX_TOKEN, INFLUX_EXTRA),
        ("ftp", "ftp://127.0.0.1", INFLUX_TOKEN, INFLUX_EXTRA),
        ("bad port", "http://127.0.0.1:99999", INFLUX_TOKEN, INFLUX_EXTRA),
        ("no host", "http://", INFLUX_TOKEN, INFLUX_EXTRA),
        ("trailing slash", INFLUX_URL + "/", INFLUX_TOKEN, INFLUX_EXTRA),
        ("credentials in URL", f"http://u:p@127.0.0.1:{INFLUX_PORT}", INFLUX_TOKEN, INFLUX_EXTRA),
        ("credentials in URL, no token", f"http://u:p%40x@127.0.0.1:{INFLUX_PORT}", None, INFLUX_EXTRA),
        ("no token", INFLUX_URL, None, INFLUX_EXTRA),
        ("empty token", INFLUX_URL, "", INFLUX_EXTRA),
        ("no extra data", INFLUX_URL, INFLUX_TOKEN, None),
        ("org only", INFLUX_URL, INFLUX_TOKEN, "SOCFORTRESS"),
        ("empty extra data", INFLUX_URL, INFLUX_TOKEN, ""),
        ("odd org", INFLUX_URL, INFLUX_TOKEN, "a&b=c+d/é?#%41~*!$()*;:@[] , telegraf "),
    ]
    for label, url, key, extra in connector_cases:
        set_connector("InfluxDB", url, api_key=key, extra=extra)
        for path, params in (("/alerts", {}), ("/check-names", {}), ("/metrics/hosts", {}), ("/metrics/cpu", {"host": "web-01"})):
            await p.same(f"GET {path} ({label})", "GET", IX + path, t_analyst, params=params, before=INFLUX.reset)
    set_connector("InfluxDB", None)
    for path, params in (("/alerts", {}), ("/check-names", {}), ("/metrics/hosts", {}), ("/metrics/summary", {"host": "web-01"})):
        await p.same(f"GET {path} (no connector)", "GET", IX + path, t_analyst, params=params)
    set_connector("InfluxDB", INFLUX_URL, api_key=INFLUX_TOKEN, extra=INFLUX_EXTRA)

    def mode(m):
        def before():
            INFLUX.reset()
            INFLUX.mode = m

        return before

    await p.same("GET /alerts (InfluxDB hangs up)", "GET", IX + "/alerts", t_analyst, before=mode("close"))
    await p.same(
        "GET /metrics/memory (InfluxDB hangs up)",
        "GET",
        M + "/memory",
        t_analyst,
        params={"host": "web-01"},
        before=mode("close"),
    )
    await p.same("GET /alerts (InfluxDB never answers: 10 s timeout)", "GET", IX + "/alerts", t_analyst, before=mode("silent"))


async def grafana_checks(p, t_admin, t_analyst, t_portal):
    R = "/api/reporting"
    U = "/api/user/user/organization/add"
    uid = samples.GRAFANA_DASHBOARD["dashboard"]["uid"]

    print("\n=== Grafana: reporting reads ===")
    for path in ("/orgs", "/dashboards/44", "/dashboards/1", "/dashboards/007", "/dashboards/%2044", "/dashboards/999", "/dashboards/-1"):
        await p.same(f"GET {path}", "GET", R + path, t_analyst, before=GRAFANA.reset)
    for path in ("/dashboards/x", "/dashboards/1.5", "/dashboards/99999999999999999999"):
        await p.same(f"GET {path}", "GET", R + path, t_analyst, before=GRAFANA.reset)
    for prefix in ("/dashboard/", "/dashboard_panels/"):
        for u in (uid, "nope", "a%20b", "%3Fx%3D1", "a%2Fb"):
            await p.same(f"GET {prefix}{u}", "GET", R + prefix + u, t_admin, before=GRAFANA.reset)
    for path in ("/orgs", "/dashboards/1", f"/dashboard/{uid}", f"/dashboard_panels/{uid}"):
        await p.same(f"GET {path}, no token", "GET", R + path)
        await p.same(f"GET {path}, bad token", "GET", R + path, "not-a-jwt")
        await p.same(f"GET {path}, portal user", "GET", R + path, t_portal)

    print("\n=== Grafana: what Grafana answers ===")
    text_panel = copy.deepcopy(samples.GRAFANA_DASHBOARD)
    text_panel["dashboard"]["panels"].append({"id": 9, "title": "Notes", "type": "text", "options": {"content": "x", "mode": "markdown"}})
    refresh_off = copy.deepcopy(samples.GRAFANA_DASHBOARD)
    refresh_off["dashboard"]["refresh"] = False
    no_meta = {"dashboard": samples.GRAFANA_DASHBOARD["dashboard"]}
    answers = [
        ("/api/orgs", 200, _json([{"id": "x", "name": 5}])),
        ("/api/orgs", 200, _json({"orgs": []})),
        ("/api/orgs", 200, _json(None)),
        ("/api/orgs", 200, b"not json"),
        ("/api/orgs", 200, b""),
        ("/api/orgs", 204, b""),
        ("/api/orgs", 500, b"<html>down</html>"),
        ("/api/orgs", 500, _json({"message": 5})),
        ("/api/orgs", 400, _json({"message": "bad", "x": [1, None]})),
        ("/api/orgs", 403, b""),
        ("/api/orgs", 404, _json(["x"])),
        ("/api/search", 200, _json([{"id": 1}])),
        ("/api/search", 200, _json([{**samples.GRAFANA_SEARCH[44][1], "tags": None, "folderId": "5"}])),
        ("/api/user/using/", 500, _json({"message": "switch failed"})),
        ("/api/dashboards/uid/", 200, _json(text_panel)),
        ("/api/dashboards/uid/", 200, _json(refresh_off)),
        ("/api/dashboards/uid/", 200, _json(no_meta)),
        ("/api/dashboards/uid/", 200, _json({"dashboard": {"panels": [{"id": 1, "title": "x"}]}})),
        ("/api/dashboards/uid/", 200, _json({"dashboard": {"panels": {"a": 1}}})),
        ("/api/dashboards/uid/", 200, _json({"dashboard": {"panels": [{"id": "x", "title": None, "type": "graph"}]}})),
        (
            "/api/dashboards/uid/",
            200,
            _json({"dashboard": {"panels": [{"id": 2, "title": "row", "type": "row"}, {"id": 3, "title": "t", "type": "stat"}]}}),
        ),
        ("/api/dashboards/uid/", 200, _json({"dashboard": []})),
        ("/api/dashboards/uid/", 200, _json([])),
        ("/api/dashboards/uid/", 200, b"oops"),
    ]
    routes_for = {
        "/api/orgs": ["/orgs"],
        "/api/search": ["/dashboards/44"],
        "/api/user/using/": ["/dashboards/44"],
        "/api/dashboards/uid/": [f"/dashboard/{uid}", f"/dashboard_panels/{uid}"],
    }
    for prefix, status, payload in answers:
        for route in routes_for[prefix]:

            def before(pr=prefix, st=status, pa=payload):
                GRAFANA.reset()
                GRAFANA.overrides[("GET" if pr != "/api/user/using/" else "POST", pr)] = (
                    st,
                    "application/json" if pa[:1] in (b"{", b"[", b"n") else "text/html",
                    pa,
                )

            await p.same(f"GET {route} ← {status} {payload[:40]!r}", "GET", R + route, t_analyst, before=before)

    print("\n=== Grafana: iframe links ===")
    link = {
        "org_id": 44,
        "dashboard_title": "huntress-summary",
        "dashboard_uid": uid,
        "panel_id": 5,
        "time_range": {"value": 7, "unit": "d"},
    }
    bodies = [
        link,
        {**link, "time_range": {"value": 30, "unit": "m"}, "theme": "light"},
        {**link, "time_range": {"value": "12", "unit": "h"}, "org_id": "007", "panel_id": True},
        {**link, "time_range": {"value": -5, "unit": "d"}, "dashboard_title": "a b/é?x"},
        {**link, "time_range": {"value": 7, "unit": "w"}},
        {**link, "time_range": {"value": "x", "unit": "w"}},
        {**link, "time_range": {"value": 7, "unit": 5}},
        {**link, "time_range": {"value": 1.5, "unit": "d"}},
        {**link, "time_range": {"value": 1000000000, "unit": "d"}},
        {**link, "time_range": {"value": 999999999, "unit": "d"}},
        {**link, "time_range": None},
        {k: v for k, v in link.items() if k != "panel_id"},
        {},
        [],
    ]
    for body in bodies:
        await p.same(
            f"POST /generate_iframe_links {json.dumps(body)[:70]}",
            "POST",
            R + "/generate_iframe_links",
            t_analyst,
            json=body,
            clock=True,
        )
    await p.same("POST /generate_iframe_links, no token", "POST", R + "/generate_iframe_links", json=link)
    await p.same(
        "POST /generate_iframe_links, malformed JSON, no token",
        "POST",
        R + "/generate_iframe_links",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    print("\n=== Grafana: adding a user to an organization ===")
    users = [
        {"loginorEmail": "a@b.c", "organizationId": "44"},
        {"loginorEmail": "viewer@acme.io", "role": "Editor", "organizationId": "44"},
        {"loginorEmail": "é@exämple.io", "role": "Admin", "organizationId": "1"},
        {"loginorEmail": "nobody@x.io", "organizationId": "44"},
        {"loginorEmail": "a@b.c", "organizationId": "999"},
        {"loginorEmail": "a@b.c", "organizationId": "4/4?x"},
        {"loginorEmail": "a@b.c", "organizationId": 44},
        {"organizationId": "44"},
        {"loginorEmail": None, "role": None},
        [],
    ]
    for body in users:
        await p.same(f"POST {U} {json.dumps(body, ensure_ascii=False)[:60]}", "POST", U, t_analyst, json=body, before=GRAFANA.reset)
    await p.same(f"POST {U}, portal user", "POST", U, t_portal, json=users[0])
    await p.same(f"POST {U}, no body", "POST", U, t_admin)

    print("\n=== Grafana: connector problems ===")
    cases = [
        ("connection refused", f"http://127.0.0.1:{CLOSED_PORT}", GRAFANA_USER, GRAFANA_PASSWORD),
        ("no scheme", f"127.0.0.1:{GRAFANA_PORT}", GRAFANA_USER, GRAFANA_PASSWORD),
        ("upper-case scheme", f"HTTP://127.0.0.1:{GRAFANA_PORT}", GRAFANA_USER, GRAFANA_PASSWORD),
        ("bad port", "http://127.0.0.1:99999", GRAFANA_USER, GRAFANA_PASSWORD),
        ("port not a number", "http://127.0.0.1:x", GRAFANA_USER, GRAFANA_PASSWORD),
        ("wrong password", GRAFANA_URL, GRAFANA_USER, "nope"),
        ("no credentials", GRAFANA_URL, None, None),
        ("empty user", GRAFANA_URL, "", GRAFANA_PASSWORD),
        ("path prefix", GRAFANA_URL + "/grafana", GRAFANA_USER, GRAFANA_PASSWORD),
        ("path prefix with slash", GRAFANA_URL + "/grafana/", GRAFANA_USER, GRAFANA_PASSWORD),
        ("own query", GRAFANA_URL + "?orgId=1", GRAFANA_USER, GRAFANA_PASSWORD),
        ("unknown host", "http://nonexistent.invalid:3000", GRAFANA_USER, GRAFANA_PASSWORD),
        ("no host", "http://", GRAFANA_USER, GRAFANA_PASSWORD),
        ("hangs up", INFLUX_URL, GRAFANA_USER, GRAFANA_PASSWORD),
    ]
    for label, url, user, password in cases:
        set_connector("Grafana", url, user, password)

        def before():
            GRAFANA.reset()
            INFLUX.reset()
            INFLUX.mode = "close"

        for route in ("/orgs", "/dashboards/44", f"/dashboard_panels/{uid}"):
            await p.same(f"GET {route} ({label})", "GET", R + route, t_analyst, before=before)
        await p.same(f"POST {U} ({label})", "POST", U, t_analyst, json=users[0], before=before)
        await p.same(f"POST /generate_iframe_links ({label})", "POST", R + "/generate_iframe_links", t_analyst, json=link, clock=True)
    set_connector("Grafana", INFLUX_URL, GRAFANA_USER, GRAFANA_PASSWORD)

    def silent():
        INFLUX.reset()
        INFLUX.mode = "silent"

    await p.same("GET /orgs (Grafana never answers: 5 s read timeout)", "GET", R + "/orgs", t_analyst, before=silent)
    set_connector("Grafana", None)
    for route in ("/orgs", "/dashboards/44", f"/dashboard/{uid}"):
        await p.same(f"GET {route} (no connector)", "GET", R + route, t_analyst)
    await p.same(f"POST {U} (no connector)", "POST", U, t_analyst, json=users[0])
    await p.same("POST /generate_iframe_links (no connector)", "POST", R + "/generate_iframe_links", t_analyst, json=link)
    set_connector("Grafana", GRAFANA_URL, GRAFANA_USER, GRAFANA_PASSWORD)
    INFLUX.reset()


async def portainer_checks(p, t_admin, t_analyst, t_portal):
    P = "/api/portainer"

    print("\n=== Portainer: reads ===")
    await p.same("GET /node-details", "GET", P + "/node-details", t_analyst, before=PORTAINER.reset)
    await p.same("GET /stacks", "GET", P + "/stacks", t_admin, before=PORTAINER.reset)
    for raw in ("5", "05", " 6 ", "7", "404", "x", "1.0", ""):
        await p.same(
            f"GET /stack-details?stack_id={raw!r}",
            "GET",
            P + "/stack-details",
            t_admin,
            params={"stack_id": raw},
            before=PORTAINER.reset,
        )
    await p.same("GET /stack-details, no stack_id", "GET", P + "/stack-details", t_admin)
    for path, tok_name in (("/node-details", None), ("/stacks", "analyst"), ("/stacks", None), ("/stack-details?stack_id=5", "portal")):
        tok = {"analyst": t_analyst, "portal": t_portal}.get(tok_name)
        await p.same(f"GET {path} ({tok_name or 'no token'})", "GET", P + path, tok)

    print("\n=== Portainer: start, stop, delete ===")
    for action, method in (
        ("start-wazuh-customer-stack", "POST"),
        ("stop-wazuh-customer-stack", "POST"),
        ("delete-wazuh-customer-stack", "DELETE"),
    ):
        for stack_id in ("5", "6", "7", "404", "x"):
            await p.same(
                f"{method} /{action}?stack_id={stack_id}",
                method,
                f"{P}/{action}",
                t_admin,
                params={"stack_id": stack_id},
                before=PORTAINER.reset,
            )
        await p.same(f"{method} /{action}, analyst", method, f"{P}/{action}", t_analyst, params={"stack_id": "5"})
        await p.same(f"{method} /{action}, no stack_id", method, f"{P}/{action}", t_admin)
    await p.same(
        "POST /start-wazuh-customer-stack, a JSON body is ignored",
        "POST",
        P + "/start-wazuh-customer-stack",
        t_admin,
        params={"stack_id": "6"},
        content=b"{",
        headers={"Content-Type": "application/json"},
        before=PORTAINER.reset,
    )

    print("\n=== Portainer: what Portainer answers ===")
    j = "application/json"
    answers = [
        (("GET", "/api/endpoints"), (200, j, _json([])), ["/node-details", "/stack-details?stack_id=5"]),
        (("GET", "/api/endpoints"), (200, j, _json([{"Name": "local", "Id": "3"}])), ["/node-details"]),
        (("GET", "/api/endpoints"), (200, j, _json([{"Name": "local", "Id": 5.7}])), ["/node-details"]),
        (("GET", "/api/endpoints"), (200, j, _json([{"Name": "local", "Id": "x"}])), ["/node-details"]),
        (("GET", "/api/endpoints"), (200, j, _json([{"Name": "local", "Id": None}])), ["/node-details"]),
        (("GET", "/api/endpoints"), (200, j, _json([{"Id": 1}])), ["/node-details"]),
        (("GET", "/api/endpoints"), (200, j, _json({"a": 1})), ["/node-details"]),
        (("GET", "/api/endpoints"), (200, j, _json(None)), ["/node-details"]),
        (("GET", "/api/endpoints"), (502, "text/html", b"<html>bad gateway</html>"), ["/node-details"]),
        (
            ("GET", "/api/endpoints/1/docker/nodes"),
            (200, j, _json([{**samples.PORTAINER_NODES[0], "CreatedAt": "yesterday"}])),
            ["/node-details"],
        ),
        (("GET", "/api/endpoints/1/docker/nodes"), (200, j, _json({"message": "boom"})), ["/node-details"]),
        (("GET", "/api/stacks"), (200, j, _json([{"Id": 1}])), ["/stacks"]),
        (("GET", "/api/stacks"), (500, j, _json({"message": "db down"})), ["/stacks"]),
        (("GET", "/api/stacks"), (200, j, b""), ["/stacks"]),
        (("GET", "/api/stacks/5"), (200, j, _json({**samples.PORTAINER_STACKS[0], "Status": "9"})), ["/stack-details?stack_id=5"]),
        (("POST", "/api/auth"), (500, "text/html", b"<html>oops</html>"), ["/stacks", "/node-details"]),
        (("POST", "/api/auth"), (200, j, _json({"token": "x"})), ["/stacks"]),
        (("POST", "/api/auth"), (200, j, b"not json"), ["/stacks"]),
        (("POST", "/api/auth"), (200, j, _json({"jwt": 5})), ["/stacks"]),
        (("POST", "/api/auth"), (200, j, _json(["jwt"])), ["/stacks"]),
    ]
    for key, answer, routes in answers:
        for route in routes:

            def before(k=key, a=answer):
                PORTAINER.reset()
                PORTAINER.overrides[k] = a

            tok = t_analyst if route == "/node-details" else t_admin
            await p.same(f"GET {route} ← {key[1]} {answer[0]} {answer[2][:40]!r}", "GET", P + route, tok, before=before)
    writes = [
        ("start", "6", ("POST", "/api/stacks/6/start"), (204, None, b"")),
        ("start", "6", ("POST", "/api/stacks/6/start"), (500, "text/html", b"<html>x</html>")),
        ("start", "6", ("POST", "/api/stacks/6/start"), (409, j, _json({"message": "conflict"}))),
        ("start", "6", ("POST", "/api/stacks/6/start"), CLOSE),
        ("stop", "5", ("POST", "/api/stacks/5/stop"), (200, j, _json({**samples.PORTAINER_STACKS[0], "Status": 2, "Name": None}))),
        ("delete", "6", ("DELETE", "/api/stacks/6"), (200, j, _json({"deleted": True}))),
        ("delete", "6", ("DELETE", "/api/stacks/6"), (500, "text/html", b"<html>x</html>")),
        ("delete", "6", ("DELETE", "/api/stacks/6"), (200, "text/plain", b"   \n")),
        ("delete", "6", ("DELETE", "/api/stacks/6"), CLOSE),
    ]
    for action, stack_id, key, answer in writes:

        def before(k=key, a=answer):
            PORTAINER.reset()
            PORTAINER.overrides[k] = a

        method = "DELETE" if action == "delete" else "POST"
        label = "hang-up" if answer is CLOSE else f"{answer[0]} {answer[2][:30]!r}"
        await p.same(
            f"{method} /{action}-wazuh-customer-stack?stack_id={stack_id} ← {label}",
            method,
            f"{P}/{action}-wazuh-customer-stack",
            t_admin,
            params={"stack_id": stack_id},
            before=before,
        )

    print("\n=== Portainer: the customer's stack id ===")
    names = [c[0] for c in PORTAINER_CUSTOMERS]
    for name in (names[0], names[0].upper(), names[1], names[2], names[3], "Nobody", ""):
        await p.same(f"GET /get-customer-stack-id {name!r}", "GET", P + "/get-customer-stack-id", t_admin, params={"customer_name": name})
    await p.same("GET /get-customer-stack-id, no name", "GET", P + "/get-customer-stack-id", t_admin)
    await p.same("GET /get-customer-stack-id, analyst", "GET", P + "/get-customer-stack-id", t_analyst, params={"customer_name": names[0]})

    def stack_of(code):
        return sql("SELECT customer_meta_portainer_stack_id FROM customersmeta WHERE customer_code = :c", c=code).scalar()

    for name, value in ((names[0], "12"), (names[0], "5"), (names[1], "007"), (names[0], "99999999999"), ("Nobody", "3"), (names[3], "4")):
        codes = [f"pt{i}{SFX}" for i, c in enumerate(PORTAINER_CUSTOMERS) if c[0] == name]
        seeded = {f"pt{i}{SFX}": c[1] for i, c in enumerate(PORTAINER_CUSTOMERS)}

        def restore():
            for code in codes:
                sql("UPDATE customersmeta SET customer_meta_portainer_stack_id = :v WHERE customer_code = :c", v=seeded[code], c=code)

        restore()
        r1, _ = await p.call(p.py, "POST", P + "/update-customer-stack-id", t_admin, params={"customer_name": name, "stack_id": value})
        after1 = [stack_of(c) for c in codes]
        restore()
        r2, _ = await p.call(p.rs, "POST", P + "/update-customer-stack-id", t_admin, params={"customer_name": name, "stack_id": value})
        after2 = [stack_of(c) for c in codes]
        restore()
        check(
            f"POST /update-customer-stack-id {name!r} {value} [{r1.status_code}]",
            (r1.status_code, r1.content, after1) == (r2.status_code, r2.content, after2),
            f"python {r1.status_code} {r1.content!r} {after1}\n        rust   {r2.status_code} {r2.content!r} {after2}",
        )
    for params in ({"customer_name": names[0]}, {"stack_id": "1"}, {"customer_name": names[0], "stack_id": "x"}, {}):
        await p.same(f"POST /update-customer-stack-id {params}", "POST", P + "/update-customer-stack-id", t_admin, params=params)

    print("\n=== Portainer: connector problems ===")
    cases = [
        ("connection refused", f"http://127.0.0.1:{CLOSED_PORT}", PORTAINER_USER, PORTAINER_PASSWORD),
        ("no scheme", f"127.0.0.1:{PORTAINER_PORT}", PORTAINER_USER, PORTAINER_PASSWORD),
        ("wrong password", PORTAINER_URL, PORTAINER_USER, "nope"),
        ("no credentials", PORTAINER_URL, None, None),
        ("path prefix", PORTAINER_URL + "/portainer", PORTAINER_USER, PORTAINER_PASSWORD),
        ("trailing slash", PORTAINER_URL + "/", PORTAINER_USER, PORTAINER_PASSWORD),
        ("unknown host", "http://nonexistent.invalid:9000", PORTAINER_USER, PORTAINER_PASSWORD),
        ("hangs up", INFLUX_URL, PORTAINER_USER, PORTAINER_PASSWORD),
    ]
    for label, url, user, password in cases:
        set_connector("Portainer", url, user, password)

        def before():
            PORTAINER.reset()
            INFLUX.reset()
            INFLUX.mode = "close"

        await p.same(f"GET /stacks ({label})", "GET", P + "/stacks", t_admin, before=before)
        await p.same(f"GET /node-details ({label})", "GET", P + "/node-details", t_analyst, before=before)
        await p.same(
            f"POST /stop-wazuh-customer-stack ({label})",
            "POST",
            P + "/stop-wazuh-customer-stack",
            t_admin,
            params={"stack_id": "5"},
            before=before,
        )
    INFLUX.reset()
    set_connector("Portainer", None)
    for path in ("/stacks", "/node-details", "/stack-details?stack_id=5"):
        await p.same(f"GET {path} (no connector)", "GET", P + path, t_admin)
    await p.same(
        "DELETE /delete-wazuh-customer-stack (no connector)",
        "DELETE",
        P + "/delete-wazuh-customer-stack",
        t_admin,
        params={"stack_id": "5"},
    )
    set_connector("Portainer", PORTAINER_URL, PORTAINER_USER, PORTAINER_PASSWORD)


async def main():
    graylog_server = start_http_stub(GRAYLOG_PORT, GRAYLOG, RECORDER)
    influx_server = start_http_stub(INFLUX_PORT, INFLUX, INFLUX_RECORDER, make_influx_handler)
    grafana_server = start_http_stub(GRAFANA_PORT, GRAFANA, GRAFANA_RECORDER, make_grafana_handler)
    portainer_server = start_http_stub(PORTAINER_PORT, PORTAINER, PORTAINER_RECORDER, make_grafana_handler)
    gelf_server = start_gelf_stub(GELF_PORT)
    seed()
    proc = start_rust()
    p = Pair()
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    try:
        sections = os.environ.get("CONNECTOR_PARITY_SECTIONS", "graylog,influxdb,grafana,portainer").split(",")
        if "graylog" in sections:
            await graylog_checks(p, t_admin, t_analyst, t_portal)
        if "influxdb" in sections:
            await influxdb_checks(p, t_admin, t_analyst, t_portal)
        if "grafana" in sections:
            await grafana_checks(p, t_admin, t_analyst, t_portal)
        if "portainer" in sections:
            await portainer_checks(p, t_admin, t_analyst, t_portal)
    finally:
        await p.close()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        graylog_server.shutdown()
        influx_server.shutdown()
        grafana_server.shutdown()
        portainer_server.shutdown()
        gelf_server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
