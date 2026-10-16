"""Parity of the Rust agents module and Velociraptor client with this backend — NOT
collected by pytest (needs a live MySQL and a running Rust binary; run by
scripts/rust-parity.sh).

Sends the same requests to the real FastAPI router (`app/agents/routes/agents.py`,
in-process) and to the Rust service (`crates/copilot-agents`,
`crates/copilot-velociraptor`) over HTTP, both on the same disposable database, and
compares status codes, bodies (key order included), the rows each write leaves, and
every request each backend sends upstream. Every upstream is a local stand-in that
records what arrives:

* the Wazuh manager API (token flow, agents, vulnerabilities, SCA, upgrade, delete);
* the Wazuh indexer (the 4.8+ vulnerability states, the scroll, the sync's checks);
* Velociraptor's gRPC API, served by grpcio with pyvelociraptor's own messages over
  mutual TLS, recording the exact `VQLCollectorArgs` bytes and the deadline;
* api.first.org's EPSS API (`COPILOT_EPSS_URL` for Rust, the patched `EPSS_URL` here);
* the Event Shipper's GELF TCP input.

Ports (all overridable): AGENTS_MANAGER_STUB_PORT, AGENTS_INDEXER_STUB_PORT,
AGENTS_VELO_STUB_PORT, EPSS_STUB_PORT (must be the one rust-parity.sh gave the Rust
binary), AGENTS_GELF_STUB_PORT, AGENTS_RUST_JOBS_PORT (a second Rust instance that
owns `agent_sync` for the hand-over checks).

    PARITY_SUITES=tests/e2e/rust_parity_agents_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
import hashlib
import json
import os
import re
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent import futures
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qsl
from urllib.parse import unquote

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# Both backends read these: rust-parity.sh hands the Rust binary the same values.
os.environ.setdefault("GRAFANA_API_HEADER_VALUE", "parity-grafana-header")
os.environ.setdefault("VELOCIRAPTOR_QUERY_TIMEOUT", "5")

import grpc  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from pyvelociraptor import api_pb2  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.connectors import cache as connector_cache  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402

RUST = os.environ.get("RUST_BASE_URL", "http://127.0.0.1:5720")
MANAGER_PORT = int(os.environ.get("AGENTS_MANAGER_STUB_PORT", "5734"))
INDEXER_PORT = int(os.environ.get("AGENTS_INDEXER_STUB_PORT", "5735"))
VELO_PORT = int(os.environ.get("AGENTS_VELO_STUB_PORT", "5731"))
EPSS_PORT = int(os.environ.get("EPSS_STUB_PORT", "5732"))
GELF_PORT = int(os.environ.get("AGENTS_GELF_STUB_PORT", "5733"))
JOBS_PORT = int(os.environ.get("AGENTS_RUST_JOBS_PORT", "5736"))
#: A port nothing listens on (a Velociraptor that is down).
CLOSED_PORT = 1
GRAFANA_HEADER = os.environ["GRAFANA_API_HEADER_VALUE"]
QUERY_TIMEOUT = int(os.environ["VELOCIRAPTOR_QUERY_TIMEOUT"])
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CERTS = os.path.join(REPO, "crates", "copilot-velociraptor", "src", "testing")

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"AgA{SFX}", f"AgB{SFX}"
ADMIN, ANALYST, PORTAL, SCHED = f"ag_admin{SFX}", f"ag_analyst{SFX}", f"ag_portal{SFX}", f"ag_sched{SFX}"
RESP = f"ag_resp{SFX}"
USERS = (ADMIN, ANALYST, PORTAL, SCHED, RESP)
OUR_CONNECTORS = ("Wazuh-Manager", "Wazuh-Indexer", "Velociraptor", "Event Shipper")
results = []

#: `Agents`' columns in declaration order, the order Rust serializes a row in.
AGENT_FIELDS = [
    "id",
    "agent_id",
    "ip_address",
    "os",
    "hostname",
    "label",
    "critical_asset",
    "wazuh_last_seen",
    "velociraptor_id",
    "velociraptor_last_seen",
    "wazuh_agent_version",
    "wazuh_agent_status",
    "velociraptor_agent_version",
    "customer_code",
    "quarantined",
    "velociraptor_org",
    "velociraptor_id_pinned",
]


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def canonical(v):
    """An `Agents` row with its keys in declaration order (see the §4 row: SQLModel
    emits a loaded row's fields in the order the ORM happened to set them)."""
    if isinstance(v, list):
        return [canonical(x) for x in v]
    if isinstance(v, dict):
        if set(v) == set(AGENT_FIELDS):
            return {k: canonical(v[k]) for k in AGENT_FIELDS}
        return {k: canonical(x) for k, x in v.items()}
    return v


def agent_orders(v, out):
    if isinstance(v, list):
        for x in v:
            agent_orders(x, out)
    elif isinstance(v, dict):
        if set(v) == set(AGENT_FIELDS):
            out.append(list(v))
        for x in v.values():
            agent_orders(x, out)
    return out


# --- HTTP stand-ins -------------------------------------------------------------------
#: Headers a client adds on its own (requests, httpx, urllib3 and reqwest differ there,
#: and none of them reaches the upstream's logic).
TRANSPORT_HEADERS = {
    "host",
    "user-agent",
    "accept-encoding",
    "accept",
    "connection",
    "content-length",
    "transfer-encoding",
}


class Recorder:
    def __init__(self, answer, port, name="r"):
        self.answer = answer
        self.name = name
        self.captured = []
        self.mode = {}
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k.lower(): v for k, v in self.headers.items() if k.lower() not in TRANSPORT_HEADERS}
                with recorder.lock:
                    recorder.captured.append({"method": self.command, "path": self.path, "headers": headers, "body": body})
                status, ctype, payload = recorder.answer(recorder, self.command, self.path, headers, body)
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

        self.server = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{port}"

    def take(self):
        with self.lock:
            out, self.captured[:] = list(self.captured), []
        return out

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def normalised(captures, unordered=False):
    out = [
        {
            "method": c["method"],
            "path": c["path"],
            "headers": dict(sorted(c["headers"].items())),
            "body": c["body"].decode("utf-8", "replace"),
        }
        for c in captures
    ]
    if unordered:
        out.sort(key=json.dumps)
    return out


def jbody(obj):
    return json.dumps(obj).encode()


def ok(obj, ctype="application/json"):
    return 200, ctype, jbody(obj)


# --- The Wazuh manager ----------------------------------------------------------------
MGR_USER, MGR_PASS = "parity-wazuh", f"mgr-{SFX}"


def wazuh_items(items, total=None, failed=None):
    failed = failed or []
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items) if total is None else total,
            "total_failed_items": len(failed),
            "failed_items": failed,
        },
        "message": "All selected items were returned",
        "error": 0,
    }


def old_vulns(agent_id, severity, mode):
    """The manager API's vulnerabilities (Wazuh before 4.8), per severity."""
    rows = {
        "Critical": [
            {
                "severity": "Critical",
                "version": "1.1.1k",
                "type": "PACKAGE",
                "name": "openssl",
                "external_references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0286", "https://openssl.org/x"],
                "detection_time": "2026-10-01T10:00:00Z",
                "cvss3_score": 7.4,
                "published": "2023-02-08",
                "architecture": "amd64",
                "cve": "CVE-2023-0286",
                "status": "VALID",
                "title": 'X.400 "type confusion", é',
                "extra": "ignored",
            },
        ],
        "High": [
            {
                "severity": "High",
                "version": "2.0",
                "type": "PACKAGE",
                "name": "curl",
                "external_references": [],
                "detection_time": "2026-10-02T10:00:00Z",
                "cvss3_score": "8",
                "published": "2024-01-01",
                "architecture": None,
                "cve": "CVE-2024-0001",
                "status": "VALID",
                "title": "line one\nline two",
            },
        ],
        "Low": [{"severity": "Low", "name": "zlib", "cve": "CVE-2024-0002", "cvss3_score": None}],
        "Medium": [],
    }
    if mode.get("bad_vuln"):
        return [{"severity": "Low", "cvss3_score": "not a number", "cve": "CVE-2024-0003", "external_references": "x"}]
    return rows.get(severity, [])


SCA_POLICIES = [
    {
        "policy_id": "cis_ubuntu22-04",
        "description": "CIS benchmark",
        "fail": 80,
        "start_scan": "2026-10-01T00:00:00Z",
        "references": "https://www.cisecurity.org/",
        "name": "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0",
        "pass": 101,
        "score": 55,
        "end_scan": "2026-10-01T00:01:00Z",
        "total_checks": 190,
        "hash_file": "abc",
        "invalid": 9,
    },
    {"policy_id": "sca_unix_audit", "name": "System audit", "pass": "7"},
]
SCA_CHECKS = [
    {
        "description": "Ensure mounting of cramfs filesystems is disabled.",
        "id": 28500,
        "reason": None,
        "command": "modprobe -n -v cramfs",
        "rationale": "Removing support reduces the attack surface.",
        "condition": "all",
        "title": 'Ensure "cramfs", is disabled',
        "result": "failed",
        "policy_id": "cis_ubuntu22-04",
        "remediation": "Edit or create a file in /etc/modprobe.d/.",
        "compliance": [{"value": "1.1.1.1", "key": "cis"}, {"value": "2.2", "key": "pci_dss"}],
        "rules": [{"type": "command", "rule": "c:modprobe -n -v cramfs -> r:install /bin/true"}],
    },
    {
        "id": "28501",
        "rationale": "r",
        "condition": "any",
        "title": "t",
        "result": "passed",
        "policy_id": "cis_ubuntu22-04",
        "remediation": "m",
        "compliance": [],
        "rules": [],
    },
]


def mgr_answer(rec, method, raw_path, headers, body):
    mode = rec.mode
    path, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    tok = f"tok-{SFX}-{mode.get('gen', 1)}"

    def err(status, title, detail):
        return status, "application/problem+json; charset=utf-8", jbody({"title": title, "detail": detail, "error": status})

    if path == "/security/user/authenticate":
        expected = "Basic " + base64.b64encode(f"{MGR_USER}:{MGR_PASS}".encode("latin-1")).decode()
        if mode.get("reject_auth") or headers.get("authorization") != expected:
            return err(401, "Unauthorized", "Invalid credentials")
        return ok({"data": {"token": tok}, "error": 0})
    if headers.get("authorization") != f"Bearer {tok}":
        return err(401, "Unauthorized", "The server could not verify that you are authorized to access the URL requested")
    if mode.get("fail") and path.startswith(mode["fail"]):
        return 500, "text/html", b"<html>boom</html>"
    if method == "GET" and path == "/":
        return ok({"data": {"title": "Wazuh API REST", "api_version": mode.get("version", "4.7.2"), "revision": 40717}, "error": 0})
    if method == "GET" and path == "/agents":
        agents = mode.get("agents", [])
        limit = int(params.get("limit", "500"))
        return ok(wazuh_items(agents[:limit], total=mode.get("total", len(agents))))
    if method == "DELETE" and path == "/agents":
        target = params.get("agents_list", "")
        if mode.get("refuse_delete"):
            return ok(wazuh_items([], failed=[{"error": {"code": 1701, "message": "Agent does not exist"}, "id": [target]}]))
        return ok({"data": {"affected_items": [target], "total_affected_items": 1, "older_than": "0s"}, "message": "deleted", "error": 0})
    if method == "PUT" and path == "/agents/upgrade":
        target = params.get("agents_list", "")
        if mode.get("upgrade") == "failed":
            return ok(
                {
                    "data": {
                        "affected_items": [],
                        "total_affected_items": 0,
                        "total_failed_items": 1,
                        "failed_items": [{"error": {"code": 1819, "message": "Upgrade procedure could not start é"}, "id": [target]}],
                    },
                    "message": "No upgrade task was created",
                    "error": 2,
                },
            )
        if mode.get("upgrade") == "odd":
            return ok({"data": {"total_failed_items": 0}, "message": 7})
        return ok(
            {"data": {"affected_items": [{"agent": target, "task_id": 1}], "total_failed_items": 0}, "message": "Upgrade task created"},
        )
    if method == "GET" and path.startswith("/vulnerability/"):
        agent_id = unquote(path.rsplit("/", 1)[1])
        return ok(wazuh_items(old_vulns(agent_id, params.get("severity"), mode)))
    if method == "GET" and path.startswith("/sca/"):
        parts = path.split("/")
        if mode.get("sca") == "missing":
            return err(400, "Bad Request", "Agent does not exist")
        if len(parts) == 3:
            items = SCA_POLICIES if not params.get("q") else [p for p in SCA_POLICIES if f"policy_id={p['policy_id']}" == params["q"]]
            return ok(wazuh_items(items))
        items = SCA_CHECKS if not params.get("q") else [c for c in SCA_CHECKS if f"id={c['id']}" == params["q"]]
        if mode.get("sca") == "bad_check":
            items = [{"id": 1, "title": "missing the rest"}]
        return ok(wazuh_items(items))
    return 404, "text/plain", b"no stub for " + raw_path.encode()


# --- The Wazuh indexer ----------------------------------------------------------------
ES_USER, ES_PASS = "parity-indexer", f"es-{SFX}"
STATES = ["wazuh-states-vulnerabilities-node1", "wazuh-states-vulnerabilities-node2"]


def state_doc(agent_id, agent_name, cve, severity, package="openssl", version="3.0.2", reference=None):
    return {
        "agent": {"id": agent_id, "name": agent_name},
        "package": {"name": package, "version": version, "type": "deb", "architecture": "amd64"},
        "vulnerability": {
            "id": cve,
            "severity": severity,
            "description": f"{cve} description, with a comma",
            "detected_at": "2026-10-03T11:00:00.000Z",
            "published_at": "2025-01-01T00:00:00Z",
            "reference": reference if reference is not None else f"https://nvd.nist.gov/vuln/detail/{cve}",
            "score": {"base": 9.8 if severity == "Critical" else 5},
        },
        "status": "Active",
    }


def es_answer(rec, method, raw_path, headers, body):
    mode = rec.mode
    path, _, query = raw_path.partition("?")
    expected = "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode("latin-1")).decode()
    if headers.get("authorization") != expected:
        return 401, "application/json", jbody({"error": "unauthorized", "status": 401})
    if method == "GET" and path == "/*/_alias":
        names = STATES + ["wazuh-alerts-4.x-2026.10.15"] + mode.get("extra_indices", [])
        return ok({n: {"aliases": {}} for n in names})
    doc = json.loads(body or b"{}")
    if method == "POST" and path == "/_search/scroll":
        sid = doc.get("scroll_id", "")
        page = int(sid.rsplit("-", 1)[1]) + 1
        hits = rec.pages.get(sid.rsplit("-", 1)[0], [])
        batch = hits[page * 2 : page * 2 + 2]
        return ok({"_scroll_id": f"{sid.rsplit('-', 1)[0]}-{page}", "hits": {"hits": [{"_source": h} for h in batch]}})
    if method == "POST" and path.endswith("/_search"):
        index = unquote(path[1:].rsplit("/", 1)[0])
        must = doc["query"]["bool"]["must"]
        terms = {}
        for clause in must:
            for kind, cond in clause.items():
                for k, v in cond.items():
                    terms[k] = v
        if index.startswith("wazuh-vulnerabilities-"):
            known = mode.get("known_cves", set())
            total = 1 if terms.get("cve") in known else 0
            return ok({"hits": {"total": {"value": total, "relation": "eq"}, "hits": []}})
        docs = [d for d in mode.get("docs", []) if index == "wazuh-states-vulnerabilities-*" or d["_index"] == index]
        if "agent.id" in terms:
            docs = [d for d in docs if d["agent"]["id"] == terms["agent.id"]]
        if "agent.name" in terms:
            docs = [d for d in docs if d["agent"]["name"] == terms["agent.name"]]
        if "vulnerability.id" in terms:
            docs = [d for d in docs if d["vulnerability"]["id"] == terms["vulnerability.id"]]
        for key in ("package.name", "package.version"):
            if key in terms:
                docs = [d for d in docs if d["package"][key.split(".")[1]] == terms[key]]
        if "vulnerability.severity" in terms:
            sev = terms["vulnerability.severity"]
            docs = [
                d
                for d in docs
                if (d["vulnerability"]["severity"] in sev if isinstance(sev, list) else d["vulnerability"]["severity"] == sev)
            ]
        sources = [{k: v for k, v in d.items() if k != "_index"} for d in docs]
        if "scroll=2m" in query:
            # The same request gets the same scroll id, whichever backend sends it.
            sid = "s" + hashlib.sha1(raw_path.encode() + body).hexdigest()[:10]
            rec.pages[sid] = sources
            return ok({"_scroll_id": f"{sid}-0", "hits": {"hits": [{"_source": h} for h in sources[:2]]}})
        return ok({"hits": {"total": {"value": len(sources)}, "hits": [{"_source": h} for h in sources]}})
    return 404, "text/plain", b"no stub for " + raw_path.encode()


# --- EPSS -----------------------------------------------------------------------------
EPSS_SCORES = {"CVE-2023-0286": "0.97341", "CVE-2024-0001": "0.0004"}


def epss_answer(rec, method, raw_path, headers, body):
    mode = rec.mode
    _, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query))
    if mode.get("down"):
        return 503, "text/plain", b"unavailable"
    if mode.get("not_json"):
        return 200, "text/html", b"<html>maintenance</html>"
    if mode.get("list"):
        return ok([1, 2])
    rows = [
        {"cve": c, "epss": EPSS_SCORES[c], "percentile": "0.99", "date": "2026-10-15"}
        for c in params.get("cve", "").split(",")
        if c in EPSS_SCORES
    ]
    return ok({"status": "OK", "status-code": 200, "version": "1.0", "total": len(rows), "data": rows})


# --- The Event Shipper's GELF input ---------------------------------------------------
GELF_FRAMES = []
GELF_LOCK = threading.Lock()


class _GelfHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.read()
        with GELF_LOCK:
            GELF_FRAMES.append(data)


class _GelfServer(socketserver.TCPServer):
    # One connection at a time: the frames are kept in the order they were sent
    # (each event is its own connection, opened after the previous one closed).
    allow_reuse_address = True


def start_gelf_stub(port):
    server = _GelfServer(("127.0.0.1", port), _GelfHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def take_gelf(expected, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with GELF_LOCK:
            if len(GELF_FRAMES) >= expected:
                break
        time.sleep(0.05)
    time.sleep(0.3)
    with GELF_LOCK:
        out, GELF_FRAMES[:] = list(GELF_FRAMES), []
    return out


# --- Velociraptor (gRPC, mutual TLS) --------------------------------------------------
#: grpc-core prints the two keys of `debug_error_string` in hash order, which varies
#: from one error to the next: Rust always puts `grpc_status` first.
DEBUG_KEYS = re.compile(r'\{grpc_message:\\"(.*?)\\", grpc_status:(\d+)\}')


def grpc_canon(v):
    return json.loads(DEBUG_KEYS.sub(lambda m: "{grpc_status:" + m.group(2) + ', grpc_message:\\"' + m.group(1) + '\\"}', json.dumps(v)))


async def wait_for_traffic(targets, recs, quiet=1.5, limit=20.0):
    """Until each recorder has at least its target and nothing new came for `quiet` s."""
    deadline = time.time() + limit
    last, since = None, time.time()
    while time.time() < deadline:
        now = [len(rec.captured) for rec in recs]
        if now != last:
            last, since = now, time.time()
        elif all(n >= t for n, t in zip(now, targets)) and time.time() - since >= quiet:
            return
        await asyncio.sleep(0.1)


def read_cert(name):
    with open(os.path.join(CERTS, name), "rb") as f:
        return f.read()


class VeloStandIn:
    """`proto.API/Query`, answered by `answer(self, vql, org_id)` -> (chunks, error)."""

    def __init__(self, port, answer):
        self.answer = answer
        self.mode = {}
        self.captured = []
        self.lock = threading.Lock()
        stand_in = self

        class Handler(grpc.GenericRpcHandler):
            def service(self, details):
                if details.method != "/proto.API/Query":
                    return None
                return grpc.unary_stream_rpc_method_handler(stand_in.query, request_deserializer=None, response_serializer=None)

        self.server = grpc.server(futures.ThreadPoolExecutor(16), handlers=[Handler()])
        creds = grpc.ssl_server_credentials(
            [(read_cert("server.key"), read_cert("server.pem"))],
            root_certificates=read_cert("ca.pem"),
            require_client_auth=True,
        )
        self.server.add_secure_port(f"127.0.0.1:{port}", creds)
        self.server.start()
        self.address = f"127.0.0.1:{port}"

    def query(self, raw, context):
        req = api_pb2.VQLCollectorArgs.FromString(raw)
        remaining = context.time_remaining()
        # The deadline to the nearest 5 s: grpc-core reads the remaining time off its
        # clock when the call starts, usually a millisecond over what Python asked
        # for, and rounds it up to its header's unit (300 s goes as `301S`, or as
        # `5M` when the clock reads it exactly, which is what Rust sends).
        with self.lock:
            self.captured.append({"request": raw.hex(), "deadline": None if remaining is None else 5 * round(remaining / 5)})
        chunks, error = self.answer(self, req.Query[0].VQL, req.org_id)
        yield api_pb2.VQLResponse(log="query started").SerializeToString()
        for chunk in chunks:
            if chunk == "hang":
                time.sleep(QUERY_TIMEOUT + 2)
                continue
            yield api_pb2.VQLResponse(Response=chunk if isinstance(chunk, str) else json.dumps(chunk)).SerializeToString()
        if error:
            context.abort(*error)

    def take(self):
        with self.lock:
            out, self.captured[:] = list(self.captured), []
        return out

    def stop(self):
        self.server.stop(0)


def velo_clients(org):
    return VELO_CLIENTS.get(org, [])


def client_row(client_id, hostname, last_seen_us, version="0.7.1"):
    return {
        "client_id": client_id,
        "agent_information": {"version": version, "name": "velociraptor", "build_time": "2026-01-01", "build_url": "u"},
        "os_info": {
            "system": "linux",
            "hostname": hostname,
            "release": "ubuntu",
            "machine": "x86_64",
            "fqdn": f"{hostname}.local",
            "mac_addresses": ["00:11:22:33:44:55"],
        },
        "first_seen_at": 1700000000,
        "last_seen_at": last_seen_us,
        "last_ip": "10.0.0.5:4444",
        "last_interrogate_flow_id": "F.ABC",
        "last_interrogate_artifact_name": "Generic.Client.Info",
        "labels": ["parity"],
        "last_hunt_timestamp": 0,
        "last_event_table_version": 1,
        "last_label_timestamp": 0,
        "extra": {"ignored": True},
    }


ORG2 = f"O{SFX.upper()}"
VELO_CLIENTS = {}


def velo_answer(stand_in, vql, org_id):
    mode = stand_in.mode
    if mode.get("deny"):
        return [], (grpc.StatusCode.PERMISSION_DENIED, f"Permission denied: api requires ANY_QUERY in {org_id}")
    if mode.get("unavailable"):
        return [], (grpc.StatusCode.UNAVAILABLE, "datastore is restarting é")
    if mode.get("hang"):
        return ["hang"], None
    if mode.get("not_json"):
        return ["{nope"], None
    if vql == "SELECT * FROM orgs()":
        if mode.get("bad_orgs"):
            return [[{"Name": "root"}]], None
        return [
            [{"Name": "<root>", "OrgId": "root", "_client_config": "Client:\n  server_urls: []\n"}],
            [{"Name": "Second", "OrgId": ORG2}],
        ], None
    m = re.fullmatch(r"SELECT \* FROM query\(org_id='([^']*)', query='SELECT \* FROM clients\(\)'\)", vql)
    if m:
        rows = velo_clients(m.group(1))
        return [rows[:1], rows[1:]] if rows else [[]], None
    if vql.startswith("SELECT collect_client(client_id='server'"):
        return [[{"collect_client(client_id='server', ...)": {"flow_id": "F.DEL", "request": {"creator": "api"}}}]], None
    if vql == "select * from config":
        if mode.get("no_version"):
            return [[]], None
        return [[{"version": {"name": "velociraptor", "version": mode.get("server_version", "0.7.1"), "commit": "abc"}}]], None
    if vql.startswith("SELECT name,description,parameters FROM artifact_definitions()"):
        rows = list(ARTIFACT_DEFS)
        if mode.get("bad_artifact"):
            rows.append({"name": "Linux.Broken", "parameters": [{"default": 3}]})
        if mode.get("artifact_str"):
            rows.append("Linux.Plain")
        m = re.fullmatch(r".* WHERE name = '(.*)'", vql)
        if m:
            rows = [r for r in rows if isinstance(r, dict) and r.get("name") == m.group(1)]
        return [rows[:3], rows[3:]], None
    if vql.startswith("SELECT collect_client(org_id="):
        if mode.get("deny_collect"):
            return [], (grpc.StatusCode.PERMISSION_DENIED, f"Permission denied: COLLECT_CLIENT in {org_id}")
        call = vql[len("SELECT ") : -len(" FROM scope()")]
        flow = 7 if mode.get("flow_id_int") else "F.CL" + SFX.upper()
        return [[{call: {"flow_id": flow, "request": {"creator": "api", "artifacts": ["x"]}}}]], None
    if vql.startswith("SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId="):
        return [[{"FlowId": vql.split("FlowId='")[1].split("'")[0], "ClientId": "C.x"}]], None
    if vql.startswith("SELECT * FROM source(") or vql.startswith("SELECT * FROM flow_results("):
        if mode.get("rows_not_dicts"):
            return [[1, "two"]], None
        return [[{"Stdout": "uid=0(root) gid=0(root) é", "Stderr": "", "ReturnCode": 0}], [{"Stdout": "", "Complete": True}]], None
    if vql.startswith("SELECT * FROM flows(client_id="):
        return [FLOW_ROWS[:2], FLOW_ROWS[2:]], None
    if vql == "SELECT * FROM info()":
        return [[{"Hostname": "velo-server", "Uptime": 1}], {"not": "a list"}] if mode.get("dict_chunk") else [
            [{"Hostname": "velo-server"}],
        ], None
    return [], (grpc.StatusCode.INVALID_ARGUMENT, f"unexpected VQL: {vql}")


ARTIFACT_DEFS = [
    {
        "name": "Linux.Sys.BashShell",
        "description": "Run a bash command.",
        "parameters": [{"name": "Command", "default": "ls -l /", "type": "", "description": "The command"}],
        "author": "Mike",
        "column_types": [],
    },
    {
        "name": "Linux.Remediation.Quarantine",
        "description": "Quarantine a Linux host.",
        "parameters": [{"name": "RemovePolicy", "type": "bool"}],
    },
    {"name": "Custom.Linux.Remediation.Quarantine", "description": "Without the connection test.", "precondition": "SELECT OS From info()"},
    {"name": "Windows.System.PowerShell", "description": "PowerShell", "parameters": [{"name": "Command", "default": True}]},
    {"name": "Windows.System.CmdShell", "description": "cmd"},
    {"name": "Windows.Remediation.Quarantine", "description": "Quarantine a Windows host.", "parameters": None},
    {
        "name": "Windows.AttackSimulation.AtomicRedTeam",
        "description": "Atomic Red Team",
        "parameters": [
            {"name": "T1552.001 - 4", "description": "Access unattend.xml", "type": "bool"},
            {"name": "InstallART", "default": "N"},
            {"name": "T1552.001 - 3", "description": "findstr", "type": "bool", "default": "Y"},
            {"name": "T1003 - 1", "type": "bool", "friendly_name": "x"},
        ],
    },
    {"name": "MacOS.Applications.Chrome.History", "description": "Chrome", "author": None},
    {"name": "Generic.Client.Info", "description": "Client info"},
    {"name": "LinuxStray.Thing", "description": "starts with Linux, not Linux."},
]
FLOW_ROWS = [
    {
        "session_id": "F.ONE",
        "client_id": "C.x",
        "request": {
            "creator": "admin",
            "artifacts": ["Linux.Sys.BashShell"],
            "specs": [{"artifact": "Linux.Sys.BashShell", "parameters": {"env": [{"key": "Command", "value": "id"}]}}, "junk"],
            "urgent": True,
            "timeout": "600",
        },
        "create_time": 1760600000123456,
        "state": "FINISHED",
        "query_stats": [{"status": "OK", "duration": 12, "names_with_response": ["Linux.Sys.BashShell"], "extra": 1}],
        "uploaded_files": [],
        "new_field": {"ignored": True},
    },
    {"session_id": "F.TWO", "request": {"specs": [{"artifact": "A", "parameters": [{"key": "k", "value": "v", "comment": None}]}]}},
    "not a flow",
    {"session_id": "F.BAD", "create_time": "yesterday"},
    {"session_id": "F.SPECS", "request": {"specs": 5}},
    {"session_id": "F.NOREQ", "request": None},
    {},
]


def api_config(directory, address, ca="ca.pem", name="api.config.yaml", raw=None):
    """An api.config.yaml as `velociraptor config api_client` writes it."""

    def block(data):
        return "".join(f"  {line}\n" for line in data.decode().splitlines())

    path = os.path.join(directory, name)
    with open(path, "w") as f:
        if raw is not None:
            f.write(raw)
        else:
            f.write(
                f"ca_certificate: |\n{block(read_cert(ca))}client_cert: |\n{block(read_cert('client.pem'))}"
                f"client_private_key: |\n{block(read_cert('client.key'))}api_connection_string: {address}\nname: api\n"
                "pinned_server_name: VelociraptorServer\n",
            )
    return path


# --- Database --------------------------------------------------------------------------
def build_python_app():
    from app.agents.routes.agents import agents_router
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors
    from app.routers import velociraptor

    api = APIRouter(prefix="/api")
    api.include_router(agents_router, prefix="/agents")
    api.include_router(connectors.router)
    api.include_router(velociraptor.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


async def sql(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        await s.commit()
        return r


async def rows(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        return [dict(m) for m in r.mappings().all()]


async def set_connector(name, url, username=None, password=None, api_key=None, extra=None, verified=1):
    await sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    if url is None:
        return None
    r = await sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
        "(:n, '4.8.0', :u, '2026-01-02 03:04:05', :user, :pw, :key, 'Parity connector', 'everything', 1, :v, 0, 0, 1, 0, 0, :x, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
        key=api_key,
        x=extra,
        v=verified,
    )
    return r.lastrowid


async def settle():
    """Let both processes' connector caches see a row written here."""
    await asyncio.sleep(connector_cache.CHECK_SECONDS + 0.5)


#: key -> (agent_id, hostname, customer, velociraptor_id, status, last seen, version, velociraptor version, pinned)
AGENTS = {
    "a1": (f"{SFX}01", f"a1-{SFX}", CUST_A, f"C.{SFX}a1", "active", "2026-10-15 08:00:00", "Wazuh v4.7.2", "0.7.1", 0),
    "a2": (f"{SFX}02", f"a2-{SFX}", CUST_A, None, "disconnected", "2020-01-01 00:00:00", "Wazuh v4.9.0", None, 0),
    "a3": (f"{SFX}03", f"dup-{SFX}", CUST_A, "Unknown", "never_connected", "2026-10-15 08:00:00", "Wazuh v4.9.0", "0.6.9", 0),
    "a4": (f"{SFX}04", f"null-{SFX}", CUST_A, f"C.{SFX}a4", "active", "2026-10-15 08:00:00", "Wazuh v4.9.0", "0.7.1", 1),
    "b1": (f"{SFX}11", f"b1-{SFX}", CUST_B, f"C.{SFX}b1", "active", "2026-10-15 08:00:00", "Wazuh v4.7.2", "0.7.1", 0),
    "b2": (f"{SFX}12", f"dup-{SFX}", CUST_B, None, "disconnected", "2020-01-01 00:00:00", "Wazuh v4.9.0", None, 0),
    "n1": (f"{SFX}21", f"null-{SFX}", None, None, "active", "2026-10-15 08:00:00", "Wazuh v4.9.0", None, 0),
    "w1": (f"{SFX}05", f"win-{SFX}", CUST_A, f"C.{SFX}e1-{SFX.upper()}", "active", "2026-10-15 08:00:00", "Wazuh v4.9.0", "0.7.1", 0),
    "x1": (f"{SFX}06", f"deb-{SFX}", CUST_A, f"C.{SFX}f1", "active", "2026-10-15 08:00:00", "Wazuh v4.9.0", "0.7.1", 0),
    "na": (f"{SFX}07", f"na-{SFX}", CUST_A, "n/a", "active", "2026-10-15 08:00:00", "Wazuh v4.9.0", None, 0),
}
#: The `os` of the agents that are not Ubuntu.
AGENT_OS = {"w1": "Microsoft Windows 11 Pro", "x1": "FreeBSD 14.1"}
IDS = {}


async def insert_agent(key):
    agent_id, host, cust, vid, status, seen, version, vversion, pinned = AGENTS[key]
    await sql(
        "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, velociraptor_id, "
        "velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, velociraptor_agent_version, customer_code, quarantined, "
        "velociraptor_org, velociraptor_id_pinned) VALUES (:i, :a, '10.0.0.7', :os, :h, :l, 0, :s, :v, :vs, :wv, :st, "
        ":vv, :c, 0, :o, :p)",
        i=IDS[key],
        os=AGENT_OS.get(key, "Ubuntu 22.04"),
        a=agent_id,
        h=host,
        l=f"grp_{cust}" if cust else "default",
        s=seen,
        v=vid,
        vs="2026-10-15 07:59:00" if vid else None,
        wv=version,
        st=status,
        vv=vversion,
        c=cust,
        o=(ORG2 if key == "w1" else "root") if vid else None,
        p=pinned,
    )


async def reset_agents():
    """Every seeded agent back to its seeded state (deleted ones re-inserted)."""
    await sql("DELETE FROM agent_vulnerabilities WHERE agent_id IN :ids".replace(":ids", in_list(a[0] for a in AGENTS.values())))
    await sql("DELETE FROM agent_datastore WHERE agent_id IN :ids".replace(":ids", in_list(a[0] for a in AGENTS.values())))
    await sql("DELETE FROM agents WHERE id IN " + in_list(IDS.values()))
    for key in AGENTS:
        await insert_agent(key)
    a1 = AGENTS["a1"][0]
    await sql(
        "INSERT INTO agent_vulnerabilities (cve_id, severity, title, `references`, status, discovered_at, agent_id, customer_code) "
        "VALUES ('CVE-2023-0286', 'High', 't', NULL, 'open', '2026-10-01 00:00:00', :a, :c)",
        a=a1,
        c=CUST_A,
    )
    await sql(
        "INSERT INTO agent_datastore (agent_id, velociraptor_id, artifact_name, flow_id, collection_time, bucket_name, object_key, "
        "file_name, content_type, file_size, file_hash, status) VALUES (:a, :v, 'Generic.Client.Info', 'F.1', '2026-10-01 00:00:00', "
        "'velociraptor-artifacts', 'k', 'f.zip', 'application/zip', 1, 'h', 'completed')",
        a=a1,
        v=AGENTS["a1"][3],
    )
    await sql("DELETE FROM audit_log WHERE entity_type = 'agent' AND entity_id IN " + in_list(a[0] for a in AGENTS.values()))


def in_list(values):
    return "(" + ",".join(repr(str(v)) if not isinstance(v, int) else str(v) for v in values) + ")"


async def agent_rows():
    # The Rust audit sink spawns its write after the answer: give it a moment.
    await asyncio.sleep(0.3)
    found = await rows("SELECT * FROM agents WHERE id IN " + in_list(IDS.values()) + " ORDER BY id")
    vulns = await rows(
        "SELECT agent_id, cve_id FROM agent_vulnerabilities WHERE agent_id IN " + in_list(a[0] for a in AGENTS.values()) + " ORDER BY id",
    )
    store = await rows(
        "SELECT agent_id, flow_id FROM agent_datastore WHERE agent_id IN " + in_list(a[0] for a in AGENTS.values()) + " ORDER BY id",
    )
    audit = await rows(
        "SELECT actor_username, customer_code, action, entity_type, entity_id, result, old_value, new_value, details FROM audit_log "
        "WHERE entity_type = 'agent' AND entity_id IN " + in_list(a[0] for a in AGENTS.values()) + " ORDER BY id",
    )
    return {"agents": found, "vulnerabilities": vulns, "datastore": store, "audit": audit}


async def velo_rows():
    """The quarantine flags and the response audit rows (by hostname)."""
    await asyncio.sleep(0.3)  # the Rust audit sink writes on a task of its own
    hosts = sorted({v[1] for v in AGENTS.values()})
    return {
        "agents": await rows("SELECT hostname, quarantined FROM agents WHERE id IN " + in_list(IDS[k] for k in AGENTS) + " ORDER BY id"),
        "audit": await rows(
            "SELECT actor_username, customer_code, action, entity_type, entity_id, result, old_value, new_value, details "
            "FROM audit_log WHERE entity_type = 'agent' AND entity_id IN " + in_list(hosts) + " ORDER BY id",
        ),
    }


async def reset_velo():
    await reset_agents()
    await sql("DELETE FROM audit_log WHERE entity_type = 'agent' AND entity_id IN " + in_list(sorted({v[1] for v in AGENTS.values()})))


async def seed():
    for c in (CUST_A, CUST_B):
        await sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=c, n=f"{c} Corp")
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (SCHED, 3), (RESP, 5)):
        await sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r)",
            n=name,
            e=f"{name}@parity.test",
            r=role,
        )
    for name in (ANALYST, PORTAL, RESP):
        await sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
            "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )
    # Explicit ids, at least seven digits and above every existing one.
    top = 0
    for table in ("agents", "incident_management_alert", "incident_management_case"):
        top = max(top, (await rows(f"SELECT COALESCE(MAX(id), 0) AS n FROM {table}"))[0]["n"])
    base = max(top + 100, 1_000_000)
    for i, key in enumerate(AGENTS):
        IDS[key] = base + i
    await reset_agents()
    # Cases on the shared hostname: one in each tenant, plus a case the agent's own
    # tenant links twice (the join used to list it once per alert).
    ctx = (await sql("INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')")).lastrowid
    IDS["ctx"] = ctx
    host = f"dup-{SFX}"
    for i, (key, cust, asset) in enumerate(
        (("alA", CUST_A, host), ("alA2", CUST_A, host), ("alB", CUST_B, host), ("alX", CUST_A, "other")),
    ):
        IDS[key] = base + 100 + i
        await sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
            "source, escalated, severity) VALUES (:i, :n, 'd', 'OPEN', '2026-10-01 10:00:00', :c, 'wazuh', 0, 'High')",
            i=IDS[key],
            n=f"Alert {key} {SFX}",
            c=cust,
        )
        await sql(
            "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, customer_code, index_name, index_id, "
            "agent_id) VALUES (:a, :n, :ctx, :c, 'wazuh-alerts-1', 'doc', '007')",
            a=IDS[key],
            n=asset,
            ctx=ctx,
            c=cust,
        )
    for i, (key, cust, alerts) in enumerate((("caA", CUST_A, ("alA", "alA2")), ("caB", CUST_B, ("alB",)), ("caX", CUST_A, ("alX",)))):
        IDS[key] = base + 200 + i
        await sql(
            "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, customer_code, "
            "notification_invoked_number, escalated) VALUES (:i, :n, 'cd', '2026-10-02 09:00:00', 'OPEN', :c, 0, 0)",
            i=IDS[key],
            n=f"Case {key} {SFX}",
            c=cust,
        )
        for a in alerts:
            await sql("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=IDS[key], a=IDS[a])


async def cleanup():
    cases = in_list(IDS[k] for k in ("caA", "caB", "caX") if k in IDS)
    alerts = in_list(IDS[k] for k in ("alA", "alA2", "alB", "alX") if k in IDS)
    if cases != "()":
        await sql("DELETE FROM incident_management_casealertlink WHERE case_id IN " + cases)
        await sql("DELETE FROM incident_management_case WHERE id IN " + cases)
    if alerts != "()":
        await sql("DELETE FROM incident_management_asset WHERE alert_linked IN " + alerts)
        await sql("DELETE FROM incident_management_alert WHERE id IN " + alerts)
    if "ctx" in IDS:
        await sql("DELETE FROM incident_management_alertcontext WHERE id = :i", i=IDS["ctx"])
    ours = in_list(a[0] for a in AGENTS.values())
    await sql("DELETE FROM agent_vulnerabilities WHERE agent_id IN " + ours)
    await sql("DELETE FROM agent_datastore WHERE agent_id IN " + ours)
    await sql("DELETE FROM agents WHERE id IN " + in_list(IDS[k] for k in AGENTS if k in IDS))
    await sql("DELETE FROM agents WHERE hostname LIKE :h", h=f"%{SFX}%")
    await sql("DELETE FROM agents WHERE agent_id = '000' AND hostname = :h", h=f"manager-{SFX}")
    await sql("DELETE FROM audit_log WHERE actor_username IN " + in_list(USERS))
    await sql("DELETE FROM scheduled_job_metadata WHERE job_id = 'agent_sync' AND job_description = 'parity'")
    for name in OUR_CONNECTORS:
        await sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    await sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username IN " + in_list(USERS) + ")")
    await sql("DELETE FROM `user` WHERE username IN " + in_list(USERS))
    await sql("DELETE FROM customers WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)


# --- The checks ------------------------------------------------------------------------
async def main():  # noqa: C901 - one scenario after the other
    await seed()
    from app.threat_intel.services import epss as epss_module

    epss_module.EPSS_URL = f"http://127.0.0.1:{EPSS_PORT}/data/v1/epss"
    mgr = Recorder(mgr_answer, MANAGER_PORT, "mgr")
    es = Recorder(es_answer, INDEXER_PORT, "es")
    es.pages = {}
    epss = Recorder(epss_answer, EPSS_PORT, "epss")
    velo = VeloStandIn(VELO_PORT, velo_answer)
    gelf_server = start_gelf_stub(GELF_PORT)
    workdir = tempfile.mkdtemp(prefix="agents-parity-")
    velo_config = api_config(workdir, velo.address)
    a1, a2, a3, a4 = (AGENTS[k][0] for k in ("a1", "a2", "a3", "a4"))
    b1 = AGENTS["b1"][0]
    host = {k: v[1] for k, v in AGENTS.items()}
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
    t_portal, t_sched = token(PORTAL, ["customer_user"]), token(SCHED, ["scheduler"])

    def body_of(r):
        try:
            return canonical(r.json())
        except ValueError:
            return r.text

    rust_orders = []

    async def both(
        name,
        method,
        path,
        tok=None,
        body=None,
        raw=None,
        headers=None,
        recs=(),
        reset=None,
        snapshot=None,
        gelf=False,
        background=False,
        unordered=False,
    ):
        """The responses, what each backend sent upstream and (`snapshot`) the rows it left.

        `background`: the route's work goes on after its answer (Python's background
        tasks have run when the in-process ASGI call returns, Rust's run on a task of
        their own), so Rust's upstream traffic is awaited until it settles. `unordered`:
        requests a backend sends concurrently are compared as a set."""
        got = {}
        for tag, client in (("py", py), ("rs", rs)):
            if reset is not None:
                await reset()
            for rec in recs:
                rec.take()
            if gelf:
                take_gelf(0, timeout=0)
            kw = {"headers": {**({"Authorization": f"Bearer {tok}"} if tok else {}), **(headers or {})}}
            if raw is not None:
                kw["content"] = raw
                kw["headers"]["Content-Type"] = "application/json"
            elif body is not None:
                kw["json"] = body
            r = await client.request(method, path, **kw)
            if background and tag == "rs":
                await wait_for_traffic([len(got["py"]["upstream"][getattr(rec, "name", "velo")]) for rec in recs], recs)
            if tag == "rs":
                try:
                    agent_orders(r.json(), rust_orders)
                except ValueError:
                    pass
            frames = None
            if gelf:
                # Python's background tasks have run when the ASGI call returns; Rust's
                # run on a task of their own after the answer.
                frames = take_gelf(len(got["py"]["gelf"]), timeout=10) if tag == "rs" else take_gelf(0, timeout=0)
                if tag == "rs" and not got["py"]["gelf"]:
                    time.sleep(1.5)
                    frames += take_gelf(0, timeout=0)
            got[tag] = {
                "status": r.status_code,
                "type": r.headers.get("content-type"),
                "disposition": r.headers.get("content-disposition"),
                "body": body_of(r),
                "upstream": {
                    getattr(rec, "name", "velo"): (normalised(rec.take(), unordered) if isinstance(rec, Recorder) else rec.take())
                    for rec in recs
                },
                "rows": await snapshot() if snapshot else None,
                "gelf": frames,
            }
        p, q = got["py"], got["rs"]
        p["body"], q["body"] = grpc_canon(p["body"]), grpc_canon(q["body"])
        same_response = all(p[k] == q[k] for k in ("status", "type", "disposition")) and json.dumps(p["body"], default=str) == json.dumps(
            q["body"],
            default=str,
        )
        check(
            f"{name} [{p['status']}]",
            same_response,
            f"python {p['status']} {p['type']} {p['disposition']} {json.dumps(p['body'], default=str)[:1500]}\n"
            f"        rust   {q['status']} {q['type']} {q['disposition']} {json.dumps(q['body'], default=str)[:1500]}",
        )
        for tool in p["upstream"]:
            a, b = p["upstream"][tool], q["upstream"][tool]
            first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), None)
            check(
                f"{name}: requests to {tool} ({len(a)})",
                a == b,
                f"python {[x.get('method', '') + ' ' + x.get('path', x.get('request', '')[:40]) for x in a]}\n"
                f"        rust   {[x.get('method', '') + ' ' + x.get('path', x.get('request', '')[:40]) for x in b]}"
                + (
                    f"\n        first difference #{first}:\n        python {json.dumps(a[first])[:2000]}\n        rust   {json.dumps(b[first])[:2000]}"
                    if first is not None
                    else ""
                ),
            )
        if snapshot:
            check(
                f"{name}: rows",
                json.dumps(p["rows"], default=str) == json.dumps(q["rows"], default=str),
                f"python {json.dumps(p['rows'], default=str)[:2500]}\n        rust   {json.dumps(q['rows'], default=str)[:2500]}",
            )
        if gelf:
            check(
                f"{name}: GELF frames ({len(p['gelf'])})",
                p["gelf"] == q["gelf"],
                f"python {[f[:300] for f in p['gelf']]}\n        rust   {[f[:300] for f in q['gelf']]}",
            )
        return p, q

    A = "/api/agents"
    try:
        # ==================================================================
        print("\n=== A. reads (database only) ===")
        await both("list: no token", "GET", A)
        await both("list: garbage token", "GET", A, "garbage")
        await both("list: 2fa temp token", "GET", A, token(ADMIN, [], type="2fa_pending"))
        await both("list: scheduler", "GET", A, t_sched)
        await both("list: analyst", "GET", A, t_analyst)
        await both("list: portal user", "GET", A, t_portal)
        await both("list: analyst asks for B", "GET", A + f"?customer_codes={CUST_B}", t_analyst)
        await both("list: admin, both tenants", "GET", A + f"?customer_codes={CUST_A}&customer_codes={CUST_B}", t_admin)
        await both("list: admin, bracketed codes", "GET", A + f"?customer_codes[]={CUST_B}", t_admin)
        await both("list: admin, legacy customer_code", "GET", A + f"?customer_code={CUST_B}", t_admin)
        await both(
            "list: search, case-insensitive",
            "GET",
            A + f"?search=DUP-{SFX}&customer_codes={CUST_A}&customer_codes={CUST_B}",
            t_admin,
        )
        await both("list: search and limit", "GET", A + f"?search={SFX}&limit=2", t_analyst)
        await both("list: limit 0", "GET", A + "?limit=0", t_analyst)
        await both("list: limit not an int", "GET", A + "?limit=ten&search=x", t_analyst)
        await both("list: admin, everything", "GET", A, t_admin)
        await both("one: no token", "GET", A + f"/{a1}")
        await both("one: own", "GET", A + f"/{a1}", t_analyst)
        await both("one: another tenant's (the 404 inside the try)", "GET", A + f"/{b1}", t_analyst)
        await both("one: missing", "GET", A + "/no-such-agent", t_admin)
        await both("one: admin", "GET", A + f"/{b1}", t_admin)
        await both("one: portal user", "GET", A + f"/{a2}", t_portal)
        await both("hostname: own", "GET", A + f"/hostname/{host['a1']}", t_analyst)
        await both("hostname: shared, first visible", "GET", A + f"/hostname/{host['a3']}", t_analyst)
        await both("hostname: another tenant's", "GET", A + f"/hostname/{host['b1']}", t_analyst)
        await both("hostname: missing", "GET", A + "/hostname/nobody", t_admin)
        await both("dashboard: no header", "GET", A + "/dashboard/agents")
        await both("dashboard: wrong header", "GET", A + "/dashboard/agents", headers={"grafana": "nope"})
        await both("dashboard: no customer", "GET", A + "/dashboard/agents", headers={"grafana": GRAFANA_HEADER})
        await both("dashboard: customer A", "GET", A + "/dashboard/agents", headers={"grafana": GRAFANA_HEADER, "customer-code": CUST_A})
        await both(
            "dashboard: unknown customer",
            "GET",
            A + "/dashboard/agents",
            headers={"grafana": GRAFANA_HEADER, "customer-code": "nobody"},
        )
        await both("cases: analyst (own tenant only, each case once)", "GET", A + f"/{host['a3']}/cases", t_analyst)
        await both("cases: admin (both tenants with that hostname)", "GET", A + f"/{host['a3']}/cases", t_admin)
        await both("cases: another tenant's hostname", "GET", A + f"/{host['b1']}/cases", t_analyst)
        await both("cases: unknown hostname", "GET", A + "/nobody/cases", t_admin)
        await both("cases: a hostname held with and without a customer", "GET", A + f"/{host['a4']}/cases", t_admin)
        await both("cases: portal user", "GET", A + f"/{host['a1']}/cases", t_portal)
        await both("outdated wazuh: portal user", "GET", A + "/wazuh/outdated", t_portal)
        await both("outdated wazuh: no manager row", "GET", A + "/wazuh/outdated", t_admin)
        await sql(
            "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, wazuh_agent_version, "
            "wazuh_agent_status, quarantined, velociraptor_id_pinned) VALUES ('000', '127.0.0.1', 'Linux', :h, 'manager', 0, "
            "'2026-10-15 00:00:00', 'Wazuh v4.9.0', 'active', 0, 0)",
            h=f"manager-{SFX}",
        )
        await both("outdated wazuh: admin", "GET", A + "/wazuh/outdated", t_admin)
        p, q = await asyncio.gather(
            py.get(A + "/wazuh/outdated", headers={"Authorization": f"Bearer {t_analyst}"}),
            rs.get(A + "/wazuh/outdated", headers={"Authorization": f"Bearer {t_analyst}"}),
        )
        py_codes = {a["customer_code"] for a in p.json()["outdated_wazuh_agents"]}
        rs_codes = {a["customer_code"] for a in q.json()["outdated_wazuh_agents"]}
        check(
            "outdated wazuh (by design): Rust lists the analyst's customers only, Python every tenant's",
            rs_codes == {CUST_A} and {CUST_A, CUST_B} <= py_codes,
            f"python {sorted(map(str, py_codes))[:6]} rust {sorted(map(str, rs_codes))}",
        )

        # ==================================================================
        print("\n=== B. Wazuh manager and indexer ===")
        await set_connector("Wazuh-Manager", mgr.url, MGR_USER, MGR_PASS)
        await set_connector("Wazuh-Indexer", es.url, ES_USER, ES_PASS)
        await set_connector("Event Shipper", "127.0.0.1", extra=str(GELF_PORT))
        await settle()
        M = (mgr,)
        MI = (mgr, es)
        es.mode["docs"] = [
            {"_index": STATES[0], **state_doc(a1, host["a1"], "CVE-2023-0286", "Critical")},
            {
                "_index": STATES[0],
                **state_doc(a1, host["a1"], "CVE-2024-0001", "High", "curl", "7.0", ["https://a.test", "https://b.test"]),
            },
            {"_index": STATES[1], **state_doc(a1, host["a1"], "CVE-2024-0002", "Low", "zlib", "1.2")},
            {"_index": STATES[1], **state_doc(a1, host["a1"], "CVE-2024-0009", "Medium", "bash", "5.1")},
            {"_index": STATES[1], **state_doc(a1, host["a1"], "CVE-2023-0286", "Critical", "libssl3", "3.0.1")},
            {"_index": STATES[0], **state_doc(b1, host["b1"], "CVE-2024-0005", "High")},
        ]
        await both("vulns: bad severity", "GET", A + f"/{a1}/vulnerabilities/Severe", t_analyst, recs=M)
        await both("vulns: another tenant's agent (nothing asked)", "GET", A + f"/{b1}/vulnerabilities/All", t_analyst, recs=M)
        await both("vulns (manager API): Critical", "GET", A + f"/{a1}/vulnerabilities/Critical", t_analyst, recs=MI)
        await both("vulns (manager API): All", "GET", A + f"/{a1}/vulnerabilities/All", t_portal, recs=MI)
        mgr.mode["bad_vuln"] = True
        await both("vulns (manager API): an invalid row", "GET", A + f"/{a1}/vulnerabilities/Low", t_analyst, recs=MI)
        mgr.mode.clear()
        await both("vuln by CVE (manager API)", "GET", A + f"/{a1}/vulnerabilities/cve/CVE-2024-0001", t_analyst, recs=MI)
        await both("vuln by CVE (manager API): unknown", "GET", A + f"/{a1}/vulnerabilities/cve/CVE-1999-0001", t_analyst, recs=MI)
        await both(
            "vulns CSV (manager API, EPSS)",
            "GET",
            A + f"/{a1}/csv/vulnerabilities/All",
            t_analyst,
            recs=(mgr, es, epss),
        )
        mgr.mode["version"] = "4.9.0"
        await both("vulns (indexer): All, scrolled", "GET", A + f"/{a1}/vulnerabilities/All", t_analyst, recs=MI)
        await both("vulns (indexer): Critical", "GET", A + f"/{a1}/vulnerabilities/Critical", t_analyst, recs=MI)
        await both("vulns (indexer): none", "GET", A + f"/{a2}/vulnerabilities/High", t_analyst, recs=MI)
        await both(
            "vuln by CVE (indexer): two packages, the first",
            "GET",
            A + f"/{a1}/vulnerabilities/cve/CVE-2023-0286",
            t_analyst,
            recs=MI,
        )
        await both(
            "vuln by CVE (indexer): narrowed by package",
            "GET",
            A + f"/{a1}/vulnerabilities/cve/CVE-2023-0286?package=libssl3&version=3.0.1",
            t_analyst,
            recs=MI,
        )
        await both("vuln by CVE (indexer): unknown", "GET", A + f"/{a1}/vulnerabilities/cve/CVE-1999-0001?package=", t_analyst, recs=MI)
        await both("vulns CSV (indexer, EPSS)", "GET", A + f"/{a1}/csv/vulnerabilities/All", t_analyst, recs=(mgr, es, epss))
        epss.mode["down"] = True
        await both("vulns CSV: EPSS down (column empty)", "GET", A + f"/{a1}/csv/vulnerabilities/Critical", t_analyst, recs=(mgr, es, epss))
        epss.mode = {"not_json": True}
        await both("vulns CSV: EPSS answers HTML", "GET", A + f"/{a1}/csv/vulnerabilities/Critical", t_analyst, recs=(mgr, es, epss))
        epss.mode = {"list": True}
        await both("vulns CSV: EPSS answers a list", "GET", A + f"/{a1}/csv/vulnerabilities/Critical", t_analyst, recs=(mgr, es, epss))
        epss.mode = {}
        await both("vulns CSV: another tenant's agent", "GET", A + f"/{b1}/csv/vulnerabilities/All", t_analyst, recs=(mgr, epss))
        es.mode["docs"].append({"_index": STATES[0], **state_doc(a2, host["a2"], "CVE-2024-0007", "High", reference=[None])})
        await both("vulns (indexer): a reference that is not a string", "GET", A + f"/{a2}/vulnerabilities/All", t_analyst, recs=MI)
        es.mode["docs"].pop()
        mgr.mode["version"] = "not.a.version!"
        await both("vulns: an unreadable manager version reads as old", "GET", A + f"/{a1}/vulnerabilities/High", t_analyst, recs=MI)
        mgr.mode = {"fail": "/"}
        await both("vulns: manager failing", "GET", A + f"/{a1}/vulnerabilities/High", t_analyst, recs=MI)
        mgr.mode = {}

        await both("sca", "GET", A + f"/{a1}/sca", t_analyst, recs=M)
        await both("sca: one policy", "GET", A + f"/{a1}/sca?policy_id=sca_unix_audit", t_portal, recs=M)
        await both("sca: another tenant's agent", "GET", A + f"/{b1}/sca", t_analyst, recs=M)
        await both("sca policy results", "GET", A + f"/{a1}/sca/cis_ubuntu22-04", t_analyst, recs=M)
        await both("sca policy results: one check", "GET", A + f"/{a1}/sca/cis_ubuntu22-04?check_id=28501", t_analyst, recs=M)
        await both("sca policy results: check_id not an int", "GET", A + f"/{a1}/sca/x?check_id=abc", t_analyst, recs=M)
        await both("sca CSV", "GET", A + f"/{a1}/csv/sca/cis_ubuntu22-04", t_analyst, recs=M)
        mgr.mode["sca"] = "missing"
        await both("sca: the agent has no SCA data (400)", "GET", A + f"/{a1}/sca", t_analyst, recs=M)
        await both("sca policy results: no SCA data", "GET", A + f"/{a1}/sca/cis_ubuntu22-04", t_analyst, recs=M)
        await both("sca CSV: no SCA data", "GET", A + f"/{a1}/csv/sca/cis_ubuntu22-04", t_analyst, recs=M)
        mgr.mode["sca"] = "bad_check"
        await both("sca policy results: an invalid check", "GET", A + f"/{a1}/sca/cis_ubuntu22-04", t_analyst, recs=M)
        mgr.mode = {"fail": "/sca"}
        await both("sca: manager failing (500)", "GET", A + f"/{a1}/sca", t_analyst, recs=M)
        mgr.mode = {}

        await both("upgrade: portal user", "POST", A + f"/{a1}/wazuh/upgrade", t_portal, recs=M)
        await both("upgrade", "POST", A + f"/{a1}/wazuh/upgrade", t_analyst, recs=M)
        await both("upgrade: another tenant's agent", "POST", A + f"/{b1}/wazuh/upgrade", t_analyst, recs=M)
        mgr.mode["upgrade"] = "failed"
        await both("upgrade: refused by the manager", "POST", A + f"/{a1}/wazuh/upgrade", t_admin, recs=M)
        mgr.mode["upgrade"] = "odd"
        await both("upgrade: a message that is not a string", "POST", A + f"/{a1}/wazuh/upgrade", t_admin, recs=M)
        mgr.mode = {"fail": "/agents"}
        await both("upgrade: manager failing", "POST", A + f"/{a1}/wazuh/upgrade", t_admin, recs=M)
        # The token both hold expires and the credentials stop working.
        mgr.mode = {"reject_auth": True, "gen": 2}
        await both("vulns: manager rejects the credentials", "GET", A + f"/{a1}/vulnerabilities/High", t_analyst, recs=MI)
        await both("upgrade: manager rejects the credentials", "POST", A + f"/{a1}/wazuh/upgrade", t_admin, recs=M)
        mgr.mode = {}
        # No manager and no indexer configured.
        await set_connector("Wazuh-Manager", None)
        await set_connector("Wazuh-Indexer", None)
        await settle()
        await both("vulns: no manager connector", "GET", A + f"/{a1}/vulnerabilities/High", t_analyst, recs=MI)
        await both("vuln by CVE: no manager connector", "GET", A + f"/{a1}/vulnerabilities/cve/CVE-2024-0001", t_analyst, recs=MI)
        await both("sca: no manager connector", "GET", A + f"/{a1}/sca", t_analyst, recs=M)
        await both("upgrade: no manager connector", "POST", A + f"/{a1}/wazuh/upgrade", t_admin, recs=M)
        await both("sync: no manager connector", "POST", A + "/sync", t_admin, recs=M, snapshot=agent_rows)
        await both("delete: no manager connector", "DELETE", A + f"/{a3}/delete", t_admin, recs=M, reset=reset_agents, snapshot=agent_rows)
        await both("sync vulns: no indexer connector", "POST", A + f"/sync/vulnerabilities/{CUST_A}", t_admin, recs=MI, background=True)
        await set_connector("Wazuh-Manager", mgr.url, MGR_USER, MGR_PASS)
        await set_connector("Wazuh-Indexer", es.url, ES_USER, ES_PASS)
        # A new row: Rust keeps no token for it, Python's cache is by name.
        from app.connectors.wazuh_manager.utils.universal import (
            clear_all_wazuh_token_caches,
        )

        await clear_all_wazuh_token_caches()
        await settle()

        # ==================================================================
        print("\n=== C. writes ===")
        await sql("UPDATE agents SET critical_asset = 0 WHERE id IN " + in_list(IDS[k] for k in AGENTS))
        await both("critical", "POST", A + f"/{a1}/critical", t_portal, reset=reset_agents, snapshot=agent_rows)
        await both("critical: another tenant's agent", "POST", A + f"/{b1}/critical", t_analyst, reset=reset_agents, snapshot=agent_rows)
        await both("critical: missing", "POST", A + "/nope/critical", t_admin, reset=reset_agents, snapshot=agent_rows)
        await both("noncritical", "POST", A + f"/{a1}/noncritical", t_analyst, reset=reset_agents, snapshot=agent_rows)
        await both("noncritical: another tenant's agent", "POST", A + f"/{b1}/noncritical", t_analyst)
        await both("update: velociraptor_id required", "PUT", A + f"/{a1}/update", t_analyst)
        await both("update: portal user", "PUT", A + f"/{a1}/update?velociraptor_id=C.1", t_portal)
        await both("update: an id that is not one", "PUT", A + f"/{a1}/update?velociraptor_id=C.1'%20OR%201", t_analyst)
        await both(
            "update",
            "PUT",
            A + f"/{a2}/update?velociraptor_id=C.0123abcd-{ORG2}",
            t_analyst,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both(
            "update: another tenant's agent",
            "PUT",
            A + f"/{b1}/update?velociraptor_id=C.12",
            t_analyst,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both("unpin", "PUT", A + f"/{a4}/velociraptor/unpin", t_analyst, reset=reset_agents, snapshot=agent_rows)
        await both(
            "unpin: another tenant's agent",
            "PUT",
            A + f"/{b1}/velociraptor/unpin",
            t_analyst,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both("unpin: missing", "PUT", A + "/nope/velociraptor/unpin", t_admin)

        await set_connector("Velociraptor", "https://velo.parity.test", api_key=velo_config)
        await settle()
        V = (mgr, velo)
        await both("delete: portal user", "DELETE", A + f"/{a1}/delete", t_portal, recs=V)
        await both(
            "delete: another tenant's agent",
            "DELETE",
            A + f"/{b1}/delete",
            t_analyst,
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both("delete: missing", "DELETE", A + "/nope/delete", t_admin, recs=V)
        await both(
            "delete (Wazuh and Velociraptor)",
            "DELETE",
            A + f"/{a1}/delete",
            t_analyst,
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both(
            "delete: no Velociraptor client id",
            "DELETE",
            A + f"/{a2}/delete",
            t_admin,
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both("delete: client id Unknown", "DELETE", A + f"/{a3}/delete", t_admin, recs=V, reset=reset_agents, snapshot=agent_rows)
        mgr.mode["refuse_delete"] = True
        velo.mode["deny"] = True
        await both("delete: both upstreams refuse", "DELETE", A + f"/{a1}/delete", t_admin, recs=V, reset=reset_agents, snapshot=agent_rows)
        mgr.mode = {"fail": "/agents"}
        velo.mode = {"unavailable": True}
        await both(
            "delete: both upstreams failing",
            "DELETE",
            A + f"/{b1}/delete",
            t_admin,
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        mgr.mode, velo.mode = {}, {}
        await both("bulk: no token", "POST", A + "/bulk/delete", body={"agent_ids": []})
        await both("bulk: malformed JSON before the token", "POST", A + "/bulk/delete", raw=b"{")
        await both("bulk: agent_ids required", "POST", A + "/bulk/delete", t_analyst, {})
        await both("bulk: agent_ids not a list", "POST", A + "/bulk/delete", t_analyst, {"agent_ids": "x"})
        await both("bulk: ids not strings", "POST", A + "/bulk/delete", t_analyst, {"agent_ids": [1, None, "x"]})
        await both(
            "bulk: own, another tenant's and a missing agent",
            "POST",
            A + "/bulk/delete",
            t_analyst,
            {"agent_ids": [a2, b1, "nope", a1]},
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        velo.mode["deny"] = True
        await both(
            "bulk: Velociraptor refusing (a warning)",
            "POST",
            A + "/bulk/delete",
            t_admin,
            {"agent_ids": [b1]},
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        velo.mode = {}
        await both("bulk filter: nothing given", "POST", A + "/bulk/delete/filter", t_analyst, {})
        await both("bulk filter: empty customer only", "POST", A + "/bulk/delete/filter", t_analyst, {"customer_code": ""})
        await both("bulk filter: bad status", "POST", A + "/bulk/delete/filter", t_analyst, {"status": "gone", "disconnected_days": 0})
        await both(
            "bulk filter: days not an int",
            "POST",
            A + "/bulk/delete/filter",
            t_analyst,
            {"disconnected_days": "x", "customer_code": 5},
        )
        await both(
            "bulk filter: own customer, disconnected",
            "POST",
            A + "/bulk/delete/filter",
            t_analyst,
            {"customer_code": CUST_A, "status": "disconnected"},
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both(
            "bulk filter: another tenant's customer (nothing)",
            "POST",
            A + "/bulk/delete/filter",
            t_analyst,
            {"customer_code": CUST_B},
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both(
            "bulk filter: admin, B, not seen for 30 days",
            "POST",
            A + "/bulk/delete/filter",
            t_admin,
            {"customer_code": CUST_B, "disconnected_days": 30},
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await reset_agents()

        # ==================================================================
        print("\n=== D. Velociraptor ===")
        velo_id = (await rows("SELECT id FROM connectors WHERE connector_name = 'Velociraptor'"))[0]["id"]

        async def velo_row():
            r = await rows("SELECT connector_verified FROM connectors WHERE id = :i", i=velo_id)
            return r

        async def unverify():
            await sql("UPDATE connectors SET connector_verified = 0 WHERE id = :i", i=velo_id)

        VERIFY = f"/api/connectors/verify/{velo_id}"
        await both("verify", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        velo.mode["dict_chunk"] = True
        await both("verify: a chunk that is not a list", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        velo.mode = {"deny": True}
        await both("verify: the server refuses", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        velo.mode = {}
        api_config(workdir, velo.address, ca="server.pem")
        await both(
            "verify: the server certificate pinned as the CA",
            "POST",
            VERIFY,
            t_admin,
            recs=(velo,),
            reset=unverify,
            snapshot=velo_row,
        )
        api_config(workdir, velo.address, ca="client.pem")
        await both("verify: a CA that did not sign the server", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        api_config(workdir, f"127.0.0.1:{CLOSED_PORT}")
        await both("verify: nothing listening", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        api_config(workdir, velo.address, raw="ca_certificate: [unclosed\n")
        # A §4 row: the parser's own sentence is libyaml's, not PyYAML's; the rest is the same.
        texts = []
        for client in (py, rs):
            await unverify()
            r = await client.post(VERIFY, headers={"Authorization": f"Bearer {t_admin}"})
            texts.append((r.status_code, r.json()["message"].split(".yaml: ")[0], await velo_row()))
        check("verify: not YAML (all but the parser's sentence)", texts[0] == texts[1], str(texts))
        api_config(workdir, velo.address, raw="client_private_key: k\n")
        await both("verify: a config without the CA", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        api_config(
            workdir,
            velo.address,
            raw="ca_certificate: |\n  not a pem\nclient_cert: x\nclient_private_key: y\napi_connection_string: 127.0.0.1:1\n",
        )
        await both("verify: certificates that are not PEM", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        os.remove(velo_config)
        await both("verify: the config file is gone", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        api_config(workdir, velo.address)

        await both("outdated velociraptor: portal user", "GET", A + "/velociraptor/outdated", t_portal, recs=(velo,))
        await both("outdated velociraptor: admin", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        p, q = await asyncio.gather(
            py.get(A + "/velociraptor/outdated", headers={"Authorization": f"Bearer {t_analyst}"}),
            rs.get(A + "/velociraptor/outdated", headers={"Authorization": f"Bearer {t_analyst}"}),
        )
        velo.take()
        py_codes = {a["customer_code"] for a in p.json()["outdated_velociraptor_agents"]}
        rs_codes = {a["customer_code"] for a in q.json()["outdated_velociraptor_agents"]}
        check(
            "outdated velociraptor (by design): Rust lists the analyst's customers only, Python every tenant's",
            rs_codes == {CUST_A} and {CUST_A, CUST_B} <= py_codes,
            f"python {sorted(map(str, py_codes))[:6]} rust {sorted(map(str, rs_codes))}",
        )
        velo.mode["no_version"] = True
        await both("outdated velociraptor: no version row", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        velo.mode = {"deny": True}
        await both("outdated velociraptor: the server refuses", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        velo.mode = {"not_json": True}
        await both("outdated velociraptor: a chunk that is not JSON", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        velo.mode = {"hang": True}
        await both("outdated velociraptor: the server never answers (deadline)", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        velo.mode = {}
        await sql("UPDATE connectors SET connector_api_key = NULL WHERE id = :i", i=velo_id)
        await settle()
        await both("verify: no config file path", "POST", VERIFY, t_admin, recs=(velo,), reset=unverify, snapshot=velo_row)
        await both("outdated velociraptor: no config file path", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        await sql("DELETE FROM connectors WHERE id = :i", i=velo_id)
        await settle()
        await both("outdated velociraptor: no connector", "GET", A + "/velociraptor/outdated", t_admin, recs=(velo,))
        await both(
            "delete: no Velociraptor connector",
            "DELETE",
            A + f"/{a1}/delete",
            t_admin,
            recs=V,
            reset=reset_agents,
            snapshot=agent_rows,
        )
        await both("sync: no Velociraptor connector", "POST", A + "/sync", t_admin, recs=V, reset=reset_agents, snapshot=agent_rows)
        velo_id = await set_connector("Velociraptor", "https://velo.parity.test", api_key=velo_config)
        await settle()

        # ==================================================================
        print("\n=== E. agent sync ===")
        sync_hosts = [host["a1"], host["a3"], host["a4"], host["n1"], f"new1-{SFX}", f"new2-{SFX}", f"bad1-{SFX}", f"fk1-{SFX}"]
        mgr.mode["agents"] = [
            {
                "id": a1,
                "name": host["a1"],
                "ip": "10.1.1.1",
                "os": {"name": "Ubuntu", "version": "24.04"},
                "group": [f"grp_{CUST_A}", "other"],
                "lastKeepAlive": "2026-10-16T07:00:00+02:00",
                "version": "Wazuh v4.9.1",
                "status": "active",
            },
            {
                "id": f"{SFX}31",
                "name": f"new1-{SFX}",
                "ip": "10.1.1.2",
                "os": {"name": "Microsoft Windows 11"},
                "group": [f"g_{CUST_B}"],
                "lastKeepAlive": "9999-12-31T23:59:59+00:00",
                "version": "Wazuh v4.7.0",
                "status": "disconnected",
            },
            {
                "id": f"{SFX}32",
                "name": f"new2-{SFX}",
                "ip": "any",
                "status": "never_connected",
                "lastKeepAlive": "1970-01-01T00:00:00+00:00",
            },
            {"id": f"{SFX}33", "name": f"bad1-{SFX}", "lastKeepAlive": "2026-10-16 07:00:00", "group": [f"g_{CUST_A}"]},
            {"id": f"{SFX}34", "name": f"fk1-{SFX}", "lastKeepAlive": "2026-10-16T07:00:00Z", "group": [f"g_nocust{SFX}"], "status": ""},
        ]
        VELO_CLIENTS.clear()
        VELO_CLIENTS["root"] = [
            client_row(f"C.{SFX}a1", host["a1"], 1760600000123456, "0.7.2"),
            client_row(f"C.{SFX}e1", f"new1-{SFX}", 1760600001999999),
            client_row(f"C.{SFX}d1", host["a3"], 1760600002000000),
        ]
        VELO_CLIENTS[ORG2] = [
            client_row(f"C.{SFX}a4-{ORG2}", "renamed", 1760600003500000),
            client_row(f"C.{SFX}a4", "renamed", 1760600003000000, "0.7.3"),
            client_row(f"C.{SFX}d2-{ORG2}", host["a3"], 1760600004000000),
        ]

        async def sync_rows():
            found = await rows(
                "SELECT agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, velociraptor_id, velociraptor_last_seen, "
                "wazuh_agent_version, wazuh_agent_status, velociraptor_agent_version, customer_code, quarantined, velociraptor_org, "
                "velociraptor_id_pinned FROM agents WHERE hostname IN " + in_list(sync_hosts) + " ORDER BY hostname, agent_id",
            )
            return found

        async def reset_sync():
            await sql("DELETE FROM agents WHERE hostname IN " + in_list(sync_hosts[4:]))
            await reset_agents()

        S = (mgr, velo)
        await both("sync: portal user", "POST", A + "/sync", t_portal, recs=S)
        await both("sync (scheduler token)", "POST", A + "/sync", t_sched, recs=S, reset=reset_sync, snapshot=sync_rows)
        mgr.mode["total"] = len(mgr.mode["agents"]) + 3
        await both("sync: more agents than the first page", "POST", A + "/sync", t_analyst, recs=S, reset=reset_sync, snapshot=sync_rows)
        mgr.mode.pop("total")
        velo.mode["bad_orgs"] = True
        await both("sync: an org without an id", "POST", A + "/sync", t_admin, recs=S, reset=reset_sync, snapshot=sync_rows)
        velo.mode = {"deny": True}
        await both("sync: Velociraptor refuses", "POST", A + "/sync", t_admin, recs=S, reset=reset_sync, snapshot=sync_rows)
        velo.mode = {}
        VELO_CLIENTS[ORG2].append({"client_id": "C.1"})
        await both("sync: an invalid client row", "POST", A + "/sync", t_admin, recs=S, reset=reset_sync, snapshot=sync_rows)
        VELO_CLIENTS[ORG2].pop()
        mgr.mode["fail"] = "/agents"
        await both("sync: the manager failing", "POST", A + "/sync", t_admin, recs=S, reset=reset_sync, snapshot=sync_rows)
        mgr.mode.pop("fail")
        await sql("UPDATE connectors SET connector_verified = 0 WHERE id = :i", i=velo_id)
        await settle()
        await both("sync: Velociraptor not verified", "POST", A + "/sync", t_admin, recs=S, reset=reset_sync, snapshot=sync_rows)
        await sql("UPDATE connectors SET connector_verified = 1 WHERE id = :i", i=velo_id)
        await settle()
        await reset_sync()

        # ==================================================================
        print("\n=== F. vulnerability sync to the Event Shipper ===")
        es.mode["docs"].append({"_index": STATES[1], **state_doc(b1, host["a1"], "CVE-2024-0100", "Low", "vim", "9")})
        await both("sync vulns: another tenant", "POST", A + f"/sync/vulnerabilities/{CUST_B}", t_analyst, recs=(es,))
        await both("sync vulns (all customers): the route crashes", "GET", A + "/sync/vulnerabilities", t_admin)
        await both(
            "sync vulns: no customer index yet",
            "POST",
            A + f"/sync/vulnerabilities/{CUST_A}",
            t_analyst,
            recs=(es,),
            gelf=True,
            background=True,
            unordered=True,
        )
        es.mode["extra_indices"] = [f"wazuh-vulnerabilities-{CUST_A.lower()}-2026.10"]
        es.mode["known_cves"] = {"CVE-2024-0001", "CVE-2024-0009"}
        await both(
            "sync vulns: some already indexed",
            "POST",
            A + f"/sync/vulnerabilities/{CUST_A}",
            t_admin,
            recs=(es,),
            gelf=True,
            background=True,
            unordered=True,
        )
        es.mode["docs"].append({"_index": STATES[0], **state_doc(a1, host["a3"], "CVE-2024-0101", "High", reference=[None])})
        await both(
            "sync vulns: one agent's row invalid (the rest are not synced)",
            "POST",
            A + f"/sync/vulnerabilities/{CUST_A}",
            t_admin,
            recs=(es,),
            gelf=True,
            background=True,
            unordered=True,
        )
        es.mode["docs"].pop()
        es.mode.pop("extra_indices")
        es.mode.pop("known_cves")

        # ==================================================================
        print("\n=== G. agent_sync, handed over ===")
        from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        from app.db.db_session import sync_engine
        from app.schedulers import scheduler as scheduler_module
        from app.schedulers.handover import manual_run
        from app.schedulers.services.agent_sync import agent_sync

        await sql(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, enabled, job_description) "
            "VALUES ('agent_sync', NULL, 1440, NULL, 0, 'parity')",
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),
            "COPILOT_DATABASE_URL": f"mysql://{os.environ['MYSQL_USER']}:{os.environ['MYSQL_PASSWORD']}@{os.environ['MYSQL_URL']}/copilot",
            "JWT_SECRET": os.environ["JWT_SECRET"],
            "COPILOT_BIND": "127.0.0.1",
            "COPILOT_PORT": str(JOBS_PORT),
            "COPILOT_RS_JOBS": "agent_sync",
            # #913's override, for the quarantine check below.
            "VELOCIRAPTOR_LINUX_QUARANTINE_ARTIFACT": " Custom.Linux.Remediation.Quarantine ",
            "VELOCIRAPTOR_QUERY_TIMEOUT": str(QUERY_TIMEOUT),
            "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        }
        binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
        rs2_proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
        for _ in range(100):
            try:
                if httpx.get(f"http://127.0.0.1:{JOBS_PORT}/_copilot/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        rs2 = httpx.AsyncClient(base_url=f"http://127.0.0.1:{JOBS_PORT}", timeout=120)
        aps = AsyncIOScheduler(event_loop=asyncio.get_running_loop())
        aps.configure(jobstores={"default": SQLAlchemyJobStore(engine=sync_engine)})
        aps.start(paused=True)
        aps.add_job(
            scheduler_module.get_function_by_name("agent_sync"),
            "interval",
            minutes=15,
            id="agent_sync",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )

        async def job_state():
            stamp = await rows("SELECT last_success FROM scheduled_job_metadata WHERE job_id = 'agent_sync' AND job_description = 'parity'")
            return {"agents": await sync_rows(), "stamped": stamp[0]["last_success"] is not None}

        async def job_both(name, expected_status=200):
            got = {}
            for tag in ("py", "rs"):
                await reset_sync()
                await sql("UPDATE scheduled_job_metadata SET last_success = NULL WHERE job_id = 'agent_sync'")
                mgr.take()
                velo.take()
                if tag == "py":
                    with manual_run():
                        try:
                            await agent_sync()
                        except HTTPException as e:
                            got["py_error"] = str(e)
                else:
                    r = await rs2.post("/api/scheduler/jobs/run/agent_sync", headers={"Authorization": f"Bearer {t_admin}"})
                    got["rs_status"] = r.status_code
                # Each process keeps the manager's token its own way (the second Rust
                # instance starts without one): the token requests are left out here.
                calls = [c for c in normalised(mgr.take()) if c["path"] != "/security/user/authenticate"]
                for c in calls:
                    c["headers"].pop("authorization", None)
                got[tag] = {"manager": calls, "velociraptor": velo.take(), **(await job_state())}
            check(
                f"{name}: requests, rows, last_success (rust {got.get('rs_status')})",
                got.get("rs_status") == expected_status and json.dumps(got["py"], default=str) == json.dumps(got["rs"], default=str),
                f"python {json.dumps(got['py'], default=str)[:3000]}\n        rust   {json.dumps(got['rs'], default=str)[:3000]}",
            )
            return got

        try:
            got = await job_both("agent_sync")
            check("agent_sync stamped last_success", got["rs"]["stamped"], json.dumps(got["rs"], default=str)[:300])
            mgr.mode["fail"] = "/agents"
            # A run that raises is the manual-run route's 500 on both sides.
            got = await job_both("agent_sync: the manager failing (no stamp)", expected_status=500)
            check(
                "python: the failed agent_sync raised",
                "Failed to send GET request to /agents" in got.get("py_error", ""),
                str(got.get("py_error")),
            )
            check("a failed agent_sync is not stamped", not got["rs"]["stamped"], json.dumps(got["rs"], default=str)[:300])
            mgr.mode.pop("fail")
            mgr.take()
            skipped = await agent_sync()
            check("python: a handed-over agent_sync tick is skipped", repr(skipped) == "JOB_SKIPPED" and not mgr.take(), repr(skipped))

            # The quarantine artifact override (VELOCIRAPTOR_LINUX_QUARANTINE_ARTIFACT, #913).
            got = {}
            for tag, client in (("py", py), ("rs", rs2)):
                await reset_velo()
                velo.take()
                os.environ["VELOCIRAPTOR_LINUX_QUARANTINE_ARTIFACT"] = " Custom.Linux.Remediation.Quarantine "
                try:
                    r = await client.post(
                        "/api/artifacts/quarantine",
                        headers={"Authorization": f"Bearer {t_admin}"},
                        json={"hostname": host["a1"], "action": "quarantine", "artifact_name": "Linux.Remediation.Quarantine"},
                    )
                finally:
                    os.environ.pop("VELOCIRAPTOR_LINUX_QUARANTINE_ARTIFACT", None)
                await asyncio.sleep(0.5)
                got[tag] = (r.status_code, r.json(), velo.take(), await velo_rows())
            check(
                f"quarantine with a configured custom artifact [{got['py'][0]}]",
                json.dumps(got["py"], default=str) == json.dumps(got["rs"], default=str) and "Custom.Linux" in json.dumps(got["rs"][3]),
                f"python {json.dumps(got['py'], default=str)[:2500]}\n        rust   {json.dumps(got['rs'], default=str)[:2500]}",
            )
        finally:
            aps.remove_job("agent_sync")
            aps.shutdown(wait=False)
            await rs2.aclose()
            rs2_proc.terminate()
            try:
                rs2_proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                rs2_proc.kill()

        # ==================================================================
        print("\n=== H. Velociraptor: /api/artifacts and /api/flows ===")
        t_resp = token(RESP, ["responder", "analyst"])
        await reset_agents()
        AR, FL = "/api/artifacts", "/api/flows"
        VO = (velo,)
        await both("artifacts: no token", "GET", AR)
        await both("artifacts: portal user", "GET", AR, t_portal, recs=VO)
        await both("artifacts", "GET", AR, t_analyst, recs=VO)
        await both("artifacts: responder", "GET", AR, t_resp, recs=VO)
        velo.mode["bad_artifact"] = True
        await both("artifacts: an invalid definition", "GET", AR, t_analyst, recs=VO)
        velo.mode = {"artifact_str": True}
        await both("artifacts: a definition that is no mapping", "GET", AR, t_analyst, recs=VO)
        velo.mode = {"deny": True}
        await both("artifacts: the server refuses", "GET", AR, t_analyst, recs=VO)
        velo.mode = {}
        # `collect`, `command` and `quarantine` are POST routes: Starlette answers their GET with `/{os_prefix}`.
        for prefix in ("linux", "WINDOWS", "MacOS", "solaris", "collect", "command", "quarantine"):
            await both(f"artifacts for OS prefix {prefix}", "GET", AR + f"/{prefix}", t_analyst, recs=VO)
        await both("artifact by name", "GET", AR + "/artifact/Linux.Sys.BashShell", t_analyst, recs=VO)
        await both("artifact by name: unknown", "GET", AR + "/artifact/Linux.Nothing", t_analyst, recs=VO)
        await both("artifact by name: not a name", "GET", AR + "/artifact/x'%20OR%20'1", t_analyst, recs=VO)
        velo.mode = {"bad_artifact": True}
        await both("artifact by name: an invalid definition", "GET", AR + "/artifact/Linux.Broken", t_analyst, recs=VO)
        velo.mode = {}
        ART = AR + "/artifact/Windows.AttackSimulation.AtomicRedTeam/parameters"
        for prefix in ("T1552.001", "T1003", "zzz", "%20"):
            await both(f"parameters with prefix {prefix!r}", "GET", ART + f"/{prefix}", t_analyst, recs=VO)
        await both(
            "parameters: an artifact without parameters",
            "GET",
            AR + "/artifact/Generic.Client.Info/parameters/x",
            t_analyst,
            recs=VO,
        )
        await both("parameters: unknown artifact", "GET", AR + "/artifact/Nope/parameters/x", t_analyst, recs=VO)
        await both("parameters: not a name", "GET", AR + "/artifact/a'b/parameters/x", t_analyst, recs=VO)
        velo.mode = {"deny": True}
        await both("parameters: the server refuses", "GET", ART + "/T1", t_analyst, recs=VO)
        velo.mode = {}
        await both("host artifacts: Linux", "GET", AR + f"/hostname/{host['a1']}", t_analyst, recs=VO)
        await both("host artifacts: Windows", "GET", AR + f"/hostname/{host['w1']}", t_resp, recs=VO)
        await both("host artifacts: an OS without a prefix", "GET", AR + f"/hostname/{host['x1']}", t_analyst, recs=VO)
        await both("host artifacts: another tenant's host", "GET", AR + f"/hostname/{host['b1']}", t_analyst, recs=VO)
        await both("host artifacts: unknown host (scoped)", "GET", AR + "/hostname/nobody", t_analyst, recs=VO)
        await both("host artifacts: unknown host (admin)", "GET", AR + "/hostname/nobody", t_admin, recs=VO)
        await both("host artifacts: a host held without a customer first", "GET", AR + f"/hostname/{host['n1']}", t_analyst, recs=VO)

        CMD = AR + "/command"
        W = {"recs": VO, "reset": reset_velo, "snapshot": velo_rows}
        bash = {"hostname": host["a1"], "artifact_name": "Linux.Sys.BashShell", "command": "id; echo 'it''s' \"q\"\n"}
        await both("command: no token", "POST", CMD, body=bash)
        await both("command: malformed JSON before the token", "POST", CMD, raw=b"{")
        await both("command: an analyst", "POST", CMD, t_analyst, bash, **W)
        await both("command: hostname required", "POST", CMD, t_resp, {"artifact_name": 5, "command": 1})
        await both("command: not one of the command artifacts", "POST", CMD, t_resp, {"hostname": "h", "artifact_name": "Linux.Sys.Ls"})
        await both("command: artifact null", "POST", CMD, t_resp, {"hostname": "h", "artifact_name": None})
        await both("command (responder)", "POST", CMD, t_resp, bash, **W)
        await both(
            "command (admin, Windows)",
            "POST",
            CMD,
            t_admin,
            {**bash, "hostname": host["w1"], "artifact_name": "Windows.System.CmdShell"},
            **W,
        )
        await both("command: another tenant's host", "POST", CMD, t_resp, {**bash, "hostname": host["b1"]}, **W)
        await both("command: no artifact named", "POST", CMD, t_resp, {"hostname": host["a1"], "command": "id"}, **W)
        await both("command: an artifact of another OS", "POST", CMD, t_resp, {**bash, "artifact_name": "Windows.System.PowerShell"}, **W)
        await both("command: no command (the flow is looked up under another key)", "POST", CMD, t_resp, {**bash, "command": None}, **W)
        await both("command: client id n/a", "POST", CMD, t_admin, {**bash, "hostname": host["na"]}, **W)
        await both("command: no org", "POST", CMD, t_resp, {**bash, "hostname": host["a2"]}, **W)
        await both("command: client id Unknown", "POST", CMD, t_resp, {**bash, "hostname": host["a3"]}, **W)
        await both("command: unknown host (admin)", "POST", CMD, t_admin, {**bash, "hostname": "nobody"}, **W)
        await both("command: an OS without a prefix", "POST", CMD, t_admin, {**bash, "hostname": host["x1"]}, **W)
        for mode in ("flow_id_int", "rows_not_dicts", "deny", "deny_collect", "not_json"):
            velo.mode = {mode: True}
            await both(f"command: {mode}", "POST", CMD, t_resp, bash, **W)
        velo.mode = {}

        QUA = AR + "/quarantine"
        q = {"hostname": host["a1"], "action": "quarantine", "artifact_name": "Linux.Remediation.Quarantine"}
        await both("quarantine: an analyst", "POST", QUA, t_analyst, q, **W)
        await both("quarantine: action required", "POST", QUA, t_resp, {"hostname": host["a1"]})
        await both("quarantine: bad action and artifact", "POST", QUA, t_resp, {"hostname": 1, "action": "isolate", "artifact_name": "x"})
        await both("quarantine (responder)", "POST", QUA, t_resp, q, **W)
        await both("quarantine: release", "POST", QUA, t_resp, {**q, "action": "remove_quarantine"}, **W)
        await both(
            "quarantine (admin, Windows)",
            "POST",
            QUA,
            t_admin,
            {**q, "hostname": host["w1"], "artifact_name": "Windows.Remediation.Quarantine"},
            **W,
        )
        await both("quarantine: another tenant's host", "POST", QUA, t_resp, {**q, "hostname": host["b1"]}, **W)
        await both("quarantine: no artifact named", "POST", QUA, t_resp, {"hostname": host["a1"], "action": "quarantine"}, **W)
        await both(
            "quarantine: an artifact of another OS",
            "POST",
            QUA,
            t_resp,
            {**q, "artifact_name": "Windows.Remediation.Quarantine"},
            **W,
        )
        await both("quarantine: no org", "POST", QUA, t_resp, {**q, "hostname": host["a2"]}, **W)
        await both("quarantine: client id n/a", "POST", QUA, t_admin, {**q, "hostname": host["na"]}, **W)
        for mode in ("deny", "deny_collect", "flow_id_int", "rows_not_dicts"):
            velo.mode = {mode: True}
            await both(f"quarantine: {mode}", "POST", QUA, t_resp, q, **W)
        velo.mode = {}

        await both("flows: no token", "GET", FL + f"/{host['a1']}")
        await both("flows: portal user", "GET", FL + f"/{host['a1']}", t_portal, recs=VO)
        await both("flows", "GET", FL + f"/{host['a1']}", t_analyst, recs=VO)
        await both("flows: an org-suffixed client", "GET", FL + f"/{host['w1']}", t_resp, recs=VO)
        await both("flows: another tenant's host", "GET", FL + f"/{host['b1']}", t_analyst, recs=VO)
        await both("flows: unknown host (admin)", "GET", FL + "/nobody", t_admin, recs=VO)
        await both("flows: client id n/a", "GET", FL + f"/{host['na']}", t_admin, recs=VO)
        await both("flows: no org", "GET", FL + f"/{host['a2']}", t_admin, recs=VO)
        await both("flows: client id Unknown", "GET", FL + f"/{host['a3']}", t_admin, recs=VO)
        velo.mode = {"deny": True}
        await both("flows: the server refuses", "GET", FL + f"/{host['a1']}", t_analyst, recs=VO)
        velo.mode = {}
        RET = FL + "/retrieve"
        flow = {"client_id": AGENTS["a1"][3], "session_id": "F.ONE"}
        await both("retrieve: no token", "POST", RET, body=flow)
        await both("retrieve", "POST", RET, t_analyst, flow, recs=VO)
        await both(
            "retrieve: an org-suffixed client",
            "POST",
            RET,
            t_analyst,
            {"client_id": AGENTS["w1"][3], "session_id": "F.X1"},
            recs=VO,
        )
        await both("retrieve: empty session", "POST", RET, t_analyst, {"session_id": "", "client_id": 1}, recs=VO)
        await both("retrieve: fields required", "POST", RET, t_analyst, {"session_id": None}, recs=VO)
        await both("retrieve: another tenant's client", "POST", RET, t_analyst, {**flow, "client_id": AGENTS["b1"][3]}, recs=VO)
        await both("retrieve: unknown client (scoped)", "POST", RET, t_analyst, {**flow, "client_id": "C.0"}, recs=VO)
        await both("retrieve: unknown client (admin)", "POST", RET, t_admin, {**flow, "client_id": "C.0"}, recs=VO)
        await both("retrieve: not a flow id", "POST", RET, t_admin, {**flow, "session_id": "F.1'2"}, recs=VO)
        for label, raw in (
            ("a list naming session_id", b'["session_id"]'),
            ("a list", b"[1]"),
            ("a string naming it", b'"x session_id"'),
            ("a number", b"5"),
            ("null", b"null"),
        ):
            await both(f"retrieve: the body is {label}", "POST", RET, t_analyst, raw=raw, recs=VO)
        velo.mode = {"rows_not_dicts": True}
        await both("retrieve: rows that are no mappings", "POST", RET, t_analyst, flow, recs=VO)
        velo.mode = {"deny": True}
        await both("retrieve: the server refuses", "POST", RET, t_analyst, flow, recs=VO)
        velo.mode = {}
        await reset_velo()

        order_ok = bool(rust_orders) and all(o == AGENT_FIELDS for o in rust_orders)
        check(f"rust: every agent row in declaration order ({len(rust_orders)} rows)", order_ok, str(rust_orders[:1]))
    finally:
        await cleanup()
        await settle()
        mgr.stop()
        es.stop()
        epss.stop()
        velo.stop()
        gelf_server.shutdown()
        gelf_server.server_close()
        await py.aclose()
        await rs.aclose()
    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
