"""Parity of the Rust response routes (`crates/copilot-response`) and the Shuffle connector
(`crates/copilot-shuffle`) with this backend — NOT collected by pytest (needs a live MySQL and the
Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process) and the Rust instances this suite starts (no legacy backend,
connector cache off) answer the same requests on one database. Every tool is a local stand-in that
records each request it receives — method, target, **every header** (Content-Length included) and
the body bytes — and both backends' requests are compared one by one:

* the Wazuh manager (token flow, `PUT /active-response`);
* MinIO (`rust_parity_objectstore_e2e.S3StandIn`: every request's SigV4 signature verified, the
  canonical requests compared) holding the Sysmon configs;
* the Wazuh master's provisioning worker (`POST /provision_worker/sysmon-config`, aiohttp's
  multipart body; the boundary, a `uuid4().hex`, is masked);
* the CoPilot Action service (`/inventory`, `/metrics`, httpx's requests;
  `CopilotActionService.BASE_URL` patched here, COPILOT_ACTION_URL for Rust);
* Velociraptor's gRPC API (`rust_parity_agents_e2e.VeloStandIn`, grpcio over mutual TLS: each
  `VQLCollectorArgs` and its deadline) for the CoPilot Action invoke;
* Shuffle (`requests` with the connector's bearer key): workflows, their executions and results,
  app-category runs, organizations, the connector's verification and the case notification.

For each request the suite compares the status, the response bytes and the outbound requests.
urllib3 prints an object's memory address in a connection error, which differs between any two
processes; it is masked. Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_response_e2e.py scripts/rust-parity.sh

Ports (all overridable): RESPONSE_PARITY_RUST_PORT and RESPONSE_PARITY_RUST_BARE_PORT (a second
Rust instance without GRAYLOG_API_HEADER_VALUE / COPILOT_API_KEY), RESPONSE_MANAGER_STUB_PORT,
RESPONSE_S3_STUB_PORT, RESPONSE_WORKER_STUB_PORT (the worker's port, 5003 in production:
COPILOT_PROVISION_WORKER_PORT for Rust, `get_wazuh_endpoint` patched here),
RESPONSE_ACTION_STUB_PORT, RESPONSE_VELO_STUB_PORT, RESPONSE_SHUFFLE_STUB_PORT.
"""

import asyncio
import base64
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

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# Read at import by app.connectors.cache: every request re-reads the connector row, as the Rust
# instances below do.
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
GRAYLOG_HEADER = "parity-response-graylog-header"
os.environ["GRAYLOG_API_HEADER_VALUE"] = GRAYLOG_HEADER
ACTION_KEY = "parity-copilot-action-key"
os.environ["COPILOT_API_KEY"] = ACTION_KEY

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_parity_agents_e2e as agents_parity  # noqa: E402
import rust_parity_objectstore_e2e as objstore  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("RESPONSE_PARITY_RUST_PORT", "5787"))
RS_BARE_PORT = int(os.environ.get("RESPONSE_PARITY_RUST_BARE_PORT", "5788"))
MANAGER_PORT = int(os.environ.get("RESPONSE_MANAGER_STUB_PORT", "5789"))
S3_PORT = int(os.environ.get("RESPONSE_S3_STUB_PORT", "5790"))
WORKER_PORT = int(os.environ.get("RESPONSE_WORKER_STUB_PORT", "5791"))
ACTION_PORT = int(os.environ.get("RESPONSE_ACTION_STUB_PORT", "5792"))
VELO_PORT = int(os.environ.get("RESPONSE_VELO_STUB_PORT", "5793"))
SHUFFLE_PORT = int(os.environ.get("RESPONSE_SHUFFLE_STUB_PORT", "5794"))
SHUFFLE_KEY = "parity-shuffle-key"
S3_USER, S3_SECRET = "minio-response", "minio-response-secret"
CLOSED_PORT = 1
OUR_CONNECTORS = ("Wazuh-Manager", "Velociraptor", "Shuffle")
CUST_A, CUST_B = f"RsA{SFX}", f"RsB{SFX}"
ADMIN, ANALYST, PORTAL, RESP = f"rs_admin{SFX}", f"rs_analyst{SFX}", f"rs_portal{SFX}", f"rs_resp{SFX}"
USERS = (ADMIN, ANALYST, PORTAL, RESP)
#: Explicit agent row ids (7 digits, this suite's range).
AGENT_ID_BASE = 7_640_000
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
    """What a stand-in was asked: (method, target, every header, body). Header names are
    lower-cased and sorted (the two HTTP stacks write them in different orders); none is
    dropped."""

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


def start_http_stub(port, answer, recorder):
    """A threaded HTTP/1.1 server; `answer(method, target, headers, body)` returns
    (status, content_type, body bytes)."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            recorder.add(self.command, self.path, self.headers, body)
            status, ctype, payload, *extra = answer(self.command, self.path, self.headers, body)
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            for name, value in (extra[0] if extra else {}).items():
                self.send_header(name, value)
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


class Manager:
    """The Wazuh manager: the token flow, and `PUT /active-response` answered per `mode`."""

    def __init__(self):
        self.mode = "ok"

    def __call__(self, method, target, headers, body):
        if target.startswith("/security/user/authenticate"):
            return 200, "application/json", json.dumps({"data": {"token": "parity-token"}, "error": 0}).encode()
        if method == "PUT" and target.startswith("/active-response"):
            if self.mode == "ok":
                return 200, "application/json", json.dumps({"data": {"affected_items": ["001"]}, "error": 0}).encode()
            if self.mode == "detail":
                return 400, "application/json", json.dumps({"title": "Bad Request", "detail": "bad agents_list"}).encode()
            if self.mode == "message":
                return 500, "application/json", json.dumps({"message": {"why": ["down"]}}).encode()
            if self.mode == "data-detail":
                return 404, "application/json", json.dumps({"data": {"detail": "no such agent"}}).encode()
            if self.mode == "text":
                return 503, "text/plain", b"upstream unavailable"
            if self.mode == "empty-detail":
                return 400, "application/json", json.dumps({"detail": ""}).encode()
            if self.mode == "not-json":
                return 200, "text/html", b"<html>ok</html>"
        return 404, "application/json", b'{"detail": "not found"}'


MANAGER = Manager()
MANAGER_RECORDER = Recorder()


class Worker:
    """The provisioning worker: answers per `mode`."""

    def __init__(self):
        self.mode = "ok"

    def __call__(self, method, target, headers, body):
        answers = {
            "ok": (200, "application/json", b'{"success": true, "message": "Sysmon config deployed to the group"}'),
            "lax": (200, "application/json; charset=utf-8", b'{"success": "yes"}'),
            "bad-bool": (200, "application/json", b'{"success": "maybe", "message": "x"}'),
            "bad-message": (200, "application/json", b'{"message": 5}'),
            "list": (200, "application/json", b"[1, 2]"),
            "html": (200, "text/html; charset=utf-8", b"<html>up</html>"),
            "empty": (200, "application/json", b"  "),
            "broken": (200, "application/json", b'{"success": tru'),
            "error": (500, "text/plain", b"worker exploded: no such group"),
            "error-json": (422, "application/json", '{"detail": "groupe inconnu: é"}'.encode()),
        }
        return answers[self.mode]


WORKER = Worker()
WORKER_RECORDER = Recorder()


def action_item(name, technology="Linux", **extra):
    return {
        "copilot_action_name": name,
        "description": "Kill a process",
        "technology": technology,
        "script_parameters": [
            {"name": "Target", "type": "string", "required": True, "arg_position": "1", "description": "pid"},
            {"name": "Mode", "type": "enum", "required": False, "enum": ["soft", "hard"], "default": "soft"},
        ],
        "repo_url": "https://raw.example/kill.sh",
        "version": "1.2",
        "last_updated": "2026-10-01T08:00:00Z",
        "tags": ["process"],
        **extra,
    }


class ActionService:
    """The CoPilot Action service: `/inventory` and `/metrics` per `mode`, an action's detail per
    its name."""

    def __init__(self):
        self.mode = "ok"

    @staticmethod
    def js(value, status=200, ctype="application/json"):
        return status, ctype, json.dumps(value).encode()

    def inventory(self):
        items = [action_item("kill-process"), action_item("win-kill", "Windows", icon="custom")]
        m = self.mode
        if m == "ok":
            return self.js({"copilot_actions": items, "message": "Returned 2 of 44 matching items", "success": True})
        if m == "total":
            return self.js({"copilot_actions": items, "message": "x", "success": True, "total": 7})
        if m == "showing":
            return self.js({"copilot_actions": items, "message": "Showing 2 of 3"})
        if m == "no-message":
            return self.js({"copilot_actions": items})
        if m == "total-str":
            return self.js({"copilot_actions": items, "total": "7"})
        if m == "total-float":
            return self.js({"copilot_actions": items, "total": 7.5})
        if m == "total-bool":
            return self.js({"copilot_actions": items, "total": True})
        if m == "message-int":
            return self.js({"copilot_actions": items, "message": 5})
        if m == "message-null":
            return self.js({"copilot_actions": items, "total": 2, "message": None})
        if m == "bad-item":
            return self.js({"copilot_actions": [action_item("x", "Solaris"), {"copilot_action_name": 1}], "total": 2})
        if m == "bad-type":
            item = action_item("x")
            item["script_parameters"][0]["type"] = "blob"
            return self.js({"copilot_actions": [item], "total": 1})
        if m == "list":
            return self.js([1, 2])
        if m == "actions-null":
            return self.js({"copilot_actions": None})
        if m == "actions-str":
            return self.js({"copilot_actions": "abc", "total": 0})
        if m == "html":
            return 200, "text/html", b"<html>maintenance</html>"
        if m == "error":
            return self.js({"detail": "license invalid"}, status=403)
        if m == "server-error":
            return 502, "text/plain", b"bad gateway"
        if m == "redirect":
            return 302, "text/plain", b"", {"Location": "https://elsewhere.example/inventory"}
        if m == "gzip":
            import gzip

            body = gzip.compress(json.dumps({"copilot_actions": items, "message": "1/2 items"}).encode())
            return 200, "application/json", body, {"Content-Encoding": "gzip"}
        if m == "not-found-message":
            return self.js({"copilot_actions": [], "message": "license expired", "success": False})
        raise AssertionError(m)

    def detail(self, name):
        if name == "kill-process":
            return self.js({"copilot_action": action_item(name), "message": "ok", "success": True})
        if name == "win-kill":
            return self.js({"copilot_action": action_item(name, "Windows"), "message": "ok", "success": True})
        if name == "no-url":
            return self.js({"copilot_action": action_item(name, repo_url=""), "message": "ok", "success": True})
        if name == "gone":
            return self.js({"copilot_action": action_item(name), "message": "Action gone: NOT FOUND", "success": False})
        if name == "fails":
            return self.js({"copilot_action": action_item(name), "message": "quota exceeded", "success": False})
        if name == "bad":
            return self.js({"copilot_action": {"copilot_action_name": name}, "message": "ok", "success": True})
        if name == "list":
            return self.js([1])
        if name == "html":
            return 200, "text/html", b"<html/>"
        if name == "broken":
            return 500, "text/plain", b"boom"
        return self.js({"detail": "Not Found"}, status=404)

    def metrics(self):
        m = self.mode
        if m in ("ok", "total"):
            return self.js({"status": "healthy", "metrics": {"actions": 44, "nested": {"a": [1, 2.5, None]}}, "x": 1})
        if m == "no-message":
            return self.js({})
        if m == "list":
            return self.js([1])
        if m == "message-int":
            return self.js({"status": 5, "metrics": {}})
        if m == "actions-null":
            return self.js({"status": "ok", "metrics": None})
        if m == "html":
            return 200, "text/html", b"<html/>"
        if m == "server-error":
            return 502, "text/plain", b"bad gateway"
        return self.js({"detail": "nope"}, status=404)

    def __call__(self, method, target, headers, body):
        path = target.split("?")[0]
        if path == "/inventory":
            return self.inventory()
        if path == "/metrics":
            return self.metrics()
        if path.startswith("/inventory/"):
            from urllib.parse import unquote

            return self.detail(unquote(path[len("/inventory/") :]))
        return self.js({"detail": "Not Found"}, status=404)


ACTION = ActionService()
ACTION_RECORDER = Recorder()


class VeloRecorder:
    """The Velociraptor stand-in's requests as outbound records: the serialized
    `VQLCollectorArgs` and its deadline (to the nearest 5 s)."""

    def __init__(self):
        self.stand_in = None

    def take(self):
        if self.stand_in is None:
            return []
        out = []
        for r in self.stand_in.take():
            raw = bytes.fromhex(r["request"])
            args = agents_parity.api_pb2.VQLCollectorArgs.FromString(raw)
            text_ = f"org={args.org_id} max_wait={args.max_wait} {[(q.Name, q.VQL) for q in args.Query]} {base64.b64encode(raw).decode()}"
            out.append(("GRPC", "/proto.API/Query", [("deadline", str(r["deadline"]))], text_.encode()))
        return out


VELO_RECORDER = VeloRecorder()

UUID_A, UUID_B = "4f1c0a9e-2b6d-4c3a-9e8f-1a2b3c4d5e6f", "8d7e6f5a-4b3c-4d2e-a1f0-9e8d7c6b5a4f"
ORG_FULL = {
    "name": "Acme MSSP",
    "description": None,
    "company_type": "MSSP",
    "image": "data:image/png;base64,AAAA",
    "id": "o1",
    "org": "Acme",
    "org_auth": {"token": "t0k", "expires": "2026-01-02T03:04:05.123456+02:00"},
    "users": [{"username": "u"}],
    "roles": ["admin", "user"],
    "active_apps": ["a1"],
    "cloud_sync": True,
    "sync_config": {"interval": "60", "api_key": "k", "source": "s", "x": 1},
    "sync_features": {"webhook": {"active": True}},
    "invites": [1],
    "child_orgs": ["c1"],
    "manager_orgs": [1, None, "m", 2.5, [1], {"k": "v"}],
    "creator_org": "root",
    "partner_info": {"reseller": "true"},
    "sso_config": {"client_id": "cid"},
    "region": "eu",
    "region_url": "https://eu.shuffler.io",
    "tutorials": [{"name": "t", "done": False}],
    "extra": "dropped",
}


class ShuffleStandIn:
    """Shuffle's API per `mode` (a dict, reset by `shuffle(...)`)."""

    def __init__(self):
        self.mode = {}
        self.results_calls = 0

    def js(self, value, status=200):
        return status, "application/json", json.dumps(value).encode()

    def __call__(self, method, target, headers, body):
        from urllib.parse import unquote

        path = unquote(target.split("?")[0])
        m = self.mode
        if path == "/api/v1/workflows" and method == "GET":
            return self.workflows(m.get("workflows", "ok"))
        if path.startswith("/api/v1/workflows/") and path.endswith("/executions"):
            return self.executions(path.split("/")[4], m.get("executions", "ok"))
        if path.startswith("/api/v1/workflows/") and path.endswith("/execute"):
            return self.execute(m.get("execute", "ok"))
        if path == "/api/v1/streams/results":
            self.results_calls += 1
            return self.results(m.get("results", "finished"), self.results_calls)
        if path == "/api/v1/apps/categories/run":
            return self.run(m.get("run", "ok"))
        if path == "/api/v1/orgs":
            return self.orgs(m.get("orgs", "ok"))
        if path.startswith("/api/v1/orgs/"):
            return self.org(path[len("/api/v1/orgs/") :])
        if path == "/api/v1/apps/authentication":
            auth = m.get("auth", "ok")
            if auth == "ok":
                return self.js([{"app": "x"}])
            if auth == "refused":
                return 401, "application/json", '{"success": false, "reason": "Invalid API key é"}'.encode()
            return 302, "text/html", b"<html>moved</html>"
        return self.js({"success": False, "reason": f"no route {path}"}, status=404)

    def workflows(self, mode):
        wf = [
            {"id": "wf-1", "name": "Notify", "actions": [{"name": "a", "large_image": "data:..."}, {"name": "b"}], "org_id": "o1"},
            {"id": "wf-2", "name": "Other", "actions": []},
            {"id": "wf-3", "name": "No actions", "_sa_internal": 1},
        ]
        answers = {
            "ok": wf,
            "empty": [],
            "null": None,
            "dict": {"x": 1, "my-actions": 2},
            "dict-plain": {"a": 1},
            "str-elem": ["has actions"],
            "int-elem": [5],
            "actions-null": [{"id": "x", "actions": None}],
            "actions-lists": [{"id": "x", "actions": [[1]]}],
            "actions-str": [{"id": "x", "actions": "abc"}],
            "actions-dict": [{"id": "x", "actions": {"k": 1}}],
            "list-elem": [["actions"]],
            "no-id": [{"name": "x"}],
            "no-name": [{"id": "wf-1"}],
            "int-id": [{"id": 5, "name": "x"}],
            "int-name": [{"id": "wf-1", "name": 5}],
        }
        if mode == "html":
            return 200, "text/html", b"<html>login</html>"
        if mode == "error":
            return self.js({"success": False, "reason": "bad key"}, status=401)
        return self.js(answers[mode])

    def executions(self, workflow_id, mode):
        if mode == "dict":
            return self.js({"a": 1})
        if mode == "no-status":
            return self.js([{}])
        if mode == "int-status":
            return self.js([{"status": 5}])
        if mode == "str":
            return self.js("abc")
        if mode == "html":
            return 200, "text/html", b"<html/>"
        answers = {"wf-1": [{"status": "FINISHED"}, {"status": "ABORTED"}], "wf-2": [], "wf-3": [{"status": None}]}
        return self.js(answers.get(workflow_id, []))

    def execute(self, mode):
        answers = {
            "ok": {"success": True, "execution_id": UUID_A.upper(), "authorization": "{" + UUID_B + "}"},
            "fail": {"success": False, "execution_id": UUID_A, "authorization": UUID_B},
            "fail-reason": {"success": False, "reason": "Workflow not found in this region é"},
            "bad": {"success": "maybe", "execution_id": "x", "authorization": 5},
            "v1": {"success": True, "execution_id": "12345678-1234-1234-1234-1234567890ab", "authorization": UUID_B},
            "missing": {},
            "list": [1],
        }
        if mode == "204":
            return 204, "", b""
        if mode == "html":
            return 200, "text/html", b"<html/>"
        if mode == "status-500":
            return self.js({"error": "boom"}, status=500)
        return self.js(answers[mode])

    def results(self, mode, n):
        finished = {"status": "FINISHED", "result": "done é", "results": [{"action": "a", "result": 1.5}]}
        if mode == "finished":
            return self.js(finished)
        if mode == "second":
            return self.js({"status": "EXECUTING"} if n == 1 else finished)
        if mode == "then-204":
            return self.js(finished) if n == 1 else (204, "", b"")
        if mode == "then-list":
            return self.js(finished) if n == 1 else self.js([1])
        if mode == "then-html":
            return self.js(finished) if n == 1 else (200, "text/html", b"<x>")
        raise AssertionError(mode)

    def run(self, mode):
        answers = {
            "ok": {"success": True, "id": "x", "_sa_hidden": 1, "nested": {"_sa": 2, "v": 1.5, "é": [True, None]}},
            "false-reason": {"success": False, "reason": "no app"},
            "false": {"success": False},
            "reason-dict": {"success": False, "reason": {"a": 1}},
            "list": [1, 2],
        }
        if mode == "204":
            return 204, "", b""
        if mode == "html":
            return 200, "text/html", b"<html/>"
        if mode == "status-400":
            return self.js({"error": "x"}, status=400)
        return self.js(answers[mode])

    def orgs(self, mode):
        if mode == "ok":
            return self.js(
                [
                    ORG_FULL,
                    {"name": "Beta", "id": "o2"},
                    {"id": 5},
                    "str",
                    {
                        "name": "Gamma",
                        "id": "o3",
                        "org_auth": {"token": "t", "expires": 1700000000},
                        "users": None,
                        "manager_orgs": ["a"],
                        "sync_config": {"interval": "5"},
                    },
                ],
            )
        if mode == "dict":
            return self.js({"a": 1})
        if mode == "null":
            return self.js(None)
        if mode == "html":
            return 200, "text/html", b"<html/>"
        raise AssertionError(mode)

    def org(self, org_id):
        answers = {
            "o1": ORG_FULL,
            "o-empty": {},
            "o-null": None,
            "o-list": [1],
            "o-bad": {"id": "x", "cloud_sync": "maybe"},
            "o-mgr-int": {"name": "M", "id": "m1", "manager_orgs": 5},
            "o-mgr-bool": {"name": "M", "id": "m2", "manager_orgs": True},
            "o-mgr-float": {"name": "M", "id": "m3", "manager_orgs": 1.5},
            "o-mgr-dict": {"name": "M", "id": "m4", "manager_orgs": {"a": 1}},
            "o-mgr-str": {"name": "M", "id": "m5", "manager_orgs": "x", "description": None},
            "o 1": {"name": "Spaced", "id": "o 1"},
        }
        if org_id == "o-html":
            return 200, "text/html", b"<html/>"
        if org_id in answers:
            return self.js(answers[org_id])
        return self.js({"success": False, "reason": "Org not found"}, status=404)


SHUFFLE = ShuffleStandIn()
SHUFFLE_RECORDER = Recorder()
RECORDERS = [MANAGER_RECORDER, WORKER_RECORDER, ACTION_RECORDER, VELO_RECORDER, SHUFFLE_RECORDER]
S3 = objstore.S3StandIn(S3_USER, S3_SECRET)
BOUNDARY = re.compile(rb"[0-9a-f]{32}")


# --- Database -------------------------------------------------------------------------------------

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


AGENTS = [
    # (row offset, agent_id, hostname, os, customer)
    (0, f"a{SFX}w", f"win-a-{SFX}", "Microsoft Windows 11 Pro", CUST_A),
    (1, f"a{SFX}l", f"lin-a-{SFX}", "Ubuntu 24.04 LTS", CUST_A),
    (2, f"a{SFX}n", f"nos-a-{SFX}", "", CUST_A),
    (3, f"b{SFX}w", f"win-b-{SFX}", "Microsoft Windows Server 2022", CUST_B),
]
AGENT_A_WIN, AGENT_A_LIN, AGENT_A_NOOS, AGENT_B_WIN = (a[1] for a in AGENTS)


def seed():
    with sync_engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(names=list(OUR_CONNECTORS)))
    SAVED_CONNECTORS.extend(dict(r._mapping) for r in rows)
    for code in (CUST_A, CUST_B):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())", c=code)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (RESP, 5)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name in (ANALYST, PORTAL, RESP):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
            "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )
    for offset, agent_id, hostname, os_name, customer in AGENTS:
        sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
            "velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, velociraptor_agent_version, "
            "customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) VALUES (:id, :a, '10.0.0.1', :os, :h, "
            "'grp', 0, '2026-10-15 08:00:00', NULL, NULL, 'Wazuh v4.9.0', 'active', NULL, :c, 0, NULL, 0)",
            id=AGENT_ID_BASE + offset,
            a=agent_id,
            os=os_name,
            h=hostname,
            c=customer,
        )
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")


def cleanup():
    sql(
        "DELETE FROM agent_datastore WHERE agent_id IN (SELECT agent_id FROM agents WHERE id BETWEEN :lo AND :hi)",
        lo=AGENT_ID_BASE,
        hi=AGENT_ID_BASE + 9999,
    )
    sql("DELETE FROM agents WHERE id BETWEEN :lo AND :hi", lo=AGENT_ID_BASE, hi=AGENT_ID_BASE + 9999)
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM audit_log WHERE actor_username = :n", n=name)
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    cleanup_incidents()
    for code in (CUST_A, CUST_B):
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)


# --- The two backends -----------------------------------------------------------------------------


def patch_python():
    """MinIO and the provisioning worker's port, as the Rust instances are configured."""
    from miniopy_async import Minio

    from app.active_response.services import sysmon_config
    from app.data_store import data_store_operations

    async def create_session():
        return Minio(f"127.0.0.1:{S3_PORT}", access_key=S3_USER, secret_key=S3_SECRET, secure=False)

    data_store_operations.create_session = create_session
    from app.integrations.copilot_action.services.copilot_action import (
        CopilotActionService,
    )

    CopilotActionService.BASE_URL = f"http://127.0.0.1:{ACTION_PORT}"
    original = sysmon_config.get_wazuh_endpoint

    async def get_wazuh_endpoint(session):
        return (await original(session)).replace(":5003/", f":{WORKER_PORT}/")

    sysmon_config.get_wazuh_endpoint = get_wazuh_endpoint


def build_python_app():
    from app.incidents.routes.db_operations import incidents_db_operations_router
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import active_response
    from app.routers import connectors
    from app.routers import copilot_action
    from app.routers import shuffle

    api = APIRouter(prefix="/api")
    api.include_router(active_response.router)
    api.include_router(copilot_action.router)
    api.include_router(shuffle.router)
    api.include_router(connectors.router)
    api.include_router(incidents_db_operations_router, prefix="/incidents/db_operations")
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port, bare=False):
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
    env.update(
        {
            "MINIO_ROOT_USER": S3_USER,
            "MINIO_ROOT_PASSWORD": S3_SECRET,
            "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{S3_PORT}",
            "COPILOT_PROVISION_WORKER_PORT": str(WORKER_PORT),
            "COPILOT_ACTION_URL": f"http://127.0.0.1:{ACTION_PORT}",
        },
    )
    for name in ("VELOCIRAPTOR_QUERY_TIMEOUT", "VELOCIRAPTOR_FLOW_TIMEOUT"):
        if name in os.environ:
            env[name] = os.environ[name]
    if not bare:
        env["GRAYLOG_API_HEADER_VALUE"] = GRAYLOG_HEADER
        env["COPILOT_API_KEY"] = ACTION_KEY
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


ADDRESS = re.compile(rb"object at 0x[0-9a-f]+")


def normalize(body):
    return ADDRESS.sub(b"object at 0x...", body)


def reset_python_caches():
    """Forget the manager token Python caches per process (the Rust instance keys its own by the
    connector row, which the checks below never change while a token is held)."""
    from app.connectors.wazuh_manager.utils import universal

    universal._token_cache._cache.clear()


RESPONSE_HEADERS = ("content-type", "content-disposition", "content-length")


def audit_rows(action):
    with sync_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT actor_username, customer_code, action, entity_type, entity_id, result, old_value, new_value, source_ip, details "
                "FROM audit_log WHERE action = :a AND actor_username IN :users ORDER BY id",
            ).bindparams(a=action, users=list(USERS)),
        )
        return [tuple(r) for r in rows]


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
        S3.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0.05)
        out = [(m, t, h, BOUNDARY.sub(b"<boundary>", normalize(b))) for recorder in RECORDERS for m, t, h, b in recorder.take()]
        out = [(m, t, [(k, BOUNDARY.sub(b"<boundary>", v.encode()).decode()) for k, v in h], b) for m, t, h, b in out]
        return r, out, S3.take()

    async def same(self, name, method, path, tok=None, before=None, outbound=True, expect=None, audit=None, canon=None, table=None, **kw):
        """Python, then Rust, with the stand-ins reset by `before` and MinIO restored for each.
        `expect` is a status both must answer; `audit` an action whose rows both must write alike;
        `canon` maps both JSON answers before they are compared (a §4 difference); `table` returns
        the rows of a table both must write alike."""
        S3.faults = []
        if before:
            before()
        start = S3.snapshot()
        audit0 = audit_rows(audit) if audit else None
        rows0 = table() if table else None
        r1, out1, s3_1 = await self.call(self.py, method, path, tok, **kw)
        end1 = S3.snapshot()
        audit1 = audit_rows(audit)[len(audit0) :] if audit else None
        rows1 = table()[len(rows0) :] if table else None
        S3.restore(start)
        if before:
            before()
        r2, out2, s3_2 = await self.call(self.rs, method, path, tok, **kw)
        end2 = S3.snapshot()
        audit2 = audit_rows(audit)[len(audit0) + len(audit1) :] if audit else None
        # Python awaits its audit row; the Rust sink writes it on a task of its own, which can
        # land after the answer: wait for as many rows as Python wrote (3 s at most).
        deadline = time.time() + 3
        while audit and len(audit2) < len(audit1) and time.time() < deadline:
            await asyncio.sleep(0.05)
            audit2 = audit_rows(audit)[len(audit0) + len(audit1) :]
        rows2 = table()[len(rows0) + len(rows1) :] if table else None
        b1, b2 = normalize(r1.content), normalize(r2.content)
        if canon:
            b1, b2 = (json.dumps(canon(json.loads(b))).encode() for b in (b1, b2))
        ok = r1.status_code == r2.status_code and b1 == b2
        if expect is not None and r1.status_code != expect:
            ok = False
        detail = f"python {r1.status_code} {b1[:900]!r}\n        rust   {r2.status_code} {b2[:900]!r}"
        h1 = {k: r1.headers.get(k) for k in RESPONSE_HEADERS}
        h2 = {k: r2.headers.get(k) for k in RESPONSE_HEADERS}
        if h1 != h2:
            ok = False
            detail += f"\n        headers python {h1}\n        headers rust   {h2}"
        if outbound:
            if out1 != out2:
                ok = False
                detail += f"\n        outbound python {out1}\n        outbound rust   {out2}"
            o1, o2 = objstore.outbound(s3_1), objstore.outbound(s3_2)
            if o1 != o2:
                ok = False
                detail += f"\n        minio python {o1}\n        minio rust   {o2}"
            if any(o[-1] != "ok" for o in o1 + o2):
                ok = False
                detail += f"\n        signatures python {[o[-1] for o in o1]} rust {[o[-1] for o in o2]}"
            c1, c2 = objstore.changes(start, end1), objstore.changes(start, end2)
            if c1 != c2:
                ok = False
                detail += f"\n        minio changes python {c1}\n        minio changes rust   {c2}"
        if audit and audit1 != audit2:
            ok = False
            detail += f"\n        audit python {audit1}\n        audit rust   {audit2}"
        if table and rows1 != rows2:
            ok = False
            detail += f"\n        rows python {rows1}\n        rows rust   {rows2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:400]!r}\n        outbound {[(m, t, b[:300]) for m, t, h, b in out1]}")
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- Active response ------------------------------------------------------------------------------


def mode(m):
    def set_mode():
        MANAGER.mode = m

    return set_mode


def firewall(agents=..., **extra):
    body = {"command": "windows_firewall", "alert": {"action": "block", "ip": "1.1.1.1"}, "params": {"wait_for_complete": True}}
    if agents is not ...:
        body["params"]["agents_list"] = agents
    body.update(extra)
    return body


INVALID_BODIES = [
    {"command": "nope", "alert": {}, "params": {}},
    {"command": True, "alert": {}, "params": {}},
    {"command": [1], "alert": {}, "params": {}},
    {"command": {"a": 1.5}, "alert": {}, "params": {}},
    {"command": 1.0, "alert": {}, "params": {}},
    {"command": "", "alert": {}, "params": {}},
    {"alert": {}, "params": {}},
    {"command": None, "alert": 5, "params": {"wait_for_complete": True}},
    {"command": "windows_firewall", "alert": [], "params": {}},
    {"command": "windows_firewall", "alert": 5, "params": {}},
    {"command": "nope", "alert": 5},
    {"command": "windows_firewall", "alert": {"action": "block", "ip": "x"}, "params": {}},
    {"command": "windows_firewall", "alert": {"action": "nuke"}, "params": {}},
    {"command": "linux_firewall", "alert": {"action": "BLOCK", "ip": 5}, "params": {}},
    {"command": "linux_firewall", "alert": {"action": "block", "ip": "1.1.1.01"}, "params": {}},
    {"command": "windows_firewall", "alert": {"action": "block", "ip": None}, "params": {}},
    {"command": "sysmon_config_reload", "alert": {"action": "block"}, "params": {}},
    {"command": "sysmon_config_reload", "alert": {"action": None}, "params": {}},
    {
        "command": "linux_firewall",
        "alert": {"action": "unblock", "ip": "::1"},
        "params": {"wait_for_complete": True},
        "custom": False,
        "endpoint": "/x",
        "arguments": [1],
    },
    {"command": "linux_firewall", "alert": {"action": "unblock", "ip": "::1"}, "params": {"wait_for_complete": True}, "custom": "true"},
    {"command": "sysmon_config_reload", "alert": {}, "params": "x"},
    {"command": "sysmon_config_reload", "alert": {}, "params": {"agents_list": "001"}},
    {"command": "sysmon_config_reload", "alert": {}, "params": {"wait_for_complete": "maybe", "agents_list": [1, "a", None]}},
    {"command": "sysmon_config_reload", "alert": {}, "params": {"wait_for_complete": True}, "arguments": "x"},
    [],
    "str",
]

VALID_BODIES = [
    firewall([AGENT_A_WIN]),
    {
        "command": "WINDOWS_FIREWALL",
        "alert": {"action": "block", "ip": " 1.1.1.1 ", "x": 1},
        "params": {"wait_for_complete": "yes", "agents_list": [AGENT_A_WIN]},
    },
    {"command": "Sysmon_Config_Reload", "alert": {}, "params": {"wait_for_complete": 1, "agents_list": [AGENT_A_WIN, AGENT_A_LIN]}},
    {
        "command": "linux_firewall",
        "alert": {"action": "unblock", "ip": "fe80::1%eth0"},
        "custom": 1.0,
        "params": {"wait_for_complete": False, "agents_list": [AGENT_A_LIN]},
        "arguments": ["a", "ü"],
        "endpoint": "/active-response",
    },
    {
        "command": "windows_firewall",
        "alert": {"action": "sysmon_config_reload", "ip": "10.0.0.1"},
        "params": {"wait_for_complete": True, "agents_list": [AGENT_A_WIN]},
    },
]


async def active_response_checks(p, t_admin, t_analyst, t_portal, t_resp):
    A = "/api/active_response"
    print("\n=== Active response: auth ===")
    for method, path, body in (
        ("GET", "/supported", None),
        ("GET", f"/supported/{AGENT_A_WIN}", None),
        ("GET", "/describe/windows_firewall", None),
        ("POST", "/invoke", firewall([AGENT_A_WIN])),
    ):
        kw = {"json": body} if body is not None else {}
        await p.same(f"{method} {path}, no token", method, A + path, **kw)
        await p.same(f"{method} {path}, bad token", method, A + path, "not-a-jwt", **kw)
        await p.same(f"{method} {path}, portal user", method, A + path, t_portal, **kw)
        await p.same(f"{method} {path}, ghost user", method, A + path, token(f"ghost{SFX}", ["admin"]), **kw)
    await p.same(
        "POST /invoke, malformed JSON, no token",
        "POST",
        A + "/invoke",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    print("\n=== Active response: reads ===")
    await p.same("GET /supported", "GET", A + "/supported", t_analyst, expect=200)
    await p.same("GET /supported, responder", "GET", A + "/supported", t_resp, expect=200)
    for name in ("windows_firewall", "WINDOWS_FIREWALL", "Windows_Firewall", "nope", "linux_firewall", "windows"):
        await p.same(f"GET /describe/{name}", "GET", f"{A}/describe/{name}", t_analyst)
    for agent in (AGENT_A_WIN, AGENT_A_LIN, AGENT_A_NOOS, AGENT_B_WIN, f"missing{SFX}"):
        await p.same(f"GET /supported/{agent}, analyst", "GET", f"{A}/supported/{agent}", t_analyst)
    await p.same("GET /supported/{other tenant}, admin", "GET", f"{A}/supported/{AGENT_B_WIN}", t_admin, expect=200)

    print("\n=== Active response: invoke, validation ===")
    for i, body in enumerate(INVALID_BODIES):
        await p.same(f"POST /invoke invalid #{i} {json.dumps(body)[:80]}", "POST", A + "/invoke", t_admin, json=body)
    for raw in (b"null", b"", b"{"):
        await p.same(f"POST /invoke raw {raw!r}", "POST", A + "/invoke", t_admin, content=raw, headers={"Content-Type": "application/json"})
    await p.same("POST /invoke, no content type", "POST", A + "/invoke", t_admin, content=json.dumps(firewall()).encode())

    print("\n=== Active response: invoke, tenancy ===")
    for agents in (["*"], [], None, ...):
        await p.same(f"POST /invoke analyst agents_list={agents!r}", "POST", A + "/invoke", t_analyst, json=firewall(agents), expect=403)
    await p.same(
        "POST /invoke analyst, a foreign agent",
        "POST",
        A + "/invoke",
        t_analyst,
        json=firewall([AGENT_A_WIN, AGENT_B_WIN]),
        expect=403,
    )
    await p.same("POST /invoke analyst, an unknown agent", "POST", A + "/invoke", t_analyst, json=firewall([f"x{SFX}"]), expect=403)
    await p.same("POST /invoke portal user", "POST", A + "/invoke", t_portal, json=firewall([AGENT_A_WIN]), expect=403)

    print("\n=== Active response: invoke, Wazuh ===")
    reset_python_caches()
    for i, body in enumerate(VALID_BODIES):
        await p.same(f"POST /invoke valid #{i}", "POST", A + "/invoke", t_analyst, json=body, before=mode("ok"), expect=200)
    await p.same("POST /invoke admin ['*'] (every agent)", "POST", A + "/invoke", t_admin, json=firewall(["*"]), before=mode("ok"))
    await p.same("POST /invoke admin, no agents_list", "POST", A + "/invoke", t_admin, json=firewall(), before=mode("ok"))
    await p.same("POST /invoke responder", "POST", A + "/invoke", t_resp, json=firewall([AGENT_A_WIN]), before=mode("ok"))
    for m in ("detail", "message", "data-detail", "text", "empty-detail", "not-json"):
        await p.same(f"POST /invoke, Wazuh answers {m}", "POST", A + "/invoke", t_admin, json=firewall(["001", "002"]), before=mode(m))
    # The manager unreachable: the token fetch fails first.
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{CLOSED_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()
    await p.same("POST /invoke, manager unreachable", "POST", A + "/invoke", t_admin, json=firewall(["001"]))
    set_connector("Wazuh-Manager", None)
    await p.same("POST /invoke, no manager connector", "POST", A + "/invoke", t_admin, json=firewall(["001"]), expect=503)
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()


def notification(fields=None, **event_extra):
    event = {
        "id": "01JNHQP35THD48VH8601F6EMHE",
        "event_definition_type": "aggregation-v1",
        "event_definition_id": "67c78b93cf26aa2045bdc2ea",
        "origin_context": "urn:graylog:message:es:graylog-01_3:766b70b4",
        "timestamp": "2025-03-04T23:21:55.840Z",
        "timestamp_processing": "2025-03-04T23:26:03.450Z",
        "timerange_start": None,
        "timerange_end": None,
        "streams": [],
        "source_streams": ["679945aa7c4dd06afcef5feb"],
        "message": "ACTIVE RESPONSE WEBSERVER THREAT INTEL",
        "source": "soc-grlog01",
        "key_tuple": [],
        "key": "",
        "priority": 2,
        "scores": {},
        "associated_assets": [],
        "alert": True,
        "fields": fields
        if fields is not None
        else {"COMMAND": "domain_sinkhole", "AGENT_ID": "032", "ACTION": "sinkhole", "VALUE": "example.com"},
        "group_by_fields": {},
        "replay_info": {
            "timerange_start": "2025-03-04T23:21:03.360Z",
            "timerange_end": "2025-03-04T23:26:03.360Z",
            "query": "_exists_:threat_intel_score",
            "streams": ["679945aa7c4dd06afcef5feb"],
            "filters": [],
        },
    }
    event.update(event_extra)
    return {
        "event_definition_id": "67c78b93cf26aa2045bdc2ea",
        "event_definition_type": "aggregation-v1",
        "event_definition_title": "ACTIVE RESPONSE WEBSERVER THREAT INTEL",
        "event_definition_description": "",
        "job_definition_id": "67c78befcf26aa2045bdc4e9",
        "job_trigger_id": "67c78c0bcf26aa2045bdc5b5",
        "event": event,
        "backlog": [],
    }


async def graylog_webhook_checks(p, bare):
    G = "/api/graylog/invoke"
    ok = {"graylog": GRAYLOG_HEADER}
    print("\n=== Graylog webhook: header ===")
    await p.same("POST /invoke, no header", "POST", G, json=notification(), expect=403)
    await p.same("POST /invoke, wrong header", "POST", G, json=notification(), headers={"graylog": "nope"}, expect=403)
    await p.same("POST /invoke, a token is not the header", "POST", G, token(ADMIN, ["admin"]), json=notification(), expect=403)
    await p.same("POST /invoke, malformed JSON", "POST", G, content=b"{", headers={"Content-Type": "application/json", **ok})
    await p.same("POST /invoke, wrong header and invalid body", "POST", G, json={}, headers={"graylog": "nope"}, expect=403)

    print("\n=== Graylog webhook: body ===")
    fields = {"COMMAND": "domain_sinkhole", "AGENT_ID": "032", "ACTION": "sinkhole", "VALUE": "example.com"}
    bad = [
        ("COMMAND with a space", notification({**fields, "COMMAND": "rm -rf /"})),
        ("COMMAND too long", notification({**fields, "COMMAND": "a" * 65, "AGENT_ID": 32})),
        ("COMMAND not ASCII", notification({**fields, "COMMAND": "dömain"})),
        ("additional_fields not a dict", notification({**fields, "additional_fields": 5})),
        ("__extra__ not a dict", notification({**fields, "__extra__": 5})),
        ("both spellings", notification({**fields, "__extra__": 5, "additional_fields": 6})),
        ("bad datetime, int, bool", notification(None, timestamp="nope", priority="x", alert="maybe")),
        ("no fields", {**notification(), "event": {k: v for k, v in notification()["event"].items() if k != "fields"}}),
        ("fields a list", notification([])),
        ("event null", {**notification(), "event": None}),
        ("origin_context null", notification(None, origin_context=None)),
        ("empty object", {}),
        ("a list", []),
    ]
    for name, body in bad:
        await p.same(f"POST /invoke, {name}", "POST", G, json=body, headers=ok)
    print("\n=== Graylog webhook: forwarded ===")
    reset_python_caches()
    good = [
        ("as sent by Graylog", notification()),
        ("extra fields", notification({**fields, "OTHER": [1, 2], "__extra__": {"k": "v"}})),
        ("timestamps as numbers", notification(None, timestamp=1741130515, timestamp_processing=1741130515840.5)),
        ("non-ASCII value", notification({**fields, "VALUE": "exämple.com", "ACTION": "tab\there"})),
    ]
    for name, body in good:
        await p.same(f"POST /invoke, {name}", "POST", G, json=body, headers=ok, before=mode("ok"), expect=200)
    for m in ("detail", "text"):
        await p.same(
            f"POST /invoke, Wazuh answers {m} (still a success)",
            "POST",
            G,
            json=notification(),
            headers=ok,
            before=mode(m),
            expect=200,
        )
    set_connector("Wazuh-Manager", None)
    await p.same("POST /invoke, no manager connector (still a success)", "POST", G, json=notification(), headers=ok, expect=200)
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()

    print("\n=== Graylog webhook: GRAYLOG_API_HEADER_VALUE unset ===")
    del os.environ["GRAYLOG_API_HEADER_VALUE"]
    try:
        await bare.same("POST /invoke, header not configured", "POST", G, json=notification(), headers=ok, expect=403)
        await bare.same("POST /invoke, header not configured, none sent", "POST", G, json=notification(), expect=403)
    finally:
        os.environ["GRAYLOG_API_HEADER_VALUE"] = GRAYLOG_HEADER


ACTION_KEY = "parity-copilot-action-key"
os.environ["COPILOT_API_KEY"] = ACTION_KEY


SYSMON = "sysmon-configs"
SYSMON_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<Sysmon schemaversion="4.90">\n  <EventFiltering>\n'
    b'    <RuleGroup name="" groupRelation="or">\n      <ProcessCreate onmatch="exclude"/>\n    </RuleGroup>\n'
    b"  </EventFiltering>\n</Sysmon>\n" + "<!-- é -->\n".encode()
)
ODD_CODE = f"Ā{SFX}"


def seed_minio():
    S3.make_bucket(SYSMON)
    S3.put(SYSMON, f"{CUST_A}/sysmon_config.xml", SYSMON_XML, "application/xml")
    S3.put(SYSMON, f"{CUST_B}/sysmon_config.xml", b"<Sysmon>\xff\xfe</Sysmon>", "application/xml")
    S3.put(SYSMON, f"{CUST_B}/notes.txt", b"not a config", "text/plain")
    S3.put(SYSMON, f"{ODD_CODE}/sysmon_config.xml", SYSMON_XML, "application/xml")
    S3.put(SYSMON, "orphan/old_sysmon_config.xml", b"<Sysmon/>", "application/xml")


def worker(m):
    def set_mode():
        WORKER.mode = m

    return set_mode


async def sysmon_checks(p, t_admin, t_analyst, t_portal, t_resp):
    S = "/api/sysmon_config"
    print("\n=== Sysmon configs: auth and tenancy ===")
    for method, path in (("GET", ""), ("GET", f"/content/{CUST_A}"), ("GET", f"/{CUST_A}"), ("POST", f"/deploy/{CUST_A}")):
        await p.same(f"{method} {path or '/'}, no token", method, S + path)
        await p.same(f"{method} {path or '/'}, bad token", method, S + path, "not-a-jwt")
        await p.same(f"{method} {path or '/'}, analyst", method, S + path, t_analyst, expect=403)
        await p.same(f"{method} {path or '/'}, portal user", method, S + path, t_portal, expect=403)
    for method, path in (("GET", f"/content/{CUST_B}"), ("GET", f"/{CUST_B}"), ("POST", f"/deploy/{CUST_B}")):
        await p.same(f"{method} {path}, a responder of another tenant", method, S + path, t_resp, expect=403)

    print("\n=== Sysmon configs: reads ===")

    def sorted_codes(body):
        return {**body, "customer_codes": sorted(body["customer_codes"])}

    # Python answers `list(set)`: its order follows the strings' hashes (§4).
    _, rs = await p.same("GET /, admin", "GET", S, t_admin, expect=200, canon=sorted_codes)
    listed = sorted({k.split("/")[0] for k in S3.buckets[SYSMON] if k.endswith("sysmon_config.xml")}, key=lambda c: c.encode())
    check("GET /: Rust answers in listing order", rs.json()["customer_codes"] == listed, f"{rs.json()['customer_codes']} != {listed}")
    await p.same("GET /, responder", "GET", S, t_resp, expect=200)
    for who, tok in (("admin", t_admin), ("responder", t_resp)):
        await p.same(f"GET /content/{{A}}, {who}", "GET", f"{S}/content/{CUST_A}", tok, expect=200)
        await p.same(f"GET /{{A}}, {who}", "GET", f"{S}/{CUST_A}", tok, expect=200)
    await p.same("GET /content/{B} (not UTF-8), admin", "GET", f"{S}/content/{CUST_B}", t_admin, expect=500)
    await p.same("GET /{B} (not UTF-8: bytes as they are), admin", "GET", f"{S}/{CUST_B}", t_admin, expect=200)
    for code in (f"none{SFX}", "x y"):
        await p.same(f"GET /content/{code!r} (missing), admin", "GET", f"{S}/content/{code}", t_admin, expect=404)
        await p.same(f"GET /{code!r} (missing), admin", "GET", f"{S}/{code}", t_admin, expect=404)
    await p.same("GET /{a code that is not latin-1}, admin", "GET", f"{S}/{ODD_CODE}", t_admin, expect=500)
    await p.same("GET /content/{a code that is not latin-1}, admin", "GET", f"{S}/content/{ODD_CODE}", t_admin, expect=200)

    snap = S3.snapshot()

    def no_bucket():
        S3.drop(SYSMON)

    await p.same("GET /, no bucket (created)", "GET", S, t_admin, before=no_bucket, expect=200)
    await p.same("GET /content/{A}, no bucket", "GET", f"{S}/content/{CUST_A}", t_admin, before=no_bucket, expect=500)
    await p.same("GET /{A}, no bucket", "GET", f"{S}/{CUST_A}", t_admin, before=no_bucket, expect=500)
    await p.same("POST /deploy/{A}, no bucket", "POST", f"{S}/deploy/{CUST_A}", t_admin, before=no_bucket, expect=200)
    S3.restore(snap)

    def failing_listing():
        S3.fault(lambda m, path, q: m == "GET" and "list-type=2" in q, (500, {"Content-Type": "application/xml"}, b"<Error/>"), count=10)

    await p.same("GET /, the listing fails ([])", "GET", S, t_admin, before=failing_listing, expect=200)

    print("\n=== Sysmon configs: deploy ===")
    for m in ("ok", "lax", "bad-bool", "bad-message", "list", "html", "empty", "broken", "error", "error-json"):
        await p.same(
            f"POST /deploy/{{A}}, the worker answers {m}",
            "POST",
            f"{S}/deploy/{CUST_A}",
            t_resp,
            before=worker(m),
            expect=200,
            audit="response.sysmon_deploy",
        )
    await p.same("POST /deploy/{none} (no config)", "POST", f"{S}/deploy/none{SFX}", t_admin, before=worker("ok"), expect=200)
    await p.same("POST /deploy/{B} (bytes as they are)", "POST", f"{S}/deploy/{CUST_B}", t_admin, before=worker("ok"), expect=200)
    for url, label in (
        (f"http://127.0.0.2:{MANAGER_PORT}", "worker unreachable"),
        ("wazuh-manager:55000", "no netloc"),
        ("https://[::1:55000", "an unclosed IPv6 bracket"),
        ("https://[1.2.3.4]:55000", "an IPv4 in brackets"),
        ("https://user:pw@127.0.0.1:55000", "credentials in the URL"),
        (None, "no manager connector"),
    ):
        set_connector("Wazuh-Manager", url, "wazuh", "wazuh-pw")
        await p.same(f"POST /deploy/{{A}}, {label}", "POST", f"{S}/deploy/{CUST_A}", t_admin, before=worker("ok"), expect=200)
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{MANAGER_PORT}", "wazuh", "wazuh-pw")
    reset_python_caches()


# --- CoPilot Actions ------------------------------------------------------------------------------

#: (row offset, agent_id, hostname, os, customer, velociraptor_id) — right after `AGENTS`: the
#: suite's explicit ids stay one block, below whatever MySQL's auto-increment hands out next.
ACTION_AGENTS = [
    (4, f"a{SFX}x1", f"act-a-{SFX}", "Ubuntu 24.04 LTS", CUST_A, f"C.{SFX}0a1"),
    (5, f"a{SFX}x2", f"act-w-{SFX}", "Microsoft Windows 11 Pro", CUST_A, f"C.{SFX}0a2"),
    (6, f"a{SFX}x3", f"act-s-{SFX}", "Solaris 11", CUST_A, f"C.{SFX}0a3"),
    (7, f"a{SFX}x4", f"act-n-{SFX}", "Ubuntu 22.04", CUST_A, None),
    (8, f"a{SFX}x5", f"act-d-{SFX}", "Debian 12", CUST_A, f"C.{SFX}0a5"),
    (9, f"b{SFX}x5", f"act-d-{SFX}", "Debian 12", CUST_B, f"C.{SFX}0b5"),
    (10, f"b{SFX}x6", f"act-b-{SFX}", "Ubuntu 22.04", CUST_B, f"C.{SFX}0b6"),
]
HOST_A, HOST_W, HOST_S, HOST_N, HOST_D, HOST_B = (a[2] for a in ACTION_AGENTS if a[0] != 9)


def seed_action_agents():
    for offset, agent_id, hostname, os_name, customer, client_id in ACTION_AGENTS:
        sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
            "velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, velociraptor_agent_version, "
            "customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) VALUES (:id, :a, '10.0.0.1', :os, :h, "
            "'grp', 0, '2026-10-15 08:00:00', :v, NULL, 'Wazuh v4.9.0', 'active', NULL, :c, 0, 'root', 0)",
            id=AGENT_ID_BASE + offset,
            a=agent_id,
            os=os_name,
            h=hostname,
            v=client_id,
            c=customer,
        )


def datastore_rows():
    """The `agent_datastore` rows of this suite's agents, without the id and the time."""
    with sync_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT agent_id, velociraptor_id, artifact_name, flow_id, bucket_name, object_key, file_name, content_type, "
                "file_size, file_hash, uploaded_by, notes, status, error_message FROM agent_datastore WHERE agent_id IN :ids "
                "ORDER BY id",
            ).bindparams(ids=[a[1] for a in ACTION_AGENTS]),
        )
        return [tuple(r) for r in rows]


BIG = bytes(range(256)) * 4096 + b"tail"


class Velo:
    """What Velociraptor answers the invoke's queries with, per `mode`."""

    def __init__(self):
        self.mode = "ok"

    def __call__(self, stand_in, vql, org_id):
        import grpc

        m = self.mode
        if vql.startswith("SELECT collect_client("):
            if m == "denied":
                return [], (grpc.StatusCode.PERMISSION_DENIED, f"Permission denied: COLLECT_CLIENT in {org_id}")
            if m == "unavailable":
                return [], (grpc.StatusCode.UNAVAILABLE, "datastore is restarting é")
            if m == "no-flow":
                return [[{"collect_client": {"request": 1}}, {"x": {"flow_id": "F.LATER"}}]], None
            if m == "no-rows":
                return [[]], None
            if m == "row-list":
                return [[[1]]], None
            if m == "bad-flow":
                return [[{"collect_client": {"flow_id": "F.bad id"}}]], None
            if m == "flow-int":
                return [[{"collect_client": {"flow_id": 5}}]], None
            if m == "results-not-dicts":
                return [[{"collect_client": {"flow_id": "F.PAR"}}]], None
            return [[{"collect_client": {"flow_id": "F.PAR", "request": {"artifacts": ["x"]}}}]], None
        if vql.startswith("SELECT * FROM watch_monitoring("):
            return [[{"FlowId": "F.PAR", "ClientId": "x"}]], None
        if vql.startswith("SELECT * FROM source("):
            if m == "source-error":
                return [], (grpc.StatusCode.UNAVAILABLE, "no such flow")
            if m == "results-not-dicts":
                return [[1, "two"]], None
            return [[{"Stdout": "killed é", "ReturnCode": 0}]], None
        if vql.startswith("SELECT os_info.hostname AS Hostname"):
            if m == "no-hostname":
                return [[]], None
            if m == "hostname-absent":
                return [[{"Other": 1}]], None
            if m == "hostname-null":
                return [[{"Hostname": None}]], None
            if m == "hostname-int":
                return [[{"Hostname": 42}]], None
            if m == "hostname-list":
                return [[[1]]], None
            return [[{"Hostname": "velo-host"}]], None
        if vql.startswith("SELECT create_flow_download("):
            if m == "download-error":
                return [], (grpc.StatusCode.INTERNAL, "download failed")
            return [[{"create_flow_download": "downloads/x.zip"}]], None
        if vql.startswith("SELECT base64encode("):
            offset = int(re.search(r"offset=(\d+)", vql).group(1))
            if m == "data-bad":
                return [[{"Data": "@@@"}]], None
            if m == "data-padding":
                return [[{"Data": "UEsDBA="}]], None
            if m == "data-int":
                return [[{"Data": 5}]], None
            if m == "data-empty":
                return [[]], None
            if m == "data-non-ascii":
                return [[{"Data": "UEsDBA==é"}]], None
            if m == "data-big":
                return [[{"Data": base64.b64encode(BIG[offset : offset + 1048576]).decode()}]], None
            return [[{"Data": "UEsDBA==" if offset == 0 else ""}]], None
        return [], (grpc.StatusCode.INVALID_ARGUMENT, f"unexpected VQL: {vql}")


VELO = Velo()


def velo(m):
    def set_mode():
        VELO.mode = m
        ACTION.mode = "ok"

    return set_mode


def action(m):
    def set_mode():
        ACTION.mode = m

    return set_mode


def no_key():
    os.environ.pop("COPILOT_API_KEY", None)
    ACTION.mode = "ok"


def sorted_lists(body):
    """Python lists a set in the message (`list(set)`: the strings' hash order, §4)."""
    if isinstance(body, dict) and isinstance(body.get("message"), str):

        def sort(m):
            items = re.findall(r"'([^']*)'", m.group(0))
            return "[" + ", ".join(f"'{i}'" for i in sorted(items)) + "]"

        body = {**body, "message": re.sub(r"\[(?:'[^']*'(?:, )?)+\]", sort, body["message"])}
    return body


INVALID_INVOKES = [
    {},
    {"copilot_action_name": 1, "agent_names": "x"},
    {"copilot_action_name": "kill-process", "agent_names": [1, None]},
    {"copilot_action_name": "kill-process", "agent_names": ["h"], "parameters": {"a": 1}},
    {"copilot_action_name": "kill-process", "agent_names": ["h"], "parameters": {"a": [{"key": "k"}]}},
    {"copilot_action_name": "kill-process", "agent_names": ["h"], "parameters": {"a": [{"key": "k", "value": 2}, "x"]}},
    {"copilot_action_name": "kill-process", "agent_names": ["h"], "parameters": "x"},
    {"copilot_action_name": "kill-process", "agent_names": ["h"], "artifact_name": 5},
    [],
    "str",
]


async def copilot_action_checks(p, bare, t_admin, t_analyst, t_portal, t_resp):
    C = "/api/copilot_action"
    print("\n=== CoPilot Actions: auth ===")
    routes = (
        ("GET", "/inventory"),
        ("GET", "/inventory/count"),
        ("GET", "/inventory/kill-process"),
        ("GET", "/metrics"),
        ("GET", "/technologies"),
        ("POST", "/invoke"),
    )
    for method, path in routes:
        await p.same(f"{method} {path}, no token", method, C + path, before=action("ok"))
        await p.same(f"{method} {path}, bad token", method, C + path, "not-a-jwt")
        for who, tok in (("analyst", t_analyst), ("portal user", t_portal)):
            await p.same(f"{method} {path}, {who}", method, C + path, tok, expect=403, json={})

    print("\n=== CoPilot Actions: the inventory ===")
    await p.same("GET /technologies", "GET", f"{C}/technologies", t_resp, expect=200)
    for m in (
        "ok",
        "total",
        "showing",
        "no-message",
        "total-str",
        "total-float",
        "total-bool",
        "message-int",
        "message-null",
        "bad-item",
        "bad-type",
        "list",
        "actions-null",
        "actions-str",
        "html",
        "error",
        "server-error",
        "redirect",
        "gzip",
        "not-found-message",
    ):
        await p.same(f"GET /inventory, the service answers {m}", "GET", f"{C}/inventory", t_resp, before=action(m), expect=200)
        await p.same(f"GET /inventory/count, the service answers {m}", "GET", f"{C}/inventory/count", t_admin, before=action(m))
    for query in (
        "?technology=Windows&category=c&tag=t&q=kill%20it&limit=5&offset=10&refresh=true&include=a,b",
        "?limit=1000&offset=0&refresh=false&technology=Velociraptor",
        "?category=&tag=&q=&include=",
        "?q=%C3%A9+x&q=last&offset=3",
        "?refresh=1&limit=7&offset=7",
        "?technology=",
        "?technology=windows",
        "?limit=0",
        "?limit=1001",
        "?limit=x&offset=-1&refresh=maybe",
        "?limit=1.5",
        "?technology=Linux&limit=0&offset=x",
    ):
        await p.same(f"GET /inventory{query}", "GET", f"{C}/inventory{query}", t_resp, before=action("ok"))
        await p.same(f"GET /inventory/count{query}", "GET", f"{C}/inventory/count{query}", t_resp, before=action("ok"))
    for name in (
        "kill-process",
        "win-kill",
        "gone",
        "fails",
        "bad",
        "list",
        "html",
        "broken",
        "missing",
        "a%20b",
        "%C3%A9",
        "a|b^[c]",
        "x%3Fy",
        "%2E%2E",
        "it's",
    ):
        await p.same(f"GET /inventory/{name}", "GET", f"{C}/inventory/{name}", t_resp)
    for m in ("ok", "no-message", "list", "message-int", "actions-null", "html", "server-error", "error"):
        await p.same(f"GET /metrics, the service answers {m}", "GET", f"{C}/metrics", t_admin, before=action(m), expect=200)

    print("\n=== CoPilot Actions: without COPILOT_API_KEY ===")
    try:
        for path in ("/inventory", "/inventory/count", "/inventory/kill-process", "/metrics", "/technologies", "/inventory?limit=0"):
            await bare.same(f"GET {path}, no key", "GET", C + path, t_admin, before=no_key)
        await bare.same(
            "POST /invoke, no key",
            "POST",
            f"{C}/invoke",
            t_admin,
            before=no_key,
            json={"copilot_action_name": "kill-process", "agent_names": [HOST_A], "parameters": {"Target": "1"}},
            audit="response.copilot_action_invoke",
        )
    finally:
        os.environ["COPILOT_API_KEY"] = ACTION_KEY

    print("\n=== CoPilot Actions: invoke, the body and the targets ===")
    for body in INVALID_INVOKES:
        await p.same(f"POST /invoke {json.dumps(body)[:90]}", "POST", f"{C}/invoke", t_resp, json=body, expect=422)
    await p.same("POST /invoke, not JSON", "POST", f"{C}/invoke", t_resp, content=b"{", headers={"Content-Type": "application/json"})

    def invoke(hosts, params=None, name="kill-process", **extra):
        return {"copilot_action_name": name, "agent_names": hosts, "parameters": params, **extra}

    au = "response.copilot_action_invoke"
    await p.same("POST /invoke, no agent", "POST", f"{C}/invoke", t_resp, json=invoke([]), expect=400, audit=au)
    await p.same("POST /invoke, another tenant's host", "POST", f"{C}/invoke", t_resp, json=invoke([HOST_A, HOST_B]), expect=403, audit=au)
    await p.same(
        "POST /invoke, an unknown host (responder)",
        "POST",
        f"{C}/invoke",
        t_resp,
        json=invoke([f"nohost-{SFX}"]),
        expect=403,
        audit=au,
    )
    await p.same(
        "POST /invoke, an unknown host (admin)",
        "POST",
        f"{C}/invoke",
        t_admin,
        json=invoke([f"nohost-{SFX}"]),
        expect=404,
        audit=au,
    )
    await p.same(
        "POST /invoke, a known and an unknown host (admin)",
        "POST",
        f"{C}/invoke",
        t_admin,
        json=invoke([HOST_A, f"nohost-{SFX}", HOST_A]),
        expect=404,
        audit=au,
    )
    for name in ("missing", "gone", "fails", "broken", "bad"):
        await p.same(
            f"POST /invoke, the action {name}",
            "POST",
            f"{C}/invoke",
            t_resp,
            json=invoke([HOST_A], {"Target": "1"}, name=name),
            before=velo("ok"),
            audit=au,
        )
    for label, name, params in (
        ("an unknown parameter", "kill-process", {"Target": "1", "Other": "x"}),
        ("two unknown parameters", "kill-process", {"Other": "x", "Else": "y", "Target": "1"}),
        ("no Target", "kill-process", {"Mode": "soft"}),
        ("no parameters", "kill-process", None),
        ("no ScriptURL", "no-url", {"Target": "1"}),
        ("no ScriptURL nor Target", "no-url", {}),
    ):
        await p.same(
            f"POST /invoke, {label}",
            "POST",
            f"{C}/invoke",
            t_resp,
            json=invoke([HOST_A], params, name=name),
            before=velo("ok"),
            expect=400,
            audit=au,
            canon=sorted_lists,
        )

    print("\n=== CoPilot Actions: invoke, the collections ===")
    ok_params = {"Mode": "it's", "Target": "1234"}
    for label, hosts, params, name, tok in (
        ("a Linux host", [HOST_A], ok_params, "kill-process", t_resp),
        ("a Windows host", [HOST_W], {"Target": "1"}, "win-kill", t_resp),
        ("two hosts", [HOST_W, HOST_A], {"Target": "1"}, "kill-process", t_admin),
        ("an OS without an artifact", [HOST_S], {"Target": "1"}, "kill-process", t_resp),
        ("a host without a client id", [HOST_N], {"Target": "1"}, "kill-process", t_resp),
        ("one of two failing", [HOST_A, HOST_S], {"Target": "1"}, "kill-process", t_resp),
        (
            "ScriptURL as pairs",
            [HOST_A],
            {"Target": "1", "ScriptURL": [{"key": "k", "value": "v'"}]},
            "no-url",
            t_resp,
        ),
        ("ScriptURL replaced", [HOST_A], {"ScriptURL": "https://evil.example/x", "Target": "1"}, "kill-process", t_resp),
        ("the same host twice", [HOST_A, HOST_A], {"Target": "1"}, "kill-process", t_resp),
        ("a host of two tenants (admin)", [HOST_D], {"Target": "1"}, "kill-process", t_admin),
    ):
        await p.same(
            f"POST /invoke, {label}",
            "POST",
            f"{C}/invoke",
            tok,
            json=invoke(hosts, params, name=name),
            before=velo("ok"),
            expect=200,
            audit=au,
            table=datastore_rows,
        )
    for m in (
        "denied",
        "unavailable",
        "no-flow",
        "no-rows",
        "row-list",
        "bad-flow",
        "flow-int",
        "results-not-dicts",
        "source-error",
        "no-hostname",
        "hostname-absent",
        "hostname-null",
        "hostname-int",
        "hostname-list",
        "download-error",
        "data-bad",
        "data-padding",
        "data-int",
        "data-empty",
        "data-non-ascii",
        "data-big",
    ):
        await p.same(
            f"POST /invoke, Velociraptor answers {m}",
            "POST",
            f"{C}/invoke",
            t_resp,
            json=invoke([HOST_A], {"Target": "1"}),
            before=velo(m),
            expect=200,
            audit=au,
            table=datastore_rows,
        )

    def upload_fails():
        velo("ok")()
        S3.fault(
            lambda m, path, q: m == "PUT" and path.startswith("/velociraptor-artifacts/"),
            (500, {"Content-Type": "application/xml"}, b"<Error/>"),
            count=10,
        )

    await p.same(
        "POST /invoke, MinIO refuses the upload",
        "POST",
        f"{C}/invoke",
        t_resp,
        json=invoke([HOST_A], {"Target": "1"}),
        before=upload_fails,
        expect=200,
        audit=au,
        table=datastore_rows,
    )

    # §4: a hostname is no tenant key. Python ran the action on every agent of that name; Rust
    # only on the caller's.
    S3.faults = []
    velo("ok")()
    for recorder in RECORDERS:
        recorder.take()
    py, _, _ = await p.call(p.py, "POST", f"{C}/invoke", t_resp, json=invoke([HOST_D], {"Target": "1"}))
    velo("ok")()
    rs, out, _ = await p.call(p.rs, "POST", f"{C}/invoke", t_resp, json=invoke([HOST_D], {"Target": "1"}))
    a_id, b_client = ACTION_AGENTS[4][1], ACTION_AGENTS[5][5]
    py_body, rs_body = py.json(), rs.json()
    mine = [r for r in py_body.get("responses", []) if (r.get("file_info") or {}).get("object_key", "").startswith(f"{a_id}/")]
    check(
        "§4 POST /invoke, a host of two tenants (responder): Python runs on both, Rust on the caller's",
        py.status_code == 200
        and len(py_body["responses"]) == 2
        and rs.status_code == 200
        and rs_body
        == {
            "responses": mine,
            "message": "Successfully invoked action on all 1 agent(s). Check the appropriate Grafana dashboard for results.",
            "success": True,
        }
        and all(b_client.encode() not in b for _, _, _, b in out),
        f"python {py.status_code} {py.content[:600]!r}\n        rust   {rs.status_code} {rs.content[:600]!r}",
    )


# --- Shuffle --------------------------------------------------------------------------------------

#: Explicit ids of the case-notification rows, one block per table from this suite's base.
INC = AGENT_ID_BASE
CUST_C = f"RsC{SFX}"
CTX = {
    "c0": {"rule_level": "12", "rule_mitre_id": "T1059", "agent_name": "h1 é", "nested": {"z": 1.5, "a": [1, None]}},
    "c1": {"rule": {"level": 3}, "data": "x"},
    "c2": [1],
    "c3": {"rule_level": 7.9, "rule_mitre_id": None},
}
#: alert key → (offset, customer, context key, or None for no asset; the asset's foreign key
#: rules out a missing context)
ALERTS = {
    "al0": (0, CUST_A, "c0"),
    "al1": (1, CUST_A, "c1"),
    "al2": (2, CUST_A, None),
    "al3": (3, CUST_A, "c2"),
    "al5": (5, CUST_B, "c0"),
    "al6": (6, CUST_C, "c3"),
}
#: case key → (offset, customer, alerts)
CASES = {
    "ok": (0, CUST_A, ["al0", "al1"]),
    "no-asset": (1, CUST_A, ["al2"]),
    "ctx-list": (2, CUST_A, ["al3"]),
    "tenant-b": (4, CUST_B, ["al5"]),
    "empty": (5, CUST_A, []),
    "disabled": (6, CUST_C, ["al6"]),
}


def case_id(key):
    return INC + CASES[key][0]


def seed_incidents():
    for i, (key, ctx) in enumerate(CTX.items()):
        sql("INSERT INTO incident_management_alertcontext (id, source, context) VALUES (:i, 'wazuh', :j)", i=INC + i, j=json.dumps(ctx))
    ctx_ids = {key: INC + i for i, key in enumerate(CTX)}
    for key, (off, cust, ctx) in ALERTS.items():
        sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
            "source, escalated) VALUES (:i, :n, 'd', 'OPEN', '2026-10-01 10:00:00', :c, 'wazuh', 0)",
            i=INC + off,
            n=f"Alert {key} {SFX} é",
            c=cust,
        )
        if ctx is not None:
            sql(
                "INSERT INTO incident_management_asset (id, alert_linked, asset_name, alert_context_id, customer_code, index_name, "
                "index_id, agent_id) VALUES (:i, :a, :n, :ctx, :c, 'wazuh-alerts-1', :doc, '007')",
                i=INC + off,
                a=INC + off,
                n=f"host-{key}",
                ctx=ctx_ids[ctx],
                c=cust,
                doc=f"doc-{key}",
            )
    for i, (value, kind) in enumerate((("1.2.3.4", "IP"), ("evil.example", "DOMAIN"), ("1.2.3.4", "HASH"))):
        sql("INSERT INTO incident_management_ioc (id, value, type, description) VALUES (:i, :v, :t, 'seen')", i=INC + i, v=value, t=kind)
        sql("INSERT INTO incident_management_alert_to_ioc (alert_id, ioc_id) VALUES (:a, :i)", a=INC, i=INC + i)
    for key, (off, cust, alerts) in CASES.items():
        sql(
            "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, customer_code, "
            "notification_invoked_number, escalated) VALUES (:i, :n, 'cd', '2026-10-02 09:00:00', 'OPEN', :c, NULL, 0)",
            i=INC + off,
            n=f"Case {key} {SFX}",
            c=cust,
        )
        for a in alerts:
            sql("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=INC + off, a=INC + ALERTS[a][0])
    sql(
        "INSERT INTO incident_management_notification (id, customer_code, shuffle_workflow_id, enabled) VALUES "
        "(:i, :a, 'wf-case', 1), (:j, :c, 'wf-off', 0)",
        i=INC,
        a=CUST_A,
        j=INC + 1,
        c=CUST_C,
    )


def cleanup_incidents():
    lo, hi = INC, INC + 999
    sql("DELETE FROM incident_management_casealertlink WHERE case_id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_case WHERE id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_alert_to_ioc WHERE alert_id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_ioc WHERE id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_asset WHERE id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_alert WHERE id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_alertcontext WHERE id BETWEEN :lo AND :hi", lo=lo, hi=hi)
    sql("DELETE FROM incident_management_notification WHERE id BETWEEN :lo AND :hi", lo=lo, hi=hi)


def notified(key):
    with sync_engine.connect() as conn:
        return conn.execute(
            text("SELECT notification_invoked_number FROM incident_management_case WHERE id = :i"),
            {"i": case_id(key)},
        ).scalar()


def shuffle(**mode):
    def set_mode():
        SHUFFLE.mode = dict(mode)
        SHUFFLE.results_calls = 0

    return set_mode


def shuffle_down():
    set_connector("Shuffle", f"http://127.0.0.1:{CLOSED_PORT}", api_key=SHUFFLE_KEY)


def shuffle_up():
    set_connector("Shuffle", f"http://127.0.0.1:{SHUFFLE_PORT}", api_key=SHUFFLE_KEY)


async def shuffle_checks(p, t_admin, t_analyst, t_portal, t_resp):
    W, I, ORGS = "/api/workflows", "/api/shuffle/integrations", "/api/shuffle/organizations/organizations"
    N = "/api/incidents/db_operations/case/notification"
    print("\n=== Shuffle: auth ===")
    for method, path in (
        ("GET", W),
        ("GET", W + "/executions"),
        ("POST", W + "/execute"),
        ("GET", I + "/credentials"),
        ("POST", I + "/execute"),
        ("POST", I + "/invoke-workflow"),
        ("POST", "/api/shuffle/singul/execute"),
        ("GET", ORGS),
        ("GET", ORGS + "/o1"),
        ("GET", ORGS + "/name/beta"),
        ("POST", N),
    ):
        await p.same(f"{method} {path}, no token", method, path, before=shuffle())
        await p.same(f"{method} {path}, bad token", method, path, "not-a-jwt")
        await p.same(f"{method} {path}, portal user", method, path, t_portal, expect=403, json={})

    print("\n=== Shuffle: workflows ===")
    for m in (
        "ok",
        "empty",
        "null",
        "dict",
        "dict-plain",
        "str-elem",
        "int-elem",
        "actions-null",
        "actions-lists",
        "actions-str",
        "actions-dict",
        "list-elem",
        "no-id",
        "no-name",
        "int-id",
        "int-name",
        "html",
        "error",
    ):
        await p.same(f"GET /workflows, Shuffle answers {m}", "GET", W, t_analyst, before=shuffle(workflows=m))
        await p.same(f"GET /workflows/executions, Shuffle answers {m}", "GET", W + "/executions", t_admin, before=shuffle(workflows=m))
    for m in ("dict", "no-status", "int-status", "str", "html"):
        await p.same(
            f"GET /workflows/executions, the executions answer {m}",
            "GET",
            W + "/executions",
            t_admin,
            before=shuffle(executions=m),
        )
    for body in ({}, {"workflow_id": 1, "execution_argument": None}, [], "x"):
        await p.same(f"POST /workflows/execute {json.dumps(body)}", "POST", W + "/execute", t_admin, json=body, expect=422)
    run = {"workflow_id": "wf-1", "execution_argument": "arg é"}
    await p.same(
        "POST /workflows/execute, an unknown workflow",
        "POST",
        W + "/execute",
        t_admin,
        json={**run, "workflow_id": "nope"},
        before=shuffle(),
    )
    for wf, res in (
        ("ok", "finished"),
        ("ok", "second"),
        ("ok", "then-204"),
        ("ok", "then-list"),
        ("ok", "then-html"),
        ("fail", "finished"),
        ("bad", "finished"),
        ("v1", "finished"),
        ("missing", "finished"),
        ("list", "finished"),
        ("204", "finished"),
        ("html", "finished"),
        ("status-500", "finished"),
    ):
        await p.same(
            f"POST /workflows/execute, execute {wf}, results {res}",
            "POST",
            W + "/execute",
            t_analyst,
            json=run,
            before=shuffle(execute=wf, results=res),
        )
    for m in ("no-id", "int-id", "html"):
        await p.same(
            f"POST /workflows/execute, the listing answers {m}",
            "POST",
            W + "/execute",
            t_admin,
            json=run,
            before=shuffle(workflows=m),
        )

    print("\n=== Shuffle: integrations ===")
    await p.same("GET /credentials", "GET", I + "/credentials", t_analyst, expect=200)
    set_connector("Shuffle", f"http://127.0.0.1:{SHUFFLE_PORT}///", api_key=SHUFFLE_KEY)
    await p.same("GET /credentials, trailing slashes", "GET", I + "/credentials", t_analyst, expect=200)
    set_connector("Shuffle", f"http://127.0.0.1:{SHUFFLE_PORT}", api_key="")
    await p.same("GET /credentials, no key", "GET", I + "/credentials", t_analyst, expect=400)
    set_connector("Shuffle", None)
    await p.same("GET /credentials, no connector", "GET", I + "/credentials", t_analyst, expect=404)
    await p.same("GET /workflows, no connector", "GET", W, t_analyst, before=shuffle())
    await p.same("POST /execute, no connector", "POST", I + "/execute", t_analyst, json={"app_name": "a", "category": "c", "label": "l"})
    shuffle_up()
    integration = {"app_name": "PagerDuty", "category": "cases", "label": "create_ticket", "fields": [{"key": "title", "value": "t é"}]}
    for body in (
        {},
        {"app_name": 1, "category": None, "label": []},
        {**integration, "fields": [1]},
        {**integration, "skip_workflow": "maybe"},
        "x",
    ):
        await p.same(f"POST /execute {json.dumps(body)[:80]}", "POST", I + "/execute", t_analyst, json=body, expect=422)
    for m in ("ok", "false-reason", "false", "reason-dict", "list", "204", "html", "status-400"):
        await p.same(f"POST /execute, Shuffle answers {m}", "POST", I + "/execute", t_analyst, json=integration, before=shuffle(run=m))
    await p.same(
        "POST /execute, nulls",
        "POST",
        I + "/execute",
        t_analyst,
        json={**integration, "fields": None, "skip_workflow": None},
        before=shuffle(),
    )
    invoke = {"workflow_id": "wf-9", "execution_arguments": {"customer_code": CUST_A, "alert": {"x": [1, 2.5]}}, "start": "s"}
    for body in (
        {"execution_arguments": {"customer_code": CUST_A}},
        {"workflow_id": "wf-9", "start": 5},
        {"workflow_id": "wf-9"},
        {"workflow_id": "wf-9", "execution_arguments": None},
        {"workflow_id": "wf-9", "execution_arguments": {"customer_code": ""}},
        {"workflow_id": "wf-9", "execution_arguments": {"customer_code": 0}},
        {"workflow_id": "wf-9", "execution_arguments": "x"},
    ):
        await p.same(f"POST /invoke-workflow {json.dumps(body)[:80]}", "POST", I + "/invoke-workflow", t_analyst, json=body)
    for m in ("ok", "fail", "fail-reason", "204", "html", "status-500"):
        await p.same(
            f"POST /invoke-workflow, Shuffle answers {m}",
            "POST",
            I + "/invoke-workflow",
            t_analyst,
            json=invoke,
            before=shuffle(execute=m),
        )
    await p.same(
        "POST /invoke-workflow, an int customer code (admin)",
        "POST",
        I + "/invoke-workflow",
        t_admin,
        json={**invoke, "execution_arguments": {"customer_code": 5}},
        before=shuffle(),
    )
    # §4: the body names the tenant. Python ran another customer's workflow for any analyst.
    for label, args in (("another tenant's customer", {"customer_code": CUST_B}), ("an int customer code", {"customer_code": 5})):
        shuffle()()
        py, out_py, _ = await p.call(p.py, "POST", I + "/invoke-workflow", t_analyst, json={**invoke, "execution_arguments": args})
        shuffle()()
        rs, out_rs, _ = await p.call(p.rs, "POST", I + "/invoke-workflow", t_analyst, json={**invoke, "execution_arguments": args})
        check(
            f"§4 POST /invoke-workflow, {label} (analyst): Python runs it, Rust refuses",
            py.status_code == 200
            and len(out_py) == 1
            and rs.status_code == 403
            and rs.json() == {"success": False, "message": f"Access denied to customer {args['customer_code']}"}
            and out_rs == [],
            f"python {py.status_code} {py.content[:300]!r}\n        rust   {rs.status_code} {rs.content[:300]!r}",
        )
    shuffle_down()
    await p.same("POST /execute, Shuffle unreachable", "POST", I + "/execute", t_analyst, json=integration)
    await p.same("POST /invoke-workflow, Shuffle unreachable", "POST", I + "/invoke-workflow", t_analyst, json=invoke)
    await p.same("GET /workflows, Shuffle unreachable", "GET", W, t_analyst)
    await p.same("GET /organizations, Shuffle unreachable", "GET", ORGS, t_analyst)
    await p.same("POST /case/notification, Shuffle unreachable", "POST", N, t_admin, json={"case_id": case_id("ok")})
    shuffle_up()

    print("\n=== Shuffle: Singul ===")
    for body in ({}, {"app": 5}, [], None):
        await p.same(f"POST /singul/execute {json.dumps(body)}", "POST", "/api/shuffle/singul/execute", t_analyst, json=body, expect=422)
    r = await p.rs.post("/api/shuffle/singul/execute", json={"app": "outlook"}, headers={"Authorization": f"Bearer {t_admin}"})
    check(
        "POST /singul/execute, a valid body: Rust answers uvicorn's bare 500 (exit(0))",
        r.status_code == 500 and r.text == "Internal Server Error",
        r.text,
    )

    print("\n=== Shuffle: organizations ===")
    for m in ("ok", "dict", "null", "html"):
        await p.same(f"GET /organizations, Shuffle answers {m}", "GET", ORGS, t_analyst, before=shuffle(orgs=m))
        await p.same(f"GET /organizations/name/beta, Shuffle answers {m}", "GET", ORGS + "/name/beta", t_analyst, before=shuffle(orgs=m))
    for query in ("?connector_name=shuffle", "?connector_name=Nope", "?connector_name=", "?connector_name=Shuffle&connector_name=Nope"):
        await p.same(f"GET /organizations{query}", "GET", ORGS + query, t_analyst, before=shuffle())
    for name in ("BETA", "gamma", "nope", "Acme%20MSSP", "o1"):
        await p.same(f"GET /organizations/name/{name}", "GET", f"{ORGS}/name/{name}", t_admin, before=shuffle())
    for org in (
        "o1",
        "o-empty",
        "o-null",
        "o-list",
        "o-bad",
        "o-mgr-int",
        "o-mgr-bool",
        "o-mgr-float",
        "o-mgr-dict",
        "o-mgr-str",
        "o%201",
        "o-html",
        "unknown",
        "name",
    ):
        await p.same(f"GET /organizations/{org}", "GET", f"{ORGS}/{org}", t_analyst, before=shuffle())
    await p.same("GET /organizations/o1?connector_name=Nope", "GET", f"{ORGS}/o1?connector_name=Nope", t_analyst)

    print("\n=== Shuffle: the connector's verification ===")
    with sync_engine.connect() as conn:
        shuffle_row = conn.execute(text("SELECT id FROM connectors WHERE connector_name = 'Shuffle'")).scalar()
    for m in ("ok", "refused", "moved"):
        await p.same(
            f"POST /connectors/verify (Shuffle answers {m})",
            "POST",
            f"/api/connectors/verify/{shuffle_row}",
            t_admin,
            before=shuffle(auth=m),
        )
    shuffle_down()
    with sync_engine.connect() as conn:
        shuffle_row = conn.execute(text("SELECT id FROM connectors WHERE connector_name = 'Shuffle'")).scalar()
    await p.same("POST /connectors/verify (Shuffle unreachable)", "POST", f"/api/connectors/verify/{shuffle_row}", t_admin)
    shuffle_up()

    print("\n=== Shuffle: the case notification ===")
    for body in ({}, {"case_id": "x"}, {"case_id": 1.5}, [], "x"):
        await p.same(f"POST /case/notification {json.dumps(body)}", "POST", N, t_admin, json=body, expect=422)
    await p.same("POST /case/notification, an unknown case", "POST", N, t_admin, json={"case_id": INC + 900}, expect=404)
    await p.same("POST /case/notification, a case id beyond the column", "POST", N, t_admin, json={"case_id": 10**18}, expect=404)
    await p.same("POST /case/notification, another tenant's case", "POST", N, t_analyst, json={"case_id": case_id("tenant-b")}, expect=403)
    for key, who, tok, mode in (
        ("ok", "analyst", t_analyst, "ok"),
        ("ok", "admin, as a string id", t_admin, "ok"),
        ("ok", "Shuffle refuses", t_admin, "fail"),
        ("ok", "Shuffle names why", t_admin, "fail-reason"),
        ("ok", "Shuffle answers 204", t_admin, "204"),
        ("ok", "Shuffle answers HTML", t_admin, "html"),
        ("no-asset", "admin", t_admin, "ok"),
        ("ctx-list", "admin", t_admin, "ok"),
        ("tenant-b", "admin (no notification row)", t_admin, "ok"),
        ("empty", "admin", t_admin, "ok"),
        ("disabled", "admin (disabled)", t_admin, "ok"),
    ):
        before_count = notified(key)
        r1, r2 = await p.same(
            f"POST /case/notification, case {key}, {who}, {mode}",
            "POST",
            N,
            tok,
            json={"case_id": str(case_id(key)) if "string" in who else case_id(key)},
            before=shuffle(execute=mode),
        )
        bumped = 2 if r1.status_code == 200 else 0
        check(
            f"POST /case/notification, case {key}, {who}, {mode}: notification_invoked_number",
            notified(key) == (before_count or 0) + bumped if bumped else notified(key) == before_count,
            f"{before_count} -> {notified(key)}",
        )


async def main():
    manager_server = start_http_stub(MANAGER_PORT, MANAGER, MANAGER_RECORDER)
    worker_server = start_http_stub(WORKER_PORT, WORKER, WORKER_RECORDER)
    s3_server = S3.serve(S3_PORT)
    action_server = start_http_stub(ACTION_PORT, ACTION, ACTION_RECORDER)
    shuffle_server = start_http_stub(SHUFFLE_PORT, SHUFFLE, SHUFFLE_RECORDER)
    velo_stand_in = agents_parity.VeloStandIn(VELO_PORT, VELO)
    VELO_RECORDER.stand_in = velo_stand_in
    workdir = tempfile.mkdtemp(prefix="response-parity-")
    patch_python()
    procs = []
    try:
        seed()
        seed_action_agents()
        seed_incidents()
        shuffle_up()
        set_connector("Velociraptor", "https://velo", api_key=agents_parity.api_config(workdir, velo_stand_in.address))
        seed_minio()
        procs.append(start_rust(RS_PORT))
        procs.append(start_rust(RS_BARE_PORT, bare=True))
    except BaseException:
        for proc_ in procs:
            proc_.kill()
        cleanup()
        raise
    p, bare = Pair(RS_PORT), Pair(RS_BARE_PORT)
    t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
    t_portal, t_resp = token(PORTAL, ["customer_user"]), token(RESP, ["responder", "analyst"])
    try:
        sections = os.environ.get("RESPONSE_PARITY_SECTIONS", "active_response,graylog,sysmon,copilot_action,shuffle").split(",")
        if "active_response" in sections:
            await active_response_checks(p, t_admin, t_analyst, t_portal, t_resp)
        if "graylog" in sections:
            await graylog_webhook_checks(p, bare)
        if "sysmon" in sections:
            await sysmon_checks(p, t_admin, t_analyst, t_portal, t_resp)
        if "copilot_action" in sections:
            # `fetch_file_from_filestore` writes the pack into the working directory and leaves
            # it there when the upload fails.
            here = os.getcwd()
            os.chdir(workdir)
            try:
                await copilot_action_checks(p, bare, t_admin, t_analyst, t_portal, t_resp)
            finally:
                os.chdir(here)
        if "shuffle" in sections:
            await shuffle_checks(p, t_admin, t_analyst, t_portal, t_resp)
    finally:
        await p.close()
        await bare.close()
        for proc_ in procs:
            proc_.terminate()
            try:
                proc_.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc_.kill()
        cleanup()
        manager_server.shutdown()
        worker_server.shutdown()
        s3_server.shutdown()
        action_server.shutdown()
        shuffle_server.shutdown()
        velo_stand_in.stop()
        shutil.rmtree(workdir, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
