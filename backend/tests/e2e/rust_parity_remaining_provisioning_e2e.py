"""Parity of the remaining provisioning routes ported to Rust with this backend — NOT collected by
pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

`POST /api/office365/provision` (`copilot-cloud-provisioning`) is answered by the real FastAPI
router and by Rust instances on one database. One Rust instance meets Graylog 6, a second Graylog 7
(both backends cache the version; Python's is pinned to the instance in use). The routers are
served by uvicorn in a thread: that app is the Python side of every check and the Rust instances'
legacy backend. The tools are local stand-ins recording every request — method, target, every
header the client sent and the body bytes: the Wazuh manager (`/wazuh`, its `ossec.conf` kept and
rewritten as a manager would), Graylog (`/graylog`, stateful: pipeline rules, pipelines, index sets,
streams, connections) and Grafana (`/grafanaapi`, the root `grafana_client` builds from a connector
URL ending in `/grafana`) on one port, the Wazuh indexer on another. For each request the suite
compares the status, the body, every outbound request and what the request left: the rows, the
manager's configuration and Graylog's objects. Deliberate differences are asserted as such
(RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_remaining_provisioning_e2e.py scripts/rust-parity.sh

Ports (all overridable): REMAINING_PROV_PARITY_RUST_PORT (6841), REMAINING_PROV_PARITY_RUST7_PORT
(6842), REMAINING_PROV_PARITY_PY_PORT (6843, the uvicorn legacy backend), REMAINING_PROV_STUB_PORT
(6844, manager, Graylog and Grafana), REMAINING_PROV_INDEXER_STUB_PORT (6845). Seeded ids are seven
digits in 7860000-7869999. `REMAINING_PROV_PARITY_SECTIONS=office365` picks the sections.
"""

import asyncio
import copy
import datetime
import fnmatch
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
from urllib.parse import urlsplit

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(BACKEND, ".."))
sys.path.insert(0, HERE)

import connector_samples as samples  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
import uvicorn  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import bindparam  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = os.environ.get("REMAINING_PROV_PARITY_SFX") or uuid.uuid4().hex[:6]
RS_PORT = int(os.environ.get("REMAINING_PROV_PARITY_RUST_PORT", "6841"))
RS7_PORT = int(os.environ.get("REMAINING_PROV_PARITY_RUST7_PORT", "6842"))
PY_PORT = int(os.environ.get("REMAINING_PROV_PARITY_PY_PORT", "6843"))
STUB_PORT = int(os.environ.get("REMAINING_PROV_STUB_PORT", "6844"))
INDEXER_PORT = int(os.environ.get("REMAINING_PROV_INDEXER_STUB_PORT", "6845"))
CLOSED_PORT = int(os.environ.get("REMAINING_PROV_CLOSED_PORT", "6848"))
SEED_LO, SEED_HI = 7_860_000, 7_869_999

CUST_A, CUST_B, CUST_C = f"RPA{SFX}", f"RPB{SFX}", f"RPC{SFX}"
CUST_D = f"RPD{SFX}"  # integration rows, but no `customers` row (the string key is not an FK)
CUSTOMERS = (CUST_A, CUST_B, CUST_C)
NAME_A, NAME_B, NAME_C = f"Alpha {SFX}", f"Beta {SFX}", f"Gamma {SFX}"
ADMIN, ANALYST, ANALYST_B, UNASSIGNED = (f"rp_admin{SFX}", f"rp_analyst{SFX}", f"rp_analyst_b{SFX}", f"rp_unassigned{SFX}")
USERS = (ADMIN, ANALYST, ANALYST_B, UNASSIGNED)
OUR_CONNECTORS = ("Wazuh-Manager", "Graylog", "Grafana", "Wazuh-Indexer")
GRAFANA_URL = f"http://127.0.0.1:{STUB_PORT}/grafana"
INDEXER_URL = f"http://127.0.0.1:{INDEXER_PORT}"
TENANT_A, TENANT_A2, TENANT_B, TENANT_D = (f"ten-a-{SFX}", f"ten-a2-{SFX}", f"ten-b-{SFX}", f"ten-d-{SFX}")
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def _bind(statement, params):
    stmt = text(statement)
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    return stmt


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(_bind(statement, params), params)


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(_bind(statement, params), params)]


def _json(value):
    return json.dumps(value).encode()


def _override(overrides, method, path):
    """The override for (method, path): one answer, or a list answered in turn (the last
    repeated); an answer with a fourth item is sent after that many seconds."""
    for (m, pattern), reply in overrides.items():
        if m == method and fnmatch.fnmatchcase(path, pattern):
            if isinstance(reply, list):
                reply = reply.pop(0) if len(reply) > 1 else reply[0]
            if len(reply) == 4:
                time.sleep(reply[3])
                reply = reply[:3]
            return reply
    return None


# --- The stand-ins ------------------------------------------------------------------------------------

OSSEC = """<!-- Wazuh - Manager - Default configuration -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <email_from>wazuh&amp;co@example.com</email_from>
  </global>
  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
</ossec_config>
"""


def ossec_with_office365(tenant):
    return OSSEC.replace(
        "  <!-- Policy monitoring -->",
        f"""  <office365>
    <enabled>yes</enabled>
    <only_future_events>yes</only_future_events>
    <interval>1m</interval>
    <curl_max_size>1M</curl_max_size>
    <api_auth>
      <tenant_id>{tenant}</tenant_id>
      <client_id>c-other</client_id>
      <client_secret>s&lt;other&gt;</client_secret>
      <api_type>commercial</api_type>
    </api_auth>
    <subscriptions>
      <subscription>Audit.SharePoint</subscription>
      <subscription>Audit.Exchange</subscription>
    </subscriptions>
  </office365>
  <!-- Policy monitoring -->""",
    )


class Manager:
    """The Wazuh manager: a token, `ossec.conf` (served raw, replaced by a PUT unless refused), the
    restart. Per-test overrides by (method, path glob)."""

    def __init__(self):
        self.reset()

    def reset(self, config=OSSEC, refuse=0, overrides=None):
        self.config = config
        # How many PUTs of the configuration answer `error: 1` before one is taken.
        self.refuse = refuse
        self.overrides = copy.deepcopy(overrides or {})

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix("/wazuh")
        reply = _override(self.overrides, method, path)
        if reply:
            return reply
        j = "application/json"
        if path == "/security/user/authenticate":
            return 200, j, _json({"data": {"token": "parity-token"}, "error": 0})
        if path == "/manager/configuration" and method == "GET":
            return 200, "text/plain; charset=utf-8", self.config.encode()
        if path == "/manager/configuration" and method == "PUT":
            if self.refuse:
                self.refuse -= 1
                return 200, j, _json({"data": {"affected_items": [], "failed_items": [{"error": {"code": 1113}}]}, "error": 1})
            self.config = body.decode()
            return 200, j, _json({"data": {"affected_items": ["manager"], "total_affected_items": 1}, "error": 0})
        if path == "/manager/restart" and method == "PUT":
            return 200, j, _json({"data": {"affected_items": ["manager"]}, "message": "Restart request sent", "error": 0})
        return 404, j, _json({"title": "Not Found", "detail": f"no stand-in for {method} {path}"})


def pipeline_rule(rid, title, source, description=None):
    return {
        "id": rid,
        "title": title,
        "description": description if description is not None else title,
        "source": source,
        "created_at": "2026-10-01T00:00:00.000Z",
        "modified_at": "2026-10-01T00:00:00.000Z",
        "errors": None,
    }


def pipeline(pid, title, description):
    return {
        "id": pid,
        "title": title,
        "description": description,
        "source": f'pipeline "{title}"\nstage 0 match either\nend',
        "stages": [{"match": "EITHER", "rules": [], "stage": 0}],
        "created_at": "2026-10-01T00:00:00.000Z",
        "modified_at": None,
        "errors": None,
    }


class Graylog:
    """Graylog 6.1 / 7.0 for the Office 365 and AWS flows: pipeline rules and pipelines, index sets,
    streams (wrapped for 7.x), their resume and pipeline connections, and the deletes of a
    rollback. Per-test overrides by (method, path glob)."""

    def __init__(self, prefix):
        self.prefix = prefix
        self.reset()

    def reset(self, version=6, rules=None, pipelines=None, overrides=None):
        self.version = version
        self.rules = copy.deepcopy(rules if rules is not None else [pipeline_rule("r-other", "Other rule", 'rule "Other rule"\nend')])
        self.pipelines = copy.deepcopy(pipelines if pipelines is not None else [pipeline("pl-wazuh", "WAZUH", "Wazuh processing")])
        self.index_sets = []
        self.streams = []
        self.connections = []
        self.deleted = []
        self.overrides = copy.deepcopy(overrides or {})
        self.counter = 0

    def _id(self, prefix):
        self.counter += 1
        return f"{prefix}{self.counter:04d}"

    def state(self):
        return {
            "rules": self.rules,
            "pipelines": [{k: p[k] for k in ("id", "title", "description", "source")} for p in self.pipelines],
            "index_sets": self.index_sets,
            "streams": self.streams,
            "connections": self.connections,
            "deleted": self.deleted,
        }

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix(self.prefix)
        reply = _override(self.overrides, method, path)
        if reply:
            return reply
        j = "application/json"
        if method == "GET" and path == "/api/system":
            return 200, j, _json(samples.GRAYLOG_SYSTEM_7 if self.version == 7 else samples.GRAYLOG_SYSTEM_6)
        if method == "GET" and path == "/api/system/pipelines/rule":
            return 200, j, _json(self.rules)
        if method == "POST" and path == "/api/system/pipelines/rule":
            data = json.loads(body)
            new = pipeline_rule(self._id("r"), data.get("title"), data.get("source"), data.get("description"))
            self.rules.append(new)
            return 200, j, _json(new)
        m = re.fullmatch(r"/api/system/pipelines/rule/([^/]+)", path)
        if method == "PUT" and m:
            found = next((r for r in self.rules if r["id"] == m.group(1)), None)
            if found is None:
                return 404, j, _json({"type": "ApiError", "message": f"Rule {m.group(1)} not found"})
            found.update(json.loads(body))
            return 200, j, _json(found)
        if method == "GET" and path == "/api/system/pipelines/pipeline":
            return 200, j, _json(self.pipelines)
        if method == "POST" and path == "/api/system/pipelines/pipeline":
            data = json.loads(body)
            new = pipeline(self._id("pl"), data.get("title"), data.get("description"))
            new["source"] = data.get("source")
            self.pipelines.append(new)
            return 200, j, _json(new)
        if method == "POST" and path == "/api/system/indices/index_sets":
            data = json.loads(body)
            data["creation_date"] = "<utcnow>"
            new = {"id": self._id("is"), **data, "can_be_default": True, "default": False}
            self.index_sets.append(new)
            return 200, j, _json(new)
        m = re.fullmatch(r"/api/system/indices/index_sets/([^/]+)", path)
        if method == "DELETE" and m:
            self.index_sets = [i for i in self.index_sets if i["id"] != m.group(1)]
            self.deleted.append(("index_set", m.group(1)))
            return 204, None, b""
        if method == "POST" and path == "/api/streams":
            entity = json.loads(body)
            if self.version >= 7:
                if "entity" not in entity:
                    return 400, j, _json({"type": "ApiError", "message": "entity cannot be null"})
                entity = entity["entity"]
            elif "entity" in entity:
                return 400, j, _json({"type": "ApiError", "message": "Unable to map property entity"})
            new_id = self._id("st")
            self.streams.append({"id": new_id, **entity, "running": False})
            return 201, j, _json({"stream_id": new_id})
        m = re.fullmatch(r"/api/streams/([^/]+)/resume", path)
        if method == "POST" and m:
            for st in self.streams:
                if st["id"] == m.group(1):
                    st["running"] = True
            return 204, None, b""
        m = re.fullmatch(r"/api/streams/([^/]+)", path)
        if method == "DELETE" and m:
            self.streams = [s for s in self.streams if s["id"] != m.group(1)]
            self.deleted.append(("stream", m.group(1)))
            return 204, None, b""
        if method == "POST" and path == "/api/system/pipelines/connections/to_stream":
            data = json.loads(body)
            new = {"id": self._id("pc"), "stream_id": data.get("stream_id"), "pipeline_ids": data.get("pipeline_ids")}
            self.connections.append(new)
            return 200, j, _json(new)
        return 404, j, _json({"type": "ApiError", "message": "HTTP 404 Not Found"})


class Grafana:
    """Grafana 11: the org switch, datasources, folders, dashboards and the deletes of a
    rollback. Per-test overrides by (method, path glob)."""

    def __init__(self):
        self.reset()

    def reset(self, overrides=None):
        self.overrides = copy.deepcopy(overrides or {})
        self.counter = 0
        self.datasources = []
        self.folders = []
        self.dashboards = 0
        self.deleted = []

    def state(self):
        return {"datasources": self.datasources, "folders": self.folders, "dashboards": self.dashboards, "deleted": self.deleted}

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix("/grafanaapi")
        reply = _override(self.overrides, method, path)
        if reply:
            return reply
        j = "application/json"
        if method == "POST" and re.fullmatch(r"/user/using/[^/]+", path):
            return 200, j, _json({"message": "Active organization changed"})
        if method == "POST" and path == "/dashboards/db":
            self.counter += 1
            self.dashboards += 1
            title = json.loads(body).get("dashboard", {}).get("title", "x")
            slug = re.sub(r"[^a-z0-9]+", "-", str(title).lower()).strip("-")
            return (
                200,
                j,
                _json(
                    {
                        "id": 500 + self.counter,
                        "slug": slug,
                        "status": "success",
                        "uid": f"uid{self.counter}",
                        "url": f"/d/uid{self.counter}/{slug}",
                        "version": 1,
                        "folderUid": "fold",
                    },
                ),
            )
        if method == "POST" and path == "/folders":
            data = json.loads(body)
            self.counter += 1
            fid = 70 + self.counter
            self.folders.append({"id": fid, "title": data.get("title")})
            return (
                200,
                j,
                _json(
                    {
                        "id": fid,
                        "uid": f"fold-{fid}",
                        "orgId": 7,
                        "title": data.get("title"),
                        "url": f"/dashboards/f/fold-{fid}/",
                        "hasAcl": False,
                        "canSave": True,
                        "canEdit": True,
                        "canAdmin": True,
                        "canDelete": True,
                        "createdBy": "admin",
                        "created": "2026-10-16T00:00:00Z",
                        "updatedBy": "admin",
                        "updated": "2026-10-16T00:00:00Z",
                        "version": 1,
                    },
                ),
            )
        if method == "POST" and path == "/datasources":
            data = json.loads(body)
            self.counter += 1
            uid = f"ds-uid-{self.counter}"
            self.datasources.append({"uid": uid, "name": data.get("name"), "database": data.get("database")})
            ds = {
                "id": 9,
                "uid": uid,
                "orgId": 7,
                "name": data.get("name"),
                "type": data.get("type"),
                "typeLogoUrl": "public/plugins/grafana-opensearch-datasource/img/logo.svg",
                "access": data.get("access"),
                "url": data.get("url"),
                "user": "",
                "database": data.get("database"),
                "basicAuth": data.get("basicAuth"),
                "basicAuthUser": data.get("basicAuthUser"),
                "withCredentials": False,
                "isDefault": data.get("isDefault"),
                "jsonData": data.get("jsonData"),
                "secureJsonFields": {"basicAuthPassword": True},
                "version": 1,
                "readOnly": data.get("readOnly"),
            }
            return 200, j, _json({"datasource": ds, "id": 9, "message": "Datasource added", "name": data.get("name")})
        if method == "DELETE" and path.startswith("/datasources/uid/"):
            self.deleted.append(("datasource", path.rsplit("/", 1)[1]))
            return 200, j, _json({"message": "Data source deleted", "id": 9})
        if method == "DELETE" and path.startswith("/folders/"):
            self.deleted.append(("folder", path.rsplit("/", 1)[1]))
            return 200, j, _json({"message": "Folder deleted", "id": 71})
        return 404, j, _json({"message": "Not found"})


HEALTH = {
    "cluster_name": "wazuh-cluster",
    "status": "green",
    "timed_out": False,
    "number_of_nodes": 3,
    "number_of_data_nodes": 3,
    "discovered_master": True,
    "discovered_cluster_manager": True,
    "active_primary_shards": 10,
    "active_shards": 20,
    "relocating_shards": 0,
    "initializing_shards": 0,
    "unassigned_shards": 0,
    "delayed_unassigned_shards": 0,
    "number_of_pending_tasks": 0,
    "number_of_in_flight_fetch": 0,
    "task_max_waiting_in_queue_millis": 0,
    "active_shards_percent_as_number": 100.0,
}


class Indexer:
    """The Wazuh indexer: cluster health (the shard count) and the nodes' versions."""

    def __init__(self):
        self.reset()

    def reset(self, overrides=None):
        self.overrides = copy.deepcopy(overrides or {})

    def answer(self, method, target, body):
        path = urlsplit(target).path
        reply = _override(self.overrides, method, path)
        if reply:
            return reply
        j = "application/json"
        if method == "GET" and path == "/_cluster/health":
            return 200, j, _json(HEALTH)
        if method == "GET" and path == "/_nodes/_local":
            return 200, j, _json({"nodes": {"n-1": {"version": "2.19.1"}, "n-2": {"version": "2.19.0"}}})
        return 404, j, _json({"error": "no such index", "status": 404})


class Recorder:
    """Every request a stand-in was sent: (method, target, every header sorted, body)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, method, target, headers, body):
        with self.lock:
            self.requests.append((method, target, headers, body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


MANAGER = Manager()
GRAYLOG = Graylog("/graylog")
GRAFANA = Grafana()
INDEXER = Indexer()
RECORDER = Recorder()


class ByPrefix:
    def __init__(self, routes):
        self.routes = routes

    def answer(self, method, target, body):
        for prefix, tool in self.routes:
            if target.startswith(prefix):
                return tool.answer(method, target, body)
        return 404, "application/json", _json({"message": "no such stand-in route"})


TOOLS = ByPrefix((("/grafanaapi", GRAFANA), ("/graylog", GRAYLOG), ("/wazuh", MANAGER)))


def start_stub(port, tool):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            # Every header the client sent, Content-Length included.
            headers = sorted((k.lower(), v) for k, v in self.headers.items())
            RECORDER.add(self.command, self.path, headers, body)
            status, ctype, payload = tool.answer(self.command, self.path, body)
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

    server = Server(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- Seed --------------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, username="parity-user", password="pässword"):
    """Point connector `name` at `url`, keeping its id when it exists."""
    found = rows("SELECT id FROM connectors WHERE connector_name = :n ORDER BY id LIMIT 1", n=name)
    if found:
        sql(
            "UPDATE connectors SET connector_url = :u, connector_username = :user, connector_password = :pw WHERE id = :i",
            u=url,
            user=username,
            pw=password,
            i=found[0]["id"],
        )
        return
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (:n, '3', :u, "
        "UTC_TIMESTAMP(), :user, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
    )


def save_connectors():
    SAVED_CONNECTORS.extend(rows("SELECT * FROM connectors WHERE connector_name IN :n OR id = 1", n=list(OUR_CONNECTORS)))


def restore_connectors():
    sql("DELETE FROM connectors WHERE connector_name IN :n OR id = 1", n=list(OUR_CONNECTORS))
    for row in SAVED_CONNECTORS:
        sql(f"INSERT INTO connectors ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)


def point_tools():
    """The manager, Graylog, Grafana, the indexer and connector id 1 at the stand-ins."""
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{STUB_PORT}/wazuh", username="wazuh-wui", password="wazuh-pässword")
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog")
    set_connector("Grafana", GRAFANA_URL)
    if rows("SELECT id FROM connectors WHERE id = 1"):
        sql(
            "UPDATE connectors SET connector_url = :u, connector_username = 'idx-user', connector_password = 'idx-pässword' WHERE id = 1",
            u=INDEXER_URL,
        )
    else:
        sql(
            "INSERT INTO connectors (id, connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
            "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
            "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
            "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (1, "
            "'Wazuh-Indexer', '3', :u, UTC_TIMESTAMP(), 'idx-user', 'idx-pässword', NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, "
            "0, NULL, 1)",
            u=INDEXER_URL,
        )
    set_connector("Wazuh-Indexer", INDEXER_URL, username="idx-user", password="idx-pässword")


# The integrations: (id, customer, service, instance, keys); subscriptions take id + 100, keys ids
# from 7860700.
INT_SERVICES = {"Office365": 7_860_001}
O365_KEYS_A = [("TENANT_ID", TENANT_A), ("CLIENT_ID", "c-a"), ("CLIENT_SECRET", "s<a>&"), ("API_TYPE", "commercial")]
O365_KEYS_A2 = [("TENANT_ID", TENANT_A2), ("CLIENT_ID", "c-a2"), ("CLIENT_SECRET", "s-a2"), ("API_TYPE", "gcc-high")]
INT_ROWS = [
    (7_860_011, CUST_A, "Office365", None, O365_KEYS_A),
    (7_860_013, CUST_B, "Office365", None, [("TENANT_ID", TENANT_B), ("CLIENT_ID", "c-b"), ("API_TYPE", "gcc")]),
    (7_860_014, CUST_D, "Office365", None, [("TENANT_ID", TENANT_D), ("CLIENT_ID", "c-d"), ("CLIENT_SECRET", "s"), ("API_TYPE", "x")]),
]
#: The second tenant of customer A, seeded by the checks that need it.
SECOND_TENANT = (7_860_012, CUST_A, "Office365", "sub.example", O365_KEYS_A2)
INT_IDS = [r[0] for r in INT_ROWS] + [SECOND_TENANT[0]]


def insert_integration(cid, code, service, instance, keys):
    sql(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, integration_service_id, integration_service_name, "
        "instance_name, deployed) VALUES (:i, :c, :n, :s, :sn, :inst, 0)",
        i=cid,
        c=code,
        n=f"{code} name",
        s=INT_SERVICES[service],
        sn=service,
        inst=instance,
    )
    sql(
        "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES (:i, :c, :s)",
        i=cid + 100,
        c=cid,
        s=INT_SERVICES[service],
    )
    for n, (k, v) in enumerate(keys):
        sql(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, :s, :k, :v)",
            i=7_860_700 + (cid - 7_860_000) * 10 + n,
            s=cid + 100,
            k=k,
            v=v,
        )


def delete_integration(cid):
    sql("DELETE FROM integration_auth_keys WHERE subscription_id = :s", s=cid + 100)
    sql("DELETE FROM integration_subscriptions WHERE id = :s", s=cid + 100)
    sql("DELETE FROM customer_integrations WHERE id = :i", i=cid)


def seed():
    cleanup()
    save_connectors()
    point_tools()
    for code, name in ((CUST_A, NAME_A), (CUST_B, NAME_B), (CUST_C, NAME_C)):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (ANALYST_B, 2), (UNASSIGNED, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name, code in ((ANALYST, CUST_A), (ANALYST_B, CUST_B)):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=code,
            n=name,
        )
    for name, sid in INT_SERVICES.items():
        sql("INSERT INTO integration_services (id, service_name, auth_type) VALUES (:i, :n, 'OAuth')", i=sid, n=name)
    for row in INT_ROWS:
        insert_integration(*row)
    for code, name, org in ((CUST_A, NAME_A, "7"), (CUST_B, NAME_B, "8")):
        sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group) VALUES (:c, :n, 'i', 's', :o, 'g')",
            c=code,
            n=name,
            o=org,
        )


def remove_python_copies():
    """The copies of `ossec.conf` Python keeps next to its Office 365 modules."""
    for path in (
        os.path.join(BACKEND, "app", "integrations", "office365", "services", "wazuh_config.xml"),
        os.path.join(BACKEND, "app", "integrations", "office365", "wazuh_decommission_config.xml"),
    ):
        if os.path.exists(path):
            os.remove(path)


def cleanup():
    sql("DELETE FROM integration_auth_keys WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM integration_subscriptions WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM customer_integrations WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM integration_services WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    codes = list(CUSTOMERS) + [CUST_D]
    sql("DELETE FROM customer_integrations_meta WHERE customer_code IN :c", c=codes)
    sql("DELETE FROM customersmeta WHERE customer_code IN :c", c=codes)
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for code in CUSTOMERS:
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)
    remove_python_copies()


# --- The backends ------------------------------------------------------------------------------------


def build_python_app():
    """The real routers, served by uvicorn in a thread: the Python side of every check and the Rust
    instances' legacy backend."""
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import office365

    api = APIRouter(prefix="/api")
    for module in (office365,):
        api.include_router(module.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_python(port):
    server = uvicorn.Server(uvicorn.Config(build_python_app(), host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(300):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError("uvicorn did not start")


def start_rust(port):
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
        "COPILOT_PORT": str(port),
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}",
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


ADDRESS = re.compile(rb"object at 0x[0-9a-f]+")
CREATION_DATE = re.compile(rb'"creation_date": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z"')
#: elasticsearch-py's `User-Agent` names the interpreter's patch version.
ES_AGENT = re.compile(r"\(Python 3\.11(?:\.\d+)?\)")


def norm_body(raw):
    return ADDRESS.sub(b"object at 0x...", raw)


def out_norm(requests):
    """The outbound requests compared: the Graylog version probe left out (both backends cache the
    version; Python's is pinned), the manager's token fetch left out (each process caches its own),
    the index set's `utcnow()` masked, the interpreter's patch version in elasticsearch-py's
    `User-Agent` dropped."""
    out = []
    for method, target, headers, body in requests:
        if method == "GET" and target == "/graylog/api/system":
            continue
        if target.startswith("/wazuh/security/user/authenticate"):
            continue
        body = CREATION_DATE.sub(b'"creation_date": "<utcnow>"', body)
        headers = [(k, ES_AGENT.sub("(Python 3.11)", v) if k == "user-agent" else v) for k, v in headers]
        out.append((method, target, headers, body))
    return out


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(base_url=f"http://127.0.0.1:{PY_PORT}", timeout=120)
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)
        self.rs7 = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS7_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        RECORDER.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, RECORDER.take()

    async def same(self, name, method, path, tok=None, before=None, state=None, expect=None, rust=None, **kw):
        """Python, then Rust, each after `before()`; `state()` returns what the request left.
        `expect=(python, rust)`: the statuses of a deliberate difference (bodies not compared)."""
        sides = []
        for client in (self.py, rust or self.rs):
            if before:
                before()
            r, out = await self.call(client, method, path, tok, **kw)
            out = out_norm(out)
            st = json.dumps(state(), default=str) if state else None
            sides.append((r, out, st))
        (r1, o1, s1), (r2, o2, s2) = sides
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2
        b1, b2 = norm_body(r1.content), norm_body(r2.content)
        ok = r1.status_code == r2.status_code and b1 == b2
        at = next((i for i, (x, y) in enumerate(zip(b1, b2)) if x != y), min(len(b1), len(b2)))
        start = max(0, at - 300)
        detail = (
            f"bodies differ at byte {at}\n        python {r1.status_code} {b1[start : at + 600]!r}\n"
            f"        rust   {r2.status_code} {b2[start : at + 600]!r}"
        )
        if o1 != o2:
            ok = False
            for i, (x, y) in enumerate(zip(o1, o2)):
                if x != y:
                    detail += f"\n        outbound #{i} python {x[:3]} {x[3][:600]!r}\n        outbound #{i} rust   {y[:3]} {y[3][:600]!r}"
                    break
            else:
                detail += f"\n        outbound python {[o[:2] for o in o1]}\n        outbound rust   {[o[:2] for o in o2]}"
        if s1 != s2:
            ok = False
            at = next((i for i, (x, y) in enumerate(zip(s1, s2)) if x != y), min(len(s1), len(s2)))
            detail += f"\n        state python {s1[max(0, at - 200) : at + 400]}\n        state rust   {s2[max(0, at - 200) : at + 400]}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {[(m, p, b[:200]) for m, p, h, b in o1]}")
        return r1, r2

    async def python_hangs_up(self, name, method, path, tok=None, before=None, state=None, **kw):
        """A request Python leaves without an answer (uvicorn closes the connection) and Rust
        answers: Rust's status and body are reported, the outbound requests and the state still
        compared (RUST_MIGRATION.md §4, "Python fails, Rust works")."""
        sides = []
        for client in (self.py, self.rs):
            if before:
                before()
            try:
                r, out = await self.call(client, method, path, tok, **kw)
            except httpx.RemoteProtocolError:
                r, out = None, RECORDER.take()
            sides.append((r, out_norm(out), json.dumps(state(), default=str) if state else None))
        (r1, o1, s1), (r2, o2, s2) = sides
        ok = r1 is None and r2 is not None and r2.status_code == 500 and o1 == o2 and s1 == s2
        check(
            f"{name} [Python: no answer; Rust: {r2.status_code if r2 is not None else None}]",
            ok,
            f"python {r1 and (r1.status_code, r1.content[:300])}\n        rust {r2 and (r2.status_code, r2.content[:400])}"
            f"\n        outbound same: {o1 == o2}, state same: {s1 == s2}",
        )
        return r2

    async def close(self):
        for c in (self.py, self.rs, self.rs7):
            await c.aclose()


def pin_graylog_version(connector, version):
    """Python's cached Graylog major version, as the Rust instance in use has it (both probe
    `GET /api/system` once per 5 minutes; the probes are left out of the comparison)."""
    from app.connectors.graylog.utils import universal

    universal._GRAYLOG_VERSION_CACHE[connector] = (version, time.monotonic())


# --- Office 365 ------------------------------------------------------------------------------------------

O365 = "/api/office365/provision"


def o365(version=6, config=OSSEC, refuse=0, manager=None, graylog=None, grafana=None, indexer=None, setup=None):
    """A fresh world: no meta rows, nothing deployed, the second tenant absent, the stand-ins
    reset."""

    def before():
        point_tools()
        codes = list(CUSTOMERS) + [CUST_D]
        sql("DELETE FROM customer_integrations_meta WHERE customer_code IN :c", c=codes)
        delete_integration(SECOND_TENANT[0])
        sql("UPDATE customer_integrations SET deployed = 0 WHERE id IN :i", i=INT_IDS)
        sql("UPDATE customersmeta SET customer_meta_office365_organization_id = NULL WHERE customer_code IN :c", c=codes)
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = '7' WHERE customer_code = :c", c=CUST_A)
        MANAGER.reset(config, refuse, manager)
        GRAYLOG.reset(version, **(graylog or {}))
        GRAFANA.reset(grafana)
        INDEXER.reset(indexer)
        pin_graylog_version("Graylog", version)
        remove_python_copies()
        if setup:
            setup()

    return before


def o365_state():
    codes = list(CUSTOMERS) + [CUST_D]
    meta = rows(
        "SELECT customer_code, integration_name, instance_name, graylog_input_id, graylog_index_id, graylog_stream_id, "
        "grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid FROM customer_integrations_meta "
        "WHERE customer_code IN :c ORDER BY id",
        c=codes,
    )
    flags = rows("SELECT id, deployed FROM customer_integrations WHERE id IN :i ORDER BY id", i=INT_IDS)
    legacy = rows(
        "SELECT customer_code, customer_meta_office365_organization_id FROM customersmeta WHERE customer_code IN :c ORDER BY customer_code",
        c=codes,
    )
    return {
        "meta": meta,
        "deployed": flags,
        "legacy": legacy,
        "ossec": MANAGER.config,
        "graylog": GRAYLOG.state(),
        "grafana": GRAFANA.state(),
    }


async def office365_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    st = o365_state
    body = {"customer_code": CUST_A}
    await p.same("o365: no token", "POST", O365, json=body)
    await p.same("o365: malformed JSON, no token", "POST", O365, content=b"{", headers={"Content-Type": "application/json"})
    await p.same("o365: a customer_user token", "POST", O365, token(ANALYST, ["customer_user"]), json=body)
    await p.same("o365: no body", "POST", O365, t_admin)
    await p.same("o365: not JSON", "POST", O365, t_admin, content=b"x", headers={"Content-Type": "text/plain"})
    await p.same("o365: a list body (the before-validator's TypeError)", "POST", O365, t_admin, json=[body])
    await p.same("o365: no customer_code", "POST", O365, t_admin, json={"instance_name": "x"})
    await p.same("o365: customer_code not a string", "POST", O365, t_admin, json={"customer_code": 7})
    await p.same("o365: instance_name not a string", "POST", O365, t_admin, before=o365(), json={**body, "instance_name": 3})
    await p.same("o365: provisioned on Graylog 6", "POST", O365, t_admin, before=o365(), state=st, json=body)
    await p.same(
        "o365: provisioned on Graylog 7, as the customer's analyst, integration_name forced",
        "POST",
        O365,
        t_analyst,
        before=o365(7),
        state=st,
        rust=p.rs7,
        json={**body, "integration_name": "ignored", "instance_name": "   "},
    )
    await p.same(
        "o365: an existing <office365> block (api_auth appended)",
        "POST",
        O365,
        t_admin,
        before=o365(config=ossec_with_office365("ten-other")),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the tenant is already on the manager",
        "POST",
        O365,
        t_admin,
        before=o365(config=ossec_with_office365(TENANT_A)),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the manager refuses the api_type (pushed again without it)",
        "POST",
        O365,
        t_admin,
        before=o365(refuse=1),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the manager refuses both pushes",
        "POST",
        O365,
        t_admin,
        before=o365(refuse=2),
        state=st,
        json=body,
    )
    two = OSSEC + "<ossec_config>\n  <localfile/>\n</ossec_config>\n"
    await p.same("o365: two ossec_config blocks, no office365 yet", "POST", O365, t_admin, before=o365(config=two), state=st, json=body)
    await p.same(
        "o365: two ossec_config blocks with an office365 block",
        "POST",
        O365,
        t_admin,
        before=o365(config=ossec_with_office365("ten-other") + "<ossec_config>\n  <localfile/>\n</ossec_config>\n"),
        state=st,
        json=body,
    )
    await p.same(
        "o365: an <office365> block without subscriptions",
        "POST",
        O365,
        t_admin,
        before=o365(config=OSSEC.replace("  <!-- Policy monitoring -->", "  <office365><enabled>yes</enabled></office365>\n")),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the manager's configuration unreadable",
        "POST",
        O365,
        t_admin,
        before=o365(manager={("GET", "/manager/configuration"): (500, "application/json", _json({"title": "boom"}))}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the restart fails (the api_auth block rolled back)",
        "POST",
        O365,
        t_admin,
        before=o365(manager={("PUT", "/manager/restart"): (500, "application/json", _json({"title": "Internal", "detail": "x"}))}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: rules and pipeline already there, the UTC rule repaired",
        "POST",
        O365,
        t_admin,
        before=o365(graylog={"rules": o365_existing_rules(broken_utc=True), "pipelines": o365_existing_pipelines()}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: a pipeline without a description (get_pipeline_id's AttributeError, rolled back)",
        "POST",
        O365,
        t_admin,
        before=o365(graylog={"pipelines": [pipeline("pl-none", "NONE", None)]}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: no pipeline names OFFICE365 (rolled back)",
        "POST",
        O365,
        t_admin,
        before=o365(graylog={"overrides": {("POST", "/api/system/pipelines/pipeline"): (200, "application/json", _json({}))}}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the index set refused",
        "POST",
        O365,
        t_admin,
        before=o365(
            graylog={"overrides": {("POST", "/api/system/indices/index_sets"): (400, "application/json", _json({"message": "prefix"}))}},
        ),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the stream refused (index set rolled back)",
        "POST",
        O365,
        t_admin,
        before=o365(graylog={"overrides": {("POST", "/api/streams"): (500, "application/json", _json({"message": "no"}))}}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the Grafana folder refused (datasource, stream, index set and api_auth rolled back)",
        "POST",
        O365,
        t_admin,
        before=o365(grafana={("POST", "/folders"): (409, "application/json", _json({"message": "a folder with the same name"}))}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: a dashboard refused, and an undo fails too",
        "POST",
        O365,
        t_admin,
        before=o365(
            grafana={
                ("POST", "/dashboards/db"): (412, "application/json", _json({"message": "version-mismatch", "status": "version-mismatch"})),
                ("DELETE", "/datasources/uid/*"): (500, "application/json", _json({"message": "cannot delete"})),
            },
            graylog={"overrides": {("DELETE", "/api/streams/*"): (500, "application/json", _json({"message": "stream busy"}))}},
        ),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the indexer unreachable for the shard count",
        "POST",
        O365,
        t_admin,
        before=o365(indexer={("GET", "/_cluster/health"): (503, "application/json", _json({"error": "down"}))}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: missing auth keys (the ValidationError)",
        "POST",
        O365,
        t_admin,
        before=o365(),
        state=st,
        json={"customer_code": CUST_B},
    )
    await p.same("o365: no integration", "POST", O365, t_admin, before=o365(), state=st, json={"customer_code": CUST_C})
    await p.same(
        "o365: integrations but no customers row",
        "POST",
        O365,
        t_admin,
        before=o365(),
        state=st,
        json={"customer_code": CUST_D},
    )

    def second():
        insert_integration(*SECOND_TENANT)

    def second_after_first():
        second()
        sql(
            "INSERT INTO customer_integrations_meta (customer_code, integration_name, instance_name, graylog_input_id, graylog_index_id, "
            "graylog_stream_id, grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid) VALUES (:c, 'Office365', NULL, "
            "NULL, 'is-first', 'st-first', '7', '71', 'ds-first')",
            c=CUST_A,
        )
        sql("UPDATE customer_integrations SET deployed = 1 WHERE id = 7860011")
        sql("UPDATE customersmeta SET customer_meta_office365_organization_id = :t WHERE customer_code = :c", t=TENANT_A, c=CUST_A)

    await p.same("o365: two instances, none named", "POST", O365, t_admin, before=o365(setup=second), state=st, json=body)
    await p.same(
        "o365: an unknown instance",
        "POST",
        O365,
        t_admin,
        before=o365(setup=second),
        state=st,
        json={**body, "instance_name": "other.example"},
    )
    await p.same(
        "o365: the second tenant, its index set and Grafana reused",
        "POST",
        O365,
        t_admin,
        before=o365(config=ossec_with_office365(TENANT_A), setup=second_after_first),
        state=st,
        json={**body, "instance_name": " sub.example "},
    )
    await p.same(
        "o365: the second tenant on Graylog 7, the folder missing from the meta (created)",
        "POST",
        O365,
        t_admin,
        before=o365(
            7,
            config=ossec_with_office365(TENANT_A),
            setup=lambda: (
                second_after_first(),
                sql("UPDATE customer_integrations_meta SET grafana_dashboard_folder_id = '' WHERE customer_code = :c", c=CUST_A),
            ),
        ),
        state=st,
        rust=p.rs7,
        json={**body, "instance_name": "sub.example"},
    )

    def reused_index_only():
        second_after_first()
        sql(
            "UPDATE customer_integrations_meta SET grafana_datasource_uid = NULL, grafana_dashboard_folder_id = '' WHERE customer_code = :c",
            c=CUST_A,
        )

    await p.same(
        "o365: the index set reused, the indexer's version a 404 (its status kept)",
        "POST",
        O365,
        t_admin,
        before=o365(
            config=ossec_with_office365(TENANT_A),
            setup=reused_index_only,
            indexer={("GET", "/_nodes/_local"): (404, "application/json", _json({"error": "no such node", "status": 404}))},
        ),
        state=st,
        json={**body, "instance_name": "sub.example"},
    )

    def indexer_closed():
        reused_index_only()
        sql("UPDATE connectors SET connector_url = :u WHERE connector_name = 'Wazuh-Indexer'", u=f"http://127.0.0.1:{CLOSED_PORT}")

    await p.same(
        "o365: the index set reused, the indexer unreachable for its version (status_code 'N/A': the bare 500)",
        "POST",
        O365,
        t_admin,
        before=o365(config=ossec_with_office365(TENANT_A), setup=indexer_closed),
        state=st,
        json={**body, "instance_name": "sub.example"},
    )
    await p.python_hangs_up(
        "o365: Grafana times out creating the folder (GrafanaTimeoutError's status_code 0)",
        "POST",
        O365,
        t_admin,
        before=o365(grafana={("POST", "/folders"): (200, "application/json", _json({"id": 1}), 6)}),
        state=st,
        json=body,
    )
    await p.same(
        "o365: the unnamed instance named by an empty string",
        "POST",
        O365,
        t_admin,
        before=o365(setup=second),
        state=st,
        json={**body, "instance_name": ""},
    )
    await p.same(
        "o365: no customersmeta row (the folder's organization)",
        "POST",
        O365,
        t_admin,
        before=o365(setup=lambda: sql("DELETE FROM customersmeta WHERE customer_code = :c", c=CUST_A)),
        state=st,
        json=body,
    )
    seed_meta_a = (
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
        "customer_meta_grafana_org_id, customer_meta_wazuh_group) VALUES (:c, :n, 'i', 's', '7', 'g')"
    )
    sql(seed_meta_a, c=CUST_A, n=NAME_A)
    # Tenancy (§4): Python provisions another tenant's integration for any analyst.
    await p.same(
        "o365: another customer's analyst",
        "POST",
        O365,
        t_analyst_b,
        before=o365(),
        expect=(200, 403),
        json=body,
    )
    await p.same("o365: an unassigned analyst", "POST", O365, t_unassigned, before=o365(), expect=(200, 403), json=body)
    await p.same(
        "o365: another customer's analyst, no integration there",
        "POST",
        O365,
        t_analyst_b,
        before=o365(),
        expect=(404, 403),
        json={"customer_code": CUST_C},
    )


def o365_existing_rules(broken_utc=False):
    out = [pipeline_rule("r-other", "Other rule", 'rule "Other rule"\nend')]
    titles = [
        "WAZUH CREATE FIELD SYSLOG LEVEL - ALERT",
        "WAZUH CREATE FIELD SYSLOG LEVEL - INFO",
        "WAZUH CREATE FIELD SYSLOG LEVEL - NOTICE",
        "WAZUH CREATE FIELD SYSLOG LEVEL - WARNING",
        "Office365 Timestamp - UTC",
        "SYSLOG TYPE OFFICE365",
    ]
    for n, title in enumerate(titles):
        source = f'rule "{title}"\nwhen\n  true\nthen\nend'
        if title == "Office365 Timestamp - UTC" and broken_utc:
            source = f'rule "{title}"\nwhen\n  has_field("data_office_365_CreationTime")\nthen\nend'
        out.append(pipeline_rule(f"r-pre{n}", title, source))
    return out


def o365_existing_pipelines():
    return [pipeline("pl-wazuh", "WAZUH", "Wazuh processing"), pipeline("pl-o365", "OFFICE365 PROCESSING PIPELINE", "office365 pipeline")]


# --- Main ------------------------------------------------------------------------------------------------


async def main():
    servers = [start_stub(STUB_PORT, TOOLS), start_stub(INDEXER_PORT, INDEXER)]
    procs = []
    python = None
    try:
        seed()
        python = start_python(PY_PORT)
        procs.append(start_rust(RS_PORT))
        procs.append(start_rust(RS7_PORT))
        p = Pair()
        t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
        t_analyst_b, t_unassigned = token(ANALYST_B, ["analyst"]), token(UNASSIGNED, ["analyst"])
        try:
            sections = os.environ.get("REMAINING_PROV_PARITY_SECTIONS", "office365").split(",")
            if "office365" in sections:
                await office365_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned)
        finally:
            await p.close()
    finally:
        if python is not None:
            python.should_exit = True
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            cleanup()
        finally:
            restore_connectors()
            for server in servers:
                server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
