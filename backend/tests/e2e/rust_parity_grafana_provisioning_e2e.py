"""Parity of the Rust Grafana dashboard, network-connector and integration provisioning
(`copilot-grafana-dashboards`, `copilot-integration-provisioning`) with this backend — NOT collected
by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers and the Rust instances this suite starts answer the same requests on one
database: `POST /api/grafana/dashboards`, `POST /api/customer_provisioning/provision/dashboards`, the
Fortinet / SonicWall / SentinelOne stack provisioning and the integrations' `/provision` routes. One
Rust instance meets Graylog 6, a second Graylog 7 (both backends cache the version, Python's is
pinned to the instance in use). The routers are served by uvicorn in a thread, over the real
APScheduler on `apscheduler_jobs` started paused: that app is the Python side of every check and
the Rust instances' legacy backend, which registers the jobs the integration routes add (Rust hands
that step to Python). The tools are local stand-ins recording every request — method, target, every
header the client sent and the body bytes (a dashboard is compared as it was sent, never
re-serialised): Graylog and Graylog-Network (`/graylog`, `/graylog-net`), Grafana (`/grafanaapi`,
the root `grafana_client` builds from a connector URL ending in `/grafana`) on one port, the Wazuh
indexer on another. For each request the suite compares the status, the body, every outbound request
and the rows the request left. Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_grafana_provisioning_e2e.py scripts/rust-parity.sh

Ports (all overridable): GRAFANA_PROV_PARITY_RUST_PORT (6420), GRAFANA_PROV_PARITY_RUST7_PORT (6421),
GRAFANA_PROV_PARITY_PY_PORT (6422, the uvicorn legacy backend), GRAFANA_PROV_STUB_PORT (6423, Graylog
and Grafana), GRAFANA_PROV_INDEXER_STUB_PORT (6424), GRAFANA_PROV_CLOSED_PORT (6425, nothing listens).
Seeded ids are seven digits in 7650000-7659999. `GRAFANA_PROV_PARITY_SECTIONS=dashboards,network,
integrations` picks the sections.
"""

import asyncio
import contextlib
import copy
import datetime
import fnmatch
import json
import os
import re
import socket
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

SFX = os.environ.get("GRAFANA_PROV_PARITY_SFX") or uuid.uuid4().hex[:6]
RS_PORT = int(os.environ.get("GRAFANA_PROV_PARITY_RUST_PORT", "6420"))
RS7_PORT = int(os.environ.get("GRAFANA_PROV_PARITY_RUST7_PORT", "6421"))
PY_PORT = int(os.environ.get("GRAFANA_PROV_PARITY_PY_PORT", "6422"))
STUB_PORT = int(os.environ.get("GRAFANA_PROV_STUB_PORT", "6423"))
INDEXER_PORT = int(os.environ.get("GRAFANA_PROV_INDEXER_STUB_PORT", "6424"))
CLOSED_PORT = int(os.environ.get("GRAFANA_PROV_CLOSED_PORT", "6425"))
SEED_LO, SEED_HI = 7_650_000, 7_659_999

CUST_A, CUST_B, CUST_C = f"GPA{SFX}", f"GPB{SFX}", f"GPC{SFX}"
CUSTOMERS = (CUST_A, CUST_B, CUST_C)
NAME_A, NAME_B, NAME_C = f"Alpha {SFX}", f"Beta {SFX}", f"Gamma {SFX}"
ADMIN, ANALYST, ANALYST_B, UNASSIGNED = (f"gp_admin{SFX}", f"gp_analyst{SFX}", f"gp_analyst_b{SFX}", f"gp_unassigned{SFX}")
USERS = (ADMIN, ANALYST, ANALYST_B, UNASSIGNED)
OUR_CONNECTORS = ("Graylog", "Graylog-Network", "Grafana", "Wazuh-Indexer")
GRAFANA_URL = f"http://127.0.0.1:{STUB_PORT}/grafana"
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


# --- The stand-ins ------------------------------------------------------------------------------------


class Grafana:
    """Grafana 11 for provisioning: the org switch, datasources, folders, dashboards. Per-test
    overrides by (method, path glob): one answer, or a list answered in turn (the last repeated)."""

    def __init__(self):
        self.reset()

    def reset(self, overrides=None):
        self.overrides = copy.deepcopy(overrides or {})
        self.counter = 0
        self.datasources = []
        self.folders = []

    def state(self):
        return {"datasources": list(self.datasources), "folders": list(self.folders)}

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix("/grafanaapi")
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(path, pattern):
                if isinstance(reply, list):
                    return reply.pop(0) if len(reply) > 1 else reply[0]
                return reply
        j = "application/json"
        m = re.fullmatch(r"/datasources/uid/([^/]+)", path)
        if method == "DELETE" and m:
            if m.group(1) not in self.datasources:
                return 404, j, _json({"message": "Data source not found"})
            self.datasources.remove(m.group(1))
            return 200, j, _json({"message": "Data source deleted", "id": 9})
        m = re.fullmatch(r"/folders/([^/]+)", path)
        if method == "DELETE" and m:
            if m.group(1) not in self.folders:
                return 404, j, _json({"message": "Folder not found", "status": "not-found"})
            self.folders.remove(m.group(1))
            return 200, j, _json({"message": "Folder deleted", "id": 77, "title": "x"})
        if method == "POST" and re.fullmatch(r"/user/using/[^/]+", path):
            return 200, j, _json({"message": "Active organization changed"})
        if method == "POST" and path == "/dashboards/db":
            self.counter += 1
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
            self.folders.append("fold-77")
            return (
                200,
                j,
                _json(
                    {
                        "id": 77,
                        "uid": "fold-77",
                        "orgId": 7,
                        "title": data.get("title"),
                        "url": "/dashboards/f/fold-77/",
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
            ds = {
                "id": 9,
                "uid": "ds-uid-9",
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
            self.datasources.append("ds-uid-9")
            return 200, j, _json({"datasource": ds, "id": 9, "message": "Datasource added", "name": data.get("name")})
        return 404, j, _json({"message": "Not found"})


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


def listed_pack(pack):
    """A content pack as `GET /api/system/content_packs` lists it (model versions as strings)."""
    listed = {**copy.deepcopy(pack), "created_at": "2026-10-01T00:00:00.000Z", "server_version": "6.1.4"}
    listed["v"] = str(listed.get("v"))
    for entity in listed.get("entities") or []:
        entity["v"] = str(entity.get("v"))
    return listed


def entity_title(entity, key="title"):
    value = (entity.get("data") or {}).get(key)
    return value.get("@value") if isinstance(value, dict) else value


class Graylog:
    """Graylog 6.1 / 7.0 for the provisioning flows: content packs (an install creates the pack's
    streams, inputs and pipelines), streams, inputs, index sets, pipelines and their connections.
    Per-test overrides by (method, path glob), as the Grafana stand-in's."""

    def __init__(self, prefix):
        self.prefix = prefix
        self.reset()

    def reset(self, version=6, content_packs=None, streams=None, inputs=None, pipelines=None, overrides=None):
        self.version = version
        self.content_packs = [listed_pack(p) for p in (content_packs or [])]
        self.streams = copy.deepcopy(streams or [{"id": "st-other", "title": "Other stream"}])
        self.inputs = copy.deepcopy(inputs or [{"id": "in-other", "title": "Other input"}])
        self.pipelines = copy.deepcopy(
            pipelines
            if pipelines is not None
            else [
                {
                    "id": "pl-wazuh",
                    "title": "WAZUH",
                    "description": "Wazuh processing",
                    "source": "pipeline",
                    "stages": [{"match": "EITHER", "rules": ["r"], "stage": 0}],
                    "created_at": "2026-10-01T00:00:00.000Z",
                    "modified_at": None,
                    "errors": None,
                },
            ],
        )
        self.index_sets = []
        self.connections = []
        self.installations = []
        self.overrides = copy.deepcopy(overrides or {})
        self.counter = 0

    def _id(self, prefix):
        self.counter += 1
        return f"{prefix}{self.counter:04d}"

    def state(self):
        return {
            "packs": [p["name"] for p in self.content_packs],
            "streams": self.streams,
            "inputs": self.inputs,
            "index_sets": self.index_sets,
            "connections": self.connections,
        }

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix(self.prefix)
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(path, pattern):
                if isinstance(reply, list):
                    return reply.pop(0) if len(reply) > 1 else reply[0]
                return reply
        j = "application/json"
        if method == "GET" and path == "/api/system":
            return 200, j, _json(samples.GRAYLOG_SYSTEM_7 if self.version == 7 else samples.GRAYLOG_SYSTEM_6)
        if method == "GET" and path == "/api/system/content_packs":
            return 200, j, _json({"total": len(self.content_packs), "content_packs": self.content_packs, "content_packs_metadata": {}})
        if method == "POST" and path == "/api/system/content_packs":
            pack = json.loads(body)
            for known in self.content_packs:
                if known["id"] == pack.get("id") and known["rev"] == pack.get("rev"):
                    message = f"Content pack {pack.get('id')} with this revision {pack.get('rev')} already found!"
                    return 400, j, _json({"type": "ApiError", "message": message})
            self.content_packs.append(listed_pack(pack))
            return 201, j, _json({"id": pack.get("id"), "rev": pack.get("rev")})
        m = re.fullmatch(r"/api/system/content_packs/([^/]+)/([^/]+)/installations", path)
        if method == "POST" and m:
            entity = json.loads(body)
            if self.version >= 7:
                if "entity" not in entity:
                    return 400, j, _json({"type": "ApiError", "message": "entity cannot be null"})
            elif "entity" in entity:
                return 400, j, _json({"type": "ApiError", "message": "Unable to map property entity"})
            pack = next((p for p in self.content_packs if p["id"] == m.group(1)), None)
            if pack is None:
                return 404, j, _json({"type": "ApiError", "message": f"Content pack {m.group(1)} not found"})
            created = []
            for e in pack.get("entities") or []:
                kind = e.get("type", {}).get("name")
                if kind == "stream":
                    self.streams.append({"id": self._id("st"), "title": entity_title(e)})
                    created.append(("streams", self.streams[-1]["id"]))
                elif kind == "input":
                    self.inputs.append({"id": self._id("in"), "title": entity_title(e)})
                    created.append(("inputs", self.inputs[-1]["id"]))
                elif kind == "pipeline":
                    self.pipelines.append(
                        {
                            "id": self._id("pl"),
                            "title": entity_title(e),
                            "description": entity_title(e, "description"),
                            "source": "pipeline",
                            "stages": [],
                            "created_at": "2026-10-16T00:00:00.000Z",
                        },
                    )
                    created.append(("pipelines", self.pipelines[-1]["id"]))
            installation = {"_id": self._id("inst"), "content_pack_id": m.group(1)}
            self.installations.append({**installation, "created": created})
            return 200, j, _json({"installation": installation, "entities_excluded": []})
        # The undo of a run (Rust's rollback; Python never deletes): an uninstall removes what
        # the installation created and is still there, a stream's deletion its connections.
        m = re.fullmatch(r"/api/system/content_packs/([^/]+)/installations", path)
        if method == "GET" and m:
            mine = [
                {"_id": i["_id"], "content_pack_id": i["content_pack_id"]} for i in self.installations if i["content_pack_id"] == m.group(1)
            ]
            return 200, j, _json({"installations": mine, "total": len(mine)})
        m = re.fullmatch(r"/api/system/content_packs/([^/]+)/installations/([^/]+)", path)
        if method == "DELETE" and m:
            found = next((i for i in self.installations if i["_id"] == m.group(2)), None)
            if found is None:
                return 404, j, _json({"type": "ApiError", "message": f"Installation {m.group(2)} not found"})
            self.installations.remove(found)
            for kind, oid in found["created"]:
                setattr(self, kind, [x for x in getattr(self, kind) if x["id"] != oid])
            return 200, j, _json({"entities": [], "failed_entities": []})
        m = re.fullmatch(r"/api/system/content_packs/([^/]+)", path)
        if method == "DELETE" and m:
            self.content_packs = [p for p in self.content_packs if p["id"] != m.group(1)]
            return 204, None, b""
        m = re.fullmatch(r"/api/streams/([^/]+)", path)
        if method == "DELETE" and m:
            if not any(st["id"] == m.group(1) for st in self.streams):
                return 404, j, _json({"type": "ApiError", "message": f"Stream <{m.group(1)}> not found!"})
            self.streams = [st for st in self.streams if st["id"] != m.group(1)]
            self.connections = [c for c in self.connections if c["stream_id"] != m.group(1)]
            return 204, None, b""
        m = re.fullmatch(r"/api/system/indices/index_sets/([^/]+)", path)
        if method == "DELETE" and m:
            if not any(i["id"] == m.group(1) for i in self.index_sets):
                return 404, j, _json({"type": "ApiError", "message": f"Index set <{m.group(1)}> not found"})
            self.index_sets = [i for i in self.index_sets if i["id"] != m.group(1)]
            return 204, None, b""
        if method == "GET" and path == "/api/streams":
            return 200, j, _json({"streams": self.streams, "total": len(self.streams)})
        if method == "POST" and path == "/api/streams":
            entity = json.loads(body)
            if self.version >= 7:
                if "entity" not in entity:
                    return 400, j, _json({"type": "ApiError", "message": "entity cannot be null"})
                entity = entity["entity"]
            new_id = self._id("st")
            self.streams.append({"id": new_id, "title": entity.get("title"), "index_set_id": entity.get("index_set_id")})
            return 201, j, _json({"stream_id": new_id})
        if method == "POST" and re.fullmatch(r"/api/streams/[^/]+/resume", path):
            return 204, None, b""
        m = re.fullmatch(r"/api/streams/([^/]+)", path)
        if method == "PUT" and m:
            stream = next((st for st in self.streams if st["id"] == m.group(1)), None)
            if stream is None:
                return 404, j, _json({"type": "ApiError", "message": f"Stream <{m.group(1)}> not found!"})
            stream.update(json.loads(body))
            return 200, j, _json(stream)
        if method == "GET" and path == "/api/system/inputs":
            return 200, j, _json({"inputs": self.inputs, "total": len(self.inputs)})
        if method == "POST" and path == "/api/system/indices/index_sets":
            data = json.loads(body)
            new = {"id": self._id("is"), **data, "can_be_default": True, "default": False}
            new["rotation_strategy"] = {**data.get("rotation_strategy", {}), "max_rotation_period": None, "rotate_empty_index_set": False}
            self.index_sets.append(new)
            return 200, j, _json(new)
        if method == "GET" and path == "/api/system/pipelines/pipeline":
            return 200, j, _json(self.pipelines)
        if method == "POST" and path == "/api/system/pipelines/connections/to_stream":
            data = json.loads(body)
            new = {"id": self._id("pc"), "stream_id": data.get("stream_id"), "pipeline_ids": data.get("pipeline_ids")}
            self.connections.append(new)
            return 200, j, _json(new)
        return 404, j, _json({"type": "ApiError", "message": "HTTP 404 Not Found"})


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
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(path, pattern):
                return reply
        j = "application/json"
        if method == "GET" and path == "/_cluster/health":
            return 200, j, _json(HEALTH)
        if method == "GET" and path == "/_nodes/_local":
            return 200, j, _json({"nodes": {"n-1": {"version": "2.19.1"}, "n-2": {"version": "2.19.0"}}})
        return 404, j, _json({"error": "no such index", "status": 404})


GRAFANA = Grafana()
GRAYLOG = Graylog("/graylog")
GRAYLOG_NET = Graylog("/graylog-net")
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


TOOLS = ByPrefix((("/grafanaapi", GRAFANA), ("/graylog-net", GRAYLOG_NET), ("/graylog", GRAYLOG)))


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
    ids = [r["id"] for r in SAVED_CONNECTORS]
    sql("DELETE FROM connectors WHERE connector_name IN :n OR id = 1", n=list(OUR_CONNECTORS))
    for row in SAVED_CONNECTORS:
        sql(f"INSERT INTO connectors ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    del ids


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
    seed_network()
    seed_integrations()


# The network connectors: (id, customer, name, service, keys); subscriptions take id + 100, keys
# ids from 7650300.
NET_SERVICES = {"Fortinet": 7_650_001, "Sonicwall": 7_650_002, "Sentinelone": 7_650_003}
NET_CONNECTORS = [
    (7_650_011, CUST_A, NAME_A, "Fortinet", [("SYSLOG_PORT", " 5_14")]),
    (
        7_650_012,
        CUST_A,
        NAME_A,
        "Sonicwall",
        [("SYSLOG_PORT", "6514"), ("TLS_CERT_FILE", "/etc/graylog/server/sw.pem"), ("TLS_KEY_FILE", "/etc/graylog/server/sw.key")],
    ),
    (
        7_650_013,
        CUST_A,
        NAME_A,
        "Sentinelone",
        [("TLS_KEY_FILE", "/k.key"), ("SYSLOG_PORT", "+6515"), ("TLS_CERT_FILE", "/c.pem"), ("SYSLOG_PORT", "6516")],
    ),
    (7_650_014, CUST_B, NAME_B, "Fortinet", [("SYSLOG_PORT", "abc")]),
    (7_650_015, CUST_B, NAME_B, "Sonicwall", [("SYSLOG_PORT", "1")]),
    (7_650_016, CUST_C, NAME_C, "Fortinet", []),
]
INDEXER_URL = f"http://127.0.0.1:{INDEXER_PORT}"
CUST_D = f"GPD{SFX}"  # integration rows, but no `customers` row (the string key is not an FK)
# The integrations: (id, customer, service, keys); subscriptions take id + 100, keys ids from
# 7650700.
INT_SERVICES = {
    name: 7_650_500 + i
    for i, name in enumerate(["Huntress", "Darktrace", "Duo", "CATO", "CarbonBlack", "Mimecast", "SAP SIEM", "SOCFortress MDR"])
}
INT_ROWS = [
    (7_650_511, CUST_A, "Huntress", [("API_KEY", "k")]),
    (7_650_512, CUST_A, "Darktrace", [("API_KEY", "k")]),
    (7_650_513, CUST_A, "Duo", []),
    (7_650_514, CUST_A, "CATO", [("API_KEY", "k")]),
    (7_650_515, CUST_A, "CarbonBlack", []),
    (7_650_516, CUST_A, "Mimecast", [("API_KEY", "k")]),
    (7_650_517, CUST_A, "SAP SIEM", [("API_KEY", "k")]),
    (7_650_518, CUST_A, "SOCFortress MDR", [("COLLECTOR_UUID", "c0ffee-collector")]),
    (7_650_519, CUST_B, "SOCFortress MDR", [("OTHER", "x"), ("COLLECTOR_UUID", " \t\x1f ")]),
    (7_650_520, CUST_B, "Huntress", []),
    (7_650_521, CUST_D, "Huntress", []),
]
INT_IDS = [r[0] for r in INT_ROWS]
JOB_IDS = [
    "invoke_huntress_integration_collect",
    "invoke_darktrace_integration_collect",
    "invoke_duo_integration_collect",
    "invoke_cato_integration_collect",
    "invoke_carbonblack_integration_collection",
    "invoke_mimecast_integration_ttp",
    "invoke_mimecast_integration",
    "invoke_sap_siem_integration_collection",
    "invoke_sap_siem_integration_suspicious_logins_analysis",
    "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
]
SAVED_JOBS = {}


def seed_integrations():
    for name, sid in INT_SERVICES.items():
        sql("INSERT INTO integration_services (id, service_name, auth_type) VALUES (:i, :n, 'API_KEY')", i=sid, n=name)
    key_id = 7_650_700
    for cid, code, service, keys in INT_ROWS:
        sql(
            "INSERT INTO customer_integrations (id, customer_code, customer_name, integration_service_id, integration_service_name, "
            "deployed) VALUES (:i, :c, :n, :s, :sn, 0)",
            i=cid,
            c=code,
            n=f"{code} name",
            s=INT_SERVICES[service],
            sn=service,
        )
        sql(
            "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES (:i, :c, :s)",
            i=cid + 100,
            c=cid,
            s=INT_SERVICES[service],
        )
        for k, v in keys:
            key_id += 1
            sql(
                "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, :s, :k, :v)",
                i=key_id,
                s=cid + 100,
                k=k,
                v=v,
            )
    # The provisioning jobs as the deployment had them (restored at the end).
    SAVED_JOBS["apscheduler_jobs"] = rows("SELECT * FROM apscheduler_jobs WHERE id IN :j", j=JOB_IDS)
    SAVED_JOBS["scheduled_job_metadata"] = rows("SELECT * FROM scheduled_job_metadata WHERE job_id IN :j", j=JOB_IDS)


def clear_jobs():
    sql("DELETE FROM apscheduler_jobs WHERE id IN :j", j=JOB_IDS)
    sql("DELETE FROM scheduled_job_metadata WHERE job_id IN :j", j=JOB_IDS)


def restore_jobs():
    if not SAVED_JOBS:
        return
    clear_jobs()
    for table, saved in SAVED_JOBS.items():
        for row in saved:
            sql(f"INSERT INTO {table} ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)


def seed_network():
    for name, sid in NET_SERVICES.items():
        sql("INSERT INTO network_connectors_services (id, service_name, auth_type) VALUES (:i, :n, 'Syslog')", i=sid, n=name)
    key_id = 7_650_300
    for cid, code, name, service, keys in NET_CONNECTORS:
        sql(
            "INSERT INTO customer_network_connectors (id, customer_code, customer_name, network_connector_service_id, "
            "network_connector_service_name, deployed) VALUES (:i, :c, :n, :s, :sn, 0)",
            i=cid,
            c=code,
            n=name,
            s=NET_SERVICES[service],
            sn=service,
        )
        sql(
            "INSERT INTO network_connectors_subscriptions (id, customer_id, network_connectors_service_id) VALUES (:i, :c, :s)",
            i=cid + 100,
            c=cid,
            s=NET_SERVICES[service],
        )
        for k, v in keys:
            key_id += 1
            sql(
                "INSERT INTO network_connectors_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, :s, :k, :v)",
                i=key_id,
                s=cid + 100,
                k=k,
                v=v,
            )
    for code, name, org in ((CUST_A, NAME_A, "7"), (CUST_B, NAME_B, "8")):
        sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group) VALUES (:c, :n, 'i', 's', :o, 'g')",
            c=code,
            n=name,
            o=org,
        )


def point_tools():
    """The Graylog connectors, Grafana, the indexer and connector id 1 at the stand-ins."""
    set_connector("Grafana", GRAFANA_URL)
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog")
    set_connector("Graylog-Network", f"http://127.0.0.1:{STUB_PORT}/graylog-net")
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


def cleanup():
    sql("DELETE FROM integration_auth_keys WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM integration_subscriptions WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM customer_integrations WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM integration_services WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM customer_integrations_meta WHERE customer_code IN :c", c=list(CUSTOMERS) + [CUST_D])
    sql("DELETE FROM network_connectors_keys WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM network_connectors_subscriptions WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM customer_network_connectors WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM network_connectors_services WHERE id BETWEEN :lo AND :hi", lo=SEED_LO, hi=SEED_HI)
    sql("DELETE FROM customer_network_connectors_meta WHERE customer_code IN :c", c=list(CUSTOMERS))
    sql("DELETE FROM customersmeta WHERE customer_code IN :c", c=list(CUSTOMERS))
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for code in CUSTOMERS:
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)


# --- The backends ------------------------------------------------------------------------------------


def build_python_app():
    """The real routers, served by uvicorn in a thread: the Python side of every check, and the
    Rust instances' legacy backend (the scheduler's `/provisioning_jobs`). The APScheduler instance
    is the real one on the real `apscheduler_jobs` store, started paused: jobs are stored, none
    fires."""
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import carbonblack
    from app.routers import cato
    from app.routers import customer_provisioning
    from app.routers import darktrace
    from app.routers import duo
    from app.routers import grafana
    from app.routers import huntress
    from app.routers import mimecast
    from app.routers import sap_siem
    from app.routers import scheduler
    from app.routers import socfortress_mdr
    from app.routers import stack_provisioning
    from app.schedulers import scheduler as scheduler_module

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        paused = AsyncIOScheduler(event_loop=asyncio.get_running_loop())
        paused.configure(jobstores={"default": SQLAlchemyJobStore(engine=sync_engine)})
        paused.start(paused=True)
        scheduler_module.scheduler_instance = paused
        yield
        paused.shutdown(wait=False)

    api = APIRouter(prefix="/api")
    for module in (
        grafana,
        customer_provisioning,
        stack_provisioning,
        huntress,
        darktrace,
        duo,
        cato,
        carbonblack,
        mimecast,
        sap_siem,
        socfortress_mdr,
        scheduler,
    ):
        api.include_router(module.router)
    app = FastAPI(redirect_slashes=False, lifespan=lifespan)
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


def wait_port(port, proc):
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
UUID = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CREATION_DATE = re.compile(rb'"creation_date": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z"')
#: elasticsearch-py's `User-Agent` names the interpreter's patch version.
ES_AGENT = re.compile(r"\(Python 3\.11(?:\.\d+)?\)")


class UuidMap:
    """UUIDs (the content packs' `uuid4()`s) as `<uuid#n>` in order of first appearance, the
    same map for one side's outbound requests, answer and state."""

    def __init__(self):
        self.seen = {}

    def sub(self, raw):
        def repl(m):
            return self.seen.setdefault(m.group(0), f"<uuid#{len(self.seen)}>".encode())

        return UUID.sub(repl, raw)


def norm_body(raw, uuids=None):
    raw = ADDRESS.sub(b"object at 0x...", raw)
    return uuids.sub(raw) if uuids else raw


def out_norm(requests, uuids):
    """The outbound requests compared: the Graylog version probes left out (both backends cache
    the version; Python's is pinned), the index set's `utcnow()` masked, UUIDs numbered, the
    interpreter's patch version in elasticsearch-py's `User-Agent` dropped."""
    out = []
    for method, target, headers, body in requests:
        if method == "GET" and target in ("/graylog/api/system", "/graylog-net/api/system"):
            continue
        body = CREATION_DATE.sub(b'"creation_date": "<utcnow>"', body)
        headers = [(k, ES_AGENT.sub("(Python 3.11)", v) if k == "user-agent" else v) for k, v in headers]
        out.append((method, uuids.sub(target.encode()).decode(), headers, uuids.sub(body)))
    return out


class Pair:
    def __init__(self):
        # A connection per request: a bare 500 closes the server's side of a kept-alive
        # connection, and the next request could be written onto it before the close arrives.
        no_reuse = httpx.Limits(max_keepalive_connections=0)
        self.py = httpx.AsyncClient(base_url=f"http://127.0.0.1:{PY_PORT}", timeout=120, limits=no_reuse)
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120, limits=no_reuse)
        self.rs7 = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS7_PORT}", timeout=120, limits=no_reuse)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        RECORDER.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, RECORDER.take()

    async def same(self, name, method, path, tok=None, before=None, state=None, expect=None, rust=None, rollback=False, **kw):
        """Python, then Rust, each after `before()`; `state()` returns what the request left.
        `expect=(python, rust)`: the statuses of a deliberate difference (bodies not compared).
        `rollback`: a run that fails after creating something (RUST_MIGRATION.md §4) — the same
        answer, Python's requests then Rust's undo (deletes, the installations they read, the
        organization switches), Python leaving objects behind and Rust none."""
        sides = []
        for client in (self.py, rust or self.rs):
            if before:
                before()
            dump = lambda: CREATION_DATE.sub(b'"creation_date": "<utcnow>"', json.dumps(state(), default=str).encode())  # noqa: E731
            pre = dump() if state else None
            r, out = await self.call(client, method, path, tok, **kw)
            uuids = UuidMap()
            out = out_norm(out, uuids)
            st = uuids.sub(dump()) if state else None
            sides.append((r, out, st, uuids, pre))
        (r1, o1, s1, u1, p1), (r2, o2, s2, u2, p2) = sides
        if rollback:
            b1, b2 = norm_body(r1.content, u1), norm_body(r2.content, u2)
            undo = o2[len(o1) :]
            undo_only = all(
                m == "DELETE" or (m == "GET" and t.endswith("/installations")) or (m == "POST" and "/user/using/" in t)
                for m, t, h, b in undo
            )
            ok = r1.status_code == r2.status_code and b1 == b2 and o2[: len(o1)] == o1 and undo and undo_only
            if rollback is True:
                ok = ok and s2 == p2 and s1 != p1
            else:
                # Only these parts rolled back; the rest as Python left it (a reused stream
                # keeps the index set it was moved onto).
                j1, j2, jp = json.loads(s1), json.loads(s2), json.loads(p2)
                ok = ok and s1 != p1 and all(j2[k] == jp[k] for k in rollback) and all(j2[k] == j1[k] for k in j1 if k not in rollback)
            check(
                f"{name} [{r1.status_code}] [diff by design: rolled back]",
                ok,
                f"python {r1.status_code} {b1[:300]!r}\n        rust   {r2.status_code} {b2[:300]!r}\n        undo {[o[:2] for o in undo]}"
                f"\n        python left {s1[:600]!r}\n        rust left   {s2[:600]!r}\n        before      {p2[:600]!r}",
            )
            return r1, r2
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2
        b1, b2 = norm_body(r1.content, u1), norm_body(r2.content, u2)
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
                    detail += f"\n        outbound #{i} python {x[:3]} {x[3][:400]!r}\n        outbound #{i} rust   {y[:3]} {y[3][:400]!r}"
                    break
            else:
                detail += f"\n        outbound python {[o[:2] for o in o1]}\n        outbound rust   {[o[:2] for o in o2]}"
        if s1 != s2:
            ok = False
            detail += f"\n        state python {s1}\n        state rust   {s2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {[(m, p, b[:200]) for m, p, h, b in o1]}")
        return r1, r2

    async def close(self):
        for c in (self.py, self.rs, self.rs7):
            await c.aclose()


# --- Dashboards ----------------------------------------------------------------------------------------

DASH = "/api/grafana/dashboards"
CPDASH = "/api/customer_provisioning/provision/dashboards"


def grafana(overrides=None):
    return lambda: GRAFANA.reset(overrides)


async def dashboard_checks(p, t_admin, t_analyst, t_unassigned):
    ok = grafana()
    await p.same("dashboards: no token", "POST", DASH, json={"dashboards": []})
    await p.same("dashboards: malformed JSON, no token", "POST", DASH, content=b"{", headers={"Content-Type": "application/json"})
    await p.same("dashboards: no body", "POST", DASH, t_admin)
    await p.same("dashboards: a list body", "POST", DASH, t_admin, json=[])
    await p.same("dashboards: not JSON", "POST", DASH, t_admin, content=b"x=1", headers={"Content-Type": "text/plain"})
    await p.same("dashboards: unknown name", "POST", DASH, t_admin, json={"dashboards": ["WAZUH_SUMMARY", "NOPE"]})
    await p.same("dashboards: commented-out member", "POST", DASH, t_admin, json={"dashboards": ["EDR_WAZUH_INVENOTRY"]})
    await p.same(
        "dashboards: bad fields",
        "POST",
        DASH,
        t_admin,
        json={"dashboards": [1], "organizationId": "x", "folderId": 1.5, "datasourceUid": 5, "grafana_url": None},
    )
    await p.same("dashboards: empty list asks nothing", "POST", DASH, t_analyst, before=ok, json={"dashboards": []})
    await p.same(
        "dashboards: defaults (org 0, folder 0, the template URL)",
        "POST",
        DASH,
        t_admin,
        before=ok,
        json={"dashboards": ["HUNTRESS_SUMMARY"]},
    )
    await p.same(
        "dashboards: several, the datasource and URL replaced",
        "POST",
        DASH,
        t_unassigned,
        before=ok,
        json={
            "dashboards": ["WAZUH_SUMMARY", "OFFICE365_SUMMARY", "SONICWALL_VPN", "WAZUH_SUMMARY", "MIMECAST_SUMMARY"],
            "organizationId": "44",
            "folderId": 7.0,
            "datasourceUid": 'ds-ü"\\x',
            "grafana_url": "https://grafana.company.local/sub",
        },
    )
    await p.same(
        "dashboards: every Fortinet and SentinelOne dashboard",
        "POST",
        DASH,
        t_admin,
        before=ok,
        json={
            "dashboards": [
                "FORTINET_SYSTEM_LOGS",
                "FORTINET_UTM_ANOMALIES",
                "FOTINET_UTM_DLP",
                "FORTINET_VPN",
                "SENTINELONE_EPP_SUMMARY",
                "SENTINELONE_EPP_MALWARE",
                "EDR_AGENT_INVENTORY",
                "EDR_OPEN_AUDIT",
            ],
            "organizationId": 100000000000000000000,
            "folderId": -3,
            "grafana_url": "http://g:3000",
        },
    )
    body = {"dashboards": ["DUO_AUTH", "CATO_SUMMARY"], "organizationId": 7, "folderId": 3}
    await p.same(
        "dashboards: the switch refused",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/user/using/*"): (404, "application/json", _json({"message": "User not found"}))}),
        json=body,
    )
    await p.same(
        "dashboards: the second upload refused (the first stays)",
        "POST",
        DASH,
        t_admin,
        before=grafana(
            {
                ("POST", "/dashboards/db"): [
                    (200, "application/json", _json({"id": 1, "slug": "s", "status": "success", "uid": "u", "url": "/d/u", "version": 1})),
                    (412, "application/json", _json({"message": "version-mismatch", "status": "version-mismatch"})),
                ],
            },
        ),
        json=body,
    )
    await p.same(
        "dashboards: Grafana 400",
        "POST",
        DASH,
        t_admin,
        before=grafana(
            {("POST", "/dashboards/db"): (400, "application/json", _json({"message": "Dashboard title cannot be empty", "x": [1]}))},
        ),
        json=body,
    )
    await p.same(
        "dashboards: Grafana 401",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (401, "application/json", _json({"message": "Unauthorized"}))}),
        json=body,
    )
    await p.same(
        "dashboards: Grafana 500 text",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (500, "text/html", b"<h1>boom</h1>")}),
        json=body,
    )
    await p.same(
        "dashboards: an answer missing fields (the model's 400)",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (200, "application/json", _json({"id": 1, "uid": 5}))}),
        json=body,
    )
    await p.same(
        "dashboards: a text answer (the TypeError's 500)",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (200, "text/plain", b"ok")}),
        json=body,
    )
    await p.same(
        "dashboards: a 204 answer",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (204, None, b"")}),
        json=body,
    )
    await p.same(
        "dashboards: an answer that is not JSON",
        "POST",
        DASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (200, "application/json", b"{nope")}),
        json=body,
    )

    def grafana_down():
        GRAFANA.reset()
        set_connector("Grafana", f"http://127.0.0.1:{CLOSED_PORT}")

    def grafana_back():
        GRAFANA.reset()
        set_connector("Grafana", GRAFANA_URL)

    await p.same("dashboards: Grafana unreachable", "POST", DASH, t_admin, before=grafana_down, json=body)

    def grafana_gone():
        GRAFANA.reset()
        sql("DELETE FROM connectors WHERE connector_name = 'Grafana'")

    await p.same("dashboards: no Grafana connector", "POST", DASH, t_admin, before=grafana_gone, json=body)

    def grafana_bad_url():
        GRAFANA.reset()
        set_connector("Grafana", "grafana.local:3000")

    await p.same("dashboards: a connector URL without a scheme", "POST", DASH, t_admin, before=grafana_bad_url, json=body)
    grafana_back()

    full = {
        "customer_name": "Acme",
        "dashboards_to_include": {"dashboards": ["HUNTRESS_SUMMARY", "CROWDSTRIKE_SUMMARY"], "organizationId": 99, "folderId": 98},
        "grafana_org_id": 7,
        "grafana_datasource_uid": "ds-2",
        "grafana_folder_id": 3,
        "grafana_url": "https://grafana.example.com",
    }
    await p.same("customer dashboards: no token", "POST", CPDASH, json=full)
    await p.same("customer dashboards: provisioned", "POST", CPDASH, t_analyst, before=ok, json=full)
    await p.same(
        "customer dashboards: missing fields",
        "POST",
        CPDASH,
        t_admin,
        json={"dashboards_to_include": {"dashboards": ["DUO_AUTH"]}},
    )
    await p.same(
        "customer dashboards: unknown dashboard and a bad org",
        "POST",
        CPDASH,
        t_admin,
        json={**full, "dashboards_to_include": {"dashboards": ["NOPE"]}, "grafana_org_id": "x"},
    )
    await p.same("customer dashboards: nested not an object", "POST", CPDASH, t_admin, json={**full, "dashboards_to_include": []})
    await p.same(
        "customer dashboards: Grafana refuses",
        "POST",
        CPDASH,
        t_admin,
        before=grafana({("POST", "/dashboards/db"): (403, "application/json", _json({"message": "Permission denied"}))}),
        json=full,
    )
    # The GET of the same path stays the customer router's.
    await p.same("customer dashboards: the GET list", "GET", CPDASH, t_admin)


# --- Network connectors --------------------------------------------------------------------------------

NET = "/api/stack_provisioning/graylog/provision"
NET_IDS = [c[0] for c in NET_CONNECTORS]
PIPELINE_PACK = "SOCFORTRESS_FORTINET_PROCESSING_PIPELINE"


def pin_graylog_version(connector, version):
    """Python's cached Graylog major version, as the Rust instance in use has it (both probe
    `GET /api/system` once per 5 minutes; the probes are left out of the comparison)."""
    from app.connectors.graylog.utils import universal

    universal._GRAYLOG_VERSION_CACHE[connector] = (version, time.monotonic())


def template(name):
    with open(os.path.join(BACKEND, "app", "stack_provisioning", "graylog", "templates", f"{name}.json")) as f:
        return json.load(f)


def net(version=6, graylog=None, grafana=None, indexer=None, setup=None):
    """A fresh world: no meta rows, nothing deployed, the stand-ins reset."""

    def before():
        point_tools()
        sql("DELETE FROM customer_network_connectors_meta WHERE customer_code IN :c", c=list(CUSTOMERS))
        sql("UPDATE customer_network_connectors SET deployed = 0 WHERE id IN :i", i=NET_IDS)
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = '7' WHERE customer_code = :c", c=CUST_A)
        GRAYLOG_NET.reset(version, **(graylog or {}))
        GRAFANA.reset(grafana)
        INDEXER.reset(indexer)
        pin_graylog_version("Graylog-Network", version)
        if setup:
            setup()

    return before


def network_state():
    meta = rows(
        "SELECT customer_code, network_connector_name, graylog_input_id, graylog_index_id, graylog_stream_id, graylog_pipeline_id, "
        "graylog_content_pack_input_id, graylog_content_pack_stream_id, grafana_org_id, grafana_dashboard_folder_id, "
        "grafana_datasource_uid FROM customer_network_connectors_meta WHERE customer_code IN :c ORDER BY id",
        c=list(CUSTOMERS),
    )
    flags = rows("SELECT id, deployed FROM customer_network_connectors WHERE id IN :i ORDER BY id", i=NET_IDS)
    return {"meta": meta, "deployed": flags, "graylog": GRAYLOG_NET.state(), "grafana": GRAFANA.state()}


def with_stream_and_input(title_stream, title_input):
    return {
        "streams": [{"id": "st-pre", "title": title_stream}],
        "inputs": [{"id": "in-pre", "title": title_input}],
    }


async def network_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    forti = {"customer_code": CUST_A, "tcp_enabled": True, "hot_data_retention": 30, "index_replicas": 1}
    st = network_state
    await p.same("fortinet: no token", "POST", f"{NET}/fortinet", json=forti)
    await p.same(
        "fortinet: malformed JSON, no token",
        "POST",
        f"{NET}/fortinet",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )
    await p.same("fortinet: no body", "POST", f"{NET}/fortinet", t_admin)
    await p.same("fortinet: a list body (the before-validator's TypeError)", "POST", f"{NET}/fortinet", t_admin, json=[forti])
    await p.same("fortinet: a string body", "POST", f"{NET}/fortinet", t_admin, json="x")
    await p.same("sonicwall: not JSON", "POST", f"{NET}/sonicwall", t_admin, content=b"x=1", headers={"Content-Type": "text/plain"})
    await p.same("sentinelone: missing fields", "POST", f"{NET}/sentinelone", t_admin, json={"integration_name": None})
    await p.same(
        "fortinet: bad field types",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        json={"customer_code": 5, "tcp_enabled": "maybe", "hot_data_retention": 1.5, "index_replicas": "x"},
    )
    await p.same("fortinet: TCP on Graylog 6", "POST", f"{NET}/fortinet", t_admin, before=net(6), state=st, json=forti)
    await p.same(
        "fortinet: UDP on Graylog 7, as the customer's analyst",
        "POST",
        f"{NET}/fortinet",
        t_analyst,
        before=net(7),
        state=st,
        rust=p.rs7,
        json={**forti, "tcp_enabled": False, "udp_enabled": True, "integration_name": "ignored", "hot_data_retention": "3"},
    )
    installed = {
        "id": "pl-forti",
        "title": "FORTINET PROCESSING PIPELINE",
        "description": "FORTINET PROCESSING PIPELINE",
        "source": "pipeline",
        "stages": [],
        "created_at": "2026-10-01T00:00:00.000Z",
    }
    await p.same(
        "fortinet: the processing pipeline already in Graylog (not installed again)",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(6, graylog={"content_packs": [template(PIPELINE_PACK)], "pipelines": [installed]}),
        state=st,
        json=forti,
    )
    await p.same(
        "fortinet: a content pack named after the customer",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(
            6,
            graylog={"content_packs": [{**template(PIPELINE_PACK), "id": "c0ffee00-0000-4000-8000-000000000001", "name": NAME_A}]},
        ),
        state=st,
        json=forti,
    )
    await p.same(
        "fortinet: both protocols",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(),
        state=st,
        json={**forti, "udp_enabled": True},
    )
    await p.same(
        "fortinet: no protocol",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(),
        state=st,
        json={**forti, "tcp_enabled": None},
    )
    await p.same("sonicwall: provisioned on Graylog 6", "POST", f"{NET}/sonicwall", t_admin, before=net(6), state=st, json=forti)
    await p.same(
        "sonicwall: provisioned on Graylog 7",
        "POST",
        f"{NET}/sonicwall",
        t_admin,
        before=net(7),
        state=st,
        rust=p.rs7,
        json={**forti, "tls_enabled": False},
    )
    s1 = with_stream_and_input(f"{NAME_A} - SENTINELONE ALERTS AND EVENTS", f"{NAME_A} - SENTINELONE ALERTS AND EVENTS")
    pipeline = {
        "id": "pl-s1",
        "title": "S1",
        "description": "SentinelOne processing",
        "source": "pipeline",
        "stages": [],
        "created_at": "2026-10-01T00:00:00.000Z",
    }
    await p.same(
        "sentinelone: no content pack, the stream and pipeline already there",
        "POST",
        f"{NET}/sentinelone",
        t_admin,
        before=net(6, graylog={**s1, "pipelines": [pipeline]}),
        state=st,
        rollback=("grafana",),
        json=forti,
    )
    await p.same(
        "sentinelone: no pipeline (the 500 naming the Wazuh content pack)",
        "POST",
        f"{NET}/sentinelone",
        t_admin,
        before=net(6, graylog=s1),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "sentinelone: no stream (PUT /api/streams/None)",
        "POST",
        f"{NET}/sentinelone",
        t_admin,
        before=net(6, graylog={"pipelines": [pipeline]}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "sentinelone: a pipeline without a description",
        "POST",
        f"{NET}/sentinelone",
        t_admin,
        before=net(6, graylog={**s1, "pipelines": [{**pipeline, "description": None}]}),
        state=st,
        rollback=True,
        json=forti,
    )
    # Python's refusals in its order.
    await p.same(
        "fortinet: the port is not an int",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(),
        state=st,
        json={**forti, "customer_code": CUST_B},
    )
    await p.same(
        "sonicwall: no TLS keys (KeyError)",
        "POST",
        f"{NET}/sonicwall",
        t_admin,
        before=net(),
        state=st,
        json={**forti, "customer_code": CUST_B},
    )
    await p.same(
        "sentinelone: no such connector (AttributeError)",
        "POST",
        f"{NET}/sentinelone",
        t_admin,
        before=net(),
        state=st,
        json={**forti, "customer_code": CUST_B},
    )
    await p.same("fortinet: no keys", "POST", f"{NET}/fortinet", t_admin, before=net(), state=st, json={**forti, "customer_code": CUST_C})
    await p.same(
        "fortinet: no network connector",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(),
        state=st,
        json={**forti, "customer_code": f"GPD{SFX}"},
    )

    def no_meta():
        sql("DELETE FROM customersmeta WHERE customer_code = :c", c=CUST_A)

    def meta_back():
        sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group) VALUES (:c, :n, 'i', 's', '7', 'g')",
            c=CUST_A,
            n=NAME_A,
        )

    await p.same("fortinet: no Grafana organization", "POST", f"{NET}/fortinet", t_admin, before=net(setup=no_meta), state=st, json=forti)
    meta_back()

    def org_x():
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = 'x' WHERE customer_code = :c", c=CUST_A)

    await p.same(
        "fortinet: an organization that is not an int (the dashboards request's 400)",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(setup=org_x),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: Graylog refuses the index set",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(
            graylog={
                "overrides": {
                    ("POST", "/api/system/indices/index_sets"): (400, "application/json", _json({"message": "Index prefix conflicts"})),
                },
            },
        ),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: Graylog refuses the stream move",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(graylog={"overrides": {("PUT", "/api/streams/*"): (400, "application/json", _json({"message": "Invalid index set"}))}}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: the connection answered 204",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(graylog={"overrides": {("POST", "/api/system/pipelines/connections/to_stream"): (204, None, b"")}}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: an install refused",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(graylog={"overrides": {("POST", "/api/system/content_packs/*/installations"): (500, "text/plain", b"boom")}}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: the indexer's health fails (the shard count)",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(indexer={("GET", "/_cluster/health"): (503, "application/json", _json({"error": "unavailable", "status": 503}))}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: no node version",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(indexer={("GET", "/_nodes/_local"): (200, "application/json", _json({"nodes": {}}))}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: Grafana refuses the datasource",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(
            grafana={
                ("POST", "/datasources"): (409, "application/json", _json({"message": "data source with the same name already exists"})),
            },
        ),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: a folder answer missing fields",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(grafana={("POST", "/folders"): (200, "application/json", _json({"id": 1, "uid": "u"}))}),
        state=st,
        rollback=True,
        json=forti,
    )
    await p.same(
        "fortinet: a dashboard refused",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(grafana={("POST", "/dashboards/db"): (412, "application/json", _json({"message": "version-mismatch"}))}),
        state=st,
        rollback=True,
        json=forti,
    )

    def no_id1():
        sql("DELETE FROM connectors WHERE id = 1")

    await p.same(
        "fortinet: no connector id 1 (the datasource's 400)",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(setup=no_id1),
        state=st,
        rollback=True,
        json=forti,
    )

    # The datasource reads the `Wazuh-Indexer` row by name, id 1 only when no row has the
    # name (Python read id 1, whatever it was): §4.
    def id1_elsewhere():
        sql(
            "UPDATE connectors SET connector_name = 'Parity-Not-The-Indexer', connector_url = 'http://127.0.0.1:9', "
            "connector_username = 'id1-user', connector_password = 'id1-pass' WHERE id = 1",
        )
        set_connector("Wazuh-Indexer", INDEXER_URL, username="named-user", password="named-pass")

    from app.connectors import cache as connector_cache

    sides = []
    for client in (p.py, p.rs):
        net(setup=id1_elsewhere)()
        # A Python process that has not resolved id 1 yet (it then reads it by the name it
        # had when first seen).
        connector_cache.invalidate_all()
        r, out = await p.call(client, "POST", f"{NET}/fortinet", t_admin, json=forti)
        ds = [json.loads(b) for m, t, h, b in out if m == "POST" and t.endswith("/datasources")]
        sides.append((r.status_code, ds[0] if ds else None))
    sql("DELETE FROM connectors WHERE connector_name = 'Wazuh-Indexer' AND id <> 1")
    sql("UPDATE connectors SET connector_name = 'Wazuh-Indexer' WHERE id = 1")
    (st1, ds1), (st2, ds2) = sides
    check(
        "fortinet: the datasource on the Wazuh-Indexer row, id 1 another connector [diff by design: by name]",
        st1 == st2 == 200
        and ds1
        and ds2
        and (ds1["url"], ds1["basicAuthUser"], ds1["secureJsonData"])
        == ("http://127.0.0.1:9", "id1-user", {"basicAuthPassword": "id1-pass"})
        and (ds2["url"], ds2["basicAuthUser"], ds2["secureJsonData"]) == (INDEXER_URL, "named-user", {"basicAuthPassword": "named-pass"})
        and {k: v for k, v in ds1.items() if k not in ("url", "basicAuthUser", "secureJsonData")}
        == {k: v for k, v in ds2.items() if k not in ("url", "basicAuthUser", "secureJsonData")},
        f"python {st1} {ds1}\n        rust   {st2} {ds2}",
    )

    def no_network_graylog():
        sql("DELETE FROM connectors WHERE connector_name = 'Graylog-Network'")

    await p.same(
        "fortinet: no Graylog-Network connector",
        "POST",
        f"{NET}/fortinet",
        t_admin,
        before=net(setup=no_network_graylog),
        state=st,
        json=forti,
    )
    point_tools()
    # Deliberate difference: the body's customer must be the caller's (Python provisioned any).
    await p.same(
        "fortinet: another tenant's customer",
        "POST",
        f"{NET}/fortinet",
        t_analyst_b,
        before=net(),
        state=st,
        expect=(200, 403),
        json=forti,
    )
    await p.same(
        "sonicwall: an analyst without customers",
        "POST",
        f"{NET}/sonicwall",
        t_unassigned,
        before=net(),
        expect=(500, 403),
        json={**forti, "customer_code": CUST_B},
    )
    left = network_state()
    check(
        "fortinet: Rust's refusal asked no tool and wrote nothing",
        not left["meta"] and not any(r["deployed"] for r in left["deployed"]) and not RECORDER.take(),
        str(left),
    )


# --- Integrations --------------------------------------------------------------------------------------


def integ(version=6, graylog=None, grafana=None, indexer=None, setup=None):
    """A fresh world: no meta rows, nothing deployed, no provisioning job stored."""

    def before():
        point_tools()
        sql("DELETE FROM customer_integrations_meta WHERE customer_code IN :c", c=list(CUSTOMERS) + [CUST_D])
        sql("UPDATE customer_integrations SET deployed = 0 WHERE id IN :i", i=INT_IDS)
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = '7' WHERE customer_code = :c", c=CUST_A)
        clear_jobs()
        GRAYLOG.reset(version, **(graylog or {}))
        GRAFANA.reset(grafana)
        INDEXER.reset(indexer)
        pin_graylog_version("Graylog", version)
        if setup:
            setup()

    return before


def integration_state():
    meta = rows(
        "SELECT customer_code, integration_name, instance_name, graylog_input_id, graylog_index_id, graylog_stream_id, "
        "grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid FROM customer_integrations_meta "
        "WHERE customer_code IN :c ORDER BY id",
        c=list(CUSTOMERS) + [CUST_D],
    )
    flags = rows("SELECT id, deployed FROM customer_integrations WHERE id IN :i ORDER BY id", i=INT_IDS)
    jobs = rows("SELECT id, next_run_time IS NOT NULL AS scheduled FROM apscheduler_jobs WHERE id IN :j ORDER BY id", j=JOB_IDS)
    metadata = rows(
        "SELECT job_id, last_success, time_interval, extra_data, enabled, job_description FROM scheduled_job_metadata "
        "WHERE job_id IN :j ORDER BY id",
        j=JOB_IDS,
    )
    return {"meta": meta, "deployed": flags, "jobs": jobs, "metadata": metadata, "graylog": GRAYLOG.state(), "grafana": GRAFANA.state()}


async def integration_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    st = integration_state
    body = {"customer_code": CUST_A, "time_interval": 5}
    await p.same("huntress: no token", "POST", "/api/huntress/provision", json=body)
    await p.same(
        "huntress: malformed JSON, no token",
        "POST",
        "/api/huntress/provision",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )
    await p.same("huntress: no body", "POST", "/api/huntress/provision", t_admin)
    await p.same("huntress: a list body (the before-validator's TypeError)", "POST", "/api/huntress/provision", t_admin, json=[body])
    await p.same("mimecast: not JSON", "POST", "/api/mimecast/provision", t_admin, content=b"x", headers={"Content-Type": "text/plain"})
    await p.same("cato: no time_interval", "POST", "/api/cato/provision", t_admin, json={"customer_code": CUST_A})
    await p.same("huntress: time_interval not an int", "POST", "/api/huntress/provision", t_admin, json={**body, "time_interval": 1.5})
    await p.same("huntress: provisioned on Graylog 6", "POST", "/api/huntress/provision", t_admin, before=integ(6), state=st, json=body)
    await p.same(
        "darktrace: the default interval, on Graylog 7, as the customer's analyst",
        "POST",
        "/api/darktrace/provision",
        t_analyst,
        before=integ(7),
        state=st,
        rust=p.rs7,
        json={"customer_code": CUST_A, "integration_name": "ignored"},
    )
    await p.same(
        "duo: provisioned",
        "POST",
        "/api/duo/provision",
        t_admin,
        before=integ(),
        state=st,
        json={"customer_code": CUST_A, "time_interval": "9"},
    )
    await p.same("cato: provisioned", "POST", "/api/cato/provision", t_admin, before=integ(), state=st, json=body)
    await p.same(
        "carbonblack: provisioned on Graylog 7",
        "POST",
        "/api/carbonblack/provision",
        t_admin,
        before=integ(7),
        state=st,
        rust=p.rs7,
        json=body,
    )
    await p.same(
        "mimecast: provisioned (two fixed jobs)",
        "POST",
        "/api/mimecast/provision",
        t_admin,
        before=integ(),
        state=st,
        json={"customer_code": CUST_A, "time_interval": 99},
    )
    await p.same("sap_siem: provisioned (three jobs)", "POST", "/api/sap_siem/provision", t_admin, before=integ(), state=st, json=body)

    def existing_meta():
        sql(
            "INSERT INTO customer_integrations_meta (customer_code, integration_name, graylog_index_id, graylog_stream_id, "
            "grafana_org_id, grafana_dashboard_folder_id) VALUES (:c, 'Huntress', 'old', 'old', '7', '1')",
            c=CUST_A,
        )

    await p.same(
        "huntress: a meta row already there (the 400 after the tools)",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(setup=existing_meta),
        state=st,
        rollback=True,
        json=body,
    )
    await p.same(
        "huntress: no integration",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(),
        state=st,
        json={**body, "customer_code": CUST_C},
    )
    await p.same(
        "huntress: integrations but no customer row",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(),
        state=st,
        json={**body, "customer_code": CUST_D},
    )

    def no_meta_b():
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = 'x' WHERE customer_code = :c", c=CUST_A)

    await p.same(
        "huntress: an organization that is not an int (the dashboards request's 400)",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(setup=no_meta_b),
        state=st,
        rollback=True,
        json=body,
    )
    await p.same(
        "huntress: Graylog refuses the stream",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(graylog={"overrides": {("POST", "/api/streams"): (400, "application/json", _json({"message": "Invalid title"}))}}),
        state=st,
        rollback=True,
        json=body,
    )
    await p.same(
        "huntress: the stream answer without its id",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(graylog={"overrides": {("POST", "/api/streams"): (201, "application/json", _json({"id": "x"}))}}),
        state=st,
        rollback=True,
        json=body,
    )
    await p.same(
        "huntress: the resume refused",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(graylog={"overrides": {("POST", "/api/streams/*/resume"): (404, "application/json", _json({"message": "gone"}))}}),
        state=st,
        rollback=True,
        json=body,
    )
    await p.same(
        "huntress: the shard count fails",
        "POST",
        "/api/huntress/provision",
        t_admin,
        before=integ(indexer={("GET", "/_cluster/health"): (500, "application/json", _json({"error": "boom", "status": 500}))}),
        state=st,
        json=body,
    )
    await p.same(
        "mimecast: one shard, the indexer not asked for it",
        "POST",
        "/api/mimecast/provision",
        t_admin,
        before=integ(indexer={("GET", "/_cluster/health"): (500, "application/json", _json({"error": "boom", "status": 500}))}),
        state=st,
        json={"customer_code": CUST_A},
    )
    await p.same(
        "sap_siem: an interval APScheduler refuses (OverflowError)",
        "POST",
        "/api/sap_siem/provision",
        t_admin,
        before=integ(),
        state=st,
        rollback=True,
        json={**body, "time_interval": 10**20},
    )
    # Deliberate difference: the body's customer must be the caller's (Python provisioned any).
    await p.same(
        "huntress: another tenant's customer",
        "POST",
        "/api/huntress/provision",
        t_analyst_b,
        before=integ(),
        expect=(200, 403),
        json=body,
    )
    left = integration_state()
    check(
        "huntress: Rust's refusal asked no tool, wrote nothing, scheduled nothing",
        not left["meta"] and not left["jobs"] and not any(r["deployed"] for r in left["deployed"]) and not RECORDER.take(),
        str(left),
    )
    # SOCFortress MDR: no tool, the deployed flag only.
    mdr = "/api/socfortress_mdr/provision"
    await p.same("mdr: provisioned", "POST", mdr, t_analyst, before=integ(), state=st, json={"customer_code": CUST_A})
    await p.same("mdr: a blank COLLECTOR_UUID", "POST", mdr, t_admin, before=integ(), state=st, json={"customer_code": CUST_B})
    await p.same(
        "mdr: Huntress named (its integration holds no MDR COLLECTOR_UUID)",
        "POST",
        mdr,
        t_admin,
        before=integ(),
        state=st,
        json={"customer_code": CUST_A, "integration_name": "Huntress"},
    )
    await p.same(
        "mdr: a service no integration holds (None's AttributeError)",
        "POST",
        mdr,
        t_admin,
        before=integ(),
        state=st,
        json={"customer_code": CUST_A, "integration_name": "Nope"},
    )
    await p.same(
        "mdr: the integration named, but no COLLECTOR_UUID under SOCFortress MDR",
        "POST",
        mdr,
        t_admin,
        before=integ(),
        state=st,
        json={"customer_code": CUST_B, "integration_name": "Huntress"},
    )
    await p.same("mdr: no integration", "POST", mdr, t_admin, before=integ(), state=st, json={"customer_code": CUST_C})
    await p.same("mdr: a list body", "POST", mdr, t_admin, json=[1])
    await p.same(
        "mdr: another tenant's customer",
        "POST",
        mdr,
        t_analyst,
        before=integ(),
        expect=(400, 403),
        json={"customer_code": CUST_B},
    )


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
        t_unassigned = token(UNASSIGNED, ["analyst"])
        try:
            sections = os.environ.get("GRAFANA_PROV_PARITY_SECTIONS", "dashboards,network,integrations").split(",")
            if "dashboards" in sections:
                await dashboard_checks(p, t_admin, t_analyst, t_unassigned)
            if "network" in sections:
                await network_checks(p, t_admin, t_analyst, token(ANALYST_B, ["analyst"]), t_unassigned)
            if "integrations" in sections:
                await integration_checks(p, t_admin, t_analyst, token(ANALYST_B, ["analyst"]), t_unassigned)
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
            restore_jobs()
        finally:
            restore_connectors()
            for server in servers:
                server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
