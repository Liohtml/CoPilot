"""Parity of the remaining provisioning routes ported to Rust with this backend — NOT collected by
pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

`POST /api/office365/provision` and `POST /api/aws/provision` (`copilot-cloud-provisioning`), and the
delete of a deployed AWS instance (`copilot-integrations`), are answered by the real FastAPI routers
and by Rust instances on one database. One Rust instance meets Graylog 6, a second Graylog 7
(both backends cache the version; Python's is pinned to the instance in use). The routers are
served by uvicorn in a thread: that app is the Python side of every check and the Rust instances'
legacy backend. The tools are local stand-ins recording every request — method, target, every
header the client sent and the body bytes: the Wazuh manager (`/wazuh`, its `ossec.conf` kept and
rewritten as a manager would), Graylog (`/graylog`, stateful: pipeline rules, pipelines, index sets,
streams, connections) and Grafana (`/grafanaapi`, the root `grafana_client` builds from a connector
URL ending in `/grafana`) on one port, the Wazuh indexer on another, and AWS (STS and S3 as botocore
reaches them through `AWS_ENDPOINT_URL`, path-style) on a third — the signing time, the signature,
the invocation id and the interpreter's patch version masked. For each request the suite
compares the status, the body, every outbound request and what the request left: the rows, the
manager's configuration and Graylog's objects. Deliberate differences are asserted as such
(RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_remaining_provisioning_e2e.py scripts/rust-parity.sh

Ports (all overridable): REMAINING_PROV_PARITY_RUST_PORT (6841), REMAINING_PROV_PARITY_RUST7_PORT
(6842), REMAINING_PROV_PARITY_PY_PORT (6843, the uvicorn legacy backend), REMAINING_PROV_STUB_PORT
(6844, manager, Graylog and Grafana), REMAINING_PROV_INDEXER_STUB_PORT (6845), REMAINING_PROV_AWS_STUB_PORT
(6846). Seeded ids are seven digits in 7860000-7869999. `REMAINING_PROV_PARITY_SECTIONS=office365,aws,
collectors` picks the sections.

The `collectors` section (`POST /api/{crowdstrike,defender_for_endpoint,bitdefender}/provision`,
`copilot-integration-provisioning`) points both backends at one temporary data directory (Python's
`UPLOAD_FOLDER` of the three modules patched, Rust's `COPILOT_BACKEND_DATA_DIR`), emptied before
each side, and compares every file and directory written there — and next to it, where a `..`
customer name reaches — byte for byte; GravityZone is a stand-in under `/gravityzone` on the tools'
port (Python's `httpx.AsyncClient` re-pointed, Rust's `COPILOT_BITDEFENDER_URL`). The content packs'
`uuid4()`s are numbered by first appearance on each side.
"""

import asyncio
import copy
import datetime
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs
from urllib.parse import quote
from urllib.parse import unquote
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
AWS_PORT = int(os.environ.get("REMAINING_PROV_AWS_STUB_PORT", "6846"))
# botocore's endpoint override, read when a client is created: both backends reach AWS here.
os.environ["AWS_ENDPOINT_URL"] = f"http://127.0.0.1:{AWS_PORT}"
#: How long both backends watch the manager's log after a restart (10 s / 60 s in production).
PROFILE_CHECK = (0.1, 0.3)
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
ACCT_A = "210987654321"
#: The backends' shared data directory (the parent catches what a `..` name writes next to it).
DATA_PARENT = tempfile.mkdtemp(prefix="rp-collectors-")
DATA_DIR = os.path.join(DATA_PARENT, "data")
GRAVITYZONE = "https://cloud.gravityzone.bitdefender.com"
GRAVITYZONE_STUB = f"http://127.0.0.1:{STUB_PORT}/gravityzone"
BUCKET_A, BUCKET_B = f"rp-{SFX}-trail", f"rp-{SFX}-prod"
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

    def reset(self, config=OSSEC, refuse=0, overrides=None, logs=None):
        self.config = config
        # How many PUTs of the configuration answer `error: 1` before one is taken.
        self.refuse = refuse
        self.overrides = copy.deepcopy(overrides or {})
        # `GET /manager/logs` by search text: the newest entry's timestamps, answered in turn (the
        # last repeated); none when absent.
        self.logs = copy.deepcopy(logs or {})

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
        if path == "/manager/configuration/validation" and method == "GET":
            return (
                200,
                j,
                _json(
                    {
                        "data": {
                            "affected_items": [{"name": "node01", "status": "OK"}],
                            "total_affected_items": 1,
                            "total_failed_items": 0,
                            "failed_items": [],
                        },
                        "message": "Validation was successfully checked",
                        "error": 0,
                    },
                ),
            )
        if path == "/manager/logs" and method == "GET":
            search = parse_qs(urlsplit(target).query).get("search", [""])[0]
            stamps = self.logs.get(search)
            stamp = (stamps.pop(0) if len(stamps) > 1 else stamps[0]) if stamps else None
            items = [{"timestamp": stamp, "tag": "wazuh-modulesd:aws-s3", "level": "warning", "description": search}] if stamp else []
            return 200, j, _json({"data": {"affected_items": items, "total_affected_items": len(items), "failed_items": []}, "error": 0})
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

    def reset(self, version=6, rules=None, pipelines=None, overrides=None, inputs=None):
        self.version = version
        self.content_packs = []
        self.inputs = copy.deepcopy(inputs or [{"id": "in-other", "title": "Other input"}])
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
            "packs": [p["name"] for p in self.content_packs],
            "inputs": self.inputs,
        }

    def answer(self, method, target, body):
        path = urlsplit(target).path.removeprefix(self.prefix)
        reply = _override(self.overrides, method, path)
        if reply:
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
            listed = {**copy.deepcopy(pack), "created_at": "2026-10-01T00:00:00.000Z", "server_version": "6.1.4"}
            listed["v"] = str(listed.get("v"))
            for entity in listed.get("entities") or []:
                entity["v"] = str(entity.get("v"))
            self.content_packs.append(listed)
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

            def value(e, key):
                v = (e.get("data") or {}).get(key)
                return v.get("@value") if isinstance(v, dict) else v

            for e in pack.get("entities") or []:
                kind = e.get("type", {}).get("name")
                if kind == "stream":
                    self.streams.append({"id": self._id("st"), "title": value(e, "title"), "running": True})
                elif kind == "input":
                    self.inputs.append({"id": self._id("in"), "title": value(e, "title")})
                elif kind == "pipeline":
                    new = pipeline(self._id("pl"), value(e, "title"), value(e, "description"))
                    self.pipelines.append(new)
            return 200, j, _json({"installation": {"_id": self._id("inst"), "content_pack_id": m.group(1)}, "entities_excluded": []})
        if method == "GET" and path == "/api/streams":
            return 200, j, _json({"streams": self.streams, "total": len(self.streams)})
        if method == "GET" and path == "/api/system/inputs":
            return 200, j, _json({"inputs": self.inputs, "total": len(self.inputs)})
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
        m = re.fullmatch(r"/api/system/pipelines/pipeline/([^/]+)", path)
        if method == "PUT" and m:
            found = next((p for p in self.pipelines if p["id"] == m.group(1)), None)
            if found is None:
                return 404, j, _json({"type": "ApiError", "message": f"Pipeline {m.group(1)} not found"})
            found.update(json.loads(body))
            return 200, j, _json(found)
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
        if method == "PUT" and m:
            stream = next((st for st in self.streams if st["id"] == m.group(1)), None)
            if stream is None:
                return 404, j, _json({"type": "ApiError", "message": f"Stream <{m.group(1)}> not found!"})
            stream.update(json.loads(body))
            return 200, j, _json(stream)
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


def _sts(account):
    return (
        '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n  <GetCallerIdentityResult>\n'
        f"    <Arn>arn:aws:iam::{account}:user/copilot</Arn>\n    <UserId>AIDAPARITY</UserId>\n    <Account>{account}</Account>\n"
        "  </GetCallerIdentityResult>\n  <ResponseMetadata><RequestId>rq-1</RequestId></ResponseMetadata>\n</GetCallerIdentityResponse>\n"
    ).encode()


def _s3_error(code, message):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>'
        + code
        + "</Code><Message>"
        + message
        + "</Message><RequestId>rq</RequestId>"
        "<HostId>h</HostId></Error>"
    ).encode()


class Aws:
    """AWS as botocore reaches it through `AWS_ENDPOINT_URL` (path-style S3): STS's
    GetCallerIdentity, a bucket's HEAD, ListObjectsV2 (`encoding-type=url`, with its delimiter's
    common prefixes) and the one-byte GetObject. Per-test overrides by (method, path glob)."""

    def __init__(self):
        self.reset()

    def reset(self, account=ACCT_A, region="eu-west-1", buckets=None, objects=None, overrides=None):
        self.account = account
        self.region = region
        self.buckets = set(buckets if buckets is not None else (BUCKET_A, BUCKET_B))
        day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y/%m/%d")
        default = {
            f"AWSLogs/{ACCT_A}/CloudTrail/eu-west-1/{day}/{ACCT_A}_CloudTrail_eu-west-1_1+x.json.gz": (1234, "STANDARD"),
            f"AWSLogs/{ACCT_A}/CloudTrail/eu-west-1/{day}/": (0, "STANDARD"),
            f"AWSLogs/{ACCT_A}/GuardDuty/eu-west-1/{day}/gd 1.jsonl.gz": (99, None),
        }
        self.objects = dict(objects if objects is not None else default)
        self.overrides = copy.deepcopy(overrides or {})

    def answer(self, method, target, body):
        parts = urlsplit(target)
        path = parts.path
        reply = _override(self.overrides, method, path)
        if reply:
            return reply
        if method == "POST" and path == "/":
            return 200, "text/xml", _sts(self.account)
        bucket, _, key = path.lstrip("/").partition("/")
        bucket = unquote(bucket)
        if bucket not in self.buckets:
            if method == "HEAD":
                return 404, {"x-amz-request-id": "rq"}, b""
            return 404, "application/xml", _s3_error("NoSuchBucket", "The specified bucket does not exist")
        if method == "HEAD":
            return 200, {"x-amz-bucket-region": self.region, "x-amz-request-id": "rq"}, b""
        if method == "GET" and not key:
            q = parse_qs(parts.query, keep_blank_values=True)
            prefix = q.get("prefix", [""])[0]
            delimiter = q.get("delimiter", [None])[0]
            max_keys = int(q.get("max-keys", ["1000"])[0])
            contents, prefixes = [], []
            for name in sorted(k for k in self.objects if k.startswith(prefix)):
                rest = name[len(prefix) :]
                if delimiter and delimiter in rest:
                    common = prefix + rest.split(delimiter, 1)[0] + delimiter
                    if common not in prefixes:
                        prefixes.append(common)
                else:
                    contents.append(name)
            contents = contents[:max_keys]
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                f"<Name>{bucket}</Name><Prefix>{quote(prefix, safe='/')}</Prefix><KeyCount>{len(contents) + len(prefixes)}</KeyCount>"
                f"<MaxKeys>{max_keys}</MaxKeys><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>"
            )
            for name in contents:
                size, storage = self.objects[name]
                xml += (
                    f"<Contents><Key>{quote(name, safe='/')}</Key><LastModified>2026-10-16T01:02:03.000Z</LastModified><Size>{size}</Size>"
                )
                xml += f"<StorageClass>{storage}</StorageClass>" if storage else ""
                xml += "</Contents>"
            for common in prefixes:
                xml += f"<CommonPrefixes><Prefix>{quote(common, safe='/')}</Prefix></CommonPrefixes>"
            return 200, "application/xml", (xml + "</ListBucketResult>").encode()
        if method == "GET":
            return 206, {"Content-Type": "binary/octet-stream", "Content-Range": "bytes 0-0/1234"}, b"x"
        return 405, "application/xml", _s3_error("MethodNotAllowed", "no")


class GravityZone:
    """GravityZone's JSON-RPC push endpoint: a JSON answer, or a text that is not JSON."""

    def reset(self, text=False):
        self.text = text

    def answer(self, method, target, body):
        if self.text:
            return 200, "text/plain", b"accepted"
        return 200, "application/json", _json({"id": "1", "jsonrpc": "2.0", "result": True})


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
AWS = Aws()
RECORDER = Recorder()
GRAVITYZONE_TOOL = GravityZone()
GRAVITYZONE_TOOL.reset()


class ByPrefix:
    def __init__(self, routes):
        self.routes = routes

    def answer(self, method, target, body):
        for prefix, tool in self.routes:
            if target.startswith(prefix):
                return tool.answer(method, target, body)
        return 404, "application/json", _json({"message": "no such stand-in route"})


TOOLS = ByPrefix((("/grafanaapi", GRAFANA), ("/graylog", GRAYLOG), ("/wazuh", MANAGER), ("/gravityzone", GRAVITYZONE_TOOL)))


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
            # A content type, or the answer's headers.
            for name, value in (ctype or {}).items() if isinstance(ctype, dict) else [("Content-Type", ctype)] if ctype else []:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle  # noqa: N815 - http.server API

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
INT_SERVICES = {
    "Office365": 7_860_001,
    "AWS": 7_860_002,
    "Crowdstrike": 7_860_003,
    "DefenderForEndpoint": 7_860_004,
    "BitDefender": 7_860_005,
}
O365_KEYS_A = [("TENANT_ID", TENANT_A), ("CLIENT_ID", "c-a"), ("CLIENT_SECRET", "s<a>&"), ("API_TYPE", "commercial")]
O365_KEYS_A2 = [("TENANT_ID", TENANT_A2), ("CLIENT_ID", "c-a2"), ("CLIENT_SECRET", "s-a2"), ("API_TYPE", "gcc-high")]
INT_ROWS = [
    (7_860_011, CUST_A, "Office365", None, O365_KEYS_A),
    (7_860_013, CUST_B, "Office365", None, [("TENANT_ID", TENANT_B), ("CLIENT_ID", "c-b"), ("API_TYPE", "gcc")]),
    (7_860_014, CUST_D, "Office365", None, [("TENANT_ID", TENANT_D), ("CLIENT_ID", "c-d"), ("CLIENT_SECRET", "s"), ("API_TYPE", "x")]),
]
#: The second tenant of customer A, seeded by the checks that need it.
SECOND_TENANT = (7_860_012, CUST_A, "Office365", "sub.example", O365_KEYS_A2)
AWS_KEYS_A = [
    ("ACCESS_KEY_ID", "AKIAPARITY0000000001"),
    ("SECRET_ACCESS_KEY", "par/ity+s3cr<et>&"),
    ("AWS_ACCOUNT_ID", ACCT_A),
    ("BUCKET_NAME", BUCKET_A),
    ("SERVICES", "cloudtrail,guardduty"),
    ("ONLY_LOGS_AFTER", "2026-oct-01"),
]
#: Customer A's unnamed AWS account, its named second one and the AWS rows of B (the bad keys, no
#: keys, and — seeded by the check that needs it — A's account claimed by B).
AWS_A = (7_860_021, CUST_A, "AWS", None, AWS_KEYS_A)
AWS_A_PROD = (
    7_860_022,
    CUST_A,
    "AWS",
    "prod",
    [
        ("ACCESS_KEY_ID", "AKIAPARITY0000000002"),
        ("SECRET_ACCESS_KEY", "s2"),
        ("AWS_ACCOUNT_ID", ACCT_A),
        ("BUCKET_NAME", BUCKET_B),
        ("SERVICES", "cloudtrail"),
    ],
)
AWS_B_BAD = (
    7_860_023,
    CUST_B,
    "AWS",
    "bad",
    [("ACCESS_KEY_ID", "akia"), ("AWS_ACCOUNT_ID", "12"), ("BUCKET_NAME", "Bad_Bucket"), ("SERVICES", "vpcflow"), ("ONLY_LOGS_AFTER", "x")],
)
AWS_B_NOKEYS = (7_860_024, CUST_B, "AWS", "nokeys", [])
AWS_B_CLAIM = (7_860_025, CUST_B, "AWS", None, [("AWS_ACCOUNT_ID", f" {ACCT_A} "), ("BUCKET_NAME", "other-bucket")])
AWS_ROWS = [AWS_A, AWS_A_PROD, AWS_B_BAD, AWS_B_NOKEYS, AWS_B_CLAIM]
INT_IDS = [r[0] for r in INT_ROWS] + [SECOND_TENANT[0]] + [r[0] for r in AWS_ROWS]
#: The collectors' integrations: A holds all three, B a port `int()` refuses and Bitdefender keys
#: Pydantic refuses, C (no Grafana organization) CrowdStrike.
CS_KEYS = [
    ("CLIENT_ID", "cs-client"),
    ("CLIENT_SECRET", "cs-s3cr3t é"),
    ("BASE_URL", "https://api.crowdstrike.com"),
    ("SYSLOG_PORT", "5556"),
]
COLLECTOR_ROWS = [
    (7_860_031, CUST_A, "Crowdstrike", None, CS_KEYS),
    (
        7_860_032,
        CUST_A,
        "DefenderForEndpoint",
        None,
        [("CLIENT_ID", "dfe-client"), ("CLIENT_SECRET", "dfe-secret"), ("TENANT_ID", "dfe-tenant"), ("SYSLOG_PORT", " 50_44 ")],
    ),
    (
        7_860_033,
        CUST_A,
        "BitDefender",
        None,
        [
            ("BASIC_AUTH_USERNAME", "gz-user"),
            ("BASIC_AUTH_PASSWORD", "gz-pässword"),
            ("WEBSERVER_HOSTNAME", "firehose.parity.example"),
            ("WEBSERVER_PORT", "3200"),
            ("GRAYLOG_PORT", "10514"),
            ("API_KEY", "gz-api-key"),
        ],
    ),
    (7_860_034, CUST_B, "Crowdstrike", None, CS_KEYS[:3] + [("SYSLOG_PORT", "55x")]),
    (7_860_035, CUST_B, "BitDefender", None, [("BASIC_AUTH_USERNAME", "u"), ("WEBSERVER_PORT", "1")]),
    (7_860_036, CUST_C, "Crowdstrike", None, CS_KEYS),
]
COLLECTOR_IDS = [r[0] for r in COLLECTOR_ROWS]
#: Connector id 3 (the collectors' syslog target), inserted when the database has none.
SYSLOG_CONNECTOR = ("Parity-Syslog", "https://graylog-syslog.parity.example:9000")


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
    for row in INT_ROWS + COLLECTOR_ROWS:
        insert_integration(*row)
    if not rows("SELECT id FROM connectors WHERE id = 3"):
        sql(
            "INSERT INTO connectors (id, connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
            "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
            "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
            "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (3, :n, '3', "
            ":u, UTC_TIMESTAMP(), NULL, NULL, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
            n=SYSLOG_CONNECTOR[0],
            u=SYSLOG_CONNECTOR[1],
        )
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
    sql("DELETE FROM customer_network_connectors_meta WHERE customer_code IN :c", c=codes)
    sql("DELETE FROM customersmeta WHERE customer_code IN :c", c=codes)
    sql("DELETE FROM connectors WHERE id = 3 AND connector_name = :n", n=SYSLOG_CONNECTOR[0])
    shutil.rmtree(DATA_PARENT, ignore_errors=True)
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
    from app.routers import aws
    from app.routers import bitdefender
    from app.routers import crowdstrike
    from app.routers import defenderforendpoint
    from app.routers import integrations
    from app.routers import office365

    api = APIRouter(prefix="/api")
    for module in (office365, aws, integrations, crowdstrike, defenderforendpoint, bitdefender):
        api.include_router(module.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def point_collectors():
    """The three collectors' `UPLOAD_FOLDER` at the shared data directory, and Bitdefender's
    `httpx.AsyncClient` at the GravityZone stand-in (everything else httpx does unchanged)."""
    from app.integrations.bitdefender.services import provision as bitdefender
    from app.integrations.crowdstrike.services import provision as crowdstrike
    from app.integrations.defender_for_endpoint.services import provision as defender

    for module in (crowdstrike, defender, bitdefender):
        module.UPLOAD_FOLDER = DATA_DIR

    class Client(httpx.AsyncClient):
        async def post(self, url, *args, **kwargs):
            return await super().post(str(url).replace(GRAVITYZONE, GRAVITYZONE_STUB), *args, **kwargs)

    bitdefender.httpx = types.SimpleNamespace(AsyncClient=Client)


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
        "AWS_ENDPOINT_URL": os.environ["AWS_ENDPOINT_URL"],
        "COPILOT_AWS_PROFILE_CHECK_SECONDS": f"{PROFILE_CHECK[0]},{PROFILE_CHECK[1]}",
        "COPILOT_BACKEND_DATA_DIR": DATA_DIR,
        "COPILOT_BITDEFENDER_URL": GRAVITYZONE_STUB,
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


UUID = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class UuidMap:
    """UUIDs (the content packs' `uuid4()`s) as `<uuid#n>` in order of first appearance, one map
    for a side's outbound requests and state."""

    def __init__(self):
        self.seen = {}

    def sub(self, raw):
        def repl(m):
            return self.seen.setdefault(m.group(0), f"<uuid#{len(self.seen)}>".encode())

        return UUID.sub(repl, raw)

    def out(self, requests):
        return [(m, self.sub(t.encode()).decode(), h, self.sub(b)) for m, t, h, b in requests]


def aws_header(name, value):
    """A botocore header with what depends on the moment or the process masked: the signing time,
    the signature over it, the invocation id, a retry's time to live, the interpreter's patch
    version and the order of the user agent's `m/` features (a set's)."""
    if name == "x-amz-date":
        return "<date>"
    if name == "authorization" and value.startswith("AWS4-HMAC-SHA256"):
        value = re.sub(r"(Credential=[^/]+/)\d{8}/", r"\1<day>/", value)
        return re.sub(r"Signature=[0-9a-f]{64}", "Signature=<sig>", value)
    if name == "amz-sdk-invocation-id":
        return "<uuid>"
    if name == "amz-sdk-request":
        return re.sub(r"ttl=\d{8}T\d{6}Z", "ttl=<ttl>", value)
    if name == "user-agent" and "Botocore/" in value:
        value = re.sub(r"lang/python#3\.11(?:\.\d+)?", "lang/python#3.11", value)
        return re.sub(r" m/([A-Za-z,]+) ", lambda m: " m/" + ",".join(sorted(m.group(1).split(","))) + " ", value)
    return value


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
        headers = [(k, aws_header(k, v)) for k, v in headers]
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
            uuids = UuidMap()
            out = uuids.out(out_norm(out))
            st = uuids.sub(json.dumps(state(), default=str).encode()).decode() if state else None
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


# --- AWS -------------------------------------------------------------------------------------------------

AWS_URL = "/api/aws/provision"
DELETE_URL = "/api/integrations/delete_integration"
SECRET_XML = "par/ity+s3cr&lt;et&gt;&amp;"


def aws_bucket(kind, name, account, key="AKIAPARITY0000000001", secret=SECRET_XML, start="2026-OCT-01", path=None):
    """One `<bucket>` as `build_bucket` writes it (text already XML-escaped)."""
    return (
        f'    <bucket type="{kind}">\n      <name>{name}</name>\n'
        + (f"      <path>{path}</path>\n" if path else "")
        + f"      <access_key>{key}</access_key>\n      <secret_key>{secret}</secret_key>\n"
        f"      <aws_account_id>{account}</aws_account_id>\n      <only_logs_after>{start}</only_logs_after>\n    </bucket>\n"
    )


def aws_ossec(*buckets, disabled="no"):
    """`OSSEC` with an aws-s3 wodle holding `buckets`."""
    wodle = (
        f'  <wodle name="aws-s3">\n    <disabled>{disabled}</disabled>\n    <interval>10m</interval>\n'
        "    <run_on_start>yes</run_on_start>\n    <skip_on_error>yes</skip_on_error>\n" + "".join(buckets) + "  </wodle>\n"
    )
    return OSSEC.replace("  <!-- Policy monitoring -->", wodle + "  <!-- Policy monitoring -->")


OTHER_BUCKET = aws_bucket("cloudtrail", "someone-else", "999999999999", key="AKIAOTHER00000000000", secret="o")
OWN_BUCKETS = (aws_bucket("cloudtrail", BUCKET_A, ACCT_A), aws_bucket("guardduty", BUCKET_A, ACCT_A))


def aws_deployed(services=("cloudtrail", "guardduty")):
    """Customer A's unnamed instance deployed: its metadata row and `deployed`."""
    pairs = lambda prefix: ",".join(f"{svc}:{prefix}-{svc}" for svc in services)  # noqa: E731
    sql(
        "INSERT INTO customer_integrations_meta (customer_code, integration_name, instance_name, graylog_input_id, graylog_index_id, "
        "graylog_stream_id, grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid) VALUES (:c, 'AWS', NULL, NULL, :i, :s, "
        "'7', '71', :d)",
        c=CUST_A,
        i=pairs("is"),
        s=pairs("st"),
        d=pairs("ds"),
    )
    sql("UPDATE customer_integrations SET deployed = 1 WHERE id = :i", i=AWS_A[0])


def set_aws_key(cid, name, value):
    sql("UPDATE integration_auth_keys SET auth_value = :v WHERE subscription_id = :s AND auth_key_name = :n", v=value, s=cid + 100, n=name)


def aws_world(
    version=6,
    config=OSSEC,
    manager=None,
    logs=None,
    graylog=None,
    grafana=None,
    indexer=None,
    aws=None,
    rows_=(AWS_A, AWS_B_BAD, AWS_B_NOKEYS),
    setup=None,
):
    """A fresh world: the AWS integrations re-seeded, no metadata, nothing deployed, the stand-ins
    reset."""

    def before():
        point_tools()
        codes = list(CUSTOMERS) + [CUST_D]
        sql("DELETE FROM customer_integrations_meta WHERE customer_code IN :c", c=codes)
        for row in AWS_ROWS:
            delete_integration(row[0])
        for row in rows_:
            insert_integration(*row)
        sql("UPDATE customer_integrations SET deployed = 0 WHERE id IN :i", i=INT_IDS)
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = '7' WHERE customer_code = :c", c=CUST_A)
        MANAGER.reset(config, 0, manager, logs)
        GRAYLOG.reset(version, **(graylog or {}))
        GRAFANA.reset(grafana)
        INDEXER.reset(indexer)
        AWS.reset(**(aws or {}))
        pin_graylog_version("Graylog", version)
        if setup:
            setup()

    return before


def aws_state():
    codes = list(CUSTOMERS) + [CUST_D]
    return {
        "meta": rows(
            "SELECT customer_code, integration_name, instance_name, graylog_input_id, graylog_index_id, graylog_stream_id, "
            "grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid FROM customer_integrations_meta "
            "WHERE customer_code IN :c ORDER BY id",
            c=codes,
        ),
        "integrations": rows("SELECT id, deployed FROM customer_integrations WHERE id IN :i ORDER BY id", i=INT_IDS),
        "keys": rows(
            "SELECT id, auth_key_name, auth_value FROM integration_auth_keys WHERE id BETWEEN :lo AND :hi ORDER BY id",
            lo=SEED_LO,
            hi=SEED_HI,
        ),
        "ossec": MANAGER.config,
        "graylog": GRAYLOG.state(),
        "grafana": GRAFANA.state(),
    }


def aws_existing_rules(stale=False):
    """Every rule the AWS flow needs, the AWS ones possibly from an older version."""
    from app.integrations.aws.services.provision import aws_rule_sources

    out = [pipeline_rule("r-other", "Other rule", 'rule "Other rule"\nend')]

    for n, title in enumerate(
        (
            "WAZUH CREATE FIELD SYSLOG LEVEL - INFO",
            "WAZUH CREATE FIELD SYSLOG LEVEL - WARNING",
            "WAZUH CREATE FIELD SYSLOG LEVEL - NOTICE",
            "WAZUH CREATE FIELD SYSLOG LEVEL - ALERT",
        ),
    ):
        out.append(pipeline_rule(f"r-wz{n}", title, f'rule "{title}"\nwhen\n  true\nthen\nend'))
    for n, (title, source) in enumerate(aws_rule_sources().items()):
        if stale and title == "AWS ACCOUNT ID":
            source = f'rule "{title}"\nwhen\n  has_field("data_aws_aws_account_id")\nthen\nend'
        elif not stale:
            source = source.replace("\n", "\n  ")
        out.append(pipeline_rule(f"r-aws{n}", title, source, description=None if n else ""))
    return out


async def aws_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    st = aws_state
    body = {"customer_code": CUST_A}
    await p.same("aws: no token", "POST", AWS_URL, json=body)
    await p.same("aws: malformed JSON, no token", "POST", AWS_URL, content=b"{", headers={"Content-Type": "application/json"})
    await p.same("aws: a customer_user token", "POST", AWS_URL, token(ANALYST, ["customer_user"]), json=body)
    await p.same("aws: a list body (the before-validator's TypeError)", "POST", AWS_URL, t_admin, json=[body])
    await p.same("aws: no customer_code", "POST", AWS_URL, t_admin, json={"integration_name": "AWS"})
    await p.same(
        "aws: another customer's analyst (Python's own check)",
        "POST",
        AWS_URL,
        t_analyst_b,
        before=aws_world(),
        state=st,
        json=body,
    )
    await p.same("aws: an unassigned analyst", "POST", AWS_URL, t_unassigned, before=aws_world(), state=st, json=body)
    await p.same("aws: no integration at all", "POST", AWS_URL, t_admin, before=aws_world(), state=st, json={"customer_code": CUST_C})
    await p.same("aws: integrations but no AWS one", "POST", AWS_URL, t_admin, before=aws_world(), state=st, json={"customer_code": CUST_D})
    await p.same(
        "aws: keys Pydantic refuses, every field named",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(),
        state=st,
        json={"customer_code": CUST_B, "instance_name": "bad"},
    )
    await p.same(
        "aws: no auth keys",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(),
        state=st,
        json={"customer_code": CUST_B, "instance_name": "nokeys"},
    )
    await p.same(
        "aws: several instances, none named",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(),
        state=st,
        json={"customer_code": CUST_B},
    )
    await p.same("aws: an unknown instance", "POST", AWS_URL, t_admin, before=aws_world(), state=st, json={**body, "instance_name": "nope"})

    # Deployments.
    await p.same("aws: deployed on Graylog 6 (the wodle created)", "POST", AWS_URL, t_admin, before=aws_world(), state=st, json=body)
    await p.same(
        "aws: deployed on Graylog 7 as the customer's analyst, beside another customer's bucket",
        "POST",
        AWS_URL,
        t_analyst,
        before=aws_world(7, config=aws_ossec(OTHER_BUCKET)),
        state=st,
        rust=p.rs7,
        json={**body, "integration_name": "x", "instance_name": " "},
    )
    await p.same(
        "aws: a re-sync with nothing to change (the manager not written)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(config=aws_ossec(*OWN_BUCKETS), graylog={"rules": aws_existing_rules()}, setup=aws_deployed),
        state=st,
        json=body,
    )
    await p.same(
        "aws: a re-sync dropping GuardDuty (its bucket, stream, index set and datasource removed)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            config=aws_ossec(*OWN_BUCKETS),
            setup=lambda: (aws_deployed(), set_aws_key(AWS_A[0], "SERVICES", "cloudtrail")),
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: a re-sync with a rotated key (the start date kept), stale AWS rules rewritten",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            config=aws_ossec(aws_bucket("cloudtrail", BUCKET_A, ACCT_A, key="AKIAOLD0000000000000", start="2026-JAN-15"), OTHER_BUCKET),
            graylog={"rules": aws_existing_rules(stale=True)},
            setup=lambda: (
                aws_deployed(("cloudtrail",)),
                set_aws_key(AWS_A[0], "SERVICES", "cloudtrail"),
                set_aws_key(AWS_A[0], "ONLY_LOGS_AFTER", " "),
            ),
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the second instance reuses the index set, datasource and folder",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(config=aws_ossec(*OWN_BUCKETS), rows_=(AWS_A, AWS_A_PROD), setup=aws_deployed),
        state=st,
        json={**body, "instance_name": "prod"},
    )
    await p.same(
        "aws: the account another customer has configured",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(rows_=(AWS_A, AWS_B_CLAIM)),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the bucket and account of another instance of the customer",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(rows_=(AWS_A, AWS_A_PROD), setup=lambda: set_aws_key(AWS_A_PROD[0], "BUCKET_NAME", BUCKET_A)),
        state=st,
        json={**body, "instance_name": "prod"},
    )
    await p.same(
        "aws: a hand-made bucket for the account (refused, nothing written)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(config=aws_ossec(aws_bucket("cloudtrail", BUCKET_A, ACCT_A, key="AKIAHAND000000000000"))),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the wodle disabled (a warning)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(config=aws_ossec(OTHER_BUCKET, disabled="yes")),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the exit-23 error after the restart (the notice says so)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(logs={"No profile named": ["2026-10-17T10:00:00Z", "2026-10-17T10:00:00Z", "2026-10-17T11:00:00Z"]}),
        state=st,
        json=body,
    )
    await p.same(
        "aws: a finished run ends the watch early",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            logs={"Fetching logs finished": ["2026-10-17T09:00:00+00:00", "2026-10-17T12:00:00Z"], "No profile named": ["garbage"]},
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: log timestamps that are not ISO (compared as text)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(logs={"No profile named": ["b", "b", "c"]}),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the manager rejects the new ossec.conf",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            manager={
                ("PUT", "/manager/configuration"): (
                    200,
                    "application/json",
                    _json({"data": {"failed_items": [1]}, "message": "bad", "error": 1}),
                ),
            },
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the new ossec.conf does not validate (the original restored)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            manager={
                ("GET", "/manager/configuration/validation"): (
                    200,
                    "application/json",
                    _json(
                        {
                            "data": {"affected_items": [{"name": "node01", "status": "KO"}], "total_failed_items": 0, "failed_items": []},
                            "error": 0,
                        },
                    ),
                ),
            },
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the manager's ossec.conf unreadable",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(manager={("GET", "/manager/configuration"): (500, "application/json", _json({"title": "boom"}))}),
        state=st,
        json=body,
    )
    await p.same(
        "aws: a stale AWS rule Graylog will not update (rolled back)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            graylog={
                "rules": aws_existing_rules(stale=True),
                "overrides": {("PUT", "/api/system/pipelines/rule/*"): (400, "application/json", _json({"message": "parse error"}))},
            },
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the stream refused (index set and buckets rolled back)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(graylog={"overrides": {("POST", "/api/streams"): (500, "application/json", _json({"message": "no"}))}}),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the Grafana folder refused, an undo fails too",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            config=aws_ossec(OTHER_BUCKET),
            grafana={("POST", "/folders"): (409, "application/json", _json({"message": "a folder with the same name"}))},
            graylog={"overrides": {("DELETE", "/api/streams/*"): (500, "application/json", _json({"message": "stream busy"}))}},
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: a datasource refused (folder, streams, index sets and buckets rolled back)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(grafana={("POST", "/datasources"): (400, "application/json", _json({"message": "bad datasource"}))}),
        state=st,
        json=body,
    )

    # The credentials, checked against AWS before anything changes.
    await p.same(
        "aws: the key belongs to another account",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(aws={"account": "999999999999"}),
        state=st,
        json=body,
    )
    bad_key = b"<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>no</Message></Error></ErrorResponse>"
    await p.same(
        "aws: AWS rejects the key",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(aws={"overrides": {("POST", "/"): (403, "text/xml", bad_key)}}),
        state=st,
        json=body,
    )
    await p.same("aws: no such bucket", "POST", AWS_URL, t_admin, before=aws_world(aws={"buckets": ()}), state=st, json=body)
    await p.same(
        "aws: listing denied",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            aws={"overrides": {("GET", f"/{BUCKET_A}"): (403, "application/xml", _s3_error("AccessDenied", "Access Denied"))}},
        ),
        state=st,
        json=body,
    )
    await p.same("aws: no logs at all", "POST", AWS_URL, t_admin, before=aws_world(aws={"objects": {}}), state=st, json=body)
    await p.same(
        "aws: only archived logs (a warning)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            aws={
                "objects": {
                    f"AWSLogs/{ACCT_A}/CloudTrail/eu-west-1/2025/01/01/old.json.gz": (10, "GLACIER"),
                    f"AWSLogs/{ACCT_A}/GuardDuty/eu-west-1/2025/01/01/old.jsonl.gz": (10, "DEEP_ARCHIVE"),
                },
            },
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: reading denied by KMS",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            aws={"overrides": {("GET", f"/{BUCKET_A}/*"): (403, "application/xml", _s3_error("AccessDenied", "kms:Decrypt denied"))}},
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: STS answers something that is not XML (ResponseParserError, a bare 500)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(aws={"overrides": {("POST", "/"): (200, "text/xml", b"not xml")}}),
        state=st,
        json=body,
    )
    await p.same(
        "aws: STS throttles twice, then answers",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            aws={
                "overrides": {
                    ("POST", "/"): [
                        (400, "text/xml", b"<ErrorResponse><Error><Code>Throttling</Code><Message>slow</Message></Error></ErrorResponse>"),
                        (503, "text/xml", b""),
                        (200, "text/xml", _sts(ACCT_A)),
                    ],
                },
            },
        ),
        state=st,
        json=body,
    )
    await p.same(
        "aws: the bucket in another region (HEAD's 301, redirected)",
        "POST",
        AWS_URL,
        t_admin,
        before=aws_world(
            aws={
                "overrides": {
                    ("HEAD", f"/{BUCKET_A}"): [
                        (301, {"x-amz-bucket-region": "ap-south-1"}, b""),
                        (200, {"x-amz-bucket-region": "ap-south-1"}, b""),
                    ],
                },
            },
        ),
        state=st,
        json=body,
    )

    # The delete of a deployed instance (Rust's own since this port).
    delete = {"customer_code": CUST_A, "integration_name": "AWS"}
    await p.same(
        "aws delete: a deployed instance (its buckets, streams, index sets, datasources and folder)",
        "DELETE",
        DELETE_URL,
        t_admin,
        before=aws_world(config=aws_ossec(*OWN_BUCKETS, OTHER_BUCKET), setup=aws_deployed),
        state=st,
        json=delete,
    )
    await p.same(
        "aws delete: a sibling instance still collects CloudTrail (its index set kept)",
        "DELETE",
        DELETE_URL,
        t_admin,
        before=aws_world(
            config=aws_ossec(*OWN_BUCKETS, aws_bucket("cloudtrail", BUCKET_B, ACCT_A, key="AKIAPARITY0000000002", secret="s2")),
            rows_=(AWS_A, AWS_A_PROD),
            setup=lambda: (
                aws_deployed(),
                sql(
                    "INSERT INTO customer_integrations_meta (customer_code, integration_name, instance_name, graylog_input_id, "
                    "graylog_index_id, graylog_stream_id, grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid) "
                    "VALUES (:c, 'AWS', 'prod', NULL, 'cloudtrail:is-cloudtrail', 'cloudtrail:st-prod', '7', '71', 'cloudtrail:ds-cloudtrail')",
                    c=CUST_A,
                ),
            ),
        ),
        state=st,
        json=delete,
    )
    await p.same(
        "aws delete: the manager unreadable (a warning, the settings removed)",
        "DELETE",
        DELETE_URL,
        t_admin,
        before=aws_world(
            config=aws_ossec(*OWN_BUCKETS),
            manager={("GET", "/manager/configuration"): (500, "application/json", _json({"title": "boom"}))},
            setup=aws_deployed,
        ),
        state=st,
        json=delete,
    )


# --- CrowdStrike, Defender for Endpoint, Bitdefender -----------------------------------------------------


def collectors(version=6, graylog=None, grafana=None, gravityzone_text=False, setup=None):
    """A fresh world: the collectors' integrations re-seeded, no network-connector metadata,
    nothing deployed, the data directory empty, the stand-ins reset."""

    def before():
        point_tools()
        codes = list(CUSTOMERS) + [CUST_D]
        sql("DELETE FROM customer_network_connectors_meta WHERE customer_code IN :c", c=codes)
        for row in COLLECTOR_ROWS:
            delete_integration(row[0])
            insert_integration(*row)
        sql("UPDATE customersmeta SET customer_meta_grafana_org_id = '7' WHERE customer_code = :c", c=CUST_A)
        shutil.rmtree(DATA_PARENT, ignore_errors=True)
        os.makedirs(DATA_DIR)
        GRAYLOG.reset(version, **(graylog or {}))
        GRAFANA.reset(grafana)
        INDEXER.reset()
        GRAVITYZONE_TOOL.reset(gravityzone_text)
        pin_graylog_version("Graylog", version)
        if setup:
            setup()

    return before


def files_under(root):
    """Every directory and file under `root`, its bytes as text."""
    out = {}
    for base, dirs, names in sorted(os.walk(root)):
        dirs.sort()
        rel = os.path.relpath(base, root)
        out[rel + "/"] = None
        for name in sorted(names):
            with open(os.path.join(base, name), "rb") as f:
                out[os.path.join(rel, name)] = f.read().decode("utf-8", "replace")
    return out


def collector_state():
    codes = list(CUSTOMERS) + [CUST_D]
    return {
        "meta": rows(
            "SELECT customer_code, network_connector_name, graylog_input_id, graylog_index_id, graylog_stream_id, "
            "graylog_pipeline_id, graylog_content_pack_input_id, graylog_content_pack_stream_id, grafana_org_id, "
            "grafana_dashboard_folder_id, grafana_datasource_uid FROM customer_network_connectors_meta "
            "WHERE customer_code IN :c ORDER BY id",
            c=codes,
        ),
        "integrations": rows("SELECT id, deployed FROM customer_integrations WHERE id IN :i ORDER BY id", i=COLLECTOR_IDS),
        "files": files_under(DATA_PARENT),
        "graylog": GRAYLOG.state(),
        "grafana": GRAFANA.state(),
    }


def set_collector_name(cid, name):
    def setup():
        sql("UPDATE customer_integrations SET customer_name = :n WHERE id = :i", n=name, i=cid)

    return setup


async def collector_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    st = collector_state
    cs, dfe, bd = "/api/crowdstrike/provision", "/api/defender_for_endpoint/provision", "/api/bitdefender/provision"
    a = {"customer_code": CUST_A}
    await p.same("crowdstrike: no token", "POST", cs, json=a)
    await p.same("crowdstrike: malformed JSON, no token", "POST", cs, content=b"{", headers={"Content-Type": "application/json"})
    await p.same("crowdstrike: a customer_user token", "POST", cs, token(ANALYST, ["customer_user"]), json=a)
    await p.same("crowdstrike: a list body (the before-validator's TypeError)", "POST", cs, t_admin, json=[a])
    await p.same("defender: a string body", "POST", dfe, t_admin, json="x")
    await p.same("bitdefender: no customer_code", "POST", bd, t_admin, json={"hot_data_retention": 3})
    await p.same("bitdefender: a retention Pydantic refuses", "POST", bd, t_admin, json={**a, "hot_data_retention": "x"})
    await p.same(
        "crowdstrike: a customer without integrations",
        "POST",
        cs,
        t_admin,
        before=collectors(),
        state=st,
        json={"customer_code": f"RPX{SFX}"},
    )
    await p.same(
        "crowdstrike: only another integration (the AttributeError of None)",
        "POST",
        cs,
        t_admin,
        before=collectors(),
        state=st,
        json={"customer_code": CUST_D},
    )
    await p.same("crowdstrike: a port int() refuses", "POST", cs, t_admin, before=collectors(), state=st, json={"customer_code": CUST_B})
    await p.same("bitdefender: keys Pydantic refuses", "POST", bd, t_admin, before=collectors(), state=st, json={"customer_code": CUST_B})
    await p.same(
        "defender: no keys under the service",
        "POST",
        dfe,
        t_admin,
        before=collectors(setup=lambda: sql("DELETE FROM integration_auth_keys WHERE subscription_id = :s", s=7_860_132)),
        state=st,
        json=a,
    )
    await p.same("crowdstrike: no Grafana organization", "POST", cs, t_admin, before=collectors(), state=st, json={"customer_code": CUST_C})
    await p.same(
        "crowdstrike: a null retention (the details' model)",
        "POST",
        cs,
        t_admin,
        before=collectors(),
        state=st,
        json={**a, "hot_data_retention": None},
    )
    await p.same(
        "crowdstrike: another tenant's customer [Python provisions it]",
        "POST",
        cs,
        t_analyst,
        before=collectors(),
        state=st,
        expect=(400, 403),
        json={"customer_code": CUST_B},
    )
    await p.same(
        "defender: an analyst without customers",
        "POST",
        dfe,
        t_unassigned,
        before=collectors(),
        state=st,
        expect=(200, 403),
        json=a,
    )
    for version, rust in ((6, None), (7, p.rs7)):
        await p.same(
            f"crowdstrike: provisioned (Graylog {version})",
            "POST",
            cs,
            t_analyst,
            before=collectors(version),
            state=st,
            rust=rust,
            json={**a, "hot_data_retention": 7, "index_replicas": "1", "integration_name": "ignored"},
        )
        await p.same(
            f"defender: provisioned (Graylog {version})",
            "POST",
            dfe,
            t_admin,
            before=collectors(version),
            state=st,
            rust=rust,
            json=a,
        )
        await p.same(
            f"bitdefender: provisioned (Graylog {version})",
            "POST",
            bd,
            t_admin,
            before=collectors(version),
            state=st,
            rust=rust,
            json=a,
        )
    await p.same(
        "crowdstrike: a name with spaces and quotes",
        "POST",
        cs,
        t_admin,
        before=collectors(setup=set_collector_name(7_860_031, 'Ä "Big" Co')),
        state=st,
        json=a,
    )
    await p.same(
        "bitdefender: GravityZone answers a text (the JSONDecodeError, after everything)",
        "POST",
        bd,
        t_admin,
        before=collectors(gravityzone_text=True),
        state=st,
        json=a,
    )
    await p.same(
        "bitdefender: a webserver port int() refuses (after the docker-compose file)",
        "POST",
        bd,
        t_admin,
        before=collectors(
            setup=lambda: sql(
                "UPDATE integration_auth_keys SET auth_value = 'PORT' WHERE subscription_id = :s AND auth_key_name = 'WEBSERVER_PORT'",
                s=7_860_133,
            ),
        ),
        state=st,
        json=a,
    )
    await p.same(
        "crowdstrike: the stream missing (Graylog's 404 after the content packs)",
        "POST",
        cs,
        t_admin,
        before=collectors(graylog={"overrides": {("GET", "/api/streams"): (200, "application/json", _json({"streams": [], "total": 0}))}}),
        state=st,
        json=a,
    )
    await p.same(
        "crowdstrike: a name with '/' [Python: Graylog and Grafana provisioned, then FileNotFoundError]",
        "POST",
        cs,
        t_admin,
        before=collectors(setup=set_collector_name(7_860_031, "A/S name")),
        state=st,
        expect=(500, 400),
        json=a,
    )
    await p.same(
        "defender: the name '..' [Python writes next to the data directory]",
        "POST",
        dfe,
        t_admin,
        before=collectors(setup=set_collector_name(7_860_032, "..")),
        state=st,
        expect=(200, 400),
        json=a,
    )


# --- Main ------------------------------------------------------------------------------------------------


async def main():
    servers = [start_stub(STUB_PORT, TOOLS), start_stub(INDEXER_PORT, INDEXER), start_stub(AWS_PORT, AWS)]
    from app.integrations.aws.services import wazuh_manager as aws_manager

    aws_manager.PROFILE_CHECK_INTERVAL_SECONDS, aws_manager.PROFILE_CHECK_TIMEOUT_SECONDS = PROFILE_CHECK
    procs = []
    python = None
    try:
        seed()
        point_collectors()
        python = start_python(PY_PORT)
        procs.append(start_rust(RS_PORT))
        procs.append(start_rust(RS7_PORT))
        p = Pair()
        t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
        t_analyst_b, t_unassigned = token(ANALYST_B, ["analyst"]), token(UNASSIGNED, ["analyst"])
        try:
            sections = os.environ.get("REMAINING_PROV_PARITY_SECTIONS", "office365,aws,collectors").split(",")
            if "office365" in sections:
                await office365_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned)
            if "aws" in sections:
                await aws_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned)
            if "collectors" in sections:
                await collector_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned)
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
