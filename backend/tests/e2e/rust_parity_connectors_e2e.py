"""Parity of the Rust connector core and Wazuh connectors with this backend — NOT
collected by pytest (needs a live MySQL and a running Rust binary; run by
scripts/rust-parity.sh).

Sends the same requests to the real FastAPI routers (in-process) and to the Rust
service (`crates/copilot-connectors`, `crates/copilot-wazuh`) over HTTP, both on the
same disposable database, and compares status codes, JSON bodies (key order
included), the rows each write leaves, and every request each backend sends to the
Wazuh indexer and manager: both connectors point at local stand-ins (an OpenSearch
REST API and the Wazuh manager API with its token flow) that record what arrives.

It also checks the connector cache's cross-process guarantee: a row written behind a
process's back (here: by SQL) stops being used by that process within
`CONNECTOR_CACHE_CHECK_SECONDS`.

    PARITY_SUITES=tests/e2e/rust_parity_connectors_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
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
from urllib.parse import unquote

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.connectors import cache as connector_cache  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402

RUST = os.environ.get("RUST_BASE_URL", "http://127.0.0.1:5199")
SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"CON_A{SFX}", f"CON_B{SFX}"
ADMIN, ANALYST, PORTAL = f"con_admin{SFX}", f"con_analyst{SFX}", f"con_portal{SFX}"
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


# --- The Wazuh indexer and manager stand-ins -------------------------------------
# One recorder per tool. Each answers from a function of the request, so both
# backends get the same answers; every request is kept for the comparison.
#: Headers a client adds on its own (urllib3, aiohttp, requests and reqwest differ
#: there, and none of them reaches Wazuh's logic) and the stub's port.
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
    def __init__(self, answer, name="r"):
        self.answer = answer
        self.name = name
        self.captured = []
        self.mode = {}
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k.lower(): v for k, v in self.headers.items() if k.lower() not in TRANSPORT_HEADERS}
                recorder.captured.append({"method": self.command, "path": self.path, "headers": headers, "body": body})
                status, ctype, payload, reason = recorder.answer(recorder, self.command, self.path, headers, body)
                self.send_response(status, reason)
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

            def process_request(self, request, client_address):
                recorder.sockets.append(request)
                super().process_request(request, client_address)

        self.sockets = []
        self.server = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        """Go away as a crashed service does: no listener, open connections reset."""
        self.server.shutdown()
        self.server.server_close()
        for sock in self.sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except OSError:
                pass


#: A UTC timestamp a backend computed at call time: digits masked, shape kept.
TS_PATTERN = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?")
#: An object address in a Python exception text (urllib3 prints its connection).
ADDR_PATTERN = re.compile(r"object at 0x[0-9a-f]+")


def mask_text(s):
    s = TS_PATTERN.sub(lambda m: re.sub(r"\d", "0", m.group(0)), s)
    return ADDR_PATTERN.sub("object at 0x", s)


def normalised(captures, unordered=False):
    out = []
    for c in captures:
        out.append(
            {
                "method": c["method"],
                "path": mask_text(c["path"]),
                "headers": dict(sorted(c["headers"].items())),
                "body": mask_text(c["body"].decode("utf-8", "replace")),
            },
        )
    if unordered:
        out.sort(key=json.dumps)
    return out


def jbody(obj):
    return json.dumps(obj).encode()


ES_USER, ES_PASS = "parity-indexer", f"pw-{SFX}"
IDX_A = f"wazuh_{CUST_A.lower()}"
IDX_B = f"wazuh_{CUST_B.lower()}"
ALIASES = [
    "wazuh-alerts-4.x-2026.10.15",
    f"{IDX_A}_1",
    f"{IDX_A}_2",
    f"{IDX_B}_1",
    "nomap_0",
    ".kibana_1",
    "wazuh-monitoring-2026.10",
    "gl-events_0",
    "graylog_deflector",
]


def hit(index, doc_id, **source):
    return {"_index": index, "_type": "_doc", "_id": doc_id, "_score": None, "_source": source, "sort": [1760572800000]}


def es_hits(index, mode):
    if index == "nomap_0":
        return [hit(index, "n1", agent_name="dc01", rule_description="Late alert", timestamp="2026-10-15T12:00:00Z", level=1.5)]
    if index.startswith(IDX_A):
        agent = 5 if mode.get("bad_agent") else "dc01"
        return [
            hit(index, "a1", agent_name="dc01", rule_description="Mimikatz é", syslog_level="ALERT", big=12345678901234, ratio=0.1),
            hit(index, "a2", agent_name=agent, rule_description="Mimikatz é", syslog_level="ALERT", nested={"x": [1, None, True]}),
            hit(index, "a3", agent_name="web01", rule_description="Brute force", syslog_level="ALERT"),
        ]
    if index.startswith(IDX_B):
        return [hit(index, "b1", agent_name="beta-host", rule_description="Other tenant", syslog_level="ALERT")]
    if index.startswith("wazuh-alerts"):
        return [] if mode.get("no_alerts") else [hit(index, "w1", agent_name="dc01", rule_description="Login")]
    return []


GL_HITS = [
    {"_id": "e1", "_source": {"origin_context": f"urn:graylog:message:es:{IDX_A}_1:a1"}},
    {"_id": "e2", "_source": {"origin_context": f"urn:graylog:message:es:{IDX_B}_1:b1"}},
    {"_id": "e3", "_source": {"origin_context": f"urn:graylog:message:es:{IDX_A}_1:gone"}},
    {"_id": "e4", "_source": {"origin_context": None}},
    {"_id": "e5", "_source": {"origin_context": "no-colon"}},
    {"_id": "e6", "_source": {}},
]


def es_error(status, etype, reason, **extra):
    root = {"type": etype, "reason": reason, **extra}
    return (
        status,
        "application/json; charset=UTF-8",
        jbody({"error": {"root_cause": [root], "type": etype, "reason": reason}, "status": status}),
        None,
    )


def es_answer(rec, method, raw_path, headers, body):
    mode = rec.mode
    path, _, query = raw_path.partition("?")
    expected = "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode("latin-1")).decode()
    if headers.get("authorization") != expected:
        return es_error(401, "security_exception", "missing authentication credentials for REST request [/]")
    if mode.get("busy"):
        return 503, "application/json; charset=UTF-8", jbody({"error": "busy", "status": 503}), None
    ok = lambda obj: (200, "application/json; charset=UTF-8", jbody(obj), None)  # noqa: E731
    if method == "GET" and path == "/*/_alias":
        return ok({name: {"aliases": {}} for name in ALIASES})
    if method == "POST" and path.endswith("/_search"):
        index = unquote(path[1:].rsplit("/", 1)[0])
        doc = json.loads(body or b"{}")
        if index.startswith("gl-events"):
            return ok({"took": 1, "hits": {"total": {"value": len(GL_HITS), "relation": "eq"}, "hits": GL_HITS}})
        sort = next(iter(doc.get("sort", [{}])[0]), None)
        if index == "nomap_0" and sort == "timestamp_utc":
            return es_error(400, "search_phase_execution_exception", "No mapping found for [timestamp_utc] in order to sort on")
        if mode.get("broken") and index == f"{IDX_A}_1":
            return es_error(400, "parse_exception", "failed to parse date field [now-x]")
        hits_ = es_hits(index, mode)
        return ok(
            {"took": 2, "timed_out": False, "hits": {"total": {"value": len(hits_), "relation": "eq"}, "max_score": None, "hits": hits_}},
        )
    if method == "GET" and "/_doc/" in path:
        index, _, doc_id = path[1:].partition("/_doc/")
        index, doc_id = unquote(index), unquote(doc_id)
        for h in es_hits(index, mode):
            if h["_id"] == doc_id:
                return ok({"_index": index, "_id": doc_id, "_version": 1, "found": True, "_source": h["_source"]})
        if index == "missing-index":
            return es_error(
                404,
                "index_not_found_exception",
                "no such index [missing-index]",
                **{"resource.type": "index_or_alias", "resource.id": "missing-index", "index": "missing-index"},
            )
        return 404, "application/json; charset=UTF-8", jbody({"_index": index, "_id": doc_id, "found": False}), None
    if method == "GET" and path == "/_cluster/health":
        health = {
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
            "unassigned_shards": 1,
            "delayed_unassigned_shards": 0,
            "number_of_pending_tasks": 0,
            "number_of_in_flight_fetch": 0,
            "task_max_waiting_in_queue_millis": 0,
            "active_shards_percent_as_number": 95.23809523809524,
        }
        if mode.get("health_missing"):
            health.pop("discovered_cluster_manager")
        return ok(health)
    if method == "GET" and path == "/_cat/allocation":
        if mode.get("html"):
            return 200, "text/html", b"<html>nope</html>", None
        return ok(
            [
                {
                    "shards": "10",
                    "disk.indices": "1gb",
                    "disk.used": "10gb",
                    "disk.avail": "90gb",
                    "disk.total": "100gb",
                    "disk.percent": "10",
                    "host": "10.0.0.1",
                    "ip": "10.0.0.1",
                    "node": "node-1",
                },
                {
                    "shards": "2",
                    "disk.indices": None,
                    "disk.used": None,
                    "disk.avail": None,
                    "disk.total": None,
                    "disk.percent": None,
                    "host": None,
                    "ip": None,
                    "node": "UNASSIGNED",
                },
            ],
        )
    if method == "GET" and path == "/_cat/indices":
        rows = []
        for i, name in enumerate(ALIASES):
            rows.append(
                {
                    "health": "green" if i % 3 else "yellow",
                    "status": "open",
                    "index": name,
                    "uuid": f"u{i}",
                    "pri": "1",
                    "rep": str(i % 2),
                    "docs.count": str(10 * i) if i != 4 else None,
                    "docs.deleted": "0",
                    "store.size": ["1.2mb", "500kb", "1gb", "12b", None, "3.5gb", "7", "0b", "1.5tb"][i],
                    "pri.store.size": "1kb",
                },
            )
        return ok(rows)
    if method == "GET" and path == "/_cat/shards":
        return ok(
            [
                {
                    "index": f"{IDX_A}_1",
                    "shard": "0",
                    "prirep": "p",
                    "state": "STARTED",
                    "docs": "12",
                    "store": "1.2mb",
                    "ip": "10.0.0.1",
                    "node": "node-1",
                },
                {
                    "index": f"{IDX_A}_1",
                    "shard": "0",
                    "prirep": "r",
                    "state": "UNASSIGNED",
                    "docs": None,
                    "store": None,
                    "ip": None,
                    "node": None,
                },
            ],
        )
    if method == "PUT" and path == "/wazuh*/_settings":
        return ok({"acknowledged": True})
    if method == "GET" and path == "/_snapshot":
        return ok(
            {"backup": {"type": "fs", "settings": {"location": "/mnt/backup", "compress": "true"}}, "s3": {"settings": {"bucket": "b"}}},
        )
    if method == "GET" and path.endswith("/_status"):
        if mode.get("bad_status"):
            return ok(
                {
                    "snapshots": [
                        {
                            "snapshot": "snap1",
                            "repository": "backup",
                            "state": "SUCCESS",
                            "indices": {"i": {"shards": {"0": {"stats": {}}}}},
                        },
                    ],
                },
            )
        if path == "/_snapshot/_all/_all/_status":
            return ok({"snapshots": []})
        return ok(
            {
                "snapshots": [
                    {
                        "snapshot": "snap1",
                        "repository": "backup",
                        "uuid": "uu-1",
                        "state": "SUCCESS",
                        "include_global_state": True,
                        "shards_stats": {"initializing": 0, "started": 0, "finalizing": 0, "done": 1, "failed": 0, "total": 1},
                        "stats": {"incremental": {"file_count": 3, "size_in_bytes": 1024}, "start_time_in_millis": 1, "time_in_millis": 5},
                        "indices": {
                            f"{IDX_A}_1": {
                                "shards_stats": {"done": 1, "total": 1},
                                "stats": {"total": {"file_count": 3}},
                                "shards": {
                                    "0": {
                                        "stage": "DONE",
                                        "stats": {"total": {"file_count": 3}},
                                        "total_file_count": 3,
                                        "done_size_in_bytes": 77,
                                    },
                                },
                            },
                        },
                    },
                ],
            },
        )
    if method == "GET" and path.startswith("/_snapshot/") and path.endswith("/_all"):
        repo = unquote(path.split("/")[2])
        if repo == "missing":
            return es_error(404, "repository_missing_exception", "[missing] missing")
        return ok(
            {
                "snapshots": [
                    {
                        "snapshot": f"scheduled_nightly_{SFX}_20261001_000000",
                        "uuid": "uu-1",
                        "version_id": 136327827,
                        "version": "2.11.0",
                        "indices": [f"{IDX_A}_1", "wazuh-alerts-4.x-2026.10.15"],
                        "data_streams": [],
                        "include_global_state": False,
                        "state": "SUCCESS",
                        "start_time": "2026-10-01T00:00:00.000Z",
                        "start_time_in_millis": 1759276800000,
                        "end_time": "2026-10-01T00:00:05.000Z",
                        "end_time_in_millis": 1759276805000,
                        "duration_in_millis": 5000,
                        "failures": [],
                        "shards": {"total": 2, "failed": 0, "successful": 2},
                    },
                    {"snapshot": "partial-one", "state": "PARTIAL", "indices": [], "failures": [{"index": "x", "reason": "boom"}]},
                ],
            },
        )
    if method == "PUT" and path.startswith("/_snapshot/"):
        if "wait_for_completion=true" in query:
            doc = json.loads(body or b"{}")
            return ok(
                {
                    "snapshot": {
                        "snapshot": path.split("/")[3],
                        "uuid": "uu-new",
                        "state": "SUCCESS",
                        "indices": (doc.get("indices") or "").split(","),
                        "shards": {"total": 4, "failed": 0, "successful": 4},
                    },
                },
            )
        return ok({"accepted": not mode.get("refuse")})
    if method == "POST" and path.endswith("/_restore"):
        return ok({"accepted": True})
    return 404, "text/plain", b"no stub for " + raw_path.encode(), None


MGR_USER, MGR_PASS = "parity-wazuh", f"mgr-{SFX}"
MGR_PASS2 = f"mgr2-{SFX}"
RULES = [
    {
        "filename": "0010-rules_config.xml",
        "relative_dirname": "ruleset/rules",
        "id": 1,
        "level": 0,
        "status": "enabled",
        "details": {"category": "syslog", "noalert": "1"},
        "pci_dss": [],
        "gpg13": [],
        "gdpr": [],
        "hipaa": [],
        "nist-800-53": ["AU.6"],
        "tsc": [],
        "mitre": [],
        "groups": ["syslog"],
        "description": "Generic template for all syslog rules.",
    },
    {
        "filename": "local_rules.xml",
        "relative_dirname": "etc/rules",
        "id": "100001",
        "level": 5.0,
        "status": "enabled",
        "description": "Local é",
        "extra": True,
    },
]
MITRE = {
    "tactics": [
        {
            "description": "The adversary is trying to get in.",
            "name": "Initial Access",
            "id": "TA0001",
            "modified_time": "2019-07-19T17:41:41.425000Z",
            "created_time": "2018-10-17T00:14:20.652000Z",
            "short_name": "initial-access",
            "techniques": ["T1078", "T1566"],
            "references": ["https://attack.mitre.org/tactics/TA0001"],
            "url": "https://attack.mitre.org/tactics/TA0001",
            "source": "mitre-attack",
            "external_id": "TA0001",
        },
    ],
    "techniques": [
        {
            "description": "Valid accounts.",
            "name": "Valid Accounts",
            "id": "attack-pattern--b17a1a56",
            "modified_time": "2023-04-03T18:55:00Z",
            "created_time": "2017-05-31T21:31:00Z",
            "tactics": ["TA0001", "TA0003"],
            "url": "https://attack.mitre.org/techniques/T1078",
            "source": "mitre-attack",
            "external_id": "T1078",
            "references": [{"url": "https://example.test/a", "description": "A", "source": "mitre-attack"}, {"url": "u", "source": "s"}],
            "mitigations": ["M1026"],
            "mitre_version": "2.6",
            "deprecated": 0,
            "platforms": ["Windows"],
        },
        {
            "description": "Domain accounts.",
            "name": "Domain Accounts",
            "id": "attack-pattern--c3d4",
            "modified_time": "2023-04-03T18:55:00Z",
            "created_time": "2020-03-13T20:21:54Z",
            "tactics": ["TA0001"],
            "url": "https://attack.mitre.org/techniques/T1078/002",
            "source": "mitre-attack",
            "external_id": "T1078.002",
            "subtechnique_of": "attack-pattern--b17a1a56",
            "remote_support": True,
        },
    ],
    "software": [
        {
            "mitre_version": "1.0",
            "description": "Mimikatz.",
            "name": "Mimikatz",
            "id": "tool--afc079f3",
            "modified_time": "2023-03-22T03:43:58Z",
            "created_time": "2017-05-31T21:32:31Z",
            "groups": ["G0007"],
            "techniques": ["T1003"],
            "url": "https://attack.mitre.org/software/S0002",
            "source": "mitre-attack",
            "external_id": "S0002",
            "type": "tool",
            "aliases": ["Mimikatz"],
        },
    ],
    "references": [
        {"url": "https://example.test/r", "description": "R", "source": "mitre-attack", "id": "T1078", "type": "technique"},
        {"url": "x", "source": "y"},
    ],
    "mitigations": [
        {
            "description": "Use MFA.",
            "name": "Multi-factor Authentication",
            "id": "course-of-action--b5dbb4c5",
            "modified_time": "2023-03-30T21:01:44Z",
            "created_time": "2019-06-10T20:53:36Z",
            "techniques": ["T1078"],
            "url": "https://attack.mitre.org/mitigations/M1032",
            "source": "mitre-attack",
            "external_id": "M1032",
        },
    ],
    "groups": [
        {
            "name": "APT28",
            "id": "intrusion-set--bef4c620",
            "modified_time": "2024-01-01T00:00:00Z",
            "created_time": "2017-05-31T21:31:48Z",
            "software": ["S0002"],
            "url": "https://attack.mitre.org/groups/G0007",
            "external_id": "G0007",
            "source": "mitre-attack",
            "aliases": ["Sofacy"],
            "country": None,
        },
    ],
}


def wazuh_items(items, **extra):
    return {
        "data": {"affected_items": items, "total_affected_items": len(items), "total_failed_items": 0, "failed_items": [], **extra},
        "message": "All selected items were returned",
        "error": 0,
    }


def mgr_answer(rec, method, raw_path, headers, body):
    mode = rec.mode
    path, _, query = raw_path.partition("?")
    gen = mode.get("gen", 1)
    tok = f"tok-{rec.name}-{gen}"
    ok = lambda obj, ctype="application/json": (200, ctype, jbody(obj), None)  # noqa: E731

    def err(status, title, detail):
        return status, "application/problem+json; charset=utf-8", jbody({"title": title, "detail": detail, "error": status}), None

    if path == "/security/user/authenticate":
        accepted = {"Basic " + base64.b64encode(f"{MGR_USER}:{pw}".encode("latin-1")).decode() for pw in (MGR_PASS, MGR_PASS2)}
        if mode.get("reject_auth") or headers.get("authorization") not in accepted:
            return err(401, "Unauthorized", "Invalid credentials")
        return ok({"data": {"token": tok}, "error": 0})
    if headers.get("authorization") != f"Bearer {tok}":
        return err(401, "Unauthorized", "The server could not verify that you are authorized to access the URL requested")
    if mode.get("fail") and path.startswith(mode["fail"]):
        return 500, "text/html", b"<html>boom</html>", None
    if method == "GET" and path == "/rules":
        if mode.get("rules_list"):
            return ok({"data": [1, 2], "error": 0})
        rules = RULES + (
            [{"filename": "x", "relative_dirname": "y", "id": 2, "level": "high", "status": "enabled", "description": "bad"}]
            if mode.get("bad_rule")
            else []
        )
        return ok(wazuh_items(rules))
    if method == "GET" and path == "/rules/files":
        return ok(
            wazuh_items(
                [
                    {"filename": "0010-rules_config.xml", "relative_dirname": "ruleset/rules", "status": "enabled"},
                    {"filename": "local_rules.xml", "relative_dirname": "etc/rules", "status": "enabled", "x": 1},
                ],
            ),
        )
    if path.startswith("/rules/files/"):
        name = unquote(path[len("/rules/files/") :])
        if method == "PUT":
            if mode.get("upload_400"):
                return err(400, "Bad Request", "Invalid XML")
            return ok(
                {
                    "data": {"affected_items": [name], "total_affected_items": 1, "failed_items": []},
                    "message": "File was successfully updated",
                    "error": 0,
                },
            )
        if name.startswith("missing"):
            return err(404, "Not Found", f"File {name} does not exist")
        if "raw=True" in query:
            if mode.get("latin1"):
                return 200, "text/plain", "<group>ä</group>".encode(), None
            return (
                200,
                "application/xml; charset=utf-8",
                f'<group name="local">\n  <rule id="100001" level="5">é {name}</rule>\n</group>\n'.encode(),
                None,
            )
        if name.startswith("empty"):
            return ok(wazuh_items([]))
        return ok(wazuh_items([{"group": {"@name": "local", "rule": [{"@id": "100001", "@level": "5"}]}}]))
    if method == "GET" and path == "/groups":
        return ok(
            wazuh_items(
                [
                    {"name": "default", "count": 2, "mergedSum": "abc", "configSum": "def", "x": 1},
                    {"name": "linux", "count": "0", "configSum": "x"},
                ],
            ),
        )
    if path.startswith("/groups/"):
        parts = path.split("/")
        group = unquote(parts[2])
        if group.startswith("nogroup"):
            return err(404, "Not Found", f"Group {group} does not exist")
        if method == "GET" and len(parts) == 4 and parts[3] == "files":
            return ok(wazuh_items([{"filename": "agent.conf", "hash": "ab12"}, {"filename": "merged.mg", "hash": "cd34"}]))
        if method == "GET" and len(parts) == 5:
            if "raw=True" in query:
                return 200, "application/xml; charset=utf-8", b"<agent_config>\n  <labels/>\n</agent_config>\n", None
            return ok(wazuh_items([{"agent_config": [{"labels": {"label": [{"key": "customer", "item": "acme"}]}}]}]))
        if method == "PUT" and parts[3] == "configuration":
            if mode.get("config_400"):
                return err(400, "Bad Request", "Wrong XML syntax")
            return ok(
                {
                    "data": {"affected_items": [group], "total_affected_items": 1},
                    "message": "Agent configuration was successfully updated",
                    "error": 0,
                },
            )
    if method == "GET" and path.startswith("/mitre/"):
        what = path[len("/mitre/") :]
        items = [dict(i) for i in MITRE.get(what, [])]
        if mode.get("bad_mitre"):
            items.append({"name": "broken"})
        return ok(wazuh_items(items))
    if method == "GET" and path == "/cluster/status":
        return ok({"data": {"enabled": mode.get("cluster", "no"), "running": "no"}, "error": 0})
    if method == "PUT" and path in ("/manager/restart", "/cluster/restart"):
        if mode.get("restart_400"):
            return err(400, "Bad Request", "Restart refused")
        return ok({"data": {"affected_items": ["node01"], "total_affected_items": 1}, "message": "Restart request sent", "error": 0})
    return 404, "text/plain", b"no stub for " + raw_path.encode(), None


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors
    from app.routers import wazuh_indexer
    from app.routers import wazuh_manager

    api = APIRouter(prefix="/api")
    api.include_router(connectors.router)
    api.include_router(wazuh_indexer.router)
    api.include_router(wazuh_manager.router)
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


async def seed():
    for c in (CUST_A, CUST_B):
        await sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=c, n=f"{c} Corp")
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        await sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r)",
            n=name,
            e=f"{name}@parity.test",
            r=role,
        )
    for name in (ANALYST, PORTAL):
        await sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
            "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )


async def add_connector(name, url, username=None, password=None, api_key=None, verified=0):
    r = await sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
        "(:n, '4.8.0', :u, '2026-01-02 03:04:05', :user, :pw, :key, 'Parity connector', 'everything', 1, :v, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
        key=api_key,
        v=verified,
    )
    return r.lastrowid


async def main():
    await seed()
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    t_admin = token(ADMIN, ["admin"])
    t_analyst = token(ANALYST, ["analyst"])
    t_portal = token(PORTAL, ["customer_user"])
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    def body_of(r):
        try:
            return r.json()
        except ValueError:
            return r.text

    async def call(client, method, path, tok=None, body=None, raw=None, ctype="application/json", files=None):
        kw = {"headers": H(tok)}
        if raw is not None:
            kw["content"] = raw
            kw["headers"] = {**kw["headers"], "Content-Type": ctype}
        elif body is not None:
            kw["json"] = body
        if files is not None:
            kw["files"] = files
        return await client.request(method, path, **kw)

    async def same(name, method, path, tok=None, body=None, raw=None, ctype="application/json", files=None, norm=None):
        r1 = await call(py, method, path, tok, body, raw, ctype, files)
        r2 = await call(rs, method, path, tok, body, raw, ctype, files)
        b1, b2 = body_of(r1), body_of(r2)
        if norm:
            b1, b2 = norm(b1), norm(b2)
        b1, b2 = json.dumps(b1), json.dumps(b2)  # key order counts
        ok = r1.status_code == r2.status_code and b1 == b2
        check(
            f"{name} [{r1.status_code}]",
            ok,
            f"python {r1.status_code} {str(b1)[:1500]}\n        rust   {r2.status_code} {str(b2)[:1500]}",
        )
        return r1, r2

    # ======================================================================
    print("\n=== A. /api/connectors reads ===")
    probe = await add_connector(f"Parity-Probe-{SFX}", "https://probe.parity.test:9200", "probe", "secret")
    await sql(
        "INSERT INTO connectorhistory (connector_id, change_timestamp, change_description) VALUES "
        "(:i, '2026-03-04 05:06:07', 'created'), (:i, '2026-03-04 05:06:08', 'rotated \"key\" é')",
        i=probe,
    )
    await same("list: no token", "GET", "/api/connectors")
    await same("list: garbage token", "GET", "/api/connectors", "garbage")
    await same("list: 2fa temp token", "GET", "/api/connectors", token(ADMIN, [], type="2fa_pending"))
    await same("list: analyst", "GET", "/api/connectors", t_analyst)
    await same("list: portal user", "GET", "/api/connectors", t_portal)
    await same("list (admin)", "GET", "/api/connectors", t_admin)
    await same("one: no token", "GET", f"/api/connectors/{probe}")
    await same("one: analyst", "GET", f"/api/connectors/{probe}", t_analyst)
    await same("one: path int", "GET", "/api/connectors/abc", t_admin)
    await same("one: missing", "GET", "/api/connectors/987654321", t_admin)
    await same("one (admin, with history)", "GET", f"/api/connectors/{probe}", t_admin)
    await same("one: unknown token user", "GET", f"/api/connectors/{probe}", token(f"ghost{SFX}", ["admin"]))

    # ======================================================================
    print("\n=== B. the cache's change check (this process) ===")
    # Rust's half of the guarantee is exercised through the Wazuh routes below;
    # here Python's own cache, read the way 89 call sites read it.
    from app.connectors.utils import get_connector_info_from_db
    from app.db.db_session import get_db_session

    interval = connector_cache.CHECK_SECONDS
    check("the check is on by default", interval == 5, f"CHECK_SECONDS={interval}")

    async def py_read(name):
        async with get_db_session() as s:
            return await get_connector_info_from_db(name, s)

    first = await py_read(f"Parity-Probe-{SFX}")
    await sql("UPDATE connectors SET connector_password = 'rotated' WHERE id = :i", i=probe)
    inside = await py_read(f"Parity-Probe-{SFX}")
    await asyncio.sleep(interval + 0.5)
    after = await py_read(f"Parity-Probe-{SFX}")
    check(
        "python: a row written behind its back is dropped within the interval",
        (first["connector_password"], inside["connector_password"], after["connector_password"]) == ("secret", "secret", "rotated"),
        f"{first['connector_password']} / {inside['connector_password']} / {after['connector_password']}",
    )

    await sql("DELETE FROM connectorhistory WHERE connector_id = :i", i=probe)
    await sql("DELETE FROM connectors WHERE id = :i", i=probe)

    async def both(
        name,
        method,
        path,
        tok=None,
        body=None,
        rec=None,
        unordered=False,
        norm=None,
        raw=None,
        ctype="application/json",
        files=None,
    ):
        """The responses, and — with `rec` — what each backend sent to that stand-in."""
        got = {}
        responses = {}
        for tag, client in (("py", py), ("rs", rs)):
            if rec is not None:
                rec.captured.clear()
            responses[tag] = await call(client, method, path, tok, body, raw, ctype, files)
            if rec is not None:
                got[tag] = normalised(list(rec.captured), unordered)
        r1, r2 = responses["py"], responses["rs"]
        b1, b2 = body_of(r1), body_of(r2)
        if norm:
            b1, b2 = norm(b1), norm(b2)
        b1, b2 = json.dumps(b1), json.dumps(b2)
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {r1.status_code} {str(b1)[:1500]}\n        rust   {r2.status_code} {str(b2)[:1500]}",
        )
        if rec is not None:
            first = next((i for i, (x, y) in enumerate(zip(got["py"], got["rs"])) if x != y), None)
            check(
                f"{name}: outbound requests ({len(got['py'])})",
                got["py"] == got["rs"],
                f"paths python {[g['method'] + ' ' + g['path'] for g in got['py']]}\n        paths rust   {[g['method'] + ' ' + g['path'] for g in got['rs']]}"
                + (
                    f"\n        first difference #{first}:\n        python {json.dumps(got['py'][first])[:2500]}\n        rust   {json.dumps(got['rs'][first])[:2500]}"
                    if first is not None
                    else ""
                ),
            )
        return r1, r2

    def masked(v):
        """Response texts with call-time timestamps and object addresses masked."""
        return json.loads(mask_text(json.dumps(v)))

    async def settle():
        """Let both processes' change checks see a connector row written here."""
        await asyncio.sleep(connector_cache.CHECK_SECONDS + 0.5)

    # ======================================================================
    print("\n=== C. Wazuh indexer ===")
    es = Recorder(es_answer)
    es2 = Recorder(es_answer)
    await sql("DELETE FROM connectors WHERE connector_name IN ('Wazuh-Indexer', 'Wazuh-Manager')")
    indexer_id = await add_connector("Wazuh-Indexer", es.url, ES_USER, ES_PASS)

    # -- C1. guards and request validation (no indexer call) ------------------------
    await both("alerts: no token", "POST", "/api/alerts", body={})
    await both("alerts: portal user", "POST", "/api/alerts", t_portal, {})
    await both("alerts: malformed JSON before the token", "POST", "/api/alerts", raw=b"{")
    await both("alerts: bad timerange", "POST", "/api/alerts", t_analyst, {"timerange": "24x"})
    await both("alerts: timerange not a number", "POST", "/api/alerts", t_analyst, {"timerange": "xh"})
    await both("alerts: empty timerange crashes the validator", "POST", "/api/alerts", t_analyst, {"timerange": "", "size": "x"})
    await both("alerts: size not an int", "POST", "/api/alerts", t_analyst, {"size": "ten", "alert_field": 5})
    await both("host: agent_name required", "POST", "/api/alerts/host", t_analyst, {})
    await both("index: index_name required", "POST", "/api/alerts/index", t_analyst, {"timerange": "1w"})
    await both("by-id: fields required", "POST", "/api/alerts/by-id", t_analyst, {"index_name": 3})
    await both("graylog: customer_codes not a list", "POST", "/api/alerts/alerts/graylog", t_analyst, {"customer_codes": "x"})
    await both("monitoring: no token", "GET", "/api/wazuh_indexer/health")
    await both("monitoring: portal user", "GET", "/api/wazuh_indexer/shards", t_portal)
    await both("indices: limit out of range", "GET", "/api/wazuh_indexer/indices?limit=0", t_analyst)
    await both("snapshots: analyst", "GET", "/api/snapshots/repositories", t_analyst)
    await both("snapshots: no token", "GET", "/api/snapshots/schedules")
    await both("schedules: path int", "GET", "/api/snapshots/schedules/abc", t_admin)
    await both("schedules: enabled_only not a bool", "GET", "/api/snapshots/schedules?enabled_only=maybe", t_admin)
    await both(
        "schedule create: validation",
        "POST",
        "/api/snapshots/schedules",
        t_admin,
        {"name": "x", "scheduled_hour": 24, "interval_days": 0, "day_of_week": "sunday"},
    )
    await both("create: body required", "POST", "/api/snapshots/create", t_admin)
    await both("status: snapshot without repository", "GET", "/api/snapshots/status?snapshot=s1", t_admin)

    # -- C2. monitoring -------------------------------------------------------------
    await both("health", "GET", "/api/wazuh_indexer/health", t_analyst, rec=es)
    await both("allocation", "GET", "/api/wazuh_indexer/allocation", t_analyst, rec=es)
    await both("indices (admin)", "GET", "/api/wazuh_indexer/indices", t_admin, rec=es)
    await both("indices: search and limit", "GET", "/api/wazuh_indexer/indices?search=WAZUH&limit=3", t_admin, rec=es)
    await both("indices (scoped analyst)", "GET", "/api/wazuh_indexer/indices", t_analyst, rec=es)
    await both("indices: analyst asks for another tenant", "GET", f"/api/wazuh_indexer/indices?customer_codes={CUST_B}", t_analyst, rec=es)
    await both("indices: admin narrows to B", "GET", f"/api/wazuh_indexer/indices?customer_code={CUST_B}", t_admin, rec=es)
    await both("size per customer (admin)", "GET", "/api/wazuh_indexer/indices/size-per-customer", t_admin, rec=es)
    await both("size per customer (scoped)", "GET", "/api/wazuh_indexer/indices/size-per-customer", t_analyst, rec=es)
    await both("shards", "GET", "/api/wazuh_indexer/shards", t_analyst, rec=es)
    await both("shard number", "GET", "/api/wazuh_indexer/output_shard_number_to_be_set_based_on_nodes", t_analyst, rec=es)
    await both("resize index fields", "GET", "/api/wazuh_indexer/resize_wazuh_index_fields", t_analyst, rec=es)
    es.mode["health_missing"] = True
    await both("health: a field missing upstream", "GET", "/api/wazuh_indexer/health", t_analyst, rec=es)
    es.mode.clear()
    es.mode["html"] = True
    await both("allocation: HTML answer", "GET", "/api/wazuh_indexer/allocation", t_analyst, rec=es)
    es.mode.clear()
    es.mode["busy"] = True
    await both("health: 503, retried ten times", "GET", "/api/wazuh_indexer/health", t_analyst, rec=es)
    await both("alerts: 503 on the index list", "POST", "/api/alerts", t_analyst, {}, rec=es)
    await both("resize: failure swallowed", "GET", "/api/wazuh_indexer/resize_wazuh_index_fields", t_analyst, rec=es)
    es.mode.clear()

    # -- C3. alerts -----------------------------------------------------------------
    await both("alerts (defaults)", "POST", "/api/alerts", t_admin, {}, rec=es)
    await both(
        "alerts: other field and window",
        "POST",
        "/api/alerts",
        t_admin,
        {"size": 2, "timerange": "2w", "alert_field": "rule_description", "alert_value": "Mimikatz é", "timestamp_field": "@timestamp"},
        rec=es,
    )
    await both("alerts: days window", "POST", "/api/alerts", t_admin, {"timerange": "3d"}, rec=es)
    await both("host alerts", "POST", "/api/alerts/host", t_admin, {"agent_name": "dc01", "timerange": "1h"}, rec=es)
    await both("index alerts", "POST", "/api/alerts/index", t_admin, {"index_name": f"  {IDX_A}_1 "}, rec=es)
    await both("index alerts: unmanaged index", "POST", "/api/alerts/index", t_admin, {"index_name": ".kibana_1"}, rec=es)
    await both("index alerts: the timestamp fallback", "POST", "/api/alerts/index", t_admin, {"index_name": "nomap_0"}, rec=es)
    await both("by host", "POST", "/api/alerts/hosts/all", t_admin, {}, rec=es)
    await both("by rule", "POST", "/api/alerts/rules/all", t_admin, {"size": 5}, rec=es)
    await both("by rule per host", "POST", "/api/alerts/rules/hosts/all", t_admin, {}, rec=es)
    es.mode["bad_agent"] = True
    await both("by host: a non-string agent name", "POST", "/api/alerts/hosts/all", t_admin, {}, rec=es)
    es.mode.clear()
    es.mode["broken"] = True
    await both("alerts: an index failing with another 400", "POST", "/api/alerts", t_admin, {}, rec=es)
    es.mode.clear()
    es.mode["no_alerts"] = True
    await both("index alerts: none found", "POST", "/api/alerts/index", t_admin, {"index_name": "wazuh-alerts-4.x-2026.10.15"}, rec=es)
    es.mode.clear()
    await both("by id", "POST", "/api/alerts/by-id", t_admin, {"index_name": f" {IDX_A}_1", "alert_id": "a2 "}, rec=es)
    await both("by id: not found", "POST", "/api/alerts/by-id", t_admin, {"index_name": f"{IDX_A}_1", "alert_id": "nope"}, rec=es)
    await both("by id: missing index", "POST", "/api/alerts/by-id", t_admin, {"index_name": "missing-index", "alert_id": "x/y z"}, rec=es)
    await both("by id: empty id is a ValueError", "POST", "/api/alerts/by-id", t_admin, {"index_name": "x", "alert_id": "  "}, rec=es)
    # By design: a scoped analyst reads their customers' indices only (Python: every tenant's).
    names = lambda r: sorted(x["index_name"] for x in r.json().get("alerts_summary", []))  # noqa: E731
    es.captured.clear()
    r_py = await call(py, "POST", "/api/alerts", t_analyst, {})
    r_rs = await call(rs, "POST", "/api/alerts", t_analyst, {})
    check(
        "by design: a scoped analyst's alerts come from their customers' indices only",
        r_py.status_code == r_rs.status_code == 200 and f"{IDX_B}_1" in names(r_py) and names(r_rs) == [f"{IDX_A}_1", f"{IDX_A}_2"],
        f"{names(r_py)} / {names(r_rs)}",
    )
    es.captured.clear()
    await call(py, "POST", "/api/alerts/rules/hosts/all", t_analyst, {})
    py_searched = sorted({unquote(c["path"].split("?")[0].split("/")[1]) for c in es.captured if "/_search" in c["path"]})
    es.captured.clear()
    await call(rs, "POST", "/api/alerts/rules/hosts/all", t_analyst, {})
    rs_searched = sorted({unquote(c["path"].split("?")[0].split("/")[1]) for c in es.captured if "/_search" in c["path"]})
    check(
        "by design: a scoped analyst's aggregations search their customers' indices only",
        f"{IDX_B}_1" in py_searched and rs_searched == [f"{IDX_A}_1", f"{IDX_A}_2"],
        f"{py_searched} / {rs_searched}",
    )
    r_py = await call(py, "POST", "/api/alerts/index", t_analyst, {"index_name": f"{IDX_B}_1"})
    r_rs = await call(rs, "POST", "/api/alerts/index", t_analyst, {"index_name": f"{IDX_B}_1"})
    r_unmanaged = await call(rs, "POST", "/api/alerts/index", t_analyst, {"index_name": "nonexistent_index_1"})
    check(
        "by design: another tenant's index reads as one that is not managed",
        r_py.status_code == 200
        and r_rs.status_code == 400
        and r_rs.json()["message"] == f"Index name '{IDX_B}_1' is not managed by Wazuh Indexer or no longer exists."
        and r_unmanaged.status_code == 400,
        f"{r_py.status_code} {r_rs.text}",
    )
    es.captured.clear()
    r_py = await call(py, "POST", "/api/alerts/by-id", t_analyst, {"index_name": f"{IDX_B}_1", "alert_id": "b1"})
    py_asked = len(es.captured)
    es.captured.clear()
    r_rs = await call(rs, "POST", "/api/alerts/by-id", t_analyst, {"index_name": f"{IDX_B}_1", "alert_id": "b1"})
    rs_asked = [c for c in es.captured if "_doc" in c["path"]]
    r_missing = await call(py, "POST", "/api/alerts/by-id", t_admin, {"index_name": f"{IDX_B}_1", "alert_id": "b1-gone"})
    check(
        "by design: another tenant's alert reads as a missing one, and the indexer is not asked",
        r_py.json()["success"] is True
        and py_asked == 1
        and not rs_asked
        and r_rs.status_code == 200
        and r_rs.json()
        == {**r_missing.json(), "alert": {**r_missing.json()["alert"], "_id": "b1"}, "message": f"Alert b1 not found in index {IDX_B}_1"},
        f"{r_rs.text}",
    )
    r_admin = await call(rs, "POST", "/api/alerts/by-id", t_admin, {"index_name": f"{IDX_B}_1", "alert_id": "b1"})
    check("an admin still reads every tenant's alert", r_admin.json()["success"] is True, r_admin.text)
    await both(
        "graylog alerts (admin)",
        "POST",
        "/api/alerts/alerts/graylog",
        t_admin,
        {"size": 20, "timerange": "1d"},
        rec=es,
        unordered=True,
    )
    await both("graylog alerts (scoped analyst)", "POST", "/api/alerts/alerts/graylog", t_analyst, {}, rec=es, unordered=True)
    await both(
        "graylog alerts: analyst asks for B",
        "POST",
        "/api/alerts/alerts/graylog",
        t_analyst,
        {"customer_codes": [CUST_B]},
        rec=es,
        unordered=True,
    )
    await both(
        "graylog alerts: admin narrows to B",
        "POST",
        "/api/alerts/alerts/graylog",
        t_admin,
        {"customer_codes": [CUST_B.lower()]},
        rec=es,
        unordered=True,
    )
    await both(
        "graylog index alerts",
        "POST",
        "/api/alerts/alerts/graylog/index",
        t_admin,
        {"index_name": f" {IDX_A}_1 ", "index_prefix": "gl-events*"},
        rec=es,
        unordered=True,
    )
    await both(
        "graylog index alerts: none",
        "POST",
        "/api/alerts/alerts/graylog/index",
        t_analyst,
        {"index_name": f"{IDX_B}_1"},
        rec=es,
        unordered=True,
    )

    # -- C4. snapshots --------------------------------------------------------------
    await both("repositories", "GET", "/api/snapshots/repositories", t_admin, rec=es)
    await both("status (all)", "GET", "/api/snapshots/status", t_admin, rec=es)
    await both("status of one snapshot", "GET", "/api/snapshots/status?repository=backup&snapshot=snap1", t_admin, rec=es)
    es.mode["bad_status"] = True
    await both("status: a shard without stage", "GET", "/api/snapshots/status?repository=backup", t_admin, rec=es)
    es.mode.clear()
    await both("snapshots of a repository", "GET", "/api/snapshots/repositories/backup/snapshots", t_admin, rec=es)
    await both("snapshots: missing repository", "GET", "/api/snapshots/repositories/missing/snapshots", t_admin, rec=es)
    await both(
        "create (skip write indices)",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {"repository": "backup", "snapshot": "snap-a"},
        rec=es,
    )
    await both(
        "create: patterns and metadata",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {
            "repository": "backup",
            "snapshot": "snap-b",
            "indices": [f"{IDX_A}_*", "explicit-one"],
            "metadata": {"by": "parity", "n": 1},
            "partial": None,
        },
        rec=es,
    )
    await both(
        "create: only the write index",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {"repository": "backup", "snapshot": "snap-c", "indices": [f"{IDX_A}_2"]},
        rec=es,
    )
    # `re.match(f"^{p}$")`: an alternation's first branch is a prefix match.
    await both(
        "create: an alternation pattern",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {"repository": "backup", "snapshot": "snap-d", "indices": [f"{IDX_A}*1|zzz*"]},
        rec=es,
    )

    def regex_error_masked(v):
        if isinstance(v, dict) and str(v.get("message", "")).startswith("Failed to create snapshot: "):
            v = {**v, "message": "Failed to create snapshot: <the regex engine's text>"}
        return v

    # By design: Rust's `regex` words a broken pattern its own way.
    await both(
        "create: a broken pattern (texts differ by design)",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {"repository": "backup", "snapshot": "snap-d", "indices": ["wazuh-*("]},
        rec=es,
        norm=regex_error_masked,
    )
    await both(
        "create: wait, no skipping",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {
            "repository": "backup",
            "snapshot": "snap-d",
            "indices": ["a", "b"],
            "skip_write_indices": False,
            "wait_for_completion": True,
            "include_global_state": None,
        },
        rec=es,
    )
    es.mode["refuse"] = True
    await both(
        "create: not accepted",
        "POST",
        "/api/snapshots/create",
        t_admin,
        {"repository": "backup", "snapshot": "snap-e", "skip_write_indices": None},
        rec=es,
    )
    es.mode.clear()
    await both("create: empty snapshot name", "POST", "/api/snapshots/create", t_admin, {"repository": "backup", "snapshot": ""}, rec=es)
    await both(
        "restore",
        "POST",
        "/api/snapshots/restore",
        t_admin,
        {"repository": "backup", "snapshot": "snap1", "indices": ["a", "b"], "rename_pattern": "(.+)", "rename_replacement": "r_$1"},
        rec=es,
    )
    await both(
        "restore: nulls",
        "POST",
        "/api/snapshots/restore",
        t_admin,
        {
            "repository": "backup",
            "snapshot": "snap1",
            "ignore_unavailable": None,
            "include_aliases": None,
            "partial": None,
            "include_global_state": None,
        },
        rec=es,
    )

    sched_mask = lambda v: json.loads(re.sub(r'"(id|created_at|updated_at)": ("[^"]*"|\d+)', r'"\1": "<v>"', json.dumps(v)))  # noqa: E731
    created = {}
    for tag, client in (("py", py), ("rs", rs)):
        created[tag] = await call(
            client,
            "POST",
            "/api/snapshots/schedules",
            t_admin,
            {
                "name": f"nightly {SFX} {tag}",
                "index_pattern": f"{IDX_A}_*",
                "repository": "backup",
                "scheduled_hour": 2,
                "scheduled_minute": None,
                "timezone": "Europe/Berlin",
                "snapshot_prefix": "",
            },
        )
    check(
        "schedule create",
        created["py"].status_code == created["rs"].status_code == 200
        and json.dumps(sched_mask(created["py"].json())).replace(" py", " X")
        == json.dumps(sched_mask(created["rs"].json())).replace(" rs", " X"),
        f"{created['py'].text}\n        {created['rs'].text}",
    )
    sid = {tag: r.json()["schedule"]["id"] for tag, r in created.items()}
    for tag in ("py", "rs"):
        await sql(
            "UPDATE index_snapshot_schedules SET created_at = '2026-01-02 03:04:05', updated_at = '2026-01-02 03:04:05' WHERE id = :i",
            i=sid[tag],
        )
    await both("schedule get (py's row)", "GET", f"/api/snapshots/schedules/{sid['py']}", t_admin)
    await both("schedule get (rs's row)", "GET", f"/api/snapshots/schedules/{sid['rs']}", t_admin)
    await both("schedule get: missing", "GET", "/api/snapshots/schedules/987654321", t_admin)
    await both("schedules", "GET", "/api/snapshots/schedules", t_admin)
    await both("schedules: enabled only", "GET", "/api/snapshots/schedules?enabled_only=true", t_admin)
    updates = {}
    for tag, client in (("py", py), ("rs", rs)):
        updates[tag] = await call(
            client,
            "PUT",
            f"/api/snapshots/schedules/{sid[tag]}",
            t_admin,
            {"enabled": False, "scheduled_hour": None, "day_of_week": 6, "retention_days": 30, "name": None, "timezone": "UTC"},
        )
    check(
        "schedule update",
        updates["py"].status_code == updates["rs"].status_code == 200
        and json.dumps(sched_mask(updates["py"].json())).replace(" py", " X")
        == json.dumps(sched_mask(updates["rs"].json())).replace(" rs", " X"),
        f"{updates['py'].text}\n        {updates['rs'].text}",
    )
    await both("schedule update: missing", "PUT", "/api/snapshots/schedules/987654321", t_admin, {"name": "x"})
    for tag, client in (("py", py), ("rs", rs)):
        r = await call(client, "DELETE", f"/api/snapshots/schedules/{sid[tag]}", t_admin)
        check(f"schedule delete ({tag})", r.status_code == 200 and r.json()["message"].endswith(f" {tag}"), r.text)
    await both("schedule delete: missing", "DELETE", f"/api/snapshots/schedules/{sid['py']}", t_admin)

    # -- C5. the connector row: problems, and a write behind Rust's back --------------
    # A read first, so that Rust's last look at the table is fresh when the row changes.
    await call(rs, "GET", "/api/wazuh_indexer/health", t_analyst)
    await sql("UPDATE connectors SET connector_url = :u WHERE id = :i", u=es2.url, i=indexer_id)
    es.captured.clear()
    es2.captured.clear()
    await call(rs, "GET", "/api/wazuh_indexer/health", t_analyst)
    # The guarantee is a bound, not a delay: inside the interval either row may serve.
    check(
        "rust: inside the check interval the cached row may still be used",
        len(es.captured) + len(es2.captured) == 1,
        f"{len(es.captured)} / {len(es2.captured)}",
    )
    await settle()
    es.captured.clear()
    es2.captured.clear()
    await call(rs, "GET", "/api/wazuh_indexer/health", t_analyst)
    check(
        "rust: after the interval the new row is used",
        not es.captured and len(es2.captured) == 1,
        f"{len(es.captured)} / {len(es2.captured)}",
    )

    closed = Recorder(es_answer)
    closed.server.shutdown()
    closed.server.server_close()
    await sql("UPDATE connectors SET connector_url = :u WHERE id = :i", u=closed.url, i=indexer_id)
    await settle()
    await both("alerts: indexer refusing connections", "POST", "/api/alerts", t_analyst, {}, norm=masked)
    await both("snapshots: indexer refusing connections", "GET", "/api/snapshots/repositories", t_admin, norm=masked)
    await sql("UPDATE connectors SET connector_url = :u, connector_password = 'wrong' WHERE id = :i", u=es.url, i=indexer_id)
    await settle()
    await both("health: credentials rejected", "GET", "/api/wazuh_indexer/health", t_analyst, rec=es)
    await both("alerts: credentials rejected", "POST", "/api/alerts", t_analyst, {}, rec=es)
    await both("repositories: credentials rejected", "GET", "/api/snapshots/repositories", t_admin, rec=es)
    await sql("UPDATE connectors SET connector_password = NULL WHERE id = :i", i=indexer_id)
    await settle()
    await both("alerts: no password", "POST", "/api/alerts", t_analyst, {})
    await both("size per customer: no password", "GET", "/api/wazuh_indexer/indices/size-per-customer", t_admin)
    await sql("UPDATE connectors SET connector_url = 'https://127.1.1.1:9200', connector_password = 'x' WHERE id = :i", i=indexer_id)
    await settle()
    await both("health: placeholder URL", "GET", "/api/wazuh_indexer/health", t_analyst)
    await both("repositories: placeholder URL", "GET", "/api/snapshots/repositories", t_admin)
    await both("resize: placeholder URL", "GET", "/api/wazuh_indexer/resize_wazuh_index_fields", t_analyst)
    await sql("UPDATE connectors SET connector_url = 'http://indexer:port' WHERE id = :i", i=indexer_id)
    await settle()
    await both("alerts: unparsable port", "POST", "/api/alerts", t_analyst, {})
    await sql("DELETE FROM connectors WHERE id = :i", i=indexer_id)
    await both("alerts: no Wazuh-Indexer connector", "POST", "/api/alerts", t_analyst, {})
    await both("graylog: no Wazuh-Indexer connector", "POST", "/api/alerts/alerts/graylog", t_admin, {})
    await settle()

    # ======================================================================
    print("\n=== D. Wazuh manager ===")
    from app.connectors.wazuh_manager.utils.universal import (
        clear_all_wazuh_token_caches,
    )

    mgr = Recorder(mgr_answer, "m1")
    mgr2 = Recorder(mgr_answer, "m2")
    manager_id = await add_connector("Wazuh-Manager", mgr.url, MGR_USER, MGR_PASS)
    M = "/api/wazuh_manager"
    XML = b'<group name="local,">\n  <rule id="100001" level="5">\n    <description>Local \xc3\xa9</description>\n  </rule>\n</group>\n'

    # -- D1. guards and validation (nothing reaches the manager) --------------------
    await both("rules: no token", "GET", f"{M}/rules", rec=mgr)
    await both("rules: analyst", "GET", f"{M}/rules", t_analyst, rec=mgr)
    await both("rules: portal user", "GET", f"{M}/rules", t_portal)
    await both("mitre: portal user", "GET", f"{M}/mitre/tactics", t_portal)
    await both("mitre: no token", "GET", f"{M}/mitre/tactics")
    await both("restart: analyst", "POST", f"{M}/management/restart", t_analyst, rec=mgr)
    await both("rules: limit 0", "GET", f"{M}/rules?limit=0", t_admin, rec=mgr)
    await both(
        "rules: offset -1, limit 100001, a bad rule id",
        "GET",
        f"{M}/rules?offset=-1&limit=100001&rule_ids=5&rule_ids=x&pretty=maybe",
        t_admin,
        rec=mgr,
    )
    await both("rule files: empty limit", "GET", f"{M}/rules/files?limit=&distinct=", t_admin)
    await both("groups: unknown hash", "GET", f"{M}/groups?hash=md4", t_admin, rec=mgr)
    await both("group file: any type is a TypeError", "GET", f"{M}/groups/default/files/agent.conf?type=conf", t_admin, rec=mgr)
    await both("mitre: limit not an int", "GET", f"{M}/mitre/techniques?limit=x&offset=1.5", t_analyst, rec=mgr)
    await both("upload: no file", "PUT", f"{M}/rules/files/local_rules.xml", t_admin, rec=mgr)
    await both(
        "upload: a text field, not a file",
        "PUT",
        f"{M}/rules/files/local_rules.xml?pretty=x",
        t_admin,
        raw=b'--b\r\nContent-Disposition: form-data; name="file"\r\n\r\ntext\r\n--b--\r\n',
        ctype="multipart/form-data; boundary=b",
        rec=mgr,
    )
    await both(
        "upload: malformed multipart before the token",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        None,
        raw=b"--b\r\nbroken",
        ctype="multipart/form-data; boundary=b",
    )
    await both("upload: no token", "PUT", f"{M}/rules/files/local_rules.xml", None, files={"file": ("r.xml", XML, "application/xml")})
    await both("an encoded slash is Starlette's 404", "GET", f"{M}/rules/files/a%2Fb.xml", t_admin, rec=mgr)

    # -- D2. the manager answering ---------------------------------------------------
    await both("rules (first call: a token each)", "GET", f"{M}/rules", t_admin, rec=mgr)
    await both(
        "rules: every filter",
        "GET",
        f"{M}/rules?rule_ids=1&rule_ids=100001&select=id&select=level&search=a b%26c=d/e~&q=level>5;groups=sysmon&filename=a.xml&filename=%C3%A4.xml&nist_800_53=AU.6&distinct=true&pretty=1&limit=10&offset=5",
        t_admin,
        rec=mgr,
    )
    mgr.mode["bad_rule"] = True
    await both("rules: a rule the model refuses", "GET", f"{M}/rules", t_admin, rec=mgr)
    mgr.mode.clear()
    mgr.mode["rules_list"] = True
    await both("rules: data that is a list", "GET", f"{M}/rules", t_admin, rec=mgr)
    mgr.mode.clear()
    await both("rule files", "GET", f"{M}/rules/files", t_admin, rec=mgr)
    await both(
        "rule files: filters",
        "GET",
        f"{M}/rules/files?status=enabled&relative_dirname=etc/rules&select=filename&filename=a&filename=b&sort=-filename",
        t_admin,
        rec=mgr,
    )
    await both("rule file (raw)", "GET", f"{M}/rules/files/local_rules.xml", t_admin, rec=mgr)
    await both("rule file (raw, a space and é in the name)", "GET", f"{M}/rules/files/my%20rules%C3%A9.xml?pretty=true", t_admin, rec=mgr)
    mgr.mode["latin1"] = True
    await both("rule file (raw, text/plain read as Latin-1)", "GET", f"{M}/rules/files/local_rules.xml", t_admin, rec=mgr)
    mgr.mode.clear()
    await both("rule file (structured)", "GET", f"{M}/rules/files/local_rules.xml?raw=false&relative_dirname=etc/rules", t_admin, rec=mgr)
    await both("rule file: not found (raw)", "GET", f"{M}/rules/files/missing.xml", t_admin, rec=mgr)
    await both("rule file: not found (structured)", "GET", f"{M}/rules/files/missing.xml?raw=false", t_admin, rec=mgr)
    await both("rule file: no content", "GET", f"{M}/rules/files/empty.xml?raw=false", t_admin, rec=mgr)
    await both(
        "upload",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        t_admin,
        files={"file": ("local_rules.xml", XML, "application/xml")},
        rec=mgr,
    )
    await both(
        "upload: overwrite off, a directory, odd content type",
        "PUT",
        f"{M}/rules/files/new.xml?overwrite=false&relative_dirname=etc/rules&pretty=true",
        t_admin,
        files={"file": ("new.xml", b"not xml", "image/png")},
        rec=mgr,
    )
    await both(
        "upload: an empty file",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        t_admin,
        files={"file": ("e.xml", b"", "application/xml")},
        rec=mgr,
    )
    mgr.mode["upload_400"] = True
    await both(
        "upload: refused by the manager",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        t_admin,
        files={"file": ("r.xml", XML, "application/xml")},
        rec=mgr,
    )
    mgr.mode.clear()
    await both("groups", "GET", f"{M}/groups", t_admin, rec=mgr)
    await both(
        "groups: filters",
        "GET",
        f"{M}/groups?groups_list=default&groups_list=linux&hash=sha256&search=x&q=count>0&distinct=true",
        t_admin,
        rec=mgr,
    )
    await both("group files", "GET", f"{M}/groups/default/files?hash=md5", t_admin, rec=mgr)
    await both("group files: unknown group", "GET", f"{M}/groups/nogroup/files", t_admin, rec=mgr)
    await both("group file (raw)", "GET", f"{M}/groups/default/files/agent.conf", t_admin, rec=mgr)
    await both("group file (structured)", "GET", f"{M}/groups/default/files/agent.conf?raw=false", t_admin, rec=mgr)
    await both("group file: unknown group", "GET", f"{M}/groups/nogroup/files/agent.conf", t_admin, rec=mgr)
    conf = b'<agent_config>\n  <labels>\n    <label key="customer">acme \xc3\xa9</label>\n  </labels>\n</agent_config>'
    await both(
        "group configuration",
        "PUT",
        f"{M}/groups/default/configuration?wait_for_complete=true",
        t_admin,
        raw=conf,
        ctype="application/xml",
        rec=mgr,
    )
    await both(
        "group configuration: empty",
        "PUT",
        f"{M}/groups/default/configuration",
        t_admin,
        raw=b"  \n",
        ctype="application/xml",
        rec=mgr,
    )
    await both(
        "group configuration: not XML",
        "PUT",
        f"{M}/groups/default/configuration",
        t_admin,
        raw=b"labels: x",
        ctype="text/plain",
        rec=mgr,
    )
    await both(
        "group configuration: not UTF-8",
        "PUT",
        f"{M}/groups/default/configuration",
        t_admin,
        raw=b"<a>\xff</a>",
        ctype="application/xml",
        rec=mgr,
    )
    await both(
        "group configuration: unknown group",
        "PUT",
        f"{M}/groups/nogroup/configuration",
        t_admin,
        raw=conf,
        ctype="application/xml",
        rec=mgr,
    )
    mgr.mode["config_400"] = True
    await both(
        "group configuration: refused",
        "PUT",
        f"{M}/groups/default/configuration",
        t_admin,
        raw=conf,
        ctype="application/xml",
        rec=mgr,
    )
    mgr.mode.clear()
    for what in ("tactics", "techniques", "software", "references", "mitigations", "groups"):
        await both(f"mitre {what}", "GET", f"{M}/mitre/{what}", t_analyst, rec=mgr)
    await both(
        "mitre techniques: every parameter",
        "GET",
        f"{M}/mitre/techniques?limit=5&offset=0&select=name&select=id&sort=+name&search=valid&q=name~acc",
        t_admin,
        rec=mgr,
    )
    await both("mitre references: select is not a parameter", "GET", f"{M}/mitre/references?select=url&limit=2", t_analyst, rec=mgr)
    await both("mitre groups: an empty select", "GET", f"{M}/mitre/groups?select=", t_analyst, rec=mgr)
    mgr.mode["bad_mitre"] = True
    await both("mitre tactics: an item the model refuses", "GET", f"{M}/mitre/tactics", t_analyst, rec=mgr)
    await both("mitre techniques: an item the model refuses", "GET", f"{M}/mitre/techniques", t_analyst, rec=mgr)
    mgr.mode.clear()
    mgr.mode["fail"] = "/mitre/software"
    await both("mitre software: the manager failing", "GET", f"{M}/mitre/software", t_analyst, rec=mgr)
    mgr.mode["fail"] = "/rules/files"
    await both("rule files: the manager failing", "GET", f"{M}/rules/files", t_admin, rec=mgr)
    mgr.mode.clear()
    await both("restart (no cluster)", "POST", f"{M}/management/restart", t_admin, rec=mgr)
    mgr.mode["cluster"] = "yes"
    await both("restart (cluster)", "POST", f"{M}/management/restart", t_admin, rec=mgr)
    mgr.mode["restart_400"] = True
    await both("restart (cluster, refused)", "POST", f"{M}/management/restart", t_admin, rec=mgr)
    mgr.mode["cluster"] = "maybe"
    await both("restart (unknown cluster state, refused)", "POST", f"{M}/management/restart", t_admin, rec=mgr)
    mgr.mode.clear()
    mgr.mode["fail"] = "/cluster/status"
    await both("restart: no cluster status", "POST", f"{M}/management/restart", t_admin, rec=mgr)
    mgr.mode.clear()

    # -- D3. tokens -------------------------------------------------------------------
    mgr.mode["gen"] = 2
    await both("an expired token: 401, a new token, the call again", "GET", f"{M}/groups", t_admin, rec=mgr)
    mgr.mode["gen"] = 3
    await both("an expired token on a raw read: no second try", "GET", f"{M}/rules/files/local_rules.xml", t_admin, rec=mgr)
    await both(
        "an expired token on an upload: no second try",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        t_admin,
        files={"file": ("r.xml", XML, "application/xml")},
        rec=mgr,
    )
    mgr.mode["gen"] = 4
    mgr.mode["reject_auth"] = True
    await both("an expired token and credentials refused", "GET", f"{M}/rules", t_admin, rec=mgr)
    await both("restart: credentials refused", "POST", f"{M}/management/restart", t_admin, rec=mgr)
    mgr.mode.clear()
    mgr.mode["gen"] = 4
    await both("tokens again after the refusal", "GET", f"{M}/mitre/tactics", t_analyst, rec=mgr)

    # By design: a token is reused only for the row it was issued against.
    await sql("UPDATE connectors SET connector_password = :p WHERE id = :i", p=MGR_PASS2, i=manager_id)
    await settle()
    mgr.captured.clear()
    r1 = await call(py, "GET", f"{M}/groups", t_admin)
    py_calls = [c["path"] for c in mgr.captured]
    mgr.captured.clear()
    r2 = await call(rs, "GET", f"{M}/groups", t_admin)
    rs_calls = [c["path"] for c in mgr.captured]
    check(
        "by design: a rotated password gets a new token in Rust (Python reuses the old one)",
        r1.json() == r2.json()
        and py_calls == ["/groups?pretty=False&wait_for_complete=False&offset=0&limit=500&distinct=False"]
        and rs_calls == ["/security/user/authenticate"] + py_calls,
        f"{py_calls} / {rs_calls}",
    )
    await sql("UPDATE connectors SET connector_url = :u WHERE id = :i", u=mgr2.url, i=manager_id)
    await settle()
    mgr2.captured.clear()
    r1 = await call(py, "GET", f"{M}/groups", t_admin)
    py_sent = [(c["path"].split("?")[0], c["headers"].get("authorization", "")) for c in mgr2.captured]
    mgr2.captured.clear()
    r2 = await call(rs, "GET", f"{M}/groups", t_admin)
    rs_sent = [(c["path"].split("?")[0], c["headers"].get("authorization", "")) for c in mgr2.captured]
    check(
        "by design: a new URL is never sent the old host's token (Python sends it, gets a 401, then authenticates)",
        r1.json() == r2.json()
        and [p for p, _ in py_sent] == ["/groups", "/security/user/authenticate", "/groups"]
        and py_sent[0][1] == "Bearer tok-m1-4"
        and [p for p, _ in rs_sent] == ["/security/user/authenticate", "/groups"]
        and all("tok-m1" not in a for _, a in rs_sent),
        f"{py_sent} / {rs_sent}",
    )
    await sql("UPDATE connectors SET connector_url = :u, connector_password = :p WHERE id = :i", u=mgr.url, p=MGR_PASS, i=manager_id)
    await settle()
    await clear_all_wazuh_token_caches()
    await both("back on the first manager", "GET", f"{M}/rules/files", t_admin, rec=mgr)

    # -- D4. the manager gone ---------------------------------------------------------
    mgr.stop()
    await both("rule files: the manager refusing connections (tokens cached)", "GET", f"{M}/rules/files", t_admin, norm=masked)
    await both(
        "upload: the manager refusing connections",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        t_admin,
        files={"file": ("r.xml", XML, "application/xml")},
        norm=masked,
    )
    await both("restart: the manager refusing connections", "POST", f"{M}/management/restart", t_admin, norm=masked)
    await clear_all_wazuh_token_caches()
    await sql("UPDATE connectors SET connector_password = 'wrong' WHERE id = :i", i=manager_id)
    await settle()
    await both("rules: no token to be had", "GET", f"{M}/rules", t_admin)
    await both("mitre: no token to be had", "GET", f"{M}/mitre/groups", t_analyst)
    await both(
        "group configuration: no token to be had",
        "PUT",
        f"{M}/groups/default/configuration",
        t_admin,
        raw=conf,
        ctype="application/xml",
    )
    await sql("DELETE FROM connectors WHERE id = :i", i=manager_id)
    await settle()
    await clear_all_wazuh_token_caches()
    await both("rule file: no Wazuh-Manager connector", "GET", f"{M}/rules/files/local_rules.xml", t_admin)
    await both(
        "upload: no Wazuh-Manager connector",
        "PUT",
        f"{M}/rules/files/local_rules.xml",
        t_admin,
        files={"file": ("r.xml", XML, "application/xml")},
    )
    await both("restart: no Wazuh-Manager connector", "POST", f"{M}/management/restart", t_admin)

    # ======================================================================
    print("\n=== E. connector writes and verification ===")
    es3 = Recorder(es_answer, "e3")
    mgr3 = Recorder(mgr_answer, "m3")
    gone = Recorder(es_answer, "gone")
    gone.stop()
    START = "2026-01-02 03:04:05"
    idx_id = await add_connector("Wazuh-Indexer", "https://old-indexer.parity.test:9200", "x", "y")
    mgr_id = await add_connector("Wazuh-Manager", "https://old-manager.parity.test:55000", "x", "y")
    other_id = await add_connector(f"Parity-Other-{SFX}", "https://other.parity.test", "u", "p")
    admin_id = (await rows("SELECT id FROM `user` WHERE username = :n", n=ADMIN))[0]["id"]

    async def reset(conn_id, url, user, pw):
        await sql(
            "UPDATE connectors SET connector_url = :u, connector_username = :user, connector_password = :pw, connector_api_key = NULL, "
            "connector_extra_data = NULL, connector_verified = 0, connector_last_updated = :t WHERE id = :i",
            u=url,
            user=user,
            pw=pw,
            t=START,
            i=conn_id,
        )

    async def row_of(conn_id):
        found = await rows(
            "SELECT connector_url, connector_username, connector_password, connector_api_key, connector_extra_data, connector_verified, "
            "connector_last_updated FROM connectors WHERE id = :i",
            i=conn_id,
        )
        if not found:
            return None
        r = dict(found[0])
        r["connector_last_updated"] = "unchanged" if str(r["connector_last_updated"]) == START else "now"
        return r

    async def audits_after(conn_id, last_id, want):
        for _ in range(50):
            found = await rows(
                "SELECT id, action, actor_user_id, actor_username, customer_code, entity_type, entity_id, result, old_value, new_value, "
                "source_ip, details FROM audit_log WHERE entity_type = 'connector' AND entity_id = :e AND id > :l ORDER BY id",
                e=str(conn_id),
                l=last_id,
            )
            if len(found) >= want:
                break
            await asyncio.sleep(0.1)
        return [{k: v for k, v in a.items() if k != "id"} for a in found]

    async def last_audit_id():
        return (await rows("SELECT COALESCE(MAX(id), 0) AS m FROM audit_log"))[0]["m"]

    async def write(name, method, path, tok, conn_id, start, body=None, rec=None, audited=0):
        """One write on each backend from the same starting row: response, outbound requests, row, audit rows."""
        got = {}
        for tag, client in (("py", py), ("rs", rs)):
            await reset(conn_id, *start)
            if method == "POST":
                # A verification reads the row by name, through the cache.
                await settle()
            if rec is not None:
                rec.captured.clear()
            before = await last_audit_id()
            r = await call(client, method, path, tok, body)
            got[tag] = {
                "status": r.status_code,
                "body": masked(body_of(r)),
                "outbound": normalised(list(rec.captured)) if rec is not None else [],
                "row": await row_of(conn_id),
                "audit": await audits_after(conn_id, before, audited),
            }
        same_effects = json.dumps(got["py"], default=str) == json.dumps(got["rs"], default=str)
        check(
            f"{name} [{got['py']['status']}]",
            same_effects and len(got["py"]["audit"]) == audited,
            f"python {json.dumps(got['py'], default=str)[:2500]}\n        rust   {json.dumps(got['rs'], default=str)[:2500]}",
        )
        return got

    good_idx = (es3.url, ES_USER, ES_PASS)
    good_mgr = (mgr3.url, MGR_USER, MGR_PASS)
    upd = {
        "connector_url": es3.url,
        "connector_username": ES_USER,
        "connector_password": ES_PASS,
        "connector_api_key": "k",
        "connector_extra_data": "ORG,BUCKET",
    }

    # -- E1. guards and validation --------------------------------------------------
    await same("update: no token", "PUT", f"/api/connectors/{idx_id}", None, upd)
    await same("update: analyst", "PUT", f"/api/connectors/{idx_id}", t_analyst, upd)
    await same("update: malformed JSON before the token", "PUT", f"/api/connectors/{idx_id}", None, raw=b"{bad", ctype="application/json")
    await same("update: path int", "PUT", "/api/connectors/abc", t_admin, upd)
    await same("update: connector_url required, username a string", "PUT", f"/api/connectors/{idx_id}", t_admin, {"connector_username": 5})
    await same("update: no body", "PUT", f"/api/connectors/{idx_id}", t_admin)
    await same("update: missing connector", "PUT", "/api/connectors/987654321", t_admin, upd)
    await same("verify: no token", "POST", f"/api/connectors/verify/{idx_id}")
    await same("verify: portal user", "POST", f"/api/connectors/verify/{idx_id}", t_portal)
    await same("verify: path int", "POST", "/api/connectors/verify/abc", t_admin)
    await same("verify: missing connector", "POST", "/api/connectors/verify/987654321", t_analyst)

    # -- E2. the indexer --------------------------------------------------------------
    first = await write(
        "update the indexer: verified on the way",
        "PUT",
        f"/api/connectors/{idx_id}",
        t_admin,
        idx_id,
        ("https://old-indexer.parity.test:9200", "x", "y"),
        upd,
        es3,
        audited=1,
    )
    check(
        "the update is answered before the verification, the row after it",
        first["rs"]["body"]["connector"]["connector_verified"] is False
        and first["rs"]["row"]["connector_verified"] == 1
        and len(first["rs"]["outbound"]) == 1
        and first["rs"]["audit"][0]["actor_user_id"] == admin_id,
        json.dumps(first["rs"], default=str)[:1500],
    )
    await write(
        "update the indexer: credentials refused",
        "PUT",
        f"/api/connectors/{idx_id}",
        t_admin,
        idx_id,
        good_idx,
        {**upd, "connector_password": "wrong"},
        es3,
        audited=1,
    )
    await write(
        "update the indexer: only the URL (the rest cleared)",
        "PUT",
        f"/api/connectors/{idx_id}",
        t_admin,
        idx_id,
        good_idx,
        {"connector_url": es3.url},
        es3,
        audited=1,
    )
    await write("verify the indexer", "POST", f"/api/connectors/verify/{idx_id}", t_analyst, idx_id, good_idx, rec=es3)
    await write(
        "verify the indexer: credentials refused",
        "POST",
        f"/api/connectors/verify/{idx_id}",
        t_admin,
        idx_id,
        (es3.url, ES_USER, "wrong"),
        rec=es3,
    )
    await write(
        "verify the indexer: no password",
        "POST",
        f"/api/connectors/verify/{idx_id}",
        t_admin,
        idx_id,
        (es3.url, ES_USER, None),
        rec=es3,
    )
    await write(
        "verify the indexer: an unparsable port",
        "POST",
        f"/api/connectors/verify/{idx_id}",
        t_admin,
        idx_id,
        ("http://indexer:port", ES_USER, ES_PASS),
        rec=es3,
    )
    await write(
        "verify the indexer: refusing connections",
        "POST",
        f"/api/connectors/verify/{idx_id}",
        t_admin,
        idx_id,
        (gone.url, ES_USER, ES_PASS),
    )

    # -- E3. the manager --------------------------------------------------------------
    mupd = {"connector_url": mgr3.url, "connector_username": MGR_USER, "connector_password": MGR_PASS}
    await write(
        "update the manager: verified on the way",
        "PUT",
        f"/api/connectors/{mgr_id}",
        t_admin,
        mgr_id,
        ("https://old-manager.parity.test:55000", "x", "y"),
        mupd,
        mgr3,
        audited=1,
    )
    await write(
        "update the manager: credentials refused",
        "PUT",
        f"/api/connectors/{mgr_id}",
        t_admin,
        mgr_id,
        good_mgr,
        {**mupd, "connector_password": "wrong"},
        mgr3,
        audited=1,
    )
    await write("verify the manager", "POST", f"/api/connectors/verify/{mgr_id}", t_admin, mgr_id, good_mgr, rec=mgr3)
    await write(
        "verify the manager: credentials refused",
        "POST",
        f"/api/connectors/verify/{mgr_id}",
        t_admin,
        mgr_id,
        (mgr3.url, MGR_USER, "wrong"),
        rec=mgr3,
    )
    await write(
        "verify the manager: no user",
        "POST",
        f"/api/connectors/verify/{mgr_id}",
        t_admin,
        mgr_id,
        (mgr3.url, None, MGR_PASS),
        rec=mgr3,
    )
    await write(
        "verify the manager: refusing connections",
        "POST",
        f"/api/connectors/verify/{mgr_id}",
        t_admin,
        mgr_id,
        (gone.url, MGR_USER, MGR_PASS),
    )
    await write(
        "verify the manager: a password Latin-1 cannot carry",
        "POST",
        f"/api/connectors/verify/{mgr_id}",
        t_admin,
        mgr_id,
        (mgr3.url, MGR_USER, "€"),
        rec=mgr3,
    )

    # -- E4. a connector neither backend verifies ---------------------------------------
    await write(
        "update a connector no service verifies",
        "PUT",
        f"/api/connectors/{other_id}",
        t_admin,
        other_id,
        ("https://other.parity.test", "u", "p"),
        {"connector_url": "https://other2.parity.test", "connector_extra_data": "x"},
        audited=1,
    )
    await write(
        "verify a connector no service verifies",
        "POST",
        f"/api/connectors/verify/{other_id}",
        t_admin,
        other_id,
        ("https://other.parity.test", "u", "p"),
    )

    for conn_id in (idx_id, mgr_id, other_id):
        await sql("DELETE FROM connectors WHERE id = :i", i=conn_id)
    await sql(
        "DELETE FROM audit_log WHERE entity_type = 'connector' AND entity_id IN (:a, :b, :c)",
        a=str(idx_id),
        b=str(mgr_id),
        c=str(other_id),
    )
    await settle()

    # ======================================================================
    print("\n=== F. the two indexer jobs, handed over ===")
    from app.schedulers.handover import manual_run
    from app.schedulers.services.invoke_snapshot_and_restore import (
        invoke_snapshot_schedules,
    )
    from app.schedulers.services.wazuh_index_resize import resize_wazuh_index_fields

    SNAP, RESIZE = "invoke_snapshot_schedules", "resize_wazuh_index_fields"
    es4 = Recorder(es_answer, "e4")
    idx4 = await add_connector("Wazuh-Indexer", es4.url, ES_USER, ES_PASS, verified=1)
    for job in (SNAP, RESIZE):
        # Disabled = handed over; a day's interval keeps Rust's own ticks out of the run.
        await sql(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, enabled, job_description) "
            "VALUES (:j, NULL, 1440, NULL, 0, 'parity')",
            j=job,
        )
    rs2_port = int(os.environ.get("RUST_JOBS_PORT", "5595"))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{os.environ['MYSQL_USER']}:{os.environ['MYSQL_PASSWORD']}@{os.environ['MYSQL_URL']}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_PORT": str(rs2_port),
        "COPILOT_RS_JOBS": f"{SNAP},{RESIZE}",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    binary = os.environ.get(
        "COPILOT_BIN",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "target", "debug", "copilot"),
    )
    rs2_proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{rs2_port}/_copilot/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    rs2 = httpx.AsyncClient(base_url=f"http://127.0.0.1:{rs2_port}", timeout=120)
    # A manual run is looked up in APScheduler's store first: put the two jobs there, paused.
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    from app.db.db_session import sync_engine
    from app.schedulers import scheduler as scheduler_module

    aps = AsyncIOScheduler(event_loop=asyncio.get_running_loop())
    aps.configure(jobstores={"default": SQLAlchemyJobStore(engine=sync_engine)})
    aps.start(paused=True)
    for job, minutes in ((SNAP, 15), (RESIZE, 1)):
        aps.add_job(
            scheduler_module.get_function_by_name(job),
            "interval",
            minutes=minutes,
            id=job,
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )
    STAMP = re.compile(r"_\d{8}_\d{6}")
    hour = datetime.datetime.utcnow().hour
    SCHEDULES = [
        # name, pattern, enabled, skip write indices, global state, hour gate, weekday gate, prefix
        (f"nightly {SFX}", f"{IDX_A}_*", 1, 1, 0, None, None, "scheduled"),
        (f"Full {SFX}", f"{IDX_A}_*", 1, 0, 1, None, None, "scheduled"),
        (f"later {SFX}", f"{IDX_A}_*", 1, 1, 0, (hour + 12) % 24, None, "scheduled"),
        (f"off {SFX}", "*", 0, 1, 0, None, None, "scheduled"),
        (f"exact {SFX}", "wazuh-alerts-4.x-2026.10.15", 1, 1, 0, None, None, "daily"),
        (f"broken day {SFX}", "*", 1, 1, 0, None, 9, "scheduled"),
    ]
    sched_ids = []
    for name, pattern, enabled, skip, glob, hr, dow, prefix in SCHEDULES:
        r = await sql(
            "INSERT INTO index_snapshot_schedules (name, index_pattern, repository, enabled, snapshot_prefix, include_global_state, "
            "skip_write_indices, retention_days, last_execution_time, last_snapshot_name, last_execution_status, scheduled_hour, "
            "scheduled_minute, interval_days, day_of_week, timezone, created_at, updated_at) VALUES "
            "(:n, :p, 'backup', :e, :pre, :g, :s, NULL, NULL, NULL, NULL, :h, NULL, 1, :d, 'UTC', :t, :t)",
            n=name,
            p=pattern,
            e=enabled,
            pre=prefix,
            g=glob,
            s=skip,
            h=hr,
            d=dow,
            t=START,
        )
        sched_ids.append(r.lastrowid)

    async def job_effects(job):
        found = await rows(
            "SELECT name, last_execution_time, last_snapshot_name, last_execution_status, updated_at FROM index_snapshot_schedules "
            "WHERE id IN :ids ORDER BY id".replace(":ids", "(" + ",".join(str(i) for i in sched_ids) + ")"),
        )
        out = []
        for r in found:
            out.append(
                {
                    "name": r["name"],
                    "ran": r["last_execution_time"] is not None,
                    "snapshot": STAMP.sub("_<ts>", r["last_snapshot_name"]) if r["last_snapshot_name"] else None,
                    "status": r["last_execution_status"],
                    "touched": str(r["updated_at"]) != START,
                },
            )
        stamp = await rows("SELECT last_success FROM scheduled_job_metadata WHERE job_id = :j", j=job)
        return {"schedules": out, "stamped": stamp[0]["last_success"] is not None}

    async def reset_jobs():
        await sql(
            "UPDATE index_snapshot_schedules SET last_execution_time = NULL, last_snapshot_name = NULL, last_execution_status = NULL, "
            "updated_at = :t WHERE id IN " + "(" + ",".join(str(i) for i in sched_ids) + ")",
            t=START,
        )
        await sql("UPDATE scheduled_job_metadata SET last_success = NULL WHERE job_id IN (:a, :b)", a=SNAP, b=RESIZE)

    async def job_both(name, job, py_fn):
        got = {}
        for tag in ("py", "rs"):
            await reset_jobs()
            es4.captured.clear()
            if tag == "py":
                with manual_run():
                    await py_fn()
            else:
                r = await rs2.post(f"/api/scheduler/jobs/run/{job}", headers=H(t_admin))
                got["rs_status"] = r.status_code
            outbound = normalised(list(es4.captured))
            for c in outbound:
                c["path"] = STAMP.sub("_<ts>", c["path"])
                c["body"] = STAMP.sub("_<ts>", c["body"])
            got[tag] = {"outbound": outbound, **(await job_effects(job))}
        check(
            f"{name}: requests, rows, last_success (rust {got.get('rs_status')})",
            got.get("rs_status") == 200 and json.dumps(got["py"], default=str) == json.dumps(got["rs"], default=str),
            f"python {json.dumps(got['py'], default=str)[:3000]}\n        rust   {json.dumps(got['rs'], default=str)[:3000]}",
        )
        return got

    try:
        snap = await job_both("invoke_snapshot_schedules", SNAP, invoke_snapshot_schedules)
        statuses = [s["status"] for s in snap["rs"]["schedules"]]
        check(
            "the schedules came out as designed",
            statuses[0] == "SKIPPED: No new indices to snapshot (1 write indices skipped) (1 already snapshotted)"
            and statuses[1] == "SUCCESS"
            and statuses[2].startswith("DEFERRED: outside scheduled hour")
            and statuses[3] is None
            and statuses[4] == "SUCCESS"
            and statuses[5] == "FAILED: list index out of range",
            json.dumps(statuses),
        )
        es4.mode["refuse"] = True
        await job_both("invoke_snapshot_schedules: the indexer refusing the snapshots", SNAP, invoke_snapshot_schedules)
        es4.mode.clear()
        await settle()
        await job_both("resize_wazuh_index_fields (verified)", RESIZE, resize_wazuh_index_fields)
        es4.mode["busy"] = True
        await job_both("resize_wazuh_index_fields: the indexer failing (the run still returns)", RESIZE, resize_wazuh_index_fields)
        es4.mode.clear()
        await sql("UPDATE connectors SET connector_verified = 0 WHERE id = :i", i=idx4)
        await settle()
        got = await job_both("resize_wazuh_index_fields (not verified: nothing, no stamp)", RESIZE, resize_wazuh_index_fields)
        check(
            "an unverified indexer is left alone",
            not got["rs"]["outbound"] and not got["rs"]["stamped"],
            json.dumps(got["rs"], default=str),
        )
        # The guard: a scheduled Python tick of a handed-over job does nothing.
        es4.captured.clear()
        skipped = await invoke_snapshot_schedules()
        check("python: a handed-over job's scheduled tick is skipped", repr(skipped) == "JOB_SKIPPED" and not es4.captured, repr(skipped))
    finally:
        for job in (SNAP, RESIZE):
            aps.remove_job(job)
        aps.shutdown(wait=False)
        await rs2.aclose()
        rs2_proc.terminate()
        try:
            rs2_proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            rs2_proc.kill()
        await sql("DELETE FROM index_snapshot_schedules WHERE id IN " + "(" + ",".join(str(i) for i in sched_ids) + ")")
        await sql("DELETE FROM scheduled_job_metadata WHERE job_id IN (:a, :b)", a=SNAP, b=RESIZE)
        await sql("DELETE FROM connectors WHERE id = :i", i=idx4)
        await settle()

    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
