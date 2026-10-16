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
import sys
import threading
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
    def __init__(self, answer):
        self.answer = answer
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

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


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


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors
    from app.routers import wazuh_indexer

    api = APIRouter(prefix="/api")
    api.include_router(connectors.router)
    api.include_router(wazuh_indexer.router)
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

    async def both(name, method, path, tok=None, body=None, rec=None, unordered=False, norm=None, raw=None, ctype="application/json"):
        """The responses, and — with `rec` — what each backend sent to that stand-in."""
        got = {}
        responses = {}
        for tag, client in (("py", py), ("rs", rs)):
            if rec is not None:
                rec.captured.clear()
            responses[tag] = await call(client, method, path, tok, body, raw, ctype)
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
    await both("alerts (defaults)", "POST", "/api/alerts", t_analyst, {}, rec=es)
    await both(
        "alerts: other field and window",
        "POST",
        "/api/alerts",
        t_analyst,
        {"size": 2, "timerange": "2w", "alert_field": "rule_description", "alert_value": "Mimikatz é", "timestamp_field": "@timestamp"},
        rec=es,
    )
    await both("alerts: days window", "POST", "/api/alerts", t_analyst, {"timerange": "3d"}, rec=es)
    await both("host alerts", "POST", "/api/alerts/host", t_analyst, {"agent_name": "dc01", "timerange": "1h"}, rec=es)
    await both("index alerts", "POST", "/api/alerts/index", t_analyst, {"index_name": f"  {IDX_A}_1 "}, rec=es)
    await both("index alerts: unmanaged index", "POST", "/api/alerts/index", t_analyst, {"index_name": ".kibana_1"}, rec=es)
    await both("index alerts: the timestamp fallback", "POST", "/api/alerts/index", t_analyst, {"index_name": "nomap_0"}, rec=es)
    await both("by host", "POST", "/api/alerts/hosts/all", t_analyst, {}, rec=es)
    await both("by rule", "POST", "/api/alerts/rules/all", t_analyst, {"size": 5}, rec=es)
    await both("by rule per host", "POST", "/api/alerts/rules/hosts/all", t_analyst, {}, rec=es)
    es.mode["bad_agent"] = True
    await both("by host: a non-string agent name", "POST", "/api/alerts/hosts/all", t_analyst, {}, rec=es)
    es.mode.clear()
    es.mode["broken"] = True
    await both("alerts: an index failing with another 400", "POST", "/api/alerts", t_analyst, {}, rec=es)
    es.mode.clear()
    es.mode["no_alerts"] = True
    await both("index alerts: none found", "POST", "/api/alerts/index", t_analyst, {"index_name": "wazuh-alerts-4.x-2026.10.15"}, rec=es)
    es.mode.clear()
    await both("by id", "POST", "/api/alerts/by-id", t_analyst, {"index_name": f" {IDX_A}_1", "alert_id": "a2 "}, rec=es)
    await both("by id: not found", "POST", "/api/alerts/by-id", t_analyst, {"index_name": f"{IDX_A}_1", "alert_id": "nope"}, rec=es)
    await both("by id: missing index", "POST", "/api/alerts/by-id", t_analyst, {"index_name": "missing-index", "alert_id": "x/y z"}, rec=es)
    await both("by id: empty id is a ValueError", "POST", "/api/alerts/by-id", t_analyst, {"index_name": "x", "alert_id": "  "}, rec=es)
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
    await sql("UPDATE connectors SET connector_url = :u WHERE id = :i", u=es2.url, i=indexer_id)
    es.captured.clear()
    es2.captured.clear()
    await call(rs, "GET", "/api/wazuh_indexer/health", t_analyst)
    check(
        "rust: inside the check interval the cached row may still be used",
        len(es.captured) == 1 and not es2.captured,
        f"{len(es.captured)} / {len(es2.captured)}",
    )
    await settle()
    es.captured.clear()
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

    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
