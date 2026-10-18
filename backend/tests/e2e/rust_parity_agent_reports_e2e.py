"""Parity of the agents' report routers (`crates/copilot-agent-reports`: /api/vulnerabilities,
/api/sca, /api/syscollector) and of Velociraptor's MinIO collections (`crates/copilot-velociraptor`:
POST /api/artifacts/collect and /api/artifacts/collect/file/agent/{agent_id}) with this backend —
NOT collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers (in-process, with copilot.py's GZipMiddleware) and a Rust instance this
suite starts answer the same requests on one database. Every upstream is a local stand-in that
records each request whole, every header the client library sends included:

* one HTTP stand-in for the Wazuh indexer (the vulnerability states and their scroll, the package
  inventory), the Wazuh manager (token flow, SCA, syscollector), the CoPilot-SCA repository on
  GitHub (`COPILOT_SCA_REPO_URL` for Rust, the patched `COPILOT_SCA_RAW_BASE` here) and
  api.first.org's EPSS API (`COPILOT_EPSS_URL` for Rust, `invoke_epss_api`'s URL replaced here);
* MinIO: the objectstore suite's `S3StandIn`, which verifies every SigV4 signature (Python's
  `create_session()` is pointed at it, Rust through `COPILOT_MINIO_ENDPOINT`);
* Velociraptor: the agents suite's grpcio stand-in over mutual TLS, recording each
  `VQLCollectorArgs` byte for byte with its deadline.

For each check: the status, the content type, the body (report ids and times masked), every
upstream request, the MinIO requests and what they changed, and the rows a write leaves.
Requests a backend sends concurrently (the SCA collection, 100 at a time) are compared as a set,
as are the stream's per-agent events. One header is normalised: elasticsearch-py names the full
Python version in its `User-Agent` (`Python 3.11.17`), the Rust port the minor one.

Deliberate differences (RUST_MIGRATION.md §4), each checked as such: the per-agent vulnerability
list is the caller's customers' only; a host's sync is refused for another tenant's host; the
indexer package search covers the caller's agents only; the registry lookup's message counts the
caller's matches.

Ports (all overridable): AGENT_REPORTS_PARITY_RUST_PORT (5740, the Rust instance),
AGENT_REPORTS_PARITY_STUB_PORT (5741), AGENT_REPORTS_PARITY_S3_PORT (5742),
AGENT_REPORTS_PARITY_VELO_PORT (5743). Ids are explicit, seven digits, in disjoint ranges.

    PARITY_SUITES=tests/e2e/rust_parity_agent_reports_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
import hashlib
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
from urllib.parse import parse_qsl
from urllib.parse import unquote

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ.setdefault("VELOCIRAPTOR_QUERY_TIMEOUT", "5")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx  # noqa: E402
import jwt  # noqa: E402
import rust_parity_agents_e2e as agents_parity  # noqa: E402 - the Velociraptor stand-in
import rust_parity_objectstore_e2e as objectstore_parity  # noqa: E402 - the MinIO stand-in
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from miniopy_async import Minio  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("AGENT_REPORTS_PARITY_RUST_PORT", "5740"))
STUB_PORT = int(os.environ.get("AGENT_REPORTS_PARITY_STUB_PORT", "5741"))
S3_PORT = int(os.environ.get("AGENT_REPORTS_PARITY_S3_PORT", "5742"))
VELO_PORT = int(os.environ.get("AGENT_REPORTS_PARITY_VELO_PORT", "5743"))
STUB = f"http://127.0.0.1:{STUB_PORT}"
S3_USER, S3_SECRET = "reports-parity", "reports-parity-secret"
ES_USER, ES_PASS = "parity-indexer", f"es-{SFX}"
MGR_USER, MGR_PASS = "parity-wazuh", f"mgr-{SFX}"
CUST_A, CUST_B = f"RpA{SFX}", f"RpB{SFX}"
ADMIN, ANALYST, PORTAL, SCHED = f"rp_admin{SFX}", f"rp_analyst{SFX}", f"rp_portal{SFX}", f"rp_sched{SFX}"
USERS = (ADMIN, ANALYST, PORTAL, SCHED)
OUR_CONNECTORS = ("Wazuh-Manager", "Wazuh-Indexer", "Velociraptor")
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


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(text(statement), params)]


def in_list(values):
    return "(" + ",".join(repr(str(v)) for v in values) + ")"


# --- Seed --------------------------------------------------------------------------------------------
#: key -> (agent_id, hostname, os, customer, velociraptor_id)
AGENTS = {
    "a1": (f"{SFX}a1", f"rp-a1-{SFX}", "Ubuntu 22.04", CUST_A, f"C.{SFX}a1"),
    "a2": (f"{SFX}a2", f"rp-a2-{SFX}", "Ubuntu 22.04", CUST_A, None),
    "w1": (f"{SFX}e1", f"rp-w1-{SFX}", "Microsoft Windows 11 Pro", CUST_A, f"C.{SFX}e1"),
    "b1": (f"{SFX}b1", f"rp-b1-{SFX}", "Ubuntu 22.04", CUST_B, f"C.{SFX}b1"),
}
IDS = {}


def seed():
    top = 0
    for table in ("agents", "vulnerability_reports", "sca_reports", "agent_vulnerabilities", "agent_datastore"):
        top = max(top, rows(f"SELECT COALESCE(MAX(id), 0) AS n FROM {table}")[0]["n"])
    base = max(top + 1000, 3_000_000)
    # Disjoint ranges: agents base.., stored reports base+1000.. (vulnerabilities) and base+2000.. (SCA).
    IDS.update({"agent": base, "vreport": base + 1000, "sreport": base + 2000})
    for c in (CUST_A, CUST_B):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=c, n=f"{c} Corp")
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (SCHED, 3)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r)",
            n=name,
            e=f"{name}@parity.test",
            r=role,
        )
    for name in (ANALYST, PORTAL):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` "
            "WHERE username = :n",
            c=CUST_A,
            n=name,
        )
    for i, (key, (agent_id, host, os_name, cust, vid)) in enumerate(AGENTS.items()):
        IDS[key] = base + i
        sql(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, velociraptor_id, "
            "wazuh_agent_version, wazuh_agent_status, customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) VALUES "
            "(:i, :a, '10.0.0.9', :os, :h, 'grp', 0, '2026-10-15 08:00:00', :v, 'Wazuh v4.9.0', 'active', :c, 0, :o, 0)",
            i=IDS[key],
            a=agent_id,
            os=os_name,
            h=host,
            v=vid,
            c=cust,
            o="root" if vid else None,
        )


def our_agent_ids():
    return in_list(a[0] for a in AGENTS.values())


def reset_vulns():
    sql("DELETE FROM agent_vulnerabilities WHERE agent_id IN " + our_agent_ids())


def vuln_rows():
    return rows(
        "SELECT cve_id, severity, title, `references`, status, discovered_at, remediated_at, epss_score, epss_percentile, "
        "package_name, agent_id, customer_code FROM agent_vulnerabilities WHERE agent_id IN " + our_agent_ids() + " ORDER BY id",
    )


def set_connector(name, url, username=None, password=None, api_key=None):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
        "(:n, '4.8.0', :u, '2026-01-02 03:04:05', :user, :pw, :key, 'Parity connector', 'everything', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
        key=api_key,
    )


def cleanup():
    if not IDS:
        return
    ours = our_agent_ids()
    sql("DELETE FROM agent_vulnerabilities WHERE agent_id IN " + ours)
    sql("DELETE FROM agent_datastore WHERE agent_id IN " + ours)
    sql("DELETE FROM vulnerability_reports WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    sql("DELETE FROM sca_reports WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    sql("DELETE FROM agents WHERE id IN " + in_list(IDS[k] for k in AGENTS))
    sql("DELETE FROM audit_log WHERE actor_username IN " + in_list(USERS))
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username IN " + in_list(USERS) + ")")
    sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username IN " + in_list(USERS) + ")")
    sql("DELETE FROM `user` WHERE username IN " + in_list(USERS))
    sql("DELETE FROM customers WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)


# --- The upstream stand-in ------------------------------------------------------------------------------


def jbody(obj):
    return json.dumps(obj).encode()


def ok(obj):
    return 200, "application/json", jbody(obj)


class Upstream:
    """One HTTP server for the indexer, the manager, GitHub and EPSS, by path. Every request is
    recorded whole: method, path with its query, every header, the body."""

    def __init__(self, port):
        self.captured = []
        self.mode = {}
        self.pages = {}
        self.lock = threading.Lock()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k.lower(): v for k, v in self.headers.items()}
                with upstream.lock:
                    upstream.captured.append({"method": self.command, "path": self.path, "headers": headers, "body": body})
                status, ctype, payload = upstream.answer(self.command, self.path, headers, body)
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

    def take(self):
        with self.lock:
            out, self.captured[:] = list(self.captured), []
        return out

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def answer(self, method, raw_path, headers, body):
        path, _, query = raw_path.partition("?")
        if path.startswith("/sca-repo/"):
            return self.github(path[len("/sca-repo") :])
        if path == "/data/v1/epss":
            return self.epss(query)
        if path == "/security/user/authenticate" or path.startswith("/sca/") or path.startswith("/syscollector/"):
            return self.manager(method, path, query, headers)
        return self.indexer(method, path, query, headers, body)

    # The CoPilot-SCA repository.
    def github(self, path):
        mode = self.mode
        if path == "/index.json":
            if mode.get("index") == "missing":
                return 404, "text/plain; charset=utf-8", b"404: Not Found"
            if mode.get("index") == "not_json":
                return 200, "text/plain; charset=utf-8", b"<html>rate limited</html>"
            if mode.get("index") == "bad_policy":
                return ok({"version": "2", "policies": [{"id": "x", "name": "no file"}]})
            if mode.get("index") == "list":
                return ok([1, 2])
            return ok(SCA_INDEX)
        if path == "/apache/cis_apache_24.yml":
            return 200, "text/plain; charset=utf-8", 'policy:\n  id: cis_apache_24\n  name: "CIS é"\n'.encode()
        return 404, "text/plain; charset=utf-8", b"404: Not Found"

    def epss(self, query):
        params = dict(parse_qsl(query))
        scores = {"CVE-2026-1001": "0.97341", "CVE-2026-1002": "0.00042"}
        cve = params.get("cve", "")
        data = [{"cve": cve, "epss": scores[cve], "percentile": "0.99", "date": "2026-10-15"}] if cve in scores else []
        return ok({"status": "OK", "status-code": 200, "version": "1.0", "total": len(data), "data": data})

    # The Wazuh manager.
    def manager(self, method, path, query, headers):
        mode = self.mode
        if path == "/security/user/authenticate":
            expected = "Basic " + base64.b64encode(f"{MGR_USER}:{MGR_PASS}".encode()).decode()
            if headers.get("authorization") != expected:
                return 401, "application/json", jbody({"title": "Unauthorized", "error": 401})
            return ok({"data": {"token": f"tok-{SFX}"}, "error": 0})
        if headers.get("authorization") != f"Bearer tok-{SFX}":
            return 401, "application/json", jbody({"title": "Unauthorized", "error": 401})
        if path.startswith("/syscollector/"):
            agent = unquote(path.split("/")[2])
            if mode.get("syscollector") == "fail":
                return 500, "text/html", b"<html>boom</html>"
            items = SYSCOLLECTOR.get(agent, [])
            return ok({"data": {"affected_items": items, "total_affected_items": len(items) + 10, "failed_items": []}, "error": 0})
        agent = unquote(path.split("/")[2])
        if agent not in SCA:
            return 400, "application/problem+json", jbody({"title": "Wazuh Cluster Error", "detail": "Unknown node ID", "error": 3022})
        return ok({"data": {"affected_items": SCA[agent], "total_affected_items": len(SCA[agent])}, "error": 0})

    # The Wazuh indexer.
    def indexer(self, method, path, query, headers, body):
        expected = "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        if headers.get("authorization") != expected:
            return 401, "application/json", jbody({"error": "unauthorized", "status": 401})
        if method == "GET" and path == "/*/_alias":
            return ok({n: {"aliases": {}} for n in ("wazuh-states-vulnerabilities-node1", "wazuh-alerts-4.x-2026.10.15")})
        doc = json.loads(body or b"{}")
        if path == "/_search/scroll":
            if method == "DELETE":
                return ok({"succeeded": True, "num_freed": 1})
            sid = doc.get("scroll_id", "")
            stem, _, n = sid.rpartition("-")
            page = int(n) + 1
            hits = self.pages.get(stem, [])
            return ok({"_scroll_id": f"{stem}-{page}", "hits": {"hits": hits[page * 2 : page * 2 + 2]}})
        if path.startswith("/wazuh-states-inventory-packages-"):
            docs = filter_docs(PACKAGES, doc)
            return ok({"took": 1, "hits": {"total": {"value": len(docs), "relation": "eq"}, "hits": docs}})
        docs = filter_docs(VULN_DOCS, doc)
        if path.endswith("/_count"):
            return ok({"count": len(docs), "_shards": {"total": 1}})
        if "aggs" in doc:
            buckets = {}
            for d in docs:
                sev = d["_source"]["vulnerability"]["severity"]
                buckets[sev] = buckets.get(sev, 0) + 1
            return ok(
                {
                    "hits": {"total": {"value": len(docs)}, "hits": []},
                    "aggregations": {"severity_counts": {"buckets": [{"key": k, "doc_count": n} for k, n in buckets.items()]}},
                },
            )
        if "scroll=" in query:
            # The same request gets the same scroll id, whichever backend sends it.
            stem = "s" + hashlib.sha1(path.encode() + body).hexdigest()[:10]
            self.pages[stem] = docs
            return ok({"_scroll_id": f"{stem}-0", "hits": {"total": {"value": len(docs)}, "hits": docs[:2]}})
        start, size = doc.get("from", 0), doc.get("size", 10)
        return ok({"hits": {"total": {"value": len(docs)}, "hits": docs[start : start + size]}})


def clause_values(query, out):
    """Every (field, value) a bool query's term/terms/match/wildcard clauses name."""
    if isinstance(query, dict):
        for kind in ("term", "terms", "match"):
            if kind in query and isinstance(query[kind], dict):
                for k, v in query[kind].items():
                    out.append((k, v if isinstance(v, list) else [v]))
        if "wildcard" in query and isinstance(query["wildcard"], dict):
            for k, v in query["wildcard"].items():
                pattern = v["value"] if isinstance(v, dict) else v
                out.append((k, ("wildcard", pattern.strip("*").lower())))
        for v in query.values():
            clause_values(v, out)
    elif isinstance(query, list):
        for v in query:
            clause_values(v, out)
    return out


def field_of(doc, dotted):
    node = doc["_source"]
    for part in dotted.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def filter_docs(docs, request):
    """The documents a request's `must` (or `should`) clauses select."""
    query = request.get("query", {})
    should = query.get("bool", {}).get("should")
    if should:
        out = []
        for d in docs:
            for _, cond in clause_values(should, []):
                name = (field_of(d, "package.name") or "").lower()
                if cond[0] == "wildcard" and cond[1] in name:
                    out.append(d)
                    break
        return out
    conds = clause_values(query, [])
    out = []
    for d in docs:
        keep = True
        for field, cond in conds:
            value = field_of(d, field)
            if isinstance(cond, tuple):
                keep = keep and cond[1] in str(value or "").lower()
            else:
                keep = keep and value in cond
        if keep:
            out.append(d)
    return out


def vuln_doc(doc_id, key, cve, severity, package="openssl", reference=None, base_score=7.5, detected="2026-10-03T11:00:00.000Z"):
    agent_id, host = AGENTS[key][0], AGENTS[key][1]
    return {
        "_index": "wazuh-states-vulnerabilities-node1",
        "_id": doc_id,
        "_source": {
            "agent": {"id": agent_id, "name": host},
            "package": {"name": package, "version": "3.0.2", "type": "deb", "architecture": "amd64"},
            "vulnerability": {
                "id": cve,
                "severity": severity,
                "description": f"{cve} description, with a comma",
                "detected_at": detected,
                "published_at": "2025-01-01T00:00:00Z",
                "reference": reference if reference is not None else f"https://nvd.nist.gov/vuln/detail/{cve}",
                "score": {"base": base_score},
            },
        },
    }


VULN_DOCS = []
PACKAGES = []
SCA = {}
SYSCOLLECTOR = {}
SCA_INDEX = {
    "version": "1.4",
    "last_updated": "2026-10-01",
    "policies": [
        {
            "id": "cis_apache_24",
            "name": "CIS Apache HTTP Server 2.4",
            "description": "Apache benchmark",
            "file": "apache/cis_apache_24.yml",
            "application": "apache",
            "app_version": "2.4",
            "platform": "linux",
            "cis_version": "2.0.0",
            "extra": "ignored",
        },
        {
            "id": "cis_nginx",
            "name": "CIS NGINX",
            "description": "NGINX benchmark",
            "file": "nginx/cis_nginx.yml",
            "application": "nginx",
            "app_version": "1.x",
            "platform": "linux",
            "cis_version": "1.0.0",
        },
    ],
}


def fill_upstream_data():
    a1, a2, b1 = (AGENTS[k][0] for k in ("a1", "a2", "b1"))
    VULN_DOCS[:] = [
        vuln_doc("v1", "a1", "CVE-2026-1001", "Critical", reference="https://a.example, https://b.example,,  https://c.example"),
        vuln_doc("v2", "a1", "CVE-2026-1002", "High", package="curl", base_score=0),
        vuln_doc("v3", "a1", "CVE-2026-1003", "Low", package="zlib", detected="2026-10-01T09:00:00+02:00"),
        vuln_doc("v4", "a2", "CVE-2026-1004", "Medium", package="bash"),
        vuln_doc("v5", "b1", "CVE-2026-1005", "High", package="sudo"),
    ]
    PACKAGES[:] = [
        {
            "_index": "wazuh-states-inventory-packages-node1",
            "_id": "p1",
            "_source": {
                "agent": {"id": a1, "name": AGENTS["a1"][1], "version": "v4.9.0", "groups": ["x"]},
                "package": {"name": "apache2", "version": "2.4.58", "architecture": "amd64", "type": "deb", "size": 1024},
            },
        },
        {
            "_index": "wazuh-states-inventory-packages-node1",
            "_id": "p2",
            "_source": {"agent": {"id": a1, "name": AGENTS["a1"][1]}, "package": {"name": "apache2-bin", "version": "2.4.58"}},
        },
        {
            "_index": "wazuh-states-inventory-packages-node1",
            "_id": "p3",
            "_source": {"agent": {"id": b1, "name": AGENTS["b1"][1]}, "package": {"name": "apache2", "vendor": "Debian"}},
        },
        {
            "_index": "wazuh-states-inventory-packages-node1",
            "_id": "p4",
            "_source": {"agent": {"id": a2, "name": AGENTS["a2"][1]}, "package": {"name": "openssl"}},
        },
    ]

    def policy(pid, name, score, refs=None):
        return {
            "policy_id": pid,
            "description": f"{name} benchmark",
            "fail": 10 - score // 10,
            "start_scan": "2026-10-01T00:00:00Z",
            "references": refs,
            "name": name,
            "pass": score // 10,
            "score": score,
            "end_scan": "2026-10-01T00:05:00Z",
            "total_checks": 10,
            "hash_file": "abc",
            "invalid": 0,
        }

    SCA.clear()
    SCA[a1] = [policy("cis_ubuntu", "CIS Ubuntu 22.04", 80, "https://www.cisecurity.org/"), policy("cis_ssh", "CIS OpenSSH", 55)]
    SCA[a2] = [policy("cis_ubuntu", "CIS Ubuntu 22.04", 40)]
    SCA[b1] = [policy("cis_ubuntu", "CIS Ubuntu 22.04", 90)]
    SYSCOLLECTOR.clear()
    SYSCOLLECTOR[a1] = [
        {
            "scan": {"id": 0, "time": "2026-10-15T08:00:00Z"},
            "name": "openssl",
            "version": "3.0.2",
            "architecture": "amd64",
            "format": "deb",
            "size": 2048,
            "vendor": "Ubuntu Developers",
            "agent_id": a1,
            "install_time": "2026-01-01",
            "multiarch": None,
        },
    ]


# --- The two backends ------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import agents
    from app.routers import velociraptor

    api = APIRouter(prefix="/api")
    api.include_router(agents.router)
    api.include_router(velociraptor.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    # As in copilot.py: it decides how a download (and not the event stream) is encoded.
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def patch_python():
    """Point the Python services at the stand-ins (the one change this suite makes to Python)."""
    from app.agents.sca.services import sca as sca_module
    from app.data_store import data_store_operations
    from app.threat_intel.services import epss as epss_module

    async def create_session():
        return Minio(f"127.0.0.1:{S3_PORT}", access_key=S3_USER, secret_key=S3_SECRET, secure=False)

    data_store_operations.create_session = create_session
    sca_module.COPILOT_SCA_RAW_BASE = f"{STUB}/sca-repo"
    sca_module.COPILOT_SCA_INDEX_URL = f"{STUB}/sca-repo/index.json"
    original = epss_module.invoke_epss_api

    async def invoke_epss_api(url, request):
        return await original(f"{STUB}/data/v1/epss", request)

    epss_module.invoke_epss_api = invoke_epss_api


def start_rust():
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
        "COPILOT_PORT": str(RS_PORT),
        "MINIO_ROOT_USER": S3_USER,
        "MINIO_ROOT_PASSWORD": S3_SECRET,
        "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{S3_PORT}",
        "COPILOT_SCA_REPO_URL": f"{STUB}/sca-repo",
        "COPILOT_EPSS_URL": f"{STUB}/data/v1/epss",
        "VELOCIRAPTOR_QUERY_TIMEOUT": os.environ["VELOCIRAPTOR_QUERY_TIMEOUT"],
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


# --- Normalisation ---------------------------------------------------------------------------------

PY_VERSION = re.compile(r"\(Python 3\.11(\.\d+)?\)")
DATETIME_REPR = re.compile(r"datetime\.datetime\([0-9, ]+\)")
VOLATILE = {"id", "report_id", "generated_at", "download_url"}


def upstream_view(captures, unordered=False):
    out = []
    for c in captures:
        headers = {k: (PY_VERSION.sub("(Python 3.11)", v) if k == "user-agent" else v) for k, v in c["headers"].items()}
        out.append(
            {
                "method": c["method"],
                "path": c["path"],
                "headers": dict(sorted(headers.items())),
                "body": c["body"].decode("utf-8", "replace"),
            },
        )
    if unordered:
        out.sort(key=json.dumps)
    return out


def substitute(value, subst):
    for old, new in subst:
        value = value.replace(old, new)
    return value


def mask(value, subst=()):
    if isinstance(value, dict):
        return {k: ("<v>" if k in VOLATILE and v is not None else mask(v, subst)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, subst) for v in value]
    if isinstance(value, str):
        return DATETIME_REPR.sub("datetime.datetime(…)", substitute(value, subst))
    return value


def decoded(r):
    """A body as the client sees it (httpx decodes a gzipped one)."""
    try:
        return r.json()
    except ValueError:
        return r.text


# Headers compared on every answer (the Rust CORS layer adds `Origin` to `Vary`: not this module's).
ANSWER_HEADERS = ("content-type", "content-disposition", "content-encoding", "cache-control", "x-accel-buffering")


def answer_headers(r):
    out = {k: r.headers.get(k) for k in ANSWER_HEADERS}
    # Header names are case-insensitive, in `Vary` too (Starlette writes `Accept-Encoding`, tower-http
    # `accept-encoding`).
    out["vary"] = [v.strip().lower() for v in (r.headers.get("vary") or "").split(",") if v.strip().lower() == "accept-encoding"]
    return out


S3 = objectstore_parity.S3StandIn(S3_USER, S3_SECRET)


class Pair:
    def __init__(self, upstream, velo):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=180,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=180)
        self.up = upstream
        self.velo = velo

    async def call(self, client, method, path, tok, kw):
        headers = {"Accept-Encoding": "identity", **dict(kw.get("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        args = {k: v for k, v in kw.items() if k != "headers"}
        return await client.request(method, path, headers=headers, **args)

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        before=None,
        db=None,
        unordered=False,
        settle=None,
        body_view=None,
        expect_diff=None,
        **kw,
    ):
        """Python, then Rust, from the same state (`before` sets it up for each). `settle(tag)` waits
        for what a backend does after its answer; `body_view` shapes a body before the comparison;
        `expect_diff(py, rs)` replaces the equality of the bodies for a deliberate difference."""
        got = {}
        start = S3.snapshot()
        for tag, client in (("py", self.py), ("rs", self.rs)):
            S3.restore(start)
            if before:
                before()
            self.up.take()
            S3.take()
            self.velo.take()
            r = await self.call(client, method, path, tok, kw)
            if settle:
                await settle(tag)
            else:
                await asyncio.sleep(0.05)
            body = decoded(r)
            got[tag] = {
                "status": r.status_code,
                "headers": answer_headers(r),
                "body": body_view(body) if body_view else body,
                "upstream": upstream_view(self.up.take(), unordered),
                "s3": objectstore_parity.outbound(S3.take()),
                "minio": objectstore_parity.changes(start, S3.snapshot()),
                "velo": sorted(self.velo.take(), key=json.dumps) if unordered else self.velo.take(),
                "rows": mask(db()) if db else None,
            }
        p, q = got["py"], got["rs"]
        detail = []
        for key in ("status", "headers", "upstream", "s3", "minio", "velo", "rows"):
            if p[key] != q[key]:
                detail.append(
                    f"{key}\n          python {json.dumps(p[key], default=str)[:1800]}\n          rust   {json.dumps(q[key], default=str)[:1800]}",
                )
        bp, bq = mask(p["body"]), mask(q["body"])
        if expect_diff:
            # A deliberate difference: the check names what must hold instead.
            reason = expect_diff(p, q)
            detail = [f"by design: {reason}"] if reason else []
        elif json.dumps(bp, default=str) != json.dumps(bq, default=str):
            detail.append(
                f"body\n          python {json.dumps(bp, default=str)[:1800]}\n          rust   {json.dumps(bq, default=str)[:1800]}",
            )
        if any(o[-1] != "ok" for o in p["s3"] + q["s3"]):
            detail.append(f"signatures python {[o[-1] for o in p['s3']]} rust {[o[-1] for o in q['s3']]}")
        check(f"{name} [{p['status']}]", not detail, "\n        ".join(detail))
        return p, q

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


async def wait_quiet(recorders, quiet=1.0, limit=30.0):
    """Until no recorder has seen anything new for `quiet` seconds."""
    deadline = time.time() + limit
    last, since = None, time.time()
    while time.time() < deadline:
        now = [len(r.captured) for r in recorders]
        if now != last:
            last, since = now, time.time()
        elif time.time() - since >= quiet:
            return
        await asyncio.sleep(0.1)


# --- Checks: /api/vulnerabilities ---------------------------------------------------------------------
V = "/api/vulnerabilities"


async def vulnerability_checks(p, t):
    a1, b1 = AGENTS["a1"][0], AGENTS["b1"][0]
    host_a1, host_a2, host_b1 = AGENTS["a1"][1], AGENTS["a2"][1], AGENTS["b1"][1]

    # The sync: batch and bulk mode, a fresh table and one already holding the rows.
    await p.same("sync one host (batch)", "POST", f"{V}/sync/agent/{host_a1}", t["analyst"], before=reset_vulns, db=vuln_rows)
    await p.same(
        "sync one host (bulk)",
        "POST",
        f"{V}/sync/agent/{host_a1}?use_bulk_mode=true",
        t["analyst"],
        before=reset_vulns,
        db=vuln_rows,
    )

    def seeded():
        reset_vulns()
        sql(
            "INSERT INTO agent_vulnerabilities (cve_id, severity, title, `references`, status, discovered_at, package_name, agent_id, "
            "customer_code, epss_score) VALUES ('CVE-2026-1001', 'Low', 'old', NULL, 'Active', '2020-01-01 00:00:00', 'openssl', :a, :c, '0.5')",
            a=a1,
            c=CUST_A,
        )

    await p.same("sync updates the rows it finds (batch)", "POST", f"{V}/sync/agent/{host_a1}", t["analyst"], before=seeded, db=vuln_rows)
    await p.same(
        "sync updates the rows it finds (bulk)",
        "POST",
        f"{V}/sync/agent/{host_a1}?use_bulk_mode=true&batch_size=2",
        t["analyst"],
        before=seeded,
        db=vuln_rows,
    )
    await p.same(
        "sync files the rows under the requested customer",
        "POST",
        f"{V}/sync/agent/{host_a2}?customer_code={CUST_A}",
        t["admin"],
        before=reset_vulns,
        db=vuln_rows,
    )
    await p.same("sync of an unknown host", "POST", f"{V}/sync/agent/nobody-{SFX}", t["admin"], before=reset_vulns, db=vuln_rows)
    await p.same(
        "sync of a customer",
        "POST",
        f"{V}/sync/customer/{CUST_A}?use_bulk_mode=true",
        t["analyst"],
        before=reset_vulns,
        db=vuln_rows,
    )
    await p.same("sync of another tenant", "POST", f"{V}/sync/customer/{CUST_B}", t["analyst"], before=reset_vulns, db=vuln_rows)
    await p.same("sync batch size 0", "POST", f"{V}/sync/customer/{CUST_A}?batch_size=0", t["admin"], before=reset_vulns, db=vuln_rows)
    await p.same("sync with a bad batch size", "POST", f"{V}/sync?batch_size=0", t["admin"])
    await p.same("sync with a bad body", "POST", f"{V}/sync", t["admin"], json={"force_refresh": "maybe"})
    await p.same("sync as a portal user", "POST", f"{V}/sync", t["portal"])
    await p.same("sync of a host with someone else's customer", "POST", f"{V}/sync/agent/{host_a1}?customer_code={CUST_B}", t["analyst"])

    # §4: another tenant's host.
    def refused(py, rs):
        if py["status"] != 200 or py["body"].get("success") is not True or not py["upstream"]:
            return f"python {py['status']} {py['body']}"
        if rs["status"] != 403 or rs["body"].get("message") != f"Access denied to host {host_b1}" or rs["upstream"]:
            return f"rust {rs['status']} {rs['body']} {len(rs['upstream'])} upstream requests"
        return None

    await p.same(
        "sync of another tenant's host (Rust refuses it)",
        "POST",
        f"{V}/sync/agent/{host_b1}",
        t["analyst"],
        before=reset_vulns,
        expect_diff=refused,
        db=None,
    )

    def synced():
        reset_vulns()
        for key in ("a1", "a2", "b1"):
            for d in VULN_DOCS:
                if d["_source"]["agent"]["name"] != AGENTS[key][1]:
                    continue
                v = d["_source"]["vulnerability"]
                sql(
                    "INSERT INTO agent_vulnerabilities (cve_id, severity, title, `references`, status, discovered_at, package_name, "
                    "agent_id, customer_code) VALUES (:cve, :sev, :t, NULL, 'Active', '2026-10-03 11:00:00', :pkg, :a, :c)",
                    cve=v["id"],
                    sev=v["severity"],
                    t=d["_source"]["package"]["name"],
                    pkg=d["_source"]["package"]["name"],
                    a=AGENTS[key][0],
                    c=AGENTS[key][3],
                )

    synced()
    await p.same("one agent's rows", "GET", f"{V}/agent/{a1}", t["analyst"])
    await p.same("one agent's rows by severity", "GET", f"{V}/agent/{a1}?severity=Critical&severity=Low", t["analyst"])
    await p.same("another tenant's agent as admin", "GET", f"{V}/agent/{b1}", t["admin"])

    def narrowed(py, rs):
        if py["status"] != 200 or rs["status"] != 200 or not py["body"].get("vulnerabilities") or rs["body"].get("vulnerabilities") != []:
            return f"python {py['status']} {py['body']} rust {rs['status']} {rs['body']}"
        expected = dict(py["body"], vulnerabilities=[], total_count=0, message=f"Retrieved 0 vulnerabilities for agent {b1}")
        if rs["body"] != expected:
            return f"rust {rs['body']} expected {expected}"
        return None

    await p.same("another tenant's agent's rows (Rust lists none)", "GET", f"{V}/agent/{b1}", t["analyst"], expect_diff=narrowed)
    await p.same("statistics", "GET", f"{V}/stats", t["analyst"])
    await p.same("statistics of a customer", "GET", f"{V}/stats?customer_code={CUST_A}", t["admin"])
    await p.same("statistics of another tenant", "GET", f"{V}/stats?customer_code={CUST_B}", t["analyst"])

    # The indexer search.
    await p.same("search", "GET", f"{V}/search?include_epss=false", t["analyst"])
    await p.same("search with EPSS", "GET", f"{V}/search", t["analyst"])
    await p.same("search as admin, filtered", "GET", f"{V}/search?severity=High&package_name=cur&page_size=1&page=1", t["admin"])
    await p.same("search a second page", "GET", f"{V}/search?customer_codes={CUST_A}&page_size=2&page=2&include_epss=false", t["admin"])
    await p.same("search another tenant", "GET", f"{V}/search?customer_codes={CUST_B}", t["analyst"])
    await p.same("search an unknown host", "GET", f"{V}/search?agent_name=nobody-{SFX}", t["admin"])
    await p.same("search too deep", "GET", f"{V}/search?agent_name={host_a1}&page=300&page_size=50&include_epss=false", t["admin"])
    await p.same("search with a bad page", "GET", f"{V}/search?page=0&page_size=2000", t["admin"])

    # The delete.
    await p.same("delete without a scope", "DELETE", f"{V}/delete", t["admin"])
    await p.same("delete with two scopes", "DELETE", f"{V}/delete?agent_name={host_a1}&customer_code={CUST_A}", t["admin"])
    await p.same("delete one host's", "DELETE", f"{V}/delete?agent_name={host_a1}", t["admin"], before=synced, db=vuln_rows)
    await p.same("delete one customer's", "DELETE", f"{V}/delete?customer_code={CUST_B}", t["admin"], before=synced, db=vuln_rows)
    await p.same("delete as an analyst", "DELETE", f"{V}/delete?agent_name={host_a1}", t["analyst"])

    # The reports.
    def no_reports():
        sql("DELETE FROM vulnerability_reports WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)

    def report_rows():
        return rows(
            "SELECT report_name, customer_code, bucket_name, object_key, file_name, file_size, file_hash, generated_by, filters_json, "
            "total_vulnerabilities, critical_count, high_count, medium_count, low_count, status, error_message FROM "
            "vulnerability_reports WHERE customer_code IN (:a, :b) ORDER BY id",
            a=CUST_A,
            b=CUST_B,
        )

    for name, body in (
        ("report", {"customer_code": CUST_A, "report_name": f"vr-{SFX}"}),
        (
            "report with EPSS and filters",
            {"customer_code": CUST_A, "report_name": f"vr2-{SFX}", "include_epss": True, "severity": "Critical"},
        ),
        ("report of one host", {"customer_code": CUST_A, "report_name": f"vr3-{SFX}", "agent_name": host_a2}),
        ("report without matches", {"customer_code": CUST_A, "report_name": f"vr4-{SFX}", "cve_id": "CVE-1999-0001"}),
        ("report of another tenant", {"customer_code": CUST_B, "report_name": f"vr5-{SFX}"}),
        ("report of an unknown customer", {"customer_code": f"nope{SFX}", "report_name": f"vr6-{SFX}"}),
        ("report with a bad body", {"customer_code": 5, "include_epss": "maybe"}),
    ):
        await p.same(
            name,
            "POST",
            f"{V}/reports/generate",
            t["analyst"] if "unknown" not in name else t["admin"],
            json=body,
            before=no_reports,
            db=report_rows,
        )

    async def finished(tag):
        for _ in range(100):
            if not [r for r in report_rows() if r["status"] == "processing"]:
                break
            await asyncio.sleep(0.1)
        await wait_quiet([p.up])

    await p.same(
        "background report",
        "POST",
        f"{V}/reports/generate/background",
        t["analyst"],
        json={"customer_code": CUST_A, "report_name": f"vb-{SFX}"},
        before=no_reports,
        db=report_rows,
        settle=finished,
    )

    def refused_first(py, rs):
        # §4: Python queues the report, then its task marks the row failed; Rust refuses the
        # customer before inserting anything.
        failed = [r for r in py["rows"] if r["customer_code"] == CUST_B and r["status"] == "failed"]
        if py["status"] != 200 or not failed or rs["status"] != 403 or rs["rows"]:
            return f"python {py['status']} {py['rows']} rust {rs['status']} {rs['body']} {rs['rows']}"
        if rs["body"].get("message") != f"Access denied to customer {CUST_B}" or rs["upstream"] or rs["s3"]:
            return f"rust {rs['body']} {rs['upstream']} {rs['s3']}"
        return None

    await p.same(
        "background report of another tenant (Rust refuses before the row)",
        "POST",
        f"{V}/reports/generate/background",
        t["analyst"],
        json={"customer_code": CUST_B, "report_name": f"vb2-{SFX}"},
        before=no_reports,
        db=report_rows,
        settle=finished,
        expect_diff=refused_first,
    )
    await p.same(
        "background report of an unknown customer",
        "POST",
        f"{V}/reports/generate/background",
        t["admin"],
        json={"customer_code": f"nope{SFX}", "report_name": f"vb3-{SFX}"},
        before=no_reports,
        db=report_rows,
    )

    # Stored reports: one per customer, the file in MinIO.
    csv = b"CVE ID,Severity\r\nCVE-2026-1001,Critical\r\n" * 40

    def stored():
        no_reports()
        for i, (cust, name) in enumerate(((CUST_A, f"stored-a-{SFX}"), (CUST_B, f"stored-b-{SFX}"), (CUST_A, f"bad ☃ {SFX}"))):
            sql(
                "INSERT INTO vulnerability_reports (id, report_name, customer_code, bucket_name, object_key, file_name, file_size, "
                "file_hash, generated_at, generated_by, filters_json, total_vulnerabilities, critical_count, high_count, medium_count, "
                "low_count, status, error_message) VALUES (:i, :n, :c, 'vulnerability-reports', :k, :f, :s, 'h', :g, 1, :fj, 3, 1, 1, 1, "
                "0, 'completed', NULL)",
                i=IDS["vreport"] + i,
                n=name,
                c=cust,
                k=f"{cust}/{name}.csv",
                f=f"{name}.csv",
                s=len(csv),
                g=f"2026-10-0{i + 1} 10:00:00",
                fj=json.dumps({"severity": "High"}) if i == 0 else None,
            )
            S3.put("vulnerability-reports", f"{cust}/{name}.csv", csv, "text/csv")

    stored()
    va, vb, vbad = IDS["vreport"], IDS["vreport"] + 1, IDS["vreport"] + 2
    await p.same("report list", "GET", f"{V}/reports", t["analyst"])
    await p.same("report list of a customer", "GET", f"{V}/reports?customer_codes={CUST_B}", t["admin"])
    await p.same("report list of another tenant", "GET", f"{V}/reports?customer_codes={CUST_B}", t["analyst"])
    await p.same("report download", "GET", f"{V}/reports/{va}/download", t["analyst"])
    await p.same("report download, gzipped", "GET", f"{V}/reports/{va}/download", t["analyst"], headers={"Accept-Encoding": "gzip"})
    await p.same("report download of another tenant", "GET", f"{V}/reports/{vb}/download", t["analyst"])
    await p.same("report download of an unknown id", "GET", f"{V}/reports/9999999/download", t["analyst"])
    await p.same("report download of a bad id", "GET", f"{V}/reports/x/download", t["analyst"])
    await p.same("report download with a non-latin-1 name", "GET", f"{V}/reports/{vbad}/download", t["analyst"])

    def missing_file():
        stored()
        S3.drop("vulnerability-reports", f"{CUST_A}/stored-a-{SFX}.csv")

    await p.same("report download of a lost file", "GET", f"{V}/reports/{va}/download", t["analyst"], before=missing_file)

    def all_reports():
        return report_rows()

    await p.same("report delete", "DELETE", f"{V}/reports/{va}", t["analyst"], before=stored, db=all_reports)
    await p.same("report delete of another tenant", "DELETE", f"{V}/reports/{vb}", t["analyst"], before=stored, db=all_reports)
    await p.same("report delete of a lost file", "DELETE", f"{V}/reports/{va}", t["analyst"], before=missing_file, db=all_reports)
    await p.same("report delete of an unknown id", "DELETE", f"{V}/reports/9999999", t["analyst"])
    no_reports()

    # The whole deployment's sync, last (it walks every agent in the database).
    async def all_synced(tag):
        await wait_quiet([p.up], quiet=1.5, limit=120)

    await p.same("sync of every agent", "POST", f"{V}/sync", t["scheduler"], before=reset_vulns, db=vuln_rows)
    await p.same(
        "background sync of every agent, as admin",
        "POST",
        f"{V}/sync/background",
        t["admin"],
        before=reset_vulns,
        db=vuln_rows,
        settle=all_synced,
    )

    def analysts_only(py, rs):
        # §4: a scoped analyst's sync of every agent covers their customers' agents only (Python
        # synced every tenant's); the scheduler and admins stay deployment-wide.
        py_codes = {r["customer_code"] for r in py["rows"]}
        rs_codes = {r["customer_code"] for r in rs["rows"]}
        if (py["status"], rs["status"]) != (200, 200) or py_codes != {CUST_A, CUST_B} or rs_codes != {CUST_A}:
            return f"python {py['status']} {sorted(py_codes)} rust {rs['status']} {sorted(rs_codes)}"
        if [r for r in py["rows"] if r["customer_code"] == CUST_A] != rs["rows"]:
            return f"the analyst's rows differ: python {py['rows']} rust {rs['rows']}"
        return None

    await p.same(
        "sync of every agent, as a scoped analyst (Rust syncs their customers')",
        "POST",
        f"{V}/sync",
        t["analyst"],
        before=reset_vulns,
        db=vuln_rows,
        expect_diff=analysts_only,
    )
    await p.same(
        "background sync of every agent, as a scoped analyst (Rust syncs their customers')",
        "POST",
        f"{V}/sync/background",
        t["analyst"],
        before=reset_vulns,
        db=vuln_rows,
        settle=all_synced,
        expect_diff=analysts_only,
    )
    reset_vulns()


# --- Checks: /api/sca --------------------------------------------------------------------------------
SCA_P = "/api/sca"


def stream_view(body):
    """The frames of an event stream, the per-agent ones (whose order is the order the agents
    answered in) as a set; the progress frames dropped (their `processed` counts depend on it)."""
    if not isinstance(body, str):
        return body
    frames = []
    for raw in body.split("\n\n"):
        if not raw:
            continue
        event, _, data = raw.partition("\n")
        frames.append([event, json.loads(data[len("data: ") :])])
    head = [f for f in frames if f[0] in ("start",)]
    tail = [f for f in frames if f[0] in ("complete", "error")]
    middle = sorted((f for f in frames if f[0] not in ("start", "complete", "error", "progress")), key=json.dumps)
    progress = [f for f in frames if f[0] == "progress"]
    return {
        "head": head,
        "agents": middle,
        "progress_count": len(progress),
        "last_progress": progress[-1:] and progress[-1][1]["percent_complete"],
        "tail": tail,
    }


async def sca_checks(p, t):
    a1 = AGENTS["a1"][0]

    await p.same("overview", "GET", f"{SCA_P}/overview", t["analyst"], unordered=True)
    await p.same("overview, paged and filtered", "GET", f"{SCA_P}/overview?page=2&page_size=1&min_score=50", t["analyst"], unordered=True)
    await p.same("overview by policy", "GET", f"{SCA_P}/overview?policy_id=cis_ubuntu&policy_name=ubuntu", t["analyst"], unordered=True)
    await p.same("overview of one host", "GET", f"{SCA_P}/overview?agent_name={AGENTS['a2'][1]}", t["analyst"], unordered=True)
    await p.same(
        "overview as admin of two customers",
        "GET",
        f"{SCA_P}/overview?customer_codes={CUST_A}&customer_codes={CUST_B}",
        t["admin"],
        unordered=True,
    )
    await p.same("overview of another tenant", "GET", f"{SCA_P}/overview?customer_codes={CUST_B}", t["analyst"])
    await p.same("overview with bad filters", "GET", f"{SCA_P}/overview?min_score=101&page=0", t["analyst"])
    await p.same("stats", "GET", f"{SCA_P}/stats", t["analyst"], unordered=True)
    await p.same(
        "stats of two customers",
        "GET",
        f"{SCA_P}/stats?customer_codes={CUST_A}&customer_codes={CUST_B}",
        t["admin"],
        unordered=True,
    )
    await p.same("stats of another tenant", "GET", f"{SCA_P}/stats?customer_codes={CUST_B}", t["analyst"])
    await p.same("stats as a portal user", "GET", f"{SCA_P}/stats", t["portal"])

    await p.same("stream", "GET", f"{SCA_P}/overview/stream", t["analyst"], unordered=True, body_view=stream_view)
    await p.same(
        "stream of two customers, filtered",
        "GET",
        f"{SCA_P}/overview/stream?customer_codes={CUST_A}&customer_codes={CUST_B}&max_score=60",
        t["admin"],
        unordered=True,
        body_view=stream_view,
    )
    await p.same("stream of one unknown host", "GET", f"{SCA_P}/overview/stream?agent_name=nobody", t["analyst"], body_view=stream_view)
    await p.same("stream of another tenant", "GET", f"{SCA_P}/overview/stream?customer_codes={CUST_B}", t["analyst"])
    await p.same("stream with a bad filter", "GET", f"{SCA_P}/overview/stream?min_score=x", t["analyst"])

    def no_reports():
        sql("DELETE FROM sca_reports WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)

    def report_rows():
        return rows(
            "SELECT report_name, customer_code, bucket_name, object_key, file_name, file_size, file_hash, generated_by, filters_json, "
            "total_policies, total_checks, passed_count, failed_count, invalid_count, status, error_message FROM sca_reports "
            "WHERE customer_code IN (:a, :b) ORDER BY id",
            a=CUST_A,
            b=CUST_B,
        )

    for name, tok, body in (
        ("report", "analyst", {"customer_code": CUST_A, "report_name": f"sr-{SFX}"}),
        (
            "report, filtered",
            "analyst",
            {
                "customer_code": CUST_A,
                "report_name": f"sr2-{SFX}",
                "policy_id": "cis_ubuntu",
                "min_score": 50,
                "agent_name": AGENTS["a1"][1],
            },
        ),
        ("report without results", "analyst", {"customer_code": CUST_A, "report_name": f"sr3-{SFX}", "max_score": 1}),
        ("report of another tenant", "analyst", {"customer_code": CUST_B, "report_name": f"sr4-{SFX}"}),
        ("report of an unknown customer", "admin", {"customer_code": f"nope{SFX}", "report_name": f"sr5-{SFX}"}),
        ("report with a bad body", "analyst", {"report_name": 3, "min_score": -1}),
    ):
        await p.same(name, "POST", f"{SCA_P}/reports/generate", t[tok], json=body, before=no_reports, db=report_rows, unordered=True)

    csv = b"Agent ID,Agent Name\r\n001,web\r\n"

    def stored():
        no_reports()
        for i, (cust, name) in enumerate(((CUST_A, f"sca-a-{SFX}"), (CUST_B, f"sca-b-{SFX}"), (CUST_A, f"sca ☃ {SFX}"))):
            sql(
                "INSERT INTO sca_reports (id, report_name, customer_code, bucket_name, object_key, file_name, file_size, file_hash, "
                "generated_at, generated_by, filters_json, total_policies, total_checks, passed_count, failed_count, invalid_count, "
                "status, error_message) VALUES (:i, :n, :c, 'sca-reports', :k, :f, :s, 'h', :g, 1, :fj, 1, 10, 8, 2, 0, :st, :e)",
                i=IDS["sreport"] + i,
                n=name,
                c=cust,
                k=f"{cust}/{name}.csv",
                f=f"{name}.csv",
                s=len(csv),
                g=f"2026-10-0{i + 1} 10:00:00",
                fj=json.dumps({"min_score": 5}) if i == 0 else "",
                st="failed" if i == 1 else "completed",
                e="boom" if i == 1 else None,
            )
            S3.put("sca-reports", f"{cust}/{name}.csv", csv, "text/csv")

    stored()
    sa, sb, sbad = IDS["sreport"], IDS["sreport"] + 1, IDS["sreport"] + 2
    await p.same("report list", "GET", f"{SCA_P}/reports", t["analyst"])
    await p.same("report list as admin", "GET", f"{SCA_P}/reports?customer_codes={CUST_A}&customer_codes={CUST_B}", t["admin"])
    await p.same("report list of another tenant", "GET", f"{SCA_P}/reports?customer_codes={CUST_B}", t["analyst"])
    await p.same("report download", "GET", f"{SCA_P}/reports/{sa}/download", t["analyst"])
    await p.same("report download of another tenant", "GET", f"{SCA_P}/reports/{sb}/download", t["analyst"])
    await p.same("report download with a non-latin-1 name", "GET", f"{SCA_P}/reports/{sbad}/download", t["analyst"])
    await p.same("report download of an unknown id", "GET", f"{SCA_P}/reports/9999999/download", t["analyst"])

    def missing_file():
        stored()
        S3.drop("sca-reports", f"{CUST_A}/sca-a-{SFX}.csv")

    await p.same("report download of a lost file", "GET", f"{SCA_P}/reports/{sa}/download", t["analyst"], before=missing_file)
    await p.same("report delete", "DELETE", f"{SCA_P}/reports/{sa}", t["analyst"], before=stored, db=report_rows)
    await p.same("report delete of a lost file", "DELETE", f"{SCA_P}/reports/{sa}", t["analyst"], before=missing_file, db=report_rows)
    await p.same("report delete of another tenant", "DELETE", f"{SCA_P}/reports/{sb}", t["analyst"], before=stored, db=report_rows)
    await p.same("report delete of a bad id", "DELETE", f"{SCA_P}/reports/x", t["analyst"])
    no_reports()

    # The CoPilot-SCA repository.
    for mode in (None, "missing", "not_json", "bad_policy", "list"):

        def set_mode(mode=mode):
            p.up.mode["index"] = mode

        label = mode or "ok"
        await p.same(f"policies ({label})", "GET", f"{SCA_P}/policies", t["analyst"], before=set_mode)
        await p.same(f"policy metadata ({label})", "GET", f"{SCA_P}/policies/cis_nginx/metadata", t["analyst"], before=set_mode)
        await p.same(f"policy content ({label})", "GET", f"{SCA_P}/policies/cis_apache_24", t["analyst"], before=set_mode)
    p.up.mode.pop("index", None)
    await p.same("policy metadata of an unknown id", "GET", f"{SCA_P}/policies/nope/metadata", t["analyst"])
    await p.same("policy content of a missing file", "GET", f"{SCA_P}/policies/cis_nginx", t["analyst"])
    await p.same("policy content of an unknown id", "GET", f"{SCA_P}/policies/nope", t["analyst"])
    await p.same("policies as a portal user", "GET", f"{SCA_P}/policies", t["portal"])

    # The package registry.
    await p.same("package registry", "GET", f"{SCA_P}/packages/registry", t["analyst"])
    await p.same("registry agents as admin", "GET", f"{SCA_P}/packages/registry/apache/agents", t["admin"])
    await p.same("registry agents of an unknown key", "GET", f"{SCA_P}/packages/registry/nope/agents", t["analyst"])

    def counted(py, rs):
        if py["upstream"] != rs["upstream"]:
            return f"upstream python {py['upstream']} rust {rs['upstream']}"
        pb, rb = py["body"], rs["body"]
        mine = [m for m in pb.get("matched_agents", []) if m["agent_id"] == a1]
        if pb.get("total") != 1 or rb.get("total") != 1 or rb.get("matched_agents") != mine:
            return f"python {pb} rust {rb}"
        if rb.get("message") != "Found 1 agent-package combinations for 'Apache HTTP Server'" or pb.get("message") == rb.get("message"):
            return f"messages python {pb.get('message')} rust {rb.get('message')}"
        if dict(pb, matched_agents=mine, message=rb["message"]) != rb:
            return f"rust {rb} python {pb}"
        return None

    await p.same(
        "registry agents (Rust counts the caller's)",
        "GET",
        f"{SCA_P}/packages/registry/apache/agents",
        t["analyst"],
        expect_diff=counted,
    )

    def index_down():
        p.up.mode["index"] = "missing"

    await p.same("registry agents without the repository", "GET", f"{SCA_P}/packages/registry/nginx/agents", t["admin"], before=index_down)
    p.up.mode.pop("index", None)


# --- Checks: /api/syscollector -----------------------------------------------------------------------
SYS = "/api/syscollector"


async def syscollector_checks(p, t):
    a1, b1 = AGENTS["a1"][0], AGENTS["b1"][0]
    await p.same("an agent's packages", "GET", f"{SYS}/{a1}/packages", t["portal"])
    await p.same(
        "an agent's packages, every parameter",
        "GET",
        f"{SYS}/{a1}/packages?limit=10&offset=5&sort=-name&search=ssl&select=name&select=version&vendor=U&name=openssl"
        f"&architecture=amd64&format=deb&version=3&q=name%3Dopenssl",
        t["analyst"],
    )
    await p.same("another tenant's agent's packages", "GET", f"{SYS}/{b1}/packages", t["portal"])
    await p.same("an unknown agent's packages", "GET", f"{SYS}/nope/packages", t["admin"])
    await p.same("packages with bad parameters", "GET", f"{SYS}/{a1}/packages?limit=0&offset=-1", t["admin"])

    def manager_down():
        p.up.mode["syscollector"] = "fail"

    await p.same("packages when the manager fails", "GET", f"{SYS}/{a1}/packages", t["admin"], before=manager_down)
    p.up.mode.pop("syscollector", None)
    await p.same("indexer package search as admin", "GET", f"{SYS}/search/packages?package_name=apache&size=3", t["admin"])
    await p.same(
        "indexer package search, every filter",
        "GET",
        f"{SYS}/search/packages?agent_name=rp&agent_id={a1}&architecture=amd64&package_type=deb&vendor=x&package_version=2.4",
        t["admin"],
    )
    await p.same("indexer package search with a bad size", "GET", f"{SYS}/search/packages?size=0", t["admin"])
    await p.same("indexer package search as a portal user", "GET", f"{SYS}/search/packages", t["portal"])

    def scoped(py, rs):
        theirs = {h["agent"]["id"] for h in py.get("packages", [])}
        mine = {h["agent"]["id"] for h in rs.get("packages", [])}
        if b1 not in theirs or b1 in mine or a1 not in mine:
            return f"python {sorted(theirs)} rust {sorted(mine)}"
        return None

    # §4: the analyst's agents only (Rust adds a `terms` clause; the upstream requests differ too).
    r_py = await p.call(p.py, "GET", f"{SYS}/search/packages", t["analyst"], {})
    p.up.take()
    r_rs = await p.call(p.rs, "GET", f"{SYS}/search/packages", t["analyst"], {})
    sent = upstream_view(p.up.take())
    reason = scoped(r_py.json(), r_rs.json())
    owned = sent and json.loads(sent[-1]["body"])["query"]["bool"]["must"][-1]
    if (
        not reason
        and owned != {"terms": {"agent.id": sorted([AGENTS[k][0] for k in ("a1", "a2", "w1")])}}
        and owned
        != {
            "terms": {"agent.id": [AGENTS[k][0] for k in ("a1", "a2", "w1")]},
        }
    ):
        reason = f"the Rust search sent {owned}"
    check("indexer package search as an analyst (Rust searches the caller's agents) [200]", not reason, reason or "")


# --- Checks: Velociraptor collections ----------------------------------------------------------------

ARTIFACT_DEFS = [
    {"name": "Linux.Sys.Users", "description": "users", "parameters": [{"name": "UserRegex"}, {"name": "Fast", "type": "bool"}]},
    {"name": "Linux.Sys.Pslist", "description": "ps"},
    {"name": "Windows.System.Pslist", "description": "ps", "parameters": [{"name": "ProcessRegex"}]},
    {"name": "Generic.Collectors.File", "description": "files", "parameters": [{"name": "collectionSpec"}, {"name": "Root"}]},
]
PACK = bytes(range(256)) * 9


def velo_answer(stand_in, vql, org_id):
    import grpc

    mode = stand_in.mode
    if vql.startswith("SELECT name,description,parameters FROM artifact_definitions()"):
        found = list(ARTIFACT_DEFS)
        m = re.fullmatch(r".* WHERE name = '(.*)'", vql)
        if m:
            found = [d for d in found if d["name"] == m.group(1)]
        return [found], None
    if vql.startswith("SELECT collect_client(org_id="):
        call = vql[len("SELECT ") : -len(" FROM scope()")]
        if mode.get("no_flow"):
            return [[{call: {"request": {}}}]], None
        if mode.get("int_flow"):
            return [[{call: {"flow_id": 7}}]], None
        return [[{"other": 1, call: {"flow_id": "F.CL" + SFX.upper(), "request": {"creator": "api"}}}]], None
    if vql.startswith("SELECT * FROM watch_monitoring("):
        return [[{"FlowId": "F.CL" + SFX.upper()}]], None
    if vql.startswith("SELECT * FROM source("):
        if mode.get("rows_not_dicts"):
            return [[1, "two"]], None
        return [[{"Name": "init", "Pid": 1}], [{"Name": "sshd é", "Pid": 22}]], None
    if vql.startswith("SELECT os_info.hostname AS Hostname"):
        if mode.get("no_hostname"):
            return [[]], None
        return [[{"Hostname": "VELO-" + SFX}]], None
    if vql.startswith("SELECT create_flow_download("):
        return [[{"create_flow_download": "downloads/x.zip"}]], None
    m = re.search(r"offset=(\d+), length=(\d+)", vql)
    if m:
        if mode.get("empty_pack"):
            return [[{"Data": ""}]], None
        offset, length = int(m.group(1)), int(m.group(2))
        if mode.get("bad_chunk"):
            return [[{"Data": "@@@"}]], None
        chunk = PACK[offset : offset + length]
        return [[{"Data": base64.b64encode(chunk).decode()}]] if chunk else [[]], None
    return [], (grpc.StatusCode.INVALID_ARGUMENT, f"unexpected VQL: {vql}")


async def velociraptor_checks(p, t):
    a1, w1, b1, a2 = (AGENTS[k][0] for k in ("a1", "w1", "b1", "a2"))
    host_a1, host_w1, host_b1 = AGENTS["a1"][1], AGENTS["w1"][1], AGENTS["b1"][1]

    def fresh():
        p.velo.mode.clear()
        sql("DELETE FROM agent_datastore WHERE agent_id IN " + our_agent_ids())
        sql("DELETE FROM audit_log WHERE actor_username IN " + in_list(USERS))

    def store_rows():
        time.sleep(0.3)  # the Rust audit sink writes on a task of its own
        return {
            "datastore": rows(
                "SELECT agent_id, velociraptor_id, artifact_name, flow_id, bucket_name, object_key, file_name, content_type, file_size, "
                "file_hash, uploaded_by, notes, status, error_message FROM agent_datastore WHERE agent_id IN "
                + our_agent_ids()
                + " ORDER BY id",
            ),
            "audit": rows(
                "SELECT actor_username, customer_code, action, entity_type, entity_id, result, old_value, new_value, details FROM audit_log "
                "WHERE actor_username IN " + in_list(USERS) + " ORDER BY id",
            ),
        }

    def with_mode(**mode):
        def before():
            fresh()
            p.velo.mode.update(mode)

        return before

    C = "/api/artifacts/collect"
    await p.same(
        "collect an artifact",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Users", "parameters": {"env": [{"key": "UserRegex", "value": "it's"}]}},
        before=fresh,
        db=store_rows,
    )
    await p.same(
        "collect with direct parameters",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Users", "parameters": {"Fast": "Y", "UserRegex": "root"}},
        before=fresh,
        db=store_rows,
    )
    await p.same(
        "collect into the data store only",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_w1, "artifact_name": "Windows.System.Pslist", "data_store_only": True},
        before=fresh,
        db=store_rows,
    )
    await p.same(
        "collect, the pack empty",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=with_mode(empty_pack=True),
        db=store_rows,
    )
    await p.same(
        "collect, a chunk that does not decode",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=with_mode(bad_chunk=True),
        db=store_rows,
    )
    await p.same(
        "collect, no hostname from Velociraptor",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=with_mode(no_hostname=True),
        db=store_rows,
    )
    await p.same(
        "collect, no flow",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=with_mode(no_flow=True),
        db=store_rows,
    )
    await p.same(
        "collect, a flow id that is no string",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=with_mode(int_flow=True),
        db=store_rows,
    )
    await p.same(
        "collect, rows that are not dicts",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=with_mode(rows_not_dicts=True),
        db=store_rows,
    )

    def s3_down():
        fresh()
        S3.fault(
            lambda m, path, q: m == "PUT" and path.startswith("/velociraptor-artifacts/"),
            (500, {"Content-Type": "text/plain"}, b"nope"),
            count=5,
        )

    await p.same(
        "collect, MinIO refuses the upload",
        "POST",
        C,
        t["admin"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist"},
        before=s3_down,
        db=store_rows,
    )
    await p.same(
        "collect with an unknown parameter",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Users", "parameters": {"env": [{"key": "Nope", "value": "1"}]}},
        before=fresh,
    )
    await p.same(
        "collect with parameters it takes none of",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_a1, "artifact_name": "Linux.Sys.Pslist", "parameters": {"X": "1"}},
        before=fresh,
    )
    await p.same(
        "collect an artifact of another OS",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_a1, "artifact_name": "Windows.System.Pslist"},
        before=fresh,
    )
    await p.same("collect without an artifact", "POST", C, t["analyst"], json={"hostname": host_a1}, before=fresh)
    await p.same(
        "collect on another tenant's host",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_b1, "artifact_name": "Linux.Sys.Pslist"},
        before=fresh,
        db=store_rows,
    )
    await p.same(
        "collect on a host without Velociraptor",
        "POST",
        C,
        t["admin"],
        json={"hostname": AGENTS["a2"][1], "artifact_name": "Linux.Sys.Pslist"},
        before=fresh,
    )
    await p.same(
        "collect on an unknown host",
        "POST",
        C,
        t["admin"],
        json={"hostname": "nobody", "artifact_name": "Linux.Sys.Pslist"},
        before=fresh,
    )
    await p.same(
        "collect with a bad body",
        "POST",
        C,
        t["analyst"],
        json={"hostname": host_a1, "parameters": {"x": 1}, "data_store_only": "maybe"},
    )
    await p.same("collect without a body", "POST", C, t["analyst"])
    await p.same("collect as a portal user", "POST", C, t["portal"], json={"hostname": host_a1})

    F = "/api/artifacts/collect/file/agent"
    await p.same(
        "collect a Windows file",
        "POST",
        f"{F}/{w1}",
        t["analyst"],
        json={"file": "Users\\Administrator\\Downloads\\LICENSE.txt"},
        before=fresh,
        db=store_rows,
    )
    await p.same(
        "collect a Linux file",
        "POST",
        f"{F}/{a1}",
        t["analyst"],
        json={"file": "/tmp/x y.txt", "root_disk": "/"},
        before=fresh,
        db=store_rows,
    )
    await p.same(
        "collect a file, the pack empty",
        "POST",
        f"{F}/{a1}",
        t["admin"],
        json={"file": "/tmp/x"},
        before=with_mode(empty_pack=True),
        db=store_rows,
    )
    await p.same(
        "collect a file, MinIO refuses the upload",
        "POST",
        f"{F}/{a1}",
        t["admin"],
        json={"file": "/tmp/x"},
        before=s3_down,
        db=store_rows,
    )
    await p.same("collect a file, no flow", "POST", f"{F}/{a1}", t["admin"], json={"file": "/tmp/x"}, before=with_mode(no_flow=True))
    await p.same("collect a file of another tenant's agent", "POST", f"{F}/{b1}", t["analyst"], json={"file": "/etc/passwd"}, before=fresh)
    await p.same(
        "collect a file of an agent without Velociraptor",
        "POST",
        f"{F}/{a2}",
        t["admin"],
        json={"file": "/etc/passwd"},
        before=fresh,
    )
    await p.same("collect a file of an unknown agent", "POST", f"{F}/nobody", t["admin"], json={"file": "/etc/passwd"}, before=fresh)
    await p.same("collect a file with a bad body", "POST", f"{F}/{a1}", t["analyst"], json={"root_disk": None})
    await p.same("collect a file of another tenant's agent with a bad body", "POST", f"{F}/{b1}", t["analyst"], json={})
    fresh()


# --- Main --------------------------------------------------------------------------------------------


async def main():
    seed()
    fill_upstream_data()
    patch_python()
    s3_server = S3.serve(S3_PORT)
    upstream = Upstream(STUB_PORT)
    velo = agents_parity.VeloStandIn(VELO_PORT, velo_answer)
    workdir = tempfile.mkdtemp(prefix="agent-reports-parity-")
    config = agents_parity.api_config(workdir, velo.address)
    set_connector("Wazuh-Indexer", STUB, ES_USER, ES_PASS)
    set_connector("Wazuh-Manager", STUB, MGR_USER, MGR_PASS)
    set_connector("Velociraptor", "https://velociraptor.parity", api_key=config)
    proc = start_rust()
    p = Pair(upstream, velo)
    t = {
        "admin": token(ADMIN, ["admin"]),
        "analyst": token(ANALYST, ["analyst"]),
        "portal": token(PORTAL, ["customer_user"], customer_codes=[CUST_A]),
        "scheduler": token(SCHED, ["scheduler"]),
    }
    try:
        sections = os.environ.get("AGENT_REPORTS_PARITY_SECTIONS", "vulnerabilities,sca,syscollector,velociraptor").split(",")
        if "vulnerabilities" in sections:
            await vulnerability_checks(p, t)
        if "sca" in sections:
            await sca_checks(p, t)
        if "syscollector" in sections:
            await syscollector_checks(p, t)
        if "velociraptor" in sections:
            # Python writes each download pack into its working directory and leaves it there when the upload fails:
            # the collections run in a directory of their own.
            home, packs = os.getcwd(), tempfile.mkdtemp(prefix="agent-reports-packs-")
            os.chdir(packs)
            try:
                await velociraptor_checks(p, t)
            finally:
                os.chdir(home)
                shutil.rmtree(packs, ignore_errors=True)
    finally:
        await p.close()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        upstream.stop()
        velo.stop()
        s3_server.shutdown()
        shutil.rmtree(workdir, ignore_errors=True)
    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
