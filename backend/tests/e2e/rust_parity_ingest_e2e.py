"""Parity of the Rust alert creation and ingest (`crates/copilot-ingest`) with this backend — NOT
collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI incidents routers (in-process) and a Rust instance this suite starts (no legacy
backend, connector cache off, the ingest settings below in its environment) answer the same
requests on one database. The tools are local stand-ins that record every request: the Wazuh
indexer (documents, searches, updates, aliases, mappings, a write-blocked index), Shuffle (the
legacy per-customer workflow), the SOCFortress MDR server and Talon. For each request the suite
compares the status, the body and every request each backend sent to each tool; every write is
also compared by the rows it leaves (alert, context, assets, IoCs, tags, comments, SLA clock,
threshold replay, exclusion statistics).

Writes run twice, Python on customer P's data and Rust on customer R's: every name a twin carries
embeds its side's tag (`py<sfx>` / `rs<sfx>`), which is replaced before comparing, and alert ids
are replaced by their rank on that side. Seeded alert ids are explicit, seven digits and below
every id an ingest creates, so replacing an id in a text never touches another number.

    PARITY_SUITES=tests/e2e/rust_parity_ingest_e2e.py scripts/rust-parity.sh

Ports (all overridable): the Rust instance on INGEST_PARITY_RUST_PORT (5700), the indexer on
INGEST_ES_STUB_PORT (5701), Shuffle on INGEST_SHUFFLE_STUB_PORT (5702), MDR on
INGEST_MDR_STUB_PORT (5703), Talon on INGEST_TALON_STUB_PORT (5704).
"""

import asyncio
import datetime
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
from urllib.parse import parse_qs
from urllib.parse import unquote
from urllib.parse import urlsplit

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# Read at import by app.connectors.cache: every request re-reads the connector row, as the Rust
# instance below does.
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("INGEST_PARITY_RUST_PORT", "5700"))
ES_PORT = int(os.environ.get("INGEST_ES_STUB_PORT", "5701"))
SHUFFLE_PORT = int(os.environ.get("INGEST_SHUFFLE_STUB_PORT", "5702"))
MDR_PORT = int(os.environ.get("INGEST_MDR_STUB_PORT", "5703"))
TALON_PORT = int(os.environ.get("INGEST_TALON_STUB_PORT", "5704"))
WEBHOOK_PORT = int(os.environ.get("INGEST_WEBHOOK_STUB_PORT", "5717"))

# What both backends read from the environment, at call time in Python.
INGEST_ENV = {
    "GRAYLOG_API_HEADER_VALUE": f"graylog-hdr-{SFX}",
    "VELOCIRAPTOR_API_HEADER_VALUE": f"velo-hdr-{SFX}",
    "MDR_ENABLED": "Yes",
    "MDR_SERVER_URL": f"http://127.0.0.1:{MDR_PORT}/",
    "MDR_COLLECTOR_UUID": f"fallback-{SFX}",
    "THRESHOLD_SOURCE_INDEX_MAPPING": json.dumps({f"MAPPED{SFX}": [f"mapped-{SFX}-*", "event_time"], "broken": 3}),
    # The deep links `alert_created` carries.
    "COPILOT_URL": "https://copilot.ingest.test/",
}
os.environ.update(INGEST_ENV)

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

PY_TAG, RS_TAG = f"py{SFX}", f"rs{SFX}"
TAGS = {"py": PY_TAG, "rs": RS_TAG}
ADMIN, ANALYST, PORTAL = f"ing_admin{SFX}", f"ing_analyst{SFX}", f"ing_portal{SFX}"
CUST_B = f"INGB{SFX}"  # another tenant: the analyst is not assigned to it
SOURCE = f"ingsrc{SFX}"
THR_SOURCE = f"thr{SFX}"
IDX = f"ing-{SFX}-2026.03.01"
WAZUH_IDX = f"wazuh-{SFX}-2026.03.01"
THR_IDX = f"thr{SFX}-2026.03.01"
MAPPED_IDX = f"mapped-{SFX}-2026.03.01"
GL_INDEX = f"gl-events_{SFX}_0"
SIGMA_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
JOB = "invoke_alert_creation_collect"
OUR_CONNECTORS = ("Wazuh-Indexer", "Shuffle", "Talon")
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(text(statement), params)


def rows(statement, **params):
    with sync_engine.begin() as conn:
        return [dict(r._mapping) for r in conn.execute(text(statement), params)]


def cust(side):
    return f"ING{TAGS[side]}"


# --- The stand-ins -----------------------------------------------------------------------------------
#: Headers a client adds on its own (urllib3, aiohttp, httpx, requests and reqwest differ there, and
#: none of them reaches the tool's logic).
TRANSPORT_HEADERS = {"host", "user-agent", "accept-encoding", "accept", "connection", "content-length", "transfer-encoding"}


class Recorder:
    def __init__(self, port, answer, name):
        self.answer = answer
        self.name = name
        self.captured = []
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k.lower(): v for k, v in self.headers.items() if k.lower() not in TRANSPORT_HEADERS}
                with recorder.lock:
                    recorder.captured.append((self.command, self.path, headers, body))
                status, payload = recorder.answer(self.command, self.path, body)
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=UTF-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle  # noqa: N815 - http.server API

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
            out, self.captured = self.captured, []
        return out


#: The indexer's state: the side whose Graylog events the collector sees, write blocks.
ES_STATE = {"side": "py", "events": "normal", "blocked": set()}


def source_doc(side, title, **extra):
    tag = TAGS[side]
    doc = {
        "syslog_type": SOURCE,
        "timestamp": "2026-03-01T10:00:00.250000+00:00",
        "timestamp_utc": "2026-03-01T10:00:00.250Z",
        "rule_description": title,
        "rule_level": 12,
        "rule_id": "92900",
        "agent_name": f"host-{tag}",
        "agent_ip": "10.1.2.3",
        "agent_labels_customer": cust(side),
        "src_ip": "203.0.113.5",
        "process_id": 4242,
        "data_win_eventdata_image": "C:\\Windows\\Temp\\mimikatz.exe",
        "data_win_eventdata_commandLine": 'mimikatz.exe "privilege::debug" é',
        "score": 0.000025,
        "big": 1e16,
        "nested": {"z": 1, "a": [1, 2.5, None, True]},
    }
    doc.update(extra)
    return {k: v for k, v in doc.items() if v is not ...}


def docs():
    """(index, id) -> _source, for both sides."""
    out = {}
    for side in ("py", "rs"):
        tag = TAGS[side]
        out[(IDX, f"one{tag}")] = source_doc(side, f"Mimikatz {SFX}")
        # Same title: merged into the first one's alert, with another asset and a composite IoC.
        out[(IDX, f"two{tag}")] = source_doc(
            side,
            f"Mimikatz {SFX}",
            agent_name=f"host2-{tag}",
            src_ip="evil.exe|d41d8cd98f00b204e9800998ecf8427e",
            timestamp_utc="2026-03-02T11:12:13.987654+02:00",
        )
        out[(IDX, f"three{tag}")] = source_doc(
            side,
            f"\ufeffSudo abuse {SFX} \x1c",
            src_ip="nope",
            rule_level="7",
            timestamp_utc=...,
            data_win_eventdata_image=...,
            data_event_Image="/usr/bin/sudo",
        )
        out[(IDX, f"bad{tag}")] = source_doc(side, f"Bad {SFX}", agent_labels_customer=f"nobody-{tag}")
        out[(IDX, f"nosrc{tag}")] = source_doc(side, f"No source {SFX}", syslog_type=f"unconfigured-{tag}")
        out[(IDX, f"notitle{tag}")] = source_doc(side, ..., rule_description=...)
        out[(IDX, f"nocust{tag}")] = {k: v for k, v in source_doc(side, f"No customer {SFX}").items() if k != "agent_labels_customer"}
        out[(IDX, f"syslogcust{tag}")] = {
            **{k: v for k, v in source_doc(side, f"Syslog customer {SFX}", rule_level=None).items() if k != "agent_labels_customer"},
            "syslog_customer": f"Ingest Name {tag}",
        }
        out[(IDX, f"integ{tag}")] = {**source_doc(side, f"Integration {SFX}"), "syslog_type": "integration", "integration": SOURCE}
        out[(IDX, f"noint{tag}")] = {k: v for k, v in source_doc(side, f"No integration {SFX}").items() if k != "syslog_type"}
        out[(IDX, f"collected{tag}")] = source_doc(side, f"Collected {SFX}", src_ip="2001:db8::1")
        out[(f"blocked-{SFX}", f"blk{tag}")] = source_doc(side, f"Blocked {SFX}")
        out[(WAZUH_IDX, f"sig{tag}")] = source_doc(side, f"Sigma via Wazuh {SFX}", src_ip="198.51.100.7")
        out[(THR_IDX, f"thr{tag}")] = source_doc(side, f"Threshold doc {SFX}", syslog_type=THR_SOURCE)
        out[(MAPPED_IDX, f"map{tag}")] = source_doc(side, f"Mapped doc {SFX}", syslog_type=f"mapped{SFX}")
    return out


DOCS = docs()


def graylog_event(side, n, doc_id, **extra):
    src = {
        "id": f"ev{n}{TAGS[side]}",
        "event_definition_type": "aggregation-v1",
        "event_definition_id": "65a0000000000000000000e1",
        "origin_context": f"urn:graylog:message:es:{IDX}:{doc_id}",
        "timestamp": "2026-03-01T10:00:01.000Z",
        "timestamp_processing": "2026-03-01T10:00:02.000Z",
        "timerange_start": None,
        "timerange_end": None,
        "streams": ["s1"],
        "source_streams": ["s2"],
        "message": "Graylog event",
        "source": "graylog01",
        "key_tuple": [],
        "key": "",
        "priority": 2,
        "alert": True,
        "fields": {"COPILOT_ALERT_ID": "NONE", "CUSTOMER_CODE": cust(side)},
        "group_by_fields": {},
    }
    src.update(extra)
    return {"_index": GL_INDEX, "_type": "_doc", "_id": f"ev{n}{TAGS[side]}", "_score": None, "_source": src}


def graylog_events():
    side, mode = ES_STATE["side"], ES_STATE["events"]
    tag = TAGS[side]
    if mode == "none":
        return [], 0
    hits = [
        graylog_event(side, 1, f"collected{tag}"),
        graylog_event(side, 2, f"bad{tag}"),
        graylog_event(side, 3, f"missing{tag}"),
    ]
    if mode == "malformed":
        hits.append({"_index": GL_INDEX, "_id": f"ev9{tag}", "_source": {"id": "x"}})
    return hits, 7


def hit(index, doc_id):
    return {"_index": index, "_type": "_doc", "_id": doc_id, "_score": 1.0, "_source": DOCS[(index, doc_id)]}


def search_answer(index, query, body):
    text_ = json.dumps(body)
    if index == GL_INDEX:
        hits, total = graylog_events()
        return {"took": 1, "timed_out": False, "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": hits}}
    found = []
    if index == f"{THR_SOURCE}-*":
        for side, tag in TAGS.items():
            if f"host-{tag}" in text_:
                found = [hit(THR_IDX, f"thr{tag}")]
    elif index == f"mapped-{SFX}-*":
        for side, tag in TAGS.items():
            if f"host-{tag}" in text_:
                found = [hit(MAPPED_IDX, f"map{tag}")]
    elif index == f"wazuh-{SFX}-*":
        for side, tag in TAGS.items():
            if f'"host-{tag}"' in text_ and '"98765"' in text_:
                found = [hit(WAZUH_IDX, f"sig{tag}")]
    elif index == IDX and "process_id" in text_:
        found = [hit(IDX, f"one{tag}") for tag in TAGS.values() if f"host-{tag}" in text_]
    elif index == IDX and "exists" in text_:
        if '"syslog_type"' in text_:
            found = [
                {"_index": IDX, "_id": "x1", "_source": {"other": 1}},
                {"_index": IDX, "_id": "x2", "_source": DOCS[(IDX, f"one{PY_TAG}")]},
            ]
    elif index == f"integ-{SFX}" and "exists" in text_:
        found = [{"_index": index, "_id": "i1", "_source": {"syslog_type": "integration", "integration": "office365"}}]
    elif index == f"integonly-{SFX}" and "exists" in text_:
        if '"integration"' in text_:
            found = [{"_index": index, "_id": "i2", "_source": {"integration": "crowdstrike"}}]
    elif index == f"weird-{SFX}" and "exists" in text_:
        return {"hits": {"hits": {"not": "a list"}}}
    return {"took": 1, "timed_out": False, "hits": {"total": {"value": len(found), "relation": "eq"}, "max_score": 1.0, "hits": found}}


INDICES = [
    IDX,
    f"wazuh-alerts-{SFX}-4.x-2026.03.01",
    f"wazuh-monitoring-{SFX}-2026.03",
    f"wazuh-statistics-{SFX}-2026.03",
    f"office365-{SFX}",
    f"Office365-UPPER-{SFX}",
    f"wazuh-alerts-{SFX}\nx",
]


def es_answer(method, path, body):
    u = urlsplit(path)
    parts = [unquote(p) for p in u.path.split("/")[1:]]
    query = parse_qs(u.query)
    data = json.loads(body) if body else None
    if method == "GET" and len(parts) == 2 and parts[1] == "_alias":
        if parts[0] == "gl-events*":
            return 200, {GL_INDEX: {"aliases": {}}, f"gl-events_{SFX}_1": {"aliases": {"gl-events_deflector": {}}}}
        if parts[0] == "*":
            return 200, {name: {"aliases": {}} for name in INDICES}
    if method == "GET" and len(parts) == 2 and parts[1] == "_mapping":
        if parts[0] == IDX:
            return 200, {IDX: {"mappings": {"properties": {"agent_name": {"type": "keyword"}, "rule_level": {"type": "long"}, "z": {}}}}}
        if parts[0] == f"flat-{SFX}":
            return 200, {f"flat-{SFX}": {"mappings": {}}}
        return 404, {
            "error": {
                "root_cause": [{"type": "index_not_found_exception", "reason": f"no such index [{parts[0]}]"}],
                "type": "index_not_found_exception",
            },
            "status": 404,
        }
    if method == "GET" and len(parts) == 3 and parts[1] == "_doc":
        src = DOCS.get((parts[0], parts[2]))
        if src is None:
            return 404, {"_index": parts[0], "_type": "_doc", "_id": parts[2], "found": False}
        return 200, {
            "_index": parts[0],
            "_type": "_doc",
            "_id": parts[2],
            "_version": 3,
            "_seq_no": 7,
            "_primary_term": 1,
            "found": True,
            "_source": src,
        }
    if method == "POST" and len(parts) == 3 and parts[1] == "_update":
        if parts[0] in ES_STATE["blocked"]:
            return 403, {
                "error": {
                    "root_cause": [
                        {"type": "cluster_block_exception", "reason": f"index [{parts[0]}] blocked by: [FORBIDDEN/8/index write (api)];"},
                    ],
                    "type": "cluster_block_exception",
                    "reason": f"index [{parts[0]}] blocked by: [FORBIDDEN/8/index write (api)];",
                },
                "status": 403,
            }
        return 200, {
            "_index": parts[0],
            "_type": "_doc",
            "_id": parts[2],
            "_version": 4,
            "result": "updated",
            "_seq_no": 8,
            "_primary_term": 1,
        }
    if method == "PUT" and len(parts) == 2 and parts[1] == "_settings":
        if (data or {}).get("index.blocks.write") is None:
            ES_STATE["blocked"].discard(parts[0])
        else:
            ES_STATE["blocked"].add(parts[0])
        return 200, {"acknowledged": True}
    if method == "POST" and parts and parts[-1] == "_search":
        return 200, search_answer(parts[0], query, data)
    return 400, {"error": f"unexpected {method} {path}"}


def shuffle_answer(method, path, body):
    if f"wf-fail{SFX}" in path:
        return 200, {"success": False, "reason": "workflow not found"}
    return 200, {"success": True, "execution_id": "e1"}


def mdr_answer(method, path, body):
    return 200, {"accepted": True}


def talon_answer(method, path, body):
    return 202, {"job_id": "stub", "status": "queued"}


def webhook_answer(method, path, body):
    return 200, {"ok": True}


ES = SHUFFLE = MDR = TALON = WEBHOOK = None


# --- Seed and cleanup -----------------------------------------------------------------------------
SAVED_CONNECTORS = []
DISABLED_RULES = []
SEEDED = {}


def connector_row(name, url, user=None, password=None, api_key=None):
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
        "(:n, '4.8', :u, '2026-01-02 03:04:05', :user, :pw, :key, 'd', 's', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=user,
        pw=password,
        key=api_key,
    )


def seed():
    global SAVED_CONNECTORS
    SAVED_CONNECTORS = [r for n in OUR_CONNECTORS for r in rows("SELECT * FROM connectors WHERE connector_name = :n", n=n)]
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectorhistory WHERE connector_id IN (SELECT id FROM connectors WHERE connector_name = :n)", n=name)
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    connector_row("Wazuh-Indexer", f"http://127.0.0.1:{ES_PORT}", "indexer", "pässword")
    connector_row("Shuffle", f"http://127.0.0.1:{SHUFFLE_PORT}", api_key=f"shuffle-key-{SFX}")
    connector_row("Talon", f"http://127.0.0.1:{TALON_PORT}", api_key=f"talon-key-{SFX}")

    # Deployment-wide exclusion rules other suites left enabled would match these Sigma alerts
    # too (rules are checked in table order): off for this run, restored at cleanup.
    DISABLED_RULES.extend(r["id"] for r in rows("SELECT id FROM incident_management_velo_sigma_exclusion WHERE enabled = 1"))
    if DISABLED_RULES:
        sql("UPDATE incident_management_velo_sigma_exclusion SET enabled = 0 WHERE id IN :ids", ids=tuple(DISABLED_RULES))

    for code, name in ((cust("py"), f"Ingest Name {PY_TAG}"), (cust("rs"), f"Ingest Name {RS_TAG}"), (CUST_B, f"Ingest B {SFX}")):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
        sql("INSERT INTO custom_alert_creation_settings (customer_code, customer_name) VALUES (:c, :n)", c=code, n=name.lower())
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'i@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for code in (cust("py"), cust("rs")):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` "
            "WHERE username = :n",
            c=code,
            n=ANALYST,
        )
    for side, tag in TAGS.items():
        for host, vid in ((f"host-{tag}", f"C.{tag}"), (f"host2-{tag}", None)):
            sql(
                "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, velociraptor_id, "
                "wazuh_agent_version, wazuh_agent_status, customer_code, quarantined) VALUES (:a, '10.1.2.3', 'Windows', :h, 'l', 0, "
                "'2026-03-01 00:00:00', :v, '4.8', 'active', :c, 0)",
                a=f"ag-{host}",
                h=host,
                v=vid,
                c=cust(side),
            )
        # Legacy Shuffle workflow, AI trigger and MDR integration, all on.
        sql(
            "INSERT INTO incident_management_notification (customer_code, shuffle_workflow_id, enabled) VALUES (:c, :w, 1)",
            c=cust(side),
            w=f"wf-{tag}",
        )
        sql("INSERT INTO incident_management_ai_analyst_trigger_enabled (customer_code, enabled) VALUES (:c, 1)", c=cust(side))
        # The notification engine's `alert_created` route (#1006), to a webhook.
        sql(
            "INSERT INTO customer_notification_route (customer_code, name, `trigger`, channel, min_severity, enabled, dispatch_count, "
            "created_by, created_at, config, scope, recipient_mode, notify_on_self_assign) VALUES (:c, :n, 'alert_created', "
            "'webhook', 'Low', 1, 0, 'parity', UTC_TIMESTAMP(), :cfg, 'customer', 'static', 0)",
            c=cust(side),
            n=f"Created hook {tag}",
            cfg=json.dumps({"url": f"http://127.0.0.1:{WEBHOOK_PORT}/hook/{tag}"}),
        )
    service = rows("SELECT id FROM integration_services WHERE service_name = 'SOCFortress MDR' ORDER BY id LIMIT 1")
    if service:
        service_id = service[0]["id"]
    else:
        service_id = sql("INSERT INTO integration_services (service_name, auth_type) VALUES ('SOCFortress MDR', 'apikey')").lastrowid
        SEEDED["service"] = service_id
    for side, tag in TAGS.items():
        ci = sql(
            "INSERT INTO customer_integrations (customer_code, customer_name, integration_service_id, integration_service_name, "
            "deployed) VALUES (:c, :n, :s, 'SOCFortress MDR', 1)",
            c=cust(side),
            n=f"Ingest Name {tag}",
            s=service_id,
        ).lastrowid
        sub = sql(
            "INSERT INTO integration_subscriptions (customer_id, integration_service_id) VALUES (:c, :s)",
            c=ci,
            s=service_id,
        ).lastrowid
        sql(
            "INSERT INTO integration_auth_keys (subscription_id, auth_key_name, auth_value) VALUES (:s, 'COLLECTOR_UUID', :v)",
            s=sub,
            v=f"collector-{tag}",
        )
    # The ingest dictionaries of the three sources.
    for source in (SOURCE, THR_SOURCE, f"mapped{SFX}"):
        for table, names in (
            ("incident_management_fieldname", ("rule_id", "agent_ip", "rule_level", "nested", "score", "big", "nope")),
            ("incident_management_assetfieldname", ("missing_field, agent_name",)),
            ("incident_management_timestampfieldname", ("timestamp_utc",)),
            ("incident_management_alerttitlefieldname", ("rule_description",)),
            ("incident_management_iocfieldname", ("src_ip", "dst_ip")),
        ):
            for n in names:
                sql(f"INSERT INTO {table} (source, field_name) VALUES (:s, :n)", s=source, n=n)
    # The tags the Sigma fallback adds: present, as on any deployment that ever received one.
    for tag_text in ("velociraptor-direct", "event_type:sysmon", "event_type:generic", "event_type:defender", "event_type:powershell"):
        if not rows("SELECT id FROM incident_management_alerttag WHERE tag = :t", t=tag_text):
            sql("INSERT INTO incident_management_alerttag (tag) VALUES (:t)", t=tag_text)
    # One alert of another tenant, with an explicit seven-digit id above every alert id so far:
    # every alert an ingest creates comes after it.
    top = rows("SELECT COALESCE(MAX(id), 0) AS n FROM incident_management_alert")[0]["n"]
    base = max(top + 1000, 2_000_000)
    SEEDED["alert_b"] = base
    sql(
        "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
        "source, escalated) VALUES (:i, 'B alert', 'd', 'OPEN', '2026-03-01 00:00:00', :c, :s, 0)",
        i=base,
        c=CUST_B,
        s=SOURCE,
    )
    # Exclusion rules: one per side (by customer), one for both by a field glob.
    for side, tag in TAGS.items():
        sql(
            "INSERT INTO incident_management_velo_sigma_exclusion (name, description, channel, title, customer_code, field_matches, "
            "created_by, created_at, match_count, enabled) VALUES (:n, 'd', :ch, :t, :c, :f, 'seed', '2026-03-01 00:00:00', 0, 1)",
            n=f"Excl {tag}",
            ch=SIGMA_CHANNEL,
            t=f"Excluded {SFX}",
            c=cust(side),
            f=json.dumps({"TargetImage": "regex:.*\\lsass.exe", "hostapplication": f"powershell.exe -c {SFX}"}),
        )


def cleanup():
    codes = (cust("py"), cust("rs"), CUST_B)
    alert_ids = [
        r["id"]
        for r in rows("SELECT id FROM incident_management_alert WHERE customer_code IN :c OR LOCATE(:s, customer_code) > 0", c=codes, s=SFX)
    ]
    if alert_ids:
        ids = tuple(alert_ids)
        sql("DELETE FROM incident_management_threshold_alert_metadata WHERE alert_id IN :i", i=ids)
        sql("DELETE FROM soc_sla_alert_tracking WHERE alert_id IN :i", i=ids)
        sql("DELETE FROM incident_management_comment WHERE alert_id IN :i", i=ids)
        tag_ids = [r["tag_id"] for r in rows("SELECT tag_id FROM incident_management_alert_to_tag WHERE alert_id IN :i", i=ids)]
        sql("DELETE FROM incident_management_alert_to_tag WHERE alert_id IN :i", i=ids)
        if tag_ids:
            sql(
                "DELETE FROM incident_management_alerttag WHERE id IN :t AND id NOT IN (SELECT tag_id FROM incident_management_alert_to_tag)",
                t=tuple(tag_ids),
            )
        ioc_ids = [r["ioc_id"] for r in rows("SELECT ioc_id FROM incident_management_alert_to_ioc WHERE alert_id IN :i", i=ids)]
        sql("DELETE FROM incident_management_alert_to_ioc WHERE alert_id IN :i", i=ids)
        if ioc_ids:
            sql("DELETE FROM incident_management_ioc WHERE id IN :i", i=tuple(ioc_ids))
        ctx_ids = [
            r["alert_context_id"] for r in rows("SELECT alert_context_id FROM incident_management_asset WHERE alert_linked IN :i", i=ids)
        ]
        sql("DELETE FROM incident_management_asset WHERE alert_linked IN :i", i=ids)
        if ctx_ids:
            sql("DELETE FROM incident_management_alertcontext WHERE id IN :i", i=tuple(ctx_ids))
        sql("UPDATE incident_management_velo_sigma_exclusion SET source_alert_id = NULL WHERE source_alert_id IN :i", i=ids)
        sql("DELETE FROM notification_dispatch_log WHERE alert_id IN :i", i=ids)
        sql("DELETE FROM incident_management_alert WHERE id IN :i", i=ids)
    sql("DELETE FROM incident_management_velo_sigma_exclusion WHERE name LIKE :n", n=f"Excl %{SFX}")
    if DISABLED_RULES:
        sql("UPDATE incident_management_velo_sigma_exclusion SET enabled = 1 WHERE id IN :ids", ids=tuple(DISABLED_RULES))
    for code in codes:
        for r in rows("SELECT id FROM customer_integrations WHERE customer_code = :c", c=code):
            for s in rows("SELECT id FROM integration_subscriptions WHERE customer_id = :c", c=r["id"]):
                sql("DELETE FROM integration_auth_keys WHERE subscription_id = :s", s=s["id"])
            sql("DELETE FROM integration_subscriptions WHERE customer_id = :c", c=r["id"])
        sql("DELETE FROM customer_integrations WHERE customer_code = :c", c=code)
        sql("DELETE FROM incident_management_notification WHERE customer_code = :c", c=code)
        sql("DELETE FROM incident_management_ai_analyst_trigger_enabled WHERE customer_code = :c", c=code)
        sql("DELETE FROM notification_dispatch_log WHERE customer_code = :c", c=code)
        sql("DELETE FROM customer_notification_route WHERE customer_code = :c", c=code)
        sql("DELETE FROM agents WHERE customer_code = :c", c=code)
        sql("DELETE FROM custom_alert_creation_settings WHERE customer_code = :c", c=code)
        sql("DELETE FROM user_customer_access WHERE customer_code = :c", c=code)
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)
    if "service" in SEEDED:
        sql("DELETE FROM integration_services WHERE id = :i", i=SEEDED["service"])
    for source in (SOURCE, THR_SOURCE, f"mapped{SFX}"):
        for table in (
            "incident_management_fieldname",
            "incident_management_assetfieldname",
            "incident_management_timestampfieldname",
            "incident_management_alerttitlefieldname",
            "incident_management_iocfieldname",
        ):
            sql(f"DELETE FROM {table} WHERE source = :s", s=source)
    sql("DELETE FROM scheduled_job_metadata WHERE job_id = :j", j=JOB)
    for row in SEEDED.get("job_rows", []):
        cols = ", ".join(row)
        sql(f"INSERT INTO scheduled_job_metadata ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    if SEEDED.get("store_row"):
        sql("DELETE FROM apscheduler_jobs WHERE id = :j", j=JOB)
    for name in (ADMIN, ANALYST, PORTAL):
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectorhistory WHERE connector_id IN (SELECT id FROM connectors WHERE connector_name = :n)", n=name)
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)


# --- The two backends -------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import incidents

    api = APIRouter(prefix="/api")
    api.include_router(incidents.router)
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
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_PORT": str(RS_PORT),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "COPILOT_RS_JOBS": JOB,
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        **INGEST_ENV,
    }
    # Both processes read the Sigma event's time in the host's local time zone.
    if "TZ" in os.environ:
        env["TZ"] = os.environ["TZ"]
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(150):
        try:
            if httpx.get(f"http://127.0.0.1:{RS_PORT}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


# --- Normalization ------------------------------------------------------------------------------------
#: A wall-clock "now" a backend computed: epoch milliseconds, or a `%Y-%m-%d %H:%M:%S.%f`[:-3]
#: within two hours of now (the Sigma search's "the last hour").
NOW_MS = re.compile(r"\b1[789]\d{11}\b")
NOW_STAMP = re.compile(r"\b20\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\b")


def _mask_stamp(m):
    at = datetime.datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S.%f")
    near = any(abs((at - now).total_seconds()) < 7200 for now in (datetime.datetime.now(), datetime.datetime.utcnow()))
    return "<stamp>" if near else m.group(0)


def alert_labels():
    """Each side's alert ids -> their rank on that side (`<a0>`, `<a1>`, …)."""
    labels = {}
    for side in ("py", "rs"):
        ids = [
            r["id"] for r in rows("SELECT id FROM incident_management_alert WHERE LOCATE(:t, customer_code) > 0 ORDER BY id", t=TAGS[side])
        ]
        labels[side] = {i: f"<a{n}>" for n, i in enumerate(ids)}
    return labels


def norm_text(textual, side, labels):
    textual = textual.replace(RS_TAG, PY_TAG) if side == "rs" else textual
    for alert_id, label in sorted(labels[side].items(), key=lambda kv: -kv[0]):
        textual = re.sub(rf"(?<![0-9]){alert_id}(?![0-9])", label, textual)
    return NOW_STAMP.sub(_mask_stamp, NOW_MS.sub("<ms>", textual))


def norm_outbound(captured, side, labels):
    out = []
    for method, path, headers, body in captured:
        out.append((method, norm_text(path, side, labels), headers, norm_text(body.decode("utf-8", "replace"), side, labels)))
    return out


def body_text(r):
    return r.content.decode("utf-8", "replace")


def first_difference(a, b):
    at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    start = max(0, at - 200)
    return f"…{a[start:at + 400]!r}\n        …{b[start:at + 400]!r}"


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)
        self.recorders = (ES, SHUFFLE, MDR, TALON, WEBHOOK)

    async def call(self, side, method, path, tok, settle, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        for recorder in self.recorders:
            recorder.take()
        client = self.py if side == "py" else self.rs
        r = await client.request(method, path, headers=headers, **kw)
        # Talon is called on a background task, on both sides.
        await asyncio.sleep(0.6 if settle else 0)
        return r, {rec.name: rec.take() for rec in self.recorders}

    async def same(self, name, method, path, tok=None, body=None, twin=False, settle=False, raw=None, **kw):
        """Python, then Rust. `twin`: `path`/`body` are functions of the side."""
        out = {}
        for side in ("py", "rs"):
            ES_STATE["side"] = side
            p = path(side) if twin and callable(path) else path
            b = body(side) if twin and callable(body) else body
            args = dict(kw)
            if raw is not None:
                args["content"] = raw
                args.setdefault("headers", {})["Content-Type"] = "application/json"
            elif b is not None:
                args["json"] = b
            out[side] = await self.call(side, method, p, tok, settle, **args)
        labels = alert_labels()
        (r1, o1), (r2, o2) = out["py"], out["rs"]
        t1, t2 = norm_text(body_text(r1), "py", labels), norm_text(body_text(r2), "rs", labels)
        ok = r1.status_code == r2.status_code and t1 == t2
        detail = f"python {r1.status_code} / rust {r2.status_code}\n        {first_difference(t1, t2)}"
        for tool in o1:
            n1, n2 = norm_outbound(o1[tool], "py", labels), norm_outbound(o2[tool], "rs", labels)
            if n1 != n2:
                ok = False
                detail += f"\n        {tool} python {n1}\n        {tool} rust   {n2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {t1[:500]}\n        outbound { {k: [(m, p) for m, p, h, b in v] for k, v in o1.items()} }")
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()


# --- Rows ----------------------------------------------------------------------------------------------


def near_now(value):
    return isinstance(value, datetime.datetime) and abs((value - datetime.datetime.utcnow()).total_seconds()) < 3600


def stored(side):
    """What the ingest left for one side: every alert of its customer with its relationships."""
    out = []
    for a in rows("SELECT * FROM incident_management_alert WHERE LOCATE(:t, customer_code) > 0 ORDER BY id", t=TAGS[side]):
        aid = a.pop("id")
        a["assets"] = rows(
            "SELECT s.asset_name, s.agent_id, s.velociraptor_id, s.customer_code, s.index_name, s.index_id, c.source AS context_source, "
            "c.context FROM incident_management_asset s JOIN incident_management_alertcontext c ON c.id = s.alert_context_id "
            "WHERE s.alert_linked = :a ORDER BY s.id",
            a=aid,
        )
        for asset in a["assets"]:
            asset["context"] = json.loads(asset["context"]) if asset["context"] is not None else None
        a["iocs"] = rows(
            "SELECT i.value, i.type, i.description FROM incident_management_alert_to_ioc l JOIN incident_management_ioc i "
            "ON i.id = l.ioc_id WHERE l.alert_id = :a ORDER BY i.id",
            a=aid,
        )
        a["tags"] = [
            r["tag"]
            for r in rows(
                "SELECT t.tag FROM incident_management_alert_to_tag l JOIN incident_management_alerttag t ON t.id = l.tag_id "
                "WHERE l.alert_id = :a ORDER BY t.id",
                a=aid,
            )
        ]
        a["comments"] = rows(
            "SELECT comment, user_name, created_at FROM incident_management_comment WHERE alert_id = :a ORDER BY id",
            a=aid,
        )
        a["sla"] = rows(
            "SELECT severity, TIMESTAMPDIFF(SECOND, opened_at, ack_due_at) AS ack, TIMESTAMPDIFF(SECOND, opened_at, resolve_due_at) AS "
            "res, first_ack_at, resolved_at, reopen_count, tracked, business_hours, paused_at FROM soc_sla_alert_tracking "
            "WHERE alert_id = :a",
            a=aid,
        )
        a["dispatch"] = rows(
            "SELECT `trigger`, status, entity_type, dedupe_key, trigger_source, triggered_by, error_message, payload_preview "
            "FROM notification_dispatch_log WHERE alert_id = :a ORDER BY id",
            a=aid,
        )
        a["threshold"] = rows(
            "SELECT event_definition_id, replay_query, timerange_start, timerange_end, group_by_fields, source_streams, source, "
            "resolved_index_name, resolved_index_id FROM incident_management_threshold_alert_metadata WHERE alert_id = :a",
            a=aid,
        )
        for t in a["threshold"]:
            t["group_by_fields"] = json.loads(t["group_by_fields"]) if t["group_by_fields"] else t["group_by_fields"]
            t["source_streams"] = json.loads(t["source_streams"]) if t["source_streams"] else t["source_streams"]
        out.append(a)
    rules = rows(
        "SELECT name, match_count, last_matched_at FROM incident_management_velo_sigma_exclusion WHERE name = :n",
        n=f"Excl {TAGS[side]}",
    )
    return {"alerts": out, "rules": rules}


def masked_rows(value):
    if isinstance(value, dict):
        return {k: masked_rows(v) for k, v in value.items()}
    if isinstance(value, list):
        return [masked_rows(v) for v in value]
    if near_now(value):
        return "<now>"
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return value


def compare_rows(name):
    labels = alert_labels()
    py = norm_text(json.dumps(masked_rows(stored("py")), default=str), "py", labels)
    rs = norm_text(json.dumps(masked_rows(stored("rs")), default=str), "rs", labels)
    check(f"rows: {name}", py == rs, first_difference(py, rs))


# --- The checks -------------------------------------------------------------------------------------
A = "/api/incidents/alerts"
D = "/api/incidents/db_operations"


def sysmon_event(tag, record_id=98765, **data):
    event_data = {
        "RuleName": "technique_id=T1003",
        "UtcTime": "2026-03-01 10:00:00.123",
        "SourceProcessGUID": "{11111111-0000-0000-0000-000000000000}",
        "SourceProcessId": 4242,
        "SourceThreadId": 7,
        "SourceImage": "C:\\Windows\\Temp\\mimi.exe",
        "TargetProcessGUID": "{22222222-0000-0000-0000-000000000000}",
        "TargetProcessId": 612,
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "GrantedAccess": 5136,
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d204",
        "SourceUser": f"CORP\\{tag}",
        "TargetUser": "NT AUTHORITY\\SYSTEM",
        "ContextInfo": f"        Severity = Warning\n        Host Application = powershell.exe -c {SFX}\n        User = {tag}\n",
    }
    event_data.update(data)
    return {
        "System": {
            "Provider": {"Name": "Microsoft-Windows-Sysmon", "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"},
            "EventID": {"Value": 10},
            "Version": 3,
            "Level": 4,
            "Task": 10,
            "Opcode": 0,
            "Keywords": 9223372036854775808,
            "TimeCreated": {"SystemTime": 1772359200.123457},
            "EventRecordID": record_id,
            "Correlation": {},
            "Execution": {"ProcessID": 3000, "ThreadID": 4000},
            "Channel": SIGMA_CHANNEL,
            "Computer": f"host-{tag}",
            "Security": {"UserID": "S-1-5-18"},
        },
        "Message": "Process accessed",
        "EventData": event_data,
    }


def sigma(side, title, **kw):
    tag = TAGS[side]
    body = {
        "computer": f"host-{tag}",
        "clientID": f"C.{tag}",
        "channel": SIGMA_CHANNEL,
        "title": title,
        "level": "high",
        "event": sysmon_event(tag),
        "type": f"sigma-{tag}",
        "index_pattern": f"wazuh-{SFX}-*",
        "sourceRef": f"ref-{tag}",
    }
    body.update(kw)
    return {k: v for k, v in body.items() if v is not ...}


def threshold(side, **over):
    tag = TAGS[side]
    event = {
        "id": f"01J{SFX}",
        "event_definition_type": "aggregation-v1",
        "event_definition_id": f"65a{SFX}",
        "origin_context": None,
        "timestamp": "2026-03-01T10:05:00.219Z",
        "timestamp_processing": "2026-03-01T10:05:01.754+02:00",
        "timerange_start": "2026-03-01T10:00:00.000Z",
        "timerange_end": "2026-03-01T10:05:00.000Z",
        "streams": [],
        "source_streams": ["67abcb0a84088513bdc09e32", "s2"],
        "message": f"MULTIPLE AUTH FAILURES {SFX}: 10.0.64.233 - count()=14.0",
        "source": "soc-grlog02",
        "key_tuple": ["10.0.64.233"],
        "key": "10.0.64.233",
        "priority": 2,
        "alert": True,
        "fields": {
            "CUSTOMER_CODE": cust(side),
            "SOURCE": THR_SOURCE,
            "ALERT_DESCRIPTION": f"Auth failures {tag}",
            "EXTRA": [1, {"b": None}],
        },
        "group_by_fields": {"agent_name": f"host-{tag}", "empty": "", "n": 0, "ratio": 0.000025, "big": 1e16},
        "replay_info": {
            "timerange_start": "2026-03-01T10:00:00.000Z",
            "timerange_end": "2026-03-01T10:05:00.000+00:00",
            "query": f"rule_group:authentication_failed AND customer:{tag}",
            "streams": ["s1"],
        },
    }
    event.update(over.pop("event", {}))
    body = {
        "event_definition_id": f"65a{SFX}",
        "event_definition_type": "aggregation-v1",
        "event_definition_title": "AUTH FAILURES",
        "job_definition_id": "j1",
        "job_trigger_id": "t1",
        "event": event,
    }
    body.update(over)
    return body


async def auth_and_validation(p, t):
    print("\n=== auth, headers and validation ===")
    for method, path in (
        ("GET", f"{A}/index/names"),
        ("GET", f"{A}/alerts/not-created"),
        ("POST", f"{A}/alert/details"),
        ("POST", f"{A}/alert/timeline"),
        ("POST", f"{A}/create/manual"),
        ("POST", f"{A}/create/auto"),
        ("GET", f"{A}/alert/1/velo-sigma/exclusion-draft"),
        ("POST", f"{A}/alert/1/velo-sigma/exclusion-dry-run"),
        ("GET", f"{D}/available-source/{IDX}"),
        ("GET", f"{D}/available-indices/wazuh"),
        ("GET", f"{D}/mappings/fields-assets-title-and-timefield?index_name={IDX}"),
    ):
        await p.same(f"no token: {method} {path.split('?')[0]}", method, path)
        await p.same(f"portal: {method} {path.split('?')[0]}", method, path, t["portal"])
    await p.same("malformed JSON before the token", "POST", f"{A}/create/manual", raw=b"{nope")
    await p.same("manual: missing fields", "POST", f"{A}/create/manual", t["admin"], body={"index_name": 3})
    await p.same("manual: not an object", "POST", f"{A}/create/manual", t["admin"], body=[1])
    await p.same("details: missing index_id", "POST", f"{A}/alert/details", t["admin"], body={"index_name": IDX, "alert_id": "x"})
    await p.same(
        "timeline: alert_id not an int",
        "POST",
        f"{A}/alert/timeline",
        t["admin"],
        body={"index_name": IDX, "index_id": "x", "alert_id": "x"},
    )
    gh = INGEST_ENV["GRAYLOG_API_HEADER_VALUE"]
    vh = INGEST_ENV["VELOCIRAPTOR_API_HEADER_VALUE"]
    await p.same("threshold: no header", "POST", f"{A}/create/threshold", body=threshold("py"))
    await p.same("threshold: wrong header", "POST", f"{A}/create/threshold", headers={"graylog": "nope"}, body=threshold("py"))
    await p.same("threshold: token is not the header", "POST", f"{A}/create/threshold", t["admin"], body=threshold("py"))
    await p.same("threshold: malformed JSON, no header", "POST", f"{A}/create/threshold", raw=b"[")
    await p.same("threshold: empty body", "POST", f"{A}/create/threshold", headers={"graylog": gh})
    await p.same("threshold: missing fields", "POST", f"{A}/create/threshold", headers={"graylog": gh}, body={"event": {"fields": {}}})
    await p.same(
        "threshold: bad datetimes and types",
        "POST",
        f"{A}/create/threshold",
        headers={"graylog": gh},
        body=threshold(
            "py",
            event={
                "timestamp": "yesterday",
                "priority": "high",
                "alert": "maybe",
                "fields": {"CUSTOMER_CODE": 5, "SOURCE": None},
                "replay_info": {"timerange_start": 1e30, "timerange_end": "2026-02-30", "query": [], "streams": "s"},
                "group_by_fields": [],
            },
            backlog={},
        ),
    )
    await p.same("velo-sigma: no header", "POST", f"{A}/create/velo-sigma", body=sigma("py", "x"))
    await p.same("velo-sigma: wrong header", "POST", f"{A}/create/velo-sigma", headers={"velociraptor": "nope"}, body=sigma("py", "x"))
    await p.same("velo-sigma: missing fields", "POST", f"{A}/create/velo-sigma", headers={"velociraptor": vh}, body={"computer": 1})
    await p.same(
        "velo-sigma: event is invalid JSON",
        "POST",
        f"{A}/create/velo-sigma",
        headers={"velociraptor": vh},
        body=sigma("py", "x", event="{not json"),
    )
    await p.same(
        "velo-sigma: event of no member",
        "POST",
        f"{A}/create/velo-sigma",
        headers={"velociraptor": vh},
        body=sigma("py", "x", event=[1, 2]),
    )
    await p.same("draft: alert id not an int", "GET", f"{A}/alert/abc/velo-sigma/exclusion-draft", t["admin"])
    await p.same("dry-run: path, then body", "POST", f"{A}/alert/abc/velo-sigma/exclusion-dry-run", t["admin"], body={"channel": 1})
    await p.same("dry-run: body", "POST", f"{A}/alert/1/velo-sigma/exclusion-dry-run", t["admin"], body={"field_matches": "x"})
    await p.same("mappings: index_name missing", "GET", f"{D}/mappings/fields-assets-title-and-timefield", t["admin"])


async def reads(p, t):
    print("\n=== indexer reads ===")
    await p.same("index names", "GET", f"{A}/index/names", t["analyst"])
    await p.same("alerts not created (a tuple: 500)", "GET", f"{A}/alerts/not-created", t["admin"])
    ES_STATE["events"] = "malformed"
    await p.same("alerts not created, a malformed event", "GET", f"{A}/alerts/not-created", t["admin"])
    ES_STATE["events"] = "normal"
    for doc in (f"one{PY_TAG}", f"three{PY_TAG}", f"integ{PY_TAG}", f"noint{PY_TAG}", f"missing{PY_TAG}", f"notitle{PY_TAG}"):
        await p.same(f"details: {doc}", "POST", f"{A}/alert/details", t["analyst"], body={"index_name": IDX, "index_id": doc})
    await p.same("details: unknown index", "POST", f"{A}/alert/details", t["admin"], body={"index_name": "nowhere", "index_id": "x"})
    await p.same("timeline: a process", "POST", f"{A}/alert/timeline", t["admin"], body={"index_name": IDX, "index_id": f"one{PY_TAG}"})
    await p.same("timeline: no process", "POST", f"{A}/alert/timeline", t["admin"], body={"index_name": IDX, "index_id": f"three{PY_TAG}"})
    await p.same(
        "timeline: no threshold metadata for that alert",
        "POST",
        f"{A}/alert/timeline",
        t["admin"],
        body={"index_name": IDX, "index_id": f"one{PY_TAG}", "alert_id": SEEDED["alert_b"]},
    )
    for index in (IDX, f"integ-{SFX}", f"integonly-{SFX}", f"none-{SFX}", f"weird-{SFX}"):
        await p.same(f"available source: {index}", "GET", f"{D}/available-source/{index}", t["analyst"])
    for source in ("wazuh", "office365", "Office365", "wazuh-alerts-.*-4", "(", "x$", "nothing"):
        await p.same(f"available indices: {source}", "GET", f"{D}/available-indices/{source}", t["analyst"])
    for index in (IDX, f"flat-{SFX}", f"none-{SFX}"):
        await p.same(f"mappings: {index}", "GET", f"{D}/mappings/fields-assets-title-and-timefield?index_name={index}", t["analyst"])
    await p.same("encoded slash goes to Python", "GET", f"{D}/available-source/a%2Fb", t["analyst"])


async def manual(p, t):
    print("\n=== manual creation (twins) ===")

    def req(doc, index=IDX):
        return lambda side: {"index_name": index, "alert_id": f"{doc}{TAGS[side]}"}

    await p.same("manual: a new alert", "POST", f"{A}/create/manual", t["admin"], body=req("one"), twin=True, settle=True)
    compare_rows("a new alert")
    await p.same("manual: merged into the open alert", "POST", f"{A}/create/manual", t["analyst"], body=req("two"), twin=True, settle=True)
    compare_rows("merged")
    await p.same("manual: the same document again", "POST", f"{A}/create/manual", t["admin"], body=req("two"), twin=True, settle=True)
    compare_rows("merged twice")
    await p.same(
        "manual: title cleaned, IoC not classifiable",
        "POST",
        f"{A}/create/manual",
        t["admin"],
        body=req("three"),
        twin=True,
        settle=True,
    )
    await p.same("manual: customer by name", "POST", f"{A}/create/manual", t["admin"], body=req("syslogcust"), twin=True, settle=True)
    await p.same(
        "manual: through the integration field",
        "POST",
        f"{A}/create/manual",
        t["admin"],
        body=req("integ"),
        twin=True,
        settle=True,
    )
    compare_rows("three more alerts")
    for doc in ("bad", "nosrc", "notitle", "nocust", "noint", "missing"):
        await p.same(f"manual: {doc}", "POST", f"{A}/create/manual", t["admin"], body=req(doc), twin=True, settle=True)
    ES_STATE["blocked"].add(f"blocked-{SFX}")
    await p.same(
        "manual: a write-blocked index",
        "POST",
        f"{A}/create/manual",
        t["admin"],
        body=req("blk", f"blocked-{SFX}"),
        twin=True,
        settle=True,
    )
    ES_STATE["blocked"].clear()
    compare_rows("after the refusals")
    # The legacy Shuffle workflow fails: logged, the alert is still created.
    sql(
        "UPDATE incident_management_notification SET shuffle_workflow_id = :w WHERE customer_code IN :c",
        w=f"wf-fail{SFX}",
        c=(cust("py"), cust("rs")),
    )
    await p.same("manual: Shuffle refuses", "POST", f"{A}/create/manual", t["admin"], body=req("collected"), twin=True, settle=True)
    compare_rows("Shuffle refuses")


async def timelines(p, t):
    print("\n=== timelines of created alerts ===")
    labels = alert_labels()
    first = {side: min(labels[side]) for side in ("py", "rs")}
    await p.same(
        "timeline of a created alert (no metadata)",
        "POST",
        f"{A}/alert/timeline",
        t["admin"],
        body=lambda side: {"index_name": IDX, "index_id": f"one{TAGS[side]}", "alert_id": first[side]},
        twin=True,
    )


async def thresholds(p, t):
    print("\n=== Graylog threshold alerts (twins) ===")
    gh = {"graylog": INGEST_ENV["GRAYLOG_API_HEADER_VALUE"]}
    await p.same("threshold: resolved event", "POST", f"{A}/create/threshold", headers=gh, body=threshold, twin=True, settle=True)
    compare_rows("threshold, resolved")
    await p.same(
        "threshold: nothing matches the replay",
        "POST",
        f"{A}/create/threshold",
        headers=gh,
        body=lambda side: threshold(side, event={"group_by_fields": {"agent_name": "nobody"}, "message": f"Unresolved {SFX}"}),
        twin=True,
        settle=True,
    )
    await p.same(
        "threshold: a mapped source",
        "POST",
        f"{A}/create/threshold",
        headers=gh,
        body=lambda side: threshold(
            side,
            event={
                "fields": {"CUSTOMER_CODE": cust(side), "SOURCE": f"mapped{SFX}", "ALERT_DESCRIPTION": "m", "ASSET_NAME": "given"},
                "message": f"Mapped {SFX}",
            },
        ),
        twin=True,
        settle=True,
    )
    compare_rows("threshold, unresolved and mapped")
    labels = alert_labels()
    for rank, name in ((-3, "resolved"), (-2, "unresolved")):
        ids = {side: sorted(labels[side])[rank] for side in ("py", "rs")}
        meta = {
            side: rows(
                "SELECT resolved_index_name, resolved_index_id FROM incident_management_threshold_alert_metadata WHERE alert_id = :a",
                a=ids[side],
            )
            for side in ids
        }
        await p.same(
            f"timeline: threshold replay ({name})",
            "POST",
            f"{A}/alert/timeline",
            t["admin"],
            body=lambda side, ids=ids, meta=meta: {
                "index_name": meta[side][0]["resolved_index_name"] if meta[side] else "x",
                "index_id": meta[side][0]["resolved_index_id"] if meta[side] else "x",
                "alert_id": ids[side],
            },
            twin=True,
        )
        await p.same(
            f"timeline: threshold replay by document ({name})",
            "POST",
            f"{A}/alert/timeline",
            t["admin"],
            body=lambda side, meta=meta: {
                "index_name": meta[side][0]["resolved_index_name"] if meta[side] else "x",
                "index_id": meta[side][0]["resolved_index_id"] if meta[side] else "x",
            },
            twin=True,
        )


async def sigma_ingest(p, t):
    print("\n=== Velociraptor Sigma ingest (twins) ===")
    vh = {"velociraptor": INGEST_ENV["VELOCIRAPTOR_API_HEADER_VALUE"]}
    await p.same(
        "velo-sigma: excluded by its customer's rule",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(side, f"Excluded {SFX}"),
        twin=True,
        settle=True,
    )
    compare_rows("exclusion statistics")
    await p.same(
        "velo-sigma: the Wazuh copy becomes the alert",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(side, f"Sigma Mimikatz {SFX}"),
        twin=True,
        settle=True,
    )
    compare_rows("Sigma, Wazuh path")
    await p.same(
        "velo-sigma: no Wazuh copy (fallback), event as a string",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(side, f"Fallback {SFX}", event=json.dumps(sysmon_event(TAGS[side], record_id=11))),
        twin=True,
        settle=True,
    )
    await p.same(
        "velo-sigma: fallback merged into its open alert",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(side, f"Fallback {SFX}", event=sysmon_event(TAGS[side], record_id=12)),
        twin=True,
        settle=True,
    )
    compare_rows("Sigma, fallback")
    await p.same(
        "velo-sigma: a generic channel, no client id",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(
            side,
            f"Generic {SFX}",
            channel="Security",
            clientID=...,
            event={**sysmon_event(TAGS[side], record_id=13), "EventData": {"Only": "this"}},
        ),
        twin=True,
        settle=True,
    )
    await p.same(
        "velo-sigma: a generic channel with a client id",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(
            side,
            f"Generic two {SFX}",
            channel="Security",
            event={**sysmon_event(TAGS[side], record_id=14), "EventData": {"Only": "this", "Nested": {"a": [1, 2]}}},
        ),
        twin=True,
        settle=True,
    )
    powershell = {
        "MessageNumber": 1,
        "MessageTotal": 1,
        "ScriptBlockText": "Invoke-Mimikatz -DumpCreds " + "x" * 250,
        "ScriptBlockId": "{33333333-0000-0000-0000-000000000000}",
        "Path": "C:\\Users\\a\\evil.ps1",
    }
    await p.same(
        "velo-sigma: a PowerShell event",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(
            side,
            f"PowerShell {SFX}",
            channel="Microsoft-Windows-PowerShell/Operational",
            event={
                **sysmon_event(TAGS[side], record_id=15),
                "System": {
                    **sysmon_event(TAGS[side], record_id=15)["System"],
                    "Provider": {"Name": "Microsoft-Windows-PowerShell", "Guid": "{A0C1853B}"},
                },
                "EventData": powershell,
            },
        ),
        twin=True,
        settle=True,
    )
    defender = {
        "Product Name": "Microsoft Defender Antivirus",
        "Product Version": "4.18.2302.7",
        "Threat Name": "HackTool:Win64/Mikatz!dha",
        "Severity Name": "High",
        "Path": "file:_C:\\Windows\\Temp\\mimi.exe",
        "Process Name": "C:\\Windows\\explorer.exe",
        "Extra": "kept",
    }
    await p.same(
        "velo-sigma: a Defender event",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(
            side,
            f"Defender {SFX}",
            channel="Microsoft-Windows-Windows Defender/Operational",
            event={**sysmon_event(TAGS[side], record_id=16), "EventData": defender},
        ),
        twin=True,
        settle=True,
    )
    await p.same(
        "velo-sigma: unknown host",
        "POST",
        f"{A}/create/velo-sigma",
        headers=vh,
        body=lambda side: sigma(side, f"Unknown {SFX}", computer=f"ghost-{TAGS[side]}", clientID=f"C.ghost{TAGS[side]}"),
        twin=True,
        settle=True,
    )
    compare_rows("Sigma, generic and unknown host")


async def drafts(p, t):
    print("\n=== exclusion draft and dry-run (twins) ===")
    by_title = {}
    for side in ("py", "rs"):
        found = rows(
            "SELECT id, alert_name FROM incident_management_alert WHERE customer_code = :c ORDER BY id",
            c=cust(side),
        )
        by_title[side] = {r["alert_name"]: r["id"] for r in found}
    for title in (
        f"Sigma via Wazuh {SFX}",
        f"Fallback {SFX}",
        f"Generic two {SFX}",
        f"PowerShell {SFX}",
        f"Defender {SFX}",
        f"Mimikatz {SFX}",
    ):
        ids = {side: by_title[side].get(title, 1) for side in by_title}
        await p.same(
            f"draft: {title}",
            "GET",
            lambda side, ids=ids: f"{A}/alert/{ids[side]}/velo-sigma/exclusion-draft",
            t["analyst"],
            twin=True,
        )
    ids = {side: by_title[side].get(f"Sigma via Wazuh {SFX}", 1) for side in by_title}
    for label, rule in (
        (
            "matches",
            lambda side: {"channel": SIGMA_CHANNEL, "title": f"Sigma Mimikatz {SFX}", "field_matches": {"SourceImage": "*mimi.exe"}},
        ),
        (
            "everything wrong",
            lambda side: {
                "channel": SIGMA_CHANNEL.lower(),
                "title": "x",
                "customer_code": "other",
                "field_matches": {"Nope": 1, "GrantedAccess": "5136"},
            },
        ),
        ("empty rule", lambda side: {}),
        ("by customer", lambda side: {"customer_code": cust(side), "field_matches": {"hostApplication": f"powershell.exe -c {SFX}"}}),
        ("a regex", lambda side: {"field_matches": {"TargetImage": "regex:.*LSASS\\.EXE$"}}),
    ):
        await p.same(
            f"dry-run: {label}",
            "POST",
            lambda side: f"{A}/alert/{ids[side]}/velo-sigma/exclusion-dry-run",
            t["admin"],
            body=rule,
            twin=True,
        )
    await p.same("draft: another tenant's alert", "GET", f"{A}/alert/{SEEDED['alert_b']}/velo-sigma/exclusion-draft", t["analyst"])
    await p.same("draft: no such alert", "GET", f"{A}/alert/999999999/velo-sigma/exclusion-draft", t["admin"])
    await p.same("draft: an alert without Sigma comments", "GET", f"{A}/alert/{SEEDED['alert_b']}/velo-sigma/exclusion-draft", t["admin"])
    await p.same(
        "dry-run: another tenant's alert",
        "POST",
        f"{A}/alert/{SEEDED['alert_b']}/velo-sigma/exclusion-dry-run",
        t["analyst"],
        body={},
    )


async def collector(p, t):
    print("\n=== the Graylog-event collector (twins) ===")
    await p.same("create/auto", "POST", f"{A}/create/auto", t["admin"], twin=True, settle=True)
    compare_rows("collected")
    ES_STATE["events"] = "malformed"
    await p.same("create/auto: a malformed event empties the batch", "POST", f"{A}/create/auto", t["admin"], twin=True, settle=True)
    ES_STATE["events"] = "none"
    await p.same("create/auto: nothing to collect", "POST", f"{A}/create/auto", t["admin"], twin=True, settle=True)
    ES_STATE["events"] = "normal"


async def handover(p, t):
    """The job: Python runs it while the row is enabled; disabled, its guard skips and Rust runs it."""
    print("\n=== invoke_alert_creation_collect hand-over ===")
    from app.schedulers import handover as handover_module
    from app.schedulers.services.invoke_alert_creation import (
        invoke_alert_creation_collect,
    )

    def take_all():
        return {rec.name: rec.take() for rec in p.recorders}

    take_all()
    ES_STATE["side"], ES_STATE["events"] = "py", "normal"
    sql("UPDATE incident_management_alert SET status = 'CLOSED' WHERE customer_code IN :c", c=(cust("py"), cust("rs")))
    ran = await invoke_alert_creation_collect()
    await asyncio.sleep(0.6)
    py_out = take_all()
    py_stamp = rows("SELECT last_success FROM scheduled_job_metadata WHERE job_id = :j", j=JOB)[0]["last_success"]
    check("Python owns the job while its row is enabled", ran is None and py_out["es"] and near_now(py_stamp), f"{ran!r} {py_stamp}")

    sql("UPDATE scheduled_job_metadata SET enabled = 0, last_success = NULL WHERE job_id = :j", j=JOB)
    skipped = await invoke_alert_creation_collect()
    check("handed over: the Python guard skips", skipped is handover_module.JOB_SKIPPED and not any(take_all().values()), repr(skipped))
    ES_STATE["side"] = "rs"
    r = await p.rs.post(f"/api/scheduler/jobs/run/{JOB}", headers={"Authorization": f"Bearer {t['admin']}"})
    await asyncio.sleep(0.6)
    rs_out = take_all()
    rs_stamp = rows("SELECT last_success FROM scheduled_job_metadata WHERE job_id = :j", j=JOB)[0]["last_success"]
    check(
        "handed over: Rust runs it and stamps it",
        r.status_code == 200 and rs_out["es"] and near_now(rs_stamp),
        f"{r.status_code} {r.text[:300]} {rs_stamp}",
    )
    labels = alert_labels()
    for tool in py_out:
        n1, n2 = norm_outbound(py_out[tool], "py", labels), norm_outbound(rs_out[tool], "rs", labels)
        check(f"job outbound: {tool}", n1 == n2, f"python {n1}\n        rust   {n2}")
    compare_rows("job runs")
    sql("UPDATE scheduled_job_metadata SET enabled = 1 WHERE job_id = :j", j=JOB)


async def store_job():
    """The job in APScheduler's store, as `init_scheduler` leaves it (the Rust run route reads it)."""
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    from app.schedulers.services.invoke_alert_creation import (
        invoke_alert_creation_collect,
    )

    if rows("SELECT id FROM apscheduler_jobs WHERE id = :j", j=JOB):
        SEEDED["kept_store_row"] = True
        return
    scheduler = AsyncIOScheduler(event_loop=asyncio.get_running_loop())
    scheduler.configure(jobstores={"default": SQLAlchemyJobStore(engine=sync_engine)})
    scheduler.start(paused=True)
    scheduler.add_job(
        invoke_alert_creation_collect,
        "interval",
        minutes=1440,
        id=JOB,
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.shutdown(wait=False)
    SEEDED["store_row"] = True


async def main():
    global ES, SHUFFLE, MDR, TALON, WEBHOOK
    WEBHOOK = Recorder(WEBHOOK_PORT, webhook_answer, "webhook")
    ES = Recorder(ES_PORT, es_answer, "es")
    SHUFFLE = Recorder(SHUFFLE_PORT, shuffle_answer, "shuffle")
    MDR = Recorder(MDR_PORT, mdr_answer, "mdr")
    TALON = Recorder(TALON_PORT, talon_answer, "talon")
    proc = p = None
    t = {"admin": token(ADMIN, ["admin"]), "analyst": token(ANALYST, ["analyst"]), "portal": token(PORTAL, ["customer_user"])}
    try:
        seed()
        SEEDED["job_rows"] = rows("SELECT * FROM scheduled_job_metadata WHERE job_id = :j ORDER BY id", j=JOB)
        sql("DELETE FROM scheduled_job_metadata WHERE job_id = :j", j=JOB)
        # The job's row before the Rust instance starts: a day-long interval, so Rust's own grid
        # never fires during the run; the hand-over is driven by hand.
        sql(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, enabled, job_description) VALUES "
            "(:j, NULL, 1440, 1, 'Invokes alert creation collection.')",
            j=JOB,
        )
        await store_job()
        proc = start_rust()
        p = Pair()
        await auth_and_validation(p, t)
        await reads(p, t)
        await manual(p, t)
        await timelines(p, t)
        await thresholds(p, t)
        await sigma_ingest(p, t)
        await drafts(p, t)
        await collector(p, t)
        await handover(p, t)
    finally:
        if p is not None:
            await p.close()
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        cleanup()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
