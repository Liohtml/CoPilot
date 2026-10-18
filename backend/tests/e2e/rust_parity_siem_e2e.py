"""Parity of the Rust SIEM and threat-intel modules with this backend — NOT collected by
pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

Sends the same requests to the real FastAPI routers (`app/routers/siem.py`,
`app/routers/threat_intel.py`, in-process) and to a Rust instance this suite starts
(`crates/copilot-siem`, `crates/copilot-threat-intel`), both on the same disposable
database, and compares status codes, bodies (key order included), the rows each write
leaves and every request each backend sends upstream — every header the client library
puts on the wire, `Content-Length` included. The upstreams are local stand-ins that
record what arrives:

* the Wazuh indexer (searches, scrolls, documents, `_field_caps`; text-field and sort
  failures, gzip-compressed answers, a closed port);
* SOCFortress (threat intel, the AI endpoints, the cyber-news MCP, the licence server),
  VirusTotal and api.first.org's EPSS API.

Python reaches the stand-ins because `httpx.AsyncClient.build_request` and
`requests.Session.request` are patched here to rewrite the public hosts; Rust because
its instance is started with the `COPILOT_*_URL` overrides (parity harness only).

Two things are masked, both with a check of their own: the time window's `gte` (each
backend reads its own clock; the two must be within seconds of each other) and the
patch version in elasticsearch-py's `User-Agent` (`Python 3.11.N`, the interpreter's).
Rows created by both backends get the same ids because the auto-increment counter is
put back between the two calls.

Ports (all overridable): SIEM_PARITY_RUST_PORT, SIEM_INDEXER_STUB_PORT,
SIEM_TI_STUB_PORT, SIEM_VT_STUB_PORT, SIEM_EPSS_STUB_PORT.

    PARITY_SUITES=tests/e2e/rust_parity_siem_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
import gzip
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
from urllib.parse import parse_qsl
from urllib.parse import unquote

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
# `send_post_request` reads it per call (`os.getenv`); the Rust instance gets the same.
os.environ["COPILOT_API_KEY"] = "parity-copilot-api-key"
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

import httpx  # noqa: E402
import jwt  # noqa: E402
import requests  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.connectors import cache as connector_cache  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("SIEM_PARITY_RUST_PORT", "5887"))
INDEXER_PORT = int(os.environ.get("SIEM_INDEXER_STUB_PORT", "5888"))
TI_PORT = int(os.environ.get("SIEM_TI_STUB_PORT", "5889"))
VT_PORT = int(os.environ.get("SIEM_VT_STUB_PORT", "5890"))
EPSS_PORT = int(os.environ.get("SIEM_EPSS_STUB_PORT", "5891"))
#: A port nothing listens on (an indexer that is down).
CLOSED_PORT = 1
RUST = f"http://127.0.0.1:{RS_PORT}"

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"SiA{SFX}", f"SiB{SFX}"
ADMIN, ANALYST, PORTAL = f"si_admin{SFX}", f"si_analyst{SFX}", f"si_portal{SFX}"
USERS = (ADMIN, ANALYST, PORTAL)
OUR_CONNECTORS = ("Wazuh-Indexer", "VirusTotal")
ES_USER, ES_PASS = "parity-indexer", f"es-{SFX}"
results = []
#: Every stand-in (`main` fills it): each call takes and compares what all of them received.
RECS = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


# --- HTTP stand-ins -------------------------------------------------------------------
class Recorder:
    """Records every request — method, path, every header as sent, body — and answers
    with `answer(rec, method, path, headers, body)`."""

    def __init__(self, answer, port, name):
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
                headers = {k.lower(): v for k, v in self.headers.items()}
                with recorder.lock:
                    recorder.captured.append({"method": self.command, "path": self.path, "headers": headers, "body": body})
                answer = recorder.answer(recorder, self.command, self.path, headers, body)
                if answer is None:
                    # Hang up without a response.
                    self.close_connection = True
                    return
                status, ctype, payload, extra = answer
                self.send_response(status)
                if ctype:
                    self.send_header("Content-Type", ctype)
                for k, v in extra.items():
                    self.send_header(k, v)
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


#: The time window's start (`utcnow() - delta`, then `isoformat() + "Z"`).
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{6})?Z")
#: elasticsearch-py's `User-Agent` names the interpreter's patch version.
ES_AGENT = re.compile(r"\(Python 3\.11(?:\.\d+)?\)")
#: httpx's multipart boundary is `os.urandom(16).hex()`.
BOUNDARY = re.compile(rb"[0-9a-f]{32}")


def normalised(captures):
    out, stamps = [], []
    for c in captures:
        body = c["body"]
        ctype = c["headers"].get("content-type", "")
        if "multipart/form-data" in ctype:
            body = BOUNDARY.sub(b"<boundary>", body)
        text_body = body.decode("utf-8", "replace")
        stamps += STAMP.findall(text_body)
        headers = {}
        for k, v in sorted(c["headers"].items()):
            if k == "user-agent":
                v = ES_AGENT.sub("(Python 3.11)", v)
            if k == "content-type" and "multipart/form-data" in v:
                v = BOUNDARY.sub(b"<boundary>", v.encode()).decode()
            headers[k] = v
        out.append({"method": c["method"], "path": c["path"], "headers": headers, "body": STAMP.sub("<now-delta>", text_body)})
    return out, stamps


def jbody(obj):
    return json.dumps(obj).encode()


def ok(obj, ctype="application/json", extra=None):
    return 200, ctype, jbody(obj), extra or {}


# --- The Wazuh indexer ------------------------------------------------------------------
TEXT_FIELD_ERROR = {
    "error": {
        "root_cause": [
            {
                "type": "illegal_argument_exception",
                "reason": "Text fields are not optimised for operations that require per-document field data like aggregations "
                "and sorting, so these operations are disabled by default. Please use a keyword field instead.",
            },
        ],
        "type": "search_phase_execution_exception",
        "reason": "all shards failed",
        "phase": "query",
        "grouped": True,
    },
    "status": 400,
}
SORT_ERROR = {
    "error": {
        "root_cause": [{"type": "query_shard_exception", "reason": "No mapping found for [bad_time] in order to sort on"}],
        "type": "search_phase_execution_exception",
        "reason": "all shards failed",
    },
    "status": 400,
}
OTHER_400 = {
    "error": {"root_cause": [{"type": "parsing_exception", "reason": "boom is not a field"}], "type": "parsing_exception"},
    "status": 400,
}
NOT_FOUND_INDEX = {
    "error": {
        "root_cause": [
            {"type": "index_not_found_exception", "reason": "no such index [missing-*]", "resource.type": "index_or_alias"},
        ],
        "type": "index_not_found_exception",
    },
    "status": 404,
}
HITS = [
    {
        "_index": "wazuh-a-2026.10.16",
        "_id": "doc-1",
        "_source": {
            "agent_name": "dc01",
            "rule_level": 12,
            "data": {"win": {"system": {"eventID": "4625"}}},
            "data_win_eventdata_image": "C:\\Windows\\cmd.exe",
            "tags": ["a", "é"],
            "score": 1.5,
            "_id": "shadowed",
            "timestamp": "2026-10-16T10:00:00.000Z",
        },
    },
    {"_index": "wazuh-a-2026.10.15", "_id": "doc-2", "_source": {"agent_name": "web01", "nested": {"k": {"deep": None}}}},
    {"_index": "wazuh-a-2026.10.15", "_id": "doc-3", "_source": {"agent_name": "db01", "rule_level": "3"}},
]


def es_answer(rec, method, raw_path, headers, body):
    mode = rec.mode
    path, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    expected = "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode("latin-1")).decode()
    if headers.get("authorization") != expected:
        return 401, "application/json", jbody({"error": "unauthorized", "status": 401}), {}
    if mode.get("down"):
        return 503, "application/json", jbody({"error": "unavailable", "status": 503}), {}

    def answer(obj, index=""):
        if index.startswith("gz-") and "gzip" in headers.get("accept-encoding", ""):
            return 200, "application/json; charset=UTF-8", gzip.compress(jbody(obj)), {"Content-Encoding": "gzip"}
        return ok(obj)

    if path == "/_search/scroll":
        if method == "DELETE":
            return ok({"succeeded": True, "num_freed": 1})
        sid = json.loads(body)["scroll_id"]
        if sid == "scroll-gone":
            return 404, "application/json", jbody({"error": {"type": "search_context_missing_exception"}, "status": 404}), {}
        if sid == "scroll-last":
            return ok({"_scroll_id": "scroll-last-2", "hits": {"total": {"value": 3}, "hits": []}})
        return ok({"_scroll_id": "scroll-next", "hits": {"total": {"value": 3}, "hits": HITS[2:]}})
    if method == "GET" and "/_doc/" in path:
        index, _, doc_id = path[1:].partition("/_doc/")
        index, doc_id = unquote(index), unquote(doc_id)
        if index == "ai-alerts" and doc_id in AI_DOCS:
            return ok({"_index": index, "_id": doc_id, "_version": 3, "found": True, "_source": AI_DOCS[doc_id]})
        for hit in HITS:
            if hit["_index"] == index and hit["_id"] == doc_id:
                return ok({**hit, "_version": 1, "found": True})
        if doc_id == "odd":
            return ok({"_index": index, "_id": doc_id, "_source": ["not", "a", "mapping"]})
        return 404, "application/json", jbody({"_index": index, "_id": doc_id, "found": False}), {}
    if method == "POST" and path.endswith("/_field_caps"):
        index = unquote(path[1:].rsplit("/", 1)[0])
        if index.startswith("odd-"):
            return ok({"indices": [index], "fields": ["not", "a", "dict"]})
        return answer(
            {
                "indices": ["wazuh-a-1", "wazuh-a-2"],
                "fields": {
                    "_id": {"_id": {"type": "_id", "metadata_field": True, "searchable": True, "aggregatable": True}},
                    "agent_name": {"keyword": {"type": "keyword", "metadata_field": False}},
                    "full_log": {"text": {"type": "text"}},
                    "full_log.keyword": {"keyword": {"type": "keyword"}},
                    "data": {"object": {"type": "object"}},
                    "data.win": {"object": {"type": "object"}},
                    "data.win.system.eventID": {"keyword": {"type": "keyword"}, "long": {"type": "long"}},
                    "rule_level": {"long": {"type": "long"}},
                    "Zeta": {"keyword": {"type": "keyword"}},
                    "nested_thing": {"nested": {"type": "nested"}},
                    "émoji": {"keyword": {"type": "keyword"}},
                },
            },
            index,
        )
    if method == "POST" and path.endswith("/_search"):
        index = unquote(path[1:].rsplit("/", 1)[0])
        if index.startswith("missing-"):
            return 404, "application/json", jbody(NOT_FOUND_INDEX), {}
        doc = json.loads(body or b"{}")
        aggs = doc.get("aggs") or {}
        odd = index.startswith("odd-")
        if "scroll" in params:
            n = int(params.get("size", "10"))
            page = HITS[:n]
            total = mode.get("total", 3)
            return answer({"_scroll_id": "scroll-first", "hits": {"total": {"value": total, "relation": "eq"}, "hits": page}}, index)
        if "over_time" in aggs:
            if odd:
                return ok({"hits": {"total": 1}})
            buckets = [
                {"key_as_string": "2026-10-16T00:00:00.000Z", "key": 1781568000000, "doc_count": 5},
                {"key_as_string": "2026-10-16T00:30:00.000Z", "key": 1781569800000, "doc_count": 0},
            ]
            return answer({"hits": {"total": {"value": 5}}, "aggregations": {"over_time": {"buckets": buckets}}}, index)
        if "top_values" in aggs:
            field = aggs["top_values"]["terms"]["field"]
            if field.startswith("text") or field == "msg":
                return 400, "application/json", jbody(TEXT_FIELD_ERROR), {}
            if field == "boom":
                return 400, "application/json", jbody(OTHER_400), {}
            if odd:
                return ok({"aggregations": {"top_values": {"buckets": {"a": {"key": "x"}}}}})
            buckets = [
                {"key": "dc01", "doc_count": 9},
                {"key": 3, "doc_count": 4},
                {"key": 2.5, "doc_count": 2},
                {"key": 1e16, "doc_count": 1},
                {"key": True, "doc_count": 1},
            ]
            return answer({"aggregations": {"top_values": {"buckets": buckets[: aggs["top_values"]["terms"]["size"]]}}}, index)
        if doc.get("size"):
            if "sort" in doc and any("bad_time" in s for s in doc["sort"]):
                return 400, "application/json", jbody(SORT_ERROR), {}
            if index.startswith("lists-"):
                return ok({"hits": {"hits": [{"_source": [0, 1, 2]}]}})
            if odd:
                return ok({"hits": {"hits": [{"_id": "x"}, {"_source": "abc"}]}})
            return answer({"hits": {"total": {"value": 3}, "hits": HITS[: doc["size"]]}}, index)
        if odd:
            return ok({"hits": {"total": [1, 2]}})
        return answer({"hits": {"total": {"value": 10000, "relation": "gte"}, "hits": []}}, index)
    return 404, "text/plain", b"no stub for " + raw_path.encode(), {}


# --- SOCFortress, VirusTotal, api.first.org --------------------------------------------------
#: Indexer documents the AI routes read (`ai-alerts/_doc/<id>`).
AI_DOCS = {
    "wazuh": {
        "timestamp": "2026-10-16T10:00:00.000Z",
        "syslog_type": "wazuh",
        "agent_name": "dc01",
        "rule_level": 12,
        "message": "dropped",
        "full_log": "dropped",
        "gl2_message_id": "dropped",
        "data_win_eventdata_image": "C:\\Windows\\cmd.exe",
        "nested": {"a": [1, 2.5, None, True]},
        "unicode": "é ✓",
    },
    "fortinet": {"timestamp": 1760600000, "syslog_type": "fortinet", "process_id": 4242, "srcip": "10.0.0.1"},
    "other": {"timestamp": "t", "syslog_type": "syslog"},
    "integration": {"timestamp": "t", "integration": "office365"},
}
LICENSE_KEY = f"lic-{SFX}"
VT_KEY = f"vt-key-{SFX}"
FEATURES = [{"name": "THREAT INTEL", "intValue": 1}, {"name": "SOCFORTRESS AI", "intValue": 1}, {"name": "OTHER", "intValue": 0}]


def ti_answer(rec, method, raw_path, headers, body):
    """SOCFortress: the licence server, threat intel, the AI endpoints, the cyber-news MCP."""
    path, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    if path == "/verify-license":
        mode = rec.mode.get("license", "ok")
        answers = {
            "ok": (200, {"data": {"license": {"key": LICENSE_KEY, "dataObjects": FEATURES}}, "success": True, "message": "ok"}),
            "disabled": (200, {"data": {"license": {"dataObjects": [{"name": "THREAT INTEL", "intValue": 0}]}}}),
            "bare": (200, {"license": {"dataObjects": FEATURES}}),
            "dataobjects": (200, {"dataObjects": FEATURES, "success": False}),
            "error500": (500, {"message": "boom", "detail": "x"}),
            "detail500": (500, {"message": "", "detail": "only detail"}),
            "list500": (500, [1]),
            "list": (200, [1]),
            "string": (200, "metadata"),
            "number": (200, 5),
            "nolicense": (200, {"data": {"message": "Internal"}}),
            "missing_intvalue": (200, {"data": {"license": {"dataObjects": [{"name": "THREAT INTEL"}]}}}),
            "dataobjects_strings": (200, {"data": {"license": {"dataObjects": ["a"]}}}),
            "name_int": (200, {"data": {"license": {"dataObjects": [{"name": 5, "intValue": 1}, {"name": "", "intValue": 1}]}}}),
            "license_list": (200, {"data": {"license": [1]}}),
            "unicode": (200, {"data": {"license": {"dataObjects": FEATURES, "note": "é ✓"}}}),
        }
        if mode == "text500":
            return 500, "text/plain", b"not json", {}
        if mode == "empty500":
            return 500, "text/plain", b"", {}
        if mode == "204":
            return 204, None, b"", {}
        if mode == "hangup":
            return None
        status, obj = answers[mode]
        return status, "application/json", jbody(obj), {}
    if path == "/search":
        value = params.get("value", "")
        if value.startswith("notjson"):
            return 200, "text/plain", b"nope", {}
        if value.startswith("list"):
            return ok([1])
        if value.startswith("nodata"):
            return ok({"success": True})
        if value.startswith("nulldata"):
            return ok({"data": None, "success": True})
        if value.startswith("badscore"):
            return ok({"data": {"score": "inf"}, "success": True, "message": "m"})
        if value.startswith("nanscore"):
            return 200, "application/json", b'{"data": {"score": NaN, "comment": 5}, "success": true}', {}
        if value.startswith("invalid"):
            return ok({"data": {"comment": 5, "score": [1]}, "success": "maybe", "message": 7})
        if value.startswith("hangup"):
            return None
        return (
            503 if value.startswith("down") else 200,
            "application/json",
            jbody(
                {
                    "data": {
                        "comment": "c",
                        "ioc_source": "x",
                        "report_url": "u",
                        "score": "100.0" if not value.startswith("num") else 7.9,
                        "timestamp": "t",
                        "type": "Domain-Name",
                        "value": value,
                        "virustotal_url": "vt",
                        "extra": 1,
                    },
                    "success": True,
                    "message": "found",
                },
            ),
            {},
        )
    if path == "/query/cyber_news":
        mode = rec.mode.get("mcp", "ok")
        if mode == "error":
            return 500, "text/plain", b"mcp boom", {}
        if mode == "notjson":
            return 200, "text/plain", b"<html>", {}
        if mode == "list":
            return ok([1])
        if mode == "invalid":
            return ok({"message": 5, "structured_result": {"thinking_process": 1}})
        if mode == "redirect":
            return 302, "text/plain", b"", {"Location": "https://elsewhere.example/x"}
        if mode == "hangup":
            return None
        return ok(
            {
                "message": "ok",
                "success": True,
                "result": {"a": [1, 2.5, None]},
                "structured_result": {"response": "r", "thinking_process": None},
                "execution_time": 3,
                "extra": "x",
            },
        )
    if path in ("/analyze-alert", "/wazuh-exclusion-rule"):
        mode = rec.mode.get("ai", "ok")
        if mode == "forbidden":
            return ok({"message": "Forbidden"})
        if mode == "429":
            return 429, "text/plain", b"slow down", {}
        if mode == "500":
            return 500, "text/plain", b"upstream boom", {}
        if mode == "notjson":
            return 200, "text/plain", b"nope", {}
        if mode == "list":
            return ok([1])
        if mode == "invalid":
            return ok({"message": "ok", "confidence_score": 2, "wazuh_exclusion_rule": 5})
        if mode == "hangup":
            return None
        if path == "/analyze-alert":
            score = {"bounds": 1.5, "negative": "-0.5"}.get(mode, 0.8)
            return ok(
                {
                    "message": "ok",
                    "success": True,
                    "analysis": f"looks bad {SFX}",
                    "base64_decoded": None,
                    "confidence_score": score,
                    "threat_indicators": "ti",
                    "risk_evaluation": "high",
                    "extra": 1,
                },
            )
        return ok(
            {"message": "ok", "success": True, "wazuh_exclusion_rule": f"<rule>{SFX}</rule>", "wazuh_exclusion_rule_justification": None},
        )
    return 404, "text/plain", b"no stub for " + raw_path.encode(), {}


def vt_answer(rec, method, raw_path, headers, body):
    """VirusTotal: lookups, file submission, analyses, file reports."""
    path = unquote(raw_path.partition("?")[0])
    if headers.get("x-apikey") != VT_KEY:
        return 401, "application/json", jbody({"error": {"code": "WrongCredentialsError"}}), {}
    if method == "POST" and path == "/api/v3/files":
        mode = rec.mode.get("submit", "ok")
        errors = {
            "400zip": (400, {"error": {"message": "Invalid zip file uploaded"}}),
            "400large": (400, {"error": {"message": "File too large for you"}}),
            "400missing": (400, {"error": {"message": "Field MISSING"}}),
            "400other": (400, {"error": {"message": "nope"}}),
            "400noerror": (400, {"other": 1}),
            "400list": (400, [1]),
            "400nonstr": (400, {"error": {"message": 5}}),
            "400listmsg": (400, {"error": {"message": ["Invalid zip file"]}}),
            "429": (429, {"error": {"message": "quota"}}),
            "413": (413, {"error": {"message": "big"}}),
            "401": (401, {"error": {"message": "denied"}}),
            "nodata": (200, {"x": 1}),
        }
        if mode == "notjson":
            return 200, "text/plain", b"nope", {}
        if mode == "400text":
            return 400, "text/plain", b"plain text error", {}
        if mode == "hangup":
            return None
        if mode in errors:
            status, obj = errors[mode]
            return status, "application/json", jbody(obj), {}
        return ok({"data": {"type": "analysis", "id": f"an-{SFX}", "links": {"self": "s"}}})
    if path.startswith("/api/v3/analyses/"):
        analysis_id = path[len("/api/v3/analyses/") :]
        if analysis_id == "missing":
            return 404, "application/json", jbody({"error": {"code": "NotFoundError"}}), {}
        if analysis_id == "notjson":
            return 200, "text/plain", b"nope", {}
        if analysis_id == "nodata":
            return ok({"x": 1})
        plan = rec.mode.get("analysis_plan")
        state = plan.pop(0) if plan else "completed"
        return ok(
            {
                "data": {
                    "type": "analysis",
                    "id": analysis_id,
                    "attributes": {
                        "date": 1760600000,
                        "status": state,
                        "stats": {"malicious": 2, "harmless": "1", "custom": 9},
                        "results": {},
                    },
                    "links": {"self": "s"},
                },
                "meta": {"file_info": {"sha256": "x"}},
            },
        )
    if path.startswith("/api/v3/files/"):
        file_id = path[len("/api/v3/files/") :]
        if file_id == "missing":
            return 404, "application/json", jbody({"error": {"code": "NotFoundError"}}), {}
        if file_id == "err":
            return 503, "text/plain", b"try later", {}
        if file_id == "invalid":
            return ok({"data": {"type": "file", "id": file_id, "attributes": {"size": "big"}}})
        return ok(
            {
                "data": {
                    "type": "file",
                    "id": file_id,
                    "attributes": {
                        "md5": "m",
                        "size": "12",
                        "last_analysis_stats": {"harmless": 1},
                        "last_analysis_results": {"E": {"method": "m", "engine_name": "E", "category": "c", "result": None, "x": 1}},
                        "names": ["a"],
                    },
                    "links": {"self": "s"},
                },
            },
        )
    for kind in ("/api/v3/ip_addresses/", "/api/v3/domains/"):
        if path.startswith(kind):
            ioc = path[len(kind) :]
            if ioc.startswith("missing"):
                return 404, "application/json", jbody({"error": {"code": "NotFoundError"}}), {}
            if ioc.startswith("notjson"):
                return 200, "text/plain", b"nope", {}
            if ioc.startswith("invalid"):
                return ok({"data": {"id": 1}})
            return ok(
                {
                    "data": {
                        "id": ioc,
                        "type": "ip_address",
                        "links": {"self": f"https://vt/{ioc}"},
                        "attributes": {
                            "total_votes": {"harmless": 1, "malicious": 2, "extra": 3},
                            "last_analysis_results": {"E": {"method": "m", "engine_name": "E", "category": "c", "result": None, "x": 1}},
                            "last_analysis_stats": {"harmless": 1, "malicious": "2"},
                            "tags": ["t"],
                            "asn": "15169",
                            "whatever": {"x": 1},
                        },
                        "extra_data": 1,
                    },
                    "meta": 1,
                },
            )
    return 404, "text/plain", b"no stub for " + raw_path.encode(), {}


def epss_answer(rec, method, raw_path, headers, body):
    """api.first.org: one CVE's EPSS score."""
    params = dict(parse_qsl(raw_path.partition("?")[2], keep_blank_values=True))
    cve = params.get("cve", "")
    base = {"status": "OK", "status-code": 200, "version": "1.0", "access": "public", "total": 1, "offset": 0, "limit": 100}
    row = {"cve": cve, "epss": "0.00043", "percentile": "0.0815", "date": "2026-10-16", "extra": 1}
    if cve == "CVE-BAD":
        return ok({**base, "status-code": 404, "data": []})
    if cve == "CVE-NOTJSON":
        return 200, "text/html", b"<html>", {}
    if cve == "CVE-LIST":
        return ok([1])
    if cve == "CVE-NUM":
        return ok({**base, "data": [{**row, "epss": 0.1, "date": None}]})
    if cve == "CVE-STR":
        return ok({**base, "data": ["x"]})
    if cve == "CVE-NULL":
        return ok({**base, "data": None})
    if cve == "CVE-NODATA":
        return ok({"status-code": 200.0})
    if cve == "CVE-TRUE":
        return ok({"status-code": True, "data": []})
    if cve == "CVE-HANGUP":
        return None
    return ok({**base, "data": [row, {**row, "cve": "CVE-OTHER"}]})


# --- the database ---------------------------------------------------------------------------
async def sql(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        await s.commit()
        return r


async def rows(query, **params):
    async with AsyncSession(async_engine) as s:
        r = await s.execute(text(query), params)
        return [dict(m) for m in r.mappings().all()]


async def set_connector(name, url, username=None, password=None, api_key=None, verified=1):
    await sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    if url is not None:
        await sql(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
            "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
            "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
            "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES "
            "(:n, '4.8.0', :u, '2026-01-02 03:04:05', :user, :pw, :key, 'Parity connector', 'everything', 1, :v, 0, 0, 1, 0, 0, "
            "NULL, 1)",
            n=name,
            u=url,
            user=username,
            pw=password,
            key=api_key,
            v=verified,
        )
    connector_cache.invalidate_all()


def in_list(values):
    return "(" + ",".join(repr(str(v)) if not isinstance(v, int) else str(v) for v in values) + ")"


IDS = {}
#: key -> (customer, name, index pattern, time field, enabled)
SOURCES = {
    "a": ("A", "Wazuh EDR", "wazuh-a-*", "timestamp", 1),
    "a_sort": ("A", "Unsortable", "badsort-*", "bad_time", 1),
    "a_off": ("A", "Disabled", "off-*", "timestamp", 0),
    "a_gz": ("A", "Compressed", "gz-*", "timestamp", 1),
    "a_missing": ("A", "Missing", "missing-*", "timestamp", 1),
    "a_odd": ("A", "Odd", "odd-*", "timestamp_utc", 1),
    "b": ("B", "Wazuh EDR", "wazuh-b-*", "timestamp", 1),
    "a_free": ("A", "Free", "free-*", "timestamp", 1),
    "a_list": ("A", "Lists", "lists-*", "timestamp", 1),
}
#: Custom templates stored by hand: key -> (customer, title, panels, default_query)
ODD_PANELS = [
    {"id": "p1", "title": "Gauge", "type": "gauge", "w": 4, "h": 100, "lucene": "*"},
    {"id": "p2", "title": "No field", "type": "pie", "w": 4, "h": 100, "lucene": ""},
    {"id": "p3", "title": "No fields", "type": "table", "w": 4, "h": 100, "lucene": "*", "fields": []},
    {"id": "p1", "title": "Again", "type": "stat", "w": 4, "h": 100, "lucene": "agent_name:dc01"},
    {"id": "p4", "title": "Keyword text", "type": "bar_h", "w": 4, "h": 100, "lucene": "*", "field": "text.keyword", "size": 2},
    {"id": "p5", "title": "Boom", "type": "pie", "w": 4, "h": 100, "lucene": "*", "field": "boom"},
    {"id": "p6", "title": "Fallback", "type": "pie", "w": 4, "h": 100, "lucene": "*", "field": "msg", "size": 3},
    {
        "id": "p7",
        "title": "Rows",
        "type": "table",
        "w": 12,
        "h": 300,
        "lucene": "*",
        "fields": ["agent_name", "data.win.system.eventID", "tags", "nested", "absent", "agent_name"],
        "size": 3,
    },
    {"id": "p8", "title": "Size zero", "type": "pie", "w": 4, "h": 100, "lucene": "*", "field": "agent_name", "size": 0},
]
CUSTOM = {
    "shared": (None, "Shared Overview", [{"id": "total", "title": "Total", "type": "stat", "w": 3, "h": 100, "lucene": "*"}], "*"),
    "scoped_a": (
        "A",
        "A only",
        [{"id": "hist", "title": "Over time", "type": "histogram", "w": 12, "h": 200, "lucene": "*"}],
        "agent_name:dc01",
    ),
    "scoped_b": ("B", "B only", [{"id": "total", "title": "Total", "type": "stat", "w": 3, "h": 100, "lucene": "*"}], "*"),
    "odd": (None, "Odd panels", ODD_PANELS, "  "),
    "int_id": (
        None,
        "Int id",
        [
            {"id": 7, "title": "Seven", "type": "stat", "w": 3, "h": 100, "lucene": "*"},
            {"id": "7", "title": "Seven as text", "type": "stat", "w": 3, "h": 100, "lucene": "*"},
            {"id": 7.0, "title": "Seven again", "type": "pie", "w": 3, "h": 100, "lucene": "*"},
            {"id": True, "title": "True", "type": "stat", "w": 3, "h": 100, "lucene": "*"},
            {"id": None, "title": "None", "type": "stat", "w": 3, "h": 100, "lucene": "*"},
            {"id": 2.5, "title": "A float", "type": "stat", "w": 3, "h": 100, "lucene": "*"},
        ],
        "*",
    ),
    "spare": (None, "Spare", [{"id": "total", "title": "Total", "type": "stat", "w": 3, "h": 100, "lucene": "*"}], "*"),
    "odd_fields": (
        None,
        "Odd fields",
        [
            {"id": f"f{i}", "title": f"Fields {i}", "type": "table", "w": 6, "h": 100, "lucene": "*", "fields": fields, "size": 1}
            for i, fields in enumerate(
                [[0, 1, True], [-1], ["x", "agent_name"], [2.0], [None], [{"a": 1}], [["l"]], "agent_name", {"k": "v"}],
            )
        ],
        "*",
    ),
    "unhashable": (None, "Unhashable", [{"id": ["x"], "title": "L", "type": "stat", "w": 3, "h": 100, "lucene": "*"}], "*"),
    "no_type": (None, "No type", [{"id": "x", "title": "X", "w": 3, "h": 100, "lucene": "*"}], "*"),
    "dups": (
        None,
        "Dup ids",
        [
            {"id": "p", "title": "P", "type": "stat", "w": 3, "h": 100, "lucene": "*"},
            {"id": "p", "title": "P2", "type": "pie", "w": 3, "h": 100, "lucene": "*", "field": "agent_name"},
        ],
        "",
    ),
}
#: Enabled dashboards: key -> (customer, source, library card, template id)
ENABLED = {
    "a_edr": ("A", "a", "wazuh_edr", "EDR_OVERVIEW"),
    "a_dns": ("A", "a", "wazuh_edr", "EDR_DNS_QUERIES"),
    "a_card": ("A", "a", "wazuh_edr", "_card"),
    "a_gz": ("A", "a_gz", "office365_cloudintegration", "O365_SUMMARY"),
    "a_off": ("A", "a_off", "wazuh_edr", "EDR_OVERVIEW"),
    "a_sort": ("A", "a_sort", "custom", "odd"),
    "a_odd": ("A", "a", "custom", "odd"),
    "a_odd_index": ("A", "a_odd", "custom", "odd"),
    "a_scoped": ("A", "a", "custom", "scoped_a"),
    "a_shared": ("A", "a", "custom", "shared"),
    "a_int": ("A", "a", "custom", "int_id"),
    "a_notype": ("A", "a", "custom", "no_type"),
    "a_gone": ("A", "a", "custom", "gone"),
    "a_dups": ("A", "a", "custom", "dups"),
    "a_missing_file": ("A", "a", "wazuh_edr", "NOPE"),
    "a_missing_idx": ("A", "a_missing", "wazuh_edr", "EDR_OVERVIEW"),
    "a_list": ("A", "a_list", "custom", "odd_fields"),
    "a_fields": ("A", "a", "custom", "odd_fields"),
    "a_fields_odd": ("A", "a_odd", "custom", "odd_fields"),
    "a_unhashable": ("A", "a", "custom", "unhashable"),
    "a_outside": ("A", "a", "wazuh_edr", "../../../stack_provisioning/influxdb/templates/SOCFORTRESS_INFLUXDB_CPU_CHECK"),
    "b_edr": ("B", "b", "wazuh_edr", "EDR_OVERVIEW"),
    "b_shared": ("B", "b", "custom", "shared"),
}
CODE = {"A": CUST_A, "B": CUST_B}
KEY = {}


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
    # Explicit ids, seven digits and above every existing one, in disjoint ranges.
    top = 0
    for table in ("event_sources", "enabled_dashboards", "custom_dashboard_templates"):
        top = max(top, (await rows(f"SELECT COALESCE(MAX(id), 0) AS n FROM {table}"))[0]["n"])
    base = max(top + 100, 1_000_000) + 10_000
    IDS["base"] = base
    for i, (key, (cust, name, pattern, field, enabled)) in enumerate(SOURCES.items()):
        IDS[f"src_{key}"] = base + i
        await sql(
            "INSERT INTO event_sources (id, customer_code, name, index_pattern, event_type, time_field, enabled, displayed_columns, "
            "created_at, updated_at) VALUES (:i, :c, :n, :p, 'EDR', :f, :e, :d, '2026-10-01 10:00:00', '2026-10-01 10:00:00')",
            i=IDS[f"src_{key}"],
            c=CODE[cust],
            n=name,
            p=pattern,
            f=field,
            e=enabled,
            d=json.dumps([{"label": "Agent", "key": "agent_name", "width": 120, "extra": 1}]) if key == "a" else None,
        )
    for i, (key, (cust, title, panels, query)) in enumerate(CUSTOM.items()):
        IDS[f"tpl_{key}"] = base + 1000 + i
        KEY[key] = f"{key}_{SFX}"
        await sql(
            "INSERT INTO custom_dashboard_templates (id, template_key, customer_code, title, description, vendor, product, event_type, "
            "tags, color, icon, default_query, panels, created_by, created_at, updated_at) VALUES (:i, :k, :c, :t, 'd', 'Custom', '', "
            "'Custom', :tags, :color, 'dashboard', :q, :p, 'seed', '2026-10-01 10:00:00', '2026-10-01 10:00:00')",
            i=IDS[f"tpl_{key}"],
            k=KEY[key],
            c=CODE[cust] if cust else None,
            t=f"{title} {SFX}",
            tags=json.dumps(["parity"]),
            color="#ff0000" if key == "scoped_a" else "",
            q=query,
            p=json.dumps(panels),
        )
    KEY["gone"] = f"gone_{SFX}"
    for i, (key, (cust, src, card, tpl)) in enumerate(ENABLED.items()):
        IDS[f"en_{key}"] = base + 2000 + i
        await sql(
            "INSERT INTO enabled_dashboards (id, customer_code, event_source_id, library_card, template_id, display_name, created_at) "
            "VALUES (:i, :c, :s, :l, :t, :d, :at)",
            i=IDS[f"en_{key}"],
            c=CODE[cust],
            s=IDS[f"src_{src}"],
            l=card,
            t=KEY.get(tpl, tpl) if card == "custom" else tpl,
            d=f"{key} {SFX}",
            at=f"2026-10-0{1 + i % 3} 10:00:00",
        )
    # Rows the routes create land here, the same id for both backends (see `reset_counters`).
    IDS["next"] = base + 5000


async def reset_counters():
    """Delete what a call created and put the counters back, so the next backend's rows get
    the same ids."""
    nxt = IDS["next"]
    await sql("DELETE FROM enabled_dashboards WHERE id >= :n AND id < :m", n=nxt, m=nxt + 5000)
    await sql("DELETE FROM custom_dashboard_templates WHERE id >= :n AND id < :m", n=nxt, m=nxt + 5000)
    await sql("DELETE FROM event_sources WHERE id >= :n AND id < :m", n=nxt, m=nxt + 5000)
    for table in ("enabled_dashboards", "custom_dashboard_templates", "event_sources"):
        await sql(f"ALTER TABLE {table} AUTO_INCREMENT = {nxt}")


async def reset_seed():
    """The seeded rows back as seeded (a write may have changed or deleted them)."""
    await reset_counters()
    base = IDS["base"]
    await sql("DELETE FROM enabled_dashboards WHERE id >= :b AND id < :n", b=base, n=IDS["next"])
    await sql("DELETE FROM custom_dashboard_templates WHERE id >= :b AND id < :n", b=base, n=IDS["next"])
    await sql("DELETE FROM event_sources WHERE id >= :b AND id < :n", b=base, n=IDS["next"])
    for c in (CUST_A, CUST_B):
        await sql("DELETE FROM enabled_dashboards WHERE customer_code = :c", c=c)
        await sql("DELETE FROM custom_dashboard_templates WHERE customer_code = :c", c=c)
        await sql("DELETE FROM event_sources WHERE customer_code = :c", c=c)
    await sql("DELETE FROM custom_dashboard_templates WHERE template_key LIKE :k", k=f"%{SFX}%")
    customers = await rows("SELECT customer_code FROM customers WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    if len(customers) == 2:
        await reseed_rows()


async def reseed_rows():
    saved = dict(IDS)
    await seed_rows_only()
    IDS.update({k: v for k, v in saved.items() if k in ("base", "next")})


async def seed_rows_only():
    base = IDS["base"]
    for i, (key, (cust, name, pattern, field, enabled)) in enumerate(SOURCES.items()):
        await sql(
            "INSERT INTO event_sources (id, customer_code, name, index_pattern, event_type, time_field, enabled, displayed_columns, "
            "created_at, updated_at) VALUES (:i, :c, :n, :p, 'EDR', :f, :e, :d, '2026-10-01 10:00:00', '2026-10-01 10:00:00')",
            i=base + i,
            c=CODE[cust],
            n=name,
            p=pattern,
            f=field,
            e=enabled,
            d=json.dumps([{"label": "Agent", "key": "agent_name", "width": 120, "extra": 1}]) if key == "a" else None,
        )
    for i, (key, (cust, title, panels, query)) in enumerate(CUSTOM.items()):
        await sql(
            "INSERT INTO custom_dashboard_templates (id, template_key, customer_code, title, description, vendor, product, event_type, "
            "tags, color, icon, default_query, panels, created_by, created_at, updated_at) VALUES (:i, :k, :c, :t, 'd', 'Custom', '', "
            "'Custom', :tags, :color, 'dashboard', :q, :p, 'seed', '2026-10-01 10:00:00', '2026-10-01 10:00:00')",
            i=base + 1000 + i,
            k=KEY[key],
            c=CODE[cust] if cust else None,
            t=f"{title} {SFX}",
            tags=json.dumps(["parity"]),
            color="#ff0000" if key == "scoped_a" else "",
            q=query,
            p=json.dumps(panels),
        )
    for i, (key, (cust, src, card, tpl)) in enumerate(ENABLED.items()):
        await sql(
            "INSERT INTO enabled_dashboards (id, customer_code, event_source_id, library_card, template_id, display_name, created_at) "
            "VALUES (:i, :c, :s, :l, :t, :d, :at)",
            i=base + 2000 + i,
            c=CODE[cust],
            s=IDS[f"src_{src}"],
            l=card,
            t=KEY.get(tpl, tpl) if card == "custom" else tpl,
            d=f"{key} {SFX}",
            at=f"2026-10-0{1 + i % 3} 10:00:00",
        )


async def siem_rows():
    """The SIEM rows of both tenants and the shared templates this suite owns."""
    sources = await rows(
        "SELECT id, customer_code, name, index_pattern, event_type, time_field, enabled, CAST(displayed_columns AS CHAR) AS columns, "
        "JSON_TYPE(displayed_columns) AS columns_type, created_at, updated_at FROM event_sources WHERE customer_code IN (:a, :b) ORDER BY id",
        a=CUST_A,
        b=CUST_B,
    )
    enabled = await rows(
        "SELECT id, customer_code, event_source_id, library_card, template_id, display_name, created_at FROM enabled_dashboards "
        "WHERE customer_code IN (:a, :b) ORDER BY id",
        a=CUST_A,
        b=CUST_B,
    )
    templates = await rows(
        "SELECT id, template_key, customer_code, title, description, vendor, product, event_type, CAST(tags AS CHAR) AS tags, color, "
        "icon, default_query, CAST(panels AS CHAR) AS panels, created_by, created_at, updated_at FROM custom_dashboard_templates "
        "WHERE customer_code IN (:a, :b) OR template_key LIKE :k OR id >= :n ORDER BY id",
        a=CUST_A,
        b=CUST_B,
        k=f"%{SFX}%",
        n=IDS["next"],
    )
    return {"event_sources": sources, "enabled": enabled, "templates": templates}


async def cleanup():
    for c in (CUST_A, CUST_B):
        await sql("DELETE FROM enabled_dashboards WHERE customer_code = :c", c=c)
    await sql("DELETE FROM enabled_dashboards WHERE id >= :n AND id < :m", n=IDS.get("next", 0), m=IDS.get("next", 0) + 5000)
    await sql("DELETE FROM custom_dashboard_templates WHERE template_key LIKE :k", k=f"%{SFX}%")
    for c in (CUST_A, CUST_B):
        await sql("DELETE FROM custom_dashboard_templates WHERE customer_code = :c", c=c)
        await sql("DELETE FROM event_sources WHERE customer_code = :c", c=c)
    if "next" in IDS:
        await sql("DELETE FROM custom_dashboard_templates WHERE id >= :n AND id < :m", n=IDS["next"], m=IDS["next"] + 5000)
    await sql("DELETE FROM license_cache WHERE license_key LIKE :k", k=f"%{SFX}%")
    await sql("DELETE FROM license WHERE license_key LIKE :k", k=f"%{SFX}%")
    for row in TI.get("saved_licenses", []):
        await sql(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) VALUES (:id, :license_key, "
            ":customer_name, :customer_email, :company_name)",
            **row,
        )
    alerts = [TI[k] for k in ("alA", "alB") if k in TI]
    if alerts:
        await sql("DELETE FROM incident_management_comment WHERE alert_id IN " + in_list(alerts))
    await sql("DELETE FROM incident_management_comment WHERE comment LIKE :c", c=f"%{SFX}%")
    await sql("DELETE FROM incident_management_alert WHERE alert_name LIKE :n", n=f"%{SFX}%")
    await sql("DELETE FROM agents WHERE agent_id LIKE :a", a=f"ti{SFX}%")
    for name in OUR_CONNECTORS:
        await sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    await sql("DELETE FROM log_entries WHERE route LIKE '/api/siem/%' OR route LIKE '/api/threat_intel/%'")
    await sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username IN " + in_list(USERS) + ")")
    await sql("DELETE FROM `user` WHERE username IN " + in_list(USERS))
    await sql("DELETE FROM customers WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    connector_cache.invalidate_all()


# --- threat intel ------------------------------------------------------------------------
TI = {}
#: Agents the Velociraptor recommendation reads: suffix -> os.
TI_AGENTS = {"w": "Microsoft Windows 11 Pro", "l": "Ubuntu 22.04.4 LTS", "m": "macOS 14.5", "x": "SunOS 5.11", "e": ""}


async def insert_license():
    await sql(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) VALUES (:k, 'Parity', 'p@parity.test', 'Parity Co')",
        k=LICENSE_KEY,
    )


async def seed_ti():
    # `get_license` reads the first row: ours is the only one while the suite runs.
    TI["saved_licenses"] = await rows("SELECT id, license_key, customer_name, customer_email, company_name FROM license ORDER BY id")
    await sql("DELETE FROM license")
    await insert_license()
    top = (await rows("SELECT COALESCE(MAX(id), 0) AS n FROM incident_management_alert"))[0]["n"]
    for i, (key, cust) in enumerate((("alA", CUST_A), ("alB", CUST_B))):
        TI[key] = top + 1000 + i
        await sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
            "source, escalated, severity) VALUES (:i, :n, 'd', 'OPEN', '2026-10-01 10:00:00', :c, 'wazuh', 0, 'High')",
            i=TI[key],
            n=f"TI {key} {SFX}",
            c=cust,
        )
    TI["unknown_alert"] = top + 1500
    for suffix, os_name in TI_AGENTS.items():
        await sql(
            "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, wazuh_agent_version, "
            "wazuh_agent_status, customer_code, quarantined) VALUES (:a, '10.0.0.1', :os, :h, '', 0, '2026-10-01 10:00:00', 'v4.8.0', "
            "'active', :c, 0)",
            a=f"ti{SFX}{suffix}",
            os=os_name,
            h=f"ti-{SFX}-{suffix}",
            c=CUST_A,
        )
    TI["cache_next"] = (await rows("SELECT COALESCE(MAX(id), 0) + 1000 AS n FROM license_cache"))[0]["n"]


def ti_state(cache=(), licensed=True):
    """A reset: the licence row (or none), the feature cache as given — `(feature, enabled,
    fresh)` — and no comment on the suite's alerts."""

    async def reset():
        await sql("DELETE FROM license_cache WHERE license_key = :k", k=LICENSE_KEY)
        await sql(f"ALTER TABLE license_cache AUTO_INCREMENT = {TI['cache_next']}")
        await sql("DELETE FROM license WHERE license_key = :k", k=LICENSE_KEY)
        if licensed:
            await insert_license()
        for feature, enabled, fresh in cache:
            await sql(
                "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, expires_at, license_data) VALUES "
                "(:k, :f, :e, UTC_TIMESTAMP() - INTERVAL 2 HOUR, UTC_TIMESTAMP() + INTERVAL :h HOUR, '{}')",
                k=LICENSE_KEY,
                f=feature,
                e=enabled,
                h=1 if fresh else -1,
            )
        await sql("DELETE FROM incident_management_comment WHERE alert_id IN " + in_list([TI["alA"], TI["alB"]]))

    return reset


async def ti_rows():
    """The feature cache of the suite's licence and the comments on its alerts."""
    cache = await rows(
        "SELECT id, license_key, feature_name, is_enabled, cached_at, expires_at, license_data FROM license_cache "
        "WHERE license_key = :k ORDER BY id",
        k=LICENSE_KEY,
    )
    comments = await rows(
        "SELECT alert_id, comment, user_name, created_at FROM incident_management_comment WHERE alert_id IN "
        + in_list([TI["alA"], TI["alB"]])
        + " ORDER BY id",
    )
    licenses = await rows("SELECT license_key, customer_name FROM license ORDER BY id")
    return {"cache": cache, "comments": comments, "licenses": licenses}


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import siem
    from app.routers import threat_intel

    api = APIRouter(prefix="/api")
    api.include_router(siem.router)
    api.include_router(threat_intel.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


#: The public hosts the Python services call, and the stand-ins they reach here.
REWRITES = {
    "https://intel.socfortress.co": f"http://127.0.0.1:{TI_PORT}",
    "https://ai.socfortress.co": f"http://127.0.0.1:{TI_PORT}",
    "https://mcp.socfortress.co": f"http://127.0.0.1:{TI_PORT}",
    "https://license.socfortress.co": f"http://127.0.0.1:{TI_PORT}",
    "https://www.virustotal.com": f"http://127.0.0.1:{VT_PORT}",
    "https://api.first.org": f"http://127.0.0.1:{EPSS_PORT}",
}


def rewrite(url):
    text_url = str(url)
    for public, local in REWRITES.items():
        if text_url.startswith(public):
            return local + text_url[len(public) :]
    return url


def patch_python_clients():
    original_build = httpx.AsyncClient.build_request

    def build_request(self, method, url, *args, **kwargs):
        return original_build(self, method, rewrite(url), *args, **kwargs)

    httpx.AsyncClient.build_request = build_request
    original_request = requests.Session.request

    def session_request(self, method, url, *args, **kwargs):
        return original_request(self, method, rewrite(url), *args, **kwargs)

    requests.Session.request = session_request


ENV = {
    "COPILOT_API_KEY": os.environ["COPILOT_API_KEY"],
    "COPILOT_EPSS_URL": f"http://127.0.0.1:{EPSS_PORT}/data/v1/epss",
    "COPILOT_SOCFORTRESS_INTEL_URL": f"http://127.0.0.1:{TI_PORT}/search",
    "COPILOT_SOCFORTRESS_AI_URL": f"http://127.0.0.1:{TI_PORT}",
    "COPILOT_SOCFORTRESS_MCP_URL": f"http://127.0.0.1:{TI_PORT}/query",
    "COPILOT_LICENSE_URL": f"http://127.0.0.1:{TI_PORT}/",
    "COPILOT_VIRUSTOTAL_URL": f"http://127.0.0.1:{VT_PORT}/api/v3",
}


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
        "COPILOT_STARTUP_TASKS": "false",  # the startup seeds no row of the shared database
        "COPILOT_PORT": str(RS_PORT),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        **ENV,
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"{RUST}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


#: Stamps the two backends write at their own instant.
CLOCK_KEYS = {"created_at", "updated_at", "cached_at", "expires_at"}


def same_instant(a, b, slack=10):
    try:
        ta = datetime.datetime.fromisoformat(str(a).replace("Z", "+00:00").replace(" ", "T"))
        tb = datetime.datetime.fromisoformat(str(b).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return False
    return abs((ta - tb).total_seconds()) <= slack


def mask_clocks(p, q):
    """`created_at`/`updated_at` written by each backend at its own instant: masked where the
    two are within seconds of each other (anything else stays a difference)."""
    if isinstance(p, dict) and isinstance(q, dict):
        out_p, out_q = {}, {}
        for k in p:
            if k in CLOCK_KEYS and k in q and p[k] != q[k] and same_instant(p[k], q[k]):
                out_p[k] = out_q[k] = "<now>"
            elif k in q:
                out_p[k], out_q[k] = mask_clocks(p[k], q[k])
            else:
                out_p[k] = p[k]
        for k in q:
            if k not in out_q:
                out_q[k] = q[k]
        return {k: out_p[k] for k in p}, {k: out_q[k] for k in q}
    if isinstance(p, list) and isinstance(q, list) and len(p) == len(q):
        pairs = [mask_clocks(a, b) for a, b in zip(p, q)]
        return [a for a, _ in pairs], [b for _, b in pairs]
    return p, q


# --- The checks ---------------------------------------------------------------------------
D, S, EV = "/api/siem/dashboards", "/api/siem/event_sources", "/api/siem/events"

#: A valid panel set: one of each type, a duplicate title (ids `top_agents`, `top_agents_2`)
#: and a terms aggregation on a text field (the `.keyword` retry).
PANELS = [
    {"title": "Total events", "type": "stat"},
    {"title": "Over time", "type": "histogram", "w": 12, "h": 200},
    {"title": "Top agents", "type": "pie", "field": "agent_name", "size": 4},
    {"title": "Top agents", "type": "bar_h", "field": "msg", "lucene": "  "},
    {"title": "Rows", "type": "table", "fields": [" agent_name ", "", "rule_level", "data.win.system.eventID"], "size": 2},
]


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


async def main():  # noqa: C901 - one scenario after the other
    es = Recorder(es_answer, INDEXER_PORT, "es")
    ti = Recorder(ti_answer, TI_PORT, "ti")
    vt = Recorder(vt_answer, VT_PORT, "vt")
    epss = Recorder(epss_answer, EPSS_PORT, "epss")
    RECS[:] = [es, ti, vt, epss]
    await seed()
    await seed_ti()
    await set_connector("Wazuh-Indexer", es.url, ES_USER, ES_PASS)
    await set_connector("VirusTotal", f"{vt.url}/api/v3", api_key=VT_KEY)
    patch_python_clients()
    rust = start_rust()
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    A, B = CUST_A, CUST_B
    src = {k[4:]: v for k, v in IDS.items() if k.startswith("src_")}
    en = {k[3:]: v for k, v in IDS.items() if k.startswith("en_")}

    async def send(client, method, path, tok, body, raw, headers, files=None, data=None):
        kw = {"headers": {**({"Authorization": f"Bearer {tok}"} if tok else {}), **(headers or {})}}
        if raw is not None:
            kw["content"] = raw
            kw["headers"].setdefault("Content-Type", "application/json")
        elif files is not None or data is not None:
            kw["files"] = files or {}
            kw["data"] = data or {}
        elif body is not None:
            kw["json"] = body
        return await client.request(method, path, **kw)

    async def both(name, method, path, tok=None, body=None, raw=None, headers=None, reset=None, snapshot=None, files=None, data=None):
        """The responses, every request each backend sent upstream and (`snapshot`) the
        rows it left; `reset` runs before each backend's call."""
        got = {}
        for tag, client in (("py", py), ("rs", rs)):
            if reset is not None:
                await reset()
            for rec in RECS:
                rec.take()
            r = await send(client, method, path, tok, body, raw, headers, files, data)
            upstream, stamps = {}, []
            for rec in RECS:
                upstream[rec.name], found = normalised(rec.take())
                stamps += found
            got[tag] = {
                "status": r.status_code,
                "type": r.headers.get("content-type"),
                "body": body_of(r),
                "upstream": upstream,
                "stamps": stamps,
                "rows": await snapshot() if snapshot else None,
            }
        p, q = got["py"], got["rs"]
        p["body"], q["body"] = mask_clocks(p["body"], q["body"])
        same = p["status"] == q["status"] and p["type"] == q["type"] and json.dumps(p["body"]) == json.dumps(q["body"])
        check(
            f"{name} [{p['status']}]",
            same,
            f"python {p['status']} {p['type']} {json.dumps(p['body'])[:2500]}\n        rust   {q['status']} {q['type']} {json.dumps(q['body'])[:2500]}",
        )
        for upstream in p["upstream"]:
            a, b = p["upstream"][upstream], q["upstream"][upstream]
            if not (a or b):
                continue
            first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), None)
            check(
                f"{name}: requests to {upstream} ({len(a)})",
                a == b,
                f"python {[x['method'] + ' ' + x['path'] for x in a]}\n        rust   {[x['method'] + ' ' + x['path'] for x in b]}"
                + (
                    f"\n        first difference #{first}:\n        python {json.dumps(a[first])}\n        rust   {json.dumps(b[first])}"
                    if first is not None
                    else ""
                ),
            )
        if p["stamps"] or q["stamps"]:
            check(
                f"{name}: the time windows start within seconds of each other",
                len(p["stamps"]) == len(q["stamps"]) and all(same_instant(x, y) for x, y in zip(p["stamps"], q["stamps"])),
                f"python {p['stamps']}\n        rust   {q['stamps']}",
            )
        if snapshot:
            pr, qr = mask_clocks(p["rows"], q["rows"])
            check(
                f"{name}: rows",
                json.dumps(pr, default=str) == json.dumps(qr, default=str),
                f"python {json.dumps(pr, default=str)[:3000]}\n        rust   {json.dumps(qr, default=str)[:3000]}",
            )
        return p, q

    async def differ(name, method, path, tok, body, py_status, rs_status, rs_detail, reset=reset_seed, snapshot=siem_rows):
        """A difference by design (§4): Python answers `py_status`, Rust `rs_status` with
        `rs_detail`, sends nothing upstream and leaves the rows as they were."""
        await reset()
        r = await send(py, method, path, tok, body, None, None)
        check(f"python: {name} [{r.status_code}]", r.status_code == py_status, f"{r.status_code} {r.text[:600]}")
        await reset()
        # Taken after the reset Rust starts from: a reset stamps rows with UTC_TIMESTAMP(), so a
        # snapshot from before Python's request differs whenever the two resets fall in two seconds.
        before = await snapshot()
        for rec in RECS:
            rec.take()
        q = await send(rs, method, path, tok, body, None, None)
        detail = body_of(q).get("message") if isinstance(body_of(q), dict) else None
        check(
            f"rust: {name} [{q.status_code}]",
            q.status_code == rs_status and detail == rs_detail,
            f"{q.status_code} {q.text[:600]}",
        )
        after = await snapshot()
        check(
            f"rust: {name}: no rows changed",
            json.dumps(before, default=str) == json.dumps(after, default=str),
            f"before {json.dumps(before, default=str)[:1500]}\n        after  {json.dumps(after, default=str)[:1500]}",
        )
        check(f"rust: {name}: no upstream request", all(rec.take() == [] for rec in RECS))
        await reset()

    try:
        # ==================================================================
        print("\n=== A. built-in templates ===")
        T = D + "/templates"
        await both("categories: no token", "GET", T)
        await both("categories: garbage token", "GET", T, "garbage")
        await both("categories: 2fa temp token", "GET", T, token(ADMIN, [], type="2fa_pending"))
        await both("categories: portal user", "GET", T, t_portal)
        await both("categories: analyst", "GET", T, t_analyst)
        for category in ("wazuh_edr", "office365_cloudintegration", "aws_cloudintegration"):
            await both(f"category {category}", "GET", f"{T}/{category}", t_portal)
        for label, segment in (
            ("unknown", "nope"),
            ("reserved name", "custom"),
            ("dot", "%2E"),
            ("dot-dot", "%2E%2E"),
            ("NUL byte", "wazuh_edr%00"),
            ("a template file", "wazuh_edr%2FEDR_OVERVIEW.json"),
            ("case", "WAZUH_EDR"),
            ("trailing space", "wazuh_edr%20"),
        ):
            if "%2F" in segment:
                continue  # an encoded `/` is Python's (copilot_wazuh::decoded_slash_to_legacy)
            await both(f"category: {label}", "GET", f"{T}/{segment}", t_analyst)

        # ==================================================================
        print("\n=== B. enabled dashboards ===")
        E = D + "/enabled"
        await both("enabled: no token", "GET", E)
        await both("enabled: portal user", "GET", E, t_portal)
        await both("enabled: analyst", "GET", E, t_analyst)
        await both("enabled: analyst asks for B", "GET", E + f"?customer_codes={B}", t_analyst)
        await both("enabled: analyst asks for A and B", "GET", E + f"?customer_codes={B}&customer_codes={A}", t_analyst)
        await both("enabled: admin, both tenants", "GET", E + f"?customer_codes={A}&customer_codes={B}", t_admin)
        await both("enabled: admin, an empty code", "GET", E + "?customer_codes=", t_admin)
        await both("enabled: admin, bracketed codes", "GET", E + f"?customer_codes[]={B}", t_admin)
        await both("enabled: admin, everything", "GET", E, t_admin)
        await both("enabled of A: portal user", "GET", f"{E}/{A}", t_portal)
        await both("enabled of A: analyst", "GET", f"{E}/{A}", t_analyst)
        await both("enabled of B: analyst", "GET", f"{E}/{B}", t_analyst)
        await both("enabled of B: admin", "GET", f"{E}/{B}", t_admin)
        await both("enabled of an unknown customer: admin", "GET", f"{E}/NOPE{SFX}", t_admin)
        await both("enabled of an unknown customer: analyst", "GET", f"{E}/NOPE{SFX}", t_analyst)

        EN = D + "/enable"
        ok_enable = {
            "customer_code": A,
            "event_source_id": src["a"],
            "library_card": "wazuh_edr",
            "template_id": "EDR_PROCESS_ACTIVITY",
            "display_name": f"Proc {SFX}",
        }
        await both("enable: no token, no body", "POST", EN)
        await both("enable: malformed JSON, no token", "POST", EN, raw=b"{")
        await both("enable: portal user", "POST", EN, t_portal, ok_enable)
        await both("enable: no body", "POST", EN, t_analyst)
        await both("enable: empty object", "POST", EN, t_analyst, {})
        await both("enable: a list", "POST", EN, t_analyst, raw=b"[1]")
        await both(
            "enable: wrong types and lengths",
            "POST",
            EN,
            t_analyst,
            {"customer_code": "x" * 51, "event_source_id": "one", "library_card": 3, "template_id": None, "display_name": "y" * 256},
        )
        await both("enable: an id as a float", "POST", EN, t_admin, {**ok_enable, "event_source_id": 1.5})
        await both("enable: unknown customer", "POST", EN, t_admin, {**ok_enable, "customer_code": f"NOPE{SFX}"})
        await both("enable: unknown category", "POST", EN, t_admin, {**ok_enable, "library_card": "nope"})
        await both(
            "enable: the reserved custom card, unknown key",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "library_card": "custom", "template_id": "nope"},
        )
        await both("enable: unknown template", "POST", EN, t_admin, {**ok_enable, "template_id": "NOPE"})
        await both(
            "enable: the card file as a template",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "template_id": "_card"},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "enable: a template path outside the category",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "template_id": "../wazuh_edr/EDR_OVERVIEW"},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "enable: a template path outside the directory",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "template_id": "../../dashboard_templates/wazuh_edr/EDR_OVERVIEW"},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "enable: a category path",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "library_card": "wazuh_edr/../wazuh_edr"},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both("enable: an absolute category", "POST", EN, t_admin, {**ok_enable, "library_card": "/etc"})
        outside = "../../../stack_provisioning/influxdb/templates/SOCFORTRESS_INFLUXDB_DISK_CHECK"
        await differ(
            "enable: a JSON file of the backend outside the templates",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "template_id": outside},
            200,
            404,
            f"Dashboard template '{outside}' not found in category 'wazuh_edr'",
        )
        await both(
            "enable: an empty category",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "library_card": "", "template_id": "wazuh_edr/EDR_OVERVIEW"},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both("enable: unknown event source", "POST", EN, t_admin, {**ok_enable, "event_source_id": 1})
        await both("enable: duplicate", "POST", EN, t_admin, {**ok_enable, "template_id": "EDR_OVERVIEW"})
        await both(
            "enable: B's scoped template for A",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "library_card": "custom", "template_id": KEY["scoped_b"]},
        )
        await both("enable: built-in", "POST", EN, t_analyst, ok_enable, reset=reset_counters, snapshot=siem_rows)
        await both(
            "enable: portal-less display name",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "display_name": ""},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "enable: a shared template for B",
            "POST",
            EN,
            t_admin,
            {**ok_enable, "customer_code": B, "event_source_id": src["b"], "library_card": "custom", "template_id": KEY["int_id"]},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "enable: A's scoped template for A",
            "POST",
            EN,
            t_analyst,
            {**ok_enable, "library_card": "custom", "template_id": KEY["scoped_a"], "event_source_id": src["a_gz"]},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await differ(
            "enable: an analyst enables for another tenant",
            "POST",
            EN,
            t_analyst,
            {**ok_enable, "customer_code": B, "event_source_id": src["b"]},
            200,
            403,
            f"Access denied to customer {B}",
        )
        await differ(
            "enable: an analyst enables on another tenant's event source",
            "POST",
            EN,
            t_analyst,
            {**ok_enable, "event_source_id": src["b"]},
            200,
            403,
            f"Access denied to customer {B}",
        )

        DIS = D + "/disable"
        await both("disable: no token", "DELETE", f"{DIS}/{en['a_dns']}")
        await both("disable: portal user", "DELETE", f"{DIS}/{en['a_dns']}", t_portal)
        await both("disable: not an int", "DELETE", f"{DIS}/x", t_analyst)
        await both("disable: unknown", "DELETE", f"{DIS}/1", t_analyst)
        await both("disable: another tenant's", "DELETE", f"{DIS}/{en['b_edr']}", t_analyst)
        await both("disable", "DELETE", f"{DIS}/{en['a_dns']}", t_analyst, reset=reset_seed, snapshot=siem_rows)
        await reset_seed()

        # ==================================================================
        print("\n=== C. custom templates ===")
        C = D + "/custom"
        await both("custom list: no token", "GET", C)
        await both("custom list: portal user", "GET", C, t_portal)
        await both("custom list: analyst (A's and the shared ones)", "GET", C, t_analyst)
        await both("custom list: analyst, A", "GET", C + f"?customer_code={A}", t_analyst)
        await both("custom list: analyst, B", "GET", C + f"?customer_code={B}", t_analyst)
        await both("custom list: analyst, empty code", "GET", C + "?customer_code=", t_analyst)
        await both("custom list: admin, B", "GET", C + f"?customer_code={B}", t_admin)
        await both("custom list: admin, unknown customer", "GET", C + f"?customer_code=NOPE{SFX}", t_admin)
        await both("custom list: admin", "GET", C, t_admin)

        new = {"title": f"New Shared {SFX}", "panels": PANELS, "default_query": "  ", "tags": ["x", "y"], "extra": "ignored"}
        await both("custom create: malformed JSON, no token", "POST", C, raw=b"{")
        await both("custom create: portal user", "POST", C, t_portal, new)
        await both("custom create: empty object", "POST", C, t_analyst, {})
        await both("custom create: a string", "POST", C, t_analyst, raw=b'"x"')
        await both("custom create: empty title and panels", "POST", C, t_analyst, {"title": "", "panels": []})
        await both("custom create: panels not a list", "POST", C, t_analyst, {"title": "t", "panels": {"a": 1}})
        await both(
            "custom create: bad panels",
            "POST",
            C,
            t_analyst,
            {
                "title": "t",
                "panels": [
                    "x",
                    {"title": "g", "type": "gauge"},
                    {"title": "p", "type": "pie"},
                    {"title": "b", "type": "bar_h", "field": "   "},
                    {"title": "t", "type": "table"},
                    {"title": "t2", "type": "table", "fields": [" ", ""]},
                    {"title": "", "type": "stat", "w": 0, "h": 50, "size": 0, "id": "i" * 65},
                    {"title": "n", "type": "stat", "w": 13, "h": 1201, "size": 101, "lucene": None},
                    {"type": "stat", "fields": "a", "field": 3},
                    {"title": "f", "type": "table", "fields": [1, None, "ok"], "size": "7"},
                ],
            },
        )
        await both(
            "custom create: bad fields",
            "POST",
            C,
            t_analyst,
            {
                "title": "t" * 256,
                "description": None,
                "vendor": 1,
                "event_type": "e" * 51,
                "tags": "x",
                "color": "#0123456789",
                "icon": ["i"],
                "default_query": None,
                "template_key": "k" * 256,
                "customer_code": "c" * 51,
                "panels": PANELS,
            },
        )
        await both("custom create: tags of the wrong type", "POST", C, t_analyst, {"title": "t", "tags": [1, None], "panels": PANELS})
        await both("custom create: unknown customer", "POST", C, t_admin, {**new, "customer_code": f"NOPE{SFX}"})
        await both("custom create: shared", "POST", C, t_analyst, new, reset=reset_counters, snapshot=siem_rows)
        await both(
            "custom create: scoped to A",
            "POST",
            C,
            t_analyst,
            {**new, "customer_code": A},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "custom create: the key taken (suffixed)",
            "POST",
            C,
            t_admin,
            {**new, "title": f"Shared Overview {SFX}", "template_key": KEY["shared"]},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "custom create: a key slugified, punctuation and Unicode",
            "POST",
            C,
            t_admin,
            {**new, "template_key": f"  Ünïcode — Key!! {SFX}  ", "panels": [{"title": "Ça marche ✓", "type": "stat", "size": None}]},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "custom create: a title that slugifies to nothing",
            "POST",
            C,
            t_admin,
            {**new, "title": "!!!", "panels": [{"title": "???", "type": "stat"}], "customer_code": B},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await sql("DELETE FROM custom_dashboard_templates WHERE template_key LIKE 'custom_dashboard%' AND customer_code = :b", b=B)
        await differ(
            "custom create: an analyst files a template under another tenant",
            "POST",
            C,
            t_analyst,
            {**new, "customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )

        IMP = C + "/import"
        definition = {"template_key": f"imported_{SFX}", "title": f"Imported {SFX}", "panels": PANELS, "color": "#123456"}
        await both("custom import: no token", "POST", IMP, body={"definition": definition})
        await both("custom import: empty object", "POST", IMP, t_analyst, {})
        await both("custom import: definition not an object", "POST", IMP, t_analyst, {"definition": "x", "overwrite": "maybe"})
        await both(
            "custom import: a bad definition",
            "POST",
            IMP,
            t_analyst,
            {"definition": {"title": "", "panels": [{"type": "pie", "title": "p"}]}},
        )
        await both("custom import: new", "POST", IMP, t_analyst, {"definition": definition}, reset=reset_counters, snapshot=siem_rows)
        await both(
            "custom import: new, scoped to A",
            "POST",
            IMP,
            t_analyst,
            {"definition": definition, "customer_code": A},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "custom import: the key from the title",
            "POST",
            IMP,
            t_analyst,
            {"definition": {**definition, "template_key": None, "title": f"From The Title {SFX}"}},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both("custom import: a collision", "POST", IMP, t_analyst, {"definition": {**definition, "template_key": KEY["shared"]}})
        await both(
            "custom import: overwrite a shared one",
            "POST",
            IMP,
            t_analyst,
            {"definition": {**definition, "template_key": KEY["int_id"]}, "overwrite": True},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both(
            "custom import: overwrite, narrowing one enabled for B",
            "POST",
            IMP,
            t_admin,
            {"definition": {**definition, "template_key": KEY["shared"]}, "overwrite": True, "customer_code": A},
        )
        await both("custom import: unknown customer", "POST", IMP, t_admin, {"definition": definition, "customer_code": f"NOPE{SFX}"})
        await differ(
            "custom import: an analyst imports under another tenant",
            "POST",
            IMP,
            t_analyst,
            {"definition": definition, "customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )
        await differ(
            "custom import: an analyst overwrites another tenant's template",
            "POST",
            IMP,
            t_analyst,
            {"definition": {**definition, "template_key": KEY["scoped_b"]}, "overwrite": True, "customer_code": A},
            200,
            403,
            f"Access denied to customer {B}",
        )
        await reset_seed()

        PRE = C + "/preview"
        preview = {"event_source_id": src["a"], "panels": PANELS, "default_query": "agent_name:dc01", "timerange": "7d"}
        await both("preview: no token", "POST", PRE, body=preview)
        await both("preview: portal user", "POST", PRE, t_portal, preview)
        await both("preview: bad body", "POST", PRE, t_analyst, {"event_source_id": "x", "panels": [], "timerange": 3})
        await both("preview: unknown event source", "POST", PRE, t_analyst, {**preview, "event_source_id": 1})
        await both("preview: another tenant's event source", "POST", PRE, t_analyst, {**preview, "event_source_id": src["b"]})
        await both("preview: a disabled event source", "POST", PRE, t_analyst, {**preview, "event_source_id": src["a_off"]})
        await both("preview", "POST", PRE, t_analyst, preview)
        await both("preview: defaults", "POST", PRE, t_admin, {"event_source_id": src["b"], "panels": PANELS[:1]})
        await both("preview: compressed answers", "POST", PRE, t_analyst, {**preview, "event_source_id": src["a_gz"]})
        await both("preview: odd answers", "POST", PRE, t_analyst, {**preview, "event_source_id": src["a_odd"], "timerange": "1h"})
        await both("preview: missing index", "POST", PRE, t_analyst, {**preview, "event_source_id": src["a_missing"]})
        await both("preview: unsortable time field", "POST", PRE, t_analyst, {**preview, "event_source_id": src["a_sort"]})
        for label, timerange in (
            ("2 weeks", "2w"),
            ("underscores and spaces", " 1_2h"),
            ("no unit", "24"),
            ("no amount", "h"),
            ("not a number", "xd"),
            ("upper case", "24H"),
            ("too far back", "1000000000d"),
            ("C int overflow", "1000000000000h"),
            ("before year one", "999999999d"),
            ("the future", "-1d"),
        ):
            await both(f"preview: timerange {label}", "POST", PRE, t_analyst, {**preview, "panels": PANELS[:2], "timerange": timerange})

        for key in ("shared", "scoped_a", "odd", "int_id", "no_type", "dups"):
            await both(f"custom get: {key}", "GET", f"{C}/{KEY[key]}", t_analyst)
            await both(f"custom export: {key}", "GET", f"{C}/{KEY[key]}/export", t_analyst)
        await both("custom get: no token", "GET", f"{C}/{KEY['shared']}")
        await both("custom get: portal user", "GET", f"{C}/{KEY['shared']}", t_portal)
        await both("custom get: another tenant's", "GET", f"{C}/{KEY['scoped_b']}", t_analyst)
        await both("custom get: another tenant's, admin", "GET", f"{C}/{KEY['scoped_b']}", t_admin)
        await both("custom get: unknown", "GET", f"{C}/nope_{SFX}", t_analyst)
        await both("custom export: another tenant's", "GET", f"{C}/{KEY['scoped_b']}/export", t_analyst)
        await both("custom export: unknown", "GET", f"{C}/nope_{SFX}/export", t_analyst)

        await both("custom update: malformed JSON, no token", "PUT", f"{C}/{KEY['shared']}", raw=b"{")
        await both("custom update: another tenant's, bad body", "PUT", f"{C}/{KEY['scoped_b']}", t_analyst, {"panels": []})
        await both(
            "custom update: bad body",
            "PUT",
            f"{C}/{KEY['shared']}",
            t_analyst,
            {"panels": [], "title": "", "share_globally": "x", "tags": "t"},
        )
        await both("custom update: unknown", "PUT", f"{C}/nope_{SFX}", t_analyst, {"title": "x"})
        await both("custom update: no body", "PUT", f"{C}/{KEY['shared']}", t_analyst)
        await both(
            "custom update: title, tags, color; nulls skipped",
            "PUT",
            f"{C}/{KEY['shared']}",
            t_analyst,
            {"title": f"Renamed {SFX}", "tags": ["n"], "color": "#000", "description": None, "panels": None, "default_query": "  q  "},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both("custom update: panels", "PUT", f"{C}/{KEY['odd']}", t_analyst, {"panels": PANELS}, reset=reset_seed, snapshot=siem_rows)
        await both("custom update: narrowing one enabled for B", "PUT", f"{C}/{KEY['shared']}", t_admin, {"customer_code": A})
        await both("custom update: unknown customer", "PUT", f"{C}/{KEY['shared']}", t_admin, {"customer_code": f"NOPE{SFX}"})
        await both(
            "custom update: scope a shared one",
            "PUT",
            f"{C}/{KEY['int_id']}",
            t_analyst,
            {"customer_code": A},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both(
            "custom update: share globally",
            "PUT",
            f"{C}/{KEY['scoped_a']}",
            t_analyst,
            {"share_globally": True, "customer_code": A},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both(
            "custom update: share_globally false",
            "PUT",
            f"{C}/{KEY['scoped_a']}",
            t_analyst,
            {"share_globally": False},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await differ(
            "custom update: an analyst scopes a shared template to another tenant",
            "PUT",
            f"{C}/{KEY['spare']}",
            t_analyst,
            {"customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )

        await both("custom delete: no token", "DELETE", f"{C}/{KEY['shared']}")
        await both("custom delete: another tenant's", "DELETE", f"{C}/{KEY['scoped_b']}", t_analyst)
        await both("custom delete: unknown", "DELETE", f"{C}/nope_{SFX}", t_analyst)
        await both("custom delete: enabled for A and B", "DELETE", f"{C}/{KEY['shared']}", t_analyst, reset=reset_seed, snapshot=siem_rows)
        await both("custom delete: never enabled", "DELETE", f"{C}/{KEY['scoped_b']}", t_admin, reset=reset_seed, snapshot=siem_rows)
        await reset_seed()

        # ==================================================================
        print("\n=== D. panel data ===")
        PD = D + "/panel-data"
        await both("panel data: malformed JSON, no token", "POST", PD, raw=b"{")
        await both("panel data: no token", "POST", PD, body={"dashboard_id": en["a_edr"]})
        await both("panel data: bad body", "POST", PD, t_portal, {"dashboard_id": "x", "timerange": None})
        await both("panel data: unknown dashboard", "POST", PD, t_portal, {"dashboard_id": 1})
        await both("panel data: another tenant's (portal)", "POST", PD, t_portal, {"dashboard_id": en["b_edr"]})
        await both("panel data: another tenant's (analyst)", "POST", PD, t_analyst, {"dashboard_id": en["b_edr"]})
        await differ(
            "panel data: a JSON file of the backend outside the templates",
            "POST",
            PD,
            t_analyst,
            {"dashboard_id": en["a_outside"]},
            400,
            404,
            "Dashboard template file not found",
        )
        for key in ENABLED:
            if key.startswith("b_") or key == "a_outside":
                continue
            await both(f"panel data: {key}", "POST", PD, t_portal, {"dashboard_id": en[key]})
        await both("panel data: B's, admin", "POST", PD, t_admin, {"dashboard_id": en["b_shared"], "timerange": "30d"})
        for timerange in ("1h", "6h", "3d", "14d", "2w", "abc", "xh", "1000000000000h"):
            await both(f"panel data: timerange {timerange}", "POST", PD, t_analyst, {"dashboard_id": en["a_edr"], "timerange": timerange})
        await sql("UPDATE event_sources SET time_field = 'timestamp_utc' WHERE id = :i", i=src["a"])
        await both("panel data: the text timestamp field", "POST", PD, t_analyst, {"dashboard_id": en["a_odd"]})
        await sql("UPDATE event_sources SET time_field = 'timestamp' WHERE id = :i", i=src["a"])

        # The indexer itself.
        es.mode = {"down": True}
        await both("panel data: the indexer answers 503 (ten retries)", "POST", PD, t_analyst, {"dashboard_id": en["a_dups"]})
        es.mode = {}
        await set_connector("Wazuh-Indexer", f"http://127.0.0.1:{CLOSED_PORT}", ES_USER, ES_PASS)
        await both("panel data: the indexer is down", "POST", PD, t_analyst, {"dashboard_id": en["a_shared"]})
        await both("events: the indexer is down", "GET", f"{EV}/{A}/Wazuh%20EDR", t_analyst)
        await both("fields: the indexer is down", "GET", f"{EV}/{A}/Wazuh%20EDR/fields", t_analyst)
        await both("document: the indexer is down", "GET", f"{EV}/{A}/Wazuh%20EDR/document?index_name=wazuh-a-1&event_id=x", t_analyst)
        await set_connector("Wazuh-Indexer", es.url, ES_USER, "wrong")
        await both("panel data: the indexer refuses the credentials", "POST", PD, t_analyst, {"dashboard_id": en["a_shared"]})
        await both("events: the indexer refuses the credentials", "GET", f"{EV}/{A}/Wazuh%20EDR", t_analyst)
        await set_connector("Wazuh-Indexer", "https://127.1.1.1:9200", ES_USER, ES_PASS)
        await both("panel data: the placeholder URL", "POST", PD, t_analyst, {"dashboard_id": en["a_shared"]})
        await both("events: the placeholder URL", "GET", f"{EV}/{A}/Wazuh%20EDR", t_analyst)
        await set_connector("Wazuh-Indexer", None)
        await both("panel data: no connector", "POST", PD, t_analyst, {"dashboard_id": en["a_shared"]})
        await both("events: no connector", "GET", f"{EV}/{A}/Wazuh%20EDR", t_analyst)
        await both("events: no connector, scrolling", "GET", f"{EV}/{A}/Wazuh%20EDR?scroll_id=s", t_analyst)
        await both("fields: no connector", "GET", f"{EV}/{A}/Wazuh%20EDR/fields", t_analyst)
        await both("document: no connector", "GET", f"{EV}/{A}/Wazuh%20EDR/document?index_name=wazuh-a-1&event_id=x", t_analyst)
        await set_connector("Wazuh-Indexer", es.url, ES_USER, ES_PASS)

        # ==================================================================
        print("\n=== E. event sources ===")
        await both("sources: no token", "GET", f"{S}/{A}")
        await both("sources of A: portal user", "GET", f"{S}/{A}", t_portal)
        await both("sources of A: analyst", "GET", f"{S}/{A}", t_analyst)
        await both("sources of B: analyst", "GET", f"{S}/{B}", t_analyst)
        await both("sources of B: admin", "GET", f"{S}/{B}", t_admin)
        await both("sources of an unknown customer", "GET", f"{S}/NOPE{SFX}", t_admin)
        await both("sources of an unknown customer: analyst", "GET", f"{S}/NOPE{SFX}", t_analyst)
        source = {
            "customer_code": A,
            "name": f"New {SFX}",
            "index_pattern": "new-*",
            "event_type": "Cloud Integration",
            "displayed_columns": [
                {"key": "agent_name", "label": "Agent", "extra": True},
                {"key": "rule.level", "label": "Level", "width": 80},
            ],
        }
        await both("source create: malformed JSON, no token", "POST", S, raw=b"{")
        await both("source create: portal user", "POST", S, t_portal, source)
        await both("source create: empty object", "POST", S, t_analyst, {})
        await both(
            "source create: bad fields",
            "POST",
            S,
            t_analyst,
            {
                "customer_code": "c" * 51,
                "name": None,
                "index_pattern": "i" * 1025,
                "event_type": "XDR",
                "time_field": 3,
                "enabled": "maybe",
                "displayed_columns": [{"key": 1}, "x", {"key": "k", "label": "l", "width": "w"}],
            },
        )
        await both("source create: columns not a list", "POST", S, t_analyst, {**source, "displayed_columns": {"key": "k"}})
        await both("source create: unknown customer", "POST", S, t_admin, {**source, "customer_code": f"NOPE{SFX}"})
        await both("source create: a duplicate name (collation)", "POST", S, t_analyst, {**source, "name": "wazuh edr"})
        await both("source create", "POST", S, t_analyst, source, reset=reset_counters, snapshot=siem_rows)
        await both(
            "source create: defaults, null columns",
            "POST",
            S,
            t_analyst,
            {
                "customer_code": A,
                "name": f"Bare {SFX}",
                "index_pattern": "bare-*",
                "event_type": "EPP",
                "displayed_columns": None,
                "enabled": "off",
            },
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await both(
            "source create: empty columns",
            "POST",
            S,
            t_admin,
            {"customer_code": B, "name": f"Empty {SFX}", "index_pattern": "e-*", "event_type": "Network Security", "displayed_columns": []},
            reset=reset_counters,
            snapshot=siem_rows,
        )
        await differ(
            "source create: an analyst creates one for another tenant",
            "POST",
            S,
            t_analyst,
            {**source, "customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )

        await both("source update: malformed JSON, no token", "PUT", f"{S}/{src['a']}", raw=b"{")
        await both("source update: portal user", "PUT", f"{S}/{src['a']}", t_portal, {"name": "x"})
        await both("source update: bad id and body", "PUT", f"{S}/x", t_analyst, {"event_type": "bad", "enabled": []})
        await both("source update: bad id, no body", "PUT", f"{S}/x", t_analyst)
        await both("source update: unknown", "PUT", f"{S}/1", t_analyst, {"name": "x"})
        await both(
            "source update: partial",
            "PUT",
            f"{S}/{src['a']}",
            t_analyst,
            {"index_pattern": "wazuh-a2-*", "enabled": "yes", "displayed_columns": [{"key": "k", "label": "L"}]},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both(
            "source update: columns to null",
            "PUT",
            f"{S}/{src['a']}",
            t_analyst,
            {"displayed_columns": None},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both("source update: nothing", "PUT", f"{S}/{src['a_free']}", t_analyst, {}, reset=reset_seed, snapshot=siem_rows)
        await both(
            "source update: name to null",
            "PUT",
            f"{S}/{src['a_free']}",
            t_analyst,
            {"name": None},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both(
            "source update: event type to null",
            "PUT",
            f"{S}/{src['a_free']}",
            t_analyst,
            {"event_type": None},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await both(
            "source update: a duplicate name is not checked",
            "PUT",
            f"{S}/{src['a_free']}",
            t_analyst,
            {"name": "Odd"},
            reset=reset_seed,
            snapshot=siem_rows,
        )
        await differ(
            "source update: an analyst rewrites another tenant's",
            "PUT",
            f"{S}/{src['b']}",
            t_analyst,
            {"index_pattern": "*"},
            200,
            403,
            f"Access denied to event source {src['b']}",
        )

        await both("source delete: no token", "DELETE", f"{S}/{src['a_free']}")
        await both("source delete: analyst", "DELETE", f"{S}/{src['a_free']}", t_analyst)
        await both("source delete: not an int", "DELETE", f"{S}/x", t_admin)
        await both("source delete: unknown", "DELETE", f"{S}/1", t_admin)
        await both("source delete: with enabled dashboards", "DELETE", f"{S}/{src['a']}", t_admin, reset=reset_seed, snapshot=siem_rows)
        await both("source delete", "DELETE", f"{S}/{src['a_free']}", t_admin, reset=reset_seed, snapshot=siem_rows)
        await reset_seed()

        # ==================================================================
        print("\n=== F. events ===")
        Q = f"{EV}/{A}/Wazuh%20EDR"
        await both("events: no token", "GET", Q)
        await both("events: another tenant (portal)", "GET", f"{EV}/{B}/Wazuh%20EDR", t_portal)
        await both("events: another tenant (analyst)", "GET", f"{EV}/{B}/Wazuh%20EDR", t_analyst)
        await both("events: bad query", "GET", Q + "?page_size=0&scroll_id=&timerange=", t_portal)
        await both("events: bad page size, another tenant", "GET", f"{EV}/{B}/Wazuh%20EDR?page_size=x", t_portal)
        await both("events: page size too large", "GET", Q + "?page_size=1001", t_portal)
        await both("events: unknown source", "GET", f"{EV}/{A}/Nope", t_portal)
        await both("events: unknown customer (admin)", "GET", f"{EV}/NOPE{SFX}/Wazuh%20EDR", t_admin)
        await both("events: source name case (collation)", "GET", f"{EV}/{A}/wazuh%20edr", t_portal)
        await both("events: a disabled source", "GET", f"{EV}/{A}/Disabled", t_portal)
        await both("events: one page", "GET", Q, t_portal)
        await both("events: a page of two (scroll kept)", "GET", Q + "?page_size=2&timerange=7d", t_analyst)
        await both(
            "events: a Lucene query and an absolute window",
            "GET",
            Q + "?query=agent_name:dc01%20AND%20rule_level:%3E5&time_from=2026-10-01T00:00:00Z&time_to=2026-10-16T00:00:00Z",
            t_analyst,
        )
        await both("events: time_from alone", "GET", Q + "?time_from=2026-10-01T00:00:00Z&timerange=1w", t_analyst)
        await both("events: an empty query", "GET", Q + "?query=", t_analyst)
        es.mode = {"total": 0}
        await both("events: a total under the hits", "GET", Q, t_analyst)
        es.mode = {}
        await both("events: a bad timerange", "GET", Q + "?timerange=24x", t_analyst)
        await both("events: a C int overflow", "GET", Q + "?timerange=1000000000000h", t_analyst)
        await both("events: compressed answers", "GET", f"{EV}/{A}/Compressed?page_size=1", t_analyst)
        await both("events: a missing index", "GET", f"{EV}/{A}/Missing", t_analyst)
        await both("events: odd answers", "GET", f"{EV}/{A}/Odd", t_analyst)
        await both("events: scroll", "GET", Q + "?scroll_id=scroll-first", t_analyst)
        await both("events: scroll, the last page", "GET", Q + "?scroll_id=scroll-last", t_analyst)
        await both("events: scroll, gone", "GET", Q + "?scroll_id=scroll-gone", t_analyst)
        await both("events: scroll on an unknown source", "GET", f"{EV}/{A}/Nope?scroll_id=scroll-first&timerange=bad", t_analyst)
        await both("events: scroll on another tenant", "GET", f"{EV}/{B}/Nope?scroll_id=scroll-first", t_analyst)

        DOC = Q + "/document"
        await both("document: no params", "GET", DOC, t_analyst)
        await both("document: no params, another tenant", "GET", f"{EV}/{B}/Wazuh%20EDR/document", t_analyst)
        await both("document: another tenant", "GET", f"{EV}/{B}/Wazuh%20EDR/document?index_name=wazuh-b-1&event_id=x", t_analyst)
        await both("document: an index outside the pattern", "GET", DOC + "?index_name=other-1&event_id=doc-1", t_analyst)
        await both("document: case matters", "GET", DOC + "?index_name=WAZUH-A-2026.10.16&event_id=doc-1", t_analyst)
        await both("document", "GET", DOC + "?index_name=wazuh-a-2026.10.16&event_id=doc-1", t_portal)
        await both("document: not found", "GET", DOC + "?index_name=wazuh-a-2026.10.16&event_id=doc-9", t_portal)
        await both("document: quoting in the path", "GET", DOC + "?index_name=wazuh-a-x%20y%2Fz&event_id=a%2Fb%20c%3F", t_portal)
        await both("document: an odd source", "GET", DOC + "?index_name=wazuh-a-1&event_id=odd", t_portal)
        await both("document: empty values", "GET", DOC + "?index_name=&event_id=", t_portal)
        await both("document: a disabled source", "GET", f"{EV}/{A}/Disabled/document?index_name=off-1&event_id=x", t_portal)

        await both("fields: no token", "GET", Q + "/fields")
        await both("fields: another tenant", "GET", f"{EV}/{B}/Wazuh%20EDR/fields", t_analyst)
        await both("fields", "GET", Q + "/fields", t_portal)
        await both("fields: compressed", "GET", f"{EV}/{A}/Compressed/fields", t_analyst)
        await both("fields: odd", "GET", f"{EV}/{A}/Odd/fields", t_analyst)
        await both("fields: unknown source", "GET", f"{EV}/{A}/Nope/fields", t_analyst)

        # ==================================================================
        print("\n=== G. threat intel ===")
        TIP = "/api/threat_intel"
        fresh = ti_state()
        enabled = ti_state(cache=[("THREAT INTEL", 1, True), ("SOCFORTRESS AI", 1, True)])

        EP = TIP + "/epss"
        await both("epss: no token", "POST", EP)
        await both("epss: malformed JSON, no token", "POST", EP, raw=b"{")
        await both("epss: portal user", "POST", EP, t_portal, {"cve": "CVE-2024-1"})
        await both("epss: no body", "POST", EP, t_analyst)
        await both("epss: no cve", "POST", EP, t_analyst, {})
        await both("epss: an int cve", "POST", EP, t_analyst, {"cve": 5})
        for cve in (
            "CVE-2024-3400",
            "CVE-BAD",
            "CVE-NOTJSON",
            "CVE-LIST",
            "CVE-NUM",
            "CVE-STR",
            "CVE-NULL",
            "CVE-NODATA",
            "CVE-TRUE",
            "CVE-HANGUP",
            "",
            "CVE 1&x=\u00e9/?#",
        ):
            await both(f"epss: {cve!r}", "POST", EP, t_admin, {"cve": cve})

        SF = TIP + "/socfortress"
        await both("socfortress: no token", "POST", SF)
        await both("socfortress: portal user", "POST", SF, t_portal, {"ioc_value": "x"})
        await both("socfortress: no body", "POST", SF, t_analyst)
        await both("socfortress: no ioc", "POST", SF, t_analyst, {"customer_code": "x"})
        await both("socfortress: an int ioc and customer", "POST", SF, t_analyst, {"ioc_value": 5, "customer_code": 7})
        ioc = {"ioc_value": "example.com"}
        await both("socfortress: no licence", "POST", SF, t_analyst, ioc, reset=ti_state(licensed=False), snapshot=ti_rows)
        await both("socfortress: the licence verified and cached", "POST", SF, t_analyst, ioc, reset=fresh, snapshot=ti_rows)
        await both("socfortress: cached as enabled", "POST", SF, t_analyst, ioc, reset=enabled, snapshot=ti_rows)
        await both(
            "socfortress: cached as disabled",
            "POST",
            SF,
            t_analyst,
            ioc,
            reset=ti_state(cache=[("THREAT INTEL", 0, True)]),
            snapshot=ti_rows,
        )
        await both(
            "socfortress: an expired cache",
            "POST",
            SF,
            t_analyst,
            ioc,
            reset=ti_state(cache=[("THREAT INTEL", 0, False)]),
            snapshot=ti_rows,
        )
        for mode in (
            "disabled",
            "bare",
            "dataobjects",
            "error500",
            "detail500",
            "list500",
            "list",
            "string",
            "number",
            "nolicense",
            "missing_intvalue",
            "dataobjects_strings",
            "name_int",
            "license_list",
            "unicode",
            "text500",
            "empty500",
            "204",
            "hangup",
        ):
            ti.mode = {"license": mode}
            await both(f"socfortress: the licence server answers {mode}", "POST", SF, t_analyst, ioc, reset=fresh, snapshot=ti_rows)
        ti.mode = {}
        for value in (
            f"good-{SFX}.com",
            "notjson-x",
            "list-x",
            "nodata-x",
            "nulldata",
            "badscore",
            "nanscore",
            "invalid",
            "hangup",
            "down",
            "num",
            "a b&c=d/\u00e9?#",
        ):
            await both(f"socfortress: lookup {value!r}", "POST", SF, t_analyst, {"ioc_value": value, "customer_code": None}, reset=enabled)
        await both("socfortress: a customer code", "POST", SF, t_admin, {"ioc_value": "x.com", "customer_code": "C1"}, reset=enabled)

        PN = TIP + "/process_name"
        await both("process name: no token", "POST", PN)
        await both("process name: portal user", "POST", PN, t_portal, {"process_name": "cmd.exe"})
        await both("process name: no body", "POST", PN, t_analyst)
        await both("process name: an int", "POST", PN, t_analyst, {"process_name": 5}, reset=enabled)
        await both("process name: a list", "POST", PN, t_analyst, {"process_name": ["a"]}, reset=enabled)
        await both("process name: null", "POST", PN, t_analyst, {"process_name": None}, reset=enabled)
        for name in ("C:\\Windows\\System32\\cmd.exe", "/usr/bin/bash", "trailing\\", "", "\u00e9 \u2713"):
            await both(f"process name: {name!r}", "POST", PN, t_analyst, {"process_name": name}, reset=enabled)
        pn = {"process_name": "svchost.exe"}
        await both("process name: no licence", "POST", PN, t_analyst, pn, reset=ti_state(licensed=False), snapshot=ti_rows)
        await both(
            "process name: SOCFORTRESS AI cached as disabled",
            "POST",
            PN,
            t_analyst,
            pn,
            reset=ti_state(cache=[("SOCFORTRESS AI", 0, True)]),
            snapshot=ti_rows,
        )
        await both("process name: the licence verified", "POST", PN, t_analyst, pn, reset=fresh, snapshot=ti_rows)
        ti.mode = {"license": "error500"}
        await both("process name: the licence server fails", "POST", PN, t_analyst, pn, reset=fresh, snapshot=ti_rows)
        for mode in ("error", "notjson", "list", "invalid", "redirect", "hangup"):
            ti.mode = {"mcp": mode}
            await both(f"process name: the MCP answers {mode}", "POST", PN, t_analyst, pn, reset=enabled)
        ti.mode = {}

        VTL = TIP + "/virustotal"
        await both("virustotal: no token", "POST", VTL)
        await both("virustotal: portal user", "POST", VTL, t_portal, {"ioc_value": "8.8.8.8"})
        await both("virustotal: no body", "POST", VTL, t_analyst)
        await both("virustotal: an int ioc", "POST", VTL, t_analyst, {"ioc_value": 5})
        for value in (
            "8.8.8.8",
            "example.com",
            "d41d8cd98f00b204e9800998ecf8427e",
            "https://example.com/x",
            "ftp://a b",
            "not an ioc!",
            "8.8.8.8\n",
            "999.1.1.1",
            "missing.example.com",
            "notjson.example.com",
            "invalid.example.com",
        ):
            await both(f"virustotal: {value!r}", "POST", VTL, t_analyst, {"ioc_value": value})
        AN = TIP + "/virustotal/analysis"
        FR = TIP + "/virustotal/file"
        for label, url, key, verified in (
            ("a rejected key", f"{vt.url}/api/v3", "wrong-key", 1),
            ("an unverified connector", f"{vt.url}/api/v3", VT_KEY, 0),
            ("an empty key", f"{vt.url}/api/v3", "", 1),
            ("no key", f"{vt.url}/api/v3", None, 1),
            ("a closed port", f"http://127.0.0.1:{CLOSED_PORT}/api/v3", VT_KEY, 1),
            ("not a URL", "not a url", VT_KEY, 1),
            ("no connector", None, None, 1),
        ):
            await set_connector("VirusTotal", url, api_key=key, verified=verified)
            await both(f"virustotal: {label}", "POST", VTL, t_analyst, {"ioc_value": "8.8.8.8"})
            await both(f"vt analysis: {label}", "GET", f"{AN}/an-x", t_analyst)
            await both(f"vt file report: {label}", "GET", f"{FR}/abc", t_analyst)
        await set_connector("VirusTotal", f"{vt.url}/api/v3", api_key=VT_KEY)

        FS = TIP + "/virustotal/file/submit"
        sample = {"file": ("sample.exe", b"MZ\x90\x00 parity " + SFX.encode(), "application/octet-stream")}
        await both("file submit: no token", "POST", FS, files=sample)
        await both("file submit: portal user", "POST", FS, t_portal, files=sample)
        await both("file submit: no form", "POST", FS, t_analyst)
        await both("file submit: no file", "POST", FS, t_analyst, data={"password": "x"})
        await both("file submit: a text file field", "POST", FS, t_analyst, data={"file": "text"})
        await both("file submit", "POST", FS, t_analyst, files=sample)
        await both("file submit: a password for an exe", "POST", FS, t_analyst, files=sample, data={"password": "pw"})
        await both(
            "file submit: a password for a zip",
            "POST",
            FS,
            t_analyst,
            files={"file": ("a.ZIP", b"PK\x03\x04", "application/octet-stream")},
            data={"password": "pw"},
        )
        await both(
            "file submit: a password, zip MIME",
            "POST",
            FS,
            t_analyst,
            files={"file": ("noext", b"PK\x03\x04", "application/x-zip")},
            data={"password": "pw \u00e9"},
        )
        await both("file submit: an empty password", "POST", FS, t_analyst, files=sample, data={"password": ""})
        await both(
            "file submit: a password file part",
            "POST",
            FS,
            t_analyst,
            files={**sample, "password": ("p.txt", b"pw", "text/plain")},
        )
        await both(
            "file submit: an odd file name",
            "POST",
            FS,
            t_analyst,
            files={"file": ('\u00e9 \u2713 "q"\\x.bin', b"x", "application/octet-stream")},
        )
        await both("file submit: a guessed content type", "POST", FS, t_analyst, files={"file": ("x.unknownext", b"x")})
        await both("file submit: an empty file", "POST", FS, t_analyst, files={"file": ("empty.bin", b"", "text/plain")})
        for mode in (
            "400zip",
            "400large",
            "400missing",
            "400other",
            "400noerror",
            "400list",
            "400nonstr",
            "400listmsg",
            "429",
            "413",
            "401",
            "nodata",
            "notjson",
            "400text",
            "hangup",
        ):
            vt.mode = {"submit": mode}
            await both(f"file submit: VirusTotal answers {mode}", "POST", FS, t_analyst, files=sample)
        vt.mode = {}
        big = {"file": ("big.bin", b"\0" * (32 * 1024 * 1024 + 1), "application/octet-stream")}
        await both("file submit: over 32 MB", "POST", FS, t_analyst, files=big)
        del big

        await both("vt analysis: no token", "GET", f"{AN}/x")
        await both("vt analysis: portal user", "GET", f"{AN}/x", t_portal)
        for analysis_id in (f"an-{SFX}", "missing", "notjson", "nodata", "a%20b%3Fc", "%C3%A9"):
            await both(f"vt analysis {analysis_id}", "GET", f"{AN}/{analysis_id}", t_analyst)

        def vt_plan(*states):
            async def reset():
                vt.mode = {"analysis_plan": list(states)}

            return reset

        await both("vt analysis: queued", "GET", f"{AN}/q", t_analyst, reset=vt_plan("queued"))
        vt.mode = {}

        await both("vt file report: no token", "GET", f"{FR}/x")
        await both("vt file report 'submit': no token", "GET", f"{FR}/submit")
        await both("vt file report 'analyze': portal user", "GET", f"{FR}/analyze", t_portal)
        for file_id in ("abc123", "missing", "err", "invalid", "submit", "analyze", "a%20b"):
            await both(f"vt file report {file_id}", "GET", f"{FR}/{file_id}", t_analyst)

        # §4: an id holding a `\` or an encoded dot segment. httpx sends both as they are; Rust's
        # URL type (`url`, under reqwest) sends the `\` as `/` and resolves the segment.
        async def vt_paths(client, uri):
            vt.take()
            r = await client.get(uri, headers={"Authorization": f"Bearer {t_analyst}"})
            return r.status_code, [c["path"] for c in vt.take()]

        for uri, py_sent, rs_sent, rs_status in (
            (f"{FR}/a%5Cb", "/api/v3/files/a\\b", "/api/v3/files/a/b", 200),
            (f"{AN}/a%5Cb", "/api/v3/analyses/a\\b", "/api/v3/analyses/a/b", 200),
            (f"{FR}/%252E%252E", "/api/v3/files/%2E%2E", "/api/v3/", 404),
        ):
            p, q = await vt_paths(py, uri), await vt_paths(rs, uri)
            check(f"python: {uri} sends {py_sent}", p == (200, [py_sent]), str(p))
            check(f"rust: {uri} sends {rs_sent} (§4)", q == (rs_status, [rs_sent]), str(q))

        FA = TIP + "/virustotal/file/analyze"
        await both("analyze: no token", "POST", FA, files=sample)
        await both("analyze: portal user", "POST", FA, t_portal, files=sample)
        await both("analyze: no file", "POST", FA, t_analyst, data={"max_wait_time": "60"})
        for label, data in (
            ("max_wait_time 29", {"max_wait_time": "29"}),
            ("max_wait_time 601", {"max_wait_time": "601"}),
            ("poll_interval 4", {"poll_interval": "4"}),
            ("poll_interval 61", {"poll_interval": "61"}),
            ("not integers", {"max_wait_time": "x", "poll_interval": "1.5"}),
            ("an empty value", {"max_wait_time": ""}),
            ("padded", {"max_wait_time": " 60 ", "poll_interval": "+5"}),
            ("a password for an exe", {"password": "pw"}),
        ):
            await both(f"analyze: {label}", "POST", FA, t_analyst, files=sample, data=data, reset=vt_plan("completed"))
        await both(
            "analyze: a number as a file part",
            "POST",
            FA,
            t_analyst,
            files={**sample, "max_wait_time": ("m", b"60", "text/plain")},
        )
        await both("analyze: completed at once", "POST", FA, t_analyst, files=sample, reset=vt_plan("completed"))
        await both(
            "analyze: queued, then completed",
            "POST",
            FA,
            t_analyst,
            files=sample,
            data={"poll_interval": "5"},
            reset=vt_plan("queued", "completed"),
        )
        vt.mode = {"submit": "429"}
        await both("analyze: the submission fails", "POST", FA, t_analyst, files=sample)
        vt.mode = {}
        await both(
            "analyze: never completes",
            "POST",
            FA,
            t_analyst,
            files=sample,
            data={"max_wait_time": "30", "poll_interval": "30"},
            reset=vt_plan("queued", "queued"),
        )
        vt.mode = {}

        alA, alB = TI["alA"], TI["alB"]

        def ai(doc, alert=alA, **extra):
            return {"index_name": "ai-alerts", "index_id": doc, "alert_id": alert, **extra}

        for label, path in (("analyze", TIP + "/ai/analyze-alert"), ("exclusion rule", TIP + "/ai/wazuh-exclusion-rule")):
            await both(f"ai {label}: no token", "POST", path)
            await both(f"ai {label}: malformed JSON, no token", "POST", path, raw=b"[")
            await both(f"ai {label}: portal user", "POST", path, t_portal, ai("wazuh"))
            await both(f"ai {label}: no body", "POST", path, t_analyst)
            await both(f"ai {label}: no index", "POST", path, t_analyst, {"alert_id": "x"})
            for doc in ("wazuh", "fortinet", "other", "integration", "nope"):
                await both(f"ai {label}: {doc}", "POST", path, t_analyst, ai(doc), reset=enabled, snapshot=ti_rows)
            await both(f"ai {label}: no alert id", "POST", path, t_admin, ai("wazuh", None), reset=enabled, snapshot=ti_rows)
            await both(
                f"ai {label}: an unknown alert (admin)",
                "POST",
                path,
                t_admin,
                ai("wazuh", TI["unknown_alert"]),
                reset=enabled,
                snapshot=ti_rows,
            )
            await both(f"ai {label}: B's alert (admin)", "POST", path, t_admin, ai("wazuh", alB), reset=enabled, snapshot=ti_rows)
            await both(f"ai {label}: no licence", "POST", path, t_analyst, ai("wazuh"), reset=ti_state(licensed=False), snapshot=ti_rows)
            await both(f"ai {label}: nothing cached", "POST", path, t_analyst, ai("wazuh"), reset=fresh, snapshot=ti_rows)
            for mode in ("forbidden", "429", "500", "notjson", "list", "invalid", "hangup", "bounds", "negative"):
                ti.mode = {"ai": mode}
                await both(
                    f"ai {label}: SOCFortress AI answers {mode}",
                    "POST",
                    path,
                    t_analyst,
                    ai("wazuh"),
                    reset=enabled,
                    snapshot=ti_rows,
                )
            ti.mode = {}
            await differ(
                f"ai {label}: an analyst on another tenant's alert",
                "POST",
                path,
                t_analyst,
                ai("wazuh", alB),
                200,
                403,
                f"Access denied to alert {alB} - insufficient customer permissions",
                reset=enabled,
                snapshot=ti_rows,
            )
            await differ(
                f"ai {label}: an analyst on an unknown alert",
                "POST",
                path,
                t_analyst,
                ai("wazuh", TI["unknown_alert"]),
                404,
                404,
                "Alert not found",
                reset=enabled,
                snapshot=ti_rows,
            )

        AIV = TIP + "/ai/velociraptor-artifact-recommendation"
        await both("ai velociraptor: no token", "POST", AIV)
        await both("ai velociraptor: portal user", "POST", AIV, t_portal, ai("wazuh", agent_id=f"ti{SFX}w"))
        await both("ai velociraptor: no body", "POST", AIV, t_analyst)
        for label, agent in (
            ("no agent", None),
            ("an unknown agent", "nope"),
            ("Windows", f"ti{SFX}w"),
            ("Linux", f"ti{SFX}l"),
            ("macOS", f"ti{SFX}m"),
            ("SunOS", f"ti{SFX}x"),
            ("an empty OS", f"ti{SFX}e"),
        ):
            await both(f"ai velociraptor: {label}", "POST", AIV, t_analyst, ai("wazuh", agent_id=agent), reset=enabled, snapshot=ti_rows)
        await both("ai velociraptor: a missing document", "POST", AIV, t_analyst, ai("nope", agent_id=f"ti{SFX}w"), reset=enabled)
    finally:
        await cleanup()
        for rec in RECS:
            rec.stop()
        rust.terminate()
        rust.wait(timeout=10)
        await py.aclose()
        await rs.aclose()
    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
