"""Parity of the Rust Detections Catalog (`crates/copilot-searches`) with this backend — NOT
collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

Sends the same requests to the real FastAPI router (`app/routers/copilot_searches.py`,
in-process) and to a Rust instance this suite starts, both on the same disposable database,
and compares status codes, bodies (key order included), and every request each backend sends
upstream, every header included. The upstreams are local stand-ins that record what arrives:

* GitHub's API (tree listings, the Contents API of the publish) and raw.githubusercontent.com
  (the rule files, and the ATT&CK STIX bundle at the path Python reads it from);
* the Wazuh manager (`GET /rules`, `PUT /logtest`) and the Wazuh indexer (the rule search,
  the firing counts, `_cat/indices`);
* Graylog 6 and 7 (event definitions, the backtest's search API);
* MinIO (the per-tenant custom-repo pointers), verifying every SigV4 signature.

Both backends load the same corpus before anything is compared: Python's caches are filled by
calling their `refresh()` here, the Rust instance warms its own at startup (its refresher), and
the two sets of upstream requests are compared. The caches that load in the background
(`ensure_fresh_nonblocking`) are compared cold (`loading: true`, nothing loaded yet) and then
warm, each backend's background refresh waited for separately.

Python reaches the stand-ins because `httpx.AsyncClient.build_request` and
`requests.Session.request` are patched here to rewrite the public hosts, and `create_session()`
of the custom repos dials the MinIO stand-in; Rust because its instance is started with
`COPILOT_GITHUB_API_URL`, `COPILOT_GITHUB_RAW_URL`, `COPILOT_MITRE_STIX_URL` and
`COPILOT_MINIO_ENDPOINT` (parity harness only).

Masked, each with a check of its own: the caches' refresh times (each backend refreshed at its
own instant; they must be within minutes of each other), elasticsearch-py's `User-Agent` patch
version, the Wazuh manager's authentication (each process keeps its token), and the order the
raw rule files are fetched in (twelve at a time on both sides: compared as a set).

Deliberate differences (RUST_MIGRATION.md §4), each a check of its own: `/backtest`, `/publish`
and `/custom-repos/test` refuse a body customer the caller may not see, and `GET /custom-repos`
lists a scoped caller's customers only.

Ports (all overridable): CATALOG_PARITY_RUST_PORT, CATALOG_GH_API_STUB_PORT,
CATALOG_GH_RAW_STUB_PORT, CATALOG_MANAGER_STUB_PORT, CATALOG_INDEXER_STUB_PORT,
CATALOG_GRAYLOG_STUB_PORT, CATALOG_S3_STUB_PORT.

    PARITY_SUITES=tests/e2e/rust_parity_catalog_e2e.py scripts/rust-parity.sh
"""

import asyncio
import copy
import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qsl
from urllib.parse import unquote

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"
# Both backends read it per call; neither gets one here.
os.environ.pop("GITHUB_TOKEN", None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import connector_samples as samples  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
import requests  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from miniopy_async import Minio  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.connectors import cache as connector_cache  # noqa: E402
from app.db.db_session import async_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("CATALOG_PARITY_RUST_PORT", "6170"))
GH_API_PORT = int(os.environ.get("CATALOG_GH_API_STUB_PORT", "6171"))
GH_RAW_PORT = int(os.environ.get("CATALOG_GH_RAW_STUB_PORT", "6172"))
MGR_PORT = int(os.environ.get("CATALOG_MANAGER_STUB_PORT", "6173"))
ES_PORT = int(os.environ.get("CATALOG_INDEXER_STUB_PORT", "6174"))
GL_PORT = int(os.environ.get("CATALOG_GRAYLOG_STUB_PORT", "6175"))
S3_PORT = int(os.environ.get("CATALOG_S3_STUB_PORT", "6176"))
RUST = f"http://127.0.0.1:{RS_PORT}"
P = "/api/copilot_searches"

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"CsA{SFX}", f"CsB{SFX}"
ADMIN, ANALYST, PORTAL, NOBODY = f"cs_admin{SFX}", f"cs_analyst{SFX}", f"cs_portal{SFX}", f"cs_nobody{SFX}"
USERS = (ADMIN, ANALYST, PORTAL, NOBODY)
OUR_CONNECTORS = ("Wazuh-Manager", "Wazuh-Indexer", "Graylog")
MGR_USER, MGR_PASS = "parity-manager", f"mgr-{SFX}"
ES_USER, ES_PASS = "parity-indexer", f"es-{SFX}"
GL_USER, GL_PASS = "parity-graylog", f"gl-{SFX}"
S3_USER, S3_SECRET = "minio-catalog", "minio-catalog-secret"
STREAM_A = "6600000000000000000000a1"
results = []
RECS = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def jbody(obj):
    return json.dumps(obj).encode()


def ok(obj, ctype="application/json", extra=None):
    return 200, ctype, jbody(obj), extra or {}


# --- HTTP stand-ins -------------------------------------------------------------------------
class Recorder:
    """Records every request — method, path, every header as sent, body — and answers with
    `answer(rec, method, path, headers, body)` (`None` hangs up)."""

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


#: elasticsearch-py's `User-Agent` names the interpreter's patch version.
ES_AGENT = re.compile(r"\(Python 3\.11(?:\.\d+)?\)")


def normalised(name, captures):
    out = []
    for c in captures:
        if name == "manager" and c["path"] == "/security/user/authenticate":
            continue
        headers = {}
        for k, v in sorted(c["headers"].items()):
            if k == "user-agent":
                v = ES_AGENT.sub("(Python 3.11)", v)
            headers[k] = v
        out.append({"method": c["method"], "path": c["path"], "headers": headers, "body": c["body"].decode("utf-8", "replace")})
    if name == "gh_raw":
        # Twelve files at a time on both sides: the arrival order is the scheduler's.
        out.sort(key=lambda c: (c["path"], json.dumps(c, sort_keys=True)))
    return out


# --- The corpus -------------------------------------------------------------------------------
CATALOG_REPO, CATALOG_BRANCH = "socfortress/CoPilot-Search-Queries", "main"
FIXTURES = os.path.join(REPO, "crates", "copilot-searches", "tests", "fixtures", "rules")
MITRE_PATH = "/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def fixture_files():
    out = {}
    root = os.path.join(FIXTURES, "detections")
    for dirpath, _, names in sorted(os.walk(root)):
        for n in sorted(names):
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, FIXTURES).replace(os.sep, "/")
            with open(full, encoding="utf-8") as fh:
                out[rel] = fh.read()
    return out


AGG_RULE = """name: Parity Aggregated Logons
id: parity-agg-0001
status: experimental
type: aggregation
description: Many logons from one source.
data_source:
  - Windows Event-Log
tags:
  analytic_story:
    - Parity Story / With Slash
  mitre_attack_id:
    - T1078
    - T1110.001
response:
  severity: high
graylog:
  query: data_win_system_eventID:4625 AND agent_name:dc01
aggregation:
  enabled: true
  function: distinct_count
  field: data_win_eventdata_targetUserName
  group_by:
    - agent_name
    - data_win_eventdata_ipAddress
  condition: '>='
  threshold: 5
  window: 10m
  execute_every: 1m
"""
MINIMAL_RULE = "id: parity-minimal-0001\nname: Parity Minimal Rule\n"
COUNT_RULE = """name: parity count rule
id: parity-count-0001
status: production
description: A count aggregation with defaults.
tags:
  analytic_story: [Parity Story / With Slash, Account Manipulation]
  mitre_attack_id: T1078
response:
  severity: Critical
graylog:
  query: 'event_code:4720'
aggregation:
  enabled: true
  function: count
  condition: '>'
  threshold: 3
  window: 2h
"""
DISABLED_AGG = """name: Parity Disabled Aggregation
id: parity-agg-off-0001
description: an aggregation block that is switched off
data_source: Linux Syslog
graylog:
  query: program:sshd
aggregation:
  enabled: false
  function: count
"""
EXTRA_FILES = {
    "detections/parity/aggregated_logons.yaml": AGG_RULE,
    "detections/parity/minimal.yml": MINIMAL_RULE,
    "detections/parity/count_rule.yaml": COUNT_RULE,
    "detections/parity/disabled_agg.yaml": DISABLED_AGG,
    "detections/parity/not_a_mapping.yaml": "- just\n- a list\n",
    "detections/parity/broken.yaml": "name: [unclosed\n",
}
#: Tree entries the fetch must skip (or fail on).
TREE_EXTRAS = [
    {"path": "README.md", "type": "blob"},
    {"path": "detections", "type": "tree"},
    {"path": "detections/parity", "type": "tree"},
    {"path": "detections/notes.txt", "type": "blob"},
    {"path": "detections/parity/missing.yaml", "type": "blob"},
    {"path": "rules/elsewhere.yaml", "type": "blob"},
]

CUSTOM_A_REPO, CUSTOM_A_BRANCH = f"acme-{SFX}/rules-a", "dev"
CUSTOM_B_REPO = f"beta-{SFX}/rules-b"
CUSTOM_A_FILES = {
    "detections/custom/acme_rule.yaml": """name: Acme Custom Rule
id: acme-custom-0001
status: production
description: A tenant's own rule.
tags:
  analytic_story: [Acme Story]
  mitre_attack_id: [T1059.001]
graylog:
  query: process_name:evil.exe
""",
    # Re-uses a catalog id: the catalog's copy wins.
    "detections/custom/duplicate.yaml": "name: Acme Duplicate\nid: parity-minimal-0001\n",
}


def build_trees():
    files = {**fixture_files(), **EXTRA_FILES}
    raw = {f"/{CATALOG_REPO}/{CATALOG_BRANCH}/{p}": t for p, t in files.items()}
    tree = [{"path": p, "mode": "100644", "type": "blob", "sha": hashlib.sha1(t.encode()).hexdigest()} for p, t in files.items()]
    tree.insert(3, TREE_EXTRAS[0])
    tree.insert(0, TREE_EXTRAS[1])
    tree.extend(TREE_EXTRAS[2:])
    trees = {(CATALOG_REPO, CATALOG_BRANCH): tree}
    trees[(CUSTOM_A_REPO, CUSTOM_A_BRANCH)] = [{"path": p, "type": "blob"} for p in CUSTOM_A_FILES]
    for p, t in CUSTOM_A_FILES.items():
        raw[f"/{CUSTOM_A_REPO}/{CUSTOM_A_BRANCH}/{p}"] = t
    trees[(f"probe-{SFX}/ok", "main")] = [
        {"path": "detections/a.yaml", "type": "blob"},
        {"path": "detections/b.yml", "type": "blob"},
        {"path": "detections/c.txt", "type": "blob"},
        {"path": "detections/d", "type": "tree"},
        {"path": "other/e.yaml", "type": "blob"},
    ]
    return trees, raw


TREES, RAW = build_trees()

#: Rules whose values are not the types the corpus uses, a phase each (refreshed, then
#: ODD_BATTERY on both backends): whatever Python raises, Rust must raise alike.
ODD_PHASES = {
    "types": {
        "detections/odd/odd_tags.yaml": "name: Odd Tags\nid: odd-tags-0001\ndate: 2026-01-29\ntags: none\ndata_source: 5\nreferences: http://x\nstatus: 7\n",
        "detections/odd/odd_tag_values.yaml": (
            "name: Odd Tag Values\nid: odd-tagvals-0001\ntags:\n  analytic_story: Single Story\n  mitre_attack_id: T1059\n"
            "  product: Wazuh\nresponse: high\ngraylog:\n  query: 5\n"
        ),
        "detections/odd/odd_lists.yaml": (
            "name: Odd Lists\nid: odd-lists-0001\ntags:\n  analytic_story: [Story A, 5, null]\n  mitre_attack_id: [1059, null, T1078]\n"
            "response:\n  severity: 3\ndata_source: [null]\nversion: 1.5\nschema_version: 2\n"
        ),
    },
    "stories": {
        "detections/odd/story_a.yaml": "name: Story A1\nid: odd-story-a1\ntags:\n  analytic_story: [' Spaced Story ', 'Spaced Story']\n  mitre_attack_id: [T1059.001]\n",
        "detections/odd/story_b.yaml": "name: Story B1\nid: odd-story-b1\ntags:\n  analytic_story: ['']\n  product: [Wazuh, Wazuh]\ndata_source: [A, A, B]\nreferences: [x, x]\n",
        "detections/odd/story_c.yaml": "name: Story C1\nid: odd-story-c1\ntags:\n  analytic_story: {a: 1}\n",
    },
    "names": {
        "detections/odd/int_name.yaml": "name: 123\nid: odd-name-0001\n",
        "detections/odd/no_name.yaml": "id: odd-noname-0001\n",
        "detections/odd/int_id.yaml": "name: Int Id\nid: 7\n",
    },
    "null name": {
        "detections/odd/null_name.yaml": "name: null\nid: odd-nullname-0001\n",
    },
    "unhashable id": {
        "detections/odd/a_first.yaml": "name: Before\nid: odd-before-0001\n",
        "detections/odd/list_id.yaml": "name: List Id\nid: [1, 2]\n",
        "detections/odd/z_after.yaml": "name: After\nid: odd-after-0001\n",
    },
}
ODD_BATTERY = [
    ("list", "GET", P, None),
    ("list ?search=odd", "GET", f"{P}?search=odd", None),
    ("list ?platform=windows", "GET", f"{P}?platform=windows", None),
    ("list ?mitre_id=T1059", "GET", f"{P}?mitre_id=T1059", None),
    ("list ?severity=high", "GET", f"{P}?severity=high", None),
    ("list ?status=production", "GET", f"{P}?status=production", None),
    ("cve", "GET", f"{P}/cve", None),
    ("stats", "GET", f"{P}/stats", None),
    ("categories", "GET", f"{P}/categories", None),
    ("by id", "GET", f"{P}/id/odd-tags-0001", None),
    ("by id odd-lists", "GET", f"{P}/id/odd-lists-0001", None),
    ("by name", "GET", f"{P}/name/Odd%20Tags", None),
    ("by ids", "POST", f"{P}/by-ids", {"ids": ["odd-tags-0001", "odd-tagvals-0001", "odd-lists-0001", "odd-name-0001", "7"]}),
    ("coverage", "GET", f"{P}/mitre/coverage", None),
    ("technique", "GET", f"{P}/mitre/T1059", None),
    ("catalog stats", "GET", f"{P}/catalog/stats", None),
    ("stories", "GET", f"{P}/catalog/stories", None),
    ("story", "GET", f"{P}/catalog/stories/Single%20Story", None),
    ("spaced story", "GET", f"{P}/catalog/stories/Spaced%20Story", None),
    ("gaps", "GET", f"{P}/catalog/coverage-gaps", None),
    ("gap", "GET", f"{P}/catalog/coverage-gaps/T1059", None),
    ("graylog query", "POST", f"{P}/graylog", {"rule_id": "odd-tagvals-0001"}),
    ("provision check", "POST", f"{P}/provision/graylog/check", {"ids": ["odd-tagvals-0001", "odd-tags-0001"]}),
]

# --- ATT&CK -----------------------------------------------------------------------------------
TACTICS = [
    ("TA0040", "impact", "Impact"),
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA9001", "parity-extra", "Parity Extra Tactic"),
]


def technique_ids():
    found = set()
    for text_ in list(fixture_files().values()) + list(EXTRA_FILES.values()) + list(CUSTOM_A_FILES.values()):
        found.update(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text_))
    found.update({"T1001", "T1001.001", "T1595", "T1595.002", "T1486", "T1490", "T1110", "T1110.001", "T1021", "T1021.001"})
    for t in list(found):
        found.add(t.split(".")[0])
    return sorted(found)


def mitre_bundle():
    objects = [{"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "name": "Enterprise ATT&CK"}]
    for ext, short, name in TACTICS:
        objects.append(
            {
                "type": "x-mitre-tactic",
                "id": f"x-mitre-tactic--{ext}",
                "name": name,
                "x_mitre_shortname": short,
                "description": f"The adversary is doing {name.lower()}.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": ext, "url": f"https://attack.mitre.org/tactics/{ext}"},
                ],
            },
        )
    objects.append({"type": "x-mitre-tactic", "name": "Deprecated", "x_mitre_shortname": "old", "x_mitre_deprecated": True})
    objects.append(
        {
            "type": "x-mitre-tactic",
            "name": "No short name",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0999"}],
        },
    )
    shorts = [s for _, s, _ in TACTICS]
    for i, tid in enumerate(technique_ids()):
        n = int(tid[1:5]) + (int(tid[6:]) if "." in tid else 0)
        phases = [{"kill_chain_name": "mitre-attack", "phase_name": shorts[n % 14]}]
        if n % 3 == 0:
            phases.append({"kill_chain_name": "mitre-attack", "phase_name": shorts[(n + 5) % 15]})
        if n % 5 == 0:
            phases.append({"kill_chain_name": "mitre-mobile-attack", "phase_name": "impact"})
        url_id = tid.replace(".", "/")
        objects.append(
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{i}",
                "name": f"Technique {tid}",
                "x_mitre_is_subtechnique": "." in tid,
                "kill_chain_phases": phases,
                "external_references": [
                    {"source_name": "capec", "external_id": "CAPEC-1"},
                    {"source_name": "mitre-attack", "external_id": tid, "url": f"https://attack.mitre.org/techniques/{url_id}"},
                ],
            },
        )
    objects.append(
        {
            "type": "attack-pattern",
            "name": "Revoked",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1222"}],
        },
    )
    objects.append({"type": "attack-pattern", "name": "No id", "kill_chain_phases": []})
    return {"type": "bundle", "id": "bundle--parity", "objects": objects}


MITRE = mitre_bundle()


def gh_api_answer(rec, method, raw_path, headers, body):
    path, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    m = re.fullmatch(r"/repos/([^/]+/[^/]+)/git/trees/([^/]+)", path)
    if method == "GET" and m:
        repo, branch = unquote(m.group(1)), unquote(m.group(2))
        owner = repo.split("/")[0]
        if owner == f"e401-{SFX}":
            return 401, "application/json", jbody({"message": "Bad credentials"}), {}
        if owner == f"e403-{SFX}":
            return 403, "application/json", jbody({"message": "rate limited"}), {}
        if owner == f"e500-{SFX}":
            return 500, "text/plain", b"upstream exploded", {}
        if owner == f"hang-{SFX}":
            return None
        if owner == f"notjson-{SFX}":
            return 200, "application/json", b"<html>not json</html>", {}
        tree = TREES.get((repo, branch))
        if tree is None:
            return 404, "application/json", jbody({"message": "Not Found", "documentation_url": "https://docs.github.com"}), {}
        return ok({"sha": "abc", "url": "x", "tree": tree, "truncated": False})
    m = re.fullmatch(r"/repos/([^/]+/[^/]+)/contents/(.+)", path)
    if m:
        repo, target = unquote(m.group(1)), unquote(m.group(2))
        if headers.get("authorization") == "Bearer revoked-token":
            return 401, "application/json", jbody({"message": "Bad credentials"}), {}
        published = rec.mode.setdefault("published", {})
        if method == "GET":
            if "readfail" in target:
                return 500, "text/plain", b"read exploded", {}
            if (repo, target, params.get("ref")) in published:
                return ok({"sha": published[(repo, target, params.get("ref"))], "path": target})
            return 404, "application/json", jbody({"message": "Not Found"}), {}
        if method == "PUT":
            if "reject" in target:
                return 422, "application/json", jbody({"message": 'Invalid request.\n\n"sha" wasn\'t supplied.'}), {}
            if "plainfail" in target:
                return 409, "text/plain", b"conflict, plain text", {}
            doc = json.loads(body)
            sha = hashlib.sha1(body).hexdigest()
            created = (repo, target, doc.get("branch")) not in published
            published[(repo, target, doc.get("branch"))] = sha
            return (
                201 if created else 200,
                "application/json",
                jbody(
                    {
                        "content": {"path": target, "sha": sha, "html_url": f"https://github.com/{repo}/blob/{doc.get('branch')}/{target}"},
                        "commit": {"sha": sha, "html_url": f"https://github.com/{repo}/commit/{sha}"},
                    },
                ),
                {},
            )
    return 404, "application/json", jbody({"message": "Not Found"}), {}


def gh_raw_answer(rec, method, raw_path, headers, body):
    path = raw_path.partition("?")[0]
    if path == MITRE_PATH:
        if rec.mode.get("mitre_fail"):
            return 503, "text/plain", b"try later", {}
        return ok(rec.mode.get("mitre", MITRE))
    text_ = RAW.get(unquote(path))
    if text_ is None:
        return 404, "text/plain", b"404: Not Found", {}
    return 200, "text/plain; charset=utf-8", text_.encode("utf-8"), {}


# --- The Wazuh manager ------------------------------------------------------------------------
def wazuh_rule(rid, level, description, groups, mitre=(), filename="0095-sshd_rules.xml", status="enabled", **extra):
    rule = {
        "filename": filename,
        "relative_dirname": "ruleset/rules",
        "id": rid,
        "level": level,
        "status": status,
        "details": extra.pop("details", {"if_sid": "5700", "match": {"pattern": "illegal user|invalid user", "negate": "no"}}),
        "pci_dss": extra.pop("pci_dss", []),
        "gpg13": extra.pop("gpg13", []),
        "gdpr": extra.pop("gdpr", []),
        "hipaa": extra.pop("hipaa", []),
        "tsc": extra.pop("tsc", []),
        "mitre": list(mitre),
        "groups": groups,
        "description": description,
    }
    rule.update(extra)
    return rule


WAZUH_RULES = [
    wazuh_rule(
        5710,
        5,
        "sshd: Attempt to login using a non-existent user",
        ["syslog", "sshd", "authentication_failed", "invalid_login"],
        ["T1110.001", "T1021.004"],
        pci_dss=["10.2.4", "10.2.5", "10.6.1"],
        gpg13=["7.1"],
        gdpr=["IV_35.7.d", "IV_32.2"],
        hipaa=["164.312.b"],
        tsc=["CC6.1", "CC6.8"],
        nist_800_53=["AU.14", "AC.7", "AU.6"],
    ),
    wazuh_rule(
        5712,
        10,
        "sshd: brute force trying to get access to the system. Non existent user.",
        ["syslog", "sshd"],
        ["T1110"],
        **{"nist-800-53": ["SI.4"]},
    ),
    wazuh_rule(
        60122,
        5,
        "Logon Failure - Unknown user or bad password",
        ["windows", "win_authentication_failed"],
        ["T1078", "T1531"],
        filename="0580-win-security_rules.xml",
        details={
            "if_sid": "60105",
            "field": {"name": "win.system.eventID", "pattern": "^529$|^4625$", "type": "pcre2"},
            "options": "no_full_log",
        },
        pci_dss=["10.2.4"],
        hipaa=["164.312.b"],
    ),
    wazuh_rule(100002, 12, 'Ransomware note <created> & "files" renamed', ["parity", "ransomware"], ["T1486"], filename="local_rules.xml"),
    wazuh_rule(100003, 7, "Dead rule: nothing ever fires it", ["parity"], [], filename="local_rules.xml", details={}, gdpr=["IV_30.1.g"]),
    wazuh_rule(100004, 0, "Level zero grouping rule", ["parity", "ossec"], [], filename="local_rules.xml", details=None),
    wazuh_rule(100005, 3, "Disabled rule", ["parity"], ["T1490"], filename="local_rules.xml", status="disabled", pci_dss=["11.4"]),
    wazuh_rule(
        100006,
        9,
        "List details",
        ["parity", "audit"],
        ["T1059.001", "T9999"],
        filename="local_rules.xml",
        details={
            "frequency": "8",
            "timeframe": "120",
            "same_source_ip": "",
            "list": {"lookup": "address_match_key", "field": "srcip", "value": "etc/lists/bad"},
        },
        tsc=["CC7.2"],
    ),
    wazuh_rule(2, 0, "Generic template for all firewall rules.", ["firewall"], [], filename="0010-rules_config.xml"),
]


def mgr_answer(rec, method, raw_path, headers, body):
    path, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    tok = f"tok-{SFX}"
    if path == "/security/user/authenticate":
        return ok({"data": {"token": tok}, "error": 0})
    if headers.get("authorization") != f"Bearer {tok}":
        return 401, "application/json", jbody({"title": "Unauthorized", "detail": "no"}), {}
    if method == "GET" and path == "/rules":
        if rec.mode.get("rules_fail"):
            return 500, "application/json", jbody({"title": "Internal error", "detail": "boom", "error": 1000}), {}
        rules = rec.mode.get("rules", WAZUH_RULES)
        limit = int(params.get("limit", "500"))
        return ok(
            {
                "data": {"affected_items": rules[:limit], "total_affected_items": len(rules), "total_failed_items": 0, "failed_items": []},
                "message": "All selected rules were returned",
                "error": 0,
            },
        )
    if method == "PUT" and path == "/logtest":
        doc = json.loads(body or b"{}")
        event = doc.get("event", "")
        if "wazuh-400" in event:
            return 400, "application/json", jbody({"title": "Bad Request", "detail": "Invalid log format", "error": 400}), {}
        if "wazuh-500" in event:
            return 500, "text/html", b"<html>boom</html>", {}
        if "no-rule" in event:
            output = {"decoder": {"name": "sshd"}, "full_log": event, "location": doc.get("location")}
        elif "empty-output" in event:
            output = {}
        elif "rule-zero" in event:
            output = {"rule": {"id": "0", "level": 0}, "full_log": event}
        elif "rule-text" in event:
            output = {"rule": {"id": "abc", "level": 3}, "full_log": event}
        elif "rule-list" in event:
            output = {"rule": ["not", "a", "dict"], "full_log": event}
        elif "rule-float" in event:
            output = {"rule": {"id": 5710.9, "level": "5", "mitre": {"id": "T1110"}, "groups": None}, "full_log": event}
        else:
            output = {
                "rule": {
                    "id": "5710",
                    "level": 5,
                    "description": "sshd: Attempt to login using a non-existent user",
                    "groups": ["syslog", "sshd"],
                    "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]},
                    "pci_dss": ["10.2.4"],
                    "gdpr": ["IV_35.7.d"],
                    "firedtimes": 1,
                },
                "decoder": {"parent": "sshd", "name": "sshd"},
                "full_log": event,
                "predecoder": {"program_name": "sshd"},
                "location": doc.get("location"),
            }
        return ok(
            {"error": 0, "data": {"messages": ["WARNING: (7309): ..."], "token": "lt", "output": output, "alert": True, "codemsg": 1}},
        )
    return 404, "application/json", jbody({"title": "Not Found", "detail": path}), {}


# --- The Wazuh indexer -----------------------------------------------------------------------
FIRING = {
    "rule.id": [
        {
            "key": "5710",
            "doc_count": 1200,
            "last_7d": {"doc_count": 300},
            "last_seen": {"value": 1.76e12, "value_as_string": "2026-10-16T22:10:01.000Z"},
        },
        {"key": 60122, "doc_count": 75, "last_7d": {"doc_count": 0}, "last_seen": {"value": 1.75e12}},
        {"key": "abc", "doc_count": 9, "last_7d": {"doc_count": 9}},
        {"key": 2, "doc_count": 999999, "last_7d": {}, "last_seen": None},
        {"key": "100002", "doc_count": 3, "last_7d": {"doc_count": 1}, "last_seen": {"value_as_string": "2026-10-10T00:00:00Z"}},
    ],
    "rule_id": [{"key": "5712", "doc_count": 4, "last_7d": {"doc_count": 4}}],
}
CUSTOMER_FIRING = {
    ("agent_labels_customer", CUST_A): [
        {"key": "5710", "doc_count": 40, "last_7d": {"doc_count": 2}, "last_seen": {"value_as_string": "2026-10-15T01:02:03.000Z"}},
    ],
    ("agent.labels.customer", CUST_B): [{"key": 100002, "doc_count": 1, "last_7d": {"doc_count": 1}}],
}
SEARCH_HITS = {
    "took": 4,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 2, "relation": "eq"},
        "max_score": None,
        "hits": [
            {
                "_index": "wazuh-alerts-4.x-2026.10.17",
                "_id": "a1",
                "_score": None,
                "_source": {"agent_name": "web-01", "rule_level": 5},
                "sort": [1],
            },
            {
                "_index": "wazuh-alerts-4.x-2026.10.17",
                "_id": "a2",
                "_score": None,
                "_source": {"agent_name": "web-02", "full_log": "useradd x"},
                "sort": [2],
            },
        ],
    },
}


def es_answer(rec, method, raw_path, headers, body):
    path, _, query = raw_path.partition("?")
    if rec.mode.get("delay"):
        time.sleep(rec.mode["delay"])
    if method == "GET" and path == "/_cat/indices":
        if rec.mode.get("cat_fail"):
            return 500, "application/json", jbody({"error": "boom", "status": 500}), {}
        return ok(
            [
                {"index": "wazuh-alerts-4.x-2026.10.17"},
                {"index": ".kibana_1"},
                {"index": "office365-acme"},
                {"index": "wazuh-monitoring-2026"},
            ],
        )
    if path.endswith("/_search"):
        doc = json.loads(body or b"{}")
        aggs = doc.get("aggs", {})
        if "by_rule" in aggs:
            if rec.mode.get("firing_fail"):
                return (
                    400,
                    "application/json",
                    jbody(
                        {
                            "error": {"root_cause": [], "type": "search_phase_execution_exception", "reason": "all shards failed"},
                            "status": 400,
                        },
                    ),
                    {},
                )
            field = aggs["by_rule"]["terms"]["field"]
            filters = doc["query"]["bool"]["filter"]
            customer = [f["term"] for f in filters if "term" in f]
            if customer:
                ((cfield, code),) = customer[0].items()
                buckets = CUSTOMER_FIRING.get((cfield, code), [])
            else:
                buckets = rec.mode.get("firing", FIRING).get(field, [])
            return ok(
                {
                    "took": 3,
                    "timed_out": False,
                    "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
                    "aggregations": {"by_rule": {"buckets": buckets}},
                },
            )
        if "missing-index" in path:
            return (
                404,
                "application/json",
                jbody({"error": {"type": "index_not_found_exception", "reason": "no such index [missing-index]"}, "status": 404}),
                {},
            )
        if "bad-query" in path:
            return (
                400,
                "application/json",
                jbody({"error": {"type": "parsing_exception", "reason": "unknown query [wildcard]"}, "status": 400}),
                {},
            )
        return ok(SEARCH_HITS)
    return 404, "application/json", jbody({"error": "no handler", "status": 404}), {}


# --- Graylog ----------------------------------------------------------------------------------
def gl_rows(n):
    base = datetime.datetime(2026, 10, 14, 0, 0, tzinfo=datetime.timezone.utc)
    rows = []
    for i in range(n):
        ts = base + datetime.timedelta(minutes=7 * i)
        stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z") if i % 4 else ts.strftime("%Y-%m-%d %H:%M:%S.000+0000")
        rows.append([stamp, f"host-{i % 3}", f"message {i}", "4625" if i % 2 else "-", "dc01", f"user{i % 4}", f"10.0.0.{i % 5}"])
    rows.append(["not a time", "host-x", "garbage", "4625", "dc01", "userx", "10.0.0.9"])
    return rows


GL_SCHEMA = [
    {"column_type": "field", "type": "date", "field": "timestamp", "name": "timestamp"},
    {"column_type": "field", "type": "string", "field": "source", "name": "source"},
    {"column_type": "field", "type": "string", "name": "message"},
    {"column_type": "field", "type": "string", "field": "data_win_system_eventID"},
    {"column_type": "field", "type": "string", "field": "agent_name"},
    "data_win_eventdata_targetUserName",
    {"column_type": "field", "type": "string", "column": "data_win_eventdata_ipAddress"},
]


def gl_answer(rec, method, raw_path, headers, body):
    path, _, query = raw_path.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    mode = rec.mode
    if method == "GET" and path == "/api/system":
        if mode.get("system_fail"):
            return 500, "text/plain", b"down", {}
        return ok(
            samples.GRAYLOG_SYSTEM_7
            if mode.get("version") == 7
            else {**samples.GRAYLOG_SYSTEM_6, "version": mode.get("v6", "6.1.4+abcdef")},
        )
    if method == "GET" and path == "/api/events/definitions":
        if mode.get("defs_fail"):
            return 500, "application/json", jbody({"type": "ApiError", "message": "boom"}), {}
        defs = mode.get("definitions", [])
        page, size = int(params.get("page", "1")), int(params.get("per_page", "50"))
        batch = defs[(page - 1) * size : page * size]
        return ok({"event_definitions": batch, "total": len(defs), "page": page, "per_page": size})
    if method == "POST" and path == "/api/events/definitions":
        entity = json.loads(body)
        if mode.get("version") == 7:
            if "entity" not in entity:
                return 400, "application/json", jbody({"type": "ApiError", "message": "entity cannot be null"}), {}
            entity = entity["entity"]
        if mode.get("create_fail"):
            return 400, "application/json", jbody({"type": "ApiError", "message": "Invalid event definition"}), {}
        new = {"id": f"ed{len(mode.setdefault('definitions', [])):022d}", "title": entity.get("title")}
        if not mode.get("dont_store"):
            mode["definitions"].append(samples.graylog_event_definition(new["id"], entity.get("title")))
        return ok({**entity, "id": new["id"]})
    if method == "POST" and path == "/api/search/messages":
        doc = json.loads(body)
        if mode.get("search") == "error-list":
            return 400, "application/json", jbody([{"message": "Unknown field", "path": "fields[3]"}, {"message": "second"}]), {}
        if mode.get("search") == "error-dict":
            return 400, "application/json", jbody({"type": "ApiError", "message": "Query parse failed"}), {}
        if mode.get("search") == "error-text":
            return 503, "text/plain", b"graylog is starting", {}
        if mode.get("search") == "not-json":
            return 200, "text/csv", b"a,b\n1,2\n", {}
        if mode.get("search") == "empty":
            return ok({"schema": [], "datarows": []})
        n = 20 if doc.get("size") == 20 else mode.get("rows", 30)
        names = list(doc.get("fields", []))
        schema = GL_SCHEMA if doc.get("size") != 20 else [{"field": f} for f in names]
        rows = gl_rows(n)
        if doc.get("size") == 20:
            rows = [[r[i] if i < len(r) else "-" for i in range(len(names))] for r in rows]
        return ok({"schema": schema, "datarows": rows, "metadata": {"effective_timerange": {"type": "relative"}}})
    if method == "POST" and path == "/api/views/fields":
        if mode.get("fields") == "fail":
            return 500, "application/json", jbody({"message": "fields broke"}), {}
        return ok(
            mode.get("fields")
            or [
                {"name": n}
                for n in (
                    "timestamp",
                    "source",
                    "message",
                    "agent_name",
                    "data_win_system_eventID",
                    "gl2_source_input",
                    {"x": 1}.get("y") or "streams",
                )
            ]
            + [{"type": "x"}, "bare"],
        )
    return 404, "application/json", jbody({"type": "ApiError", "message": "HTTP 404 Not Found"}), {}


# --- The MinIO stand-in -----------------------------------------------------------------------
NS = "http://s3.amazonaws.com/doc/2006-03-01/"
REQUEST_ID = "18A2F7C3D4E5F601"
HOST_ID = "dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8"


def go_xml_escape(s):
    table = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&#34;", "'": "&#39;", "\t": "&#x9;", "\n": "&#xA;", "\r": "&#xD;"}
    return "".join(table.get(ch, ch) for ch in s)


def s3_url_encode(s):
    out = []
    for b in s.encode("utf-8"):
        c = chr(b)
        if c.isascii() and (c.isalnum() or c in "-_./*"):
            out.append(c)
        elif c == " ":
            out.append("+")
        else:
            out.append("%%%02X" % b)
    return "".join(out)


class S3StandIn:
    """In-memory buckets with the calls miniopy-async makes for the custom-repo pointers; every
    request's SigV4 signature verified and recorded."""

    def __init__(self, access_key, secret_key):
        self.access_key, self.secret_key = access_key, secret_key
        self.lock = threading.Lock()
        self.buckets, self.requests = {}, []
        self.name = "s3"

    def snapshot(self):
        with self.lock:
            return {b: dict(objs) for b, objs in self.buckets.items()}

    def restore(self, snap):
        with self.lock:
            self.buckets = {b: dict(objs) for b, objs in snap.items()}

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out

    def verify(self, method, raw_path, raw_query, headers):
        auth = headers.get("authorization")
        if auth is None:
            return "anonymous"
        m = re.fullmatch(
            r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})",
            auth,
        )
        if not m:
            return "malformed"
        access, date, region, signed, signature = m.groups()
        if access != self.access_key:
            return "unknown access key"
        pairs = sorted(p.split("=") for p in raw_query.split("&")) if raw_query else [[""]]
        canonical_query = "&".join("=".join(p) for p in pairs)
        lines = []
        for name in signed.split(";"):
            value = headers.get(name)
            if value is None:
                return f"signed header {name} not sent"
            lines.append(f"{name}:{re.sub(' +', ' ', value).strip()}")
        payload = headers.get("x-amz-content-sha256", "")
        canonical = f"{method}\n{raw_path or '/'}\n{canonical_query}\n" + "\n".join(lines) + f"\n\n{signed}\n{payload}"
        amz_date = headers.get("x-amz-date", "")
        scope = f"{date}/{region}/s3/aws4_request"
        to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
        key = ("AWS4" + self.secret_key).encode()
        for part in (date, region, "s3", "aws4_request"):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        expected = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
        return "ok" if hmac.compare_digest(expected, signature) else "bad signature"

    def error(self, status, code, message, resource, bucket=None, key=None, head=False):
        if head:
            return status, {}, b""
        parts = [f"<Code>{code}</Code><Message>{go_xml_escape(message)}</Message>"]
        if key:
            parts.append(f"<Key>{go_xml_escape(key)}</Key>")
        if bucket:
            parts.append(f"<BucketName>{go_xml_escape(bucket)}</BucketName>")
        parts.append(f"<Resource>{go_xml_escape(resource)}</Resource><RequestId>{REQUEST_ID}</RequestId><HostId>{HOST_ID}</HostId>")
        return (
            status,
            {"Content-Type": "application/xml"},
            ('<?xml version="1.0" encoding="UTF-8"?>\n<Error>' + "".join(parts) + "</Error>").encode(),
        )

    def handle(self, method, raw_path, raw_query, headers, body):
        record = {
            "method": method,
            "path": raw_path,
            "query": raw_query,
            "headers": headers,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "signature": self.verify(method, raw_path, raw_query, headers),
        }
        with self.lock:
            self.requests.append(record)
            return self.dispatch(method, raw_path, raw_query, headers, body)

    def dispatch(self, method, raw_path, raw_query, headers, body):
        path = unquote(raw_path)
        query = dict(parse_qsl(raw_query, keep_blank_values=True))
        head = method == "HEAD"
        bucket, _, key = path[1:].partition("/")
        objs = self.buckets.get(bucket)
        if not key:
            if method == "PUT":
                if objs is not None:
                    return self.error(
                        409,
                        "BucketAlreadyOwnedByYou",
                        "Your previous request to create the named bucket succeeded and you already own it.",
                        path,
                        bucket=bucket,
                    )
                self.buckets[bucket] = {}
                return 200, {"Location": "/" + bucket}, b""
            if objs is None:
                return self.error(404, "NoSuchBucket", "The specified bucket does not exist", path, bucket=bucket, head=head)
            if "location" in query:
                xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<LocationConstraint xmlns="{NS}"></LocationConstraint>'
                return 200, {"Content-Type": "application/xml"}, xml.encode()
            if head:
                return 200, {}, b""
            if query.get("list-type") == "2":
                prefix = query.get("prefix", "")
                keys = sorted(k for k in objs if k.startswith(prefix))
                enc = s3_url_encode if query.get("encoding-type") == "url" else (lambda s: s)
                parts = [
                    f'<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="{NS}"><Name>{bucket}</Name><Prefix>{go_xml_escape(enc(prefix))}</Prefix>'
                    f"<KeyCount>{len(keys)}</KeyCount><MaxKeys>1000</MaxKeys>",
                ]
                if query.get("encoding-type") == "url":
                    parts.append("<EncodingType>url</EncodingType>")
                parts.append("<IsTruncated>false</IsTruncated>")
                for k in keys:
                    data = objs[k][0]
                    parts.append(
                        f"<Contents><Key>{go_xml_escape(enc(k))}</Key><LastModified>2026-01-02T03:04:05.000Z</LastModified>"
                        f"<ETag>&#34;{hashlib.md5(data).hexdigest()}&#34;</ETag><Size>{len(data)}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                    )
                parts.append("</ListBucketResult>")
                return 200, {"Content-Type": "application/xml"}, "".join(parts).encode()
            return self.error(501, "NotImplemented", "not here", path, bucket=bucket)
        if objs is None:
            return self.error(404, "NoSuchBucket", "The specified bucket does not exist", path, bucket=bucket, head=head)
        if method == "PUT":
            objs[key] = (body, headers.get("content-type") or "binary/octet-stream")
            return 200, {"ETag": '"' + hashlib.md5(body).hexdigest() + '"'}, b""
        if method == "DELETE":
            objs.pop(key, None)
            return 204, {}, b""
        obj = objs.get(key)
        if obj is None:
            return self.error(404, "NoSuchKey", "The specified key does not exist.", path, bucket=bucket, key=key, head=head)
        meta = {
            "Content-Type": obj[1],
            "ETag": '"' + hashlib.md5(obj[0]).hexdigest() + '"',
            "Last-Modified": formatdate(1767323045, usegmt=True),
        }
        if head:
            return 200, {**meta, "Content-Length": str(len(obj[0]))}, b""
        return 200, meta, obj[0]

    def serve(self, port):
        standin = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _any(self):
                raw_path, _, raw_query = self.path.partition("?")
                headers = {k.lower(): v for k, v in self.headers.items()}
                body = self.rfile.read(int(headers.get("content-length") or 0))
                status, hdrs, data = standin.handle(self.command, raw_path, raw_query, headers, body)
                self.send_response(status)
                hdrs = {"x-amz-request-id": REQUEST_ID, "Server": "MinIO", **hdrs}
                for k, v in hdrs.items():
                    if k.lower() != "content-length":
                        self.send_header(k, v)
                if self.command == "HEAD":
                    if "Content-Length" in hdrs:
                        self.send_header("Content-Length", hdrs["Content-Length"])
                elif status not in (204, 304):
                    self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD" and status not in (204, 304):
                    self.wfile.write(data)

            do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _any  # noqa: N815 - http.server API

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        server = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.server = server
        return server


S3 = S3StandIn(S3_USER, S3_SECRET)
CREDENTIAL = re.compile(r"Credential=[^/]+/\d{8}/([^/]+)/s3/aws4_request, SignedHeaders=([^,]+), Signature=[0-9a-f]{64}")
ADDRESS = re.compile(r"object at 0x[0-9a-f]+")


def s3_outbound(records):
    out = []
    for r in records:
        headers = dict(r["headers"])
        auth = headers.pop("authorization", None)
        headers.pop("x-amz-date", None)
        if "range" in headers:
            headers["range"] = ADDRESS.sub("object at 0x…", headers["range"])
        signed = None
        if auth is not None:
            m = CREDENTIAL.search(auth)
            signed = list(m.groups()) if m else ["unparsed", auth]
        out.append(
            {
                "method": r["method"],
                "path": r["path"],
                "query": r["query"],
                "headers": dict(sorted(headers.items())),
                "signed": signed,
                "body": r["body_sha256"],
                "signature": r["signature"],
            },
        )
    return out


# --- the database -----------------------------------------------------------------------------
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


SAVED = {}


async def seed():
    SAVED["connectors"] = await rows(
        "SELECT * FROM connectors WHERE connector_name IN :names".replace(":names", "(" + ",".join(repr(n) for n in OUR_CONNECTORS) + ")"),
    )
    for c in (CUST_A, CUST_B):
        await sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=c, n=f"{c} Corp")
    for code, stream in ((CUST_A, STREAM_A),):
        await sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group) VALUES (:c, :n, 'idx', :s, '1', 'grp')",
            c=code,
            n=f"{code} Corp",
            s=stream,
        )
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (NOBODY, 2)):
        await sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r)",
            n=name,
            e=f"{name}@parity.test",
            r=role,
        )
    for name in (ANALYST, PORTAL):
        await sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )


async def cleanup():
    for name in USERS:
        await sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        await sql("DELETE FROM `user` WHERE username = :n", n=name)
    for c in (CUST_A, CUST_B):
        await sql("DELETE FROM customersmeta WHERE customer_code = :c", c=c)
        await sql("DELETE FROM customers WHERE customer_code = :c", c=c)
    for name in OUR_CONNECTORS:
        await sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED.get("connectors", []):
        cols = ", ".join(row)
        await sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + k for k in row)})", **row)
    connector_cache.invalidate_all()


# --- the two backends -------------------------------------------------------------------------
def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import copilot_searches

    api = APIRouter(prefix="/api")
    api.include_router(copilot_searches.router)
    app = FastAPI()
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


REWRITES = {}


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
    from app.integrations.copilot_searches.services import custom_repos

    async def create_session():
        return Minio(f"127.0.0.1:{S3_PORT}", access_key=S3_USER, secret_key=S3_SECRET, secure=False)

    custom_repos.create_session = create_session


def start_rust(gh_api, gh_raw):
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        "COPILOT_PORT": str(RS_PORT),
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
        "MINIO_ROOT_USER": S3_USER,
        "MINIO_ROOT_PASSWORD": S3_SECRET,
        "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{S3_PORT}",
        "COPILOT_GITHUB_API_URL": gh_api.url,
        "COPILOT_GITHUB_RAW_URL": gh_raw.url,
        "COPILOT_MITRE_STIX_URL": gh_raw.url + MITRE_PATH,
        # The catalog refresher stays on here; the sidebar's, which follows it by default,
        # would send its own warm-up requests to the indexer and MinIO stand-ins.
        "COPILOT_SIDEBAR_REFRESH": "false",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(150):
        try:
            if httpx.get(f"{RUST}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


#: Keys whose values each backend stamps at its own refresh.
CLOCK_KEYS = {
    "last_refreshed",
    "matrix_last_refreshed",
    "rules_last_refreshed",
    "last_refresh",
    "wazuh_last_refresh",
    "firing_stats_last_refresh",
    "last_refresh_at",
    "fetched_at",
    "timestamp",
}


def same_instant(a, b, slack=1800):
    try:
        ta = datetime.datetime.fromisoformat(str(a).replace("Z", "+00:00").replace(" ", "T"))
        tb = datetime.datetime.fromisoformat(str(b).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return False
    if (ta.tzinfo is None) != (tb.tzinfo is None):
        return False
    return abs((ta - tb).total_seconds()) <= slack


def mask_clocks(p, q):
    if isinstance(p, dict) and isinstance(q, dict):
        out_p, out_q = {}, {}
        for k in p:
            if k in CLOCK_KEYS and k in q and p[k] != q[k] and isinstance(p[k], str) and isinstance(q[k], str) and same_instant(p[k], q[k]):
                out_p[k] = out_q[k] = "<refreshed>"
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


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


async def wait_quiet(recorders, seconds=1.0, limit=120):
    """Until no recorder received anything for `seconds`."""
    deadline = time.time() + limit
    last = None
    while time.time() < deadline:
        sizes = tuple(len(r.captured) if hasattr(r, "captured") else len(r.requests) for r in recorders)
        if sizes == last:
            return
        last = sizes
        await asyncio.sleep(seconds)


async def main():  # noqa: C901 - one scenario after the other
    gh_api = Recorder(gh_api_answer, GH_API_PORT, "gh_api")
    gh_raw = Recorder(gh_raw_answer, GH_RAW_PORT, "gh_raw")
    mgr = Recorder(mgr_answer, MGR_PORT, "manager")
    es = Recorder(es_answer, ES_PORT, "indexer")
    gl = Recorder(gl_answer, GL_PORT, "graylog")
    S3.serve(S3_PORT)
    RECS[:] = [gh_api, gh_raw, mgr, es, gl, S3]
    REWRITES.update({"https://api.github.com": gh_api.url, "https://raw.githubusercontent.com": gh_raw.url})
    gl.mode["definitions"] = copy.deepcopy(samples.GRAYLOG_EVENT_DEFINITIONS)
    await seed()
    await set_connector("Wazuh-Manager", mgr.url, MGR_USER, MGR_PASS)
    await set_connector("Wazuh-Indexer", es.url, ES_USER, ES_PASS)
    await set_connector("Graylog", gl.url, GL_USER, GL_PASS)
    patch_python_clients()

    from app.integrations.copilot_searches.services.copilot_searches import rules_cache
    from app.integrations.copilot_searches.services.mitre_coverage import mitre_matrix
    from app.integrations.copilot_searches.services.wazuh_firing_stats_cache import (
        wazuh_firing_stats_cache,
    )
    from app.integrations.copilot_searches.services.wazuh_rules_cache import (
        wazuh_rules_cache,
    )

    def take_all():
        out = {}
        for rec in RECS:
            captured = rec.take()
            out[rec.name] = s3_outbound(captured) if rec is S3 else normalised(rec.name, captured)
        return out

    def compare_upstream(name, a, b):
        for upstream in a:
            x, y = a[upstream], b[upstream]
            if not (x or y):
                continue
            first = next((i for i, (u, v) in enumerate(zip(x, y)) if u != v), None if len(x) == len(y) else min(len(x), len(y)))
            check(
                f"{name}: requests to {upstream} ({len(x)})",
                x == y,
                f"python {[u['method'] + ' ' + u['path'] for u in x][:12]}\n        rust   {[v['method'] + ' ' + v['path'] for v in y][:12]}"
                + (
                    f"\n        first difference #{first}:\n        python {json.dumps(x[first] if first < len(x) else None)[:1500]}\n        rust   {json.dumps(y[first] if first < len(y) else None)[:1500]}"
                    if first is not None
                    else ""
                ),
            )

    # --- warm-up: Python by hand, Rust at its startup ------------------------------------------
    print("\n=== 0. the caches load the same corpus ===")
    take_all()
    await rules_cache.refresh()
    await mitre_matrix.refresh()
    await wazuh_rules_cache.refresh()
    py_warm = take_all()
    rust = start_rust(gh_api, gh_raw)
    await asyncio.sleep(1)
    await wait_quiet([gh_api, gh_raw, mgr, S3])
    rs_warm = take_all()
    compare_upstream("warm-up", py_warm, rs_warm)
    check(
        "warm-up: both fetched the rule files and the bundle",
        len(py_warm["gh_raw"]) > 40 and len(py_warm["manager"]) == 1,
        json.dumps({k: len(v) for k, v in py_warm.items()}),
    )

    py = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
        base_url="http://py",
        timeout=120,
    )
    rs = httpx.AsyncClient(base_url=RUST, timeout=120)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    t_nobody = token(NOBODY, ["analyst"])
    A, B = CUST_A, CUST_B

    async def send(client, method, path, tok, body, raw, headers):
        kw = {"headers": {**({"Authorization": f"Bearer {tok}"} if tok else {}), **(headers or {})}}
        if raw is not None:
            kw["content"] = raw
            kw["headers"].setdefault("Content-Type", "application/json")
        elif body is not None:
            kw["json"] = body
        return await client.request(method, path, **kw)

    async def both(name, method, path, tok=None, body=None, raw=None, headers=None, before=None, s3=True, settle=0.0):
        """Python, then Rust: the responses and every request each sent upstream; the MinIO
        stand-in's contents are put back between the two (and compared after)."""
        got = {}
        start = S3.snapshot()
        for tag, client in (("py", py), ("rs", rs)):
            S3.restore(start)
            if before is not None:
                before()
            take_all()
            r = await send(client, method, path, tok, body, raw, headers)
            if settle:
                await asyncio.sleep(settle)
            got[tag] = {
                "status": r.status_code,
                "type": r.headers.get("content-type"),
                "body": body_of(r),
                "upstream": take_all(),
                "s3": S3.snapshot(),
            }
        p, q = got["py"], got["rs"]
        pb, qb = mask_clocks(p["body"], q["body"])
        same = p["status"] == q["status"] and p["type"] == q["type"] and json.dumps(pb) == json.dumps(qb)
        check(
            f"{name} [{p['status']}]",
            same,
            f"python {p['status']} {p['type']} {json.dumps(pb)[:3000]}\n        rust   {q['status']} {q['type']} {json.dumps(qb)[:3000]}",
        )
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {json.dumps(pb)[:400]}")
        compare_upstream(name, p["upstream"], q["upstream"])
        if s3 and p["s3"] != q["s3"]:
            check(f"{name}: MinIO contents", False, f"python {p['s3']}\n        rust   {q['s3']}")
        return pb, qb

    async def differ(name, method, path, tok, body, py_status, rs_status, rs_message):
        """A difference by design (§4): Python answers `py_status`, Rust `rs_status` with
        `rs_message`, sending nothing upstream and leaving MinIO as it was."""
        start = S3.snapshot()
        take_all()
        r = await send(py, method, path, tok, body, None, None)
        check(f"python: {name} [{r.status_code}]", r.status_code == py_status, f"{r.status_code} {r.text[:600]}")
        S3.restore(start)
        take_all()
        q = await send(rs, method, path, tok, body, None, None)
        msg = body_of(q).get("message") if isinstance(body_of(q), dict) else None
        check(f"rust: {name} [{q.status_code}]", q.status_code == rs_status and msg == rs_message, f"{q.status_code} {q.text[:600]}")
        sent = take_all()
        check(f"rust: {name}: nothing sent upstream", all(not v for v in sent.values()), json.dumps({k: len(v) for k, v in sent.items()}))
        check(f"rust: {name}: MinIO unchanged", S3.snapshot() == start)
        S3.restore(start)

    async def until_loaded(client, limit=60):
        for _ in range(limit * 4):
            r = await client.get(f"{P}/catalog/stats", headers={"Authorization": f"Bearer {t_admin}"})
            if r.status_code == 200 and not r.json().get("loading"):
                return True
            await asyncio.sleep(0.25)
        return False

    try:
        # ==================================================================
        print("\n=== A. the firing counts load in the background ===")
        es.mode["delay"] = 1.0
        for tag, client in (("python", py), ("rust", rs)):
            take_all()
            r = await send(client, "GET", f"{P}/catalog/wazuh-rules", t_analyst, None, None, None)
            cold = body_of(r)
            s = await send(client, "GET", f"{P}/catalog/stats", t_analyst, None, None, None)
            check(
                f"{tag}: the first Wazuh listing answers at once, the stats say loading",
                r.status_code == 200 and body_of(s).get("loading") is True,
                json.dumps(body_of(s))[:400],
            )
            check(
                f"{tag}: nothing loaded yet",
                cold.get("firing_stats_last_refresh") is None and all(x.get("hits_30d") == 0 for x in cold.get("rules", [])),
                json.dumps(cold)[:400],
            )
            check(f"{tag}: the background refresh finished", await until_loaded(client))
            if tag == "python":
                py_bg = take_all()
                cold_py = cold
            else:
                compare_upstream("background firing refresh", py_bg, take_all())
                a_, b_ = mask_clocks(cold_py, cold)
                check("the two cold listings", a_ == b_, f"python {json.dumps(a_)[:1500]}\n        rust   {json.dumps(b_)[:1500]}")
        es.mode["delay"] = 0

        # ==================================================================
        print("\n=== B. tokens and scopes ===")
        await both("rules: no token", "GET", P)
        await both("rules: garbage token", "GET", P, "garbage")
        await both("rules: 2fa temp token", "GET", P, token(ADMIN, [], type="2fa_pending"))
        await both("rules: a token without scopes", "GET", P, token(ADMIN, []))
        await both("refresh: portal user", "POST", f"{P}/refresh", t_portal)
        await both("execute: portal user", "POST", f"{P}/execute", t_portal, {"rule_id": "x", "index_pattern": "y"})
        await both("execute: portal user, malformed JSON", "POST", f"{P}/execute", t_portal, raw=b"{")
        await both("execute: no token, malformed JSON", "POST", f"{P}/execute", raw=b"{")
        await both("custom-repos: portal user", "GET", f"{P}/custom-repos", t_portal)

        # ==================================================================
        print("\n=== C. rule lists and lookups ===")
        await both("list: analyst", "GET", P, t_analyst)
        await both("list: portal user", "GET", P, t_portal)
        for q in (
            "platform=windows",
            "platform=linux&limit=2",
            "platform=office365",
            "platform=nope",
            "category=syslog",
            "category=eid_01_process_creation&category=web",
            "status=production",
            "status=Production",
            "severity=high",
            "severity=bogus",
            "mitre_id=T1059",
            "mitre_id=t1136.001",
            "search=LSASS",
            "search=%20",
            "has_graylog=true",
            "has_graylog=false",
            "has_graylog=maybe",
            "provenance=catalog",
            "provenance=custom",
            "provenance=other",
            "skip=5&limit=3",
            "skip=-1",
            "limit=0",
            "limit=1001",
            "limit=abc",
            "skip=1e3",
            "limit=10&skip=10000",
        ):
            await both(f"list ?{q}", "GET", f"{P}?{q}", t_analyst)
        for sub in ("linux", "windows", "powershell", "cve"):
            await both(f"{sub}", "GET", f"{P}/{sub}", t_analyst)
            await both(f"{sub} ?limit=1&skip=1", "GET", f"{P}/{sub}?limit=1&skip=1", t_analyst)
        await both("cve ?search=CVE-2021", "GET", f"{P}/cve?search=CVE-2021&status=experimental", t_analyst)
        await both("stats", "GET", f"{P}/stats", t_portal)
        await both("categories", "GET", f"{P}/categories", t_portal)
        for rid in ("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "parity-agg-0001", "parity-minimal-0001", "nope", "%20", "PARITY-AGG-0001"):
            await both(f"by id {rid}", "GET", f"{P}/id/{rid}", t_analyst)
        for name in (
            "Linux User Account Creation Detection",
            "linux_user_account_creation_detection",
            "LINUX-USER-ACCOUNT-CREATION-DETECTION",
            "Parity%20Minimal%20Rule",
            "parity count rule",
            "a/b/c",
            "nope",
            "%E2%9C%93",
        ):
            await both(f"by name {name}", "GET", f"{P}/name/{name}", t_analyst)
        BI = f"{P}/by-ids"
        await both("by-ids: no body", "POST", BI, t_analyst)
        await both("by-ids: malformed", "POST", BI, t_analyst, raw=b"{")
        await both("by-ids: empty object", "POST", BI, t_analyst, {})
        await both("by-ids: not a list", "POST", BI, t_analyst, {"ids": "parity-agg-0001"})
        await both(
            "by-ids: mixed",
            "POST",
            BI,
            t_analyst,
            {"ids": ["parity-agg-0001", "nope", "parity-agg-0001", "", "parity-minimal-0001"]},
        )
        await both("by-ids: wrong item types", "POST", BI, t_analyst, {"ids": [1, None, True]})
        await both("by-ids: too many", "POST", BI, t_analyst, {"ids": [str(i) for i in range(501)]})
        await both("by-ids: portal user", "POST", BI, t_portal, {"ids": []})

        # ==================================================================
        print("\n=== D. ATT&CK ===")
        await both("coverage", "GET", f"{P}/mitre/coverage", t_portal)
        for q in (
            "platform=windows",
            "platform=bad",
            "category=syslog",
            "status=experimental",
            "provenance=custom",
            "include_subtechniques=false",
            "has_graylog=true",
        ):
            await both(f"coverage ?{q}", "GET", f"{P}/mitre/coverage?{q}", t_analyst)
        for tid in ("T1059", "T1059.001", "t1078", "T1222", "T0000", "TA0002", "%20"):
            await both(f"technique {tid}", "GET", f"{P}/mitre/{tid}", t_analyst)
        await both("mitre refresh: portal user", "POST", f"{P}/mitre/refresh", t_portal)
        await both("mitre refresh", "POST", f"{P}/mitre/refresh", t_analyst)
        gh_raw.mode["mitre_fail"] = True
        await both("mitre refresh: GitHub answers 503", "POST", f"{P}/mitre/refresh", t_admin)
        await both("coverage after a failed refresh", "GET", f"{P}/mitre/coverage", t_analyst)
        gh_raw.mode.pop("mitre_fail")
        await both("mitre refresh again", "POST", f"{P}/mitre/refresh", t_admin)

        # ==================================================================
        print("\n=== E. the rule search and the Graylog query ===")
        EX = f"{P}/execute"
        for label, body in (
            ("empty object", {}),
            ("unknown rule", {"rule_id": "nope", "index_pattern": "wazuh-alerts-*"}),
            ("missing required parameter", {"rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "index_pattern": "wazuh-alerts-*"}),
            (
                "parameters",
                {
                    "rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "index_pattern": "wazuh-alerts-*",
                    "parameters": {"AGENT_NAME": "web-01", "CUSTOMER_CODE": A, "EXTRA": 1},
                },
            ),
            (
                "parameters of odd types, size",
                {
                    "rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "index_pattern": "wazuh-*",
                    "parameters": {"AGENT_NAME": 7, "CUSTOMER_CODE": None, "START_TIME": ["a"], "END_TIME": {"x": 1}},
                    "size": 3,
                },
            ),
            ("size out of range", {"rule_id": "x", "index_pattern": "y", "size": 0}),
            ("parameters not an object", {"rule_id": "x", "index_pattern": "y", "parameters": []}),
            ("missing index", {"rule_id": "parity-agg-0001", "index_pattern": "missing-index"}),
            ("rule without search", {"rule_id": "parity-minimal-0001", "index_pattern": "wazuh-alerts-*"}),
            (
                "bad query",
                {
                    "rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "index_pattern": "bad-query",
                    "parameters": {"AGENT_NAME": "a", "CUSTOMER_CODE": "b"},
                },
            ),
        ):
            await both(f"execute: {label}", "POST", EX, t_analyst, body)
        GQ = f"{P}/graylog"
        for label, body in (
            ("empty", {}),
            ("unknown", {"rule_id": "nope"}),
            ("no graylog block", {"rule_id": "parity-minimal-0001"}),
            ("aggregation rule", {"rule_id": "parity-agg-0001"}),
            ("with parameters", {"rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "parameters": {"AGENT_NAME": "x"}}),
            ("parameters wrong type", {"rule_id": "parity-agg-0001", "parameters": "x"}),
        ):
            await both(f"graylog query: {label}", "POST", GQ, t_analyst, body)

        # ==================================================================
        print("\n=== F. Graylog event definitions ===")
        CK = f"{P}/provision/graylog/check"
        await both("check: portal user", "POST", CK, t_portal, {"ids": ["parity-agg-0001", "parity-count-0001", "nope"]})
        await both("check: empty", "POST", CK, t_analyst, {"ids": []})
        PR = f"{P}/provision/graylog"
        BU = f"{P}/provision/graylog/bulk"

        async def graylog_checks(version):
            gl.mode["version"] = version
            defs = copy.deepcopy(samples.GRAYLOG_EVENT_DEFINITIONS)

            def reset_defs(defs=defs):
                gl.mode["definitions"] = copy.deepcopy(defs)

            for label, body in (
                ("aggregation rule", {"rule_id": "parity-agg-0001", "streams": ["s1", "s2"], "event_limit": 50}),
                (
                    "count rule, custom title, priority",
                    {"rule_id": "parity-count-0001", "custom_title": "MY TITLE", "priority": 1, "search_within_seconds": 600},
                ),
                ("plain rule", {"rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}),
                ("disabled aggregation", {"rule_id": "parity-agg-off-0001", "custom_title": ""}),
                ("no graylog query", {"rule_id": "parity-minimal-0001"}),
                ("unknown rule", {"rule_id": "nope"}),
                ("out of range", {"rule_id": "parity-agg-0001", "search_within_seconds": 59, "priority": 4, "event_limit": 0}),
                ("wrong types", {"rule_id": 1, "streams": "s", "custom_title": 3}),
            ):
                await both(f"graylog {version}: provision {label}", "POST", PR, t_analyst, body, before=reset_defs)
            gl.mode["definitions"] = copy.deepcopy(defs)
            await both(f"graylog {version}: provision once", "POST", PR, t_analyst, {"rule_id": "parity-count-0001"}, before=reset_defs)
            gl.mode["definitions"] = defs + [samples.graylog_event_definition("6600000000000000000000ff", "PARITY - COUNT - RULE")]
            await both(f"graylog {version}: provision a title that exists", "POST", PR, t_analyst, {"rule_id": "parity-count-0001"})
            await both(f"graylog {version}: check after", "POST", CK, t_analyst, {"ids": ["parity-count-0001", "parity-agg-0001"]})
            for label, body in (
                (
                    "three and a missing one",
                    {
                        "rule_ids": ["parity-agg-0001", "parity-count-0001", "nope", "parity-minimal-0001", "parity-agg-0001"],
                        "streams": ["s"],
                    },
                ),
                ("empty", {"rule_ids": []}),
                ("too many", {"rule_ids": ["x"] * 201}),
            ):
                await both(f"graylog {version}: bulk {label}", "POST", BU, t_analyst, body, before=reset_defs)
            gl.mode["create_fail"] = True
            await both(
                f"graylog {version}: Graylog refuses the definition",
                "POST",
                PR,
                t_analyst,
                {"rule_id": "parity-agg-0001"},
                before=reset_defs,
            )
            await both(
                f"graylog {version}: bulk, Graylog refuses",
                "POST",
                BU,
                t_analyst,
                {"rule_ids": ["parity-agg-0001", "parity-count-0001"]},
                before=reset_defs,
            )
            gl.mode.pop("create_fail")
            gl.mode["defs_fail"] = True
            await both(f"graylog {version}: listing fails", "POST", PR, t_analyst, {"rule_id": "parity-agg-0001"})
            await both(f"graylog {version}: check, listing fails", "POST", CK, t_analyst, {"ids": ["parity-agg-0001"]})
            await both(f"graylog {version}: bulk, listing fails", "POST", BU, t_analyst, {"rule_ids": ["parity-agg-0001"]})
            gl.mode.pop("defs_fail")

        await graylog_checks(6)
        gl.mode["version"] = 6
        gl.mode["v6"] = "5.1.2"
        await both(
            "graylog 5.1: no event_limit",
            "POST",
            PR,
            t_analyst,
            {"rule_id": "parity-agg-0001"},
            before=lambda: gl.mode.update(definitions=[]),
        )
        gl.mode.pop("v6")

        # ==================================================================
        print("\n=== G. the catalog views ===")
        await both("catalog stats", "GET", f"{P}/catalog/stats", t_portal)
        await both("stories", "GET", f"{P}/catalog/stories", t_portal)
        for q in ("search=linux", "search=PARITY", "page=2&page_size=3", "page=0", "page_size=1000", "sort=name", "search=%2F"):
            await both(f"stories ?{q}", "GET", f"{P}/catalog/stories?{q}", t_analyst)
        for story in (
            "Account%20Manipulation",
            "Parity%20Story%20/%20With%20Slash",
            "parity%20story%20%2F%20with%20slash",
            "nope",
            "%20",
            "Linux%20Persistence%20Techniques",
        ):
            await both(f"story {unquote(story)}", "GET", f"{P}/catalog/stories/{story}", t_analyst)
        W = f"{P}/catalog/wazuh-rules"
        await both("wazuh rules", "GET", W, t_portal)
        for q in ("search=sshd", "page=2&page_size=2", "customer_code=" + A, "customer_code=", "customer_code=%20", "search=5710"):
            await both(f"wazuh rules ?{q}", "GET", f"{W}?{q}", t_analyst)
        await both("wazuh rules: analyst asks for B", "GET", f"{W}?customer_code={B}", t_analyst)
        await both("wazuh rules: admin asks for B", "GET", f"{W}?customer_code={B}", t_admin)
        await both("wazuh rules: admin asks for an unknown customer", "GET", f"{W}?customer_code=NOPE{SFX}", t_admin)
        await both("wazuh rules: unassigned analyst asks for A", "GET", f"{W}?customer_code={A}", t_nobody)
        for rid in ("5710", "100002", "100004", "2", "99999", "abc", "5710.0", "-1", "%205710", "0x10"):
            await both(f"wazuh rule {rid}", "GET", f"{W}/{rid}", t_portal)
        await both("coverage gaps", "GET", f"{P}/catalog/coverage-gaps", t_portal)
        for tid in ("T1001", "T1059", "T1486", "t1595", "T0000", "T1110.001"):
            await both(f"coverage gap {tid}", "GET", f"{P}/catalog/coverage-gaps/{tid}", t_analyst)
        await both("frameworks", "GET", f"{P}/catalog/compliance/frameworks", t_portal)
        for fw in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13", "PCI_DSS", "nope"):
            await both(f"compliance {fw}", "GET", f"{P}/catalog/compliance/{fw}", t_analyst)
        for fw, control in (
            ("pci_dss", "10.2.4"),
            ("gdpr", "IV_35.7.d"),
            ("tsc", "CC6.1"),
            ("pci_dss", "nope"),
            ("nope", "1"),
            ("nist_800_53", "AU.14"),
            ("pci_dss", "10.2.4/x"),
        ):
            await both(f"compliance {fw}/{control}", "GET", f"{P}/catalog/compliance/{fw}/{control}", t_analyst)
        LT = f"{W}/test"
        for label, body in (
            ("matched", {"event": "Oct 17 sshd[1]: Invalid user admin from 10.0.0.1"}),
            ("no rule", {"event": "no-rule line", "log_format": "json", "location": "x"}),
            ("empty output", {"event": "empty-output"}),
            ("rule zero", {"event": "rule-zero"}),
            ("rule id text", {"event": "rule-text"}),
            ("rule not a dict", {"event": "rule-list"}),
            ("rule odd values", {"event": "rule-float"}),
            ("Wazuh 400", {"event": "wazuh-400"}),
            ("Wazuh 500", {"event": "wazuh-500"}),
            ("blank event", {"event": "   "}),
            ("no event", {}),
            ("event not a string", {"event": 5}),
        ):
            await both(f"logtest: {label}", "POST", LT, t_portal, body)
        await both("logtest: GET is the rule-id route", "GET", LT, t_portal)

        # ==================================================================
        print("\n=== H. the rule editor: validate ===")
        V = f"{P}/validate"
        LINT = [
            "",
            "name: [unclosed",
            "- a list",
            "just text",
            "42",
            "name: x\n",
            AGG_RULE,
            COUNT_RULE,
            MINIMAL_RULE,
            DISABLED_AGG,
            "name: Bad Agg\nid: not-a-uuid\nstatus: weird\ndate: 2026-13-45\ngraylog:\n  query: 'a:1 AND ${UNSET}'\naggregation:\n  enabled: true\n  function: avg\n  condition: '=>'\n  threshold: -1\n  window: 10x\n",
            "name: Fields\nid: 8b1f8c3e-2f63-4d5a-9a43-2b5f6c7d8e9f\ndescription: d\ngraylog:\n  query: '_exists_:foo AND NOT bar:baz OR rule.groups:(a OR b) AND agent.name:\"x\"'\ntags:\n  mitre_attack_id: [T1059, TX, t1059.001]\n",
            "name: Dup\nname: Again\n",
            "name: Tabs\n\tid: x\n",
            "name: Types\nid: 5\ngraylog: query-string\naggregation: [1, 2]\ntags: none\n",
            "name: Nested\ngraylog:\n  query: ''\naggregation:\n  enabled: true\n  function: distinct_count\n  window: 5m\n  threshold: 3\n  condition: '>'\n",
            "name: Window\ngraylog:\n  query: x:1\naggregation:\n  enabled: true\n  function: count\n  window: 30\n  execute_every: 0m\n  threshold: 2.5\n  condition: '>='\n  group_by: field_a\n",
            "name: 'Unicode ✓'\nid: 8B1F8C3E-2F63-4D5A-9A43-2B5F6C7D8E9F\ndate: '2026-02-30'\nreferences: http://x\nstatus: production\ngraylog:\n  query: ü:1\n",
            "%YAML 1.1\n---\nname: Doc\n...\n",
            "name: anchors\nbase: &b {query: 'x:1'}\ngraylog: *b\n",
        ]
        for i, y in enumerate(LINT):
            await both(f"validate #{i}", "POST", V, t_analyst, {"yaml": y})
        await both("validate: no yaml", "POST", V, t_analyst, {})
        await both("validate: yaml not a string", "POST", V, t_analyst, {"yaml": ["a"]})
        await both("validate: portal user", "POST", V, t_portal, {"yaml": "name: x"})

        # ==================================================================
        print("\n=== I. backtest ===")
        BT = f"{P}/backtest"
        gl.mode.update(version=6, rows=30)
        for label, body in (
            ("aggregation rule", {"yaml": AGG_RULE, "customer_code": A}),
            ("count rule, a day", {"yaml": COUNT_RULE, "customer_code": A, "range_seconds": 86400}),
            (
                "plain rule, 30 days",
                {
                    "yaml": RAW[f"/{CATALOG_REPO}/{CATALOG_BRANCH}/detections/syslog/linux_add_user_account.yaml"],
                    "customer_code": A,
                    "range_seconds": 2592000,
                },
            ),
            ("no query", {"yaml": MINIMAL_RULE, "customer_code": A}),
            ("not a mapping", {"yaml": "- x", "customer_code": A}),
            ("unparseable", {"yaml": "name: [", "customer_code": A}),
            ("range too small", {"yaml": AGG_RULE, "customer_code": A, "range_seconds": 299}),
            ("missing customer", {"yaml": AGG_RULE}),
            ("empty customer", {"yaml": AGG_RULE, "customer_code": ""}),
        ):
            await both(f"backtest: {label}", "POST", BT, t_analyst, body)
        for mode_ in ("error-list", "error-dict", "error-text", "not-json", "empty"):
            gl.mode["search"] = mode_
            await both(f"backtest: Graylog {mode_}", "POST", BT, t_analyst, {"yaml": AGG_RULE, "customer_code": A})
        gl.mode.pop("search")
        gl.mode["fields"] = "fail"
        await both("backtest: the field listing fails", "POST", BT, t_analyst, {"yaml": AGG_RULE, "customer_code": A})
        gl.mode["fields"] = [{"name": "timestamp"}]
        await both("backtest: a stream with few fields", "POST", BT, t_analyst, {"yaml": AGG_RULE, "customer_code": A})
        gl.mode.pop("fields")
        gl.mode["rows"] = 0
        await both("backtest: no events", "POST", BT, t_analyst, {"yaml": AGG_RULE, "customer_code": A})
        gl.mode["rows"] = 30
        await both("backtest: admin, a customer without a stream", "POST", BT, t_admin, {"yaml": AGG_RULE, "customer_code": B})
        await sql("UPDATE customersmeta SET customer_meta_graylog_stream = 'string' WHERE customer_code = :c", c=A)
        await both("backtest: a placeholder stream", "POST", BT, t_analyst, {"yaml": AGG_RULE, "customer_code": A})
        await sql("UPDATE customersmeta SET customer_meta_graylog_stream = :s WHERE customer_code = :c", s=STREAM_A, c=A)
        await differ(
            "backtest: analyst names B",
            "POST",
            BT,
            t_analyst,
            {"yaml": AGG_RULE, "customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )

        # ==================================================================
        print("\n=== J. custom repositories ===")
        CR = f"{P}/custom-repos"
        await both("list: nothing stored", "GET", CR, t_analyst)
        await both("get A: nothing stored", "GET", f"{CR}/{A}", t_analyst)
        await both("delete A: nothing stored", "DELETE", f"{CR}/{A}", t_analyst)
        await both("put A: no body", "PUT", f"{CR}/{A}", t_analyst)
        await both("put A: malformed", "PUT", f"{CR}/{A}", t_analyst, raw=b"{")
        await both("put A: wrong types", "PUT", f"{CR}/{A}", t_analyst, {"repo": 1, "enabled": "maybe"})
        await both("put B: analyst", "PUT", f"{CR}/{B}", t_analyst, {"repo": "x/y"})
        await both("get B: analyst", "GET", f"{CR}/{B}", t_analyst)
        await both("put A: portal user", "PUT", f"{CR}/{A}", t_portal, {"repo": "x/y"})
        await both(
            "put A",
            "PUT",
            f"{CR}/{A}",
            t_analyst,
            {"repo": f"  {CUSTOM_A_REPO} ", "branch": f" {CUSTOM_A_BRANCH} ", "token": "read-token-a"},
        )
        S3_A = S3.snapshot()
        await both("get A", "GET", f"{CR}/{A}", t_analyst)
        await both(
            "put B: admin, disabled, blank branch",
            "PUT",
            f"{CR}/{B}",
            t_admin,
            {"repo": CUSTOM_B_REPO, "branch": "  ", "enabled": False, "token": ""},
        )
        S3.restore(S3_A)
        # Stored once more by hand, so both backends see it.
        await send(py, "PUT", f"{CR}/{B}", t_admin, {"repo": CUSTOM_B_REPO, "branch": "  ", "enabled": False, "token": ""}, None, None)
        take_all()
        await both("list: admin", "GET", CR, t_admin)
        # By design (§4): a scoped caller lists their customers' pointers only.
        r = await send(py, "GET", CR, t_analyst, None, None, None)
        check(
            "python: list: analyst sees B's pointer too",
            r.status_code == 200 and [x["customer_code"] for x in r.json()["repos"]] == [A, B],
            r.text[:600],
        )
        take_all()
        q = await send(rs, "GET", CR, t_analyst, None, None, None)
        expected = {
            **r.json(),
            "message": "1 custom repositories configured",
            "repos": [x for x in r.json()["repos"] if x["customer_code"] == A],
        }
        check("rust: list: analyst sees A's pointer only", q.status_code == 200 and q.json() == expected, q.text[:600])
        take_all()
        q = await send(rs, "GET", CR, t_nobody, None, None, None)
        check("rust: list: an unassigned analyst sees none", q.status_code == 200 and q.json()["repos"] == [], q.text[:600])
        take_all()
        await both("list: an unassigned analyst asks for nothing", "GET", f"{CR}/{B}", t_nobody)
        # A record that is not JSON, and one that is a list.
        S3.buckets["copilot-searches"]["custom-repos/garbage.json"] = (b"not json", "application/json")
        S3.buckets["copilot-searches"]["custom-repos/listy.json"] = (b"[1, 2]", "application/json")
        S3.buckets["copilot-searches"]["custom-repos/readme.txt"] = (b"{}", "text/plain")
        await both("list: admin, odd records", "GET", CR, t_admin)
        del S3.buckets["copilot-searches"]["custom-repos/listy.json"]
        S3.buckets["copilot-searches"][f"custom-repos/{A}x.json"] = (
            json.dumps({"repo": None, "branch": None, "token": 5, "enabled": 0}).encode(),
            "application/json",
        )
        await both("list: admin, odd values", "GET", CR, t_admin)
        del S3.buckets["copilot-searches"][f"custom-repos/{A}x.json"]
        del S3.buckets["copilot-searches"]["custom-repos/garbage.json"]
        del S3.buckets["copilot-searches"]["custom-repos/readme.txt"]

        TR = f"{CR}/test"
        for label, body in (
            ("ok", {"repo": f"probe-{SFX}/ok"}),
            ("unknown branch", {"repo": f"probe-{SFX}/ok", "branch": "nope"}),
            ("401", {"repo": f"e401-{SFX}/x", "token": "t"}),
            ("403", {"repo": f"e403-{SFX}/x"}),
            ("500", {"repo": f"e500-{SFX}/x"}),
            ("not JSON", {"repo": f"notjson-{SFX}/x"}),
            ("A's stored token", {"repo": f"probe-{SFX}/ok", "customer_code": A}),
            ("a token beats the stored one", {"repo": f"probe-{SFX}/ok", "customer_code": A, "token": "given"}),
            ("a customer without a pointer", {"repo": f"probe-{SFX}/ok", "customer_code": "NOPE"}),
            ("no repo", {}),
            ("odd path", {"repo": "a b/c?d#e", "branch": "x/y"}),
        ):
            await both(f"test repo: {label}", "POST", TR, t_admin, body)
        await differ(
            "test repo: analyst names B",
            "POST",
            TR,
            t_analyst,
            {"repo": f"probe-{SFX}/ok", "customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )
        await both("test repo: analyst names A", "POST", TR, t_analyst, {"repo": f"probe-{SFX}/ok", "customer_code": A})

        # ==================================================================
        print("\n=== K. refresh with the custom repositories ===")
        await both("refresh: analyst", "POST", f"{P}/refresh", t_analyst)
        await both("stats after", "GET", f"{P}/stats", t_analyst)
        await both("list ?provenance=custom", "GET", f"{P}?provenance=custom", t_analyst)
        await both("by id: the custom rule", "GET", f"{P}/id/acme-custom-0001", t_analyst)
        await both("by id: the duplicate kept the catalog's", "GET", f"{P}/id/parity-minimal-0001", t_analyst)
        await both("coverage ?provenance=custom", "GET", f"{P}/mitre/coverage?provenance=custom", t_analyst)
        await both("stories after", "GET", f"{P}/catalog/stories", t_analyst)
        await both("catalog stats after", "GET", f"{P}/catalog/stats", t_analyst)

        # ==================================================================
        print("\n=== L. publish ===")
        PB = f"{P}/publish"
        own = (CUSTOM_A_REPO, "detections/custom/acme_rule.yaml", CUSTOM_A_BRANCH)

        def published(*keys):
            return lambda: gh_api.mode.__setitem__("published", {k: "abc123" for k in keys})

        NEW_RULE = (
            "name: Brand New Rule\nid: 0f8b2b0e-1a2b-4c3d-9e8f-001122334455\nstatus: production\ndescription: d\ngraylog:\n  query: x:1\n"
        )
        for label, body in (
            ("new rule", {"yaml": NEW_RULE, "customer_code": A}),
            ("message and path", {"yaml": NEW_RULE, "customer_code": A, "message": "msg", "path": " detections/team/new.yml "}),
            ("bad path", {"yaml": NEW_RULE, "customer_code": A, "path": "README.md"}),
            ("dotdot path", {"yaml": NEW_RULE, "customer_code": A, "path": "detections/../x.yaml"}),
            ("backslash path", {"yaml": NEW_RULE, "customer_code": A, "path": "detections\\x.yaml"}),
            ("lint errors", {"yaml": "name: Bad\nid: nope\n", "customer_code": A}),
            ("no name", {"yaml": "id: x\n", "customer_code": A}),
            ("not a mapping", {"yaml": "[1]", "customer_code": A}),
            ("unparseable", {"yaml": "a: [", "customer_code": A}),
            ("catalog id", {"yaml": AGG_RULE.replace("parity-agg-0001", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"), "customer_code": A}),
            ("empty customer", {"yaml": NEW_RULE, "customer_code": ""}),
            ("Graylog rejects", {"yaml": NEW_RULE, "customer_code": A, "path": "detections/reject.yaml"}),
            ("plain-text failure", {"yaml": NEW_RULE, "customer_code": A, "path": "detections/plainfail.yaml"}),
            ("read fails", {"yaml": NEW_RULE, "customer_code": A, "path": "detections/readfail.yaml"}),
        ):
            await both(f"publish: {label}", "POST", PB, t_analyst, body, before=published())
        await both(
            "publish: an update of the tenant's own rule",
            "POST",
            PB,
            t_analyst,
            {"yaml": CUSTOM_A_FILES["detections/custom/acme_rule.yaml"], "customer_code": A, "path": "detections/custom/acme_rule.yaml"},
            before=published(own),
        )
        await both(
            "publish: the tenant's rule to another path",
            "POST",
            PB,
            t_analyst,
            {"yaml": CUSTOM_A_FILES["detections/custom/acme_rule.yaml"], "customer_code": A},
            before=published(own),
        )
        await both("publish: admin, B has no write token", "POST", PB, t_admin, {"yaml": NEW_RULE, "customer_code": B})
        await both("publish: admin, unknown customer", "POST", PB, t_admin, {"yaml": NEW_RULE, "customer_code": f"NOPE{SFX}"})
        await differ(
            "publish: analyst names B",
            "POST",
            PB,
            t_analyst,
            {"yaml": NEW_RULE, "customer_code": B},
            200,
            403,
            f"Access denied to customer {B}",
        )
        await both("delete B: admin", "DELETE", f"{CR}/{B}", t_admin)
        await both("delete A", "DELETE", f"{CR}/{A}", t_analyst)

        # ==================================================================
        print("\n=== N. rules of odd shapes ===")
        normal_tree = TREES[(CATALOG_REPO, CATALOG_BRANCH)]
        for phase, files in ODD_PHASES.items():
            for path_, text_ in files.items():
                RAW[f"/{CATALOG_REPO}/{CATALOG_BRANCH}/{path_}"] = text_
            TREES[(CATALOG_REPO, CATALOG_BRANCH)] = normal_tree[:20] + [{"path": p_, "type": "blob"} for p_ in files]
            await both(f"{phase}: refresh", "POST", f"{P}/refresh", t_admin)
            for label, method, path_, body in ODD_BATTERY:
                await both(f"{phase}: {label}", method, path_, t_analyst, body)
        TREES[(CATALOG_REPO, CATALOG_BRANCH)] = normal_tree
        await both("back to the corpus: refresh", "POST", f"{P}/refresh", t_admin)
        await both("back to the corpus: stats", "GET", f"{P}/stats", t_analyst)

        # ==================================================================
        print("\n=== M. the Wazuh caches when Wazuh fails (a second Rust instance, cold) ===")
        mgr.mode["rules_fail"] = True
        es.mode["firing_fail"] = True
        rust.terminate()
        rust.wait(timeout=10)
        take_all()
        await rules_cache.refresh()
        wazuh_rules_cache._rules, wazuh_rules_cache._last_refresh, wazuh_rules_cache._unavailable_reason = {}, None, None
        await wazuh_rules_cache.refresh()
        wazuh_firing_stats_cache._stats, wazuh_firing_stats_cache._last_refresh = {}, None
        wazuh_firing_stats_cache._unavailable_reason, wazuh_firing_stats_cache._winning_field = None, None
        py_cold = take_all()
        rust = start_rust(gh_api, gh_raw)
        await asyncio.sleep(1)
        await wait_quiet([gh_api, gh_raw, mgr, S3])
        rs_cold = take_all()
        compare_upstream(
            "cold start, Wazuh failing",
            {k: v for k, v in py_cold.items() if k != "gh_raw"},
            {k: v for k, v in rs_cold.items() if k != "gh_raw"},
        )
        for client in (py, rs):
            await send(client, "GET", W, t_analyst, None, None, None)
            await until_loaded(client)
        take_all()
        await both("wazuh rules, Wazuh down", "GET", W, t_analyst)
        await both("wazuh rules ?customer_code=A, Wazuh down", "GET", f"{W}?customer_code={A}", t_analyst)
        await both("catalog stats, Wazuh down", "GET", f"{P}/catalog/stats", t_analyst)
        await both("wazuh rule 5710, Wazuh down", "GET", f"{W}/5710", t_analyst)
        await both("compliance, Wazuh down", "GET", f"{P}/catalog/compliance/pci_dss", t_analyst)
        await both("coverage gaps, Wazuh down", "GET", f"{P}/catalog/coverage-gaps", t_analyst)
        mgr.mode.pop("rules_fail")
        es.mode.pop("firing_fail")

        # Graylog 7, on a fresh process: both backends cache the major version for 5 minutes.
        from app.connectors.graylog.utils import universal as graylog_universal

        graylog_universal._GRAYLOG_VERSION_CACHE.clear()
        await graylog_checks(7)
    finally:
        await py.aclose()
        await rs.aclose()
        rust.terminate()
        try:
            rust.wait(timeout=10)
        except subprocess.TimeoutExpired:
            rust.kill()
        await cleanup()
        for rec in (gh_api, gh_raw, mgr, es, gl):
            rec.stop()
        S3.server.shutdown()

    failed = [n for n, passed in results if not passed]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
