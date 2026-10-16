"""Parity of the Rust customer WAF, stack provisioning and customer provisioning ports with this
backend — NOT collected by pytest (needs a live MySQL and the Rust binary; run by
scripts/rust-parity.sh).

The real FastAPI routers (in-process) and Rust instances this suite starts (no legacy backend,
connector cache off) answer the same requests on one database. The tools are local stand-ins that
record every request: a SOCFortress WAF admin API (plain HTTP, and HTTPS with a certificate from a
test CA), and Graylog (6.x, and 7.x on a Rust instance of its own, since both backends cache the
version). For each request the suite compares the status, the response (byte for byte, or with
created ids and fresh timestamps masked), every request each backend sent to a tool (method,
target, the headers that matter, body bytes) and the rows the request left. Deliberate
differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_provisioning_e2e.py scripts/rust-parity.sh

Ports (all overridable): PROVISIONING_PARITY_RUST_PORT (5751), PROVISIONING_PARITY_RUST_NOKEY_PORT
(5752, no WAF key and no alert-forwarding settings), PROVISIONING_PARITY_RUST7_PORT (5753, Graylog
7), PROVISIONING_STUB_PORT (5754, Graylog), WAF_STUB_PORT (5755), WAF_TLS_STUB_PORT (5756).
`PROVISIONING_PARITY_SECTIONS=waf` picks the sections.
"""

import asyncio
import copy
import datetime
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs
from urllib.parse import urlsplit

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import connector_samples as samples  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("PROVISIONING_PARITY_RUST_PORT", "5751"))
RS_NOKEY_PORT = int(os.environ.get("PROVISIONING_PARITY_RUST_NOKEY_PORT", "5752"))
RS7_PORT = int(os.environ.get("PROVISIONING_PARITY_RUST7_PORT", "5753"))
STUB_PORT = int(os.environ.get("PROVISIONING_STUB_PORT", "5754"))
WAF_PORT = int(os.environ.get("WAF_STUB_PORT", "5755"))
WAF_TLS_PORT = int(os.environ.get("WAF_TLS_STUB_PORT", "5756"))
CLOSED_PORT = 1

WAF_KEY = Fernet.generate_key().decode()
OTHER_KEY = Fernet.generate_key().decode()
TOKEN = f"wafst_parity{SFX}abcdefghijklmnop"
ENV = {
    "WAF_TOKEN_ENCRYPTION_KEY": WAF_KEY,
    "WAF_SYSLOG_PORT_RANGE": "5600-5603",
    "WAF_SYSLOG_DEFAULT_HOST": "graylog.parity.test",
    "ALERT_FORWARDING_IP": "10.9.8.7",
    "GRAYLOG_API_HEADER_VALUE": "parity-header-secret",
}
NOKEY_UNSET = ("WAF_TOKEN_ENCRYPTION_KEY", "ALERT_FORWARDING_IP", "GRAYLOG_API_HEADER_VALUE", "WAF_SYSLOG_DEFAULT_HOST")
os.environ.update(ENV)

CUST_A, CUST_B = f"WAFA{SFX}", f"WAFB{SFX}"
ADMIN, ANALYST, ANALYST_B, PORTAL = f"waf_admin{SFX}", f"waf_analyst{SFX}", f"waf_analyst_b{SFX}", f"waf_portal{SFX}"
UNASSIGNED = f"waf_unassigned{SFX}"
USERS = (ADMIN, ANALYST, ANALYST_B, PORTAL, UNASSIGNED)
OUR_CONNECTORS = ("Graylog",)
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


# --- TLS material ---------------------------------------------------------------------------------


def make_tls():
    """A CA and a server certificate for 127.0.0.1 signed by it."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Parity CA {SFX}")])
    start, end = datetime.datetime(2020, 1, 1), datetime.datetime(2040, 1, 1)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    folder = tempfile.mkdtemp(prefix="waf-parity-")
    cert_path, key_path = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode(), cert_path, key_path


CA_PEM, CERT_PATH, KEY_PATH = make_tls()


# --- The stand-ins ----------------------------------------------------------------------------------


class Recorder:
    def __init__(self, headers):
        self.lock = threading.Lock()
        self.requests = []
        self.headers = headers

    def add(self, method, target, headers, body):
        kept = {k: headers.get(k) for k in self.headers if headers.get(k) is not None}
        with self.lock:
            self.requests.append((method, target, kept, body))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


def _json(value):
    return json.dumps(value).encode()


WAF_EVENTS = [
    {
        "id": 501,
        "timestamp": "2026-10-15T10:00:00Z",
        "transaction_id": "tx-1",
        "site_id": 3,
        "client_ip": "203.0.113.9",
        "method": "GET",
        "uri": "/login?u=1' OR 1=1",
        "host": "crm.example.com",
        "rule_id": "942100",
        "action": "blocked",
        "severity": "CRITICAL",
        "anomaly_score": "15",
        "matched_rules": [{"id": "942100", "msg": "SQL Injection Attack Detected via libinjection", "extra": 1}, "not-a-dict"],
        "geoip_country_code": "NL",
        "geoip_country_name": "Netherlands",
        "geoip_city": None,
        "raw_log": {"secret": "never shown"},
        "unknown_field": True,
    },
    {
        "id": "502",
        "timestamp": "2026-10-15T10:01:00.123456+02:00",
        "transaction_id": "tx-2",
        "site_id": None,
        "client_ip": "198.51.100.4",
        "method": "POST",
        "uri": "/",
        "host": "crm.example.com",
        "action": "detected",
    },
]
WAF_STATS = {
    "total_1h": 120,
    "blocked_1h": "30",
    "detected_1h": 12,
    "block_rate": 0.25,
    "top_rules": [{"rule_id": "942100", "count": 20}, {"rule_id": None, "count": 1.0}],
    "top_ips": [{"client_ip": "203.0.113.9", "count": 25}],
    "requests_per_hour": [{"hour": "2026-10-15T09:00:00Z", "count": 60}],
    "attack_categories": [{"category": "sqli", "count": 20}],
    "top_countries": [{"country_code": "NL", "country_name": "Netherlands", "count": 25}],
    "ingestion_lag_seconds": 1.5,
    "events_per_minute": 2,
    "caddy_healthy": True,
    "extra": "dropped",
}
WAF_TI_STATS = {"total_ips": 2, "last_run_at": "2026-10-15T08:00:00Z", "window_days": 7, "min_score": 50}
WAF_TI = [
    {
        "ip_address": "203.0.113.9",
        "block_count": 25,
        "rule_hit_count": 40,
        "total_events": 60,
        "threat_score": 90,
        "top_rules": None,
        "country_code": "NL",
        "first_seen_at": "2026-10-10T00:00:00Z",
        "last_seen_at": "2026-10-15T10:00:00Z",
        "is_blocked": False,
    },
    {
        "ip_address": "198.51.100.4",
        "block_count": 1,
        "rule_hit_count": 2,
        "total_events": 3,
        "threat_score": 51,
        "top_rules": [{"rule_id": "1", "count": 2}],
        "first_seen_at": "2026-10-14T00:00:00",
        "last_seen_at": "2026-10-15T00:00:00",
        "is_blocked": 1,
    },
]
WAF_SITES = [
    {
        "id": 3,
        "name": "CRM",
        "hostname": "crm.example.com",
        "upstream_url": "http://10.0.0.5:80",
        "is_enabled": 1,
        "detection_mode": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "tls": {"key": "x"},
    },
    {"id": "uuid-4", "hostname": "shop.example.com", "is_enabled": True},
]


def ti_block_rule(rule_id, value, enabled=True):
    return {
        "id": f"ti-{rule_id}",
        "rule_id": rule_id,
        "name": f"Threat Intel block {rule_id}",
        "description": "auto",
        "is_enabled": enabled,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": value,
        "conf_text": f'SecRule REMOTE_ADDR "@ipMatch {value}" "id:{rule_id},phase:1,deny,status:403"',
        "created_at": "2026-10-01T00:00:00Z",
    }


class Waf:
    """A SOCFortress WAF admin API: users/me, health, sites, logs, threat intel, custom rules,
    forwarders. Per-test overrides by (method, path)."""

    def __init__(self):
        self.reset()

    def reset(self, roles=("admin",), rules=None, overrides=None):
        self.roles = list(roles)
        self.rules = copy.deepcopy(rules or [])
        self.overrides = dict(overrides or {})
        self.next_rule = 9000
        self.next_forwarder = 70

    def answer(self, method, target, body):
        parts = urlsplit(target)
        path = parts.path
        for key in ((method, target), (method, path)):
            if key in self.overrides:
                return self.overrides[key]
        if method == "GET" and path == "/api/v1/users/me":
            return 200, "application/json", _json({"email": "svc@waf.test", "roles": [{"name": r} for r in self.roles] + ["x"], "id": 5})
        if method == "GET" and path == "/health":
            return 200, "application/json", _json({"status": "ok", "db": "ok", "redis": "ok"})
        if method == "GET" and path == "/api/v1/sites/":
            return 200, "application/json", _json(WAF_SITES)
        if method == "GET" and path == "/api/v1/logs/":
            return 200, "application/json", _json(WAF_EVENTS)
        if method == "GET" and path == "/api/v1/logs/stats":
            return 200, "application/json", _json(WAF_STATS)
        if method == "GET" and path == "/api/v1/threat-intel/stats":
            return 200, "application/json", _json(WAF_TI_STATS)
        if method == "GET" and path == "/api/v1/threat-intel/":
            return 200, "application/json", _json(WAF_TI)
        if method == "GET" and path == "/api/v1/rules/custom":
            return 200, "application/json", _json(self.rules)
        if method == "POST" and path == "/api/v1/rules/custom":
            data = json.loads(body)
            self.next_rule += 1
            value = re.search(r'@ipMatch ([^"]+)"', data["raw_conf_text"]).group(1)
            rule = {
                "id": f"r-{self.next_rule}",
                "rule_id": self.next_rule,
                "name": data["name"],
                "description": data.get("description"),
                "is_enabled": True,
                "field": "REMOTE_ADDR",
                "operator": "@ipMatch",
                "value": value,
                "conf_text": data["raw_conf_text"].replace("id:AUTO", f"id:{self.next_rule}"),
                "created_at": "2026-10-16T00:00:00Z",
            }
            self.rules.append(rule)
            return 201, "application/json", _json(rule)
        m = re.fullmatch(r"/api/v1/rules/custom/([^/]+)", path)
        if method == "PUT" and m:
            data = json.loads(body)
            for rule in self.rules:
                if str(rule["id"]) == m.group(1):
                    rule.update({k: v for k, v in data.items() if k in ("is_enabled", "description")})
                    return 200, "application/json", _json(rule)
            return 404, "application/json", _json({"detail": "Rule not found"})
        if method == "POST" and path == "/api/v1/forwarders/":
            self.next_forwarder += 1
            return 201, "application/json", _json({"id": self.next_forwarder, **json.loads(body)})
        if method == "POST" and re.fullmatch(r"/api/v1/forwarders/\d+/test", path):
            return 200, "application/json", _json({"success": True, "message": "Test event sent"})
        if method == "DELETE" and re.fullmatch(r"/api/v1/forwarders/\d+", path):
            return 204, None, b""
        return 404, "application/json", _json({"detail": "Not Found"})


class Graylog:
    """Graylog 6.1 / 7.0 for what forwarding and the WAF alerts send: inputs, static fields,
    extractors, index sets, streams, event definitions and notifications, the URL allowlist."""

    def __init__(self):
        self.reset()

    def reset(
        self,
        version=6,
        inputs=None,
        index_sets=None,
        streams=None,
        notifications=None,
        definitions=None,
        allowlist=None,
        overrides=None,
    ):
        self.version = version
        self.inputs = copy.deepcopy(
            inputs
            if inputs is not None
            else [
                {"id": "in-old", "title": "old", "attributes": {"port": 5600}},
                {"id": "in-x", "attributes": {"port": "n/a"}},
                {"id": "in-y"},
            ],
        )
        self.index_sets = copy.deepcopy(index_sets or [])
        self.streams = copy.deepcopy(streams or [])
        self.notifications = copy.deepcopy(notifications or [])
        self.definitions = copy.deepcopy(definitions if definitions is not None else samples.GRAYLOG_EVENT_DEFINITIONS)
        self.allowlist = copy.deepcopy(
            allowlist
            if allowlist is not None
            else {"entries": [{"id": "e1", "title": "x", "type": "regex", "value": "http://.*"}], "disabled": False},
        )
        self.overrides = dict(overrides or {})
        self.counter = 0

    def _id(self, prefix):
        self.counter += 1
        return f"{prefix}{self.counter:020d}"

    def answer(self, method, target, body):
        parts = urlsplit(target)
        path = parts.path.removeprefix("/graylog")
        query = parse_qs(parts.query)
        for key in ((method, path),):
            if key in self.overrides:
                return self.overrides[key]
        if method == "GET" and path == "/api/system":
            return 200, "application/json", _json(samples.GRAYLOG_SYSTEM_7 if self.version == 7 else samples.GRAYLOG_SYSTEM_6)
        if method == "GET" and path == "/api/system/inputs":
            return 200, "application/json", _json({"inputs": self.inputs, "total": len(self.inputs)})
        if method == "POST" and path == "/api/system/inputs":
            new = {"id": self._id("in")}
            self.inputs.append({**new, "attributes": json.loads(body)["configuration"]})
            return 201, "application/json", _json(new)
        if method == "POST" and re.fullmatch(r"/api/system/inputs/[^/]+/staticfields", path):
            return 201, None, b""
        if method == "POST" and re.fullmatch(r"/api/system/inputs/[^/]+/extractors", path):
            return 201, "application/json", _json({"extractor_id": self._id("ex")})
        if method == "DELETE" and re.fullmatch(r"/api/system/inputs/[^/]+", path):
            return 204, None, b""
        if method == "GET" and path == "/api/system/indices/index_sets":
            return 200, "application/json", _json({"index_sets": self.index_sets, "total": len(self.index_sets)})
        if method == "POST" and path == "/api/system/indices/index_sets":
            new = {"id": self._id("is"), **json.loads(body)}
            self.index_sets.append(new)
            return 200, "application/json", _json(new)
        if method == "DELETE" and re.fullmatch(r"/api/system/indices/index_sets/[^/]+", path):
            return 204, None, b""
        if method == "GET" and path == "/api/streams":
            return 200, "application/json", _json({"streams": self.streams, "total": len(self.streams)})
        if method == "POST" and path == "/api/streams":
            entity = json.loads(body)
            if self.version >= 7:
                if "entity" not in entity:
                    return 400, "application/json", _json({"type": "ApiError", "message": "entity cannot be null"})
                entity = entity["entity"]
            new_id = self._id("st")
            self.streams.append({"id": new_id, "title": entity["title"]})
            return 201, "application/json", _json({"stream_id": new_id})
        if method == "POST" and re.fullmatch(r"/api/streams/[^/]+/resume", path):
            return 204, None, b""
        if method == "DELETE" and re.fullmatch(r"/api/streams/[^/]+", path):
            return 204, None, b""
        if method == "GET" and path == "/api/events/definitions":
            page = int(query.get("page", ["1"])[0])
            size = int(query.get("per_page", ["50"])[0])
            batch = self.definitions[(page - 1) * size : page * size]
            return (
                200,
                "application/json",
                _json({"event_definitions": batch, "total": len(self.definitions), "page": page, "per_page": size}),
            )
        if method == "POST" and path == "/api/events/definitions":
            entity = json.loads(body)
            if self.version >= 7:
                entity = entity.get("entity") or {}
            return 200, "application/json", _json({"id": self._id("ed"), "title": entity.get("title")})
        if method == "GET" and path == "/api/events/notifications":
            return 200, "application/json", _json({"notifications": self.notifications, "total": len(self.notifications)})
        if method == "POST" and path == "/api/events/notifications":
            entity = json.loads(body)
            if self.version >= 7:
                entity = entity.get("entity") or {}
            new = {"id": self._id("nt"), "title": entity.get("title")}
            self.notifications.append(new)
            return 200, "application/json", _json(new)
        allow = "/api/system/urlallowlist" if self.version >= 7 else "/api/system/urlwhitelist"
        if path == allow and method == "GET":
            return 200, "application/json", _json(self.allowlist)
        if path == allow and method == "PUT":
            self.allowlist = json.loads(body)
            return 204, None, b""
        return 404, "application/json", _json({"type": "ApiError", "message": "HTTP 404 Not Found"})


WAF = Waf()
GRAYLOG = Graylog()
WAF_REC = Recorder(("authorization", "accept", "content-type", "content-length"))
GRAYLOG_REC = Recorder(("authorization", "x-requested-by", "content-type", "content-length"))
RECORDERS = (WAF_REC, GRAYLOG_REC)


def make_handler(tool, recorder):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            recorder.add(self.command, self.path, headers, body)
            status, ctype, payload = tool.answer(self.command, self.path, body)
            if isinstance(payload, tuple):  # (delay, payload)
                time.sleep(payload[0])
                payload = payload[1]
            self.send_response_only(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _serve  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    return Handler


def start_stub(port, tool, recorder, tls=False):
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(tool, recorder))
    server.daemon_threads = True
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_PATH, KEY_PATH)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- Database ----------------------------------------------------------------------------------------

SAVED_CONNECTORS = []
IDS = {}


def set_connector(name, url, username=None, password=None):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) "
        "VALUES (:n, '3', :u, UTC_TIMESTAMP(), :un, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        un=username,
        pw=password,
    )


def encrypt(value, key=WAF_KEY):
    return Fernet(key.encode()).encrypt(value.encode()).decode()


WAF_ROWS = [
    # key, customer, name, url, enabled, verify_tls, ca, ciphertext key
    ("alpha", CUST_A, "alpha", f"http://127.0.0.1:{WAF_PORT}", 1, 0, None, WAF_KEY),
    ("disabled", CUST_A, "disabled", f"http://127.0.0.1:{WAF_PORT}", 0, 0, None, WAF_KEY),
    ("beta", CUST_B, "beta", f"http://127.0.0.1:{WAF_PORT}", 1, 0, None, WAF_KEY),
    ("tls_ok", CUST_A, "tls-ok", f"https://127.0.0.1:{WAF_TLS_PORT}", 1, 1, CA_PEM, WAF_KEY),
    ("tls_untrusted", CUST_A, "tls-untrusted", f"https://127.0.0.1:{WAF_TLS_PORT}", 1, 1, None, WAF_KEY),
    ("tls_off", CUST_A, "tls-off", f"https://127.0.0.1:{WAF_TLS_PORT}/api/v1", 1, 0, None, WAF_KEY),
    ("rotated", CUST_A, "rotated", f"http://127.0.0.1:{WAF_PORT}", 1, 0, None, OTHER_KEY),
    # Stored by hand: a CA that does not parse, and a token the key cannot read — the TLS context is built first.
    ("bad_ca", CUST_A, "bad-ca", f"https://127.0.0.1:{WAF_TLS_PORT}", 1, 1, "not a certificate", OTHER_KEY),
    ("down", CUST_A, "down", f"http://127.0.0.1:{CLOSED_PORT}", 1, 0, None, WAF_KEY),
    ("fwd", CUST_A, "fwd", f"http://127.0.0.1:{WAF_PORT}", 1, 0, None, WAF_KEY),
    ("fwd2", CUST_A, "fwd2", f"http://127.0.0.1:{WAF_PORT}", 1, 0, None, WAF_KEY),
]


def reset_waf_row(key):
    _, code, name, url, enabled, verify, ca, ckey = next(r for r in WAF_ROWS if r[0] == key)
    sql(
        "UPDATE customer_waf_instances SET name = :n, api_url = :u, service_token_encrypted = :t, token_prefix = :p, "
        "verify_tls = :v, ca_cert_pem = :ca, enabled = :e, last_verified_at = NULL, last_verified_role = NULL, "
        "created_by = NULL, created_at = '2026-01-02 03:04:05', updated_by = NULL, updated_at = NULL, syslog_host = NULL, "
        "syslog_port = NULL, graylog_input_id = NULL, graylog_stream_id = NULL, graylog_index_set_id = NULL, "
        "waf_forwarder_id = NULL, forwarding_provisioned_at = NULL WHERE id = :i",
        i=IDS[key],
        n=name,
        u=url,
        t=encrypt(TOKEN, ckey),
        p=TOKEN[:12] + "...",
        v=verify,
        ca=ca,
        e=enabled,
    )


def seed():
    with sync_engine.connect() as conn:
        found = conn.execute(text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(names=list(OUR_CONNECTORS)))
        SAVED_CONNECTORS.extend(dict(r._mapping) for r in found)
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog", "admin", "pässword")
    for code, name in ((CUST_A, f"Alpha Co {SFX}"), (CUST_B, f"Beta Co {SFX}")):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (ANALYST_B, 2), (PORTAL, 4), (UNASSIGNED, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name, code in ((ANALYST, CUST_A), (PORTAL, CUST_A), (ANALYST_B, CUST_B)):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=code,
            n=name,
        )
    # Explicit ids, seven digits and in ranges of their own.
    top = 0
    for table in ("customer_waf_instances", "incident_management_alert", "incident_management_case"):
        top = max(top, rows(f"SELECT COALESCE(MAX(id), 0) AS n FROM {table}")[0]["n"])
    base = max(top + 100, 1_000_000)
    for i, (key, code, name, url, enabled, verify, ca, ckey) in enumerate(WAF_ROWS):
        IDS[key] = base + i
        sql(
            "INSERT INTO customer_waf_instances (id, customer_code, name, api_url, service_token_encrypted, token_prefix, "
            "verify_tls, ca_cert_pem, enabled, created_at) VALUES (:i, :c, :n, :u, 'x', 'x', 0, NULL, 1, '2026-01-02 03:04:05')",
            i=IDS[key],
            c=code,
            n=name,
            u=url,
        )
        reset_waf_row(key)
    for i, (key, code) in enumerate((("alert_a", CUST_A), ("alert_b", CUST_B))):
        IDS[key] = base + 30 + i
        sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, "
            "customer_code, source, escalated) VALUES (:i, 'SQLi', 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'waf', 0)",
            i=IDS[key],
            c=code,
        )
    for i, (key, code) in enumerate((("case_a", CUST_A), ("case_b", CUST_B), ("case_none", None))):
        IDS[key] = base + 40 + i
        sql(
            "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, "
            "customer_code, escalated) VALUES (:i, 'Case', 'd', '2026-01-02 03:04:05', 'OPEN', :c, 0)",
            i=IDS[key],
            c=code,
        )
    IDS["missing"] = base + 90


def cleanup():
    for key in ("alert_a", "alert_b"):
        sql("DELETE FROM incident_management_comment WHERE alert_id = :i", i=IDS.get(key, -1))
        sql("DELETE FROM incident_management_alert WHERE id = :i", i=IDS.get(key, -1))
    for key in ("case_a", "case_b", "case_none"):
        sql("DELETE FROM incident_management_case WHERE id = :i", i=IDS.get(key, -1))
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
    for code in (CUST_A, CUST_B):
        sql("DELETE FROM customer_waf_instances WHERE customer_code = :c", c=code)
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)
    for table in ("fieldname", "assetfieldname", "timestampfieldname", "alerttitlefieldname", "iocfieldname"):
        sql(f"DELETE FROM incident_management_{table} WHERE source = 'waf'")
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)


# --- The backends ---------------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import customer_waf
    from app.routers import monitoring_alert

    api = APIRouter(prefix="/api")
    api.include_router(customer_waf.router)
    api.include_router(monitoring_alert.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port, unset=()):
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
        **{k: v for k, v in ENV.items() if k not in unset},
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
VOLATILE = {"id", "created_at", "updated_at", "last_verified_at", "forwarding_provisioned_at", "created_by", "updated_by"}


def mask(value, keys):
    if isinstance(value, dict):
        return {k: ("<m>" if k in keys and v is not None else mask(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, keys) for v in value]
    return value


def body_norm(raw, keys):
    raw = ADDRESS.sub(b"object at 0x...", raw)
    if not keys:
        return raw
    try:
        return json.dumps(mask(json.loads(raw), keys)).encode()
    except ValueError:
        return raw


OUT_MASKS = [
    (re.compile(rb'"creation_date": "[^"]*"'), b'"creation_date": "<t>"'),
    (re.compile(rb'"id": "[0-9a-f]{24}", "title": "\\"SEND TO COPILOT'), b'"id": "<hex>", "title": "\\"SEND TO COPILOT'),
]


def pin_graylog_version(version):
    """Python's cached Graylog major version, as the Rust instance in use has it (both probe
    `GET /api/system` once per 5 minutes; the probes are left out of the comparison)."""
    from app.connectors.graylog.utils import universal

    universal._GRAYLOG_VERSION_CACHE["Graylog"] = (version, time.monotonic())


def out_norm(requests):
    out = []
    for method, target, headers, body in requests:
        if method == "GET" and target == "/graylog/api/system":
            continue
        for pattern, repl in OUT_MASKS:
            body = pattern.sub(repl, body)
        out.append((method, target, headers, body))
    return out


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)
        self.rs_nokey = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_NOKEY_PORT}", timeout=120)
        self.rs7 = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS7_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        for recorder in RECORDERS:
            recorder.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, [request for recorder in RECORDERS for request in recorder.take()]

    async def same(self, name, method, path, tok=None, before=None, after=None, masked=(), rust=None, nokey=False, expect=None, **kw):
        """Python, then Rust, each after `before(side)`; `after(side)` returns the state the
        request left, compared too. `nokey`: Python without the WAF key and alert-forwarding
        settings, against the Rust instance started without them. `expect`: a deliberate
        difference — `(python_status, rust_status)`, the bodies are not compared."""
        saved = {}
        if nokey:
            for k in NOKEY_UNSET:
                saved[k] = os.environ.pop(k, None)
        try:
            if before:
                before("py")
            r1, out1 = await self.call(self.py, method, path, tok, **kw)
            s1 = after("py") if after else None
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
        client = rust or (self.rs_nokey if nokey else self.rs)
        if before:
            before("rs")
        r2, out2 = await self.call(client, method, path, tok, **kw)
        s2 = after("rs") if after else None
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2
        b1, b2 = body_norm(r1.content, masked), body_norm(r2.content, masked)
        ok = r1.status_code == r2.status_code and b1 == b2
        detail = f"python {r1.status_code} {b1[:1200]!r}\n        rust   {r2.status_code} {b2[:1200]!r}"
        o1, o2 = out_norm(out1), out_norm(out2)
        if o1 != o2:
            ok = False
            detail += f"\n        outbound python {o1}\n        outbound rust   {o2}"
        if s1 != s2:
            ok = False
            detail += f"\n        state python {s1}\n        state rust   {s2}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:600]!r}\n        outbound {[(m, t, b[:300]) for m, t, h, b in o1]}")
        return r1, r2

    async def close(self):
        for c in (self.py, self.rs, self.rs_nokey, self.rs7):
            await c.aclose()


def waf_state(key=None, code=None, name=None):
    """The row a write left (the token decrypted, ids and fresh timestamps masked)."""
    if key:
        found = rows("SELECT * FROM customer_waf_instances WHERE id = :i", i=IDS[key])
    else:
        found = rows("SELECT * FROM customer_waf_instances WHERE customer_code = :c AND name = :n", c=code, n=name)
    if not found:
        return None
    row = found[0]
    try:
        row["service_token_encrypted"] = Fernet(WAF_KEY.encode()).decrypt(row["service_token_encrypted"].encode()).decode()
    except Exception:  # noqa: BLE001 - recorded
        row["service_token_encrypted"] = "<undecryptable>"
    for k in ("id", "created_by", "updated_by"):
        row[k] = "<m>" if row[k] is not None else None
    for k in ("created_at", "updated_at", "last_verified_at", "forwarding_provisioned_at"):
        row[k] = "<t>" if row[k] is not None else None
    return row


def comments(key):
    return [
        (c["comment"], c["user_name"])
        for c in rows("SELECT comment, user_name FROM incident_management_comment WHERE alert_id = :i ORDER BY id", i=IDS[key])
    ]


def field_rows():
    out = []
    for table in ("fieldname", "assetfieldname", "timestampfieldname", "alerttitlefieldname", "iocfieldname"):
        out.append(sorted(r["field_name"] for r in rows(f"SELECT field_name FROM incident_management_{table} WHERE source = 'waf'")))
    return out


# --- The checks -------------------------------------------------------------------------------------------


async def waf_checks(p, t_admin, t_analyst, t_analyst_b, t_portal):
    W = "/api/customer_waf"
    A, B = f"{W}/{CUST_A}", f"{W}/{CUST_B}"
    alpha = f"{A}/{IDS['alpha']}"

    def fresh_waf(**kw):
        def before(side):
            WAF.reset(**kw)

        return before

    # ---- auth and tenancy
    await p.same("list all: no token", "GET", W)
    await p.same("list all: portal user", "GET", W, t_portal)
    await p.same("list all: admin", "GET", W, t_admin)
    await p.same("list all: analyst sees A only", "GET", W, t_analyst)
    await p.same("list all: unassigned analyst sees nothing", "GET", W, token(UNASSIGNED, ["analyst"]))
    await p.same("list A: unassigned analyst", "GET", A, token(UNASSIGNED, ["analyst"]))
    await p.same("list A: analyst", "GET", A, t_analyst)
    await p.same("list B: analyst of A", "GET", B, t_analyst)
    await p.same("list unknown customer: admin", "GET", f"{W}/NOPE{SFX}", t_admin)
    await p.same("B's WAF under A's path", "GET", f"{A}/{IDS['beta']}/sites", t_analyst)
    await p.same("missing WAF id", "GET", f"{A}/{IDS['missing']}/sites", t_admin)
    await p.same("non-integer WAF id", "GET", f"{A}/abc/sites", t_admin)
    await p.same("non-integer WAF id on B (tenancy first)", "GET", f"{B}/abc/sites", t_analyst)
    await p.same("write as analyst", "PUT", alpha, t_analyst, json={"enabled": True})
    await p.same("list A without the key", "GET", A, t_admin, nokey=True)

    # ---- reads
    await p.same("sites", "GET", f"{alpha}/sites", t_analyst, before=fresh_waf())
    await p.same("stats", "GET", f"{alpha}/stats", t_analyst, before=fresh_waf())
    await p.same("threat intel", "GET", f"{alpha}/threat-intel", t_analyst, before=fresh_waf())
    await p.same("events, defaults", "GET", f"{alpha}/events", t_analyst, before=fresh_waf())
    await p.same(
        "events, every filter",
        "GET",
        f"{alpha}/events",
        t_analyst,
        before=fresh_waf(),
        params={
            "action": "blocked",
            "severity": "",
            "client_ip": "2001:db8::1",
            "rule_id": "942100",
            "site_id": "3",
            "start_time": "2026-10-15T10:00:00+02:00",
            "end_time": "2026-10-15T12:00:00.250",
            "limit": "500",
            "offset": "10",
        },
    )
    await p.same("events, unix start", "GET", f"{alpha}/events", t_analyst, before=fresh_waf(), params={"start_time": "1700000000"})
    for label, params in (
        ("bad action", {"action": "denied"}),
        ("limit 0", {"limit": "0"}),
        ("limit 501", {"limit": "501"}),
        ("offset -1", {"offset": "-1"}),
        ("limit text", {"limit": "x"}),
        ("severity too long", {"severity": "x" * 21}),
        ("bad start time", {"start_time": "yesterday"}),
        ("several errors", {"limit": "0", "action": "x", "end_time": ""}),
    ):
        await p.same(f"events: {label}", "GET", f"{alpha}/events", t_analyst, before=fresh_waf(), params=params)
    await p.same("events: bad id and bad query together", "GET", f"{A}/x/events", t_analyst, params={"limit": "0"})
    for label, path, body in (
        ("events: one without a timestamp", "/api/v1/logs/", _json([{**WAF_EVENTS[1], "timestamp": None}])),
        ("events: not a list of dicts", "/api/v1/logs/", _json([1])),
        ("events: null body", "/api/v1/logs/", b"null"),
        ("events: an event without id", "/api/v1/logs/", _json([{k: v for k, v in WAF_EVENTS[1].items() if k != "id"}])),
        ("stats: missing totals", "/api/v1/logs/stats", _json({"total_1h": 1})),
        ("stats: a list", "/api/v1/logs/stats", _json([])),
        ("sites: a site without id", "/api/v1/sites/", _json([{"name": "x"}])),
        ("sites: a name that is a number", "/api/v1/sites/", _json([{"id": 1, "name": 5}])),
        ("threat intel: empty stats", "/api/v1/threat-intel/stats", _json({})),
    ):
        what = path.rstrip("/").rsplit("/", 1)[-1]
        route = {"logs": "events", "stats": "stats", "sites": "sites"}.get(what, "threat-intel")
        if "threat" in path:
            route = "threat-intel"
        await p.same(
            label,
            "GET",
            f"{alpha}/{route}",
            t_analyst,
            before=fresh_waf(overrides={("GET", path): (200, "application/json", body)}),
        )

    # ---- upstream failures
    for label, answer in (
        ("401", (401, "application/json", _json({"detail": "Invalid token"}))),
        ("403 with a detail", (403, "application/json", _json({"detail": "Missing permission: logs:read"}))),
        ("403 without", (403, "text/plain", b"nope")),
        ("404 with a detail", (404, "application/json", _json({"detail": "No such thing"}))),
        ("404 without", (404, "text/html", b"<html>")),
        ("500", (500, "application/json", _json({"detail": "boom"}))),
        ("204", (204, None, b"")),
        ("HTML 200", (200, "text/html", b"<!doctype html><html></html>")),
        ("gzip JSON", (200, "application/json", None)),
    ):
        if label == "gzip JSON":
            continue
        await p.same(
            f"stats: WAF answers {label}",
            "GET",
            f"{alpha}/stats",
            t_analyst,
            before=fresh_waf(overrides={("GET", "/api/v1/logs/stats"): answer}),
        )
    await p.same("sites: disabled WAF", "GET", f"{A}/{IDS['disabled']}/sites", t_analyst)
    await p.same("sites: unreachable WAF", "GET", f"{A}/{IDS['down']}/sites", t_analyst)
    await p.same("sites: rotated key", "GET", f"{A}/{IDS['rotated']}/sites", t_analyst)
    await p.same("sites: stored CA unparsable", "GET", f"{A}/{IDS['bad_ca']}/sites", t_analyst)
    await p.same("sites: no key", "GET", f"{alpha}/sites", t_analyst, nokey=True)
    await p.same("sites: TLS with its CA", "GET", f"{A}/{IDS['tls_ok']}/sites", t_analyst, before=fresh_waf())
    await p.same("sites: TLS untrusted", "GET", f"{A}/{IDS['tls_untrusted']}/sites", t_analyst, before=fresh_waf())
    await p.same("sites: TLS unverified, URL with /api/v1", "GET", f"{A}/{IDS['tls_off']}/sites", t_analyst, before=fresh_waf())

    # ---- verify
    def verify_before(**kw):
        def before(side):
            WAF.reset(**kw)
            reset_waf_row("alpha")

        return before

    def alpha_state(side):
        return waf_state("alpha")

    for label, kw in (
        ("admin role", {}),
        ("viewer role", {"roles": ("viewer",)}),
        ("no roles", {"roles": ()}),
        ("token rejected", {"overrides": {("GET", "/api/v1/users/me"): (401, "application/json", b"{}")}}),
        ("not a WAF (404)", {"overrides": {("GET", "/api/v1/users/me"): (404, "text/html", b"<html>")}}),
        ("not a WAF (HTML)", {"overrides": {("GET", "/api/v1/users/me"): (200, "text/html", b"<html>")}}),
        ("WAF error", {"overrides": {("GET", "/api/v1/users/me"): (502, "text/html", b"bad gateway")}}),
        ("health is HTML", {"overrides": {("GET", "/health"): (200, "text/html", b"<html>")}}),
        ("health fails", {"overrides": {("GET", "/health"): (500, "text/html", b"x")}}),
        ("health is a list", {"overrides": {("GET", "/health"): (200, "application/json", b"[1]")}}),
        (
            "email is a number",
            {"overrides": {("GET", "/api/v1/users/me"): (200, "application/json", _json({"email": 5, "roles": [{"name": "viewer"}]}))}},
        ),
        (
            "roles not a list",
            {"overrides": {("GET", "/api/v1/users/me"): (200, "application/json", _json({"email": "a@b", "roles": "admin"}))}},
        ),
        ("me is a list", {"overrides": {("GET", "/api/v1/users/me"): (200, "application/json", b"[]")}}),
        ("long role names", {"roles": ("admin", "operator", "viewer", "auditor-with-a-very-long-role-name-that-goes-on")}),
    ):
        await p.same(
            f"verify: {label}",
            "POST",
            f"{alpha}/verify",
            t_analyst,
            before=verify_before(**kw),
            after=alpha_state,
            masked=("last_verified_at",),
        )
    await p.same(
        "verify: health times out",
        "POST",
        f"{alpha}/verify",
        t_analyst,
        before=verify_before(overrides={("GET", "/health"): (200, "application/json", (6, b"{}"))}),
        after=alpha_state,
        masked=("last_verified_at",),
    )
    await p.same(
        "verify: disabled WAF is checked",
        "POST",
        f"{A}/{IDS['disabled']}/verify",
        t_analyst,
        before=fresh_waf(),
        masked=("last_verified_at",),
    )
    await p.same("verify: unreachable", "POST", f"{A}/{IDS['down']}/verify", t_analyst)
    await p.same("verify: TLS untrusted", "POST", f"{A}/{IDS['tls_untrusted']}/verify", t_analyst, before=fresh_waf())
    await p.same("verify: rotated key", "POST", f"{A}/{IDS['rotated']}/verify", t_analyst)

    # ---- create
    created = {}

    def create_before(name):
        def before(side):
            WAF.reset()
            sql("DELETE FROM customer_waf_instances WHERE customer_code = :c AND name = :n", c=CUST_A, n=name)

        return before

    def create_after(name):
        def after(side):
            return waf_state(code=CUST_A, name=name)

        return after

    good = {"name": f"new{SFX}", "api_url": f"  http://127.0.0.1:{WAF_PORT}/api/v1/  ", "service_token": f"  {TOKEN}  "}
    await p.same(
        "create",
        "POST",
        A,
        t_admin,
        json=good,
        before=create_before(good["name"]),
        after=create_after(good["name"]),
        masked=VOLATILE,
    )
    await p.same("create: duplicate name", "POST", A, t_admin, json=good, after=create_after(good["name"]), masked=VOLATILE)
    for label, body in (
        ("no body", None),
        ("empty object", {}),
        ("not an object", [1]),
        ("blank name", {**good, "name": "   "}),
        ("name too long", {**good, "name": "x" * 101}),
        ("empty name", {**good, "name": ""}),
        ("name not a string", {**good, "name": 5}),
        ("verify_tls null", {**good, "verify_tls": None}),
        ("verify_tls yes", {**good, "name": f"tls{SFX}", "verify_tls": "yes", "ca_cert_pem": CA_PEM}),
        ("bad URL", {**good, "api_url": "ftp://x"}),
        ("bracketed IPv4 URL", {**good, "api_url": "https://[1.2.3.4]/"}),
        ("not a service token", {**good, "service_token": "waf_site_key"}),
        ("token prefix only", {**good, "service_token": "wafst_"}),
        ("bad CA", {**good, "ca_cert_pem": "not a cert"}),
        ("CA then junk", {**good, "ca_cert_pem": CA_PEM + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}),
        ("non-ASCII CA", {**good, "ca_cert_pem": "é"}),
        ("blank CA", {**good, "name": f"blankca{SFX}", "ca_cert_pem": "  \n "}),
        ("disabled, http", {**good, "name": f"off{SFX}", "enabled": False}),
        ("unreachable", {**good, "name": f"down{SFX}", "api_url": f"http://127.0.0.1:{CLOSED_PORT}"}),
    ):
        name = body.get("name") if isinstance(body, dict) and isinstance(body.get("name"), str) else good["name"]
        kw = {"json": body} if body is not None else {}
        await p.same(f"create: {label}", "POST", A, t_admin, before=create_before(name), after=create_after(name), masked=VOLATILE, **kw)
    await p.same("create: malformed JSON", "POST", A, t_admin, content=b'{"name": ', headers={"Content-Type": "application/json"})
    await p.same(
        "create: malformed JSON without a token",
        "POST",
        A,
        None,
        content=b'{"name": ',
        headers={"Content-Type": "application/json"},
    )
    await p.same("create: form body", "POST", A, t_admin, content=b"name=x", headers={"Content-Type": "application/x-www-form-urlencoded"})
    await p.same("create: unknown customer", "POST", f"{W}/NOPE{SFX}", t_admin, json=good)
    await p.same(
        "create: no key",
        "POST",
        A,
        t_admin,
        json=good,
        nokey=True,
        before=create_before(good["name"]),
        after=create_after(good["name"]),
    )
    await p.same(
        "create: viewer token (verification passes)",
        "POST",
        A,
        t_admin,
        json={**good, "name": f"viewer{SFX}"},
        before=lambda s: (create_before(f"viewer{SFX}")(s), WAF.reset(roles=("viewer",))),
        after=create_after(f"viewer{SFX}"),
        masked=VOLATILE,
    )
    created["name"] = good["name"]

    # ---- update
    def update_before(**kw):
        def before(side):
            WAF.reset(**kw)
            reset_waf_row("alpha")
            sql("DELETE FROM customer_waf_instances WHERE customer_code = :c AND name = :n", c=CUST_A, n=f"renamed{SFX}")

        return before

    for label, body in (
        ("nothing", {}),
        ("enable only", {"enabled": False}),
        ("rename", {"name": f"  renamed{SFX} "}),
        ("rename to a sibling's name", {"name": "beta-not"}),
        ("rename to an existing name", {"name": "down"}),
        ("blank token keeps it", {"service_token": "   "}),
        ("new token", {"service_token": f"wafst_rotated{SFX}"}),
        ("bad token", {"service_token": "nope"}),
        ("same URL", {"api_url": f"http://127.0.0.1:{WAF_PORT}"}),
        ("new URL", {"api_url": f"http://127.0.0.1:{WAF_PORT}/"}),
        ("bad URL", {"api_url": "nope"}),
        ("verify on", {"verify_tls": True}),
        ("CA removed", {"ca_cert_pem": ""}),
        ("bad CA", {"ca_cert_pem": "x"}),
        (
            "explicit nulls",
            {"name": None, "api_url": None, "service_token": None, "verify_tls": None, "ca_cert_pem": None, "enabled": None},
        ),
        ("name too short", {"name": ""}),
        ("verify_tls not a bool", {"verify_tls": "maybe"}),
    ):
        await p.same(f"update: {label}", "PUT", alpha, t_admin, json=body, before=update_before(), after=alpha_state, masked=VOLATILE)
    await p.same(
        "update: new token without the key",
        "PUT",
        alpha,
        t_admin,
        json={"service_token": TOKEN},
        nokey=True,
        before=update_before(),
        after=alpha_state,
        masked=VOLATILE,
    )
    await p.same("update: bad id and bad body", "PUT", f"{A}/x", t_admin, json={"name": ""})
    await p.same("update: another tenant's WAF", "PUT", f"{A}/{IDS['beta']}", t_admin, json={})

    # ---- delete
    def delete_before(side):
        sql("DELETE FROM customer_waf_instances WHERE customer_code = :c AND name = :n", c=CUST_A, n=f"todelete{SFX}")
        sql(
            "INSERT INTO customer_waf_instances (customer_code, name, api_url, service_token_encrypted, token_prefix, verify_tls, enabled, created_at) "
            "VALUES (:c, :n, 'http://x', 'x', 'wafst_abcdef...', 0, 1, UTC_TIMESTAMP())",
            c=CUST_A,
            n=f"todelete{SFX}",
        )
        IDS["todelete"] = rows(
            "SELECT id FROM customer_waf_instances WHERE customer_code = :c AND name = :n",
            c=CUST_A,
            n=f"todelete{SFX}",
        )[0]["id"]

    async def delete_pair(name):
        # The id differs per side: one request each, compared.
        delete_before("py")
        r1, o1 = await p.call(p.py, "DELETE", f"{A}/{IDS['todelete']}", t_admin)
        s1 = waf_state(code=CUST_A, name=f"todelete{SFX}")
        delete_before("rs")
        r2, o2 = await p.call(p.rs, "DELETE", f"{A}/{IDS['todelete']}", t_admin)
        s2 = waf_state(code=CUST_A, name=f"todelete{SFX}")
        check(
            f"{name} [{r1.status_code}]",
            (r1.status_code, r1.content, s1, o1) == (r2.status_code, r2.content, s2, o2),
            f"python {r1.content!r}\n        rust   {r2.content!r}",
        )

    await delete_pair("delete")

    # ---- blocks
    def blocks_before(rules=None, **kw):
        def before(side):
            WAF.reset(rules=rules, **kw)
            sql("DELETE FROM incident_management_comment WHERE alert_id IN (:a, :b)", a=IDS["alert_a"], b=IDS["alert_b"])

        return before

    def comment_state(side):
        return comments("alert_a")

    existing = [
        ti_block_rule(100, "198.51.100.0/24, 192.0.2.5"),
        {
            **ti_block_rule(101, "203.0.113.50"),
            "name": "CoPilot block: 203.0.113.50",
            "conf_text": 'SecRule REMOTE_ADDR "@ipMatch 203.0.113.50" "id:101,phase:1,deny,tag:\'copilot-block\'"',
            "is_enabled": False,
        },
        {**ti_block_rule(102, "203.0.113.60"), "name": "CoPilot block: 203.0.113.60", "conf_text": "deny,tag:'copilot-block'"},
        ti_block_rule(103, "10.0.0.0/16", enabled=False),
        {**ti_block_rule(104, "10.1.0.0/16"), "conf_text": "pass,ctl:ruleEngine=Off,deny"},
        {
            "id": "x105",
            "rule_id": 105,
            "name": "args",
            "field": "ARGS",
            "operator": "@rx",
            "value": "x",
            "conf_text": "deny",
            "is_enabled": True,
        },
    ]
    await p.same("blocks: list", "GET", f"{alpha}/blocks", t_analyst, before=blocks_before(existing))
    await p.same("blocks: list, none", "GET", f"{alpha}/blocks", t_analyst, before=blocks_before([]))
    reason = "  brute force\n from   scanner "
    for label, body in (
        ("new block", {"target": " 203.0.113.7 ", "reason": reason}),
        ("new range", {"target": "203.0.113.7/24", "reason": "r"}),
        ("IPv6", {"target": "2001:DB8::1", "reason": "r"}),
        ("covered by the WAF's own rule", {"target": "198.51.100.9", "reason": "r"}),
        ("CoPilot's own, enabled", {"target": "203.0.113.60", "reason": "r"}),
        ("CoPilot's own, disabled: re-enabled", {"target": "203.0.113.50", "reason": "again", "alert_id": IDS["alert_a"]}),
        ("disabled WAF rule is no block", {"target": "10.0.5.5", "reason": "r"}),
        ("bypass rule is no block", {"target": "10.1.0.5", "reason": "r"}),
        ("private address warns", {"target": "10.2.0.1", "reason": "r"}),
        ("loopback warns", {"target": "::1", "reason": "r"}),
        ("too broad", {"target": "10.0.0.0/8", "reason": "r"}),
        ("not an IP", {"target": "example.com", "reason": "r"}),
        ("netmask form", {"target": "203.0.113.7/255.255.255.0", "reason": "r"}),
        ("with an alert", {"target": "203.0.113.8", "reason": "SQLi\tfrom here", "alert_id": IDS["alert_a"]}),
        ("with an alert and a case", {"target": "203.0.113.9", "reason": "x", "alert_id": IDS["alert_a"], "case_id": IDS["case_a"]}),
        ("another tenant's alert", {"target": "203.0.113.10", "reason": "x", "alert_id": IDS["alert_b"]}),
        ("missing alert", {"target": "203.0.113.10", "reason": "x", "alert_id": IDS["missing"]}),
        ("another tenant's case", {"target": "203.0.113.10", "reason": "x", "case_id": IDS["case_b"]}),
        ("case without customer", {"target": "203.0.113.10", "reason": "x", "case_id": IDS["case_none"]}),
        ("missing case", {"target": "203.0.113.10", "reason": "x", "case_id": IDS["missing"]}),
        ("empty reason", {"target": "203.0.113.10", "reason": ""}),
        ("target too long", {"target": "1" * 65, "reason": "x"}),
        ("alert id not a number", {"target": "203.0.113.10", "reason": "x", "alert_id": "a"}),
    ):
        await p.same(
            f"block: {label}",
            "POST",
            f"{alpha}/blocks",
            t_analyst,
            json=body,
            before=blocks_before(existing),
            after=comment_state,
        )
    await p.same(
        "block: admin sees another tenant's alert, still refused",
        "POST",
        f"{alpha}/blocks",
        t_admin,
        json={"target": "203.0.113.11", "reason": "x", "alert_id": IDS["alert_b"]},
        before=blocks_before(existing),
    )
    await p.same(
        "block: analyst of B on B's alert under A",
        "POST",
        f"{alpha}/blocks",
        t_analyst_b,
        json={"target": "203.0.113.11", "reason": "x"},
    )
    await p.same(
        "block: viewer token",
        "POST",
        f"{alpha}/blocks",
        t_analyst,
        json={"target": "203.0.113.12", "reason": "x"},
        before=blocks_before(
            existing,
            overrides={("POST", "/api/v1/rules/custom"): (403, "application/json", _json({"detail": "Missing permission: rules:write"}))},
        ),
    )
    await p.same(
        "block: rule answer without rule_id",
        "POST",
        f"{alpha}/blocks",
        t_analyst,
        json={"target": "203.0.113.13", "reason": "x"},
        before=blocks_before(existing, overrides={("POST", "/api/v1/rules/custom"): (201, "application/json", _json({"id": "q"}))}),
    )
    await p.same(
        "block: an IPv6 zone (deliberate difference)",
        "POST",
        f"{alpha}/blocks",
        t_analyst,
        json={"target": 'fe80::1%x",ctl:ruleEngine=Off,"', "reason": "x"},
        before=blocks_before([]),
        expect=(200, 422),
    )
    await p.same(
        "block: an IPv6 zone with host bits (same)",
        "POST",
        f"{alpha}/blocks",
        t_analyst,
        json={"target": "fe80::1%eth0/64", "reason": "x"},
        before=blocks_before([]),
    )
    for label, target, rules in (
        ("unblock", "203.0.113.60", existing),
        ("unblock, already lifted", "203.0.113.50", existing),
        ("unblock, WAF-owned", "198.51.100.9", existing),
        ("unblock, nothing", "203.0.113.99", existing),
        (
            "unblock, CoPilot's and the WAF's",
            "192.0.2.5",
            existing + [{**ti_block_rule(106, "192.0.2.5"), "name": "CoPilot block: 192.0.2.5", "conf_text": "deny,tag:'copilot-block'"}],
        ),
        ("unblock, invalid", "nope", existing),
    ):
        await p.same(f"{label}", "DELETE", f"{alpha}/blocks", t_analyst, params={"target": target}, before=blocks_before(rules))
    await p.same("unblock, no target", "DELETE", f"{alpha}/blocks", t_analyst)
    await p.same("unblock, target too long", "DELETE", f"{alpha}/blocks", t_analyst, params={"target": "1" * 65})
    await p.same(
        "blocks: rules answer is a dict",
        "GET",
        f"{alpha}/blocks",
        t_analyst,
        before=blocks_before(overrides={("GET", "/api/v1/rules/custom"): (200, "application/json", b"{}")}),
    )
    await p.same(
        "blocks: rules answer null",
        "GET",
        f"{alpha}/blocks",
        t_analyst,
        before=blocks_before(overrides={("GET", "/api/v1/rules/custom"): (200, "application/json", b"null")}),
    )


async def forwarding_checks(p, t_admin, t_analyst):
    A = f"/api/customer_waf/{CUST_A}"
    fwd = f"{A}/{IDS['fwd']}"

    def fwd_state(side):
        return waf_state("fwd")

    def setup(version=6, waf=None, sibling=False, provisioned=False, **graylog):
        def before(side):
            GRAYLOG.reset(version=version, **graylog)
            pin_graylog_version(version)
            WAF.reset(**(waf or {}))
            reset_waf_row("fwd")
            reset_waf_row("fwd2")
            if sibling:
                sql(
                    "UPDATE customer_waf_instances SET forwarding_provisioned_at = '2026-01-02 03:04:05', graylog_stream_id = 'st-shared' WHERE id = :i",
                    i=IDS["fwd2"],
                )
            if provisioned:
                sql(
                    "UPDATE customer_waf_instances SET syslog_host = 'h', syslog_port = 5601, graylog_input_id = 'in-1', graylog_stream_id = 'st-1', "
                    "graylog_index_set_id = 'is-1', waf_forwarder_id = '77', forwarding_provisioned_at = '2026-01-02 03:04:05' WHERE id = :i",
                    i=IDS["fwd"],
                )

        return before

    masked = ("forwarding_provisioned_at",)
    await p.same(
        "forwarding: set up",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={"syslog_host": " 10.0.0.9 "},
        before=setup(),
        after=fwd_state,
        masked=masked,
    )
    await p.same("forwarding: default host", "POST", f"{fwd}/forwarding", t_admin, json={}, before=setup(), after=fwd_state, masked=masked)
    await p.same(
        "forwarding: no host",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={"syslog_host": "  "},
        before=setup(),
        after=fwd_state,
        nokey=True,
    )
    await p.same("forwarding: no body", "POST", f"{fwd}/forwarding", t_admin, before=setup())
    await p.same("forwarding: host too long", "POST", f"{fwd}/forwarding", t_admin, json={"syslog_host": "h" * 256}, before=setup())
    await p.same(
        "forwarding: reuses the index set and stream",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(
            index_sets=[{"id": "is-x", "index_prefix": "other"}, {"id": "is-shared", "index_prefix": f"waf-{CUST_A.lower()}"}],
            streams=[{"id": "st-shared", "title": f"SOCFORTRESS WAF - {CUST_A}"}],
        ),
        after=fwd_state,
        masked=masked,
    )
    await p.same(
        "forwarding: Graylog 7",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(version=7),
        after=fwd_state,
        masked=masked,
        rust=p.rs7,
    )
    await p.same(
        "forwarding: already set up",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(provisioned=True),
        after=fwd_state,
    )
    await p.same(
        "forwarding: viewer token",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(waf={"roles": ("viewer", "operator")}),
        after=fwd_state,
    )
    await p.same(
        "forwarding: no free port",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(inputs=[{"id": f"i{n}", "attributes": {"port": n}} for n in range(5600, 5604)]),
        after=fwd_state,
    )
    await p.same(
        "forwarding: WAF refuses the forwarder, rollback",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(waf={"overrides": {("POST", "/api/v1/forwarders/"): (500, "application/json", b"{}")}}),
        after=fwd_state,
    )
    await p.same(
        "forwarding: forwarder without id, rollback that fails",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(
            waf={"overrides": {("POST", "/api/v1/forwarders/"): (201, "application/json", b'{"x": 1}')}},
            overrides={
                ("DELETE", "/api/system/inputs/in00000000000000000001"): (500, "application/json", _json({"message": "cannot delete"})),
            },
        ),
        after=fwd_state,
    )
    await p.same(
        "forwarding: stream creation refused",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(overrides={("POST", "/api/streams"): (400, "application/json", _json({"message": "Invalid stream"}))}),
        after=fwd_state,
    )
    await p.same(
        "forwarding: input answer without id",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(overrides={("POST", "/api/system/inputs"): (201, "application/json", b"{}")}),
        after=fwd_state,
    )
    await p.same(
        "forwarding: test event fails",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(waf={"overrides": {("POST", "/api/v1/forwarders/71/test"): (502, "text/plain", b"x")}}),
        after=fwd_state,
        masked=masked,
    )
    await p.same(
        "forwarding: test reports failure",
        "POST",
        f"{fwd}/forwarding",
        t_admin,
        json={},
        before=setup(
            waf={
                "overrides": {
                    ("POST", "/api/v1/forwarders/71/test"): (200, "application/json", _json({"success": False, "message": "timeout"})),
                },
            },
        ),
        after=fwd_state,
        masked=masked,
    )
    await p.same("forwarding: remove", "DELETE", f"{fwd}/forwarding", t_admin, before=setup(provisioned=True), after=fwd_state)
    await p.same(
        "forwarding: remove with a sibling",
        "DELETE",
        f"{fwd}/forwarding",
        t_admin,
        before=setup(provisioned=True, sibling=True),
        after=fwd_state,
    )
    await p.same(
        "forwarding: remove with failures",
        "DELETE",
        f"{fwd}/forwarding",
        t_admin,
        before=setup(
            provisioned=True,
            waf={"overrides": {("DELETE", "/api/v1/forwarders/77"): (500, "text/plain", b"x")}},
            overrides={
                ("DELETE", "/api/system/inputs/in-1"): (404, "application/json", _json({"message": "gone"})),
                ("DELETE", "/api/streams/st-1"): (500, "application/json", _json({"message": "busy"})),
            },
        ),
        after=fwd_state,
    )
    await p.same(
        "forwarding: remove, forwarder already gone",
        "DELETE",
        f"{fwd}/forwarding",
        t_admin,
        before=setup(provisioned=True, waf={"overrides": {("DELETE", "/api/v1/forwarders/77"): (404, "application/json", b"{}")}}),
        after=fwd_state,
    )
    await p.same("forwarding: remove when not set up", "DELETE", f"{fwd}/forwarding", t_admin, before=setup(), after=fwd_state)
    await p.same("forwarding: analyst", "POST", f"{fwd}/forwarding", t_analyst, json={})

    # Deleting a WAF tears its forwarding down first (one request per side: the row goes).
    async def delete_forwarding(name, **kw):
        out = []
        for side, client in (("py", p.py), ("rs", p.rs)):
            setup(provisioned=True, **kw)(side)
            r, o = await p.call(client, "DELETE", fwd, t_admin)
            out.append((r.status_code, r.content, out_norm(o), waf_state("fwd")))
            sql(
                "INSERT INTO customer_waf_instances (id, customer_code, name, api_url, service_token_encrypted, token_prefix, "
                "verify_tls, ca_cert_pem, enabled, created_at) VALUES (:i, :c, 'fwd', :u, 'x', 'x', 0, NULL, 1, '2026-01-02 03:04:05')",
                i=IDS["fwd"],
                c=CUST_A,
                u=f"http://127.0.0.1:{WAF_PORT}",
            )
        check(f"{name} [{out[0][0]}]", out[0] == out[1], f"python {out[0]}\n        rust   {out[1]}")

    await delete_forwarding("delete a forwarding WAF")
    await delete_forwarding(
        "delete a forwarding WAF, Graylog refuses",
        overrides={("DELETE", "/api/system/inputs/in-1"): (500, "application/json", _json({"message": "no"}))},
    )
    reset_waf_row("fwd")


async def alert_checks(p, t_admin, t_analyst, t_portal):
    P = "/api/monitoring_alert/provision"

    def setup(version=6, **graylog):
        def before(side):
            GRAYLOG.reset(version=version, **graylog)
            pin_graylog_version(version)
            for table in ("fieldname", "assetfieldname", "timestampfieldname", "alerttitlefieldname", "iocfieldname"):
                sql(f"DELETE FROM incident_management_{table} WHERE source = 'waf'")

        return before

    def fields(side):
        return field_rows()

    defs = [d for d in samples.GRAYLOG_EVENT_DEFINITIONS if "WAF" not in d["title"]]
    blocked = {"search_within_last": 60, "execute_every": "120", "alert_name": "socfortress waf blocked"}
    brute = {"search_within_last": 1, "execute_every": 1, "alert_name": "SOCFORTRESS_WAF_BRUTE_FORCE", "graylog_instance": "network"}
    await p.same("WAF blocked alert", "POST", P, t_analyst, json=blocked, before=setup(definitions=defs), after=fields)
    await p.same(
        "WAF blocked alert on Graylog 7",
        "POST",
        P,
        t_analyst,
        json=blocked,
        before=setup(version=7, definitions=defs),
        after=fields,
        rust=p.rs7,
    )
    await p.same(
        "WAF blocked alert, already there",
        "POST",
        P,
        t_analyst,
        json=blocked,
        before=setup(definitions=defs + [samples.graylog_event_definition("6600000000000000000000e1", "SOCFORTRESS WAF BLOCKED")]),
        after=fields,
    )
    await p.same(
        "WAF brute force alert (allowlist, notification)",
        "POST",
        P,
        t_admin,
        json=brute,
        before=setup(definitions=defs),
        after=fields,
    )
    await p.same(
        "WAF brute force alert on Graylog 7",
        "POST",
        P,
        t_admin,
        json=brute,
        before=setup(version=7, definitions=defs),
        after=fields,
        rust=p.rs7,
    )
    await p.same(
        "WAF brute force: notification exists",
        "POST",
        P,
        t_admin,
        json=brute,
        before=setup(definitions=defs, notifications=[{"id": "nt-old", "title": "SEND TO COPILOT - WAF THRESHOLD"}]),
        after=fields,
    )
    await p.same(
        "WAF brute force: URL already allowed",
        "POST",
        P,
        t_admin,
        json=brute,
        before=setup(
            definitions=defs,
            allowlist={
                "entries": [
                    {"id": "a", "title": "t", "type": "literal", "value": "http://10.9.8.7:5000/api/incidents/alerts/create/threshold"},
                ],
                "disabled": False,
            },
        ),
        after=fields,
    )
    await p.same(
        "WAF brute force: allowlist disabled",
        "POST",
        P,
        t_admin,
        json=brute,
        before=setup(definitions=defs, allowlist={"entries": [], "disabled": True}),
        after=fields,
    )
    await p.same(
        "WAF brute force: no forwarding settings",
        "POST",
        P,
        t_admin,
        json=brute,
        before=setup(definitions=defs),
        after=fields,
        nokey=True,
    )
    await p.same("WAF brute force: already there", "POST", P, t_admin, json=brute, before=setup(), after=fields)
    for label, body in (
        ("zero window", {**blocked, "search_within_last": 0}),
        ("zero interval, window missing", {"execute_every": 0, "alert_name": "SOCFORTRESS_WAF_BLOCKED"}),
        ("missing ints", {"alert_name": "SOCFORTRESS_WAF_BLOCKED"}),
        ("bad instance", {**blocked, "graylog_instance": "graylog02"}),
        ("int as text", {**blocked, "search_within_last": "x"}),
    ):
        await p.same(f"WAF alert: {label}", "POST", P, t_analyst, json=body, before=setup(definitions=defs), after=fields)
    await p.same("WAF alert: no token", "POST", P, None, json=blocked)
    await p.same("WAF alert: portal user", "POST", P, t_portal, json=blocked)
    await p.same(
        "WAF alert: Graylog unreachable",
        "POST",
        P,
        t_analyst,
        json=blocked,
        before=lambda s: (setup(definitions=defs)(s), set_connector("Graylog", f"http://127.0.0.1:{CLOSED_PORT}", "admin", "pw")),
        after=fields,
    )
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog", "admin", "pässword")


async def main():
    servers = [
        start_stub(STUB_PORT, GRAYLOG, GRAYLOG_REC),
        start_stub(WAF_PORT, WAF, WAF_REC),
        start_stub(WAF_TLS_PORT, WAF, WAF_REC, tls=True),
    ]
    seed()
    procs = [start_rust(RS_PORT), start_rust(RS_NOKEY_PORT, unset=NOKEY_UNSET), start_rust(RS7_PORT)]
    p = Pair()
    t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
    t_analyst_b, t_portal = token(ANALYST_B, ["analyst"]), token(PORTAL, ["customer_user"])
    try:
        sections = os.environ.get("PROVISIONING_PARITY_SECTIONS", "waf,forwarding,alerts").split(",")
        if "waf" in sections:
            await waf_checks(p, t_admin, t_analyst, t_analyst_b, t_portal)
        if "forwarding" in sections:
            await forwarding_checks(p, t_admin, t_analyst)
        if "alerts" in sections:
            await alert_checks(p, t_admin, t_analyst, t_portal)
    finally:
        await p.close()
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        cleanup()
        for s in servers:
            s.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
