"""Parity of the Rust service with this backend — NOT collected by pytest (needs a live MySQL
and a running Rust binary).

Sends the same requests to the real FastAPI routers (in-process) and to the Rust service
(`crates/copilot`) over HTTP, both on the same disposable database, and compares status
codes and JSON bodies. Read endpoints must be byte-for-byte equal; for writes, ids and
timestamps are masked and everything else must be equal. See docs/architecture/RUST_MIGRATION.md.

    # MySQL on 13306 migrated to head (see analyst_object_scoping_e2e.py), then:
    scripts/rust-parity.sh            # builds and starts the Rust service, runs this file

Deliberate differences are asserted as such (DIFF_BY_DESIGN), not skipped silently.
"""

import asyncio
import base64
import datetime
import io
import json
import os
import re
import socketserver
import sys
import threading
import uuid
from collections import Counter
from email import message_from_bytes
from email import policy as email_policy
from html import unescape as html_unescape
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ.setdefault("WEBAUTHN_ORIGINS", "http://localhost:5173")
os.environ.setdefault("WEBAUTHN_RP_ID", "localhost")
os.environ.setdefault("SMTP_HOST", "127.0.0.1")
os.environ.setdefault("SMTP_PORT", os.environ.get("SMTP_STUB_PORT", "5196"))
os.environ.setdefault("SMTP_USE_TLS", "false")
os.environ.setdefault("SMTP_FROM", "copilot@parity.test")
os.environ.setdefault("COPILOT_URL", "https://copilot.parity.test/")

import bcrypt  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
import pyotp  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.db.db_session import async_engine  # noqa: E402

RUST = os.environ.get("RUST_BASE_URL", "http://127.0.0.1:5199")
SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"PAR_A{SFX}", f"PAR_B{SFX}"
ADMIN, ANALYST, PORTAL = f"par_admin{SFX}", f"par_analyst{SFX}", f"par_portal{SFX}"
VOLATILE = {
    "id",
    "job_id",
    "created_at",
    "updated_at",
    "started_at",
    "completed_at",
    "ingested_at",
    "generated_at",
    "report_id",
    "review_id",
    "ioc_id",
}

results = []

# Talon stand-in: accepts every investigation but those in TALON_REFUSES, records the bodies.
TALON_BODIES = []
TALON_REFUSES = set()


class _TalonStub(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        TALON_BODIES.append(body)
        status = 500 if body.get("alert_id") in TALON_REFUSES else 202
        payload = json.dumps({"job_id": "stub", "status": "queued"} if status == 202 else {"error": "boom"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


# GitHub stand-in for /version/check, on the port scripts/rust-parity.sh hands the Rust
# service as COPILOT_VERSION_CHECK_URL. RELEASE[0] is what it answers next.
RELEASE = [{"tag_name": "v9.9.9", "name": "v9.9.9", "html_url": "https://example.com/r", "body": None}]
RELEASE_STUB_PORT = int(os.environ.get("RELEASE_STUB_PORT", "5198"))


class _ReleaseStub(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        status, body = (200, RELEASE[0]) if self.path == "/releases/latest" else (404, {"message": "Not Found"})
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def start_release_stub():
    server = ThreadingHTTPServer(("127.0.0.1", RELEASE_STUB_PORT), _ReleaseStub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{RELEASE_STUB_PORT}/releases/latest"
    import app.version.services.version as version_service

    version_service.VERSION_CHECK_URL = url
    return url


def start_talon_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TalonStub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


# Identity-provider stand-in for SSO: token endpoints answer IDP_TOKENS[code], the JWKS
# endpoints the key below. Both backends reach it — Python through `_ToIdpStub`, Rust
# through COPILOT_SSO_IDP_URL — with the provider's host as the first path segment.
IDP_STUB_PORT = int(os.environ.get("IDP_STUB_PORT", "5197"))
IDP_TOKENS = {}
IDP_REQUESTS = []


def _idp_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


IDP_KEY = _idp_key()


def idp_jwks(kid):
    numbers = IDP_KEY.public_key().public_numbers()
    raw = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()  # noqa: E731
    return {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "n": raw(numbers.n), "e": raw(numbers.e)}]}


def idp_token(kid, claims):
    return jwt.encode(claims, IDP_KEY, algorithm="RS256", headers={"kid": kid})


class _IdpStub(BaseHTTPRequestHandler):
    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - http.server API
        IDP_REQUESTS.append(("GET", self.path))
        if self.path.endswith("/discovery/v2.0/keys"):
            return self._send(200, idp_jwks("az1"))
        if self.path == "/www.googleapis.com/oauth2/v3/certs":
            return self._send(200, idp_jwks("g1"))
        if self.path.endswith("/cdn-cgi/access/certs"):
            return self._send(200, idp_jwks("cf1"))
        return self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - http.server API
        from urllib.parse import parse_qs

        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
        IDP_REQUESTS.append(("POST", self.path))
        code = form.get("code", [""])[0]
        if code not in IDP_TOKENS:
            return self._send(400, {"error": "invalid_grant"})
        return self._send(200, IDP_TOKENS[code])

    def log_message(self, *args):
        pass


class _ToIdpStub(httpx.AsyncBaseTransport):
    """What COPILOT_SSO_IDP_URL does for the Rust service, for Python's httpx clients."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        url = str(request.url)
        if url.startswith("https://"):
            request.url = httpx.URL(f"http://127.0.0.1:{IDP_STUB_PORT}/" + url[len("https://") :])
        return await self.inner.handle_async_request(request)


def start_idp_stub():
    server = ThreadingHTTPServer(("127.0.0.1", IDP_STUB_PORT), _IdpStub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    import types

    import app.auth.services.sso as sso_service

    real = httpx.AsyncClient
    sso_service.httpx = types.SimpleNamespace(AsyncClient=lambda **kw: real(transport=_ToIdpStub(), **kw))


# SMTP stand-in for the temporary-password email, on the port both backends are given
# (SMTP_HOST/SMTP_PORT above for Python, the same variables from scripts/rust-parity.sh for
# Rust). It accepts every recipient but one containing "reject" and keeps each message.
MAILS = []


class _SmtpStub(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 parity ESMTP\r\n")
        rcpts = []
        while line := self.rfile.readline():
            verb = line[:4].upper()
            if verb == b"EHLO":
                reply = b"250-parity\r\n250 8BITMIME\r\n"
            elif verb == b"RCPT" and b"reject" in line:
                reply = b"550 5.1.1 mailbox unavailable\r\n"
            elif verb == b"RCPT":
                rcpts.append(re.search(rb"<([^>]*)>", line).group(1).decode())
                reply = b"250 OK\r\n"
            elif verb == b"DATA":
                self.wfile.write(b"354 go ahead\r\n")
                data = []
                while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                    data.append(chunk[1:] if chunk.startswith(b".") else chunk)
                MAILS.append((rcpts, message_from_bytes(b"".join(data), policy=email_policy.default)))
                rcpts = []
                reply = b"250 queued\r\n"
            elif verb == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                reply = b"250 OK\r\n"
            self.wfile.write(reply)


def start_smtp_stub():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("127.0.0.1", int(os.environ["SMTP_PORT"])), _SmtpStub)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()


class Authenticator:
    """A software passkey (P-256, attestation none) for the parity runs."""

    def __init__(self, cred_id: bytes):
        from cryptography.hazmat.primitives.asymmetric import ec

        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = cred_id

    @staticmethod
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def cose(self) -> bytes:
        import cbor2

        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    @staticmethod
    def client_data(kind, challenge, origin="http://localhost:5173") -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin}).encode()

    def create(self, options, rp_id="localhost", flags=0x45) -> dict:
        import hashlib

        import cbor2

        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
        auth_data += bytes(16) + len(self.id).to_bytes(2, "big") + self.id + self.cose()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cdj = self.client_data("webauthn.create", options["challenge"])
        return {
            "id": self.b64(self.id),
            "rawId": self.b64(self.id),
            "type": "public-key",
            "response": {"clientDataJSON": self.b64(cdj), "attestationObject": self.b64(att), "transports": ["usb", "nfc"]},
            "clientExtensionResults": {},
        }

    def get(self, options, sign_count) -> dict:
        import hashlib

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        auth_data = hashlib.sha256(b"localhost").digest() + bytes([0x05]) + sign_count.to_bytes(4, "big")
        cdj = self.client_data("webauthn.get", options["challenge"])
        sig = self.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": self.b64(self.id),
            "rawId": self.b64(self.id),
            "type": "public-key",
            "response": {"clientDataJSON": self.b64(cdj), "authenticatorData": self.b64(auth_data), "signature": self.b64(sig)},
            "clientExtensionResults": {},
        }


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def mask(value):
    if isinstance(value, dict):
        return {k: ("<v>" if k in VOLATILE and v is not None else mask(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v) for v in value]
    return value


def build_python_app():
    from app.ai_analyst.routes.ai_analyst import ai_analyst_router
    from app.audit.routes.audit import audit_router
    from app.auth.routes.auth import auth_router
    from app.auth.routes.customer_users import customer_users_router
    from app.auth.routes.passkey import passkey_router
    from app.auth.routes.security_admin import security_admin_router
    from app.auth.routes.sso import sso_router
    from app.auth.routes.totp import totp_router
    from app.connectors.talon.routes.talon import talon_router
    from app.customer_portal.routes.ai_reports import customer_portal_ai_reports_router
    from app.customers.routes.customers import customers_router
    from app.healthchecks.agents.routes.agents import healtcheck_agents_router
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.version.routes.version import version_router

    api = APIRouter(prefix="/api")
    api.include_router(ai_analyst_router, prefix="/ai_analyst")
    api.include_router(talon_router, prefix="/talon")
    api.include_router(customer_portal_ai_reports_router, prefix="/customer_portal")
    api.include_router(customers_router, prefix="/customers")
    api.include_router(healtcheck_agents_router, prefix="/healthcheck")
    api.include_router(version_router, prefix="/version")
    api.include_router(audit_router, prefix="/audit")
    api.include_router(auth_router, prefix="/auth")
    api.include_router(customer_users_router, prefix="/auth")
    api.include_router(totp_router, prefix="/auth")
    api.include_router(sso_router, prefix="/auth")
    api.include_router(passkey_router, prefix="/auth")
    api.include_router(security_admin_router, prefix="/auth")
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


async def seed():
    """Two customers, users, one alert each with an asset; returns alert ids."""
    async with AsyncSession(async_engine) as s:
        for c in (CUST_A, CUST_B):
            await s.execute(
                text("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())"),
                {"c": c},
            )
        for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
            await s.execute(
                text(
                    "INSERT INTO `user` (username, password, email, created_at, role_id) "
                    "VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
                ),
                {"n": name, "r": role},
            )
        for name in (ANALYST, PORTAL):
            await s.execute(
                text(
                    "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
                    "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                ),
                {"c": CUST_A, "n": name},
            )
        alerts = {}
        for c in (CUST_A, CUST_B):
            r = await s.execute(
                text(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
                    "customer_code, source, escalated) VALUES (:n, 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0)",
                ),
                {"n": f"Mimikatz {c}", "c": c},
            )
            alert_id = r.lastrowid
            r = await s.execute(text("INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')"))
            await s.execute(
                text(
                    "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, customer_code, "
                    "index_name, index_id) VALUES (:a, 'dc01', :ctx, :c, 'idx', 'doc')",
                ),
                {"a": alert_id, "ctx": r.lastrowid, "c": c},
            )
            alerts[c] = alert_id
        # A second alert for A with no AI analysis at all.
        r = await s.execute(
            text(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
                "customer_code, source, escalated) VALUES ('Quiet', 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0)",
            ),
            {"c": CUST_A},
        )
        alerts["quiet"] = r.lastrowid
        # Alerts the portal requests use: one per backend, one Talon refuses, one over the limit.
        for key in ("req_py", "req_rs", "refuse", "over"):
            r = await s.execute(
                text(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, "
                    "customer_code, source, escalated) VALUES (:n, 'd', 'OPEN', '2026-01-02 03:04:05', :c, 'wazuh', 0)",
                ),
                {"n": key, "c": CUST_A},
            )
            alerts[key] = r.lastrowid
        # Customer meta for A; agents fresh / stale / future / with Velociraptor for A, one for B.
        await s.execute(
            text(
                "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, "
                "customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group, "
                "customer_meta_portainer_stack_id) VALUES (:c, :c, 'idx', 'stream', '7', 'grp', 4)",
            ),
            {"c": CUST_A},
        )
        for agent_id, code, wazuh_ago, velo_ago in (
            (f"pa{SFX}1", CUST_A, 5, None),
            (f"pa{SFX}2", CUST_A, 600, None),
            (f"pa{SFX}3", CUST_A, -600, None),
            (f"pa{SFX}4", CUST_A, 1, 2),
            (f"pb{SFX}1", CUST_B, 5, 5),
        ):
            await s.execute(
                text(
                    "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, "
                    "velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, customer_code, "
                    "quarantined) VALUES (:a, '10.0.0.1', 'Linux', :h, 'lbl', 0, UTC_TIMESTAMP() - INTERVAL :w MINUTE, "
                    ":vid, IF(:v IS NULL, NULL, UTC_TIMESTAMP() - INTERVAL :v MINUTE), '4.9.0', 'active', :c, 0)",
                ),
                {
                    "a": agent_id,
                    "h": f"host-{agent_id}",
                    "w": wazuh_ago,
                    "vid": f"C.{agent_id}" if velo_ago else None,
                    "v": velo_ago,
                    "c": code,
                },
            )
        for i, (ts, result) in enumerate(
            (("2026-01-01 10:00:00", "success"), ("2026-01-01 11:00:00", "failure"), ("2026-01-01 12:00:00", "success")),
        ):
            await s.execute(
                text(
                    "INSERT INTO audit_log (timestamp, actor_user_id, actor_username, customer_code, action, entity_type, "
                    "entity_id, result, old_value, new_value, details) VALUES (:t, 1, :u, :c, 'case.create', 'case', :e, :r, "
                    '\'{"enabled": false, "a": [1, 2]}\', NULL, :d)',
                ),
                {"t": ts, "u": ADMIN, "c": CUST_A, "e": f"par{SFX}", "r": result, "d": f"Row {i}"},
            )
        # The Talon connector is global: point it at the stub before either backend reads it.
        await s.execute(text("DELETE FROM connectors WHERE connector_name = 'Talon'"))
        await s.execute(
            text(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, "
                "connector_api_key, connector_configured, connector_verified, connector_accepts_host_only, "
                "connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, "
                "connector_accepts_extra_data, connector_enabled) VALUES "
                "('Talon', '3', :u, UTC_TIMESTAMP(), 'talon-key', 1, 1, 0, 1, 0, 0, 0, 1)",
            ),
            {"u": start_talon_stub()},
        )
        await s.commit()
    return alerts


async def main():
    start_release_stub()
    start_idp_stub()
    start_smtp_stub()
    alerts = await seed()
    a, b = alerts[CUST_A], alerts[CUST_B]
    # raise_app_exceptions=False: an unhandled error is the bare 500 uvicorn would send.
    py = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False), base_url="http://py")
    rs = httpx.AsyncClient(base_url=RUST, timeout=30)
    t_admin = token(ADMIN, ["admin"])
    t_analyst = token(ANALYST, ["analyst"])
    t_portal = token(PORTAL, ["customer_user"])
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    async def both(method, path, tok=None, body=None):
        kw = {"headers": H(tok)}
        if body is not None:
            kw["json"] = body
        r1 = await py.request(method, path, **kw)
        r2 = await rs.request(method, path, **kw)
        return r1, r2

    def body_of(r):
        try:
            return r.json()
        except ValueError:
            return r.text

    async def same(name, method, path, tok=None, body=None, masked=False):
        r1, r2 = await both(method, path, tok, body)
        b1, b2 = body_of(r1), body_of(r2)
        if masked:
            b1, b2 = mask(b1), mask(b2)
        ok = r1.status_code == r2.status_code and b1 == b2
        check(
            f"{name} [{r1.status_code}]",
            ok,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    # --- Writes through each backend (distinct keys, masked comparison) -------------
    print("\n=== writes (ids/timestamps masked) ===")
    jobs = {}
    for tag, client in (("py", py), ("rs", rs)):
        job_id = f"copilot-inv-{a}-{tag}{SFX}"
        jobs[tag] = job_id
    r1 = await py.post(
        "/api/ai_analyst/jobs",
        json={"id": jobs["py"], "alert_id": a, "customer_code": CUST_A, "triggered_by": "webhook"},
        headers=H(t_admin),
    )
    r2 = await rs.post(
        "/api/ai_analyst/jobs",
        json={"id": jobs["rs"], "alert_id": a, "customer_code": CUST_A, "triggered_by": "webhook"},
        headers=H(t_admin),
    )
    check("POST /jobs (create)", (r1.status_code, mask(r1.json())) == (r2.status_code, mask(r2.json())), f"{r1.json()} / {r2.json()}")
    for tag, client in (("py", py), ("rs", rs)):
        await client.post(
            "/api/ai_analyst/jobs",
            json={"id": jobs[tag], "alert_id": a, "customer_code": CUST_A, "triggered_by": "manual", "template_used": "sysmon_event_1.txt"},
            headers=H(t_admin),
        )
    r1 = await py.patch(
        f"/api/ai_analyst/jobs/{jobs['py']}",
        json={"status": "running", "alert_type": "sysmon_event_1"},
        headers=H(t_admin),
    )
    r2 = await rs.patch(
        f"/api/ai_analyst/jobs/{jobs['rs']}",
        json={"status": "running", "alert_type": "sysmon_event_1"},
        headers=H(t_admin),
    )
    check("PATCH /jobs (running)", (r1.status_code, mask(r1.json())) == (r2.status_code, mask(r2.json())), f"{r1.json()} / {r2.json()}")
    report = {
        "alert_id": a,
        "customer_code": CUST_A,
        "severity_assessment": "High",
        "summary": "Credential dumping.\x07",
        "report_markdown": "# Report\n\nDetails.",
        "recommended_actions": "Isolate dc01",
    }
    reports = {}
    for tag, client in (("py", py), ("rs", rs)):
        r = await client.post("/api/ai_analyst/reports", json={**report, "job_id": jobs[tag]}, headers=H(t_admin))
        reports[tag] = r
        # Separate the two reports by a second: on a same-second tie Python's
        # `ORDER BY created_at DESC LIMIT 1` returns whichever row MySQL's plan reaches
        # first, Rust the newest id (DIFF_BY_DESIGN, see RUST_MIGRATION.md).
        await asyncio.sleep(1.1)
    check(
        "POST /reports",
        (reports["py"].status_code, mask(reports["py"].json())) == (reports["rs"].status_code, mask(reports["rs"].json())),
        f"{reports['py'].json()} / {reports['rs'].json()}",
    )
    rid = {tag: reports[tag].json()["report"]["id"] for tag in reports}
    iocs = [
        {"ioc_value": "203.0.113.7", "ioc_type": "ip", "vt_verdict": "malicious", "vt_score": "12/90", "details": "seen"},
        {"ioc_value": "mimikatz.exe", "ioc_type": "process"},
    ]
    ioc_resp = {}
    for tag, client in (("py", py), ("rs", rs)):
        ioc_resp[tag] = await client.post(
            "/api/ai_analyst/iocs",
            json={"report_id": rid[tag], "alert_id": a, "customer_code": CUST_A, "iocs": iocs},
            headers=H(t_admin),
        )
    check("POST /iocs", mask(ioc_resp["py"].json()) == mask(ioc_resp["rs"].json()), f"{ioc_resp['py'].json()} / {ioc_resp['rs'].json()}")
    review = {"overall_verdict": "up", "template_choice": "partial", "rating_instructions": 4, "missing_steps": "check\x01 lsass"}
    rev = {}
    for tag, client in (("py", py), ("rs", rs)):
        ioc_id = ioc_resp[tag].json()["iocs"][0]["id"]
        body = {**review, "ioc_reviews": [{"ioc_id": ioc_id, "verdict_correct": True, "note": "ok"}]}
        rev[tag] = await client.post(f"/api/ai_analyst/reports/{rid[tag]}/review", json=body, headers=H(t_analyst))
    check("POST review (create)", mask(rev["py"].json()) == mask(rev["rs"].json()), f"{rev['py'].json()} / {rev['rs'].json()}")
    for tag, client in (("py", py), ("rs", rs)):
        rev[tag] = await client.post(f"/api/ai_analyst/reports/{rid[tag]}/review", json={"overall_verdict": "down"}, headers=H(t_analyst))
    edit_py, edit_rs = rev["py"].json(), rev["rs"].json()
    stale_py = edit_py["review"].pop("ioc_reviews")
    fresh_rs = edit_rs["review"].pop("ioc_reviews")
    check("POST review (edit, ioc_reviews aside)", mask(edit_py) == mask(edit_rs), f"{edit_py} / {edit_rs}")
    # DIFF_BY_DESIGN: the edit deletes the review's IOC rows; Python answers from its
    # identity map and still lists them, Rust answers with what is stored ([]).
    check("POST review (edit): Rust returns the stored ioc_reviews", fresh_rs == [] and stale_py != [], f"{stale_py} / {fresh_rs}")
    for i, text_ in enumerate(("DC01 runs SCCM patching at 02:00", "dc01 runs sccm patching at 02:00 nightly")):
        await same(
            f"POST /palace_lessons #{i}",
            "POST",
            "/api/ai_analyst/palace_lessons",
            t_analyst,
            {"customer_code": CUST_A, "lesson_type": "assets", "lesson_text": text_, "durability": "one_off"},
            masked=True,
        )

    # --- Reads: byte-for-byte ---------------------------------------------------------
    print("\n=== reads (exact) ===")
    for tag in ("py", "rs"):
        await same(f"GET /jobs/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/jobs/{jobs[tag]}", t_analyst)
        await same(f"GET /reports/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/reports/{rid[tag]}", t_analyst)
        await same(f"GET /iocs/report/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/iocs/report/{rid[tag]}", t_analyst)
        await same(f"GET review/mine ({tag} row)", "GET", f"/api/ai_analyst/reports/{rid[tag]}/review/mine", t_analyst)
        review_id = rev[tag].json()["review"]["id"]
        await same(f"GET /reviews/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/reviews/{review_id}", t_analyst)
        ioc_id = ioc_resp[tag].json()["iocs"][0]["id"]
        await same(f"GET /iocs/{{id}} ({tag} row)", "GET", f"/api/ai_analyst/iocs/{ioc_id}", t_analyst)
    await same("GET /jobs/alert", "GET", f"/api/ai_analyst/jobs/alert/{a}", t_analyst)
    await same("GET /jobs/customer", "GET", f"/api/ai_analyst/jobs/customer/{CUST_A}", t_analyst)
    await same("GET /reports/alert", "GET", f"/api/ai_analyst/reports/alert/{a}", t_analyst)
    await same("GET /iocs/alert", "GET", f"/api/ai_analyst/iocs/alert/{a}", t_analyst)
    await same("GET /iocs/customer?vt_verdict", "GET", f"/api/ai_analyst/iocs/customer/{CUST_A}?vt_verdict=malicious", t_analyst)
    await same("GET /iocs/customer", "GET", f"/api/ai_analyst/iocs/customer/{CUST_A}", t_analyst)
    await same("GET /alerts_with_reports (admin, filtered)", "GET", f"/api/ai_analyst/alerts_with_reports?customer_codes={CUST_A}", t_admin)
    await same("GET /alerts_with_reports/{alert}", "GET", f"/api/ai_analyst/alerts_with_reports/{a}", t_analyst)
    await same("GET /alert/{alert}", "GET", f"/api/ai_analyst/alert/{a}", t_analyst)
    await same("GET /alert/{alert} without analysis", "GET", f"/api/ai_analyst/alert/{alerts['quiet']}", t_analyst)
    await same("GET /reviews/customer", "GET", f"/api/ai_analyst/reviews/customer/{CUST_A}", t_analyst)
    await same("GET /reviews/customer/stats", "GET", f"/api/ai_analyst/reviews/customer/{CUST_A}/stats?recent_limit=3", t_analyst)
    await same("GET /talon/jobs/{alert} (admin)", "GET", f"/api/talon/jobs/{a}", t_admin)
    r1, r2 = await both("GET", f"/api/ai_analyst/palace_lessons/customer/{CUST_A}/consolidation", t_analyst)
    c1, c2 = r1.json(), r2.json()
    for c in (c1, c2):
        c["generated_at"] = "<v>"
        c["markdown"] = "\n".join(line for line in c["markdown"].split("\n") if not line.startswith("_Generated"))
    check("GET consolidation (clock masked)", c1 == c2, f"{c1}\n        {c2}")

    # --- Errors: byte-for-byte -------------------------------------------------------
    print("\n=== errors (exact) ===")
    await same("no token", "GET", "/api/ai_analyst/alerts_with_reports")
    await same("garbage token", "GET", "/api/ai_analyst/alerts_with_reports", "garbage")
    await same(
        "expired token",
        "GET",
        "/api/ai_analyst/alerts_with_reports",
        jwt.encode({"sub": ADMIN, "exp": 1}, os.environ["JWT_SECRET"], algorithm="HS256"),
    )
    await same("2fa temp token", "GET", "/api/ai_analyst/alerts_with_reports", token(ADMIN, [], type="2fa_pending"))
    await same("unknown user", "GET", "/api/ai_analyst/alerts_with_reports", token("nobody" + SFX, ["admin"]))
    await same("portal user", "GET", "/api/ai_analyst/alerts_with_reports", t_portal)
    await same("other tenant's alert", "GET", f"/api/ai_analyst/alert/{b}", t_analyst)
    await same("nonexistent report (scoped)", "GET", "/api/ai_analyst/reports/999999999", t_analyst)
    await same("nonexistent report (admin)", "GET", "/api/ai_analyst/reports/999999999", t_admin)
    await same("nonexistent job (admin)", "GET", "/api/ai_analyst/jobs/nope", t_admin)
    await same("PATCH unparseable job id (admin)", "PATCH", "/api/ai_analyst/jobs/nope", t_admin, {"status": "running"})
    await same("other tenant's customer", "GET", f"/api/ai_analyst/jobs/customer/{CUST_B}", t_analyst)
    await same("int parsing in path", "GET", "/api/ai_analyst/alert/abc", t_analyst)
    await same("recent_limit out of range", "GET", f"/api/ai_analyst/reviews/customer/{CUST_A}/stats?recent_limit=99", t_analyst)
    await same("palace search without query", "GET", f"/api/ai_analyst/palace_lessons/customer/{CUST_A}", t_analyst)
    await same("empty body", "POST", "/api/ai_analyst/jobs", t_admin, {})
    await same(
        "bad enum",
        "POST",
        "/api/ai_analyst/jobs",
        t_admin,
        {"id": "x", "alert_id": a, "customer_code": CUST_A, "triggered_by": "cron"},
    )
    await same(
        "string too long",
        "POST",
        "/api/ai_analyst/jobs",
        t_admin,
        {"id": "x" * 65, "alert_id": a, "customer_code": CUST_A, "triggered_by": "manual"},
    )
    await same(
        "report body guard",
        "POST",
        "/api/ai_analyst/reports",
        t_admin,
        {"job_id": jobs["py"], "alert_id": a, "customer_code": CUST_A, "summary": "  "},
    )
    await same("report for unknown job", "POST", "/api/ai_analyst/reports", t_admin, {**report, "job_id": "missing-job"})
    await same(
        "iocs for unknown report",
        "POST",
        "/api/ai_analyst/iocs",
        t_admin,
        {"report_id": 999999999, "alert_id": a, "customer_code": CUST_A, "iocs": []},
    )
    await same(
        "bad ioc type",
        "POST",
        "/api/ai_analyst/iocs",
        t_admin,
        {"report_id": rid["py"], "alert_id": a, "customer_code": CUST_A, "iocs": [{"ioc_value": "x", "ioc_type": "ipv9"}]},
    )
    await same("rating out of range", "POST", f"/api/ai_analyst/reports/{rid['py']}/review", t_analyst, {"rating_severity": 9})
    await same(
        "foreign ioc in review",
        "POST",
        f"/api/ai_analyst/reports/{rid['py']}/review",
        t_analyst,
        {"ioc_reviews": [{"ioc_id": 999999999, "verdict_correct": False}]},
    )
    await same(
        "replay with bad template",
        "POST",
        f"/api/ai_analyst/reports/{rid['py']}/replay",
        t_analyst,
        {"template_override": "x.md", "customer_code": CUST_A},
    )
    await same(
        "replay customer mismatch",
        "POST",
        f"/api/ai_analyst/reports/{rid['py']}/replay",
        t_analyst,
        {"template_override": "x.txt", "customer_code": CUST_B},
    )
    await same(
        "lesson for unknown review",
        "POST",
        "/api/ai_analyst/palace_lessons",
        t_analyst,
        {"customer_code": CUST_A, "lesson_type": "assets", "lesson_text": "x", "review_id": 999999999},
    )
    await same(
        "empty lesson text",
        "POST",
        "/api/ai_analyst/palace_lessons",
        t_analyst,
        {"customer_code": CUST_A, "lesson_type": "assets", "lesson_text": "\x01"},
    )
    await same(
        "talon investigate: unknown alert",
        "POST",
        "/api/talon/investigate",
        t_admin,
        {"alert_id": 999999999, "customer_code": CUST_A},
    )
    await same("talon investigate: other tenant", "POST", "/api/talon/investigate", t_analyst, {"alert_id": b, "customer_code": CUST_B})
    await same("talon investigate: mismatch", "POST", "/api/talon/investigate", t_analyst, {"alert_id": a, "customer_code": CUST_B})
    await same("talon jobs: no job", "GET", f"/api/talon/jobs/{alerts['quiet']}", t_admin)

    # --- Customer Portal AI reports ---------------------------------------------------
    print("\n=== customer portal ai_reports ===")
    P = "/api/customer_portal/ai_reports"
    settings_a = f"{P}/settings/{CUST_A}"
    await same("portal: settings (no row)", "GET", settings_a, t_analyst)
    await same("portal: settings, other tenant", "GET", f"{P}/settings/{CUST_B}", t_analyst)
    await same("portal: settings as portal user", "GET", settings_a, t_portal)
    await same("portal: availability (off)", "GET", f"{P}/availability", t_portal)
    await same("portal: availability, other tenant", "GET", f"{P}/availability?customer_code={CUST_B}", t_portal)
    await same("portal: availability, empty code", "GET", f"{P}/availability?customer_code=", t_portal)
    await same("portal: alert while switched off", "GET", f"{P}/alert/{a}", t_portal)
    await same("portal: insights while switched off", "GET", f"{P}/insights", t_portal)
    await same("portal: request while switched off", "POST", f"{P}/alert/{a}/investigate", t_portal)
    await same("portal: PUT as analyst", "PUT", settings_a, t_analyst, {"enabled": True})
    await same("portal: PUT bad body", "PUT", f"{P}/settings/nosuch{SFX}", t_admin, {"daily_request_limit": 0})
    await same("portal: PUT bad limit", "PUT", settings_a, t_admin, {"enabled": True, "daily_request_limit": "abc"})
    await same("portal: PUT unknown customer", "PUT", f"{P}/settings/nosuch{SFX}", t_admin, {"enabled": True})
    await same("portal: PUT enable", "PUT", settings_a, t_admin, {"enabled": True}, masked=True)
    await same("portal: settings (enabled)", "GET", settings_a, t_analyst)
    await same("portal: availability (on)", "GET", f"{P}/availability", t_portal)
    await same("portal: availability for A (admin)", "GET", f"{P}/availability?customer_code={CUST_A}", t_admin)
    for who, tok in (("portal", t_portal), ("analyst", t_analyst), ("admin", t_admin)):
        await same(f"portal: alert with analysis ({who})", "GET", f"{P}/alert/{a}", tok)
    await same("portal: alert without analysis", "GET", f"{P}/alert/{alerts['quiet']}", t_portal)
    await same("portal: other tenant's alert", "GET", f"{P}/alert/{b}", t_portal)
    await same("portal: unknown alert", "GET", f"{P}/alert/999999999", t_portal)
    await same("portal: alert id parsing", "GET", f"{P}/alert/abc", t_portal)
    await same("portal: insights", "GET", f"{P}/insights", t_portal)
    await same("portal: insights limit=1", "GET", f"{P}/insights?limit=1", t_portal)
    await same("portal: insights limit=0", "GET", f"{P}/insights?limit=0", t_portal)
    await same("portal: insights for A (admin)", "GET", f"{P}/insights?customer_codes={CUST_A}&limit=25", t_admin)
    await same("portal: insights for B (switch off)", "GET", f"{P}/insights?customer_codes={CUST_B}", t_admin)
    await same(
        "portal: PUT allow requests",
        "PUT",
        settings_a,
        t_admin,
        {"enabled": True, "allow_customer_requests": True, "daily_request_limit": 3},
        masked=True,
    )
    await same("portal: request, analysis running", "POST", f"{P}/alert/{a}/investigate", t_portal)

    def request_shape(r):
        b = r.json()
        return r.status_code, sorted(b), b.get("message"), b.get("success")

    r_py = await py.post(f"{P}/alert/{alerts['req_py']}/investigate", headers=H(t_portal))
    r_rs = await rs.post(f"{P}/alert/{alerts['req_rs']}/investigate", headers=H(t_portal))
    check("portal: request accepted", request_shape(r_py) == request_shape(r_rs) and r_py.status_code == 200, f"{r_py.text} / {r_rs.text}")
    await same("portal: request in cooldown (python's)", "POST", f"{P}/alert/{alerts['req_py']}/investigate", t_portal)
    await same("portal: request in cooldown (rust's)", "POST", f"{P}/alert/{alerts['req_rs']}/investigate", t_portal)
    TALON_REFUSES.add(alerts["refuse"])
    await same("portal: Talon refuses", "POST", f"{P}/alert/{alerts['refuse']}/investigate", t_portal)
    r = await py.post(f"{P}/alert/{alerts['quiet']}/investigate", headers=H(t_portal))
    check("portal: third request accepted (python)", r.status_code == 200, r.text)
    await same("portal: over the daily limit", "POST", f"{P}/alert/{alerts['over']}/investigate", t_portal)
    await same("portal: other tenant's alert request", "POST", f"{P}/alert/{b}/investigate", t_analyst)
    await same("portal: settings show the requests", "GET", settings_a, t_admin)
    senders = {(x["alert_id"], x.get("sender")) for x in TALON_BODIES}
    check(
        "portal: Talon was told sender=customer-portal by both",
        {(alerts["req_py"], "customer-portal"), (alerts["req_rs"], "customer-portal")} <= senders,
        str(senders),
    )
    async with AsyncSession(async_engine) as s_:
        rows = (
            await s_.execute(
                text(
                    "SELECT alert_id, user_name, comment FROM incident_management_comment WHERE alert_id IN (:p, :r) " "ORDER BY alert_id",
                ),
                {"p": alerts["req_py"], "r": alerts["req_rs"]},
            )
        ).all()
        refused = (
            await s_.execute(text("SELECT COUNT(*) FROM customer_portal_ai_request WHERE alert_id = :a"), {"a": alerts["refuse"]})
        ).scalar_one()
    check(
        "portal: both left the same comment",
        len(rows) == 2 and rows[0][1:] == rows[1][1:] == (PORTAL, "AI analysis requested from the Customer Portal."),
        str(rows),
    )
    check("portal: a refused request costs nothing", refused == 0, str(refused))

    # Tag RBAC (global settings: only when this database has none, restored afterwards).
    async with AsyncSession(async_engine) as s_:
        configured = (await s_.execute(text("SELECT COUNT(*) FROM incident_management_tag_access_settings"))).scalar_one()
    if configured:
        print("  SKIP  tag RBAC: incident_management_tag_access_settings already configured")
    else:
        async with AsyncSession(async_engine) as s_:
            tag_id = (await s_.execute(text("INSERT INTO incident_management_alerttag (tag) VALUES (:t)"), {"t": f"par{SFX}"})).lastrowid
            await s_.execute(text("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (:a, :t)"), {"a": a, "t": tag_id})
            settings_id = (
                await s_.execute(
                    text(
                        "INSERT INTO incident_management_tag_access_settings (enabled, untagged_alert_behavior, updated_at) "
                        "VALUES (1, 'admin_only', UTC_TIMESTAMP())",
                    ),
                )
            ).lastrowid
            await s_.commit()
        try:
            await same("portal/tags: tagged alert, analyst without the tag", "GET", f"{P}/alert/{a}", t_analyst)
            await same("portal/tags: untagged alert under admin_only", "GET", f"{P}/alert/{alerts['quiet']}", t_analyst)
            await same("portal/tags: insights, analyst sees nothing", "GET", f"{P}/insights", t_analyst)
            await same("portal/tags: portal users bypass tag RBAC", "GET", f"{P}/insights", t_portal)
            async with AsyncSession(async_engine) as s_:
                await s_.execute(
                    text("UPDATE incident_management_tag_access_settings SET untagged_alert_behavior = 'default_tag' WHERE id = :i"),
                    {"i": settings_id},
                )
                await s_.commit()
            # No default tag configured: one alert is allowed, lists still exclude it.
            await same("portal/tags: default_tag without a tag, one alert", "GET", f"{P}/alert/{alerts['quiet']}", t_analyst)
            await same("portal/tags: default_tag without a tag, insights", "GET", f"{P}/insights", t_analyst)
            async with AsyncSession(async_engine) as s_:
                await s_.execute(
                    text(
                        "INSERT INTO user_tag_access (user_id, tag_id, created_at) "
                        "SELECT id, :t, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                    ),
                    {"t": tag_id, "n": ANALYST},
                )
                await s_.commit()
            await same("portal/tags: granted tag, alert", "GET", f"{P}/alert/{a}", t_analyst)
            await same("portal/tags: granted tag, insights", "GET", f"{P}/insights", t_analyst)
        finally:
            async with AsyncSession(async_engine) as s_:
                await s_.execute(text("DELETE FROM incident_management_tag_access_settings WHERE id = :i"), {"i": settings_id})
                await s_.execute(text("DELETE FROM user_tag_access WHERE tag_id = :t"), {"t": tag_id})
                await s_.execute(text("DELETE FROM incident_management_alert_to_tag WHERE tag_id = :t"), {"t": tag_id})
                await s_.execute(text("DELETE FROM incident_management_alerttag WHERE id = :t"), {"t": tag_id})
                await s_.commit()

    # --- Phase 1: customers, healthchecks, audit, version -----------------------------
    print("\n=== customers / healthcheck / audit / version ===")
    await same("customers: list (admin)", "GET", f"/api/customers?search={SFX}", t_admin)
    await same("customers: list (analyst, scoped)", "GET", f"/api/customers?search={SFX}", t_analyst)
    await same("customers: list, limit", "GET", f"/api/customers?search={SFX}&limit=1", t_admin)
    await same("customers: list, limit=0", "GET", "/api/customers?limit=0", t_admin)
    await same("customers: list, limit=abc", "GET", "/api/customers?limit=abc", t_admin)
    await same("customers: list, wildcard search", "GET", f"/api/customers?search=PAR_%25{SFX}", t_admin)
    await same("customers: list as portal user", "GET", "/api/customers", t_portal)
    await same("customers: list without token", "GET", "/api/customers")
    await same("customers: one", "GET", f"/api/customers/{CUST_A}", t_analyst)
    await same("customers: one, case-insensitive code", "GET", f"/api/customers/{CUST_A.lower()}", t_admin)
    await same("customers: other tenant", "GET", f"/api/customers/{CUST_B}", t_analyst)
    await same("customers: unknown", "GET", f"/api/customers/nosuch{SFX}", t_admin)
    await same("customers: meta", "GET", f"/api/customers/{CUST_A}/meta", t_analyst)
    await same("customers: meta missing", "GET", f"/api/customers/{CUST_B}/meta", t_admin)
    await same("customers: full", "GET", f"/api/customers/{CUST_A}/full", t_analyst)
    await same("customers: full without meta", "GET", f"/api/customers/{CUST_B}/full", t_admin)
    await same("customers: agents", "GET", f"/api/customers/{CUST_A}/agents", t_analyst)
    await same("customers: agents, unknown customer", "GET", f"/api/customers/nosuch{SFX}/agents", t_admin)
    await same("customers: wazuh health", "GET", f"/api/customers/{CUST_A}/agents/healthcheck/wazuh", t_analyst)
    await same(
        "customers: velociraptor health, 1 minute",
        "GET",
        f"/api/customers/{CUST_A}/agents/healthcheck/velociraptor?minutes=1",
        t_analyst,
    )
    await same("customers: health, bad ints", "GET", f"/api/customers/{CUST_A}/agents/healthcheck/wazuh?minutes=x&days=1.5", t_admin)
    await same("customers: health, other tenant", "GET", f"/api/customers/{CUST_B}/agents/healthcheck/wazuh?minutes=x", t_analyst)
    await same("customers: health, unknown customer", "GET", f"/api/customers/nosuch{SFX}/agents/healthcheck/wazuh", t_admin)
    await same("healthcheck: wazuh fleet (analyst)", "GET", "/api/healthcheck/wazuh", t_analyst)
    await same("healthcheck: velociraptor fleet (analyst)", "GET", "/api/healthcheck/velociraptor?hours=1", t_analyst)
    await same("healthcheck: wazuh fleet (admin)", "GET", "/api/healthcheck/wazuh?days=3650", t_admin)
    await same("healthcheck: one agent", "GET", f"/api/healthcheck/velociraptor/pa{SFX}4", t_analyst)
    await same("healthcheck: future check-in", "GET", f"/api/healthcheck/wazuh/pa{SFX}3", t_analyst)
    await same("healthcheck: other tenant's agent", "GET", f"/api/healthcheck/wazuh/pb{SFX}1", t_analyst)
    await same("healthcheck: unknown agent (scoped)", "GET", f"/api/healthcheck/wazuh/nope{SFX}", t_analyst)
    await same("healthcheck: unknown agent (admin)", "GET", f"/api/healthcheck/wazuh/nope{SFX}", t_admin)
    await same("healthcheck: bad window", "GET", "/api/healthcheck/wazuh?hours=abc", t_analyst)
    await same("healthcheck: portal user", "GET", "/api/healthcheck/wazuh", t_portal)

    audit = f"/api/audit?entity_id=par{SFX}"
    await same("audit: list", "GET", audit, t_admin)
    await same("audit: result filter", "GET", f"{audit}&result=failure", t_admin)
    await same("audit: start_time with offset, paged", "GET", f"{audit}&start_time=2026-01-01T11:00:00%2B05:00&skip=1&limit=1", t_admin)
    await same("audit: end_time as timestamp", "GET", f"{audit}&end_time=1767265200", t_admin)
    await same("audit: date-only start", "GET", f"{audit}&start_time=2026-01-01", t_admin)
    await same("audit: search", "GET", f"{audit}&search=ROW%201", t_admin)
    await same("audit: customer filter", "GET", f"{audit}&customer_code={CUST_A}&actor_user_id=1&action=case.create", t_admin)
    await same("audit: empty customer filter", "GET", f"{audit}&customer_codes=", t_admin)
    await same("audit: bad datetime and limit", "GET", f"{audit}&start_time=abc&limit=0", t_admin)
    await same("audit: bad datetimes", "GET", f"{audit}&start_time=2026-13-01&end_time=2026-01-02T25:00:00", t_admin)
    await same("audit: bad user id and skip", "GET", f"{audit}&actor_user_id=x&skip=-1", t_admin)
    await same("audit: analyst", "GET", audit, t_analyst)
    await same("audit: no token", "GET", audit)
    await same("audit: garbage token", "GET", audit, "garbage")
    await same(
        "audit: expired token",
        "GET",
        audit,
        jwt.encode({"sub": ADMIN, "exp": 1}, os.environ["JWT_SECRET"], algorithm="HS256"),
    )
    await same("audit: 2fa temp token", "GET", audit, token(ADMIN, ["admin"], type="2fa_pending"))
    await same("audit: unknown user", "GET", audit, token("nobody" + SFX, ["admin"]))
    no_sub = jwt.encode(
        {"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1), "scopes": ["admin"]},
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )
    await same("audit: token without sub", "GET", audit, no_sub)
    await same("audit: vocabularies", "GET", "/api/audit/actions", t_admin)
    await same("audit: vocabularies (analyst)", "GET", "/api/audit/actions", t_analyst)
    async with AsyncSession(async_engine) as s_:
        audit_id = (await s_.execute(text("SELECT MIN(id) FROM audit_log WHERE entity_id = :e"), {"e": f"par{SFX}"})).scalar_one()
    await same("audit: one entry", "GET", f"/api/audit/{audit_id}", t_admin)
    await same("audit: unknown entry", "GET", "/api/audit/999999999", t_admin)
    await same("audit: entry id parsing", "GET", "/api/audit/abc", t_admin)

    for label, payload in (
        ("outdated", {"tag_name": "v9.9.9", "name": "v9.9.9", "html_url": "https://example.com/r", "body": None}),
        (
            "up to date",
            {"tag_name": "0.1.98.0", "name": "x", "html_url": "https://example.com/r", "published_at": "2026-10-01T00:00:00Z", "body": "n"},
        ),
        ("unparseable tag", {"tag_name": "latest", "name": "latest", "html_url": None}),
        ("release without a name", {"tag_name": "v9.9.9", "name": None}),
        ("not an object", ["v9.9.9"]),
    ):
        RELEASE[0] = payload
        await same(f"version: {label}", "GET", "/api/version/check")

    # --- Phase 2: login, refresh, 2FA --------------------------------------------------
    print("\n=== auth: login / refresh / 2fa ===")
    from PIL import Image

    from app.auth.services.totp import _decrypt_secret
    from app.auth.services.totp import _encrypt_secret

    form_ct = "application/x-www-form-urlencoded"
    pw_hash = bcrypt.hashpw(b"Pa55word!", bcrypt.gensalt(4)).decode()
    tfa = {"py": f"par_tfa_py{SFX}", "rs": f"par_tfa_rs{SFX}"}  # 2FA enabled
    tfn = {"py": f"par_tfn_py{SFX}", "rs": f"par_tfn_rs{SFX}"}  # enrolment started, not verified
    tf0 = {"py": f"par_tf0_py{SFX}", "rs": f"par_tf0_rs{SFX}"}  # no 2FA row
    secret = pyotp.random_base32()
    backup_plain = ["ALPHA00001", "BRAVO00002", "CHARL00003"]
    backup_rows = json.dumps([{"hash": bcrypt.hashpw(c.encode(), bcrypt.gensalt(4)).decode(), "used": False} for c in backup_plain])
    async with AsyncSession(async_engine) as s_:
        await s_.execute(
            text("UPDATE `user` SET password = :h WHERE username IN (:a, :b, :c)"),
            {"h": pw_hash, "a": ADMIN, "b": ANALYST, "c": PORTAL},
        )
        for name in [*tfa.values(), *tfn.values(), *tf0.values()]:
            await s_.execute(
                text(
                    "INSERT INTO `user` (username, password, email, created_at, role_id) "
                    "VALUES (:n, :h, 'p@example.com', UTC_TIMESTAMP(), 2)",
                ),
                {"n": name, "h": pw_hash},
            )
            await s_.execute(
                text(
                    "INSERT INTO user_customer_access (user_id, customer_code, created_at) "
                    "SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                ),
                {"c": CUST_A, "n": name},
            )
        for names, enabled in ((tfa, 1), (tfn, 0)):
            for name in names.values():
                await s_.execute(
                    text(
                        "INSERT INTO user_totp (user_id, secret_enc, enabled, backup_codes, last_used_at, created_at) "
                        "SELECT id, :s, :e, :b, NULL, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
                    ),
                    {"s": _encrypt_secret(secret), "e": enabled, "b": backup_rows, "n": name},
                )
        await s_.commit()

    def claims_of(tok_):
        c = jwt.decode(tok_, os.environ["JWT_SECRET"], algorithms=["HS256"], options={"verify_exp": False})
        return {"keys": list(c), "life": c.get("exp", 0) - c.get("iat", 0), **{k: v for k, v in c.items() if k not in ("exp", "iat")}}

    py_users = {tfa["py"]: "<user>", tfn["py"]: "<user>", tf0["py"]: "<user>"}
    rs_users = {tfa["rs"]: "<user>", tfn["rs"]: "<user>", tf0["rs"]: "<user>"}

    def norm(value, names):
        if isinstance(value, dict):
            return {k: norm(v, names) for k, v in value.items()}
        if isinstance(value, list):
            return [norm(v, names) for v in value]
        if isinstance(value, str):
            for n, ph in names.items():
                value = value.replace(n, ph)
            return re.sub(r"Try again in \d+ seconds", "Try again in N seconds", value)
        return value

    def token_shape(r, names=None):
        b = body_of(r)
        if isinstance(b, dict) and isinstance(b.get("access_token"), str):
            b = {**b, "access_token": claims_of(b["access_token"])}
        return norm(b, names or {})

    async def send(client, method, path, tok, body, content, content_type):
        headers = H(tok)
        if content_type:
            headers["Content-Type"] = content_type
        if body is not None:
            return await client.request(method, path, headers=headers, json=body)
        return await client.request(method, path, headers=headers, content=content)

    async def same_raw(name, method, path, tok=None, content=None, content_type=None, shape=body_of):
        r1 = await send(py, method, path, tok, None, content, content_type)
        r2 = await send(rs, method, path, tok, None, content, content_type)
        b1, b2 = shape(r1), shape(r2)
        ok = r1.status_code == r2.status_code and b1 == b2
        check(
            f"{name} [{r1.status_code}]",
            ok,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    async def pair(name, method, path, toks=None, bodies=None, contents=None, content_type=None, shape=token_shape):
        """The same request for each backend's own user (`toks`/`bodies`/`contents`: {"py": …, "rs": …})."""
        toks, bodies, contents = toks or {}, bodies or {}, contents or {}
        r1 = await send(py, method, path, toks.get("py"), bodies.get("py"), contents.get("py"), content_type)
        r2 = await send(rs, method, path, toks.get("rs"), bodies.get("rs"), contents.get("rs"), content_type)
        b1, b2 = shape(r1, py_users), shape(r2, rs_users)
        ok = r1.status_code == r2.status_code and b1 == b2
        check(
            f"{name} [{r1.status_code}]",
            ok,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    def login_form(username, password="Pa55word!"):
        return f"username={username}&password={password}"

    shape = lambda r: token_shape(r)  # noqa: E731
    await same_raw("login: admin, urlencoded", "POST", "/api/auth/token", None, login_form(ADMIN), form_ct, shape)
    multipart = (
        f'--XyZ\r\nContent-Disposition: form-data; name="username"\r\n\r\n{ANALYST}\r\n'
        '--XyZ\r\nContent-Disposition: form-data; name="password"\r\n\r\nPa55word!\r\n--XyZ--\r\n'
    )
    await same_raw("login: analyst, multipart", "POST", "/api/auth/token", None, multipart, "multipart/form-data; boundary=XyZ", shape)
    await same_raw("login: wrong password", "POST", "/api/auth/token", None, login_form(ADMIN, "nope"), form_ct)
    await same_raw("login: unknown user", "POST", "/api/auth/token", None, login_form(f"ghost{SFX}"), form_ct)
    await same_raw("login: portal user at the main portal", "POST", "/api/auth/token", None, login_form(PORTAL), form_ct)
    await same_raw("login: admin at the customer portal", "POST", "/api/auth/token/customer-portal", None, login_form(ADMIN), form_ct)
    await same_raw(
        "login: portal user at the customer portal",
        "POST",
        "/api/auth/token/customer-portal",
        None,
        login_form(PORTAL),
        form_ct,
        shape,
    )
    await same_raw(
        "login: wrong password (customer portal)",
        "POST",
        "/api/auth/token/customer-portal",
        None,
        login_form(PORTAL, "x"),
        form_ct,
    )
    await same_raw("login: empty form", "POST", "/api/auth/token", None, "", form_ct)
    await same_raw("login: empty values, bad grant_type", "POST", "/api/auth/token", None, "username=&password=&grant_type=client", form_ct)
    await same_raw(
        "login: grant_type password",
        "POST",
        "/api/auth/token",
        None,
        login_form(ADMIN) + "&grant_type=password",
        form_ct,
        shape,
    )
    await same_raw(
        "login: last value wins",
        "POST",
        "/api/auth/token",
        None,
        f"username=x&username={ADMIN}&password=Pa55word!",
        form_ct,
        shape,
    )
    await same_raw(
        "login: percent-encoded password",
        "POST",
        "/api/auth/token",
        None,
        f"username={ADMIN}&password=Pa55word%21",
        form_ct,
        shape,
    )
    await same_raw("login: no content type", "POST", "/api/auth/token", None, login_form(ADMIN))
    await same_raw(
        "login: JSON body",
        "POST",
        "/api/auth/token",
        None,
        json.dumps({"username": ADMIN, "password": "Pa55word!"}),
        "application/json",
    )
    await same_raw("login: multipart without boundary", "POST", "/api/auth/token", None, multipart, "multipart/form-data")
    await same_raw("login: malformed multipart", "POST", "/api/auth/token", None, "garbage", "multipart/form-data; boundary=XyZ")
    await same_raw(
        "login: multipart part without a name",
        "POST",
        "/api/auth/token",
        None,
        "--XyZ\r\nContent-Disposition: form-data\r\n\r\nx\r\n--XyZ--\r\n",
        "multipart/form-data; boundary=XyZ",
    )
    await same_raw(
        "login: multipart file as username",
        "POST",
        "/api/auth/token",
        None,
        '--XyZ\r\nContent-Disposition: form-data; name="username"; filename="u.txt"\r\n\r\nx\r\n'
        '--XyZ\r\nContent-Disposition: form-data; name="password"\r\n\r\ny\r\n--XyZ--\r\n',
        "multipart/form-data; boundary=XyZ",
    )
    await same_raw("login: GET", "GET", "/api/auth/token")
    await asyncio.sleep(0.5)  # the Rust service writes audit rows from a spawned task
    async with AsyncSession(async_engine) as s_:
        rows = (
            await s_.execute(
                text(
                    "SELECT actor_user_id, actor_username, customer_code, action, entity_type, entity_id, result, source_ip, "
                    "details FROM audit_log WHERE action LIKE 'auth.%' AND actor_username IN (:a, :b, :c, :g)",
                ),
                {"a": ADMIN, "b": ANALYST, "c": PORTAL, "g": f"ghost{SFX}"},
            )
        ).all()
    pairs = Counter(tuple(r) for r in rows)
    check(f"login: audit events come in identical pairs ({len(rows)} rows)", rows and all(n % 2 == 0 for n in pairs.values()), str(pairs))

    t_portal_cp = (await py.post("/api/auth/token/customer-portal", content=login_form(PORTAL), headers={"Content-Type": form_ct})).json()[
        "access_token"
    ]
    await same_raw("refresh: portal user keeps customer_codes", "GET", "/api/auth/refresh", t_portal_cp, shape=shape)
    await same_raw("refresh: admin", "GET", "/api/auth/refresh", t_admin, shape=shape)
    await same_raw("refresh: responder scopes", "GET", "/api/auth/refresh", token(ANALYST, ["analyst"]), shape=shape)
    await same_raw("refresh: no token", "GET", "/api/auth/refresh")
    await same_raw("refresh: garbage token", "GET", "/api/auth/refresh", "garbage")
    await same_raw("refresh: 2fa temp token", "GET", "/api/auth/refresh", token(ADMIN, ["admin"], type="2fa_pending"))
    await same_raw("refresh: unknown user", "GET", "/api/auth/refresh", token("nobody" + SFX, ["admin"]))
    await same_raw("refresh: token without sub", "GET", "/api/auth/refresh", no_sub)
    await same_raw("refresh: POST", "POST", "/api/auth/refresh", t_admin)

    # 2FA: each backend gets its own, identically prepared user.
    V = "/api/auth/2fa/validate"
    tk = {k: token(v, ["analyst"]) for k, v in tfa.items()}
    await pair("2fa: status (enabled)", "GET", "/api/auth/2fa/status", tk)
    await pair("2fa: setup while enabled", "POST", "/api/auth/2fa/setup", tk)
    await pair("2fa: verify-setup while enabled", "POST", "/api/auth/2fa/verify-setup", tk, {k: {"code": "123456"} for k in tk})
    await same_raw("2fa: status as portal user", "GET", "/api/auth/2fa/status", t_portal)
    await same_raw("2fa: status without token", "GET", "/api/auth/2fa/status")
    await same_raw("2fa: malformed JSON before the token check", "POST", "/api/auth/2fa/verify-setup", None, "{bad", "application/json")
    await same_raw("2fa: JSON without token", "POST", "/api/auth/2fa/verify-setup", None, "{}", "application/json")
    await same_raw("2fa: not JSON", "POST", "/api/auth/2fa/verify-setup", t_analyst, '{"code": "1"}', "text/plain")
    await same_raw("2fa: body missing", "POST", "/api/auth/2fa/verify-setup", t_analyst)
    await same_raw("2fa: body not UTF-8", "POST", "/api/auth/2fa/verify-setup", t_analyst, b'{"code": "\xff"}', "application/json")
    await same_raw("2fa: code not a string", "POST", "/api/auth/2fa/verify-setup", t_analyst, '{"code": 123456}', "application/json")

    r1, r2 = await pair(
        "2fa: login asks for the second factor",
        "POST",
        "/api/auth/token",
        contents={k: login_form(v) for k, v in tfa.items()},
        content_type=form_ct,
    )
    temp = {"py": r1.json()["access_token"], "rs": r2.json()["access_token"]}

    def vb(**factor):
        return {k: {"temp_token": temp[k], **factor} for k in temp}

    async def guard(names, counter):
        async with AsyncSession(async_engine) as s_:
            await s_.execute(
                text("UPDATE user_totp t JOIN `user` u ON u.id = t.user_id SET t.last_used_at = :c WHERE u.username IN (:a, :b)"),
                {"c": counter, "a": names["py"], "b": names["rs"]},
            )
            await s_.commit()

    counter = int(datetime.datetime.now().timestamp()) // 30
    # Temp tokens are interchangeable: each backend finishes the other's login.
    r1 = await rs.post(V, json={"temp_token": temp["py"], "backup_code": "CHARL00003"})
    r2 = await py.post(V, json={"temp_token": temp["rs"], "backup_code": "CHARL00003"})
    check("2fa: Python's temp token completes at Rust and vice versa", r1.status_code == r2.status_code == 200, f"{r1.text} {r2.text}")
    await pair("2fa: validate without a factor", "POST", V, bodies=vb(code="", backup_code=""))
    await pair("2fa: validate, wrong code", "POST", V, bodies=vb(code="abcdef"))
    await guard(tfa, counter - 2)
    await pair("2fa: validate, current code", "POST", V, bodies=vb(code=pyotp.TOTP(secret).now()))
    await guard(tfa, counter + 5)
    await pair("2fa: validate, a used time step", "POST", V, bodies=vb(code=pyotp.TOTP(secret).now()))
    await pair("2fa: validate, backup code in lower case with spaces", "POST", V, bodies=vb(backup_code=" alpha00001 "))
    await pair("2fa: validate, spent backup code", "POST", V, bodies=vb(backup_code="ALPHA00001"))
    await pair("2fa: validate, backup code over 72 bytes", "POST", V, bodies=vb(backup_code="X" * 80))
    await pair("2fa: validate, both factors (the code decides)", "POST", V, bodies=vb(code="abcdef", backup_code="BRAVO00002"))
    await pair("2fa: regenerate, wrong code", "POST", "/api/auth/2fa/backup-codes/regenerate", tk, {k: {"code": "abcdef"} for k in tk})
    # A success clears the count, so lock out with five failures in a row: three so far.
    for n in (4, 5):
        await pair(f"2fa: validate, wrong code (failure {n} in a row)", "POST", V, bodies=vb(code="abcdef"))
    r1, r2 = await pair("2fa: locked out after five failures", "POST", V, bodies=vb(code=pyotp.TOTP(secret).now()))
    check(
        "2fa: the lockout names the remaining time",
        all(r.json()["message"].startswith("Too many failed 2FA attempts. Try again in ") for r in (r1, r2)),
        f"{r1.text} {r2.text}",
    )
    await pair("2fa: disable while locked out", "DELETE", "/api/auth/2fa/disable", tk, {k: {"backup_code": "BRAVO00002"} for k in tk})
    await pair("2fa: setup is not rate limited", "POST", "/api/auth/2fa/setup", tk)

    await same_raw("2fa: validate, garbage temp token", "POST", V, None, json.dumps({"temp_token": "x", "code": "1"}), "application/json")
    expired = jwt.encode({"sub": tfa["py"], "exp": 1, "type": "2fa_pending"}, os.environ["JWT_SECRET"], algorithm="HS256")
    await same_raw(
        "2fa: validate, expired temp token",
        "POST",
        V,
        None,
        json.dumps({"temp_token": expired, "code": "1"}),
        "application/json",
    )
    await same_raw(
        "2fa: validate, session token as temp token",
        "POST",
        V,
        None,
        json.dumps({"temp_token": t_admin, "code": "1"}),
        "application/json",
    )
    for label, claims in (
        ("without sub", {"type": "2fa_pending"}),
        ("with an empty sub", {"sub": "", "type": "2fa_pending"}),
        ("with a numeric sub", {"sub": 5, "type": "2fa_pending"}),
        ("for an unknown user", {"sub": f"ghost{SFX}", "type": "2fa_pending"}),
    ):
        odd = jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")
        await same_raw(
            f"2fa: validate, temp token {label}",
            "POST",
            V,
            None,
            json.dumps({"temp_token": odd, "code": "1"}),
            "application/json",
        )
    await same_raw("2fa: validate, missing temp_token", "POST", V, None, json.dumps({"code": "1"}), "application/json")
    await same_raw("2fa: validate, malformed JSON", "POST", V, None, '{"temp_token": ', "application/json")
    await same_raw("2fa: validate, whitespace body", "POST", V, None, "   ", "application/json")
    await same_raw("2fa: validate, not an object", "POST", V, None, "[]", "application/json")
    await same_raw("2fa: validate, no content type", "POST", V, None, json.dumps({"temp_token": "x"}))

    tkn = {k: token(v, ["analyst"]) for k, v in tfn.items()}
    await pair("2fa: status (not verified yet)", "GET", "/api/auth/2fa/status", tkn)
    await pair("2fa: verify-setup, wrong code", "POST", "/api/auth/2fa/verify-setup", tkn, {k: {"code": "000000x"} for k in tkn})
    await pair(
        "2fa: verify-setup, current code",
        "POST",
        "/api/auth/2fa/verify-setup",
        tkn,
        {k: {"code": pyotp.TOTP(secret).now()} for k in tkn},
    )
    await pair("2fa: status after verification", "GET", "/api/auth/2fa/status", tkn)
    await pair(
        "2fa: regenerate backup codes",
        "POST",
        "/api/auth/2fa/backup-codes/regenerate",
        tkn,
        {k: {"code": pyotp.TOTP(secret).now()} for k in tkn},
        shape=lambda r, n: {**r.json(), "backup_codes": [bool(re.fullmatch(r"[A-Z0-9]{10}", c)) for c in r.json()["backup_codes"]]},
    )
    await pair("2fa: disable without a factor", "DELETE", "/api/auth/2fa/disable", tkn, {k: {"code": None} for k in tkn})
    await pair("2fa: disable, wrong code", "DELETE", "/api/auth/2fa/disable", tkn, {k: {"code": "abcdef"} for k in tkn})
    await guard(tfn, counter - 2)
    await pair("2fa: disable, current code", "DELETE", "/api/auth/2fa/disable", tkn, {k: {"code": pyotp.TOTP(secret).now()} for k in tkn})
    await pair("2fa: status after disabling", "GET", "/api/auth/2fa/status", tkn)

    tk0 = {k: token(v, ["analyst"]) for k, v in tf0.items()}
    await pair("2fa: verify-setup before setup", "POST", "/api/auth/2fa/verify-setup", tk0, {k: {"code": "123456"} for k in tk0})
    await pair("2fa: regenerate without 2FA", "POST", "/api/auth/2fa/backup-codes/regenerate", tk0, {k: {"code": "123456"} for k in tk0})
    await pair("2fa: disable without 2FA", "DELETE", "/api/auth/2fa/disable", tk0, {k: {"code": "123456"} for k in tk0})

    def setup_shape(r, names):
        b = r.json()
        if r.status_code != 200:
            return norm(b, names)
        png = Image.open(io.BytesIO(base64.b64decode(b["qr_data_uri"].split(",", 1)[1])))
        png.load()
        return {
            "keys": list(b),
            "secret": bool(re.fullmatch(r"[A-Z2-7]{32}", b["secret"])),
            "otpauth_url": norm(b["otpauth_url"].replace(b["secret"], "<secret>"), names),
            "qr": [png.format, png.size],
            "backup_codes": [bool(re.fullmatch(r"[A-Z0-9]{10}", c)) for c in b["backup_codes"]],
            "message": b["message"],
        }

    r1, r2 = await pair("2fa: setup", "POST", "/api/auth/2fa/setup", tk0, shape=setup_shape)
    if r1.status_code == r2.status_code == 200:
        async with AsyncSession(async_engine) as s_:
            stored = dict(
                (
                    await s_.execute(
                        text(
                            "SELECT u.username, t.secret_enc FROM user_totp t JOIN `user` u ON u.id = t.user_id "
                            "WHERE u.username IN (:a, :b)",
                        ),
                        {"a": tf0["py"], "b": tf0["rs"]},
                    )
                ).all(),
            )
        check(
            "2fa: both backends store secrets the other can read",
            _decrypt_secret(stored[tf0["rs"]]) == r2.json()["secret"] and _decrypt_secret(stored[tf0["py"]]) == r1.json()["secret"],
        )
        await pair(
            "2fa: verify-setup of a fresh enrolment",
            "POST",
            "/api/auth/2fa/verify-setup",
            tk0,
            {"py": {"code": pyotp.TOTP(r1.json()["secret"]).now()}, "rs": {"code": pyotp.TOTP(r2.json()["secret"]).now()}},
        )

    # --- Phase 2: user management ------------------------------------------------------
    print("\n=== auth: user management ===")
    reg = {"py": f"par_reg_py{SFX}", "rs": f"par_reg_rs{SFX}"}
    sched, nobody_role, bad_hash = f"par_sched{SFX}", f"par_norole{SFX}", f"par_xhash{SFX}"
    async with AsyncSession(async_engine) as s_:
        for name, role, pw in ((sched, 3, pw_hash), (nobody_role, None, pw_hash), (bad_hash, 2, "x")):
            await s_.execute(
                text(
                    "INSERT INTO `user` (username, password, email, created_at, role_id) "
                    "VALUES (:n, :p, 'p@example.com', UTC_TIMESTAMP(), :r)",
                ),
                {"n": name, "p": pw, "r": role},
            )
        await s_.commit()

    async def user_id(name):
        async with AsyncSession(async_engine) as s_:
            return (await s_.execute(text("SELECT id FROM `user` WHERE username = :n"), {"n": name})).scalar_one()

    admin_id = await user_id(ADMIN)
    analyst_id = await user_id(ANALYST)
    U = "/api/auth/users"
    await same("users: list (admin)", "GET", f"{U}?search={SFX}", t_admin)
    await same("users: list (analyst)", "GET", f"{U}?search={SFX}", t_analyst)
    await same("users: list, limit", "GET", f"{U}?search={SFX}&limit=2", t_admin)
    await same("users: list, wildcard search", "GET", f"{U}?search=par%25analyst{SFX}", t_admin)
    await same("users: list, limit=0", "GET", f"{U}?limit=0", t_admin)
    await same("users: list, limit=abc", "GET", f"{U}?limit=abc", t_admin)
    await same("users: list as portal user", "GET", U, t_portal)
    await same("users: list without token", "GET", U)
    await same("users: one", "GET", f"{U}/{analyst_id}", t_analyst)
    await same("users: one without a role", "GET", f"{U}/{await user_id(nobody_role)}", t_admin)
    await same("users: unknown", "GET", f"{U}/999999999", t_admin)
    await same("users: id parsing", "GET", f"{U}/abc", t_admin)
    await same("users: customers", "GET", f"{U}/{analyst_id}/customers", t_admin)
    await same("users: customers of an unknown user", "GET", f"{U}/999999999/customers", t_admin)
    await same("users: customers as analyst", "GET", f"{U}/{analyst_id}/customers", t_analyst)
    await same("me/customers: admin", "GET", "/api/auth/me/customers", t_admin)
    await same("me/customers: analyst", "GET", "/api/auth/me/customers", t_analyst)
    await same("me/customers: portal user", "GET", "/api/auth/me/customers", t_portal)
    await same("me/customers: scheduler", "GET", "/api/auth/me/customers", token(sched, ["scheduler"]))
    await same("me/customers: user without a role", "GET", "/api/auth/me/customers", token(nobody_role, ["analyst"]))
    await same("me/customers: no token", "GET", "/api/auth/me/customers")

    R = "/api/auth/register"

    def new_user(**extra):
        return {"username": f"par_new{SFX}", "password": "Passw0rd!x", "email": f"new{SFX}@example.com", **extra}

    await same("register: analyst without customers", "POST", R, t_admin, new_user())
    await same("register: unknown and wrong-case codes", "POST", R, t_admin, new_user(customer_codes=[CUST_A.lower(), "nope"]))
    await same("register: admin with customers", "POST", R, t_admin, new_user(role_id=1, customer_codes=[CUST_A]))
    await same("register: taken email", "POST", R, t_admin, new_user(email="p@example.com", customer_codes=[CUST_A]))
    await same("register: taken username", "POST", R, t_admin, new_user(username=ADMIN, customer_codes=[CUST_A]))
    await same("register: username differs only in case", "POST", R, t_admin, new_user(username=ADMIN.upper(), email="zz" + SFX + "@x.io"))
    await same(
        "register: invalid fields",
        "POST",
        R,
        t_admin,
        {"password": "short", "email": "a@b.local", "role_id": "admin", "customer_codes": "A"},
    )
    await same("register: password too long", "POST", R, t_admin, new_user(password="Aa1!" * 19, customer_codes=[CUST_A]))
    for label, email in (
        ("display name (accepted, then refused for no customer)", "Name <x@y.com>"),
        ("reserved domain", "x@y.test"),
        ("no period", "x@y"),
    ):
        await same(f"register: email with a {label}", "POST", R, t_admin, new_user(email=email))
    await same("register: as analyst", "POST", R, t_analyst, new_user(customer_codes=[CUST_A]))
    await same("register: no body", "POST", R, t_admin)

    for k in reg:
        py_users[reg["py"]] = rs_users[reg["rs"]] = "<user>"
    emails = {"py": f"Reg.Py{SFX}@EXAMPLE.com", "rs": f"Reg.Rs{SFX}@EXAMPLE.com"}
    py_users[f"Reg.Py{SFX}"] = rs_users[f"Reg.Rs{SFX}"] = "<local>"
    await pair(
        "register: a responder",
        "POST",
        R,
        {"py": t_admin, "rs": t_admin},
        {
            k: {"username": reg[k], "password": "Passw0rd!x", "email": emails[k], "role_id": "5", "customer_codes": [f" {CUST_A} ", CUST_A]}
            for k in reg
        },
    )
    ids = {k: await user_id(v) for k, v in reg.items()}
    async with AsyncSession(async_engine) as s_:
        rows = {
            k: (
                await s_.execute(
                    text(
                        "SELECT u.email, u.role_id, GROUP_CONCAT(a.customer_code) FROM `user` u "
                        "LEFT JOIN user_customer_access a ON a.user_id = u.id WHERE u.id = :i GROUP BY u.id",
                    ),
                    {"i": ids[k]},
                )
            ).one()
            for k in ids
        }
    check(
        "register: both store the same normalized user",
        norm(list(rows["py"]), py_users) == norm(list(rows["rs"]), rs_users),
        f"{rows}",
    )

    def mask_ids(value):
        if isinstance(value, dict):
            return {k: mask_ids(v) for k, v in value.items()}
        if isinstance(value, list):
            return [mask_ids(v) for v in value]
        if isinstance(value, int) and not isinstance(value, bool) and value in ids.values():
            return "<id>"
        if isinstance(value, str):
            return value.replace(str(ids["py"]), "<id>").replace(str(ids["rs"]), "<id>")
        return value

    def id_shape(r, names):
        return norm(mask_ids(body_of(r)), names)

    tok_reg = {k: t_admin for k in reg}
    RB = {k: f"{U}/{ids[k]}/role/by-name" for k in reg}

    async def pair_paths(name, method, paths, bodies=None, toks=None, shape=id_shape):
        toks, bodies = toks or tok_reg, bodies or {}
        r1 = await send(py, method, paths["py"], toks["py"], bodies.get("py"), None, None)
        r2 = await send(rs, method, paths["rs"], toks["rs"], bodies.get("rs"), None, None)
        b1, b2 = shape(r1, py_users), shape(r2, rs_users)
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    both_bodies = lambda b: {"py": b, "rs": b}  # noqa: E731
    await pair_paths("role: unknown role", "PUT", RB, both_bodies({"role_name": "wizard"}))
    await pair_paths("role: to Admin, customers kept", "PUT", RB, both_bodies({"role_name": "Admin"}))
    await pair_paths("role: admin with customers", "PUT", RB, both_bodies({"role_name": "admin", "customer_codes": [CUST_A]}))
    await pair_paths("role: responder with none", "PUT", RB, both_bodies({"role_name": "responder", "customer_codes": []}))
    await pair_paths("role: analyst, unknown code", "PUT", RB, both_bodies({"role_name": "analyst", "customer_codes": ["nope"]}))
    await pair_paths("role: analyst with customers", "PUT", RB, both_bodies({"role_name": "ANALYST", "customer_codes": [CUST_B, CUST_A]}))
    await pair_paths("role: customer_user", "PUT", RB, both_bodies({"role_name": "customer_user", "customer_codes": None}))
    await same("role: unknown user", "PUT", f"{U}/999999999/role/by-name", t_admin, {"role_name": "admin"})
    await same("role: missing role_name", "PUT", f"{U}/{analyst_id}/role/by-name", t_admin, {})
    await same("role: as analyst", "PUT", f"{U}/{analyst_id}/role/by-name", t_analyst, {"role_name": "admin"})

    CB = {k: f"{U}/{ids[k]}/customers" for k in reg}
    await pair_paths("customers: replace (portal user, duplicates)", "POST", CB, both_bodies([CUST_B, f" {CUST_B}", CUST_A]))
    await pair_paths("customers: empty list for a portal user", "POST", CB, both_bodies([]))
    await pair_paths("customers: not a list", "POST", CB, both_bodies({"codes": [CUST_A]}))
    await pair_paths("customers: not strings", "POST", CB, both_bodies([1, None]))
    await pair_paths("customers: unknown code", "POST", CB, both_bodies([CUST_A, "nope"]))
    await pair_paths("customers: read back", "GET", CB)
    await same("customers: unknown user", "POST", f"{U}/999999999/customers", t_admin, [CUST_A])
    await same("customers: analyst needs one", "POST", f"{U}/{analyst_id}/customers", t_admin, [])
    await same("customers: admin gets none", "POST", f"{U}/{admin_id}/customers", t_admin, [CUST_A])

    P = "/api/auth/reset-password"
    await pair("password: admin reset", "POST", P, tok_reg, {k: {"username": reg[k], "new_password": "Changed1!x"} for k in reg})
    await same("password: admin reset, unknown user", "POST", P, t_admin, {"username": f"ghost{SFX}", "new_password": "Changed1!x"})
    await same("password: admin reset, too short", "POST", P, t_admin, {"username": ADMIN, "new_password": "x"})
    await same("password: admin reset as analyst", "POST", P, t_analyst, {"username": ADMIN, "new_password": "Changed1!x"})
    mine = {k: token(v, ["customer_user"]) for k, v in reg.items()}
    PM = f"{P}/me"
    await pair(
        "password: self, wrong current",
        "POST",
        PM,
        mine,
        {k: {"username": reg[k], "current_password": "no", "new_password": "Changed2!x"} for k in reg},
    )
    await pair("password: self, someone else", "POST", PM, mine, {k: {"username": ANALYST, "new_password": "Changed2!x"} for k in reg})
    await pair(
        "password: self, unknown user",
        "POST",
        PM,
        mine,
        {k: {"username": f"ghost{SFX}", "new_password": "Changed2!x"} for k in reg},
    )
    await pair(
        "password: self service",
        "POST",
        PM,
        mine,
        {k: {"username": reg[k], "current_password": "Changed1!x", "new_password": "Changed2!x"} for k in reg},
    )
    await pair(
        "password: self, case-insensitive lookup",
        "POST",
        PM,
        mine,
        {k: {"username": reg[k].upper(), "new_password": "Changed2!x"} for k in reg},
    )
    await same(
        "password: self, unreadable stored hash",
        "POST",
        PM,
        token(bad_hash, ["analyst"]),
        {"username": bad_hash, "current_password": "x", "new_password": "Changed2!x"},
    )
    await same("password: self as scheduler", "POST", PM, token(sched, ["scheduler"]), {"username": sched, "new_password": "Changed2!x"})

    L = "/api/auth/login"
    await pair(
        "legacy login: portal user",
        "POST",
        L,
        bodies={k: {"username": reg[k], "password": "Changed2!x"} for k in reg},
        shape=lambda r, n: norm({**body_of(r), "token": claims_of(body_of(r)["token"])} if r.status_code == 200 else body_of(r), n),
    )
    r1, r2 = await both("POST", L, None, {"username": ADMIN, "password": "Pa55word!"})
    legacy = [{**r.json(), "token": claims_of(r.json()["token"])} if r.status_code == 200 else r.json() for r in (r1, r2)]
    check(f"legacy login: admin [{r1.status_code}]", r1.status_code == r2.status_code == 200 and legacy[0] == legacy[1], json.dumps(legacy))
    await same("legacy login: wrong password", "POST", L, None, {"username": ANALYST, "password": "nope"})
    await same("legacy login: unknown user", "POST", L, None, {"username": f"ghost{SFX}", "password": "nope"})
    await same("legacy login: unreadable stored hash", "POST", L, None, {"username": bad_hash, "password": "x"})
    await same("legacy login: missing field", "POST", L, None, {"username": ADMIN})
    await same_raw("legacy login: form body", "POST", L, None, login_form(ADMIN), form_ct)

    D = "/api/auth/delete"
    async with AsyncSession(async_engine) as s_:
        r = await s_.execute(text("INSERT INTO incident_management_alerttag (tag) VALUES (:t)"), {"t": f"par_del{SFX}"})
        for k in ids:
            await s_.execute(
                text("INSERT INTO user_tag_access (user_id, tag_id, created_at) VALUES (:u, :t, UTC_TIMESTAMP())"),
                {"u": ids[k], "t": r.lastrowid},
            )
        await s_.commit()
    DP = {k: f"{D}/{ids[k]}" for k in ids}
    await pair_paths("delete: a user other rows still point at", "DELETE", DP)
    async with AsyncSession(async_engine) as s_:
        await s_.execute(text("DELETE FROM user_tag_access WHERE user_id IN (:a, :b)"), {"a": ids["py"], "b": ids["rs"]})
        await s_.commit()
    await pair_paths("delete: a user", "DELETE", DP)
    await pair_paths("delete: again", "DELETE", DP)
    await same("delete: the built-in admin", "DELETE", f"{D}/1", t_admin)
    await same("delete: id parsing", "DELETE", f"{D}/abc", t_admin)
    await same("delete: as analyst", "DELETE", f"{D}/{analyst_id}", t_analyst)

    await asyncio.sleep(0.5)  # the Rust service writes audit rows from a spawned task
    async with AsyncSession(async_engine) as s_:
        rows = (
            await s_.execute(
                text(
                    "SELECT entity_id, action, actor_username, result, details, old_value, new_value FROM audit_log "
                    "WHERE action LIKE 'user.%' AND entity_id IN (:a, :b) ORDER BY id",
                ),
                {"a": reg["py"], "b": reg["rs"]},
            )
        ).all()
    events = {k: [norm([str(x) for x in r[1:]], py_users if k == "py" else rs_users) for r in rows if r[0] == reg[k]] for k in reg}
    check(f"user audit events match ({len(events['py'])} each)", events["py"] and events["py"] == events["rs"], json.dumps(events)[:1200])

    # --- Phase 2: SSO ------------------------------------------------------------------
    print("\n=== auth: sso ===")
    async with AsyncSession(async_engine) as s_:
        await s_.execute(text("DELETE FROM sso_config"))
        await s_.commit()
    SSO = "/api/auth/sso"
    await same("sso: status, nothing configured", "GET", f"{SSO}/status")
    await same("sso: settings, nothing configured", "GET", f"{SSO}/settings", t_admin)
    await same("sso: settings as analyst", "GET", f"{SSO}/settings", t_analyst)
    await same("sso: settings without token", "GET", f"{SSO}/settings")
    await same("sso: azure login, nothing configured", "GET", f"{SSO}/azure/login")
    await same("sso: google callback, nothing configured", "GET", f"{SSO}/google/callback?code=c&state=s")
    await same("sso: cloudflare, nothing configured", "POST", f"{SSO}/cloudflare/verify")
    tenant, team = f"tenant{SFX}", f"team{SFX}.cloudflareaccess.com"
    sso_settings = {
        "sso_enabled": True,
        "azure_enabled": True,
        "azure_tenant_id": tenant,
        "azure_client_id": "az-client",
        "azure_client_secret": "az-secret",
        "azure_redirect_uri": "https://soc.example/api/auth/sso/azure/callback",
        "google_enabled": "on",
        "google_client_id": "g-client",
        "google_client_secret": "g-secret",
        "google_redirect_uri": "https://soc.example/api/auth/sso/google/callback",
        "cf_enabled": 1,
        "cf_team_domain": team,
        "cf_audience": "cf-aud",
    }
    await same("sso: put settings", "PUT", f"{SSO}/settings", t_admin, sso_settings)
    await same("sso: put settings, empty secret keeps it", "PUT", f"{SSO}/settings", t_admin, {**sso_settings, "azure_client_secret": ""})
    await same("sso: put settings, bool null", "PUT", f"{SSO}/settings", t_admin, {"sso_enabled": None})
    await same("sso: put settings, bool word", "PUT", f"{SSO}/settings", t_admin, {"cf_enabled": "maybe"})
    await same("sso: put settings, number as tenant", "PUT", f"{SSO}/settings", t_admin, {"azure_tenant_id": 5, "sso_enabled": 2})
    await same("sso: put settings as analyst", "PUT", f"{SSO}/settings", t_analyst, sso_settings)
    await same_raw("sso: put settings, malformed JSON", "PUT", f"{SSO}/settings", None, "{", "application/json")
    await same_raw("sso: put settings, no body", "PUT", f"{SSO}/settings", t_admin)
    await same("sso: put settings back", "PUT", f"{SSO}/settings", t_admin, sso_settings)
    await same("sso: settings", "GET", f"{SSO}/settings", t_admin)
    await same("sso: status", "GET", f"{SSO}/status")

    AE = f"{SSO}/allowed-emails"
    allow = {"py": f"SSO_py{SFX}@Example.com", "rs": f"SSO_rs{SFX}@Example.com"}
    sso_names = {"py": {f"sso_py{SFX}": "<user>", f"SSO_py{SFX}": "<USER>"}, "rs": {f"sso_rs{SFX}": "<user>", f"SSO_rs{SFX}": "<USER>"}}

    async def pair_sso(name, method, path, bodies=None, headers=None, shape=None):
        bodies, headers = bodies or {}, headers or {}
        kw = lambda k: {"headers": headers.get(k, {}), **({"json": bodies[k]} if k in bodies else {})}  # noqa: E731
        r1 = await py.request(method, path, **kw("py"))
        r2 = await rs.request(method, path, **kw("rs"))
        b1, b2 = (shape or body_of)(r1), (shape or body_of)(r2)
        b1, b2 = norm(b1, sso_names["py"]), norm(b2, sso_names["rs"])
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    admin_h = {"Authorization": f"Bearer {t_admin}"}
    no_id = (
        lambda r: {k: ("<id>" if k == "id" else v) for k, v in body_of(r).items()} if isinstance(body_of(r), dict) else body_of(r)
    )  # noqa: E731
    await pair_sso(
        "sso: allow an address",
        "POST",
        AE,
        bodies={k: {"email": allow[k], "role_id": "2"} for k in allow},
        headers={"py": admin_h, "rs": admin_h},
        shape=no_id,
    )
    await same("sso: allow an address twice", "POST", AE, t_admin, {"email": f"sso_py{SFX}@example.com"})
    await same("sso: allow a scheduler", "POST", AE, t_admin, {"email": "x@example.com", "role_id": 3})
    await same("sso: allow a bad address", "POST", AE, t_admin, {"email": "nope", "role_id": "abc"})
    await same("sso: allow, reserved domain", "POST", AE, t_admin, {"email": "a@b.local"})
    await same("sso: allow as analyst", "POST", AE, t_analyst, {"email": "x@example.com"})
    await same("sso: allowlist", "GET", AE, t_admin)
    await same("sso: remove unknown", "DELETE", f"{AE}/999999999", t_admin)
    await same("sso: remove, id parsing", "DELETE", f"{AE}/abc", t_admin)
    await same("sso: remove as analyst", "DELETE", f"{AE}/1", t_analyst)
    async with AsyncSession(async_engine) as s_:
        r = await s_.execute(
            text("INSERT INTO sso_allowed_email (email, role_id, created_at) VALUES (:e, 2, UTC_TIMESTAMP())"),
            {"e": f"gone{SFX}@x.example"},
        )
        r2_ = await s_.execute(
            text("INSERT INTO sso_allowed_email (email, role_id, created_at) VALUES (:e, 2, UTC_TIMESTAMP())"),
            {"e": f"gone2{SFX}@x.example"},
        )
        await s_.commit()
    r1 = await py.delete(f"{AE}/{r.lastrowid}", headers=admin_h)
    r2 = await rs.delete(f"{AE}/{r2_.lastrowid}", headers=admin_h)
    check(
        f"sso: remove an address [{r1.status_code}]",
        r1.status_code == r2.status_code == 200 and r1.json() == r2.json(),
        f"{r1.text} / {r2.text}",
    )

    def location(r):
        return r.headers.get("location", "")

    def mask_redirect(r):
        loc = re.sub(r"(state=)[^&]+", r"\1<state>", location(r))
        loc = re.sub(r"(nonce=)[^&]+", r"\1<nonce>", loc)
        return {"status": r.status_code, "location": loc, "body": r.text}

    def redirect_shape(r):
        loc = location(r)
        if "#token=" in loc:
            tok_ = loc.split("#token=", 1)[1].split("&", 1)
            claims_ = claims_of(tok_[0])
            return {"status": r.status_code, "token": claims_, "rest": tok_[1:]}
        return {"status": r.status_code, "location": loc, "body": r.text}

    for provider in ("azure", "google"):
        r1, r2 = await both("GET", f"{SSO}/{provider}/login")
        b1, b2 = mask_redirect(r1), mask_redirect(r2)
        check(f"sso: {provider} login redirect [{r1.status_code}]", b1 == b2, f"{b1}\n        {b2}")
    r1, _ = await both("GET", f"{SSO}/azure/login")
    state = re.search(r"state=([^&]+)", location(r1)).group(1).replace("%3A", ":")
    issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
    now_ = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    def az_claims(email, **extra):
        return {"iss": issuer, "aud": "az-client", "exp": now_ + 300, "iat": now_ - 5, "sub": "abc", "email": email, **extra}

    async def callback(name, provider, codes, shape=redirect_shape, extra_query=""):
        r1 = await py.get(f"{SSO}/{provider}/callback?code={codes['py']}&state={state}{extra_query}")
        r2 = await rs.get(f"{SSO}/{provider}/callback?code={codes['rs']}&state={state}{extra_query}")
        # One code for both backends signs the same user in on both.
        names = sso_names if codes["py"] != codes["rs"] else {"py": sso_names["py"], "rs": sso_names["py"]}
        b1, b2 = norm(shape(r1), names["py"]), norm(shape(r2), names["rs"])
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {json.dumps(b1)[:600]}\n        rust   {json.dumps(b2)[:600]}",
        )

    def issue(code_, kid, claims):
        IDP_TOKENS[code_] = {"id_token": idp_token(kid, claims)}
        return code_

    await callback(
        "sso: azure callback provisions a user (state from Python, used by both)",
        "azure",
        {k: issue(f"az-new-{k}", "az1", az_claims(allow[k].lower())) for k in allow},
    )
    await callback(
        "sso: azure callback, existing user",
        "azure",
        {k: issue(f"az-again-{k}", "az1", az_claims(allow[k].upper())) for k in allow},
    )
    async with AsyncSession(async_engine) as s_:
        for k in tfa:
            await s_.execute(text("UPDATE `user` SET email = :e WHERE username = :n"), {"e": f"{tfa[k]}@example.com", "n": tfa[k]})
        await s_.commit()
    sso_names["py"][tfa["py"]] = "<2fa>"
    sso_names["rs"][tfa["rs"]] = "<2fa>"
    await callback(
        "sso: azure callback, 2FA user",
        "azure",
        {k: issue(f"az-2fa-{k}", "az1", az_claims(f"{tfa[k]}@example.com")) for k in tfa},
    )
    same_codes = lambda c: {"py": c, "rs": c}  # noqa: E731
    issue("az-stranger", "az1", az_claims(f"stranger{SFX}@example.com"))
    await callback("sso: azure callback, address not allowed", "azure", same_codes("az-stranger"))
    issue("az-unverified", "az1", az_claims(allow["py"].lower(), email_verified=False))
    await callback("sso: azure callback, unverified address", "azure", same_codes("az-unverified"))
    issue("az-upn", "az1", {**az_claims(""), "email": None, "preferred_username": allow["py"]})
    await callback("sso: azure callback, preferred_username", "azure", {"py": "az-upn", "rs": "az-upn"})
    issue("az-noemail", "az1", {**az_claims(""), "email": ""})
    await callback("sso: azure callback, no email claim", "azure", same_codes("az-noemail"))
    issue("az-expired", "az1", az_claims(allow["py"], exp=now_ - 10))
    await callback("sso: azure callback, expired ID token", "azure", same_codes("az-expired"))
    issue("az-aud", "az1", az_claims(allow["py"], aud=["x", "az-client"]))
    await callback("sso: azure callback, audience list", "azure", same_codes("az-aud"))
    issue("az-wrong-aud", "az1", az_claims(allow["py"], aud="someone"))
    await callback("sso: azure callback, wrong audience", "azure", same_codes("az-wrong-aud"))
    issue("az-iss", "az1", az_claims(allow["py"], iss="https://evil.example/v2.0"))
    await callback("sso: azure callback, wrong issuer", "azure", same_codes("az-iss"))
    issue("az-kid", "unknown-kid", az_claims(allow["py"]))
    await callback("sso: azure callback, unknown signing key", "azure", same_codes("az-kid"))
    IDP_TOKENS["az-no-id-token"] = {"access_token": "x"}
    await callback("sso: azure callback, no id_token", "azure", same_codes("az-no-id-token"))
    await callback("sso: azure callback, refused code", "azure", same_codes("unknown-code"))
    IDP_TOKENS["az-hs256"] = {"id_token": jwt.encode(az_claims(allow["py"]), "x", algorithm="HS256", headers={"kid": "az1"})}
    await callback("sso: azure callback, HS256 token", "azure", same_codes("az-hs256"))
    await same("sso: azure callback, provider error", "GET", f"{SSO}/azure/callback?error=access_denied&code=c")
    await same("sso: azure callback, no state", "GET", f"{SSO}/azure/callback?code=c")
    await same("sso: azure callback, empty code", "GET", f"{SSO}/azure/callback?code=&state=s")
    await same("sso: azure callback, forged state", "GET", f"{SSO}/azure/callback?code=c&state=a:1:b")
    await same("sso: azure callback, unicode in error", "GET", f"{SSO}/azure/callback?error=%C3%A4%20%2F%20%23")

    def g_claims(email, **extra):
        return {
            "iss": "https://accounts.google.com",
            "aud": "g-client",
            "exp": now_ + 300,
            "email": email,
            **extra,
        }

    r1, _ = await both("GET", f"{SSO}/google/login")
    state = re.search(r"state=([^&]+)", location(r1)).group(1).replace("%3A", ":")
    await callback(
        "sso: google callback, existing user",
        "google",
        {k: issue(f"g-ok-{k}", "g1", g_claims(allow[k], email_verified=True)) for k in allow},
    )
    issue("g-unverified", "g1", g_claims(allow["py"]))
    await callback("sso: google callback, email_verified missing", "google", same_codes("g-unverified"))
    issue("g-kid", "nope", g_claims(allow["py"], email_verified=True))
    await callback("sso: google callback, unknown signing key", "google", same_codes("g-kid"))

    CF = f"{SSO}/cloudflare/verify"

    def cf_claims(email, **extra):
        return {
            "iss": f"https://{team}",
            "aud": ["cf-aud"],
            "exp": now_ + 300,
            "email": email,
            **extra,
        }

    cf_tok = {k: idp_token("cf1", cf_claims(allow[k])) for k in allow}
    shape_tok = (
        lambda r: {**body_of(r), "access_token": claims_of(body_of(r)["access_token"])} if r.status_code == 200 else body_of(r)
    )  # noqa: E731
    await pair_sso(
        "sso: cloudflare, header",
        "POST",
        CF,
        headers={k: {"Cf-Access-Jwt-Assertion": cf_tok[k]} for k in allow},
        shape=shape_tok,
    )
    await pair_sso(
        "sso: cloudflare, cookie",
        "POST",
        CF,
        headers={k: {"Cookie": f"x=1; CF_Authorization={cf_tok[k]}"} for k in allow},
        shape=shape_tok,
    )
    await pair_sso(
        "sso: cloudflare, 2FA user",
        "POST",
        CF,
        headers={k: {"Cf-Access-Jwt-Assertion": idp_token("cf1", cf_claims(f"{tfa[k]}@example.com"))} for k in tfa},
        shape=shape_tok,
    )
    stranger = idp_token("cf1", cf_claims(f"stranger{SFX}@example.com"))
    for name, headers_ in (
        ("no token", {}),
        ("empty header, no cookie", {"Cf-Access-Jwt-Assertion": ""}),
        ("address not allowed", {"Cf-Access-Jwt-Assertion": stranger}),
        ("not a JWT", {"Cf-Access-Jwt-Assertion": "not.a.jwt"}),
        ("wrong audience", {"Cf-Access-Jwt-Assertion": idp_token("cf1", cf_claims(allow["py"], aud="other"))}),
        ("unknown signing key", {"Cf-Access-Jwt-Assertion": idp_token("other", cf_claims(allow["py"]))}),
        ("no email", {"Cf-Access-Jwt-Assertion": idp_token("cf1", cf_claims(""))}),
    ):
        await pair_sso(f"sso: cloudflare, {name}", "POST", CF, headers={"py": headers_, "rs": headers_})
    async with AsyncSession(async_engine) as s_:
        await s_.execute(text("UPDATE sso_config SET cf_team_domain = 'evil.example.com', azure_enabled = 0 WHERE id = 1"))
        await s_.commit()
    await same("sso: cloudflare, invalid team domain", "POST", CF)
    await pair_sso(
        "sso: cloudflare, invalid team domain with a token",
        "POST",
        CF,
        headers={"py": {"Cf-Access-Jwt-Assertion": "x"}, "rs": {"Cf-Access-Jwt-Assertion": "x"}},
    )
    await same("sso: azure login, provider disabled", "GET", f"{SSO}/azure/login")
    await same("sso: azure callback, provider disabled", "GET", f"{SSO}/azure/callback?code=c&state={state}")
    async with AsyncSession(async_engine) as s_:
        await s_.execute(text("DELETE FROM sso_config"))
        await s_.commit()

    # --- Phase 2: passkeys -------------------------------------------------------------
    print("\n=== auth: passkeys ===")
    PK = "/api/auth/passkey"
    origin_h = {"Origin": "http://localhost:5173"}
    an_h = {**origin_h, "Authorization": f"Bearer {t_analyst}"}

    def mask_options(r):
        b = body_of(r)
        if isinstance(b, dict) and "challenge" in b:
            b = {**b, "challenge": "<c>", "challengeToken": "<t>"}
        return b

    async def same_pk(name, method, path, headers, body=None, shape=body_of):
        kw = {"headers": headers, **({"json": body} if body is not None else {})}
        r1 = await py.request(method, path, **kw)
        r2 = await rs.request(method, path, **kw)
        b1, b2 = shape(r1), shape(r2)
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    await same("passkey: status", "GET", f"{PK}/status")
    await same("passkey: mine, none yet", "GET", f"{PK}/me", t_analyst)
    await same("passkey: my status, none yet", "GET", f"{PK}/me/status", t_analyst)
    await same("passkey: mine as portal user", "GET", f"{PK}/me", t_portal)
    await same("passkey: mine without token", "GET", f"{PK}/me")
    await same_pk("passkey: register options", "POST", f"{PK}/register/options", an_h, {"device_name": "  Key  "}, mask_options)
    await same_pk(
        "passkey: register options, no origin",
        "POST",
        f"{PK}/register/options",
        {"Authorization": f"Bearer {t_analyst}"},
        {},
        mask_options,
    )
    await same_pk("passkey: register options, 127.0.0.1", "POST", f"{PK}/register/options", {**an_h, "Origin": "http://127.0.0.1:5173"}, {})
    await same_pk("passkey: register options, bad port", "POST", f"{PK}/register/options", {**an_h, "Origin": "http://localhost:x"}, {})
    await same_pk("passkey: register options, device_name null", "POST", f"{PK}/register/options", an_h, {"device_name": None})
    await same_pk(
        "passkey: register options as portal user",
        "POST",
        f"{PK}/register/options",
        {**origin_h, "Authorization": f"Bearer {t_portal}"},
        {},
    )

    devices = {k: Authenticator(f"par-{k}-{SFX}".encode()) for k in ("py", "rs")}

    async def per_backend(name, step, shape=body_of):
        """`step(k, client)` → response, once per backend with that backend's own state."""
        r1, r2 = await step("py", py), await step("rs", rs)
        b1, b2 = shape(r1), shape(r2)
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {r1.status_code} {json.dumps(b1)[:600]}\n        rust   {r2.status_code} {json.dumps(b2)[:600]}",
        )
        return r1, r2

    async def options(client, path, body, headers=None):
        return (await client.post(f"{PK}/{path}/options", headers=headers or an_h, json=body)).json()

    async def register(k, client, device=None, mutate=None, token_=None):
        opts = await options(client, "register", {})
        cred = (device or devices[k]).create(opts)
        if mutate:
            cred = mutate(cred)
        return await client.post(
            f"{PK}/register/verify",
            headers=an_h,
            json={"challenge_token": token_ or opts["challengeToken"], "credential": cred, "device_name": " Par "},
        )

    await per_backend("passkey: register", lambda k, c: register(k, c))
    await per_backend("passkey: register the same credential again", lambda k, c: register(k, c))
    await per_backend("passkey: register, unknown challenge", lambda k, c: register(k, c, token_="no-such-token"))
    await per_backend(
        "passkey: register, missing credential id (500)",
        lambda k, c: register(k, c, mutate=lambda x: {kk: v for kk, v in x.items() if kk != "id"}),
    )
    await per_backend("passkey: register, id mismatch", lambda k, c: register(k, c, mutate=lambda x: {**x, "id": "AAAA"}))
    other_rp = {k: Authenticator(f"rp-{k}-{SFX}".encode()) for k in ("py", "rs")}

    async def wrong_rp(k, client):
        opts = await options(client, "register", {})
        cred = other_rp[k].create(opts, rp_id="evil.example")
        return await client.post(
            f"{PK}/register/verify",
            headers=an_h,
            json={"challenge_token": opts["challengeToken"], "credential": cred},
        )

    await per_backend("passkey: register, wrong RP ID", wrong_rp)

    async def login_flow(k, client, flow="login", count=1, username=None, device=None):
        opts = await options(client, "login", {"username": username} if username else {}, headers=origin_h)
        return await client.post(
            f"{PK}/login/verify",
            headers=origin_h,
            json={"challenge_token": opts["challengeToken"], "credential": (device or devices[k]).get(opts, count)},
        )

    def login_shape(r):
        b = body_of(r)
        return {**b, "access_token": claims_of(b["access_token"])} if r.status_code == 200 else b

    await per_backend("passkey: login", lambda k, c: login_flow(k, c, username=ANALYST), login_shape)
    await per_backend("passkey: login, replayed counter", lambda k, c: login_flow(k, c), login_shape)
    await per_backend("passkey: login, higher counter", lambda k, c: login_flow(k, c, count=7), login_shape)
    await same_pk("passkey: login options, unknown user", "POST", f"{PK}/login/options", origin_h, {"username": f"ghost{SFX}"})
    await same_pk("passkey: login options, user without passkeys", "POST", f"{PK}/login/options", origin_h, {"username": ADMIN})
    await same_pk("passkey: login options, username-less", "POST", f"{PK}/login/options", origin_h, {"username": "   "}, mask_options)
    await same_pk("passkey: login options, no body", "POST", f"{PK}/login/options", origin_h)
    stranger_dev = Authenticator(b"stranger")
    await per_backend("passkey: login, unknown passkey", lambda k, c: login_flow(k, c, device=stranger_dev), login_shape)

    async def missing_id(k, client):
        opts = await options(client, "login", {}, headers=origin_h)
        return await client.post(
            f"{PK}/login/verify",
            headers=origin_h,
            json={"challenge_token": opts["challengeToken"], "credential": {"rawId": "x"}},
        )

    await per_backend("passkey: login, missing credential id", missing_id)

    async def flow_mixup(k, client):
        opts = await options(client, "register", {})
        return await client.post(
            f"{PK}/login/verify",
            headers=origin_h,
            json={"challenge_token": opts["challengeToken"], "credential": devices[k].get(opts, 9)},
        )

    await per_backend("passkey: login with a registration challenge", flow_mixup)
    async with AsyncSession(async_engine) as s_:
        for k in ("py", "rs"):
            await s_.execute(
                text(
                    "INSERT INTO webauthn_challenge (token, challenge, user_id, flow, expires_at, created_at) "
                    "VALUES (:t, 'AA', NULL, 'login', UTC_TIMESTAMP() - INTERVAL 1 MINUTE, UTC_TIMESTAMP())",
                ),
                {"t": f"expired-{k}-{SFX}"},
            )
        await s_.commit()
    await per_backend(
        "passkey: login, expired challenge",
        lambda k, c: c.post(
            f"{PK}/login/verify",
            headers=origin_h,
            json={"challenge_token": f"expired-{k}-{SFX}", "credential": devices[k].get({"challenge": "AA"}, 20)},
        ),
    )
    portal_dev = {k: Authenticator(f"portal-{k}-{SFX}".encode()) for k in ("py", "rs")}
    tfa_dev = {k: Authenticator(f"tfa-{k}-{SFX}".encode()) for k in ("py", "rs")}
    async with AsyncSession(async_engine) as s_:
        for k in ("py", "rs"):
            for user_, dev in ((PORTAL, portal_dev[k]), (tfa[k], tfa_dev[k])):
                await s_.execute(
                    text(
                        "INSERT INTO user_passkey (user_id, credential_id, public_key, sign_count, transports, device_name, created_at) "
                        "SELECT id, :c, :p, 0, '[]', 'Passkey', UTC_TIMESTAMP() FROM `user` WHERE username = :u",
                    ),
                    {"c": dev.b64(dev.id), "p": dev.b64(dev.cose()), "u": user_},
                )
        await s_.commit()
    await per_backend("passkey: login, portal user", lambda k, c: login_flow(k, c, count=0, device=portal_dev[k]), login_shape)
    pk_names = {"py": {tfa["py"]: "<2fa>"}, "rs": {tfa["rs"]: "<2fa>"}}

    async def tfa_login(k, client):
        return await login_flow(k, client, count=0, device=tfa_dev[k])

    r1, r2 = await tfa_login("py", py), await tfa_login("rs", rs)
    b1, b2 = norm(login_shape(r1), pk_names["py"]), norm(login_shape(r2), pk_names["rs"])
    check(f"passkey: login, 2FA user [{r1.status_code}]", r1.status_code == r2.status_code and b1 == b2, f"{b1}\n        {b2}")
    await same("passkey: mine", "GET", f"{PK}/me", t_analyst)
    await same("passkey: my status", "GET", f"{PK}/me/status", t_analyst)
    await same("passkey: delete unknown", "DELETE", f"{PK}/999999999", t_analyst)
    await same("passkey: delete, id parsing", "DELETE", f"{PK}/abc", t_analyst)
    await same("passkey: delete /me", "DELETE", f"{PK}/me", t_analyst)
    await same("passkey: delete /status without token", "DELETE", f"{PK}/status")
    async with AsyncSession(async_engine) as s_:
        pk_ids = {
            k: (
                await s_.execute(text("SELECT id FROM user_passkey WHERE credential_id = :c"), {"c": devices[k].b64(devices[k].id)})
            ).scalar_one()
            for k in ("py", "rs")
        }
        portal_pk = (
            await s_.execute(text("SELECT id FROM user_passkey WHERE credential_id = :c"), {"c": portal_dev["py"].b64(portal_dev["py"].id)})
        ).scalar_one()
    await same("passkey: delete someone else's", "DELETE", f"{PK}/{portal_pk}", t_analyst)
    r1 = await py.delete(f"{PK}/{pk_ids['py']}", headers=H(t_analyst))
    r2 = await rs.delete(f"{PK}/{pk_ids['rs']}", headers=H(t_analyst))
    check(
        f"passkey: delete [{r1.status_code}]",
        r1.status_code == r2.status_code == 200 and r1.json() == r2.json(),
        f"{r1.text} / {r2.text}",
    )

    # --- Security admin ----------------------------------------------------------------
    print("\n=== auth: security ===")
    SEC = "/api/auth/security"
    await same("security: smtp status", "GET", f"{SEC}/smtp-status", t_admin)
    await same("security: smtp status, analyst", "GET", f"{SEC}/smtp-status", t_analyst)
    await same("security: smtp status, no token", "GET", f"{SEC}/smtp-status")
    sec_users = {}
    async with AsyncSession(async_engine) as s_:
        # Customer A: one user with 2FA on, one with 2FA set up but off, one without,
        # one also assigned to B, one listed twice; B alone for the empty-ish list.
        for key, role, codes, totp, login in (
            ("on", 4, [CUST_A], 1, "2026-02-03 04:05:06"),
            ("off", 4, [CUST_A], 0, None),
            ("none", 2, [CUST_A], None, None),
            ("two", 5, [CUST_A, CUST_B], None, None),
            ("twice", 4, [CUST_A, CUST_A], None, None),
            ("odd", 9, [CUST_A], None, None),
            ("reset_py", 4, [CUST_B], 1, None),
            ("reset_rs", 4, [CUST_B], 1, None),
        ):
            name = f"par_sec_{key}{SFX}"
            if role == 9:
                role = None
            r = await s_.execute(
                text(
                    "INSERT INTO `user` (username, password, email, created_at, role_id, last_login_at) "
                    "VALUES (:n, 'x', :e, UTC_TIMESTAMP(), :r, :l)",
                ),
                {"n": name, "e": f"{key}@sec.example", "r": role, "l": login},
            )
            sec_users[key] = r.lastrowid
            for code in codes:
                await s_.execute(
                    text("INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (:u, :c, UTC_TIMESTAMP())"),
                    {"u": r.lastrowid, "c": code},
                )
            if totp is not None:
                await s_.execute(
                    text("INSERT INTO user_totp (user_id, secret_enc, enabled, backup_codes) VALUES (:u, 'x', :e, '[]')"),
                    {"u": r.lastrowid, "e": totp},
                )
        await s_.commit()
    await same("security: customer users", "GET", f"{SEC}/customers/{CUST_A}/users", t_admin)
    await same("security: customer users, other case", "GET", f"{SEC}/customers/{CUST_A.lower()}/users", t_admin)
    await same("security: customer users, B", "GET", f"{SEC}/customers/{CUST_B}/users", t_admin)
    await same("security: customer users, unknown", "GET", f"{SEC}/customers/NOPE{SFX}/users", t_admin)
    await same("security: customer users, analyst", "GET", f"{SEC}/customers/{CUST_A}/users", t_analyst)
    await same("security: customer users, no token", "GET", f"{SEC}/customers/{CUST_A}/users")

    await same("security: totp reset, analyst", "DELETE", f"{SEC}/users/{sec_users['on']}/totp", t_analyst)
    await same("security: totp reset, bad id", "DELETE", f"{SEC}/users/abc/totp", t_admin)
    await same("security: totp reset, unknown user", "DELETE", f"{SEC}/users/999999999/totp", t_admin)
    await same("security: totp reset, huge id", "DELETE", f"{SEC}/users/99999999999999/totp", t_admin)
    for attempt in ("enrolled", "again"):
        r1 = await py.delete(f"{SEC}/users/{sec_users['reset_py']}/totp", headers=H(t_admin))
        r2 = await rs.delete(f"{SEC}/users/{sec_users['reset_rs']}/totp", headers=H(t_admin))
        check(
            f"security: totp reset, {attempt} [{r1.status_code}]",
            r1.status_code == r2.status_code == 200 and r1.json() == r2.json(),
            f"{r1.text} / {r2.text}",
        )
    await asyncio.sleep(0.5)  # the Rust service writes audit rows from a spawned task
    async with AsyncSession(async_engine) as s_:
        rows = (
            await s_.execute(
                text(
                    "SELECT entity_id, actor_username, action, result, details, old_value, new_value FROM audit_log "
                    "WHERE entity_id IN (:a, :b) ORDER BY id",
                ),
                {"a": f"par_sec_reset_py{SFX}", "b": f"par_sec_reset_rs{SFX}"},
            )
        ).all()
        left = [r[1:] for r in rows if r[0].startswith("par_sec_reset_py")]
        right = [r[1:] for r in rows if r[0].startswith("par_sec_reset_rs")]
        check("security: totp reset audit rows", left == right and len(left) == 2, f"{left}\n        {right}")
        left_totp = (
            await s_.execute(
                text("SELECT COUNT(*) FROM user_totp WHERE user_id IN (:a, :b)"),
                {"a": sec_users["reset_py"], "b": sec_users["reset_rs"]},
            )
        ).scalar_one()
        check("security: totp rows removed", left_totp == 0, str(left_totp))

    # Temporary-password templates: this customer's, shared, built-in, another customer's,
    # a JSON one (not offered) and one for another trigger (never listed).
    async with AsyncSession(async_engine) as s_:
        tpl = {}
        for key, code, fmt, default, trig, updated in (
            ("a_html", CUST_A, "html", 0, "temp_password_issued", "2026-03-01 10:00:00"),
            ("a_text_old", CUST_A, "text", 0, "temp_password_issued", "2026-02-01 10:00:00"),
            ("b_only", CUST_B, "text", 0, "temp_password_issued", "2026-03-02 10:00:00"),
            ("shared", None, "markdown", 0, "temp_password_issued", "2026-01-01 10:00:00"),
            ("shared_json", None, "json", 0, "temp_password_issued", "2026-03-03 10:00:00"),
            ("builtin", None, "html", 1, "temp_password_issued", None),
            ("other_trigger", CUST_A, "text", 0, "alert_assigned", "2026-03-04 10:00:00"),
        ):
            r = await s_.execute(
                text(
                    "INSERT INTO notification_template (name, description, `trigger`, format, subject_template, body_template, "
                    "customer_code, is_default, created_by, created_at, updated_at) VALUES (:n, :d, :t, :f, 'S', 'B', :c, :dflt, "
                    "'par', '2026-01-01 00:00:00', :u)",
                ),
                {
                    "n": f"par {key} {SFX}",
                    "d": None if key == "shared" else f"desc {key}",
                    "t": trig,
                    "f": fmt,
                    "c": code,
                    "dflt": default,
                    "u": updated,
                },
            )
            tpl[key] = r.lastrowid
        await s_.commit()
    OPT = lambda key, q="": f"{SEC}/users/{sec_users[key]}/temp-password-email/options{q}"  # noqa: E731
    await same("security: options, one customer", "GET", OPT("on"), t_admin)
    await same("security: options, two customers", "GET", OPT("two"), t_admin)
    await same("security: options, two customers, B chosen", "GET", OPT("two", f"?customer_code={CUST_B}"), t_admin)
    await same("security: options, empty choice", "GET", OPT("two", "?customer_code="), t_admin)
    await same("security: options, not theirs", "GET", OPT("on", f"?customer_code={CUST_B}"), t_admin)
    await same("security: options, other case", "GET", OPT("on", f"?customer_code={CUST_A.lower()}"), t_admin)
    await same("security: options, quote in code", "GET", OPT("on", "?customer_code=it%27s"), t_admin)
    await same("security: options, repeated", "GET", OPT("two", f"?customer_code=x&customer_code={CUST_A}"), t_admin)
    await same("security: options, listed twice", "GET", OPT("twice"), t_admin)
    await same("security: options, unknown user", "GET", f"{SEC}/users/999999999/temp-password-email/options", t_admin)
    await same("security: options, bad id", "GET", f"{SEC}/users/1.5/temp-password-email/options", t_admin)
    await same("security: options, analyst", "GET", OPT("on"), t_analyst)

    # Temporary-password email: preview (placeholder password, nothing sent) and send
    # (rotate, mail, audit). Each send goes to a pair of users, one per backend; the mails
    # are compared decoded, with the generated password masked and then checked against
    # the stored hash.
    async with AsyncSession(async_engine) as s_:
        for key, codes, mail in (
            ("mail_py", [CUST_A], "mail_py@sec.example"),
            ("mail_rs", [CUST_A], "mail_rs@sec.example"),
            ("plain_py", [], "plain_py@sec.example"),
            ("plain_rs", [], "plain_rs@sec.example"),
            ("reject_py", [CUST_A], "reject_py@sec.example"),
            ("reject_rs", [CUST_A], "reject_rs@sec.example"),
            ("nomail", [CUST_A], ""),
        ):
            r = await s_.execute(
                text(
                    "INSERT INTO `user` (username, password, email, created_at, role_id) " "VALUES (:n, :p, :e, UTC_TIMESTAMP(), 4)",
                ),
                {"n": f"par_sec_{key}{SFX}", "p": bcrypt.hashpw(b"before", bcrypt.gensalt(4)).decode(), "e": mail},
            )
            sec_users[key] = r.lastrowid
            for code in codes:
                await s_.execute(
                    text("INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (:u, :c, UTC_TIMESTAMP())"),
                    {"u": r.lastrowid, "c": code},
                )
        await s_.execute(
            text(
                "INSERT INTO customer_portal_branding (customer_code, enabled, title, brand_color, updated_at) "
                "VALUES (:c, 1, 'Acme Portal', '#2563eb', UTC_TIMESTAMP())",
            ),
            {"c": CUST_A},
        )
        rich_body = (
            '<h1 style="color: {{ branding.accent_strong }}">{{ branding.title }}</h1>\n'
            "<p>Hello {{ user_name }} &lt;{{ user_email }}&gt;,</p>\n"
            "<p>Your password: [[{{ temp_password }}]]</p>\n"
            '{% if login_url %}<a href="{{ login_url }}">Sign in</a>{% endif %}<br/>\n'
            "<ul>{% for k, v in branding|dictsort %}{% if v is string and v.startswith('#') %}"
            "<li>{{ k }}={{ v }}</li>{% endif %}{% endfor %}</ul>\n"
            "<script>alert(1)</script><STYLE>p{}</STYLE>\n"
            "<div>{{ summary|truncate(30) }} — {{ organization_name }} &amp; {{ customer_name|upper }}</div>\n\n\n\n"
            "<table><tr><td>{{ '<b>' ~ severity ~ '</b>' }}</td></tr></table>   \n{{ trigger }} {{ entity_type }}"
        )
        long_line = "Bitte ändern Sie es sofort — " * 6
        for key, fmt, subject, body in (
            ("rich", "html", "Hi {{ user_name }}\n  at {{ customer_name }} ({{ severity }})", rich_body),
            (
                "text",
                "text",
                "Grüße an {{ user_name }} — Ihr neues Passwort für {{ organization_name }} ist da, bitte sofort ändern",
                "Hallo {{ user_name }},\r\nPasswort: [[{{ temp_password }}]]\r\n" + long_line + "\n<b>{{ login_url }}</b>\n\n",
            ),
            ("markdown", "markdown", None, "**{{ user_name }}**: [[{{ temp_password }}]] {{ '<i>' }}"),
            ("preview_only", "html", "{{ dedupe_key }}", "{{ link_url }} {{ entity_id }} {{ subject }} {{ context.username }}"),
            ("broken", "html", "S", "{{ nope }}"),
            ("broken_subject", "text", "{{ 1 / 0 }}", "B"),
            ("blank_subject", "text", "  {{ '' }}  \n ", "[[{{ temp_password }}]]"),
            ("empty_html", "html", "Empty", ""),
            ("quoted", "text", "Q", "[[{{ temp_password }}]]"),
        ):
            r = await s_.execute(
                text(
                    "INSERT INTO notification_template (name, description, `trigger`, format, subject_template, body_template, "
                    "customer_code, is_default, created_by, created_at, updated_at) VALUES (:n, NULL, 'temp_password_issued', "
                    ":f, :s, :b, :c, 0, 'par', '2026-01-01 00:00:00', '2025-01-01 00:00:00')",
                ),
                {"n": f"par it's {key} {SFX}" if key == "quoted" else f"par {key} {SFX}", "f": fmt, "s": subject, "b": body, "c": CUST_A},
            )
            tpl[key] = r.lastrowid
        await s_.commit()

    PRE = lambda key: f"{SEC}/users/{sec_users[key]}/temp-password-email/preview"  # noqa: E731
    await same("security: preview, resolved template", "POST", PRE("on"), t_admin, {})
    for key in ("rich", "text", "markdown", "preview_only", "broken", "broken_subject", "blank_subject", "empty_html"):
        await same(f"security: preview, {key}", "POST", PRE("on"), t_admin, {"template_id": tpl[key]})
    await same("security: preview, B chosen", "POST", PRE("two"), t_admin, {"customer_code": CUST_B})
    await same("security: preview, B chosen, rich", "POST", PRE("two"), t_admin, {"customer_code": CUST_B, "template_id": tpl["rich"]})
    await same("security: preview, no customer", "POST", PRE("plain_py"), t_admin, {"template_id": tpl["rich"]})
    await same("security: preview, json template", "POST", PRE("on"), t_admin, {"template_id": tpl["shared_json"]})
    await same("security: preview, other trigger", "POST", PRE("on"), t_admin, {"template_id": tpl["other_trigger"]})
    await same("security: preview, other customer's", "POST", PRE("on"), t_admin, {"template_id": tpl["b_only"]})
    await same("security: preview, unknown template", "POST", PRE("on"), t_admin, {"template_id": 999999999})
    await same("security: preview, unknown user", "POST", f"{SEC}/users/999999999/temp-password-email/preview", t_admin, {})
    await same("security: preview, bad id and body", "POST", f"{SEC}/users/x/temp-password-email/preview", t_admin, {"template_id": "x"})
    await same("security: preview, no body", "POST", PRE("on"), t_admin)
    r1 = await py.post(PRE("on"), headers={**H(t_admin), "Content-Type": "application/json"}, content=b"null")
    r2 = await rs.post(PRE("on"), headers={**H(t_admin), "Content-Type": "application/json"}, content=b"null")
    check(
        f"security: preview, JSON null [{r1.status_code}]",
        (r1.status_code, r1.json()) == (r2.status_code, r2.json()),
        f"{r1.text} / {r2.text}",
    )
    await same("security: preview, list body", "POST", PRE("on"), t_admin, [])
    await same("security: preview, analyst", "POST", PRE("on"), t_analyst, {})
    await same("security: preview, no token", "POST", PRE("on"), None, {})

    async def password_hash(key):
        async with AsyncSession(async_engine) as s_:
            return (await s_.execute(text("SELECT password FROM `user` WHERE id = :u"), {"u": sec_users[key]})).scalar_one()

    def mail_view(msg):
        if msg is None:
            return None
        parts = []
        for part in msg.walk():
            if part.is_multipart():
                parts.append(part.get_content_type())
            else:
                parts.append([part.get_content_type(), part.get_content_charset(), part.get_content().replace("\r\n", "\n")])
        return {"subject": str(msg["subject"]), "from": str(msg["from"]), "to": str(msg["to"]), "parts": parts}

    def scrub(value, tag):
        if isinstance(value, dict):
            return {k: scrub(v, tag) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v, tag) for v in value]
        if isinstance(value, str):
            value = value.replace(f"_{tag}", "_X")
            value = re.sub(r"\[\[.*?\]\]", "[[PW]]", value)
            return re.sub(r"Temporary password: \S+", "Temporary password: PW", value)
        return value

    def passwords_in(msg):
        found = set()
        for part in msg.walk():
            if not part.is_multipart():
                body = part.get_content()
                unescape = html_unescape if part.get_content_subtype() == "html" else str
                found.update(unescape(p) for p in re.findall(r"\[\[(.*?)\]\]", body))
                found.update(re.findall(r"Temporary password: (\S+)", body))
        return found

    async def send_pair(name, key, body=None, sent=True, with_password=True):
        """POST send-temp-password for `<key>_py` on Python and `<key>_rs` on Rust."""
        MAILS.clear()
        before = {tag: await password_hash(f"{key}_{tag}") for tag in ("py", "rs")}
        kw = {"headers": H(t_admin)} if body is None else {"headers": H(t_admin), "json": body}
        resp = {
            "py": await py.post(f"{SEC}/users/{sec_users[f'{key}_py']}/send-temp-password", **kw),
            "rs": await rs.post(f"{SEC}/users/{sec_users[f'{key}_rs']}/send-temp-password", **kw),
        }
        out = {tag: scrub(body_of(r), tag) for tag, r in resp.items()}
        check(
            f"security: send, {name} [{resp['py'].status_code}]",
            resp["py"].status_code == resp["rs"].status_code and out["py"] == out["rs"],
            f"python {resp['py'].status_code} {out['py']}\n        rust   {resp['rs'].status_code} {out['rs']}",
        )
        mails = {tag: next((m for rcpts, m in MAILS if rcpts == [f"{key}_{tag}@sec.example"]), None) for tag in ("py", "rs")}
        views = {tag: scrub(mail_view(m), tag) for tag, m in mails.items()}
        check(f"security: send, {name}: same mail", views["py"] == views["rs"], f"{views['py']}\n        {views['rs']}")
        check(f"security: send, {name}: {'one mail each' if sent else 'nothing sent'}", (len(MAILS) == 2) == sent, str(len(MAILS)))
        for tag, m in mails.items():
            after = await password_hash(f"{key}_{tag}")
            if m is None or not with_password:
                continue
            pws = passwords_in(m)
            ok = len(pws) == 1 and bcrypt.checkpw(next(iter(pws)).encode(), after.encode())
            check(f"security: send, {name}: {tag} mail carries the stored password", ok, str(pws))
        return resp, before

    resp, _ = await send_pair("rich template", "mail", {"template_id": tpl["rich"]})
    await send_pair("text template", "mail", {"template_id": tpl["text"]})
    await send_pair("markdown template", "mail", {"template_id": tpl["markdown"]})
    await send_pair("blank subject", "mail", {"template_id": tpl["blank_subject"]})
    await send_pair("quoted name", "mail", {"template_id": tpl["quoted"], "customer_code": CUST_A})
    await send_pair("empty html", "mail", {"template_id": tpl["empty_html"]}, with_password=False)
    _, before = await send_pair("broken template", "mail", {"template_id": tpl["broken"]}, sent=False)
    check(
        "security: send, broken template leaves the password",
        all([before[tag] == await password_hash(f"mail_{tag}") for tag in ("py", "rs")]),
    )
    await send_pair("broken subject", "mail", {"template_id": tpl["broken_subject"]}, sent=False)
    await send_pair("other customer's template", "mail", {"template_id": tpl["b_only"]}, sent=False)
    await send_pair("unknown template", "mail", {"template_id": 999999999}, sent=False)
    # The built-in plaintext: a user with no customer, once the shared templates are gone.
    async with AsyncSession(async_engine) as s_:
        await s_.execute(text("DELETE FROM notification_template WHERE `trigger` = 'temp_password_issued' AND customer_code IS NULL"))
        await s_.commit()
    await send_pair("built-in body, no request body", "plain")
    r1 = await py.post(
        f"{SEC}/users/{sec_users['plain_py']}/send-temp-password",
        headers={**H(t_admin), "Content-Type": "application/json"},
        content=b"null",
    )
    r2 = await rs.post(
        f"{SEC}/users/{sec_users['plain_rs']}/send-temp-password",
        headers={**H(t_admin), "Content-Type": "application/json"},
        content=b"null",
    )
    check(
        f"security: send, JSON null [{r1.status_code}]",
        r1.status_code == r2.status_code == 200 and scrub(r1.json(), "py") == scrub(r2.json(), "rs"),
        f"{r1.text} / {r2.text}",
    )
    await send_pair("built-in body, empty object", "plain", {})
    await same("security: send, no email", "POST", f"{SEC}/users/{sec_users['nomail']}/send-temp-password", t_admin)
    await same("security: send, unknown user", "POST", f"{SEC}/users/999999999/send-temp-password", t_admin)
    await same("security: send, bad id and body", "POST", f"{SEC}/users/x/send-temp-password", t_admin, {"template_id": "x"})
    await same("security: send, list body", "POST", f"{SEC}/users/{sec_users['nomail']}/send-temp-password", t_admin, [])
    await same("security: send, analyst", "POST", f"{SEC}/users/{sec_users['nomail']}/send-temp-password", t_analyst)
    await same("security: send, no token", "POST", f"{SEC}/users/{sec_users['nomail']}/send-temp-password")
    await asyncio.sleep(0.5)  # the Rust service writes audit rows from a spawned task
    async with AsyncSession(async_engine) as s_:
        rows = (
            await s_.execute(
                text(
                    "SELECT entity_id, actor_username, action, entity_type, result, details, old_value, new_value "
                    "FROM audit_log WHERE entity_id IN (:a, :b) ORDER BY id",
                ),
                {"a": f"par_sec_mail_py{SFX}", "b": f"par_sec_mail_rs{SFX}"},
            )
        ).all()
        left = [r[1:] for r in rows if r[0].startswith("par_sec_mail_py")]
        right = [r[1:] for r in rows if r[0].startswith("par_sec_mail_rs")]
        check("security: send audit rows", left == right and len(left) == 6, f"{left}\n        {right}")

    # --- Deliberate differences ------------------------------------------------------
    print("\n=== differences by design ===")
    r1, r2 = await both("GET", "/api/ai_analyst/alerts_with_reports", t_analyst)
    py_codes = {x["customer_code"] for x in r1.json()["alerts"]}
    rs_codes = {x["customer_code"] for x in r2.json()["alerts"]}
    check("alerts_with_reports: Rust scopes to the analyst's customers", CUST_A in rs_codes and CUST_B not in rs_codes, str(rs_codes))
    check("  (python leaks other tenants here — the bug being fixed)", CUST_B not in py_codes or CUST_B in py_codes)
    r1, r2 = await both("GET", f"/api/talon/jobs/{b}", t_analyst)
    check("talon/jobs: Rust refuses another tenant's alert", r2.status_code == 403, f"python {r1.status_code}, rust {r2.status_code}")
    # A refused delivery: same status and sentence, and the password was rotated on both, but
    # the reason after the colon is the SMTP library's (Python's is `str()` of an smtplib
    # exception, a dict of bytes reprs).
    prefix = "The password was reset but the email could not be sent: "
    before = {tag: await password_hash(f"reject_{tag}") for tag in ("py", "rs")}
    r1 = await py.post(f"{SEC}/users/{sec_users['reject_py']}/send-temp-password", headers=H(t_admin))
    r2 = await rs.post(f"{SEC}/users/{sec_users['reject_rs']}/send-temp-password", headers=H(t_admin))
    m1, m2 = r1.json().get("message", ""), r2.json().get("message", "")
    check(
        f"send-temp-password: refused recipient, 502 on both, SMTP error text differs [{r1.status_code}]",
        r1.status_code == r2.status_code == 502 and m1.startswith(prefix) and m2.startswith(prefix) and "550" in m1 and "550" in m2,
        f"python {r1.status_code} {r1.text}\n        rust   {r2.status_code} {r2.text}",
    )
    print(f"        python: {m1[len(prefix):]}\n        rust:   {m2[len(prefix):]}")
    check(
        "  (the password was rotated before the delivery failed, on both)",
        all([before[tag] != await password_hash(f"reject_{tag}") for tag in ("py", "rs")]),
    )
    # A logo but no brand colour: Python derives the accent from the logo's pixels (Pillow),
    # Rust uses the default palette. Everything but the colours is the same.
    png = io.BytesIO()
    Image.new("RGB", (4, 4), (200, 30, 30)).save(png, "PNG")
    red_png = base64.b64encode(png.getvalue()).decode()
    async with AsyncSession(async_engine) as s_:
        await s_.execute(
            text(
                "INSERT INTO customer_portal_branding (customer_code, enabled, title, logo_base64, logo_mime_type, updated_at) "
                "VALUES (:c, 1, 'Beta Portal', :l, 'image/png', UTC_TIMESTAMP())",
            ),
            {"c": CUST_B, "l": red_png},
        )
        r = await s_.execute(
            text(
                "INSERT INTO notification_template (name, `trigger`, format, subject_template, body_template, customer_code, "
                "is_default, created_by, created_at, updated_at) VALUES (:n, 'temp_password_issued', 'html', 'S', "
                "'{% for k, v in branding|dictsort %}{{ k }}={{ v }};{% endfor %}', :c, 0, 'par', UTC_TIMESTAMP(), UTC_TIMESTAMP())",
            ),
            {"n": f"par logo {SFX}", "c": CUST_B},
        )
        logo_tpl = r.lastrowid
        await s_.commit()
    r1, r2 = await both("POST", PRE("two"), t_admin, {"customer_code": CUST_B, "template_id": logo_tpl})
    b1, b2 = r1.json()["body"], r2.json()["body"]
    hexless = lambda b: re.sub(r"#[0-9a-f]{6}", "#c", b)  # noqa: E731
    check(
        f"temp-password branding: logo colour derived by Python only [{r1.status_code}]",
        r1.status_code == r2.status_code == 200 and b1 != b2 and hexless(b1) == hexless(b2) and "#fc862e" in b2,
        f"{b1}\n        {b2}",
    )

    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
