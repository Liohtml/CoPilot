"""Parity of the GitHub organization audit and the Nuclei scans (`crates/copilot-assessments`) with
this backend — NOT collected by pytest (needs a live MySQL and the Rust binary; run by
scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts (no legacy backend)
answer the same requests on one database. GitHub's API and the `copilot-nuclei-module` container
are local stand-ins that record every request — method, target, every header in the order it was
sent (names compared case-insensitively: hyper writes them lower-cased when httpx's spelling is not
title case), the body bytes — and both backends' requests are compared:

* configurations, exclusions, baselines and reports: every route, the ORM's shapes (a table model's
  keys compared one by one, Rust's in declaration order), the rows each backend leaves, the 422s,
  the bare 500s of a delete that a foreign key refuses;
* the audit, from a configuration (its report row and the configuration's `last_audit_*`), its
  summary and the ad-hoc audit: organization, repository, workflow and member checks over GitHub
  answers of every shape — pagination, rate limits (403 / 429), a hang-up, odd JSON — the requests
  compared as a multiset (the repositories are audited ten at a time, concurrently);
* the tenant checks Rust adds (RUST_MIGRATION.md §4): Python's answer and Rust's, side by side;
* paths with an encoded `/`, which Starlette routes decoded;
* Nuclei: the report list and one report, the scan and the delete, every failure shape.

    PARITY_SUITES=tests/e2e/rust_parity_github_audit_e2e.py scripts/rust-parity.sh

Ports (all overridable, defaults in the suite's own range): GITHUB_AUDIT_PARITY_RUST_PORT,
GITHUB_AUDIT_GH_STUB_PORT, GITHUB_AUDIT_NUCLEI_STUB_PORT. Seeded rows use ids 7844000-7844999.
"""

import asyncio
import datetime
import json
import os
import subprocess
import sys
import threading
import time
import types
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

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

from app.db.db_session import sync_engine  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RS_PORT = int(os.environ.get("GITHUB_AUDIT_PARITY_RUST_PORT", "6231"))
GH_PORT = int(os.environ.get("GITHUB_AUDIT_GH_STUB_PORT", "6232"))
NUCLEI_PORT = int(os.environ.get("GITHUB_AUDIT_NUCLEI_STUB_PORT", "6233"))
GH_BASE = f"http://127.0.0.1:{GH_PORT}"
NUCLEI_BASE = f"http://127.0.0.1:{NUCLEI_PORT}"

SFX = uuid.uuid4().hex[:6]
CUST_A, CUST_B = f"gha{SFX}", f"ghb{SFX}"
ADMIN, ANALYST, LONELY, PORTAL = f"gh_admin{SFX}", f"gh_analyst{SFX}", f"gh_lonely{SFX}", f"gh_portal{SFX}"
USERS = (ADMIN, ANALYST, LONELY, PORTAL)
#: Seeded ids (no other suite uses 7844xxx).
CFG_A, CFG_A2, CFG_B, CFG_OFF, CFG_INCL = 7844001, 7844002, 7844003, 7844004, 7844005
REP_A1, REP_A2, REP_A3, REP_B1 = 7844101, 7844102, 7844103, 7844104
EXC_A1, EXC_A2, EXC_B1 = 7844201, 7844202, 7844203
BAS_A1, BAS_A2, BAS_B1 = 7844301, 7844302, 7844303
ORG = f"acme{SFX}"
results = []

CONFIG_ORDER = [
    "id",
    "customer_code",
    "github_token",
    "organization",
    "token_type",
    "token_expires_at",
    "enabled",
    "auto_audit_enabled",
    "audit_schedule_cron",
    "include_repos",
    "include_workflows",
    "include_members",
    "include_archived_repos",
    "repo_filter_mode",
    "repo_filter_list",
    "notify_on_critical",
    "notify_on_high",
    "notification_webhook_url",
    "notification_email",
    "minimum_passing_score",
    "created_at",
    "updated_at",
    "created_by",
    "updated_by",
    "last_audit_at",
    "last_audit_score",
    "last_audit_grade",
]
REPORT_ORDER = [
    "id",
    "config_id",
    "customer_code",
    "report_name",
    "organization",
    "audit_started_at",
    "audit_completed_at",
    "audit_duration_seconds",
    "total_repos_audited",
    "total_checks",
    "passed_checks",
    "failed_checks",
    "warning_checks",
    "critical_findings",
    "high_findings",
    "medium_findings",
    "low_findings",
    "score",
    "grade",
    "status",
    "error_message",
    "full_report",
    "top_findings",
    "triggered_by",
    "triggered_by_user",
]
EXCLUSION_ORDER = [
    "id",
    "config_id",
    "customer_code",
    "check_id",
    "resource_name",
    "resource_type",
    "reason",
    "approved_by",
    "approved_at",
    "expires_at",
    "enabled",
    "created_at",
    "created_by",
]
BASELINE_ORDER = [
    "id",
    "config_id",
    "customer_code",
    "name",
    "description",
    "expected_checks",
    "baseline_report_id",
    "is_active",
    "created_at",
    "created_by",
]


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
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(text(statement), params)]


# --- the stand-ins -----------------------------------------------------------------------------------


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, method, target, headers, body):
        with self.lock:
            self.requests.append((method, target, [(k.lower(), v) for k, v in headers], body.decode("latin-1")))

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out


class GitHub:
    """GitHub's REST API: `routes` maps `path?query` → (status, body, extra headers); anything else
    is GitHub's 404. `hangup` closes every connection without an answer."""

    def __init__(self):
        self.reset()

    def reset(self, routes=None, hangup=False):
        self.routes = dict(routes or {})
        self.hangup = hangup

    def __call__(self, method, target, headers, body):
        if self.hangup:
            return None
        answer = self.routes.get(target)
        if answer is None:
            return 404, "application/json; charset=utf-8", json.dumps({"message": "Not Found"}).encode(), []
        status, payload, extra = (answer + ([],))[:3] if len(answer) == 2 else answer
        if payload is None:
            return status, None, b"", extra
        if isinstance(payload, (bytes, str)):
            raw = payload.encode() if isinstance(payload, str) else payload
            return status, "text/plain", raw, extra
        return status, "application/json; charset=utf-8", json.dumps(payload).encode(), extra


class Nuclei:
    """The module container, reached as `/copilot-nuclei-module/...`: `routes` maps
    `METHOD path` → (status, body); anything else is a 404."""

    def __init__(self):
        self.reset()

    def reset(self, routes=None):
        self.routes = dict(routes or {})

    def __call__(self, method, target, headers, body):
        answer = self.routes.get(f"{method} {target}")
        if answer is None:
            return 404, "application/json", json.dumps({"detail": "Not Found"}).encode(), []
        status, payload = answer
        if isinstance(payload, (bytes, str)):
            raw = payload.encode() if isinstance(payload, str) else payload
            return status, "text/html", raw, []
        return status, "application/json", json.dumps(payload).encode(), []


GH, NU = GitHub(), Nuclei()
GH_REC, NU_REC = Recorder(), Recorder()


def start_stub(port, answer, recorder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            recorder.add(self.command, self.path, self.headers.items(), body)
            out = answer(self.command, self.path, self.headers, body)
            if out is None:
                self.close_connection = True
                return
            status, ctype, payload, extra = out
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815 - http.server API

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- GitHub's answers --------------------------------------------------------------------------------


def org_data(**over):
    data = {
        "login": ORG,
        "html_url": f"https://github.com/{ORG}",
        "two_factor_requirement_enabled": True,
        "default_repository_permission": "read",
        "members_can_create_repositories": True,
        "members_can_create_public_repositories": False,
    }
    data.update(over)
    return data


def repo(name, **over):
    data = {
        "name": name,
        "full_name": f"{ORG}/{name}",
        "html_url": f"https://github.com/{ORG}/{name}",
        "private": True,
        "archived": False,
        "default_branch": "main",
        "license": None,
    }
    data.update(over)
    return data


PROTECTED = {
    "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False},
    "enforce_admins": {"enabled": False},
    "required_status_checks": None,
}


def github(org=None, repos=(), per_repo=None, domains=None, saml=None, actions=None, workflow=None, members=(), admins=(), org_name=None):
    """GitHub's answers for one organization."""
    name = org_name or ORG
    table = {
        f"/orgs/{name}": org if isinstance(org, tuple) else (200, org_data() if org is None else org),
        f"/orgs/{name}/actions/permissions": actions or (200, {"allowed_actions": "all"}),
        f"/orgs/{name}/actions/permissions/workflow": workflow or (200, {"default_workflow_permissions": "write"}),
    }
    if domains:
        table[f"/orgs/{name}/domains"] = domains
    if saml:
        table[f"/orgs/{name}/saml"] = saml
    repos = list(repos)
    pages = [repos[i : i + 100] for i in range(0, len(repos), 100)] or [[]]
    for n, page in enumerate(pages, start=1):
        table[f"/orgs/{name}/repos?per_page=100&page={n}"] = (200, page)
    for r in repos:
        rn, branch = r["name"], r.get("default_branch", "main")
        custom = (per_repo or {}).get(rn, {})
        table[f"/repos/{name}/{rn}/branches/{branch}/protection"] = custom.get("protection", (200, PROTECTED))
        table[f"/repos/{name}/{rn}"] = custom.get("repo", (200, {"security_and_analysis": {"secret_scanning": {"status": "enabled"}}}))
        table[f"/repos/{name}/{rn}/vulnerability-alerts"] = custom.get("vuln", (204, None))
        table[f"/repos/{name}/{rn}/code-scanning/alerts?per_page=1"] = custom.get("code", (200, []))
        table[f"/repos/{name}/{rn}/branches/{branch}"] = custom.get("branch", (200, {"name": branch, "protected": True}))
    table[f"/orgs/{name}/members?per_page=100&page=1"] = (200, [{"login": m} for m in members])
    table[f"/orgs/{name}/members?role=admin&per_page=100&page=1"] = (200, [{"login": m} for m in admins])
    return table


RATE_LIMITED = (403, {"message": "API rate limit exceeded"}, [("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "1900000000")])

FULL_ORG = github(
    repos=[
        repo("web", private=False, license={"name": "MIT License", "spdx_id": "MIT"}),
        repo("api", default_branch="develop"),
        repo("old", archived=True),
        repo("docs", private=False),
        repo("infra"),
    ],
    per_repo={
        "api": {"protection": (404, {"message": "Branch not protected"}), "vuln": (404, None), "code": (404, None)},
        "docs": {"protection": (200, {"required_pull_request_reviews": None}), "repo": (200, {}), "branch": (200, {"protected": False})},
        "infra": {"protection": RATE_LIMITED, "repo": (429, {"message": "slow down"}), "vuln": (500, None), "code": RATE_LIMITED},
    },
    domains=(200, [{"domain": "acme.example", "is_verified": True}]),
    saml=(200, {"enforced": False}),
    members=["alice", "bob", "carol"],
    admins=["alice"],
)


# --- the database ------------------------------------------------------------------------------------


def seed_config(cid, customer, org=ORG, **over):
    values = {
        "id": cid,
        "customer_code": customer,
        "github_token": f"ghp_parity_{cid}",
        "organization": org,
        "token_type": "pat",
        "token_expires_at": None,
        "enabled": 1,
        "auto_audit_enabled": 0,
        "audit_schedule_cron": None,
        "include_repos": 1,
        "include_workflows": 1,
        "include_members": 1,
        "include_archived_repos": 0,
        "repo_filter_mode": "all",
        "repo_filter_list": None,
        "notify_on_critical": 1,
        "notify_on_high": 0,
        "notification_webhook_url": None,
        "notification_email": None,
        "minimum_passing_score": 72.3,
        "created_at": "2026-01-02 03:04:05",
        "updated_at": "2026-01-02 03:04:05",
        "created_by": "seed",
        "updated_by": None,
        "last_audit_at": None,
        "last_audit_score": None,
        "last_audit_grade": None,
    }
    values.update(over)
    cols = ", ".join(values)
    sql(f"INSERT INTO github_audit_config ({cols}) VALUES ({', '.join(':' + c for c in values)})", **values)


def seed_report(rid, cid, customer, started, **over):
    full = {
        "success": True,
        "message": "Audit completed successfully. Score: 61.1 (D,)",
        "summary": {"organization": ORG, "score": 61.1, "grade": "D"},
        "organization_results": {
            "org_name": ORG,
            "checks": [{"check_id": "org-2fa-required", "status": "fail"}, {"check_id": "org-sso-enforcement", "status": "not_applicable"}],
        },
        "repository_results": [{"repo_name": "web", "checks": [{"check_id": "repo-license", "status": "warning"}]}],
    }
    values = {
        "id": rid,
        "config_id": cid,
        "customer_code": customer,
        "report_name": f"Audit-{ORG}-seed-{rid}",
        "organization": ORG,
        "audit_started_at": started,
        "audit_completed_at": started,
        "audit_duration_seconds": 1.23456789,
        "total_repos_audited": 3,
        "total_checks": 12,
        "passed_checks": 6,
        "failed_checks": 3,
        "warning_checks": 3,
        "critical_findings": 1,
        "high_findings": 1,
        "medium_findings": 2,
        "low_findings": 2,
        "score": 61.1,
        "grade": "D",
        "status": "completed",
        "error_message": None,
        "full_report": json.dumps(full),
        "top_findings": json.dumps([{"check_id": "org-2fa-required", "severity": "critical", "details": {"b": 1, "a": [1.0, None]}}]),
        "triggered_by": "manual",
        "triggered_by_user": None,
    }
    values.update(over)
    cols = ", ".join(values)
    sql(f"INSERT INTO github_audit_report ({cols}) VALUES ({', '.join(':' + c for c in values)})", **values)


def seed_exclusion(eid, cid, customer, **over):
    values = {
        "id": eid,
        "config_id": cid,
        "customer_code": customer,
        "check_id": "repo-license",
        "resource_name": None,
        "resource_type": None,
        "reason": "accepted risk",
        "approved_by": None,
        "approved_at": None,
        "expires_at": None,
        "enabled": 1,
        "created_at": "2026-01-02 03:04:05",
        "created_by": "seed",
    }
    values.update(over)
    cols = ", ".join(values)
    sql(f"INSERT INTO github_audit_check_exclusion ({cols}) VALUES ({', '.join(':' + c for c in values)})", **values)


def seed_baseline(bid, cid, customer, **over):
    values = {
        "id": bid,
        "config_id": cid,
        "customer_code": customer,
        "name": f"baseline {bid}",
        "description": None,
        "expected_checks": json.dumps({"zz": "pass", "a": "fail", "org-2fa-required": "pass"}),
        "baseline_report_id": None,
        "is_active": 1,
        "created_at": "2026-01-02 03:04:05",
        "created_by": "seed",
    }
    values.update(over)
    cols = ", ".join(values)
    sql(f"INSERT INTO github_audit_baseline ({cols}) VALUES ({', '.join(':' + c for c in values)})", **values)


OURS = "customer_code IN (:a, :b)"


def wipe():
    for table in ("github_audit_baseline", "github_audit_check_exclusion", "github_audit_report", "github_audit_config"):
        sql(f"DELETE FROM {table} WHERE {OURS}", a=CUST_A, b=CUST_B)


def seed_rows():
    """The fixed rows every check starts from."""
    wipe()
    seed_config(CFG_A, CUST_A, created_by=None)
    seed_config(
        CFG_A2,
        CUST_A,
        org="acme-two",
        repo_filter_list=json.dumps(["web", "api"]),
        repo_filter_mode="exclude",
        last_audit_score=66.7,
    )
    seed_config(CFG_B, CUST_B, org="beta-org")
    seed_config(CFG_OFF, CUST_A, org="disabled-org", enabled=0)
    seed_config(CFG_INCL, CUST_A, org=ORG + "-incl", repo_filter_mode="include", repo_filter_list=json.dumps(["web", "docs"]))
    seed_report(REP_A1, CFG_A, CUST_A, "2026-03-01 10:00:00")
    seed_report(REP_A2, CFG_A, CUST_A, "2026-03-02 10:00:00", status="failed", score=0.0, grade="F")
    seed_report(REP_A3, CFG_A2, CUST_A, "2026-03-02 10:00:00", organization="acme-two")
    seed_report(REP_B1, CFG_B, CUST_B, "2026-03-03 10:00:00", organization="beta-org")
    seed_exclusion(EXC_A1, CFG_A, CUST_A)
    seed_exclusion(EXC_A2, CFG_A, CUST_A, check_id="repo-code-scanning", resource_name="api", expires_at="2001-01-01 00:00:00")
    seed_exclusion(EXC_B1, CFG_B, CUST_B)
    seed_baseline(BAS_A1, CFG_A, CUST_A)
    seed_baseline(BAS_A2, CFG_A, CUST_A, is_active=0, baseline_report_id=REP_A1)
    seed_baseline(BAS_B1, CFG_B, CUST_B)


VOLATILE = {
    "id",
    "created_at",
    "updated_at",
    "approved_at",
    "audit_started_at",
    "audit_completed_at",
    "audit_duration_seconds",
    "last_audit_at",
    "report_name",
    "audit_timestamp",
}


def masked(value, keys=VOLATILE):
    if isinstance(value, dict):
        return {k: ("<m>" if k in keys and v is not None else masked(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [masked(v, keys) for v in value]
    return value


def state():
    """Every row of our customers, ids and clock values masked, JSON columns parsed."""
    out = {}
    for table, order in (
        ("github_audit_config", "organization, customer_code, created_by"),
        ("github_audit_report", "customer_code, organization, status, score"),
        ("github_audit_check_exclusion", "customer_code, check_id, reason"),
        ("github_audit_baseline", "customer_code, name"),
    ):
        got = rows(f"SELECT * FROM {table} WHERE {OURS} ORDER BY {order}", a=CUST_A, b=CUST_B)
        for r in got:
            for k, v in list(r.items()):
                if k in ("repo_filter_list", "full_report", "top_findings", "expected_checks") and isinstance(v, str):
                    r[k] = json.loads(v)
                elif isinstance(v, datetime.datetime):
                    r[k] = v.isoformat()
                elif k in ("config_id", "baseline_report_id") and v is not None and not (7844000 <= v < 7845000):
                    r[k] = "<fresh>"
        out[table] = masked(got)
    return out


def seed():
    for code, name in ((CUST_A, "GH Parity A"), (CUST_B, "GH Parity B")):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (LONELY, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name in (ANALYST, PORTAL):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=CUST_A,
            n=name,
        )


def cleanup():
    wipe()
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    for code in (CUST_A, CUST_B):
        sql("DELETE FROM customers WHERE customer_code = :c", c=code)


# --- the two backends --------------------------------------------------------------------------------


class _Redirect(httpx.AsyncBaseTransport):
    """What COPILOT_NUCLEI_MODULE_URL does for the Rust service: `{base}/{host}{path}`."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        rest = str(request.url).split("://", 1)[1]
        request.url = httpx.URL(f"{NUCLEI_BASE}/{rest}")
        request.headers["Host"] = NUCLEI_BASE.split("://", 1)[1]
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


def build_python_app():
    import app.integrations.github_audit.services.github_audit as gh_service
    import app.integrations.nuclei.services.nuclei as nuclei_service
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import github_audit
    from app.routers import nuclei

    gh_service.GITHUB_API_BASE = GH_BASE
    real = httpx.AsyncClient
    shim = types.SimpleNamespace(**{k: getattr(httpx, k) for k in dir(httpx) if not k.startswith("_")})
    shim.AsyncClient = lambda *a, **kw: real(*a, transport=_Redirect(), **kw)
    nuclei_service.httpx = shim

    api = APIRouter(prefix="/api")
    api.include_router(github_audit.router)
    api.include_router(nuclei.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port):
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        "COPILOT_PORT": str(port),
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_GITHUB_AUDIT_API_URL": GH_BASE,
        "COPILOT_NUCLEI_MODULE_URL": NUCLEI_BASE,
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


RESPONSE_HEADERS = ("content-type", "content-length")


def ordered_ok(value):
    """Whether every table-model object of a Rust answer lists its keys in declaration order."""
    if isinstance(value, list):
        return all(ordered_ok(v) for v in value)
    if not isinstance(value, dict):
        return True
    keys = list(value)
    for order in (CONFIG_ORDER, REPORT_ORDER, EXCLUSION_ORDER, BASELINE_ORDER):
        if keys and set(keys) == set(order) and keys != order:
            return False
    return all(ordered_ok(v) for v in value.values())


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = {"Accept-Encoding": "identity", **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        GH_REC.take()
        NU_REC.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0.05)
        return r, {"github": GH_REC.take(), "nuclei": NU_REC.take()}

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        before=None,
        gh=None,
        nuclei=None,
        mask=(),
        expect=None,
        outbound="exact",
        table=True,
        py_view=None,
        **kw,
    ):
        """Python, then Rust, each after `before()` and with the stand-ins set from `gh` / `nuclei`.
        `mask`: keys whose values may differ (fresh ids, clocks); `outbound`: `exact`, `sorted`
        (concurrent requests) or `skip` (a timing-dependent cut); `expect=(python, rust)`: the
        statuses of a deliberate difference, whose rows must still agree unless `table=False`."""
        sides = []
        for client in (self.py, self.rs):
            if before:
                before()
            GH.reset(**(gh or {}))
            NU.reset(nuclei)
            r, out = await self.call(client, method, path, tok, **kw)
            sides.append((r, out, state() if table else None))
        (r1, o1, s1), (r2, o2, s2) = sides
        if expect:
            ok = (r1.status_code, r2.status_code) == expect
            check(
                f"{name} [diff by design {expect}]",
                ok,
                f"python {r1.status_code} {r1.content[:400]!r}\n        rust   {r2.status_code} {r2.content[:400]!r}",
            )
            return r1, r2

        def norm(r, view=None):
            try:
                value = json.loads(r.content)
            except ValueError:
                return r.content
            if view:
                value = view(value)
            return masked(value, set(mask)) if mask else value

        # `py_view` turns Python's answer into what Rust answers by design (§4).
        b1, b2 = norm(r1, py_view), norm(r2)
        # Values with their JSON types (`1` is not `1.0`), keys compared as sets: a table model's
        # key order is process-dependent in Python (RUST_MIGRATION.md §4).
        ok = r1.status_code == r2.status_code and typed(b1) == typed(b2)
        detail = f"python {r1.status_code} {r1.content[:1500]!r}\n        rust   {r2.status_code} {r2.content[:1500]!r}"
        if not mask and not isinstance(b1, (bytes, str)) and ok:
            # Unmasked JSON in the same key order: the very bytes.
            if json.dumps(b1) == json.dumps(b2) and r1.content != r2.content:
                ok = False
                detail += "\n        same values, other bytes"
        if isinstance(b2, (dict, list)) and not ordered_ok(b2):
            ok = False
            detail += "\n        rust: a table model's keys out of declaration order"
        h1 = {k: r1.headers.get(k) for k in RESPONSE_HEADERS}
        h2 = {k: r2.headers.get(k) for k in RESPONSE_HEADERS}
        if mask:
            h1.pop("content-length")
            h2.pop("content-length")
        if h1 != h2:
            ok = False
            detail += f"\n        headers python {h1}\n        headers rust   {h2}"
        if outbound != "skip":
            p1, p2 = o1, o2
            if outbound == "sorted":
                p1 = {k: sorted(v) for k, v in o1.items()}
                p2 = {k: sorted(v) for k, v in o2.items()}
            if p1 != p2:
                ok = False
                detail += f"\n        outbound python {p1}\n        outbound rust   {p2}"
        if s1 != s2:
            ok = False
            detail += f"\n        rows python {s1}\n        rows rust   {s2}"
        check(f"{name} [{r1.status_code}]" + (" [diff by design: py_view]" if py_view else ""), ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {r1.content[:800]!r}")
        return r1, r2


def typed(value):
    """A JSON value with each number's type kept, for comparison."""
    if isinstance(value, dict):
        return {k: typed(v) for k, v in value.items()}
    if isinstance(value, list):
        return [typed(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return ("float", repr(value))
    if isinstance(value, int):
        return ("int", value)
    return value


# --- the checks --------------------------------------------------------------------------------------

G = "/api/github-audit"


async def config_checks(p, t):
    print("\n== configurations")
    await p.same("checks catalog", "GET", f"{G}/checks", t["analyst"], before=seed_rows)
    await p.same("checks, no token", "GET", f"{G}/checks", before=seed_rows)
    await p.same("checks, portal user", "GET", f"{G}/checks", t["portal"], before=seed_rows)
    await p.same("list configs, admin", "GET", f"{G}/config", t["admin"], before=seed_rows)
    await p.same(
        "list configs, admin, both customers",
        "GET",
        f"{G}/config?customer_codes={CUST_A}&customer_codes={CUST_B}",
        t["admin"],
        before=seed_rows,
    )
    await p.same("list configs, admin, legacy customer_code", "GET", f"{G}/config?customer_code={CUST_B}", t["admin"], before=seed_rows)
    await p.same("list configs, analyst, own customer", "GET", f"{G}/config?customer_codes={CUST_A}", t["analyst"], before=seed_rows)
    await p.same("list configs, admin, an empty code", "GET", f"{G}/config?customer_codes=", t["admin"], before=seed_rows)
    r1, r2 = await p.same("list configs, analyst, no filter", "GET", f"{G}/config", t["analyst"], before=seed_rows, expect=(200, 200))
    py_codes = {c["customer_code"] for c in r1.json()["configs"]}
    rs_codes = {c["customer_code"] for c in r2.json()["configs"]}
    check(
        "§4 list configs: Python lists another tenant's configuration, Rust the caller's only",
        CUST_B in py_codes and rs_codes == {CUST_A},
    )
    r1, r2 = await p.same(
        "list configs, unassigned analyst",
        "GET",
        f"{G}/config?customer_codes={CUST_A}",
        t["lonely"],
        before=seed_rows,
        expect=(200, 200),
    )
    check("§4 list configs: an unassigned analyst sees nothing in Rust", r2.json()["configs"] == [] and len(r1.json()["configs"]) > 0)

    await p.same("one config, analyst", "GET", f"{G}/config/{CFG_A}", t["analyst"], before=seed_rows)
    await p.same("one config, filters and a stored score", "GET", f"{G}/config/{CFG_A2}", t["admin"], before=seed_rows)
    await p.same("one config, admin, unknown id", "GET", f"{G}/config/7844999", t["admin"], before=seed_rows)
    await p.same("one config, not an int", "GET", f"{G}/config/abc", t["admin"], before=seed_rows)
    await p.same("one config, a float string", "GET", f"{G}/config/{CFG_A}.0", t["admin"], before=seed_rows)
    await p.same("one config, an int beyond any id", "GET", f"{G}/config/99999999999999999999999", t["admin"], before=seed_rows)
    await p.same("one config, another tenant's", "GET", f"{G}/config/{CFG_B}", t["analyst"], before=seed_rows, expect=(200, 403))
    await p.same("one config, scoped, unknown id", "GET", f"{G}/config/7844999", t["analyst"], before=seed_rows, expect=(404, 403))

    body = {
        "customer_code": CUST_A,
        "github_token": "ghp_new_token_1234",
        "organization": "new-org",
        "repo_filter_list": ["a"],
        "minimum_passing_score": 55,
    }
    fresh = ("id", "created_at", "updated_at")

    def token_masked(answer):
        # §4: Python's create echoes the token in clear; Rust masks it as every other config
        # answer does (`***` and its last four characters). The stored row is the same.
        config = answer.get("config") if isinstance(answer, dict) else None
        if not isinstance(config, dict) or not isinstance(config.get("github_token"), str):
            return answer
        token = config["github_token"]
        return {**answer, "config": {**config, "github_token": "***" + token[-4:] if len(token) > 4 else "***"}}

    await p.same("create config", "POST", f"{G}/config", t["admin"], before=seed_rows, json=body, mask=fresh, py_view=token_masked)
    full = {
        **body,
        "token_type": "app",
        "token_expires_at": "2027-05-06T07:08:09.600000+02:00",
        "enabled": "false",
        "audit_schedule_cron": "0 3 * * 1",
        "include_archived_repos": True,
        "repo_filter_mode": "include",
        "notify_on_high": 1,
        "notification_webhook_url": "https://hooks.example.com/é",
        "notification_email": "soc@example.com",
        "minimum_passing_score": "88.8",
        "created_by": "alice",
    }
    await p.same(
        "create config, every field",
        "POST",
        f"{G}/config",
        t["analyst"],
        before=seed_rows,
        json=full,
        mask=fresh,
        py_view=token_masked,
    )
    await p.same("create config, an existing pair", "POST", f"{G}/config", t["admin"], before=seed_rows, json={**body, "organization": ORG})
    await p.same("create config, missing fields", "POST", f"{G}/config", t["admin"], before=seed_rows, json={})
    await p.same(
        "create config, invalid fields",
        "POST",
        f"{G}/config",
        t["admin"],
        before=seed_rows,
        json={**body, "customer_code": "x" * 51, "minimum_passing_score": 101, "enabled": "maybe"},
    )
    await p.same(
        "create config, malformed JSON",
        "POST",
        f"{G}/config",
        before=seed_rows,
        content=b"{",
        headers={"Content-Type": "application/json"},
    )
    await p.same(
        "create config, not JSON",
        "POST",
        f"{G}/config",
        t["admin"],
        before=seed_rows,
        content=b"x=1",
        headers={"Content-Type": "text/plain"},
    )
    await p.same(
        "create config, a filter mode too long for its column",
        "POST",
        f"{G}/config",
        t["admin"],
        before=seed_rows,
        json={**body, "repo_filter_mode": "m" * 21},
    )
    await p.same("create config, portal user", "POST", f"{G}/config", t["portal"], before=seed_rows, json=body)
    await p.same(
        "create config, analyst, another tenant",
        "POST",
        f"{G}/config",
        t["analyst"],
        before=seed_rows,
        json={**body, "customer_code": CUST_B},
        expect=(200, 403),
        table=False,
    )
    check(
        "§4 create config: Rust filed nothing under another tenant",
        not rows("SELECT id FROM github_audit_config WHERE customer_code = :c AND organization = 'new-org'", c=CUST_B),
    )

    upd = {
        "organization": "renamed",
        "enabled": None,
        "include_members": "off",
        "repo_filter_list": [],
        "token_expires_at": "2028-01-01T00:00:00Z",
        "minimum_passing_score": 12,
        "updated_by": "bob",
    }
    await p.same("update config", "PUT", f"{G}/config/{CFG_A}", t["analyst"], before=seed_rows, json=upd, mask=("updated_at",))
    await p.same("update config, nothing", "PUT", f"{G}/config/{CFG_A}", t["admin"], before=seed_rows, json={}, mask=("updated_at",))
    await p.same(
        "update config, invalid path and body",
        "PUT",
        f"{G}/config/x",
        t["admin"],
        before=seed_rows,
        json={"minimum_passing_score": -5, "token_type": "t" * 51},
    )
    await p.same("update config, unknown id", "PUT", f"{G}/config/7844999", t["admin"], before=seed_rows, json={})
    await p.same(
        "update config, another tenant's",
        "PUT",
        f"{G}/config/{CFG_B}",
        t["analyst"],
        before=seed_rows,
        json={"organization": "x"},
        expect=(200, 403),
        table=False,
    )

    await p.same("delete config, analyst", "DELETE", f"{G}/config/{CFG_A}", t["analyst"], before=seed_rows)
    await p.same("delete config with reports (a foreign key refuses it)", "DELETE", f"{G}/config/{CFG_A}", t["admin"], before=seed_rows)
    await p.same(
        "delete config with exclusions only",
        "DELETE",
        f"{G}/config/{CFG_INCL}",
        t["admin"],
        before=lambda: (seed_rows(), seed_exclusion(7844290, CFG_INCL, CUST_A)),
    )
    await p.same("delete config", "DELETE", f"{G}/config/{CFG_OFF}", t["admin"], before=seed_rows)
    await p.same("delete config, unknown id", "DELETE", f"{G}/config/7844999", t["admin"], before=seed_rows)


async def report_checks(p, t):
    print("\n== reports")
    await p.same("reports, admin, ours", "GET", f"{G}/reports?customer_code={CUST_A}", t["admin"], before=seed_rows)
    await p.same(
        "reports, admin, filters",
        "GET",
        f"{G}/reports?customer_code={CUST_A}&config_id={CFG_A}&status=completed&organization={ORG}",
        t["admin"],
        before=seed_rows,
    )
    await p.same("reports, admin, a page", "GET", f"{G}/reports?customer_code={CUST_A}&limit=2&offset=1", t["admin"], before=seed_rows)
    await p.same(
        "reports, config_id 0 filters nothing",
        "GET",
        f"{G}/reports?customer_code={CUST_A}&config_id=0",
        t["admin"],
        before=seed_rows,
    )
    await p.same("reports, invalid query", "GET", f"{G}/reports?limit=0&offset=-1&config_id=x", t["admin"], before=seed_rows)
    await p.same("reports, limit too large", "GET", f"{G}/reports?limit=201", t["admin"], before=seed_rows)
    await p.same(
        "reports, analyst names another tenant",
        "GET",
        f"{G}/reports?customer_code={CUST_B}&limit=0",
        t["analyst"],
        before=seed_rows,
    )
    await p.same("reports, analyst, own customer", "GET", f"{G}/reports?customer_code={CUST_A}", t["analyst"], before=seed_rows)
    r1, r2 = await p.same(
        "reports, analyst, no customer filter",
        "GET",
        f"{G}/reports?status=completed",
        t["analyst"],
        before=seed_rows,
        expect=(200, 200),
    )
    check(
        "§4 reports: the same page, but Python's total counts another tenant's reports",
        r1.json()["reports"] == r2.json()["reports"] and r1.json()["total_count"] > r2.json()["total_count"] == len(r2.json()["reports"]),
        f"{r1.json()['total_count']} vs {r2.json()['total_count']}",
    )
    await p.same(
        "reports, unassigned analyst",
        "GET",
        f"{G}/reports?organization=beta-org",
        t["lonely"],
        before=seed_rows,
        expect=(200, 200),
    )

    await p.same("one report", "GET", f"{G}/reports/{REP_A1}", t["analyst"], before=seed_rows)
    await p.same("one report, admin, unknown", "GET", f"{G}/reports/7844999", t["admin"], before=seed_rows)
    await p.same("one report, another tenant's", "GET", f"{G}/reports/{REP_B1}", t["analyst"], before=seed_rows, expect=(200, 403))
    await p.same("delete report, analyst", "DELETE", f"{G}/reports/{REP_A2}", t["analyst"], before=seed_rows)
    await p.same("delete report", "DELETE", f"{G}/reports/{REP_A2}", t["admin"], before=seed_rows)
    await p.same("delete report a baseline names", "DELETE", f"{G}/reports/{REP_A1}", t["admin"], before=seed_rows)
    await p.same("delete report, unknown", "DELETE", f"{G}/reports/7844999", t["admin"], before=seed_rows)


async def exclusion_checks(p, t):
    print("\n== exclusions")
    await p.same("exclusions", "GET", f"{G}/config/{CFG_A}/exclusions", t["analyst"], before=seed_rows)
    await p.same(
        "exclusions, expired included",
        "GET",
        f"{G}/config/{CFG_A}/exclusions?include_expired=true",
        t["analyst"],
        before=seed_rows,
    )
    await p.same("exclusions, invalid query", "GET", f"{G}/config/{CFG_A}/exclusions?include_expired=maybe", t["analyst"], before=seed_rows)
    await p.same("exclusions, admin, unknown config", "GET", f"{G}/config/7844999/exclusions", t["admin"], before=seed_rows)
    await p.same("exclusions, another tenant's", "GET", f"{G}/config/{CFG_B}/exclusions", t["analyst"], before=seed_rows, expect=(200, 403))
    await p.same(
        "exclusions, scoped, unknown config",
        "GET",
        f"{G}/config/7844999/exclusions",
        t["analyst"],
        before=seed_rows,
        expect=(200, 403),
    )
    fresh = ("id", "created_at", "approved_at")
    body = {
        "check_id": "repo-license",
        "resource_name": "web",
        "reason": "public mirror",
        "approved_by": "lead",
        "expires_at": "2030-01-01T00:00:00.700000",
        "created_by": "alice",
    }
    await p.same("create exclusion", "POST", f"{G}/config/{CFG_A}/exclusions", t["analyst"], before=seed_rows, json=body, mask=fresh)
    await p.same(
        "create exclusion, empty approver",
        "POST",
        f"{G}/config/{CFG_A}/exclusions",
        t["analyst"],
        before=seed_rows,
        json={**body, "approved_by": ""},
        mask=fresh,
    )
    await p.same(
        "create exclusion, invalid",
        "POST",
        f"{G}/config/{CFG_A}/exclusions",
        t["analyst"],
        before=seed_rows,
        json={"check_id": "c" * 101},
    )
    await p.same(
        "create exclusion, a reason too long for its column",
        "POST",
        f"{G}/config/{CFG_A}/exclusions",
        t["admin"],
        before=seed_rows,
        json={**body, "reason": "r" * 1025},
    )
    await p.same("create exclusion, unknown config", "POST", f"{G}/config/7844999/exclusions", t["admin"], before=seed_rows, json=body)
    await p.same(
        "create exclusion, another tenant's config",
        "POST",
        f"{G}/config/{CFG_B}/exclusions",
        t["analyst"],
        before=seed_rows,
        json=body,
        expect=(200, 403),
        table=False,
    )
    await p.same(
        "update exclusion",
        "PUT",
        f"{G}/exclusions/{EXC_A1}",
        t["analyst"],
        before=seed_rows,
        json={"reason": "new", "approved_by": None, "enabled": "false", "expires_at": "2031-02-03"},
    )
    await p.same("update exclusion, nothing", "PUT", f"{G}/exclusions/{EXC_A1}", t["analyst"], before=seed_rows, json={})
    await p.same(
        "update exclusion, invalid",
        "PUT",
        f"{G}/exclusions/{EXC_A1}",
        t["analyst"],
        before=seed_rows,
        json={"enabled": 2, "expires_at": "x"},
    )
    await p.same("update exclusion, unknown", "PUT", f"{G}/exclusions/7844999", t["admin"], before=seed_rows, json={})
    await p.same(
        "update exclusion, another tenant's",
        "PUT",
        f"{G}/exclusions/{EXC_B1}",
        t["analyst"],
        before=seed_rows,
        json={"reason": "x"},
        expect=(200, 403),
        table=False,
    )
    await p.same("delete exclusion", "DELETE", f"{G}/exclusions/{EXC_A1}", t["admin"], before=seed_rows)
    await p.same("delete exclusion, analyst", "DELETE", f"{G}/exclusions/{EXC_A1}", t["analyst"], before=seed_rows)
    await p.same("delete exclusion, unknown", "DELETE", f"{G}/exclusions/7844999", t["admin"], before=seed_rows)


async def baseline_checks(p, t):
    print("\n== baselines")
    await p.same("baselines", "GET", f"{G}/config/{CFG_A}/baselines", t["analyst"], before=seed_rows)
    await p.same("baselines, active only", "GET", f"{G}/config/{CFG_A}/baselines?active_only=1", t["analyst"], before=seed_rows)
    await p.same("baselines, another tenant's", "GET", f"{G}/config/{CFG_B}/baselines", t["analyst"], before=seed_rows, expect=(200, 403))
    fresh = ("id", "created_at")
    body = {"name": "May", "description": "d", "expected_checks": {"z": "pass", "org-2fa-required": "fail"}, "created_by": "alice"}
    await p.same(
        "create baseline (deactivates the active one)",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["analyst"],
        before=seed_rows,
        json=body,
        mask=fresh,
    )
    await p.same(
        "create baseline, inactive",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["analyst"],
        before=seed_rows,
        json={**body, "is_active": "no"},
        mask=fresh,
    )
    await p.same(
        "create baseline from a report",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["analyst"],
        before=seed_rows,
        json={**body, "baseline_report_id": REP_A1},
        mask=fresh,
    )
    await p.same(
        "create baseline from a report without full_report",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["analyst"],
        before=lambda: (seed_rows(), sql("UPDATE github_audit_report SET full_report = NULL WHERE id = :i", i=REP_A2)),
        json={**body, "baseline_report_id": REP_A2},
        mask=fresh,
    )
    await p.same(
        "create baseline from an odd report (KeyError)",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["admin"],
        before=lambda: (
            seed_rows(),
            sql(
                "UPDATE github_audit_report SET full_report = :f WHERE id = :i",
                i=REP_A2,
                f=json.dumps({"organization_results": {"checks": [{"status": "x"}]}}),
            ),
        ),
        json={**body, "baseline_report_id": REP_A2},
    )
    await p.same(
        "create baseline, report id 0",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["admin"],
        before=seed_rows,
        json={**body, "baseline_report_id": 0},
    )
    await p.same(
        "create baseline, unknown report",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["admin"],
        before=seed_rows,
        json={**body, "baseline_report_id": 7844999},
    )
    await p.same(
        "create baseline, invalid",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["admin"],
        before=seed_rows,
        json={"name": "n" * 256, "expected_checks": {"a": 1}, "baseline_report_id": "x"},
    )
    await p.same(
        "create baseline, another tenant's report",
        "POST",
        f"{G}/config/{CFG_A}/baselines",
        t["analyst"],
        before=seed_rows,
        json={**body, "baseline_report_id": REP_B1},
        expect=(200, 403),
        table=False,
    )
    await p.same("delete baseline", "DELETE", f"{G}/baselines/{BAS_A1}", t["admin"], before=seed_rows)
    await p.same("delete baseline, unknown", "DELETE", f"{G}/baselines/7844999", t["admin"], before=seed_rows)
    await p.same("delete baseline, analyst", "DELETE", f"{G}/baselines/{BAS_A1}", t["analyst"], before=seed_rows)
    await p.same("baselines, wrong method", "GET", f"{G}/baselines/{BAS_A1}", t["admin"], before=seed_rows)


AUDIT_MASK = ("audit_timestamp",)


async def audit_checks(p, t):
    print("\n== audits")
    run = f"{G}/config/{CFG_A}/audit"
    await p.same(
        "audit from a configuration",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={"routes": FULL_ORG},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same(
        "audit, the exclusions applied",
        "POST",
        run,
        t["analyst"],
        before=lambda: (
            seed_rows(),
            seed_exclusion(7844291, CFG_A, CUST_A, check_id="repo-branch-protection", resource_name="api"),
            seed_exclusion(7844292, CFG_A, CUST_A, check_id="org-member-repo-creation", enabled=0),
        ),
        gh={"routes": FULL_ORG},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same(
        "audit, a disabled configuration",
        "POST",
        f"{G}/config/{CFG_OFF}/audit",
        t["analyst"],
        before=seed_rows,
        gh={"routes": FULL_ORG},
    )
    await p.same("audit, unknown configuration", "POST", f"{G}/config/7844999/audit", t["admin"], before=seed_rows)
    await p.same(
        "audit, another tenant's configuration",
        "POST",
        f"{G}/config/{CFG_B}/audit",
        t["analyst"],
        before=seed_rows,
        gh={"routes": github(org_name="beta-org")},
        expect=(200, 403),
        table=False,
    )
    incl = github(org_name=ORG + "-incl", repos=[repo("web"), repo("api"), repo("docs")])
    await p.same(
        "audit, the include filter",
        "POST",
        f"{G}/config/{CFG_INCL}/audit",
        t["analyst"],
        before=seed_rows,
        gh={"routes": incl},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same(
        "audit, a stored filter the request model refuses",
        "POST",
        f"{G}/config/{CFG_INCL}/audit",
        t["admin"],
        before=lambda: (seed_rows(), sql("UPDATE github_audit_config SET repo_filter_list = '[1, \"web\"]' WHERE id = :i", i=CFG_INCL)),
        gh={"routes": incl},
    )
    many = github(repos=[repo(f"r{i:03}", archived=i % 7 != 0) for i in range(130)])
    await p.same(
        "audit, two pages and two batches",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={"routes": many},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same("audit, GitHub hangs up", "POST", run, t["analyst"], before=seed_rows, gh={"hangup": True}, mask=AUDIT_MASK)
    await p.same(
        "audit, the organization is not found",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={"routes": github(org=(404, {"message": "Not Found"}))},
        mask=AUDIT_MASK,
    )
    await p.same(
        "audit, rate limited everywhere",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={"routes": {k: RATE_LIMITED for k in FULL_ORG}},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    odd = github(
        repos=[repo("ok"), repo("weird", license="MIT", private=False)],
        per_repo={"ok": {"protection": (200, {"enforce_admins": None})}},
    )
    await p.same(
        "audit, an answer the checks choke on",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={"routes": odd},
        mask=AUDIT_MASK,
        outbound="skip",
    )
    await p.same(
        "audit, a member login that is a number",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={
            "routes": {
                **github(),
                f"/orgs/{ORG}/members?per_page=100&page=1": (200, [{"login": 7}]),
                f"/orgs/{ORG}/members?role=admin&per_page=100&page=1": (200, [{"login": 7.0}]),
            },
        },
        mask=AUDIT_MASK,
    )
    await p.same(
        "audit, HTML where JSON was expected",
        "POST",
        run,
        t["analyst"],
        before=seed_rows,
        gh={"routes": {**github(), f"/orgs/{ORG}": (200, "<html>")}},
        mask=AUDIT_MASK,
    )
    await p.same(
        "audit, a token httpx refuses",
        "POST",
        run,
        t["analyst"],
        before=lambda: (seed_rows(), sql("UPDATE github_audit_config SET github_token = 'tok ' WHERE id = :i", i=CFG_A)),
        gh={"routes": FULL_ORG},
        mask=AUDIT_MASK,
    )
    await p.same(
        "audit, an organization name with ? and #",
        "POST",
        run,
        t["analyst"],
        before=lambda: (seed_rows(), sql("UPDATE github_audit_config SET organization = 'a b?c#d' WHERE id = :i", i=CFG_A)),
        gh={"routes": {}},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same(
        "audit through an encoded /",
        "POST",
        f"{G}/config/{CFG_A}%2Faudit",
        t["analyst"],
        before=seed_rows,
        gh={"routes": FULL_ORG},
        mask=AUDIT_MASK,
        outbound="sorted",
    )

    summary = f"{G}/config/{CFG_A}/audit/summary"
    await p.same(
        "audit summary",
        "POST",
        summary,
        t["analyst"],
        before=seed_rows,
        gh={"routes": FULL_ORG},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same(
        "audit summary, include filter ignored",
        "POST",
        f"{G}/config/{CFG_INCL}/audit/summary",
        t["analyst"],
        before=seed_rows,
        gh={"routes": incl},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same("audit summary, disabled", "POST", f"{G}/config/{CFG_OFF}/audit/summary", t["admin"], before=seed_rows)
    await p.same(
        "audit summary, another tenant's",
        "POST",
        f"{G}/config/{CFG_B}/audit/summary",
        t["analyst"],
        before=seed_rows,
        gh={"routes": github(org_name="beta-org")},
        expect=(200, 403),
        table=False,
    )

    adhoc = f"{G}/audit"
    await p.same(
        "ad-hoc audit",
        "POST",
        f"{adhoc}?github_token=ghp_adhoc",
        t["analyst"],
        before=seed_rows,
        gh={"routes": FULL_ORG},
        json={"organization": ORG},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same(
        "ad-hoc audit, scoped",
        "POST",
        f"{adhoc}?github_token=ghp_adhoc",
        t["analyst"],
        before=seed_rows,
        gh={"routes": FULL_ORG},
        json={"organization": ORG, "include_repos": "yes", "include_members": False, "include_workflows": 0, "repo_filter": ["web", "api"]},
        mask=AUDIT_MASK,
        outbound="sorted",
    )
    await p.same("ad-hoc audit, no token", "POST", adhoc, t["analyst"], before=seed_rows, json={"organization": ORG})
    await p.same("ad-hoc audit, no token and no body", "POST", adhoc, t["analyst"], before=seed_rows)
    await p.same(
        "ad-hoc audit, invalid body",
        "POST",
        f"{adhoc}?github_token=x",
        t["analyst"],
        before=seed_rows,
        json={"organization": 5, "repo_filter": "web"},
    )
    await p.same("ad-hoc audit, portal user", "POST", f"{adhoc}?github_token=x", t["portal"], before=seed_rows, json={"organization": ORG})


N = "/api/nuclei"
NM = "/copilot-nuclei-module"


async def nuclei_checks(p, t):
    print("\n== nuclei")
    reports = {"reports": ["a.example", "b.example"], "success": True, "message": "Reports found", "extra": 1}
    await p.same("all reports", "GET", f"{N}/all_reports", t["analyst"], nuclei={f"GET {NM}/all_reports": (200, reports)}, table=False)
    await p.same("all reports, 404", "GET", f"{N}/all_reports", t["analyst"], nuclei={}, table=False)
    await p.same(
        "all reports, 500",
        "GET",
        f"{N}/all_reports",
        t["analyst"],
        nuclei={f"GET {NM}/all_reports": (500, {"detail": "boom"})},
        table=False,
    )
    await p.same("all reports, 302", "GET", f"{N}/all_reports", t["analyst"], nuclei={f"GET {NM}/all_reports": (302, {})}, table=False)
    await p.same(
        "all reports, not JSON",
        "GET",
        f"{N}/all_reports",
        t["analyst"],
        nuclei={f"GET {NM}/all_reports": (200, "<html>")},
        table=False,
    )
    await p.same("all reports, a list", "GET", f"{N}/all_reports", t["analyst"], nuclei={f"GET {NM}/all_reports": (200, [1])}, table=False)
    await p.same(
        "all reports, the model refuses it",
        "GET",
        f"{N}/all_reports",
        t["analyst"],
        nuclei={f"GET {NM}/all_reports": (200, {"reports": "x", "success": "maybe"})},
        table=False,
    )
    await p.same("all reports, no token", "GET", f"{N}/all_reports", nuclei={}, table=False)
    await p.same("all reports, portal user", "GET", f"{N}/all_reports", t["portal"], nuclei={}, table=False)
    page = {"markdown": "# a.example\n\n* finding", "success": True, "message": "ok"}
    await p.same(
        "one report",
        "GET",
        f"{N}/report/a.example/index.md",
        t["analyst"],
        nuclei={f"GET {NM}/report/a.example/index.md": (200, page)},
        table=False,
    )
    await p.same("one report, 404", "GET", f"{N}/report/a.example/x.md", t["analyst"], nuclei={}, table=False)
    await p.same(
        "one report, a host with a space and a query",
        "GET",
        f"{N}/report/a%20b%3Fc/index.md",
        t["analyst"],
        nuclei={},
        table=False,
    )
    await p.same(
        "one report, an encoded slash",
        "GET",
        f"{N}/report/https%3A%2F%2Fa.example/index.md",
        t["analyst"],
        nuclei={},
        table=False,
    )
    await p.same("one report, a dot-dot host", "GET", f"{N}/report/../x.md", t["analyst"], nuclei={}, table=False)
    await p.same(
        "scan",
        "POST",
        f"{N}/scan",
        t["analyst"],
        nuclei={f"POST {NM}/scan": (200, {"message": "Scan started", "success": True})},
        json={"host": "a.example"},
        table=False,
    )
    await p.same(
        "scan, the module refuses it",
        "POST",
        f"{N}/scan",
        t["analyst"],
        nuclei={f"POST {NM}/scan": (500, {"message": "busy", "success": False})},
        json={"host": "é.example"},
        table=False,
    )
    await p.same(
        "scan, not JSON",
        "POST",
        f"{N}/scan",
        t["analyst"],
        nuclei={f"POST {NM}/scan": (502, "bad gateway")},
        json={"host": "a"},
        table=False,
    )
    await p.same("scan, invalid body", "POST", f"{N}/scan", t["analyst"], nuclei={}, json={"host": 5}, table=False)
    await p.same(
        "scan, malformed JSON",
        "POST",
        f"{N}/scan",
        content=b"{",
        headers={"Content-Type": "application/json"},
        nuclei={},
        table=False,
    )
    await p.same(
        "delete report",
        "DELETE",
        f"{N}/delete_report/a.example",
        t["analyst"],
        nuclei={f"DELETE {NM}/report/a.example": (200, {"success": True, "message": "deleted"})},
        table=False,
    )
    await p.same("delete report, 404", "DELETE", f"{N}/delete_report/a.example", t["analyst"], nuclei={}, table=False)
    await p.same(
        "delete report, 500 with a valid body",
        "DELETE",
        f"{N}/delete_report/a.example",
        t["analyst"],
        nuclei={f"DELETE {NM}/report/a.example": (500, {"success": False, "message": "x"})},
        table=False,
    )
    await p.same("delete report, wrong method", "GET", f"{N}/delete_report/a.example", t["analyst"], nuclei={}, table=False)
    await p.same("unknown nuclei path", "GET", f"{N}/nope", t["analyst"], nuclei={}, table=False)


async def path_checks(p, t):
    print("\n== encoded paths")
    await p.same("exclusions through an encoded /", "GET", f"{G}/config/{CFG_A}%2Fexclusions", t["analyst"], before=seed_rows)
    await p.same(
        "another tenant's exclusions through an encoded /",
        "GET",
        f"{G}/config/{CFG_B}%2fexclusions",
        t["analyst"],
        before=seed_rows,
        expect=(200, 403),
    )
    await p.same("an encoded / that names no route", "GET", f"{G}/reports%2F{REP_A1}%2Fx", t["admin"], before=seed_rows)
    await p.same("an unknown path", "GET", f"{G}/nope", t["admin"], before=seed_rows)
    await p.same("a trailing slash", "GET", f"{G}/config/", t["admin"], before=seed_rows)


async def main():
    servers = [start_stub(GH_PORT, GH, GH_REC), start_stub(NUCLEI_PORT, NU, NU_REC)]
    proc = None
    try:
        seed()
        proc = start_rust(RS_PORT)
    except BaseException:
        if proc:
            proc.kill()
        cleanup()
        raise
    p = Pair()
    t = {
        "admin": token(ADMIN, ["admin"]),
        "analyst": token(ANALYST, ["analyst"]),
        "lonely": token(LONELY, ["analyst"]),
        "portal": token(PORTAL, ["customer_user"]),
    }
    try:
        sections = os.environ.get("GITHUB_AUDIT_PARITY_SECTIONS", "config,reports,exclusions,baselines,audits,nuclei,paths").split(",")
        if "config" in sections:
            await config_checks(p, t)
        if "reports" in sections:
            await report_checks(p, t)
        if "exclusions" in sections:
            await exclusion_checks(p, t)
        if "baselines" in sections:
            await baseline_checks(p, t)
        if "audits" in sections:
            await audit_checks(p, t)
        if "nuclei" in sections:
            await nuclei_checks(p, t)
        if "paths" in sections:
            await path_checks(p, t)
    finally:
        await p.py.aclose()
        await p.rs.aclose()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        cleanup()
        for server in servers:
            server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
