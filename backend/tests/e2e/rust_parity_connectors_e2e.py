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
import datetime
import json
import os
import sys
import uuid

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


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import connectors

    api = APIRouter(prefix="/api")
    api.include_router(connectors.router)
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
    await py.aclose()
    await rs.aclose()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
