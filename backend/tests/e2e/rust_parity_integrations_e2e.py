"""Parity of the Rust integrations core (`copilot-integrations`) with this backend — NOT collected
by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

The real FastAPI routers of `/api/integrations`, `/api/api/v1/alert_settings` and
`/api/network_connectors` (in-process) and a Rust instance answer the same requests on one
database. The Rust instance's legacy backend is the same routers served by uvicorn in a
subprocess, so what Rust hands over (the 405s) is answered by Python too; the delete of a deployed
AWS instance is Rust's own since AWS provisioning was ported (the two share the ossec.conf lock).
One local stand-in records every request either backend sends — every header, the body bytes —
as the Wazuh manager (`/wazuh`), Graylog (`/graylog`) and Grafana (`/grafana/api`).

For each request the suite compares the status, the body (byte for byte, or with created ids
masked, or — for a table model, whose key order Python takes from its process — key by key), the
requests sent to the tools (the token fetch aside: each process caches its own) and the rows the
request left (ids the seed did not give masked). Each side starts from the same seeded rows.
Deliberate differences are asserted as such (RUST_MIGRATION.md §4).

    PARITY_SUITES=tests/e2e/rust_parity_integrations_e2e.py scripts/rust-parity.sh

Ports: INTEGRATIONS_PARITY_RUST_PORT (5837), INTEGRATIONS_PARITY_PY_PORT (5838, the uvicorn
legacy backend), INTEGRATIONS_STUB_PORT (5839). Seeded ids are seven digits in 7530000-7539999.
"""

import asyncio
import copy
import datetime
import fnmatch
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")
os.environ["CONNECTOR_CACHE_TTL_SECONDS"] = "0"

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(BACKEND, ".."))
sys.path.insert(0, HERE)

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import bindparam  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = os.environ.get("INTEGRATIONS_PARITY_SFX") or uuid.uuid4().hex[:6]
RS_PORT = int(os.environ.get("INTEGRATIONS_PARITY_RUST_PORT", "5837"))
PY_PORT = int(os.environ.get("INTEGRATIONS_PARITY_PY_PORT", "5838"))
STUB_PORT = int(os.environ.get("INTEGRATIONS_STUB_PORT", "5839"))
SEED_LO, SEED_HI = 7_530_000, 7_539_999

CUST_A, CUST_B, CUST_C = f"IA{SFX}", f"IB{SFX}", f"IC{SFX}"
CUSTOMERS = (CUST_A, CUST_B, CUST_C)
NAME_A, NAME_B = f"Alpha {SFX}", f"Beta {SFX}"
ADMIN, ANALYST, ANALYST_B, UNASSIGNED = (f"int_admin{SFX}", f"int_analyst{SFX}", f"int_analyst_b{SFX}", f"int_unassigned{SFX}")
USERS = (ADMIN, ANALYST, ANALYST_B, UNASSIGNED)
TENANT_A, TENANT_B, TENANT_C = f"tenant-a-{SFX}", f"tenant-b-{SFX}", f"tenant-c-{SFX}"
ACCOUNT_1, ACCOUNT_2 = f"1111{SFX}", f"2222{SFX}"
OUR_CONNECTORS = ("Wazuh-Manager", "Graylog", "Grafana")
CATALOG = (
    (7530001, "Office365", ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")),
    (7530002, "AWS", ("AWS_ACCOUNT_ID", "BUCKET_NAME", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY")),
    (7530003, "Mimecast", ("API_KEY",)),
    (7530004, "Crowdstrike", ("CLIENT_ID",)),
    (7530005, "FORTINET", ("SYSLOG_PORT",)),
)
NETWORK_CATALOG = ((7530101, "Fortinet", ("SYSLOG_PORT", "PROTOCOL")), (7530102, "SonicWall", ("PORT",)))
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def sql(statement, **params):
    stmt = text(statement)
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    with sync_engine.begin() as conn:
        return conn.execute(stmt, params)


def rows(statement, **params):
    stmt = text(statement)
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            stmt = stmt.bindparams(bindparam(k, expanding=True))
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(stmt, params)]


# --- The stand-in -----------------------------------------------------------------------------------

CONFIG = f"""<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <email_from>wazuh&amp;co@example.com</email_from>
  </global>
  <!-- Microsoft 365 -->
  <office365>
    <enabled>yes</enabled>
    <only_future_events>yes</only_future_events>
    <api_auth>
      <tenant_id>{TENANT_A}</tenant_id>
      <client_id>c-a</client_id>
      <client_secret>s&lt;a&gt;</client_secret>
      <api_type>commercial</api_type>
    </api_auth>
    <api_auth>
      <tenant_id> {TENANT_B} </tenant_id>
      <client_id>c-b</client_id>
    </api_auth>
    <subscriptions>
      <subscription>Audit.SharePoint</subscription>
    </subscriptions>
  </office365>
  <office365>
    <api_auth>
      <tenant_id>{TENANT_C}</tenant_id>
    </api_auth>
  </office365>
  <wodle name="aws-s3" note='say "hi"'>
    <bucket type="cloudtrail"><name>bucket-2</name><empty/></bucket>
  </wodle>
</ossec_config>
"""
TWO_BLOCKS = CONFIG + "<ossec_config>\n  <localfile/>\n</ossec_config>\n"


class Stub:
    """The Wazuh manager, Graylog and Grafana on one port, by path prefix."""

    def __init__(self):
        self.lock = threading.Lock()
        self.captured = []
        self.reset()

    def reset(self, config=CONFIG, overrides=None):
        self.config = config
        # (method, glob on the path after the prefix) -> (status, content type, body)
        self.overrides = dict(overrides or {})

    def take(self):
        with self.lock:
            out, self.captured = self.captured, []
        return out

    def answer(self, method, path, body):
        for (m, pattern), reply in self.overrides.items():
            if m == method and fnmatch.fnmatchcase(path, pattern):
                return reply
        j = "application/json"
        if path.startswith("/wazuh/"):
            p = path[len("/wazuh") :]
            if p.startswith("/security/user/authenticate"):
                return 200, j, json.dumps({"data": {"token": "parity-token"}, "error": 0}).encode()
            if p.startswith("/manager/configuration") and method == "GET":
                return 200, "text/plain; charset=utf-8", self.config.encode()
            if p.startswith("/manager/configuration") and method == "PUT":
                return 200, j, json.dumps({"data": {"affected_items": ["manager"], "total_affected_items": 1}, "error": 0}).encode()
            if p.startswith("/manager/restart"):
                return 200, j, json.dumps({"data": {"affected_items": ["manager"]}, "message": "Restart requested", "error": 0}).encode()
            if p.startswith("/manager/configuration/validation"):
                return 200, j, json.dumps({"data": {"affected_items": [{"status": "OK"}], "total_failed_items": 0}, "error": 0}).encode()
            return 404, j, json.dumps({"title": "Not Found"}).encode()
        if path.startswith("/graylog/"):
            if method == "DELETE":
                return 204, None, b""
            return 200, j, json.dumps({"version": "6.1.4"}).encode()
        if path.startswith("/grafana/api/"):
            p = path[len("/grafana/api") :]
            if p.startswith("/user/using/"):
                return 200, j, json.dumps({"message": "Active organization changed"}).encode()
            if p == "/folders" and method == "GET":
                return (
                    200,
                    j,
                    json.dumps(
                        [
                            {"id": 70, "uid": "f70", "title": "Office365"},
                            {"id": 80, "uid": "f80", "title": "Office365 B"},
                            {"id": 30, "uid": "f30", "title": "Mimecast"},
                            {"id": 90, "uid": "f90", "title": "Fortinet"},
                        ],
                    ).encode(),
                )
            if p.startswith("/folders/") and method == "DELETE":
                return 200, j, json.dumps({"message": "Folder deleted", "id": 1}).encode()
            if p.startswith("/datasources/uid/") and method == "DELETE":
                return 200, j, json.dumps({"message": "Data source deleted"}).encode()
        return 404, j, json.dumps({"message": "no such stand-in route"}).encode()


STUB = Stub()


def start_stub():
    stub = STUB

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            # Every header the client sent, Content-Length included.
            headers = sorted((k.lower(), v) for k, v in self.headers.items())
            with stub.lock:
                stub.captured.append((self.command, self.path, headers, body))
            status, ctype, payload = stub.answer(self.command, self.path, body)
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

    server = Server(("127.0.0.1", STUB_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def outbound(requests):
    """What a backend sent, the token fetch left out (each process caches its own)."""
    return [r for r in requests if not r[1].startswith("/wazuh/security/user/authenticate")]


# --- Seed ------------------------------------------------------------------------------------------

SAVED_CONNECTORS = []


def set_connector(name, url, username, password):
    sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    sql(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_username, "
        "connector_password, connector_api_key, connector_description, connector_supports, connector_configured, "
        "connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, "
        "connector_accepts_file, connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (:n, '3', :u, "
        "UTC_TIMESTAMP(), :user, :pw, NULL, 'parity', 'parity', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        n=name,
        u=url,
        user=username,
        pw=password,
    )


def wipe():
    """Every row of the test customers in the module's tables, and the seed's id range."""
    codes = list(CUSTOMERS)
    cis = [r["id"] for r in rows("SELECT id FROM customer_integrations WHERE customer_code IN :c", c=codes)]
    cis += list(range(7_531_000, 7_531_100))
    subs = rows("SELECT id, integration_service_id FROM integration_subscriptions WHERE customer_id IN :c", c=cis)
    sub_ids = [r["id"] for r in subs] + list(range(7_531_300, 7_531_400))
    services = list({r["integration_service_id"] for r in subs if r["integration_service_id"]}) + list(range(7_531_100, 7_531_200))
    sql("DELETE FROM integration_auth_keys WHERE subscription_id IN :s OR id BETWEEN 7531400 AND 7531499", s=sub_ids)
    sql("DELETE FROM integration_subscriptions WHERE id IN :s", s=sub_ids)
    sql("DELETE FROM integration_configs WHERE integration_service_id IN :v OR id BETWEEN 7531200 AND 7531299", v=services)
    sql("DELETE FROM customer_integrations WHERE id IN :c", c=cis)
    sql("DELETE FROM integration_services WHERE id IN :v", v=services)
    sql("DELETE FROM customer_integrations_meta WHERE customer_code IN :c OR id BETWEEN 7531500 AND 7531599", c=codes)
    ncs = [r["id"] for r in rows("SELECT id FROM customer_network_connectors WHERE customer_code IN :c", c=codes)]
    ncs += list(range(7_532_000, 7_532_100))
    nsubs = rows("SELECT id, network_connectors_service_id FROM network_connectors_subscriptions WHERE customer_id IN :c", c=ncs)
    nsub_ids = [r["id"] for r in nsubs] + list(range(7_532_300, 7_532_400))
    nservices = list({r["network_connectors_service_id"] for r in nsubs}) + list(range(7_532_100, 7_532_200))
    sql("DELETE FROM network_connectors_keys WHERE subscription_id IN :s OR id BETWEEN 7532400 AND 7532499", s=nsub_ids)
    sql("DELETE FROM network_connectors_subscriptions WHERE id IN :s", s=nsub_ids)
    sql(
        "DELETE FROM network_connectors_configs WHERE network_connector_service_id IN :v OR id BETWEEN 7532200 AND 7532299",
        v=nservices,
    )
    sql("DELETE FROM customer_network_connectors WHERE id IN :c", c=ncs)
    sql("DELETE FROM network_connectors_services WHERE id IN :v", v=nservices)
    sql("DELETE FROM customer_network_connectors_meta WHERE customer_code IN :c OR id BETWEEN 7532500 AND 7532599", c=codes)
    settings = [r["id"] for r in rows("SELECT id FROM custom_alert_creation_settings WHERE customer_code IN :c", c=codes)]
    settings += list(range(7_533_000, 7_533_100))
    orders = [r["id"] for r in rows("SELECT id FROM custom_alert_creation_event_order WHERE alert_creation_settings_id IN :s", s=settings)]
    orders += list(range(7_533_100, 7_533_200))
    sql("DELETE FROM custom_alert_creation_event_config WHERE event_order_id IN :o OR id BETWEEN 7533200 AND 7533299", o=orders)
    sql("DELETE FROM custom_alert_creation_condition WHERE event_order_id IN :o OR id BETWEEN 7533300 AND 7533399", o=orders)
    sql("DELETE FROM custom_alert_creation_event_order WHERE id IN :o", o=orders)
    sql("DELETE FROM custom_alert_creation_settings WHERE id IN :s", s=settings)


SAVED_CATALOG = []


def save_rows(table, column, ids):
    for row in rows(f"SELECT * FROM {table} WHERE {column} IN :i AND NOT ({column} BETWEEN :lo AND :hi)", i=ids, lo=SEED_LO, hi=SEED_HI):
        SAVED_CATALOG.append((table, row))


def seed_catalog():
    names = [c[1] for c in CATALOG]
    ids = [
        r["id"]
        for r in rows("SELECT id FROM available_integrations WHERE integration_name IN :n OR id BETWEEN 7530000 AND 7530099", n=names)
    ]
    if ids:
        # A catalog the deployment seeded keeps its rows: put back by `seed_catalog_cleanup`.
        save_rows("available_integrations", "id", ids)
        save_rows("available_integrations_auth_keys", "integration_id", ids)
        sql("DELETE FROM available_integrations_auth_keys WHERE integration_id IN :i", i=ids)
        sql("DELETE FROM available_integrations WHERE id IN :i", i=ids)
    names = [c[1] for c in NETWORK_CATALOG]
    ids = [
        r["id"]
        for r in rows(
            "SELECT id FROM available_network_connectors WHERE network_connector_name IN :n OR id BETWEEN 7530100 AND 7530199",
            n=names,
        )
    ]
    if ids:
        save_rows("available_network_connectors", "id", ids)
        save_rows("available_network_connectors_keys", "network_connector_id", ids)
        sql("DELETE FROM available_network_connectors_keys WHERE network_connector_id IN :i", i=ids)
        sql("DELETE FROM available_network_connectors WHERE id IN :i", i=ids)


def reset_catalog():
    """The seeded catalog, as a request starts from it (a PUT changes it)."""
    sql("DELETE FROM available_integrations_auth_keys WHERE integration_id BETWEEN 7530000 AND 7530099")
    sql("DELETE FROM available_integrations WHERE id BETWEEN 7530000 AND 7530099")
    sql("DELETE FROM available_network_connectors_keys WHERE network_connector_id BETWEEN 7530100 AND 7530199")
    sql("DELETE FROM available_network_connectors WHERE id BETWEEN 7530100 AND 7530199")
    for i, (cid, name, keys) in enumerate(CATALOG):
        sql(
            "INSERT INTO available_integrations (id, integration_name, description, integration_details) VALUES (:i, :n, :d, :x)",
            i=cid,
            n=name,
            d=f"{name} integration",
            x=f"Details of {name}",
        )
        for j, key in enumerate(keys):
            sql(
                "INSERT INTO available_integrations_auth_keys (id, integration_id, integration_name, auth_key_name) VALUES (:i, :c, :n, :k)",
                i=7_530_010 + 10 * i + j,
                c=cid,
                n=name,
                k=key,
            )
    for i, (cid, name, keys) in enumerate(NETWORK_CATALOG):
        sql(
            "INSERT INTO available_network_connectors (id, network_connector_name, description, network_connector_details) "
            "VALUES (:i, :n, :d, :x)",
            i=cid,
            n=name,
            d=f"{name} connector",
            x=f"Details of {name}",
        )
        for j, key in enumerate(keys):
            sql(
                "INSERT INTO available_network_connectors_keys (id, network_connector_id, network_connector_name, auth_key_name) "
                "VALUES (:i, :c, :n, :k)",
                i=7_530_110 + 10 * i + j,
                c=cid,
                n=name,
                k=key,
            )


# (ci id, customer, catalog id, name, instance, deployed, [(key, value), ...])
INTEGRATIONS = (
    (7531001, CUST_A, 7530001, "Office365", None, 0, (("TENANT_ID", TENANT_A), ("CLIENT_ID", "c-a"), ("CLIENT_SECRET", "s-a"))),
    (7531002, CUST_A, 7530001, "Office365", "tenant-b", 1, (("TENANT_ID", TENANT_B), ("CLIENT_ID", "c-b"), ("CLIENT_SECRET", "s-b"))),
    (
        7531003,
        CUST_A,
        7530002,
        "AWS",
        "acct-1",
        0,
        (("AWS_ACCOUNT_ID", ACCOUNT_1), ("BUCKET_NAME", "bucket-1"), ("ACCESS_KEY_ID", "AKIA1"), ("SECRET_ACCESS_KEY", "secret-1")),
    ),
    (7531004, CUST_A, 7530003, "Mimecast", None, 1, (("API_KEY", "mk"),)),
    (
        7531005,
        CUST_A,
        7530002,
        "AWS",
        "acct-2",
        1,
        (("AWS_ACCOUNT_ID", ACCOUNT_2), ("BUCKET_NAME", "bucket-2"), ("ACCESS_KEY_ID", "AKIA2"), ("SECRET_ACCESS_KEY", "secret-2")),
    ),
    (7531006, CUST_A, 7530005, "FORTINET", None, 1, (("SYSLOG_PORT", "514"),)),
    (7531011, CUST_B, 7530001, "Office365", None, 1, (("TENANT_ID", TENANT_C), ("CLIENT_ID", "c-c"))),
    (7531012, CUST_B, 7530004, "Crowdstrike", None, 0, (("CLIENT_ID", "cs"),)),
)
# (id, customer, name, instance, input, index, stream, org, folder, datasource)
METAS = (
    (7531501, CUST_A, "Office365", "tenant-b", None, "is-o365", "st-b", "7", "70", "ds-o365"),
    (7531502, CUST_A, "Mimecast", None, "in-m", "is-m", "st-m", "3", "f30", None),
    (7531503, CUST_A, "AWS", "acct-2", None, "cloudtrail:is-aws", "cloudtrail:st-aws", "4", "40", "cloudtrail:ds-aws"),
    (7531511, CUST_B, "Office365", None, None, "is-c", "st-c", "8", "80", "ds-c"),
)


def seed_rows(extra=None):
    """The seed every request starts from; `extra(…)` adjusts it."""
    wipe()
    reset_catalog()
    for code, name, o365 in ((CUST_A, NAME_A, None), (CUST_B, NAME_B, TENANT_C)):
        sql("DELETE FROM customersmeta WHERE customer_code = :c", c=code)
        sql(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, customer_meta_graylog_stream, "
            "customer_meta_grafana_org_id, customer_meta_wazuh_group, customer_meta_office365_organization_id) VALUES "
            "(:c, :n, 'i', 's', '1', 'g', :o)",
            c=code,
            n=name,
            o=o365,
        )
    sub_id, key_id = 7_531_300, 7_531_400
    for n, (ci, code, catalog, name, instance, deployed, keys) in enumerate(INTEGRATIONS):
        svc = 7_531_100 + n
        sql("INSERT INTO integration_services (id, service_name, auth_type) VALUES (:i, :n, 'OAuth')", i=svc, n=name)
        sql(
            "INSERT INTO integration_configs (id, integration_service_id, config_key, config_value) VALUES (:i, :s, 'endpoint', :v)",
            i=7_531_200 + n,
            s=svc,
            v=f"https://{name.lower()}.example",
        )
        sql(
            "INSERT INTO customer_integrations (id, customer_code, customer_name, integration_service_id, integration_service_name, "
            "instance_name, deployed) VALUES (:i, :c, :cn, :s, :n, :inst, :d)",
            i=ci,
            c=code,
            cn=NAME_A if code == CUST_A else NAME_B,
            s=catalog,
            n=name,
            inst=instance,
            d=deployed,
        )
        for key, value in keys:
            sql(
                "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES (:i, :c, :s)",
                i=sub_id,
                c=ci,
                s=svc,
            )
            sql(
                "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, :s, :k, :v)",
                i=key_id,
                s=sub_id,
                k=key,
                v=value,
            )
            sub_id += 1
            key_id += 1
    for mid, code, name, instance, input_id, index, stream, org, folder, ds in METAS:
        sql(
            "INSERT INTO customer_integrations_meta (id, customer_code, integration_name, instance_name, graylog_input_id, graylog_index_id, "
            "graylog_stream_id, grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid) VALUES (:i, :c, :n, :inst, :gi, :ix, "
            ":st, :o, :f, :ds)",
            i=mid,
            c=code,
            n=name,
            inst=instance,
            gi=input_id,
            ix=index,
            st=stream,
            o=org,
            f=folder,
            ds=ds,
        )
    # A network integration's metadata (FORTINET, through /integrations) and two network connectors.
    for mid, code, name, folder in ((7532501, CUST_A, "FORTINET", "f90"), (7532502, CUST_A, "Fortinet", "90")):
        sql(
            "INSERT INTO customer_network_connectors_meta (id, customer_code, network_connector_name, graylog_input_id, graylog_index_id, "
            "graylog_stream_id, graylog_pipeline_id, graylog_content_pack_input_id, graylog_content_pack_stream_id, grafana_org_id, "
            "grafana_dashboard_folder_id, grafana_datasource_uid) VALUES (:i, :c, :n, NULL, 'is-f', 'st-f', 'p', 'cpi', 'cps', '9', :f, "
            "'ds-f')",
            i=mid,
            c=code,
            n=name,
            f=folder,
        )
    nsub, nkey = 7_532_300, 7_532_400
    for n, (cid, code, catalog, name, deployed, keys) in enumerate(
        (
            (7532001, CUST_A, 7530101, "Fortinet", 1, (("SYSLOG_PORT", "514"), ("PROTOCOL", "tcp"))),
            (7532002, CUST_B, 7530102, "SonicWall", 0, (("PORT", "443"),)),
        ),
    ):
        svc = 7_532_100 + n
        sql("INSERT INTO network_connectors_services (id, service_name, auth_type) VALUES (:i, :n, 'syslog')", i=svc, n=name)
        sql(
            "INSERT INTO network_connectors_configs (id, network_connector_service_id, config_key, config_value) VALUES (:i, :s, 'k', 'v')",
            i=7_532_200 + n,
            s=svc,
        )
        sql(
            "INSERT INTO customer_network_connectors (id, customer_code, customer_name, network_connector_service_id, "
            "network_connector_service_name, deployed) VALUES (:i, :c, :cn, :s, :n, :d)",
            i=cid,
            c=code,
            cn=NAME_A if code == CUST_A else NAME_B,
            s=catalog,
            n=name,
            d=deployed,
        )
        for key, value in keys:
            sql(
                "INSERT INTO network_connectors_subscriptions (id, customer_id, network_connectors_service_id) VALUES (:i, :c, :s)",
                i=nsub,
                c=cid,
                s=svc,
            )
            sql(
                "INSERT INTO network_connectors_keys (id, subscription_id, auth_key_name, auth_value) VALUES (:i, :s, :k, :v)",
                i=nkey,
                s=nsub,
                k=key,
                v=value,
            )
            nsub += 1
            nkey += 1
    for sid, code, name, o365 in ((7533001, CUST_A, NAME_A, None), (7533002, CUST_B, NAME_B, TENANT_C)):
        sql(
            "INSERT INTO custom_alert_creation_settings (id, customer_code, customer_name, excluded_wazuh_rules, office365_organization_id, "
            "iris_customer_id, timefield, nvd_url) VALUES (:i, :c, :n, '1,2', :o, 5, 'timestamp_utc', 'https://nvd.example')",
            i=sid,
            c=code,
            n=name,
            o=o365,
        )
    sql("INSERT INTO custom_alert_creation_event_order (id, alert_creation_settings_id, order_label) VALUES (7533101, 7533001, 'L1')")
    sql("INSERT INTO custom_alert_creation_event_order (id, alert_creation_settings_id, order_label) VALUES (7533102, 7533001, 'L2')")
    sql("INSERT INTO custom_alert_creation_event_order (id, alert_creation_settings_id, order_label) VALUES (7533103, 7533002, 'B1')")
    for cid, order, event in ((7533201, 7533101, "e1"), (7533202, 7533101, "e2"), (7533203, 7533103, "b1")):
        sql(
            "INSERT INTO custom_alert_creation_event_config (id, event_order_id, event_id, field, value) VALUES (:i, :o, :e, 'f', 'v')",
            i=cid,
            o=order,
            e=event,
        )
    sql("INSERT INTO custom_alert_creation_condition (id, event_order_id, field_name, field_value) VALUES (7533301, 7533101, 'a', 'b')")
    if extra:
        extra()
    # Ids MySQL hands out after a wipe keep counting (InnoDB never lowers its counter), so a row
    # either side creates is told apart from the seed by not being in it.
    # The wipe and the reinserts queue InnoDB's background statistics recalculation; computed
    # while a table was empty, it can change a join's plan (and so the row order the ORM keeps)
    # between the Python call and the Rust one. Recomputed here, the statistics are the full seed's.
    sql("ANALYZE TABLE " + ", ".join(ANALYZED))
    SEEDED.clear()
    for section, rs in raw_state().items():
        for r in rs:
            for column, v in r.items():
                SEEDED.setdefault((section, column), set()).add(v)


def seed():
    with sync_engine.connect() as conn:
        found = conn.execute(
            text("SELECT * FROM connectors WHERE connector_name IN :names").bindparams(bindparam("names", expanding=True)),
            {"names": list(OUR_CONNECTORS)},
        )
        SAVED_CONNECTORS.extend(dict(r._mapping) for r in found)
    set_connector("Wazuh-Manager", f"http://127.0.0.1:{STUB_PORT}/wazuh", "wazuh-wui", "wazuh-pass")
    set_connector("Graylog", f"http://127.0.0.1:{STUB_PORT}/graylog", "admin", "gl-pass")
    # grafana_client appends "api" to the URL's path as it is: the trailing slash makes it /grafana/api.
    set_connector("Grafana", f"http://127.0.0.1:{STUB_PORT}/grafana/", "admin", "gf-pass")
    for code, name in ((CUST_A, NAME_A), (CUST_B, NAME_B), (CUST_C, f"Gamma {SFX}")):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())", c=code, n=name)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (ANALYST_B, 2), (UNASSIGNED, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'i@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for name, code in ((ANALYST, CUST_A), (ANALYST_B, CUST_B)):
        sql(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
            c=code,
            n=name,
        )
    seed_catalog()
    seed_rows()


def cleanup():
    wipe()
    for name in USERS:
        sql("DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username = :n)", n=name)
        sql("DELETE FROM `user` WHERE username = :n", n=name)
    sql("DELETE FROM customersmeta WHERE customer_code IN :c", c=list(CUSTOMERS))
    sql("DELETE FROM customers WHERE customer_code IN :c", c=list(CUSTOMERS))
    for name in OUR_CONNECTORS:
        sql("DELETE FROM connectors WHERE connector_name = :n", n=name)
    for row in SAVED_CONNECTORS:
        cols = ", ".join(row)
        sql(f"INSERT INTO connectors ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)
    # Python keeps a copy of the configuration it pushed next to its module.
    copy_path = os.path.join(BACKEND, "app", "integrations", "office365", "wazuh_decommission_config.xml")
    if os.path.exists(copy_path):
        os.remove(copy_path)


SEEDED = {}
ANALYZED = (
    "customers",
    "customersmeta",
    "available_integrations",
    "available_integrations_auth_keys",
    "customer_integrations",
    "integration_subscriptions",
    "integration_services",
    "integration_configs",
    "integration_auth_keys",
    "customer_integrations_meta",
    "available_network_connectors",
    "available_network_connectors_keys",
    "customer_network_connectors",
    "network_connectors_subscriptions",
    "network_connectors_services",
    "network_connectors_configs",
    "network_connectors_keys",
    "customer_network_connectors_meta",
    "custom_alert_creation_settings",
    "custom_alert_creation_event_order",
    "custom_alert_creation_event_config",
    "custom_alert_creation_condition",
)


def masked_id(section, column, v):
    if isinstance(v, int) and not isinstance(v, bool) and v not in SEEDED.get((section, column), ()) and v > 1000:
        return "<new>"
    return v


def state():
    """The rows of the test customers, created ids masked."""
    return {k: [{c: masked_id(k, c, v) for c, v in r.items()} for r in rs] for k, rs in raw_state().items()}


def raw_state():
    codes = list(CUSTOMERS)
    out = {
        "integrations": rows(
            "SELECT ci.id, ci.customer_code, ci.customer_name, ci.integration_service_id, ci.integration_service_name, ci.instance_name, "
            "ci.deployed, s.id AS sub, s.integration_service_id AS svc, v.service_name, v.auth_type, k.id AS key_id, k.auth_key_name, "
            "k.auth_value FROM customer_integrations ci LEFT JOIN integration_subscriptions s ON s.customer_id = ci.id LEFT JOIN "
            "integration_services v ON v.id = s.integration_service_id LEFT JOIN integration_auth_keys k ON k.subscription_id = s.id "
            "WHERE ci.customer_code IN :c ORDER BY ci.id, s.id, k.id",
            c=codes,
        ),
        "configs": rows(
            "SELECT c.id, c.integration_service_id, c.config_key, c.config_value FROM integration_configs c WHERE c.integration_service_id "
            "IN (SELECT s.integration_service_id FROM integration_subscriptions s JOIN customer_integrations ci ON ci.id = s.customer_id "
            "WHERE ci.customer_code IN :c) ORDER BY c.id",
            c=codes,
        ),
        "meta": rows("SELECT * FROM customer_integrations_meta WHERE customer_code IN :c ORDER BY id", c=codes),
        "network_meta": rows("SELECT * FROM customer_network_connectors_meta WHERE customer_code IN :c ORDER BY id", c=codes),
        "network": rows(
            "SELECT n.*, s.id AS sub, s.network_connectors_service_id AS svc, k.id AS key_id, k.auth_key_name, k.auth_value FROM "
            "customer_network_connectors n LEFT JOIN network_connectors_subscriptions s ON s.customer_id = n.id LEFT JOIN "
            "network_connectors_keys k ON k.subscription_id = s.id WHERE n.customer_code IN :c ORDER BY n.id, s.id, k.id",
            c=codes,
        ),
        "settings": rows("SELECT * FROM custom_alert_creation_settings WHERE customer_code IN :c ORDER BY id", c=codes),
        "orders": rows(
            "SELECT o.id, o.alert_creation_settings_id, o.order_label, c.id AS config, c.event_id, c.field, c.value FROM "
            "custom_alert_creation_event_order o JOIN custom_alert_creation_settings s ON s.id = o.alert_creation_settings_id LEFT JOIN "
            "custom_alert_creation_event_config c ON c.event_order_id = o.id WHERE s.customer_code IN :c ORDER BY o.id, c.id",
            c=codes,
        ),
        "conditions": rows(
            "SELECT id, event_order_id, field_name FROM custom_alert_creation_condition WHERE id BETWEEN 7533300 AND 7533399",
        ),
        "customersmeta": rows(
            "SELECT customer_code, customer_meta_office365_organization_id FROM customersmeta WHERE customer_code IN :c ORDER BY customer_code",
            c=codes,
        ),
        "catalog": rows(
            "SELECT id, integration_name, description, integration_details FROM available_integrations WHERE id BETWEEN 7530000 AND 7530099 "
            "ORDER BY id",
        ),
        "network_catalog": rows(
            "SELECT id, network_connector_name, description, network_connector_details FROM available_network_connectors WHERE id BETWEEN "
            "7530100 AND 7530199 ORDER BY id",
        ),
    }
    return out


# --- The backends ------------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import alert_creation_settings
    from app.routers import integrations
    from app.routers import network_connectors

    api = APIRouter(prefix="/api")
    api.include_router(integrations.router)
    api.include_router(alert_creation_settings.router)
    api.include_router(network_connectors.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def wait_port(port, proc):
    for _ in range(150):
        if proc.poll() is not None:
            raise RuntimeError(f"the process for port {port} exited")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"nothing listens on {port}")


def start_python_legacy():
    code = (
        "import sys; sys.path.insert(0, %r); import rust_parity_integrations_e2e as m; import uvicorn; "
        "uvicorn.run(m.build_python_app(), host='127.0.0.1', port=%d, log_level='warning')" % (HERE, PY_PORT)
    )
    env = {**os.environ, "PYTHONPATH": BACKEND}
    proc = subprocess.Popen([sys.executable, "-c", code], env=env, cwd=BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(PY_PORT, proc)
    return proc


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
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}",
        "CONNECTOR_CACHE_TTL_SECONDS": "0",
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


def sorted_keys(value):
    if isinstance(value, dict):
        return {k: sorted_keys(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [sorted_keys(v) for v in value]
    return value


def mask_ids(value, keys):
    if isinstance(value, dict):
        return {k: ("<id>" if k in keys and v is not None else mask_ids(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_ids(v, keys) for v in value]
    return value


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = dict(kw.pop("headers", {}))
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        STUB.take()
        r = await client.request(method, path, headers=headers, **kw)
        await asyncio.sleep(0)
        return r, outbound(STUB.take())

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        seed=True,
        before=None,
        stub=None,
        masked=(),
        unordered=False,
        py_view=None,
        expect=None,
        py_state=None,
        **kw,
    ):
        """Python, then Rust, each from the same rows (`seed`, then `before()`) and the same
        stand-in (`stub`: `(config, overrides)`). `py_view` turns Python's JSON into what Rust
        answers by design; `expect=(python, rust)` statuses of a deliberate difference."""
        sides = []
        for client in (self.py, self.rs):
            if seed:
                seed_rows(before)
            elif before:
                before()
            STUB.reset(*(stub or ()))
            r, out = await self.call(client, method, path, tok, **kw)
            left = state()
            if py_state and client is self.py:
                left = py_state(left)
            sides.append((r, out, left))
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
            raw = r.content
            try:
                value = json.loads(raw)
            except ValueError:
                return raw
            if view:
                value = view(value)
            if masked:
                value = mask_ids(value, set(masked))
            if unordered:
                value = sorted_keys(value)
            return json.dumps(value).encode() if (py_view or masked or unordered) else raw

        b1, b2 = norm(r1, py_view), norm(r2)
        ok = r1.status_code == r2.status_code and b1 == b2
        at = next((i for i, (x, y) in enumerate(zip(b1, b2)) if x != y), min(len(b1), len(b2)))
        start = max(0, at - 300)
        detail = (
            f"bodies differ at byte {at}\n        python {r1.status_code} {b1[start : at + 600]!r}\n"
            f"        rust   {r2.status_code} {b2[start : at + 600]!r}"
        )
        if o1 != o2:
            ok = False
            detail += f"\n        outbound python {o1}\n        outbound rust   {o2}"
        if s1 != s2:
            ok = False
            diff = {k: (s1[k], s2[k]) for k in s1 if s1[k] != s2[k]}
            detail += f"\n        state differs: {diff}"
        check(f"{name} [{r1.status_code}]" + (" [diff by design: state]" if py_state else ""), ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {b1[:800]!r}\n        outbound {[(m, p, b[:300]) for m, p, h, b in o1]}")
        return r1, r2

    async def close(self):
        for c in (self.py, self.rs):
            await c.aclose()


def visible_only(codes, key="customer_code"):
    """Python's listing narrowed to `codes` (what Rust answers a scoped caller)."""

    def view(body):
        body = copy.deepcopy(body)
        for field in (
            "available_integrations",
            "customer_integrations_meta",
            "available_network_connectors",
            "customer_network_connectors_meta",
        ):
            if isinstance(body.get(field), list):
                body[field] = [item for item in body[field] if item.get(key) in codes]
        return body

    return view


# --- The checks ----------------------------------------------------------------------------------------

INT = "/api/integrations"
A = "/api/api/v1/alert_settings"
N = "/api/network_connectors"


async def catalog_checks(p, t_admin, t_analyst):
    await p.same("catalog: no token", "GET", f"{INT}/available_integrations")
    await p.same("catalog: list", "GET", f"{INT}/available_integrations", t_admin)
    await p.same("catalog: one", "GET", f"{INT}/available_integrations/7530001", t_analyst)
    await p.same("catalog: one, padded", "GET", f"{INT}/available_integrations/007530002", t_admin)
    await p.same("catalog: missing", "GET", f"{INT}/available_integrations/7530099", t_admin)
    await p.same("catalog: not an int", "GET", f"{INT}/available_integrations/abc", t_admin)
    await p.same("catalog: not an int, no token", "GET", f"{INT}/available_integrations/abc")
    put = f"{INT}/available_integrations"
    await p.same("catalog put: empty list", "PUT", put, t_admin, json=[])
    await p.same(
        "catalog put: two rows (committed, then the response model's 400)",
        "PUT",
        put,
        t_admin,
        json=[
            {"integration_details": "new details", "integration_name": "Mimecast", "description": "new"},
            {"id": 3, "description": 5, "integration_name": "Crowdstrike", "integration_details": "x" * 80, "bogus": [1]},
        ],
    )
    await p.same(
        "catalog put: unknown name",
        "PUT",
        put,
        t_admin,
        json=[{"integration_name": "Mimecast", "description": "a", "integration_details": "b"}, {"integration_name": "Nope"}],
    )
    await p.same("catalog put: no name", "PUT", put, t_admin, json=[{"description": "d"}])
    await p.same(
        "catalog put: a missing column (NOT NULL)",
        "PUT",
        put,
        t_admin,
        json=[{"integration_name": "Mimecast", "description": "d"}],
    )
    await p.same(
        "catalog put: a numeric name",
        "PUT",
        put,
        t_admin,
        json=[{"integration_name": 7530003, "description": "d", "integration_details": "x"}],
    )
    await p.same("catalog put: not a list", "PUT", put, t_admin, json={"integration_name": "Mimecast"})
    await p.same("catalog put: items not objects", "PUT", put, t_admin, json=[1, None, "x"])
    await p.same("catalog put: no body", "PUT", put, t_admin)
    await p.same("catalog put: raw bytes", "PUT", put, t_admin, content=b"[]")
    await p.same("catalog put: malformed JSON, no token", "PUT", put, content=b"[", headers={"Content-Type": "application/json"})
    await p.same(
        "catalog put: the relationship as []",
        "PUT",
        put,
        t_admin,
        json=[{"integration_name": "Mimecast", "description": "d", "integration_details": "x", "auth_keys": []}],
    )


async def customer_integration_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    await p.same(
        "customer integrations: all, admin",
        "GET",
        f"{INT}/customer_integrations",
        t_admin,
        py_view=visible_only(None) if False else None,
    )
    await p.same(
        "customer integrations: all, analyst of A (narrowed)",
        "GET",
        f"{INT}/customer_integrations",
        t_analyst,
        py_view=visible_only({CUST_A}),
    )
    await p.same(
        "customer integrations: all, unassigned analyst (narrowed)",
        "GET",
        f"{INT}/customer_integrations",
        t_unassigned,
        py_view=visible_only(set()),
    )
    await p.same("customer integrations: A, analyst of A", "GET", f"{INT}/customer_integrations/{CUST_A}", t_analyst)
    await p.same("customer integrations: B, analyst of A", "GET", f"{INT}/customer_integrations/{CUST_B}", t_analyst)
    await p.same("customer integrations: unknown, admin", "GET", f"{INT}/customer_integrations/NOPE{SFX}", t_admin)
    await p.same("metas: all, admin", "GET", f"{INT}/customer_integrations_meta", t_admin)
    await p.same(
        "metas: all, analyst of B (narrowed)",
        "GET",
        f"{INT}/customer_integrations_meta",
        t_analyst_b,
        py_view=visible_only({CUST_B}),
    )
    await p.same("metas: A", "GET", f"{INT}/customer_integrations_meta/{CUST_A}", t_analyst)
    await p.same("metas: B, analyst of A", "GET", f"{INT}/customer_integrations_meta/{CUST_B}", t_analyst)


async def create_checks(p, t_admin, t_analyst):
    url = f"{INT}/create_integration"

    def body(name="Mimecast", code=CUST_A, keys=(("API_KEY", "k"),), **extra):
        return {
            "customer_code": code,
            "customer_name": "Alpha",
            "integration_name": name,
            "integration_config": {"auth_type": "API Key", "config_key": "endpoint", "config_value": "https://x"},
            "integration_auth_keys": [{"auth_key_name": k, "auth_value": v} for k, v in keys],
            **extra,
        }

    o365 = (("TENANT_ID", f"t-new-{SFX}"), ("CLIENT_ID", "c"), ("CLIENT_SECRET", "s"))
    aws = (("AWS_ACCOUNT_ID", f" {ACCOUNT_1} "), ("BUCKET_NAME", "b"), ("ACCESS_KEY_ID", "a"), ("SECRET_ACCESS_KEY", "s"))
    await p.same("create: no token", "POST", url, json=body())
    await p.same("create: malformed JSON", "POST", url, t_admin, content=b"{", headers={"Content-Type": "application/json"})
    await p.same("create: not an object", "POST", url, t_admin, json=[1])
    await p.same(
        "create: fields missing and mistyped",
        "POST",
        url,
        t_admin,
        json={"customer_code": 1, "integration_config": "x", "integration_auth_keys": [{}]},
    )
    await p.same("create: unknown integration", "POST", url, t_admin, json=body(name="Nope"))
    await p.same("create: a catalog key missing", "POST", url, t_admin, json=body(name="Office365", keys=(("CLIENT_ID", "c"),)))
    await p.same("create: unknown customer", "POST", url, t_admin, json=body(code=f"NOPE{SFX}"))
    await p.same("create: customer without meta", "POST", url, t_admin, json=body(code=CUST_C))
    await p.same(
        "create: an instance on a single-instance integration",
        "POST",
        url,
        t_admin,
        json=body(name="Crowdstrike", keys=(("CLIENT_ID", "c"),), code=CUST_B, instance_name="x"),
    )
    await p.same("create: a second single-instance row", "POST", url, t_admin, json=body())
    await p.same("create: a second unnamed Office365 tenant", "POST", url, t_admin, json=body(name="Office365", keys=o365))
    await p.same(
        "create: a blank instance is the unnamed one",
        "POST",
        url,
        t_admin,
        json=body(name="Office365", keys=o365, instance_name="   "),
    )
    await p.same(
        "create: a named instance that exists",
        "POST",
        url,
        t_admin,
        json=body(name="Office365", keys=o365, instance_name="tenant-b"),
    )
    await p.same(
        "create: a named Office365 tenant (claims the empty alert-settings column)",
        "POST",
        url,
        t_admin,
        json=body(name="Office365", keys=o365, instance_name=" tenant-new "),
    )
    await p.same(
        "create: B's first unnamed Office365 tenant? (B has one) — named one",
        "POST",
        url,
        t_admin,
        json=body(name="Office365", code=CUST_B, keys=o365, instance_name="second"),
    )
    await p.same(
        "create: an AWS account another customer owns",
        "POST",
        url,
        t_admin,
        json=body(name="AWS", code=CUST_B, keys=aws, instance_name="x"),
    )
    await p.same("create: an AWS account the customer owns", "POST", url, t_admin, json=body(name="AWS", keys=aws, instance_name="acct-3"))
    await p.same("create: Mimecast for B", "POST", url, t_admin, json=body(code=CUST_B, keys=(("API_KEY", "k"), ("EXTRA", "e"))))
    await p.same(
        "create: a value too long (a later key's commit fails)",
        "POST",
        url,
        t_admin,
        json=body(code=CUST_B, keys=(("API_KEY", "k"), ("X", "v" * 2000))),
    )
    await p.same(
        "create: an auth type too long",
        "POST",
        url,
        t_admin,
        json={**body(code=CUST_B), "integration_config": {"auth_type": "a" * 60, "config_key": "k", "config_value": "v"}},
    )
    await p.same(
        "create: analyst of A, for A",
        "POST",
        url,
        t_analyst,
        json=body(code=CUST_A, name="Crowdstrike", keys=(("CLIENT_ID", "c"),)),
    )
    await p.same(
        "create: analyst of A, for B's existing integration (Python's 400 names it)",
        "POST",
        url,
        t_analyst,
        json=body(code=CUST_B, name="Crowdstrike", keys=(("CLIENT_ID", "c"),)),
        expect=(400, 403),
    )
    await p.same(
        "create: analyst of A, for B's new integration",
        "POST",
        url,
        t_analyst,
        json=body(code=CUST_B, name="Mimecast"),
        expect=(200, 403),
    )

    meta = f"{INT}/create_integration_meta"
    mbody = {
        "customer_code": CUST_A,
        "integration_name": "Crowdstrike",
        "graylog_index_id": 5,
        "graylog_stream_id": "s",
        "grafana_org_id": "1",
        "grafana_dashboard_folder_id": 9,
    }
    await p.same("create meta: created (ints become text)", "POST", meta, t_admin, json=mbody)
    await p.same("create meta: exists", "POST", meta, t_admin, json={**mbody, "integration_name": "Mimecast"})
    await p.same(
        "create meta: named instance next to the unnamed one",
        "POST",
        meta,
        t_admin,
        json={**mbody, "integration_name": "Mimecast", "instance_name": "two"},
    )
    await p.same(
        "create meta: blank instance is the unnamed one",
        "POST",
        meta,
        t_admin,
        json={**mbody, "integration_name": "Mimecast", "instance_name": " "},
    )
    await p.same("create meta: a taken id (success: false)", "POST", meta, t_admin, json={**mbody, "id": 7531501})
    await p.same("create meta: invalid", "POST", meta, t_admin, json={"customer_code": CUST_A, "graylog_index_id": True})
    await p.same("create meta: no customer meta", "POST", meta, t_admin, json={**mbody, "customer_code": CUST_C})
    await p.same("create meta: analyst of A for B", "POST", meta, t_analyst, json={**mbody, "customer_code": CUST_B}, expect=(200, 403))


async def update_checks(p, t_admin, t_analyst):
    def url(code=CUST_A):
        return f"{INT}/update_integration/{code}"

    def body(name="Office365", keys=(("TENANT_ID", "t-x"),), **extra):
        return {"integration_name": name, "integration_auth_keys": [{"auth_key_name": k, "auth_value": v} for k, v in keys], **extra}

    await p.same("update: no token", "PUT", url(), json=body())
    await p.same("update: B as analyst of A", "PUT", url(CUST_B), t_analyst, json=body())
    await p.same("update: B as analyst of A, invalid body (tenancy first)", "PUT", url(CUST_B), t_analyst, json={"x": 1})
    await p.same("update: invalid body", "PUT", url(), t_admin, json={"integration_auth_keys": "x"})
    await p.same("update: unknown integration", "PUT", url(), t_admin, json=body(name="Nope"))
    await p.same("update: several Office365 instances, none named", "PUT", url(), t_admin, json=body())
    await p.same("update: a blank instance is unnamed (still several)", "PUT", url(), t_admin, json=body(instance_name=""))
    await p.same(
        "update: the named instance",
        "PUT",
        url(),
        t_admin,
        json=body(instance_name="tenant-b", keys=(("TENANT_ID", "t-y"), ("CLIENT_ID", "c-y"))),
    )
    await p.same("update: an instance that does not exist", "PUT", url(), t_admin, json=body(instance_name="nope"))
    await p.same(
        "update: a key the catalog does not know",
        "PUT",
        url(),
        t_admin,
        json=body(instance_name="tenant-b", keys=(("BAD", "x"),)),
    )
    await p.same("update: the single instance, resolved", "PUT", url(), t_admin, json=body(name="Mimecast", keys=(("API_KEY", "new"),)))
    await p.same(
        "update: Crowdstrike's additional info",
        "PUT",
        url(CUST_B),
        t_admin,
        json=body(name="Crowdstrike", keys=(("CLIENT_ID", "new"),)),
    )
    await p.same("update: an integration the customer does not have", "PUT", url(CUST_B), t_admin, json=body(name="Mimecast", keys=()))
    await p.same(
        "update: AWS, the write-only secret sent back as the placeholder",
        "PUT",
        url(),
        t_admin,
        json=body(name="AWS", instance_name="acct-1", keys=(("SECRET_ACCESS_KEY", "********"), ("ACCESS_KEY_ID", "AKIA9"))),
    )
    await p.same(
        "update: AWS deployed, the account changed",
        "PUT",
        url(),
        t_admin,
        json=body(name="AWS", instance_name="acct-2", keys=(("AWS_ACCOUNT_ID", "999"),)),
    )
    await p.same(
        "update: AWS deployed, same identity (padded)",
        "PUT",
        url(),
        t_admin,
        json=body(name="AWS", instance_name="acct-2", keys=(("AWS_ACCOUNT_ID", f" {ACCOUNT_2} "), ("ACCESS_KEY_ID", "AKIA8"))),
    )
    await p.same(
        "update: AWS, another customer's account",
        "PUT",
        url(),
        t_admin,
        json=body(name="AWS", instance_name="acct-1", keys=(("AWS_ACCOUNT_ID", ACCOUNT_2),)),
    )
    await p.same("update: a key the instance does not hold", "PUT", url(CUST_B), t_admin, json=body(keys=(("CLIENT_SECRET", "x"),)))


async def delete_checks(p, t_admin, t_analyst):
    url = f"{INT}/delete_integration"

    def body(name="Office365", code=CUST_A, **extra):
        return {"customer_code": code, "integration_name": name, **extra}

    await p.same("delete: no token", "DELETE", url, json=body())
    await p.same("delete: invalid", "DELETE", url, t_admin, json={"customer_code": CUST_A})
    await p.same("delete: several instances, none named", "DELETE", url, t_admin, json=body())
    await p.same("delete: an unknown instance", "DELETE", url, t_admin, json=body(instance_name="nope"))
    await p.same("delete: an integration the customer does not have", "DELETE", url, t_admin, json=body(name="Crowdstrike"))
    await p.same(
        "delete: a deployed tenant with a sibling (its stream only; its api_auth block out)",
        "DELETE",
        url,
        t_admin,
        json=body(instance_name="tenant-b"),
    )
    # Python keeps a copy of the ossec.conf it wrote next to its module (every tenant's client
    # secret, on the Python host); Rust writes none (RUST_MIGRATION.md §4).
    copy_path = os.path.join(BACKEND, "app", "integrations", "office365", "wazuh_decommission_config.xml")
    for client, side, writes in ((p.py, "python", True), (p.rs, "rust", False)):
        if os.path.exists(copy_path):
            os.remove(copy_path)
        seed_rows()
        STUB.reset()
        r, _ = await p.call(client, "DELETE", url, t_admin, json=body(instance_name="tenant-b"))
        check(
            f"delete: the ossec.conf copy ({side} {'writes one' if writes else 'writes none'}) [diff by design]",
            r.status_code == 200 and os.path.exists(copy_path) == writes,
            f"{r.status_code} {r.content[:300]!r} copy exists: {os.path.exists(copy_path)}",
        )
    if os.path.exists(copy_path):
        os.remove(copy_path)
    await p.same(
        "delete: the undeployed unnamed tenant (Wazuh block out, no Graylog)",
        "DELETE",
        url,
        t_admin,
        json=body(instance_name=""),
        before=lambda: sql("UPDATE customer_integrations SET instance_name = 'gone' WHERE id = 7531002"),
    )

    def only_b():
        sql("UPDATE customer_integrations SET instance_name = NULL WHERE id = 7531011")

    await p.same(
        "delete: B's last tenant, deployed (stream, index, folder, datasource)",
        "DELETE",
        url,
        t_admin,
        json=body(code=CUST_B),
        before=only_b,
    )
    await p.same(
        "delete: a tenant the manager does not have (no write, no restart)",
        "DELETE",
        url,
        t_admin,
        json=body(code=CUST_B),
        stub=(CONFIG.replace(TENANT_C, "someone-else"),),
    )
    await p.same("delete: ossec.conf with two blocks (ET refuses it)", "DELETE", url, t_admin, json=body(code=CUST_B), stub=(TWO_BLOCKS,))
    await p.same(
        "delete: the manager refuses the configuration",
        "DELETE",
        url,
        t_admin,
        json=body(code=CUST_B),
        stub=(
            CONFIG,
            {
                ("PUT", "/wazuh/manager/configuration*"): (
                    400,
                    "application/json",
                    json.dumps({"title": "Bad Request", "detail": "invalid ossec.conf", "error": 1}).encode(),
                ),
            },
        ),
    )
    await p.same(
        "delete: the manager answers error 1",
        "DELETE",
        url,
        t_admin,
        json=body(code=CUST_B),
        stub=(CONFIG, {("PUT", "/wazuh/manager/configuration*"): (200, "application/json", json.dumps({"data": {}, "error": 1}).encode())}),
    )
    await p.same(
        "delete: the manager unreachable (no data)",
        "DELETE",
        url,
        t_admin,
        json=body(code=CUST_B),
        stub=(CONFIG, {("GET", "/wazuh/manager/configuration*"): (500, "text/plain", b"down")}),
    )
    await p.same(
        "delete: Graylog refuses the stream and the index set, Grafana its folder",
        "DELETE",
        url,
        t_admin,
        json=body(name="Mimecast"),
        stub=(
            CONFIG,
            {
                ("DELETE", "/graylog/api/streams/*"): (404, "application/json", json.dumps({"message": "Stream not found"}).encode()),
                ("DELETE", "/graylog/api/system/indices/*"): (500, "text/html", b"<html>"),
                ("GET", "/grafana/api/folders"): (200, "application/json", json.dumps([{"id": "x", "uid": 1}]).encode()),
            },
        ),
    )
    await p.same("delete: Mimecast deployed (folder by uid)", "DELETE", url, t_admin, json=body(name="Mimecast"))
    await p.same(
        "delete: Mimecast deployed, folder unknown to Grafana",
        "DELETE",
        url,
        t_admin,
        json=body(name="Mimecast"),
        before=lambda: sql("UPDATE customer_integrations_meta SET grafana_dashboard_folder_id = '31' WHERE id = 7531502"),
    )
    await p.same(
        "delete: deployed without metadata",
        "DELETE",
        url,
        t_admin,
        json=body(name="Mimecast"),
        before=lambda: sql("DELETE FROM customer_integrations_meta WHERE id = 7531502"),
    )
    await p.same("delete: a network integration (FORTINET, its network metadata)", "DELETE", url, t_admin, json=body(name="FORTINET"))
    await p.same("delete: Crowdstrike, undeployed (its note)", "DELETE", url, t_admin, json=body(name="Crowdstrike", code=CUST_B))
    await p.same("delete: AWS undeployed", "DELETE", url, t_admin, json=body(name="AWS", instance_name="acct-1"))
    # Python leaves a deleted AWS instance's metadata row behind; Rust deletes it with the
    # instance (§4).
    await p.same(
        "delete: AWS deployed (Rust's own decommission)",
        "DELETE",
        url,
        t_admin,
        json=body(name="AWS", instance_name="acct-2"),
        py_state=lambda left: {**left, "meta": [m for m in left["meta"] if m["id"] != 7531503]},
    )
    await p.same("delete: analyst of A, for A", "DELETE", url, t_analyst, json=body(name="Mimecast"))
    await p.same("delete: analyst of A, for B", "DELETE", url, t_analyst, json=body(name="Crowdstrike", code=CUST_B), expect=(200, 403))


async def meta_checks(p, t_admin, t_analyst, t_analyst_b):
    await p.same("meta auto: Office365, any instance", "GET", f"{INT}/meta_auto/{CUST_A}/Office365", t_admin, unordered=True)
    from app.integrations.models.customer_integration_settings import (
        CustomerIntegrationsMeta,
    )

    seed_rows()
    r, _ = await p.call(p.rs, "GET", f"{INT}/meta_auto/{CUST_A}/Office365", t_admin)
    keys = list(json.loads(r.content)["data"])
    check("meta auto: Rust's key order is the declaration order", keys == list(CustomerIntegrationsMeta.model_fields), f"{keys}")
    await p.same(
        "meta auto: Office365, named",
        "GET",
        f"{INT}/meta_auto/{CUST_A}/Office365",
        t_admin,
        params={"instance_name": " tenant-b "},
        unordered=True,
    )
    await p.same(
        "meta auto: Office365, blank instance",
        "GET",
        f"{INT}/meta_auto/{CUST_A}/Office365",
        t_admin,
        params={"instance_name": ""},
        unordered=True,
    )
    await p.same(
        "meta auto: Office365, unknown instance",
        "GET",
        f"{INT}/meta_auto/{CUST_A}/Office365",
        t_admin,
        params={"instance_name": "x"},
    )
    await p.same("meta auto: missing", "GET", f"{INT}/meta_auto/{CUST_A}/Crowdstrike", t_admin)
    await p.same("meta auto: network integration", "GET", f"{INT}/meta_auto/{CUST_A}/FORTINET", t_admin, unordered=True)
    await p.same("meta auto: network integration missing", "GET", f"{INT}/meta_auto/{CUST_B}/CROWDSTRIKE", t_admin)
    await p.same("meta auto: B as analyst of A", "GET", f"{INT}/meta_auto/{CUST_B}/Office365", t_analyst)
    url = f"{INT}/update_meta_auto"
    await p.same("update meta: no fields", "PUT", url, t_admin, json={"customer_code": CUST_A, "integration_name": "Mimecast"})
    await p.same(
        "update meta: update",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_A, "integration_name": "Mimecast", "graylog_stream_id": "st-2", "grafana_org_id": "5"},
    )
    await p.same(
        "update meta: unnamed updates every instance's row",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_A, "integration_name": "Office365", "graylog_index_id": "is-2"},
    )
    await p.same(
        "update meta: create for a named instance",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_A, "integration_name": "Office365", "instance_name": " fresh ", "graylog_stream_id": "s"},
    )
    await p.same(
        "update meta: create, unnamed",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_B, "integration_name": "Crowdstrike", "graylog_input_id": "in"},
    )
    await p.same(
        "update meta: network, pipeline field",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_A, "integration_name": "FORTINET", "graylog_pipeline_id": "p2", "instance_name": "ignored"},
    )
    await p.same(
        "update meta: network create",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_B, "integration_name": "Sonicwall", "grafana_datasource_uid": "u"},
    )
    await p.same(
        "update meta: integration ignores the network-only field",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_A, "integration_name": "Mimecast", "graylog_pipeline_id": "p"},
    )
    await p.same(
        "update meta: invalid",
        "PUT",
        url,
        t_admin,
        json={"customer_code": CUST_A, "integration_name": "Mimecast", "graylog_stream_id": 5},
    )
    await p.same(
        "update meta: analyst of B, for A",
        "PUT",
        url,
        t_analyst_b,
        json={"customer_code": CUST_A, "integration_name": "Mimecast", "graylog_stream_id": "s"},
        expect=(200, 403),
    )


async def lookup_checks(p, t_admin, t_analyst):
    url = f"{INT}/integration_customer"
    await p.same("lookup: found", "GET", f"{url}/Office365/TENANT_ID/{TENANT_A}", t_admin)
    await p.same("lookup: not found", "GET", f"{url}/Office365/TENANT_ID/none", t_admin)
    await p.same("lookup: another service's key", "GET", f"{url}/Mimecast/TENANT_ID/{TENANT_A}", t_admin)
    await p.same("lookup: analyst of A, A's tenant", "GET", f"{url}/Office365/TENANT_ID/{TENANT_B}", t_analyst)
    await p.same("lookup: analyst of A, B's tenant", "GET", f"{url}/Office365/TENANT_ID/{TENANT_C}", t_analyst, expect=(200, 404))


async def alert_settings_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned):
    await p.same("alert settings: event configs", "GET", f"{A}/{CUST_A}/event_configs", t_admin)
    await p.same("alert settings: event configs, no orders", "GET", f"{A}/{CUST_C}/event_configs", t_admin)
    await p.same("alert settings: event configs, B as analyst of A", "GET", f"{A}/{CUST_B}/event_configs", t_analyst)
    await p.same("alert settings: by name", "GET", f"{A}/{NAME_A}", t_analyst)
    await p.same("alert settings: by name, other case (MySQL compares)", "GET", f"{A}/{NAME_A.upper()}", t_admin)
    await p.same("alert settings: B's name as analyst of A", "GET", f"{A}/{NAME_B}", t_analyst)
    await p.same("alert settings: an unknown name, analyst (fail closed)", "GET", f"{A}/nobody{SFX}", t_analyst)
    await p.same("alert settings: an unknown name, admin", "GET", f"{A}/nobody{SFX}", t_admin)
    await p.same("alert settings: by name, unassigned", "GET", f"{A}/{NAME_A}", t_unassigned)
    await p.same("alert settings: GET /create is a name (Python)", "GET", f"{A}/create", t_admin)
    create = f"{A}/create"
    full = {
        "customer_code": CUST_C,
        "customer_name": f"Gamma {SFX}",
        "iris_customer_id": "12",
        "nvd_url": None,
        "event_orders": [
            {
                "order_label": "O1",
                "event_configs": [{"event_id": "c", "field": "f", "value": "v"}, {"event_id": "a", "field": "f", "value": "v"}],
            },
            {"order_label": "O2", "event_configs": [{"event_id": "z", "field": "f", "value": "v"}]},
        ],
    }
    await p.same("alert settings create: created", "POST", create, t_admin, json=full, unordered=True, masked=("id",))
    # Python's key order is the order SQLAlchemy loaded the attributes in (it varies between
    # processes); Rust answers in the model's declaration order (RUST_MIGRATION.md §4).
    from app.integrations.alert_creation_settings.models.alert_creation_settings import (
        AlertCreationSettings,
    )

    seed_rows()
    r, _ = await p.call(p.rs, "POST", create, t_admin, json=full)
    keys = list(json.loads(r.content))
    check("alert settings create: Rust's key order is the declaration order", keys == list(AlertCreationSettings.model_fields), f"{keys}")
    await p.same("alert settings create: exists (a 200 error)", "POST", create, t_admin, json={**full, "customer_code": CUST_A})
    await p.same(
        "alert settings create: invalid",
        "POST",
        create,
        t_admin,
        json={"customer_code": CUST_C, "iris_customer_id": "x", "event_orders": [{}]},
    )
    await p.same("alert settings create: not an object", "POST", create, t_admin, json=[1])
    await p.same(
        "alert settings create: a name too long",
        "POST",
        create,
        t_admin,
        json={"customer_code": CUST_C, "customer_name": "n" * 60},
    )
    await p.same("alert settings create: analyst of A for C", "POST", create, t_analyst, json=full)
    await p.same("alert settings create: analyst of A for A (exists)", "POST", create, t_analyst, json={**full, "customer_code": CUST_A})
    add = f"{A}/{NAME_A}/event"
    await p.same(
        "alert settings add order",
        "POST",
        add,
        t_admin,
        json={
            "order_label": "L3",
            "event_configs": [{"event_id": "x", "field": "f", "value": "v"}, {"event_id": "b", "field": "f", "value": "v"}],
        },
    )
    await p.same(
        "alert settings add order: no settings (admin)",
        "POST",
        f"{A}/nobody{SFX}/event",
        t_admin,
        json={"order_label": "L", "event_configs": []},
    )
    await p.same(
        "alert settings add order: B's as analyst of A",
        "POST",
        f"{A}/{NAME_B}/event",
        t_analyst,
        json={"order_label": "L", "event_configs": []},
    )
    await p.same("alert settings add order: invalid", "POST", add, t_admin, json={"order_label": 1})
    await p.same("alert settings add order: GET (405 in both)", "GET", add, t_admin)
    put = f"{A}/{NAME_A}"
    await p.same(
        "alert settings put: configs added to L1",
        "PUT",
        put,
        t_admin,
        json=[{"order_label": "L1", "event_configs": [{"event_id": "e9", "field": "f", "value": "v"}]}],
    )
    await p.same(
        "alert settings put: an unknown label",
        "PUT",
        put,
        t_admin,
        json=[
            {"order_label": "L1", "event_configs": [{"event_id": "e9", "field": "f", "value": "v"}]},
            {"order_label": "LX", "event_configs": []},
        ],
    )
    await p.same("alert settings put: not a list", "PUT", put, t_admin, json={"order_label": "L1"})
    await p.same("alert settings put: invalid items", "PUT", put, t_admin, json=[{"order_label": 5}])
    await p.same("alert settings put: no settings", "PUT", f"{A}/nobody{SFX}", t_admin, json=[])
    delete = f"{A}/{NAME_A}/event"
    await p.same("alert settings delete: L1 (configs out, condition orphaned)", "DELETE", f"{delete}/L1", t_admin)
    await p.same("alert settings delete: L2 (no configs)", "DELETE", f"{delete}/L2", t_admin)
    await p.same("alert settings delete: unknown label", "DELETE", f"{delete}/LX", t_admin)
    await p.same("alert settings delete: label case matters", "DELETE", f"{delete}/l1", t_admin)
    await p.same("alert settings delete: B's as analyst of A", "DELETE", f"{A}/{NAME_B}/event/B1", t_analyst)
    await p.same("alert settings delete: B's as analyst of B", "DELETE", f"{A}/{NAME_B}/event/B1", t_analyst_b)


async def network_checks(p, t_admin, t_analyst, t_analyst_b):
    await p.same("network: catalog", "GET", f"{N}/available_network_connectors", t_admin)
    await p.same("network: catalog one", "GET", f"{N}/available_network_connectors/7530102", t_admin)
    await p.same("network: catalog missing", "GET", f"{N}/available_network_connectors/9", t_admin)
    await p.same("network: catalog not an int", "GET", f"{N}/available_network_connectors/x", t_admin)
    await p.same("network: all, admin", "GET", f"{N}/customer_network_connectors", t_admin)
    await p.same(
        "network: all, analyst of A (narrowed)",
        "GET",
        f"{N}/customer_network_connectors",
        t_analyst,
        py_view=visible_only({CUST_A}),
    )
    await p.same("network: A", "GET", f"{N}/customer_network_connectors/{CUST_A}", t_analyst)
    await p.same("network: B as analyst of A", "GET", f"{N}/customer_network_connectors/{CUST_B}", t_analyst)
    await p.same("network: metas, admin", "GET", f"{N}/customer_network_connectors_meta", t_admin)
    await p.same(
        "network: metas, analyst of B (narrowed)",
        "GET",
        f"{N}/customer_network_connectors_meta",
        t_analyst_b,
        py_view=visible_only({CUST_B}),
    )
    await p.same("network: metas of A", "GET", f"{N}/customer_network_connectors_meta/{CUST_A}", t_analyst)
    create = f"{N}/create_network_connector"

    def body(name="SonicWall", code=CUST_A, keys=(("PORT", "443"),)):
        return {
            "customer_code": code,
            "customer_name": "Alpha",
            "network_connector_name": name,
            "network_connector_config": {"auth_type": "syslog", "config_key": "k", "config_value": "v"},
            "network_connector_auth_keys": [{"auth_key_name": k, "auth_value": v} for k, v in keys],
        }

    await p.same("network create: created", "POST", create, t_admin, json=body(keys=(("PORT", "443"), ("EXTRA", "x"))))
    await p.same(
        "network create: exists",
        "POST",
        create,
        t_admin,
        json=body(name="Fortinet", keys=(("SYSLOG_PORT", "1"), ("PROTOCOL", "udp"))),
    )
    await p.same("network create: a key missing", "POST", create, t_admin, json=body(name="Fortinet", keys=(("PROTOCOL", "udp"),)))
    await p.same("network create: unknown", "POST", create, t_admin, json=body(name="Nope"))
    await p.same("network create: no customer", "POST", create, t_admin, json=body(code=f"NOPE{SFX}"))
    await p.same("network create: no meta", "POST", create, t_admin, json=body(code=CUST_C))
    await p.same("network create: invalid", "POST", create, t_admin, json={"network_connector_name": 1})
    await p.same("network create: analyst of A for B", "POST", create, t_analyst, json=body(code=CUST_B), expect=(400, 403))
    meta = f"{N}/create_network_connector_meta"
    mbody = {
        "customer_code": CUST_A,
        "network_connector_name": "SonicWall",
        "graylog_index_id": "i",
        "graylog_stream_id": 7,
        "grafana_org_id": "2",
        "grafana_dashboard_folder_id": "f",
    }
    await p.same("network create meta: never insertable", "POST", meta, t_admin, json=mbody)
    await p.same("network create meta: exists", "POST", meta, t_admin, json={**mbody, "network_connector_name": "Fortinet"})
    await p.same("network create meta: invalid", "POST", meta, t_admin, json={"customer_code": CUST_A})
    update = f"{N}/update_network_connector"
    await p.same(
        "network update: found (Python's AttributeError)",
        "PUT",
        f"{update}/{CUST_A}",
        t_admin,
        json={"network_connector_name": "Fortinet", "network_connector_auth_keys": [{"auth_key_name": "PROTOCOL", "auth_value": "udp"}]},
    )
    await p.same(
        "network update: not found",
        "PUT",
        f"{update}/{CUST_A}",
        t_admin,
        json={"network_connector_name": "SonicWall", "network_connector_auth_keys": []},
    )
    await p.same(
        "network update: unknown name",
        "PUT",
        f"{update}/{CUST_A}",
        t_admin,
        json={"network_connector_name": "Nope", "network_connector_auth_keys": []},
    )
    await p.same(
        "network update: B as analyst of A",
        "PUT",
        f"{update}/{CUST_B}",
        t_analyst,
        json={"network_connector_name": "SonicWall", "network_connector_auth_keys": []},
    )
    put = f"{N}/available_network_connectors"
    await p.same(
        "network catalog put: written, then the response's 400",
        "PUT",
        put,
        t_admin,
        json=[{"network_connector_name": "SonicWall", "description": "s2", "network_connector_details": "d2"}],
    )
    await p.same("network catalog put: empty (still the 400)", "PUT", put, t_admin, json=[])
    await p.same("network catalog put: unknown", "PUT", put, t_admin, json=[{"network_connector_name": "Nope"}])
    delete = f"{N}/delete_network_connector"
    await p.same("network delete: deleted", "DELETE", delete, t_admin, json={"customer_code": CUST_A, "network_connector_name": "Fortinet"})
    await p.same(
        "network delete: not found",
        "DELETE",
        delete,
        t_admin,
        json={"customer_code": CUST_A, "network_connector_name": "SonicWall"},
    )
    await p.same("network delete: invalid", "DELETE", delete, t_admin, json={})
    await p.same(
        "network delete: analyst of A for B",
        "DELETE",
        delete,
        t_analyst,
        json={"customer_code": CUST_B, "network_connector_name": "SonicWall"},
        expect=(200, 403),
    )
    dmeta = f"{N}/delete_network_connector_meta"
    full = {
        "customer_code": CUST_A,
        "network_connector_name": "Fortinet",
        "graylog_index_id": "i",
        "graylog_stream_id": "s",
        "grafana_org_id": "2",
        "grafana_dashboard_folder_id": "f",
    }
    await p.same("network delete meta: deleted", "DELETE", dmeta, t_admin, json=full)
    await p.same(
        "network delete meta: invalid (the whole schema)",
        "DELETE",
        dmeta,
        t_admin,
        json={"customer_code": CUST_A, "network_connector_name": "Fortinet"},
    )
    await p.same("network delete meta: analyst of B for A", "DELETE", dmeta, t_analyst_b, json=full, expect=(200, 403))


async def main():
    server = start_stub()
    procs = []
    try:
        seed()
        procs.append(start_python_legacy())
        procs.append(start_rust())
        p = Pair()
        t_admin, t_analyst = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"])
        t_analyst_b, t_unassigned = token(ANALYST_B, ["analyst"]), token(UNASSIGNED, ["analyst"])
        try:
            sections = os.environ.get(
                "INTEGRATIONS_PARITY_SECTIONS",
                "catalog,customers,create,update,delete,meta,lookup,alerts,network",
            ).split(",")
            if "catalog" in sections:
                await catalog_checks(p, t_admin, t_analyst)
            if "customers" in sections:
                await customer_integration_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned)
            if "create" in sections:
                await create_checks(p, t_admin, t_analyst)
            if "update" in sections:
                await update_checks(p, t_admin, t_analyst)
            if "delete" in sections:
                await delete_checks(p, t_admin, t_analyst)
            if "meta" in sections:
                await meta_checks(p, t_admin, t_analyst, t_analyst_b)
            if "lookup" in sections:
                await lookup_checks(p, t_admin, t_analyst)
            if "alerts" in sections:
                await alert_settings_checks(p, t_admin, t_analyst, t_analyst_b, t_unassigned)
            if "network" in sections:
                await network_checks(p, t_admin, t_analyst, t_analyst_b)
        finally:
            await p.close()
            # The in-process routers' pool, closed while its loop runs (else aiomysql's
            # finalizers complain at exit).
            from app.db.db_session import async_engine

            await async_engine.dispose()
    finally:
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            cleanup()
        finally:
            seed_catalog_cleanup()
            server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


def seed_catalog_cleanup():
    ids = [r["id"] for r in rows("SELECT id FROM available_integrations WHERE id BETWEEN 7530000 AND 7530099")]
    if ids:
        sql("DELETE FROM available_integrations_auth_keys WHERE integration_id IN :i", i=ids)
        sql("DELETE FROM available_integrations WHERE id IN :i", i=ids)
    ids = [r["id"] for r in rows("SELECT id FROM available_network_connectors WHERE id BETWEEN 7530100 AND 7530199")]
    if ids:
        sql("DELETE FROM available_network_connectors_keys WHERE network_connector_id IN :i", i=ids)
        sql("DELETE FROM available_network_connectors WHERE id IN :i", i=ids)
    for table, row in SAVED_CATALOG:
        sql(f"INSERT INTO {table} ({', '.join(row)}) VALUES ({', '.join(':' + c for c in row)})", **row)
    SAVED_CATALOG.clear()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
