"""Parity of the Rust startup (`copilot-startup`, `copilot-migrate`) with `copilot.py`'s `lifespan` —
NOT collected by pytest (needs a live MySQL and the Rust binary; run by scripts/rust-parity.sh).

Python's real `lifespan` (in a subprocess of its own, from `backend/`, as the image runs it) and a
Rust `copilot serve` each start on an EMPTY database of their own on the suite's MySQL; then:

* the whole schema is compared — `SHOW CREATE TABLE` of every table, the AUTO_INCREMENT counter
  removed and nothing else — but for Rust's own history table, which is reported on its own;
* every seeded row: connectors (but `connector_last_updated`), roles, the integration and
  network-connector catalogs with their keys, the users (the password a bcrypt hash, `created_at`
  dropped), the built-in templates (`created_at` dropped), the portal settings (`updated_at`
  dropped), the scheduler rows, `alembic_version`, and the row count of every other table — while
  the process runs, and again after it stopped (the scheduler user removed);
* every request each sent to MinIO (a recording S3 stand-in: method, path, query, every header —
  the signature's date and value masked) and to Graylog (the Office 365 rule check, a recording
  stand-in holding the Office 365 pipeline, two of its rules missing and one in its broken form:
  method, path, query, every header, the body).

Then each starts again on its own database (nothing changes: the same requests of a second start,
the same rows but the scheduler user's new id), Rust on Python's database (adopted: its history
records the baseline as `adopted`, no table touched) and Python on Rust's (Alembic sees its head
and runs nothing); both start at once on one empty database, Rust first and then Python first —
Rust started while Python holds the startup lock, Alembic about to run — (one schema, one set of
rows: the lock both take); Rust refuses a database at an older Alembic revision with what to do,
the last Python release's start upgrades it, and Rust then adopts it; with `ENVIRONMENT=PRODUCTION`
and a user that does not exist yet, Python's start fails (it makes sure of `copilot`, whatever
`MYSQL_USER` says) and Rust's creates the database and that user through root (§4).

The Python side is unchanged code, with two in-process patches: `create_session()` dials the S3
stand-in (Python dials `MINIO_URL:9000` whatever the environment, as rust_parity_objectstore_e2e.py
patches it), and the catalog warm-up is a no-op (the Rust instance runs with
`COPILOT_CATALOG_REFRESH=false`; each process warms its own caches). Its database is reached
through `MYSQL_URL=<host:port>/<db>?`: Python appends `/copilot`, which the `?` turns into an empty
query string. Python runs with `COPILOT_PY_SCHEDULER=false` (the configuration in which the Rust
service owns the schedule): `init_scheduler()` then seeds the scheduler rows only.

    PARITY_SUITES=tests/e2e/rust_parity_startup_e2e.py scripts/rust-parity.sh

Ports: STARTUP_PARITY_RUST_PORT (6300), STARTUP_PARITY_RUST2_PORT (6301), STARTUP_S3_STUB_PORT (6302),
STARTUP_GRAYLOG_STUB_PORT (6303). Root: STARTUP_PARITY_ROOT_PASSWORD (default empty); without a
root login the PRODUCTION checks are skipped and both start in DEVELOPMENT. Databases
`copilot_parity_startup_*` and the user `copilot_parity_boot` are created and dropped by the suite.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

import httpx
import pymysql

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(BACKEND, ".."))

HOST, _, PORT = os.environ.get("MYSQL_URL", "127.0.0.1:13306").partition(":")
PORT = int(PORT or 3306)
USER = os.environ.get("MYSQL_USER", "copilot")
PASSWORD = os.environ.get("MYSQL_PASSWORD", "e2epass")
JWT_SECRET = os.environ.get("JWT_SECRET", "e2e-test-secret-not-the-default")
ROOT_PASSWORD = os.environ.get("STARTUP_PARITY_ROOT_PASSWORD", "")
PYTHON = sys.executable

RS_PORT = int(os.environ.get("STARTUP_PARITY_RUST_PORT", "6300"))
RS2_PORT = int(os.environ.get("STARTUP_PARITY_RUST2_PORT", "6301"))
S3_PORT = int(os.environ.get("STARTUP_S3_STUB_PORT", "6302"))
GRAYLOG_PORT = int(os.environ.get("STARTUP_GRAYLOG_STUB_PORT", "6303"))
S3_USER, S3_SECRET = "startup-minio", "startup-minio-secret"

PY_DB, RS_DB = "copilot_parity_startup_py", "copilot_parity_startup_rs"
RACE_DB, OLD_DB = "copilot_parity_startup_race", "copilot_parity_startup_old"
BOOT_DB, BOOT_USER = "copilot_parity_startup_boot", "copilot_parity_boot"
DATABASES = (PY_DB, RS_DB, RACE_DB, OLD_DB, BOOT_DB)
HISTORY = "copilot_rs_schema_history"
HEAD = "d15ab1ed7e1e"
OLDER = "c1241a1b2c3d"

# The connector variables both processes read (`load_connector_data`).
CONNECTOR_ENV = {
    "GRAYLOG_URL": f"http://127.0.0.1:{GRAYLOG_PORT}",
    "GRAYLOG_USERNAME": "parity",
    "GRAYLOG_PASSWORD": "parity-secret",
    "WAZUH_INDEXER_URL": "https://indexer.parity:9200",
    "WAZUH_INDEXER_USERNAME": "",
    "SHUFFLE_VERIFIED": "false",
    "INFLUXDB_ORG_AND_BUCKET": "SOCFORTRESS,telegraf",
    "VIRUSTOTAL_API_KEY": "vt-parity",
    "TALON_SUPPORTS": "investigations",
    "OPENCTI_PUBLIC_URL": "https://cti.parity",
}

results = []
skipped = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""), flush=True)


def skip(name, why):
    skipped.append(name)
    print(f"  SKIP  {name} ({why})", flush=True)


def connect(db=None, user=USER, password=PASSWORD):
    return pymysql.connect(host=HOST, port=PORT, user=user, password=password, database=db, autocommit=True, charset="utf8mb4")


def server_sql(*statements, user=USER, password=PASSWORD):
    conn = connect(user=user, password=password)
    try:
        with conn.cursor() as cur:
            for s in statements:
                cur.execute(s)
    finally:
        conn.close()


def query(db, statement, args=None):
    conn = connect(db)
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(statement, args)
            return list(cur.fetchall())
    finally:
        conn.close()


def root_works():
    try:
        connect(user="root", password=ROOT_PASSWORD).close()
        return True
    except pymysql.MySQLError:
        return False


# --- The stand-ins ----------------------------------------------------------------------------------


class Recorder:
    """One recording HTTP server; `handle(method, path, query, headers, body)` answers."""

    def __init__(self, port, handle):
        self.seen = []
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path, _, qs = self.path.partition("?")
                # Every header, by name (case-insensitive, as HTTP's are) and value.
                headers = sorted((k.lower(), v) for k, v in self.headers.items())
                with recorder.lock:
                    recorder.seen.append(
                        {"method": self.command, "path": path, "query": qs, "headers": headers, "body": body.decode("utf-8", "replace")},
                    )
                    status, extra, data = handle(self.command, path, qs, body)
                self.send_response(status)
                for k, v in extra:
                    self.send_header(k, v)
                if self.command != "HEAD":
                    self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _any

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def take(self):
        with self.lock:
            out, self.seen = self.seen, []
        return out

    def wait_for(self, n, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if len(self.seen) >= n:
                    time.sleep(0.3)
                    return
            time.sleep(0.1)


S3_STATE = {"buckets": set()}
XML = '<?xml version="1.0" encoding="UTF-8"?>\n'


def s3_handle(method, path, qs, body):
    bucket = path.lstrip("/")
    exists = bucket in S3_STATE["buckets"]
    xml = [("Content-Type", "application/xml")]
    missing = (
        404,
        xml,
        (
            f"{XML}<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>"
            f"<BucketName>{bucket}</BucketName><Resource>/{bucket}</Resource><RequestId>PARITY</RequestId>"
            "<HostId>parity</HostId></Error>"
        ).encode(),
    )
    if method == "GET" and qs == "location=":
        if not exists:
            return missing
        return 200, xml, f'{XML}<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>'.encode()
    if method == "HEAD":
        return (200, [], b"") if exists else (404, [], b"")
    if method == "PUT" and qs == "":
        S3_STATE["buckets"].add(bucket)
        return 200, [("Location", f"/{bucket}")], b""
    return 501, xml, b"<Error><Code>NotImplemented</Code></Error>"


# Graylog: the Office 365 pipeline, four of its six rules, the UTC rule in the broken form earlier
# CoPilot versions created.
PIPELINE = {
    "id": "p-office365",
    "title": "OFFICE365 PROCESSING PIPELINE",
    "description": "OFFICE365 PROCESSING PIPELINE",
    "source": 'pipeline "OFFICE365 PROCESSING PIPELINE"\nstage 0 match either\nend',
    "stages": [{"stage": 0, "match": "EITHER", "rules": []}],
    "created_at": "2026-01-01T00:00:00.000Z",
    "modified_at": "2026-01-01T00:00:00.000Z",
    "errors": None,
}


def initial_rules():
    def rule(i, title, source):
        return {
            "id": f"r{i}",
            "title": title,
            "description": None if i == 1 else title,
            "source": source,
            "created_at": "2026-01-01T00:00:00.000Z",
            "modified_at": None,
            "errors": None,
        }

    return [
        rule(
            1,
            "Office365 Timestamp - UTC",
            'rule "Office365 Timestamp - UTC"\nwhen\n  has_field("data_office_365_CreationTime")\nthen\nend',
        ),
        rule(2, "WAZUH CREATE FIELD SYSLOG LEVEL - INFO", 'rule "WAZUH CREATE FIELD SYSLOG LEVEL - INFO"\nwhen true\nthen\nend'),
        rule(3, "WAZUH CREATE FIELD SYSLOG LEVEL - WARNING", 'rule "WAZUH CREATE FIELD SYSLOG LEVEL - WARNING"\nwhen true\nthen\nend'),
        rule(4, "WAZUH CREATE FIELD SYSLOG LEVEL - NOTICE", 'rule "WAZUH CREATE FIELD SYSLOG LEVEL - NOTICE"\nwhen true\nthen\nend'),
    ]


GRAYLOG_STATE = {"rules": initial_rules()}


def graylog_handle(method, path, qs, body):
    js = [("Content-Type", "application/json")]
    if method == "GET" and path == "/api/system/pipelines/pipeline":
        return 200, js, json.dumps([PIPELINE]).encode()
    if method == "GET" and path == "/api/system/pipelines/rule":
        return 200, js, json.dumps(GRAYLOG_STATE["rules"]).encode()
    if method == "POST" and path == "/api/system/pipelines/rule":
        sent = json.loads(body)
        rule = dict(sent, id=f"r{len(GRAYLOG_STATE['rules']) + 1}", created_at="2026-01-02T00:00:00.000Z", modified_at=None, errors=None)
        GRAYLOG_STATE["rules"].append(rule)
        return 200, js, json.dumps(rule).encode()
    if method == "PUT" and path.startswith("/api/system/pipelines/rule/"):
        sent = json.loads(body)
        for r in GRAYLOG_STATE["rules"]:
            if r["id"] == path.rsplit("/", 1)[1]:
                r.update(sent)
                return 200, js, json.dumps(r).encode()
        return 404, js, b'{"message": "not found"}'
    return 404, js, b'{"message": "not found"}'


SIGNATURE = re.compile(r"Credential=([^/]+)/\d{8}/([^/]+)/s3/aws4_request, SignedHeaders=([^,]+), Signature=[0-9a-f]{64}")


def normalise(seen):
    out = []
    for r in seen:
        headers = []
        for k, v in r["headers"]:
            if k.lower() == "x-amz-date":
                v = "<date>"
            if k.lower() == "authorization":
                v = SIGNATURE.sub(
                    lambda m: f"Credential={m.group(1)}/<day>/{m.group(2)}/s3/aws4_request, SignedHeaders={m.group(3)}, Signature=<sig>",
                    v,
                )
            headers.append((k, v))
        out.append({**r, "headers": headers})
    return out


# --- The two processes ------------------------------------------------------------------------------

PERF_DIR = tempfile.mkdtemp(prefix="startup-parity-perf-")
RUST_CWD = tempfile.mkdtemp(prefix="startup-parity-rust-")

PY_DRIVER = r"""
import asyncio, os, sys
from miniopy_async import Minio
import copilot
from app.data_store import data_store_setup

async def create_session():
    return Minio(os.environ["STARTUP_S3"], access_key=os.environ["STARTUP_S3_USER"], secret_key=os.environ["STARTUP_S3_SECRET"], secure=False)

async def no_warm_up():
    return None

data_store_setup.create_session = create_session
copilot.warm_catalog_caches = no_warm_up

async def main():
    async with copilot.lifespan(copilot.app):
        print("READY", flush=True)
        await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
    print("DONE", flush=True)

asyncio.run(main())
"""


class Python:
    """`copilot.py`'s lifespan on `db` (started, then stopped by `stop()`)."""

    def __init__(self, db, production, user=USER, password=PASSWORD):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),
            "MYSQL_URL": f"{HOST}:{PORT}/{db}?",
            "MYSQL_USER": user,
            "MYSQL_PASSWORD": password,
            "MYSQL_ROOT_PASSWORD": ROOT_PASSWORD,
            "ENVIRONMENT": "PRODUCTION" if production else "DEVELOPMENT",
            "JWT_SECRET": JWT_SECRET,
            "COPILOT_PY_SCHEDULER": "false",
            "PERF_LOG_DIR": PERF_DIR,
            "STARTUP_S3": f"127.0.0.1:{S3_PORT}",
            "STARTUP_S3_USER": S3_USER,
            "STARTUP_S3_SECRET": S3_SECRET,
            **CONNECTOR_ENV,
        }
        self.log = tempfile.NamedTemporaryFile(prefix="startup-parity-py-", suffix=".log", delete=False)
        self.proc = subprocess.Popen(
            [PYTHON, "-c", PY_DRIVER],
            cwd=BACKEND,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
        )

    def wait_ready(self, timeout=180):
        line = self._line(timeout)
        if line != "READY":
            raise RuntimeError(f"Python's startup did not finish: {line!r}\n{self.tail()}")

    def _line(self, timeout):
        box = []
        t = threading.Thread(target=lambda: box.append(self.proc.stdout.readline().strip()), daemon=True)
        t.start()
        t.join(timeout)
        return box[0] if box else None

    def stop(self):
        try:
            self.proc.stdin.write("\n")
            self.proc.stdin.flush()
        except BrokenPipeError:
            pass
        line = self._line(60)
        self.proc.wait(timeout=60)
        if line != "DONE":
            raise RuntimeError(f"Python's shutdown did not finish: {line!r}\n{self.tail()}")

    def tail(self):
        with open(self.log.name, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-30:])

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


class Rust:
    """`copilot serve` on `db`."""

    def __init__(self, db, production, port=RS_PORT, user=USER, password=PASSWORD):
        binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),
            "MYSQL_URL": f"{HOST}:{PORT}",
            "MYSQL_USER": user,
            "MYSQL_PASSWORD": password,
            "MYSQL_DATABASE": db,
            "MYSQL_ROOT_PASSWORD": ROOT_PASSWORD,
            "ENVIRONMENT": "PRODUCTION" if production else "DEVELOPMENT",
            "JWT_SECRET": JWT_SECRET,
            "COPILOT_BIND": "127.0.0.1",
            "COPILOT_PORT": str(port),
            # The catalog caches are this process's own (Python's warm-up is patched out).
            "COPILOT_CATALOG_REFRESH": "false",
            "MINIO_ROOT_USER": S3_USER,
            "MINIO_ROOT_PASSWORD": S3_SECRET,
            "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{S3_PORT}",
            "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
            **CONNECTOR_ENV,
        }
        self.port = port
        self.log = tempfile.NamedTemporaryFile(prefix="startup-parity-rs-", suffix=".log", delete=False)
        self.proc = subprocess.Popen(
            [binary, "--root", "/nonexistent", "serve"],
            cwd=RUST_CWD,
            env=env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )

    def wait_ready(self, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"the Rust instance exited ({self.proc.returncode}):\n{self.tail()}")
            try:
                if httpx.get(f"http://127.0.0.1:{self.port}/_copilot/health", timeout=1).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError(f"the Rust instance did not start:\n{self.tail()}")

    def wait_exit(self, timeout=60):
        return self.proc.wait(timeout=timeout)

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=60)

    def tail(self):
        with open(self.log.name, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-30:])

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


# --- Snapshots --------------------------------------------------------------------------------------

AUTO_INCREMENT = re.compile(r" AUTO_INCREMENT=\d+")
SEEDED = {
    "connectors": ("SELECT * FROM connectors ORDER BY id", {"connector_last_updated"}),
    "role": ("SELECT * FROM role ORDER BY id", set()),
    "user": ("SELECT * FROM `user` ORDER BY id", {"created_at"}),
    "available_integrations": ("SELECT * FROM available_integrations ORDER BY id", set()),
    "available_integrations_auth_keys": ("SELECT * FROM available_integrations_auth_keys ORDER BY id", set()),
    "available_network_connectors": ("SELECT * FROM available_network_connectors ORDER BY id", set()),
    "available_network_connectors_keys": ("SELECT * FROM available_network_connectors_keys ORDER BY id", set()),
    "notification_template": ("SELECT * FROM notification_template ORDER BY id", {"created_at"}),
    "customer_portal_settings": ("SELECT * FROM customer_portal_settings ORDER BY id", {"updated_at"}),
    "scheduled_job_metadata": ("SELECT * FROM scheduled_job_metadata ORDER BY id", set()),
    "alembic_version": ("SELECT * FROM alembic_version", set()),
}
BCRYPT = re.compile(r"^\$2b\$12\$[./A-Za-z0-9]{53}$")


def tables(db):
    return [
        r["t"]
        for r in query(
            db,
            "SELECT CAST(table_name AS CHAR) AS t FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name",
        )
    ]


def schema(db):
    out = {}
    for t in tables(db):
        if t == HISTORY:
            continue
        ddl = query(db, f"SHOW CREATE TABLE `{t}`")[0]["Create Table"]
        out[t] = AUTO_INCREMENT.sub("", ddl)
    return out


def snapshot(db):
    rows = {}
    for table, (statement, dropped) in SEEDED.items():
        found = []
        for r in query(db, statement):
            r = {k: v for k, v in r.items() if k not in dropped}
            if table == "user":
                r["password"] = "<bcrypt>" if BCRYPT.match(r["password"]) else r["password"]
            found.append({k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()})
        rows[table] = found
    counts = {t: query(db, f"SELECT COUNT(*) AS n FROM `{t}`")[0]["n"] for t in tables(db) if t not in SEEDED and t != HISTORY}
    return {"rows": rows, "others": {t: n for t, n in counts.items() if n}}


def history(db):
    if HISTORY not in tables(db):
        return None
    return query(db, f"SELECT version, name, checksum, method, success FROM {HISTORY} ORDER BY version")


def without_scheduler_user(snap):
    rows = dict(snap["rows"])
    rows["user"] = [u for u in rows["user"] if u["username"] != "scheduler"]
    return {**snap, "rows": rows}


def diff(a, b, depth=0):
    """A short description of where two values differ."""
    if a == b:
        return ""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a) + [k for k in b if k not in a]:
            if a.get(k) != b.get(k):
                return f"[{k}] " + diff(a.get(k), b.get(k), depth + 1)
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"len {len(a)} != {len(b)}: {str(a)[:300]} / {str(b)[:300]}"
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return f"[{i}] " + diff(x, y, depth + 1)
    return f"{str(a)[:400]} != {str(b)[:400]}"


S3 = None
GRAYLOG = None


def run_python(db, production, keep_running=False):
    py = Python(db, production)
    try:
        py.wait_ready()
        GRAYLOG.wait_for(2, timeout=30)  # the Office 365 check (on a task)
        GRAYLOG.wait_for(5, timeout=5)
        running = snapshot(db)
        if keep_running:
            return py, running
        py.stop()
        return running, snapshot(db)
    except BaseException:
        py.kill()
        raise


def run_rust(db, production, **kw):
    rs = Rust(db, production, **kw)
    try:
        rs.wait_ready()
        GRAYLOG.wait_for(2, timeout=30)
        GRAYLOG.wait_for(5, timeout=5)
        running = snapshot(db)
        rs.stop()
        return running, snapshot(db)
    except BaseException:
        rs.kill()
        raise


def fresh(db):
    server_sql(f"DROP DATABASE IF EXISTS `{db}`", f"CREATE DATABASE `{db}`")


def first_start(production):
    print("\n== The first start on an empty database", flush=True)
    fresh(PY_DB)
    server_sql(f"DROP DATABASE IF EXISTS `{RS_DB}`")
    if not production:
        fresh(RS_DB)
    S3_STATE["buckets"] = set()
    GRAYLOG_STATE["rules"] = initial_rules()
    S3.take(), GRAYLOG.take()
    py_running, py_stopped = run_python(PY_DB, production)
    py_s3, py_gl = normalise(S3.take()), GRAYLOG.take()
    py_buckets, py_rules = set(S3_STATE["buckets"]), [dict(r) for r in GRAYLOG_STATE["rules"]]

    S3_STATE["buckets"] = set()
    GRAYLOG_STATE["rules"] = initial_rules()
    rs_running, rs_stopped = run_rust(RS_DB, production)
    rs_s3, rs_gl = normalise(S3.take()), GRAYLOG.take()
    rs_buckets, rs_rules = set(S3_STATE["buckets"]), [dict(r) for r in GRAYLOG_STATE["rules"]]

    py_schema, rs_schema = schema(PY_DB), schema(RS_DB)
    check("the schema: every table, SHOW CREATE TABLE", py_schema == rs_schema, diff(py_schema, rs_schema))
    check("the schema has the 116 tables of the Alembic head", len(rs_schema) == 116, str(len(rs_schema)))
    check(
        "Rust's history records the baseline as applied",
        [(h["version"], h["name"], h["method"], h["success"]) for h in history(RS_DB) or []] == [(1, "baseline", "applied", 1)],
        str(history(RS_DB)),
    )
    check("Python's database has no Rust history", history(PY_DB) is None)
    check("the seeded rows while running", py_running == rs_running, diff(py_running, rs_running))
    check("the seeded rows after the stop (the scheduler user removed)", py_stopped == rs_stopped, diff(py_stopped, rs_stopped))
    check(
        "the scheduler user exists while running, not after",
        any(u["username"] == "scheduler" for u in rs_running["rows"]["user"])
        and not any(u["username"] == "scheduler" for u in rs_stopped["rows"]["user"]),
    )
    check(
        "the catalogs are complete",
        [
            len(rs_running["rows"][t])
            for t in (
                "connectors",
                "available_integrations",
                "available_integrations_auth_keys",
                "notification_template",
                "scheduled_job_metadata",
            )
        ]
        == [18, 13, 53, 9, 12],
    )
    check(
        "no other table holds a row",
        rs_running["others"] == {} == py_running["others"],
        f"{py_running['others']} / {rs_running['others']}",
    )
    check("MinIO: every request and header", py_s3 == rs_s3, diff(py_s3, rs_s3))
    check("MinIO: the five buckets made", py_buckets == rs_buckets and len(rs_buckets) == 5, f"{py_buckets} / {rs_buckets}")
    check("Graylog: the Office 365 rule check, every request, header and body", py_gl == rs_gl, diff(py_gl, rs_gl))
    check(
        "Graylog: two rules created and the broken one repaired",
        [r["method"] for r in rs_gl] == ["GET", "GET", "POST", "POST", "PUT"],
        str([(r["method"], r["path"]) for r in rs_gl]),
    )
    check("Graylog: the rules each left", py_rules == rs_rules, diff(py_rules, rs_rules))
    return py_stopped, rs_stopped, py_buckets, rs_buckets, py_rules, rs_rules


def second_start(production, py_before, rs_before, py_buckets, rs_buckets, py_rules, rs_rules):
    print("\n== Each again on its own database (idempotence)", flush=True)
    S3_STATE["buckets"], GRAYLOG_STATE["rules"] = set(py_buckets), [dict(r) for r in py_rules]
    py_schema_before = schema(PY_DB)
    py_running, py_stopped = run_python(PY_DB, production)
    py_s3, py_gl = normalise(S3.take()), GRAYLOG.take()
    S3_STATE["buckets"], GRAYLOG_STATE["rules"] = set(rs_buckets), [dict(r) for r in rs_rules]
    rs_schema_before, rs_history_before = schema(RS_DB), history(RS_DB)
    rs_running, rs_stopped = run_rust(RS_DB, production)
    rs_s3, rs_gl = normalise(S3.take()), GRAYLOG.take()
    check(
        "Python: nothing changes",
        without_scheduler_user(py_stopped) == without_scheduler_user(py_before) and schema(PY_DB) == py_schema_before,
        diff(py_before, py_stopped),
    )
    check(
        "Rust: nothing changes",
        without_scheduler_user(rs_stopped) == without_scheduler_user(rs_before) and schema(RS_DB) == rs_schema_before,
        diff(rs_before, rs_stopped),
    )
    check("Rust: no migration recorded again", history(RS_DB) == rs_history_before, str(history(RS_DB)))
    check("the rows of a second start (the scheduler user's new id included)", py_running == rs_running, diff(py_running, rs_running))
    check(
        "MinIO on a second start: the region and HEAD of each bucket, nothing made",
        py_s3 == rs_s3 and all(r["method"] in ("GET", "HEAD") for r in rs_s3),
        diff(py_s3, rs_s3),
    )
    check(
        "Graylog on a second start: the two reads only",
        py_gl == rs_gl and [r["method"] for r in rs_gl] == ["GET", "GET"],
        diff(py_gl, rs_gl),
    )
    return py_stopped, rs_stopped


def cross_starts(production, py_before, rs_before):
    print("\n== Rust on Python's database, Python on Rust's", flush=True)
    py_schema = schema(PY_DB)
    S3_STATE["buckets"] = set()
    _, after = run_rust(PY_DB, production)
    S3.take(), GRAYLOG.take()
    check(
        "Rust adopts Python's database: the baseline recorded as adopted",
        [(h["version"], h["method"], h["success"]) for h in history(PY_DB) or []] == [(1, "adopted", 1)],
        str(history(PY_DB)),
    )
    check("Rust adopts Python's database: no table touched", schema(PY_DB) == py_schema)
    check(
        "Rust adopts Python's database: no row added",
        without_scheduler_user(after) == without_scheduler_user(py_before),
        diff(py_before, after),
    )
    rs_schema, rs_history = schema(RS_DB), history(RS_DB)
    _, after = run_python(RS_DB, production)
    S3.take(), GRAYLOG.take()
    check("Python on Rust's database: Alembic runs nothing", schema(RS_DB) == rs_schema and history(RS_DB) == rs_history)
    check(
        "Python on Rust's database: no row added",
        without_scheduler_user(after) == without_scheduler_user(rs_before),
        diff(rs_before, after),
    )


def race(python_first):
    print(f"\n== Both at once on one empty database ({'Python' if python_first else 'Rust'} takes the lock first)", flush=True)
    fresh(RACE_DB)
    S3_STATE["buckets"] = set()
    if python_first:
        py = Python(RACE_DB, False)
        # Rust is started once Python holds the lock (Alembic about to run): it waits for it.
        deadline = time.time() + 120
        while time.time() < deadline and "Startup lock taken" not in py.tail() and py.proc.poll() is None:
            time.sleep(0.05)
        rs = Rust(RACE_DB, False, port=RS2_PORT)
    else:
        rs = Rust(RACE_DB, False, port=RS2_PORT)
        py = Python(RACE_DB, False)
    try:
        py.wait_ready()
        rs.wait_ready()
        GRAYLOG.wait_for(4, timeout=30)
        snap = snapshot(RACE_DB)
        counts = {t: len(v) for t, v in snap["rows"].items()}
        check(
            "one set of rows",
            counts
            == {
                "connectors": 18,
                "role": 5,
                "user": 2,
                "available_integrations": 13,
                "available_integrations_auth_keys": 53,
                "available_network_connectors": 3,
                "available_network_connectors_keys": 7,
                "notification_template": 9,
                "customer_portal_settings": 1,
                "scheduled_job_metadata": 12,
                "alembic_version": 1,
            },
            str(counts),
        )
        check("one schema", schema(RACE_DB) == schema(RS_DB))
        h = history(RACE_DB)
        expected = "adopted" if python_first else "applied"
        check(
            f"the baseline recorded once: {expected} ({'after Python' + chr(39) + 's Alembic' if python_first else 'Python then finds the head'})",
            h is not None and [(r["version"], r["method"]) for r in h] == [(1, expected)],
            str(h),
        )
    finally:
        rs.stop() if rs.proc.poll() is None else None
        py.stop() if py.proc.poll() is None else None
        S3.take(), GRAYLOG.take()


def older_revision(production):
    print("\n== A database at an older Alembic revision", flush=True)
    fresh(OLD_DB)
    code = "from alembic import command; from alembic.config import Config; import sys; from app.db.db_session import SQLALCHEMY_DATABASE_URI as U; c = Config('alembic/alembic.ini'); c.set_main_option('sqlalchemy.url', U.replace('+aiomysql', '+pymysql')); c.set_main_option('script_location', 'alembic'); command.upgrade(c, sys.argv[1])"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "MYSQL_URL": f"{HOST}:{PORT}/{OLD_DB}?",
        "MYSQL_USER": USER,
        "MYSQL_PASSWORD": PASSWORD,
        "MYSQL_ROOT_PASSWORD": ROOT_PASSWORD,
        "JWT_SECRET": JWT_SECRET,
    }
    subprocess.run([PYTHON, "-c", code, OLDER], cwd=BACKEND, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    before = schema(OLD_DB)
    rs = Rust(OLD_DB, False)
    code_ = rs.wait_exit(timeout=60)
    text = rs.tail()
    check("Rust refuses it and exits", code_ != 0, str(code_))
    check("the refusal names the revision and what to do", OLDER in text and "last release of the Python backend" in text, text[-600:])
    check("the refused database is untouched", schema(OLD_DB) == before and history(OLD_DB) is None)
    S3_STATE["buckets"] = set()
    run_python(OLD_DB, False)
    S3.take(), GRAYLOG.take()
    check(
        "the Python backend's start upgrades it to the head",
        query(OLD_DB, "SELECT version_num FROM alembic_version") == [{"version_num": HEAD}],
    )
    upgraded = schema(OLD_DB)
    run_rust(OLD_DB, False)
    S3.take(), GRAYLOG.take()
    check(
        "Rust then adopts it",
        [(h["version"], h["method"]) for h in history(OLD_DB) or []] == [(1, "adopted")] and schema(OLD_DB) == upgraded,
        str(history(OLD_DB)),
    )
    check("an upgraded database has the baseline's schema", upgraded == schema(RS_DB), diff(upgraded, schema(RS_DB)))


def production_bootstrap():
    print("\n== ENVIRONMENT=PRODUCTION: the database and its user through root", flush=True)
    boot_password = "boot-pass-'quoted'"
    # Python makes sure of `copilot` (database and user), whatever MYSQL_USER names, then connects
    # as MYSQL_USER: with a user that does not exist yet, its start fails (§4: "Python fails, Rust
    # works"). Its root connection needs the database it is pointed at, which root makes first.
    server_sql(
        f"DROP DATABASE IF EXISTS `{BOOT_DB}`",
        f"DROP USER IF EXISTS '{BOOT_USER}'@'%'",
        f"CREATE DATABASE `{BOOT_DB}`",
        user="root",
        password=ROOT_PASSWORD,
    )
    py = Python(BOOT_DB, True, user=BOOT_USER, password=boot_password)
    try:
        line = py._line(120)
        py.proc.wait(timeout=60)
    finally:
        py.kill()
    check(
        "Python's start with that user fails (it created `copilot`'s, not this one)",
        line != "READY" and py.proc.returncode != 0 and not query_root(f"SELECT user FROM mysql.user WHERE user = '{BOOT_USER}'"),
        f"{line!r} {py.proc.returncode}\n{py.tail()[-800:]}",
    )
    server_sql(f"DROP DATABASE IF EXISTS `{BOOT_DB}`", user="root", password=ROOT_PASSWORD)
    S3_STATE["buckets"] = set()
    rs = Rust(BOOT_DB, True, user=BOOT_USER, password=boot_password)
    try:
        rs.wait_ready()
        conn = connect(BOOT_DB, user=BOOT_USER, password=boot_password)
        conn.close()
        grants = [list(r.values())[0] for r in query_root(f"SHOW GRANTS FOR '{BOOT_USER}'@'%'")]
        check(
            "the user is created and granted the database",
            f"GRANT ALL PRIVILEGES ON `{BOOT_DB}`.* TO `{BOOT_USER}`@`%`" in grants,
            str(grants),
        )
        check(
            "the schema and the rows follow on the database root made",
            history(BOOT_DB) is not None and len(snapshot(BOOT_DB)["rows"]["connectors"]) == 18,
        )
    finally:
        rs.stop() if rs.proc.poll() is None else None
        S3.take(), GRAYLOG.take()


def query_root(statement):
    conn = connect(user="root", password=ROOT_PASSWORD)
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(statement)
            return list(cur.fetchall())
    finally:
        conn.close()


def cleanup():
    for db in DATABASES:
        try:
            server_sql(f"DROP DATABASE IF EXISTS `{db}`")
        except pymysql.MySQLError as e:
            print(f"  cleanup: {db}: {e}")
    if root_works():
        server_sql(f"DROP DATABASE IF EXISTS `{BOOT_DB}`", f"DROP USER IF EXISTS '{BOOT_USER}'@'%'", user="root", password=ROOT_PASSWORD)
    shutil.rmtree(PERF_DIR, ignore_errors=True)
    shutil.rmtree(RUST_CWD, ignore_errors=True)


def main():
    global S3, GRAYLOG
    S3 = Recorder(S3_PORT, s3_handle)
    GRAYLOG = Recorder(GRAYLOG_PORT, graylog_handle)
    production = root_works()
    if not production:
        skip("ENVIRONMENT=PRODUCTION", f"root cannot log in at {HOST}:{PORT}; set STARTUP_PARITY_ROOT_PASSWORD")
    try:
        py_stopped, rs_stopped, py_buckets, rs_buckets, py_rules, rs_rules = first_start(production)
        py_stopped, rs_stopped = second_start(production, py_stopped, rs_stopped, py_buckets, rs_buckets, py_rules, rs_rules)
        cross_starts(production, py_stopped, rs_stopped)
        race(python_first=False)
        race(python_first=True)
        older_revision(production)
        if production:
            production_bootstrap()
    finally:
        cleanup()
        S3.server.shutdown()
        GRAYLOG.server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + (f" ({len(skipped)} skipped)" if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
