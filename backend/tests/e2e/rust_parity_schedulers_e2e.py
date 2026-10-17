"""Parity of the Rust scheduler port (`crates/copilot-scheduler`) — NOT collected by pytest.

Run by `scripts/rust-parity.sh` (or alone with `PARITY_SUITES=tests/e2e/rust_parity_schedulers_e2e.py`).

The Scheduler routes act on APScheduler, which lives in the Python process, so the Python side
here is the real router served by uvicorn (in a thread) over a real `AsyncIOScheduler` on the
`apscheduler_jobs` store — started *paused*, so no job ever fires on its own during the run. Two Rust
processes answer the same requests:

* the suite's shared binary (`RUST_BASE_URL`, no legacy backend): the reads it answers from the
  job store itself — list, one job, next run — compared response by response;
* a second binary this suite starts with the uvicorn app as its legacy backend and
  `COPILOT_RS_JOBS=prune_audit_log`: the hand-over. Forwarded writes, pause/start carrying the
  `enabled` flag, a manual run executed by Rust, the cross-process run lock (Python's guard and
  Rust's manual run both refuse while it is held), and the Python guard skipping a handed-over job.

Deliberate differences are asserted as such (see RUST_MIGRATION.md §4).
"""

import asyncio
import contextlib
import datetime
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["AUDIT_LOG_RETENTION_DAYS"] = "36500"  # a century: only the suite's 1900 rows are old

import httpx  # noqa: E402
import rust_parity_e2e as base  # noqa: E402
import uvicorn  # noqa: E402
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore  # noqa: E402
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

check, token, results = base.check, base.token, base.results
SFX = uuid.uuid4().hex[:6]
ADMIN, ANALYST, PORTAL = f"sch_admin{SFX}", f"sch_analyst{SFX}", f"sch_portal{SFX}"
PRUNE, DRAINER = "prune_audit_log", "invoke_palace_lesson_drainer"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
LOCK_SQL = "SELECT GET_LOCK(CONCAT('copilot_job:', SHA1(CONCAT(DATABASE(), '/', :j))), 0)"
UNLOCK_SQL = "SELECT RELEASE_LOCK(CONCAT('copilot_job:', SHA1(CONCAT(DATABASE(), '/', :j))))"

# (job id, function name, minutes, paused, metadata: None or (enabled, interval, description, last_success))
JOBS = [
    (PRUNE, PRUNE, 1440, False, (True, 1440, "Prunes audit_log entries", None)),
    (DRAINER, DRAINER, 2, False, (True, 2, "Drains palace lessons", "2026-01-02 03:04:05")),
    (f"sch_agent{SFX}", "agent_sync", 15, False, (True, 15, "Synchronizes agents", None)),
    (f"sch_agent2{SFX}", "agent_sync", 15, False, (True, 15, "Second agent sync", None)),
    (f"sch_renamed{SFX}", "invoke_carbonblack_integration_collection", 30, False, None),
    (f"sch_paused{SFX}", "refresh_sidebar_health", 6, True, (False, 6, "Paused one", "2026-03-04 05:06:07")),
    (f"sch_bare_paused{SFX}", "refresh_sidebar_indicators", 4, True, None),
]
OUR_IDS = [j[0] for j in JOBS] + [f"sch_add_{tag}{SFX}" for tag in ("py", "rs")]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(text(statement), params)


def scalar(statement, **params):
    with sync_engine.connect() as conn:
        return conn.execute(text(statement), params).scalar()


def cleanup():
    for job_id in OUR_IDS:
        sql("DELETE FROM apscheduler_jobs WHERE id = :i", i=job_id)
        sql("DELETE FROM scheduled_job_metadata WHERE job_id = :i", i=job_id)
    sql("DELETE FROM audit_log WHERE entity_id LIKE :m", m=f"sch{SFX}%")


def seed():
    cleanup()
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    for job_id, _, _, _, meta in JOBS:
        if meta is None:
            continue
        enabled, minutes, description, last_success = meta
        sql(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, enabled, job_description) "
            "VALUES (:j, :l, :m, NULL, :e, :d)",
            j=job_id,
            l=last_success,
            m=minutes,
            e=enabled,
            d=description,
        )


def audit_marker(tag):
    marker = f"sch{SFX}{tag}"
    sql(
        "INSERT INTO audit_log (timestamp, actor_username, action, entity_type, entity_id, result) "
        "VALUES ('1900-01-01 00:00:00', 'parity', 'case.create', 'case', :m, 'success')",
        m=marker,
    )
    return marker


def marker_left(marker):
    return scalar("SELECT COUNT(*) FROM audit_log WHERE entity_id = :m", m=marker)


def enabled_of(job_id):
    return scalar("SELECT enabled FROM scheduled_job_metadata WHERE job_id = :j ORDER BY id LIMIT 1", j=job_id)


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.schedulers import scheduler as scheduler_module
    from app.schedulers.routes.scheduler import scheduler_router

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        # The real scheduler on the real store, paused: jobs are stored and listed, none fires.
        scheduler = AsyncIOScheduler(event_loop=asyncio.get_running_loop())
        scheduler.configure(jobstores={"default": SQLAlchemyJobStore(engine=sync_engine)})
        scheduler.start(paused=True)
        scheduler_module.scheduler_instance = scheduler
        for job_id, function, minutes, paused, _ in JOBS:
            scheduler.add_job(
                scheduler_module.get_function_by_name(function),
                "interval",
                minutes=minutes,
                id=job_id,
                replace_existing=True,
                coalesce=True,
                max_instances=1,
            )
            if paused:
                scheduler.pause_job(job_id)
        yield
        scheduler.shutdown(wait=False)

    test_router = APIRouter()

    @test_router.post("/__test/tick/{job_id}")
    async def scheduled_tick(job_id: str):
        """What APScheduler does on a fire: call the function (outside a manual run)."""
        from app.schedulers.handover import JOB_SKIPPED

        result = await scheduler_module.get_function_by_name(job_id)()
        return {"outcome": "skipped" if result is JOB_SKIPPED else "ran"}

    api = APIRouter(prefix="/api")
    api.include_router(scheduler_router, prefix="/scheduler")
    app = FastAPI(redirect_slashes=False, lifespan=lifespan)
    app.include_router(api)
    app.include_router(test_router)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_python(port):
    server = uvicorn.Server(uvicorn.Config(build_python_app(), host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError("uvicorn did not start")


def start_rust(port, legacy_port):
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
        "COPILOT_PORT": str(port),
        "COPILOT_LEGACY_URL": f"http://127.0.0.1:{legacy_port}",
        "COPILOT_RS_JOBS": PRUNE,
        "AUDIT_LOG_RETENTION_DAYS": os.environ["AUDIT_LOG_RETENTION_DAYS"],
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
    raise RuntimeError("the second Rust instance did not start")


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


def main():
    seed()
    py_port, rs2_port = free_port(), free_port()
    start_python(py_port)
    rs2_proc = start_rust(rs2_port, py_port)
    py = httpx.Client(base_url=f"http://127.0.0.1:{py_port}", timeout=60)
    rs = httpx.Client(base_url=base.RUST, timeout=60)
    rs2 = httpx.Client(base_url=f"http://127.0.0.1:{rs2_port}", timeout=60)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    def same(name, method, path, tok=None, other=rs, **kw):
        r1 = py.request(method, path, headers=H(tok), **kw)
        r2 = other.request(method, path, headers=H(tok), **kw)
        b1, b2 = body_of(r1), body_of(r2)
        check(
            f"{name} [{r1.status_code}]",
            r1.status_code == r2.status_code and b1 == b2,
            f"python {r1.status_code} {json.dumps(b1)[:700]}\n        rust   {r2.status_code} {json.dumps(b2)[:700]}",
        )
        return r1, r2

    try:
        print("\n=== scheduler reads (Rust from the job store) ===")
        same("list", "GET", "/api/scheduler", t_admin)
        same("list, analyst", "GET", "/api/scheduler", t_analyst)
        same("list, search", "GET", f"/api/scheduler?search=SCH_AGENT{SFX}", t_admin)
        same("list, search matches names", "GET", "/api/scheduler?search=agent_sync", t_admin)
        same("list, search across id and name", "GET", f"/api/scheduler?search={SFX} refresh", t_admin)
        same("list, empty search", "GET", "/api/scheduler?search=&limit=3", t_admin)
        same("list, limit", "GET", f"/api/scheduler?search={SFX}&limit=2", t_admin)
        same("list, limit 0", "GET", "/api/scheduler?limit=0", t_admin)
        same("list, limit 1001", "GET", "/api/scheduler?limit=1001", t_admin)
        same("list, limit x", "GET", "/api/scheduler?limit=x&search=a", t_admin)
        same("list, no token", "GET", "/api/scheduler")
        same("list, bad token", "GET", "/api/scheduler", "not-a-jwt")
        same("list, portal user", "GET", "/api/scheduler", t_portal)
        same("list, trailing slash", "GET", "/api/scheduler/", t_admin)
        for job_id, *_ in JOBS:
            same(f"job {job_id}", "GET", f"/api/scheduler/{job_id}", t_admin)
            same(f"next run {job_id}", "GET", f"/api/scheduler/next_run/{job_id}", t_analyst)
        same("job, unknown", "GET", "/api/scheduler/no-such-job", t_admin)
        same("job, other case", "GET", f"/api/scheduler/SCH_AGENT{SFX}", t_admin)
        same("job, portal user", "GET", f"/api/scheduler/{PRUNE}", t_portal)
        same("next run, unknown", "GET", "/api/scheduler/next_run/no-such-job", t_admin)
        same("next run, no token", "GET", f"/api/scheduler/next_run/{PRUNE}")
        same("run, no token", "POST", f"/api/scheduler/jobs/run/{PRUNE}")
        same("run, unknown job", "POST", "/api/scheduler/jobs/run/no-such-job", t_admin)
        same("start, portal user", "POST", f"/api/scheduler/start/{PRUNE}", t_portal)

        print("\n=== through a Rust instance in front of Python (forwarded writes) ===")
        same("list, via the proxy instance", "GET", "/api/scheduler", t_admin, other=rs2)
        r1 = py.post(f"/api/scheduler/add?job_id=sch_add_py{SFX}&function_name=agent_sync&time_interval=9", headers=H(t_admin))
        r2 = rs2.post(f"/api/scheduler/add?job_id=sch_add_rs{SFX}&function_name=agent_sync&time_interval=9", headers=H(t_admin))
        check(f"add [{r1.status_code}]", (r1.status_code, r1.json()) == (r2.status_code, r2.json()), f"{r1.text} / {r2.text}")
        same("add, unknown function", "POST", "/api/scheduler/add?job_id=x&function_name=nope&time_interval=1", t_admin, other=rs2)
        same("add, missing interval", "POST", "/api/scheduler/add?job_id=x&function_name=agent_sync", t_admin, other=rs2)
        for tag, client in (("py", py), ("rs", rs2)):
            r = client.put(f"/api/scheduler/update/sch_add_{tag}{SFX}?time_interval=7", headers=H(t_admin))
            check(f"update via {tag} [{r.status_code}]", r.json() == {"success": True, "message": "Job updated successfully"}, r.text)
        same("job after update", "GET", f"/api/scheduler/sch_add_py{SFX}", t_admin)
        check(
            "  both updates reached APScheduler and the metadata",
            [scalar("SELECT time_interval FROM scheduled_job_metadata WHERE job_id = :j", j=f"sch_add_{t}{SFX}") for t in ("py", "rs")]
            == [7, 7],
        )
        # pause/start of a job Rust cannot run: forwarded, the flag untouched.
        for action in ("pause", "start"):
            r1 = py.post(f"/api/scheduler/{action}/sch_agent{SFX}", headers=H(t_analyst))
            r2 = rs2.post(f"/api/scheduler/{action}/sch_agent2{SFX}", headers=H(t_analyst))
            check(f"{action}, a Python-only job [{r1.status_code}]", (r1.status_code, r1.json()) == (r2.status_code, r2.json()), r2.text)
        check("  its enabled flag is untouched", enabled_of(f"sch_agent2{SFX}") == 1)
        same("pause, unknown job", "POST", "/api/scheduler/pause/no-such-job", t_admin, other=rs2)
        same("start, unknown job", "POST", "/api/scheduler/start/no-such-job", t_admin, other=rs2)
        for tag, client in (("py", py), ("rs", rs2)):
            r = client.delete(f"/api/scheduler/sch_add_{tag}{SFX}", headers=H(t_admin))
            check(f"delete via {tag} [{r.status_code}]", r.json() == {"success": True, "message": "Job deleted successfully"}, r.text)

        print("\n=== the hand-over (prune_audit_log) ===")
        m = audit_marker("a")
        r = py.post(f"/__test/tick/{PRUNE}")
        check("Python's scheduled tick runs a job its row gives it", r.json() == {"outcome": "ran"} and marker_left(m) == 0, r.text)
        # A manual run of a job APScheduler owns: Rust forwards it.
        m = audit_marker("b")
        r1, r2 = same("run, owned by APScheduler (forwarded)", "POST", f"/api/scheduler/jobs/run/{PRUNE}", t_admin, other=rs2)
        check("  ran in Python", marker_left(m) == 0)
        # Pause through Rust: APScheduler pauses it, and the row is disabled.
        r = rs2.post(f"/api/scheduler/pause/{PRUNE}", headers=H(t_admin))
        check(
            "pause through Rust [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job paused successfully"}),
            r.text,
        )
        check("  the row is disabled: the job is Rust's", enabled_of(PRUNE) == 0)
        same("job, once handed over", "GET", f"/api/scheduler/{PRUNE}", t_admin)
        same("next run, handed over, from the job store", "GET", f"/api/scheduler/next_run/{PRUNE}", t_admin)
        m = audit_marker("c")
        r = py.post(f"/__test/tick/{PRUNE}")
        check("Python's scheduled tick skips a handed-over job", r.json() == {"outcome": "skipped"} and marker_left(m) == 1, r.text)
        r1 = rs2.post(f"/api/scheduler/jobs/run/{PRUNE}", headers=H(t_admin))
        check(
            f"run, handed over: executed by Rust [{r1.status_code}]",
            (r1.status_code, r1.json()) == (200, {"success": True, "message": "Job executed successfully", "result": None})
            and marker_left(m) == 0,
            r1.text,
        )
        m = audit_marker("d")
        r2 = py.post(f"/api/scheduler/jobs/run/{PRUNE}", headers=H(t_admin))
        check(f"  the same answer as Python's manual run [{r2.status_code}]", r1.json() == r2.json() and marker_left(m) == 0, r2.text)
        check(
            "  a manual prune stamps no last_success on either side",
            scalar("SELECT last_success FROM scheduled_job_metadata WHERE job_id = :j", j=PRUNE) is None,
        )
        # The run lock held elsewhere: a scheduled tick skips, a manual run waits, then refuses.
        with sync_engine.connect() as holder:
            check("hold the run lock from another session", holder.execute(text(LOCK_SQL), {"j": PRUNE}).scalar() == 1)
            sql("UPDATE scheduled_job_metadata SET enabled = 1 WHERE job_id = :j", j=PRUNE)
            m = audit_marker("e")
            r = py.post(f"/__test/tick/{PRUNE}")
            check(
                "Python's scheduled tick skips while the lock is held",
                r.json() == {"outcome": "skipped"} and marker_left(m) == 1,
                r.text,
            )
            sql("UPDATE scheduled_job_metadata SET enabled = 0 WHERE job_id = :j", j=PRUNE)
            r1 = py.post(f"/api/scheduler/jobs/run/{PRUNE}", headers=H(t_admin))
            r2 = rs2.post(f"/api/scheduler/jobs/run/{PRUNE}", headers=H(t_admin))
            check(
                f"run while the lock is held: both wait, then refuse alike [{r1.status_code}]",
                (r1.status_code, r1.json())
                == (r2.status_code, r2.json())
                == (
                    500,
                    {"success": False, "message": "Job prune_audit_log is already running; try again when it has finished"},
                ),
                f"{r1.text} / {r2.text}",
            )
            check("  nothing ran", marker_left(m) == 1)
            holder.execute(text(UNLOCK_SQL), {"j": PRUNE})
        # Start through Rust hands it back.
        r = rs2.post(f"/api/scheduler/start/{PRUNE}", headers=H(t_admin))
        check(
            "start through Rust [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job started successfully"}),
            r.text,
        )
        check("  the row is enabled again: APScheduler's", enabled_of(PRUNE) == 1)
        same("next run, handed back", "GET", f"/api/scheduler/next_run/{PRUNE}", t_admin, other=rs2)
        r = py.post(f"/__test/tick/{PRUNE}")
        check("Python's scheduled tick runs it again", r.json() == {"outcome": "ran"} and marker_left(m) == 0, r.text)

        print("\n=== differences by design ===")
        # Pause through Python leaves the flag alone (the Scheduler UI then shows the job enabled
        # again after a reload); through Rust it is the hand-over switch.
        r1 = py.post(f"/api/scheduler/pause/{DRAINER}", headers=H(t_admin))
        check("pause, Python: enabled flag untouched", r1.json()["success"] is True and enabled_of(DRAINER) == 1, r1.text)
        py.post(f"/api/scheduler/start/{DRAINER}", headers=H(t_admin))
        r2 = rs2.post(f"/api/scheduler/pause/{PRUNE}", headers=H(t_admin))
        check("pause, Rust: the flag follows (hand-over)", r2.json() == r1.json() and enabled_of(PRUNE) == 0, r2.text)
        # A job Rust runs: its next run is Rust's, where APScheduler's paused copy has none.
        r1 = py.get(f"/api/scheduler/next_run/{PRUNE}", headers=H(t_admin))
        r2 = rs2.get(f"/api/scheduler/next_run/{PRUNE}", headers=H(t_admin))
        at = r2.json().get("next_run_time", "") if r2.status_code == 200 else ""
        ahead = None
        if at:
            ahead = (
                datetime.datetime.fromisoformat(at.replace("Z", "+00:00")) - datetime.datetime.now(datetime.timezone.utc)
            ).total_seconds()
        check(
            f"next run of a job Rust runs: Rust's next run [{r1.status_code} / {r2.status_code}]",
            r1.status_code == 400 and r2.status_code == 200 and at.endswith("Z") and ahead is not None and 0 < ahead <= 1440 * 60,
            f"python {r1.text}\n        rust   {r2.text}",
        )
        rs2.post(f"/api/scheduler/start/{PRUNE}", headers=H(t_admin))
    finally:
        rs2_proc.terminate()
        try:
            rs2_proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            rs2_proc.kill()
        cleanup()

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
