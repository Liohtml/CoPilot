"""Parity of the Rust scheduler port (`crates/copilot-scheduler`) — NOT collected by pytest.

Run by `scripts/rust-parity.sh` (or alone with `PARITY_SUITES=tests/e2e/rust_parity_schedulers_e2e.py`).

The Scheduler routes act on APScheduler, which lives in the Python process, so the Python side
here is the real router (with Mimecast's scheduler router) served by uvicorn (in a thread) over a
real `AsyncIOScheduler` on the `apscheduler_jobs` store — started *paused*, so no job ever fires on
its own during the run. Three Rust processes answer the same requests:

* the suite's shared binary (`RUST_BASE_URL`, no legacy backend): the reads it answers from the
  job store itself — list, one job, next run — compared response by response;
* a second binary this suite starts with the uvicorn app as its legacy backend and
  `COPILOT_RS_JOBS=prune_audit_log` (the hand-over): every write route answered in Rust, only
  APScheduler's own calls handed to the app's `/apscheduler_ops` — twin jobs written through
  Python and through Rust end with the same responses, `scheduled_job_metadata` rows and
  `apscheduler_jobs` states; a manual run executed by Rust; the cross-process run lock; the Python
  guard skipping a handed-over job, the six jobs this wave made Rust-capable included;
* a third binary with `COPILOT_SCHEDULER_OWNER=rust` and no legacy backend (the ownership): it runs
  a job from its row on its own (the same effect as Python's tick), Pause/Start/the writes edit the
  rows only, the job store is never touched; `copilot doctor` reads APScheduler's store.

Deliberate differences are asserted as such (see RUST_MIGRATION.md §4).
"""

import contextlib
import datetime
import json
import os
import pickle
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
SCOPED = f"sch_scoped{SFX}"
CUSTOMER = f"schc{SFX}"
PRUNE, DRAINER = "prune_audit_log", "invoke_palace_lesson_drainer"
HUNTRESS, DUO, CATO = "invoke_huntress_integration_collect", "invoke_duo_integration_collect", "invoke_cato_integration_collect"
MIMECAST, MIMECAST_TTP = "invoke_mimecast_integration", "invoke_mimecast_integration_ttp"
RESIZE, RESIZE_ALIAS = "resize_wazuh_index_fields", "wazuh_index_fields_resize"
REFRESHERS = ("refresh_catalog_caches", "refresh_wazuh_rules_cache", "refresh_sidebar_health", "refresh_sidebar_indicators")
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
LOCK_SQL = "SELECT GET_LOCK(CONCAT('copilot_job:', SHA1(CONCAT(DATABASE(), '/', :j))), 0)"
UNLOCK_SQL = "SELECT RELEASE_LOCK(CONCAT('copilot_job:', SHA1(CONCAT(DATABASE(), '/', :j))))"
PY_PORT = int(os.environ.get("SCHEDULERS_PARITY_PY_PORT", "7200"))
RS2_PORT = int(os.environ.get("SCHEDULERS_PARITY_RUST_PORT", "7201"))
OWNER_PORT = int(os.environ.get("SCHEDULERS_PARITY_RUST_OWNER_PORT", "7202"))

# (job id, function name, minutes, paused, metadata: None or (enabled, interval, description, last_success))
JOBS = [
    (PRUNE, PRUNE, 1440, False, (True, 1440, "Prunes audit_log entries", None)),
    (DRAINER, DRAINER, 2, False, (True, 2, "Drains palace lessons", "2026-01-02 03:04:05")),
    (f"sch_agent{SFX}", "agent_sync", 15, False, (True, 15, "Synchronizes agents", None)),
    (f"sch_agent2{SFX}", "agent_sync", 15, False, (True, 15, "Second agent sync", None)),
    (f"sch_renamed{SFX}", "invoke_carbonblack_integration_collection", 30, False, None),
    (f"sch_paused{SFX}", "refresh_sidebar_health", 6, True, (False, 6, "Paused one", "2026-03-04 05:06:07")),
    (f"sch_bare_paused{SFX}", "refresh_sidebar_indicators", 4, True, None),
    (f"sch_bare_py{SFX}", "agent_sync", 4, True, None),
    (f"sch_bare_rs{SFX}", "agent_sync", 4, True, None),
    (CATO, CATO, 5, False, (True, 5, "Cato", None)),
    (RESIZE_ALIAS, RESIZE, 1, False, None),
]
REAL_IDS = [PRUNE, DRAINER, HUNTRESS, DUO, CATO, MIMECAST, MIMECAST_TTP, RESIZE, RESIZE_ALIAS, *REFRESHERS]
OUR_IDS = [j[0] for j in JOBS] + [f"sch_{tag}{SFX}" for tag in ("add_py", "add_rs", "w_py", "w_rs", "neg_py", "overdue")]


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(text(statement), params)


def scalar(statement, **params):
    with sync_engine.connect() as conn:
        return conn.execute(text(statement), params).scalar()


def forget(job_id):
    sql("DELETE FROM apscheduler_jobs WHERE id = :i", i=job_id)
    sql("DELETE FROM scheduled_job_metadata WHERE job_id = :i", i=job_id)


def cleanup():
    for job_id in OUR_IDS + REAL_IDS:
        forget(job_id)
    sql("DELETE FROM audit_log WHERE entity_id LIKE :m", m=f"sch{SFX}%")
    sql("DELETE FROM user_customer_access WHERE customer_code = :c", c=CUSTOMER)
    sql("DELETE FROM customers WHERE customer_code = :c", c=CUSTOMER)


def meta(job_id, enabled, minutes, description=None, last_success=None):
    sql(
        "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, enabled, job_description) "
        "VALUES (:j, :l, :m, NULL, :e, :d)",
        j=job_id,
        l=last_success,
        m=minutes,
        e=enabled,
        d=description,
    )


def seed():
    cleanup()
    sql(
        "INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :n, UTC_TIMESTAMP())",
        c=CUSTOMER,
        n=f"{CUSTOMER} Corp",
    )
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (SCOPED, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'p@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
    sql(
        "INSERT INTO user_customer_access (user_id, customer_code, created_at) SELECT id, :c, UTC_TIMESTAMP() FROM `user` WHERE username = :n",
        c=CUSTOMER,
        n=SCOPED,
    )
    for job_id, _, _, _, m in JOBS:
        if m is not None:
            meta(job_id, *m)


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


def meta_rows(job_id):
    with sync_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT time_interval, extra_data, enabled, job_description, last_success IS NOT NULL "
                "FROM scheduled_job_metadata WHERE job_id = :j ORDER BY id",
            ),
            {"j": job_id},
        ).fetchall()
    return [tuple(r) for r in rows]


def store_state(job_id):
    """What APScheduler stored for the job, but its id and times (the twins differ in both)."""
    with sync_engine.connect() as conn:
        row = conn.execute(text("SELECT next_run_time, job_state FROM apscheduler_jobs WHERE id = :i"), {"i": job_id}).first()
    if row is None:
        return None
    state = pickle.loads(row[1])  # the suite's own store: trusted
    trigger = state["trigger"]
    return {
        "func": state["func"],
        "name": state["name"],
        "args": list(state["args"]),
        "kwargs": state["kwargs"],
        "executor": state["executor"],
        "coalesce": state["coalesce"],
        "max_instances": state["max_instances"],
        "misfire_grace_time": state["misfire_grace_time"],
        "trigger": type(trigger).__name__,
        "interval": trigger.interval.total_seconds(),
        "paused": state["next_run_time"] is None,
        "column_paused": row[0] is None,
    }


def build_python_app():
    from app.integrations.mimecast.routes.provision import (
        integration_mimecast_scheduler_router,
    )
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.schedulers import scheduler as scheduler_module
    from app.schedulers.routes.scheduler import scheduler_router

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        import asyncio

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
        """What APScheduler does on a fire of the stored job: call its function (outside a manual run)."""
        from app.schedulers.handover import JOB_SKIPPED

        job = scheduler_module.scheduler_instance.get_job(job_id)
        result = await job.func()
        return {"outcome": "skipped" if result is JOB_SKIPPED else "ran"}

    @test_router.post("/__test/tick_fn/{function_name}")
    async def function_tick(function_name: str):
        """A scheduled fire of a job no stored job holds: the guarded function itself, outside a manual run."""
        from app.schedulers.handover import JOB_SKIPPED

        result = await scheduler_module.get_function_by_name(function_name)()
        return {"outcome": "skipped" if result is JOB_SKIPPED else "ran"}

    @test_router.post("/__test/repair_cato")
    async def repair_cato():
        from sqlalchemy.ext.asyncio import AsyncSession

        from app.db.db_session import async_engine

        async with AsyncSession(async_engine) as session:
            await scheduler_module._repair_cato_row(session)
        return {"done": True}

    @test_router.post("/__test/overdue/{job_id}")
    async def overdue(job_id: str):
        """A scheduled job whose next run time is an hour behind the clock (APScheduler idle)."""
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        scheduler_module.scheduler_instance.add_job(
            scheduler_module.get_function_by_name("agent_sync"),
            "interval",
            minutes=5,
            id=job_id,
            replace_existing=True,
            next_run_time=past,
        )
        return {"done": True}

    api = APIRouter(prefix="/api")
    api.include_router(scheduler_router, prefix="/scheduler")
    api.include_router(integration_mimecast_scheduler_router, prefix="/mimecast")
    app = FastAPI(redirect_slashes=False, lifespan=lifespan)
    app.include_router(api)
    app.include_router(test_router)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_python(port):
    server = uvicorn.Server(uvicorn.Config(build_python_app(), host="127.0.0.1", port=port, log_level="critical", lifespan="on"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError("uvicorn did not start")


def rust_env(port, extra):
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        # The catalog caches (and the sidebar) load on demand: no warm-up, no timers.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_PORT": str(port),
        "AUDIT_LOG_RETENTION_DAYS": os.environ["AUDIT_LOG_RETENTION_DAYS"],
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    env.update(extra)
    return env


def binary():
    return os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))


def start_rust(port, extra):
    proc = subprocess.Popen([binary(), "--root", "/nonexistent", "serve"], env=rust_env(port, extra))
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"the Rust instance on {port} did not start")


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()


def doctor(extra):
    out = subprocess.run(
        [binary(), "--root", "/nonexistent", "doctor"],
        env=rust_env(OWNER_PORT, extra),
        capture_output=True,
        text=True,
        timeout=180,
    )
    return [line for line in out.stdout.splitlines() if line.startswith("scheduler")]


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.text


def wait_until(predicate, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


def main():
    seed()
    start_python(PY_PORT)
    rs2_proc = start_rust(RS2_PORT, {"COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}", "COPILOT_RS_JOBS": PRUNE})
    owner_proc = None
    py = httpx.Client(base_url=f"http://127.0.0.1:{PY_PORT}", timeout=60)
    rs = httpx.Client(base_url=base.RUST, timeout=60)
    rs2 = httpx.Client(base_url=f"http://127.0.0.1:{RS2_PORT}", timeout=60)
    owner = httpx.Client(base_url=f"http://127.0.0.1:{OWNER_PORT}", timeout=60)
    t_admin, t_analyst, t_portal = token(ADMIN, ["admin"]), token(ANALYST, ["analyst"]), token(PORTAL, ["customer_user"])
    t_scoped = token(SCOPED, ["analyst"])
    H = lambda t: {"Authorization": f"Bearer {t}"} if t else {}  # noqa: E731

    def same(name, method, path, tok=None, other=rs, headers=None, **kw):
        headers = {**H(tok), **(headers or {})}
        r1 = py.request(method, path, headers=headers, **kw)
        r2 = other.request(method, path, headers=headers, **kw)
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

        print("\n=== the writes, answered by Rust (APScheduler's part handed to Python) ===")
        same("list, through the hand-over instance", "GET", "/api/scheduler", t_admin, other=rs2)
        same("add, unknown function", "POST", "/api/scheduler/add?job_id=x&function_name=nope&time_interval=1", t_admin, other=rs2)
        same("add, missing interval", "POST", "/api/scheduler/add?job_id=x&function_name=agent_sync", t_admin, other=rs2)
        same("add, nothing", "POST", "/api/scheduler/add", t_admin, other=rs2)
        same("add, interval x", "POST", "/api/scheduler/add?job_id=x&function_name=agent_sync&time_interval=x", t_admin, other=rs2)
        same(
            "add, interval overflows timedelta",
            "POST",
            "/api/scheduler/add?job_id=x&function_name=agent_sync&time_interval=1440000000000",
            t_admin,
            other=rs2,
        )
        same(
            "add, interval overflows the date",
            "POST",
            "/api/scheduler/add?job_id=x&function_name=agent_sync&time_interval=1439999999999",
            t_admin,
            other=rs2,
        )
        same("add, no token", "POST", "/api/scheduler/add?job_id=x&function_name=agent_sync&time_interval=1", other=rs2)
        same("add, portal user", "POST", "/api/scheduler/add?job_id=x&function_name=agent_sync&time_interval=1", t_portal, other=rs2)
        check("  nothing was written", meta_rows("x") == [] and store_state("x") is None)
        same("update, not found", "PUT", "/api/scheduler/update/no-such-job?time_interval=5", t_admin, other=rs2)
        same("update, missing interval", "PUT", f"/api/scheduler/update/{PRUNE}", t_admin, other=rs2)
        same("delete, not found", "DELETE", "/api/scheduler/no-such-job", t_admin, other=rs2)
        same("pause, unknown job", "POST", "/api/scheduler/pause/no-such-job", t_admin, other=rs2)
        same("start, unknown job", "POST", "/api/scheduler/start/no-such-job", t_admin, other=rs2)
        same("delete, portal user", "DELETE", f"/api/scheduler/{PRUNE}", t_portal, other=rs2)

        # Twin jobs, one written through Python, one through Rust: every step's answer, rows and
        # stored APScheduler state alike.
        twins = {}
        for tag, client in (("py", py), ("rs", rs2)):
            jid = f"sch_w_{tag}{SFX}"
            steps = []
            for name, method, url in (
                ("add", "POST", f"/api/scheduler/add?job_id={jid}&function_name=agent_sync&time_interval=9&extra_data=e1"),
                ("add again (a second row)", "POST", f"/api/scheduler/add?job_id={jid}&function_name=agent_sync&time_interval=3"),
                ("update", "PUT", f"/api/scheduler/update/{jid}?time_interval=7"),
                ("update, interval overflows", "PUT", f"/api/scheduler/update/{jid}?time_interval=1440000000000"),
                ("pause", "POST", f"/api/scheduler/pause/{jid}"),
                ("update while paused", "PUT", f"/api/scheduler/update/{jid}?time_interval=8&extra_data=e2"),
                ("pause again", "POST", f"/api/scheduler/pause/{jid}"),
                ("start", "POST", f"/api/scheduler/start/{jid}"),
                ("delete (the first row)", "DELETE", f"/api/scheduler/{jid}"),
                ("delete again", "DELETE", f"/api/scheduler/{jid}"),
                ("update once gone", "PUT", f"/api/scheduler/update/{jid}?time_interval=5"),
            ):
                r = client.request(method, url, headers=H(t_admin))
                steps.append((name, r.status_code, body_of(r), store_state(jid), meta_rows(jid)))
            twins[tag] = steps
        for a, b in zip(twins["py"], twins["rs"]):
            check(f"twin {a[0]} [{a[1]}]", a[1:] == b[1:], f"python {a[1:]}\n        rust   {b[1:]}")
        for tag, client in (("py", py), ("rs", rs2)):
            jid = f"sch_bare_{tag}{SFX}"
            r = client.put(f"/api/scheduler/update/{jid}?time_interval=6", headers=H(t_admin))
            twins[f"bare_{tag}"] = (r.status_code, body_of(r), store_state(jid), meta_rows(jid))
        check(
            "update of a stored job without a row: rescheduled (unpaused), then the 500",
            twins["bare_py"] == twins["bare_rs"] and twins["bare_py"][0] == 500 and twins["bare_py"][2]["paused"] is False,
            f"{twins['bare_py']}\n        {twins['bare_rs']}",
        )
        r1 = py.post(f"/api/scheduler/add?job_id=sch_add_py{SFX}&function_name=agent_sync&time_interval=9", headers=H(t_admin))
        r2 = rs2.post(f"/api/scheduler/add?job_id=sch_add_rs{SFX}&function_name=agent_sync&time_interval=9", headers=H(t_admin))
        check(f"add [{r1.status_code}]", (r1.status_code, r1.json()) == (r2.status_code, r2.json()), f"{r1.text} / {r2.text}")
        check(
            "  the same stored job and row",
            store_state(f"sch_add_py{SFX}") == store_state(f"sch_add_rs{SFX}") is not None
            and meta_rows(f"sch_add_py{SFX}") == meta_rows(f"sch_add_rs{SFX}"),
        )
        # pause/start of a job Rust does not know by its id: APScheduler's, the flag untouched.
        for action in ("pause", "start"):
            r1 = py.post(f"/api/scheduler/{action}/sch_agent{SFX}", headers=H(t_analyst))
            r2 = rs2.post(f"/api/scheduler/{action}/sch_agent2{SFX}", headers=H(t_analyst))
            check(
                f"{action}, a job id Rust does not run [{r1.status_code}]",
                (r1.status_code, r1.json()) == (r2.status_code, r2.json()),
                r2.text,
            )
        check("  its enabled flag is untouched", enabled_of(f"sch_agent2{SFX}") == 1)
        check("  both stored jobs alike", store_state(f"sch_agent{SFX}") == store_state(f"sch_agent2{SFX}"))

        print("\n=== the hand-over (prune_audit_log) ===")
        m = audit_marker("a")
        r = py.post(f"/__test/tick/{PRUNE}")
        check("Python's scheduled tick runs a job its row gives it", r.json() == {"outcome": "ran"} and marker_left(m) == 0, r.text)
        m = audit_marker("b")
        r1 = rs2.post(f"/api/scheduler/jobs/run/{PRUNE}", headers=H(t_admin))
        check("run, APScheduler's schedule: executed by Rust", r1.status_code == 200 and marker_left(m) == 0, r1.text)
        m = audit_marker("b2")
        r2 = py.post(f"/api/scheduler/jobs/run/{PRUNE}", headers=H(t_admin))
        check(f"  the same answer as Python's manual run [{r2.status_code}]", r1.json() == r2.json() and marker_left(m) == 0, r2.text)
        r = rs2.post(f"/api/scheduler/pause/{PRUNE}", headers=H(t_admin))
        check(
            "pause through Rust [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job paused successfully"}),
            r.text,
        )
        check("  the row is disabled: the job is Rust's", enabled_of(PRUNE) == 0)
        check("  APScheduler paused its job", store_state(PRUNE)["paused"] is True)
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
        check(
            "  a manual prune stamps no last_success on either side",
            scalar("SELECT last_success FROM scheduled_job_metadata WHERE job_id = :j", j=PRUNE) is None,
        )
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
                == (500, {"success": False, "message": "Job prune_audit_log is already running; try again when it has finished"}),
                f"{r1.text} / {r2.text}",
            )
            check("  nothing ran", marker_left(m) == 1)
            holder.execute(text(UNLOCK_SQL), {"j": PRUNE})
        r = rs2.post(f"/api/scheduler/start/{PRUNE}", headers=H(t_admin))
        check(
            "start through Rust [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job started successfully"}),
            r.text,
        )
        check("  the row is enabled again: APScheduler's", enabled_of(PRUNE) == 1)
        check("  APScheduler resumed its job", store_state(PRUNE)["paused"] is False)
        same("next run, handed back", "GET", f"/api/scheduler/next_run/{PRUNE}", t_admin, other=rs2)
        r = py.post(f"/__test/tick/{PRUNE}")
        check("Python's scheduled tick runs it again", r.json() == {"outcome": "ran"} and marker_left(m) == 0, r.text)

        print("\n=== the six jobs this wave made Rust-capable ===")
        # Each one's deciding row disabled (handed over); Cato keeps its stored job, the others have none.
        for job_id in (*REFRESHERS, CATO, RESIZE):
            sql("DELETE FROM scheduled_job_metadata WHERE job_id = :j", j=job_id)
            meta(job_id, False, 5, "handed over")
        for job_id in REFRESHERS:
            # The tick is the guard's: a disabled row skips before the function does anything.
            r = py.post(f"/__test/tick_fn/{job_id}")
            check(f"Python's tick of a handed-over {job_id} is skipped", r.json() == {"outcome": "skipped"}, r.text)
        r = py.post(f"/__test/tick/{CATO}")
        check(f"Python's tick of a handed-over {CATO} is skipped", r.json() == {"outcome": "skipped"}, r.text)
        from app.schedulers import handover
        from app.schedulers import scheduler as scheduler_module

        for job_id in REFRESHERS:
            fn = scheduler_module.get_function_by_name(job_id)
            check(f"{job_id} is guarded by its own row", getattr(fn, "__rust_handover_job_id__", None) == job_id)
        r = py.post(f"/__test/tick/{RESIZE_ALIAS}")
        check(
            f"{RESIZE_ALIAS} is {RESIZE} under an old id: its tick follows {RESIZE}'s row",
            r.json() == {"outcome": "skipped"},
            r.text,
        )
        same(f"job {RESIZE_ALIAS} (its callable is {RESIZE})", "GET", f"/api/scheduler/{RESIZE_ALIAS}", t_admin)
        check("every job of get_function_by_name can be handed over", len(handover.RUST_CAPABLE_JOBS) == 29)
        # Cato, run by hand on both sides: the same answer and the same stamp.
        sql("UPDATE scheduled_job_metadata SET enabled = 1, last_success = NULL WHERE job_id = :j", j=CATO)
        r1 = py.post(f"/api/scheduler/jobs/run/{CATO}", headers=H(t_admin))
        stamped_py = meta_rows(CATO)[0][4]
        sql("UPDATE scheduled_job_metadata SET last_success = NULL WHERE job_id = :j", j=CATO)
        r2 = rs2.post(f"/api/scheduler/jobs/run/{CATO}", headers=H(t_admin))
        stamped_rs = meta_rows(CATO)[0][4]
        check(
            f"run {CATO}: the same answer, last_success stamped by both [{r1.status_code}]",
            (r1.status_code, body_of(r1)) == (r2.status_code, body_of(r2)) and stamped_py == stamped_rs == 1,
            f"{r1.text} / {r2.text}",
        )
        # Cato's row, disabled by every earlier start while its stored job kept running: enabled again
        # once; a pause (which pauses the stored job too) is left alone.
        sql("UPDATE scheduled_job_metadata SET enabled = 0 WHERE job_id = :j", j=CATO)
        py.post("/__test/repair_cato")
        check("Cato's row, disabled with its stored job running, is enabled at startup", enabled_of(CATO) == 1)
        py.post(f"/api/scheduler/pause/{CATO}", headers=H(t_admin))
        sql("UPDATE scheduled_job_metadata SET enabled = 0 WHERE job_id = :j", j=CATO)
        py.post("/__test/repair_cato")
        check("  a paused one stays disabled", enabled_of(CATO) == 0)
        # CarbonBlack's callable is no key of get_function_by_name: Python's manual run always failed.
        r1 = py.post(f"/api/scheduler/jobs/run/sch_renamed{SFX}", headers=H(t_admin))
        r2 = rs2.post(f"/api/scheduler/jobs/run/sch_renamed{SFX}", headers=H(t_admin))
        check(
            "run of a CarbonBlack job: Python's ValueError 500, run in Rust (§4)",
            r1.status_code == 500
            and "has no entry in get_function_by_name" in r1.json()["message"]
            and (r2.status_code, r2.json())
            == (
                200,
                {
                    "success": True,
                    "message": "Job executed successfully",
                    "result": {"success": True, "message": "Carbonblack integration invoked."},
                },
            ),
            f"python {r1.text}\n        rust   {r2.text}",
        )

        print("\n=== /provisioning_jobs and Mimecast's scheduler routes ===")
        route = "/api/scheduler/provisioning_jobs"
        job = {"function_name": HUNTRESS, "job_id": HUNTRESS, "time_interval": 5}
        same(
            "provisioning jobs, not a provisioning job",
            "POST",
            route,
            t_admin,
            other=rs2,
            json={"jobs": [{**job, "job_id": PRUNE, "function_name": PRUNE}]},
        )
        same("provisioning jobs, renamed", "POST", route, t_admin, other=rs2, json={"jobs": [{**job, "function_name": DUO}]})
        same("provisioning jobs, Pydantic's 422", "POST", route, t_admin, other=rs2, json={"jobs": [{"job_id": 1, "time_interval": "x"}]})
        same("provisioning jobs, no body", "POST", route, t_admin, other=rs2)
        same(
            "provisioning jobs, malformed JSON before the token",
            "POST",
            route,
            None,
            other=rs2,
            content=b"{",
            headers={"Content-Type": "application/json"},
        )

        def provision_round(client, body, tok=t_admin, rows_before=()):
            forget(HUNTRESS)
            for enabled, minutes in rows_before:
                meta(HUNTRESS, enabled, minutes)
            r = client.post(route, json=body, headers=H(tok))
            return r.status_code, body_of(r), store_state(HUNTRESS), meta_rows(HUNTRESS)

        for label, body, rows_before in (
            ("a new job", {"jobs": [job]}, ()),
            ("the one row updated and enabled", {"jobs": [{**job, "time_interval": "1_5"}]}, ((False, 1),)),
            ("two rows: MultipleResultsFound, after APScheduler's add", {"jobs": [job]}, ((True, 1), (True, 2))),
        ):
            a = provision_round(py, body, rows_before=rows_before)
            b = provision_round(rs2, body, rows_before=rows_before)
            check(f"provisioning jobs, {label} [{a[0]}]", a == b, f"python {a}\n        rust   {b}")
        a = provision_round(py, {"jobs": [job]}, t_scoped)
        b = provision_round(rs2, {"jobs": [job]}, t_scoped)
        check(
            "provisioning jobs, a scoped analyst naming no customer: Python registers, Rust 403 (§4)",
            a[0] == 200 and b[:2] == (403, {"success": False, "message": f"Access denied to job {HUNTRESS}"}) and b[3] == [],
            f"python {a}\n        rust   {b}",
        )
        a = provision_round(py, {"jobs": [{**job, "customer_code": "someone-else"}]}, t_scoped)
        b = provision_round(rs2, {"jobs": [{**job, "customer_code": "someone-else"}]}, t_scoped)
        check(
            "  … or another customer: 403 (§4)",
            a[0] == 200 and b[:2] == (403, {"success": False, "message": "Access denied to customer someone-else"}),
            f"python {a}\n        rust   {b}",
        )
        a = provision_round(py, {"jobs": [{**job, "customer_code": CUSTOMER}]}, t_scoped)
        b = provision_round(rs2, {"jobs": [{**job, "customer_code": CUSTOMER}]}, t_scoped)
        check("  … one of theirs: registered alike", a == b and a[0] == 200, f"python {a}\n        rust   {b}")

        def mimecast_round(client, path):
            for j in (MIMECAST, MIMECAST_TTP):
                forget(j)
            r = client.post(path, headers=H(t_admin))
            return (
                r.status_code,
                body_of(r),
                store_state(MIMECAST),
                meta_rows(MIMECAST),
                store_state(MIMECAST_TTP),
                meta_rows(MIMECAST_TTP),
            )

        a = mimecast_round(py, "/api/mimecast/invoke/scheduler/siem?time_interval=9")
        b = mimecast_round(rs2, "/api/mimecast/invoke/scheduler/siem?time_interval=9")
        check(f"Mimecast SIEM schedule [{a[0]}]", a == b, f"python {a}\n        rust   {b}")
        a = mimecast_round(py, "/api/mimecast/invoke/scheduler/ttp?time_interval=11")
        b = mimecast_round(rs2, "/api/mimecast/invoke/scheduler/ttp?time_interval=11")
        check(
            "Mimecast TTP schedule: Python replaces the SIEM job's function, Rust schedules the TTP job (§4)",
            a[:2] == b[:2] == (200, {"success": True, "message": "Mimecast integration scheduled."})
            and a[2]["func"].endswith(":invoke_mimecast_integration_ttp")
            and a[3] == [(11, None, 1, None, 0)]
            and a[4] is None
            and b[2] is None
            and b[4]["func"].endswith(":invoke_mimecast_integration_ttp")
            and b[5] == [(11, None, 1, None, 0)],
            f"python {a}\n        rust   {b}",
        )
        same("Mimecast, missing interval", "POST", "/api/mimecast/invoke/scheduler/ttp", t_admin, other=rs2)
        same("Mimecast, no token", "POST", "/api/mimecast/invoke/scheduler/siem?time_interval=1", other=rs2)

        print("\n=== differences by design ===")
        r1 = py.post(f"/api/scheduler/pause/{DRAINER}", headers=H(t_admin))
        check("pause, Python: enabled flag untouched", r1.json()["success"] is True and enabled_of(DRAINER) == 1, r1.text)
        py.post(f"/api/scheduler/start/{DRAINER}", headers=H(t_admin))
        r2 = rs2.post(f"/api/scheduler/pause/{PRUNE}", headers=H(t_admin))
        check("pause, Rust: the flag follows (hand-over)", r2.json() == r1.json() and enabled_of(PRUNE) == 0, r2.text)
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
        r1 = py.post(f"/api/scheduler/add?job_id=sch_neg_py{SFX}&function_name=agent_sync&time_interval=-5", headers=H(t_admin))
        neg_stored = store_state(f"sch_neg_py{SFX}")
        py.delete(f"/api/scheduler/sch_neg_py{SFX}", headers=H(t_admin))
        r2 = rs2.post(f"/api/scheduler/add?job_id=sch_neg_rs{SFX}&function_name=agent_sync&time_interval=-5", headers=H(t_admin))
        check(
            "a negative interval: Python stores it (a running APScheduler then never gets past it), Rust refuses (§4)",
            r1.status_code == 200
            and neg_stored is not None
            and neg_stored["interval"] == -300
            and r2.status_code == 400
            and "must not be negative" in r2.json()["message"]
            and meta_rows(f"sch_neg_rs{SFX}") == [],
            f"python {r1.text}\n        rust   {r2.text}",
        )

        r1 = py.post("/api/scheduler/apscheduler_ops", json={"ops": []}, headers=H(t_admin))
        r2 = rs2.post("/api/scheduler/apscheduler_ops", json={"ops": []}, headers=H(t_admin))
        check(
            "the hand-off hook: Python's internal route, a 404 through Rust (§4)",
            (r1.status_code, r1.json()) == (200, {"success": True, "found": []}) and r2.status_code == 404,
            f"python {r1.text}\n        rust   {r2.text}",
        )

        print("\n=== the ownership (COPILOT_SCHEDULER_OWNER=rust, COPILOT_PY_SCHEDULER=false) ===")
        # Python's switch: its guard skips every scheduled tick, an operator's run still runs.
        m = audit_marker("f")
        os.environ["COPILOT_PY_SCHEDULER"] = "false"
        try:
            r = py.post(f"/__test/tick/{PRUNE}")
            check(
                "COPILOT_PY_SCHEDULER=false: Python's scheduled tick is skipped",
                r.json() == {"outcome": "skipped"} and marker_left(m) == 1,
                r.text,
            )
        finally:
            os.environ.pop("COPILOT_PY_SCHEDULER", None)
        # The owner runs prune_audit_log from its row: every second (a zero interval is APScheduler's
        # one second) — the same effect as Python's tick, and it stamps last_success.
        forget(PRUNE)
        meta(PRUNE, True, 0, "Prunes audit_log entries")
        before_store = {r[0]: r[1] for r in sql("SELECT id, next_run_time FROM apscheduler_jobs").fetchall()}
        owner_proc = start_rust(OWNER_PORT, {"COPILOT_SCHEDULER_OWNER": "rust"})
        check("the owner runs the job from its enabled row", wait_until(lambda: marker_left(m) == 0, 10))
        check("  and stamps last_success", meta_rows(PRUNE)[0][4] == 1)
        r = owner.post(f"/api/scheduler/pause/{PRUNE}", headers=H(t_admin))
        check(
            "pause through the owner [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job paused successfully"}),
            r.text,
        )
        check("  the row is disabled", enabled_of(PRUNE) == 0)
        time.sleep(1.5)
        m2 = audit_marker("g")
        time.sleep(2.5)
        check("  a paused job does not run", marker_left(m2) == 1)
        r = owner.get(f"/api/scheduler/next_run/{PRUNE}", headers=H(t_admin))
        check("  its next run is the paused job's ValidationError 400", r.status_code == 400, r.text)
        r = owner.post(f"/api/scheduler/start/{PRUNE}", headers=H(t_admin))
        check(
            "start through the owner [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job started successfully"}),
            r.text,
        )
        check("  resumed on its grid, it runs again", wait_until(lambda: marker_left(m2) == 0, 6))
        r = owner.put(f"/api/scheduler/update/{PRUNE}?time_interval=1440", headers=H(t_admin))
        check(
            "update through the owner [200]",
            (r.status_code, r.json()) == (200, {"success": True, "message": "Job updated successfully"}),
            r.text,
        )
        r = owner.get(f"/api/scheduler/next_run/{PRUNE}", headers=H(t_admin))
        ahead = (
            datetime.datetime.fromisoformat(r.json()["next_run_time"].replace("Z", "+00:00")) - datetime.datetime.now(datetime.timezone.utc)
        ).total_seconds()
        check("  a new trigger from now, one interval ahead", 1439 * 60 < ahead <= 1440 * 60, r.text)
        r = owner.get("/api/scheduler?search=prune", headers=H(t_admin))
        check(
            "the owner lists the jobs of the rows",
            r.json()["jobs"]
            == [
                {
                    "id": PRUNE,
                    "name": PRUNE,
                    "enabled": True,
                    "time_interval": 1440,
                    "last_success": r.json()["jobs"][0]["last_success"],
                    "description": "Prunes audit_log entries",
                },
            ],
            r.text,
        )
        # The writes on a job id that is its function (the rows have no function column): the
        # same answers and rows as Python's, and APScheduler's store never touched.
        rounds = {}
        for tag, client in (("py", py), ("owner", owner)):
            forget(DUO)
            steps = []
            for name, method, url in (
                ("add", "POST", f"/api/scheduler/add?job_id={DUO}&function_name={DUO}&time_interval=9&extra_data=e"),
                ("update", "PUT", f"/api/scheduler/update/{DUO}?time_interval=7"),
                ("delete", "DELETE", f"/api/scheduler/{DUO}"),
                ("delete again", "DELETE", f"/api/scheduler/{DUO}"),
            ):
                r = client.request(method, url, headers=H(t_admin))
                steps.append((name, r.status_code, body_of(r), meta_rows(DUO)))
            rounds[tag] = steps
        for a, b in zip(rounds["py"], rounds["owner"]):
            check(f"owner {a[0]} [{a[1]}]", a[1:] == b[1:], f"python {a[1:]}\n        rust   {b[1:]}")
        r = owner.post(f"/api/scheduler/add?job_id=sch_x{SFX}&function_name={DUO}&time_interval=9", headers=H(t_admin))
        check(
            "the owner refuses a job under another id than its function's (§4)",
            r.status_code == 400 and meta_rows(f"sch_x{SFX}") == [],
            r.text,
        )
        forget(HUNTRESS)
        r = owner.post(route, json={"jobs": [job]}, headers=H(t_admin))
        check(
            "the owner registers provisioning jobs as rows",
            r.status_code == 200 and meta_rows(HUNTRESS) == [(5, None, 1, None, 0)],
            r.text,
        )
        for j in (MIMECAST, MIMECAST_TTP):
            forget(j)
        r = owner.post("/api/mimecast/invoke/scheduler/ttp?time_interval=11", headers=H(t_admin))
        check(
            "the owner schedules Mimecast's TTP job",
            r.status_code == 200 and meta_rows(MIMECAST_TTP) == [(11, None, 1, None, 0)],
            r.text,
        )
        after_store = {r[0]: r[1] for r in sql("SELECT id, next_run_time FROM apscheduler_jobs").fetchall()}
        # The ids this section wrote through Python or forgot itself.
        touched_here = (DUO, HUNTRESS, MIMECAST, MIMECAST_TTP)
        check(
            "  APScheduler's store was never touched by the owner",
            {k: v for k, v in after_store.items() if k not in touched_here}
            == {k: v for k, v in before_store.items() if k not in touched_here},
        )
        stop(owner_proc)
        owner_proc = None

        print("\n=== copilot doctor ===")
        py.post(f"/__test/overdue/sch_overdue{SFX}")
        lines = doctor({"COPILOT_SCHEDULER_OWNER": "rust"})
        check(
            "doctor, owner=rust and an idle APScheduler: no mismatch",
            any("owner=rust" in line for line in lines)
            and any("ok   APScheduler is idle" in line for line in lines)
            and not any("FAIL" in line for line in lines),
            "\n".join(lines),
        )
        lines = doctor({"COPILOT_LEGACY_URL": f"http://127.0.0.1:{PY_PORT}"})
        check(
            "doctor, the hand-over and an idle APScheduler: the mismatch reported",
            any("FAIL APScheduler is not running" in line for line in lines),
            "\n".join(lines),
        )
    finally:
        if owner_proc is not None:
            stop(owner_proc)
        stop(rs2_proc)
        cleanup()

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
