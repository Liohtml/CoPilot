"""Hand-over of scheduled jobs to the Rust service — the Python half of the guarantee.

The Rust backend (`crates/copilot-scheduler`) can run some of the jobs this scheduler runs.
A job must never run in both, so ownership is decided by data both processes read, and every
run of such a job — here and there — happens under one MySQL named lock:

* **The row decides.** `scheduled_job_metadata` (the row with the lowest id for the job):
  APScheduler runs the job while that row is enabled, or absent; the Rust service runs it only
  while the row exists and is disabled *and* its own opt-in (`COPILOT_RS_JOBS`) names the job.
  The two conditions cannot both hold. Disabled without the opt-in means paused.
* **Checked at every run, not at scheduling time.** APScheduler keeps jobs in its own store
  (`apscheduler_jobs`) across restarts, so a job that was handed over may still be in it and fire.
  The guard below therefore wraps the job function itself: whichever store entry, id or
  pickled reference reaches it, a scheduled run re-reads the row and skips when it is not ours.
* **One lock across both processes.** The row is read *under* `GET_LOCK` (no wait for a
  scheduled run: a busy lock means the other side is running it, so this tick is skipped), so
  a hand-over in the middle of a run cannot start the other side while this one is still at
  work. MySQL releases the lock when the connection ends, so a crashed run cannot strand it.
* **A skipped tick is not a success.** The guard returns `JOB_SKIPPED`; the scheduler's
  listener does not stamp `last_success` for it.

A run started by hand (`POST /scheduler/jobs/run/{id}`) is an operator's request: it waits up
to `MANUAL_LOCK_WAIT_SECONDS` for the lock and then runs whatever the row says. With the Rust
service in front, such a request reaches this process only for jobs Rust does not run.

`RUST_CAPABLE_JOBS` lists the jobs the Rust service knows; a Rust test reads this tuple and
fails when the two lists drift apart.
"""

import contextlib
import contextvars
import functools

from loguru import logger
from sqlalchemy import text

from app.db.db_session import async_engine

# Job ids (== function names) the Rust service can run. Keep in step with the job registry in
# crates/copilot-scheduler (pinned by a Rust test that parses this tuple).
RUST_CAPABLE_JOBS = (
    "invoke_palace_lesson_drainer",
    "invoke_palace_lesson_sweeper",
    "notify_sla_transitions",
    "prune_audit_log",
)

# Seconds a run started by hand waits for a run in progress (here or in Rust) to finish.
MANUAL_LOCK_WAIT_SECONDS = 10

# The lock name, computed by MySQL on both sides: scoped to the database, at most 52 characters.
LOCK_NAME_SQL = "CONCAT('copilot_job:', SHA1(CONCAT(DATABASE(), '/', :job_id)))"
# The row that decides, read the way the Rust service reads it.
OWNER_ROW_SQL = "SELECT enabled FROM scheduled_job_metadata WHERE job_id = :job_id ORDER BY id LIMIT 1"


class _Skipped:
    """Return value of a scheduled run that did not happen (see `scheduler_listener`)."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "JOB_SKIPPED"

    def __reduce__(self):
        return (_Skipped, ())


JOB_SKIPPED = _Skipped()

_manual_run = contextvars.ContextVar("copilot_manual_job_run", default=False)


@contextlib.contextmanager
def manual_run():
    """Mark the calls made inside as an operator's "run now", not a scheduled tick."""
    token = _manual_run.set(True)
    try:
        yield
    finally:
        _manual_run.reset(token)


class JobBusyError(RuntimeError):
    """A run started by hand found the job running elsewhere for too long."""


def legacy_scheduler_owns(enabled) -> bool:
    """`enabled` of the deciding row (None when there is none) → whether APScheduler runs the job."""
    return enabled is None or bool(enabled)


@contextlib.asynccontextmanager
async def job_run_lock(job_id: str, wait_seconds: int):
    """Hold the job's cross-process lock; yields `(held, conn)`.

    `conn` is the connection holding the lock (None off MySQL, where there is only this
    process). The lock is released before the connection goes back to the pool; if that
    fails, the connection is invalidated so the server drops the lock with the session.
    """
    if async_engine.dialect.name != "mysql":
        yield True, None
        return
    async with async_engine.connect() as conn:
        got = (await conn.execute(text(f"SELECT GET_LOCK({LOCK_NAME_SQL}, :wait)"), {"job_id": job_id, "wait": wait_seconds})).scalar()
        # End the implicit transaction: the lock belongs to the session, not to it, and the row
        # must be read in a fresh snapshot.
        await conn.rollback()
        if got != 1:
            yield False, conn
            return
        try:
            yield True, conn
        finally:
            try:
                await conn.execute(text(f"SELECT RELEASE_LOCK({LOCK_NAME_SQL})"), {"job_id": job_id})
                await conn.rollback()
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Could not release the run lock of {job_id!r}: {exc}; dropping the connection")
                await conn.invalidate()


async def _owner_row_enabled(conn, job_id: str):
    """`enabled` of the deciding row, or None when the job has no row."""
    if conn is None:
        async with async_engine.connect() as fresh:
            return (await fresh.execute(text(OWNER_ROW_SQL), {"job_id": job_id})).scalar()
    enabled = (await conn.execute(text(OWNER_ROW_SQL), {"job_id": job_id})).scalar()
    await conn.rollback()
    return enabled


def rust_handover(job_id: str):
    """Guard a job function the Rust service can also run (see the module docstring).

    `functools.wraps` keeps `__module__`/`__qualname__`, so APScheduler's pickled reference
    (`module:function`) resolves to the guarded function and `job.name` is unchanged.
    """

    def decorate(func):
        @functools.wraps(func)
        async def guarded(*args, **kwargs):
            manual = _manual_run.get()
            async with job_run_lock(job_id, MANUAL_LOCK_WAIT_SECONDS if manual else 0) as (held, conn):
                if not held:
                    if manual:
                        raise JobBusyError(f"Job {job_id} is already running; try again when it has finished")
                    logger.info(f"Job {job_id} is running elsewhere; skipping this tick")
                    return JOB_SKIPPED
                if not manual:
                    enabled = await _owner_row_enabled(conn, job_id)
                    if not legacy_scheduler_owns(enabled):
                        logger.debug(f"Job {job_id} is disabled here (handed over or paused); skipping this tick")
                        return JOB_SKIPPED
                return await func(*args, **kwargs)

        guarded.__rust_handover_job_id__ = job_id
        return guarded

    return decorate
