"""The Python half of the scheduled-job hand-over to the Rust service (`app/schedulers/handover.py`).

A job the Rust service can run (`RUST_CAPABLE_JOBS`) must never run in both schedulers. The guard on
the job function itself is what makes APScheduler respect that — whichever store entry fires it —
so these tests pin its decisions:

* a scheduled run happens only while the deciding `scheduled_job_metadata` row is enabled (or
  absent) and the cross-process run lock is free, and otherwise returns `JOB_SKIPPED`;
* the listener does not stamp `last_success` for a skipped run;
* a manual run waits for the lock, ignores the row and says so when the job stays busy;
* startup no longer re-enables a handed-over job, and the guarded functions are still what
  APScheduler can pickle by reference.

No DB: the lock and the row are faked. `tests/e2e/rust_parity_schedulers_e2e.py` runs the same rules
against MySQL and the Rust binary.

Run with: cd backend && python -m pytest tests/test_scheduler_handover.py
"""

import asyncio
import contextlib
import os

import pytest
from apscheduler.events import EVENT_JOB_EXECUTED
from apscheduler.events import JobExecutionEvent
from apscheduler.util import get_callable_name
from apscheduler.util import obj_to_ref
from apscheduler.util import ref_to_obj

os.environ.setdefault("JWT_SECRET", "test-only-secret-not-the-compromised-default")

from app.schedulers import handover  # noqa: E402
from app.schedulers import scheduler as scheduler_module  # noqa: E402


class FakeDb:
    """The lock and the deciding row, as the guard reads them."""

    def __init__(self, enabled=True, lock_free=True):
        self.enabled = enabled
        self.lock_free = lock_free
        self.waits = []

    def lock(self):
        db = self

        @contextlib.asynccontextmanager
        async def job_run_lock(job_id, wait_seconds):
            db.waits.append(wait_seconds)
            yield db.lock_free, None

        return job_run_lock

    async def owner_row_enabled(self, conn, job_id):
        return self.enabled


@pytest.fixture()
def fake_db(monkeypatch):
    db = FakeDb()
    monkeypatch.setattr(handover, "job_run_lock", db.lock())
    monkeypatch.setattr(handover, "_owner_row_enabled", db.owner_row_enabled)
    return db


def guarded_counter():
    calls = []

    @handover.rust_handover("some_job")
    async def some_job():
        calls.append(1)
        return "ran"

    return some_job, calls


def run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("enabled", [True, None])
def test_a_scheduled_run_happens_while_the_row_is_enabled_or_absent(fake_db, enabled):
    fake_db.enabled = enabled
    job, calls = guarded_counter()
    assert run(job()) == "ran"
    assert calls == [1]
    assert fake_db.waits == [0], "a scheduled tick never waits for the lock"


def test_a_handed_over_job_is_skipped(fake_db):
    fake_db.enabled = False
    job, calls = guarded_counter()
    assert run(job()) is handover.JOB_SKIPPED
    assert calls == []


def test_a_job_running_elsewhere_is_skipped(fake_db):
    fake_db.lock_free = False
    job, calls = guarded_counter()
    assert run(job()) is handover.JOB_SKIPPED
    assert calls == []


def test_a_manual_run_waits_ignores_the_row_and_reports_a_busy_job(fake_db):
    fake_db.enabled = False
    job, calls = guarded_counter()

    async def manual():
        with handover.manual_run():
            return await job()

    assert run(manual()) == "ran"
    assert calls == [1]
    assert fake_db.waits == [handover.MANUAL_LOCK_WAIT_SECONDS]

    fake_db.lock_free = False
    with pytest.raises(handover.JobBusyError) as excinfo:
        run(manual())
    # The text the run route answers with (500), and the Rust service too.
    assert str(excinfo.value) == "Job some_job is already running; try again when it has finished"


def test_ownership_rule():
    assert handover.legacy_scheduler_owns(None)
    assert handover.legacy_scheduler_owns(1)
    assert handover.legacy_scheduler_owns(True)
    assert not handover.legacy_scheduler_owns(0)
    assert not handover.legacy_scheduler_owns(False)


def test_a_skipped_run_is_not_stamped(monkeypatch):
    stamped = []

    async def record(job_id):
        stamped.append(job_id)
        return True

    monkeypatch.setattr(scheduler_module, "record_job_success", record)

    async def scenario():
        for retval in (handover.JOB_SKIPPED, None, "something"):
            scheduler_module.scheduler_listener(
                JobExecutionEvent(EVENT_JOB_EXECUTED, "prune_audit_log", "default", None, retval=retval),
            )
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    asyncio.run(scenario())
    assert stamped == ["prune_audit_log", "prune_audit_log"]


def test_the_guarded_jobs_are_still_picklable_references():
    """APScheduler stores `module:function`; it must resolve to the guarded function."""
    for job_id in handover.RUST_CAPABLE_JOBS:
        function = scheduler_module.get_function_by_name(job_id)
        assert getattr(function, "__rust_handover_job_id__", None) == job_id
        assert ref_to_obj(obj_to_ref(function)) is function
        assert get_callable_name(function) == job_id, "job.name (the run route's lookup) is unchanged"
        assert asyncio.iscoroutinefunction(function)


def test_every_rust_capable_job_is_seeded():
    from tests.test_scheduler_job_registration import _known_job_ids

    assert set(handover.RUST_CAPABLE_JOBS) <= set(_known_job_ids())


class _Result:
    def __init__(self, row):
        self.row = row

    def scalars(self):
        return self

    def one_or_none(self):
        return self.row


class _Session:
    """Stands in for AsyncSession in `initialize_job_metadata`: one stored row per job."""

    rows = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):
        job_id = stmt.whereclause.right.value
        return _Result(self.rows.get(job_id))

    def add(self, row):
        self.rows[row.job_id] = row

    async def commit(self):
        pass


def test_startup_keeps_a_handed_over_job_disabled(monkeypatch):
    from app.schedulers.models.scheduler import JobMetadata

    _Session.rows = {
        "prune_audit_log": JobMetadata(job_id="prune_audit_log", time_interval=5, enabled=False, job_description="x"),
        "invoke_alert_creation_collect": JobMetadata(
            job_id="invoke_alert_creation_collect",
            time_interval=5,
            enabled=False,
            job_description="x",
        ),
    }
    monkeypatch.setattr(scheduler_module, "AsyncSession", _Session)
    asyncio.run(scheduler_module.initialize_job_metadata())

    prune = _Session.rows["prune_audit_log"]
    assert prune.enabled is False, "a handed-over job stays with the Rust service across restarts"
    assert prune.time_interval == 1440, "the interval is still reset as before"
    assert _Session.rows["invoke_alert_creation_collect"].enabled is True, "every other job is re-enabled as before"
