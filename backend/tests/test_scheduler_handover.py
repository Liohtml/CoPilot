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


# A job whose APScheduler id (and metadata row) is not its function's name: the guard follows the
# id; a manual run resolves the function's name, which the Rust service does not run.
RENAMED_JOBS = {"invoke_carbonblack_integration_collection": "invoke_carbonblack_integration_collect"}

# Jobs `initialize_job_metadata` does not seed: a provisioning route (or POST /scheduler/add)
# creates them with their row, enabled.
ROUTE_CREATED_JOBS = {
    "invoke_carbonblack_integration_collection",
    "invoke_cato_integration_collect",
    "invoke_darktrace_integration_collect",
    "invoke_duo_integration_collect",
    "invoke_huntress_integration_collect",
    "invoke_mimecast_integration",
    "invoke_mimecast_integration_ttp",
    "invoke_sap_siem_integration_brute_force_failed_logins",
    "invoke_sap_siem_integration_brute_force_failed_logins_same_ip",
    "invoke_sap_siem_integration_collection",
    "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
    "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location",
    "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
    "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location",
    "invoke_sap_siem_integration_successful_login_after_multiple_failed_logins",
    "invoke_sap_siem_integration_successful_user_login_with_different_ip",
    "invoke_sap_siem_integration_suspicious_logins_analysis",
}


def test_the_guarded_jobs_are_still_picklable_references():
    """APScheduler stores `module:function`; it must resolve to the guarded function."""
    for job_id in handover.RUST_CAPABLE_JOBS:
        function = scheduler_module.get_function_by_name(job_id)
        assert getattr(function, "__rust_handover_job_id__", None) == job_id
        assert ref_to_obj(obj_to_ref(function)) is function
        assert get_callable_name(function) == RENAMED_JOBS.get(job_id, job_id), "job.name (the run route's lookup) is unchanged"
        assert asyncio.iscoroutinefunction(function)


def test_every_rust_capable_job_is_seeded():
    from tests.test_scheduler_job_registration import _known_job_ids

    assert set(handover.RUST_CAPABLE_JOBS) <= set(_known_job_ids()) | ROUTE_CREATED_JOBS
    assert not ROUTE_CREATED_JOBS & set(_known_job_ids()), "a seeded job is not route-created"
    assert ROUTE_CREATED_JOBS <= set(handover.RUST_CAPABLE_JOBS)


def test_every_scheduled_job_can_be_handed_over():
    """After the last wave every job of `get_function_by_name` is guarded (Cato and the refreshers included)."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(scheduler_module.get_function_by_name))
    keys = {k.value for node in ast.walk(tree) if isinstance(node, ast.Dict) for k in node.keys}
    assert keys == set(handover.RUST_CAPABLE_JOBS)


def test_the_cato_row_is_no_longer_disabled_at_startup():
    """`schedule_enabled_jobs` used to disable Cato's row at every start while its stored job kept running."""
    source = inspect_source(scheduler_module.schedule_enabled_jobs)
    disabled = source[source.index("job_ids_to_disable = [") : source.index("]")]
    assert "invoke_cato_integration_collect" not in disabled
    function = scheduler_module.get_function_by_name("invoke_cato_integration_collect")
    assert function.__rust_handover_job_id__ == "invoke_cato_integration_collect"


def inspect_source(function):
    import inspect

    return inspect.getsource(function)


@pytest.mark.parametrize(
    "value,enabled",
    [(None, True), ("true", True), ("false", False), (" FALSE ", False), ("0", False), ("off", False)],
)
def test_the_python_scheduler_switch(monkeypatch, value, enabled):
    if value is None:
        monkeypatch.delenv(handover.PY_SCHEDULER_ENV, raising=False)
    else:
        monkeypatch.setenv(handover.PY_SCHEDULER_ENV, value)
    assert handover.py_scheduler_enabled() is enabled


def test_with_apscheduler_off_every_scheduled_tick_is_skipped(fake_db, monkeypatch):
    monkeypatch.setenv(handover.PY_SCHEDULER_ENV, "false")
    job, calls = guarded_counter()
    assert run(job()) is handover.JOB_SKIPPED
    assert calls == [] and fake_db.waits == [], "skipped before the lock is even asked for"

    async def manual():
        with handover.manual_run():
            return await job()

    assert run(manual()) == "ran", "an operator's run still runs"


def test_with_apscheduler_off_init_scheduler_seeds_the_rows_and_starts_nothing(monkeypatch):
    monkeypatch.setenv(handover.PY_SCHEDULER_ENV, "false")
    seeded = []

    async def seed():
        seeded.append(1)

    monkeypatch.setattr(scheduler_module, "initialize_job_metadata", seed)
    monkeypatch.setattr(scheduler_module, "scheduler_instance", None)
    monkeypatch.setattr(scheduler_module, "_metadata_seeded_without_scheduler", False)
    assert run(scheduler_module.init_scheduler()) is None
    assert run(scheduler_module.init_scheduler()) is None
    assert seeded == [1], "seeded once"
    with pytest.raises(scheduler_module.SchedulerDisabledError):
        run(scheduler_module.get_scheduler_instance())


class _CatoSession:
    """The two reads `_repair_cato_row` makes: the stored job's next_run_time, the deciding row."""

    def __init__(self, stored, row):
        self.stored, self.row, self.commits = stored, row, 0

    async def execute(self, stmt, params=None):
        session = self

        class R:
            def first(self):
                return session.stored

            def scalars(self):
                return self

        r = R()
        if params is None:
            r.first = lambda: session.row
        return r

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        pass


@pytest.mark.parametrize(
    "stored,enabled,repaired",
    [
        ((1700000000.0,), False, True),  # the old startup list's doing: the stored job kept running
        ((None,), False, False),  # paused in APScheduler too: a pause or a hand-over
        (None, False, False),  # no stored job
        ((1700000000.0,), True, False),  # already enabled
    ],
)
def test_the_cato_row_repair(stored, enabled, repaired):
    from app.schedulers.models.scheduler import JobMetadata

    row = JobMetadata(job_id="invoke_cato_integration_collect", time_interval=5, enabled=enabled, job_description=None)
    session = _CatoSession(stored, row)
    run(scheduler_module._repair_cato_row(session))
    assert row.enabled is (enabled or repaired)
    assert session.commits == (1 if repaired else 0)


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
        "refresh_wazuh_rules_cache": JobMetadata(
            job_id="refresh_wazuh_rules_cache",
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
    assert _Session.rows["refresh_wazuh_rules_cache"].enabled is False, "every seeded job is Rust-capable now"
