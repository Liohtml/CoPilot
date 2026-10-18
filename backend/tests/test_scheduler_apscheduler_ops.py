"""The scheduler's `/apscheduler_ops` hook: APScheduler's part of the Scheduler's write routes, which the
Rust service answers itself and hands this part of here while APScheduler owns the schedule (no DB,
no scheduler: a fake one records the calls)."""

import asyncio
import os

import pytest

os.environ.setdefault("JWT_SECRET", "test-only-secret-not-the-compromised-default")

from app.schedulers.routes import scheduler as routes  # noqa: E402


class FakeJob:
    def __init__(self, scheduler, job_id):
        self.scheduler, self.id = scheduler, job_id

    def reschedule(self, **kwargs):
        self.scheduler.calls.append(("reschedule", self.id, kwargs))

    def pause(self):
        self.scheduler.calls.append(("pause", self.id))

    def resume(self):
        self.scheduler.calls.append(("resume", self.id))


class FakeScheduler:
    running = True

    def __init__(self, ids):
        self.ids, self.calls = list(ids), []

    def get_jobs(self):
        return [FakeJob(self, i) for i in self.ids]

    def add_job(self, func, trigger, **kwargs):
        self.calls.append(("add", func.__name__, trigger, kwargs))
        if kwargs["id"] not in self.ids:
            self.ids.append(kwargs["id"])

    def remove_job(self, job_id):
        self.calls.append(("remove", job_id))
        self.ids.remove(job_id)


@pytest.fixture()
def fake(monkeypatch):
    scheduler = FakeScheduler(["prune_audit_log"])

    async def instance():
        return scheduler

    monkeypatch.setattr(routes, "get_scheduler_instance", instance)
    return scheduler


def ops(*items):
    return asyncio.run(routes.apscheduler_ops(routes.ApschedulerOpsRequest(ops=list(items))))


def test_each_operation_is_the_routes_call(fake):
    answer = ops(
        {"op": "add", "job_id": "x", "function_name": "agent_sync", "time_interval": 9, "defaults": True},
        {"op": "add", "job_id": "agent_sync", "function_name": "agent_sync", "time_interval": 15},
        {"op": "reschedule", "job_id": "x", "time_interval": 7},
        {"op": "pause", "job_id": "prune_audit_log"},
        {"op": "resume", "job_id": "prune_audit_log"},
        {"op": "remove", "job_id": "x"},
        {"op": "pause", "job_id": "no-such-job"},
    )
    assert answer == {"success": True, "found": [True, True, True, True, True, True, False]}
    assert fake.calls == [
        ("add", "agent_sync", "interval", {"minutes": 9, "id": "x", "replace_existing": True}),
        (
            "add",
            "agent_sync",
            "interval",
            {"minutes": 15, "id": "agent_sync", "replace_existing": True, "coalesce": True, "max_instances": 1},
        ),
        ("reschedule", "x", {"trigger": "interval", "minutes": 7}),
        ("pause", "prune_audit_log"),
        ("resume", "prune_audit_log"),
        ("remove", "x"),
    ]


def test_find_job_by_id_is_exact(fake):
    assert ops({"op": "pause", "job_id": "PRUNE_AUDIT_LOG"}) == {"success": True, "found": [False]}
    assert fake.calls == []


def test_an_unknown_function_raises_the_routes_value_error(fake):
    with pytest.raises(ValueError, match="has no entry in get_function_by_name"):
        ops({"op": "add", "job_id": "x", "function_name": "nope", "time_interval": 1})
