"""Generate APScheduler job-store vectors for copilot-scheduler's pickle reader.

    backend/.venv/bin/python -I scripts/gen-apscheduler-vectors.py \
        > crates/copilot-scheduler/src/apscheduler_vectors.json

Each vector is an `apscheduler_jobs.job_state` blob exactly as `SQLAlchemyJobStore` writes it
(`pickle.dumps(job.__getstate__(), HIGHEST_PROTOCOL)`, read back from a real store) and what
the Scheduler routes make of it: the job's `id`, `name` and `func` reference, and
`next_run_time` as Pydantic renders it in `JobsNextRunResponse` (`null` while paused).
`tz_supported` is false for a timezone the Rust reader does not convert; every `zoneinfo` zone is
converted (through the IANA database compiled into chrono-tz, the pickled wall time and its `fold`
choosing the offset), so today every vector is supported. Each zone also carries a job pinned to a
winter date and, for zones with a transition back, one to the repeated hour with `fold=1`.

Regenerate after upgrading APScheduler, pydantic, pytz or tzlocal.
"""
import asyncio
import datetime
import json
import sys
import zoneinfo

import apscheduler
import pydantic
import pytz
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy import text


class JobsNextRunResponse(BaseModel):
    next_run_time: datetime.datetime
    success: bool
    message: str


async def noop():
    pass


async def other_name():
    pass


async def with_args(*args, **kwargs):
    pass


SCHEDULER_ZONES = [
    ("zoneinfo Etc/UTC", zoneinfo.ZoneInfo("Etc/UTC")),
    ("zoneinfo UTC", zoneinfo.ZoneInfo("UTC")),
    ("timezone.utc", datetime.timezone.utc),
    ("fixed +05:30", datetime.timezone(datetime.timedelta(hours=5, minutes=30))),
    ("fixed -03:00 named", datetime.timezone(datetime.timedelta(hours=-3), "BRT")),
    ("zoneinfo Etc/GMT+5", zoneinfo.ZoneInfo("Etc/GMT+5")),
    ("pytz utc", pytz.utc),
    ("pytz Europe/Berlin", pytz.timezone("Europe/Berlin")),
    ("zoneinfo Europe/Berlin", zoneinfo.ZoneInfo("Europe/Berlin")),
    ("zoneinfo America/New_York", zoneinfo.ZoneInfo("America/New_York")),
    ("zoneinfo Europe/London", zoneinfo.ZoneInfo("Europe/London")),
    ("zoneinfo Asia/Kolkata", zoneinfo.ZoneInfo("Asia/Kolkata")),
    ("zoneinfo Australia/Lord_Howe", zoneinfo.ZoneInfo("Australia/Lord_Howe")),
]


# ZoneInfo keys the Rust reader converts without a tz database: UTC under its aliases and the
# fixed `Etc/GMT±N` zones. Every other ZoneInfo is left to the Python backend.
UTC_KEYS = {"UTC", "Etc/UTC", "Etc/UCT", "UCT", "Etc/Universal", "Universal", "Etc/Zulu", "Zulu", "Etc/GMT", "GMT"}
UTC_KEYS |= {"Etc/GMT0", "GMT0", "Etc/GMT+0", "Etc/GMT-0", "GMT+0", "GMT-0", "Etc/Greenwich", "Greenwich"}


def rust_reads_tz(tzinfo):
    """Every zone this generator uses: fixed offsets, pytz (the pickle carries the offset) and
    zoneinfo through chrono-tz."""
    return True


def aware(tz, *fields, fold=0):
    if hasattr(tz, "localize"):
        return tz.localize(datetime.datetime(*fields))
    return datetime.datetime(*fields, tzinfo=tz, fold=fold)


async def vectors_for(label, tz):
    engine = create_engine("sqlite://")
    scheduler = AsyncIOScheduler()
    scheduler.configure(jobstores={"default": SQLAlchemyJobStore(engine=engine)}, timezone=tz)
    scheduler.start(paused=True)
    try:
        scheduler.add_job(noop, "interval", minutes=5, id="a_job", replace_existing=True, coalesce=True, max_instances=1)
        scheduler.add_job(other_name, "interval", minutes=1440, id="renamed_job", replace_existing=True, coalesce=True, max_instances=1)
        scheduler.add_job(
            with_args,
            "interval",
            minutes=2,
            id="paused_job",
            replace_existing=True,
            args=[1, "x"],
            kwargs={"k": [None, 2.5]},
        )
        scheduler.get_job("paused_job").pause()
        # A whole-second next run (Pydantic renders no fraction then).
        scheduler.modify_job("a_job", next_run_time=aware(tz, 2026, 10, 15, 18, 0, 0))
        # A winter one, and the repeated hour of a transition back (fold=1), where zones differ.
        scheduler.add_job(noop, "interval", minutes=60, id="winter_job", replace_existing=True)
        scheduler.modify_job("winter_job", next_run_time=aware(tz, 2026, 12, 15, 18, 0, 0, 250000))
        if isinstance(tz, zoneinfo.ZoneInfo):
            scheduler.add_job(noop, "interval", minutes=60, id="fold_job", replace_existing=True)
            scheduler.modify_job("fold_job", next_run_time=aware(tz, 2026, 11, 1, 1, 30, 0, fold=1))
        out = []
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT id, job_state FROM apscheduler_jobs ORDER BY id")).fetchall()
        for job_id, state in rows:
            job = scheduler.get_job(job_id)
            nrt = job.next_run_time
            rendered = None
            if nrt is not None:
                rendered = JobsNextRunResponse(next_run_time=nrt, success=True, message="m").model_dump(mode="json")["next_run_time"]
            out.append(
                {
                    "label": f"{label}: {job_id}",
                    "job_state": state.hex(),
                    "id": job.id,
                    "name": job.name,
                    "func": job.func_ref,
                    "next_run_time": rendered,
                    "tz_supported": nrt is None or rust_reads_tz(nrt.tzinfo),
                },
            )
        return out
    finally:
        scheduler.shutdown(wait=False)


async def main():
    vectors = []
    for label, tz in SCHEDULER_ZONES:
        vectors.extend(await vectors_for(label, tz))
    json.dump(
        {
            "generator": "scripts/gen-apscheduler-vectors.py",
            "apscheduler": apscheduler.__version__,
            "pydantic": pydantic.VERSION,
            "pytz": pytz.__version__,
            "vectors": vectors,
        },
        sys.stdout,
        indent=1,
    )
    sys.stdout.write("\n")


asyncio.run(main())
