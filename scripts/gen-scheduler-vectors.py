"""Generate the scheduler vectors for copilot-scheduler (the jobs table and APScheduler's arithmetic).

    MYSQL_URL=127.0.0.1:3306 MYSQL_USER=x MYSQL_PASSWORD=x JWT_SECRET=<not the default> \
        backend/.venv/bin/python -I scripts/gen-scheduler-vectors.py \
        > crates/copilot-scheduler/src/scheduler_vectors.json

(run from the repository root; the backend is imported for `get_function_by_name`, nothing connects
to the database.)

* `functions` — `get_function_by_name`'s map, in its order: the key (a job id), the callable's
  `job.name` (`get_callable_name`), its `func` reference (`obj_to_ref`) and the hand-over guard's
  job id; `unknown_function` is the `ValueError` an unknown name raises.
* `next_fire` — `IntervalTrigger(minutes=m, start_date=…, timezone=utc).get_next_fire_time(prev, now)`
  in epoch microseconds: the first run (no previous fire, `now` before, on or after the start
  date: `ceil` over float seconds), the next one after a fire, a zero interval (one second).
* `run_times` — what `_process_jobs` makes of a due job with `coalesce=True`: `_get_run_times(now)`,
  the one run time coalescing keeps, and the next run time stored (`get_next_fire_time(last, now)`).
* `fromtimestamp` — `datetime.fromtimestamp(t, timezone.utc)` for floats whose microseconds round
  half to even.
* `intervals` — `IntervalTrigger(minutes=m, timezone=utc)` built at a fixed `now`: its interval
  (a zero one is one second) and `start_date` (now + interval), or the `OverflowError` `timedelta`
  or the date addition raises.

Regenerate after upgrading APScheduler or Python, or after a change to `get_function_by_name`.
"""

import ast
import datetime
import inspect
import json
import sys

import apscheduler
from apscheduler.job import Job
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.util import get_callable_name
from apscheduler.util import obj_to_ref

sys.path.insert(0, "backend")

from app.schedulers import scheduler as scheduler_module  # noqa: E402

UTC = datetime.timezone.utc
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)


def us(dt):
    """Epoch microseconds of an aware datetime (exact)."""
    if dt is None:
        return None
    delta = dt - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def at(value):
    return EPOCH + datetime.timedelta(microseconds=value)


def functions():
    tree = ast.parse(inspect.getsource(scheduler_module.get_function_by_name))
    keys = [k.value for node in ast.walk(tree) if isinstance(node, ast.Dict) for k in node.keys]
    out = []
    for key in keys:
        function = scheduler_module.get_function_by_name(key)
        out.append(
            {
                "key": key,
                "name": get_callable_name(function),
                "func": obj_to_ref(function),
                "guard": getattr(function, "__rust_handover_job_id__", None),
            },
        )
    try:
        scheduler_module.get_function_by_name("{name}")
    except ValueError as e:
        unknown = str(e)
    return out, unknown


START = us(datetime.datetime(2026, 10, 15, 18, 0, 0, 123457, tzinfo=UTC))
MINUTES = [0, 1, 2, 4, 5, 6, 15, 30, 60, 1440, 10080, 525600]
OFFSETS_US = [
    -3_600_000_000,
    -1,
    0,
    1,
    499_999,
    500_000,
    59_999_999,
    60_000_000,
    60_000_001,
    61_123_456,
    299_999_999,
    300_000_000,
    86_399_999_999,
    86_400_000_000,
    86_400_000_001,
    7 * 86_400_000_000 + 3,
    400 * 86_400_000_000 + 777_777,
]


def next_fire():
    out = []
    for minutes in MINUTES:
        trigger = IntervalTrigger(minutes=minutes, start_date=at(START), timezone=UTC)
        for offset in OFFSETS_US:
            now = START + offset
            out.append(
                {
                    "minutes": minutes,
                    "start": START,
                    "prev": None,
                    "now": now,
                    "next": us(trigger.get_next_fire_time(None, at(now))),
                },
            )
        for prev_offset in (0, 1, 333_333, 60_000_000, 86_400_000_000 * 3 + 5):
            prev = START + prev_offset
            out.append(
                {
                    "minutes": minutes,
                    "start": START,
                    "prev": prev,
                    "now": prev,
                    "next": us(trigger.get_next_fire_time(at(prev), at(prev))),
                },
            )
    return out


def run_times():
    out = []
    for minutes in (1, 2, 5, 15, 1440):
        trigger = IntervalTrigger(minutes=minutes, start_date=at(START), timezone=UTC)
        for next_offset, now_offset in (
            (0, 0),
            (0, 1),
            (0, 999_999),
            (0, 1_000_001),
            (0, minutes * 60_000_000 - 1),
            (0, minutes * 60_000_000),
            (0, minutes * 60_000_000 * 3 + 17),
            (minutes * 60_000_000, minutes * 60_000_000 * 10 + 5),
            (0, 86_400_000_000 * 2 + 123),
        ):
            job = Job.__new__(Job)
            job.trigger = trigger
            job.next_run_time = at(START + next_offset)
            now = at(START + now_offset)
            times = job._get_run_times(now)
            kept = times[-1:]
            following = trigger.get_next_fire_time(kept[-1], now) if kept else None
            out.append(
                {
                    "minutes": minutes,
                    "start": START,
                    "next_run_time": START + next_offset,
                    "now": START + now_offset,
                    "run_times": [us(t) for t in times],
                    "kept": [us(t) for t in kept],
                    "next": us(following),
                },
            )
    return out


def fromtimestamp():
    out = []
    for t in (
        1_800_000_000.0,
        1_800_000_000.0000005,
        1_800_000_000.0000015,
        1_800_000_000.0000025,
        1_800_000_000.123456,
        1_800_000_000.1234565,
        1_800_000_000.9999995,
        1_800_000_000.9999999,
        1_760_551_200.123457 + 300.0,
        1_760_551_200.123457 + 86_400.0 * 3,
        1_760_551_200.123457 + 60.0 * 7,
        0.0000005,
        -0.0000005,
        -1.5,
    ):
        out.append({"t": t, "repr": repr(t), "us": us(datetime.datetime.fromtimestamp(t, UTC))})
    return out


class _FixedNow(datetime.datetime):
    """`datetime.now()` at a fixed instant, for the trigger's `start_date = now + interval`."""

    fixed = None

    @classmethod
    def now(cls, tz=None):
        return cls.fixed.astimezone(tz)


def intervals():
    import apscheduler.triggers.interval as interval_module

    out = []
    now = datetime.datetime(2026, 10, 15, 18, 0, 0, 1, tzinfo=UTC)
    _FixedNow.fixed = now
    real = interval_module.datetime
    interval_module.datetime = _FixedNow
    try:
        for minutes in (
            0,
            1,
            5,
            1440,
            10**8,
            3_986_000_000,
            4_000_000_000,
            999_999_999 * 1440 + 1439,
            999_999_999 * 1440 + 1440,
            10**30,
            -1,
            -999_999_999 * 1440,
            -999_999_999 * 1440 - 1,
        ):
            entry = {"minutes": str(minutes), "now": us(now)}
            try:
                trigger = IntervalTrigger(minutes=minutes, timezone=UTC)
                entry["interval_us"] = str(round(trigger.interval_length * 1_000_000))
                entry["start"] = us(trigger.start_date)
            except OverflowError as e:
                entry["error"] = f"OverflowError: {e}"
            out.append(entry)
    finally:
        interval_module.datetime = real
    return out


def main():
    table, unknown = functions()
    json.dump(
        {
            "generator": "scripts/gen-scheduler-vectors.py",
            "apscheduler": apscheduler.__version__,
            "python": sys.version.split()[0],
            "functions": table,
            "unknown_function": unknown,
            "next_fire": next_fire(),
            "run_times": run_times(),
            "fromtimestamp": fromtimestamp(),
            "intervals": intervals(),
        },
        sys.stdout,
        indent=1,
        ensure_ascii=False,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
