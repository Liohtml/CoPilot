"""Regenerate the vectors that pin the Pydantic models of the ported connectors (and the
model engine they run on) to pydantic.

    cd backend && PYTHONPATH=.:tests/e2e MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-connector-model-vectors.py

Writes:

* `crates/copilot-upstream/src/model_vectors.json` — the lax rules: every probe value through
  every field type of a test model (`int`, `float`, `bool`, `str`, `None`, `datetime`, lists,
  dicts, `Any`, optional fields, smart unions with and without models), as the JSON FastAPI's
  `serialize_json` writes, or `str(ValidationError)`;
* `crates/copilot-graylog/src/model_vectors.json` — every Graylog model on samples of Graylog 6.1
  and 7.0 answers (`tests/e2e/connector_samples.py`) and on mutations of them (a key deleted, or
  set to a value of another type), likewise.

A vector holds the JSON-mode dump's text (`ok`) or its SHA-256 (`ok_sha256`, for mutations of a
large sample), or the `ValidationError` text (`err`). Re-run after a Pydantic upgrade or a change
to one of these models.
"""

import hashlib
import json
import math
import pathlib
from datetime import datetime
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

import connector_samples as samples
from pydantic import BaseModel
from pydantic import TypeAdapter
from pydantic import ValidationError

ROOT = pathlib.Path(__file__).resolve().parent.parent / "crates"


def dump(model, instance):
    return TypeAdapter(model).dump_json(instance, by_alias=True).decode()


def run(model, value):
    """`Model(**value)` (or `model_validate` for a non-dict): the dump, or the error text."""
    try:
        instance = model(**value) if isinstance(value, dict) else model.model_validate(value)
    except ValidationError as e:
        return {"err": str(e)}
    return {"ok": dump(model, instance)}


def text(value):
    return json.dumps(value, allow_nan=True, ensure_ascii=False)


# --- the engine's own vectors ------------------------------------------------------------------


class Sub(BaseModel):
    x: int
    y: Optional[str] = None


class Lax(BaseModel):
    i: int = 0
    f: float = 0.0
    b: bool = False
    s: str = ""
    n: Optional[None] = None
    oi: Optional[int] = None
    li: List[int] = []
    ld: List[Optional[str]] = []
    ds: Dict[str, str] = {}
    da: dict = {}
    la: list = []
    a: Any = None
    dt: Optional[datetime] = None
    m: Optional[Sub] = None
    u_str_model: Optional[Union[str, Sub]] = None
    u_int_str: Optional[Union[int, str]] = None
    u_str_list: Optional[Union[str, List[Sub]]] = None
    u_dict: Optional[Dict[str, Union[str, List[str]]]] = None


PROBES = [
    None,
    True,
    False,
    0,
    1,
    2,
    -1,
    12345678901234567890123,
    1.0,
    1.5,
    0.0,
    -0.0,
    1e20,
    2.5e-5,
    float("nan"),
    float("inf"),
    "",
    "x",
    " 12 ",
    "1_000",
    "1.0",
    "1.00",
    "1.5",
    "+5",
    "-0",
    "0x10",
    "1e3",
    " 1.5 ",
    "inf",
    "nan",
    "true",
    "YES",
    "off",
    " t ",
    "2026-01-02",
    "2026-01-02T03:04:05Z",
    "2026-01-02T03:04:05.123456789+05:30",
    "2026-01-02 03:04:05",
    "2026-13-02",
    "1700000000",
    "1700000000123",
    [],
    [1],
    ["1", None],
    [{"x": "1"}],
    {},
    {"a": 1},
    {"x": "1"},
    {"x": 1, "y": 2},
    {"k": ["a", 1]},
]


def engine_vectors():
    out = []
    for field in Lax.model_fields:
        for probe in PROBES:
            value = {field: probe}
            out.append({"field": field, "input": text(value), **run(Lax, value)})
    for value in ([], "x", 5, None):
        out.append({"field": "", "input": text(value), **run(Lax, value)})
    out.append({"field": "", "input": text({"m": {}}), **run(Lax, {"m": {}})})
    return out


# --- per-connector model vectors ----------------------------------------------------------------

MUTATIONS = [None, "x", "12", 1.5, True, [], {}]


def mutations(sample, depth=2, path=()):
    """(path, op, value) patches: delete each key, or set it to each mutation value."""
    if not isinstance(sample, dict) or depth == 0:
        return
    for key, value in sample.items():
        yield (path + (key,), "del", None)
        for m in MUTATIONS:
            if m != value:
                yield (path + (key,), "set", m)
        if isinstance(value, dict):
            yield from mutations(value, depth - 1, path + (key,))
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            yield from mutations(value[0], depth - 1, path + (key, 0))


def apply(sample, path, op, value):
    data = json.loads(json.dumps(sample))
    target = data
    for part in path[:-1]:
        target = target[part]
    if op == "del":
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return data


def model_vectors(cases):
    bases, vectors, mutated = [], [], set()
    for name, model, sample in cases:
        idx = len(bases)
        base = run(model, sample)
        bases.append({"model": name, "input": text(sample), **base})
        if name in mutated:
            continue
        mutated.add(name)
        for path, op, value in mutations(sample):
            result = run(model, apply(sample, path, op, value))
            entry = {"base": idx, "path": list(path), "op": op}
            if op == "set":
                entry["value"] = text(value)
            if "ok" in result:
                entry["ok_sha256"] = hashlib.sha256(result["ok"].encode()).hexdigest()
            else:
                entry["err"] = result["err"]
            vectors.append(entry)
    return {"bases": bases, "vectors": vectors}


def graylog_cases():
    from app.connectors.graylog.schema import collector
    from app.connectors.graylog.schema import events
    from app.connectors.graylog.schema import management
    from app.connectors.graylog.schema import monitoring
    from app.connectors.graylog.schema import pipelines
    from app.connectors.graylog.schema import streams
    from app.integrations.utils.schema import EventShipperPayload

    cases = []
    for name, info in samples.GRAYLOG_INDICES["all"]["indices"].items():
        cases.append(("GraylogIndexItem", collector.GraylogIndexItem, {"index_name": name, "index_info": info}))
        break
    for version in (6, 7):
        for inp in samples.graylog_inputs(version)["inputs"]:
            cases.append(("ConfiguredInput", collector.ConfiguredInput, inp))
        for state in samples.graylog_input_states(version)["states"]:
            cases.append(("RunningInput", collector.RunningInput, state))
    for definition in samples.GRAYLOG_EVENT_DEFINITIONS:
        cases.append(("EventDefinition", events.EventDefinition, definition))
    cases.append(("AlertQuery", events.AlertQuery, {}))
    cases.append(
        (
            "AlertQuery",
            events.AlertQuery,
            {
                "query": "x",
                "page": 2,
                "per_page": "50",
                "filter": {"alerts": "include", "event_definitions": ["a"]},
                "timerange": {"range": 3600, "type": "relative"},
            },
        ),
    )
    cases.append(("AlertEvent", events.AlertEvent, samples.GRAYLOG_ALERT_EVENT))
    cases.append(("Context", events.Context, samples.GRAYLOG_EVENTS_SEARCH["context"]))
    cases.append(("Parameters", events.Parameters, samples.GRAYLOG_EVENTS_SEARCH["parameters"]))
    cases.append(("DeletedIndexBody", management.DeletedIndexBody, {"index_name": " x "}))
    cases.append(("StopInputBody", management.StopInputBody, {"input_id": "a"}))
    cases.append(("StopStreamBody", management.StopStreamBody, {"stream_id": "a"}))
    cases.append(
        (
            "UrlWhitelistEntryResponse",
            management.UrlWhitelistEntryResponse,
            {"url_whitelist_entries": samples.GRAYLOG_URL_ALLOWLIST, "success": True, "message": "m"},
        ),
    )
    cases.append(("GraylogMessages", monitoring.GraylogMessages, samples.GRAYLOG_MESSAGES["messages"][1]))
    cases.append(("GraylogThroughputMetrics", monitoring.GraylogThroughputMetrics, {"metric": "m", "value": 7}))
    cases.append(("GraylogUncommittedJournalEntries", monitoring.GraylogUncommittedJournalEntries, {"uncommitted_journal_entries": 3}))
    cases.append(
        (
            "GraylogEventNotificationsResponse",
            monitoring.GraylogEventNotificationsResponse,
            {"event_notifications": samples.GRAYLOG_EVENT_NOTIFICATIONS, "success": True, "message": "m"},
        ),
    )
    for pipeline in samples.GRAYLOG_PIPELINES:
        cases.append(("Pipeline", pipelines.Pipeline, pipeline))
    cases.append(
        ("StageWithRuleID", pipelines.StageWithRuleID, {"match": "EITHER", "rules": ["a", "b"], "stage": 0, "rule_ids": ["1", None]}),
    )
    for rule in samples.GRAYLOG_PIPELINE_RULES:
        cases.append(("PipelineRule", pipelines.PipelineRule, rule))
    for stream in samples.GRAYLOG_STREAMS["streams"]:
        cases.append(("Stream", streams.Stream, stream))
    cases.append(("EventShipperPayload", EventShipperPayload, {"integration": "x", "customer_code": "c", "z": None, "a": [1]}))
    return cases


def write(path, doc):
    """One vector per line: diffable, and small enough for the repository."""
    lines = ["{"]
    keys = list(doc)
    for k_i, key in enumerate(keys):
        items = doc[key]
        lines.append(f"{json.dumps(key)}: [")
        for i, item in enumerate(items):
            lines.append(json.dumps(item, ensure_ascii=False) + ("," if i + 1 < len(items) else ""))
        lines.append("]" + ("," if k_i + 1 < len(keys) else ""))
    lines.append("}")
    path.write_text("\n".join(lines) + "\n")


def main():
    engine = {"vectors": engine_vectors()}
    write(ROOT / "copilot-upstream" / "src" / "model_vectors.json", engine)
    graylog = model_vectors(graylog_cases())
    write(ROOT / "copilot-graylog" / "src" / "model_vectors.json", graylog)
    print(f"engine: {len(engine['vectors'])} vectors; graylog: {len(graylog['bases'])} bases, {len(graylog['vectors'])} mutations")
    assert not math.isnan(0.0)


if __name__ == "__main__":
    main()
