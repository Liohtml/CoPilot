"""Regenerate the vectors that pin the pure parts of the SOCFortress UBA port (`copilot-uba`) to the
Python module it ports (`app/connectors/uba/`) and the libraries under it.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-uba-vectors.py

Writes `crates/copilot-uba/src/uba_vectors.json`:

* `bodies` — every request model of the routes (`schema/uba.py`, `schema/provision.py`) on probe
  inputs, as FastAPI validates a body (`TypeAdapter(model).validate_python(…, from_attributes=True)`):
  what the service sends (`model_dump()`, with `exclude_none` / `exclude_unset` where the service
  asks for it) as httpx's compact JSON, or the errors `(type, loc, msg)`;
* `queries` — the routes' query and path parameter types (`float` / `int` with their bounds,
  `bool`, `str` with lengths and patterns) on raw strings: the value or the error type;
* `params` — httpx 0.28's `QueryParams` of the values the services pass (`str()` of a float,
  `true`/`false`, lists), as the URL's query string;
* `segments` — `path_segment()` (`quote(value, safe="")`);
* `formats` — `str.format(source=…, tenant=…)` of UBA's object-name templates, or the
  exception class and text (provisioning names its Graylog objects with them);
* `lowers` — `str.lower()` (the default index patterns are built on the lowered customer code).

Re-run after a Pydantic, httpx or Python upgrade, or a change to the request models.
"""

import json
import pathlib
from typing import Annotated

import httpx
from pydantic import Field
from pydantic import TypeAdapter
from pydantic import ValidationError

from app.connectors.uba.schema.provision import UbaModeRequest
from app.connectors.uba.schema.provision import UbaProvisionRequest
from app.connectors.uba.schema.uba import UbaAlertThresholdRequest
from app.connectors.uba.schema.uba import UbaBacktestRequest
from app.connectors.uba.schema.uba import UbaFeedbackRequest
from app.connectors.uba.schema.uba import UbaIdentityMergeRequest
from app.connectors.uba.schema.uba import UbaRuleSettingRequest
from app.connectors.uba.schema.uba import UbaScoreRequest
from app.connectors.uba.schema.uba import UbaSuppressionRequest
from app.connectors.uba.utils.universal import path_segment

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-uba" / "src" / "uba_vectors.json"


def errors(e: ValidationError):
    return [[x["type"], list(x["loc"]), x["msg"]] for x in e.errors()]


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


MODELS = {
    "feedback": (UbaFeedbackRequest, {}),
    "suppression": (UbaSuppressionRequest, {}),
    "backtest": (UbaBacktestRequest, {"exclude_none": True}),
    "score": (UbaScoreRequest, {}),
    "merge": (UbaIdentityMergeRequest, {}),
    "rule_setting": (UbaRuleSettingRequest, {"exclude_unset": True}),
    "alert_threshold": (UbaAlertThresholdRequest, {}),
    "mode": (UbaModeRequest, {}),
    "provision": (UbaProvisionRequest, {}),
}

BODIES = {
    "feedback": [
        {"verdict": "TRUE_POSITIVE"},
        {"verdict": "FALSE_POSITIVE", "reason": "EXPECTED_ACTIVITY", "note": "é", "suppress": "off", "suppress_days": "7"},
        {"verdict": "FALSE_POSITIVE\n"},
        {"verdict": "false_positive"},
        {"verdict": "TRUE_POSITIVE", "reason": "r" * 51, "note": None, "suppress": None, "suppress_days": 0},
        {"verdict": 1, "reason": 5, "note": ["x"], "suppress": 2, "suppress_days": 365.0},
        {"verdict": "TRUE_POSITIVE", "suppress_days": 7.5, "suppress": 1},
        {"verdict": "TRUE_POSITIVE", "suppress_days": "1_0", "suppress": "YES"},
        {"verdict": "TRUE_POSITIVE", "suppress_days": True, "suppress": " true"},
        {},
    ],
    "suppression": [
        {"entity_key": "k", "rule_ids": ["a"]},
        {"entity_key": "", "rule_ids": []},
        {"entity_key": "x" * 513, "rule_ids": [1, None], "days": 366, "reason": "r" * 501},
        {"entity_key": "k", "rule_ids": "a"},
        {"entity_key": "k", "rule_ids": {"a": 1}, "days": "30"},
        {"rule_ids": ["a"], "days": None},
    ],
    "backtest": [
        {},
        {"days": 2, "warmup_days": "1.5"},
        {"days": 0, "warmup_days": 15},
        {"days": "nan", "warmup_days": "-inf"},
        {"days": 7.0000001, "warmup_days": 14},
        {"days": True, "rules": ["r1"], "filter": "f"},
        {"rules": "r1", "filter": "x" * 1001},
        {"rules": None, "filter": None, "days": None},
        {"days": "1e0", "warmup_days": " 2 "},
    ],
    "score": [{"score": 0}, {"score": 100}, {"score": -0.0}, {"score": 100.5}, {"score": "inf"}, {"score": None}, {}, {"score": "1_5"}],
    "merge": [{"into": "a"}, {"into": ""}, {"into": "x" * 65}, {"into": 5}, {}],
    "rule_setting": [
        {},
        {"enabled": None},
        {"score": None},
        {"enabled": "off", "score": "12.5"},
        {"enabled": "maybe", "score": 101},
        {"enabled": 0, "score": True},
        {"other": 1},
    ],
    "alert_threshold": [{"alert_threshold": 20}, {"alert_threshold": 19.99}, {"alert_threshold": "1000"}, {"alert_threshold": True}, {}],
    "mode": [{"mode": "active"}, {"mode": "learning"}, {"mode": "LEARNING"}, {"mode": None}, {}],
    "provision": [
        {},
        {"bootstrap_days": 0, "deploy_wazuh_rules": "true"},
        {"bootstrap_days": 31},
        {"bootstrap_days": "-1", "deploy_wazuh_rules": "nope"},
        {"bootstrap_days": 1.5},
    ],
}

QUERY_TYPES = {
    "float_ge0": Annotated[float, Field(ge=0)],
    "int_ge1": Annotated[int, Field(ge=1)],
    "int_1_500": Annotated[int, Field(ge=1, le=500)],
    "int_1_100": Annotated[int, Field(ge=1, le=100)],
    "int": int,
    "bool": bool,
    "str_1_512": Annotated[str, Field(min_length=1, max_length=512)],
    "str_2_200": Annotated[str, Field(min_length=2, max_length=200)],
    "str_step": Annotated[str, Field(pattern="^(15m|1h|6h|1d)$")],
    "str_status": Annotated[str, Field(pattern="^(open|closed)$")],
}
QUERY_INPUTS = [
    "0",
    "1",
    " 1 ",
    "1.0",
    "1.5",
    "-0",
    "1_000",
    "1__0",
    "_1",
    "+2",
    "1e3",
    "1E-5",
    ".5",
    "5.",
    "inf",
    "-Infinity",
    "nan",
    "NaN",
    "0x10",
    "500",
    "501",
    "100",
    "101",
    "99999999999999999999999",
    "",
    " ",
    "true",
    "True",
    " true",
    "yes",
    "On",
    "off",
    "f",
    "N",
    "2",
    "1h",
    "6h",
    "1h\n",
    "open",
    "closed",
    "OPEN",
    "j",
    "ja",
    "é",
    "x" * 201,
    "x" * 513,
]

PARAMS = [
    {"a": True, "b": False, "c": 0.0, "d": 1e-05, "e": 1e16, "f": 12, "g": "é /?&=+"},
    {"min_risk": 1.0, "native": "false", "page": 1, "page_size": 50},
    {"entity_key": ["a", None, True, 1.5], "status": "open", "page_size": 500},
    {"x": {"k": [1]}, "y": None, "z": ""},
]

SEGMENTS = ["acme", "windows-demo\\jdoe", "upn:jane@contoso.com", "é ü", "a/b", "..", "~_.-", "%2F", "x?#&=+"]

TEMPLATES = [
    "UBA FEED - {source} - {tenant}",
    "UBA ALERTS - {tenant}",
    "{tenant}",
    "{{literal}} {tenant}",
    "no placeholder",
    "{tenant!r}",
    "{tenant!s:>12}",
    "{tenant:.2}",
    "{tenant:_<8}",
    "{source:^9}",
    "{missing}",
    "{0}",
    "{}",
    "{",
    "}",
    "a } b",
    "{tenant",
    "{tenant!x}",
    "{tenant:d}",
]
TENANTS = ["acme", "é'x", ""]

LOWERS = ["ACME", "Acme-01", "İSTANBUL", "ΣΑΣ", "ß", "ǅ", "Ⅻ", "ﬃ"]


def body_vectors():
    out = []
    for name, inputs in BODIES.items():
        model, dump = MODELS[name]
        for value in inputs:
            case = {"model": name, "input": value}
            try:
                parsed = TypeAdapter(model).validate_python(value, from_attributes=True)
                case["dump"] = compact(parsed.model_dump(**dump))
            except ValidationError as e:
                case["errors"] = errors(e)
            out.append(case)
    return out


def query_vectors():
    out = []
    for name, ty in QUERY_TYPES.items():
        adapter = TypeAdapter(ty)
        for raw in QUERY_INPUTS:
            case = {"type": name, "input": raw}
            try:
                value = adapter.validate_python(raw)
                case["value"] = value if isinstance(value, (str, bool)) else repr(value)
            except ValidationError as e:
                case["error"] = e.errors()[0]["type"]
            out.append(case)
    return out


def format_vectors():
    out = []
    for template in TEMPLATES:
        for tenant in TENANTS:
            case = {"template": template, "tenant": tenant}
            try:
                case["ok"] = template.format(source="WAZUH", tenant=tenant)
            except Exception as e:  # noqa: BLE001 - the class and text are the vector
                case["error"] = [type(e).__name__, str(e)]
            out.append(case)
    return out


def main():
    data = {
        "bodies": body_vectors(),
        "queries": query_vectors(),
        "params": [{"params": [[k, v] for k, v in p.items()], "query": str(httpx.QueryParams(p))} for p in PARAMS],
        "segments": [{"input": s, "quoted": path_segment(s)} for s in SEGMENTS],
        "formats": format_vectors(),
        "lowers": [{"input": s, "lower": s.lower()} for s in LOWERS],
    }
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False, allow_nan=True) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
