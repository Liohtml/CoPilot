"""Generate pydantic datetime-parsing vectors for copilot-web (query/body `datetime` fields).

Each vector: the raw string, and either the naive wall-clock value the backend binds
into SQL (tzinfo dropped, as pymysql does) or the pydantic error type + message.

    backend/.venv/bin/python -I scripts/gen-pydantic-datetime-vectors.py \
        > crates/copilot-web/src/pydantic_datetime_vectors.json

Re-run after a pydantic upgrade and keep `speedate` in Cargo.toml at pydantic-core's version.
"""
import json
import sys
from datetime import datetime
from typing import Optional

import pydantic
import pydantic_core
from pydantic import TypeAdapter
from pydantic import ValidationError

ta = TypeAdapter(Optional[datetime])
inputs = [
    "2026-01-02T03:04:05",
    "2026-01-02 03:04:05",
    "2026-01-02t03:04:05",
    "2026-01-02_03:04:05",
    "2026-01-02",
    "2026-01-02T03:04:05Z",
    "2026-01-02T03:04:05z",
    "2026-01-02T03:04:05+05:00",
    "2026-01-02T03:04:05-0130",
    "2026-01-02T03:04:05+05",
    "2026-01-02T03:04:05.123456",
    "2026-01-02T03:04:05,5",
    "2026-01-02T03:04:05.1234567",
    "2026-01-02T03:04:05.123456789123",
    "2026-01-02T03:04",
    "2026-01-02T03",
    "2026-01-02T",
    "2026-01-02T03:04:60",
    "2026-01-02T23:59:59",
    "1700000000",
    "1700000000.5",
    "-1",
    "0",
    "20260102",
    "17000000000000",
    "1700000000123",
    "1e9",
    "1700000000.123456789",
    "99999999999999999999",
    "abc",
    "",
    " ",
    "2026-13-01",
    "2026-02-30",
    "2026-01-02T25:00:00",
    "2026-1-2",
    " 2026-01-02",
    "2026-01-02 ",
    "2026/01/02",
    "2026-01-02X03:04:05",
    "2026-01-02T03:04:05+25:00",
    "2026-01-02T03:04:05+05:00:00",
    "0001-01-01T00:00:00",
    "9999-12-31T23:59:59.999999",
    "2024-02-29",
    "2023-02-29",
    "2026-01-02T03:04:05.",
    "2026-01-02T03:04:05Zjunk",
    "+2026-01-02",
    "2026-01-02T03:4:05",
    "12345",
    "2026",
    "2026-01",
    "2026-01-0",
    "T03:04:05",
]
out = []
for raw in inputs:
    try:
        v = ta.validate_python(raw)
        out.append({"input": raw, "ok": v.replace(tzinfo=None).isoformat()})
    except ValidationError as e:
        err = e.errors()[0]
        out.append({"input": raw, "type": err["type"], "msg": err["msg"]})
json.dump(
    {"pydantic": pydantic.VERSION, "pydantic_core": pydantic_core.__version__, "vectors": out},
    sys.stdout,
    indent=1,
    ensure_ascii=False,
)
