"""Regenerate the vectors that pin the pure parts of the Customer Portal port
(`copilot-customer-portal`) to the Python modules and libraries it reproduces.

    cd backend && TZ=UTC PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-customer-portal-vectors.py

Writes `crates/copilot-customer-portal/src/portal_vectors.json`:

* `validators` — `utils/validators.py` on raw values: the value kept or the `ValueError` text;
* `b64decode` — `base64.b64decode(s, validate=True)` (CPython's strict `a2b_base64`): the bytes
  (hex) or the `binascii.Error` text;
* `models` — the three request models (`UpdatePortalSettingsRequest`,
  `PatchPortalSettingsRequest`, `UpdateCustomerBrandingRequest`) on request bodies: the
  validated fields (and, for the PATCH, the fields sent and `reset`) or Pydantic's errors
  (`type`, `loc`, `msg`). Bodies naming several null fields are left out: Python's message
  then depends on its string hashes;
* `bools` / `ints` — Pydantic's lax `bool` (any value) and `int` (from query text);
* `csv` — `csv.writer` rows (the `excel` dialect);
* `timestamps` — `schema/overview.py:_utc_timestamp`;
* `content_versions` — `services/settings.py:logo_content_version`;
* `logo_versions` — `services/settings.py:_logo_version` (the generator runs with TZ=UTC);
* `sorted_customers` — `services/me.py`'s name order (`casefold`, then the code);
* `responses` — a Starlette `Response(content, status, headers, media_type)` through
  `GZipMiddleware(minimum_size=1000)`: the raw headers in order and whether the body was
  gzipped.

Re-run after a Python, Pydantic or Starlette upgrade, or a change to these modules.
"""

import asyncio
import base64
import binascii
import csv
import datetime
import gzip
import io
import json
import pathlib

from pydantic import TypeAdapter
from pydantic import ValidationError
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import Response

from app.customer_portal.schema.branding import UpdateCustomerBrandingRequest
from app.customer_portal.schema.overview import _utc_timestamp
from app.customer_portal.schema.settings import PatchPortalSettingsRequest
from app.customer_portal.schema.settings import UpdatePortalSettingsRequest
from app.customer_portal.services.settings import _logo_version
from app.customer_portal.services.settings import logo_content_version
from app.customer_portal.utils import validators

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-customer-portal" / "src" / "portal_vectors.json"

LONG = "A" * (validators.MAX_LOGO_BASE64_BYTES + 4)

VALIDATOR_INPUTS = {
    "brand_color": [
        None,
        "",
        "  ",
        " #ABC ",
        "#abcdef",
        "#ABCDEF",
        "#12345",
        "red",
        "#abcd",
        "#ggg",
        "　#abc\n",
        "#abc\n",
        "##abc",
        "#ABCDEF0",
    ],
    "logo_base64": [
        None,
        "",
        "QQ==",
        "QR==",
        "QQ=",
        "QQ",
        "Q",
        "QUJD",
        "QUJD=",
        "QUJD==",
        "QUJD===",
        "=",
        "==",
        "QQ==\n",
        "QUJD\n",
        "QQ==\n\n",
        "not base64!",
        "data:image/png;base64,iVBORw0KGgo=",
        "data:,",
        "data:x",
        "data:image/png;base64,",
        "data:a,b,c",
        "iVBORw0KGgo=",
        "a=b",
        "Q=Q=",
        "é",
        LONG,
        "A" * validators.MAX_LOGO_BASE64_BYTES,
    ],
    "logo_mime_type": [None, "", "image/png", "image/svg+xml", "IMAGE/PNG", "application/pdf", " image/png"],
}

B64_INPUTS = [
    "",
    "=",
    "==",
    "QQ==",
    "QQ=",
    "QQ",
    "Q",
    "QUJD",
    "QUJDR",
    "QUJDRA==",
    "QUJDRA=",
    "QR==",
    "QQ==QQ==",
    "QQ=a",
    "Q=Q=",
    "QUJD=",
    "QUJD==",
    "QQ===",
    "Q===",
    "QUI=",
    "QUI==",
    "QU=I",
    "Q U",
    "QQ==\n",
    "QUJD\n",
    "=QUJD",
    "QUJDRA",
    "QUJ",
    "QUJDRAE",
    " QQ==",
    "é",
    "+/+/",
    "-_-_",
]

BODIES = [
    {},
    {"title": "x"},
    {"title": ""},
    {"title": None},
    {"title": 5},
    {"title": "x" * 255},
    {"title": "x" * 256},
    {"title": "é" * 255},
    {"brand_color": " #ABC "},
    {"brand_color": "#12345"},
    {"brand_color": "  "},
    {"brand_color": None},
    {"brand_color": "   #abcdef   "},
    {"logo_base64": "QQ=="},
    {"logo_base64": "QQ==", "logo_mime_type": "image/png"},
    {"logo_base64": "data:image/png;base64,QQ==", "logo_mime_type": "image/png"},
    {"logo_base64": "", "logo_mime_type": "image/png"},
    {"logo_base64": "QQ==", "logo_mime_type": ""},
    {"logo_base64": "QQ==", "logo_mime_type": None},
    {"logo_base64": "QQ=", "logo_mime_type": "image/png"},
    {"logo_base64": 5, "logo_mime_type": "image/png"},
    {"logo_mime_type": "x" * 51},
    {"logo_mime_type": "application/pdf"},
    {"reset": []},
    {"reset": ["title"]},
    {"reset": ["logo", "brand_color", "title"]},
    {"reset": ["logo", "logo"]},
    {"reset": ["x"]},
    {"reset": [5, None, "Title"]},
    {"reset": None},
    {"reset": "title"},
    {"reset": {"title": 1}},
    {"title": "x", "reset": ["title"]},
    {"logo_base64": "QQ==", "logo_mime_type": "image/png", "reset": ["logo"]},
    {"logo_base64": "QQ==", "logo_mime_type": "image/png", "title": "x", "reset": ["logo", "title", "brand_color"]},
    {"title": "", "brand_color": "zz", "reset": ["x"]},
    {"title": "T", "brand_color": "#ABC", "unknown": 1},
    {"enabled": True},
    {"enabled": False, "title": "Off"},
    {"enabled": None},
    {"enabled": "yes"},
    {"enabled": "True "},
    {"enabled": 1.0},
    {"enabled": 2},
    {"enabled": 0.5},
    {"enabled": [], "title": 3},
]

BOOLS = [
    True,
    False,
    0,
    1,
    2,
    -1,
    1.0,
    0.0,
    -0.0,
    1.5,
    "TRUE",
    " true",
    "true ",
    "Yes",
    "oN",
    "F",
    "",
    "1",
    "0",
    "01",
    "off",
    "no",
    "nope",
    None,
    [],
    {},
]

INTS = [
    "1",
    "+5",
    " 5 ",
    "5_000",
    "-0",
    "1e3",
    "0x10",
    "1.0",
    "1.00",
    "1.",
    "1.01",
    ".0",
    "5__0",
    "_5",
    "5_",
    "1_0.0",
    " +1_0.000 ",
    "　 5",
    "5\n",
    "\t5\t",
    "1.0_0",
    "-1.0",
    "+-1",
    "",
    " ",
    "00012",
    "1 2",
    "٣",
]

CSV_ROWS = [
    ["a", "", "b c"],
    ["a,b", 'say "hi"', "x\ny"],
    ["\r"],
    ["tab\there", "semi;colon", "'single'"],
    ["é", "ü,", " lead", "trail "],
    ["a\r\nb"],
]

TIMESTAMPS = [
    datetime.datetime(2026, 9, 1, 12, 0, 0),
    datetime.datetime(2026, 9, 1, 12, 0, 0, 987654),
    datetime.datetime(2026, 12, 31, 23, 59, 59, 999),
    datetime.datetime(1999, 1, 2, 3, 4, 5, 1000),
]

CUSTOMER_LISTS = [
    [("b", "Beta"), ("a", "alpha"), ("c", "Árvíz"), ("d", "STRASSE"), ("e", "straße"), ("f", "Beta")],
    [("z", "z"), ("y", "Z"), ("x", "ǅ")],
]


def failure(e):
    if isinstance(e, ValidationError):
        return {"errors": [{"type": x["type"], "loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}
    return {"error": f"{type(e).__name__}: {e}"}


def compact(value):
    """A long run of one character as `{"repeat", "times"}` (the size limit's cases)."""
    if isinstance(value, str) and len(value) > 1000 and len(set(value)) == 1:
        return {"repeat": value[0], "times": len(value)}
    return value


def run_validator(name, value):
    try:
        return {"ok": compact(getattr(validators, f"validate_{name}")(value))}
    except ValueError as e:
        return {"error": str(e)}


def model_case(model, body):
    try:
        m = model.model_validate(body)
    except ValidationError as e:
        return failure(e)
    out = {"fields": {k: getattr(m, k) for k in ("title", "logo_base64", "logo_mime_type", "brand_color")}}
    if model is PatchPortalSettingsRequest:
        out["sent"] = [f for f in ("title", "logo_base64", "logo_mime_type", "brand_color") if f in m.model_fields_set]
        out["reset"] = list(m.reset)
    if model is UpdateCustomerBrandingRequest:
        out["enabled"] = m.enabled
    return out


def adapter_case(adapter, value):
    try:
        return {"ok": adapter.validate_python(value)}
    except ValidationError as e:
        return failure(e)


def csv_row(fields):
    buffer = io.StringIO()
    csv.writer(buffer).writerow(fields)
    return buffer.getvalue()


RESPONSES = [
    {
        "status": 200,
        "size": 3,
        "media_type": "text/csv",
        "headers": {"Content-Disposition": 'attachment; filename="x.csv"'},
        "accept": None,
    },
    {"status": 200, "size": 999, "media_type": "image/png", "headers": {"ETag": '"1"'}, "accept": "gzip"},
    {"status": 200, "size": 1000, "media_type": "image/png", "headers": {"ETag": '"1"'}, "accept": None},
    {"status": 200, "size": 1000, "media_type": "image/png", "headers": {"ETag": '"1"'}, "accept": "gzip, deflate"},
    {"status": 200, "size": 1500, "media_type": "text/plain", "headers": {}, "accept": "deflate"},
    {"status": 200, "size": 1500, "media_type": "text/plain; charset=latin-1", "headers": {"Vary": "Origin"}, "accept": "GZIP"},
    {"status": 200, "size": 1500, "media_type": "text/event-stream", "headers": {}, "accept": "gzip"},
    {"status": 304, "size": 0, "media_type": None, "headers": {"ETag": '"1"', "Cache-Control": "public, max-age=3600"}, "accept": "gzip"},
    {"status": 200, "size": 2000, "media_type": "image/svg+xml", "headers": {"Content-Encoding": "br"}, "accept": "gzip"},
]


async def starlette_response(case):
    body = b"a" * case["size"]
    response = Response(content=body, status_code=case["status"], headers=case["headers"], media_type=case["media_type"])
    app = GZipMiddleware(response, minimum_size=1000)
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    headers = [(b"accept-encoding", case["accept"].encode())] if case["accept"] is not None else []
    await app({"type": "http", "method": "GET", "path": "/", "headers": headers}, receive, send)
    start = sent[0]
    content = b"".join(m.get("body", b"") for m in sent[1:])
    gzipped = content != body
    if gzipped:
        assert gzip.decompress(content) == body
    return {
        "headers_out": [[k.decode("latin-1"), v.decode("latin-1")] for k, v in start["headers"] if k != b"content-length" or not gzipped],
        "gzipped": gzipped,
    }


def main():
    vectors = {
        "validators": [
            {"field": field, "value": compact(value), **run_validator(field, value)}
            for field, values in VALIDATOR_INPUTS.items()
            for value in values
        ],
        "b64decode": [],
        "models": [],
        "bools": [{"value": v, **adapter_case(TypeAdapter(bool), v)} for v in BOOLS],
        "ints": [{"value": v, **adapter_case(TypeAdapter(int), v)} for v in INTS],
        "csv": [{"row": row, "text": csv_row(row)} for row in CSV_ROWS],
        "timestamps": [{"value": t.isoformat(), "text": _utc_timestamp(t)} for t in TIMESTAMPS],
        "content_versions": [{"logo": v, "version": logo_content_version(v)} for v in ["iVBORw0KGgo=", "QQ==", "é", ""]],
        "logo_versions": [
            {"value": t.isoformat(), "version": _logo_version(t)}
            for t in (datetime.datetime(2026, 10, 17, 10, 5, 23), datetime.datetime(1970, 1, 1), datetime.datetime(2038, 1, 19, 3, 14, 8))
        ],
        "sorted_customers": [
            {
                "customers": rows,
                "sorted": [code for code, _ in sorted(rows, key=lambda r: (r[1].casefold(), r[0]))],
            }
            for rows in CUSTOMER_LISTS
        ],
        "responses": [],
    }
    for value in B64_INPUTS:
        try:
            vectors["b64decode"].append({"value": value, "ok": base64.b64decode(value, validate=True).hex()})
        except (binascii.Error, ValueError) as e:
            vectors["b64decode"].append({"value": value, "error": str(e)})
    for model in (UpdatePortalSettingsRequest, PatchPortalSettingsRequest, UpdateCustomerBrandingRequest):
        for body in BODIES:
            vectors["models"].append({"model": model.__name__, "body": body, **model_case(model, body)})
    for case in RESPONSES:
        out = {k: v for k, v in case.items() if k != "headers"}
        vectors["responses"].append({**out, "headers_in": case["headers"], **asyncio.run(starlette_response(case))})
    OUT.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
