"""Regenerate the vectors that pin the pure parts of the OpenCTI and Cortex ports
(`copilot-intel-connectors`) to the Python modules they port (`app/connectors/opencti/`,
`app/connectors/cortex/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-intel-connectors-vectors.py

Writes `crates/copilot-intel-connectors/src/intel_vectors.json`:

* `paginate` — `utils.universal.paginate_graphql` walking scripted answers (`_post_graphql`
  replaced by a list of envelopes, nothing sent): the `variables` of every page asked for and
  the dict it returns, or the exception it raises;
* `parse` — `services.opencti.parse_indicator` / `parse_observable` / `parse_entity` on GraphQL
  nodes: the model's JSON (as FastAPI writes it) or the exception (`ValidationError` with its
  text, anything else by class);
* `graphql_errors` — `format_graphql_errors` on `errors` arrays;
* `batch` — `OpenCTIBatchLookupRequest` on request bodies: the cleaned values or Pydantic's
  errors (`type`, `loc`, `msg`);
* `platform_urls` — `resolve_platform_url(connector_url, public_url)`, or urlparse's
  `ValueError`;
* `datatypes` — `RunAnalyzerBody.is_valid_datatype` (CPython's `ipaddress`, `re` and its `$`).

Re-run after a Pydantic or Python upgrade, or a change to these functions.
"""

import asyncio
import json
import os
import pathlib

from pydantic import ValidationError

from app.connectors.cortex.schema.analyzers import RunAnalyzerBody
from app.connectors.opencti.schema.opencti import OpenCTIBatchLookupRequest
from app.connectors.opencti.services import opencti as services
from app.connectors.opencti.utils import universal

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-intel-connectors" / "src" / "intel_vectors.json"


def failure(e):
    if isinstance(e, ValidationError):
        return {"class": "ValidationError", "text": str(e)}
    return {"class": type(e).__name__, "text": str(e)}


# --- paginate_graphql ------------------------------------------------------------------------------


def ok(data):
    return {"success": True, "message": "Successfully retrieved data", "data": data, "errors": []}


def conn(nodes, next_page=False, cursor=None, count=None, path=("indicators",)):
    page = {"pageInfo": {"hasNextPage": next_page, "endCursor": cursor, "globalCount": count}, "edges": [{"node": n} for n in nodes]}
    for key in reversed(path):
        page = {key: page}
    return ok(page)


def n(i):
    return {"id": f"n{i}"}


PAGINATE = [
    {"name": "one page", "pages": [conn([n(1), n(2)], count=2)], "path": ["indicators"]},
    {
        "name": "three pages",
        "pages": [conn([n(1), n(2)], True, "c2", 5), conn([n(3), n(4)], True, "c4", 99), conn([n(5)], False, "c5")],
        "path": ["indicators"],
        "page_size": 2,
    },
    {
        "name": "max_items cuts the walk",
        "pages": [conn([n(1), n(2)], True, "c2", 9), conn([n(3)], True, "c3")],
        "path": ["indicators"],
        "page_size": 2,
        "max_items": 3,
    },
    {"name": "max_items zero", "pages": [conn([], True, "c", 9)], "path": ["indicators"], "max_items": 0},
    {
        "name": "a repeated cursor stops",
        "pages": [conn([n(1)], True, "c1"), conn([n(2)], True, "c1"), conn([n(3)], True, "c9")],
        "path": ["indicators"],
    },
    {"name": "an empty cursor stops", "pages": [conn([n(1)], True, "")], "path": ["indicators"]},
    {"name": "a nested path", "pages": [conn([n(1)], path=("stixCoreObject", "reports"), count=1)], "path": ["stixCoreObject", "reports"]},
    {"name": "no connection", "pages": [ok({"indicators": None})], "path": ["indicators"]},
    {"name": "data not an object", "pages": [ok([1])], "path": ["indicators"]},
    {
        "name": "a failure mid-walk",
        "pages": [
            conn([n(1)], True, "c1", 4),
            {"success": False, "message": "OpenCTI GraphQL error: x (Y)", "data": None, "errors": [{"message": "x"}]},
        ],
        "path": ["indicators"],
    },
    {
        "name": "odd edges",
        "pages": [ok({"indicators": {"edges": [None, {"node": None}, {}, {"node": 0}, {"node": n(1)}], "pageInfo": None}})],
        "path": ["indicators"],
    },
    {
        "name": "variables kept, first and after replaced",
        "pages": [conn([n(1)])],
        "path": ["indicators"],
        "variables": {"after": "x", "search": "s", "first": 1},
    },
    {"name": "an edge that is no object", "pages": [ok({"indicators": {"edges": ["x"]}})], "path": ["indicators"]},
    {"name": "a list cursor", "pages": [conn([n(1)], True, ["c"]), conn([n(2)])], "path": ["indicators"]},
    {"name": "a number cursor equal to a float", "pages": [conn([n(1)], True, 1), conn([n(2)], True, 1.0)], "path": ["indicators"]},
    {
        "name": "globalCount kept from the first page",
        "pages": [conn([n(1)], True, "a", None), conn([n(2)], False, "b", 7)],
        "path": ["indicators"],
    },
]


async def paginate(case):
    pages = list(case["pages"])
    asked = []

    async def fake_post(client, attributes, query, variables=None):
        asked.append(variables)
        return pages.pop(0)

    async def fake_attributes(name):
        return {"connector_url": "http://opencti", "connector_api_key": "k"}

    universal._post_graphql = fake_post
    universal._get_attributes = fake_attributes
    try:
        result = await universal.paginate_graphql(
            "query Q { x }",
            case["path"],
            variables=case.get("variables"),
            page_size=case.get("page_size", universal.DEFAULT_PAGE_SIZE),
            max_items=case.get("max_items"),
        )
        out = {"result": result}
    except Exception as e:  # noqa: BLE001 - the vector records what was raised
        out = {"error": failure(e)}
    return {**case, "asked": asked, **out}


# --- parse ---------------------------------------------------------------------------------------

BASE = {
    "id": "i1",
    "standard_id": "indicator--1",
    "entity_type": "Indicator",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": None,
    "createdBy": {"name": "A"},
    "objectLabel": [{"value": "v", "color": "#fff"}, {"value": ""}, None, {"value": "w"}],
    "objectMarking": [{"definition": "TLP:CLEAR"}, {}, None, {"definition": None}],
}


def node(**over):
    return {**BASE, **over}


PARSE = [
    ("indicator", node(name="n", x_opencti_score=50, confidence="70", revoked=True, x_opencti_main_observable_type="IPv4-Addr")),
    ("indicator", node(x_opencti_score=5.5)),
    ("indicator", node(x_opencti_score=5.0, valid_from=1, revoked="maybe")),
    ("indicator", node(id=None)),
    ("indicator", {k: v for k, v in BASE.items() if k != "id"}),
    ("indicator", node(entity_type=None, createdBy=None, objectLabel=None, objectMarking=None)),
    ("indicator", node(objectLabel={"a": 1})),
    ("indicator", node(objectLabel=[[1]])),
    ("indicator", node(objectMarking=[{"definition": 5}])),
    ("indicator", node(createdBy=[1])),
    ("indicator", "x"),
    ("indicator", node(objectLabel=[{"value": 5, "color": 3}])),
    (
        "observable",
        node(observable_value="v", hashes=[{"algorithm": "MD5", "hash": "AA"}, {"algorithm": "", "hash": "x"}, None], name="f.exe"),
    ),
    (
        "observable",
        node(
            indicators={"pageInfo": {"globalCount": "3"}, "edges": [{"node": node(id="i2")}, {"node": None}]},
            reports={"pageInfo": {"globalCount": 0}, "edges": [{"node": {"id": "r", "published": 5}}]},
        ),
    ),
    ("observable", node(indicators={"edges": [{"node": node(x_opencti_score="high")}]})),
    ("observable", node(indicators={"pageInfo": {"globalCount": 1.5}})),
    ("observable", node(hashes=[{"algorithm": "MD5", "hash": 1}], x_opencti_score=True)),
    ("observable", node(indicators=[1])),
    ("observable", node(reports={"edges": [{"node": {"name": "no id"}}]}, indicators={"pageInfo": "x"})),
    ("entity", node(parent_types=["A", "B"], representative={"main": "M", "secondary": "S"}, confidence=80, x_opencti_score=None)),
    ("entity", node(parent_types=None, representative=None, externalReferences={"edges": [{"node": {"url": 5}}]})),
    ("entity", node(representative=[1])),
    ("entity", node(parent_types="ab", confidence="x")),
]


def parse(kind, value):
    fn = {"indicator": services.parse_indicator, "observable": services.parse_observable, "entity": services.parse_entity}[kind]
    try:
        return {"kind": kind, "node": value, "json": fn(value).model_dump_json()}
    except Exception as e:  # noqa: BLE001
        return {"kind": kind, "node": value, "error": failure(e)}


# --- the rest ------------------------------------------------------------------------------------

GRAPHQL_ERRORS = [
    [{"message": "You must be logged in", "extensions": {"code": "AUTH_REQUIRED"}}],
    [
        {"message": "a", "name": "N"},
        {},
        {"message": None, "extensions": None, "name": ""},
        {"message": [1], "extensions": {"code": 0}, "name": "Z"},
    ],
    [{"message": {"x": 1.5}, "extensions": {"code": True}}],
    [{"message": 5}],
    ["x"],
    {"message": "m"},
    "ab",
    5,
]


def graphql_errors(errors):
    try:
        return {"errors": errors, "text": universal.format_graphql_errors(errors)}
    except Exception as e:  # noqa: BLE001
        return {"errors": errors, "error": failure(e)}


BATCH = [
    {},
    {"values": []},
    {"values": "a"},
    {"values": None},
    {"values": {"a": 1}},
    {"values": [" A ", "a", "b", "", " B "]},
    {"values": ["İstanbul", "i̇stanbul", "ß", "SS", "ss"]},
    {"values": [1, None, "x", True]},
    {"values": ["  ", "　"]},
    {"values": ["x" * 2048, " " + "y" * 2048 + " "]},
    {"values": ["a", "x" * 2049]},
    {"values": ["a"] * 100},
    {"values": ["a"] * 101},
    {"values": [1] * 101},
    {"values": [f"v{i}" for i in range(100)]},
]


def batch(body):
    try:
        return {"body": body, "values": OpenCTIBatchLookupRequest.model_validate(body).values}
    except ValidationError as e:
        return {"body": body, "errors": [{"type": x["type"], "loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}


PLATFORM_URLS = [
    ("http://opencti:8080", None),
    ("http://opencti:8080/graphql/", ""),
    (" http://opencti:8080/// ", "   "),
    ("http://internal:8080", " https://cti.example.com/graphql "),
    ("http://internal:8080", "HTTPS://CTI.example.com"),
    ("http://internal:8080", "ftp://cti.example.com"),
    ("http://internal:8080", "cti.example.com"),
    ("http://internal:8080", "http:///path"),
    ("http://internal:8080", "http://[::1"),
    ("http://internal:8080", "http://[::1]:8443/"),
    ("http://internal:8080", "http://[foo]/"),
    ("http://internal:8080", "https://ｃｔｉ.example/"),
    ("http://internal:8080", "https://a℀b.example/"),
    ("", None),
]


def platform_url(url, public):
    try:
        return {"connector_url": url, "public_url": public, "url": universal.resolve_platform_url(url, public)}
    except ValueError as e:
        return {"connector_url": url, "public_url": public, "error": str(e)}


DATATYPES = [
    "1.2.3.4",
    "0.0.0.0",
    "255.255.255.255",
    "256.0.0.1",
    "01.2.3.4",
    "1.2.3",
    "1.2.3.4.5",
    "1.2.3.4\n",
    " 1.2.3.4",
    "1.2.3.٤",
    "1.2.3.+4",
    "d41d8cd98f00b204e9800998ecf8427e",
    "D41D8CD98F00B204E9800998ECF8427E",
    "d41d8cd98f00b204e9800998ecf8427",
    "d41d8cd98f00b204e9800998ecf8427e-and-more",
    "١" * 32,
    "１" * 32,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "example.com",
    "sub.example.co.uk",
    "example.com\n",
    "example.com\n\n",
    "Example.com",
    "example.c",
    "example.abcdefg",
    "-example.com",
    "exa_mple.com",
    "a" * 63 + ".com",
    "a" * 64 + ".com",
    "example.com.",
    "",
    "not an ioc",
]


def datatype(value):
    ok_, kind = RunAnalyzerBody.is_valid_datatype(value)
    return {"value": value, "type": kind if ok_ else None}


async def main():
    out = {
        "_comment": "Generated by scripts/gen-intel-connectors-vectors.py; do not edit.",
        "paginate": [await paginate(c) for c in PAGINATE],
        "parse": [parse(k, v) for k, v in PARSE],
        "graphql_errors": [graphql_errors(e) for e in GRAPHQL_ERRORS],
        "batch": [batch(b) for b in BATCH],
        "platform_urls": [platform_url(u, p) for u, p in PLATFORM_URLS],
        "datatypes": [datatype(v) for v in DATATYPES],
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({sum(len(v) for k, v in out.items() if isinstance(v, list))} vectors)")


if __name__ == "__main__":
    os.environ.setdefault("CONNECTOR_CACHE_TTL_SECONDS", "0")
    asyncio.run(main())
