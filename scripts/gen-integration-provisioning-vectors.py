"""Regenerate the vectors that pin `copilot-integration-provisioning` to the Python provisioning.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x-not-default-123 python ../scripts/gen-integration-provisioning-vectors.py

Writes `crates/copilot-integration-provisioning/src/integration_provisioning_vectors.json`:

* `packs` — the `AvailableContentPacks` member names in declaration order, and what
  `retrieve_valid_content_packs` + `filter_content_packs` keep for each network connector and
  protocol;
* `renders` — every network content-pack template rendered as `process_content_pack` renders it
  (`replace_keywords_in_json_complex` with a `ReplaceContentPackKeywords` dump, then
  `convert_port_value_to_int`) for fixed UUIDs and a few keyword sets (names holding other
  keywords, ports with signs and underscores, `None` TLS files): the SHA-256 of `json.dumps` of
  the result, and the full text of small documents;
* `models` — each model built from inputs (`Model(**kwargs)`): the JSON dump or the
  `ValidationError` text;
* `requests` — the request bodies of the provisioning routes as FastAPI validates them, the
  `mode="before"` validators included (a non-dict body is their `TypeError`: status 500);
* `index_set` / `datasource` — `TimeBasedIndexSet(...)` and `GrafanaDatasource(...)` as the
  services build them, `model_dump()` then `json.dumps`.

Re-run after a change to a content-pack template, to `stack_provisioning/graylog/schema/`,
`customer_provisioning/schema/{graylog,grafana}.py`, or after a Pydantic or FastAPI upgrade.
"""

import hashlib
import json
import pathlib

from fastapi import HTTPException
from pydantic import TypeAdapter
from pydantic import ValidationError

from app.customer_provisioning.schema import grafana as grafana_schema
from app.customer_provisioning.schema import graylog as graylog_schema
from app.middleware.exception_handlers import _describe
from app.stack_provisioning.graylog.schema.fortinet import ProvisionFortinetRequest
from app.stack_provisioning.graylog.schema.provision import AvailableContentPacks
from app.stack_provisioning.graylog.schema.provision import ReplaceContentPackKeywords
from app.stack_provisioning.graylog.schema.sentinelone import (
    ProvisionSentinelOneRequest,
)
from app.stack_provisioning.graylog.schema.sonicwall import ProvisionSonicwallRequest
from app.stack_provisioning.graylog.services import provision as provision_services
from app.utils import ErrorType
from app.utils import ValidationErrorItem
from app.utils import ValidationErrorResponse

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "copilot-integration-provisioning" / "src" / "integration_provisioning_vectors.json"

UUID_G = "11111111-2222-4333-8444-555555555555"
UUID_S = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def json_response(content):
    """The bytes of Starlette's `JSONResponse(content)`."""
    return json.dumps(content, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))


def body_outcome(model, value):
    """What FastAPI makes of `value` as the body of a route whose body parameter is `model`."""
    if value is None:
        value_errors = [{"type": "missing", "loc": (), "msg": "Field required", "input": None}]
        return validation_response(value_errors)
    try:
        dump = TypeAdapter(model).validate_python(value, from_attributes=True).model_dump(mode="json")
    except HTTPException as e:
        return {"status": e.status_code, "body": json_response({"success": False, "message": e.detail})}
    except ValidationError as e:
        return validation_response(e.errors(include_url=False))
    except TypeError:
        return {"status": 500}
    return {"status": 200, "dump": json.dumps(dump)}


def validation_response(errors):
    details = []
    for error in errors:
        loc = ("body",) + tuple(error["loc"])
        field = str(loc[-1]) if loc else "body"
        try:
            error_type = ErrorType(error["type"])
        except ValueError:
            error_type = ErrorType.GENERAL
        message = _describe(error, loc) if error_type is ErrorType.GENERAL else None
        details.append(ValidationErrorItem(field=field, error_type=error_type, message=message))
    main = details[0].message if details else "Validation Error"
    return {"status": 422, "body": json_response(ValidationErrorResponse(message=main, details=details).model_dump())}


def construct_outcome(model, kwargs):
    try:
        return {"dump": json.dumps(model(**kwargs).model_dump(mode="json"))}
    except ValidationError as e:
        return {"error": str(e)}


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


KEYWORD_SETS = [
    {"customer_name": "Acme", "customer_code": "acme01", "SYSLOG_PORT": 514, "TLS_CERT_FILE": None, "TLS_KEY_FILE": None},
    {
        "customer_name": "Name customer_code SYSLOG_PORT",
        "customer_code": "C-1",
        "SYSLOG_PORT": 6514,
        "TLS_CERT_FILE": "/etc/graylog/c.pem",
        "TLS_KEY_FILE": '/etc/k"ey\\.key',
    },
    {"customer_name": 'Ü "q" \\', "customer_code": "REPLACE_UUID_GLOBAL", "SYSLOG_PORT": -1, "TLS_CERT_FILE": "", "TLS_KEY_FILE": "x"},
]

SMALL_DOCS = [
    {"customer_name": ["customer_name x", {"port": {"@value": "SYSLOG_PORT"}}], "n": 1, "port": {"@value": "abc"}},
    {"port": {"@value": " +5_1_4 "}, "x": {"port": {"@type": "integer", "@value": "TLS_KEY_FILE"}}, "y": [None, True, 1.5]},
    {"port": "SYSLOG_PORT", "p": {"port": {"@value": 7}}, "q": [{"port": {"@value": "0x10"}}]},
]


def render(doc, keywords):
    replacements = ReplaceContentPackKeywords(REPLACE_UUID_GLOBAL=UUID_G, REPLACE_UUID_SPECIFIC=UUID_S, **keywords)
    out = provision_services.replace_keywords_in_json_complex(doc, replacements.model_dump())
    return provision_services.convert_port_value_to_int(out)


async def packs():
    names = [pack.name for pack in AvailableContentPacks]
    kept = {}
    for tag in ("FORTINET", "SONICWALL", "SENTINELONE"):
        for protocol in ("TCP", "UDP", None):
            valid = await provision_services.retrieve_valid_content_packs(tag)
            kept[f"{tag}/{protocol}"] = await provision_services.filter_content_packs(valid, protocol)
    return {"names": names, "kept": kept}


def renders():
    out = []
    for name in sorted(n for n in (p.name for p in AvailableContentPacks) if any(t in n for t in ("FORTINET", "SONICWALL"))):
        template = provision_services.load_content_pack_json(f"{name}.json")
        for i, keywords in enumerate(KEYWORD_SETS):
            text = json.dumps(render(json.loads(json.dumps(template)), keywords))
            out.append({"pack": name, "keywords": i, "sha256": sha(text), "len": len(text)})
    small = []
    for doc in SMALL_DOCS:
        for i, keywords in enumerate(KEYWORD_SETS):
            small.append({"input": json.dumps(doc), "keywords": i, "out": json.dumps(render(json.loads(json.dumps(doc)), keywords))})
    return {"keywords": KEYWORD_SETS, "uuids": [UUID_G, UUID_S], "packs": out, "small": small}


MODEL_INPUTS = {
    "GraylogIndexSetCreationResponse": [
        {
            "data": {
                "id": "is1",
                "title": "t",
                "description": "d",
                "can_be_default": True,
                "index_prefix": "p",
                "shards": 1,
                "replicas": 0,
                "rotation_strategy_class": "r",
                "rotation_strategy": {"type": "x", "rotation_period": "P1D", "max_rotation_period": None, "rotate_empty_index_set": False},
                "retention_strategy_class": "c",
                "retention_strategy": {"type": "y", "max_number_of_indices": 30},
                "creation_date": "2026-01-01T00:00:00.000Z",
                "index_analyzer": "standard",
                "index_optimization_max_num_segments": 1,
                "index_optimization_disabled": False,
                "field_type_refresh_interval": 5000,
                "index_template_type": None,
                "default": False,
                "writable": True,
                "extra": 1,
            },
            "success": True,
            "message": "m",
        },
        {"data": {"id": "is1"}, "success": True, "message": "m"},
        {"data": None, "success": True, "message": "Successfully completed request with no content"},
    ],
    "StreamCreationResponse": [
        {"data": {"stream_id": "st1"}, "success": True, "message": "m"},
        {"data": {"stream_id": 5}, "success": True, "message": "m"},
        {"data": {}, "success": "yes", "message": None},
    ],
    "StreamConnectionToPipelineRequest": [
        {"stream_id": "s", "pipeline_ids": ["p1"]},
        {"stream_id": None, "pipeline_ids": ["p1"]},
        {"stream_id": "s", "pipeline_ids": [None]},
    ],
    "StreamConnectionToPipelineResponse": [
        {"data": {"id": "c1", "stream_id": "s", "pipeline_ids": ["p1"]}, "success": True, "message": "m"},
        {"data": None, "success": True, "message": "m"},
    ],
    "GrafanaDataSourceCreationResponse": [
        {
            "datasource": {
                "id": 3,
                "uid": "u1",
                "orgId": 2,
                "name": "N",
                "type": "grafana-opensearch-datasource",
                "typeLogoUrl": "x",
                "access": "proxy",
                "url": "https://i:9200",
                "user": "",
                "database": "d*",
                "basicAuth": True,
                "basicAuthUser": "admin",
                "withCredentials": False,
                "isDefault": False,
                "jsonData": {
                    "database": "d*",
                    "flavor": "opensearch",
                    "includeFrozen": False,
                    "logLevelField": "severity",
                    "logMessageField": "summary",
                    "maxConcurrentShardRequests": 5,
                    "timeField": "timestamp",
                    "tlsSkipVerify": True,
                    "version": "2.19.1",
                },
                "secureJsonFields": {"basicAuthPassword": True},
                "version": 1,
                "readOnly": True,
            },
            "id": 3,
            "message": "Datasource added",
            "name": "N",
        },
        {"datasource": {"uid": "u"}, "id": "x", "message": "m", "name": "n"},
        {"message": "data source with the same name already exists"},
    ],
    "GrafanaFolderCreationResponse": [
        {
            "id": 7,
            "uid": "f1",
            "title": "FORTINET",
            "url": "/dashboards/f/f1/fortinet",
            "hasAcl": False,
            "canSave": True,
            "canEdit": True,
            "canAdmin": True,
            "canDelete": True,
            "createdBy": "admin",
            "created": "2026-10-16T10:00:00Z",
            "updatedBy": "admin",
            "updated": "2026-10-16T10:00:00.123456+02:00",
            "version": 1,
        },
        {"id": 7, "uid": "f1", "title": "t", "url": "/u", "created": "never", "updated": 0},
        {"message": "a folder with the same name already exists"},
    ],
    "NodesVersionResponse": [
        {"nodes": {"n1": {"version": "2.19.1"}, "n2": {"version": "2.19.0"}}},
        {"nodes": {}},
        {"nodes": {"n1": {"build": 1}}},
        {},
    ],
}

MODELS = {
    "GraylogIndexSetCreationResponse": graylog_schema.GraylogIndexSetCreationResponse,
    "StreamCreationResponse": graylog_schema.StreamCreationResponse,
    "StreamConnectionToPipelineRequest": graylog_schema.StreamConnectionToPipelineRequest,
    "StreamConnectionToPipelineResponse": graylog_schema.StreamConnectionToPipelineResponse,
    "GrafanaDataSourceCreationResponse": grafana_schema.GrafanaDataSourceCreationResponse,
    "GrafanaFolderCreationResponse": grafana_schema.GrafanaFolderCreationResponse,
    "NodesVersionResponse": grafana_schema.NodesVersionResponse,
}

REQUEST_MODELS = {
    "ProvisionFortinetRequest": ProvisionFortinetRequest,
    "ProvisionSonicwallRequest": ProvisionSonicwallRequest,
    "ProvisionSentinelOneRequest": ProvisionSentinelOneRequest,
}

REQUEST_BODIES = [
    {"customer_code": "c1", "hot_data_retention": 30, "index_replicas": 1},
    {"customer_code": "c1", "integration_name": "Other", "tcp_enabled": True, "hot_data_retention": "30", "index_replicas": 1.0},
    {"customer_code": "c1", "tcp_enabled": None, "udp_enabled": "yes", "tls_enabled": None, "hot_data_retention": 30, "index_replicas": 0},
    {"customer_code": 5, "hot_data_retention": 1.5, "index_replicas": "x"},
    {"customer_code": "c1", "tcp_enabled": "maybe", "tls_enabled": 2, "hot_data_retention": 30, "index_replicas": 1},
    {},
    {"integration_name": None},
    None,
    [],
    [{"customer_code": "c1"}],
    "x",
    5,
    True,
]


def index_set():
    out = []
    for title, prefix, retention, shards, replicas in [
        ("Acme - FORTINET EVENTS", "fortinet-acme", 30, 3, 1),
        ('Ü "q" - SONICWALL EVENTS', "sonicwall-x", 1, 1, 0),
    ]:
        model = graylog_schema.TimeBasedIndexSet(
            title=title,
            description=title,
            index_prefix=prefix,
            rotation_strategy_class="org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
            rotation_strategy={
                "type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",
                "rotation_period": "P1D",
                "rotate_empty_index_set": False,
                "max_rotation_period": None,
            },
            retention_strategy_class="org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
            retention_strategy={
                "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
                "max_number_of_indices": retention,
            },
            creation_date="2026-10-17T08:09:10.123456Z",
            index_analyzer="standard",
            shards=shards,
            replicas=replicas,
            index_optimization_max_num_segments=1,
            index_optimization_disabled=False,
            writable=True,
            field_type_refresh_interval=5000,
        )
        out.append(
            {
                "title": title,
                "prefix": prefix,
                "retention": retention,
                "shards": shards,
                "replicas": replicas,
                "json": json.dumps(model.model_dump()),
            },
        )
    return out


def datasource():
    out = []
    for name, database, level, message, url, user, password, version in [
        ("FORTINET", "fortinet-acme*", "severity", "summary", "https://indexer:9200", "admin", "p@ss", "2.19.1"),
        ("SAP SIEM", "sap_siem_x*", "level", "params_loginID", "https://i", "u", 'q"\\ü', "1.3.0"),
        ("MIMECAST", "mimecast_x*", "syslog_level", "rule_description", None, None, None, "x"),
    ]:
        kwargs = dict(
            name=name,
            type="grafana-opensearch-datasource",
            typeName="OpenSearch",
            access="proxy",
            url=url,
            database=database,
            basicAuth=True,
            basicAuthUser=user,
            secureJsonData={"basicAuthPassword": password},
            isDefault=False,
            jsonData={
                "database": database,
                "flavor": "opensearch",
                "includeFrozen": False,
                "logLevelField": level,
                "logMessageField": message,
                "maxConcurrentShardRequests": 5,
                "pplEnabled": True,
                "timeField": "timestamp",
                "tlsSkipVerify": True,
                "version": version,
            },
            readOnly=True,
        )
        entry = {"name": name, "database": database, "level": level, "message": message, "url": url, "user": user}
        entry["password"] = password
        entry["version"] = version
        entry.update(construct_outcome(grafana_schema.GrafanaDatasource, kwargs))
        out.append(entry)
    return out


async def main():
    doc = {
        "packs": await packs(),
        "renders": renders(),
        "models": {
            name: [{"input": json.dumps(v), **construct_outcome(MODELS[name], v)} for v in values] for name, values in MODEL_INPUTS.items()
        },
        "requests": {
            name: [{"input": json.dumps(b), **body_outcome(model, json.loads(json.dumps(b)))} for b in REQUEST_BODIES]
            for name, model in REQUEST_MODELS.items()
        },
        "index_set": index_set(),
        "datasource": datasource(),
    }
    OUT.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
