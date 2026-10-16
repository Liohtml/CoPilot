"""Regenerate the vectors that pin `copilot-provisioning` to the Python stack provisioning.

    cd backend && PYTHONPATH=.:tests/e2e MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x-not-default-123 python ../scripts/gen-provisioning-vectors.py

Writes `crates/copilot-provisioning/src/provisioning_vectors.json`:

* `enums` — the names and descriptions of `AvailbleContentPacksOverview`, `AvailableContentPacks`,
  `AvailableInfluxDBChecks` and `AvailableNetworkConnectors`;
* `etw_rule` — the source `create_etw_rule` sends;
* `models` — `ContentPackList` (`parse_obj_as`), `GraylogServerInfo` and
  `ProvisionedInfluxDBCheck` (`Model(**value)`) on samples and their mutations: the JSON dump by
  alias (`ok`; for `ContentPackList` only the packs' names, which is all the code reads) or the
  `ValidationError` text (`err`);
* `render` — `render_check_template`'s text replacement on the four templates with odd org ids
  and buckets: the payload's JSON dump, or the exception's class and text.

Re-run after a Pydantic upgrade or a change to one of these models or templates.
"""

import asyncio
import copy
import json
import pathlib
from unittest import mock

import connector_samples as samples
from pydantic import TypeAdapter
from pydantic import ValidationError

from app.connectors.graylog.schema.content_packs import ContentPackList
from app.connectors.graylog.schema.management import GraylogServerInfo
from app.stack_provisioning.graylog.schema.decommission import (
    AvailableNetworkConnectors,
)
from app.stack_provisioning.graylog.schema.provision import AvailableContentPacks
from app.stack_provisioning.graylog.schema.provision import AvailbleContentPacksOverview
from app.stack_provisioning.graylog.services import provision as graylog_provision
from app.stack_provisioning.influxdb.schema.provision import AvailableInfluxDBChecks
from app.stack_provisioning.influxdb.schema.provision import ProvisionedInfluxDBCheck
from app.stack_provisioning.influxdb.services import provision as influx_provision

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-provisioning" / "src" / "provisioning_vectors.json"


def dump(model, instance):
    return TypeAdapter(model).dump_json(instance, by_alias=True).decode()


PACK = {
    "v": "1",
    "id": "pack-1",
    "rev": 2,
    "name": "SOCFORTRESS_WAZUH_CONTENT_PACK",
    "summary": "s",
    "description": "d",
    "vendor": "v",
    "url": "u",
    "created_at": "2026-10-01T00:00:00.000Z",
    "server_version": "6.1.4",
    "parameters": [{"name": "p"}],
    "entities": [
        {
            "v": "1",
            "type": {"name": "stream", "version": "1"},
            "id": "e-1",
            "data": {"title": {"@type": "string", "@value": "x"}, "@value": "shared"},
            "constraints": [{"type": "server-version", "version": ">=6.0.0", "extra": 1}],
        },
    ],
    "extra": True,
}
LIST = {"total": 1, "content_packs": [PACK], "content_packs_metadata": {"pack-1": {}}}


def mutations(value, depth=0):
    """The sample with one key deleted, or one value set to another type, at every place."""
    yield value
    if depth > 4:
        return
    if isinstance(value, dict):
        for key in list(value):
            gone = copy.deepcopy(value)
            del gone[key]
            yield gone
            for other in (None, 5, "x", [], {}, 1.5, True):
                changed = copy.deepcopy(value)
                changed[key] = other
                yield changed
            for inner in mutations(value[key], depth + 1):
                if inner is value[key]:
                    continue
                changed = copy.deepcopy(value)
                changed[key] = inner
                yield changed
    elif isinstance(value, list) and value:
        for inner in mutations(value[0], depth + 1):
            if inner is value[0]:
                continue
            yield [inner] + copy.deepcopy(value[1:])


def unique(values):
    seen, out = set(), []
    for v in values:
        key = json.dumps(v, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def content_pack_list(value):
    try:
        parsed = TypeAdapter(ContentPackList).validate_python(value)
    except ValidationError as e:
        return {"err": str(e)}
    return {"names": [p.name for p in parsed.content_packs]}


def star(model, value):
    try:
        return {"ok": dump(model, model(**value))}
    except ValidationError as e:
        return {"err": str(e)}


def render(name, org_id, bucket):
    async def run():
        with mock.patch.object(influx_provision, "get_influxdb_org_id", mock.AsyncMock(return_value=org_id)):
            with mock.patch.object(influx_provision, "get_influxdb_bucket", mock.AsyncMock(return_value=bucket)):
                return await influx_provision.render_check_template(name)

    try:
        out = asyncio.run(run())
    except Exception as e:  # noqa: BLE001 - recorded
        return {"exc": type(e).__name__, "text": str(e)}
    return {"ok": json.dumps(out, ensure_ascii=False)}


def main():
    vectors = {
        "enums": {
            "overview": [[p.name, p.value] for p in AvailbleContentPacksOverview],
            "content_packs": [p.name for p in AvailableContentPacks],
            "influx_checks": [[c.name, c.value] for c in AvailableInfluxDBChecks],
            "network_connectors": [c.name for c in AvailableNetworkConnectors],
        },
        "models": {
            "ContentPackList": [{"input": v, **content_pack_list(v)} for v in unique(mutations(LIST))],
            "GraylogServerInfo": [
                {"input": v, **star(GraylogServerInfo, v)} for v in unique(mutations(samples.GRAYLOG_SYSTEM_6)) if isinstance(v, dict)
            ],
            "ProvisionedInfluxDBCheck": [
                {"input": v, **star(ProvisionedInfluxDBCheck, v)}
                for v in unique(mutations({"name": "N", "check_name": "C", "action": "created", "check_id": "c-1"}))
                if isinstance(v, dict)
            ],
        },
        "render": [
            {"name": c.name, "org_id": org, "bucket": bucket, **render(c.name, org, bucket)}
            for c in AvailableInfluxDBChecks
            for org, bucket in (
                ("0a1b2c3d4e5f6789", "telegraf"),
                ('a"b', "telegraf"),
                ("a\\q", "telegraf"),
                ("x", 'tele"graf'),
                ("é", "ünï"),
                ("REPLACE_BUCKET", "b"),
                (5, "b"),
            )
        ],
    }
    captured = {}

    async def capture(rule):
        captured["source"] = rule.source

    with mock.patch.object(graylog_provision, "create_pipeline_rule", capture):
        asyncio.run(graylog_provision.create_etw_rule("Set Syslog Level to ALERT for ETW Registry"))
    vectors["etw_rule"] = captured["source"]
    OUT.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
