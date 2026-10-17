"""Regenerate the vectors that pin `copilot-grafana-dashboards` to the Python dashboard provisioning.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x-not-default-123 python ../scripts/gen-grafana-dashboard-vectors.py

Writes `crates/copilot-grafana-dashboards/src/grafana_dashboard_vectors.json`:

* `files` — every JSON file under `app/connectors/grafana/dashboards/` (the tree Rust embeds),
  by its path relative to that directory;
* `classes` — the dashboard enums of `schema/dashboards.py` in the order `provision_dashboards`
  concatenates them, each member's name and its `(folder, file)` value, and `valid` — the
  `valid_dashboards` dict that order builds (name → value, in the dict's order);
* `bodies` — for every valid dashboard and three `(datasource uid, Grafana URL, folder id)`
  triples: the SHA-256 and length of the bytes niquests sends for
  `dashboard.update_dashboard({"dashboard": load_dashboard_json(...), "folderId": …,
  "overwrite": True})` (`json.dumps(…, allow_nan=False)`, UTF-8);
* `edits` — `replace_uid_value` and `replace_grafana_url` on small documents (non-string
  values, nesting, a URL that holds the old one twice): `json.dumps` of the result;
* `requests` — `DashboardProvisionRequest` (`POST /grafana/dashboards`) and
  `ProvisionDashboardRequest` (`POST /customer_provisioning/provision/dashboards`) validated as
  FastAPI validates a body (`validate_python(…, from_attributes=True)`): the JSON-mode dump, or
  the 422 `validation_exception_handler` answers;
* `answers` — `GrafanaDashboard(**answer)` on Grafana answers: the JSON dump, or the exception's
  class and text.

Re-run after a change to a dashboard template, to `schema/dashboards.py` or
`services/dashboards.py`, or after a Pydantic or FastAPI upgrade.
"""

import hashlib
import json
import pathlib

from fastapi import HTTPException
from pydantic import TypeAdapter
from pydantic import ValidationError

from app.connectors.grafana.schema import dashboards as schema
from app.connectors.grafana.services import dashboards as services
from app.customer_provisioning.schema.provision import ProvisionDashboardRequest
from app.middleware.exception_handlers import _describe
from app.utils import ErrorType
from app.utils import ValidationErrorItem
from app.utils import ValidationErrorResponse

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "copilot-grafana-dashboards" / "src" / "grafana_dashboard_vectors.json"
TEMPLATES = ROOT / "backend" / "app" / "connectors" / "grafana" / "dashboards"

CLASSES = [
    schema.WazuhDashboard,
    schema.Office365Dashboard,
    schema.MimecastDashboard,
    schema.SapSiemDashboard,
    schema.HuntressDashboard,
    schema.CarbonBlackDashboard,
    schema.FortinetDashboard,
    schema.CrowdstrikeDashboard,
    schema.DuoDashboard,
    schema.DarktraceDashboard,
    schema.BitdefenderDashboard,
    schema.CatoDashboard,
    schema.DefenderForEndpointDashboard,
    schema.SonicwallDashboard,
    schema.SentinelOneDashboard,
]

TRIPLES = [
    ("uid-to-be-replaced", "https://grafana.company.local", 0),
    ('ds-ü"x\\y', "https://grafana.company.local/x", 12),
    ("", "http://g:3000", -1),
]


def json_response(content):
    """The bytes of Starlette's `JSONResponse(content)`."""
    return json.dumps(content, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))


def body_outcome(model, value):
    """What FastAPI makes of `value` as the body of a route whose body parameter is `model`."""
    try:
        dump = TypeAdapter(model).validate_python(value, from_attributes=True).model_dump(mode="json")
    except HTTPException as e:
        return {"status": e.status_code, "body": json_response({"success": False, "message": e.detail})}
    except ValidationError as e:
        details = []
        for error in e.errors(include_url=False):
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
    return {"status": 200, "dump": json.dumps(dump)}


DASHBOARD_BODIES = [
    {"dashboards": ["WAZUH_SUMMARY"]},
    {"dashboards": [], "organizationId": "7", "folderId": 3.0, "datasourceUid": "ds", "grafana_url": "https://g"},
    {"dashboards": ["WAZUH_SUMMARY", "SENTINELONE_EPP_SUMMARY", "WAZUH_SUMMARY"], "organizationId": True},
    {"dashboards": ["NOPE"]},
    {"dashboards": ["WAZUH_SUMMARY", "Nope", "x"]},
    {"dashboards": ["wazuh_summary"]},
    {"dashboards": ["EDR_WAZUH_INVENOTRY"]},
    {"dashboards": "WAZUH_SUMMARY"},
    {"dashboards": [1, "WAZUH_SUMMARY"]},
    {"dashboards": None},
    {},
    {"dashboards": ["WAZUH_SUMMARY"], "organizationId": "x", "folderId": 1.5, "datasourceUid": 5, "grafana_url": None},
    {"dashboards": ["WAZUH_SUMMARY"], "organizationId": 100000000000000000000},
    {"dashboards": ["MIMECAST_SUMMARY"], "unknown": 1},
    [],
    "x",
    5,
]

CUSTOMER_BODIES = [
    {
        "customer_name": "Acme",
        "dashboards_to_include": {"dashboards": ["HUNTRESS_SUMMARY"], "organizationId": 9},
        "grafana_org_id": 3,
        "grafana_datasource_uid": "ds-1",
        "grafana_folder_id": 4,
        "grafana_url": "https://grafana.example.com",
    },
    {
        "customer_name": "Acme",
        "dashboards_to_include": {"dashboards": ["NOPE"]},
        "grafana_org_id": "x",
        "grafana_datasource_uid": "ds-1",
        "grafana_folder_id": 4,
        "grafana_url": "u",
    },
    {"customer_name": "Acme", "dashboards_to_include": None, "grafana_org_id": 3},
    {"customer_name": "Acme", "dashboards_to_include": [], "grafana_org_id": 3, "grafana_folder_id": "1"},
    {"dashboards_to_include": {"dashboards": ["DUO_AUTH"]}},
    {},
    {
        "customer_name": 1,
        "dashboards_to_include": {"dashboards": ["DUO_AUTH"], "folderId": "z"},
        "grafana_org_id": "3",
        "grafana_datasource_uid": "d",
        "grafana_folder_id": 1,
        "grafana_url": "",
    },
]

ANSWERS = [
    {"id": 41, "slug": "summary", "status": "success", "uid": "abc", "url": "/d/abc/summary", "version": 1, "folderUid": "f"},
    {"id": "41", "slug": "s", "status": "success", "uid": "abc", "url": "/d/abc/s", "version": 2.0},
    {"id": 41, "slug": "s", "status": "success", "uid": 5, "url": "/d", "version": "x"},
    {"message": "Dashboard not found"},
    {},
    "not-a-dict",
    None,
    [1],
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    files = sorted(str(p.relative_to(TEMPLATES)) for p in TEMPLATES.rglob("*.json"))
    classes = [{"name": cls.__name__, "members": [[m.name, m.value[0], m.value[1]] for m in cls]} for cls in CLASSES]
    valid = {item.name: item for cls in CLASSES for item in list(cls)}
    bodies = []
    for name, member in valid.items():
        for uid, url, folder in TRIPLES:
            dashboard = services.load_dashboard_json(member.value, datasource_uid=uid, grafana_url=url)
            payload = {"dashboard": dashboard, "folderId": folder, "overwrite": True}
            data = json.dumps(payload, allow_nan=False).encode("utf-8")
            bodies.append({"name": name, "uid": uid, "url": url, "folder": folder, "sha256": sha(data), "len": len(data)})
    edits = []
    for doc in [
        {"uid": "replace_datasource_uid", "x": [{"uid": "replace_datasource_uid"}, {"uid": 5}, ["replace_datasource_uid"]]},
        {"a": {"uid": "replace_datasource_uid_2", "b": {"uid": "replace_datasource_uid", "uid2": "replace_datasource_uid"}}},
        {"uid": {"uid": "replace_datasource_uid"}},
        {"url": "https://grafana.company.local/d/x?var=https://grafana.company.local", "u": "https://grafana.company.local"},
        {"links": [{"url": "https://grafana.company.localhost/x"}, {"url": "http://grafana.company.local"}, {"url": 5}]},
        {"url": {"url": "https://grafana.company.local"}},
        [{"url": "https://grafana.company.local"}, "https://grafana.company.local", [{"uid": "replace_datasource_uid"}]],
    ]:
        for uid, url, _ in TRIPLES:
            out = json.loads(json.dumps(doc))
            services.replace_uid_value(out, uid)
            services.replace_grafana_url(out, url)
            edits.append({"input": json.dumps(doc), "uid": uid, "url": url, "out": json.dumps(out)})
    requests = {
        "grafana": [{"input": json.dumps(b), **body_outcome(schema.DashboardProvisionRequest, b)} for b in DASHBOARD_BODIES],
        "customer": [{"input": json.dumps(b), **body_outcome(ProvisionDashboardRequest, b)} for b in CUSTOMER_BODIES],
    }
    answers = []
    for answer in ANSWERS:
        try:
            out = {"ok": json.dumps(schema.GrafanaDashboard(**answer).model_dump(mode="json"))}
        except ValidationError as e:
            out = {"exc": "ValidationError", "text": str(e)}
        except TypeError as e:
            out = {"exc": "TypeError", "text": str(e)}
        answers.append({"input": json.dumps(answer), **out})
    doc = {
        "files": files,
        "classes": classes,
        "valid": [[name, member.value[0], member.value[1]] for name, member in valid.items()],
        "bodies": bodies,
        "edits": edits,
        "requests": requests,
        "answers": answers,
    }
    OUT.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({len(files)} files, {len(valid)} dashboards, {len(bodies)} bodies)")


if __name__ == "__main__":
    main()
