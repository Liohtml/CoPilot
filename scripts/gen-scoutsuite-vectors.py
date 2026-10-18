"""Regenerate the vectors that pin the ScoutSuite port (`copilot-scoutsuite`) to the Python module it
ports (`app/integrations/scoutsuite/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-scoutsuite-vectors.py

Writes `crates/copilot-scoutsuite/src/scoutsuite_vectors.json`:

* `options` — `GET /report-generation-options`' answer;
* `aws`, `azure` — the request models on bodies, as FastAPI validates a body
  (`from_attributes=True`): the dump and the `scout` command the background task runs, Pydantic's
  errors (`type`, `loc`, `msg`), or the `HTTPException` the `model_validator` raises;
* `gcp` — an upload's contents through `read_json_file` and `validate_json_data`: the command for
  a credential path, or the exception (class, `str()`, status for an `HTTPException`);
* `splitext` — `os.path.splitext(name)[0]`, the report's base name the delete route derives.

Re-run after a change to the module or a Pydantic upgrade.
"""

import asyncio
import json
import os
import pathlib

from fastapi import HTTPException
from pydantic import ValidationError

from app.integrations.scoutsuite.routes.scoutsuite import get_report_generation_options
from app.integrations.scoutsuite.schema.scoutsuite import AWSScoutSuiteReportRequest
from app.integrations.scoutsuite.schema.scoutsuite import AzureScoutSuiteReportRequest
from app.integrations.scoutsuite.schema.scoutsuite import GCPScoutSuiteReportRequest
from app.integrations.scoutsuite.services.scoutsuite import construct_aws_command
from app.integrations.scoutsuite.services.scoutsuite import construct_azure_command
from app.integrations.scoutsuite.services.scoutsuite import construct_gcp_command
from app.integrations.scoutsuite.services.scoutsuite import read_json_file
from app.integrations.scoutsuite.services.scoutsuite import validate_json_data

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-scoutsuite" / "src" / "scoutsuite_vectors.json"

AWS = [
    {"report_type": "aws", "access_key_id": "AKIA", "secret_access_key": "s3cr3t", "report_name": "aws-report"},
    {"report_type": "aws", "access_key_id": "--flag", "secret_access_key": "a b", "report_name": "ü ✓", "extra": 1},
    {"report_type": "azure", "access_key_id": "AKIA", "secret_access_key": "s", "report_name": "r"},
    {"report_type": "AWS", "access_key_id": "AKIA", "secret_access_key": "s", "report_name": "r"},
    {"report_type": "azure", "access_key_id": 1, "secret_access_key": "s", "report_name": "r"},
    {},
    {"report_type": None, "access_key_id": ["x"], "secret_access_key": True, "report_name": 1.5},
    {"report_type": "aws", "access_key_id": "", "secret_access_key": "", "report_name": ""},
]

AZURE = [
    {"report_type": "azure", "username": "u@example.com", "password": "p", "tenant_id": "t", "report_name": "azure-report"},
    {"report_type": "aws", "username": "u", "password": "p", "tenant_id": "t", "report_name": "r"},
    {"report_type": "azure", "username": "u", "password": "p", "report_name": "r"},
    {"report_type": "azure", "username": {"a": 1}, "password": "p", "tenant_id": "t", "report_name": "r"},
    {"report_type": "aws", "username": 5},
]

KEY = {
    "type": "service_account",
    "project_id": "proj",
    "private_key_id": "kid",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n",
    "client_email": "sa@proj.iam.gserviceaccount.com",
    "client_id": "123",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa",
    "universe_domain": "googleapis.com",
}

GCP = [
    json.dumps(KEY).encode(),
    json.dumps({**KEY, "extra": [1]}).encode(),
    json.dumps({k: v for k, v in KEY.items() if k != "universe_domain"}).encode(),
    json.dumps({**KEY, "client_id": 123, "project_id": None}).encode(),
    b"[1, 2]",
    b'"text"',
    b"null",
    b"42",
    b"{}",
    b"",
    b"   ",
    b"{bad json",
    b'{"a": 1} trailing',
    b"\xff\xfe" + json.dumps(KEY).encode("utf-16-le"),
    json.dumps(KEY).encode("utf-16-be"),
    b"\xef\xbb\xbf" + json.dumps(KEY).encode(),
    b'{"type": "\xe9"}',
    b"\xc3\x28",
    b'{"type": NaN}',
]

SPLITEXT = ["aws-report.html", "a.b.c", ".bashrc", "..", ".", "...x", "a.", "noext", "x.html.", "..a.html", " .html", "é.html", "a..b"]


def model_outcome(model, command, body):
    try:
        request = model.model_validate(body, from_attributes=True)
    except HTTPException as e:
        return {"http": [e.status_code, e.detail]}
    except ValidationError as e:
        return {"errors": [{"type": x["type"], "loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}
    return {"ok": request.model_dump(mode="json"), "command": command(request)}


def gcp_outcome(contents):
    try:
        data = asyncio.run(read_json_file(contents))
        validate_json_data(data)
    except HTTPException as e:
        return {"error": {"class": "HTTPException", "status": e.status_code, "text": e.detail}}
    except Exception as e:  # noqa: BLE001 - the exception is the vector
        return {"error": {"class": type(e).__name__, "text": str(e)}}
    request = GCPScoutSuiteReportRequest(report_name="gcp-report", file_path="/tmp/x/gcp-service-account.json")
    return {"command": construct_gcp_command(request)}


def main():
    out = {
        "options": asyncio.run(get_report_generation_options()).model_dump(mode="json"),
        "aws": [{"body": b, "outcome": model_outcome(AWSScoutSuiteReportRequest, construct_aws_command, b)} for b in AWS],
        "azure": [{"body": b, "outcome": model_outcome(AzureScoutSuiteReportRequest, construct_azure_command, b)} for b in AZURE],
        "gcp": [{"contents": c.hex(), "outcome": gcp_outcome(c)} for c in GCP],
        "splitext": [{"name": n, "base": os.path.splitext(n)[0]} for n in SPLITEXT],
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
