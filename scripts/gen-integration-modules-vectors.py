"""Regenerate the vectors that pin the pure parts of the integration modules' port
(`copilot-integration-modules`) to the Python modules they port (`app/integrations/modules/`,
`app/integrations/mimecast/`, `app/integrations/sap_siem/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-integration-modules-vectors.py

Writes `crates/copilot-integration-modules/src/integration_modules_vectors.json`:

* `models` — `Model(**input)` for the auth-key models, the payload models posted to the module
  containers, `CustomerDetails`, `InvokeSapSiemAnalysis` and Mimecast's `DataItem`: the model's
  JSON (`model_dump_json()`) or the exception (`ValidationError` with its text, anything else by
  class);
* `bounded` — `InvokeSapSiemRequest(**input)`, `MimecastRequest(**input)` and
  `MimecastTTPURLSRequest(**input)` (its `__init__` decoding the secret key; `headers`, which
  carry a random id, left out) with `datetime.utcnow()` fixed at `NOW`: the `set_time_bounds`
  validator, the `time_range` pattern, the fields;
* `b64decode` — `base64.b64decode(text)`: the bytes (hex) or the exception's text;
* `http_urls` — whether Pydantic's `HttpUrl` takes the text (the region discovery's check).

Re-run after a Pydantic or Python upgrade, or a change to these models.
"""

import base64
import datetime as dt
import json
import pathlib

from pydantic import HttpUrl
from pydantic import TypeAdapter
from pydantic import ValidationError

from app.integrations.mimecast.schema import mimecast as mimecast_schema
from app.integrations.modules.schema import carbonblack
from app.integrations.modules.schema import cato
from app.integrations.modules.schema import darktrace
from app.integrations.modules.schema import duo
from app.integrations.modules.schema import huntress
from app.integrations.modules.schema import mimecast
from app.integrations.modules.schema import sap_siem as sap_schema
from app.integrations.sap_siem.schema import sap_siem as sap_jobs_schema

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-integration-modules" / "src" / "integration_modules_vectors.json"

NOW = dt.datetime(2026, 10, 17, 10, 20, 30, 123987)


class FixedDatetime(dt.datetime):
    @classmethod
    def utcnow(cls):
        return NOW


for module in (sap_schema, sap_jobs_schema, mimecast_schema):
    module.datetime = FixedDatetime


def failure(e):
    if isinstance(e, ValidationError):
        return {"class": "ValidationError", "text": str(e)}
    return {"class": type(e).__name__, "text": str(e)}


MODELS = {
    "HuntressAuthKeys": huntress.HuntressAuthKeys,
    "DuoAuthKeys": duo.DuoAuthKeys,
    "CatoAuthKeys": cato.CatoAuthKeys,
    "DarktraceAuthKeys": darktrace.DarktraceAuthKeys,
    "MimecastAuthKeys": mimecast.MimecastAuthKeys,
    "CarbonBlackAuthKeys": carbonblack.CarbonBlackAuthKeys,
    "SapSiemAuthKeys": sap_schema.SapSiemAuthKeys,
    "CustomerDetails": sap_schema.CustomerDetails,
    "InvokeSapSiemAnalysis": sap_schema.InvokeSapSiemAnalysis,
    "CollectDuo": duo.CollectDuo,
    "CollectCato": cato.CollectCato,
    "CollectCarbonBlack": carbonblack.CollectCarbonBlack,
    "CollectDarktrace": darktrace.CollectDarktrace,
    "CollectMimecast": mimecast.CollectMimecast,
    "DataItem": mimecast_schema.DataItem,
}

CATO = {"API_KEY": "k", "EVENT_TYPES": "Security", "EVENT_SUB_TYPES": "IPS"}
MIMECAST_KEYS = {"APP_ID": "a", "APP_KEY": "b", "EMAIL_ADDRESS": "e@x", "ACCESS_KEY": "c", "SECRET_KEY": "c2VjcmV0"}
GRAYLOG = {"customer_code": "c", "graylog_host": "10.0.0.5", "graylog_port": "12201"}

MODEL_CASES = [
    ("HuntressAuthKeys", {"API_KEY": "k", "API_SECRET": "s"}),
    ("HuntressAuthKeys", {"API_KEY": "k"}),
    ("HuntressAuthKeys", {}),
    ("HuntressAuthKeys", {"API_KEY": 1, "API_SECRET": None}),
    ("HuntressAuthKeys", {"API_KEY": "k", "API_SECRET": "s", "EXTRA": "x"}),
    ("DuoAuthKeys", {"API_HOSTNAME": "h", "INTEGRATION_KEY": "i", "SECRET_KEY": "s"}),
    ("DuoAuthKeys", {"INTEGRATION_KEY": "i"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "42"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": " 42 "}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "5.0"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "5."}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "5.5"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "abc"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": ""}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "-7"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "+7"}),
    ("CatoAuthKeys", {**CATO, "ACCOUNT_ID": "99999999999999999999999"}),
    ("CatoAuthKeys", {"API_KEY": "k", "ACCOUNT_ID": "5."}),
    ("CatoAuthKeys", {"ACCOUNT_ID": "x"}),
    ("DarktraceAuthKeys", {"PUBLIC_TOKEN": "p", "PRIVATE_TOKEN": "q", "HOST": "h", "PORT": "443"}),
    ("DarktraceAuthKeys", {"PUBLIC_TOKEN": "p"}),
    ("MimecastAuthKeys", MIMECAST_KEYS),
    ("MimecastAuthKeys", {**MIMECAST_KEYS, "URI": "/api/x"}),
    ("MimecastAuthKeys", {"APP_ID": "a"}),
    (
        "CarbonBlackAuthKeys",
        {"carbonblack_api_url": "u", "carbonblack_api_key": "k", "carbonblack_api_id": "i", "carbonblack_org_key": "o"},
    ),
    ("CarbonBlackAuthKeys", {"carbonblack_api_url": "u", "carbonblack_api_key": None}),
    ("SapSiemAuthKeys", {"API_KEY": "k", "SECRET_KEY": "s", "API_DOMAIN": "d"}),
    ("SapSiemAuthKeys", {"API_KEY": "k", "SECRET_KEY": "s", "USER_KEY": None, "API_DOMAIN": "d"}),
    ("SapSiemAuthKeys", {"API_KEY": "k"}),
    ("CustomerDetails", {"customer_code": "c", "iris_customer_id": 7}),
    ("CustomerDetails", {"customer_code": "c", "iris_customer_id": "12"}),
    ("CustomerDetails", {"customer_code": "c", "iris_customer_id": None}),
    ("CustomerDetails", {"customer_code": "c", "iris_customer_id": 1.5}),
    ("InvokeSapSiemAnalysis", {"iris_customer_id": 3}),
    ("InvokeSapSiemAnalysis", {"iris_customer_id": "3", "threshold": "2", "time_range": "15"}),
    ("InvokeSapSiemAnalysis", {"iris_customer_id": 3, "threshold": None, "time_range": "x"}),
    ("InvokeSapSiemAnalysis", {"threshold": True, "time_range": 2.0}),
    (
        "CollectDuo",
        {**GRAYLOG, "integration": "duo", "integration_key": "i", "secret_key": "s", "api_host": "h", "api_endpoint": "/e", "range": "15m"},
    ),
    ("CollectDuo", {**GRAYLOG, "graylog_host": None, "integration": "duo", "integration_key": "i", "secret_key": "s", "api_host": "h"}),
    ("CollectCato", {**GRAYLOG, "integration": "cato", "api_key": "k", "account_id": 42, "event_types": "S", "event_sub_types": "I"}),
    ("CollectCato", {**GRAYLOG, "graylog_port": None, "integration": "cato", "api_key": "k", "account_id": 42, "event_types": "S"}),
    (
        "CollectCarbonBlack",
        {
            **GRAYLOG,
            "integration": "carbonblack",
            "carbonblack_api_url": "u",
            "carbonblack_api_key": "k",
            "carbonblack_api_id": "i",
            "carbonblack_org_key": "o",
            "time_range": "-15m",
        },
    ),
    ("CollectCarbonBlack", {**GRAYLOG, "integration": "carbonblack", "carbonblack_api_url": "u", "time_range": None}),
    (
        "CollectDarktrace",
        {
            **GRAYLOG,
            "integration": "darktrace",
            "public_token": "p",
            "private_token": "q",
            "darktrace_host": "h",
            "darktrace_port": "443",
            "timeframe": "15m",
        },
    ),
    ("CollectDarktrace", {**GRAYLOG, "integration": "darktrace", "public_token": "p", "darktrace_port": None}),
    (
        "CollectMimecast",
        {
            **GRAYLOG,
            "integration": "mimecast",
            "app_id": "a",
            "app_key": "b",
            "email_address": "e",
            "access_key": "c",
            "secret_key": "s",
            "uri": "/api/audit/get-siem-logs",
            "time_range": "15m",
        },
    ),
    ("CollectMimecast", {**GRAYLOG, "graylog_host": None, "integration": "mimecast", "app_id": "a"}),
    (
        "DataItem",
        {"oldestFirst": False, "from_": "2026-10-17T10:05:30.123Z", "to": "2026-10-17T10:20:30.123Z", "route": "all", "scanResult": "all"},
    ),
    ("DataItem", {"oldestFirst": False, "from_": None, "to": "2026-10-17T10:20:30.123Z", "route": "all", "scanResult": "all"}),
    ("DataItem", {"oldestFirst": False, "from_": "1011-01-01T00:00:00.000Z", "to": "x", "route": "all", "scanResult": "all"}),
]


def model_case(name, values):
    out = {"model": name, "input": values}
    try:
        out["json"] = MODELS[name](**values).model_dump_json()
    except Exception as e:  # noqa: BLE001 - every exception is a vector
        out["error"] = failure(e)
    return out


SAP = {"customer_code": "c"}
TTP = {"ApplicationID": "a", "ApplicationKey": "b", "AccessKey": "c", "SecretKey": "c2VjcmV0", "EmailAddress": "e@x"}

BOUNDED = [
    ("InvokeSapSiemRequest", SAP),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "1h", "threshold": "7"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "2d"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "3w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "05m"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "-5m"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "0m"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": " 5m"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "5x"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "ab"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "m"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": ""}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": None}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": 5}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": ["5", "m"]}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "53000w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "99999999999w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "200000000w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "-200000000w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "-400000000w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "106000w"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "999999999999999999999m"}),
    ("InvokeSapSiemRequest", {**SAP, "time_range": "1_0m"}),
    ("InvokeSapSiemRequest", {"time_range": "5x"}),
    ("InvokeSapSiemRequest", {"time_range": "05m", "threshold": "x"}),
    ("InvokeSapSiemRequest", {**SAP, "lower_bound": "keep", "time_range": None}),
    ("MimecastRequest", {"customer_code": "c"}),
    ("MimecastRequest", {"customer_code": "c", "time_range": "10h"}),
    ("MimecastRequest", {"customer_code": "c", "time_range": "1x"}),
    ("MimecastRequest", {"time_range": "0d"}),
    ("MimecastRequest", {"customer_code": "c", "time_range": None, "integration_name": None}),
    ("MimecastTTPURLSRequest", TTP),
    ("MimecastTTPURLSRequest", {**TTP, "time_range": "1h"}),
    ("MimecastTTPURLSRequest", {**TTP, "time_range": "1x"}),
    ("MimecastTTPURLSRequest", {**TTP, "time_range": "01h"}),
    ("MimecastTTPURLSRequest", {**TTP, "SecretKey": "abc"}),
    ("MimecastTTPURLSRequest", {**TTP, "SecretKey": "abcde"}),
    ("MimecastTTPURLSRequest", {**TTP, "SecretKey": "c2Vj cmV0!"}),
    ("MimecastTTPURLSRequest", {**TTP, "SecretKey": None}),
    ("MimecastTTPURLSRequest", {"ApplicationID": "a"}),
]

BOUNDED_MODELS = {
    "InvokeSapSiemRequest": sap_jobs_schema.InvokeSapSiemRequest,
    "MimecastRequest": mimecast_schema.MimecastRequest,
    "MimecastTTPURLSRequest": mimecast_schema.MimecastTTPURLSRequest,
}


def bounded_case(name, values):
    out = {"model": name, "input": values}
    try:
        model = BOUNDED_MODELS[name](**dict(values))
        out["json"] = model.model_dump_json(exclude={"headers"})
    except Exception as e:  # noqa: BLE001 - every exception is a vector
        out["error"] = failure(e)
    return out


B64 = ["", "YWJj", "YWJjZA==", "YWJjZA", "YW Jj!", "abc", "abcde", "a===", "====", "YQ==YQ==", "é", "c2VjcmV0LWtleQ==", "-_-_", "YW\nJj"]


def b64_case(text):
    try:
        return {"input": text, "hex": base64.b64decode(text).hex()}
    except Exception as e:  # noqa: BLE001 - every exception is a vector
        return {"input": text, "error": failure(e)}


URLS = [
    "https://us-api.mimecast.com",
    "http://127.0.0.1:8080/x?y=1",
    "HTTPS://EXAMPLE.COM",
    "ftp://example.com",
    "not a url",
    "http://",
    "https://",
    "//example.com",
    "https:example.com",
    "mailto:a@example.com",
    "https://[::1]:443/",
    "https://exa mple.com",
    "https://e.com/" + "a" * 2069,
    "https://e.com/" + "a" * 2070,
    "https://e.com/" + "é" * 1040,
    "https://e.com/" + "é" * 600,
    "https://e.com/" + "%C3%A9" * 345,
    "",
]


def url_case(text):
    try:
        TypeAdapter(HttpUrl).validate_python(text)
        return {"input": text, "ok": True}
    except ValidationError:
        return {"input": text, "ok": False}


def main():
    out = {
        "now": NOW.isoformat(),
        "models": [model_case(n, v) for n, v in MODEL_CASES],
        "bounded": [bounded_case(n, v) for n, v in BOUNDED],
        "b64decode": [b64_case(t) for t in B64],
        "http_urls": [url_case(t) for t in URLS],
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
