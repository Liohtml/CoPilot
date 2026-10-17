"""Regenerate the vectors that pin the pure parts of the platform-status ports
(`copilot-status`, `copilot-license`) to the Python code they port (`app/utils.py`'s logs router,
`app/middleware/license.py`, `app/status/services/context_indicators.py`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-platform-vectors.py

Writes `crates/copilot-status/src/platform_vectors.json`:

* `time_range` — `TimeRangeModel.model_validate(body)` on request bodies: the value kept, the
  `RequestValidationError` its validator raises (its `msg`), Pydantic's own errors (`type`,
  `loc`, `msg`) or the class of anything else;
* `license_expiry` — `context_indicators._parse_license_expiry` on cached `expires` values: the
  naive datetime it gives (ISO) or `None`;

and `crates/copilot-license/src/license_vectors.json`:

* `models` — every licence model built from keyword arguments (`Model(**kwargs)`): its JSON as
  FastAPI writes it, or the `ValidationError`'s text.

Re-run after a Pydantic or Python upgrade, or a change to these modules.
"""

import datetime
import json
import pathlib

from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from app.middleware import license as lic
from app.status.services.context_indicators import _parse_license_expiry
from app.utils import TimeRangeModel

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATUS_OUT = ROOT / "crates" / "copilot-status" / "src" / "platform_vectors.json"
LICENSE_OUT = ROOT / "crates" / "copilot-license" / "src" / "license_vectors.json"

TIME_RANGE_BODIES = [
    {},
    {"time_range": "1d"},
    {"time_range": "7d"},
    {"time_range": "24h"},
    {"time_range": "1w"},
    {"time_range": "2w"},
    {"time_range": "0d"},
    {"time_range": "-1h"},
    {"time_range": "+3d"},
    {"time_range": " 3d"},
    {"time_range": "3 d"},
    {"time_range": "1_0d"},
    {"time_range": "1__0d"},
    {"time_range": "_1d"},
    {"time_range": "٣d"},
    {"time_range": " 3d"},
    {"time_range": "3m"},
    {"time_range": "3D"},
    {"time_range": "d"},
    {"time_range": "5"},
    {"time_range": ""},
    {"time_range": "abc"},
    {"time_range": "99999999999999999999999999999999999999999d"},
    {"time_range": "99999999999999999999999999999999999999999w"},
    {"time_range": "-99999999999999999999999999999999999999999d"},
    {"time_range": 1},
    {"time_range": 7},
    {"time_range": 8},
    {"time_range": 0},
    {"time_range": -2},
    {"time_range": 3.0},
    {"time_range": 1.5},
    {"time_range": True},
    {"time_range": False},
    {"time_range": None},
    {"time_range": []},
    {"time_range": {}},
    {"time_range": 10**30},
    {"time_range": "1d", "extra": 1},
]

EXPIRIES = [
    "2027-01-02T03:04:05.123456",
    "2027-01-02T03:04:05",
    "2027-01-02T03:04:05Z",
    "2027-01-02T03:04:05.5Z",
    "2027-01-02T03:04:05+02:00",
    "2027-01-02T03:04:05.123+02:00",
    "2027-01-02",
    "2027-01-02 03:04:05",
    "2027-01-02T03:04",
    "20270102T030405",
    "not a date",
    "",
    5,
    None,
    ["2027-01-02"],
]


def time_range_vectors():
    out = []
    for body in TIME_RANGE_BODIES:
        try:
            v = TimeRangeModel.model_validate(body)
            outcome = {"ok": v.time_range}
        except RequestValidationError as e:
            outcome = {"invalid": e.errors()[0]["msg"]}
        except ValidationError as e:
            outcome = {"errors": [{"type": x["type"], "loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}
        except Exception as e:  # noqa: BLE001 - recorded by class
            outcome = {"crash": type(e).__name__}
        out.append({"body": body, **outcome})
    return out


def expiry_vectors():
    out = []
    for raw in EXPIRIES:
        parsed = _parse_license_expiry(raw)
        out.append({"input": raw, "parsed": parsed.isoformat() if isinstance(parsed, datetime.datetime) else None})
    return out


LICENSE_OBJ = {
    "productId": 1,
    "id": "7",
    "key": "K",
    "created": "2026-01-02T03:04:05.123",
    "expires": 1767323045,
    "period": 365.0,
    "f1": True,
    "f2": "no",
    "f3": 1,
    "f4": "true",
    "f5": False,
    "f6": False,
    "f7": False,
    "f8": False,
    "notes": "",
    "block": False,
    "globalId": 9,
    "customer": {"id": 3, "name": "N", "email": "e", "companyName": "C", "created": "2025-06-01T00:00:00Z"},
    "activatedMachines": [1, "x"],
    "trialActivation": False,
    "maxNoOfMachines": 0,
    "dataObjects": [],
    "signDate": "2026-01-02T03:04:05+02:00",
}

MODEL_CASES = [
    ("VerifyLicenseResponse", {"license": LICENSE_OBJ, "success": True, "message": "m"}),
    ("VerifyLicenseResponse", {"license": {**LICENSE_OBJ, "created": "soon", "customer": None}, "success": "x", "message": 5}),
    ("VerifyLicenseResponse", {"license": [], "success": True, "message": "m"}),
    ("GetLicenseResponse", {"license_key": "k", "success": 1, "message": "m"}),
    ("GetLicenseResponse", {"license_key": 5, "success": "maybe"}),
    ("GetLicenseFeaturesResponse", {"features": ["a", 1, None], "success": True, "message": "m"}),
    ("GetLicenseFeaturesResponse", {"features": {"a": 1}, "success": True, "message": "m"}),
    (
        "IsFeatureEnabledResponse",
        {"status_code": 400, "message": "Feature is not enabled. You must purchase the X license to use this feature."},
    ),
    (
        "GetSubscriptionCatalogFeaturesResponse",
        {
            "features": [
                {
                    "id": "1",
                    "subscription_price_id": "p",
                    "name": "n",
                    "price": 10.0,
                    "currency": "usd",
                    "info": "i",
                    "short_description": "s",
                    "full_description": "f",
                },
                {"id": 2.5},
            ],
            "success": True,
            "message": "m",
        },
    ),
    ("TrialLicenseResponse", {"license_key": None, "success": True, "message": "m"}),
    ("CancelSubscriptionResponse", {"success": "yes", "message": "m"}),
    ("RetrieveDockerCompose", {"docker_compose": 5, "success": True, "message": "m"}),
    ("AddLicenseToDB", {"customer_email": 1, "customer_name": None}),
    ("TrialLicenseRequest", {"email": "e", "feature_name": "f", "customer_name": "c", "company_name": "co"}),
    ("TrialLicenseRequest", {"period": "3", "email": "e", "feature_name": "f", "customer_name": "c", "company_name": "co"}),
    ("FeatureSubscriptionRequest", {"feature_id": "x", "cancel_url": 1}),
    (
        "CheckoutSessionResponse",
        {
            "session": {
                "amount_subtotal": 1,
                "amount_total": 1,
                "automatic_tax": {"enabled": False},
                "cancel_url": "c",
                "created": 1,
                "currency": "usd",
                "custom_text": {},
                "expires_at": 2,
                "id": "i",
                "livemode": False,
                "metadata": {},
                "mode": "m",
                "object": "o",
                "payment_method_collection": "always",
                "payment_method_options": {"card": {"request_three_d_secure": "automatic"}},
                "payment_method_types": ["card"],
                "payment_status": "unpaid",
                "phone_number_collection": {"enabled": False},
                "status": "open",
                "success_url": "s",
                "total_details": {"amount_discount": 0, "amount_shipping": 0, "amount_tax": 0},
                "ui_mode": "hosted",
                "url": "u",
                "customer_details": {"email": "e"},
                "invoice_creation": {"enabled": True, "invoice_data": {}},
            },
        },
    ),
    ("CheckoutSessionResponse", {"session": {"created": "x"}, "success": "no"}),
]


def model_vectors():
    out = []
    for name, kwargs in MODEL_CASES:
        model = getattr(lic, name)
        try:
            dumped = json.loads(model(**kwargs).model_dump_json())
            out.append({"model": name, "kwargs": kwargs, "json": dumped})
        except ValidationError as e:
            out.append({"model": name, "kwargs": kwargs, "error": str(e)})
    return out


def write(path, data):
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {path}")


def main():
    write(STATUS_OUT, {"time_range": time_range_vectors(), "license_expiry": expiry_vectors()})
    write(LICENSE_OUT, {"models": model_vectors()})


if __name__ == "__main__":
    main()
