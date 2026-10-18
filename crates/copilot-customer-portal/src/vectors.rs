//! The pure parts of this crate against `portal_vectors.json`, generated
//! from the Python modules and libraries they reproduce
//! (`scripts/gen-customer-portal-vectors.py`).

use chrono::{Local, NaiveDateTime, TimeZone};
use serde_json::{Map, Value, json};

use copilot_web::validate::{LocPart, Validator, body_loc};

use crate::agents::csv;
use crate::branding::schema::{
    PatchPortalSettingsRequest, UpdateCustomerBrandingRequest, UpdatePortalSettingsRequest, py_bool,
};
use crate::branding::{services, validators};
use crate::dashboard::schema::utc_timestamp;
use crate::me::schema::PortalCustomer;
use crate::me::services::sort_customers;
use crate::query::pyd_int;
use crate::starlette;

fn vectors() -> Value {
    serde_json::from_str(include_str!("portal_vectors.json")).expect("vectors")
}

fn expand(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => {
            let c = o["repeat"].as_str().expect("repeat");
            let n = o["times"].as_u64().expect("times");
            Some(c.repeat(usize::try_from(n).expect("size")))
        }
        other => panic!("value {other}"),
    }
}

fn compact(v: Option<String>) -> Value {
    match v {
        None => Value::Null,
        Some(s) if s.len() > 1000 && s.chars().all(|c| s.starts_with(c)) => {
            json!({"repeat": s.chars().next().map(String::from), "times": s.chars().count()})
        }
        Some(s) => Value::String(s),
    }
}

#[test]
fn validators_match_python() {
    for case in vectors()["validators"].as_array().expect("cases") {
        let value = expand(&case["value"]);
        let got = match case["field"].as_str().expect("field") {
            "brand_color" => validators::validate_brand_color(value.as_deref()),
            "logo_base64" => validators::validate_logo_base64(value.as_deref()),
            _ => validators::validate_logo_mime_type(value.as_deref()),
        };
        let got = match got {
            Ok(v) => json!({"ok": compact(v)}),
            Err(e) => json!({"error": e}),
        };
        let want = match case.get("error") {
            Some(e) => json!({"error": e}),
            None => json!({"ok": case["ok"]}),
        };
        assert_eq!(got, want, "{}", case["field"]);
    }
}

#[test]
fn strict_base64_matches_cpython() {
    for case in vectors()["b64decode"].as_array().expect("cases") {
        let value = case["value"].as_str().expect("value");
        let got = match copilot_auth::pybase64::b64decode_validate(value) {
            Ok(b) => json!({"ok": hex::encode(b)}),
            Err(e) => json!({"error": e.to_string()}),
        };
        let want = match case.get("error") {
            Some(e) => json!({"error": e}),
            None => json!({"ok": case["ok"]}),
        };
        assert_eq!(got, want, "{value:?}");
    }
}

fn errors(v: &Validator) -> Value {
    Value::Array(
        v.errors()
            .iter()
            .map(|e| {
                let loc: Vec<Value> = e.loc[1..]
                    .iter()
                    .map(|p| match p {
                        LocPart::Key(k) => json!(k),
                        LocPart::Index(i) => json!(i),
                    })
                    .collect();
                json!({"type": e.kind, "loc": loc, "msg": e.msg})
            })
            .collect(),
    )
}

#[test]
fn request_models_match_pydantic() {
    for case in vectors()["models"].as_array().expect("cases") {
        let body: &Map<String, Value> = case["body"].as_object().expect("body");
        let mut v = Validator::new();
        let at = body_loc();
        let got = match case["model"].as_str().expect("model") {
            "UpdatePortalSettingsRequest" => {
                let r = UpdatePortalSettingsRequest::read(&mut v, body, &at);
                json!({"fields": fields(&r.fields)})
            }
            "PatchPortalSettingsRequest" => {
                let r = PatchPortalSettingsRequest::read(&mut v, body, &at);
                json!({"fields": fields(&r.fields), "sent": r.sent, "reset": r.reset})
            }
            _ => {
                let r = UpdateCustomerBrandingRequest::read(&mut v, body, &at);
                json!({"fields": fields(&r.fields), "enabled": r.enabled})
            }
        };
        let got = if v.has_errors() {
            json!({"errors": errors(&v)})
        } else {
            got
        };
        let mut want = case.as_object().expect("case").clone();
        want.remove("model");
        want.remove("body");
        assert_eq!(
            got,
            Value::Object(want),
            "{} {}",
            case["model"],
            case["body"]
        );
    }
}

fn fields(f: &crate::branding::schema::BrandingFields) -> Value {
    json!({
        "title": f.title,
        "logo_base64": f.logo_base64,
        "logo_mime_type": f.logo_mime_type,
        "brand_color": f.brand_color,
    })
}

#[test]
fn bools_and_ints_match_pydantic() {
    let v = vectors();
    for case in v["bools"].as_array().expect("cases") {
        let got = match py_bool(&case["value"]) {
            Ok(b) => json!({"ok": b}),
            Err((kind, msg)) => json!({"errors": [{"type": kind, "loc": [], "msg": msg}]}),
        };
        let mut want = case.as_object().expect("case").clone();
        want.remove("value");
        assert_eq!(got, Value::Object(want), "{}", case["value"]);
    }
    for case in v["ints"].as_array().expect("cases") {
        let raw = case["value"].as_str().expect("value");
        match (pyd_int(raw), case.get("ok")) {
            (Some(n), Some(want)) => assert_eq!(Some(n), want.as_i64().map(i128::from), "{raw:?}"),
            (None, None) => assert_eq!(case["errors"][0]["type"], "int_parsing", "{raw:?}"),
            (got, want) => panic!("{raw:?}: {got:?} vs {want:?}"),
        }
    }
}

#[test]
fn csv_timestamps_versions_and_names_match_python() {
    let v = vectors();
    for case in v["csv"].as_array().expect("cases") {
        let row: Vec<String> = case["row"]
            .as_array()
            .expect("row")
            .iter()
            .map(|f| f.as_str().expect("field").to_string())
            .collect();
        assert_eq!(csv::row(&row), case["text"].as_str().expect("text"));
    }
    for case in v["timestamps"].as_array().expect("cases") {
        let t = NaiveDateTime::parse_from_str(
            case["value"].as_str().expect("t"),
            "%Y-%m-%dT%H:%M:%S%.f",
        )
        .expect("datetime");
        assert_eq!(utc_timestamp(&t), case["text"].as_str().expect("text"));
    }
    for case in v["content_versions"].as_array().expect("cases") {
        assert_eq!(
            services::logo_content_version(case["logo"].as_str().expect("logo")),
            case["version"].as_str().expect("version")
        );
    }
    for case in v["logo_versions"].as_array().expect("cases") {
        let t =
            NaiveDateTime::parse_from_str(case["value"].as_str().expect("t"), "%Y-%m-%dT%H:%M:%S")
                .expect("datetime");
        // Generated under TZ=UTC: only comparable where this process's zone is UTC too.
        if Local.offset_from_utc_datetime(&t).local_minus_utc() == 0 {
            assert_eq!(
                services::logo_version(t),
                case["version"].as_str().expect("version")
            );
        }
    }
    for case in v["sorted_customers"].as_array().expect("cases") {
        let mut customers: Vec<PortalCustomer> = case["customers"]
            .as_array()
            .expect("customers")
            .iter()
            .map(|c| PortalCustomer {
                customer_code: c[0].as_str().expect("code").into(),
                customer_name: c[1].as_str().expect("name").into(),
            })
            .collect();
        sort_customers(&mut customers);
        let codes: Vec<&str> = customers.iter().map(|c| c.customer_code.as_str()).collect();
        let want: Vec<&str> = case["sorted"]
            .as_array()
            .expect("sorted")
            .iter()
            .map(|c| c.as_str().expect("code"))
            .collect();
        assert_eq!(codes, want);
    }
}

#[test]
fn byte_responses_match_starlette_and_gzip_middleware() {
    for case in vectors()["responses"].as_array().expect("cases") {
        let size = usize::try_from(case["size"].as_u64().expect("size")).expect("size");
        let given: Vec<(&str, String)> = case_headers(case);
        let mut request = http::HeaderMap::new();
        if let Some(accept) = case["accept"].as_str() {
            request.insert("accept-encoding", accept.parse().expect("header"));
        }
        let status = http::StatusCode::from_u16(
            u16::try_from(case["status"].as_u64().expect("status")).expect("status"),
        )
        .expect("status");
        let r = starlette::response(
            status,
            vec![b'a'; size],
            case["media_type"].as_str(),
            &given,
            &request,
        )
        .expect("response");
        let gzipped = r.headers().contains_key("content-encoding")
            && r.headers()["content-encoding"] == "gzip";
        let got: Vec<Value> = r
            .headers()
            .iter()
            .filter(|(k, _)| !(gzipped && k.as_str() == "content-length"))
            .map(|(k, v)| json!([k.as_str(), v.to_str().expect("ascii")]))
            .collect();
        assert_eq!(Value::Array(got), case["headers_out"], "{case}");
        assert_eq!(json!(gzipped), case["gzipped"], "{case}");
    }
}

fn case_headers(case: &Value) -> Vec<(&str, String)> {
    case["headers_in"]
        .as_object()
        .expect("headers")
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str().expect("value").to_string()))
        .collect()
}
