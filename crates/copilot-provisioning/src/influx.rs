//! The InfluxDB monitoring checks — port of
//! `app/stack_provisioning/influxdb/services/provision.py` — over the v2 REST
//! helpers of `app/connectors/influxdb/utils/universal.py`.
//!
//! **The transport** ([`request`]) is `_influxdb_request`: a fresh
//! `httpx.AsyncClient(verify=INFLUXDB_VERIFY_SSL, timeout=60)` per call,
//! `{connector_url minus trailing /}{endpoint}`, `Authorization: Token
//! {connector_api_key}` (`Token None` without one), `Content-Type:
//! application/json`, httpx's own `User-Agent` / `Accept-Encoding` and query
//! encoding, `json=` as compact UTF-8; any failure to get an answer is
//! `HTTPException(500, "Failed to reach InfluxDB: {e}")`, a status ≥ 300
//! `HTTPException(500, "InfluxDB request failed ({status}): {text}")`, an
//! empty body `None`, anything else `response.json()` (whose
//! `JSONDecodeError` is the `ValueError` handler's 400).
//!
//! **The checks** are rendered the way Python renders them: `json.dumps` of
//! the template (default separators, ASCII), `str.replace` of the two
//! placeholders, `json.loads` again — so an org id or bucket that breaks the
//! JSON text fails with `json`'s own message. A check that already exists is
//! skipped unless `overwrite`.

use std::time::Duration;

use bytes::Bytes;
use copilot_auth::pyvalue::{PyValue, loads_bytes};
use copilot_influxdb::InfluxClient;
use copilot_upstream::http::urlencode;
use copilot_upstream::json::{Dumps, py_dumps, py_loads};
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, PyResult, getitem, type_name};
use copilot_web::form::py_strip;
use http::Method;

use crate::schema::{INFLUX_CHECKS, PROVISIONED_CHECK};
use crate::templates;

/// `_influxdb_request`'s timeout.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// httpx's `User-Agent`.
pub const USER_AGENT: &str = "python-httpx/0.28.1";
/// The org-id placeholder.
pub const REPLACE_ORG_ID: &str = "REPLACE_ORG_ID";
/// The bucket placeholder.
pub const REPLACE_BUCKET: &str = "REPLACE_BUCKET";

/// `_influxdb_verify_ssl()` (read on every call, as Python does).
fn verify_ssl() -> bool {
    std::env::var("INFLUXDB_VERIFY_SSL")
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

fn reach(text: impl std::fmt::Display) -> PyExc {
    PyExc::http(500, format!("Failed to reach InfluxDB: {text}"))
}

/// httpx's answer decoding (`gzip`, `deflate`); `None` is its
/// `DecodingError`.
fn decode(headers: &http::HeaderMap, raw: Bytes) -> Option<Bytes> {
    use std::io::Read as _;
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    match encoding.as_str() {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .ok()?;
        }
        "deflate" => {
            if flate2::read::ZlibDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(&raw[..])
                    .read_to_end(&mut out)
                    .ok()?;
            }
        }
        _ => return Some(raw),
    }
    Some(Bytes::from(out))
}

/// How httpx words a transport failure (`str(e)`).
fn transport_text(e: &reqwest::Error) -> String {
    let chain = error_chain(e);
    if e.is_timeout() {
        String::new()
    } else if chain.contains("failed to lookup") || chain.contains("dns error") {
        "[Errno -2] Name or service not known".into()
    } else if chain.contains("certificate") {
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer \
         certificate (_ssl.c:1006)"
            .into()
    } else if e.is_connect() {
        "All connection attempts failed".into()
    } else {
        chain
    }
}

/// `_influxdb_request(method, endpoint, params, data)`.
pub async fn request(
    client: &InfluxClient,
    method: Method,
    endpoint: &str,
    params: &[(String, String)],
    json: Option<&PyValue>,
) -> PyResult<PyValue> {
    let row = client.attributes().await?;
    let url = format!("{}{endpoint}", row.connector_url.trim_end_matches('/'));
    let key = row.connector_api_key.as_deref().unwrap_or("None");
    let parsed = match url.split_once("://") {
        Some((scheme, _)) if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") => {
            reqwest::Url::parse(&url).map_err(reach)?
        }
        Some((scheme, _)) if !scheme.is_empty() && !scheme.contains('/') => {
            return Err(reach(format!(
                "Request URL has an unsupported protocol '{}://'.",
                scheme.to_ascii_lowercase()
            )));
        }
        _ => {
            return Err(reach(
                "Request URL is missing an 'http://' or 'https://' protocol.",
            ));
        }
    };
    let mut target = parsed;
    if !params.is_empty() {
        target.set_query(Some(&urlencode(params)));
    }
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_ssl())
        .connect_timeout(TIMEOUT)
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| reach(error_chain(&e)))?;
    let mut builder = http
        .request(method.clone(), target)
        .header(http::header::ACCEPT_ENCODING, "gzip, deflate")
        .header(http::header::AUTHORIZATION, format!("Token {key}"))
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(body) = json {
        let text = py_dumps(body, Dumps::HTTPX).map_err(|e| reach(e.to_string()))?;
        builder = builder.body(text.into_bytes());
    } else if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder.header(http::header::CONTENT_LENGTH, "0");
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| reach(transport_text(&e)))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let raw = resp.bytes().await.map_err(|e| reach(transport_text(&e)))?;
    let body = decode(&headers, raw).ok_or_else(|| reach("Error -3 while decompressing data"))?;
    if status >= 300 {
        return Err(PyExc::http(
            500,
            format!(
                "InfluxDB request failed ({status}): {}",
                String::from_utf8_lossy(&body)
            ),
        ));
    }
    if body.is_empty() {
        return Ok(PyValue::None);
    }
    // `response.json()`: `json.loads` of the bytes.
    loads_bytes(&body).map_err(|_| {
        PyExc::JsonDecode(
            py_loads(&String::from_utf8_lossy(&body))
                .err()
                .unwrap_or_else(|| "Expecting value: line 1 column 1 (char 0)".into()),
        )
    })
}

/// `send_get_request(endpoint, params)`.
pub async fn get(
    client: &InfluxClient,
    endpoint: &str,
    params: &[(&str, &str)],
) -> PyResult<PyValue> {
    let params: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    request(client, Method::GET, endpoint, &params, None).await
}

/// `get_influxdb_org_id()`: the org's `id`, as InfluxDB gave it.
pub async fn org_id(client: &InfluxClient) -> PyResult<PyValue> {
    let org = client.organization().await?;
    let response = get(client, "/api/v2/orgs", &[("org", &org)]).await?;
    let PyValue::Dict(_) = &response else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(&response)
        )));
    };
    let orgs = response
        .get("orgs")
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    for o in copilot_upstream::py::iterate(&orgs)? {
        let PyValue::Dict(_) = &o else {
            return Err(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'get'",
                type_name(&o)
            )));
        };
        if o.get("name")
            .is_some_and(|n| n == &PyValue::Str(org.clone()))
        {
            return getitem(&o, "id").cloned();
        }
    }
    Err(PyExc::http(
        404,
        format!("InfluxDB organization {org} not found"),
    ))
}

/// `get_influxdb_bucket()`.
pub async fn bucket(client: &InfluxClient) -> PyResult<String> {
    let row = client.attributes().await?;
    let extra = row.connector_extra_data.as_deref().ok_or_else(|| {
        PyExc::AttributeError("'NoneType' object has no attribute 'split'".into())
    })?;
    let parts: Vec<&str> = extra.split(',').collect();
    match parts.get(1) {
        Some(b) => Ok(py_strip(b).to_string()),
        None => Err(PyExc::http(
            500,
            "Invalid connector_extra_data format for InfluxDB. Expected 'ORG,BUCKET'.",
        )),
    }
}

/// `str.replace(old, new)` where `new` must be a `str`.
fn replace(text: &str, old: &str, new: &PyValue) -> PyResult<String> {
    match new {
        PyValue::Str(s) => Ok(text.replace(old, s)),
        other => Err(PyExc::TypeError(format!(
            "replace() argument 2 must be str, not {}",
            type_name(other)
        ))),
    }
}

/// `render_check_template(name)`: the payload.
pub fn render(template: &PyValue, org_id: &PyValue, bucket: &str) -> PyResult<PyValue> {
    let text = py_dumps(template, Dumps::DEFAULT).map_err(|e| PyExc::ValueError(e.to_string()))?;
    let text = replace(&text, REPLACE_ORG_ID, org_id)?;
    let text = text.replace(REPLACE_BUCKET, bucket);
    py_loads(&text).map_err(PyExc::JsonDecode)
}

/// `load_raw_check_template(name)`.
fn template(name: &str) -> PyResult<PyValue> {
    templates::check(name)
        .ok_or_else(|| PyExc::http(404, format!("InfluxDB check template {name} not found")))
}

/// `get_existing_checks()`: `(name, id)` pairs, a later name replacing an
/// earlier one as a dict does.
pub async fn existing_checks(client: &InfluxClient) -> PyResult<Vec<(PyValue, PyValue)>> {
    let response = get(client, "/api/v2/checks", &[("limit", "100")]).await?;
    let response = if response.truthy() {
        response
    } else {
        PyValue::Dict(Vec::new())
    };
    let PyValue::Dict(_) = &response else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(&response)
        )));
    };
    let checks = response
        .get("checks")
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    let mut out: Vec<(PyValue, PyValue)> = Vec::new();
    for check in copilot_upstream::py::iterate(&checks)? {
        let PyValue::Dict(_) = &check else {
            return Err(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'get'",
                type_name(&check)
            )));
        };
        if !check.get("name").is_some_and(PyValue::truthy) {
            continue;
        }
        let name = getitem(&check, "name")?.clone();
        let id = getitem(&check, "id")?.clone();
        if matches!(name, PyValue::List(_) | PyValue::Dict(_)) {
            return Err(PyExc::TypeError(format!(
                "unhashable type: '{}'",
                type_name(&name)
            )));
        }
        match out
            .iter_mut()
            .find(|(k, _)| copilot_upstream::py::py_eq(k, &name))
        {
            Some(slot) => slot.1 = id,
            None => out.push((name, id)),
        }
    }
    Ok(out)
}

fn lookup<'a>(existing: &'a [(PyValue, PyValue)], name: &str) -> Option<&'a PyValue> {
    existing
        .iter()
        .find(|(k, _)| matches!(k, PyValue::Str(s) if s == name))
        .map(|(_, v)| v)
}

fn st(s: &str) -> PyValue {
    PyValue::Str(s.to_string())
}

/// `get_available_checks()`: the response dump.
pub async fn available_checks(client: &InfluxClient) -> PyResult<PyValue> {
    let existing = existing_checks(client).await?;
    let mut items = Vec::new();
    for (name, description) in INFLUX_CHECKS {
        let t = template(name)?;
        let check_name = getitem(&t, "name")?.clone();
        let provisioned = match &check_name {
            PyValue::Str(s) => lookup(&existing, s).is_some(),
            _ => false,
        };
        items.push(kwargs(vec![
            ("name", st(name)),
            ("description", st(description)),
            ("check_name", check_name),
            ("provisioned", PyValue::Bool(provisioned)),
        ]));
    }
    Ok(kwargs(vec![
        ("available_checks", PyValue::List(items)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            st("Available InfluxDB checks retrieved successfully"),
        ),
    ]))
}

/// One `ProvisionedInfluxDBCheck` (its dump) and its action.
#[derive(Debug, Clone, PartialEq)]
pub struct Provisioned {
    /// The dump.
    pub dump: PyValue,
    /// `action`.
    pub action: &'static str,
    /// `check_name`.
    pub check_name: String,
}

/// `provision_single_check(name, overwrite)`.
pub async fn provision_single(
    client: &InfluxClient,
    name: &str,
    overwrite: bool,
) -> PyResult<Provisioned> {
    let raw = template(name)?;
    let org = org_id(client).await?;
    let bucket = bucket(client).await?;
    let payload = render(&raw, &org, &bucket)?;
    let check_name = getitem(&payload, "name")?.clone();
    let existing = existing_checks(client).await?;
    let check_name_text = check_name.py_str();
    let existing_id = match &check_name {
        PyValue::Str(s) => lookup(&existing, s).cloned(),
        _ => None,
    };
    let make = |action: &'static str, id: PyValue| -> PyResult<Provisioned> {
        let dump = construct(
            &PROVISIONED_CHECK,
            &kwargs(vec![
                ("name", st(name)),
                ("check_name", check_name.clone()),
                ("action", st(action)),
                ("check_id", id),
            ]),
        )?;
        Ok(Provisioned {
            dump,
            action,
            check_name: check_name_text.clone(),
        })
    };
    let truthy = existing_id.as_ref().is_some_and(PyValue::truthy);
    if truthy && !overwrite {
        return make("skipped", existing_id.unwrap_or(PyValue::None));
    }
    let (response, action) = if truthy {
        let id = existing_id
            .as_ref()
            .map(PyValue::py_str)
            .unwrap_or_default();
        (
            request(
                client,
                Method::PUT,
                &format!("/api/v2/checks/{id}"),
                &[],
                Some(&payload),
            )
            .await?,
            "updated",
        )
    } else {
        (
            request(client, Method::POST, "/api/v2/checks", &[], Some(&payload)).await?,
            "created",
        )
    };
    let id = if response.truthy() {
        match &response {
            PyValue::Dict(_) => response.get("id").cloned().unwrap_or(PyValue::None),
            other => {
                return Err(PyExc::AttributeError(format!(
                    "'{}' object has no attribute 'get'",
                    type_name(other)
                )));
            }
        }
    } else {
        PyValue::None
    };
    make(action, id)
}

/// `provision_check(request)`: the response dump.
pub async fn provision_check(
    client: &InfluxClient,
    name: &str,
    overwrite: bool,
) -> PyResult<PyValue> {
    let result = provision_single(client, name, overwrite).await?;
    let message = if result.action == "skipped" {
        format!(
            "{} already exists in InfluxDB and was left unchanged. Set overwrite to replace it.",
            result.check_name
        )
    } else {
        format!("{} {} successfully", result.check_name, result.action)
    };
    Ok(kwargs(vec![
        ("results", PyValue::List(vec![result.dump])),
        ("success", PyValue::Bool(true)),
        ("message", PyValue::Str(message)),
    ]))
}

/// `provision_all_checks(overwrite)`: the response dump.
pub async fn provision_all(client: &InfluxClient, overwrite: bool) -> PyResult<PyValue> {
    let mut results = Vec::new();
    for (name, _) in INFLUX_CHECKS {
        results.push(provision_single(client, name, overwrite).await?);
    }
    let count = |a: &str| results.iter().filter(|r| r.action == a).count();
    let message = format!(
        "InfluxDB checks provisioned: {} created, {} updated, {} skipped",
        count("created"),
        count("updated"),
        count("skipped")
    );
    Ok(kwargs(vec![
        (
            "results",
            PyValue::List(results.into_iter().map(|r| r.dump).collect()),
        ),
        ("success", PyValue::Bool(true)),
        ("message", PyValue::Str(message)),
    ]))
}

/// `decommission_check(name)`: the response dump.
pub async fn decommission(client: &InfluxClient, name: &str) -> PyResult<PyValue> {
    let raw = template(name)?;
    let check_name = getitem(&raw, "name")?.clone();
    let existing = existing_checks(client).await?;
    let existing_id = match &check_name {
        PyValue::Str(s) => lookup(&existing, s).cloned(),
        _ => None,
    };
    let Some(id) = existing_id.filter(PyValue::truthy) else {
        return Err(PyExc::http(
            404,
            format!("InfluxDB check {} does not exist", check_name.py_str()),
        ));
    };
    request(
        client,
        Method::DELETE,
        &format!("/api/v2/checks/{}", id.py_str()),
        &[],
        None,
    )
    .await?;
    Ok(kwargs(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            PyValue::Str(format!(
                "{} decommissioned successfully",
                check_name.py_str()
            )),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn rendering_is_text_replacement() {
        let t = templates::check("SOCFORTRESS_INFLUXDB_DISK_CHECK").unwrap();
        let out = render(&t, &st("0a1b"), "telegraf").unwrap();
        assert_eq!(out.get("orgID"), Some(&st("0a1b")));
        let text = out.get("query").unwrap().get("text").unwrap().py_str();
        assert!(text.starts_with("from(bucket: \"telegraf\")"));
        let err = render(&t, &loads("5").unwrap(), "x").unwrap_err();
        assert_eq!(err.text(), "replace() argument 2 must be str, not int");
        assert!(matches!(
            render(&t, &st("a\"b"), "x").unwrap_err(),
            PyExc::JsonDecode(_)
        ));
    }
}
