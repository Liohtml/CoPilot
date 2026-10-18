//! `POST /api/mimecast/invoke` and `POST /api/mimecast/ttp/urls`
//! (`app/integrations/mimecast/routes/mimecast.py`, `services/mimecast.py`).
//!
//! Both start the same way: the customer's Mimecast keys, then
//! `get_base_url` — a POST to Mimecast's region discovery through
//! `app/integrations/utils/collection.py:send_post_request` (httpx's default
//! client, a 429 retried once after `X-RateLimit-Reset` seconds), whose
//! answer must validate as `MimecastAPIEndpointResponse`; any failure there
//! is one 400.
//!
//! Python gets no further. The region's `api` is a Pydantic `HttpUrl`, and
//! both services add a `str` to it (`base_url + auth_keys.URI`,
//! `BaseURL + "/api/ttp/url/get-logs"`): a `TypeError` on every run, so
//! Mimecast never collects. Here the region's `api` is used as the string
//! Mimecast sent (it still has to validate as an `HttpUrl`), and both
//! routes do what Python's code does past that line — [`siem`] (the SIEM
//! download, its checkpoint file and log directory in [`files`], the zip in
//! [`zip`]) and [`ttp`] (the TTP URL pages), every event shipped through
//! the Event Shipper (RUST_MIGRATION.md §4, "Python fails, Rust works").
//! The region URL is Mimecast's answer, so `COPILOT_INTEGRATION_MODULES_URL`
//! does not rewrite it (the parity harness's discovery stand-in answers
//! with its own address).

pub mod files;
pub mod siem;
pub mod ttp;
#[cfg(test)]
mod vectors;
pub mod zip;

use std::time::Duration;

use chrono::Utc;
use copilot_auth::pybase64::{Base64Error, a2b_base64};
use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::{self, Client, DEFAULT_TIMEOUT, HttpxError, Request, Response};
use copilot_upstream::model::{Invalid, construct, field, kwargs, validate};
use copilot_upstream::py::{PyExc, PyResult, int_of};
use http::Method;

use crate::ModulesState;
use crate::error::{Fail, FailResult};
use crate::lookups;
use crate::sap_siem::{construct_bounded, utcnow};
use crate::schema;
use crate::upstream::MIMECAST_DISCOVER_URL;

const BASE_URL_FAILED: &str = "Unable to retrieve base URL for Mimecast integration.";

/// The customer's `MimecastAuthKeys` (the route's first three steps).
async fn auth_keys(st: &ModulesState, code: &str, name: &str) -> FailResult<PyValue> {
    let cis = lookups::integration_response(&st.ctx.db, code).await?;
    let ci = lookups::find_customer_integration(&cis, name)?;
    let keys = lookups::extract_auth_keys(ci, "Mimecast")?;
    Ok(construct(&schema::MIMECAST_KEYS, &keys)?)
}

/// `base64.b64decode(value)` of a `str`: the non-ASCII `ValueError`, or
/// `binascii.Error` (both `ValueError`s).
pub fn b64decode(value: &str) -> PyResult<Vec<u8>> {
    if !value.is_ascii() {
        return Err(PyExc::ValueError(Base64Error::NonAscii.to_string()));
    }
    a2b_base64(value.as_bytes()).map_err(|e| PyExc::ValueError(e.to_string()))
}

/// Pydantic's `HttpUrl` on a string: what pydantic-core's `url` parse
/// accepts, an http(s) scheme, a host, the input at most 2083 bytes long
/// (UTF-8, before any percent-encoding).
pub fn is_http_url(s: &str) -> bool {
    if s.len() > 2083 {
        return false;
    }
    match url::Url::parse(s) {
        Ok(u) => {
            matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty())
        }
        Err(_) => false,
    }
}

/// `datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")`.
pub(crate) fn hdr_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S UTC").to_string()
}

/// `send_post_request`'s outcome: the answer's data, or its
/// `{"success": False}` (whose text no caller reads).
async fn send_post_request(
    st: &ModulesState,
    headers: &[(&str, String)],
    data: PyValue,
) -> Option<PyValue> {
    let client = Client::new(DEFAULT_TIMEOUT).ok()?;
    let request = || {
        let mut req =
            Request::new(Method::POST, st.upstream.url(MIMECAST_DISCOVER_URL)).json(data.clone());
        for (name, value) in headers {
            req = req.header(name, Some(value));
        }
        req
    };
    let attempt = async {
        let mut resp: Response = httpx::send_on(&client, request()).await?;
        if resp.status == 429 {
            let reset = resp
                .headers
                .get("X-RateLimit-Reset")
                .map(|v| PyValue::Str(String::from_utf8_lossy(v.as_bytes()).into_owned()))
                .unwrap_or(PyValue::Int("1".into()));
            let seconds = int_of(&reset).map_err(|e| HttpxError {
                class: "ValueError",
                message: e.text(),
            })?;
            let seconds: f64 = seconds.parse().unwrap_or(f64::MAX);
            tracing::warn!(target: "copilot::integration_modules",
                "Rate limit exceeded. Retrying after {seconds} seconds.");
            if seconds > 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(seconds.min(1.0e9))).await;
            }
            resp = httpx::send_on(&client, request()).await?;
        }
        Ok::<Response, HttpxError>(resp)
    };
    let resp = match attempt.await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: "copilot::integration_modules",
                "Failed to send POST request: {}", e.message);
            return None;
        }
    };
    if resp.status != 200 {
        tracing::error!(target: "copilot::integration_modules",
            "Request failed with status code {}", resp.status);
        return None;
    }
    let content_type = resp
        .headers
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    if content_type.contains("application/json") {
        resp.json().ok()
    } else {
        // `response.content`: bytes, which no model below accepts.
        Some(PyValue::List(vec![PyValue::None]))
    }
}

/// `get_base_url(keys)`: the first region's `api` as Mimecast sent it
/// (`mimecast_base_url.data.data[0].region.api`, which each caller reads in
/// its own way), `None` when the answer lists no region.
async fn discover(
    st: &ModulesState,
    app_id: &PyValue,
    email: &PyValue,
) -> FailResult<Option<String>> {
    let fail = || Fail::Py(PyExc::http(400, BASE_URL_FAILED));
    let headers = [
        (
            "x-mc-app-id",
            app_id.as_str().unwrap_or_default().to_string(),
        ),
        ("x-mc-req-id", uuid::Uuid::new_v4().to_string()),
        ("x-mc-date", hdr_date()),
    ];
    let body = PyValue::Dict(vec![(
        "data".into(),
        PyValue::List(vec![PyValue::Dict(vec![(
            "emailAddress".into(),
            email.clone(),
        )])]),
    )]);
    let Some(data) = send_post_request(st, &headers, body).await else {
        return Err(fail());
    };
    let response = PyValue::Dict(vec![
        ("data".into(), data),
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Successfully retrieved data".into()),
        ),
    ]);
    let dump = match validate(&schema::ENDPOINT_RESPONSE, &response) {
        Ok(d) => d,
        Err(Invalid::Errors(_) | Invalid::Abort(..)) => return Err(fail()),
    };
    let items = field(field(&dump, "data"), "data");
    let PyValue::List(items) = items else {
        return Err(fail());
    };
    let urls_ok = items.iter().all(|item| {
        let region = field(item, "region");
        ["api", "mpp", "adminConsole"]
            .iter()
            .all(|k| field(region, k).as_str().is_some_and(is_http_url))
    });
    if !urls_ok {
        return Err(fail());
    }
    Ok(items.first().map(|item| {
        field(field(item, "region"), "api")
            .as_str()
            .unwrap_or_default()
            .to_string()
    }))
}

/// `invoke_mimecast_route` after its body: the keys, the discovery (an
/// empty region list is the route's `try`'s 400), then the collection
/// ([`siem::collect`]).
pub async fn invoke(st: &ModulesState, code: &str, integration_name: &str) -> FailResult<()> {
    let keys = auth_keys(st, code, integration_name).await?;
    let Some(base_url) =
        discover(st, field(&keys, "APP_ID"), field(&keys, "EMAIL_ADDRESS")).await?
    else {
        return Err(PyExc::http(400, BASE_URL_FAILED).into());
    };
    tracing::info!(target: "copilot::integration_modules", "mimecast_base_url: {base_url}");
    siem::collect(st, code, &keys, &base_url).await
}

/// `mimecast_ttp_url_route` after its body: the keys, the
/// `MimecastTTPURLSRequest` (its model validator, then the `__init__`'s
/// header signature over the decoded secret key), the discovery (no region
/// is the `IndexError`, outside any `try`), then the pages ([`ttp::pages`]).
pub async fn ttp_urls(
    st: &ModulesState,
    code: &str,
    integration_name: &str,
    time_range: &PyValue,
) -> FailResult<()> {
    let keys = auth_keys(st, code, integration_name).await?;
    let request = construct_bounded(
        &schema::MIMECAST_TTP_REQUEST,
        &kwargs(vec![
            ("ApplicationID", field(&keys, "APP_ID").clone()),
            ("ApplicationKey", field(&keys, "APP_KEY").clone()),
            ("AccessKey", field(&keys, "ACCESS_KEY").clone()),
            ("SecretKey", field(&keys, "SECRET_KEY").clone()),
            ("EmailAddress", field(&keys, "EMAIL_ADDRESS").clone()),
            ("time_range", time_range.clone()),
        ]),
        utcnow(),
    )?;
    let secret = b64decode(field(&request, "SecretKey").as_str().unwrap_or_default())?;
    let signed = ttp::headers(&request, &secret);
    // `mimecast_request.BaseURL = …data[0].region.api`, outside any `try`.
    let Some(base_url) = discover(
        st,
        field(&request, "ApplicationID"),
        field(&request, "EmailAddress"),
    )
    .await?
    else {
        return Err(Fail::other("IndexError", "list index out of range"));
    };
    ttp::pages(st, code, &request, &signed, &base_url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64decode_raises_like_python() {
        assert_eq!(b64decode("YWJj").expect("ok"), b"abc");
        assert_eq!(b64decode("YW Jj!").expect("ok"), b"abc");
        assert_eq!(
            b64decode("abc").expect_err("bad").text(),
            "Incorrect padding"
        );
        assert_eq!(
            b64decode("abcde").expect_err("bad").text(),
            "Invalid base64-encoded string: number of data characters (5) cannot be 1 more than \
             a multiple of 4"
        );
        assert_eq!(
            b64decode("é").expect_err("bad").text(),
            "string argument should contain only ASCII characters"
        );
        assert_eq!(b64decode("").expect("ok"), b"");
    }

    #[test]
    fn http_urls_as_pydantic_takes_them() {
        assert!(is_http_url("https://us-api.mimecast.com"));
        assert!(is_http_url("http://127.0.0.1:8080/x"));
        assert!(!is_http_url("ftp://example.com"));
        assert!(!is_http_url("not a url"));
        assert!(!is_http_url("http://"));
        assert!(!is_http_url(&format!("https://e.com/{}", "a".repeat(2100))));
    }
}
