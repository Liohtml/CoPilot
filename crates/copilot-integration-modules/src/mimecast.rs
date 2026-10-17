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
//! Neither gets further. The region's `api` is a Pydantic `HttpUrl`, and
//! both services add a `str` to it (`base_url + auth_keys.URI`,
//! `BaseURL + "/api/ttp/url/get-logs"`): a `TypeError`. `/invoke` catches it
//! into its own 400 (after decoding the secret key, whose `binascii.Error`
//! comes first); `/ttp/urls` does not — uvicorn's bare 500, once the TTP
//! request body (`DataItem`) has validated. The SIEM log download, its
//! checkpoint file, the zip handling and the event shipping behind them are
//! therefore unreachable, and not ported: Python creates an empty checkpoint
//! file and log directory next to its module before failing; Rust writes
//! nothing (§4).

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
const SIEM_LOGS_FAILED: &str = "Unable to retrieve MTA SIEM logs from Mimecast integration.";

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
fn hdr_date() -> String {
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

/// `get_base_url(keys)`: whether the answer carries a region
/// (`mimecast_base_url.data.data[0]`, which each caller reads in its own
/// way).
async fn discover(st: &ModulesState, app_id: &PyValue, email: &PyValue) -> FailResult<bool> {
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
    Ok(!items.is_empty())
}

/// `invoke_mimecast_route` after its body: the keys, the discovery, then
/// `get_mta_siem_logs`' secret-key decode and the `TypeError` its `try`
/// turns into the 400.
pub async fn invoke(st: &ModulesState, code: &str, integration_name: &str) -> FailResult<()> {
    let keys = auth_keys(st, code, integration_name).await?;
    // The region is read inside the route's `try`: an empty list is its 400.
    if !discover(st, field(&keys, "APP_ID"), field(&keys, "EMAIL_ADDRESS")).await? {
        return Err(PyExc::http(400, BASE_URL_FAILED).into());
    }
    b64decode(field(&keys, "SECRET_KEY").as_str().unwrap_or_default())?;
    Err(PyExc::http(400, SIEM_LOGS_FAILED).into())
}

/// `mimecast_ttp_url_route` after its body: the keys, the
/// `MimecastTTPURLSRequest` (its model validator, then the `__init__`'s
/// header signature over the decoded secret key), the discovery, the first
/// page's `DataItem`, then the uncaught `TypeError`.
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
    b64decode(field(&request, "SecretKey").as_str().unwrap_or_default())?;
    // `mimecast_request.BaseURL = …data[0].region.api`, outside any `try`.
    if !discover(
        st,
        field(&request, "ApplicationID"),
        field(&request, "EmailAddress"),
    )
    .await?
    {
        return Err(Fail::other("IndexError", "list index out of range"));
    }
    construct(
        &schema::DATA_ITEM,
        &kwargs(vec![
            ("oldestFirst", PyValue::Bool(false)),
            ("from_", field(&request, "lower_bound").clone()),
            ("route", PyValue::Str("all".into())),
            ("to", field(&request, "upper_bound").clone()),
            ("scanResult", PyValue::Str("all".into())),
        ]),
    )?;
    Err(Fail::other(
        "TypeError",
        "unsupported operand type(s) for +: 'HttpUrl' and 'str'",
    ))
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
