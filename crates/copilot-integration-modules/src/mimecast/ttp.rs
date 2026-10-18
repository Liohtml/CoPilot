//! `get_ttp_urls` past the region discovery: the TTP URL pages, as
//! `app/integrations/mimecast/services/mimecast.py` sends them had
//! `mimecast_request.BaseURL` been the string Mimecast sent (it is the
//! region's `HttpUrl`, and `BaseURL + "/api/ttp/url/get-logs"` is the
//! `TypeError` every Python run ends in — RUST_MIGRATION.md §4).
//!
//! Per page: the `RequestBody` (`DataItem` from the request's two bounds,
//! the page token in `meta.pagination.pageToken` from the second page on),
//! dumped by alias with `from`/`to` written `%Y-%m-%dT%H:%M:%S%z`, then
//! `requests.post(url=BaseURL + "/api/ttp/url/get-logs", headers=…,
//! data=str(request_dict), timeout=60)` — the body is the dict's `repr()`,
//! as Python sends it, and the signed headers are the ones
//! `MimecastTTPURLSRequest.__init__` made once for every page. The answer
//! is `TtpURLResponseBody(**response.json())`; each click log of its first
//! data item is one event through the Event Shipper; `meta.pagination.next`
//! names the next page. Nothing is caught: a `ValueError` (requests'
//! URL and header refusals, `JSONDecodeError`, the `ValidationError`) is the
//! handler's 400, anything else uvicorn's bare 500.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::http::PyRequest;
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::PyExc;
use http::Method;

use crate::ModulesState;
use crate::error::{Fail, FailResult};
use crate::schema;

/// The URI the TTP headers are signed for and the page path.
pub const TTP_URI: &str = "/api/ttp/url/get-logs";

/// `MimecastTTPURLSRequest.generate_headers(TTP_URI)`: the five headers
/// in `MimecastHeaders`' order.
pub fn headers(request: &PyValue, secret: &[u8]) -> Vec<(&'static str, String)> {
    let text = |k: &str| field(request, k).as_str().unwrap_or_default().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S UTC")
        .to_string();
    let to_sign = [
        date.as_str(),
        request_id.as_str(),
        TTP_URI,
        &text("ApplicationKey"),
    ]
    .join(":");
    let sig = super::siem::signature(secret, &to_sign);
    vec![
        ("Authorization", format!("MC {}:{sig}", text("AccessKey"))),
        ("x-mc-app-id", text("ApplicationID")),
        ("x-mc-date", date),
        ("x-mc-req-id", request_id),
        ("Content-Type", "application/json".into()),
    ]
}

/// `custom_datetime_format` of a bound `DataItem` read: the bound's
/// seconds, then its UTC offset (`+0000`; the bounds are `…Z`).
fn mimecast_time(bound: &str) -> String {
    format!("{}+0000", bound.get(..19).unwrap_or(bound))
}

/// requests' exceptions that are also `ValueError`s (the handler's 400).
fn requests_value_error(e: &PyExc) -> bool {
    matches!(
        e,
        PyExc::Other(
            "InvalidURL" | "InvalidSchema" | "MissingSchema" | "InvalidHeader" | "InvalidProxyURL",
            _
        )
    ) || e.is_value_error()
}

/// The pages after the discovery (`base_url`), for `request` (the
/// validated `MimecastTTPURLSRequest` dump) and its `signed` headers.
pub async fn pages(
    st: &ModulesState,
    code: &str,
    request: &PyValue,
    signed: &[(&'static str, String)],
    base_url: &str,
) -> FailResult<()> {
    let client = super::siem::requests_client()?;
    let mut token: Option<String> = None;
    loop {
        tracing::info!(target: "copilot::integration_modules", "Mimecast TTP URL request received");
        construct(
            &schema::DATA_ITEM,
            &kwargs(vec![
                ("oldestFirst", PyValue::Bool(false)),
                ("from_", field(request, "lower_bound").clone()),
                ("route", PyValue::Str("all".into())),
                ("to", field(request, "upper_bound").clone()),
                ("scanResult", PyValue::Str("all".into())),
            ]),
        )?;
        let bound = |k: &str| field(request, k).as_str().unwrap_or_default().to_string();
        let meta = match &token {
            Some(t) if !t.is_empty() => PyValue::Dict(vec![(
                "pagination".into(),
                PyValue::Dict(vec![("pageToken".into(), PyValue::Str(t.clone()))]),
            )]),
            _ => PyValue::Dict(Vec::new()),
        };
        let body = PyValue::Dict(vec![
            ("meta".into(), meta),
            (
                "data".into(),
                PyValue::List(vec![PyValue::Dict(vec![
                    ("oldestFirst".into(), PyValue::Bool(false)),
                    (
                        "from".into(),
                        PyValue::Str(mimecast_time(&bound("lower_bound"))),
                    ),
                    (
                        "to".into(),
                        PyValue::Str(mimecast_time(&bound("upper_bound"))),
                    ),
                    ("route".into(), PyValue::Str("all".into())),
                    ("scanResult".into(), PyValue::Str("all".into())),
                ])]),
            ),
        ]);
        let mut req = PyRequest::new(Method::POST, format!("{base_url}{TTP_URI}"));
        for (name, value) in signed {
            req = req.header(name, value.clone());
        }
        let resp = client.send(req.data(body.py_repr())).await.map_err(|e| {
            if requests_value_error(&e) {
                Fail::Py(PyExc::ValueError(e.text()))
            } else {
                Fail::Py(e)
            }
        })?;
        let answer = resp.json()?;
        let page = construct_star(
            &schema::TTP_RESPONSE,
            "app.integrations.mimecast.schema.mimecast.TtpURLResponseBody",
            &answer,
        )?;
        let PyValue::List(items) = field(&page, "data") else {
            return Err(Fail::other("TypeError", "data is not a list"));
        };
        let Some(first) = items.first() else {
            return Err(Fail::Py(PyExc::IndexError(
                "list index out of range".into(),
            )));
        };
        if let PyValue::List(logs) = field(first, "clickLogs") {
            for log in logs {
                let PyValue::Dict(fields) = log else { continue };
                let message = super::files::event_payload(code, fields.clone())?;
                copilot_graylog::gelf::ship(&st.ctx.connectors, &message).await?;
            }
        }
        let next = field(field(field(&page, "meta"), "pagination"), "next");
        match next {
            PyValue::Str(n) if !n.is_empty() => token = Some(n.clone()),
            _ => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_written_as_strftime_with_the_offset() {
        assert_eq!(
            mimecast_time("2026-10-17T21:45:00.123Z"),
            "2026-10-17T21:45:00+0000"
        );
    }

    #[test]
    fn the_body_is_the_dict_s_repr() {
        let body = PyValue::Dict(vec![
            ("meta".into(), PyValue::Dict(Vec::new())),
            (
                "data".into(),
                PyValue::List(vec![PyValue::Dict(vec![(
                    "oldestFirst".into(),
                    PyValue::Bool(false),
                )])]),
            ),
        ]);
        assert_eq!(
            body.py_repr(),
            "{'meta': {}, 'data': [{'oldestFirst': False}]}"
        );
    }
}
