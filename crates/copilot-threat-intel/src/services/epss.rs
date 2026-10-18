//! `app/threat_intel/services/epss.py:collect_epss_score`: one CVE's EPSS
//! score from api.first.org.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, construct_star, kwargs};
use copilot_upstream::py::{PyExc, PyResult, get, iterate, py_eq};
use http::Method;

use crate::ThreatIntelState;
use crate::httpx::{self, HttpxError, Request};
use crate::schema::{EPSS_DATA, EPSS_RESPONSE};

/// `collect_epss_score(request)`: `GET {EPSS}?cve=…` with
/// `content-type: application/json`, httpx's default timeout; an answer
/// whose `status-code` is not 200 is the 500 `Failed to retrieve EPSS
/// score`. Nothing else is caught.
pub async fn collect_epss_score(st: &ThreatIntelState, cve: &str) -> PyResult<PyValue> {
    tracing::info!("Invoking EPSS for {cve}");
    let response = httpx::send(
        Request::new(Method::GET, st.urls.epss.clone())
            .header("content-type", Some("application/json"))
            .params(vec![("cve".into(), cve.to_string())]),
    )
    .await
    .map_err(HttpxError::into_py)?;
    let data = response.json()?;
    let status = get(&data, "status-code")?;
    if !status.is_some_and(|v| py_eq(v, &PyValue::Int("200".into()))) {
        return Err(PyExc::http(500, "Failed to retrieve EPSS score"));
    }
    let items = get(&data, "data")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    let mut rows = Vec::new();
    for item in iterate(&items)? {
        rows.push(construct_star(
            &EPSS_DATA,
            "app.threat_intel.schema.epss.EpssData",
            &item,
        )?);
    }
    construct(
        &EPSS_RESPONSE,
        &kwargs(vec![
            ("data", PyValue::List(rows)),
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("EPSS score retrieved successfully".into()),
            ),
        ]),
    )
}
