//! The elasticsearch-py 7.10.1 calls the SIEM services make, on
//! `copilot_wazuh::es` with the `AsyncElasticsearch` flavour (aiohttp's
//! headers): paths quoted by `_make_path`, the query parameters in the API's
//! own (alphabetical) order, `JSONSerializer.dumps`' compact bodies, the
//! answers as the Python values `json.loads` makes.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::es::{Es, EsError, Flavor, flag, make_path, require};
use copilot_wazuh::pymodel::py;
use reqwest::Method;

use crate::SiemState;

/// `create_wazuh_indexer_client_async("Wazuh-Indexer")`: its
/// `HTTPException(500, …)`, or the connector lookup's own failure.
pub async fn client(st: &SiemState) -> PyResult<Es> {
    Es::connect(&st.es, &st.ctx.connectors, Flavor::Async)
        .await
        .map_err(|e| match e {
            copilot_wazuh::es::ConnectError::Http(d) => PyExc::http(500, d),
            copilot_wazuh::es::ConnectError::Db(d) => PyExc::Other("OperationalError", d),
        })
}

async fn call(
    es: &Es,
    method: Method,
    path: &str,
    params: &[(&str, String)],
    body: Option<&PyValue>,
) -> Result<PyValue, EsError> {
    let payload = match body {
        None => None,
        Some(b) => Some(
            py_dumps(b, Dumps::HTTPX)
                .map_err(|e| EsError::Serialization(format!("Unable to serialize {}", e)))?
                .into_bytes(),
        ),
    };
    es.perform_raw(method, path, params, payload)
        .await
        .map(|v| py(&v))
}

/// `es.search(index=…, body=…)` with `size` / `scroll` keyword parameters
/// (sent as `?scroll=…&size=…`).
pub async fn search(
    es: &Es,
    index: &str,
    body: &PyValue,
    size: Option<i64>,
    scroll: Option<&str>,
) -> Result<PyValue, EsError> {
    let mut params = Vec::new();
    if let Some(s) = scroll {
        params.push(("scroll", s.to_string()));
    }
    if let Some(n) = size {
        params.push(("size", n.to_string()));
    }
    call(
        es,
        Method::POST,
        &make_path(&[index, "_search"]),
        &params,
        Some(body),
    )
    .await
}

/// `es.scroll(scroll_id=…, scroll=…)`.
pub async fn scroll(es: &Es, scroll_id: &str, scroll: &str) -> Result<PyValue, EsError> {
    let body = PyValue::Dict(vec![("scroll_id".into(), PyValue::Str(scroll_id.into()))]);
    call(
        es,
        Method::POST,
        "/_search/scroll",
        &[("scroll", scroll.to_string())],
        Some(&body),
    )
    .await
}

/// `es.clear_scroll(scroll_id=…)`.
pub async fn clear_scroll(es: &Es, scroll_id: &str) -> Result<PyValue, EsError> {
    let body = PyValue::Dict(vec![(
        "scroll_id".into(),
        PyValue::List(vec![PyValue::Str(scroll_id.into())]),
    )]);
    call(es, Method::DELETE, "/_search/scroll", &[], Some(&body)).await
}

/// `es.get(index=…, id=…)`.
pub async fn get(es: &Es, index: &str, id: &str) -> Result<PyValue, EsError> {
    require(&[index, id])?;
    call(es, Method::GET, &make_path(&[index, "_doc", id]), &[], None).await
}

/// `es.field_caps(index=…, fields="*", ignore_unavailable=True,
/// allow_no_indices=True)`.
pub async fn field_caps(es: &Es, index: &str) -> Result<PyValue, EsError> {
    call(
        es,
        Method::POST,
        &make_path(&[index, "_field_caps"]),
        &[
            ("allow_no_indices", flag(true)),
            ("fields", "*".to_string()),
            ("ignore_unavailable", flag(true)),
        ],
        None,
    )
    .await
}

/// An indexer exception as the Python value the services catch.
pub fn exc(e: EsError) -> PyExc {
    match e {
        EsError::Value(s) => PyExc::ValueError(s),
        EsError::Transport { class, .. } => PyExc::Other(class_name(class), e.to_string()),
        other => PyExc::Other("TransportError", other.to_string()),
    }
}

fn class_name(class: &'static str) -> &'static str {
    class
}
