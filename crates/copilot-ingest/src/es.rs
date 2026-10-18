//! The elasticsearch-py 7.10.1 calls the ingest services make, on
//! `copilot_wazuh::es` (paths quoted by `_make_path`, the query parameters
//! in the API's own order, compact JSON bodies), with the answers as Python
//! values.
//!
//! `create_wazuh_indexer_client_async` (the services' `await es.…`) and
//! `create_wazuh_indexer_client` (`run_blocking(es.…)`) differ only in the
//! transport; both are [`copilot_wazuh::es::Es`].

use copilot_auth::pyvalue::PyValue;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::es::{Es, EsError, Flavor, make_path, require};
use reqwest::Method;

use crate::IngestState;
use copilot_upstream::json::{Dumps, py_dumps};

use crate::py::to_py;

/// `create_wazuh_indexer_client_async("Wazuh-Indexer")`.
pub async fn async_client(st: &IngestState) -> Result<Es, PyErr> {
    Ok(Es::connect(&st.es, &st.ctx.connectors, Flavor::Async).await?)
}

/// `create_wazuh_indexer_client("Wazuh-Indexer")`.
pub async fn sync_client(st: &IngestState) -> Result<Es, PyErr> {
    Ok(Es::connect(&st.es, &st.ctx.connectors, Flavor::Sync).await?)
}

async fn call(
    es: &Es,
    method: Method,
    path: &str,
    params: &[(&str, String)],
    body: Option<&PyValue>,
) -> Result<PyValue, EsError> {
    // `JSONSerializer.dumps`: `json.dumps(…, ensure_ascii=False,
    // separators=(",", ":"))`, floats in Python's `repr`.
    let payload = body.map(|b| {
        py_dumps(b, Dumps::HTTPX)
            .unwrap_or_else(|_| crate::py::dumps_compact_allow_nan(b))
            .into_bytes()
    });
    es.perform_raw(method, path, params, payload)
        .await
        .map(|v| to_py(&v))
}

/// `es.get(index=…, id=…)`.
pub async fn get(es: &Es, index: &str, id: &str) -> Result<PyValue, EsError> {
    require(&[index, id])?;
    call(es, Method::GET, &make_path(&[index, "_doc", id]), &[], None).await
}

/// `es.search(index=…, body=…, size=…, scroll=…, timeout=…)`: the
/// parameters go out in the API's order (`scroll`, `size`, `timeout`).
pub async fn search(
    es: &Es,
    index: &str,
    body: &PyValue,
    size: Option<i64>,
    timeout: Option<&str>,
) -> Result<PyValue, EsError> {
    let mut params = Vec::new();
    if let Some(n) = size {
        params.push(("size", n.to_string()));
    }
    if let Some(t) = timeout {
        params.push(("timeout", t.to_string()));
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

/// `es.update(index=…, id=…, body=…)`.
pub async fn update(es: &Es, index: &str, id: &str, body: &PyValue) -> Result<PyValue, EsError> {
    require(&[index, id])?;
    call(
        es,
        Method::POST,
        &make_path(&[index, "_update", id]),
        &[],
        Some(body),
    )
    .await
}

/// `es.indices.put_settings(index=…, body=…)`.
pub async fn put_settings(es: &Es, index: &str, body: &PyValue) -> Result<PyValue, EsError> {
    call(
        es,
        Method::PUT,
        &make_path(&[index, "_settings"]),
        &[],
        Some(body),
    )
    .await
}

/// `es.indices.get_alias(index)`.
pub async fn get_alias(es: &Es, index: &str) -> Result<PyValue, EsError> {
    call(es, Method::GET, &make_path(&[index, "_alias"]), &[], None).await
}

/// `es.indices.get_mapping(index=…)`.
pub async fn get_mapping(es: &Es, index: &str) -> Result<PyValue, EsError> {
    call(es, Method::GET, &make_path(&[index, "_mapping"]), &[], None).await
}

/// `{"index.blocks.write": value}`.
fn write_block(value: PyValue) -> PyValue {
    PyValue::Dict(vec![("index.blocks.write".into(), value)])
}

/// The write-back both alert stamps share (`add_alert_to_document`,
/// `add_copilot_alert_id`): update; on failure lift the index's write block,
/// update again and put the block back. `Ok(true)` when the document was
/// updated, `Ok(false)` when the second attempt failed too.
pub async fn update_lifting_write_block(
    es: &Es,
    index: &str,
    id: &str,
    body: &PyValue,
    what: &str,
) -> bool {
    match update(es, index, id, body).await {
        Ok(_) => true,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Failed to {what}: {e}");
            let retry = async {
                put_settings(es, index, &write_block(PyValue::None)).await?;
                update(es, index, id, body).await?;
                put_settings(es, index, &write_block(PyValue::Bool(true))).await?;
                Ok::<(), EsError>(())
            };
            match retry.await {
                Ok(()) => true,
                Err(e2) => {
                    tracing::error!(
                        target: "copilot::ingest",
                        "Failed to remove read-only block from index {index}: {e2}"
                    );
                    false
                }
            }
        }
    }
}
