//! The indexer lookups behind the source dictionary
//! (`/api/incidents/db_operations`): `get_index_source`,
//! `get_available_indices_via_source`, `get_index_mappings_key_names`
//! (`app/connectors/wazuh_indexer/utils/universal.py`).

use copilot_auth::pyvalue::PyValue;
use copilot_wazuh::error::PyErr;
use regex::Regex;

use crate::IngestState;
use crate::es;
use crate::py::dict_get;
use crate::source::getitem;

fn exists_query(field: &str) -> PyValue {
    crate::py::to_py(&serde_json::json!({
        "size": 10,
        "query": {"bool": {"must": [{"exists": {"field": field}}]}},
    }))
}

/// `for hit in response["hits"]["hits"]` (Python's errors are a 500).
fn hits(response: &PyValue) -> Result<Vec<PyValue>, PyErr> {
    let h =
        getitem(getitem(response, "hits").map_err(PyErr::Other)?, "hits").map_err(PyErr::Other)?;
    match h {
        PyValue::List(items) => Ok(items.clone()),
        PyValue::Dict(d) => Ok(d.iter().map(|(k, _)| PyValue::Str(k.clone())).collect()),
        PyValue::Str(s) => Ok(s.chars().map(|c| PyValue::Str(c.to_string())).collect()),
        other => Err(PyErr::Other(format!(
            "'{}' object is not iterable",
            crate::py::type_name(other)
        ))),
    }
}

/// `"key" in hit["_source"]` and `hit["_source"][key]`.
fn source_get(hit: &PyValue, key: &str) -> Result<Option<PyValue>, PyErr> {
    let source = getitem(hit, "_source").map_err(PyErr::Other)?;
    match source {
        PyValue::Dict(d) => Ok(dict_get(d, key).cloned()),
        PyValue::Str(s) if !s.contains(key) => Ok(None),
        PyValue::List(items) if !items.iter().any(|i| i.as_str() == Some(key)) => Ok(None),
        PyValue::Str(_) => Err(PyErr::Other(
            "string indices must be integers, not 'str'".into(),
        )),
        PyValue::List(_) => Err(PyErr::Other(
            "list indices must be integers or slices, not str".into(),
        )),
        other => Err(PyErr::Other(format!(
            "argument of type '{}' is not iterable",
            crate::py::type_name(other)
        ))),
    }
}

/// `get_index_source(index_name)`: the `syslog_type` (or `integration`) of
/// one of the index's ten latest documents.
pub async fn index_source(st: &IngestState, index: &str) -> Result<PyValue, PyErr> {
    let client = es::sync_client(st).await?;
    let first = es::search(&client, index, &exists_query("syslog_type"), None, None).await?;
    for hit in hits(&first)? {
        if let Some(syslog_type) = source_get(&hit, "syslog_type")? {
            if syslog_type == PyValue::Str("integration".into()) {
                if let Some(integration) = source_get(&hit, "integration")? {
                    return Ok(integration);
                }
            }
            return Ok(syslog_type);
        }
    }
    let second = es::search(&client, index, &exists_query("integration"), None, None).await?;
    for hit in hits(&second)? {
        if let Some(integration) = source_get(&hit, "integration")? {
            return Ok(integration);
        }
    }
    Err(PyErr::http(
        404,
        format!("Source not found in index {index}"),
    ))
}

/// `get_available_indices_via_source(source)`: the indices whose name the
/// `source` regex finds (Wazuh's monitoring and statistics indices
/// excluded); `[]` on any failure.
pub async fn available_indices(st: &IngestState, source: &str) -> Result<Vec<String>, PyErr> {
    let client = es::sync_client(st).await?;
    let names = match es::get_alias(&client, "*").await {
        Ok(PyValue::Dict(d)) => d.into_iter().map(|(k, _)| k).collect::<Vec<_>>(),
        Ok(_) => return Ok(Vec::new()),
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "An error occurred: {e}");
            return Ok(Vec::new());
        }
    };
    let Ok(pattern) = Regex::new(&crate::sigma::matcher::python_pattern(source)) else {
        return Ok(Vec::new());
    };
    Ok(names
        .into_iter()
        .filter(|i| {
            pattern.is_match(i)
                && !i.contains("wazuh-monitoring")
                && !i.contains("wazuh-statistics")
        })
        .collect())
}

/// `get_index_mappings_key_names(index_name)`: the index's top-level field
/// names.
pub async fn mapping_keys(st: &IngestState, index: &str) -> Result<Vec<String>, PyErr> {
    let client = es::sync_client(st).await?;
    let mappings = es::get_mapping(&client, index).await?;
    let lookup = || -> Result<Vec<String>, String> {
        let props = getitem(
            getitem(getitem(&mappings, index)?, "mappings")?,
            "properties",
        )?;
        match props {
            PyValue::Dict(d) => Ok(d.iter().map(|(k, _)| k.clone()).collect()),
            other => Err(format!(
                "'{}' object has no attribute 'keys'",
                crate::py::type_name(other)
            )),
        }
    };
    lookup().map_err(PyErr::Other)
}
