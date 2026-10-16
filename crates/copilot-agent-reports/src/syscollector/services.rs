//! `app/agents/wazuh/syscollector/services/packages.py`.

use reqwest::Method;
use serde_json::{Value, json};

use copilot_agents::services::wazuh_err;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, kwargs};
use copilot_upstream::py::{self, PyExc, PyResult};
use copilot_wazuh::es::make_path;
use copilot_wazuh::indexer::services::async_client;
use copilot_wazuh::manager::client::{self as manager, Param};
use copilot_wazuh::pymodel::py as to_py;

use crate::AgentReportsState;
use crate::pyfmt::s;

use super::schema::{
    AGENT_PACKAGES_RESPONSE, INDEXER_PACKAGE_AGENT, INDEXER_PACKAGE_DETAIL, INDEXER_PACKAGE_ITEM,
    INDEXER_PACKAGES_RESPONSE, PACKAGE_ITEM,
};

/// `PACKAGES_INDEX_PATTERN`.
pub const PACKAGES_INDEX: &str = "wazuh-states-inventory-packages-*";

const MODULE: &str = "app.agents.wazuh.syscollector.schema.packages";

/// The manager query of `collect_agent_packages`.
#[derive(Debug, Clone, Default)]
pub struct PackagesQuery {
    /// `limit`.
    pub limit: i64,
    /// `offset`.
    pub offset: i64,
    /// `sort`.
    pub sort: Option<String>,
    /// `search`.
    pub search: Option<String>,
    /// `select` (joined with `,`).
    pub select: Option<Vec<String>>,
    /// `vendor`.
    pub vendor: Option<String>,
    /// `name`.
    pub name: Option<String>,
    /// `architecture`.
    pub architecture: Option<String>,
    /// `format`.
    pub format: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `q`.
    pub q: Option<String>,
}

impl PackagesQuery {
    /// The `params` dict, in Python's insertion order.
    pub fn params(&self) -> Vec<(String, Param)> {
        let mut p = vec![
            ("limit".to_string(), Param::Int(self.limit)),
            ("offset".to_string(), Param::Int(self.offset)),
            ("wait_for_complete".to_string(), Param::Bool(true)),
        ];
        let select = self.select.as_ref().map(|s| s.join(","));
        for (k, v) in [
            ("sort", &self.sort),
            ("search", &self.search),
            ("select", &select),
            ("vendor", &self.vendor),
            ("name", &self.name),
            ("architecture", &self.architecture),
            ("format", &self.format),
            ("version", &self.version),
            ("q", &self.q),
        ] {
            if let Some(v) = v {
                p.push((k.to_string(), Param::Str(v.clone())));
            }
        }
        p
    }
}

fn get_or(v: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(py::get(v, key)?.cloned().unwrap_or(default))
}

fn empty() -> PyValue {
    PyValue::Dict(Vec::new())
}

/// `collect_agent_packages(agent_id, …)`: the `AgentPackagesResponse`
/// dump, or what Python raises (nothing past the manager call is caught).
pub async fn agent_packages(
    st: &AgentReportsState,
    agent_id: &str,
    query: &PackagesQuery,
) -> PyResult<PyValue> {
    let params = query.params();
    let reply = manager::send_get(
        &st.wazuh,
        &format!("/syscollector/{agent_id}/packages"),
        Some(&params),
    )
    .await
    .map_err(wazuh_err)?;
    let reply = to_py(&reply);
    let success = py::get(&reply, "success")?
        .cloned()
        .unwrap_or(PyValue::None);
    if !success.truthy() {
        let message = get_or(
            &reply,
            "message",
            s("Failed to fetch packages from Wazuh Manager"),
        )?;
        return Err(PyExc::http(500, message.py_str()));
    }
    let data = get_or(&reply, "data", empty())?;
    let data = get_or(&data, "data", empty())?;
    let items = get_or(&data, "affected_items", PyValue::List(Vec::new()))?;
    let total = match py::get(&data, "total_affected_items")? {
        Some(v) => v.clone(),
        None => PyValue::Int(py::len(&items)?.to_string()),
    };
    let packages = py::iterate(&items)?
        .iter()
        .map(|item| model::construct_star(&PACKAGE_ITEM, &format!("{MODULE}.PackageItem"), item))
        .collect::<PyResult<Vec<_>>>()?;
    let n = packages.len();
    tracing::info!("Fetched {n} packages for agent {agent_id}");
    model::construct(
        &AGENT_PACKAGES_RESPONSE,
        &kwargs(vec![
            ("packages", PyValue::List(packages)),
            ("total_affected_items", total),
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!(
                    "Successfully fetched {n} packages for agent {agent_id}"
                )),
            ),
        ]),
    )
}

/// The indexer search's filters.
#[derive(Debug, Clone, Default)]
pub struct IndexerFilters {
    /// `package_name` (wildcard).
    pub package_name: Option<String>,
    /// `agent_name` (wildcard).
    pub agent_name: Option<String>,
    /// `agent_id` (term).
    pub agent_id: Option<String>,
    /// `architecture` (term).
    pub architecture: Option<String>,
    /// `package_type` (term).
    pub package_type: Option<String>,
    /// `vendor` (wildcard).
    pub vendor: Option<String>,
    /// `package_version` (wildcard).
    pub package_version: Option<String>,
    /// `size`.
    pub size: i64,
}

fn wildcard(field: &str, value: &str) -> Value {
    json!({"wildcard": {field: {"value": format!("*{value}*"), "case_insensitive": true}}})
}

/// The search body: Python's clauses, then (Rust) the caller's agents for a
/// scoped caller.
pub fn indexer_query(f: &IndexerFilters, owned: Option<&[String]>) -> Value {
    let mut must: Vec<Value> = Vec::new();
    if let Some(v) = &f.package_name {
        must.push(wildcard("package.name", v));
    }
    if let Some(v) = &f.agent_name {
        must.push(wildcard("agent.name", v));
    }
    if let Some(v) = &f.agent_id {
        must.push(json!({"term": {"agent.id": v}}));
    }
    if let Some(v) = &f.architecture {
        must.push(json!({"term": {"package.architecture": v}}));
    }
    if let Some(v) = &f.package_type {
        must.push(json!({"term": {"package.type": v}}));
    }
    if let Some(v) = &f.vendor {
        must.push(wildcard("package.vendor", v));
    }
    if let Some(v) = &f.package_version {
        must.push(wildcard("package.version", v));
    }
    if let Some(ids) = owned {
        must.push(json!({"terms": {"agent.id": ids}}));
    }
    if must.is_empty() {
        json!({"query": {"match_all": {}}})
    } else {
        json!({"query": {"bool": {"must": must}}})
    }
}

/// The `IndexerPackagesResponse` of a search answer.
fn indexer_response(response: &PyValue) -> PyResult<PyValue> {
    let hits = get_or(response, "hits", empty())?;
    let total = get_or(&hits, "total", empty())?;
    let total = match &total {
        PyValue::Dict(_) => get_or(&total, "value", PyValue::Int("0".into()))?,
        other => other.clone(),
    };
    let mut packages = Vec::new();
    for hit in py::iterate(&get_or(&hits, "hits", PyValue::List(Vec::new()))?)? {
        let source = get_or(&hit, "_source", empty())?;
        let index = get_or(&hit, "_index", PyValue::None)?;
        let id = get_or(&hit, "_id", PyValue::None)?;
        let nested = |key: &str, m, class: &str| -> PyResult<PyValue> {
            let present = get_or(&source, key, PyValue::None)?;
            if !present.truthy() {
                return Ok(PyValue::None);
            }
            let value = get_or(&source, key, empty())?;
            model::construct_star(m, &format!("{MODULE}.{class}"), &value)
        };
        let agent = nested("agent", &INDEXER_PACKAGE_AGENT, "IndexerPackageAgent")?;
        let package = nested("package", &INDEXER_PACKAGE_DETAIL, "IndexerPackageDetail")?;
        packages.push(model::construct(
            &INDEXER_PACKAGE_ITEM,
            &kwargs(vec![
                ("_index", index),
                ("_id", id),
                ("agent", agent),
                ("package", package),
            ]),
        )?);
    }
    let n = packages.len();
    tracing::info!(
        "Indexer search returned {n} packages (total matched: {})",
        total.py_str()
    );
    model::construct(
        &INDEXER_PACKAGES_RESPONSE,
        &kwargs(vec![
            ("packages", PyValue::List(packages)),
            ("total", total),
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!(
                    "Successfully retrieved {n} packages from the indexer"
                )),
            ),
        ]),
    )
}

/// The answer to a scoped caller who owns no agent (no indexer call).
pub fn nothing_owned() -> PyValue {
    crate::pyfmt::dict(vec![
        ("packages", PyValue::List(Vec::new())),
        ("total", PyValue::Int("0".into())),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("Successfully retrieved 0 packages from the indexer"),
        ),
    ])
}

/// `search_packages_in_indexer(...)`, limited (Rust) to `owned` agent ids
/// for a scoped caller.
pub async fn search_indexer(
    st: &AgentReportsState,
    f: &IndexerFilters,
    owned: Option<&[String]>,
) -> PyResult<PyValue> {
    let es = async_client(&st.wazuh).await.map_err(wazuh_err)?;
    let search = async {
        let path = format!("{}/_search", make_path(&[PACKAGES_INDEX]));
        let response = es
            .perform(
                Method::POST,
                &path,
                &[("size", f.size.to_string())],
                Some(&indexer_query(f, owned)),
            )
            .await
            .map_err(|e| PyExc::Other("Exception", e.to_string()))?;
        indexer_response(&to_py(&response))
    };
    search.await.map_err(|e| {
        tracing::error!("Error searching packages in Wazuh Indexer: {}", e.display());
        PyExc::http(
            500,
            format!(
                "Failed to search packages in Wazuh Indexer: {}",
                e.display()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn the_query_is_pythons_plus_the_callers_agents() {
        let f = IndexerFilters {
            package_name: Some("ssl".into()),
            agent_id: Some("001".into()),
            size: 5,
            ..Default::default()
        };
        assert_eq!(
            indexer_query(&f, None),
            json!({"query": {"bool": {"must": [
                {"wildcard": {"package.name": {"value": "*ssl*", "case_insensitive": true}}},
                {"term": {"agent.id": "001"}}
            ]}}})
        );
        assert_eq!(
            indexer_query(&IndexerFilters::default(), None),
            json!({"query": {"match_all": {}}})
        );
        assert_eq!(
            indexer_query(&IndexerFilters::default(), Some(&["001".to_string()])),
            json!({"query": {"bool": {"must": [{"terms": {"agent.id": ["001"]}}]}}})
        );
    }

    #[test]
    fn hits_become_items_by_alias() {
        let resp = loads(
            r#"{"hits": {"total": {"value": 9}, "hits": [
                {"_index": "i", "_id": "x", "_source": {"agent": {"id": "001", "groups": ["g"]},
                 "package": {"name": "openssl", "size": "12"}}},
                {"_index": "i", "_id": "y", "_source": {"agent": {}}}
            ]}}"#,
        )
        .expect("json");
        let out = indexer_response(&resp).expect("response");
        let text = copilot_upstream::json::pydantic_json(&out);
        assert_eq!(
            text,
            "{\"packages\":[{\"_index\":\"i\",\"_id\":\"x\",\"agent\":{\"id\":\"001\",\"name\":null,\
             \"version\":null},\"package\":{\"architecture\":null,\"description\":null,\"name\":\
             \"openssl\",\"size\":12,\"type\":null,\"vendor\":null,\"version\":null}},{\"_index\":\
             \"i\",\"_id\":\"y\",\"agent\":null,\"package\":null}],\"total\":9,\"success\":true,\
             \"message\":\"Successfully retrieved 2 packages from the indexer\"}"
        );
        let bad = loads(r#"{"hits": {"hits": [{"_source": {"agent": ["a"]}}]}}"#).expect("json");
        assert_eq!(
            indexer_response(&bad).expect_err("list").text(),
            "app.agents.wazuh.syscollector.schema.packages.IndexerPackageAgent() argument after \
             ** must be a mapping, not list"
        );
    }

    #[test]
    fn params_keep_pythons_order() {
        let q = PackagesQuery {
            limit: 5,
            offset: 0,
            select: Some(vec!["name".into(), "version".into()]),
            q: Some("name=openssl".into()),
            ..Default::default()
        };
        let keys: Vec<String> = q.params().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            ["limit", "offset", "wait_for_complete", "select", "q"]
        );
    }
}
