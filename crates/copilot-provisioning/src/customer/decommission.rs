//! Decommissioning a customer — port of
//! `app/customer_provisioning/services/decommission.py` (with the Wazuh
//! manager, Graylog and Grafana deletes of `services/wazuh_manager.py`,
//! `services/graylog.py` and `services/grafana.py`).
//!
//! The steps run in Python's order and fail where Python fails: the Wazuh
//! manager helpers never raise (an agent lookup that does not read is no
//! agents), a Graylog `DELETE` answered with an error is its 404, the Grafana
//! org id goes through `int()` (a `ValueError` is the 400), the organization
//! delete is retried once from org 1, and the worker / HAProxy calls are
//! `requests.post` (their answers are not looked at; a URL `requests`
//! refuses is a `ValueError`, any other transport failure a bare 500). The
//! answer is validated last, after the row is gone — an agent id that is not
//! a string is the `ValidationError`'s 400, as in Python.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_portainer::PortainerClient;
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::model::{Field, Model, Ty, construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, int_of};
use copilot_wazuh::WazuhState;
use copilot_wazuh::manager::client as manager;
use copilot_web::AppContext;
use http::Method;
use serde_json::Value;

use super::store::{self, MetaRow};

/// `DEFAULT_HTTP_TIMEOUT` (the worker and HAProxy calls).
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(60);
/// The three Wazuh groups of a customer (`{group}_{customer_code}`).
pub const WAZUH_GROUPS: &[&str] = &["Linux", "Windows", "Mac"];

/// The `requests` client of the worker and HAProxy calls.
pub type WorkerHttp = PyHttp;

/// `requests` with `timeout=60` and certificates verified (its default).
pub fn worker_http() -> Result<WorkerHttp, reqwest::Error> {
    PyHttp::new(WORKER_TIMEOUT, true)
}

/// What decommissioning needs.
#[derive(Clone)]
pub struct Tools {
    /// Database, connector rows.
    pub ctx: AppContext,
    /// The Wazuh manager.
    pub wazuh: WazuhState,
    /// Graylog.
    pub graylog: GraylogClient,
    /// Grafana.
    pub grafana: GrafanaClient,
    /// Portainer.
    pub portainer: PortainerClient,
    /// `requests` for the worker and HAProxy provisioning services.
    pub http: PyHttp,
}

impl axum::extract::FromRef<Tools> for AppContext {
    fn from_ref(t: &Tools) -> Self {
        t.ctx.clone()
    }
}

/// `DecommissionedData`.
pub static DECOMMISSIONED_DATA: Model = Model::new(
    "DecommissionedData",
    &[
        Field::req("agents_deleted", Ty::List(&Ty::Str)),
        Field::req("groups_deleted", Ty::List(&Ty::Str)),
        Field::req("stream_deleted", Ty::Str),
        Field::req("index_deleted", Ty::Str),
    ],
);

/// `DecommissionCustomerResponse`.
pub static DECOMMISSION_RESPONSE: Model = Model::new(
    "DecommissionCustomerResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("decomissioned_data", Ty::Model(&DECOMMISSIONED_DATA)),
        Field::def("manual_steps", Ty::List(&Ty::Str), || {
            PyValue::List(Vec::new())
        }),
    ],
);

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

/// A `serde_json` value as Python holds it.
fn py(v: &Value) -> PyValue {
    copilot_auth::pyvalue::loads(&v.to_string()).unwrap_or(PyValue::None)
}

/// `is_connector_verified(name)`.
async fn connector_verified(ctx: &AppContext, name: &str) -> PyResult<bool> {
    Ok(ctx
        .connectors
        .get(name)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .is_some_and(|r| r.connector_verified))
}

/// `get_connector_attribute(name, column)` for the two columns read here:
/// `(connector_url, connector_verified)`, `None` without a row.
async fn connector(ctx: &AppContext, name: &str) -> PyResult<Option<(String, bool)>> {
    Ok(ctx
        .connectors
        .get(name)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .map(|r| (r.connector_url, r.connector_verified)))
}

/// `[agent.get("id") for agent in response.get("data", {}).get("data", {})
/// .get("affected_items", [])]`, or `[]` when any of it raises.
fn agent_ids(response: &Value) -> Vec<PyValue> {
    let response = py(response);
    let step = |v: &PyValue, key: &str, default: PyValue| -> Option<PyValue> {
        match v {
            PyValue::Dict(_) => Some(v.get(key).cloned().unwrap_or(default)),
            _ => None,
        }
    };
    let empty = || PyValue::Dict(Vec::new());
    let items = step(&response, "data", empty())
        .and_then(|d| step(&d, "data", empty()))
        .and_then(|d| step(&d, "affected_items", PyValue::List(Vec::new())));
    let Some(items) = items else {
        return Vec::new();
    };
    let Ok(items) = copilot_upstream::py::iterate(&items) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for agent in items {
        match &agent {
            PyValue::Dict(_) => ids.push(agent.get("id").cloned().unwrap_or(PyValue::None)),
            _ => return Vec::new(),
        }
    }
    ids
}

/// `requests`' `params=` encoding of one value: `None` dropped, a list (or
/// a dict's keys) one pair per item, anything else `str()`.
fn param(name: &str, v: &PyValue, out: &mut Vec<(String, String)>) {
    let text = |v: &PyValue| match v {
        PyValue::Float(f) => copilot_auth::pyvalue::float_repr(*f),
        other => other.py_str(),
    };
    match v {
        PyValue::None => {}
        PyValue::Str(s) => out.push((name.into(), s.clone())),
        PyValue::List(items) => {
            for item in items {
                if !matches!(item, PyValue::None) {
                    out.push((name.into(), text(item)));
                }
            }
        }
        PyValue::Dict(items) => {
            for (k, _) in items {
                out.push((name.into(), k.clone()));
            }
        }
        other => out.push((name.into(), text(other))),
    }
}

/// `gather_wazuh_agents(code)` then `delete_wazuh_agents(ids)`.
async fn delete_agents(st: &WazuhState, code: &str) -> PyResult<Vec<PyValue>> {
    let mut ids = Vec::new();
    for group in WAZUH_GROUPS {
        let params = [(
            "group".to_string(),
            manager::Param::Str(format!("{group}_{code}")),
        )];
        let response = manager::send_get(st, "/agents", Some(&params))
            .await
            .map_err(|e| PyExc::Other("Exception", format!("{e:?}")))?;
        ids.extend(agent_ids(&response));
    }
    let mut deleted = Vec::new();
    for id in ids {
        let mut params = vec![("older_than".to_string(), "0s".to_string())];
        param("agents_list", &id, &mut params);
        params.push(("status".into(), "all".into()));
        let params = strs(params);
        manager::send_delete(st, "/agents", Some(&params))
            .await
            .map_err(|e| PyExc::Other("Exception", format!("{e:?}")))?;
        deleted.push(id);
    }
    Ok(deleted)
}

/// Query parameters that are all strings, as the manager client takes them.
fn strs(params: Vec<(String, String)>) -> Vec<(String, manager::Param)> {
    params
        .into_iter()
        .map(|(k, v)| (k, manager::Param::Str(v)))
        .collect()
}

/// `delete_wazuh_groups(code)`: the three group codes.
async fn delete_groups(st: &WazuhState, code: &str) -> PyResult<Vec<PyValue>> {
    let mut deleted = Vec::new();
    for group in WAZUH_GROUPS {
        let group_code = format!("{group}_{code}");
        let params = [(
            "groups_list".to_string(),
            manager::Param::Str(group_code.clone()),
        )];
        manager::send_delete(st, "/groups", Some(&params))
            .await
            .map_err(|e| PyExc::Other("Exception", format!("{e:?}")))?;
        deleted.push(PyValue::Str(group_code));
    }
    Ok(deleted)
}

/// `delete_grafana_organization(int(org_id))`: from org 1 again when the
/// first delete raised.
async fn delete_organization(grafana: &GrafanaClient, raw: &str) -> PyResult<()> {
    let org = int_of(&PyValue::Str(raw.to_string()))?;
    let api = grafana.create(copilot_grafana::client::CONNECTOR).await?;
    let path = format!("/orgs/{org}");
    if grafana
        .call(&api, Method::DELETE, &path, None, Vec::new())
        .await
        .is_err()
    {
        grafana.switch_organization(&api, "1").await?;
        grafana
            .call(&api, Method::DELETE, &path, None, Vec::new())
            .await?;
    }
    Ok(())
}

/// `requests.post(url, json=body, timeout=60)`: the status, or the
/// exception (a URL `requests` refuses is a `ValueError`).
async fn post(http: &PyHttp, url: String, body: PyValue) -> PyResult<u16> {
    let resp = http
        .send(PyRequest::new(Method::POST, url).json(Some(body)))
        .await
        .map_err(|e| match e {
            PyExc::Other("MissingSchema" | "InvalidURL" | "InvalidSchema", m) => {
                PyExc::ValueError(m)
            }
            other => other,
        })?;
    Ok(resp.status())
}

fn worker_body(meta: &MetaRow, portainer: Option<bool>) -> PyValue {
    kwargs(vec![
        ("customer_name", s(&meta.customer_name)),
        ("customer_code", s(&meta.customer_code)),
        (
            "portainer_deployment",
            portainer.map_or(PyValue::None, PyValue::Bool),
        ),
    ])
}

/// `decommission_wazuh_worker(...)` (its answer is not used).
async fn decommission_worker(t: &Tools, meta: &MetaRow) -> PyResult<()> {
    if !connector_verified(&t.ctx, "Portainer").await? {
        let row = connector(&t.ctx, "Wazuh Worker Provisioning").await?;
        if row.as_ref().is_some_and(|(_, verified)| !verified) {
            return Ok(());
        }
        let endpoint = row.map_or_else(|| "None".to_string(), |(url, _)| url);
        post(
            &t.http,
            format!("{endpoint}/provision_worker/decommission"),
            worker_body(meta, Some(false)),
        )
        .await?;
        return Ok(());
    }
    // The stack first (`get_customer_portainer_stack_id`), then the nodes.
    let found = store::meta_by_name(&t.ctx.db, &meta.customer_name)
        .await?
        .ok_or_else(|| {
            PyExc::http(
                404,
                format!("Customer {} not found in database", meta.customer_name),
            )
        })?;
    let stack_id = found
        .customer_meta_portainer_stack_id
        .filter(|id| *id != 0)
        .ok_or_else(|| {
            PyExc::http(
                404,
                format!(
                    "No Portainer stack ID found for customer {}",
                    meta.customer_name
                ),
            )
        })?;
    copilot_portainer::services::delete_stack(&t.portainer, &stack_id.to_string()).await?;
    if store::meta_by_name(&t.ctx.db, &meta.customer_name)
        .await?
        .is_none()
    {
        return Err(PyExc::http(
            404,
            format!("Customer {} not found in database", meta.customer_name),
        ));
    }
    store::clear_stack_id(&t.ctx.db, &meta.customer_name).await?;
    let nodes = copilot_portainer::services::node_details(&t.portainer).await?;
    let ips: Vec<String> = match field(&nodes, "nodes") {
        PyValue::List(items) => items
            .iter()
            .map(|n| field(field(n, "Status"), "Addr").py_str())
            .collect(),
        _ => Vec::new(),
    };
    for ip in ips {
        let status = post(
            &t.http,
            format!("http://{ip}:5003/provision_worker/decommission"),
            worker_body(meta, Some(true)),
        )
        .await?;
        if status != 200 {
            break;
        }
    }
    Ok(())
}

/// `decommission_haproxy(...)` (its answer is not used).
async fn decommission_haproxy(t: &Tools, meta: &MetaRow) -> PyResult<()> {
    let row = connector(&t.ctx, "HAProxy Provisioning").await?;
    if row.as_ref().is_some_and(|(_, verified)| !verified) {
        return Ok(());
    }
    let endpoint = row.map_or_else(|| "None".to_string(), |(url, _)| url);
    post(
        &t.http,
        format!("{endpoint}/provision_worker/haproxy/decommission"),
        worker_body(meta, None),
    )
    .await?;
    Ok(())
}

/// `decomission_wazuh_customer(meta)`: the response dump.
pub async fn decommission(t: &Tools, meta: &MetaRow) -> PyResult<PyValue> {
    let portainer = connector_verified(&t.ctx, "Portainer").await?;
    let agents = delete_agents(&t.wazuh, &meta.customer_code).await?;
    let groups = delete_groups(&t.wazuh, &meta.customer_code).await?;
    t.graylog
        .delete(
            &format!("/api/streams/{}", meta.customer_meta_graylog_stream),
            &[],
        )
        .await?;
    t.graylog
        .delete(
            &format!(
                "/api/system/indices/index_sets/{}",
                meta.customer_meta_graylog_index
            ),
            &[],
        )
        .await?;
    delete_organization(&t.grafana, &meta.customer_meta_grafana_org_id).await?;
    decommission_worker(t, meta).await?;
    decommission_haproxy(t, meta).await?;
    store::delete_meta(&t.ctx.db, meta.id).await?;
    let mut manual = Vec::new();
    if portainer {
        let stack = format!("wazuh-worker-{}", meta.customer_code.replace(' ', "_")).to_lowercase();
        manual.push(PyValue::Str(format!(
            "Portainer does not allow CoPilot to fully remove the associated stack through the \
             API. Please manually delete the stack '{stack}' from Portainer -> Stacks before \
             recreating or reprovisioning the customer, reusing the customer code, or \
             provisioning another customer on the same Wazuh ports."
        )));
    }
    construct(
        &DECOMMISSION_RESPONSE,
        &kwargs(vec![
            (
                "message",
                PyValue::Str(format!(
                    "Customer {} decomissioned successfully.",
                    meta.customer_name
                )),
            ),
            ("success", PyValue::Bool(true)),
            ("manual_steps", PyValue::List(manual)),
            (
                "decomissioned_data",
                kwargs(vec![
                    ("agents_deleted", PyValue::List(agents)),
                    ("groups_deleted", PyValue::List(groups)),
                    ("stream_deleted", s(&meta.customer_meta_graylog_stream)),
                    ("index_deleted", s(&meta.customer_meta_graylog_index)),
                ]),
            ),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn agent_lookups_fail_soft() {
        let ids = |v: Value| agent_ids(&v);
        assert_eq!(
            ids(json!({"data": {"data": {"affected_items": [{"id": "001"}, {"name": "x"}]}}})),
            [PyValue::Str("001".into()), PyValue::None]
        );
        assert!(ids(json!({"success": false})).is_empty());
        assert!(ids(json!({"data": [1]})).is_empty());
        assert!(ids(json!({"data": {"data": {"affected_items": ["a"]}}})).is_empty());
        assert!(ids(json!({"data": {"data": {"affected_items": null}}})).is_empty());
        let mut out = Vec::new();
        param("agents_list", &PyValue::None, &mut out);
        param("agents_list", &PyValue::Int("7".into()), &mut out);
        assert_eq!(out, [("agents_list".to_string(), "7".to_string())]);
    }
}
