//! `app/connectors/portainer/services/` (`nodes.py`, `stack.py`; the stack
//! creation's template and flow are `copilot-integration-provisioning`'s, on
//! [`swarm_id`] and [`create_stack`]) and the stack-id helpers of
//! `utils/universal.py`, line by line: each Portainer call authenticates first, a missing connector row
//! surfaces as the `TypeError` of subscripting `None`, and the response
//! models' `ValidationError`s are the `ValueError` handler's 400.

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, getitem, int_of, iterate, py_eq};

use crate::client::{PortainerClient, Reply};
use crate::schema::{
    DELETE_STACK_RESPONSE, NODES_RESPONSE, STACK_ID_RESPONSE, STACK_RESPONSE, STACKS_RESPONSE,
};

const STACK_QUALNAME: &str = "app.connectors.portainer.schema.stack";

/// `StackStatus.ACTIVE`.
pub const ACTIVE: &str = "1";
/// `StackStatus.DOWN`.
pub const DOWN: &str = "2";

fn none_subscript() -> PyExc {
    PyExc::TypeError("'NoneType' object is not subscriptable".into())
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.into())
}

/// `response["data"]` of a helper's answer.
fn data(reply: Option<Reply>) -> PyResult<PyValue> {
    reply.map(|r| r.data).ok_or_else(none_subscript)
}

/// `Model(**response)` of a helper's answer.
fn star(model: &'static copilot_upstream::model::Model, reply: Option<Reply>) -> PyResult<PyValue> {
    let qualname = format!("{STACK_QUALNAME}.{}", model.name);
    construct_star(
        model,
        &qualname,
        &reply.map_or(PyValue::None, |r| r.to_py()),
    )
}

/// `get_endpoint_id()`: the id of the `local` or `primary` environment, as
/// Python formats it into a URL (`None` when there is neither).
pub async fn endpoint_id(client: &PortainerClient) -> PyResult<String> {
    let endpoints = data(client.get("/api/endpoints", Vec::new()).await?)?;
    for endpoint in iterate(&endpoints)? {
        for name in ["local", "primary"] {
            if py_eq(getitem(&endpoint, "Name")?, &s(name)) {
                return int_of(getitem(&endpoint, "Id")?);
            }
        }
    }
    Ok("None".into())
}

/// `get_node_details()`.
pub async fn node_details(client: &PortainerClient) -> PyResult<PyValue> {
    let id = endpoint_id(client).await?;
    let nodes = data(
        client
            .get(&format!("/api/endpoints/{id}/docker/nodes"), Vec::new())
            .await?,
    )?;
    construct(
        &NODES_RESPONSE,
        &kwargs(vec![
            ("nodes", nodes),
            ("success", PyValue::Bool(true)),
            ("message", s("Nodes fetched successfully")),
        ]),
    )
}

/// `get_swarm_id()`: `response["data"]["ID"]` of the endpoint's swarm.
pub async fn swarm_id(client: &PortainerClient) -> PyResult<PyValue> {
    let id = endpoint_id(client).await?;
    let swarm = data(
        client
            .get(&format!("/api/endpoints/{id}/docker/swarm"), Vec::new())
            .await?,
    )?;
    Ok(getitem(&swarm, "ID")?.clone())
}

/// The stack creation's request (`POST /api/stacks?type=1&method=string&
/// endpointId=…`, `send_post_request`), then `StackResponse(**response)`.
pub async fn create_stack(
    client: &PortainerClient,
    endpoint_id: &str,
    payload: PyValue,
) -> PyResult<PyValue> {
    let reply = client
        .post(
            &format!("/api/stacks?type=1&method=string&endpointId={endpoint_id}"),
            Some(payload),
        )
        .await?;
    star(&STACK_RESPONSE, reply)
}

/// `get_stacks()`.
pub async fn stacks(client: &PortainerClient) -> PyResult<PyValue> {
    let stacks = data(client.get("/api/stacks", Vec::new()).await?)?;
    construct(
        &STACKS_RESPONSE,
        &kwargs(vec![
            ("data", stacks),
            ("message", s("Stacks fetched successfully")),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

/// `get_stack_details(stack_id)`: the `StackResponse` dump.
pub async fn stack_details(client: &PortainerClient, stack_id: &str) -> PyResult<PyValue> {
    let id = endpoint_id(client).await?;
    let reply = client
        .get(
            &format!("/api/stacks/{stack_id}?endpointId={id}"),
            Vec::new(),
        )
        .await?;
    star(&STACK_RESPONSE, reply)
}

/// `start_wazuh_customer_stack` / `stop_wazuh_customer_stack`: nothing to
/// do when the stack is already there, the action when it is in the other
/// state, a 400 otherwise.
async fn toggle(
    client: &PortainerClient,
    stack_id: &str,
    done: &str,
    from: &str,
    action: &str,
) -> PyResult<PyValue> {
    let details = stack_details(client, stack_id).await?;
    let status = field(field(&details, "data"), "Status").py_str();
    if status == done {
        return Ok(details);
    }
    if status == from {
        let id = endpoint_id(client).await?;
        let reply = client
            .post(
                &format!("/api/stacks/{stack_id}/{action}?endpointId={id}"),
                None,
            )
            .await?;
        return star(&STACK_RESPONSE, reply);
    }
    Err(PyExc::http(
        400,
        format!("Unexpected stack status: {status}"),
    ))
}

/// `start_wazuh_customer_stack(stack_id)`.
pub async fn start_stack(client: &PortainerClient, stack_id: &str) -> PyResult<PyValue> {
    toggle(client, stack_id, ACTIVE, DOWN, "start").await
}

/// `stop_wazuh_customer_stack(stack_id)`.
pub async fn stop_stack(client: &PortainerClient, stack_id: &str) -> PyResult<PyValue> {
    toggle(client, stack_id, DOWN, ACTIVE, "stop").await
}

/// `delete_wazuh_customer_stack(stack_id)`: stopped first, then deleted.
pub async fn delete_stack(client: &PortainerClient, stack_id: &str) -> PyResult<PyValue> {
    let id = endpoint_id(client).await?;
    stop_stack(client, stack_id).await?;
    // `params={"endpointId": None}` sends no parameter.
    let params = if id == "None" {
        Vec::new()
    } else {
        vec![("endpointId".to_string(), id)]
    };
    let reply = client
        .delete(&format!("/api/stacks/{stack_id}"), params)
        .await?;
    star(&DELETE_STACK_RESPONSE, reply)
}

fn db_error(e: sqlx::Error) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `select(CustomersMeta).where(customer_name == name)` then
/// `scalar_one_or_none()`: `(id, customer_meta_portainer_stack_id)`.
async fn customer_meta(db: &Db, name: &str) -> PyResult<(i64, Option<i64>)> {
    let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT CAST(id AS SIGNED), CAST(customer_meta_portainer_stack_id AS SIGNED) \
         FROM customersmeta WHERE customer_name = ? LIMIT 2",
    )
    .bind(name)
    .fetch_all(db.pool())
    .await
    .map_err(db_error)?;
    match rows.as_slice() {
        [] => Err(PyExc::http(
            404,
            format!("Customer {name} not found in database"),
        )),
        [row] => Ok(*row),
        _ => Err(PyExc::Other(
            "MultipleResultsFound",
            "Multiple rows were found when one or none was required".into(),
        )),
    }
}

/// `GET /portainer/get-customer-stack-id`.
pub async fn customer_stack_id(db: &Db, name: &str) -> PyResult<PyValue> {
    let (_, stack_id) = customer_meta(db, name).await?;
    let stack_id = stack_id.filter(|id| *id != 0).ok_or_else(|| {
        PyExc::http(
            404,
            format!("No Portainer stack ID found for customer {name}"),
        )
    })?;
    construct(
        &STACK_ID_RESPONSE,
        &kwargs(vec![
            ("stack_id", PyValue::Int(stack_id.to_string())),
            ("success", PyValue::Bool(true)),
            ("message", s("Customer stack ID retrieved successfully.")),
        ]),
    )
}

/// `POST /portainer/update-customer-stack-id`.
pub async fn update_customer_stack_id(db: &Db, name: &str, stack_id: &str) -> PyResult<PyValue> {
    let (id, current) = customer_meta(db, name).await?;
    let value: i64 = stack_id.parse().map_err(|_| {
        PyExc::Other(
            "DataError",
            "Out of range value for column 'customer_meta_portainer_stack_id'".into(),
        )
    })?;
    // The ORM writes only an attribute that changed.
    if current != Some(value) {
        sqlx::query("UPDATE customersmeta SET customer_meta_portainer_stack_id = ? WHERE id = ?")
            .bind(value)
            .bind(id)
            .execute(db.pool())
            .await
            .map_err(db_error)?;
    }
    construct(
        &STACK_ID_RESPONSE,
        &kwargs(vec![
            ("stack_id", PyValue::Int(stack_id.to_string())),
            ("success", PyValue::Bool(true)),
            ("message", s("Customer stack ID updated successfully.")),
        ]),
    )
}
