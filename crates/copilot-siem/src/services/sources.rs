//! `app/siem/services/event_sources.py`: a customer's event sources (index
//! pattern, time field, the event table's columns).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult};
use serde_json::Value;

use crate::SiemState;
use crate::py::{db, dt, from_json, http, int, model, s, to_json};
use crate::schema::{EVENT_SOURCE, EventSourceCreate, EventSourceUpdate};
use crate::store::{self, EventSourceChange, EventSourceRow, NewEventSource};

/// `EventSourceResponse.from_orm(row)`.
pub fn event_source_dump(row: &EventSourceRow) -> PyResult<PyValue> {
    model(
        &EVENT_SOURCE,
        vec![
            ("id", int(i64::from(row.id))),
            ("customer_code", s(&row.customer_code)),
            ("name", s(&row.name)),
            ("index_pattern", s(&row.index_pattern)),
            ("event_type", s(&row.event_type)),
            ("time_field", s(&row.time_field)),
            ("enabled", PyValue::Bool(row.enabled)),
            (
                "displayed_columns",
                row.displayed_columns
                    .as_ref()
                    .map_or(PyValue::None, |c| from_json(&c.0)),
            ),
            ("created_at", dt(row.created_at)),
            ("updated_at", dt(row.updated_at)),
        ],
    )
}

/// `get_event_sources_by_customer(customer_code)`.
pub async fn list_of(st: &SiemState, code: &str) -> PyResult<Vec<EventSourceRow>> {
    store::event_sources_of(&st.ctx.db, code).await.map_err(db)
}

/// `get_event_source_by_id(id)`: 404 when unknown.
pub async fn get_by_id(st: &SiemState, id: i64) -> PyResult<EventSourceRow> {
    store::event_source(&st.ctx.db, id)
        .await
        .map_err(db)?
        .ok_or_else(|| http(404, "Event source not found"))
}

/// `create_event_source(data)`: a name is unique per customer (MySQL's
/// collation compares it), then the row.
pub async fn create(st: &SiemState, req: &EventSourceCreate) -> PyResult<EventSourceRow> {
    if store::event_source_named(&st.ctx.db, &req.customer_code, &req.name)
        .await
        .map_err(db)?
        .is_some()
    {
        return Err(http(
            400,
            format!(
                "Event source '{}' already exists for customer {}",
                req.name, req.customer_code
            ),
        ));
    }
    let columns = req.displayed_columns.as_ref().map_or(Value::Null, to_json);
    let id = store::insert_event_source(
        &st.ctx.db,
        &NewEventSource {
            customer_code: &req.customer_code,
            name: &req.name,
            index_pattern: &req.index_pattern,
            event_type: &req.event_type,
            time_field: &req.time_field,
            enabled: req.enabled,
            displayed_columns: &columns,
            created_at: copilot_core::time::now_utc_micros(),
            updated_at: copilot_core::time::now_utc_micros(),
        },
    )
    .await
    .map_err(db)?;
    get_by_id(st, id)
        .await
        .map_err(|_| PyExc::Other("InvalidRequestError", "row vanished".into()))
}

/// `update_event_source(id, data)`: every field the body sent (`null`
/// included), then `updated_at`.
pub async fn update(
    st: &SiemState,
    row: &EventSourceRow,
    req: &EventSourceUpdate,
) -> PyResult<EventSourceRow> {
    let mut changes = Vec::new();
    for (col, v) in [
        ("name", &req.name),
        ("index_pattern", &req.index_pattern),
        ("event_type", &req.event_type),
        ("time_field", &req.time_field),
    ] {
        if let Some(value) = v {
            changes.push(EventSourceChange::Text(col, value.clone()));
        }
    }
    if let Some(enabled) = req.enabled {
        changes.push(EventSourceChange::Enabled(enabled));
    }
    if let Some(columns) = &req.displayed_columns {
        changes.push(EventSourceChange::Columns(
            columns.as_ref().map_or(Value::Null, to_json),
        ));
    }
    store::update_event_source(
        &st.ctx.db,
        i64::from(row.id),
        &changes,
        copilot_core::time::now_utc_micros(),
    )
    .await
    .map_err(db)?;
    get_by_id(st, i64::from(row.id)).await
}

/// `delete_event_source(id)`: an enabled dashboard on it makes MySQL refuse
/// (the foreign key), a bare 500 as in Python.
pub async fn delete(st: &SiemState, id: i64) -> PyResult<()> {
    let row = get_by_id(st, id).await?;
    store::delete_event_source(&st.ctx.db, i64::from(row.id))
        .await
        .map_err(db)?;
    tracing::info!("Deleted event source {id}");
    Ok(())
}
