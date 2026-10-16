//! The `agent_datastore` reads and writes of `data_store_routes.py`, issued
//! as SQLAlchemy issues them (the listing's `ORDER BY collection_time DESC`
//! leaves same-second ties to MySQL, so the statement is the ORM's, column
//! list included).

use std::collections::HashMap;

use sqlx::{MySql, QueryBuilder};

use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

use crate::schema::ArtifactRow;

/// The `agent_datastore` columns this crate reads.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "agent_datastore",
    columns: &[
        "id",
        "agent_id",
        "velociraptor_id",
        "artifact_name",
        "flow_id",
        "collection_time",
        "bucket_name",
        "object_key",
        "file_name",
        "content_type",
        "file_size",
        "file_hash",
        "uploaded_by",
        "notes",
        "status",
        "error_message",
    ],
}];

const COLUMNS: &str = "agent_datastore.id, agent_datastore.agent_id, \
    agent_datastore.velociraptor_id, agent_datastore.artifact_name, agent_datastore.flow_id, \
    agent_datastore.collection_time, agent_datastore.bucket_name, agent_datastore.object_key, \
    agent_datastore.file_name, agent_datastore.content_type, agent_datastore.file_size, \
    agent_datastore.file_hash, agent_datastore.uploaded_by, agent_datastore.notes, \
    agent_datastore.status, agent_datastore.error_message";

/// `select(AgentDataStore).where(agent_id == …)[.where(flow_id == …)]
/// .order_by(desc(collection_time))`.
pub async fn list_artifacts(
    db: &Db,
    agent_id: &str,
    flow_id: Option<&str>,
) -> Result<Vec<ArtifactRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {COLUMNS} \nFROM agent_datastore \nWHERE agent_datastore.agent_id = "
    ));
    qb.push_bind(agent_id);
    if let Some(flow) = flow_id {
        qb.push(" AND agent_datastore.flow_id = ").push_bind(flow);
    }
    qb.push(" ORDER BY agent_datastore.collection_time DESC");
    Ok(qb
        .build_query_as::<ArtifactRow>()
        .fetch_all(db.pool())
        .await?)
}

/// `select(AgentDataStore).where(id == …, agent_id == …)` → `.first()`.
pub async fn artifact(
    db: &Db,
    artifact_id: i64,
    agent_id: &str,
) -> Result<Option<ArtifactRow>, DbError> {
    let sql = format!(
        "SELECT {COLUMNS} \nFROM agent_datastore \nWHERE agent_datastore.id = ? AND \
         agent_datastore.agent_id = ?"
    );
    Ok(sqlx::query_as::<_, ArtifactRow>(&sql)
        .bind(artifact_id)
        .bind(agent_id)
        .fetch_optional(db.pool())
        .await?)
}

/// `selectinload(AgentDataStore.agent)`: each agent's `customer_code`.
pub async fn agent_customers(
    db: &Db,
    agent_ids: &[&str],
) -> Result<HashMap<String, Option<String>>, DbError> {
    if agent_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT agents.agent_id, agents.customer_code FROM agents WHERE agents.agent_id IN (",
    );
    let mut list = qb.separated(", ");
    for id in agent_ids {
        list.push_bind(*id);
    }
    qb.push(")");
    let rows: Vec<(String, Option<String>)> = qb.build_query_as().fetch_all(db.pool()).await?;
    Ok(rows.into_iter().collect())
}

/// `session.delete(artifact); session.commit()`.
pub async fn delete_artifact(db: &Db, artifact_id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM agent_datastore WHERE agent_datastore.id = ?")
        .bind(artifact_id)
        .execute(db.pool())
        .await?;
    Ok(())
}
