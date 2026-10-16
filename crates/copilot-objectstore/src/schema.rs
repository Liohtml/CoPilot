//! `app/data_store/data_store_schema.py`: the response models of
//! `/api/agent_data_store`, in their field order.

use chrono::NaiveDateTime;
use serde::Serialize;

use copilot_core::time::pydantic;

/// `FileUploadResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct FileUploadResponse {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// `bucket_name`.
    pub bucket_name: String,
    /// `object_key`.
    pub object_key: String,
    /// `file_name`.
    pub file_name: String,
    /// `file_size`.
    pub file_size: i64,
    /// `file_hash`.
    pub file_hash: String,
    /// `content_type`.
    pub content_type: Option<String>,
}

/// An `agent_datastore` row (`AgentDataStore`).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ArtifactRow {
    /// `id`.
    pub id: i32,
    /// `agent_id`.
    pub agent_id: String,
    /// `velociraptor_id`.
    pub velociraptor_id: String,
    /// `artifact_name`.
    pub artifact_name: String,
    /// `flow_id`.
    pub flow_id: String,
    /// `collection_time`.
    pub collection_time: NaiveDateTime,
    /// `bucket_name`.
    pub bucket_name: String,
    /// `object_key`.
    pub object_key: String,
    /// `file_name`.
    pub file_name: String,
    /// `content_type`.
    pub content_type: String,
    /// `file_size`.
    pub file_size: i32,
    /// `file_hash`.
    pub file_hash: String,
    /// `uploaded_by`.
    pub uploaded_by: Option<i32>,
    /// `notes`.
    pub notes: Option<String>,
    /// `status`.
    pub status: String,
}

/// `AgentDataStoreData`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentDataStoreData {
    /// `id`.
    pub id: i32,
    /// `agent_id`.
    pub agent_id: String,
    /// `velociraptor_id`.
    pub velociraptor_id: String,
    /// `customer_code` (the agent's).
    pub customer_code: Option<String>,
    /// `artifact_name`.
    pub artifact_name: String,
    /// `flow_id`.
    pub flow_id: String,
    /// `bucket_name`.
    pub bucket_name: String,
    /// `object_key`.
    pub object_key: String,
    /// `file_name`.
    pub file_name: String,
    /// `content_type`.
    pub content_type: String,
    /// `file_size`.
    pub file_size: i32,
    /// `file_hash`.
    pub file_hash: String,
    /// `collection_time`.
    #[serde(serialize_with = "pydantic::datetime")]
    pub collection_time: NaiveDateTime,
    /// `uploaded_by`.
    pub uploaded_by: Option<i32>,
    /// `notes`.
    pub notes: Option<String>,
    /// `status`.
    pub status: String,
}

impl AgentDataStoreData {
    /// The row with its agent's customer.
    pub fn from_row(row: ArtifactRow, customer_code: Option<String>) -> Self {
        Self {
            id: row.id,
            agent_id: row.agent_id,
            velociraptor_id: row.velociraptor_id,
            customer_code,
            artifact_name: row.artifact_name,
            flow_id: row.flow_id,
            bucket_name: row.bucket_name,
            object_key: row.object_key,
            file_name: row.file_name,
            content_type: row.content_type,
            file_size: row.file_size,
            file_hash: row.file_hash,
            collection_time: row.collection_time,
            uploaded_by: row.uploaded_by,
            notes: row.notes,
            status: row.status,
        }
    }
}

/// `AgentDataStoreListResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentDataStoreListResponse {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// `data`.
    pub data: Vec<AgentDataStoreData>,
    /// `total`.
    pub total: usize,
}

/// `AgentDataStoreResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentDataStoreResponse {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// `data`.
    pub data: Option<AgentDataStoreData>,
}
