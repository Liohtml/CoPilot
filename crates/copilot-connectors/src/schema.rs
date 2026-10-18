//! Response and request shapes of `app/connectors/schema.py`.

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_core::time::pydantic;
use copilot_db::connectors::ConnectorRow;
use copilot_web::validate::{Loc, StrRules, Validator};

/// `ConnectorHistoryResponse`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ConnectorHistoryOut {
    /// Row id.
    pub id: Option<i32>,
    /// The connector.
    pub connector_id: i32,
    /// When.
    #[serde(serialize_with = "pydantic::datetime")]
    pub change_timestamp: NaiveDateTime,
    /// What.
    pub change_description: String,
}

/// `ConnectorResponse`, in its field order (secrets included: the routes
/// that return it are admin-only, GHSA-c5pw-2h98-r798).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectorOut {
    /// Row id.
    pub id: Option<i32>,
    /// `Wazuh-Indexer`, `Graylog`, …
    pub connector_name: String,
    /// Kind.
    pub connector_type: String,
    /// Base URL.
    pub connector_url: String,
    /// Last change.
    #[serde(serialize_with = "pydantic::datetime")]
    pub connector_last_updated: NaiveDateTime,
    /// User name.
    pub connector_username: Option<String>,
    /// Password.
    pub connector_password: Option<String>,
    /// API key (a file path for Velociraptor).
    pub connector_api_key: Option<String>,
    /// Description.
    pub connector_description: Option<String>,
    /// Capability text.
    pub connector_supports: Option<String>,
    /// Configured.
    pub connector_configured: bool,
    /// Last verification succeeded.
    pub connector_verified: bool,
    /// Enabled.
    pub connector_enabled: bool,
    /// Accepts a host only.
    pub connector_accepts_host_only: bool,
    /// Accepts an API key.
    pub connector_accepts_api_key: bool,
    /// Accepts username/password.
    pub connector_accepts_username_password: bool,
    /// Accepts a file.
    pub connector_accepts_file: bool,
    /// Accepts extra data.
    pub connector_accepts_extra_data: bool,
    /// Extra data.
    pub connector_extra_data: Option<String>,
    /// `history_logs` (always loaded: `lazy="selectin"`).
    pub history_logs: Option<Vec<ConnectorHistoryOut>>,
}

impl ConnectorOut {
    /// `ConnectorResponse.from_orm(row)` with its history rows.
    pub fn from_row(row: ConnectorRow, history: Vec<ConnectorHistoryOut>) -> Self {
        Self {
            id: Some(row.id),
            connector_name: row.connector_name,
            connector_type: row.connector_type,
            connector_url: row.connector_url,
            connector_last_updated: row.connector_last_updated,
            connector_username: row.connector_username,
            connector_password: row.connector_password,
            connector_api_key: row.connector_api_key,
            connector_description: row.connector_description,
            connector_supports: row.connector_supports,
            connector_configured: row.connector_configured,
            connector_verified: row.connector_verified,
            connector_enabled: row.connector_enabled,
            connector_accepts_host_only: row.connector_accepts_host_only,
            connector_accepts_api_key: row.connector_accepts_api_key,
            connector_accepts_username_password: row.connector_accepts_username_password,
            connector_accepts_file: row.connector_accepts_file,
            connector_accepts_extra_data: row.connector_accepts_extra_data,
            connector_extra_data: row.connector_extra_data,
            history_logs: Some(history),
        }
    }
}

/// `ConnectorsListResponse`.
#[derive(Debug, Serialize)]
pub struct ConnectorsListResponse {
    /// Every connector.
    pub connectors: Vec<ConnectorOut>,
    /// Always true.
    pub success: bool,
    /// Fixed text.
    pub message: String,
}

/// `ConnectorListResponse` (one connector).
#[derive(Debug, Serialize)]
pub struct ConnectorListResponse {
    /// The connector.
    pub connector: ConnectorOut,
    /// Always true.
    pub success: bool,
    /// Fixed text.
    pub message: String,
}

/// `VerifyConnectorResponse` — also what each tool's verifier returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyConnectorResponse {
    /// The tool answered.
    #[serde(rename = "connectionSuccessful")]
    pub connection_successful: bool,
    /// What happened.
    pub message: String,
}

/// `UpdateConnector` (the `PUT /{id}` body). Every field is written: an
/// absent optional one clears its column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateConnector {
    /// Base URL (required).
    pub connector_url: String,
    /// User name.
    pub connector_username: Option<String>,
    /// Password.
    pub connector_password: Option<String>,
    /// API key.
    pub connector_api_key: Option<String>,
    /// Extra data.
    pub connector_extra_data: Option<String>,
}

impl UpdateConnector {
    /// Read the body with Pydantic's rules (`str` and `Optional[str] = None`).
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        Self {
            connector_url: v.req_str(obj, at, "connector_url", any),
            connector_username: v.opt_str(obj, at, "connector_username", any),
            connector_password: v.opt_str(obj, at, "connector_password", any),
            connector_api_key: v.opt_str(obj, at, "connector_api_key", any),
            connector_extra_data: v.opt_str(obj, at, "connector_extra_data", any),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::validate::body_loc;
    use serde_json::json;

    #[test]
    fn field_order_matches_connector_response() {
        let out = ConnectorOut {
            id: Some(1),
            connector_name: "Wazuh-Indexer".into(),
            connector_type: "4.4.1".into(),
            connector_url: "https://x:9200".into(),
            connector_last_updated: chrono::NaiveDate::from_ymd_opt(2026, 1, 2)
                .unwrap()
                .and_hms_micro_opt(3, 4, 5, 6)
                .unwrap(),
            connector_username: None,
            connector_password: None,
            connector_api_key: None,
            connector_description: None,
            connector_supports: None,
            connector_configured: true,
            connector_verified: false,
            connector_enabled: true,
            connector_accepts_host_only: false,
            connector_accepts_api_key: false,
            connector_accepts_username_password: true,
            connector_accepts_file: false,
            connector_accepts_extra_data: false,
            connector_extra_data: None,
            history_logs: Some(vec![]),
        };
        let v = serde_json::to_value(&out).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys[..5],
            [
                "id",
                "connector_name",
                "connector_type",
                "connector_url",
                "connector_last_updated"
            ]
        );
        assert_eq!(
            keys[10..13],
            [
                "connector_configured",
                "connector_verified",
                "connector_enabled"
            ]
        );
        assert_eq!(keys.last(), Some(&"history_logs"));
        assert_eq!(
            v["connector_last_updated"],
            json!("2026-01-02T03:04:05.000006")
        );
    }

    #[test]
    fn update_body_follows_pydantic() {
        let mut v = Validator::new();
        let body = json!({"connector_url": "https://x", "connector_password": null});
        let read = UpdateConnector::read(&mut v, body.as_object().unwrap(), &body_loc());
        assert!(!v.has_errors());
        assert_eq!(read.connector_password, None);
        let mut v = Validator::new();
        let body = json!({"connector_username": 3});
        UpdateConnector::read(&mut v, body.as_object().unwrap(), &body_loc());
        let kinds: Vec<_> = v.errors().iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, ["missing", "string_type"]);
    }
}
