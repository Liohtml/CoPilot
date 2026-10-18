//! What provisioning and rollback call — Graylog, UBA, the Wazuh manager —
//! behind traits, so the step order and the plan can be pinned with Python's
//! own fakes (`tests/test_uba_provisioning.py`, `tests/test_uba_rollback.py`).
//!
//! The real implementations are the shared clients: [`GraylogClient`]
//! (`send_get_request` … on the default `Graylog` connector, entity creation
//! wrapped for 7.x), [`UbaClient`] (`uba_request`) and the Wazuh manager's
//! `update_wazuh_rule_file` / `send_put_request`.

use async_trait::async_trait;
use copilot_auth::pyvalue::PyValue;
use copilot_graylog::client::{DEFAULT_CONNECTOR, EntityKind, GraylogClient, Reply};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::manager::client::{Param, PutKind, send_put};
use copilot_wazuh::manager::services::update_rule_file;

use crate::client::{Call, UbaClient, UbaResult};

/// `app/connectors/graylog/utils/universal.py`'s helpers.
#[async_trait]
pub trait GraylogOps: Send + Sync {
    /// `send_get_request(endpoint, params)`.
    async fn get(&self, endpoint: &str, params: &[(&str, String)]) -> PyResult<Reply>;
    /// `send_post_request(endpoint, data)`.
    async fn post(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Reply>;
    /// `send_put_request(endpoint, data)` (`None` without a connector).
    async fn put(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Option<Reply>>;
    /// `send_delete_request(endpoint)`.
    async fn delete(&self, endpoint: &str) -> PyResult<Reply>;
    /// `send_post_request_create_entity(endpoint="/api/streams", entity=…)`.
    async fn create_stream(&self, entity: PyValue) -> PyResult<Reply>;
}

#[async_trait]
impl GraylogOps for GraylogClient {
    async fn get(&self, endpoint: &str, params: &[(&str, String)]) -> PyResult<Reply> {
        GraylogClient::get(self, endpoint, params).await
    }

    async fn post(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Reply> {
        GraylogClient::post(self, endpoint, data).await
    }

    async fn put(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Option<Reply>> {
        GraylogClient::put(self, endpoint, data).await
    }

    async fn delete(&self, endpoint: &str) -> PyResult<Reply> {
        GraylogClient::delete(self, endpoint, &[]).await
    }

    async fn create_stream(&self, entity: PyValue) -> PyResult<Reply> {
        self.create_entity(DEFAULT_CONNECTOR, &EntityKind::Stream, entity, None)
            .await
    }
}

/// `uba_request`.
#[async_trait]
pub trait UbaOps: Send + Sync {
    /// One call; the decoded JSON body.
    async fn call(&self, call: Call) -> UbaResult<PyValue>;
}

#[async_trait]
impl UbaOps for UbaClient {
    async fn call(&self, call: Call) -> UbaResult<PyValue> {
        self.request(call).await
    }
}

/// The Wazuh manager calls of setup's optional last step.
#[async_trait]
pub trait WazuhOps: Send + Sync {
    /// `update_wazuh_rule_file(filename, content, overwrite=True)`.
    async fn upload_rules(&self, filename: &str, content: Vec<u8>) -> PyResult<()>;
    /// `send_put_request(endpoint="/manager/restart", data=None)`.
    async fn restart(&self) -> PyResult<()>;
}

fn from_wazuh(e: PyErr) -> PyExc {
    match e {
        PyErr::Http { status, detail } => PyExc::Http(status, detail),
        PyErr::Value(s) => PyExc::ValueError(s),
        PyErr::Other(s) => PyExc::Other("Exception", s),
    }
}

#[async_trait]
impl WazuhOps for WazuhState {
    async fn upload_rules(&self, filename: &str, content: Vec<u8>) -> PyResult<()> {
        // `str(False).lower()` and friends; `relative_dirname` is `None`.
        let params = vec![
            ("pretty".to_string(), Param::Str("false".into())),
            ("wait_for_complete".to_string(), Param::Str("false".into())),
            ("overwrite".to_string(), Param::Str("true".into())),
        ];
        update_rule_file(self, filename, content, params)
            .await
            .map(|_| ())
            .map_err(from_wazuh)
    }

    async fn restart(&self) -> PyResult<()> {
        send_put(self, "/manager/restart", None, None, PutKind::Json)
            .await
            .map(|_| ())
            .map_err(from_wazuh)
    }
}

/// The three upstreams of one setup or rollback.
#[derive(Clone, Copy)]
pub struct Ops<'a> {
    /// Graylog.
    pub graylog: &'a dyn GraylogOps,
    /// SOCFortress UBA.
    pub uba: &'a dyn UbaOps,
    /// The Wazuh manager.
    pub wazuh: &'a dyn WazuhOps,
}
