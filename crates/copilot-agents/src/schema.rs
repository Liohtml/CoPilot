//! `app/agents/schema/agents.py`, `app/agents/wazuh/schema/agents.py` and
//! `app/agents/velociraptor/schema/agents.py`.
//!
//! The responses that carry `agents` rows serialize the SQLModel `Agents`
//! table. Python writes such a row's fields in the order SQLAlchemy filled
//! the instance's `__dict__`, which varies between processes; here they come
//! in the model's declaration order (a §4 row of the migration doc).
//!
//! The models Python builds from Wazuh's and Velociraptor's answers are
//! `copilot_upstream::model` statics: their `ValidationError` texts end up
//! in messages and in the `ValueError` handler's 400s.

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::FromRow;

use copilot_auth::pyvalue::PyValue;
use copilot_core::time::pydantic;
use copilot_upstream::model::{Field, Model, Ty};

/// One `agents` row (`Agents`), in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct AgentRecord {
    /// Primary key.
    pub id: i32,
    /// Wazuh agent id (`000` is the manager).
    pub agent_id: String,
    /// IP address.
    pub ip_address: String,
    /// Operating system.
    pub os: String,
    /// Hostname.
    pub hostname: String,
    /// Wazuh group (`label`).
    pub label: String,
    /// Critical asset flag.
    pub critical_asset: bool,
    /// Last keep-alive seen by Wazuh (naive UTC).
    #[serde(serialize_with = "pydantic::datetime")]
    pub wazuh_last_seen: NaiveDateTime,
    /// Velociraptor client id.
    pub velociraptor_id: Option<String>,
    /// Last check-in seen by Velociraptor.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub velociraptor_last_seen: Option<NaiveDateTime>,
    /// Wazuh agent version.
    pub wazuh_agent_version: String,
    /// Wazuh status.
    pub wazuh_agent_status: String,
    /// Velociraptor client version.
    pub velociraptor_agent_version: Option<String>,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Quarantined by Velociraptor.
    pub quarantined: bool,
    /// Velociraptor org.
    pub velociraptor_org: Option<String>,
    /// Velociraptor id entered by hand (#1195).
    pub velociraptor_id_pinned: bool,
}

/// `AgentsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentsResponse {
    /// Rows.
    pub agents: Vec<AgentRecord>,
    /// Outcome.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `AgentModifyResponse` (and `AgentWazuhUpgradeResponse`).
#[derive(Debug, Clone, Serialize)]
pub struct AgentModifyResponse {
    /// Outcome.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `SyncedAgentsResponse`.
pub type SyncedAgentsResponse = AgentModifyResponse;

/// `BulkDeleteAgentResult`.
#[derive(Debug, Clone, Serialize)]
pub struct BulkDeleteAgentResult {
    /// The agent.
    pub agent_id: String,
    /// Outcome.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `BulkDeleteAgentsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct BulkDeleteAgentsResponse {
    /// No failure.
    pub success: bool,
    /// Summary.
    pub message: String,
    /// Agents asked for (or matched).
    pub total_requested: usize,
    /// Deleted.
    pub successful_deletions: usize,
    /// Not deleted.
    pub failed_deletions: usize,
    /// One per agent.
    pub results: Vec<BulkDeleteAgentResult>,
}

/// `OutdatedWazuhAgentsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct OutdatedWazuhAgentsResponse {
    /// Agents whose version differs from the manager's.
    pub outdated_wazuh_agents: Vec<AgentRecord>,
    /// Outcome.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `OutdatedVelociraptorAgentsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct OutdatedVelociraptorAgentsResponse {
    /// Agents whose client version differs from the server's.
    pub outdated_velociraptor_agents: Vec<AgentRecord>,
    /// Outcome.
    pub success: bool,
    /// Message.
    pub message: String,
}

// --- Pydantic models over upstream data --------------------------------------

/// `WazuhAgent`, built by field name (`populate_by_name`), so errors name
/// the fields.
pub static WAZUH_AGENT: Model = Model::new(
    "WazuhAgent",
    &[
        Field::req("agent_id", Ty::Str),
        Field::req("agent_name", Ty::Str),
        Field::req("agent_ip", Ty::Str),
        Field::req("agent_os", Ty::Str),
        Field::req("agent_label", Ty::Str),
        Field::req("agent_last_seen", Ty::Str),
        Field::req("wazuh_agent_version", Ty::Str),
        Field::opt("wazuh_agent_status", Ty::Nullable(&Ty::Str)),
    ],
);

/// `WazuhAgentVulnerabilities`.
pub static WAZUH_AGENT_VULNERABILITIES: Model = Model::new(
    "WazuhAgentVulnerabilities",
    &[
        Field::opt("severity", Ty::Nullable(&Ty::Str)),
        Field::opt("version", Ty::Nullable(&Ty::Str)),
        Field::opt("type", Ty::Nullable(&Ty::Str)),
        Field::opt("name", Ty::Nullable(&Ty::Str)),
        Field::opt("external_references", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("detection_time", Ty::Nullable(&Ty::Str)),
        Field::opt("cvss3_score", Ty::Nullable(&Ty::Float)),
        Field::opt("published", Ty::Nullable(&Ty::Str)),
        Field::opt("architecture", Ty::Nullable(&Ty::Str)),
        Field::opt("cve", Ty::Nullable(&Ty::Str)),
        Field::opt("status", Ty::Nullable(&Ty::Str)),
        Field::opt("title", Ty::Nullable(&Ty::Str)),
    ],
);

fn int_zero() -> PyValue {
    PyValue::Int("0".into())
}

/// `WazuhAgentScaResults` (`pass` is `pass_count`'s alias).
pub static WAZUH_AGENT_SCA_RESULTS: Model = Model::new(
    "WazuhAgentScaResults",
    &[
        Field::req("policy_id", Ty::Str),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::def("fail", Ty::Int, int_zero),
        Field::opt("start_scan", Ty::Nullable(&Ty::Str)),
        Field::opt("references", Ty::Nullable(&Ty::Str)),
        Field::opt("name", Ty::Nullable(&Ty::Str)),
        Field::def("pass_count", Ty::Int, int_zero).alias("pass"),
        Field::def("score", Ty::Int, int_zero),
        Field::opt("end_scan", Ty::Nullable(&Ty::Str)),
        Field::def("total_checks", Ty::Int, int_zero),
        Field::opt("hash_file", Ty::Nullable(&Ty::Str)),
        Field::def("invalid", Ty::Int, int_zero),
    ],
);

/// `Compliance`.
pub static COMPLIANCE: Model = Model::new(
    "Compliance",
    &[Field::req("value", Ty::Str), Field::req("key", Ty::Str)],
);

/// `Rules`.
pub static RULES: Model = Model::new(
    "Rules",
    &[Field::req("type", Ty::Str), Field::req("rule", Ty::Str)],
);

fn description_not_found() -> PyValue {
    PyValue::Str("Description not found".into())
}
fn reason_not_found() -> PyValue {
    PyValue::Str("Reason not found".into())
}
fn command_not_found() -> PyValue {
    PyValue::Str("Command not found".into())
}

/// `WazuhAgentScaPolicyResults`.
pub static WAZUH_AGENT_SCA_POLICY_RESULTS: Model = Model::new(
    "WazuhAgentScaPolicyResults",
    &[
        Field::def("description", Ty::Nullable(&Ty::Str), description_not_found),
        Field::req("id", Ty::Int),
        Field::def("reason", Ty::Nullable(&Ty::Str), reason_not_found),
        Field::def("command", Ty::Nullable(&Ty::Str), command_not_found),
        Field::req("rationale", Ty::Str),
        Field::req("condition", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("result", Ty::Str),
        Field::req("policy_id", Ty::Str),
        Field::req("remediation", Ty::Str),
        Field::req("compliance", Ty::List(&Ty::Model(&COMPLIANCE))),
        Field::req("rules", Ty::List(&Ty::Model(&RULES))),
    ],
);

/// `VelociraptorAgentInformation`.
pub static VELOCIRAPTOR_AGENT_INFORMATION: Model = Model::new(
    "VelociraptorAgentInformation",
    &[
        Field::req("version", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("build_time", Ty::Str),
        Field::req("build_url", Ty::Str),
    ],
);

/// `VelociraptorOSInfo`.
pub static VELOCIRAPTOR_OS_INFO: Model = Model::new(
    "VelociraptorOSInfo",
    &[
        Field::req("system", Ty::Str),
        Field::req("hostname", Ty::Str),
        Field::req("release", Ty::Str),
        Field::req("machine", Ty::Str),
        Field::req("fqdn", Ty::Str),
        Field::req("mac_addresses", Ty::List(&Ty::Str)),
    ],
);

/// `VelociraptorClient`.
pub static VELOCIRAPTOR_CLIENT: Model = Model::new(
    "VelociraptorClient",
    &[
        Field::req("client_id", Ty::Str),
        Field::req(
            "agent_information",
            Ty::Model(&VELOCIRAPTOR_AGENT_INFORMATION),
        ),
        Field::req("os_info", Ty::Model(&VELOCIRAPTOR_OS_INFO)),
        Field::req("first_seen_at", Ty::Int),
        Field::req("last_seen_at", Ty::Int),
        Field::req("last_ip", Ty::Str),
        Field::req("last_interrogate_flow_id", Ty::Str),
        Field::req("last_interrogate_artifact_name", Ty::Str),
        Field::req("labels", Ty::List(&Ty::Str)),
        Field::req("last_hunt_timestamp", Ty::Int),
        Field::req("last_event_table_version", Ty::Int),
        Field::req("last_label_timestamp", Ty::Int),
    ],
);

/// `VelociraptorClients`.
pub static VELOCIRAPTOR_CLIENTS: Model = Model::new(
    "VelociraptorClients",
    &[Field::req(
        "clients",
        Ty::List(&Ty::Model(&VELOCIRAPTOR_CLIENT)),
    )],
);

/// `Organization` (its `_client_config` is not read).
pub static ORGANIZATION: Model = Model::new(
    "Organization",
    &[Field::req("Name", Ty::Str), Field::req("OrgId", Ty::Str)],
);

/// `VelociraptorOrganizations`.
pub static VELOCIRAPTOR_ORGANIZATIONS: Model = Model::new(
    "VelociraptorOrganizations",
    &[Field::req(
        "organizations",
        Ty::List(&Ty::Model(&ORGANIZATION)),
    )],
);
