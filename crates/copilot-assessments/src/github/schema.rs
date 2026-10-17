//! `app/integrations/github_audit/schema/github_audit.py`: the request bodies
//! as FastAPI validates them, and the result models the audit builds (whose
//! `ValidationError` texts end up in a failed audit's message).
//!
//! Request bodies go through the shared lax engine one field at a time
//! (`copilot_uba::params`, pinned by `copilot_upstream`'s model vectors and
//! this crate's own), so a body fails with Pydantic's errors in declaration
//! order. Result models are [`copilot_upstream::model::Model`]s built from
//! the values the service hands them; fields Python fills with model
//! *instances* (`checks`, `summary`) are `Any` here, as Pydantic does not
//! validate an instance again.

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use copilot_auth::pyvalue::PyValue;
use copilot_uba::params::{
    NumSpec, StrSpec, b_bool_or, b_float_or, b_opt_bool, b_opt_float, b_opt_str, b_opt_str_list,
    b_req_str, check_int, field,
};
use copilot_upstream::model::{EnumTy, Field, Invalid, Loc as ModelLoc, Model, Ty, validate_ty};
use copilot_web::validate::{Loc, LocPart, Validator};
use serde_json::{Map, Value};

// --- the result models ------------------------------------------------------------------

/// `AuditStatus`.
pub static AUDIT_STATUS: EnumTy = EnumTy {
    name: "AuditStatus",
    values: &["pass", "fail", "warning", "not_applicable"],
};

/// `SeverityLevel`.
pub static SEVERITY: EnumTy = EnumTy {
    name: "SeverityLevel",
    values: &["critical", "high", "medium", "low", "info"],
};

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

fn no() -> PyValue {
    PyValue::Bool(false)
}

/// `AuditCheck`.
pub static AUDIT_CHECK: Model = Model::new(
    "AuditCheck",
    &[
        Field::req("check_id", Ty::Str),
        Field::req("check_name", Ty::Str),
        Field::req("category", Ty::Str),
        Field::req("status", Ty::Enum(&AUDIT_STATUS)),
        Field::req("severity", Ty::Enum(&SEVERITY)),
        Field::req("description", Ty::Str),
        Field::opt("recommendation", Ty::Nullable(&Ty::Str)),
        Field::opt("details", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        Field::opt("resource_name", Ty::Nullable(&Ty::Str)),
        Field::opt("resource_type", Ty::Nullable(&Ty::Str)),
    ],
);

/// `RepositoryAuditResult` (`checks` holds `AuditCheck` instances).
pub static REPOSITORY_RESULT: Model = Model::new(
    "RepositoryAuditResult",
    &[
        Field::req("repo_name", Ty::Str),
        Field::req("repo_full_name", Ty::Str),
        Field::req("repo_url", Ty::Str),
        Field::req("is_private", Ty::Bool),
        Field::def("is_archived", Ty::Bool, no),
        Field::req("default_branch", Ty::Str),
        Field::def("checks", Ty::Any, empty_list),
        Field::def("passed_count", Ty::Int, zero),
        Field::def("failed_count", Ty::Int, zero),
        Field::def("warning_count", Ty::Int, zero),
    ],
);

/// `OrganizationAuditResult`.
pub static ORGANIZATION_RESULT: Model = Model::new(
    "OrganizationAuditResult",
    &[
        Field::req("org_name", Ty::Str),
        Field::req("org_url", Ty::Str),
        Field::def("checks", Ty::Any, empty_list),
        Field::def("passed_count", Ty::Int, zero),
        Field::def("failed_count", Ty::Int, zero),
        Field::def("warning_count", Ty::Int, zero),
    ],
);

/// `WorkflowAuditResult`.
pub static WORKFLOW_RESULT: Model = Model::new(
    "WorkflowAuditResult",
    &[
        Field::req("repo_name", Ty::Str),
        Field::req("workflow_name", Ty::Str),
        Field::req("workflow_path", Ty::Str),
        Field::def("checks", Ty::Any, empty_list),
    ],
);

/// `MemberAuditResult`.
pub static MEMBER_RESULT: Model = Model::new(
    "MemberAuditResult",
    &[
        Field::req("username", Ty::Str),
        Field::req("role", Ty::Str),
        Field::opt("has_2fa", Ty::Nullable(&Ty::Bool)),
        Field::def("checks", Ty::Any, empty_list),
    ],
);

fn yes() -> PyValue {
    PyValue::Bool(true)
}

/// `GitHubAuditRequest`, as `run_audit_from_config` builds it from a stored
/// configuration (`repo_filter` is whatever the JSON column holds).
pub static AUDIT_REQUEST: Model = Model::new(
    "GitHubAuditRequest",
    &[
        Field::req("organization", Ty::Str),
        Field::def("include_repos", Ty::Bool, yes),
        Field::def("include_workflows", Ty::Bool, yes),
        Field::def("include_members", Ty::Bool, yes),
        Field::opt("repo_filter", Ty::Nullable(&Ty::List(&Ty::Str))),
    ],
);

// --- request bodies ---------------------------------------------------------------------

fn child(at: &Loc, key: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(key.into()));
    l
}

fn push_model_errors(v: &mut Validator, at: &Loc, e: Invalid) {
    if let Invalid::Errors(errors) = e {
        for err in errors {
            let mut l = at.clone();
            for part in err.loc {
                l.push(match part {
                    ModelLoc::Key(k) => LocPart::Key(k),
                    ModelLoc::Index(i) => LocPart::Index(i),
                });
            }
            v.push(err.kind, l, err.msg);
        }
    }
}

/// The wall clock of a Pydantic JSON-mode datetime
/// (`YYYY-MM-DDTHH:MM:SS[.ffffff][Z|±HH:MM]`): what pymysql binds for an
/// aware value (it drops the offset).
pub fn wall_clock(iso: &str) -> Option<NaiveDateTime> {
    let date = NaiveDate::parse_from_str(iso.get(0..10)?, "%Y-%m-%d").ok()?;
    let time = NaiveTime::parse_from_str(iso.get(11..19)?, "%H:%M:%S").ok()?;
    let micros = match iso.get(19..20) {
        Some(".") => iso.get(20..26)?.parse::<u32>().ok()?,
        _ => 0,
    };
    date.and_time(time)
        .checked_add_signed(chrono::Duration::microseconds(i64::from(micros)))
}

/// An `Optional[datetime] = None` field: the wall clock stored.
pub fn b_opt_datetime(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
) -> Option<NaiveDateTime> {
    let value = field(obj, name)?;
    if value == PyValue::None {
        return None;
    }
    let l = child(at, name);
    match validate_ty(&Ty::DateTime, &value) {
        Ok(PyValue::Str(iso)) => wall_clock(&iso),
        Ok(_) => None,
        Err(e) => {
            push_model_errors(v, &l, e);
            None
        }
    }
}

/// An `Optional[int] = None` field: its decimal text.
pub fn b_opt_int(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
) -> Option<String> {
    match field(obj, name) {
        None | Some(PyValue::None) => None,
        Some(value) => check_int(v, &child(at, name), &value, NumSpec::ANY),
    }
}

/// An `Optional[Dict[str, str]] = None` field.
pub fn b_opt_str_dict(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
) -> Option<PyValue> {
    let value = field(obj, name)?;
    if value == PyValue::None {
        return None;
    }
    match validate_ty(&Ty::Dict(&Ty::Str), &value) {
        Ok(dict) => Some(dict),
        Err(e) => {
            push_model_errors(v, &child(at, name), e);
            None
        }
    }
}

/// A validated `str` (empty when the field failed).
pub fn text(v: PyValue) -> String {
    match v {
        PyValue::Str(s) => s,
        _ => String::new(),
    }
}

/// A validated `Optional[str]`.
pub fn opt_text(v: PyValue) -> Option<String> {
    match v {
        PyValue::Str(s) => Some(s),
        _ => None,
    }
}

fn flag(v: PyValue, default: bool) -> bool {
    match v {
        PyValue::Bool(b) => b,
        _ => default,
    }
}

fn opt_flag(v: PyValue) -> Option<bool> {
    match v {
        PyValue::Bool(b) => Some(b),
        _ => None,
    }
}

fn number(v: &PyValue) -> Option<f64> {
    match v {
        PyValue::Float(f) => Some(*f),
        PyValue::Int(i) => i.parse().ok(),
        _ => None,
    }
}

fn str_list(v: PyValue) -> Option<Vec<String>> {
    match v {
        PyValue::List(items) => Some(items.into_iter().map(text).collect()),
        _ => None,
    }
}

/// `GitHubAuditConfigCreate`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigCreate {
    /// `customer_code` (≤ 50).
    pub customer_code: String,
    /// `github_token` (≤ 500).
    pub github_token: String,
    /// `organization` (≤ 100).
    pub organization: String,
    /// `token_type` (≤ 50, default `pat`).
    pub token_type: String,
    /// `token_expires_at` (the wall clock stored).
    pub token_expires_at: Option<NaiveDateTime>,
    /// `enabled`.
    pub enabled: bool,
    /// `auto_audit_enabled` (stored only: nothing schedules audits).
    pub auto_audit_enabled: bool,
    /// `audit_schedule_cron` (≤ 50; stored only).
    pub audit_schedule_cron: Option<String>,
    /// `include_repos`.
    pub include_repos: bool,
    /// `include_workflows`.
    pub include_workflows: bool,
    /// `include_members`.
    pub include_members: bool,
    /// `include_archived_repos` (stored only: the audit never reads it).
    pub include_archived_repos: bool,
    /// `repo_filter_mode` (no length check in the schema).
    pub repo_filter_mode: String,
    /// `repo_filter_list`.
    pub repo_filter_list: Option<Vec<String>>,
    /// `notify_on_critical` (stored only).
    pub notify_on_critical: bool,
    /// `notify_on_high` (stored only).
    pub notify_on_high: bool,
    /// `notification_webhook_url` (≤ 500; stored only).
    pub notification_webhook_url: Option<String>,
    /// `notification_email` (≤ 255; stored only).
    pub notification_email: Option<String>,
    /// `minimum_passing_score` (`0 ≤ x ≤ 100`; stored only).
    pub minimum_passing_score: f64,
    /// `created_by` (≤ 100).
    pub created_by: Option<String>,
}

const SCORE: NumSpec = NumSpec::range(0.0, 100.0);

impl ConfigCreate {
    /// Read the body, every field in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            customer_code: text(b_req_str(v, obj, at, "customer_code", StrSpec::max(50))),
            github_token: text(b_req_str(v, obj, at, "github_token", StrSpec::max(500))),
            organization: text(b_req_str(v, obj, at, "organization", StrSpec::max(100))),
            token_type: str_or(v, obj, at, "token_type", StrSpec::max(50), "pat"),
            token_expires_at: b_opt_datetime(v, obj, at, "token_expires_at"),
            enabled: flag(b_bool_or(v, obj, at, "enabled", true), true),
            auto_audit_enabled: flag(b_bool_or(v, obj, at, "auto_audit_enabled", false), false),
            audit_schedule_cron: opt_text(b_opt_str(
                v,
                obj,
                at,
                "audit_schedule_cron",
                StrSpec::max(50),
            )),
            include_repos: flag(b_bool_or(v, obj, at, "include_repos", true), true),
            include_workflows: flag(b_bool_or(v, obj, at, "include_workflows", true), true),
            include_members: flag(b_bool_or(v, obj, at, "include_members", true), true),
            include_archived_repos: flag(
                b_bool_or(v, obj, at, "include_archived_repos", false),
                false,
            ),
            repo_filter_mode: str_or(v, obj, at, "repo_filter_mode", StrSpec::ANY, "all"),
            repo_filter_list: str_list(b_opt_str_list(v, obj, at, "repo_filter_list")),
            notify_on_critical: flag(b_bool_or(v, obj, at, "notify_on_critical", true), true),
            notify_on_high: flag(b_bool_or(v, obj, at, "notify_on_high", false), false),
            notification_webhook_url: opt_text(b_opt_str(
                v,
                obj,
                at,
                "notification_webhook_url",
                StrSpec::max(500),
            )),
            notification_email: opt_text(b_opt_str(
                v,
                obj,
                at,
                "notification_email",
                StrSpec::max(255),
            )),
            minimum_passing_score: number(&b_float_or(
                v,
                obj,
                at,
                "minimum_passing_score",
                SCORE,
                PyValue::Float(70.0),
            ))
            .unwrap_or(70.0),
            created_by: opt_text(b_opt_str(v, obj, at, "created_by", StrSpec::max(100))),
        }
    }
}

/// A `str = Field(default, …)` field (an explicit `null` is an error).
fn str_or(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: StrSpec,
    default: &str,
) -> String {
    match field(obj, name) {
        None => default.to_string(),
        Some(value) => {
            copilot_uba::params::check_str(v, &child(at, name), &value, spec).unwrap_or_default()
        }
    }
}

/// One `GitHubAuditConfigUpdate` field that was sent with a non-`null`
/// value (`model_dump(exclude_unset=True)`, `None`s skipped).
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    /// A string column.
    Text(String),
    /// A boolean column.
    Flag(bool),
    /// `token_expires_at`.
    Time(NaiveDateTime),
    /// `repo_filter_list` (a JSON column).
    List(Vec<String>),
    /// `minimum_passing_score`.
    Number(f64),
}

/// `GitHubAuditConfigUpdate`: the columns to write, in declaration order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigUpdate {
    /// `(column, value)` pairs.
    pub set: Vec<(&'static str, ConfigValue)>,
}

impl ConfigUpdate {
    /// Read the body, every field in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let mut set = Vec::new();
        let mut text_field = |v: &mut Validator, name: &'static str, spec: StrSpec| {
            if let Some(s) = opt_text(b_opt_str(v, obj, at, name, spec)) {
                set.push((name, ConfigValue::Text(s)));
            }
        };
        text_field(v, "github_token", StrSpec::max(500));
        text_field(v, "organization", StrSpec::max(100));
        text_field(v, "token_type", StrSpec::max(50));
        if let Some(t) = b_opt_datetime(v, obj, at, "token_expires_at") {
            set.push(("token_expires_at", ConfigValue::Time(t)));
        }
        for name in ["enabled", "auto_audit_enabled"] {
            if let Some(b) = opt_flag(b_opt_bool(v, obj, at, name)) {
                set.push((name, ConfigValue::Flag(b)));
            }
        }
        if let Some(s) = opt_text(b_opt_str(
            v,
            obj,
            at,
            "audit_schedule_cron",
            StrSpec::max(50),
        )) {
            set.push(("audit_schedule_cron", ConfigValue::Text(s)));
        }
        for name in [
            "include_repos",
            "include_workflows",
            "include_members",
            "include_archived_repos",
        ] {
            if let Some(b) = opt_flag(b_opt_bool(v, obj, at, name)) {
                set.push((name, ConfigValue::Flag(b)));
            }
        }
        if let Some(s) = opt_text(b_opt_str(v, obj, at, "repo_filter_mode", StrSpec::ANY)) {
            set.push(("repo_filter_mode", ConfigValue::Text(s)));
        }
        if let Some(items) = str_list(b_opt_str_list(v, obj, at, "repo_filter_list")) {
            set.push(("repo_filter_list", ConfigValue::List(items)));
        }
        for name in ["notify_on_critical", "notify_on_high"] {
            if let Some(b) = opt_flag(b_opt_bool(v, obj, at, name)) {
                set.push((name, ConfigValue::Flag(b)));
            }
        }
        if let Some(s) = opt_text(b_opt_str(
            v,
            obj,
            at,
            "notification_webhook_url",
            StrSpec::max(500),
        )) {
            set.push(("notification_webhook_url", ConfigValue::Text(s)));
        }
        if let Some(s) = opt_text(b_opt_str(
            v,
            obj,
            at,
            "notification_email",
            StrSpec::max(255),
        )) {
            set.push(("notification_email", ConfigValue::Text(s)));
        }
        if let Some(f) = number(&b_opt_float(v, obj, at, "minimum_passing_score", SCORE)) {
            set.push(("minimum_passing_score", ConfigValue::Number(f)));
        }
        if let Some(s) = opt_text(b_opt_str(v, obj, at, "updated_by", StrSpec::max(100))) {
            set.push(("updated_by", ConfigValue::Text(s)));
        }
        Self { set }
    }
}

/// `GitHubAuditExclusionCreate`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExclusionCreate {
    /// `check_id` (≤ 100).
    pub check_id: String,
    /// `resource_name` (≤ 255).
    pub resource_name: Option<String>,
    /// `resource_type` (≤ 50).
    pub resource_type: Option<String>,
    /// `reason`.
    pub reason: String,
    /// `approved_by` (≤ 100).
    pub approved_by: Option<String>,
    /// `expires_at` (the wall clock stored).
    pub expires_at: Option<NaiveDateTime>,
    /// `created_by` (≤ 100).
    pub created_by: String,
}

impl ExclusionCreate {
    /// Read the body, every field in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            check_id: text(b_req_str(v, obj, at, "check_id", StrSpec::max(100))),
            resource_name: opt_text(b_opt_str(v, obj, at, "resource_name", StrSpec::max(255))),
            resource_type: opt_text(b_opt_str(v, obj, at, "resource_type", StrSpec::max(50))),
            reason: text(b_req_str(v, obj, at, "reason", StrSpec::ANY)),
            approved_by: opt_text(b_opt_str(v, obj, at, "approved_by", StrSpec::max(100))),
            expires_at: b_opt_datetime(v, obj, at, "expires_at"),
            created_by: text(b_req_str(v, obj, at, "created_by", StrSpec::max(100))),
        }
    }
}

/// One `GitHubAuditExclusionUpdate` field sent with a non-`null` value.
#[derive(Debug, Clone, PartialEq)]
pub enum ExclusionValue {
    /// `reason` / `approved_by`.
    Text(String),
    /// `expires_at`.
    Time(NaiveDateTime),
    /// `enabled`.
    Flag(bool),
}

/// `GitHubAuditExclusionUpdate`: the columns to write, in declaration order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExclusionUpdate {
    /// `(column, value)` pairs.
    pub set: Vec<(&'static str, ExclusionValue)>,
}

impl ExclusionUpdate {
    /// Read the body, every field in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let mut set = Vec::new();
        if let Some(s) = opt_text(b_opt_str(v, obj, at, "reason", StrSpec::ANY)) {
            set.push(("reason", ExclusionValue::Text(s)));
        }
        if let Some(s) = opt_text(b_opt_str(v, obj, at, "approved_by", StrSpec::max(100))) {
            set.push(("approved_by", ExclusionValue::Text(s)));
        }
        if let Some(t) = b_opt_datetime(v, obj, at, "expires_at") {
            set.push(("expires_at", ExclusionValue::Time(t)));
        }
        if let Some(b) = opt_flag(b_opt_bool(v, obj, at, "enabled")) {
            set.push(("enabled", ExclusionValue::Flag(b)));
        }
        Self { set }
    }
}

/// `GitHubAuditBaselineCreate`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BaselineCreate {
    /// `name` (≤ 255).
    pub name: String,
    /// `description`.
    pub description: Option<String>,
    /// `expected_checks` (`Dict[str, str]`).
    pub expected_checks: Option<PyValue>,
    /// `baseline_report_id` (its decimal text).
    pub baseline_report_id: Option<String>,
    /// `is_active`.
    pub is_active: bool,
    /// `created_by` (≤ 100).
    pub created_by: String,
}

impl BaselineCreate {
    /// Read the body, every field in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            name: text(b_req_str(v, obj, at, "name", StrSpec::max(255))),
            description: opt_text(b_opt_str(v, obj, at, "description", StrSpec::ANY)),
            expected_checks: b_opt_str_dict(v, obj, at, "expected_checks"),
            baseline_report_id: b_opt_int(v, obj, at, "baseline_report_id"),
            is_active: flag(b_bool_or(v, obj, at, "is_active", true), true),
            created_by: text(b_req_str(v, obj, at, "created_by", StrSpec::max(100))),
        }
    }
}

/// `GitHubAuditRequest` as a request body (the ad-hoc audit).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditRequest {
    /// `organization`.
    pub organization: String,
    /// `include_repos`.
    pub include_repos: bool,
    /// `include_workflows`.
    pub include_workflows: bool,
    /// `include_members`.
    pub include_members: bool,
    /// `repo_filter`.
    pub repo_filter: Option<Vec<String>>,
}

impl AuditRequest {
    /// Read the body, every field in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            organization: text(b_req_str(v, obj, at, "organization", StrSpec::ANY)),
            include_repos: flag(b_bool_or(v, obj, at, "include_repos", true), true),
            include_workflows: flag(b_bool_or(v, obj, at, "include_workflows", true), true),
            include_members: flag(b_bool_or(v, obj, at, "include_members", true), true),
            repo_filter: str_list(b_opt_str_list(v, obj, at, "repo_filter")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clocks_drop_the_offset() {
        let t = |s: &str| wall_clock(s).map(|d| d.format("%Y-%m-%d %H:%M:%S%.6f").to_string());
        assert_eq!(
            t("2026-10-20T10:00:00+02:00").as_deref(),
            Some("2026-10-20 10:00:00.000000")
        );
        assert_eq!(
            t("2026-10-20T10:00:00.250000Z").as_deref(),
            Some("2026-10-20 10:00:00.250000")
        );
        assert_eq!(
            t("2026-10-20T10:00:00").as_deref(),
            Some("2026-10-20 10:00:00.000000")
        );
    }
}
