//! Request models of the write routes (`app/incidents/schema/db_operations.py`),
//! read with Pydantic's lax rules and messages.

use chrono::NaiveDateTime;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use copilot_web::ApiError;
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator};

use crate::schema::{ALERT_STATUSES, CASE_SEVERITIES, FALSE_POSITIVE_REASONS, IOC_TYPES, VERDICTS};

type Obj = Map<String, Value>;

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

/// A `datetime` as Pydantic holds it: the wall clock and, for an aware
/// value, its UTC offset in seconds. Serializes like Pydantic
/// (`…T10:00:00Z`, `…T10:00:00.500000+02:00`, naive without an offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PyDateTime {
    /// Wall clock (what `pymysql` binds into SQL).
    pub wall: NaiveDateTime,
    /// UTC offset in seconds, for an aware value.
    pub offset: Option<i32>,
}

impl PyDateTime {
    /// A naive value.
    pub fn naive(wall: NaiveDateTime) -> Self {
        Self { wall, offset: None }
    }

    /// Pydantic's JSON rendering.
    pub fn render(&self) -> String {
        let mut out = copilot_core::time::to_pydantic_iso(self.wall);
        if let Some(offset) = self.offset {
            if offset == 0 {
                out.push('Z');
            } else {
                let sign = if offset < 0 { '-' } else { '+' };
                let abs = offset.unsigned_abs();
                out.push_str(&format!("{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60));
                if abs % 60 != 0 {
                    out.push_str(&format!(":{:02}", abs % 60));
                }
            }
        }
        out
    }
}

impl Serialize for PyDateTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.render())
    }
}

fn check_datetime(v: &mut Validator, at: &Loc, value: &Value) -> Option<PyDateTime> {
    let raw = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => {
            v.push(
                "datetime_type",
                at.clone(),
                "Input should be a valid datetime",
            );
            return None;
        }
    };
    match copilot_web::datetime::parse_lax_offset(&raw) {
        Ok((wall, offset)) => Some(PyDateTime { wall, offset }),
        Err(e) => {
            v.push(e.kind, at.clone(), e.msg);
            None
        }
    }
}

/// A required `datetime` field.
pub fn req_datetime(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> Option<PyDateTime> {
    let l = child(at, name);
    match obj.get(name) {
        None => {
            v.missing(l);
            None
        }
        Some(value) => check_datetime(v, &l, value),
    }
}

/// An `Optional[datetime] = None` field.
pub fn opt_datetime(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> Option<PyDateTime> {
    match obj.get(name) {
        None | Some(Value::Null) => None,
        Some(value) => check_datetime(v, &child(at, name), value),
    }
}

/// A `List[int]` field (`min_length` / `max_length` as Pydantic checks them:
/// too long before the items, too short after).
pub fn int_list(
    v: &mut Validator,
    obj: &Obj,
    at: &Loc,
    name: &str,
    min: Option<usize>,
    max: Option<usize>,
) -> Vec<i64> {
    let l = child(at, name);
    let items = match obj.get(name) {
        None => {
            v.missing(l);
            return Vec::new();
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            v.push("list_type", l, "Input should be a valid list");
            return Vec::new();
        }
    };
    if let Some(max) = max.filter(|m| items.len() > *m) {
        v.push(
            "too_long",
            l,
            format!(
                "List should have at most {max} item{} after validation, not {}",
                if max == 1 { "" } else { "s" },
                items.len()
            ),
        );
        return Vec::new();
    }
    let before = v.errors().len();
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let mut il = l.clone();
        il.push(LocPart::Index(i));
        if let Some(n) = v.check_int(&il, item, IntRules::default()) {
            out.push(n);
        }
    }
    if v.errors().len() == before {
        if let Some(min) = min.filter(|m| out.len() < *m) {
            v.push(
                "too_short",
                l,
                format!(
                    "List should have at least {min} item{} after validation, not {}",
                    if min == 1 { "" } else { "s" },
                    out.len()
                ),
            );
        }
    }
    out
}

/// A `List[str]` field.
pub fn str_list(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> Vec<String> {
    let l = child(at, name);
    match obj.get(name) {
        None => {
            v.missing(l);
            Vec::new()
        }
        Some(value) => v.str_items(value, &l),
    }
}

/// An `Optional[List[str]] = None` field.
pub fn opt_str_list(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> Option<Vec<String>> {
    match obj.get(name) {
        None | Some(Value::Null) => None,
        Some(value) => Some(v.str_items(value, &child(at, name))),
    }
}

fn int(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> i64 {
    v.req_int(obj, at, name, IntRules::default())
}

fn text(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> String {
    v.req_str(obj, at, name, StrRules::any())
}

fn opt_text(v: &mut Validator, obj: &Obj, at: &Loc, name: &str) -> Option<String> {
    v.opt_str(obj, at, name, StrRules::any())
}

/// Report query/path errors and the body's together, as FastAPI does (the
/// parameters' first).
pub fn merge<T>(params: Validator, body: Result<T, ApiError>) -> Result<T, ApiError> {
    match (params.finish(), body) {
        (Ok(()), body) => body,
        (Err(ApiError::Validation(mut a)), Err(ApiError::Validation(b))) => {
            a.extend(b);
            Err(ApiError::Validation(a))
        }
        (Err(e), _) => Err(e),
    }
}

/// `PutAITrigger`.
#[derive(Debug, Clone)]
pub struct PutAiTrigger {
    /// Tenant.
    pub customer_code: String,
    /// Enabled.
    pub enabled: bool,
}

impl PutAiTrigger {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            customer_code: text(v, o, at, "customer_code"),
            enabled: v.req_bool(o, at, "enabled"),
        }
    }
}

/// `PutNotification`.
#[derive(Debug, Clone)]
pub struct PutNotification {
    /// Tenant.
    pub customer_code: String,
    /// Shuffle workflow.
    pub shuffle_workflow_id: String,
    /// Enabled.
    pub enabled: bool,
}

impl PutNotification {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            customer_code: text(v, o, at, "customer_code"),
            shuffle_workflow_id: text(v, o, at, "shuffle_workflow_id"),
            enabled: v.req_bool(o, at, "enabled"),
        }
    }
}

/// `FieldAndAssetNames`.
#[derive(Debug, Clone)]
pub struct FieldAndAssetNames {
    /// Field names.
    pub field_names: Vec<String>,
    /// Asset field.
    pub asset_name: String,
    /// Time field.
    pub timefield_name: String,
    /// Title field.
    pub alert_title_name: String,
    /// IoC fields.
    pub ioc_field_names: Option<Vec<String>>,
    /// Source.
    pub source: String,
}

impl FieldAndAssetNames {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            field_names: str_list(v, o, at, "field_names"),
            asset_name: text(v, o, at, "asset_name"),
            timefield_name: text(v, o, at, "timefield_name"),
            alert_title_name: text(v, o, at, "alert_title_name"),
            ioc_field_names: opt_str_list(v, o, at, "ioc_field_names"),
            source: text(v, o, at, "source"),
        }
    }
}

/// `AlertCreate`.
#[derive(Debug, Clone)]
pub struct AlertCreate {
    /// Title.
    pub alert_name: String,
    /// Description.
    pub alert_description: String,
    /// Status (free text).
    pub status: String,
    /// Creation time.
    pub alert_creation_time: Option<PyDateTime>,
    /// Tenant.
    pub customer_code: String,
    /// Closed at.
    pub time_closed: Option<PyDateTime>,
    /// Source.
    pub source: String,
    /// Assignee.
    pub assigned_to: String,
}

impl AlertCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            alert_name: text(v, o, at, "alert_name"),
            alert_description: text(v, o, at, "alert_description"),
            status: text(v, o, at, "status"),
            alert_creation_time: req_datetime(v, o, at, "alert_creation_time"),
            customer_code: text(v, o, at, "customer_code"),
            time_closed: opt_datetime(v, o, at, "time_closed"),
            source: text(v, o, at, "source"),
            assigned_to: text(v, o, at, "assigned_to"),
        }
    }
}

/// `UpdateAlertStatus` / `UpdateCaseStatus` (`id` is `alert_id` or `case_id`).
#[derive(Debug, Clone)]
pub struct UpdateStatus {
    /// The item.
    pub id: i64,
    /// `AlertStatus`.
    pub status: String,
}

impl UpdateStatus {
    /// Read with the id field `key`.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc, key: &str) -> Self {
        Self {
            id: int(v, o, at, key),
            status: v.req_enum(o, at, "status", ALERT_STATUSES),
        }
    }
}

/// `BulkUpdateAlertStatus`.
#[derive(Debug, Clone)]
pub struct BulkUpdateAlertStatus {
    /// Alerts.
    pub alert_ids: Vec<i64>,
    /// `AlertStatus`.
    pub status: String,
}

impl BulkUpdateAlertStatus {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            alert_ids: int_list(v, o, at, "alert_ids", None, None),
            status: v.req_enum(o, at, "status", ALERT_STATUSES),
        }
    }
}

/// `UpdateAlertVerdict` (with its `after` model validator).
#[derive(Debug, Clone)]
pub struct UpdateAlertVerdict {
    /// Alert.
    pub alert_id: i64,
    /// Verdict (`None` clears).
    pub verdict: Option<String>,
    /// Reason.
    pub verdict_reason: Option<String>,
    /// Note (≤ 1024 characters).
    pub verdict_note: Option<String>,
}

impl UpdateAlertVerdict {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let before = v.errors().len();
        let out = Self {
            alert_id: int(v, o, at, "alert_id"),
            verdict: v.opt_enum(o, at, "verdict", VERDICTS),
            verdict_reason: v.opt_enum(o, at, "verdict_reason", FALSE_POSITIVE_REASONS),
            verdict_note: v.opt_str(
                o,
                at,
                "verdict_note",
                StrRules {
                    max_len: Some(1024),
                    ..StrRules::any()
                },
            ),
        };
        if v.errors().len() == before {
            let fp = out.verdict.as_deref() == Some("FALSE_POSITIVE");
            if out.verdict_reason.is_some() && !fp {
                v.push(
                    "value_error",
                    at.clone(),
                    "Value error, verdict_reason is only valid when verdict is FALSE_POSITIVE",
                );
            } else if fp && out.verdict_reason.is_none() {
                v.push(
                    "value_error",
                    at.clone(),
                    "Value error, verdict_reason is required when verdict is FALSE_POSITIVE",
                );
            }
        }
        out
    }
}

/// `AlertVerdictStateRequest` (1 to 500 ids).
#[derive(Debug, Clone)]
pub struct VerdictStateRequest {
    /// Alerts.
    pub alert_ids: Vec<i64>,
}

impl VerdictStateRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            alert_ids: int_list(v, o, at, "alert_ids", Some(1), Some(500)),
        }
    }
}

/// `{key}: int` plus a second field: `EscalateAlert`, `EscalateCase`,
/// `AssignedToAlert`, `AssignedToCase`, the link/unlink bodies.
#[derive(Debug, Clone)]
pub struct IdBool {
    /// The item.
    pub id: i64,
    /// The flag.
    pub value: bool,
}

impl IdBool {
    /// Read `{key: int, flag: bool}`.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc, key: &str, flag: &str) -> Self {
        Self {
            id: int(v, o, at, key),
            value: v.req_bool(o, at, flag),
        }
    }
}

/// `{key: int, field: str}`.
#[derive(Debug, Clone)]
pub struct IdText {
    /// The item.
    pub id: i64,
    /// The text.
    pub value: String,
}

impl IdText {
    /// Read `{key: int, field: str}`.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc, key: &str, field: &str) -> Self {
        Self {
            id: int(v, o, at, key),
            value: text(v, o, at, field),
        }
    }
}

/// `{a: int, b: int}`.
#[derive(Debug, Clone)]
pub struct TwoIds {
    /// First.
    pub a: i64,
    /// Second.
    pub b: i64,
}

impl TwoIds {
    /// Read two integer fields.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc, a: &str, b: &str) -> Self {
        Self {
            a: int(v, o, at, a),
            b: int(v, o, at, b),
        }
    }
}

/// `{key: int}`.
pub fn one_id(v: &mut Validator, o: &Obj, at: &Loc, key: &str) -> i64 {
    int(v, o, at, key)
}

/// `BulkAssignedToAlert`.
#[derive(Debug, Clone)]
pub struct BulkAssign {
    /// Alerts.
    pub alert_ids: Vec<i64>,
    /// User.
    pub assigned_to: String,
}

impl BulkAssign {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            alert_ids: int_list(v, o, at, "alert_ids", None, None),
            assigned_to: text(v, o, at, "assigned_to"),
        }
    }
}

/// `DeleteAlertsRequest` / `CaseAlertLinksCreate.alert_ids`.
pub fn alert_ids(v: &mut Validator, o: &Obj, at: &Loc) -> Vec<i64> {
    int_list(v, o, at, "alert_ids", None, None)
}

/// `CommentCreate` / `CaseCommentCreate` (`parent` is `alert_id` / `case_id`).
#[derive(Debug, Clone)]
pub struct CommentCreate {
    /// Alert or case.
    pub parent: i64,
    /// Text.
    pub comment: String,
    /// Ignored (stamped from the caller), but required.
    pub user_name: String,
    /// Creation time, when sent.
    pub created_at: Option<PyDateTime>,
}

impl CommentCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc, parent: &str) -> Self {
        Self {
            parent: int(v, o, at, parent),
            comment: text(v, o, at, "comment"),
            user_name: text(v, o, at, "user_name"),
            created_at: opt_datetime(v, o, at, "created_at"),
        }
    }
}

/// `CommentEdit` / `CaseCommentEdit`.
#[derive(Debug, Clone)]
pub struct CommentEdit {
    /// Alert or case.
    pub parent: i64,
    /// Comment.
    pub comment_id: i64,
    /// New text.
    pub comment: String,
}

impl CommentEdit {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc, parent: &str) -> Self {
        let out = Self {
            parent: int(v, o, at, parent),
            comment_id: int(v, o, at, "comment_id"),
            comment: text(v, o, at, "comment"),
        };
        let _ = text(v, o, at, "user_name");
        let _ = req_datetime(v, o, at, "created_at");
        out
    }
}

/// `AlertContextCreate`.
#[derive(Debug, Clone)]
pub struct AlertContextCreate {
    /// Source.
    pub source: String,
    /// Context.
    pub context: Value,
}

impl AlertContextCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            source: text(v, o, at, "source"),
            context: v.req_dict(o, at, "context").cloned().unwrap_or(Value::Null),
        }
    }
}

/// `AssetCreate`.
#[derive(Debug, Clone)]
pub struct AssetCreate {
    /// Alert.
    pub alert_linked: i64,
    /// Name.
    pub asset_name: String,
    /// Context.
    pub alert_context_id: i64,
    /// Agent.
    pub agent_id: Option<String>,
    /// Velociraptor client.
    pub velociraptor_id: Option<String>,
    /// Tenant.
    pub customer_code: String,
    /// Index.
    pub index_name: String,
    /// Document.
    pub index_id: String,
}

impl AssetCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            alert_linked: int(v, o, at, "alert_linked"),
            asset_name: text(v, o, at, "asset_name"),
            alert_context_id: int(v, o, at, "alert_context_id"),
            agent_id: opt_text(v, o, at, "agent_id"),
            velociraptor_id: opt_text(v, o, at, "velociraptor_id"),
            customer_code: text(v, o, at, "customer_code"),
            index_name: text(v, o, at, "index_name"),
            index_id: text(v, o, at, "index_id"),
        }
    }
}

/// `AlertIoCCreate`.
#[derive(Debug, Clone)]
pub struct IocCreate {
    /// Alert.
    pub alert_id: i64,
    /// Value.
    pub ioc_value: String,
    /// `IP` | `DOMAIN` | `HASH` | `URL`.
    pub ioc_type: String,
    /// Description.
    pub ioc_description: Option<String>,
}

impl IocCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            alert_id: int(v, o, at, "alert_id"),
            ioc_value: text(v, o, at, "ioc_value"),
            ioc_type: v.req_enum(o, at, "ioc_type", IOC_TYPES),
            ioc_description: opt_text(v, o, at, "ioc_description"),
        }
    }
}

/// `CaseCreate`.
#[derive(Debug, Clone)]
pub struct CaseCreate {
    /// Name.
    pub case_name: String,
    /// Description.
    pub case_description: String,
    /// Creation time.
    pub case_creation_time: Option<PyDateTime>,
    /// Status (free text).
    pub case_status: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Tenant.
    pub customer_code: Option<String>,
    /// `CaseSeverity`.
    pub severity: Option<String>,
}

impl CaseCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            case_name: text(v, o, at, "case_name"),
            case_description: text(v, o, at, "case_description"),
            case_creation_time: req_datetime(v, o, at, "case_creation_time"),
            case_status: text(v, o, at, "case_status"),
            assigned_to: opt_text(v, o, at, "assigned_to"),
            customer_code: opt_text(v, o, at, "customer_code"),
            severity: v.opt_enum(o, at, "severity", CASE_SEVERITIES),
        }
    }
}

/// `UpdateCaseSeverity`.
#[derive(Debug, Clone)]
pub struct UpdateCaseSeverity {
    /// Case.
    pub case_id: i64,
    /// `None` = follow the alerts.
    pub severity: Option<String>,
}

impl UpdateCaseSeverity {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            case_id: int(v, o, at, "case_id"),
            severity: v.opt_enum(o, at, "severity", CASE_SEVERITIES),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_like_pydantic() {
        let t = |s: &str| {
            let (wall, offset) = copilot_web::datetime::parse_lax_offset(s).unwrap();
            PyDateTime { wall, offset }.render()
        };
        assert_eq!(t("2026-01-01T10:00:00+00:00"), "2026-01-01T10:00:00Z");
        assert_eq!(
            t("2026-01-01T10:00:00.5+02:00"),
            "2026-01-01T10:00:00.500000+02:00"
        );
        assert_eq!(t("2026-01-01T10:00:00-03:30"), "2026-01-01T10:00:00-03:30");
        assert_eq!(t("1700000000"), "2023-11-14T22:13:20Z");
        assert_eq!(t("2026-01-01"), "2026-01-01T00:00:00");
    }

    #[test]
    fn list_lengths_follow_pydantic() {
        let read = |value: Value| {
            let mut v = Validator::new();
            let o = json!({ "alert_ids": value });
            let ids = int_list(
                &mut v,
                o.as_object().unwrap(),
                &vec![],
                "alert_ids",
                Some(1),
                Some(3),
            );
            (
                ids,
                v.errors().iter().map(|e| e.msg.clone()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            read(json!([])).1,
            vec!["List should have at least 1 item after validation, not 0"]
        );
        assert_eq!(
            read(json!([1, "x", 3, 4, 5])).1,
            vec!["List should have at most 3 items after validation, not 5"]
        );
        assert_eq!(read(json!([1, "2"])).0, vec![1, 2]);
        assert_eq!(read(json!("abc")).1, vec!["Input should be a valid list"]);
    }
}
