//! `/api/incidents/customer_reports` — port of the database half of
//! `app/incidents/routes/customer_report.py`: the report list (CoPilot and
//! the Customer Portal) and the portal-visibility switch.
//!
//! Still Python: `/generate/background` (the PDF is rendered by
//! wkhtmltopdf from indexer and database figures, then stored in MinIO),
//! `/{report_id}/download` and `DELETE /{report_id}` (MinIO).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, patch};
use chrono::NaiveDateTime;
use serde_json::{Map, Value, json};
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_auth::pyvalue::{self, PyValue};
use copilot_core::time::to_pydantic_iso;
use copilot_web::validate::{IntRules, Loc, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized, QueryPairs,
    WithJson,
};

use super::common::{CUSTOMER_USER, json};
use crate::requests::merge;
use crate::views::pydantic_input_value;

type Obj = Map<String, Value>;

/// `DOWNLOAD_URL_TEMPLATE`.
const DOWNLOAD_URL: &str = "/api/v1/incidents/customer_reports/{report_id}/download";

/// Every column, in the model's order (what `select(IncidentManagementCustomerReport)` lists).
const COLS: &str = "incident_management_customer_reports.id, \
    incident_management_customer_reports.report_name, \
    incident_management_customer_reports.customer_code, \
    incident_management_customer_reports.bucket_name, \
    incident_management_customer_reports.object_key, \
    incident_management_customer_reports.file_name, \
    incident_management_customer_reports.file_size, \
    incident_management_customer_reports.file_hash, \
    incident_management_customer_reports.generated_at, \
    incident_management_customer_reports.generated_by, \
    incident_management_customer_reports.generated_by_role, \
    incident_management_customer_reports.date_from, \
    incident_management_customer_reports.date_to, \
    incident_management_customer_reports.filters_json, \
    incident_management_customer_reports.total_alerts, \
    incident_management_customer_reports.total_cases, \
    incident_management_customer_reports.open_cases, \
    incident_management_customer_reports.closed_cases, \
    incident_management_customer_reports.visible_to_customer, \
    incident_management_customer_reports.status, \
    incident_management_customer_reports.error_message";

/// The router, to be nested at `/api/incidents/customer_reports`.
pub fn customer_reports(ctx: AppContext) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{report_id}/visibility", patch(set_visibility))
        .with_state(ctx)
}

/// `incident_management_customer_reports` (the columns the routes read).
#[derive(Debug, Clone, FromRow)]
struct Report {
    id: i32,
    report_name: String,
    customer_code: String,
    file_name: String,
    file_size: i32,
    generated_at: NaiveDateTime,
    generated_by: i32,
    generated_by_role: Option<String>,
    date_from: NaiveDateTime,
    date_to: NaiveDateTime,
    filters_json: Option<String>,
    total_alerts: i32,
    total_cases: i32,
    open_cases: i32,
    closed_cases: i32,
    visible_to_customer: bool,
    status: String,
    error_message: Option<String>,
}

/// A `json.loads` value as the JSON FastAPI writes back.
fn to_json(v: &PyValue) -> Result<Value, ApiError> {
    Ok(match v {
        PyValue::None => Value::Null,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(i) => serde_json::from_str(i).map_err(ApiError::internal)?,
        PyValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .ok_or_else(|| ApiError::internal("non-finite float in filters_json"))?,
        PyValue::Str(s) => Value::String(s.clone()),
        PyValue::List(items) => Value::Array(items.iter().map(to_json).collect::<Result<_, _>>()?),
        PyValue::Dict(items) => Value::Object(
            items
                .iter()
                .map(|(k, v)| Ok((k.clone(), to_json(v)?)))
                .collect::<Result<Map<_, _>, ApiError>>()?,
        ),
    })
}

impl Report {
    /// `_to_response`: `filters_json` through `json.loads` (unreadable → `{}`);
    /// anything but a dict fails `CustomerReportResponse` — a `ValueError`,
    /// the backend's 400 with Pydantic's text.
    fn to_json(&self, user_name: Option<&str>) -> Result<Value, ApiError> {
        let filters = match self.filters_json.as_deref().filter(|t| !t.is_empty()) {
            None => Value::Object(Map::new()),
            Some(text) => match pyvalue::loads(text) {
                Err(_) => Value::Object(Map::new()),
                Ok(v @ PyValue::Dict(_)) => to_json(&v)?,
                Ok(other) => {
                    let kind = match other {
                        PyValue::None => "NoneType",
                        PyValue::Bool(_) => "bool",
                        PyValue::Int(_) => "int",
                        PyValue::Float(_) => "float",
                        PyValue::Str(_) => "str",
                        PyValue::List(_) => "list",
                        PyValue::Dict(_) => "dict",
                    };
                    return Err(ApiError::bad_request(format!(
                        "1 validation error for CustomerReportResponse\nfilters_applied\n  Input \
                         should be a valid dictionary [type=dict_type, input_value={}, \
                         input_type={kind}]\n    For further information visit \
                         https://errors.pydantic.dev/2.13/v/dict_type",
                        pydantic_input_value(other.py_repr())
                    )));
                }
            },
        };
        Ok(json!({
            "id": self.id,
            "report_name": self.report_name,
            "customer_code": self.customer_code,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "generated_at": to_pydantic_iso(self.generated_at),
            "generated_by": self.generated_by,
            "generated_by_role": self.generated_by_role,
            "generated_by_name": user_name,
            "date_from": to_pydantic_iso(self.date_from),
            "date_to": to_pydantic_iso(self.date_to),
            "filters_applied": filters,
            "total_alerts": self.total_alerts,
            "total_cases": self.total_cases,
            "open_cases": self.open_cases,
            "closed_cases": self.closed_cases,
            "visible_to_customer": self.visible_to_customer,
            "status": self.status,
            "error_message": self.error_message,
            "download_url": (self.status == "completed")
                .then(|| DOWNLOAD_URL.replace("{report_id}", &self.id.to_string())),
        }))
    }
}

/// `GET ?customer_code=&customer_codes=`: the caller's customers (narrowed
/// by the request, never widened); a portal user sees their own reports and
/// those flagged visible.
async fn list(
    auth: Authorized<AnyPortalOrSoc>,
    State(ctx): State<AppContext>,
    q: QueryPairs,
) -> ApiResult {
    let customer_code = q.get("customer_code").map(str::to_string);
    let requested = q.get_all("customer_codes");
    let requested = (!requested.is_empty()).then_some(requested);
    let accessible = auth
        .access(&ctx)
        .await?
        .resolve_effective(requested.as_deref())
        .to_python_list();
    let only_customer_visible = auth.role_id == Some(CUSTOMER_USER);
    let mut reports: Vec<Report> = Vec::new();
    let wildcard = accessible.iter().any(|c| c == "*");
    if wildcard || !accessible.is_empty() {
        let mut qb = QueryBuilder::<MySql>::new(format!(
            "SELECT {COLS} FROM incident_management_customer_reports"
        ));
        let mut clauses = 0;
        let mut and = |qb: &mut QueryBuilder<'_, MySql>| {
            qb.push(if clauses == 0 { " WHERE " } else { " AND " });
            clauses += 1;
        };
        if let Some(code) = customer_code.as_ref().filter(|c| !c.is_empty()) {
            and(&mut qb);
            qb.push("incident_management_customer_reports.customer_code = ")
                .push_bind(code.clone());
        }
        if !wildcard {
            and(&mut qb);
            qb.push("incident_management_customer_reports.customer_code IN (");
            crate::store::push_list(&mut qb, accessible.iter().cloned());
            qb.push(")");
        }
        if only_customer_visible {
            and(&mut qb);
            qb.push(
                "(incident_management_customer_reports.visible_to_customer IS true OR \
                 incident_management_customer_reports.generated_by_role = ",
            )
            .push_bind("customer_user")
            .push(")");
        }
        qb.push(" ORDER BY incident_management_customer_reports.generated_at DESC");
        reports = qb
            .build_query_as::<Report>()
            .fetch_all(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
    }
    // `resolve_user_names`.
    let mut ids: Vec<i32> = reports.iter().map(|r| r.generated_by).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut names: Vec<(i32, String)> = Vec::new();
    if !ids.is_empty() {
        let mut qb = QueryBuilder::<MySql>::new("SELECT id, username FROM `user` WHERE id IN (");
        crate::store::push_list(&mut qb, ids.iter().copied());
        qb.push(")");
        names = qb
            .build_query_as::<(i32, String)>()
            .fetch_all(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
    }
    let items = reports
        .iter()
        .map(|r| {
            let name = names
                .iter()
                .find(|(id, _)| *id == r.generated_by)
                .map(|(_, n)| n.as_str());
            r.to_json(name)
        })
        .collect::<Result<Vec<Value>, ApiError>>()?;
    let total = items.len();
    Ok(json(json!({
        "reports": items,
        "total_count": total,
        "success": true,
        "message": "Reports retrieved successfully",
    })))
}

/// `CustomerReportVisibilityRequest`.
fn read_visible(v: &mut Validator, o: &Obj, at: &Loc) -> bool {
    v.req_bool(o, at, "visible")
}

/// `PATCH /{report_id}/visibility` (admin/analyst).
async fn set_visibility(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = v
        .check_int(
            &loc("path", "report_id"),
            &Value::String(raw),
            IntRules::default(),
        )
        .unwrap_or_default();
    let visible = merge(v, body.model(read_visible))?;
    // `_require_report`.
    let found: Option<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT customer_code, generated_by_role, visible_to_customer FROM \
         incident_management_customer_reports WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    let Some((customer, role, current)) = found else {
        return Err(ApiError::not_found(format!(
            "Report with ID {id} not found"
        )));
    };
    // `_ensure_customer_access`.
    if !auth.access(&ctx).await?.can_access(&customer) {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {customer}"
        )));
    }
    if role.as_deref() == Some("customer_user") {
        return Err(ApiError::bad_request(
            "Customer-generated reports are always visible to the customer.",
        ));
    }
    if current != visible {
        sqlx::query(
            "UPDATE incident_management_customer_reports SET visible_to_customer = ? WHERE id = ?",
        )
        .bind(visible)
        .bind(id)
        .execute(ctx.db.pool())
        .await
        .map_err(ApiError::internal)?;
    }
    let message = if visible {
        "Report is now visible to the customer."
    } else {
        "Report is now hidden from the customer."
    };
    Ok(json(json!({
        "success": true,
        "message": message,
        "report_id": id,
        "visible_to_customer": visible,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(filters: Option<&str>, status: &str) -> Report {
        let t = NaiveDateTime::default();
        Report {
            id: 4,
            report_name: "r".into(),
            customer_code: "c".into(),
            file_name: "f.pdf".into(),
            file_size: 0,
            generated_at: t,
            generated_by: 1,
            generated_by_role: None,
            date_from: t,
            date_to: t,
            filters_json: filters.map(str::to_string),
            total_alerts: 0,
            total_cases: 0,
            open_cases: 0,
            closed_cases: 0,
            visible_to_customer: false,
            status: status.into(),
            error_message: None,
        }
    }

    #[test]
    fn filters_and_download_url_follow_to_response() {
        let r = report(Some(r#"{"b": 1, "a": [true, null]}"#), "completed")
            .to_json(Some("admin"))
            .unwrap();
        assert_eq!(
            serde_json::to_string(&r["filters_applied"]).unwrap(),
            r#"{"b":1,"a":[true,null]}"#
        );
        assert_eq!(
            r["download_url"],
            json!("/api/v1/incidents/customer_reports/4/download")
        );
        let r = report(Some("not json"), "processing")
            .to_json(None)
            .unwrap();
        assert_eq!(r["filters_applied"], json!({}));
        assert_eq!(r["download_url"], Value::Null);
        let err = report(Some("[1]"), "failed").to_json(None).unwrap_err();
        assert!(format!("{err:?}").contains("input_value=[1], input_type=list"));
    }
}
