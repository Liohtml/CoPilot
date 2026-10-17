//! `/api/logs` — the six routes of `app/utils.py:logs_router`, each guarded
//! by `Security(get_current_user, scopes=["admin"])` as in Python.
//!
//! Route order is Python's: `POST /timerange` is declared before
//! `POST /{event_type}`, `DELETE ""` and `DELETE /timerange` are the two
//! purges.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Ty, field, validate_ty};
use copilot_upstream::respond::body_model;
use copilot_web::validate::{FieldError, LocPart};
use copilot_web::{AdminOnly, ApiError, ApiResult, AppContext, JsonBody, ScopedUser, WithJson};

use super::schema::{
    EVENT_TYPES, LogOut, LogRow, LogsResponse, TIME_RANGE_MODEL, event_type_format,
};
use super::services::{self, TimeRangeError, validate_time_range, window_start};

type Admin = ScopedUser<AdminOnly>;

/// The router to nest at `/api/logs`.
pub fn router(ctx: AppContext) -> Router {
    Router::new()
        .route("/", get(get_logs).delete(purge_logs))
        // `GET /timerange` is `GET /{user_id}` in Starlette (its 422).
        .route(
            "/timerange",
            get(timerange_as_user_id)
                .post(logs_by_time_range)
                .delete(purge_logs_by_time_range),
        )
        .route("/{segment}", get(logs_by_user_id).post(logs_by_event_type))
        .with_state(ctx)
}

fn answer(logs: Vec<LogRow>, message: &str) -> Response {
    Json(LogsResponse {
        logs: logs.into_iter().map(LogOut::from).collect(),
        success: true,
        message: message.to_string(),
    })
    .into_response()
}

const FETCHED: &str = "Logs fetched successfully";
const PURGED: &str = "Logs purged successfully";

fn no_logs() -> ApiError {
    ApiError::not_found("No logs found")
}

async fn get_logs(_admin: Admin, State(ctx): State<AppContext>) -> ApiResult {
    let logs = services::all_logs(&ctx.db).await?;
    if logs.is_empty() {
        return Err(no_logs());
    }
    Ok(answer(logs, FETCHED))
}

/// A path value validated as one parameter: the 422 FastAPI reports.
fn path_error(name: &str, kind: &str, msg: String) -> ApiError {
    ApiError::Validation(vec![
        FieldError {
            kind: kind.to_string(),
            loc: vec![LocPart::Key("path".into()), LocPart::Key(name.into())],
            msg,
        }
        .to_item(),
    ])
}

async fn logs_by_user_id(
    _admin: Admin,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    user_logs(&ctx, raw).await
}

async fn timerange_as_user_id(_admin: Admin, State(ctx): State<AppContext>) -> ApiResult {
    user_logs(&ctx, "timerange".into()).await
}

async fn user_logs(ctx: &AppContext, raw: String) -> ApiResult {
    // `user_id: int` read from the path with Pydantic's lax rules (`" 7 "`,
    // `"1_0"`, `"7.0"` are ints; Python's ints have no size limit).
    let user_id = match validate_ty(&Ty::Int, &PyValue::Str(raw)) {
        Ok(PyValue::Int(digits)) => digits,
        Ok(_) => return Err(ApiError::internal("int validation gave a non-int")),
        Err(copilot_upstream::model::Invalid::Errors(errors)) => {
            let first = errors.into_iter().next();
            let (kind, msg) = first.map_or(("int_parsing", String::new()), |e| (e.kind, e.msg));
            return Err(path_error("user_id", kind, msg));
        }
        Err(copilot_upstream::model::Invalid::Abort(..)) => {
            return Err(ApiError::internal("int validation aborted"));
        }
    };
    // A value beyond 64 bits matches no `int` column.
    let logs = match user_id.parse::<i64>() {
        Ok(id) => services::logs_of_user(&ctx.db, id).await?,
        Err(_) => Vec::new(),
    };
    if logs.is_empty() {
        return Err(ApiError::not_found(format!(
            "No logs found for user ID: {user_id}"
        )));
    }
    Ok(answer(logs, FETCHED))
}

/// The body as `TimeRangeModel`, its validator applied.
fn time_range(body: &JsonBody) -> Result<String, ApiError> {
    let dump = body_model(body, &TIME_RANGE_MODEL)?;
    match validate_time_range(field(&dump, "time_range")) {
        Ok(v) => Ok(v),
        Err(TimeRangeError::Invalid(msg)) => Err(ApiError::Validation(vec![
            FieldError {
                kind: "value_error.time_range".into(),
                loc: vec![LocPart::Key("time_range".into())],
                msg: msg.into(),
            }
            .to_item(),
        ])),
        Err(TimeRangeError::Crash(cause)) => Err(ApiError::internal(cause)),
    }
}

/// The rows within the window, read and filtered as Python does (every row
/// read; nothing filtered when there is none).
async fn rows_in_range(ctx: &AppContext, range: &str) -> Result<Vec<LogRow>, ApiError> {
    let logs = services::all_logs(&ctx.db).await?;
    if logs.is_empty() {
        return Err(no_logs());
    }
    let start = window_start(range, chrono::Local::now().naive_local())
        .map_err(|e| ApiError::internal(format!("OverflowError: {e}")))?;
    let kept: Vec<LogRow> = logs.into_iter().filter(|l| l.timestamp >= start).collect();
    if kept.is_empty() {
        return Err(ApiError::not_found(format!(
            "No logs found for time range: {range}"
        )));
    }
    Ok(kept)
}

async fn logs_by_time_range(
    State(ctx): State<AppContext>,
    WithJson(_admin, body): WithJson<Admin>,
) -> ApiResult {
    let range = time_range(&body)?;
    let kept = rows_in_range(&ctx, &range).await?;
    Ok(answer(kept, FETCHED))
}

async fn logs_by_event_type(
    _admin: Admin,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let Some(value) = EVENT_TYPES.iter().find(|v| **v == raw) else {
        return Err(path_error(
            "event_type",
            "enum",
            "Input should be 'Info' or 'Error'".into(),
        ));
    };
    let logs = services::logs_of_event_type(&ctx.db, value).await?;
    if logs.is_empty() {
        return Err(ApiError::not_found(format!(
            "No logs found for event type: {}",
            event_type_format(value)
        )));
    }
    Ok(answer(logs, FETCHED))
}

async fn purge_logs(_admin: Admin, State(ctx): State<AppContext>) -> ApiResult {
    let logs = services::all_logs(&ctx.db).await?;
    if logs.is_empty() {
        return Err(no_logs());
    }
    services::delete_rows(&ctx.db, &logs).await?;
    Ok(answer(Vec::new(), PURGED))
}

async fn purge_logs_by_time_range(
    State(ctx): State<AppContext>,
    WithJson(_admin, body): WithJson<Admin>,
) -> ApiResult {
    let range = time_range(&body)?;
    let kept = rows_in_range(&ctx, &range).await?;
    services::delete_rows(&ctx.db, &kept).await?;
    Ok(answer(Vec::new(), PURGED))
}
