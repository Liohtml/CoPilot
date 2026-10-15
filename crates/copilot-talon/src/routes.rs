//! `/api/talon` — port of `app/connectors/talon/routes/talon.py`.
//!
//! | Method | Path | Notes |
//! |---|---|---|
//! | POST | `/message` | SSE passthrough of Talon's `/message`; lane = caller |
//! | POST | `/investigate` | alert must exist, be the caller's, match `customer_code` |
//! | POST | `/session/reset` | clears only the caller's lane |
//! | GET | `/session/context` | the caller's lane size; never an error |
//! | GET | `/status` | Talon's `/status` |
//! | GET | `/templates` | prompt templates for the replay picker |
//! | GET | `/jobs/{alert_id}` | database only; **now tenancy-checked** (Python was not) |
//!
//! All routes: `require_any_scope("admin", "analyst")`.

use std::convert::Infallible;

use axum::Router;
use axum::body::Body;
use axum::extract::{FromRef, Path, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{Value, json};

use copilot_db::alerts;
use copilot_web::validate::{IntRules, StrRules, Validator, parse_json_body, path_int};
use copilot_web::{AdminOrAnalyst, ApiResult, AppContext, Authorized, ok};

use crate::client::TalonConnector;
use crate::services;

/// State of the Talon routes.
#[derive(Clone, Debug)]
pub struct TalonState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Talon connector.
    pub talon: TalonConnector,
}

impl FromRef<TalonState> for AppContext {
    fn from_ref(s: &TalonState) -> AppContext {
        s.ctx.clone()
    }
}

/// The router, to be nested at `/api/talon`.
pub fn router(state: TalonState) -> Router {
    Router::new()
        .route("/message", post(send_message))
        .route("/investigate", post(trigger_investigation))
        .route("/session/reset", post(reset_session))
        .route("/session/context", get(session_context))
        .route("/status", get(status))
        .route("/templates", get(templates))
        .route("/jobs/{alert_id}", get(job))
        .with_state(state)
}

fn sse_error_frame(message: &str) -> Bytes {
    let body = json!({ "error": message });
    Bytes::from(format!("data: {body}\n\n"))
}

async fn send_message(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<TalonState>,
    body: Bytes,
) -> ApiResult {
    let value = parse_json_body(&body)?;
    let mut v = Validator::new();
    let root = vec![copilot_web::validate::LocPart::Key("body".into())];
    let (message, sender) = match v.object(&value, &root) {
        Some(obj) => (
            v.req_str(obj, &root, "message", StrRules::any()),
            v.str_or(obj, &root, "sender", StrRules::any(), "copilot"),
        ),
        None => (String::new(), String::new()),
    };
    v.finish()?;
    tracing::info!(user_id = auth.id, "sending message to Talon");
    let payload = services::message_payload(&message, &sender, &auth);
    let stream: futures::stream::BoxStream<'static, Result<Bytes, Infallible>> =
        match st.talon.post_stream("/message", &payload).await {
            Ok(resp) => resp
                .bytes_stream()
                .scan(false, |failed, item| {
                    let out = if *failed {
                        None
                    } else {
                        match item {
                            Ok(chunk) => Some(chunk),
                            Err(e) => {
                                *failed = true;
                                tracing::error!(err = %e, "Talon /message stream broke");
                                Some(sse_error_frame("Failed to stream from /message"))
                            }
                        }
                    };
                    futures::future::ready(out)
                })
                .map(Ok)
                .boxed(),
            Err(crate::client::TalonError::NotConfigured) => futures::stream::once(async {
                Ok(sse_error_frame("No Talon connector found in the database"))
            })
            .boxed(),
            Err(e) => {
                tracing::error!(err = %e, "failed to stream from Talon /message");
                futures::stream::once(async {
                    Ok(sse_error_frame("Failed to stream from /message"))
                })
                .boxed()
            }
        };
    Ok((
        [
            (
                http::header::CONTENT_TYPE,
                "text/event-stream; charset=utf-8",
            ),
            (http::header::CACHE_CONTROL, "no-cache"),
            (http::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

async fn trigger_investigation(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<TalonState>,
    body: Bytes,
) -> ApiResult {
    let value = parse_json_body(&body)?;
    let mut v = Validator::new();
    let root = vec![copilot_web::validate::LocPart::Key("body".into())];
    let (alert_id, customer_code) = match v.object(&value, &root) {
        Some(obj) => {
            let alert_id = v.req_int(obj, &root, "alert_id", IntRules::default());
            let code = v.req_str(obj, &root, "customer_code", StrRules::max(64));
            v.str_or(obj, &root, "sender", StrRules::any(), "copilot");
            (alert_id, code)
        }
        None => (0, String::new()),
    };
    v.finish()?;
    tracing::info!(alert_id, "triggering Talon investigation");
    let data =
        services::investigate_alert_for_user(&st.ctx, &st.talon, &auth, alert_id, &customer_code)
            .await?;
    Ok(ok(
        "Investigation triggered successfully",
        json!({ "data": data }),
    ))
}

async fn reset_session(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<TalonState>,
) -> ApiResult {
    tracing::info!(user_id = auth.id, "resetting Talon session");
    let cleared = services::reset_session(&st.talon, auth.id).await?;
    Ok(ok(
        "Talon session cleared",
        json!({ "lanes_cleared": cleared }),
    ))
}

async fn session_context(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<TalonState>,
) -> ApiResult {
    let c = services::session_context(&st.talon, auth.id).await;
    Ok(ok(c.message, &c))
}

async fn status(_auth: Authorized<AdminOrAnalyst>, State(st): State<TalonState>) -> ApiResult {
    let data = services::status(&st.talon).await?;
    let data = if data.is_object() { data } else { Value::Null };
    Ok(ok(
        "Talon status retrieved successfully",
        json!({ "data": data }),
    ))
}

async fn templates(_auth: Authorized<AdminOrAnalyst>, State(st): State<TalonState>) -> ApiResult {
    let templates = services::templates(&st.talon).await?;
    Ok(ok(
        format!("{} templates retrieved", templates.len()),
        json!({ "templates": templates }),
    ))
}

async fn job(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = path_int("alert_id", &raw)?;
    let owner = alerts::alert_customer_code(&st.ctx.db, alert_id).await?;
    auth.enforce_owned(&st.ctx, owner.as_deref(), &format!("alert {alert_id}"))
        .await?;
    let data = services::talon_job(&st.ctx, alert_id).await?;
    Ok(ok(
        "Talon job retrieved successfully",
        json!({ "data": data }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_frame_is_python_shaped() {
        assert_eq!(
            sse_error_frame("Failed to stream from /message"),
            Bytes::from("data: {\"error\":\"Failed to stream from /message\"}\n\n")
        );
    }
}
