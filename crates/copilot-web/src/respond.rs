//! Success responses. CoPilot's response models all start with
//! `success` and `message`; payload keys follow.

use axum::Json;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Map, Value};

/// `200 {"success": true, "message": message, ...payload}`. `payload` must
/// serialize to an object (its keys are appended in order).
pub fn ok(message: impl Into<String>, payload: impl Serialize) -> Response {
    envelope(true, message, payload)
}

/// The envelope with an explicit `success` flag (some routes answer 200 with
/// `success: false`).
pub fn envelope(success: bool, message: impl Into<String>, payload: impl Serialize) -> Response {
    let mut body = Map::new();
    body.insert("success".into(), Value::Bool(success));
    body.insert("message".into(), Value::String(message.into()));
    match serde_json::to_value(payload) {
        Ok(Value::Object(extra)) => body.extend(extra),
        Ok(Value::Null) => {}
        Ok(other) => {
            tracing::error!(?other, "response payload is not an object");
        }
        Err(e) => {
            tracing::error!(err = %e, "response payload failed to serialize");
        }
    }
    Json(Value::Object(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn keys_follow_the_envelope() {
        let resp = ok("Jobs retrieved", json!({"jobs": []}));
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"success":true,"message":"Jobs retrieved","jobs":[]}"#
        );
    }
}
