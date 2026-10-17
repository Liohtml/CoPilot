//! Port of `app/customer_portal/routes/errors.py`.

use copilot_web::ApiError;

/// `internal_errors(action)`: a service's `HTTPException` (403/404) passes
/// through; anything unexpected is logged with its cause and answered as
/// `500 Failed to <action>` — never `str(e)`, which carries SQL.
pub fn internal_errors<T>(action: &str, result: Result<T, ApiError>) -> Result<T, ApiError> {
    result.map_err(|e| match e {
        ApiError::Internal(cause) => {
            tracing::error!(%cause, "Failed to {action}");
            ApiError::server_error(format!("Failed to {action}"))
        }
        other => other,
    })
}
