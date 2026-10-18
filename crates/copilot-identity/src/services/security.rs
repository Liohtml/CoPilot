//! The admin Security tab — `app/auth/services/security_admin.py` and the
//! template-resolution half of `app/auth/services/temp_password_email.py`.

use copilot_auth::pyvalue::str_repr;
use copilot_core::config::{SmtpEnv, python_int};
use copilot_core::roles::Role;
use copilot_db::security::{self, TemplateRow};
use copilot_db::users::{self, UserRow};
use copilot_web::{ApiError, CurrentUser};

use crate::IdentityState;
use crate::security_schema::{SecurityUser, TemplateOption, TemplateOptions};

/// The `notification_template.trigger` of a temporary-password email.
pub const TEMPLATE_TRIGGER: &str = "temp_password_issued";

/// Formats this sender can put in an email (`markdown` goes out as text).
pub const SUPPORTED_FORMATS: [&str; 3] = ["text", "markdown", "html"];

/// `_smtp_config()`, resolved.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// `SMTP_HOST`.
    pub host: String,
    /// `int(SMTP_PORT or "587")`.
    pub port: i64,
    /// `SMTP_USERNAME`.
    pub username: Option<String>,
    /// `SMTP_PASSWORD`.
    pub password: Option<String>,
    /// `SMTP_FROM or SMTP_USERNAME or "no-reply@copilot.local"`.
    pub from_addr: String,
    /// `SMTP_USE_TLS` in `1`/`true`/`yes` (default `true`).
    pub use_tls: bool,
}

/// `_smtp_config()`: `None` without a host. `SMTP_PORT` is read with
/// `int()` on every call, so a malformed one is the request's `ValueError`
/// (400), as in Python.
pub fn smtp_config(env: &SmtpEnv) -> Result<Option<SmtpConfig>, ApiError> {
    let Some(host) = env.host.clone().filter(|h| !h.is_empty()) else {
        return Ok(None);
    };
    let raw_port = env.port.clone().unwrap_or_else(|| "587".into());
    // A literal too large for i64 is still an int to Python; it fails only
    // when the connection is made, as any port over 65535 does.
    let port = python_int(&raw_port)
        .or_else(|| is_int_literal(&raw_port).then_some(i64::MAX))
        .ok_or_else(|| {
            // `%.200R`: CPython cuts the repr of a long literal.
            let repr: String = str_repr(&raw_port).chars().take(200).collect();
            ApiError::bad_request(format!("invalid literal for int() with base 10: {repr}"))
        })?;
    let username = env.username.clone();
    let from_addr = [env.from.clone(), username.clone()]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| "no-reply@copilot.local".into());
    let use_tls = env.use_tls.as_deref().unwrap_or("true").to_lowercase();
    Ok(Some(SmtpConfig {
        host,
        port,
        username,
        password: env.password.as_ref().map(|p| p.expose().to_string()),
        from_addr,
        use_tls: matches!(use_tls.as_str(), "1" | "true" | "yes"),
    }))
}

/// Python's `int()` syntax for a base-10 literal, without a range limit.
fn is_int_literal(text: &str) -> bool {
    let t = text.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_')
}

/// `smtp_configured()`.
pub fn smtp_configured(st: &IdentityState) -> Result<bool, ApiError> {
    Ok(smtp_config(&st.smtp)?.is_some())
}

/// `list_customer_users(customer_code)`.
pub async fn customer_users(
    st: &IdentityState,
    customer_code: &str,
) -> Result<Vec<SecurityUser>, ApiError> {
    let found = security::customer_users(&st.ctx.db, customer_code).await?;
    if found.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i32> = found.iter().map(|u| u.id).collect();
    let totp = security::totp_enabled(&st.ctx.db, &ids).await?;
    Ok(found
        .into_iter()
        .map(|u| SecurityUser {
            role_name: u
                .role_id
                .and_then(Role::from_id)
                .map(|r| r.name().to_string()),
            totp_enabled: totp.get(&u.id).copied().unwrap_or(false),
            id: u.id,
            username: u.username,
            email: u.email,
            role_id: u.role_id,
            last_login_at: u.last_login_at,
        })
        .collect())
}

/// `_get_user_or_404(user_id)`.
pub async fn user_or_404(st: &IdentityState, user_id: i64) -> Result<UserRow, ApiError> {
    let found = match i32::try_from(user_id) {
        Ok(id) => users::find_by_id(&st.ctx.db, id).await?,
        Err(_) => None,
    };
    found.ok_or_else(|| ApiError::not_found(format!("User {user_id} not found")))
}

/// `force_reset_user_totp`: the reset, then the audit row.
pub async fn reset_totp(
    st: &IdentityState,
    actor: &CurrentUser,
    user_id: i64,
) -> Result<&'static str, ApiError> {
    let user = user_or_404(st, user_id).await?;
    let removed = security::delete_totp(&st.ctx.db, user.id).await?;
    let details = format!(
        "Forced TOTP (2FA) reset by admin ({})",
        if removed {
            "removed"
        } else {
            "no enrolment present"
        }
    );
    audit(st, actor, &user.username, details);
    tracing::info!(
        actor = %actor.username,
        user = %user.username,
        removed,
        "admin force-reset TOTP"
    );
    Ok(if removed {
        "Two-factor authentication has been reset."
    } else {
        "The user had no two-factor authentication configured."
    })
}

/// A `user.update` audit row about `username` (`record_audit_event`, which
/// never fails the request).
pub fn audit(st: &IdentityState, actor: &CurrentUser, username: &str, details: String) {
    st.ctx.audit.record(
        copilot_core::audit::AuditRecord::new("user.update")
            .actor(Some(actor.id), Some(&actor.username))
            .entity("user", username)
            .details(details)
            .source_ip(actor.source_ip.clone()),
    );
}

/// `resolve_customer_code(user, requested)`: a requested code must be one
/// of the user's (compared exactly); without one, the user's only customer,
/// else `None`.
pub async fn resolve_customer_code(
    st: &IdentityState,
    user: &UserRow,
    requested: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let codes = users::assigned_customer_codes(&st.ctx.db, user.id).await?;
    match requested.filter(|r| !r.is_empty()) {
        Some(requested) if codes.iter().any(|c| c == requested) => Ok(Some(requested.into())),
        Some(requested) => Err(ApiError::bad_request(format!(
            "User {} does not have access to customer {}.",
            str_repr(&user.username),
            str_repr(requested)
        ))),
        None if codes.len() == 1 => Ok(codes.into_iter().next()),
        None => Ok(None),
    }
}

/// `list_available_templates(customer_code)`: the trigger's templates,
/// newest edit first, then stably by scope — this customer's, shared,
/// built-in; another customer's never.
pub async fn available_templates(
    st: &IdentityState,
    customer_code: Option<&str>,
) -> Result<Vec<TemplateRow>, ApiError> {
    let rank = |t: &TemplateRow| -> u8 {
        match (&t.customer_code, customer_code) {
            (Some(own), Some(wanted)) if !wanted.is_empty() && own == wanted => 0,
            (None, _) if !t.is_default => 1,
            (None, _) => 2,
            _ => 3,
        }
    };
    let mut found: Vec<TemplateRow> = security::templates_for_trigger(&st.ctx.db, TEMPLATE_TRIGGER)
        .await?
        .into_iter()
        .filter(|t| rank(t) < 3)
        .collect();
    found.sort_by_key(|t| rank(t));
    Ok(found)
}

/// `get_temp_password_email_options`.
pub async fn template_options(
    st: &IdentityState,
    user_id: i64,
    requested: Option<&str>,
) -> Result<TemplateOptions, ApiError> {
    let user = user_or_404(st, user_id).await?;
    let code = resolve_customer_code(st, &user, requested).await?;
    let options: Vec<TemplateOption> = available_templates(st, code.as_deref())
        .await?
        .into_iter()
        .filter(|t| SUPPORTED_FORMATS.contains(&t.format.as_str()))
        .map(|t| TemplateOption {
            id: t.id,
            name: t.name,
            description: t.description,
            format: t.format,
            customer_code: t.customer_code,
            is_default: t.is_default,
        })
        .collect();
    Ok(TemplateOptions {
        resolved_template_id: options.first().map(|t| t.id),
        message: format!("{} template(s) available", options.len()),
        templates: options,
        customer_code: code,
        smtp_configured: smtp_configured(st)?,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_core::config::Secret;

    fn env(pairs: &[(&str, &str)]) -> SmtpEnv {
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        };
        SmtpEnv {
            host: get("SMTP_HOST"),
            port: get("SMTP_PORT"),
            username: get("SMTP_USERNAME"),
            password: get("SMTP_PASSWORD").map(Secret::new),
            from: get("SMTP_FROM"),
            use_tls: get("SMTP_USE_TLS"),
        }
    }

    #[test]
    fn smtp_settings_read_like_python() {
        assert!(smtp_config(&env(&[])).unwrap().is_none());
        assert!(smtp_config(&env(&[("SMTP_HOST", "")])).unwrap().is_none());
        // Without a host nothing else is read, not even a broken port.
        assert!(smtp_config(&env(&[("SMTP_PORT", "x")])).unwrap().is_none());

        let c = smtp_config(&env(&[("SMTP_HOST", "mx")])).unwrap().unwrap();
        assert_eq!((c.port, c.use_tls), (587, true));
        assert_eq!(c.from_addr, "no-reply@copilot.local");

        let c = smtp_config(&env(&[
            ("SMTP_HOST", "mx"),
            ("SMTP_PORT", " +2_5 "),
            ("SMTP_USERNAME", "bot@x"),
            ("SMTP_FROM", ""),
            ("SMTP_USE_TLS", "YES"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!((c.port, c.use_tls), (25, true));
        assert_eq!(c.from_addr, "bot@x");
        for (raw, tls) in [("1", true), ("True", true), ("on", false), ("", false)] {
            let c = smtp_config(&env(&[("SMTP_HOST", "mx"), ("SMTP_USE_TLS", raw)]))
                .unwrap()
                .unwrap();
            assert_eq!(c.use_tls, tls, "{raw:?}");
        }

        let err = |port: &str| match smtp_config(&env(&[("SMTP_HOST", "mx"), ("SMTP_PORT", port)]))
        {
            Err(ApiError::Http { detail, .. }) => detail.as_str().unwrap_or_default().to_string(),
            other => panic!("{other:?}"),
        };
        assert_eq!(err(""), "invalid literal for int() with base 10: ''");
        assert_eq!(
            err("it's"),
            "invalid literal for int() with base 10: \"it's\""
        );
        assert_eq!(
            err("1__0"),
            "invalid literal for int() with base 10: '1__0'"
        );
        assert_eq!(err(&"x".repeat(300)).chars().count(), 40 + 200);
        // Too large for i64, still an int: it fails when the connection is made.
        let big = smtp_config(&env(&[("SMTP_HOST", "mx"), ("SMTP_PORT", &"9".repeat(30))]));
        assert_eq!(big.unwrap().unwrap().port, i64::MAX);
    }
}
