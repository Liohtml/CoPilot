//! The temporary-password email's template variables
//! (`app/auth/services/temp_password_email.py`: `build_event`,
//! `build_extra_context`, `login_url`). Shared by the sender
//! (`copilot_identity::services::temp_password`) and the template editor's
//! preview (`POST /notifications/templates/preview` with
//! `trigger=temp_password_issued`), so both render the same names.

use copilot_jinja::{Event, Input};
use copilot_web::form::py_strip;

/// The template scope of the email (not a dispatch trigger).
pub const TEMPLATE_TRIGGER: &str = "temp_password_issued";

/// Rendered in every preview instead of a real password.
pub const PREVIEW_PASSWORD: &str = "PREVIEW-Not-A-Real-Password";

/// The subject without a template, or when one renders blank.
pub const DEFAULT_SUBJECT: &str = "CoPilot — temporary password";

/// The event's `summary`.
pub const SUMMARY: &str = "An administrator has issued a temporary password for your CoPilot \
                           account. Sign in with it and change it immediately.";

/// `login_url()`: `COPILOT_URL` + `/login`, or "" without one.
pub fn login_url(copilot_url: Option<&str>) -> String {
    let base = py_strip(copilot_url.unwrap_or_default()).trim_end_matches('/');
    if base.is_empty() {
        String::new()
    } else {
        format!("{base}/login")
    }
}

/// `build_event(username=…, customer_code=…, user_id=…)`.
pub fn event(
    username: &str,
    customer_code: Option<&str>,
    user_id: i64,
    copilot_url: Option<&str>,
) -> Event {
    let login = login_url(copilot_url);
    Event {
        customer_code: customer_code.map(str::to_string),
        trigger: TEMPLATE_TRIGGER.into(),
        severity: "Informational".into(),
        subject: DEFAULT_SUBJECT.into(),
        summary: SUMMARY.into(),
        entity_type: "user".into(),
        entity_id: user_id,
        dedupe_key: format!("user:{user_id}:{TEMPLATE_TRIGGER}"),
        link_url: (!login.is_empty()).then_some(login),
        assignee_username: None,
        actor_username: None,
        context: vec![("username".into(), username.into())],
    }
}

/// `build_extra_context(...)`: the top-level variables of the email.
pub fn extra_context(
    username: &str,
    email: &str,
    temp_password: &str,
    copilot_url: Option<&str>,
    customer_code: Option<&str>,
    customer_name: Option<&str>,
) -> Vec<(String, Input)> {
    let organization = customer_name
        .filter(|n| !n.is_empty())
        .or(customer_code.filter(|c| !c.is_empty()))
        .unwrap_or_default();
    vec![
        ("user_name".into(), username.into()),
        ("user_email".into(), email.into()),
        ("temp_password".into(), temp_password.into()),
        ("login_url".into(), login_url(copilot_url).into()),
        ("customer_name".into(), organization.into()),
        ("organization_name".into(), organization.into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_url_and_organization() {
        assert_eq!(
            login_url(Some(" https://c.example/ ")),
            "https://c.example/login"
        );
        assert_eq!(login_url(None), "");
        let extra = extra_context("jdoe", "j@x", "pw", None, Some("ACME"), None);
        assert_eq!(
            extra[4],
            ("customer_name".into(), Input::Str("ACME".into()))
        );
        let e = event("jdoe", Some("ACME"), 0, Some("https://c.example"));
        assert_eq!(e.dedupe_key, "user:0:temp_password_issued");
        assert_eq!(e.link_url.as_deref(), Some("https://c.example/login"));
    }
}
