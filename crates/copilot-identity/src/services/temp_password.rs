//! The temporary-password email (`app/auth/services/temp_password_email.py`
//! and the send half of `security_admin.py`): render the operator's template
//! (sandboxed Jinja2, `copilot_jinja`), rotate the password, send over SMTP.
//!
//! The order is load-bearing, as in Python: the template is rendered
//! *before* the password changes, so a broken template costs a 400 and
//! nobody is locked out; a delivery failure after the rotation is a 502
//! that says so.

use std::sync::OnceLock;
use std::time::Duration;

use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use regex::Regex;

use copilot_auth::pyvalue::str_repr;
use copilot_db::customers;
use copilot_db::security::TemplateRow;
use copilot_db::users::{self, UserRow};
use copilot_jinja::{Event, Input};
use copilot_web::form::py_strip;
use copilot_web::{ApiError, CurrentUser};

use crate::IdentityState;
use crate::security_schema::{Preview, TemplateChoice};
use crate::services::branding;
use crate::services::security::{
    self, SUPPORTED_FORMATS, SmtpConfig, TEMPLATE_TRIGGER, audit, resolve_customer_code,
    smtp_config, user_or_404,
};

/// Rendered in every preview instead of a real password.
pub const PREVIEW_PASSWORD: &str = "PREVIEW-Not-A-Real-Password";

/// The subject without a template, or when one renders blank.
pub const DEFAULT_SUBJECT: &str = "CoPilot — temporary password";

/// `TEMP_PASSWORD_LENGTH`.
const TEMP_PASSWORD_LENGTH: usize = 16;

const SUMMARY: &str = "An administrator has issued a temporary password for your CoPilot account. \
                       Sign in with it and change it immediately.";

/// `login_url()`: `COPILOT_URL` + `/login`, or "" without one.
pub fn login_url(copilot_url: Option<&str>) -> String {
    let base = py_strip(copilot_url.unwrap_or_default()).trim_end_matches('/');
    if base.is_empty() {
        String::new()
    } else {
        format!("{base}/login")
    }
}

/// `build_temp_password_email`: the plaintext body when no template applies.
pub fn plaintext_body(username: &str, temp_password: &str) -> String {
    format!(
        "Hello {username},\n\n\
         An administrator has issued a temporary password for your CoPilot account.\n\n\
         Temporary password: {temp_password}\n\n\
         For your security, please sign in with this password and change it immediately.\n\
         If you did not expect this change, contact your security team.\n"
    )
}

/// `Password.generate(16)`: one of each class, the rest from all four,
/// shuffled.
pub fn generate_password() -> String {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"@$!%*?&#";
    let pick = |set: &[u8]| char::from(set[OsRng.gen_range(0..set.len())]);
    let alphabet: Vec<u8> = [LOWER, UPPER, DIGITS, SPECIAL].concat();
    let mut chars: Vec<char> = vec![pick(LOWER), pick(UPPER), pick(DIGITS), pick(SPECIAL)];
    chars.extend((4..TEMP_PASSWORD_LENGTH).map(|_| pick(&alphabet)));
    chars.shuffle(&mut OsRng);
    chars.into_iter().collect()
}

fn regex(slot: &'static OnceLock<Option<Regex>>, pattern: &str) -> Option<&'static Regex> {
    slot.get_or_init(|| Regex::new(pattern).ok()).as_ref()
}

fn replace(
    text: String,
    slot: &'static OnceLock<Option<Regex>>,
    pattern: &str,
    with: &str,
) -> String {
    match regex(slot, pattern) {
        Some(re) => re.replace_all(&text, with).into_owned(),
        None => text,
    }
}

/// `html_to_text`: the plaintext part of an HTML email.
pub fn html_to_text(html: &str) -> String {
    static SCRIPT: OnceLock<Option<Regex>> = OnceLock::new();
    static BR: OnceLock<Option<Regex>> = OnceLock::new();
    static BLOCK: OnceLock<Option<Regex>> = OnceLock::new();
    static TAG: OnceLock<Option<Regex>> = OnceLock::new();
    static TRAILING: OnceLock<Option<Regex>> = OnceLock::new();
    static BLANKS: OnceLock<Option<Regex>> = OnceLock::new();
    // `<(script|style)\b.*?</\1>`: the backreference is one alternative per tag.
    let mut text = replace(
        html.to_string(),
        &SCRIPT,
        r"(?is)<script\b.*?</script>|<style\b.*?</style>",
        "",
    );
    text = replace(text, &BR, r"(?i)<br\s*/?>", "\n");
    text = replace(text, &BLOCK, r"(?i)</(p|div|tr|li|h[1-6]|table)\s*>", "\n");
    text = replace(text, &TAG, r"(?s)<[^>]+>", "");
    for (entity, c) in [
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
    ] {
        text = text.replace(entity, c);
    }
    text = replace(text, &TRAILING, r"[ \t]+\n", "\n");
    text = replace(text, &BLANKS, r"\n{3,}", "\n\n");
    py_strip(&text).to_string()
}

/// `" ".join(s.split())`.
fn collapse_whitespace(s: &str) -> String {
    s.split(copilot_web::form::is_py_space)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `resolve_template(customer_code, template_id)`: the per-send override,
/// checked; else the best available template; else none (the plaintext).
pub async fn resolve_template(
    st: &IdentityState,
    customer_code: Option<&str>,
    template_id: Option<i64>,
) -> Result<Option<TemplateRow>, ApiError> {
    let Some(id) = template_id else {
        return Ok(security::available_templates(st, customer_code)
            .await?
            .into_iter()
            .next());
    };
    let template = copilot_db::security::template(&st.ctx.db, id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Template {id} not found")))?;
    if template.trigger.as_deref() != Some(TEMPLATE_TRIGGER) {
        return Err(ApiError::bad_request(
            "That template is not a temporary-password email template. Set its trigger to \
             'Temporary password issued' to use it here.",
        ));
    }
    if let Some(owner) = template.customer_code.as_deref().filter(|c| !c.is_empty()) {
        if Some(owner) != customer_code {
            return Err(ApiError::bad_request(format!(
                "That template belongs to customer {}, not {}.",
                str_repr(owner),
                customer_code.map_or_else(|| "None".to_string(), str_repr)
            )));
        }
    }
    if !SUPPORTED_FORMATS.contains(&template.format.as_str()) {
        return Err(ApiError::bad_request(format!(
            "A {} template cannot be sent as an email (supported: ['text', 'markdown', 'html']).",
            str_repr(&template.format)
        )));
    }
    Ok(Some(template))
}

/// `customer_name_for(customer_code)`.
async fn customer_name(
    st: &IdentityState,
    customer_code: Option<&str>,
) -> Result<Option<String>, ApiError> {
    match customer_code.filter(|c| !c.is_empty()) {
        Some(code) => Ok(customers::find_customer(&st.ctx.db, code)
            .await?
            .map(|c| c.customer_name)),
        None => Ok(None),
    }
}

/// A rendered email: subject, the text part, the HTML part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    /// Subject (one line).
    pub subject: String,
    /// The text part.
    pub text: String,
    /// The HTML part, for an HTML template.
    pub html: Option<String>,
}

/// Who the email is for.
pub struct Recipient<'a> {
    /// The user.
    pub user: &'a UserRow,
    /// The password to put in it.
    pub temp_password: &'a str,
    /// The customer whose template and branding apply.
    pub customer_code: Option<&'a str>,
    /// That customer's display name.
    pub customer_name: Option<&'a str>,
}

async fn render(
    source: &str,
    event: &Event,
    autoescape: bool,
    extra: &[(String, Input)],
) -> Result<String, copilot_jinja::Error> {
    let (source, event, extra) = (source.to_string(), event.clone(), extra.to_vec());
    tokio::task::spawn_blocking(move || copilot_jinja::render(&source, &event, autoescape, &extra))
        .await
        .unwrap_or_else(|e| Err(copilot_jinja::Error::new("RuntimeError", e.to_string())))
}

/// `render_email`: the template rendered for this user, or the plaintext
/// body without one. A template error is returned, never papered over.
pub async fn render_email(
    st: &IdentityState,
    template: Option<&TemplateRow>,
    to: &Recipient<'_>,
) -> Result<Email, copilot_jinja::Error> {
    let Some(template) = template else {
        return Ok(Email {
            subject: DEFAULT_SUBJECT.into(),
            text: plaintext_body(&to.user.username, to.temp_password),
            html: None,
        });
    };
    let login = login_url(st.ctx.notification_defaults.copilot_url.as_deref());
    let event = Event {
        customer_code: to.customer_code.map(str::to_string),
        trigger: TEMPLATE_TRIGGER.into(),
        severity: "Informational".into(),
        subject: DEFAULT_SUBJECT.into(),
        summary: SUMMARY.into(),
        entity_type: "user".into(),
        entity_id: i64::from(to.user.id),
        dedupe_key: format!("user:{}:{TEMPLATE_TRIGGER}", to.user.id),
        link_url: (!login.is_empty()).then(|| login.clone()),
        assignee_username: None,
        actor_username: None,
        context: vec![("username".into(), to.user.username.as_str().into())],
    };
    let organization = to
        .customer_name
        .filter(|n| !n.is_empty())
        .or(to.customer_code)
        .unwrap_or_default();
    let mut extra: Vec<(String, Input)> = vec![
        ("user_name".into(), to.user.username.as_str().into()),
        ("user_email".into(), to.user.email.as_str().into()),
        ("temp_password".into(), to.temp_password.into()),
        ("login_url".into(), login.into()),
        ("customer_name".into(), organization.into()),
        ("organization_name".into(), organization.into()),
    ];
    let subject_source = template.subject_template.as_deref().unwrap_or_default();
    if template.body_template.contains("branding") || subject_source.contains("branding") {
        extra.push((
            "branding".into(),
            branding::context(&st.ctx.db, to.customer_code).await,
        ));
    }
    let is_html = template.format == "html";
    let body = render(&template.body_template, &event, is_html, &extra).await?;
    let mut subject = DEFAULT_SUBJECT.to_string();
    if !subject_source.is_empty() {
        subject = collapse_whitespace(&render(subject_source, &event, is_html, &extra).await?);
        if subject.is_empty() {
            subject = DEFAULT_SUBJECT.into();
        }
    }
    Ok(if is_html {
        Email {
            subject,
            text: html_to_text(&body),
            html: Some(body),
        }
    } else {
        Email {
            subject,
            text: body,
            html: None,
        }
    })
}

/// `preview_temp_password_email`: the email this user would get, with the
/// placeholder password; a template error is shown, not raised.
pub async fn preview(
    st: &IdentityState,
    user_id: i64,
    choice: &TemplateChoice,
) -> Result<Preview, ApiError> {
    let user = user_or_404(st, user_id).await?;
    let code = resolve_customer_code(st, &user, choice.customer_code.as_deref()).await?;
    let template = resolve_template(st, code.as_deref(), choice.template_id).await?;
    let name = customer_name(st, code.as_deref()).await?;
    let to = Recipient {
        user: &user,
        temp_password: PREVIEW_PASSWORD,
        customer_code: code.as_deref(),
        customer_name: name.as_deref(),
    };
    Ok(match render_email(st, template.as_ref(), &to).await {
        Ok(email) => Preview {
            subject: Some(email.subject),
            format: if email.html.is_some() { "html" } else { "text" },
            body: email.html.unwrap_or(email.text),
            error: None,
            success: true,
            message: "Rendered",
        },
        Err(e) => {
            tracing::warn!(
                template = template.as_ref().map(|t| t.id),
                "temp-password preview failed: {}: {}",
                e.kind,
                e.message
            );
            Preview {
                subject: None,
                body: String::new(),
                format: "text",
                error: Some(format!("{}: {}", e.kind, e.message)),
                success: false,
                message: "Template failed to render",
            }
        }
    })
}

/// `send_temp_password`: render, rotate, send, audit. Returns the success
/// message.
pub async fn send(
    st: &IdentityState,
    actor: &CurrentUser,
    user_id: i64,
    choice: &TemplateChoice,
) -> Result<String, ApiError> {
    let Some(smtp) = smtp_config(&st.smtp)? else {
        return Err(ApiError::bad_request(
            "SMTP is not configured; cannot send the temporary-password email.",
        ));
    };
    let user = user_or_404(st, user_id).await?;
    if user.email.is_empty() {
        return Err(ApiError::bad_request("User has no email address on file."));
    }
    let code = resolve_customer_code(st, &user, choice.customer_code.as_deref()).await?;
    let template = resolve_template(st, code.as_deref(), choice.template_id).await?;
    let name = customer_name(st, code.as_deref()).await?;

    let password = generate_password();
    let hash = {
        let password = password.clone();
        tokio::task::spawn_blocking(move || copilot_auth::password::hash_password(&password))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(|e| ApiError::internal(e.to_string()))?
    };
    let to = Recipient {
        user: &user,
        temp_password: &password,
        customer_code: code.as_deref(),
        customer_name: name.as_deref(),
    };
    let email = match render_email(st, template.as_ref(), &to).await {
        Ok(email) => email,
        Err(e) => {
            tracing::error!(
                template = template.as_ref().map(|t| t.id),
                user = %user.username,
                "temp-password template failed to render: {}",
                e.message
            );
            return Err(ApiError::bad_request(format!(
                "The email template could not be rendered, so nothing was sent and the password was \
                 left unchanged: {}: {}",
                e.kind, e.message
            )));
        }
    };

    users::set_password(&st.ctx.db, user.id, &hash).await?;
    if let Err(e) = send_mail(&smtp, &user.email, &email).await {
        tracing::error!(to = %user.email, error = %e, "failed to send the temp-password email");
        return Err(ApiError::http(
            http::StatusCode::BAD_GATEWAY,
            format!("The password was reset but the email could not be sent: {e}"),
        ));
    }
    tracing::info!(to = %user.email, subject = %email.subject, "sent security email");

    let note = match &template {
        Some(t) => format!("template {}", str_repr(&t.name)),
        None => "the built-in default body".into(),
    };
    audit(
        st,
        actor,
        &user.username,
        format!("Temporary password issued and emailed by admin using {note}"),
    );
    tracing::info!(
        actor = %actor.username,
        user = %user.username,
        "admin issued a temporary password using {note}"
    );
    Ok(format!(
        "A temporary password has been emailed to {}.",
        user.email
    ))
}

/// What `EmailMessage.set_content` makes of a text part
/// (`email.contentmanager._encode_text`): its lines (split at `\r\n`, `\r`
/// and `\n`, like `bytes.splitlines`) joined by `\n`, with a final `\n`.
fn mime_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 1);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// `_send_email_blocking`: plaintext first, the HTML as its alternative;
/// STARTTLS when `SMTP_USE_TLS`, login when both credentials are set.
pub async fn send_mail(cfg: &SmtpConfig, to: &str, email: &Email) -> Result<(), String> {
    use lettre::message::{Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let from: Mailbox = cfg.from_addr.parse().map_err(|e| format!("{e}"))?;
    let to: Mailbox = to.parse().map_err(|e| format!("{e}"))?;
    let builder = Message::builder()
        .from(from)
        .to(to)
        .subject(email.subject.clone());
    let message = match email.html.as_deref().filter(|h| !h.is_empty()) {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(
            mime_text(&email.text),
            mime_text(html),
        )),
        None => builder.singlepart(SinglePart::plain(mime_text(&email.text))),
    }
    .map_err(|e| e.to_string())?;
    let port = u16::try_from(cfg.port).map_err(|_| "port must be 0-65535.".to_string())?;
    let mut transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(cfg.host.as_str())
        .port(port)
        .timeout(Some(Duration::from_secs(30)));
    if cfg.use_tls {
        let tls = TlsParameters::new(cfg.host.clone()).map_err(|e| e.to_string())?;
        transport = transport.tls(Tls::Required(tls));
    }
    if let (Some(user), Some(pass)) = (
        cfg.username.as_deref().filter(|u| !u.is_empty()),
        cfg.password.as_deref().filter(|p| !p.is_empty()),
    ) {
        transport = transport.credentials(Credentials::new(user.into(), pass.into()));
    }
    // lettre ends the message with a CRLF of its own (after a single-part body)
    // and writes the DATA terminator as "\r\n.\r\n": the recipient would read
    // two blank lines after the text. smtplib sends the message as it is, ending
    // in its last line's CRLF, then ".\r\n" — the bytes sent here.
    let mut raw = message.formatted();
    for _ in 0..2 {
        if raw.ends_with(b"\r\n") {
            raw.truncate(raw.len() - 2);
        }
    }
    transport
        .build()
        .send_raw(message.envelope(), &raw)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_parts_end_lines_like_set_content() {
        for (input, want) in [
            ("", "\n"),
            ("a", "a\n"),
            ("a\n", "a\n"),
            ("a\r\nb\rc\n\n", "a\nb\nc\n\n"),
            ("\n", "\n"),
            ("a\x0bb\u{2028}c", "a\x0bb\u{2028}c\n"),
        ] {
            assert_eq!(mime_text(input), want, "{input:?}");
        }
    }

    #[test]
    fn generated_passwords_have_every_class() {
        for _ in 0..50 {
            let p = generate_password();
            assert_eq!(p.len(), 16);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| "@$!%*?&#".contains(c)));
        }
    }

    #[test]
    fn login_url_is_copilot_url_plus_login() {
        assert_eq!(login_url(None), "");
        assert_eq!(login_url(Some(" / ")), "");
        assert_eq!(
            login_url(Some("https://c.example//")),
            "https://c.example/login"
        );
    }

    #[test]
    fn html_becomes_readable_text() {
        let html = "<style>p{}</style><SCRIPT>x</script><p>Hello&nbsp;<b>bob</b></p>\
                    <br/>  \n\n\n\n<div>a &amp; b&#39;s</div><h2 class=x>T</h2 >";
        assert_eq!(html_to_text(html), "Hello bob\n\na & b's\nT");
        assert_eq!(collapse_whitespace(" a \n b\u{1c}c "), "a b c");
    }
}
