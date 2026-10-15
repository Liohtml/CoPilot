//! Message bodies: the per-trigger channel defaults (`_format_default_body`),
//! the fail-safe Jinja render (`render_body`) and a route's precedence chain
//! inline → named template → channel default (`_render_body`), with the
//! `branding` and `context.ai_report` lookups done only when a template
//! names them.

use copilot_db::Db;
use copilot_jinja::{Event, Input};

use crate::branding;
use crate::db::{self, RouteRow, TemplateRow};
use crate::event::{
    INTERNAL_TRIGGERS, SLA_TRIGGERS, collapse_whitespace, ctx_get, ctx_set, dict_get, entity,
    py_str, py_strip, truthy, truthy_opt,
};
use crate::services::ai_report;
use crate::services::memo::Memo;

/// A Python exception that escapes the render path (a malformed
/// `context.ai_report` handed in by a caller): the dispatch fails as it does
/// in Python.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault(pub String);

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `RenderedMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The body.
    pub body: String,
    /// `text` | `markdown` | `html` | `json`.
    pub format: String,
    /// A named template's subject; `None` lets the provider compose one.
    pub subject: Option<String>,
    /// Operator-authored rather than the channel default.
    pub is_custom: bool,
}

impl Rendered {
    fn plain(body: String) -> Self {
        Self {
            body,
            format: "text".into(),
            subject: None,
            is_custom: false,
        }
    }
}

/// Jinja2's `TemplateError` family (what `render_body` words as "failed"
/// rather than "failed unexpectedly", and what save-time validation turns
/// into a 400).
pub fn is_template_error(kind: &str) -> bool {
    matches!(
        kind,
        "TemplateError"
            | "TemplateSyntaxError"
            | "TemplateAssertionError"
            | "TemplateRuntimeError"
            | "UndefinedError"
            | "SecurityError"
            | "FilterArgumentError"
            | "TemplateNotFound"
            | "TemplatesNotFound"
            | "TemplateTooLargeError"
    )
}

/// `rendering.render(source, event, …)` off the async workers.
pub async fn render(
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

/// `compile_template(source, autoescape=…)` off the async workers.
pub async fn compile(source: &str, autoescape: bool) -> Result<(), copilot_jinja::Error> {
    let source = source.to_string();
    tokio::task::spawn_blocking(move || copilot_jinja::compile_template(&source, autoescape))
        .await
        .unwrap_or_else(|e| Err(copilot_jinja::Error::new("RuntimeError", e.to_string())))
}

/// `render_body(source, event, fallback, …)`: the render, or the fallback
/// and the reason it was used.
pub async fn render_body(
    source: Option<&str>,
    event: &Event,
    fallback: &str,
    autoescape: bool,
    extra: &[(String, Input)],
) -> (String, Option<String>) {
    let Some(source) = source.filter(|s| !s.is_empty()) else {
        return (fallback.to_string(), None);
    };
    match render(source, event, autoescape, extra).await {
        Ok(body) => (body, None),
        Err(e) => {
            let message = if is_template_error(e.kind) {
                format!(
                    "Template render failed ({}: {}); sent the channel default instead.",
                    e.kind, e.message
                )
            } else {
                format!(
                    "Template render failed unexpectedly ({}: {}); sent the channel default \
                     instead.",
                    e.kind, e.message
                )
            };
            tracing::warn!(trigger = %event.trigger, entity = %event.entity_type,
                id = event.entity_id, "{message}");
            (fallback.to_string(), Some(message))
        }
    }
}

fn opt_none(s: Option<&str>) -> &str {
    s.unwrap_or("None")
}

/// `ctx.get(key)` printed (`None` when absent).
fn ctx_str(e: &Event, key: &str) -> Option<String> {
    ctx_get(e, key).map(py_str)
}

/// `ctx.get(key) is not None`.
fn ctx_is_some(e: &Event, key: &str) -> bool {
    !matches!(ctx_get(e, key), None | Some(Input::None))
}

/// `ctx.get("title") or event.subject`, printed.
fn label(e: &Event) -> String {
    truthy_opt(ctx_get(e, "title")).map_or_else(|| e.subject.clone(), py_str)
}

fn sla_timing(late: bool, e: &Event) -> String {
    if late {
        if ctx_is_some(e, "overdue_minutes") {
            format!(
                "{} min overdue",
                ctx_str(e, "overdue_minutes").unwrap_or_default()
            )
        } else {
            String::new()
        }
    } else if ctx_is_some(e, "remaining_minutes") {
        format!(
            "{} min left",
            ctx_str(e, "remaining_minutes").unwrap_or_default()
        )
    } else {
        String::new()
    }
}

fn link_and_summary(parts: &mut Vec<String>, e: &Event, link_label: &str) {
    if !e.summary.is_empty() {
        parts.push(String::new());
        parts.push(py_strip(&e.summary).to_string());
    }
    if let Some(link) = e.link_url.as_deref().filter(|l| !l.is_empty()) {
        parts.push(String::new());
        parts.push(format!("{link_label}: {link}"));
    }
}

/// `_format_default_body_core`: the per-trigger default wording.
pub fn default_body_core(e: &Event) -> String {
    let trig = e.trigger.as_str();
    let mut parts: Vec<String> = Vec::new();
    let suffix = |label: &str| {
        if label.is_empty() {
            String::new()
        } else {
            format!(" — {label}")
        }
    };
    if SLA_TRIGGERS.contains(&trig) {
        let what = if e.entity_type == entity::CASE {
            "Case"
        } else {
            "Alert"
        };
        let late = trig == "sla_breached";
        let heading = if late { "SLA breached" } else { "SLA at risk" };
        let when = sla_timing(late, e);
        let clock = ctx_get(e, "clock").map_or_else(|| "resolve".to_string(), py_str);
        let mut first = format!("*{heading}* — {clock} target, severity *{}*", e.severity);
        if !when.is_empty() {
            first.push_str(&format!(" ({when})"));
        }
        parts.push(first);
        parts.push(String::new());
        parts.push(format!("{what}: #{}{}", e.entity_id, suffix(&label(e))));
        if let Some(c) = e.customer_code.as_deref().filter(|c| !c.is_empty()) {
            parts.push(format!("Customer: `{c}`"));
        }
        parts.push(format!(
            "Assigned to: {}",
            e.assignee_username
                .as_deref()
                .filter(|a| !a.is_empty())
                .unwrap_or("nobody")
        ));
        if truthy_opt(ctx_get(e, "due_at")).is_some() {
            parts.push(format!(
                "Due: {} UTC",
                ctx_str(e, "due_at").unwrap_or_default()
            ));
        }
        if let Some(link) = e.link_url.as_deref().filter(|l| !l.is_empty()) {
            parts.push(String::new());
            parts.push(format!("Open in CoPilot: {link}"));
        }
        return parts.join("\n");
    }
    if INTERNAL_TRIGGERS.contains(&trig) {
        let what = match trig {
            "alert_assigned" => "Alert",
            "case_assigned" => "Case",
            "case_task_assigned" => "Task",
            _ => "Item",
        };
        parts.push(format!(
            "*{what} assigned* — {}",
            e.assignee_username
                .as_deref()
                .filter(|a| !a.is_empty())
                .unwrap_or("unassigned")
        ));
        parts.push(String::new());
        parts.push(format!("{what}: #{}{}", e.entity_id, suffix(&label(e))));
        if let Some(c) = e.customer_code.as_deref().filter(|c| !c.is_empty()) {
            parts.push(format!("Customer: `{c}`"));
        }
        if let Some(a) = e.actor_username.as_deref().filter(|a| !a.is_empty()) {
            parts.push(format!("Assigned by: {a}"));
        }
        link_and_summary(&mut parts, e, "Open in CoPilot");
        return parts.join("\n");
    }
    if trig == "alert_created" {
        parts.push(format!("*New alert* — severity: *{}*", e.severity));
        parts.push(String::new());
        parts.push(format!(
            "Customer: `{}`",
            opt_none(e.customer_code.as_deref())
        ));
        parts.push(format!("Alert: #{}{}", e.entity_id, suffix(&e.subject)));
        if truthy_opt(ctx_get(e, "asset_name")).is_some() {
            parts.push(format!(
                "Asset: {}",
                ctx_str(e, "asset_name").unwrap_or_default()
            ));
        }
        if ctx_is_some(e, "rule_level") {
            parts.push(format!(
                "Rule level: {}",
                ctx_str(e, "rule_level").unwrap_or_default()
            ));
        }
        link_and_summary(&mut parts, e, "Open in CoPilot");
        return parts.join("\n");
    }
    if trig == "ai_report_reviewed" {
        parts.push(format!("*AI report reviewed* — severity: *{}*", e.severity));
        parts.push(String::new());
        parts.push(format!(
            "Customer: `{}`",
            opt_none(e.customer_code.as_deref())
        ));
        let name = truthy_opt(ctx_get(e, "alert_name")).map(py_str);
        parts.push(format!(
            "Alert: #{}{}",
            e.entity_id,
            suffix(name.as_deref().unwrap_or(""))
        ));
        if truthy_opt(ctx_get(e, "reviewer")).is_some() {
            parts.push(format!(
                "Reviewed by: {}",
                ctx_str(e, "reviewer").unwrap_or_default()
            ));
        }
        if truthy_opt(ctx_get(e, "verdict")).is_some() {
            parts.push(format!(
                "Verdict: {}",
                ctx_str(e, "verdict").unwrap_or_default()
            ));
        }
        link_and_summary(&mut parts, e, "Open in CoPilot");
        return parts.join("\n");
    }
    // investigation_complete — the pre-#1006 wording.
    let name = truthy_opt(ctx_get(e, "alert_name")).map(py_str);
    parts.push(format!(
        "*AI investigation complete* — severity: *{}*",
        e.severity
    ));
    parts.push(String::new());
    parts.push(format!(
        "Customer: `{}`",
        opt_none(e.customer_code.as_deref())
    ));
    parts.push(format!(
        "Alert: #{}{}",
        e.entity_id,
        suffix(name.as_deref().unwrap_or(""))
    ));
    parts.push(String::new());
    parts.push(py_strip(&e.summary).to_string());
    if let Some(link) = e.link_url.as_deref().filter(|l| !l.is_empty()) {
        parts.push(String::new());
        parts.push(format!("Full report: {link}"));
    }
    parts.join("\n")
}

/// `_ai_report_section`: the AI report appended to a default body.
fn ai_report_section(e: &Event) -> Result<String, Fault> {
    let Some(report) = truthy_opt(ctx_get(e, "ai_report")) else {
        return Ok(String::new());
    };
    let Input::Dict(_) = report else {
        return Err(Fault(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            py_type(report)
        )));
    };
    let body = truthy_opt(dict_get(report, "markdown"))
        .or_else(|| truthy_opt(dict_get(report, "summary")))
        .cloned()
        .unwrap_or(Input::Str(String::new()));
    let body = match &body {
        Input::Str(s) | Input::Markup(s) => s.clone(),
        other => {
            return Err(Fault(format!(
                "AttributeError: '{}' object has no attribute 'strip'",
                py_type(other)
            )));
        }
    };
    if py_strip(&body).is_empty() {
        return Ok(String::new());
    }
    let heading = match truthy_opt(dict_get(report, "severity")) {
        Some(sev) => format!("*AI investigation* — assessed severity: *{}*", py_str(sev)),
        None => "*AI investigation*".to_string(),
    };
    Ok(["", "---", "", &heading, "", py_strip(&body)].join("\n"))
}

/// `type(v).__name__`.
pub fn py_type(v: &Input) -> &'static str {
    match v {
        Input::None => "NoneType",
        Input::Bool(_) => "bool",
        Input::Int(_) => "int",
        Input::Float(_) => "float",
        Input::Str(_) => "str",
        Input::Markup(_) => "Markup",
        Input::List(_) => "list",
        Input::Dict(_) => "dict",
    }
}

/// `_format_default_body`: the default plus the AI report, when attached.
pub fn default_body(e: &Event) -> Result<String, Fault> {
    Ok(default_body_core(e) + &ai_report_section(e)?)
}

/// `_ensure_ai_report_context`: load the alert's newest AI report onto the
/// event when `source` names `ai_report` (memoized per dispatch).
pub async fn ensure_ai_report(db: &Db, source: &str, e: &mut Event, memo: Option<&mut Memo>) {
    if !source.contains("ai_report") || ctx_get(e, "ai_report").is_some() {
        return;
    }
    if e.entity_type != entity::ALERT {
        return;
    }
    let report = match memo {
        Some(m) => {
            if let Some(r) = m.ai_report.get(&e.entity_id) {
                r.clone()
            } else {
                let r = ai_report::safe_load(db, e.entity_id).await;
                m.ai_report.insert(e.entity_id, r.clone());
                r
            }
        }
        None => ai_report::safe_load(db, e.entity_id).await,
    };
    ctx_set(e, "ai_report", report);
}

/// `_branding_context`: `{"branding": …}` when the template names it.
async fn branding_extra(
    db: &Db,
    template: &TemplateRow,
    e: &Event,
    memo: Option<&mut Memo>,
) -> Vec<(String, Input)> {
    let source = format!(
        "{}{}",
        template.body_template,
        template.subject_template.as_deref().unwrap_or("")
    );
    if !source.contains("branding") {
        return Vec::new();
    }
    let code = e.customer_code.clone();
    let value = match memo {
        Some(m) => {
            if let Some(b) = m.branding.get(&code) {
                b.clone()
            } else {
                let b = branding::context(db, code.as_deref()).await;
                m.branding.insert(code, b.clone());
                b
            }
        }
        None => branding::context(db, code.as_deref()).await,
    };
    vec![("branding".into(), value)]
}

/// `resolve_template_for_route`: the route's named template, if any.
pub async fn template_for_route(db: &Db, route: &RouteRow) -> Result<Option<TemplateRow>, Fault> {
    let Some(id) = route.template_id.filter(|id| *id != 0) else {
        return Ok(None);
    };
    let template = db::template(db, i64::from(id))
        .await
        .map_err(|e| Fault(e.to_string()))?;
    if template.is_none() {
        tracing::warn!(
            route = route.id,
            template = id,
            "route references a template that no longer exists"
        );
    }
    Ok(template)
}

/// `_render_body(route, event)`: the message and, when a custom template
/// failed (or only its subject did), the reason.
pub async fn render_route(
    db: &Db,
    route: &RouteRow,
    e: &mut Event,
    mut memo: Option<&mut Memo>,
) -> Result<(Rendered, Option<String>), Fault> {
    if let Some(inline) = route.format_template.as_deref().filter(|s| !s.is_empty()) {
        ensure_ai_report(db, inline, e, memo.as_deref_mut()).await;
        let fallback = default_body(e)?;
        let (body, error) = render_body(Some(inline), e, &fallback, false, &[]).await;
        let is_custom = error.is_none();
        return Ok((
            Rendered {
                is_custom,
                ..Rendered::plain(body)
            },
            error,
        ));
    }
    let Some(template) = template_for_route(db, route).await? else {
        let fallback = default_body(e)?;
        let format = if truthy_opt(ctx_get(e, "ai_report")).is_some() {
            "markdown"
        } else {
            "text"
        };
        return Ok((
            Rendered {
                format: format.into(),
                ..Rendered::plain(fallback)
            },
            None,
        ));
    };
    let source = format!(
        "{}{}",
        template.body_template,
        template.subject_template.as_deref().unwrap_or("")
    );
    ensure_ai_report(db, &source, e, memo.as_deref_mut()).await;
    let fallback = default_body(e)?;
    let autoescape = template.format == "html";
    let extra = branding_extra(db, &template, e, memo).await;
    let (body, error) = render_body(
        Some(&template.body_template),
        e,
        &fallback,
        autoescape,
        &extra,
    )
    .await;
    if error.is_some() {
        return Ok((Rendered::plain(body), error));
    }
    let (subject, subject_error) = render_body(
        template.subject_template.as_deref(),
        e,
        "",
        autoescape,
        &extra,
    )
    .await;
    let subject = collapse_whitespace(&subject);
    Ok((
        Rendered {
            body,
            format: template.format.clone(),
            subject: (!subject.is_empty()).then_some(subject),
            is_custom: true,
        },
        subject_error,
    ))
}

/// `truthy` for an optional context value.
pub fn ctx_truthy(e: &Event, key: &str) -> bool {
    ctx_get(e, key).is_some_and(truthy)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn event(trigger: &str) -> Event {
        Event {
            customer_code: Some("ACME".into()),
            trigger: trigger.into(),
            severity: "High".into(),
            subject: "Mimikatz".into(),
            summary: " Credential dumping. ".into(),
            entity_type: "alert".into(),
            entity_id: 14,
            dedupe_key: "k".into(),
            link_url: Some("https://c/alerts/14".into()),
            assignee_username: Some("bob".into()),
            actor_username: Some("alice".into()),
            context: vec![
                ("alert_name".into(), Input::Str("Mimikatz".into())),
                ("asset_name".into(), Input::Str("dc01".into())),
                ("rule_level".into(), Input::Int(12)),
            ],
        }
    }

    #[test]
    fn default_bodies_per_trigger() {
        assert_eq!(
            default_body_core(&event("investigation_complete")),
            "*AI investigation complete* — severity: *High*\n\nCustomer: `ACME`\nAlert: #14 — \
             Mimikatz\n\nCredential dumping.\n\nFull report: https://c/alerts/14"
        );
        assert_eq!(
            default_body_core(&event("alert_created")),
            "*New alert* — severity: *High*\n\nCustomer: `ACME`\nAlert: #14 — Mimikatz\nAsset: \
             dc01\nRule level: 12\n\nCredential dumping.\n\nOpen in CoPilot: https://c/alerts/14"
        );
        assert_eq!(
            default_body_core(&event("alert_assigned")),
            "*Alert assigned* — bob\n\nAlert: #14 — Mimikatz\nCustomer: `ACME`\nAssigned by: \
             alice\n\nCredential dumping.\n\nOpen in CoPilot: https://c/alerts/14"
        );
        let mut sla = event("sla_breached");
        sla.context.push(("overdue_minutes".into(), Input::Int(20)));
        sla.context
            .push(("due_at".into(), Input::Str("2026-09-01 12:00".into())));
        assert_eq!(
            default_body_core(&sla),
            "*SLA breached* — resolve target, severity *High* (20 min overdue)\n\nAlert: #14 — \
             Mimikatz\nCustomer: `ACME`\nAssigned to: bob\nDue: 2026-09-01 12:00 UTC\n\nOpen in \
             CoPilot: https://c/alerts/14"
        );
    }

    #[test]
    fn ai_report_section_is_appended() {
        let mut e = event("investigation_complete");
        e.context.push((
            "ai_report".into(),
            Input::Dict(vec![
                ("markdown".into(), Input::Str("\n# R\n".into())),
                ("severity".into(), Input::Str("Medium".into())),
            ]),
        ));
        let body = default_body(&e).unwrap();
        assert!(
            body.ends_with(
                "Full report: https://c/alerts/14\n---\n\n*AI investigation* — assessed \
                 severity: *Medium*\n\n# R"
            ),
            "{body}"
        );
        e.context.pop();
        e.context.push(("ai_report".into(), Input::Str("x".into())));
        assert_eq!(
            default_body(&e).unwrap_err().0,
            "AttributeError: 'str' object has no attribute 'get'"
        );
    }
}
