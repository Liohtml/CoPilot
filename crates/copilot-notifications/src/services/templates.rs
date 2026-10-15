//! Named message templates (`services/templates.py`): CRUD with the
//! save-time checks, the attach-time compatibility rules, and the editor's
//! preview against a sample event.

use copilot_jinja::{Event, Input};
use copilot_web::ApiError;
use serde_json::{Map, Value};

use crate::branding;
use crate::db::{self, NewTemplate, SetValue, TemplateRow, TemplateScope};
use crate::dispatcher::Dispatcher;
use crate::event::{collapse_whitespace, entity, py_strip, trigger_values};
use crate::schema::{PreviewRequest, TemplateCreate, TemplateUpdate};
use crate::services::admin::{get_template, incompatibility};
use crate::services::dispatch::{dict_merge, sla_sample_context};
use crate::services::render::{self, is_template_error};
use crate::temp_password;

/// `_validate(name, fmt, body, subject)`.
async fn validate(
    name: Option<&str>,
    format: Option<&str>,
    body: Option<&str>,
    subject: Option<&str>,
) -> Result<(), ApiError> {
    if name.is_none_or(|n| py_strip(n).is_empty()) {
        return Err(ApiError::bad_request("A template needs a name."));
    }
    let Some(format) = format.filter(|f| crate::schema::TEMPLATE_FORMATS.contains(f)) else {
        return Err(ApiError::bad_request(
            "format must be one of ('text', 'markdown', 'html', 'json')",
        ));
    };
    if body.is_none_or(|b| py_strip(b).is_empty()) {
        return Err(ApiError::bad_request("A template needs a body."));
    }
    let autoescape = format == "html";
    for (label, source) in [("body_template", body), ("subject_template", subject)] {
        let Some(source) = source.filter(|s| !s.is_empty()) else {
            continue;
        };
        if let Err(e) = render::compile(source, autoescape).await {
            if is_template_error(e.kind) {
                return Err(ApiError::bad_request(format!(
                    "{label} is not valid Jinja: {}",
                    e.message
                )));
            }
            return Err(ApiError::internal(format!("{}: {}", e.kind, e.message)));
        }
    }
    Ok(())
}

/// `list_templates`.
pub async fn list(
    d: &Dispatcher,
    customer_code: Option<&str>,
    trigger: Option<&str>,
    accessible: &copilot_auth::AccessScope,
) -> Result<Vec<TemplateRow>, ApiError> {
    let scope = match customer_code.filter(|c| !c.is_empty()) {
        Some(c) => TemplateScope::Customer(c.to_string()),
        None => match accessible {
            copilot_auth::AccessScope::All => TemplateScope::All,
            copilot_auth::AccessScope::Customers(codes) => TemplateScope::Customers(codes.clone()),
        },
    };
    Ok(db::list_templates(d.db(), &scope, trigger.filter(|t| !t.is_empty())).await?)
}

/// `create_template`.
pub async fn create(
    d: &Dispatcher,
    p: &TemplateCreate,
    created_by: Option<String>,
) -> Result<TemplateRow, ApiError> {
    validate(
        Some(&p.name),
        Some(&p.format),
        Some(&p.body_template),
        p.subject_template.as_deref(),
    )
    .await?;
    let id = db::insert_template(
        d.db(),
        &NewTemplate {
            name: py_strip(&p.name).to_string(),
            description: p.description.clone(),
            trigger: p.trigger.clone(),
            format: p.format.clone(),
            subject_template: p.subject_template.clone(),
            body_template: p.body_template.clone(),
            customer_code: p.customer_code.clone(),
            created_by,
            created_at: copilot_core::time::now_utc_naive(),
        },
    )
    .await?;
    get_template(d, id).await
}

fn patched<T: Clone>(p: &Option<Option<T>>, current: Option<T>) -> Option<T> {
    match p {
        Some(v) => v.clone(),
        None => current,
    }
}

/// `update_template`: refused for built-ins and for an edit that would break
/// a route using the template (checked inside the transaction, like
/// SQLAlchemy's autoflush before the conflict query).
pub async fn update(d: &Dispatcher, id: i64, p: &TemplateUpdate) -> Result<TemplateRow, ApiError> {
    let template = get_template(d, id).await?;
    if template.is_default {
        return Err(ApiError::bad_request(
            "Built-in templates cannot be edited. Duplicate it first — the copy is yours to \
             change, and the original stays available as a reference.",
        ));
    }
    let edited = TemplateRow {
        name: patched(&p.name, Some(template.name.clone())).unwrap_or_default(),
        description: patched(&p.description, template.description.clone()),
        trigger: patched(&p.trigger, template.trigger.clone()),
        format: patched(&p.format, Some(template.format.clone())).unwrap_or_default(),
        subject_template: patched(&p.subject_template, template.subject_template.clone()),
        body_template: patched(&p.body_template, Some(template.body_template.clone()))
            .unwrap_or_default(),
        customer_code: patched(&p.customer_code, template.customer_code.clone()),
        ..template.clone()
    };
    validate(
        patched(&p.name, Some(template.name.clone())).as_deref(),
        patched(&p.format, Some(template.format.clone())).as_deref(),
        patched(&p.body_template, Some(template.body_template.clone())).as_deref(),
        edited.subject_template.as_deref(),
    )
    .await?;
    let mut sets: Vec<(&'static str, SetValue)> = Vec::new();
    let mut push = |col: &'static str, v: &Option<Option<String>>| {
        if let Some(v) = v {
            sets.push((col, v.clone().map_or(SetValue::Null, SetValue::Str)));
        }
    };
    push("name", &p.name);
    push("description", &p.description);
    push("trigger", &p.trigger);
    push("format", &p.format);
    push("subject_template", &p.subject_template);
    push("body_template", &p.body_template);
    push("customer_code", &p.customer_code);
    sets.push((
        "updated_at",
        SetValue::Time(copilot_core::time::now_utc_naive()),
    ));
    let mut tx = d
        .db()
        .pool()
        .begin()
        .await
        .map_err(copilot_db::DbError::from)?;
    {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("UPDATE notification_template SET ");
        for (i, (col, value)) in sets.iter().enumerate() {
            if i > 0 {
                qb.push(", ");
            }
            qb.push(format!("`{col}` = "));
            match value {
                SetValue::Null => {
                    qb.push("NULL");
                }
                SetValue::Str(s) => {
                    qb.push_bind(s.clone());
                }
                SetValue::Time(t) => {
                    qb.push_bind(*t);
                }
                SetValue::Int(n) => {
                    qb.push_bind(*n);
                }
                SetValue::Bool(b) => {
                    qb.push_bind(*b);
                }
            }
        }
        qb.push(" WHERE id = ");
        qb.push_bind(id);
        qb.build()
            .execute(&mut *tx)
            .await
            .map_err(copilot_db::DbError::from)?;
    }
    let routes = db::routes_with_template(d.db(), id).await?;
    let conflicts: Vec<String> = routes
        .iter()
        .filter_map(|r| {
            incompatibility(&edited, &r.channel, &r.trigger, r.customer_code.as_deref())
                .map(|problem| format!("{} — {problem}", copilot_auth::pyvalue::str_repr(&r.name)))
        })
        .collect();
    if !conflicts.is_empty() {
        tx.rollback().await.map_err(copilot_db::DbError::from)?;
        return Err(ApiError::bad_request(format!(
            "That change would break {} already using this template: {}",
            if conflicts.len() == 1 {
                "a route".to_string()
            } else {
                format!("{} routes", conflicts.len())
            },
            conflicts.join("; ")
        )));
    }
    tx.commit().await.map_err(copilot_db::DbError::from)?;
    get_template(d, id).await
}

/// `delete_template`: refused for built-ins; routes using it are detached.
/// Returns how many.
pub async fn delete(d: &Dispatcher, id: i64) -> Result<u64, ApiError> {
    let template = get_template(d, id).await?;
    if template.is_default {
        return Err(ApiError::bad_request(
            "Built-in templates cannot be deleted.",
        ));
    }
    let detached = db::delete_template(d.db(), id).await?;
    if detached > 0 {
        tracing::info!(
            "Deleted template {id}; detached from {detached} route(s), which fall back to their \
             channel default."
        );
    }
    Ok(detached)
}

/// `sample_event(trigger, customer_code)`: the editor's preview event.
pub fn sample_event(
    trigger: &str,
    customer_code: Option<&str>,
    copilot_url: Option<&str>,
) -> Event {
    let parsed = if trigger_values().contains(&trigger) {
        trigger
    } else {
        "alert_created"
    };
    let code = customer_code.filter(|c| !c.is_empty()).unwrap_or("ACME");
    if parsed == temp_password::TEMPLATE_TRIGGER {
        return temp_password::event("jdoe", Some(code), 0, copilot_url);
    }
    let entity_type = match parsed {
        "case_assigned" => entity::CASE,
        "case_task_assigned" => entity::CASE_TASK,
        _ => entity::ALERT,
    };
    let title = "Suspicious PowerShell execution on WKSTN-014";
    let ioc = |value: &str, kind: &str| {
        Input::Dict(vec![
            ("value".into(), Input::Str(value.into())),
            ("type".into(), Input::Str(kind.into())),
        ])
    };
    let mut context: Vec<(String, Input)> = vec![
        ("alert_name".into(), Input::Str(title.into())),
        ("title".into(), Input::Str(title.into())),
        ("asset_name".into(), Input::Str("WKSTN-014".into())),
        ("rule_level".into(), Input::Int(12)),
        (
            "iocs".into(),
            Input::List(vec![
                ioc("185.199.108.153", "ip"),
                ioc("a1b2c3d4e5f6", "hash"),
            ]),
        ),
    ];
    dict_merge(&mut context, sla_sample_context(parsed));
    Event {
        customer_code: Some(code.to_string()),
        trigger: parsed.to_string(),
        severity: "High".into(),
        subject: title.into(),
        summary: "An encoded PowerShell command was executed by a non-administrative user. The \
                  parent process was winword.exe, which is consistent with a malicious document."
            .into(),
        entity_type: entity_type.into(),
        entity_id: 4821,
        dedupe_key: "preview".into(),
        link_url: Some("https://copilot.example.com/alerts/4821".into()),
        assignee_username: Some("jdoe".into()),
        actor_username: Some("asmith".into()),
        context,
    }
}

/// `preview(payload)`: `{body, subject, error}` — a render failure is
/// reported, not raised.
pub async fn preview(d: &Dispatcher, p: &PreviewRequest) -> Result<Map<String, Value>, ApiError> {
    let copilot_url = d.defaults().copilot_url.as_deref();
    let event = sample_event(&p.trigger, p.customer_code.as_deref(), copilot_url);
    let autoescape = p.format == "html";
    let mut extra: Vec<(String, Input)> = Vec::new();
    let source = format!(
        "{}{}",
        p.body_template,
        p.subject_template.as_deref().unwrap_or("")
    );
    if source.contains("branding") {
        extra.push((
            "branding".into(),
            branding::context(d.db(), p.customer_code.as_deref()).await,
        ));
    }
    if p.trigger == temp_password::TEMPLATE_TRIGGER {
        let code = p.customer_code.as_deref().filter(|c| !c.is_empty());
        let name = match code {
            Some(c) => copilot_db::customers::find_customer(d.db(), c)
                .await?
                .map(|c| c.customer_name),
            None => None,
        };
        dict_merge(
            &mut extra,
            temp_password::extra_context(
                "jdoe",
                "jdoe@example.com",
                temp_password::PREVIEW_PASSWORD,
                copilot_url,
                Some(code.unwrap_or("ACME")),
                name.as_deref(),
            ),
        );
    }
    let mut out = Map::new();
    let body = match render::render(&p.body_template, &event, autoescape, &extra).await {
        Ok(b) => b,
        Err(e) => {
            out.insert("body".into(), Value::String(String::new()));
            out.insert("subject".into(), Value::Null);
            out.insert(
                "error".into(),
                Value::String(format!("{}: {}", e.kind, e.message)),
            );
            return Ok(out);
        }
    };
    let mut subject = Value::Null;
    if let Some(src) = p.subject_template.as_deref().filter(|s| !s.is_empty()) {
        match render::render(src, &event, autoescape, &extra).await {
            Ok(s) => subject = Value::String(collapse_whitespace(&s)),
            Err(e) => {
                out.insert("body".into(), Value::String(body));
                out.insert("subject".into(), Value::Null);
                out.insert(
                    "error".into(),
                    Value::String(format!("Subject: {}: {}", e.kind, e.message)),
                );
                return Ok(out);
            }
        }
    }
    out.insert("body".into(), Value::String(body));
    out.insert("subject".into(), subject);
    out.insert("error".into(), Value::Null);
    Ok(out)
}
