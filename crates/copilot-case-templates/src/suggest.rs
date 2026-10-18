//! Smart case-template suggestions (#935) — `template_suggestions.py`.
//!
//! The templates are ranked against the alert a case is about to be opened
//! for (`alert_id`), or against a bare customer and source (manual
//! creation). Every signal is Python's: the customer and source scope (a
//! hard filter, `_in_scope`), the auto-apply condition evaluated on the
//! stored alert context and — only when an in-scope conditional template
//! names a field that context lacks — the raw Wazuh document
//! (`AsyncElasticsearch.get`, through `copilot-wazuh`), the alert's tags,
//! MITRE ids and names, rule groups and title keywords matched against each
//! template's own text, the usage history (`CaseTask.template_task_id`) and
//! `is_default`; weights, caps, the partition of condition-matched templates
//! and the stable sort are `score_template` / `suggest_templates`'.
//!
//! Differences by design (tenant leaks, §4): an alert the caller may not see
//! (customer or tag RBAC) answers as a missing one; a `customer_code` the
//! caller may not see is a 403; without a customer, a scoped caller's usage
//! history counts their customers' cases only.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_incidents::case_templates::{Template, TemplateTask, load_all, template_json};
use copilot_wazuh::es::{Es, Flavor};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::text::{
    as_string_list, contains_phrase, dedupe_stripped, flatten_values, mitre_ids, mitre_parent,
    tokenize,
};

/// `WEIGHT_CONDITION_MATCH`.
pub const WEIGHT_CONDITION_MATCH: i64 = 40;
/// `WEIGHT_CUSTOMER_MATCH`.
pub const WEIGHT_CUSTOMER_MATCH: i64 = 25;
/// `WEIGHT_SOURCE_MATCH`.
pub const WEIGHT_SOURCE_MATCH: i64 = 20;
/// `WEIGHT_TAG_MATCH`.
pub const WEIGHT_TAG_MATCH: i64 = 10;
/// `CAP_TAG_MATCH`.
pub const CAP_TAG_MATCH: i64 = 30;
/// `WEIGHT_MITRE_MATCH`.
pub const WEIGHT_MITRE_MATCH: i64 = 15;
/// `WEIGHT_MITRE_PARENT_MATCH`.
pub const WEIGHT_MITRE_PARENT_MATCH: i64 = 7;
/// `CAP_MITRE_MATCH`.
pub const CAP_MITRE_MATCH: i64 = 30;
/// `WEIGHT_RULE_GROUP_MATCH`.
pub const WEIGHT_RULE_GROUP_MATCH: i64 = 6;
/// `CAP_RULE_GROUP_MATCH`.
pub const CAP_RULE_GROUP_MATCH: i64 = 18;
/// `WEIGHT_KEYWORD_MATCH`.
pub const WEIGHT_KEYWORD_MATCH: i64 = 4;
/// `CAP_KEYWORD_MATCH`.
pub const CAP_KEYWORD_MATCH: i64 = 12;
/// `WEIGHT_USAGE_HISTORY_MAX`.
pub const WEIGHT_USAGE_HISTORY_MAX: i64 = 12;
/// `WEIGHT_IS_DEFAULT`.
pub const WEIGHT_IS_DEFAULT: i64 = 5;
/// `CONFIDENCE_HIGH_THRESHOLD`.
pub const CONFIDENCE_HIGH_THRESHOLD: i64 = 55;
/// `CONFIDENCE_MEDIUM_THRESHOLD`.
pub const CONFIDENCE_MEDIUM_THRESHOLD: i64 = 25;
/// `DEFAULT_SUGGESTION_LIMIT`.
pub const DEFAULT_SUGGESTION_LIMIT: i64 = 5;
/// `_MIN_TOKEN_LENGTH`.
pub const MIN_TOKEN_LENGTH: usize = 3;

/// `_KEYWORD_STOPWORDS`.
pub const KEYWORD_STOPWORDS: &[&str] = &[
    "a",
    "alert",
    "an",
    "and",
    "at",
    "by",
    "detected",
    "detection",
    "event",
    "for",
    "from",
    "has",
    "in",
    "is",
    "of",
    "on",
    "or",
    "possible",
    "potential",
    "rule",
    "suspicious",
    "the",
    "to",
    "was",
    "with",
];

/// `_GENERIC_RULE_GROUPS`.
pub const GENERIC_RULE_GROUPS: &[&str] = &[
    "attack",
    "attacks",
    "gdpr",
    "gpg13",
    "hipaa",
    "ids",
    "nist_800_53",
    "pci_dss",
    "sca",
    "syscheck",
    "syslog",
    "tsc",
    "wazuh",
];

/// `_RULE_GROUP_KEYS`.
const RULE_GROUP_KEYS: &[&str] = &["rule_groups", "rule_group", "rule.groups"];

/// `_MITRE_NAME_KEYS`.
const MITRE_NAME_KEYS: &[&str] = &[
    "rule_mitre_technique",
    "rule_mitre_tactic",
    "rule.mitre.technique",
    "rule.mitre.tactic",
];

/// `AlertSignals`.
#[derive(Debug, Clone, Default)]
pub struct Signals {
    /// The case's customer.
    pub customer_code: Option<String>,
    /// The alert's source.
    pub source: Option<String>,
    /// The alert's title.
    pub alert_name: Option<String>,
    /// The alert's tags.
    pub tags: Vec<String>,
    /// MITRE technique ids.
    pub mitre_ids: BTreeSet<String>,
    /// MITRE technique / tactic names.
    pub mitre_names: Vec<String>,
    /// Wazuh rule groups.
    pub rule_groups: Vec<String>,
    /// Title keywords.
    pub keywords: Vec<String>,
    /// The merged key/value bag the conditions are evaluated against.
    pub document: Vec<(String, PyValue)>,
    /// Whether that bag could be read.
    pub document_available: bool,
}

impl Signals {
    fn doc_get(&self, key: &str) -> Option<&PyValue> {
        self.document.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// `document.update(other)`.
    fn doc_update(&mut self, other: &[(String, PyValue)]) {
        for (k, v) in other {
            match self.document.iter_mut().find(|(key, _)| key == k) {
                Some(slot) => slot.1 = v.clone(),
                None => self.document.push((k.clone(), v.clone())),
            }
        }
    }

    /// `_signals_from_document(signals, document)`.
    fn fold(&mut self, document: &PyValue) {
        for key in MITRE_NAME_KEYS {
            if let Some(v) = document.get(key) {
                self.mitre_names.extend(as_string_list(v));
            }
        }
        for key in RULE_GROUP_KEYS {
            if let Some(v) = document.get(key) {
                self.rule_groups.extend(as_string_list(v));
            }
        }
        let mut scalars = Vec::new();
        flatten_values(document, &mut scalars);
        for scalar in &scalars {
            self.mitre_ids.extend(mitre_ids(scalar));
        }
    }

    fn dedupe(&mut self) {
        self.mitre_names = dedupe_stripped(&self.mitre_names);
        self.rule_groups = dedupe_stripped(&self.rule_groups);
    }
}

/// `TemplateCorpus`.
#[derive(Debug, Clone)]
pub struct Corpus {
    /// The lowered text.
    pub text: String,
    /// Its tokens.
    pub tokens: BTreeSet<String>,
    /// The MITRE ids it names.
    pub mitre_ids: BTreeSet<String>,
}

/// What a template's text and scope are made of (a `CaseTemplate` with its
/// tasks, in the relationship's order).
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Id.
    pub id: i64,
    /// Name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Customer scope.
    pub customer_code: Option<String>,
    /// Source scope.
    pub source: Option<String>,
    /// Default of its scope.
    pub is_default: bool,
    /// Condition field.
    pub match_field: Option<String>,
    /// Condition value.
    pub match_value: Option<String>,
    /// `(title, description, guidelines)` per task.
    pub tasks: Vec<(String, Option<String>, Option<String>)>,
}

impl Candidate {
    fn of(t: &Template, tasks: &[TemplateTask]) -> Self {
        Self {
            id: i64::from(t.id),
            name: t.name.clone(),
            description: t.description.clone(),
            customer_code: t.customer_code.clone(),
            source: t.source.clone(),
            is_default: t.is_default,
            match_field: t.match_field.clone(),
            match_value: t.match_value.clone(),
            tasks: tasks
                .iter()
                .map(|x| (x.title.clone(), x.description.clone(), x.guidelines.clone()))
                .collect(),
        }
    }
}

fn truthy(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|t| !t.is_empty())
}

/// `build_template_corpus(template)`.
pub fn corpus(t: &Candidate) -> Corpus {
    let mut parts: Vec<&str> = vec![&t.name, t.description.as_deref().unwrap_or("")];
    for (title, description, guidelines) in &t.tasks {
        parts.push(title);
        parts.push(description.as_deref().unwrap_or(""));
        parts.push(guidelines.as_deref().unwrap_or(""));
    }
    let joined = parts
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let text = copilot_jinja::unicode::lower(&joined);
    Corpus {
        tokens: tokenize(&text).into_iter().collect(),
        mitre_ids: mitre_ids(&text),
        text,
    }
}

/// One `SuggestionReason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// The signal key.
    pub signal: &'static str,
    /// The explanation.
    pub detail: String,
    /// The points it brought.
    pub points: i64,
}

fn reason(signal: &'static str, detail: String, points: i64) -> Reason {
    Reason {
        signal,
        detail,
        points,
    }
}

/// `_usage_points(count)`: `min(12, int(round(4 * log2(1 + count))))`.
pub fn usage_points(count: i64) -> i64 {
    if count <= 0 {
        return 0;
    }
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let points = (4.0 * (1.0 + count as f64).log2()).round_ties_even() as i64;
    WEIGHT_USAGE_HISTORY_MAX.min(points)
}

/// `_confidence_for(score)`.
pub fn confidence(score: i64) -> &'static str {
    if score >= CONFIDENCE_HIGH_THRESHOLD {
        "high"
    } else if score >= CONFIDENCE_MEDIUM_THRESHOLD {
        "medium"
    } else {
        "low"
    }
}

/// `_evaluate_condition`: `None` is "unknown".
fn evaluate_condition(t: &Candidate, signals: &Signals) -> Option<bool> {
    let field = truthy(&t.match_field)?;
    let value = truthy(&t.match_value)?;
    if !signals.document_available {
        return None;
    }
    Some(match signals.doc_get(field) {
        None | Some(PyValue::None) => false,
        Some(v) => v.py_str() == value,
    })
}

/// `_in_scope(template, signals)`.
pub fn in_scope(t: &Candidate, signals: &Signals) -> bool {
    let customer = truthy(&signals.customer_code);
    let source = truthy(&signals.source);
    if let Some(tc) = truthy(&t.customer_code) {
        match customer {
            Some(c) if c != tc => return false,
            None => return false,
            _ => {}
        }
    }
    if let (Some(ts), Some(s)) = (truthy(&t.source), source) {
        if ts != s {
            return false;
        }
    }
    true
}

fn score_tags(c: &Corpus, signals: &Signals, reasons: &mut Vec<Reason>) -> i64 {
    let mut matched: Vec<&str> = Vec::new();
    for tag in &signals.tags {
        let in_tag = mitre_ids(tag);
        if !in_tag.is_empty() {
            if in_tag.iter().any(|id| c.mitre_ids.contains(id)) {
                matched.push(tag);
            }
            continue;
        }
        if contains_phrase(&c.tokens, &c.text, tag) {
            matched.push(tag);
        }
    }
    if matched.is_empty() {
        return 0;
    }
    let score = CAP_TAG_MATCH.min(WEIGHT_TAG_MATCH * matched.len() as i64);
    reasons.push(reason(
        "tag",
        format!("Matches alert tag(s): {}", matched.join(", ")),
        score,
    ));
    score
}

fn score_mitre(c: &Corpus, signals: &Signals, reasons: &mut Vec<Reason>) -> i64 {
    let exact: Vec<&String> = signals.mitre_ids.intersection(&c.mitre_ids).collect();
    let mut parents: Vec<(&str, &str)> = Vec::new();
    for id in &signals.mitre_ids {
        if c.mitre_ids.contains(id) {
            continue;
        }
        if let Some(parent) = mitre_parent(id) {
            if c.mitre_ids.contains(parent) {
                parents.push((id, parent));
            }
        }
    }
    let exact_points = CAP_MITRE_MATCH.min(WEIGHT_MITRE_MATCH * exact.len() as i64);
    let raw =
        WEIGHT_MITRE_MATCH * exact.len() as i64 + WEIGHT_MITRE_PARENT_MATCH * parents.len() as i64;
    let mut score = CAP_MITRE_MATCH.min(raw);
    if !exact.is_empty() {
        let ids: Vec<&str> = exact.iter().map(|s| s.as_str()).collect();
        reasons.push(reason(
            "mitre",
            format!("Covers MITRE technique(s): {}", ids.join(", ")),
            exact_points,
        ));
    }
    if !parents.is_empty() && score > 0 {
        let detail: Vec<String> = parents
            .iter()
            .map(|(child, parent)| format!("{child} \u{2192} {parent}"))
            .collect();
        reasons.push(reason(
            "mitre_parent",
            format!("Covers the parent technique of: {}", detail.join(", ")),
            0.max(score - exact_points),
        ));
    }
    if exact.is_empty() && parents.is_empty() {
        let named: Vec<&str> = signals
            .mitre_names
            .iter()
            .filter(|n| contains_phrase(&c.tokens, &c.text, n))
            .map(String::as_str)
            .collect();
        if !named.is_empty() {
            score = CAP_MITRE_MATCH.min(WEIGHT_MITRE_PARENT_MATCH * named.len() as i64);
            reasons.push(reason(
                "mitre_name",
                format!("Mentions MITRE technique(s): {}", named.join(", ")),
                score,
            ));
        }
    }
    score
}

fn score_rule_groups(c: &Corpus, signals: &Signals, reasons: &mut Vec<Reason>) -> i64 {
    let matched: Vec<&str> = signals
        .rule_groups
        .iter()
        .filter(|g| {
            !GENERIC_RULE_GROUPS.contains(&copilot_jinja::unicode::lower(g).as_str())
                && contains_phrase(&c.tokens, &c.text, g)
        })
        .map(String::as_str)
        .collect();
    if matched.is_empty() {
        return 0;
    }
    let score = CAP_RULE_GROUP_MATCH.min(WEIGHT_RULE_GROUP_MATCH * matched.len() as i64);
    reasons.push(reason(
        "rule_group",
        format!("Matches rule group(s): {}", matched.join(", ")),
        score,
    ));
    score
}

fn score_keywords(c: &Corpus, signals: &Signals, reasons: &mut Vec<Reason>) -> i64 {
    let matched: Vec<&str> = signals
        .keywords
        .iter()
        .filter(|k| c.tokens.contains(*k))
        .map(String::as_str)
        .collect();
    if matched.is_empty() {
        return 0;
    }
    let score = CAP_KEYWORD_MATCH.min(WEIGHT_KEYWORD_MATCH * matched.len() as i64);
    reasons.push(reason(
        "keyword",
        format!("Alert title mentions: {}", matched.join(", ")),
        score,
    ));
    score
}

/// `score_template`: the score, the reasons (highest first, stable) and the
/// condition's outcome.
pub fn score(
    t: &Candidate,
    signals: &Signals,
    usage: &BTreeMap<i64, i64>,
) -> (i64, Vec<Reason>, Option<bool>) {
    let c = corpus(t);
    let mut reasons = Vec::new();
    let mut total = 0;
    let condition = evaluate_condition(t, signals);
    match condition {
        Some(true) => {
            total += WEIGHT_CONDITION_MATCH;
            reasons.push(reason(
                "condition",
                format!(
                    "Auto-apply condition matches ({} = {})",
                    t.match_field.as_deref().unwrap_or("None"),
                    t.match_value.as_deref().unwrap_or("None")
                ),
                WEIGHT_CONDITION_MATCH,
            ));
        }
        None if truthy(&t.match_field).is_some() => {
            reasons.push(reason(
                "condition_unverified",
                format!(
                    "Auto-apply condition on {} could not be checked \u{2014} the originating \
                     event was not readable",
                    t.match_field.as_deref().unwrap_or("None")
                ),
                0,
            ));
        }
        _ => {}
    }
    // `_score_scope`.
    if let (Some(tc), Some(sc)) = (truthy(&t.customer_code), truthy(&signals.customer_code)) {
        if tc == sc {
            total += WEIGHT_CUSTOMER_MATCH;
            reasons.push(reason(
                "customer",
                format!("Scoped to customer {tc}"),
                WEIGHT_CUSTOMER_MATCH,
            ));
        }
    }
    if let (Some(ts), Some(ss)) = (truthy(&t.source), truthy(&signals.source)) {
        if ts == ss {
            total += WEIGHT_SOURCE_MATCH;
            reasons.push(reason(
                "source",
                format!("Scoped to {ts} alerts"),
                WEIGHT_SOURCE_MATCH,
            ));
        }
    }
    total += score_tags(&c, signals, &mut reasons);
    total += score_mitre(&c, signals, &mut reasons);
    total += score_rule_groups(&c, signals, &mut reasons);
    total += score_keywords(&c, signals, &mut reasons);
    let count = usage.get(&t.id).copied().unwrap_or(0);
    let points = usage_points(count);
    if points != 0 {
        total += points;
        let scope = truthy(&signals.customer_code)
            .map(|c| format!(" for {c}"))
            .unwrap_or_default();
        reasons.push(reason(
            "usage",
            format!("Applied to {count} case(s){scope}"),
            points,
        ));
    }
    if t.is_default {
        total += WEIGHT_IS_DEFAULT;
        reasons.push(reason(
            "default",
            "Default template for its scope".into(),
            WEIGHT_IS_DEFAULT,
        ));
    }
    // `sorted(reasons, key=points, reverse=True)`: stable, highest first.
    reasons.sort_by_key(|r| std::cmp::Reverse(r.points));
    (total, reasons, condition)
}

/// `_tokenize(alert_name)` deduplicated, without the short and stop words.
pub fn keywords(alert_name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in tokenize(alert_name) {
        if out.contains(&token) {
            continue;
        }
        out.push(token);
    }
    out.retain(|t| {
        t.chars().count() >= MIN_TOKEN_LENGTH && !KEYWORD_STOPWORDS.contains(&t.as_str())
    });
    out
}

// --- the database and the indexer -------------------------------------------------------

/// The alert row the signals read.
struct AlertRef {
    id: i64,
    name: String,
    customer_code: String,
    source: String,
}

/// `select(Alert).where(Alert.id == alert_id)`, `None` also for an alert the
/// caller may not see (tag RBAC, then the customer).
async fn visible_alert(
    ctx: &AppContext,
    user: &CurrentUser,
    id: i64,
) -> Result<Option<AlertRef>, ApiError> {
    let Some(alert) = copilot_incidents::views::load_alert(&ctx.db, id).await? else {
        return Ok(None);
    };
    let tags = copilot_incidents::access::tag_scope(ctx, user).await?;
    if !copilot_incidents::access::tag_allows(&tags, &alert.tag_ids()) {
        return Ok(None);
    }
    if !copilot_incidents::access::can_access(ctx, user, Some(&alert.row.customer_code)).await? {
        return Ok(None);
    }
    Ok(Some(AlertRef {
        id: i64::from(alert.row.id),
        name: alert.row.alert_name.clone(),
        customer_code: alert.row.customer_code.clone(),
        source: alert.row.source.clone(),
    }))
}

/// `_load_alert_tags`.
async fn alert_tags(ctx: &AppContext, alert_id: i64) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT incident_management_alerttag.tag FROM incident_management_alerttag \
         JOIN incident_management_alert_to_tag ON incident_management_alert_to_tag.tag_id = \
         incident_management_alerttag.id WHERE incident_management_alert_to_tag.alert_id = ?",
    )
    .bind(alert_id)
    .fetch_all(ctx.db.pool())
    .await?;
    Ok(rows
        .into_iter()
        .flatten()
        .filter(|t| !t.is_empty())
        .collect())
}

/// `_load_alert_context`: the contexts of the alert's assets, by asset id,
/// the first value of a key winning.
async fn alert_context(
    ctx: &AppContext,
    alert_id: i64,
) -> Result<Vec<(String, PyValue)>, sqlx::Error> {
    let rows: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT CAST(incident_management_alertcontext.context AS CHAR) FROM \
         incident_management_alertcontext JOIN incident_management_asset ON \
         incident_management_asset.alert_context_id = incident_management_alertcontext.id \
         WHERE incident_management_asset.alert_linked = ? ORDER BY incident_management_asset.id ASC",
    )
    .bind(alert_id)
    .fetch_all(ctx.db.pool())
    .await?;
    let mut merged: Vec<(String, PyValue)> = Vec::new();
    for text in rows.into_iter().flatten() {
        let Ok(PyValue::Dict(items)) = copilot_auth::pyvalue::loads(&text) else {
            continue;
        };
        for (k, v) in items {
            if !merged.iter().any(|(key, _)| *key == k) {
                merged.push((k, v));
            }
        }
    }
    Ok(merged)
}

/// `_fetch_raw_event_for_alert`: the `_source` of the alert's lowest-id
/// asset's document, `None` on any failure.
async fn raw_event(
    ctx: &AppContext,
    es: &copilot_wazuh::es::EsHttp,
    alert_id: i64,
) -> Option<PyValue> {
    let asset: Option<(String, String)> = sqlx::query_as(
        "SELECT index_name, index_id FROM incident_management_asset WHERE \
         incident_management_asset.alert_linked = ? ORDER BY incident_management_asset.id ASC \
         LIMIT 1",
    )
    .bind(alert_id)
    .fetch_optional(ctx.db.pool())
    .await
    .ok()
    .flatten();
    let (index, id) = asset?;
    let client = Es::connect(es, &ctx.connectors, Flavor::Async).await.ok()?;
    match copilot_ingest::es::get(&client, &index, &id).await {
        Ok(doc) => {
            let source = doc.get("_source").cloned().unwrap_or(PyValue::None);
            Some(source)
        }
        Err(e) => {
            tracing::warn!(
                "pick_templates_for_alert: raw-event fetch failed for alert id={alert_id} \
                 (index={index}, id={id}): {e:?}. Falling back to non-field-match templates."
            );
            None
        }
    }
}

/// `load_usage_counts(session, customer_code)`, narrowed to `customers`
/// when given.
async fn usage_counts(
    ctx: &AppContext,
    customer: Option<&str>,
    customers: Option<&[String]>,
) -> BTreeMap<i64, i64> {
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT incident_management_case_template_task.template_id, count(DISTINCT \
         incident_management_case_task.case_id) AS count_1 FROM \
         incident_management_case_template_task JOIN incident_management_case_task ON \
         incident_management_case_task.template_task_id = incident_management_case_template_task.id",
    );
    if let Some(code) = customer {
        qb.push(
            " JOIN incident_management_case ON incident_management_case.id = \
             incident_management_case_task.case_id WHERE incident_management_case.customer_code = ",
        );
        qb.push_bind(code.to_string());
    } else if let Some(codes) = customers {
        if codes.is_empty() {
            return BTreeMap::new();
        }
        qb.push(
            " JOIN incident_management_case ON incident_management_case.id = \
             incident_management_case_task.case_id WHERE incident_management_case.customer_code IN (",
        );
        let mut list = qb.separated(", ");
        for c in codes {
            list.push_bind(c.clone());
        }
        list.push_unseparated(")");
    }
    qb.push(" GROUP BY incident_management_case_template_task.template_id");
    let rows: Result<Vec<(Option<i32>, i64)>, _> =
        qb.build_query_as().fetch_all(ctx.db.pool()).await;
    match rows {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|(id, n)| id.map(|id| (i64::from(id), n)))
            .collect(),
        Err(e) => {
            tracing::warn!(
                "template suggestions: usage-history lookup failed, scoring without it: {e}"
            );
            BTreeMap::new()
        }
    }
}

/// A finished answer (`CaseTemplateSuggestionListResponse`).
fn answer(suggestions: Vec<Value>, total: usize, success: bool, message: String) -> Value {
    json!({
        "suggestions": suggestions,
        "total_candidates": total,
        "success": success,
        "message": message,
    })
}

/// The request's inputs.
#[derive(Debug, Clone)]
pub struct Request {
    /// `alert_id`, as Pydantic's `int` wrote it (any size).
    pub alert_id: Option<String>,
    /// `customer_code`.
    pub customer_code: Option<String>,
    /// `source`.
    pub source: Option<String>,
    /// `limit` (1–50).
    pub limit: i64,
}

/// `suggest_templates(...)`: never fails the caller — a failure is
/// `success: false` with an empty list.
pub async fn suggest(
    ctx: &AppContext,
    es: &copilot_wazuh::es::EsHttp,
    user: &CurrentUser,
    scope: &AccessScope,
    req: Request,
) -> Value {
    match run(ctx, es, user, scope, &req).await {
        Ok(v) => v,
        Err(message) => {
            tracing::error!("Failed to build case template suggestions: {message}");
            answer(
                Vec::new(),
                0,
                false,
                format!("Failed to build case template suggestions: {message}"),
            )
        }
    }
}

async fn run(
    ctx: &AppContext,
    es: &copilot_wazuh::es::EsHttp,
    user: &CurrentUser,
    scope: &AccessScope,
    req: &Request,
) -> Result<Value, String> {
    let mut alert = None;
    if let Some(raw_id) = &req.alert_id {
        let found = match raw_id.parse::<i64>() {
            Ok(id) => visible_alert(ctx, user, id)
                .await
                .map_err(|e| format!("{e:?}"))?,
            Err(_) => None,
        };
        match found {
            Some(a) => alert = Some(a),
            None => {
                return Ok(answer(
                    Vec::new(),
                    0,
                    false,
                    format!("Alert id={raw_id} not found"),
                ));
            }
        }
    }
    let mut signals = Signals {
        customer_code: req.customer_code.clone(),
        source: req.source.clone(),
        ..Signals::default()
    };
    if let Some(a) = &alert {
        signals.alert_name = Some(a.name.clone());
        signals.customer_code = Some(a.customer_code.clone());
        signals.source = Some(a.source.clone());
        signals.tags = alert_tags(ctx, a.id).await.map_err(|e| e.to_string())?;
        let context = alert_context(ctx, a.id).await.map_err(|e| e.to_string())?;
        if !context.is_empty() {
            signals.doc_update(&context);
            signals.document_available = true;
            signals.fold(&PyValue::Dict(context));
        }
        signals.keywords = keywords(&a.name);
        signals.dedupe();
    }
    let templates = load_all(&ctx.db).await.map_err(|e| e.to_string())?;
    let candidates: Vec<(Candidate, &Template, &Vec<TemplateTask>)> = templates
        .iter()
        .map(|(t, tasks)| (Candidate::of(t, tasks), t, tasks))
        .filter(|(c, _, _)| in_scope(c, &signals))
        .collect();
    if let Some(a) = &alert {
        let unresolved = candidates.iter().any(|(c, _, _)| {
            match (truthy(&c.match_field), truthy(&c.match_value)) {
                (Some(field), Some(_)) => signals.doc_get(field).is_none(),
                _ => false,
            }
        });
        if unresolved {
            // `doc.get("_source") or {}`; an indexer document's `_source` is
            // always an object.
            if let Some(PyValue::Dict(items)) = raw_event(ctx, es, a.id).await {
                if !items.is_empty() {
                    signals.doc_update(&items);
                    signals.document_available = true;
                    signals.fold(&PyValue::Dict(items));
                    signals.dedupe();
                }
            }
        }
    }
    let narrowed: Option<Vec<String>> = match scope {
        AccessScope::All => None,
        AccessScope::Customers(codes) => Some(codes.clone()),
    };
    let customer = truthy(&signals.customer_code).map(str::to_string);
    let usage = usage_counts(
        ctx,
        customer.as_deref(),
        if customer.is_none() {
            narrowed.as_deref()
        } else {
            None
        },
    )
    .await;
    let mut ranked: Vec<(bool, i64, bool, String, Value)> = Vec::new();
    for (c, t, tasks) in &candidates {
        let (total, reasons, condition) = score(c, &signals, &usage);
        if condition == Some(false) {
            continue;
        }
        let reasons: Vec<Value> = reasons
            .iter()
            .map(|r| json!({"signal": r.signal, "detail": r.detail, "points": r.points}))
            .collect();
        ranked.push((
            condition == Some(true),
            total,
            t.is_default,
            copilot_jinja::unicode::lower(&t.name),
            json!({
                "template": template_json(t, tasks),
                "score": total,
                "confidence": confidence(total),
                "condition_matched": condition == Some(true),
                "reasons": reasons,
            }),
        ));
    }
    // `(not condition_matched, -score, not is_default, name.lower())`, stable.
    ranked.sort_by(|a, b| (!a.0, -a.1, !a.2, &a.3).cmp(&(!b.0, -b.1, !b.2, &b.3)));
    let total = ranked.len();
    let limit = usize::try_from(req.limit.max(0)).unwrap_or(usize::MAX);
    let top: Vec<Value> = ranked.into_iter().take(limit).map(|r| r.4).collect();
    Ok(answer(
        top,
        total,
        true,
        format!("Ranked {total} applicable template(s)"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vectors {
        text: TextVectors,
        scores: ScoreVectors,
    }

    #[derive(Deserialize)]
    struct TextVectors {
        usage: Vec<i64>,
    }

    #[derive(Deserialize)]
    struct ScoreVectors {
        templates: Vec<TemplateCase>,
        usage: BTreeMap<String, i64>,
        cases: Vec<ScoreCase>,
    }

    #[derive(Deserialize)]
    struct TemplateCase {
        id: i64,
        name: String,
        description: Option<String>,
        customer_code: Option<String>,
        source: Option<String>,
        is_default: bool,
        match_field: Option<String>,
        match_value: Option<String>,
        tasks: Vec<TaskCase>,
    }

    #[derive(Deserialize)]
    struct TaskCase {
        title: String,
        description: Option<String>,
        guidelines: Option<String>,
    }

    #[derive(Deserialize)]
    struct ScoreCase {
        signals: serde_json::Value,
        keywords: Vec<String>,
        results: Vec<ResultCase>,
    }

    #[derive(Deserialize)]
    struct ResultCase {
        template: i64,
        in_scope: bool,
        score: i64,
        confidence: String,
        condition: Option<bool>,
        reasons: Vec<ReasonCase>,
    }

    #[derive(Deserialize)]
    struct ReasonCase {
        signal: String,
        detail: String,
        points: i64,
    }

    fn strings(v: &serde_json::Value, key: &str) -> Vec<String> {
        v.get(key)
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn usage_points_are_python_s() {
        let v: Vectors = serde_json::from_str(include_str!("case_templates_vectors.json")).unwrap();
        for (n, want) in v.text.usage.iter().enumerate() {
            assert_eq!(usage_points(n as i64), *want, "{n}");
        }
    }

    #[test]
    fn templates_score_as_python_scores_them() {
        let v: Vectors = serde_json::from_str(include_str!("case_templates_vectors.json")).unwrap();
        let templates: Vec<Candidate> = v
            .scores
            .templates
            .iter()
            .map(|t| Candidate {
                id: t.id,
                name: t.name.clone(),
                description: t.description.clone(),
                customer_code: t.customer_code.clone(),
                source: t.source.clone(),
                is_default: t.is_default,
                match_field: t.match_field.clone(),
                match_value: t.match_value.clone(),
                tasks: t
                    .tasks
                    .iter()
                    .map(|k| (k.title.clone(), k.description.clone(), k.guidelines.clone()))
                    .collect(),
            })
            .collect();
        let usage: BTreeMap<i64, i64> = v
            .scores
            .usage
            .iter()
            .map(|(k, n)| (k.parse().unwrap(), *n))
            .collect();
        for case in &v.scores.cases {
            let raw = &case.signals;
            let document = match raw.get("document") {
                Some(d) => match copilot_auth::pyvalue::loads(&d.to_string()).unwrap() {
                    PyValue::Dict(items) => items,
                    _ => Vec::new(),
                },
                None => Vec::new(),
            };
            let signals = Signals {
                customer_code: raw["customer_code"].as_str().map(str::to_string),
                source: raw["source"].as_str().map(str::to_string),
                alert_name: raw
                    .get("alert_name")
                    .and_then(|a| a.as_str())
                    .map(str::to_string),
                tags: strings(raw, "tags"),
                mitre_ids: strings(raw, "mitre_ids").into_iter().collect(),
                mitre_names: strings(raw, "mitre_names"),
                rule_groups: strings(raw, "rule_groups"),
                keywords: keywords(raw.get("alert_name").and_then(|a| a.as_str()).unwrap_or("")),
                document,
                document_available: raw
                    .get("document_available")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            };
            assert_eq!(signals.keywords, case.keywords);
            for (t, want) in templates.iter().zip(&case.results) {
                assert_eq!(t.id, want.template);
                assert_eq!(in_scope(t, &signals), want.in_scope, "{} {raw}", t.id);
                let (total, reasons, condition) = score(t, &signals, &usage);
                assert_eq!(total, want.score, "{} {raw}", t.id);
                assert_eq!(confidence(total), want.confidence);
                assert_eq!(condition, want.condition, "{} {raw}", t.id);
                let got: Vec<(String, String, i64)> = reasons
                    .iter()
                    .map(|r| (r.signal.to_string(), r.detail.clone(), r.points))
                    .collect();
                let expected: Vec<(String, String, i64)> = want
                    .reasons
                    .iter()
                    .map(|r| (r.signal.clone(), r.detail.clone(), r.points))
                    .collect();
                assert_eq!(got, expected, "{} {raw}", t.id);
            }
        }
    }
}
