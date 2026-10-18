//! What the routes of `routes/github_audit.py` do beyond reading and
//! writing rows: the tenant decision for an object addressed by its own id,
//! the audit run with its report, and a baseline's expected checks.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::construct;
use copilot_upstream::py::{PyExc, PyResult, getitem, iterate, py_eq, type_name};
use copilot_web::{ApiError, CurrentUser};

use super::audit::{Audit, AuditResponse, Scope, apply_exclusions};
use super::client::GithubHttp;
use super::schema::AUDIT_REQUEST;
use super::store::{self, AuditWriteBack, ConfigRow};
use crate::AssessmentsState;

/// Which object a route resolves (for the 404 and 403 texts).
#[derive(Debug, Clone, Copy)]
pub enum Object {
    /// `github_audit_config`.
    Config,
    /// `github_audit_report`.
    Report,
    /// `github_audit_check_exclusion`.
    Exclusion,
    /// `github_audit_baseline`.
    Baseline,
}

impl Object {
    fn not_found(self) -> &'static str {
        match self {
            Object::Config => "Configuration not found",
            Object::Report => "Report not found",
            Object::Exclusion => "Exclusion not found",
            Object::Baseline => "Baseline not found",
        }
    }

    fn subject(self, id: &str) -> String {
        match self {
            Object::Config => format!("GitHub audit configuration {id}"),
            Object::Report => format!("GitHub audit report {id}"),
            Object::Exclusion => format!("GitHub audit exclusion {id}"),
            Object::Baseline => format!("GitHub audit baseline {id}"),
        }
    }
}

/// An object addressed by its own id: its owner must be one of the caller's
/// customers (§4: Python checked none). Fail closed: an id that does not
/// exist is a 403 for a scoped caller; an admin gets Python's 404 (`detail`
/// for that case: `None` when Python answers without one).
pub async fn owned<T>(
    st: &AssessmentsState,
    user: &CurrentUser,
    object: Object,
    id: &str,
    row: Option<T>,
    owner: impl Fn(&T) -> &str,
) -> Result<T, ApiError> {
    match row {
        Some(row) => {
            user.enforce_owned(&st.ctx, Some(owner(&row)), &object.subject(id))
                .await?;
            Ok(row)
        }
        None => {
            user.enforce_owned(&st.ctx, None, &object.subject(id))
                .await?;
            Err(ApiError::not_found(object.not_found()))
        }
    }
}

/// A configuration that a listing names (`GET …/exclusions`,
/// `…/baselines`): Python lists without looking it up, so a missing one is
/// only refused to a scoped caller.
pub async fn listing_owner(
    st: &AssessmentsState,
    user: &CurrentUser,
    id: &str,
) -> Result<(), ApiError> {
    let row = store::config(&st.ctx.db, id).await?;
    user.enforce_owned(
        &st.ctx,
        row.as_ref().map(|r| r.customer_code.as_str()),
        &Object::Config.subject(id),
    )
    .await?;
    Ok(())
}

/// The GitHub API base: `GITHUB_API_BASE`, or the harness's stand-in.
pub fn api_base(st: &AssessmentsState) -> &str {
    st.github_api
        .as_deref()
        .unwrap_or(super::client::GITHUB_API_BASE)
}

/// `run_github_audit(token, request)`.
pub async fn run_audit(st: &AssessmentsState, token: &str, scope: &Scope) -> AuditResponse {
    match GithubHttp::new(api_base(st), token) {
        Ok(http) => Audit::new(&http, &scope.organization).run(scope).await,
        Err(e) => AuditResponse {
            success: false,
            message: format!("Audit failed: {}", e.message),
            organization: scope.organization.clone(),
            summary: None,
            organization_results: None,
            repository_results: Vec::new(),
            workflow_results: Vec::new(),
            member_results: Vec::new(),
            top_findings: Vec::new(),
        },
    }
}

/// `GitHubAuditRequest(organization=…, …, repo_filter=…)` built from a
/// stored configuration: a `repo_filter_list` the model refuses is its
/// `ValidationError` (the handler's 400).
pub fn config_scope(config: &ConfigRow, with_filter: bool) -> PyResult<Scope> {
    let repo_filter = match &config.repo_filter_list {
        Some(list) if with_filter && config.repo_filter_mode == "include" && list.truthy() => {
            list.clone()
        }
        _ => PyValue::None,
    };
    let dump = construct(
        &AUDIT_REQUEST,
        &copilot_upstream::model::kwargs(vec![
            ("organization", PyValue::Str(config.organization.clone())),
            ("include_repos", PyValue::Bool(config.include_repos)),
            ("include_workflows", PyValue::Bool(config.include_workflows)),
            ("include_members", PyValue::Bool(config.include_members)),
            ("repo_filter", repo_filter),
        ]),
    )?;
    let repo_filter = match copilot_upstream::model::field(&dump, "repo_filter") {
        PyValue::List(items) => Some(
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
    };
    Ok(Scope {
        organization: config.organization.clone(),
        include_repos: config.include_repos,
        include_workflows: config.include_workflows,
        include_members: config.include_members,
        repo_filter,
    })
}

/// `run_audit_from_config` after its checks: the `running` report, the
/// audit, the exclusions applied to the top findings, the write-back.
pub async fn audit_from_config(
    st: &AssessmentsState,
    config: &ConfigRow,
    scope: &Scope,
    exclusions: &[(String, Option<String>)],
) -> Result<AuditResponse, ApiError> {
    let now = chrono::Utc::now();
    let report_name = format!(
        "Audit-{}-{}",
        config.organization,
        now.format("%Y%m%d-%H%M%S")
    );
    let report_id = store::insert_running_report(&st.ctx.db, config, &report_name).await?;
    let start = chrono::Utc::now();
    let mut response = run_audit(st, &config.github_token, scope).await;
    let end = chrono::Utc::now();
    apply_exclusions(&mut response.top_findings, exclusions);
    let duration = (end - start)
        .num_microseconds()
        .map_or(0.0, |us| us as f64 / 1e6);
    let top: Vec<PyValue> = response
        .top_findings
        .iter()
        .take(20)
        .map(|c| c.dump.clone())
        .collect();
    let dumps = |v: &PyValue| {
        copilot_upstream::json::py_dumps_allow_nan(v, copilot_upstream::json::Dumps::DEFAULT)
    };
    let write = AuditWriteBack {
        status: if response.success {
            "completed"
        } else {
            "failed"
        },
        completed_at: end.naive_utc(),
        duration,
        summary: response
            .summary
            .as_ref()
            .map(|s| (s.counts, s.score, s.grade.clone())),
        full_report: dumps(&response.dump()),
        top_findings: dumps(&PyValue::List(top)),
    };
    store::finish_report(&st.ctx.db, report_id, config.id, &write).await?;
    Ok(response)
}

/// `expected_checks[key] = value` with Python's dict semantics on a key
/// that may be any hashable `json.loads` value.
fn set_key(map: &mut Vec<(PyValue, PyValue)>, key: PyValue, value: PyValue) -> PyResult<()> {
    if matches!(key, PyValue::List(_) | PyValue::Dict(_)) {
        return Err(PyExc::TypeError(format!(
            "unhashable type: '{}'",
            type_name(&key)
        )));
    }
    match map.iter_mut().find(|(k, _)| py_eq(k, &key)) {
        Some(slot) => slot.1 = value,
        None => map.push((key, value)),
    }
    Ok(())
}

/// `json.dumps`' key for a dict key (`str` kept; `int`, `float`, `bool`
/// and `None` converted).
fn json_key(key: &PyValue) -> String {
    match key {
        PyValue::Str(s) => s.clone(),
        PyValue::Bool(true) => "true".into(),
        PyValue::Bool(false) => "false".into(),
        PyValue::None => "null".into(),
        PyValue::Float(f) if f.is_nan() => "NaN".into(),
        PyValue::Float(f) if f.is_infinite() => {
            if *f > 0.0 { "Infinity" } else { "-Infinity" }.into()
        }
        other => other.py_repr(),
    }
}

/// `key in value` (`TypeError` where CPython raises it).
fn contains(value: &PyValue, key: &str) -> PyResult<bool> {
    match value {
        PyValue::Dict(items) => Ok(items.iter().any(|(k, _)| k == key)),
        PyValue::List(items) => Ok(items
            .iter()
            .any(|i| py_eq(i, &PyValue::Str(key.to_string())))),
        PyValue::Str(s) => Ok(s.contains(key)),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

/// `create_baseline`'s extraction of the expected checks from a report's
/// `full_report`: the organization checks by `check_id`, the repository
/// checks by `check_id:repo_name`.
pub fn expected_checks(full_report: &PyValue) -> PyResult<PyValue> {
    let mut out: Vec<(PyValue, PyValue)> = Vec::new();
    if contains(full_report, "organization_results")? {
        let org = getitem(full_report, "organization_results")?;
        if org.truthy() {
            let checks = copilot_upstream::py::get(org, "checks")?
                .cloned()
                .unwrap_or(PyValue::List(Vec::new()));
            for check in iterate(&checks)? {
                let key = getitem(&check, "check_id")?.clone();
                let status = getitem(&check, "status")?.clone();
                set_key(&mut out, key, status)?;
            }
        }
    }
    let repos = copilot_upstream::py::get(full_report, "repository_results")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    for repo in iterate(&repos)? {
        let checks = copilot_upstream::py::get(&repo, "checks")?
            .cloned()
            .unwrap_or(PyValue::List(Vec::new()));
        for check in iterate(&checks)? {
            let key = format!(
                "{}:{}",
                getitem(&check, "check_id")?.py_str(),
                getitem(&repo, "repo_name")?.py_str()
            );
            let status = getitem(&check, "status")?.clone();
            set_key(&mut out, PyValue::Str(key), status)?;
        }
    }
    Ok(PyValue::Dict(
        out.into_iter().map(|(k, v)| (json_key(&k), v)).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn baselines_read_reports_like_python() {
        let report = loads(
            r#"{"organization_results": {"checks": [{"check_id": "org-2fa-required",
            "status": "fail"}, {"check_id": "org-sso", "status": "pass"}]},
            "repository_results": [{"repo_name": "web", "checks": [{"check_id": "repo-license",
            "status": "warning"}]}, {"repo_name": 7, "checks": []}]}"#,
        )
        .unwrap();
        assert_eq!(
            expected_checks(&report).unwrap().py_repr(),
            "{'org-2fa-required': 'fail', 'org-sso': 'pass', 'repo-license:web': 'warning'}"
        );
        let e = expected_checks(&loads(r#"{"repository_results": [1]}"#).unwrap()).unwrap_err();
        assert_eq!(e.text(), "'int' object has no attribute 'get'");
        let e = expected_checks(&loads("[1]").unwrap()).unwrap_err();
        assert_eq!(e.text(), "'list' object has no attribute 'get'");
        let e = expected_checks(
            &loads(r#"{"organization_results": {"checks": [{"check_id": [1], "status": 1}]}}"#)
                .unwrap(),
        )
        .unwrap_err();
        assert_eq!(e.text(), "unhashable type: 'list'");
        let e = expected_checks(&loads(r#"{"repository_results": [{"checks": ["x"]}]}"#).unwrap())
            .unwrap_err();
        assert_eq!(e.text(), "string indices must be integers, not 'str'");
    }
}
