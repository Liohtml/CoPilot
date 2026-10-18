//! `GitHubAuditService.run_full_audit`, line by line.
//!
//! Every value the checks read comes from GitHub's JSON as `json.loads`
//! made it ([`PyValue`]), and every operation on it is Python's: `.get` on a
//! non-dict is the `AttributeError` that fails the whole audit (`Audit
//! failed: 'NoneType' object has no attribute 'get'`), truthiness decides
//! the branches, f-strings print `str()`, `in` compares with `==`, and the
//! result models validate what they are handed (a repository whose `name` is
//! a number fails `AuditCheck` with Pydantic's text). The repositories are
//! audited ten at a time, concurrently, as `asyncio.gather` runs them; the
//! first one to fail (in time) is the audit's failure. `gather` does not
//! cancel the batch's other tasks, so they finish here too (in Python they
//! run on after the failure until the client closes, a timing-dependent
//! cut — the one place the requests sent can differ, never the answer).
//!
//! The transport is a trait ([`Transport`]) so the vectors drive the same
//! code with GitHub's answers canned (`assessments_vectors.json`).

use std::future::Future;
use std::pin::Pin;

use copilot_auth::pyvalue::{PyValue, float_repr};
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, get, py_eq, type_name};
use futures::StreamExt;
use futures::stream::FuturesUnordered;

use super::schema::{
    AUDIT_CHECK, MEMBER_RESULT, ORGANIZATION_RESULT, REPOSITORY_RESULT, WORKFLOW_RESULT,
};

/// What `_request` returns: the JSON of a 200 (else `None`) and the status
/// (`500` for any exception: a transport failure, a body that is not JSON).
pub type Fetch = (Option<PyValue>, u16);

/// `GitHubAuditService._request("GET", endpoint, params)`.
pub trait Transport: Send + Sync {
    /// One GET of `{GITHUB_API_BASE}{endpoint}` with `params=` (in order;
    /// empty for `params=None`).
    fn get(
        &self,
        endpoint: String,
        params: Vec<(String, String)>,
    ) -> Pin<Box<dyn Future<Output = Fetch> + Send + '_>>;
}

/// One `AuditCheck`: its JSON-mode dump and what the service reads back.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    /// The dump.
    pub dump: PyValue,
    /// `check_id`.
    pub check_id: String,
    /// `status` (the enum's value).
    pub status: String,
    /// `severity` (the enum's value).
    pub severity: String,
    /// `resource_name` (a `str` or `None`).
    pub resource_name: PyValue,
}

fn s(text: impl Into<String>) -> PyValue {
    PyValue::Str(text.into())
}

fn opt(text: Option<&str>) -> PyValue {
    text.map_or(PyValue::None, s)
}

/// `AuditCheck(...)` with every argument given.
#[allow(clippy::too_many_arguments)]
fn audit_check(
    check_id: &str,
    check_name: &str,
    category: &str,
    status: &str,
    severity: &str,
    description: String,
    recommendation: Option<&str>,
    details: Option<PyValue>,
    resource_name: PyValue,
    resource_type: Option<&str>,
) -> PyResult<Check> {
    let dump = construct(
        &AUDIT_CHECK,
        &kwargs(vec![
            ("check_id", s(check_id)),
            ("check_name", s(check_name)),
            ("category", s(category)),
            ("status", s(status)),
            ("severity", s(severity)),
            ("description", s(description)),
            ("recommendation", opt(recommendation)),
            ("details", details.unwrap_or(PyValue::None)),
            ("resource_name", resource_name),
            ("resource_type", opt(resource_type)),
        ]),
    )?;
    Ok(Check {
        check_id: check_id.to_string(),
        status: status.to_string(),
        severity: severity.to_string(),
        resource_name: field(&dump, "resource_name").clone(),
        dump,
    })
}

/// `value.get(key, default)` (an `AttributeError` on anything but a dict).
fn get_or(value: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(get(value, key)?.cloned().unwrap_or(default))
}

/// `value.get(key)`.
fn get_none(value: &PyValue, key: &str) -> PyResult<PyValue> {
    get_or(value, key, PyValue::None)
}

fn is_str(value: &PyValue, text: &str) -> bool {
    py_eq(value, &s(text))
}

/// `hash(value)`: a list or dict raises.
fn hashable(value: &PyValue) -> PyResult<()> {
    match value {
        PyValue::List(_) | PyValue::Dict(_) => Err(PyExc::TypeError(format!(
            "unhashable type: '{}'",
            type_name(value)
        ))),
        _ => Ok(()),
    }
}

fn counts(checks: &[Check]) -> (usize, usize, usize) {
    let n = |st: &str| checks.iter().filter(|c| c.status == st).count();
    (n("pass"), n("fail"), n("warning"))
}

fn int(n: usize) -> PyValue {
    PyValue::Int(n.to_string())
}

fn dumps(checks: &[Check]) -> PyValue {
    PyValue::List(checks.iter().map(|c| c.dump.clone()).collect())
}

/// One result model and the checks it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    /// The model's dump.
    pub dump: PyValue,
    /// Its `checks`.
    pub checks: Vec<Check>,
}

/// `AuditSummary`.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    /// `audit_timestamp` (`datetime.now(timezone.utc).isoformat()`).
    pub audit_timestamp: String,
    /// `total_repos_audited` … `low_findings`, in field order.
    pub counts: [i64; 9],
    /// `score`.
    pub score: f64,
    /// `grade`.
    pub grade: String,
}

const SUMMARY_COUNTS: [&str; 9] = [
    "total_repos_audited",
    "total_checks",
    "passed_checks",
    "failed_checks",
    "warning_checks",
    "critical_findings",
    "high_findings",
    "medium_findings",
    "low_findings",
];

impl Summary {
    fn dump(&self, organization: &str) -> PyValue {
        let mut pairs = vec![
            ("organization".to_string(), s(organization)),
            (
                "audit_timestamp".to_string(),
                s(self.audit_timestamp.clone()),
            ),
        ];
        for (name, n) in SUMMARY_COUNTS.iter().zip(self.counts) {
            pairs.push(((*name).to_string(), PyValue::Int(n.to_string())));
        }
        pairs.push(("score".into(), PyValue::Float(self.score)));
        pairs.push(("grade".into(), s(self.grade.clone())));
        PyValue::Dict(pairs)
    }
}

/// `GitHubAuditResponse`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditResponse {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// The organization audited (the summary's `organization`).
    pub organization: String,
    /// `summary`.
    pub summary: Option<Summary>,
    /// `organization_results`.
    pub organization_results: Option<PyValue>,
    /// `repository_results`.
    pub repository_results: Vec<PyValue>,
    /// `workflow_results`.
    pub workflow_results: Vec<PyValue>,
    /// `member_results`.
    pub member_results: Vec<PyValue>,
    /// `top_findings`.
    pub top_findings: Vec<Check>,
}

impl AuditResponse {
    fn failed(organization: &str, e: &PyExc) -> Self {
        Self {
            success: false,
            message: format!("Audit failed: {}", e.display()),
            organization: organization.to_string(),
            summary: None,
            organization_results: None,
            repository_results: Vec::new(),
            workflow_results: Vec::new(),
            member_results: Vec::new(),
            top_findings: Vec::new(),
        }
    }

    /// The summary's dump (`None`).
    pub fn summary_dump(&self) -> PyValue {
        self.summary
            .as_ref()
            .map_or(PyValue::None, |sm| sm.dump(&self.organization))
    }

    /// `model_dump()` (JSON mode: the enums as their values).
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(self.success)),
            ("message".into(), s(self.message.clone())),
            ("summary".into(), self.summary_dump()),
            (
                "organization_results".into(),
                self.organization_results.clone().unwrap_or(PyValue::None),
            ),
            (
                "repository_results".into(),
                PyValue::List(self.repository_results.clone()),
            ),
            (
                "workflow_results".into(),
                PyValue::List(self.workflow_results.clone()),
            ),
            (
                "member_results".into(),
                PyValue::List(self.member_results.clone()),
            ),
            ("top_findings".into(), dumps(&self.top_findings)),
        ])
    }

    /// `GitHubAuditSummaryResponse(..., top_findings=top_findings[:10])`.
    pub fn summary_response(&self) -> PyValue {
        let top: Vec<Check> = self.top_findings.iter().take(10).cloned().collect();
        PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(self.success)),
            ("message".into(), s(self.message.clone())),
            ("summary".into(), self.summary_dump()),
            ("top_findings".into(), dumps(&top)),
        ])
    }
}

/// What the audit is asked to do (`GitHubAuditRequest`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scope {
    /// `organization`.
    pub organization: String,
    /// `include_repos`.
    pub include_repos: bool,
    /// `include_workflows`.
    pub include_workflows: bool,
    /// `include_members`.
    pub include_members: bool,
    /// `repo_filter` (the names; `None` = every repository).
    pub repo_filter: Option<Vec<String>>,
}

/// `round(x, 1)`: the correctly rounded one-decimal value (ties to even on
/// the exact binary value, as `_Py_dg_dtoa` rounds).
pub fn py_round1(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.1}").parse().unwrap_or(x)
}

/// `datetime.now(timezone.utc).isoformat()`.
pub fn utc_isoformat(now: chrono::DateTime<chrono::Utc>) -> String {
    let base = now.format("%Y-%m-%dT%H:%M:%S").to_string();
    let micros = now.timestamp_subsec_micros();
    if micros == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micros:06}+00:00")
    }
}

/// The service for one organization over one transport.
pub struct Audit<'a, T: Transport> {
    t: &'a T,
    org: String,
}

impl<'a, T: Transport> Audit<'a, T> {
    /// `GitHubAuditService(token, organization)` (the token is the
    /// transport's).
    pub fn new(t: &'a T, organization: &str) -> Self {
        Self {
            t,
            org: organization.to_string(),
        }
    }

    async fn request(&self, endpoint: String, params: Vec<(String, String)>) -> Fetch {
        self.t.get(endpoint, params).await
    }

    /// `_paginate`: 100 a page until a short page, a non-200 or an empty
    /// answer; an answer that is not a list is appended as one item.
    async fn paginate(&self, endpoint: String, mut params: Vec<(String, String)>) -> Vec<PyValue> {
        let mut results = Vec::new();
        params.push(("per_page".into(), "100".into()));
        params.push(("page".into(), String::new()));
        let mut page = 1u64;
        loop {
            if let Some(last) = params.last_mut() {
                last.1 = page.to_string();
            }
            let (data, status) = self.request(endpoint.clone(), params.clone()).await;
            let Some(data) = data.filter(|d| status == 200 && d.truthy()) else {
                break;
            };
            match data {
                PyValue::List(items) => {
                    let short = items.len() < 100;
                    results.extend(items);
                    if short {
                        break;
                    }
                }
                other => {
                    results.push(other);
                    break;
                }
            }
            page += 1;
        }
        results
    }

    // --- the organization -----------------------------------------------------------------

    async fn audit_organization(&self) -> PyResult<Section> {
        let org = &self.org;
        let (org_data, status) = self.request(format!("/orgs/{org}"), Vec::new()).await;
        let Some(org_data) = org_data.filter(|d| status == 200 && d.truthy()) else {
            let check = audit_check(
                "org-access",
                "Organization Access",
                "organization",
                "fail",
                "critical",
                "Unable to access organization".into(),
                Some("Verify the token has org:read permissions"),
                None,
                PyValue::None,
                None,
            )?;
            let dump = construct(
                &ORGANIZATION_RESULT,
                &kwargs(vec![
                    ("org_name", s(org.clone())),
                    ("org_url", s(format!("https://github.com/{org}"))),
                    ("checks", dumps(std::slice::from_ref(&check))),
                    ("failed_count", int(1)),
                ]),
            )?;
            return Ok(Section {
                dump,
                checks: vec![check],
            });
        };
        let checks = vec![
            self.check_2fa(&org_data)?,
            self.check_default_permission(&org_data)?,
            self.check_member_creation(&org_data)?,
            self.check_public_creation(&org_data)?,
            self.check_verified_domains().await?,
            self.check_sso().await?,
        ];
        let (passed, failed, warnings) = counts(&checks);
        let org_url = get_or(
            &org_data,
            "html_url",
            s(format!("https://github.com/{org}")),
        )?;
        let dump = construct(
            &ORGANIZATION_RESULT,
            &kwargs(vec![
                ("org_name", s(org.clone())),
                ("org_url", org_url),
                ("checks", dumps(&checks)),
                ("passed_count", int(passed)),
                ("failed_count", int(failed)),
                ("warning_count", int(warnings)),
            ]),
        )?;
        Ok(Section { dump, checks })
    }

    fn check_2fa(&self, org_data: &PyValue) -> PyResult<Check> {
        let required = get_or(
            org_data,
            "two_factor_requirement_enabled",
            PyValue::Bool(false),
        )?;
        let ok = required.truthy();
        audit_check(
            "org-2fa-required",
            "Two-Factor Authentication Required",
            "organization",
            if ok { "pass" } else { "fail" },
            "critical",
            "Checks if 2FA is required for all organization members".into(),
            (!ok).then_some(
                "Enable 2FA requirement in Organization Settings > Authentication security",
            ),
            None,
            s(self.org.clone()),
            Some("organization"),
        )
    }

    fn check_default_permission(&self, org_data: &PyValue) -> PyResult<Check> {
        let permission = get_or(org_data, "default_repository_permission", s("read"))?;
        let secure = is_str(&permission, "none") || is_str(&permission, "read");
        audit_check(
            "org-default-permission",
            "Default Repository Permission",
            "organization",
            if secure { "pass" } else { "warning" },
            "medium",
            format!(
                "Default repository permission is set to '{}'",
                permission.py_str()
            ),
            (!secure).then_some(
                "Set default repository permission to 'read' or 'none' to follow least privilege",
            ),
            Some(PyValue::Dict(vec![(
                "current_permission".into(),
                permission,
            )])),
            s(self.org.clone()),
            Some("organization"),
        )
    }

    fn check_member_creation(&self, org_data: &PyValue) -> PyResult<Check> {
        let can = get_or(
            org_data,
            "members_can_create_repositories",
            PyValue::Bool(true),
        )?
        .truthy();
        audit_check(
            "org-member-repo-creation",
            "Member Repository Creation",
            "organization",
            if can { "warning" } else { "pass" },
            "low",
            if can {
                "Members can create repositories"
            } else {
                "Members cannot create repositories"
            }
            .into(),
            can.then_some(
                "Consider restricting repository creation to admins for better governance",
            ),
            None,
            s(self.org.clone()),
            Some("organization"),
        )
    }

    fn check_public_creation(&self, org_data: &PyValue) -> PyResult<Check> {
        let can = get_or(
            org_data,
            "members_can_create_public_repositories",
            PyValue::Bool(true),
        )?
        .truthy();
        audit_check(
            "org-public-repo-creation",
            "Public Repository Creation",
            "organization",
            if can { "fail" } else { "pass" },
            "high",
            if can {
                "Members can create public repositories"
            } else {
                "Members cannot create public repositories"
            }
            .into(),
            can.then_some(
                "Restrict public repository creation to prevent accidental exposure of internal code",
            ),
            None,
            s(self.org.clone()),
            Some("organization"),
        )
    }

    async fn check_verified_domains(&self) -> PyResult<Check> {
        let (domains, status) = self
            .request(format!("/orgs/{}/domains", self.org), Vec::new())
            .await;
        if status == 404 {
            return audit_check(
                "org-verified-domains",
                "Verified Domains",
                "organization",
                "not_applicable",
                "info",
                "Domain verification not available (requires GitHub Enterprise)".into(),
                None,
                None,
                s(self.org.clone()),
                Some("organization"),
            );
        }
        let mut verified = Vec::new();
        if let Some(PyValue::List(items)) = domains.as_ref().filter(|d| d.truthy()) {
            for d in items {
                if get_or(d, "is_verified", PyValue::Bool(false))?.truthy() {
                    verified.push(d.clone());
                }
            }
        }
        let has = !verified.is_empty();
        let details = if has {
            let mut names = Vec::new();
            for d in &verified {
                names.push(get_none(d, "domain")?);
            }
            Some(PyValue::Dict(vec![(
                "verified_domains".into(),
                PyValue::List(names),
            )]))
        } else {
            None
        };
        audit_check(
            "org-verified-domains",
            "Verified Domains",
            "organization",
            if has { "pass" } else { "warning" },
            "medium",
            if has {
                format!("Organization has {} verified domain(s)", verified.len())
            } else {
                "Organization has no verified domains".into()
            },
            (!has).then_some(
                "Add and verify your organization's domain to improve trust and enable \
                 additional features",
            ),
            details,
            s(self.org.clone()),
            Some("organization"),
        )
    }

    async fn check_sso(&self) -> PyResult<Check> {
        let (saml, status) = self
            .request(format!("/orgs/{}/saml", self.org), Vec::new())
            .await;
        if status == 404 {
            return audit_check(
                "org-sso-enforcement",
                "SAML SSO Enforcement",
                "organization",
                "not_applicable",
                "info",
                "SAML SSO configuration not available (requires GitHub Enterprise Cloud)".into(),
                None,
                None,
                s(self.org.clone()),
                Some("organization"),
            );
        }
        let enforced = match saml.filter(PyValue::truthy) {
            Some(data) => get_or(&data, "enforced", PyValue::Bool(false))?.truthy(),
            None => false,
        };
        audit_check(
            "org-sso-enforcement",
            "SAML SSO Enforcement",
            "organization",
            if enforced { "pass" } else { "warning" },
            "high",
            if enforced {
                "SAML SSO is enforced"
            } else {
                "SAML SSO is not enforced"
            }
            .into(),
            (!enforced).then_some("Enable SAML SSO enforcement for centralized authentication"),
            None,
            s(self.org.clone()),
            Some("organization"),
        )
    }

    // --- the repositories -----------------------------------------------------------------

    async fn audit_repositories(&self, repo_filter: Option<&[String]>) -> PyResult<Vec<Section>> {
        let mut repos = self
            .paginate(format!("/orgs/{}/repos", self.org), Vec::new())
            .await;
        if repos.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(filter) = repo_filter.filter(|f| !f.is_empty()) {
            let mut kept = Vec::new();
            for r in repos {
                let name = get_none(&r, "name")?;
                if filter.iter().any(|f| py_eq(&name, &s(f.clone()))) {
                    kept.push(r);
                }
            }
            repos = kept;
        }
        let mut results = Vec::with_capacity(repos.len());
        for batch in repos.chunks(10) {
            let mut slots: Vec<Option<Section>> = vec![None; batch.len()];
            let mut running: FuturesUnordered<_> = batch
                .iter()
                .enumerate()
                .map(|(i, repo)| async move { (i, self.audit_single_repo(repo).await) })
                .collect();
            // `asyncio.gather` raises the first exception to happen; the
            // batch's other tasks are not cancelled — they run on.
            let mut first_error = None;
            while let Some((i, outcome)) = running.next().await {
                match outcome {
                    Ok(section) => slots[i] = Some(section),
                    Err(e) => {
                        first_error.get_or_insert(e);
                    }
                }
            }
            if let Some(e) = first_error {
                return Err(e);
            }
            results.extend(slots.into_iter().flatten());
        }
        Ok(results)
    }

    async fn audit_single_repo(&self, repo: &PyValue) -> PyResult<Section> {
        let repo_name = get_or(repo, "name", s("unknown"))?;
        let full_name = get_or(
            repo,
            "full_name",
            s(format!("{}/{}", self.org, repo_name.py_str())),
        )?;
        if get_or(repo, "archived", PyValue::Bool(false))?.truthy() {
            let repo_url = get_or(repo, "html_url", s(""))?;
            let is_private = get_or(repo, "private", PyValue::Bool(true))?;
            let default_branch = get_or(repo, "default_branch", s("main"))?;
            let check = audit_check(
                "repo-archived",
                "Repository Archived",
                "repository",
                "not_applicable",
                "info",
                "Repository is archived - skipping security checks".into(),
                None,
                None,
                repo_name.clone(),
                Some("repository"),
            )?;
            let dump = construct(
                &REPOSITORY_RESULT,
                &kwargs(vec![
                    ("repo_name", repo_name),
                    ("repo_full_name", full_name),
                    ("repo_url", repo_url),
                    ("is_private", is_private),
                    ("is_archived", PyValue::Bool(true)),
                    ("default_branch", default_branch),
                    ("checks", dumps(std::slice::from_ref(&check))),
                ]),
            )?;
            return Ok(Section {
                dump,
                checks: vec![check],
            });
        }
        let checks = vec![
            self.check_branch_protection(repo).await?,
            self.check_secret_scanning(repo).await?,
            self.check_dependabot(repo).await?,
            self.check_code_scanning(repo).await?,
            check_private_vulnerability_reporting(repo)?,
            check_license(repo)?,
            self.check_branch_deletion(repo).await?,
        ];
        let (passed, failed, warnings) = counts(&checks);
        let dump = construct(
            &REPOSITORY_RESULT,
            &kwargs(vec![
                ("repo_name", repo_name),
                ("repo_full_name", full_name),
                ("repo_url", get_or(repo, "html_url", s(""))?),
                ("is_private", get_or(repo, "private", PyValue::Bool(true))?),
                ("is_archived", PyValue::Bool(false)),
                ("default_branch", get_or(repo, "default_branch", s("main"))?),
                ("checks", dumps(&checks)),
                ("passed_count", int(passed)),
                ("failed_count", int(failed)),
                ("warning_count", int(warnings)),
            ]),
        )?;
        Ok(Section { dump, checks })
    }

    async fn check_branch_protection(&self, repo: &PyValue) -> PyResult<Check> {
        let repo_name = get_none(repo, "name")?;
        let branch = get_or(repo, "default_branch", s("main"))?;
        let (protection, status) = self
            .request(
                format!(
                    "/repos/{}/{}/branches/{}/protection",
                    self.org,
                    repo_name.py_str(),
                    branch.py_str()
                ),
                Vec::new(),
            )
            .await;
        if status == 404 {
            return audit_check(
                "repo-branch-protection",
                "Default Branch Protection",
                "repository",
                "fail",
                "high",
                format!(
                    "Default branch '{}' has no protection rules",
                    branch.py_str()
                ),
                Some("Enable branch protection rules to prevent direct pushes and require reviews"),
                None,
                repo_name,
                Some("repository"),
            );
        }
        let mut details: Vec<(String, PyValue)> = Vec::new();
        let mut issues: Vec<&str> = Vec::new();
        if let Some(protection) = protection.filter(PyValue::truthy) {
            let reviews = get_none(&protection, "required_pull_request_reviews")?;
            if reviews.truthy() {
                details.push((
                    "required_approving_reviews".into(),
                    get_or(
                        &reviews,
                        "required_approving_review_count",
                        PyValue::Int("0".into()),
                    )?,
                ));
            } else {
                issues.push("Pull request reviews not required");
            }
            let admins = get_or(&protection, "enforce_admins", PyValue::Dict(Vec::new()))?;
            if !get_or(&admins, "enabled", PyValue::Bool(false))?.truthy() {
                issues.push("Admins can bypass protection");
            }
            if !get_none(&protection, "required_status_checks")?.truthy() {
                issues.push("No required status checks");
            }
            let reviews = if reviews.truthy() {
                reviews
            } else {
                PyValue::Dict(Vec::new())
            };
            details.push((
                "dismiss_stale_reviews".into(),
                get_or(&reviews, "dismiss_stale_reviews", PyValue::Bool(false))?,
            ));
            details.push((
                "require_code_owner_reviews".into(),
                get_or(&reviews, "require_code_owner_reviews", PyValue::Bool(false))?,
            ));
        }
        if !issues.is_empty() {
            return audit_check(
                "repo-branch-protection",
                "Default Branch Protection",
                "repository",
                "warning",
                "medium",
                format!(
                    "Branch protection enabled but with gaps: {}",
                    issues.join(", ")
                ),
                Some("Strengthen branch protection by requiring reviews and enforcing for admins"),
                Some(PyValue::Dict(details)),
                repo_name,
                Some("repository"),
            );
        }
        audit_check(
            "repo-branch-protection",
            "Default Branch Protection",
            "repository",
            "pass",
            "high",
            format!(
                "Default branch '{}' has protection rules enabled",
                branch.py_str()
            ),
            None,
            Some(PyValue::Dict(details)),
            repo_name,
            Some("repository"),
        )
    }

    async fn check_secret_scanning(&self, repo: &PyValue) -> PyResult<Check> {
        let repo_name = get_none(repo, "name")?;
        let (config, status) = self
            .request(
                format!("/repos/{}/{}", self.org, repo_name.py_str()),
                Vec::new(),
            )
            .await;
        if status != 200 {
            return audit_check(
                "repo-secret-scanning",
                "Secret Scanning",
                "repository",
                "not_applicable",
                "info",
                "Unable to check secret scanning status".into(),
                None,
                None,
                repo_name,
                Some("repository"),
            );
        }
        let analysis = match config.filter(PyValue::truthy) {
            Some(c) => get_or(&c, "security_and_analysis", PyValue::Dict(Vec::new()))?,
            None => PyValue::Dict(Vec::new()),
        };
        let scanning = get_or(&analysis, "secret_scanning", PyValue::Dict(Vec::new()))?;
        let push = get_or(
            &analysis,
            "secret_scanning_push_protection",
            PyValue::Dict(Vec::new()),
        )?;
        let scanning_on = is_str(&get_none(&scanning, "status")?, "enabled");
        let push_on = is_str(&get_none(&push, "status")?, "enabled");
        let flags = |a: bool, b: bool| {
            Some(PyValue::Dict(vec![
                ("secret_scanning".into(), PyValue::Bool(a)),
                ("push_protection".into(), PyValue::Bool(b)),
            ]))
        };
        if scanning_on && push_on {
            audit_check(
                "repo-secret-scanning",
                "Secret Scanning",
                "repository",
                "pass",
                "high",
                "Secret scanning and push protection are enabled".into(),
                None,
                flags(true, true),
                repo_name,
                Some("repository"),
            )
        } else if scanning_on {
            audit_check(
                "repo-secret-scanning",
                "Secret Scanning",
                "repository",
                "warning",
                "medium",
                "Secret scanning enabled but push protection is disabled".into(),
                Some(
                    "Enable secret scanning push protection to block secrets before they're \
                     committed",
                ),
                flags(true, false),
                repo_name,
                Some("repository"),
            )
        } else {
            audit_check(
                "repo-secret-scanning",
                "Secret Scanning",
                "repository",
                "fail",
                "high",
                "Secret scanning is not enabled".into(),
                Some("Enable secret scanning in repository Security settings"),
                flags(false, false),
                repo_name,
                Some("repository"),
            )
        }
    }

    async fn check_dependabot(&self, repo: &PyValue) -> PyResult<Check> {
        let repo_name = get_none(repo, "name")?;
        let (_, status) = self
            .request(
                format!(
                    "/repos/{}/{}/vulnerability-alerts",
                    self.org,
                    repo_name.py_str()
                ),
                Vec::new(),
            )
            .await;
        match status {
            204 => audit_check(
                "repo-dependabot-alerts",
                "Dependabot Alerts",
                "repository",
                "pass",
                "high",
                "Dependabot vulnerability alerts are enabled".into(),
                None,
                None,
                repo_name,
                Some("repository"),
            ),
            404 => audit_check(
                "repo-dependabot-alerts",
                "Dependabot Alerts",
                "repository",
                "fail",
                "high",
                "Dependabot vulnerability alerts are not enabled".into(),
                Some("Enable Dependabot alerts in repository Security settings"),
                None,
                repo_name,
                Some("repository"),
            ),
            _ => audit_check(
                "repo-dependabot-alerts",
                "Dependabot Alerts",
                "repository",
                "not_applicable",
                "info",
                "Unable to determine Dependabot alerts status".into(),
                None,
                None,
                repo_name,
                Some("repository"),
            ),
        }
    }

    async fn check_code_scanning(&self, repo: &PyValue) -> PyResult<Check> {
        let repo_name = get_none(repo, "name")?;
        let (_, status) = self
            .request(
                format!(
                    "/repos/{}/{}/code-scanning/alerts",
                    self.org,
                    repo_name.py_str()
                ),
                vec![("per_page".into(), "1".into())],
            )
            .await;
        match status {
            200 => audit_check(
                "repo-code-scanning",
                "Code Scanning",
                "repository",
                "pass",
                "medium",
                "Code scanning is enabled".into(),
                None,
                None,
                repo_name,
                Some("repository"),
            ),
            404 => audit_check(
                "repo-code-scanning",
                "Code Scanning",
                "repository",
                "warning",
                "medium",
                "Code scanning is not configured".into(),
                Some("Enable GitHub Advanced Security and configure CodeQL analysis"),
                None,
                repo_name,
                Some("repository"),
            ),
            _ => audit_check(
                "repo-code-scanning",
                "Code Scanning",
                "repository",
                "not_applicable",
                "info",
                "Unable to determine code scanning status".into(),
                None,
                None,
                repo_name,
                Some("repository"),
            ),
        }
    }

    async fn check_branch_deletion(&self, repo: &PyValue) -> PyResult<Check> {
        let repo_name = get_none(repo, "name")?;
        let branch = get_or(repo, "default_branch", s("main"))?;
        let (info, status) = self
            .request(
                format!(
                    "/repos/{}/{}/branches/{}",
                    self.org,
                    repo_name.py_str(),
                    branch.py_str()
                ),
                Vec::new(),
            )
            .await;
        let Some(info) = info.filter(|i| status == 200 && i.truthy()) else {
            return audit_check(
                "repo-branch-deletion",
                "Default Branch Deletion Protection",
                "repository",
                "not_applicable",
                "info",
                "Unable to check branch deletion protection".into(),
                None,
                None,
                repo_name,
                Some("repository"),
            );
        };
        let protected = get_or(&info, "protected", PyValue::Bool(false))?.truthy();
        audit_check(
            "repo-branch-deletion",
            "Default Branch Deletion Protection",
            "repository",
            if protected { "pass" } else { "fail" },
            "high",
            if protected {
                format!(
                    "Default branch '{}' is protected from deletion",
                    branch.py_str()
                )
            } else {
                format!("Default branch '{}' can be deleted", branch.py_str())
            },
            (!protected).then_some(
                "Enable branch protection to prevent accidental deletion of default branch",
            ),
            None,
            repo_name,
            Some("repository"),
        )
    }

    // --- GitHub Actions -------------------------------------------------------------------

    async fn audit_workflows(&self) -> PyResult<Vec<Section>> {
        let org = &self.org;
        let (perms, status) = self
            .request(format!("/orgs/{org}/actions/permissions"), Vec::new())
            .await;
        let Some(perms) = perms.filter(|p| status == 200 && p.truthy()) else {
            return Ok(Vec::new());
        };
        let mut checks = Vec::new();
        let allowed = get_or(&perms, "allowed_actions", s("all"))?;
        if is_str(&allowed, "all") {
            checks.push(audit_check(
                "actions-allowed-all",
                "Actions Permission Policy",
                "workflow",
                "warning",
                "medium",
                "All GitHub Actions are allowed to run".into(),
                Some("Restrict to verified creators or specific allowed actions"),
                None,
                s(org.clone()),
                Some("organization"),
            )?);
        } else if is_str(&allowed, "selected") {
            checks.push(audit_check(
                "actions-allowed-selected",
                "Actions Permission Policy",
                "workflow",
                "pass",
                "medium",
                "Only selected GitHub Actions are allowed".into(),
                None,
                None,
                s(org.clone()),
                Some("organization"),
            )?);
        }
        let (defaults, _) = self
            .request(
                format!("/orgs/{org}/actions/permissions/workflow"),
                Vec::new(),
            )
            .await;
        if let Some(defaults) = defaults.filter(PyValue::truthy) {
            let token_perms = get_or(&defaults, "default_workflow_permissions", s("write"))?;
            checks.push(if is_str(&token_perms, "write") {
                audit_check(
                    "actions-default-token-perms",
                    "Default Workflow Token Permissions",
                    "workflow",
                    "warning",
                    "medium",
                    "Default workflow token has write permissions".into(),
                    Some(
                        "Set default workflow permissions to 'read' and grant write access \
                         explicitly where needed",
                    ),
                    None,
                    s(org.clone()),
                    Some("organization"),
                )?
            } else {
                audit_check(
                    "actions-default-token-perms",
                    "Default Workflow Token Permissions",
                    "workflow",
                    "pass",
                    "medium",
                    "Default workflow token has read-only permissions".into(),
                    None,
                    None,
                    s(org.clone()),
                    Some("organization"),
                )?
            });
        }
        let dump = construct(
            &WORKFLOW_RESULT,
            &kwargs(vec![
                ("repo_name", s(org.clone())),
                ("workflow_name", s("Organization Actions Settings")),
                ("workflow_path", s("N/A")),
                ("checks", dumps(&checks)),
            ]),
        )?;
        Ok(vec![Section { dump, checks }])
    }

    // --- members --------------------------------------------------------------------------

    async fn audit_members(&self) -> PyResult<Vec<Section>> {
        let org = &self.org;
        let members = self
            .paginate(format!("/orgs/{org}/members"), Vec::new())
            .await;
        let admins = self
            .paginate(
                format!("/orgs/{org}/members"),
                vec![("role".into(), "admin".into())],
            )
            .await;
        // `set(m.get("login") for m in admins)`.
        let mut admin_logins: Vec<PyValue> = Vec::new();
        for m in &admins {
            let login = get_none(m, "login")?;
            hashable(&login)?;
            admin_logins.push(login);
        }
        let mut results = Vec::new();
        for member in &members {
            let login = get_or(member, "login", s("unknown"))?;
            hashable(&login)?;
            let is_admin = admin_logins.iter().any(|a| py_eq(a, &login));
            let mut checks = Vec::new();
            if is_admin {
                checks.push(audit_check(
                    "member-is-admin",
                    "Admin Role",
                    "member",
                    "warning",
                    "low",
                    format!("User '{}' has admin role", login.py_str()),
                    Some("Regularly review admin access and remove if not needed"),
                    None,
                    login.clone(),
                    Some("member"),
                )?);
            }
            let dump = construct(
                &MEMBER_RESULT,
                &kwargs(vec![
                    ("username", login),
                    ("role", s(if is_admin { "admin" } else { "member" })),
                    ("checks", dumps(&checks)),
                ]),
            )?;
            results.push(Section { dump, checks });
        }
        Ok(results)
    }

    // --- the audit ------------------------------------------------------------------------

    async fn audit(&self, scope: &Scope) -> PyResult<AuditResponse> {
        let org_results = self.audit_organization().await?;
        let repo_results = if scope.include_repos {
            self.audit_repositories(scope.repo_filter.as_deref())
                .await?
        } else {
            Vec::new()
        };
        let workflow_results = if scope.include_workflows {
            self.audit_workflows().await?
        } else {
            Vec::new()
        };
        let member_results = if scope.include_members {
            self.audit_members().await?
        } else {
            Vec::new()
        };
        let all: Vec<&Check> = org_results
            .checks
            .iter()
            .chain(repo_results.iter().flat_map(|r| &r.checks))
            .chain(workflow_results.iter().flat_map(|r| &r.checks))
            .chain(member_results.iter().flat_map(|r| &r.checks))
            .collect();
        let scorable: Vec<&&Check> = all
            .iter()
            .filter(|c| c.status != "not_applicable")
            .collect();
        let n = |pred: &dyn Fn(&Check) -> bool| scorable.iter().filter(|c| pred(c)).count() as i64;
        let total = scorable.len() as i64;
        let passed = n(&|c| c.status == "pass");
        let failed = n(&|c| c.status == "fail");
        let warnings = n(&|c| c.status == "warning");
        let critical = n(&|c| c.status == "fail" && c.severity == "critical");
        let high = n(&|c| c.status == "fail" && c.severity == "high");
        let open = |c: &Check| c.status == "fail" || c.status == "warning";
        let medium = n(&|c| open(c) && c.severity == "medium");
        let low = n(&|c| open(c) && c.severity == "low");
        let score = if total > 0 {
            let mut total_weight = 0i64;
            let mut earned = 0.0f64;
            for c in &scorable {
                let weight = match c.severity.as_str() {
                    "critical" => 4,
                    "high" => 3,
                    "medium" => 2,
                    _ => 1,
                };
                total_weight += weight;
                if c.status == "pass" {
                    earned += weight as f64;
                } else if c.status == "warning" {
                    earned += weight as f64 * 0.5;
                }
            }
            if total_weight > 0 {
                (earned / total_weight as f64) * 100.0
            } else {
                100.0
            }
        } else {
            100.0
        };
        let score = py_round1(score);
        let grade = if score >= 90.0 {
            "A"
        } else if score >= 80.0 {
            "B"
        } else if score >= 70.0 {
            "C"
        } else if score >= 60.0 {
            "D"
        } else {
            "F"
        };
        let summary = Summary {
            audit_timestamp: utc_isoformat(chrono::Utc::now()),
            counts: [
                repo_results.len() as i64,
                total,
                passed,
                failed,
                warnings,
                critical,
                high,
                medium,
                low,
            ],
            score,
            grade: grade.into(),
        };
        let rank = |c: &Check| match c.severity.as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            "info" => 4,
            _ => 5,
        };
        let mut open_checks: Vec<Check> = all
            .iter()
            .filter(|c| open(c))
            .map(|c| (*c).clone())
            .collect();
        open_checks.sort_by_key(rank);
        open_checks.truncate(20);
        Ok(AuditResponse {
            success: true,
            message: format!(
                "Audit completed successfully. Score: {} ({grade},)",
                float_repr(score)
            ),
            organization: self.org.clone(),
            summary: Some(summary),
            organization_results: Some(org_results.dump),
            repository_results: repo_results.into_iter().map(|r| r.dump).collect(),
            workflow_results: workflow_results.into_iter().map(|r| r.dump).collect(),
            member_results: member_results.into_iter().map(|r| r.dump).collect(),
            top_findings: open_checks,
        })
    }

    /// `run_full_audit`: any exception is the failed response.
    pub async fn run(&self, scope: &Scope) -> AuditResponse {
        match self.audit(scope).await {
            Ok(response) => response,
            Err(e) => AuditResponse::failed(&self.org, &e),
        }
    }
}

fn check_private_vulnerability_reporting(repo: &PyValue) -> PyResult<Check> {
    let repo_name = get_none(repo, "name")?;
    let on = get_or(
        repo,
        "private_vulnerability_reporting_enabled",
        PyValue::Bool(false),
    )?
    .truthy();
    audit_check(
        "repo-private-vuln-reporting",
        "Private Vulnerability Reporting",
        "repository",
        if on { "pass" } else { "warning" },
        "low",
        if on {
            "Private vulnerability reporting is enabled"
        } else {
            "Private vulnerability reporting is not enabled"
        }
        .into(),
        (!on).then_some(
            "Enable private vulnerability reporting to allow security researchers to report \
             issues confidentially",
        ),
        None,
        repo_name,
        Some("repository"),
    )
}

fn check_license(repo: &PyValue) -> PyResult<Check> {
    let repo_name = get_none(repo, "name")?;
    let license = get_none(repo, "license")?;
    let is_private = get_or(repo, "private", PyValue::Bool(true))?;
    if is_private.truthy() {
        return audit_check(
            "repo-license",
            "Repository License",
            "repository",
            "not_applicable",
            "info",
            "License check not applicable for private repositories".into(),
            None,
            None,
            repo_name,
            Some("repository"),
        );
    }
    let has = license != PyValue::None;
    let description = if has {
        format!(
            "Repository has license: {}",
            get_or(&license, "name", s("Unknown"))?.py_str()
        )
    } else {
        "Public repository has no license".to_string()
    };
    let spdx = if license.truthy() {
        get_none(&license, "spdx_id")?
    } else {
        PyValue::None
    };
    audit_check(
        "repo-license",
        "Repository License",
        "repository",
        if has { "pass" } else { "warning" },
        "low",
        description,
        (!has).then_some("Add a LICENSE file to clarify usage terms for public repositories"),
        Some(PyValue::Dict(vec![("license".into(), spdx)])),
        repo_name,
        Some("repository"),
    )
}

/// The exclusion filter `run_audit_from_config` applies to the top findings:
/// a finding goes when `(check_id, resource_name)` or `(check_id, None)` is
/// excluded.
pub fn apply_exclusions(findings: &mut Vec<Check>, excluded: &[(String, Option<String>)]) {
    if excluded.is_empty() {
        return;
    }
    findings.retain(|f| {
        let named = excluded.iter().any(|(id, res)| {
            *id == f.check_id
                && match (res, &f.resource_name) {
                    (None, PyValue::None) => true,
                    (Some(r), PyValue::Str(n)) => r == n,
                    _ => false,
                }
        });
        let all = excluded
            .iter()
            .any(|(id, res)| *id == f.check_id && res.is_none());
        !named && !all
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_like_python() {
        // `round(x, 1)` in CPython 3.11.
        for (x, want) in [
            (6.25, 6.2),
            (0.25, 0.2),
            (0.35, 0.3),
            (66.66666666666667, 66.7),
            (62.5, 62.5),
            (100.0, 100.0),
            (0.05, 0.1),
        ] {
            assert_eq!(py_round1(x), want, "{x}");
        }
    }

    #[test]
    fn isoformat_like_python() {
        use chrono::TimeZone;
        let t = chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(utc_isoformat(t), "2026-01-02T03:04:05+00:00");
        let t = t + chrono::Duration::microseconds(12);
        assert_eq!(utc_isoformat(t), "2026-01-02T03:04:05.000012+00:00");
    }
}
