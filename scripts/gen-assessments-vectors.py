"""Regenerate the vectors that pin the GitHub audit and Nuclei ports (`copilot-assessments`) to
the Python modules they port (`app/integrations/github_audit/`, `app/integrations/nuclei/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-assessments-vectors.py

Writes `crates/copilot-assessments/src/assessments_vectors.json`:

* `round` — `round(x, 1)` on the scores the audit can compute (and its float ties);
* `requests` — the request bodies (`GitHubAuditConfigCreate`, `…ConfigUpdate`,
  `…ExclusionCreate`, `…ExclusionUpdate`, `…BaselineCreate`, `GitHubAuditRequest`,
  `NucleiScanRequest`) validated as FastAPI validates them: the JSON dump (`exclude_unset` for
  the two updates, `None`s dropped as the routes drop them) or Pydantic's errors (`type`, `loc`,
  `msg`);
* `audits` — `run_github_audit` on scripted GitHub answers (`GitHubAuditService._request`
  replaced by a table of `endpoint?query` → status and body, nothing sent): the response as
  FastAPI writes it (`audit_timestamp` masked) and every request asked for, in order;
* `baselines` — `create_baseline`'s extraction of the expected checks from a stored
  `full_report`, or the exception it raises;
* `urls` — what httpx 0.28 sends for `client.request("GET", url, params=…)`: the URL's own query
  replaced by the params;
* `nuclei` — the Nuclei answers' models (`Model(**answer)`): the dump or the exception.

Re-run after a Pydantic, httpx or Python upgrade, or a change to these modules.
"""

import asyncio
import json
import pathlib
from urllib.parse import urlencode

import httpx
from pydantic import ValidationError

from app.integrations.github_audit.schema import github_audit as schema
from app.integrations.github_audit.services import github_audit as service
from app.integrations.nuclei.schema import nuclei as nuclei_schema

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-assessments" / "src" / "assessments_vectors.json"


def failure(e):
    if isinstance(e, ValidationError):
        return {"class": "ValidationError", "text": str(e)}
    return {"class": type(e).__name__, "text": str(e)}


# --- round ------------------------------------------------------------------------------------------


def rounds():
    xs = [6.25, 0.25, 0.35, 0.05, 2.675, 62.5, 100.0, 0.0, 66.66666666666667, 33.333333333333336, 87.5, 12.45, 12.55]
    # Every score the weights can produce for up to 12 checks.
    for total in range(1, 49):
        for halves in range(0, 2 * total + 1):
            xs.append((halves / 2 / total) * 100)
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append([x, round(x, 1)])
    return out


# --- request bodies ---------------------------------------------------------------------------------

REQUEST_MODELS = {
    "ConfigCreate": (schema.GitHubAuditConfigCreate, False),
    "ConfigUpdate": (schema.GitHubAuditConfigUpdate, True),
    "ExclusionCreate": (schema.GitHubAuditExclusionCreate, False),
    "ExclusionUpdate": (schema.GitHubAuditExclusionUpdate, True),
    "BaselineCreate": (schema.GitHubAuditBaselineCreate, False),
    "AuditRequest": (schema.GitHubAuditRequest, False),
    "NucleiScan": (nuclei_schema.NucleiScanRequest, False),
}

LONG = "x" * 51

REQUEST_BODIES = {
    "ConfigCreate": [
        {"customer_code": "acme", "github_token": "ghp_x", "organization": "acme"},
        {
            "customer_code": "acme",
            "github_token": "ghp_x",
            "organization": "acme",
            "token_type": "app",
            "token_expires_at": "2026-12-31T10:00:00+02:00",
            "enabled": "false",
            "auto_audit_enabled": 1,
            "audit_schedule_cron": "0 0 * * 1",
            "include_repos": "yes",
            "include_workflows": False,
            "include_members": "0",
            "include_archived_repos": True,
            "repo_filter_mode": "include",
            "repo_filter_list": ["web", "api"],
            "notify_on_critical": False,
            "notify_on_high": True,
            "notification_webhook_url": "https://hooks.example.com/x",
            "notification_email": "soc@example.com",
            "minimum_passing_score": "85.5",
            "created_by": "alice",
        },
        {},
        {"customer_code": LONG, "github_token": 5, "organization": None},
        {"customer_code": "a", "github_token": "t", "organization": "o", "minimum_passing_score": 100.5},
        {"customer_code": "a", "github_token": "t", "organization": "o", "minimum_passing_score": -1},
        {"customer_code": "a", "github_token": "t", "organization": "o", "minimum_passing_score": None},
        {"customer_code": "a", "github_token": "t", "organization": "o", "token_type": None, "repo_filter_mode": None},
        {"customer_code": "a", "github_token": "t", "organization": "o", "token_expires_at": "not a date"},
        {"customer_code": "a", "github_token": "t", "organization": "o", "token_expires_at": 1700000000},
        {"customer_code": "a", "github_token": "t", "organization": "o", "token_expires_at": "2026-01-02"},
        {"customer_code": "a", "github_token": "t", "organization": "o", "repo_filter_list": "web"},
        {"customer_code": "a", "github_token": "t", "organization": "o", "repo_filter_list": [1, "x", None]},
        {"customer_code": "a", "github_token": "t", "organization": "o", "enabled": "maybe", "include_repos": None},
        {"customer_code": "a", "github_token": "t", "organization": "x" * 101, "audit_schedule_cron": LONG},
        {"customer_code": "a", "github_token": "t", "organization": "o", "notification_email": "e" * 256, "created_by": "c" * 101},
    ],
    "ConfigUpdate": [
        {},
        {"organization": "beta", "enabled": None, "minimum_passing_score": 50, "repo_filter_list": []},
        {"github_token": None, "token_expires_at": "2027-01-01T00:00:00Z", "include_members": "off", "updated_by": "bob"},
        {"minimum_passing_score": 101, "token_type": LONG, "repo_filter_mode": 3},
        {"notify_on_high": "x", "audit_schedule_cron": None, "auto_audit_enabled": True},
        {"unknown": 1, "include_archived_repos": 0},
    ],
    "ExclusionCreate": [
        {"check_id": "repo-license", "reason": "public mirror", "created_by": "alice"},
        {
            "check_id": "repo-license",
            "resource_name": "web",
            "resource_type": "repository",
            "reason": "r",
            "approved_by": "",
            "expires_at": "2030-01-01T00:00:00.700000",
            "created_by": "alice",
        },
        {},
        {"check_id": "c" * 101, "reason": None, "created_by": 1, "resource_name": "r" * 256},
        {"check_id": "x", "reason": "y", "created_by": "z", "expires_at": "yesterday"},
    ],
    "ExclusionUpdate": [
        {},
        {"reason": "new", "approved_by": None, "enabled": "false"},
        {"approved_by": "a" * 101, "expires_at": 5, "enabled": 2},
    ],
    "BaselineCreate": [
        {"name": "b", "created_by": "alice"},
        {
            "name": "b",
            "created_by": "alice",
            "description": "d",
            "expected_checks": {"org-2fa-required": "pass"},
            "baseline_report_id": "7",
            "is_active": "no",
        },
        {"name": "n" * 256, "expected_checks": {"a": 1}, "baseline_report_id": "x"},
        {"name": "b", "created_by": "c", "expected_checks": [1], "baseline_report_id": 1.5, "is_active": None},
        {"name": "b", "created_by": "c", "baseline_report_id": 0},
    ],
    "AuditRequest": [
        {"organization": "acme"},
        {"organization": "acme", "include_repos": False, "include_workflows": "no", "repo_filter": ["web"]},
        {},
        {"organization": 1, "repo_filter": "web", "include_members": None},
    ],
    "NucleiScan": [{"host": "example.com"}, {}, {"host": 5}, {"host": None}],
}


def request_vectors():
    out = []
    for name, bodies in REQUEST_BODIES.items():
        model, partial = REQUEST_MODELS[name]
        for body in bodies:
            entry = {"model": name, "body": json.dumps(body)}
            try:
                m = model.model_validate(body)
                if partial:
                    dump = {k: v for k, v in m.model_dump(mode="json", exclude_unset=True).items() if v is not None}
                else:
                    dump = m.model_dump(mode="json")
                entry["ok"] = dump
            except ValidationError as e:
                entry["err"] = [[err["type"], list(err["loc"]), err["msg"]] for err in e.errors()]
            out.append(entry)
    return out


# --- the audit --------------------------------------------------------------------------------------

ORG = "acme"


def org_data(**over):
    data = {
        "login": ORG,
        "html_url": f"https://github.com/{ORG}",
        "two_factor_requirement_enabled": True,
        "default_repository_permission": "read",
        "members_can_create_repositories": False,
        "members_can_create_public_repositories": False,
    }
    data.update(over)
    return data


def repo(name, **over):
    data = {
        "name": name,
        "full_name": f"{ORG}/{name}",
        "html_url": f"https://github.com/{ORG}/{name}",
        "private": True,
        "archived": False,
        "default_branch": "main",
        "license": None,
        "private_vulnerability_reporting_enabled": False,
    }
    data.update(over)
    return data


PROTECTED = {
    "required_pull_request_reviews": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
    },
    "enforce_admins": {"enabled": True},
    "required_status_checks": {"strict": True, "contexts": ["ci"]},
}

SECURED = {"security_and_analysis": {"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}}


def answers(org=None, repos=(), per_repo=None, domains=(404, None), saml=(404, None), actions=None, workflow=None, members=(), admins=()):
    """The `endpoint?query` → (status, body text) table of one audit."""
    table = {}

    def put(key, status, body=None):
        table[key] = [status, body if isinstance(body, str) or body is None else json.dumps(body)]

    org_answer = org if isinstance(org, tuple) else (200, org_data() if org is None else org)
    put(f"/orgs/{ORG}", *org_answer)
    put(f"/orgs/{ORG}/domains", *domains)
    put(f"/orgs/{ORG}/saml", *saml)
    repos = list(repos)
    pages = [repos[i : i + 100] for i in range(0, len(repos), 100)] or [[]]
    if len(repos) % 100 == 0 and repos:
        pages.append([])
    for n, page in enumerate(pages, start=1):
        put(f"/orgs/{ORG}/repos?per_page=100&page={n}", 200, page)
    for r in repos:
        if not isinstance(r, dict) or r.get("archived"):
            continue  # an archived repository is never asked about
        name, branch = r.get("name"), r.get("default_branch", "main")
        custom = (per_repo or {}).get(str(name), {})
        put(f"/repos/{ORG}/{name}/branches/{branch}/protection", *custom.get("protection", (200, PROTECTED)))
        put(f"/repos/{ORG}/{name}", *custom.get("repo", (200, SECURED)))
        put(f"/repos/{ORG}/{name}/vulnerability-alerts", *custom.get("vuln", (204, None)))
        put(f"/repos/{ORG}/{name}/code-scanning/alerts?per_page=1", *custom.get("code", (200, [])))
        put(f"/repos/{ORG}/{name}/branches/{branch}", *custom.get("branch", (200, {"name": branch, "protected": True})))
    put(f"/orgs/{ORG}/actions/permissions", *(actions or (200, {"enabled_repositories": "all", "allowed_actions": "selected"})))
    put(f"/orgs/{ORG}/actions/permissions/workflow", *(workflow or (200, {"default_workflow_permissions": "read"})))
    put(f"/orgs/{ORG}/members?per_page=100&page=1", 200, list(members))
    put(f"/orgs/{ORG}/members?role=admin&per_page=100&page=1", 200, list(admins))
    return table


SCENARIOS = [
    (
        "all good, members and an admin",
        {},
        dict(members=[{"login": "alice"}, {"login": "bob"}], admins=[{"login": "alice"}], repos=[repo("web")]),
    ),
    ("organization unreachable", {}, dict(org=(404, None))),
    ("organization answers 403", {}, dict(org=(403, {"message": "rate limited"}))),
    ("organization answers an empty object", {}, dict(org={})),
    ("organization answers a list", {}, dict(org=[1])),
    ("organization answers HTML", {}, dict(org=(200, "<html>"))),
    (
        "weak organization settings",
        {},
        dict(
            org=org_data(
                two_factor_requirement_enabled=None,
                default_repository_permission={"x": [1, None]},
                members_can_create_repositories="",
                members_can_create_public_repositories=1,
                html_url=None,
            ),
        ),
    ),
    ("organization html_url missing", {}, dict(org=org_data(html_url="https://ghe.example.com/acme"), domains=(200, []), saml=(200, None))),
    (
        "verified domains and SAML",
        {},
        dict(
            domains=(
                200,
                [{"domain": "a.example", "is_verified": True}, {"domain": "b.example", "is_verified": False}, {"is_verified": 1}],
            ),
            saml=(200, {"enforced": True}),
        ),
    ),
    ("domains not a list, SAML falsy", {}, dict(domains=(200, {"domain": "x"}), saml=(200, {}))),
    ("a domain that is no object", {}, dict(domains=(200, ["a.example"]))),
    ("SAML answers a list", {}, dict(saml=(200, [1]))),
    ("domains 500", {}, dict(domains=(500, None), saml=(502, None))),
    (
        "repositories of every kind",
        {},
        dict(
            repos=[
                repo("web", private=False, license={"name": "MIT License", "spdx_id": "MIT"}, private_vulnerability_reporting_enabled=True),
                repo("old", archived=True),
                repo("docs", private=False, license={}),
                repo("nolicense", private=False),
                repo("legacy", default_branch="master"),
                repo("odd", private="yes", archived=0),
            ],
            per_repo={
                "web": {"protection": (404, None), "repo": (200, {"security_and_analysis": {"secret_scanning": {"status": "enabled"}}})},
                "docs": {
                    "protection": (200, {"required_pull_request_reviews": None, "enforce_admins": {"enabled": False}}),
                    "repo": (200, {}),
                    "vuln": (404, None),
                    "code": (404, None),
                    "branch": (200, {"protected": False}),
                },
                "nolicense": {
                    "protection": (403, None),
                    "repo": (403, None),
                    "vuln": (403, None),
                    "code": (403, None),
                    "branch": (404, None),
                },
                "legacy": {"repo": (200, "not json"), "vuln": (200, {}), "code": (200, "{"), "branch": (200, {})},
            },
        ),
    ),
    ("a repository whose name is a number", {}, dict(repos=[repo(7)])),
    ("a repository without a name", {}, dict(repos=[{k: v for k, v in repo("x").items() if k != "name"}])),
    ("a repository whose name is null", {}, dict(repos=[repo(None)])),
    ("an archived repository whose name is null", {}, dict(repos=[repo(None, archived=True)])),
    ("a repository that is no object", {}, dict(repos=["web"])),
    ("a repository list answer that is an object", {}, dict()),  # patched below
    (
        "enforce_admins null",
        {},
        dict(repos=[repo("web")], per_repo={"web": {"protection": (200, {"required_pull_request_reviews": {}, "enforce_admins": None})}}),
    ),
    (
        "reviews that are a list",
        {},
        dict(repos=[repo("web")], per_repo={"web": {"protection": (200, {"required_pull_request_reviews": [1]})}}),
    ),
    ("protection that is a list", {}, dict(repos=[repo("web")], per_repo={"web": {"protection": (200, [1])}})),
    ("security_and_analysis null", {}, dict(repos=[repo("web")], per_repo={"web": {"repo": (200, {"security_and_analysis": None})}})),
    ("a license that is a string", {}, dict(repos=[repo("web", private=False, license="MIT")])),
    ("private that is no bool", {}, dict(repos=[repo("web", private="maybe", archived=True)])),
    ("a branch answer that is a list", {}, dict(repos=[repo("web")], per_repo={"web": {"branch": (200, [1])}})),
    (
        "two batches, the twelfth fails",
        {},
        dict(repos=[repo(f"r{i}") for i in range(11)] + [repo("bad", default_branch=None, private=False, license=5)]),
    ),
    ("two failures in one batch", {}, dict(repos=[repo("a"), repo("b", license=[1], private=False), repo(3), repo("d")])),
    # Bare archived repositories: the pages, not the checks, are what these two pin.
    ("pagination", {}, dict(repos=[{"name": f"p{i}", "archived": True} for i in range(101)])),
    ("exactly one page", {}, dict(repos=[{"name": f"q{i}", "archived": 1} for i in range(100)])),
    ("a repository filter", {"repo_filter": ["web", "docs", "nope"]}, dict(repos=[repo("web"), repo("api"), repo("docs")])),
    ("an empty repository filter", {"repo_filter": []}, dict(repos=[repo("web")])),
    (
        "nothing but the organization",
        {"include_repos": False, "include_workflows": False, "include_members": False},
        dict(repos=[repo("web")]),
    ),
    (
        "actions all, write tokens",
        {},
        dict(actions=(200, {"allowed_actions": "all"}), workflow=(200, {"default_workflow_permissions": "write"})),
    ),
    ("actions without the key", {}, dict(actions=(200, {"enabled_repositories": "none"}), workflow=(200, {}))),
    ("actions local_only, workflow 404", {}, dict(actions=(200, {"allowed_actions": "local_only"}), workflow=(404, None))),
    ("actions 403", {}, dict(actions=(403, None))),
    ("actions a list", {}, dict(actions=(200, [1]))),
    ("workflow a list", {}, dict(workflow=(200, ["x"]))),
    ("admins without login", {}, dict(members=[{"login": "alice"}, {}], admins=[{"x": 1}])),
    ("a member login that is a number", {}, dict(members=[{"login": 5}], admins=[{"login": 5.0}])),
    ("a member login that is a list", {}, dict(members=[{"login": [1]}])),
    ("an admin login that is an object", {}, dict(admins=[{"login": {"a": 1}}])),
    ("a member that is no object", {}, dict(members=["alice"])),
    ("a member login null", {}, dict(members=[{"login": None}], admins=[{"login": None}])),
]


def run_scenario(name, scope, table):
    log = []

    async def fake_request(self, method, endpoint, params=None):
        key = endpoint + ("?" + urlencode(params) if params else "")
        log.append(f"{method} {key}")
        status, body = table.get(key, [404, None])
        if status == 200:
            try:
                return json.loads(body), 200
            except Exception:  # noqa: BLE001 - `_request`'s own except
                return None, 500
        if status == 404:
            return None, 404
        return None, status

    service.GitHubAuditService._request = fake_request
    request = schema.GitHubAuditRequest(organization=ORG, **scope)
    response = asyncio.run(service.run_github_audit("tok", request))
    dump = response.model_dump(mode="json")
    if dump["summary"]:
        dump["summary"]["audit_timestamp"] = "<now>"
    return {
        "name": name,
        "organization": ORG,
        "scope": {
            "include_repos": request.include_repos,
            "include_workflows": request.include_workflows,
            "include_members": request.include_members,
            "repo_filter": request.repo_filter,
        },
        "answers": table,
        "response": json.dumps(dump),
        "requests": log,
    }


def audit_vectors():
    out = []
    for name, scope, kw in SCENARIOS:
        table = answers(**kw)
        if name == "a repository list answer that is an object":
            table[f"/orgs/{ORG}/repos?per_page=100&page=1"] = [200, json.dumps({"name": "solo", "private": True, "archived": True})]
        out.append(run_scenario(name, scope, table))
    return out


# --- baselines --------------------------------------------------------------------------------------


def extract(full_report):
    """`create_baseline`'s loop, verbatim."""
    expected_checks = {}
    if "organization_results" in full_report and full_report["organization_results"]:
        for check in full_report["organization_results"].get("checks", []):
            expected_checks[check["check_id"]] = check["status"]
    for repo_ in full_report.get("repository_results", []):
        for check in repo_.get("checks", []):
            key = f"{check['check_id']}:{repo_['repo_name']}"
            expected_checks[key] = check["status"]
    return expected_checks


BASELINE_REPORTS = [
    {"organization_results": {"checks": [{"check_id": "org-2fa-required", "status": "fail"}]}, "repository_results": []},
    {
        "organization_results": None,
        "repository_results": [
            {
                "repo_name": "web",
                "checks": [{"check_id": "repo-license", "status": "warning"}, {"check_id": "repo-license", "status": "pass"}],
            },
            {"repo_name": 5, "checks": [{"check_id": None, "status": None}]},
        ],
    },
    {
        "organization_results": {
            "checks": [{"check_id": 1, "status": "x"}, {"check_id": True, "status": "y"}, {"check_id": 1.5, "status": "z"}],
        },
    },
    {
        "organization_results": {"checks": [{"check_id": "a:web", "status": "org"}]},
        "repository_results": [{"repo_name": "web", "checks": [{"check_id": "a", "status": "repo"}]}],
    },
    {"organization_results": {"checks": [{"status": "x"}]}},
    {"organization_results": {"checks": [{"check_id": [1], "status": "x"}]}},
    {"organization_results": [1]},
    {"organization_results": {"checks": "ab"}},
    {"repository_results": [{"checks": [{"check_id": "x", "status": "y"}]}]},
    {"repository_results": [None]},
    {"repository_results": 5},
    [1, 2],
    "organization_results",
    {"other": 1},
]


def baseline_vectors():
    out = []
    for report in BASELINE_REPORTS:
        entry = {"full_report": json.dumps(report)}
        try:
            entry["ok"] = json.dumps(extract(report))
        except Exception as e:  # noqa: BLE001 - recorded
            entry["err"] = failure(e)
        out.append(entry)
    return out


# --- httpx's params= --------------------------------------------------------------------------------


def url_vectors():
    out = []
    cases = [
        ("https://api.github.com/orgs/acme/repos", [("per_page", 100), ("page", 1)]),
        ("https://api.github.com/orgs/a?b/repos", [("per_page", 100), ("page", 2)]),
        ("https://api.github.com/orgs/a#b?c/members", [("role", "admin"), ("per_page", 100), ("page", 1)]),
        ("https://api.github.com/repos/acme/a b/code-scanning/alerts", [("per_page", 1)]),
        ("https://api.github.com/repos/acme/x/branches/release/1.x/protection", []),
        ("https://api.github.com/repos/acme/x?y/branches/main", []),
        ("https://api.github.com/repos/acme/é/../web", []),
    ]
    for url, params in cases:
        request = httpx.Request("GET", url, params=dict(params) if params else None)
        out.append({"url": url, "params": [[k, str(v)] for k, v in params], "sent": str(request.url)})
    return out


# --- the Nuclei answers -----------------------------------------------------------------------------

NUCLEI_MODELS = {
    "NucleiReportsAvailableResponse": nuclei_schema.NucleiReportsAvailableResponse,
    "NucleiReportCollectionResponse": nuclei_schema.NucleiReportCollectionResponse,
    "DeleteNucleiReportResponse": nuclei_schema.DeleteNucleiReportResponse,
    "NucleiScanResponse": nuclei_schema.NucleiScanResponse,
}

NUCLEI_ANSWERS = [
    {"reports": ["a.example", "b.example"], "success": True, "message": "ok", "extra": 1},
    {"markdown": "# Report", "success": "true", "message": "m"},
    {"success": False, "message": "gone"},
    {"message": "started", "success": 1},
    {},
    {"reports": "a", "success": "maybe", "message": None, "markdown": 5},
    [1],
    "text",
    None,
]


def nuclei_vectors():
    out = []
    for name, model in NUCLEI_MODELS.items():
        for answer in NUCLEI_ANSWERS:
            entry = {"model": name, "answer": json.dumps(answer)}
            try:
                entry["ok"] = model(**answer).model_dump(mode="json")
            except Exception as e:  # noqa: BLE001 - recorded
                entry["err"] = failure(e)
            out.append(entry)
    return out


def main():
    data = {
        "round": rounds(),
        "requests": request_vectors(),
        "audits": audit_vectors(),
        "baselines": baseline_vectors(),
        "urls": url_vectors(),
        "nuclei": nuclei_vectors(),
    }
    OUT.write_text(json.dumps(data, indent=0, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}: " + ", ".join(f"{len(v)} {k}" for k, v in data.items()))


if __name__ == "__main__":
    main()
