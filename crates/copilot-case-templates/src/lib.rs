//! # copilot-case-templates — the case-template library and suggestions
//!
//! The two parts of `app/incidents/routes/case_templates.py` that
//! `copilot-incidents` (the template CRUD) left to Python, served under
//! `/api/incidents/case_templates` (admin/analyst, `require_any_scope`):
//!
//! - the **library** ([`library`]): `GET /library`, `POST /library/refresh`,
//!   `GET /library/{key}`, `POST /library/{key}/import` — the playbooks of
//!   `socfortress/CoPilot-Case-Templates` fetched from GitHub over httpx,
//!   parsed with PyYAML's `safe_load` (`copilot-yaml`), normalised and
//!   cached per process for 30 minutes as `TemplateLibraryCache` does; an
//!   import creates a global template through `copilot-incidents`'
//!   `create_template`;
//! - the **suggestions** ([`suggest`]): `GET /suggest`, the templates ranked
//!   against an alert (or a bare customer and source), with Python's
//!   weights, caps, texts and order; the raw Wazuh document is read through
//!   `copilot-wazuh` only when a conditional template needs it.
//!
//! Python's `re` and `str` operations on the texts are [`text`]'s, pinned
//! with the normalisation, the models and the scorer by
//! `case_templates_vectors.json` (`scripts/gen-case-templates-vectors.py`).
//!
//! Tenancy (RUST_MIGRATION.md §4): the library is deployment-wide, as in
//! Python; `/suggest` treats an alert the caller may not see as a missing
//! one, refuses a `customer_code` that is not the caller's, and counts a
//! scoped caller's usage history over their customers only.

#![warn(missing_docs)]

pub mod library;
pub mod routes;
pub mod suggest;
pub mod text;

use std::sync::Arc;

use copilot_db::schema::TableRequirement;
use copilot_web::AppContext;

pub use routes::router;

/// What the routes share.
#[derive(Clone, Debug)]
pub struct CaseTemplatesState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Wazuh indexer's HTTP stack (the raw document of `/suggest`).
    pub es: copilot_wazuh::es::EsHttp,
    /// This process's library cache.
    pub library: Arc<library::Library>,
}

impl axum::extract::FromRef<CaseTemplatesState> for AppContext {
    fn from_ref(state: &CaseTemplatesState) -> Self {
        state.ctx.clone()
    }
}

impl CaseTemplatesState {
    /// The state, the library on GitHub's API and raw bases.
    pub fn new(
        ctx: AppContext,
        es: copilot_wazuh::es::EsHttp,
        github_api: impl Into<String>,
        github_raw: impl Into<String>,
    ) -> Self {
        Self {
            ctx,
            es,
            library: library::Library::new(github_api, github_raw),
        }
    }
}

/// Every column this crate reads (Alembic owns the schema).
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "incident_management_case_template",
        columns: &[
            "id",
            "name",
            "description",
            "customer_code",
            "source",
            "is_default",
            "match_field",
            "match_value",
            "created_by",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "incident_management_case_template_task",
        columns: &[
            "id",
            "template_id",
            "title",
            "description",
            "guidelines",
            "mandatory",
            "order_index",
        ],
    },
    TableRequirement {
        table: "incident_management_case_task",
        columns: &["case_id", "template_task_id"],
    },
    TableRequirement {
        table: "incident_management_case",
        columns: &["id", "customer_code"],
    },
    TableRequirement {
        table: "incident_management_asset",
        columns: &[
            "id",
            "alert_linked",
            "alert_context_id",
            "index_name",
            "index_id",
        ],
    },
    TableRequirement {
        table: "incident_management_alertcontext",
        columns: &["id", "context"],
    },
    TableRequirement {
        table: "incident_management_alerttag",
        columns: &["id", "tag"],
    },
    TableRequirement {
        table: "incident_management_alert_to_tag",
        columns: &["alert_id", "tag_id"],
    },
];
