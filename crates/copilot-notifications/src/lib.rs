//! # copilot-notifications — notification routing and delivery
//!
//! Port of `app/notifications/`: the routes that configure where
//! notifications go, the channel providers that deliver them, the dispatch
//! pipeline with its log, and the in-process sink every other Rust module
//! emits through.
//!
//! | Route | Python | Guard |
//! |---|---|---|
//! | `GET`/`POST /api/customers/{code}/notification_routes`, `PATCH`/`DELETE …/{id}`, `POST …/{id}/test` | per-customer routes | admin, analyst + customer access |
//! | `GET /api/customers/{code}/notification_dispatch_log` | the dispatch log (100 newest) | admin, analyst + customer access |
//! | `GET`/`POST /api/customers/{code}/shuffle_integrations`, `PATCH`/`DELETE …/{id}`, `GET …/{id}/apps`, `GET …/{id}/verify` | Shuffle integrations | admin, analyst + customer access |
//! | `GET`/`POST /api/internal_notification_routes`, `GET`/`PATCH`/`DELETE …/{id}`, `POST …/{id}/test` | internal-scope routes | admin |
//! | `GET /api/notification_channels`, `GET …/resend/quota` | channel catalog, Resend usage | admin, analyst |
//! | `POST /api/notifications/send`, `…/send/preview` | manual send (checks in [`services::manual`]) | admin, analyst |
//! | `GET /api/notifications/shuffle/orgs` | Shuffle org picker | admin, analyst |
//! | `POST /api/notifications/dispatch` | Talon's push | admin, analyst + customer access (Rust only) |
//! | `GET`/`POST /api/notifications/templates`, `POST …/preview`, `GET`/`PATCH`/`DELETE …/{id}` | named templates | reads admin, analyst; writes admin |
//! | `POST /api/notifications/events` | the former bridge endpoint | admin, analyst + customer access |
//!
//! Wire parity is the point: Pydantic's lax validation and its error texts
//! ([`pydantic`], [`channels::config`]), CPython's `json.dumps`
//! ([`pyjson`]), Jinja2's sandbox (`copilot-jinja`) and markdown-it-py
//! (`copilot-markdown`) are reproduced, and the providers send the bytes,
//! headers and timeouts httpx sent.
//!
//! Module map: [`routes`] → [`services`] (configuration, templates,
//! rendering, dispatch, manual send) → [`channels`] (Shuffle, webhook,
//! Resend, Teams) and [`db`]; [`schema`] (request and response shapes),
//! [`event`] (the event and the trigger groups), [`branding`] (portal
//! branding as templates see it, shared with the temporary-password email),
//! [`temp_password`] (that email's template variables), [`sink`] (in-process
//! emission), [`dispatcher`] (what a dispatch needs).

#![warn(missing_docs)]

pub mod branding;
pub mod channels;
pub mod db;
pub mod dispatcher;
pub mod event;
pub mod pydantic;
pub mod pyjson;
pub mod routes;
pub mod schema;
pub mod services;
pub mod sink;
pub mod temp_password;

use axum::extract::FromRef;
use copilot_web::AppContext;

pub use dispatcher::Dispatcher;
pub use routes::router;
pub use sink::DispatchingSink;

/// State of the notification routes.
#[derive(Clone, Debug)]
pub struct NotificationsState {
    /// Shared dependencies (auth, tenancy).
    pub ctx: AppContext,
    /// Dispatch dependencies.
    pub dispatcher: Dispatcher,
}

impl FromRef<NotificationsState> for AppContext {
    fn from_ref(s: &NotificationsState) -> AppContext {
        s.ctx.clone()
    }
}
