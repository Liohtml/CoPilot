//! # copilot-waf — a customer's SOCFortress WAFs
//!
//! Port of `app/customer_waf/` (`routes / services / schema`, and
//! `utils/universal.py` as [`client`]), mounted at `/api/customer_waf`, plus
//! the WAF half of `POST /api/monitoring_alert/provision` ([`alerts`]).
//!
//! - [`crypto`]     — the service token, Fernet under `WAF_TOKEN_ENCRYPTION_KEY`
//!   (no fallback key)
//! - [`client`]     — the httpx-shaped transport and its error mapping (502 with
//!   a `reason`, never 401/403)
//! - [`ip`], [`pem`] — CPython's `ipaddress` and OpenSSL's CA loading, as far
//!   as the module reads them
//! - [`store`]      — `customer_waf_instances`
//! - [`schema`]     — the response projections and request bodies
//! - [`services`]   — instances, the connection check, events / stats / threat
//!   intel, block provenance
//! - [`blocks`]     — IP blocks (one rule shape, idempotent, unblock disables)
//! - [`forwarding`] — event forwarding into Graylog, with rollback
//! - [`alerts`]     — the two WAF monitoring alerts
//! - [`routes`]     — the 16 routes and the monitoring-alert hand-off

#![warn(missing_docs)]

use copilot_db::schema::TableRequirement;

pub mod alerts;
pub mod blocks;
pub mod client;
pub mod crypto;
pub mod forwarding;
pub mod ip;
pub mod pem;
pub mod routes;
pub mod schema;
pub mod services;
pub mod store;

pub use client::WafClient;
pub use routes::{monitoring_router, router};
pub use services::{WafEnv, WafState};

/// The columns this crate reads or writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_waf_instances",
        columns: store::COLUMNS,
    },
    TableRequirement {
        table: "customers",
        columns: &["customer_code", "customer_name"],
    },
];
