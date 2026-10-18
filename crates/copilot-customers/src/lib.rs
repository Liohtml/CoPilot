//! # copilot-customers — customers and their meta rows
//!
//! Port of `app/customers/routes/customers.py`, mounted at `/api/customers`:
//! every route of the router.
//!
//! The reads are admin/analyst. The list is scoped to the caller's
//! customers (it feeds every customer picker); the `{customer_code}` reads
//! check that customer before anything else. The writes are admin only, as
//! in Python, and touch nothing but the database (provisioning is
//! `/api/customer_provisioning`'s):
//!
//! - `POST ""` — the MSSP licence check (`mssp_license_check`: the "MSSP
//!   Seats" allowance read fresh from the licence server, else the boolean
//!   tiers through `copilot_license::is_feature_enabled_with`), the unique
//!   code, the row;
//! - `PUT /{code}` — every field set, an `UPDATE` of what changed;
//! - `DELETE /{code}` — the ORM's flush: the customer's agents and meta row
//!   get a `NULL` customer code (the relationships have no delete cascade,
//!   so a meta row makes the delete fail), then the row; a failing foreign
//!   key is Python's 400;
//! - `POST`/`PUT`/`DELETE /{code}/meta` (deprecated in Python).
//!
//! - [`schema`]   — `CustomerOut`, `CustomerMetaOut`, `AgentModel`, the
//!   request models, envelopes
//! - [`services`] — lookups with the Python 404 texts, the writes
//! - [`routes`]   — `/`, `/{code}`, `/{code}/meta`, `/{code}/full`,
//!   `/{code}/agents`, `/{code}/agents/healthcheck/{wazuh,velociraptor}`

#![warn(missing_docs)]

pub mod routes;
pub mod schema;
pub mod services;

pub use routes::{CustomersState, router};
