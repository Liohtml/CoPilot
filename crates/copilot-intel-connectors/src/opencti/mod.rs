//! The OpenCTI connector (#1143) — port of `app/connectors/opencti/`:
//! [`transport`] (`utils/universal.py`), [`queries`] (the GraphQL documents),
//! [`schema`], [`services`], [`routes`] (`/api/opencti`, six routes).

pub mod queries;
pub mod routes;
pub mod schema;
pub mod services;
pub mod transport;
