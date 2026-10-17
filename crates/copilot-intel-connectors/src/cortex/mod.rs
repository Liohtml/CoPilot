//! The Cortex connector — port of `app/connectors/cortex/`: [`client`]
//! (cortex4py's `Api` and models over `requests`), [`schema`],
//! [`services`], [`routes`] (`/api/analyzers`, two routes).

pub mod client;
pub mod routes;
pub mod schema;
pub mod services;
