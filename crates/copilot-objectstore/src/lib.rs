//! # copilot-objectstore — the MinIO object store
//!
//! Port of `app/data_store/`: the client `create_session()` returns, the
//! operations `data_store_operations.py` performs with it, and the
//! `/api/agent_data_store` routes.
//!
//! - [`endpoint`] — `BaseURL`: endpoint parsing, path-style URLs, `quote`
//! - [`sigv4`]    — AWS Signature V4 as `signer.py` computes it
//! - [`xml`]      — the ElementTree subset the client reads S3 answers with
//! - [`client`]   — `Minio`: requests, region discovery, retries, multipart
//! - [`error`]    — `S3Error` and the other exceptions, with Python's texts
//! - [`store`]    — `data_store_session.py`: settings, `create_session()`
//! - [`ops`]      — `data_store_operations.py`
//! - [`web`]      — multipart bodies, `StreamingResponse`, path decoding
//! - [`routes`], [`services`], [`schema`] — `/api/agent_data_store`
//!
//! The client sends what miniopy-async 1.23.5 over aiohttp 3.13 sends
//! (every header, the signature, the region lookup each fresh client makes,
//! the retries) and fails with its exception texts; the parity suite
//! `rust_parity_objectstore_e2e.py` compares both backends' requests to one
//! recording S3 stand-in.

#![warn(missing_docs)]

pub mod client;
pub mod endpoint;
pub mod error;
pub mod ops;
pub mod routes;
pub mod schema;
pub mod services;
pub mod sigv4;
pub mod store;
pub mod web;
pub mod xml;

pub use client::Minio;
pub use copilot_upstream::py::PyExc;
pub use error::{MinioError, S3Error};
pub use routes::{DataStoreState, router};
pub use services::REQUIREMENTS;
pub use store::ObjectStore;
