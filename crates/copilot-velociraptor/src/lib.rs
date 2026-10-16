//! # copilot-velociraptor — the Velociraptor connector
//!
//! Port of `app/connectors/velociraptor/` and the transport under it,
//! pyvelociraptor's gRPC client:
//!
//! - [`config`] — `pyvelociraptor.LoadConfigFile`: the `api.config.yaml`
//!   whose path the `Velociraptor` connector row stores, and its errors
//! - [`proto`] — `VQLCollectorArgs` / `VQLResponse`, encoded byte for byte as
//!   the Python protobuf runtime encodes them
//! - [`grpc`] — `proto.API/Query` over HTTP/2 with mutual TLS pinned to the
//!   config's CA (`VelociraptorServer`), grpc's status codes and texts
//! - [`client`] — `UniversalService`: VQL in, `json.loads`'d rows out, the
//!   504/403/500 `HTTPException`s, the query and flow deadlines
//! - [`validation`] — the identifier formats VQL interpolation relies on
//!   (GHSA-5542-j2fc-gqjm)
//! - [`verify`] — the connector check for `/api/connectors`
//!
//! There is no `protoc` at build time: the five messages CoPilot uses are
//! written out by hand in [`proto`] and pinned by tests against bytes the
//! Python runtime produced.

#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod grpc;
mod pinned;
pub mod proto;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod validation;
pub mod verify;

pub use client::{Service, Timeouts, VelociraptorClient};
