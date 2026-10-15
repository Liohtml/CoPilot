//! # copilot-gateway — the strangler-fig seam to the Python backend
//!
//! The Rust service is the front door; the Python backend keeps serving
//! every module that has not been ported yet:
//!
//! - [`legacy`]        — streaming reverse proxy for unported routes
//! - [`notify_bridge`] — hands notification events to the Python pipeline
//!
//! Both disappear module by module: once nothing is proxied and the
//! notification module is ported, this crate is deleted.

#![warn(missing_docs)]

pub mod legacy;
pub mod notify_bridge;

pub use legacy::{LegacyProxy, proxy_handler};
pub use notify_bridge::LegacyNotificationSink;
