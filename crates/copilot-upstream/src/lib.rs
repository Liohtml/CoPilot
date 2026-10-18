//! # copilot-upstream — what CoPilot's Python connector helpers did with a
//! tool's answers
//!
//! The connector modules (Graylog, InfluxDB, Grafana, Portainer, and the ones
//! after them) are thin: call the tool, index into its JSON, build Pydantic
//! models, answer. What makes porting them exact is everything around that,
//! and it lives here once:
//!
//! - [`http`]  — `requests`/`niquests` request preparation and failure texts
//! - [`json`]  — CPython's `json.dumps`/`JSONDecodeError`, pydantic-core's
//!   JSON writer
//! - [`model`] — Pydantic models (lax validation, `ValidationError` text,
//!   JSON-mode dumps), for answers and request bodies
//! - [`py`]    — Python exceptions as values (`KeyError`, `TypeError`, …) and
//!   what the backend's exception handlers make of them
//! - [`respond`] — FastAPI's answers: a `response_model` body, a 422 from a
//!   model's errors

#![warn(missing_docs)]

pub mod http;
pub mod json;
pub mod model;
pub mod py;
pub mod respond;
