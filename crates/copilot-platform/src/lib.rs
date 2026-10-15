//! # copilot-platform — release check and audit log reads
//!
//! Two small read surfaces of the *Platform* menu:
//!
//! - [`version`] — `GET /api/version/check` (`app/version/`): the running
//!   release against GitHub's latest, compared as PEP 440 versions
//!   ([`pep440`]). No authentication, as in Python. `COPILOT_VERSION_CHECK_URL`
//!   points it at a mirror (or a test stub).
//! - [`audit`]   — `GET /api/audit`, `/api/audit/actions`,
//!   `/api/audit/{id}` (`app/audit/routes/audit.py`): admin only, guarded the
//!   way Python guards them (`Security(get_current_user, scopes=["admin"])`).
//!   The table stays append-only: writes happen where actions happen.
//! - [`routes`]  — both routers.

#![warn(missing_docs)]

pub mod audit;
pub mod pep440;
pub mod routes;
pub mod version;

pub use routes::{PlatformState, audit_router, version_router};
