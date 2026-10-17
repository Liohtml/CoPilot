//! `/api/nuclei/*` — `app/integrations/nuclei/` (routes, services, schema):
//! the reports and scans of the `copilot-nuclei-module` container.
//!
//! Every call is `async with httpx.AsyncClient() as client:` and one request
//! (`copilot_threat_intel::httpx`: httpx 0.28's URL handling, headers and
//! `json=`), then what the service makes of the answer: a 404 is the
//! service's own `HTTPException`, `raise_for_status()` (the listing and the
//! report; not the delete or the scan) a bare 500, `response.json()` a
//! `JSONDecodeError` (the `ValueError` handler's 400), `Model(**answer)` the
//! `TypeError` of a non-dict (a bare 500) or the `ValidationError` (400). A
//! transport failure is uncaught: a bare 500.
//!
//! Tenancy: a scanned host or a report names no customer (the module keeps
//! them by host), so the routes keep Python's scope — any admin or analyst.

pub mod routes;
pub mod schema;
pub mod services;
