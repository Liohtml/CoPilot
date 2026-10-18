//! # copilot-reports — every PDF and DOCX CoPilot generates
//!
//! - [`pdfkit`]    — `convert_html_to_pdf` / `html_to_pdf_bytes`: the
//!   `wkhtmltopdf` binary found as `reports_pdf.py` finds it, run with the
//!   arguments pdfkit 1.0 builds, failing with pdfkit's texts
//! - [`starlette`] — Starlette's `FileResponse` (stat headers, ranges) and
//!   `Response`, through `copilot.py`'s `GZipMiddleware(minimum_size=1000)`
//! - [`tempfile`]  — `NamedTemporaryFile(delete=False, suffix=…)` names
//! - [`case`]      — the case DOCX (`copilot-docx`) and PDF reports

#![warn(missing_docs)]

pub mod case;
pub mod pdfkit;
pub mod starlette;
pub mod tempfile;
