//! Business logic: configuration ([`admin`]), named templates
//! ([`templates`]), rendering ([`render`]), the dispatch loop
//! ([`dispatch`]), manual sends ([`manual`]) and the AI report context
//! ([`ai_report`]).

pub mod admin;
pub mod ai_report;
pub mod dispatch;
pub mod manual;
pub mod memo;
pub mod render;
pub mod templates;
