//! `POST /api/incidents/db_operations/case/notification` — the case's
//! customer notification through Shuffle (`create_case_notification_endpoint`,
//! `handle_customer_notifications_case`, `increment_case_notification_count`).

pub mod routes;
pub mod schema;
pub mod services;
