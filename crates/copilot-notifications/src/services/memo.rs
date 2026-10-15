//! `DispatchContext.memoize`: lookups several routes of one dispatch share
//! (branding per customer, an alert's AI report, the webhook's full report,
//! connector credentials), read at most once per dispatch.

use std::collections::HashMap;

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::Input;

use crate::channels::send::Credentials;

/// Per-dispatch memo.
#[derive(Debug, Default)]
pub struct Memo {
    /// `branding:{customer_code}`.
    pub branding: HashMap<Option<String>, Input>,
    /// `ai_report:{alert_id}` (`None` stored as `Input::None`).
    pub ai_report: HashMap<i64, Input>,
    /// `full_report:{alert_id}` (the webhook's report fields).
    pub full_report: HashMap<i64, Option<PyValue>>,
    /// `resend_creds` (only a successful lookup is kept, like `memoize`).
    pub resend: Option<Credentials>,
    /// `shuffle_creds`.
    pub shuffle: Option<Credentials>,
}
