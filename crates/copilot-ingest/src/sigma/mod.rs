//! The Velociraptor Sigma ingest and the in-context exclusion rules built
//! on it (#934): the event models, `extract_event_fields`, the matcher, the
//! comments the ingest writes and the draft and dry-run that read them back.
//!
//! One flattening ([`fields::extract_event_fields`]) and one matcher
//! ([`matcher::matches`]) serve the ingest, the draft and the dry-run, as in
//! Python: a rule built from a draft can only name fields the ingest will
//! find, and "matches" in a dry-run means the next identical alert is
//! suppressed.

pub mod draft;
pub mod events;
pub mod fields;
pub mod ingest;
pub mod matcher;

/// The ingest's meta comment on a Wazuh-matched alert
/// (`Velociraptor Sigma: <title> | <channel>`): a writer/reader contract
/// with [`draft::parse_sigma_comments`].
pub const SIGMA_META_COMMENT_PREFIX: &str = "Velociraptor Sigma: ";
/// The fallback path's comment (`Title:` / `Channel:` lines follow).
pub const SIGMA_FALLBACK_COMMENT_PREFIX: &str = "Velociraptor Sigma Alert (No Wazuh match found)";
/// The fenced event payload comment.
pub const SIGMA_PAYLOAD_COMMENT_PREFIX: &str = "Full Event Payload:";
