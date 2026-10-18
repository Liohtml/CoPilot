//! The Alembic history the Python backend shipped, frozen at
//! [`crate::ALEMBIC_HEAD`].
//!
//! `alembic_revisions.json` lists every revision of `backend/alembic/versions/`
//! (`scripts/gen-startup-vectors.py`, from Alembic's own `ScriptDirectory`):
//! what tells a database Python left at an *older* revision — which a run of
//! the last Python release upgrades — from one at a revision CoPilot never
//! shipped. A test fails when the versions directory gains a revision.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Frozen {
    head: String,
    revisions: Vec<String>,
}

fn frozen() -> &'static Option<Frozen> {
    static FROZEN: OnceLock<Option<Frozen>> = OnceLock::new();
    FROZEN.get_or_init(|| serde_json::from_str(include_str!("alembic_revisions.json")).ok())
}

/// Whether `revision` is one of the Python backend's migrations.
pub fn is_known(revision: &str) -> bool {
    frozen()
        .as_ref()
        .is_some_and(|f| f.revisions.iter().any(|r| r == revision))
}

/// Every revision of the frozen history.
pub fn revisions() -> BTreeSet<&'static str> {
    frozen()
        .as_ref()
        .map(|f| f.revisions.iter().map(String::as_str).collect())
        .unwrap_or_default()
}

/// The frozen head as the generator recorded it.
pub fn recorded_head() -> Option<&'static str> {
    frozen().as_ref().map(|f| f.head.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_is_the_baseline_revision() {
        assert_eq!(recorded_head(), Some(crate::ALEMBIC_HEAD));
        assert_eq!(crate::ALEMBIC_HEAD, copilot_db::schema::TESTED_ALEMBIC_HEAD);
        assert!(is_known(crate::ALEMBIC_HEAD));
        assert!(is_known("bdf40d064ed1"));
        assert!(!is_known("ffffffffffff"));
    }

    #[test]
    fn the_python_migrations_are_frozen() {
        // Every `revision = "…"` of backend/alembic/versions/ is in the frozen
        // list and no other: a new Python migration is an error (schema
        // changes are Rust migrations now). scripts/check-alembic-head.py
        // reports the same in CI.
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../backend/alembic/versions");
        let mut found = BTreeSet::new();
        for entry in std::fs::read_dir(&dir).expect("alembic versions") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("py") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("migration source");
            for line in text.lines() {
                let rest = line
                    .strip_prefix("revision: str = ")
                    .or_else(|| line.strip_prefix("revision = "));
                if let Some(rest) = rest {
                    found.insert(
                        rest.trim()
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string(),
                    );
                }
            }
        }
        let frozen: BTreeSet<String> = revisions().iter().map(|s| s.to_string()).collect();
        assert_eq!(found, frozen);
        assert_eq!(frozen.len(), 99);
    }
}
