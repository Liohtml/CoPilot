//! # copilot-migrate — the schema, owned by the Rust service
//!
//! Until phase 5 Alembic (`backend/alembic/`) owned the schema and the binary
//! only checked it (`copilot_db::schema`). Now the binary owns it:
//!
//! - **The baseline** ([`migrations::BASELINE`]) is the schema at the Alembic
//!   head [`ALEMBIC_HEAD`], exactly what `alembic upgrade head` creates on an
//!   empty database (`alembic_version` and the five roles included, so a
//!   Python backend started against the database for a rollback sees its
//!   head and runs nothing). Alembic is frozen there: the 99 historical Python
//!   migrations are not ported, so a database at an older Alembic revision is
//!   refused with what to do (run the last Python release once — its startup
//!   upgrades it — then this service adopts it).
//! - **Later changes are Rust migrations**: plain SQL files, forward-only,
//!   each recorded with its SHA-256 in [`state::HISTORY_TABLE`]
//!   ([`migrations`]).
//! - **What the runner does** is a pure decision on what it finds
//!   ([`plan`]): an empty database gets the baseline; one at the Alembic head
//!   is *adopted* (the baseline recorded, no table touched); a recorded one
//!   gets the migrations it lacks; anything else is refused.
//! - **One at a time**: the runner works on the connection holding the
//!   [`StartupLock`], which the Python backend takes too.
//!
//! `copilot migrate` runs it; `copilot serve` runs it at start unless
//! `COPILOT_RUN_MIGRATIONS=false`; `copilot doctor` reports it ([`describe`]).

#![warn(missing_docs)]

pub mod alembic;
pub mod lock;
pub mod migrations;
pub mod plan;
pub mod runner;
pub mod sql;
pub mod state;

pub use lock::StartupLock;
pub use migrations::{ALEMBIC_HEAD, BASELINE, MIGRATIONS, Migration};
pub use plan::{Baseline, Plan, Refusal};
pub use runner::{Action, MigrateError, Report, migrate, status};
pub use state::{HISTORY_TABLE, SchemaState};

/// One line of `copilot doctor` per finding, and whether it is a failure.
pub fn describe(state: &SchemaState, decision: &Result<Plan, Refusal>) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    match decision {
        Err(refusal) => out.push((format!("FAIL {refusal}"), true)),
        Ok(plan) => {
            match plan.baseline {
                Baseline::Recorded => {
                    let applied: Vec<String> = state
                        .history
                        .iter()
                        .map(|r| {
                            format!(
                                "{:04}_{} ({} {} UTC)",
                                r.version, r.name, r.method, r.applied_at
                            )
                        })
                        .collect();
                    out.push((format!("ok   history: {}", applied.join(", ")), false));
                }
                Baseline::Adopt => out.push((
                    format!(
                        "warn at Alembic {ALEMBIC_HEAD}, not yet recorded: `copilot migrate` (or \
                         serve's start) adopts it as the baseline without touching a table"
                    ),
                    false,
                )),
                Baseline::Create => out.push((
                    "warn empty database: `copilot migrate` (or serve's start) creates the \
                     baseline schema"
                        .to_string(),
                    false,
                )),
            }
            if plan.pending.is_empty() {
                if plan.baseline == Baseline::Recorded {
                    out.push(("ok   no migration pending".to_string(), false));
                }
            } else {
                let names: Vec<String> = plan.pending.iter().map(Migration::label).collect();
                out.push((
                    format!(
                        "warn {} migration(s) pending: {} (applied by `copilot migrate`, or at \
                         serve's start while COPILOT_RUN_MIGRATIONS is on)",
                        names.len(),
                        names.join(", ")
                    ),
                    false,
                ));
            }
            for w in &plan.warnings {
                out.push((format!("warn {w}"), false));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use state::Alembic;

    #[test]
    fn describe_names_each_state() {
        let empty = SchemaState {
            tables: vec![],
            history_table: false,
            history: vec![],
            alembic: Alembic::Absent,
        };
        let lines = describe(&empty, &plan::plan(&empty, MIGRATIONS));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].0.starts_with("warn empty database"));
        let older = SchemaState {
            tables: vec!["alembic_version".into()],
            history_table: false,
            history: vec![],
            alembic: Alembic::Revisions(vec!["bdf40d064ed1".into()]),
        };
        let lines = describe(&older, &plan::plan(&older, MIGRATIONS));
        assert!(lines[0].1 && lines[0].0.contains("bdf40d064ed1"));
    }
}
