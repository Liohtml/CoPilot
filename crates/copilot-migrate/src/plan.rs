//! What the runner does with a database: a pure decision on its state.
//!
//! | The database holds | The runner |
//! |---|---|
//! | nothing (no table but an empty history table) | creates the baseline |
//! | `alembic_version` = the head, no history | records the baseline as *adopted*, touches no table |
//! | the history | applies the migrations it lacks, in order |
//! | an older Alembic revision | refuses: run the last Python release once, which upgrades it |
//! | any other revision, an empty or branched `alembic_version` | refuses |
//! | tables but no version at all | refuses: not a database this service can adopt |
//! | a migration recorded as unfinished, unknown to this build, changed since it ran, or missing below a later one | refuses |

use std::fmt;

use crate::ALEMBIC_HEAD;
use crate::migrations::Migration;
use crate::state::{Alembic, HistoryRow, SchemaState};

/// What happens to the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Baseline {
    /// Already recorded.
    Recorded,
    /// The database is at the Alembic head: record it, touch nothing.
    Adopt,
    /// The database is empty: run the baseline's SQL.
    Create,
}

/// The work for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The baseline's fate.
    pub baseline: Baseline,
    /// The migrations after the baseline still to apply, in order.
    pub pending: Vec<Migration>,
    /// Things worth an operator's look that do not stop the run.
    pub warnings: Vec<String>,
}

impl Plan {
    /// Whether the run changes nothing.
    pub fn is_noop(&self) -> bool {
        self.baseline == Baseline::Recorded && self.pending.is_empty()
    }
}

/// Why the runner will not touch a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `alembic_version` holds a revision of the Python history before the head.
    OlderAlembic(String),
    /// `alembic_version` holds a revision CoPilot never shipped.
    UnknownAlembic(String),
    /// `alembic_version` has no row.
    EmptyAlembic,
    /// `alembic_version` has several rows.
    BranchedAlembic(Vec<String>),
    /// Tables, but neither an Alembic revision nor a Rust history.
    Unversioned(Vec<String>),
    /// A migration started and did not finish.
    Unfinished(HistoryRow),
    /// The history names a migration this build does not have.
    UnknownMigration(HistoryRow),
    /// The file of an applied migration changed since.
    ChecksumMismatch(HistoryRow),
    /// A history without the baseline.
    NoBaseline,
    /// A migration this build has is missing below one that was applied.
    OutOfOrder {
        /// The missing one.
        missing: String,
        /// The newest applied one.
        applied: String,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OlderAlembic(rev) => write!(
                f,
                "the database is at Alembic revision {rev}, older than {ALEMBIC_HEAD}, the last \
                 Python migration; this service does not run the Python migrations. Start the \
                 last release of the Python backend once against this database (its startup runs \
                 `alembic upgrade head`), then start this service again: it adopts a database at \
                 {ALEMBIC_HEAD} as its baseline"
            ),
            Self::UnknownAlembic(rev) => write!(
                f,
                "the database is at Alembic revision {rev}, which no CoPilot release has: it was \
                 not created by CoPilot, or by a branch this build does not know. Refusing to \
                 touch it"
            ),
            Self::EmptyAlembic => f.write_str(
                "alembic_version exists but holds no revision (an Alembic run that stopped?): \
                 repair the database, or start again from an empty one",
            ),
            Self::BranchedAlembic(revs) => write!(
                f,
                "alembic_version holds several revisions ({}): not a CoPilot history. Refusing \
                 to touch it",
                revs.join(", ")
            ),
            Self::Unversioned(tables) => write!(
                f,
                "the database holds {} table(s) ({}{}) but no recorded schema version (no \
                 alembic_version, no {}): not a CoPilot database this service can adopt. Point \
                 it at an empty database, or at one a CoPilot release created",
                tables.len(),
                tables
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if tables.len() > 5 { ", …" } else { "" },
                crate::state::HISTORY_TABLE,
            ),
            Self::Unfinished(row) => write!(
                f,
                "migration {:04}_{} started at {} UTC and did not finish: its statements are not \
                 transactional, so part of it may be applied. Repair the schema by hand (or, for \
                 the baseline of a database that was empty, drop its tables), delete its row from \
                 {}, then start again",
                row.version,
                row.name,
                row.applied_at,
                crate::state::HISTORY_TABLE
            ),
            Self::UnknownMigration(row) => write!(
                f,
                "the database is at migration {:04}_{}, which this build does not have: it was \
                 migrated by a newer release. Run that release (or a newer one)",
                row.version, row.name
            ),
            Self::ChecksumMismatch(row) => write!(
                f,
                "migration {:04}_{} was applied from a file whose checksum ({}) differs from this \
                 build's: a released migration was edited. Refusing to go on",
                row.version, row.name, row.checksum
            ),
            Self::NoBaseline => write!(
                f,
                "{} has rows but not the baseline (version 1): refusing to guess what the schema \
                 is",
                crate::state::HISTORY_TABLE
            ),
            Self::OutOfOrder { missing, applied } => write!(
                f,
                "migration {missing} was never applied, yet the later {applied} was: refusing to \
                 apply migrations out of order"
            ),
        }
    }
}

/// Decide what to do with a database in `state`, given this build's
/// `migrations` (the baseline first).
pub fn plan(state: &SchemaState, migrations: &[Migration]) -> Result<Plan, Refusal> {
    let mut warnings = Vec::new();
    if state.history.is_empty() {
        let baseline = match &state.alembic {
            Alembic::Revisions(revs) if revs.len() > 1 => {
                return Err(Refusal::BranchedAlembic(revs.clone()));
            }
            Alembic::Revisions(revs) => {
                let rev = revs[0].as_str();
                if rev == ALEMBIC_HEAD {
                    Baseline::Adopt
                } else if crate::alembic::is_known(rev) {
                    return Err(Refusal::OlderAlembic(rev.to_string()));
                } else {
                    return Err(Refusal::UnknownAlembic(rev.to_string()));
                }
            }
            Alembic::Empty => return Err(Refusal::EmptyAlembic),
            Alembic::Absent if state.tables.is_empty() => Baseline::Create,
            Alembic::Absent => return Err(Refusal::Unversioned(state.tables.clone())),
        };
        return Ok(Plan {
            baseline,
            pending: migrations
                .iter()
                .filter(|m| !m.is_baseline())
                .copied()
                .collect(),
            warnings,
        });
    }

    for row in &state.history {
        if !row.success {
            return Err(Refusal::Unfinished(row.clone()));
        }
        let known = migrations
            .iter()
            .find(|m| i64::from(m.version) == row.version);
        match known {
            None => return Err(Refusal::UnknownMigration(row.clone())),
            Some(m) if m.checksum() != row.checksum => {
                return Err(Refusal::ChecksumMismatch(row.clone()));
            }
            Some(_) => {}
        }
    }
    if !state.history.iter().any(|r| r.version == 1) {
        return Err(Refusal::NoBaseline);
    }
    let newest = state.history.iter().map(|r| r.version).max().unwrap_or(1);
    let mut pending = Vec::new();
    for m in migrations {
        if state
            .history
            .iter()
            .any(|r| r.version == i64::from(m.version))
        {
            continue;
        }
        if i64::from(m.version) < newest {
            let applied = state
                .history
                .iter()
                .find(|r| r.version == newest)
                .map(|r| format!("{:04}_{}", r.version, r.name))
                .unwrap_or_default();
            return Err(Refusal::OutOfOrder {
                missing: m.label(),
                applied,
            });
        }
        pending.push(*m);
    }
    match &state.alembic {
        Alembic::Revisions(revs) if revs.len() == 1 && revs[0] == ALEMBIC_HEAD => {}
        other => warnings.push(format!(
            "alembic_version is {} instead of {ALEMBIC_HEAD}: a Python backend started against \
             this database (a rollback) would try to run Alembic migrations on it",
            match other {
                Alembic::Absent => "missing".to_string(),
                Alembic::Empty => "empty".to_string(),
                Alembic::Revisions(revs) => revs.join(", "),
            }
        )),
    }
    Ok(Plan {
        baseline: Baseline::Recorded,
        pending,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{BASELINE, MIGRATIONS};
    use chrono::NaiveDate;

    const SECOND: Migration = Migration {
        version: 2,
        name: "second",
        sql: "CREATE TABLE x (id int);",
    };
    const THIRD: Migration = Migration {
        version: 3,
        name: "third",
        sql: "CREATE TABLE y (id int);",
    };

    fn row(m: &Migration, success: bool) -> HistoryRow {
        HistoryRow {
            version: i64::from(m.version),
            name: m.name.into(),
            checksum: m.checksum(),
            method: "applied".into(),
            success,
            applied_at: NaiveDate::from_ymd_opt(2026, 10, 18)
                .and_then(|d| d.and_hms_opt(6, 0, 0))
                .unwrap(),
        }
    }

    fn state(tables: &[&str], alembic: Alembic, history: Vec<HistoryRow>) -> SchemaState {
        SchemaState {
            tables: tables.iter().map(|t| t.to_string()).collect(),
            history_table: !history.is_empty(),
            history,
            alembic,
        }
    }

    fn head() -> Alembic {
        Alembic::Revisions(vec![ALEMBIC_HEAD.into()])
    }

    #[test]
    fn an_empty_database_gets_the_baseline() {
        let p = plan(&state(&[], Alembic::Absent, vec![]), MIGRATIONS).unwrap();
        assert_eq!(p.baseline, Baseline::Create);
        assert!(p.pending.is_empty());
        let p = plan(&state(&[], Alembic::Absent, vec![]), &[BASELINE, SECOND]).unwrap();
        assert_eq!(p.pending, vec![SECOND]);
    }

    #[test]
    fn the_alembic_head_is_adopted() {
        let s = state(&["alembic_version", "user"], head(), vec![]);
        let p = plan(&s, &[BASELINE, SECOND]).unwrap();
        assert_eq!(p.baseline, Baseline::Adopt);
        assert_eq!(p.pending, vec![SECOND]);
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn older_unknown_empty_and_branched_revisions_are_refused() {
        let older = state(
            &["alembic_version"],
            Alembic::Revisions(vec!["bdf40d064ed1".into()]),
            vec![],
        );
        let e = plan(&older, MIGRATIONS).unwrap_err();
        assert_eq!(e, Refusal::OlderAlembic("bdf40d064ed1".into()));
        let text = e.to_string();
        assert!(text.contains("bdf40d064ed1") && text.contains("last release of the Python"));
        let unknown = state(
            &["alembic_version"],
            Alembic::Revisions(vec!["0123456789ab".into()]),
            vec![],
        );
        assert_eq!(
            plan(&unknown, MIGRATIONS).unwrap_err(),
            Refusal::UnknownAlembic("0123456789ab".into())
        );
        assert_eq!(
            plan(
                &state(&["alembic_version"], Alembic::Empty, vec![]),
                MIGRATIONS
            )
            .unwrap_err(),
            Refusal::EmptyAlembic
        );
        let branched = Alembic::Revisions(vec![ALEMBIC_HEAD.into(), "bdf40d064ed1".into()]);
        assert!(matches!(
            plan(&state(&["alembic_version"], branched, vec![]), MIGRATIONS),
            Err(Refusal::BranchedAlembic(_))
        ));
    }

    #[test]
    fn tables_without_a_version_are_refused() {
        let e = plan(&state(&["foo", "bar"], Alembic::Absent, vec![]), MIGRATIONS).unwrap_err();
        assert_eq!(e, Refusal::Unversioned(vec!["foo".into(), "bar".into()]));
        assert!(e.to_string().contains("2 table(s) (foo, bar)"));
    }

    #[test]
    fn the_history_decides_once_it_exists() {
        let s = state(&["alembic_version"], head(), vec![row(&BASELINE, true)]);
        assert!(plan(&s, MIGRATIONS).unwrap().is_noop());
        let p = plan(&s, &[BASELINE, SECOND, THIRD]).unwrap();
        assert_eq!(p.baseline, Baseline::Recorded);
        assert_eq!(p.pending, vec![SECOND, THIRD]);
        // The history wins over alembic_version, which only warns.
        let s = state(&["x"], Alembic::Absent, vec![row(&BASELINE, true)]);
        let p = plan(&s, MIGRATIONS).unwrap();
        assert!(p.is_noop());
        assert_eq!(p.warnings.len(), 1);
    }

    #[test]
    fn the_history_is_checked() {
        let unfinished = state(&[], head(), vec![row(&BASELINE, true), row(&SECOND, false)]);
        assert!(matches!(
            plan(&unfinished, &[BASELINE, SECOND]),
            Err(Refusal::Unfinished(r)) if r.version == 2
        ));
        let newer = state(&[], head(), vec![row(&BASELINE, true), row(&SECOND, true)]);
        assert!(matches!(
            plan(&newer, MIGRATIONS),
            Err(Refusal::UnknownMigration(r)) if r.version == 2
        ));
        let mut edited = row(&SECOND, true);
        edited.checksum = "0".repeat(64);
        let s = state(&[], head(), vec![row(&BASELINE, true), edited]);
        assert!(matches!(
            plan(&s, &[BASELINE, SECOND]),
            Err(Refusal::ChecksumMismatch(r)) if r.version == 2
        ));
        let s = state(&[], head(), vec![row(&SECOND, true)]);
        assert_eq!(
            plan(&s, &[BASELINE, SECOND]).unwrap_err(),
            Refusal::NoBaseline
        );
        let s = state(&[], head(), vec![row(&BASELINE, true), row(&THIRD, true)]);
        assert_eq!(
            plan(&s, &[BASELINE, SECOND, THIRD]).unwrap_err(),
            Refusal::OutOfOrder {
                missing: "0002_second".into(),
                applied: "0003_third".into()
            }
        );
    }
}
