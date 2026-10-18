//! The migrations this build knows, in order.
//!
//! **Version 1 is the baseline**: the schema at the Alembic head
//! [`ALEMBIC_HEAD`], exactly what `alembic upgrade head` creates on an empty
//! database (`migrations/0001_baseline.sql`, written by
//! `scripts/gen-baseline-schema.sh` the way `scripts/dump-schema.sh` writes
//! the e2e fixture, and pinned to it by a test). Every later schema change is
//! one more file here: plain SQL, forward-only (no down migration), numbered
//! after the last one and never edited once released — the runner records each
//! file's SHA-256 and refuses a database whose recorded checksum differs.
//!
//! Adding one: `migrations/000N_<what>.sql`, a [`Migration`] at the end of
//! [`MIGRATIONS`], then regenerate the e2e fixture (`scripts/dump-schema.sh`
//! on a database `copilot migrate` brought to the new head) and add the
//! columns a crate needs to its `TableRequirement`s. A statement MySQL cannot
//! run inside a transaction (any DDL) is not rolled back on a failure: write
//! each file so it can be repaired by hand from where it stopped.

use sha2::{Digest, Sha256};

/// The Alembic revision the Python migrations are frozen at; the baseline is
/// the schema they create.
pub const ALEMBIC_HEAD: &str = "d15ab1ed7e1e";

/// One migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Its number: 1, 2, 3, … with no gap.
    pub version: u32,
    /// Its name (the file name without the number and `.sql`).
    pub name: &'static str,
    /// The SQL, statements separated by `;`.
    pub sql: &'static str,
}

impl Migration {
    /// SHA-256 of the file's bytes, lower-case hex: what the history records.
    pub fn checksum(&self) -> String {
        hex::encode(Sha256::digest(self.sql.as_bytes()))
    }

    /// `0001_baseline`.
    pub fn label(&self) -> String {
        format!("{:04}_{}", self.version, self.name)
    }

    /// Whether this is the baseline.
    pub fn is_baseline(&self) -> bool {
        self.version == BASELINE.version
    }
}

/// The baseline: the schema at Alembic [`ALEMBIC_HEAD`].
pub const BASELINE: Migration = Migration {
    version: 1,
    name: "baseline",
    sql: include_str!("../migrations/0001_baseline.sql"),
};

/// Every migration, in order (the baseline first).
pub const MIGRATIONS: &[Migration] = &[BASELINE];

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture body without its header comments.
    fn body(sql: &str) -> String {
        sql.lines()
            .filter(|l| !l.starts_with("-- "))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_baseline_is_the_e2e_fixture() {
        // While the baseline is the only migration, the fixture the e2e
        // suites load (`scripts/dump-schema.sh`) is the baseline itself: both
        // are `mysqldump` of a database `alembic upgrade head` created. Once a
        // migration follows, the e2e suite's runner test compares the
        // migrated schema with the regenerated fixture instead.
        if MIGRATIONS.len() == 1 {
            let fixture = include_str!("../../copilot/tests/fixtures/schema.sql");
            assert_eq!(body(BASELINE.sql), body(fixture));
        }
        assert!(BASELINE.sql.contains(&format!(
            "INSERT INTO `alembic_version` VALUES ('{ALEMBIC_HEAD}');"
        )));
    }

    #[test]
    fn versions_are_sequential_and_names_unique() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version as usize, i + 1, "{}", m.label());
            assert!(
                !m.name.is_empty()
                    && m.name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            );
        }
        assert!(MIGRATIONS[0].is_baseline());
    }

    #[test]
    fn checksum_is_sha256_of_the_bytes() {
        let m = Migration {
            version: 9,
            name: "x",
            sql: "SELECT 1;\n",
        };
        assert_eq!(
            m.checksum(),
            "b4e0497804e46e0a0b0b8c31975b062152d551bac49c3c2e80932567b4085dcd"
        );
        assert_eq!(m.label(), "0009_x");
        assert_eq!(BASELINE.checksum().len(), 64);
    }
}
