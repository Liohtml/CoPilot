//! Splitting a migration script into the statements MySQL runs one by one.
//!
//! A migration is a plain SQL file. It is cut at every `;` outside a string,
//! a quoted identifier and a comment, the way the `mysql` client cuts what it
//! is fed — so the baseline (a `mysqldump`) and later hand-written files run
//! statement by statement on one connection, each failure naming its
//! statement. `/*! … */` (an executable comment, which `mysqldump` writes) and
//! `/*+ … */` (an optimizer hint) are code; any other comment is not, and a
//! piece holding nothing else is dropped.

/// The statements of `script`, trimmed, in order.
pub fn split_statements(script: &str) -> Vec<&str> {
    let bytes = script.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut has_code = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                has_code = true;
                i = skip_quoted(bytes, i, b);
                continue;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-')
                && bytes.get(i + 2).is_none_or(|c| c.is_ascii_whitespace()) =>
            {
                i = skip_line(bytes, i);
                continue;
            }
            b'#' => {
                i = skip_line(bytes, i);
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                if matches!(bytes.get(i + 2), Some(b'!' | b'+')) {
                    has_code = true;
                }
                i = skip_block_comment(bytes, i);
                continue;
            }
            b';' => {
                if has_code {
                    out.push(script[start..i].trim());
                }
                start = i + 1;
                has_code = false;
            }
            c if !c.is_ascii_whitespace() => has_code = true,
            _ => {}
        }
        i += 1;
    }
    if has_code {
        out.push(script[start..].trim());
    }
    out
}

/// Past the closing quote (a doubled quote or a backslash escape stays
/// inside; backticks have no backslash escape).
fn skip_quoted(bytes: &[u8], open: usize, quote: u8) -> usize {
    let mut i = open + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && quote != b'`' {
            i += 2;
            continue;
        }
        if b == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_line(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |p| from + p + 1)
}

fn skip_block_comment(bytes: &[u8], open: usize) -> usize {
    let mut i = open + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuts_at_semicolons_outside_strings_and_comments() {
        let script = "-- header; not a statement\nSET A=1;\n\nCREATE TABLE `a;b` (x varchar(9) \
                      DEFAULT 'x;''y' COMMENT \"q;\\\"\");\n/* note; */\n# also; a comment\n\
                      INSERT INTO t VALUES ('a\\';b');\n";
        assert_eq!(
            split_statements(script),
            vec![
                "-- header; not a statement\nSET A=1",
                "CREATE TABLE `a;b` (x varchar(9) DEFAULT 'x;''y' COMMENT \"q;\\\"\")",
                "/* note; */\n# also; a comment\nINSERT INTO t VALUES ('a\\';b')",
            ]
        );
    }

    #[test]
    fn executable_comments_are_statements_and_plain_ones_are_not() {
        let script = "/*!40101 SET @x=@@sql_mode */;\n/* nothing */;\n/*+ hint */ SELECT 1;\n  \n";
        assert_eq!(
            split_statements(script),
            vec!["/*!40101 SET @x=@@sql_mode */", "/*+ hint */ SELECT 1"]
        );
    }

    #[test]
    fn a_trailing_statement_without_semicolon_is_kept() {
        assert_eq!(
            split_statements("SELECT 1;SELECT 2"),
            vec!["SELECT 1", "SELECT 2"]
        );
        assert!(split_statements("-- only a comment\n").is_empty());
        // `--` without a following space is an operator, as in MySQL.
        assert_eq!(split_statements("SELECT 1--1;"), vec!["SELECT 1--1"]);
    }

    #[test]
    fn the_baseline_splits_into_its_statements() {
        let stmts = split_statements(crate::migrations::BASELINE.sql);
        let creates = stmts
            .iter()
            .filter(|s| s.starts_with("CREATE TABLE"))
            .count();
        assert_eq!(creates, 116);
        assert!(stmts.iter().all(|s| !s.ends_with(';')));
        assert_eq!(
            stmts.first(),
            Some(
                &"-- CoPilot schema at Alembic d15ab1ed7e1e: the baseline of the Rust migrations (copilot-migrate).\n-- Generated by scripts/gen-baseline-schema.sh from an empty database `alembic upgrade head` migrated.\n-- Never edit: its SHA-256 is recorded in copilot_rs_schema_history of every database it created.\nSET FOREIGN_KEY_CHECKS=0"
            )
        );
        assert_eq!(stmts.last(), Some(&"SET FOREIGN_KEY_CHECKS=1"));
    }
}
