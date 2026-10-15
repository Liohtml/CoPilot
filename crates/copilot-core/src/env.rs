//! `.env` reader (vendored from `talon_core::env`, Talon 2.0).
//!
//! Values are returned to the caller and never loaded into `std::env`, so
//! secrets don't leak into child processes. Unlike Talon, CoPilot is normally
//! started by Docker Compose with `env_file: .env`, so its secrets arrive as
//! real environment variables; [`EnvFile::get`] therefore reads the process
//! environment first and the `.env` file second for every key. The Python
//! backend loads the same repo-root `.env` (`python-dotenv`), so both services
//! resolve identical values during the migration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parsed `.env` file plus a view of the real process environment.
#[derive(Debug, Clone)]
pub struct EnvFile {
    path: Option<PathBuf>,
    values: HashMap<String, String>,
    /// `false` in tests: only the literal content is visible, so a variable
    /// set in the developer's shell cannot change a test's outcome.
    use_process_env: bool,
}

impl Default for EnvFile {
    fn default() -> Self {
        Self {
            path: None,
            values: HashMap::new(),
            use_process_env: true,
        }
    }
}

impl EnvFile {
    /// Load `<project_root>/.env`. A missing file yields an empty set.
    pub fn load(project_root: &Path) -> Self {
        let path = project_root.join(".env");
        match std::fs::read_to_string(&path) {
            Ok(content) => Self {
                path: Some(path),
                values: parse_env(&content),
                use_process_env: true,
            },
            Err(_) => Self::default(),
        }
    }

    /// Build from literal content, still consulting the process environment.
    pub fn from_str_content(content: &str) -> Self {
        Self {
            path: None,
            values: parse_env(content),
            use_process_env: true,
        }
    }

    /// Build from literal content only, ignoring the process environment
    /// (deterministic tests).
    pub fn isolated(content: &str) -> Self {
        Self {
            path: None,
            values: parse_env(content),
            use_process_env: false,
        }
    }

    /// Path of the loaded `.env`, if one was found.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Value from the `.env` file only.
    pub fn file_value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Process environment first (non-empty), then `.env`.
    pub fn get(&self, key: &str) -> Option<String> {
        let from_process = if self.use_process_env {
            std::env::var(key).ok().filter(|v| !v.is_empty())
        } else {
            None
        };
        from_process.or_else(|| self.values.get(key).cloned())
    }

    /// [`get`](Self::get) with a default.
    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_string())
    }

    /// Parsed integer setting with a default and lower bound.
    pub fn get_u64(&self, key: &str, default: u64, min: u64) -> u64 {
        self.get(key)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
            .max(min)
    }

    /// Boolean setting; accepts the spellings Python's `environs` accepts.
    pub fn get_bool(&self, key: &str) -> bool {
        self.get_bool_or(key, false)
    }

    /// Boolean setting with an explicit default for absent/unknown values.
    pub fn get_bool_or(&self, key: &str, default: bool) -> bool {
        match self.get(key).as_deref().map(str::trim) {
            Some("1" | "true" | "TRUE" | "True" | "yes" | "Yes" | "on" | "y") => true,
            Some("0" | "false" | "FALSE" | "False" | "no" | "No" | "off" | "n") => false,
            _ => default,
        }
    }
}

/// Parse `KEY=VALUE` lines. Supports comments, blank lines, `export KEY=...`
/// and single/double quoted values. Empty values are dropped. A trailing
/// ` # comment` after an unquoted value is stripped, matching `python-dotenv`
/// (the shipped `.env.example` uses that form).
pub fn parse_env(content: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq].trim();
        if key.is_empty() {
            continue;
        }
        let mut value = trimmed[eq + 1..].trim();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = &value[1..value.len() - 1];
        } else if let Some(hash) = value.find(" #") {
            value = value[..hash].trim_end();
        }
        if !value.is_empty() {
            out.insert(key.to_string(), value.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_comments_and_export() {
        let env = EnvFile::isolated(
            "# c\nA=1\nexport B=\"two words\"\nC='x'\nEMPTY=\n  D = spaced \nE=v # note\n",
        );
        assert_eq!(env.file_value("A"), Some("1"));
        assert_eq!(env.file_value("B"), Some("two words"));
        assert_eq!(env.file_value("C"), Some("x"));
        assert_eq!(env.file_value("EMPTY"), None);
        assert_eq!(env.file_value("D"), Some("spaced"));
        assert_eq!(env.file_value("E"), Some("v"));
    }

    #[test]
    fn isolated_ignores_process_env() {
        let env = EnvFile::isolated("PATH=/only/this\n");
        assert_eq!(env.get("PATH").as_deref(), Some("/only/this"));
        assert_eq!(env.get("HOME"), None);
    }

    #[test]
    fn bools_and_numbers() {
        let env = EnvFile::isolated("T=True\nF=false\nN=42\nBAD=x\n");
        assert!(env.get_bool("T"));
        assert!(!env.get_bool_or("F", true));
        assert!(env.get_bool_or("MISSING", true));
        assert_eq!(env.get_u64("N", 1, 0), 42);
        assert_eq!(env.get_u64("BAD", 7, 0), 7);
        assert_eq!(env.get_u64("N", 1, 100), 100);
    }
}
