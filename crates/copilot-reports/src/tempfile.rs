//! `tempfile.NamedTemporaryFile(delete=False, suffix=…)`: a new file in the
//! temporary directory, `tmp` + eight characters of
//! `abcdefghijklmnopqrstuvwxyz0123456789_` + the suffix, created exclusively
//! with mode `0600`, written and closed. The reports hand such files to
//! `wkhtmltopdf`, so its argument list names them as Python's does.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand::Rng as _;

const CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
/// `tempfile.TMP_MAX`.
const TMP_MAX: usize = 10_000;

/// `tempfile.gettempdir()`: `TMPDIR` (then `TEMP`, `TMP`), else `/tmp`.
pub fn temp_dir() -> PathBuf {
    for var in ["TMPDIR", "TEMP", "TMP"] {
        if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            return PathBuf::from(dir);
        }
    }
    std::env::temp_dir()
}

fn random_name(suffix: &str) -> String {
    let mut rng = rand::thread_rng();
    let mut name = String::from("tmp");
    for _ in 0..8 {
        name.push(char::from(CHARACTERS[rng.gen_range(0..CHARACTERS.len())]));
    }
    name.push_str(suffix);
    name
}

/// Create `dir/tmpXXXXXXXX<suffix>` holding `content`; returns its path.
pub fn named_in(dir: &Path, suffix: &str, content: &[u8]) -> std::io::Result<PathBuf> {
    let mut last = None;
    for _ in 0..TMP_MAX {
        let path = dir.join(random_name(suffix));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(content)?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("No usable temporary file name found")))
}

/// [`named_in`] the temporary directory.
pub fn named(suffix: &str, content: &[u8]) -> std::io::Result<PathBuf> {
    named_in(&temp_dir(), suffix, content)
}

/// Remove `path` if it is there (`os.path.exists` then `os.remove`, the
/// failure ignored).
pub fn remove(path: &Path) {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_tempfile() {
        let dir = std::env::temp_dir();
        let p = named_in(&dir, ".html", b"<p>x</p>").unwrap();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        assert!(name.starts_with("tmp") && name.ends_with(".html"), "{name}");
        assert_eq!(name.len(), 3 + 8 + 5);
        assert!(name[3..11].bytes().all(|b| CHARACTERS.contains(&b)));
        assert_eq!(std::fs::read(&p).unwrap(), b"<p>x</p>");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        remove(&p);
        assert!(!p.exists());
        remove(&p);
    }
}
