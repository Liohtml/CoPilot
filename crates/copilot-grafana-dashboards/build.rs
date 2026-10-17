//! Embeds the Grafana dashboard templates straight from the Python backend's
//! tree (`backend/app/connectors/grafana/dashboards/`): one source for both
//! backends while Python still serves part of the API. Every `*.json` file
//! under it becomes an `include_str!` entry of `FILES`, keyed by its path
//! relative to that directory (`Wazuh/summary.json`), sorted.

use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={}", dir.display());
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            println!("cargo:rerun-if-changed={}", path.display());
            out.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest
        .join("../../backend/app/connectors/grafana/dashboards")
        .canonicalize()
        .map_err(|e| {
            format!(
                "the dashboard templates must be at backend/app/connectors/grafana/dashboards \
                 (the Rust image's Dockerfile copies them): {e}"
            )
        })?;
    let mut files = Vec::new();
    walk(&root, &mut files)?;
    files.sort();
    let mut code = String::from(
        "/// Every dashboard template, by its path under\n\
         /// `backend/app/connectors/grafana/dashboards/`.\n\
         pub static FILES: &[(&str, &str)] = &[\n",
    );
    for path in &files {
        let rel = path
            .strip_prefix(&root)?
            .to_str()
            .ok_or("a template path is not UTF-8")?
            .replace('\\', "/");
        let abs = path.to_str().ok_or("a template path is not UTF-8")?;
        writeln!(code, "    ({rel:?}, include_str!({abs:?})),")?;
    }
    code.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR")?).join("templates.rs");
    std::fs::write(out, code)?;
    Ok(())
}
