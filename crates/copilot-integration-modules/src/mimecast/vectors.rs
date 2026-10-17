//! `mimecast_vectors.json` (`scripts/gen-mimecast-vectors.py`): the zip
//! extraction, UTF-8 decoding, line reading and `convert_to_json` against
//! CPython 3.11.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::{files, zip};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../mimecast_vectors.json")).expect("vectors")
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `os.walk`'s view of `root`: files as hex, directories ending in `/`.
fn tree(root: &Path) -> BTreeMap<String, Value> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Value>) {
        let Ok(read) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in read {
            let path = entry.expect("entry").path();
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .display()
                .to_string();
            if path.is_dir() {
                out.insert(format!("{rel}/"), Value::Null);
                walk(root, &path, out);
            } else {
                out.insert(
                    rel,
                    Value::String(to_hex(&std::fs::read(&path).expect("read"))),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.is_dir() {
        walk(root, root, &mut out);
    }
    out
}

#[test]
fn zips_extract_as_zipfile_extracts_them() {
    for (n, case) in vectors()["zips"]
        .as_array()
        .expect("zips")
        .iter()
        .enumerate()
    {
        let label = case["label"].as_str().expect("label");
        let dir =
            std::env::temp_dir().join(format!("copilot-mimecast-vec-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("page.zip");
        let outcome = match zip::extract_all(&hex(case["data"].as_str().expect("data")), &target) {
            Ok(()) => "ok",
            Err(_) => "error",
        };
        assert_eq!(outcome, case["outcome"], "{label}");
        let want: BTreeMap<String, Value> =
            serde_json::from_value(case["files"].clone()).expect("files");
        assert_eq!(tree(&target), want, "{label}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}

#[test]
fn utf8_errors_read_as_cpython_s() {
    for case in vectors()["decode"].as_array().expect("decode") {
        let raw = hex(case["bytes"].as_str().expect("bytes"));
        match std::str::from_utf8(&raw) {
            Ok(text) => assert_eq!(case["text"], text),
            Err(e) => assert_eq!(case["error"], files::utf8_error_text(&raw, &e)),
        }
    }
}

#[test]
fn lines_are_read_as_the_text_layer_reads_them() {
    for (n, case) in vectors()["lines"]
        .as_array()
        .expect("lines")
        .iter()
        .enumerate()
    {
        let label = case["label"].as_str().expect("label");
        let path =
            std::env::temp_dir().join(format!("copilot-mimecast-lines-{}-{n}", std::process::id()));
        std::fs::write(&path, hex(case["bytes"].as_str().expect("bytes"))).expect("write");
        let (lines, failure) = files::read_lines(&path)
            .map_err(|e| e.message())
            .expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        let want: Vec<String> = serde_json::from_value(case["lines"].clone()).expect("lines");
        assert_eq!(lines, want, "{label}");
        assert_eq!(
            failure.map(|f| f.message()),
            case["error"].as_str().map(str::to_string),
            "{label}"
        );
    }
}

#[test]
fn convert_to_json_pairs_as_python_s_dict() {
    for case in vectors()["convert"].as_array().expect("convert") {
        let want: Vec<(String, String)> =
            serde_json::from_value(case["pairs"].clone()).expect("pairs");
        assert_eq!(
            files::convert_to_json(case["line"].as_str().expect("line")),
            want,
            "{}",
            case["line"]
        );
    }
}
