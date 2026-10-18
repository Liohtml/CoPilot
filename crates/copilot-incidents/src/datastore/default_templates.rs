//! The report templates `POST /case-report-template/default-template`
//! uploads: every file directly under `backend/app/incidents/templates`
//! (Python's `templates_dir.iterdir()`, directories skipped), compiled in
//! from the Python backend's tree — one source while Python still renders
//! the reports (the Rust image's Dockerfile copies the directory). A test
//! fails when a file is added there and not here.
//!
//! Python visits them in the order the host's directory lists them, which
//! the filesystem decides; here they go in name order (RUST_MIGRATION.md §4).

/// The files, by name, in name order.
pub static FILES: &[(&str, &[u8])] = &[
    (
        "_report_base.html",
        include_bytes!("../../../../backend/app/incidents/templates/_report_base.html"),
    ),
    (
        "_report_macros.html",
        include_bytes!("../../../../backend/app/incidents/templates/_report_macros.html"),
    ),
    (
        "case_report_jinja_template.docx",
        include_bytes!(
            "../../../../backend/app/incidents/templates/case_report_jinja_template.docx"
        ),
    ),
    (
        "case_report_jinja_template.html",
        include_bytes!(
            "../../../../backend/app/incidents/templates/case_report_jinja_template.html"
        ),
    ),
    (
        "customer_incident_report_analytics.html",
        include_bytes!(
            "../../../../backend/app/incidents/templates/customer_incident_report_analytics.html"
        ),
    ),
    (
        "customer_incident_report_executive.html",
        include_bytes!(
            "../../../../backend/app/incidents/templates/customer_incident_report_executive.html"
        ),
    ),
    (
        "customer_incident_report_operational.html",
        include_bytes!(
            "../../../../backend/app/incidents/templates/customer_incident_report_operational.html"
        ),
    ),
    (
        "customer_incident_report_template.html",
        include_bytes!(
            "../../../../backend/app/incidents/templates/customer_incident_report_template.html"
        ),
    ),
];

/// The directory entries that are not files (only logged, as Python logs
/// every entry before its `is_file()` check).
pub static DIRECTORIES: &[&str] = &["assets"];

/// `mimetypes.guess_type(path)[0]` for these names, as on a host with
/// Debian's `/etc/mime.types` (`libpython3.11-stdlib` depends on it).
pub fn guess_type(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".docx") {
        Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    } else if lower.ends_with(".html") || lower.ends_with(".htm") {
        Some("text/html")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiled-in list is the directory: the same files, the same bytes.
    #[test]
    fn the_list_is_the_python_directory() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../backend/app/incidents/templates");
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("templates dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().into_string().expect("utf-8 name");
            if entry.path().is_file() {
                files.push(name);
            } else {
                dirs.push(name);
            }
        }
        files.sort();
        dirs.sort();
        let listed: Vec<&str> = FILES.iter().map(|(n, _)| *n).collect();
        assert_eq!(files, listed);
        assert_eq!(dirs, DIRECTORIES);
        for (name, data) in FILES {
            assert_eq!(
                std::fs::read(dir.join(name)).expect("file"),
                *data,
                "{name}"
            );
        }
        assert_eq!(guess_type("x.html"), Some("text/html"));
    }
}
