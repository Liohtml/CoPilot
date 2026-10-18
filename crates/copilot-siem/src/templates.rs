//! The built-in dashboard templates, compiled in — and the directory they
//! came from, as `pathlib` sees it.
//!
//! Python reads `app/siem/dashboard_templates/<category>/*.json` from disk on
//! every call (`TEMPLATES_DIR / library_card / f"{template_id}.json"`). The
//! Rust image carries no `backend/`, so the files are copied under
//! `crates/copilot-siem/templates/` and embedded; a test fails when a copy
//! differs from the backend's, or when either side has a file the other
//! lacks.
//!
//! `library_card` and `template_id` come from request bodies and stored rows,
//! so they may hold `/`, `.` and `..`. [`resolve`] walks such a path the way
//! the operating system walks `TEMPLATES_DIR / a / b`: `pathlib` drops empty
//! and `.` parts, `..` climbs (only through a directory that exists), a file
//! is not a directory. Inside the templates directory this is exact. A path
//! that leaves it (an absolute one, or `..` above `siem/`) reads as missing:
//! Python would read whatever the host has there (§4).

/// One `<category>/` directory: its files by name, sorted, `_card.json`
/// included.
#[derive(Debug)]
pub struct Category {
    /// The directory name (the category id, `library_card`).
    pub dir: &'static str,
    /// `(file name, contents)`, sorted by name.
    pub files: &'static [(&'static str, &'static str)],
}

/// Every category directory, sorted by name (`sorted(TEMPLATES_DIR.iterdir())`).
pub const CATEGORIES: &[Category] = &[
    Category {
        dir: "aws_cloudintegration",
        files: &[
            (
                "AWS_CLOUDTRAIL_ERRORS.json",
                include_str!("../templates/aws_cloudintegration/AWS_CLOUDTRAIL_ERRORS.json"),
            ),
            (
                "AWS_CLOUDTRAIL_IAM.json",
                include_str!("../templates/aws_cloudintegration/AWS_CLOUDTRAIL_IAM.json"),
            ),
            (
                "AWS_CLOUDTRAIL_SECURITY_CHANGES.json",
                include_str!(
                    "../templates/aws_cloudintegration/AWS_CLOUDTRAIL_SECURITY_CHANGES.json"
                ),
            ),
            (
                "AWS_CLOUDTRAIL_SIGNIN.json",
                include_str!("../templates/aws_cloudintegration/AWS_CLOUDTRAIL_SIGNIN.json"),
            ),
            (
                "AWS_CLOUDTRAIL_SUMMARY.json",
                include_str!("../templates/aws_cloudintegration/AWS_CLOUDTRAIL_SUMMARY.json"),
            ),
            (
                "AWS_GUARDDUTY_NETWORK.json",
                include_str!("../templates/aws_cloudintegration/AWS_GUARDDUTY_NETWORK.json"),
            ),
            (
                "AWS_GUARDDUTY_SUMMARY.json",
                include_str!("../templates/aws_cloudintegration/AWS_GUARDDUTY_SUMMARY.json"),
            ),
            (
                "_card.json",
                include_str!("../templates/aws_cloudintegration/_card.json"),
            ),
        ],
    },
    Category {
        dir: "office365_cloudintegration",
        files: &[
            (
                "O365_ACTIVE_DIRECTORY.json",
                include_str!("../templates/office365_cloudintegration/O365_ACTIVE_DIRECTORY.json"),
            ),
            (
                "O365_APPLICATIONS.json",
                include_str!("../templates/office365_cloudintegration/O365_APPLICATIONS.json"),
            ),
            (
                "O365_COMPLIANCE_CENTER.json",
                include_str!("../templates/office365_cloudintegration/O365_COMPLIANCE_CENTER.json"),
            ),
            (
                "O365_DEFENDER_FOR_IDENTITY.json",
                include_str!(
                    "../templates/office365_cloudintegration/O365_DEFENDER_FOR_IDENTITY.json"
                ),
            ),
            (
                "O365_DLP.json",
                include_str!("../templates/office365_cloudintegration/O365_DLP.json"),
            ),
            (
                "O365_ENDPOINT.json",
                include_str!("../templates/office365_cloudintegration/O365_ENDPOINT.json"),
            ),
            (
                "O365_EXCHANGE.json",
                include_str!("../templates/office365_cloudintegration/O365_EXCHANGE.json"),
            ),
            (
                "O365_FORMS.json",
                include_str!("../templates/office365_cloudintegration/O365_FORMS.json"),
            ),
            (
                "O365_MITRE.json",
                include_str!("../templates/office365_cloudintegration/O365_MITRE.json"),
            ),
            (
                "O365_ONEDRIVE.json",
                include_str!("../templates/office365_cloudintegration/O365_ONEDRIVE.json"),
            ),
            (
                "O365_POWERBI.json",
                include_str!("../templates/office365_cloudintegration/O365_POWERBI.json"),
            ),
            (
                "O365_SHAREPOINT.json",
                include_str!("../templates/office365_cloudintegration/O365_SHAREPOINT.json"),
            ),
            (
                "O365_SUMMARY.json",
                include_str!("../templates/office365_cloudintegration/O365_SUMMARY.json"),
            ),
            (
                "O365_TEAMS.json",
                include_str!("../templates/office365_cloudintegration/O365_TEAMS.json"),
            ),
            (
                "O365_THREAT_INTELLIGENCE.json",
                include_str!(
                    "../templates/office365_cloudintegration/O365_THREAT_INTELLIGENCE.json"
                ),
            ),
            (
                "_card.json",
                include_str!("../templates/office365_cloudintegration/_card.json"),
            ),
        ],
    },
    Category {
        dir: "wazuh_edr",
        files: &[
            (
                "EDR_DNS_QUERIES.json",
                include_str!("../templates/wazuh_edr/EDR_DNS_QUERIES.json"),
            ),
            (
                "EDR_FILE_OPERATIONS.json",
                include_str!("../templates/wazuh_edr/EDR_FILE_OPERATIONS.json"),
            ),
            (
                "EDR_IMAGE_LOAD.json",
                include_str!("../templates/wazuh_edr/EDR_IMAGE_LOAD.json"),
            ),
            (
                "EDR_NETWORK_CONNECTIONS.json",
                include_str!("../templates/wazuh_edr/EDR_NETWORK_CONNECTIONS.json"),
            ),
            (
                "EDR_OVERVIEW.json",
                include_str!("../templates/wazuh_edr/EDR_OVERVIEW.json"),
            ),
            (
                "EDR_PROCESS_ACTIVITY.json",
                include_str!("../templates/wazuh_edr/EDR_PROCESS_ACTIVITY.json"),
            ),
            (
                "EDR_REGISTRY_ACTIVITY.json",
                include_str!("../templates/wazuh_edr/EDR_REGISTRY_ACTIVITY.json"),
            ),
            (
                "EDR_THREAT_DETECTIONS.json",
                include_str!("../templates/wazuh_edr/EDR_THREAT_DETECTIONS.json"),
            ),
            (
                "_card.json",
                include_str!("../templates/wazuh_edr/_card.json"),
            ),
        ],
    },
];

/// The directory `TEMPLATES_DIR` lives in (`app/siem/`): the only name this
/// build knows in it is `dashboard_templates`.
const TEMPLATES_DIR_NAME: &str = "dashboard_templates";

/// Where a path under `TEMPLATES_DIR` leads.
#[derive(Debug, Clone, Copy)]
pub enum Node {
    /// `TEMPLATES_DIR` itself.
    Root,
    /// Its parent, `app/siem/`.
    Parent,
    /// A category directory.
    Dir(&'static Category),
    /// A file: its name and contents.
    File(&'static str, &'static str),
}

impl Node {
    /// `Path.is_dir()`.
    pub fn is_dir(self) -> bool {
        !matches!(self, Node::File(..))
    }

    /// The contents, when this is a file (`Path.is_file()`).
    pub fn file(self) -> Option<&'static str> {
        match self {
            Node::File(_, text) => Some(text),
            _ => None,
        }
    }
}

fn category(name: &str) -> Option<&'static Category> {
    CATEGORIES.iter().find(|c| c.dir == name)
}

/// `TEMPLATES_DIR / parts[0] / parts[1] / …`, resolved as `stat` would.
/// `None`: nothing there (or outside the templates' directory).
pub fn resolve(parts: &[&str]) -> Option<Node> {
    let mut node = Node::Root;
    for part in parts {
        // `PurePath` joins: an absolute part replaces everything before it.
        if part.starts_with('/') {
            return None;
        }
        // A NUL makes `os.stat` raise `ValueError`, which `is_file()` and
        // `is_dir()` answer as `False`.
        if part.contains('\0') {
            return None;
        }
        for name in part.split('/') {
            if name.is_empty() || name == "." {
                continue;
            }
            node = match (node, name) {
                (Node::Root, "..") => Node::Parent,
                (Node::Parent, "..") => return None,
                (Node::Dir(_), "..") => Node::Root,
                (Node::File(..), _) => return None,
                (Node::Root, n) => Node::Dir(category(n)?),
                (Node::Parent, n) if n == TEMPLATES_DIR_NAME => Node::Root,
                (Node::Parent, _) => return None,
                (Node::Dir(c), n) => {
                    let (name, text) = c.files.iter().find(|(f, _)| *f == n)?;
                    Node::File(name, text)
                }
            };
        }
    }
    Some(node)
}

/// The `*.json` templates of a category (`sorted(category_dir.glob("*.json"))`
/// without the names starting with `_`), as `(stem, contents)`.
pub fn templates_of(c: &'static Category) -> Vec<(&'static str, &'static str)> {
    c.files
        .iter()
        .filter(|(name, _)| !name.starts_with('_') && name.ends_with(".json"))
        .map(|(name, text)| (name.trim_end_matches(".json"), *text))
        .collect()
}

/// A category's `_card.json`.
pub fn card_of(c: &'static Category) -> Option<&'static str> {
    c.files
        .iter()
        .find(|(name, _)| *name == "_card.json")
        .map(|(_, text)| *text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn backend_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../backend/app/siem/dashboard_templates")
    }

    /// Every compiled-in file is the backend's, byte for byte, and the
    /// backend has no file this crate lacks.
    #[test]
    fn copies_match_the_backend_templates() {
        let root = backend_dir();
        let mut dirs: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "__pycache__")
            .collect();
        dirs.sort();
        let ours: Vec<&str> = CATEGORIES.iter().map(|c| c.dir).collect();
        assert_eq!(dirs, ours, "the backend's category directories differ");
        for c in CATEGORIES {
            let mut files: Vec<String> = std::fs::read_dir(root.join(c.dir))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            files.sort();
            let names: Vec<&str> = c.files.iter().map(|(n, _)| *n).collect();
            assert_eq!(files, names, "{} lists different files", c.dir);
            for (name, text) in c.files {
                let theirs = std::fs::read_to_string(root.join(c.dir).join(name)).unwrap();
                assert!(
                    theirs == *text,
                    "{}/{name} differs from the backend's",
                    c.dir
                );
            }
        }
    }

    #[test]
    fn paths_resolve_as_the_filesystem_does() {
        let file = |parts: &[&str]| resolve(parts).and_then(Node::file).is_some();
        assert!(file(&["wazuh_edr", "_card.json"]));
        assert!(file(&["wazuh_edr", "EDR_OVERVIEW.json"]));
        assert!(file(&["wazuh_edr/../wazuh_edr", "EDR_OVERVIEW.json"]));
        assert!(file(&[
            "wazuh_edr",
            "../office365_cloudintegration/O365_DLP.json"
        ]));
        assert!(file(&["../dashboard_templates/wazuh_edr", "_card.json"]));
        assert!(file(&["./wazuh_edr//", "_card.json"]));
        assert!(!file(&["wazuh_edr", "_card.json/.."]));
        assert!(!file(&["nope/../wazuh_edr", "_card.json"]));
        assert!(!file(&["/etc", "_card.json"]));
        assert!(!file(&["", "_card.json"]));
        assert!(!file(&["..", "_card.json"]));
        assert!(!file(&["../..", "x"]));
        assert!(!file(&["wazuh_edr", "EDR_OVERVIEW\0.json"]));
        assert!(resolve(&["."]).is_some_and(Node::is_dir));
        assert!(resolve(&["wazuh_edr"]).is_some_and(Node::is_dir));
    }

    #[test]
    fn every_template_parses() {
        for c in CATEGORIES {
            assert!(card_of(c).is_some(), "{}", c.dir);
            for (stem, text) in templates_of(c) {
                let v = copilot_auth::pyvalue::loads(text).unwrap();
                assert!(v.get("panels").is_some(), "{}/{stem}", c.dir);
            }
        }
    }
}
