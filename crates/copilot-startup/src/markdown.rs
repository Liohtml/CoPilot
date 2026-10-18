//! The deployment instructions `available_integrations.integration_details`
//! and `available_network_connectors.network_connector_details` hold.
//!
//! Python reads them from `app/integrations/markdown/` and
//! `app/network_connectors/markdown/` relative to its working directory
//! (`load_markdown_for_*`: the name lower-cased, its spaces made `_`). They
//! are compiled in here: `crates/copilot-startup/markdown/` holds copies of
//! the files the catalogs name, and a test fails when one differs from the
//! backend's — edit both.

/// The file stem `load_markdown_for_*` opens for `name`.
pub fn file_stem(name: &str) -> String {
    name.replace(' ', "_").to_lowercase()
}

const INTEGRATIONS: &[(&str, &str)] = &[
    ("aws", include_str!("../markdown/integrations/aws.md")),
    (
        "bitdefender",
        include_str!("../markdown/integrations/bitdefender.md"),
    ),
    (
        "carbonblack",
        include_str!("../markdown/integrations/carbonblack.md"),
    ),
    ("cato", include_str!("../markdown/integrations/cato.md")),
    (
        "crowdstrike",
        include_str!("../markdown/integrations/crowdstrike.md"),
    ),
    (
        "darktrace",
        include_str!("../markdown/integrations/darktrace.md"),
    ),
    (
        "defenderforendpoint",
        include_str!("../markdown/integrations/defenderforendpoint.md"),
    ),
    ("duo", include_str!("../markdown/integrations/duo.md")),
    (
        "huntress",
        include_str!("../markdown/integrations/huntress.md"),
    ),
    (
        "mimecast",
        include_str!("../markdown/integrations/mimecast.md"),
    ),
    (
        "office365",
        include_str!("../markdown/integrations/office365.md"),
    ),
    (
        "sap_siem",
        include_str!("../markdown/integrations/sap_siem.md"),
    ),
    (
        "socfortress_mdr",
        include_str!("../markdown/integrations/socfortress_mdr.md"),
    ),
];

const NETWORK_CONNECTORS: &[(&str, &str)] = &[
    (
        "fortinet",
        include_str!("../markdown/network_connectors/fortinet.md"),
    ),
    (
        "sentinelone",
        include_str!("../markdown/network_connectors/sentinelone.md"),
    ),
    (
        "sonicwall",
        include_str!("../markdown/network_connectors/sonicwall.md"),
    ),
];

/// `load_markdown_for_integration(name)`, `None` where Python finds no file.
pub fn integration_details(name: &str) -> Option<&'static str> {
    let stem = file_stem(name);
    INTEGRATIONS
        .iter()
        .find(|(s, _)| *s == stem)
        .map(|(_, t)| *t)
}

/// `load_markdown_for_network_connector(name)`.
pub fn network_connector_details(name: &str) -> Option<&'static str> {
    let stem = file_stem(name);
    NETWORK_CONNECTORS
        .iter()
        .find(|(s, _)| *s == stem)
        .map(|(_, t)| *t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_copies_are_the_backend_files() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../backend/app");
        for (dir, table) in [
            ("integrations/markdown", INTEGRATIONS),
            ("network_connectors/markdown", NETWORK_CONNECTORS),
        ] {
            for (stem, text) in table {
                let path = root.join(dir).join(format!("{stem}.md"));
                let backend = std::fs::read_to_string(&path).expect("backend markdown");
                assert_eq!(*text, backend, "{} differs: edit both", path.display());
                // Python opens it in text mode (universal newlines).
                assert!(!text.contains('\r'));
            }
        }
    }
}
