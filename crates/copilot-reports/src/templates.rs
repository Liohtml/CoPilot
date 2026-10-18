//! The report templates, compiled in from the backend's tree (one source
//! until Python is retired; `crates/copilot/Dockerfile` copies the two
//! directories): `backend/app/incidents/templates` (the customer reports and
//! the shared chrome) and `backend/app/soc_management/templates` (the SOC
//! operations report), loaded as the `FileSystemLoader`s (and the
//! `ChoiceLoader`) Python builds over them.

use copilot_jinja::{Autoescape, Directory, Environment};

/// `incidents/templates`, as `TEMPLATE_DIR` names it in messages.
pub const INCIDENT_DIR: &str = "/opt/copilot/backend/app/incidents/templates";
/// `soc_management/templates`.
pub const SOC_DIR: &str = "/opt/copilot/backend/app/soc_management/templates";

/// The incident templates by file name.
pub const INCIDENT_TEMPLATES: [(&str, &str); 7] = [
    (
        "_report_base.html",
        include_str!("../../../backend/app/incidents/templates/_report_base.html"),
    ),
    (
        "_report_macros.html",
        include_str!("../../../backend/app/incidents/templates/_report_macros.html"),
    ),
    (
        "case_report_jinja_template.html",
        include_str!("../../../backend/app/incidents/templates/case_report_jinja_template.html"),
    ),
    (
        "customer_incident_report_analytics.html",
        include_str!(
            "../../../backend/app/incidents/templates/customer_incident_report_analytics.html"
        ),
    ),
    (
        "customer_incident_report_executive.html",
        include_str!(
            "../../../backend/app/incidents/templates/customer_incident_report_executive.html"
        ),
    ),
    (
        "customer_incident_report_operational.html",
        include_str!(
            "../../../backend/app/incidents/templates/customer_incident_report_operational.html"
        ),
    ),
    (
        "customer_incident_report_template.html",
        include_str!(
            "../../../backend/app/incidents/templates/customer_incident_report_template.html"
        ),
    ),
];

/// The SOC operations report.
pub const SOC_TEMPLATES: [(&str, &str); 1] = [(
    "soc_operations_report.html",
    include_str!("../../../backend/app/soc_management/templates/soc_operations_report.html"),
)];

/// The SOCFortress logo of the `socfortress` theme.
pub const SOCFORTRESS_LOGO_SVG: &[u8] =
    include_bytes!("../../../backend/app/incidents/templates/assets/socfortress_logo.svg");

fn directory(path: &str, files: &[(&str, &str)]) -> Directory {
    Directory {
        path: path.to_string(),
        files: files
            .iter()
            .map(|(n, s)| ((*n).to_string(), (*s).to_string()))
            .collect(),
    }
}

/// `SandboxedEnvironment(loader=FileSystemLoader(TEMPLATE_DIR),
/// autoescape=select_autoescape(["html", "htm", "xml"], default=True))`.
pub fn incident_env() -> Environment {
    Environment::new(Autoescape::SelectHtml)
        .with_directory(directory(INCIDENT_DIR, &INCIDENT_TEMPLATES))
}

/// The SOC report's `ChoiceLoader([soc templates, incident templates])`.
pub fn soc_env() -> Environment {
    Environment::new(Autoescape::SelectHtml)
        .with_directory(directory(SOC_DIR, &SOC_TEMPLATES))
        .with_directory(directory(INCIDENT_DIR, &INCIDENT_TEMPLATES))
}
