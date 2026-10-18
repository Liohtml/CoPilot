//! `app/agents/sca/models/sca_package_registry.py`: the application
//! categories the SCA policies target, and the package names that show an
//! agent runs one.

/// One `ScaPackageEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The registry key.
    pub key: &'static str,
    /// `display_name`.
    pub display_name: &'static str,
    /// `sca_application` (the CoPilot-SCA index's `application`).
    pub sca_application: &'static str,
    /// `package_patterns` (wildcards on both sides, case-insensitive).
    pub package_patterns: &'static [&'static str],
}

/// `SCA_PACKAGE_REGISTRY`, in its declaration order.
pub const REGISTRY: &[Entry] = &[
    Entry {
        key: "apache",
        display_name: "Apache HTTP Server",
        sca_application: "apache",
        package_patterns: &["apache2", "httpd", "apache2-bin", "apache2-utils"],
    },
    Entry {
        key: "nginx",
        display_name: "NGINX",
        sca_application: "nginx",
        package_patterns: &["nginx", "nginx-common", "nginx-core", "nginx-full"],
    },
    Entry {
        key: "iis",
        display_name: "Microsoft IIS",
        sca_application: "iis",
        package_patterns: &["iis", "w3svc"],
    },
    Entry {
        key: "mysql",
        display_name: "MySQL / MariaDB",
        sca_application: "mysql",
        package_patterns: &[
            "mysql-server",
            "mysql-community-server",
            "mysql-common",
            "mariadb-server",
            "mariadb-common",
        ],
    },
    Entry {
        key: "postgresql",
        display_name: "PostgreSQL",
        sca_application: "postgresql",
        package_patterns: &["postgresql", "postgresql-common", "postgresql-client"],
    },
    Entry {
        key: "sqlserver",
        display_name: "Microsoft SQL Server",
        sca_application: "sqlserver",
        package_patterns: &["mssql-server", "mssql-tools"],
    },
];

/// `SCA_PACKAGE_REGISTRY.get(key)`.
pub fn get(key: &str) -> Option<&'static Entry> {
    REGISTRY.iter().find(|e| e.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is the Python module's, entry for entry.
    #[test]
    fn registry_matches_the_python_module() {
        let src = include_str!("../../../../backend/app/agents/sca/models/sca_package_registry.py");
        let body = &src[src.find("SCA_PACKAGE_REGISTRY: Dict").expect("registry")..];
        for e in REGISTRY {
            let at = body
                .find(&format!("\"{}\": ScaPackageEntry(", e.key))
                .unwrap_or_else(|| panic!("{} missing", e.key));
            let entry = &body[at..];
            let end = entry.find("\n    ),").expect("entry end");
            let entry = &entry[..end];
            assert!(entry.contains(&format!("display_name=\"{}\"", e.display_name)));
            assert!(entry.contains(&format!("sca_application=\"{}\"", e.sca_application)));
            let patterns: Vec<&str> = entry
                .split("package_patterns=[")
                .nth(1)
                .expect("patterns")
                .split(']')
                .next()
                .expect("list")
                .split(',')
                .map(|p| p.trim().trim_matches('"'))
                .filter(|p| !p.is_empty())
                .collect();
            assert_eq!(patterns, e.package_patterns, "{}", e.key);
        }
        assert_eq!(body.matches("ScaPackageEntry(").count(), REGISTRY.len());
    }
}
