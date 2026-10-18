//! The EDR agent install commands — port of
//! `app/customer_provisioning/services/edr_install.py`: three templates and
//! one ordered `str.replace` per token (a value carrying a later token is
//! replaced again, as in Python).

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_upstream::py::{PyExc, PyResult};

use super::store;

/// `LINUX_INSTALLER_FILENAME`.
pub const LINUX_INSTALLER: &str = "Client_EDR_install.bash";
/// `MACOS_INSTALLER_FILENAME`.
pub const MACOS_INSTALLER: &str = "macOS_kickstart.sh";

/// `WINDOWS_TEMPLATE`.
pub const WINDOWS_TEMPLATE: &str = concat!(
    "$user = '__REPO_USERNAME__'; $pass = '__REPO_PASSWORD__'; ",
    "$pair = \"$($user):$($pass)\"; ",
    "$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair)); ",
    "$basicAuthValue = \"Basic $encodedCreds\"; ",
    "$Headers = @{ Authorization = $basicAuthValue }; ",
    "Invoke-RestMethod -Uri '__REPO_URL__/repository/__REPO_USERNAME__/prod/__WINDOWS_INSTALLER__' ",
    "-Headers $Headers -OutFile \"$env:TMP\\__WINDOWS_INSTALLER__\"; ",
    "Start-Process -FilePath \"$env:TMP\\__WINDOWS_INSTALLER__\" ",
    "-ArgumentList '/q WAZUHMANAGER=\"__WAZUH_DOMAIN__\" WAZUHPASSWORD=\"__REGISTRATION_PASSWORD__\" ",
    "CUSTOMERCODE=\"Windows___CUSTOMER_CODE__\" WAZUHREGISTRATIONPORT=\"__REGISTRATION_PORT__\" ",
    "WAZUHMANAGERPORT=\"__LOGS_PORT__\"';",
);

/// `LINUX_TEMPLATE`.
pub const LINUX_TEMPLATE: &str = concat!(
    "if command -v apt >/dev/null 2>&1; then apt update && apt install -y sudo dos2unix; ",
    "elif command -v yum >/dev/null 2>&1; then sudo yum install -y dos2unix; ",
    "else echo \"Error: Neither apt nor yum package manager found.\"; exit 1; fi; ",
    "curl -u __REPO_USERNAME__:__REPO_PASSWORD__ -so ~/__LINUX_INSTALLER__ ",
    "__REPO_URL__/repository/__REPO_USERNAME__/installer/__LINUX_INSTALLER__ && ",
    "dos2unix ~/__LINUX_INSTALLER__ && ",
    "CLIENT_USER=__REPO_USERNAME__ CLIENT_PASS=__REPO_PASSWORD__ bash ~/__LINUX_INSTALLER__ ",
    "-i __WAZUH_DOMAIN__ __LOGS_PORT__ __REGISTRATION_PORT__ __REGISTRATION_PASSWORD__ Linux___CUSTOMER_CODE__",
);

/// `MACOS_TEMPLATE`.
pub const MACOS_TEMPLATE: &str = concat!(
    "curl -fsSL -u '__REPO_USERNAME__:__REPO_PASSWORD__' ",
    "'__REPO_URL__/repository/__REPO_USERNAME__/installer/__MACOS_INSTALLER__' | sudo bash -s -- --no-stagger",
);

/// The three commands for `values` (token → value, in Python's order).
pub fn render(values: &[(&str, String)]) -> (String, String, String) {
    let (mut windows, mut linux, mut macos) = (
        WINDOWS_TEMPLATE.to_string(),
        LINUX_TEMPLATE.to_string(),
        MACOS_TEMPLATE.to_string(),
    );
    for (token, value) in values {
        windows = windows.replace(token, value);
        linux = linux.replace(token, value);
        macos = macos.replace(token, value);
    }
    (windows, linux, macos)
}

fn blank(v: &Option<String>) -> bool {
    v.as_deref().is_none_or(str::is_empty)
}

/// `generate_edr_install_commands(code)`: the `EDRInstallCommands` dump.
pub async fn commands(pool: &Db, code: &str) -> PyResult<PyValue> {
    if !store::customer_exists(pool, code).await? {
        return Err(PyExc::http(
            404,
            format!("Customer: {code} not found. Please create the customer first."),
        ));
    }
    let settings = store::first_settings(pool).await?.ok_or_else(|| {
        PyExc::http(
            404,
            "No customer provisioning default settings found. Configure the EDR repo settings \
             first.",
        )
    })?;
    let meta = store::meta_by_code(pool, code).await?.ok_or_else(|| {
        PyExc::http(
            404,
            format!(
                "Customer meta not found for customer: {code}. Please provision the customer \
                 first."
            ),
        )
    })?;
    let values = EdrValues {
        repo_url: settings.repo_url,
        repo_username: settings.repo_username,
        repo_password: settings.repo_password,
        windows_edr_installer: settings.windows_edr_installer,
        wazuh_domain: settings.wazuh_domain,
        registration_port: meta.customer_meta_wazuh_registration_port,
        logs_port: meta.customer_meta_wazuh_log_ingestion_port,
        registration_password: meta.customer_meta_wazuh_auth_password,
    };
    build(&values, code)
}

/// What the commands are made of: the default settings' EDR repo fields and
/// the customer's enrollment values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdrValues {
    /// `repo_url`.
    pub repo_url: Option<String>,
    /// `repo_username`.
    pub repo_username: Option<String>,
    /// `repo_password`.
    pub repo_password: Option<String>,
    /// `windows_edr_installer`.
    pub windows_edr_installer: Option<String>,
    /// `wazuh_domain`.
    pub wazuh_domain: Option<String>,
    /// `customer_meta_wazuh_registration_port`.
    pub registration_port: Option<String>,
    /// `customer_meta_wazuh_log_ingestion_port`.
    pub logs_port: Option<String>,
    /// `customer_meta_wazuh_auth_password`.
    pub registration_password: Option<String>,
}

/// `_require(...)`, then the three commands (`EDRInstallCommands`' dump).
pub fn build(v: &EdrValues, code: &str) -> PyResult<PyValue> {
    let required = [
        ("repo_url", &v.repo_url),
        ("repo_username", &v.repo_username),
        ("repo_password", &v.repo_password),
        ("windows_edr_installer", &v.windows_edr_installer),
        ("wazuh_domain", &v.wazuh_domain),
        (
            "customer_meta_wazuh_registration_port",
            &v.registration_port,
        ),
        ("customer_meta_wazuh_log_ingestion_port", &v.logs_port),
        (
            "customer_meta_wazuh_auth_password",
            &v.registration_password,
        ),
    ];
    let missing: Vec<&str> = required
        .iter()
        .filter(|(_, v)| blank(v))
        .map(|(n, _)| *n)
        .collect();
    if !missing.is_empty() {
        return Err(PyExc::http(
            400,
            format!(
                "Cannot generate EDR install commands; missing required value(s): {}.",
                missing.join(", ")
            ),
        ));
    }
    let get = |v: &Option<String>| v.clone().unwrap_or_default();
    let values = [
        (
            "__REPO_URL__",
            get(&v.repo_url).trim_end_matches('/').to_string(),
        ),
        ("__REPO_USERNAME__", get(&v.repo_username)),
        ("__REPO_PASSWORD__", get(&v.repo_password)),
        ("__WINDOWS_INSTALLER__", get(&v.windows_edr_installer)),
        ("__LINUX_INSTALLER__", LINUX_INSTALLER.to_string()),
        ("__MACOS_INSTALLER__", MACOS_INSTALLER.to_string()),
        ("__WAZUH_DOMAIN__", get(&v.wazuh_domain)),
        ("__REGISTRATION_PASSWORD__", get(&v.registration_password)),
        ("__REGISTRATION_PORT__", get(&v.registration_port)),
        ("__LOGS_PORT__", get(&v.logs_port)),
        ("__CUSTOMER_CODE__", code.to_string()),
    ];
    let (windows, linux, macos) = render(&values);
    Ok(PyValue::Dict(vec![
        ("windows".into(), PyValue::Str(windows)),
        ("linux".into(), PyValue::Str(linux)),
        ("macos".into(), PyValue::Str(macos)),
    ]))
}
