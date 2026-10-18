//! `app/integrations/aws/schema/provision.py`: the request, the auth keys
//! (`ProvisionAwsAuthKeys`, validated as the route's `parse_aws_auth_keys`
//! reports it) and the answer.

use copilot_auth::pyvalue::PyValue;
use copilot_integrations::aws::config::BucketKeys;
use copilot_integrations::aws::services::{
    ServiceConfig, default_only_logs_after, normalize_only_logs_after, parse_services,
};
use copilot_integrations::etree::py_strip;
use copilot_upstream::model::{Field, Model, Ty, kwargs};

/// `AWS_INTEGRATION_NAME`.
pub const AWS_INTEGRATION_NAME: &str = "AWS";

fn aws() -> PyValue {
    PyValue::Str(AWS_INTEGRATION_NAME.into())
}

/// `ProvisionAwsRequest` (its `integration_name` forced by the
/// `mode="before"` validator).
pub static PROVISION_AWS_REQUEST: Model = Model::new(
    "ProvisionAwsRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, aws),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
    ],
);

/// `PipelineRuleTitles.AWS_SYSLOG_TYPE`.
pub const AWS_SYSLOG_TYPE: &str = "SYSLOG TYPE AWS";
/// `PipelineRuleTitles.AWS_TIMESTAMP`.
pub const AWS_TIMESTAMP: &str = "AWS Timestamp - UTC";
/// `PipelineRuleTitles.AWS_ACCOUNT_ID`.
pub const AWS_ACCOUNT_ID: &str = "AWS ACCOUNT ID";
/// `PipelineTitles.AWS`.
pub const PIPELINE_TITLE: &str = "AWS PROCESSING PIPELINE";

/// `PipelineRuleTitles`, in declaration order.
pub const PIPELINE_RULE_TITLES: [&str; 7] = [
    crate::graylog::WAZUH_INFO,
    crate::graylog::WAZUH_WARNING,
    crate::graylog::WAZUH_NOTICE,
    crate::graylog::WAZUH_ALERT,
    AWS_SYSLOG_TYPE,
    AWS_TIMESTAMP,
    AWS_ACCOUNT_ID,
];

/// A validated `ProvisionAwsAuthKeys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKeys {
    /// `ACCESS_KEY_ID`.
    pub access_key_id: String,
    /// `SECRET_ACCESS_KEY` (`get_secret_value()`).
    pub secret_access_key: String,
    /// `AWS_ACCOUNT_ID`.
    pub account_id: String,
    /// `AWS_ACCOUNT_ALIAS`.
    pub account_alias: Option<String>,
    /// `AWS_ORGANIZATION_ID`.
    pub organization_id: Option<String>,
    /// `BUCKET_NAME`.
    pub bucket_name: String,
    /// `SERVICES`.
    pub services: String,
    /// `ONLY_LOGS_AFTER` (normalized).
    pub only_logs_after: Option<String>,
}

impl AuthKeys {
    /// `service_configs()` (the field validator already parsed them).
    pub fn service_configs(&self) -> Vec<ServiceConfig> {
        parse_services(&self.services).unwrap_or_default()
    }

    /// `only_logs_after()`: the key, or today.
    pub fn only_logs_after(&self) -> String {
        self.only_logs_after
            .clone()
            .unwrap_or_else(default_only_logs_after)
    }

    /// The fields the `<bucket>` entries are built from.
    pub fn bucket_keys(&self) -> BucketKeys {
        BucketKeys {
            bucket_name: self.bucket_name.clone(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            account_id: self.account_id.clone(),
            account_alias: self.account_alias.clone(),
            organization_id: self.organization_id.clone(),
        }
    }
}

/// `re.fullmatch(r"[A-Z0-9]{16,128}", value)`.
fn access_key_matches(v: &str) -> bool {
    (16..=128).contains(&v.chars().count())
        && v.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// `re.fullmatch(r"\d{12}", value)` (`\d`: any Unicode decimal digit).
fn account_matches(v: &str) -> bool {
    v.chars().count() == 12
        && v.chars()
            .all(|c| copilot_jinja::unicode::decimal_value(c).is_some())
}

/// `re.fullmatch(r"o-[a-z0-9]{10,32}", value)`.
fn organization_matches(v: &str) -> bool {
    v.strip_prefix("o-").is_some_and(|rest| {
        (10..=32).contains(&rest.chars().count())
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

/// `re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value)`.
fn bucket_matches(v: &str) -> bool {
    let chars: Vec<char> = v.chars().collect();
    let edge = |c: &char| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=63).contains(&chars.len())
        && chars.first().is_some_and(edge)
        && chars.last().is_some_and(edge)
        && chars[1..chars.len() - 1]
            .iter()
            .all(|c| edge(c) || *c == '.' || *c == '-')
}

/// `re.fullmatch(r"[A-Za-z0-9._-]{1,63}", value)`.
fn alias_matches(v: &str) -> bool {
    (1..=63).contains(&v.chars().count())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

type Check = fn(&str) -> Result<String, String>;

/// One field: absent, `None` (blank) or a value its validator accepted.
fn field_value(
    name: &str,
    value: Option<Option<String>>,
    required: bool,
    check: Check,
    problems: &mut Vec<String>,
) -> Option<String> {
    match value {
        None if required => {
            problems.push(format!("{name}: Field required"));
            None
        }
        Some(None) if required => {
            problems.push(format!("{name}: Input should be a valid string"));
            None
        }
        None | Some(None) => None,
        Some(Some(v)) => match check(&v) {
            Ok(v) => Some(v),
            Err(m) => {
                problems.push(format!("{name}: Value error, {m}"));
                None
            }
        },
    }
}

fn check_access_key(v: &str) -> Result<String, String> {
    if access_key_matches(v) {
        Ok(v.to_string())
    } else {
        Err("ACCESS_KEY_ID does not look like an AWS access key ID (e.g. AKIA…).".into())
    }
}

fn check_any(v: &str) -> Result<String, String> {
    Ok(v.to_string())
}

fn check_account(v: &str) -> Result<String, String> {
    if account_matches(v) {
        Ok(v.to_string())
    } else {
        Err("AWS_ACCOUNT_ID must be the 12-digit AWS account ID.".into())
    }
}

fn check_alias(v: &str) -> Result<String, String> {
    if alias_matches(v) {
        Ok(v.to_string())
    } else {
        Err("AWS_ACCOUNT_ALIAS may only contain letters, digits, '.', '_' and '-'.".into())
    }
}

fn check_organization(v: &str) -> Result<String, String> {
    if organization_matches(v) {
        Ok(v.to_string())
    } else {
        Err("AWS_ORGANIZATION_ID must look like o-a1b2c3d4e5.".into())
    }
}

fn check_bucket(v: &str) -> Result<String, String> {
    if bucket_matches(v) {
        Ok(v.to_string())
    } else {
        Err("BUCKET_NAME is not a valid S3 bucket name.".into())
    }
}

fn check_services(v: &str) -> Result<String, String> {
    parse_services(v).map(|_| v.to_string())
}

/// `parse_aws_auth_keys(auth_keys)`: `ProvisionAwsAuthKeys(**auth_keys)`
/// after `blank_means_unset` (each value stripped, an empty one `None`);
/// `Err` is the 400's detail, naming each bad field in declaration order.
pub fn parse_auth_keys(keys: &[(String, Option<String>)]) -> Result<AuthKeys, String> {
    // The dict `extract_aws_auth_keys` built: a repeated name keeps its last
    // value.
    let value = |name: &str| -> Option<Option<String>> {
        keys.iter().rev().find(|(k, _)| k == name).map(|(_, v)| {
            v.as_deref()
                .map(py_strip)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
    };
    let mut problems: Vec<String> = Vec::new();
    let p = &mut problems;
    let access_key_id = field_value(
        "ACCESS_KEY_ID",
        value("ACCESS_KEY_ID"),
        true,
        check_access_key,
        p,
    );
    let secret_access_key = field_value(
        "SECRET_ACCESS_KEY",
        value("SECRET_ACCESS_KEY"),
        true,
        check_any,
        p,
    );
    let account_id = field_value(
        "AWS_ACCOUNT_ID",
        value("AWS_ACCOUNT_ID"),
        true,
        check_account,
        p,
    );
    let account_alias = field_value(
        "AWS_ACCOUNT_ALIAS",
        value("AWS_ACCOUNT_ALIAS"),
        false,
        check_alias,
        p,
    );
    let organization_id = field_value(
        "AWS_ORGANIZATION_ID",
        value("AWS_ORGANIZATION_ID"),
        false,
        check_organization,
        p,
    );
    let bucket_name = field_value("BUCKET_NAME", value("BUCKET_NAME"), true, check_bucket, p);
    let services = field_value("SERVICES", value("SERVICES"), true, check_services, p);
    let only_logs_after = field_value(
        "ONLY_LOGS_AFTER",
        value("ONLY_LOGS_AFTER"),
        false,
        normalize_only_logs_after,
        p,
    );
    match (
        access_key_id,
        secret_access_key,
        account_id,
        bucket_name,
        services,
    ) {
        (Some(access_key_id), Some(secret_access_key), Some(account_id), Some(bucket), Some(s))
            if problems.is_empty() =>
        {
            Ok(AuthKeys {
                access_key_id,
                secret_access_key,
                account_id,
                account_alias,
                organization_id,
                bucket_name: bucket,
                services: s,
                only_logs_after,
            })
        }
        _ => Err(format!(
            "The AWS integration's auth keys are not valid: {}",
            problems.join("; ")
        )),
    }
}

/// `aws_config_notice(detected, region)`'s dump.
pub fn aws_config_notice(detected: bool, region: Option<&str>) -> PyValue {
    let region = region.filter(|r| !r.is_empty()).unwrap_or("us-east-1");
    let summary = if detected {
        "Action required: the Wazuh manager's aws-s3 module stopped with exit code 23 because \
         /root/.aws/config exists but has no [default] section. No AWS logs are collected until it \
         is fixed. CoPilot cannot edit that file through the Wazuh API, so add the section below by \
         hand."
    } else {
        "CoPilot cannot read or write /root/.aws/config on the Wazuh master — the Wazuh API only \
         edits ossec.conf. If that file exists, it must contain a [default] section, or the aws-s3 \
         module exits with code 23 and collects nothing. If the file does not exist, nothing needs \
         doing."
    };
    let steps = [
        "Log in to the Wazuh master node (the manager CoPilot's Wazuh Manager connector points at).",
        "Check whether the file exists: sudo ls -l /root/.aws/config",
        "If it exists and has no [default] section, append the section below, leaving any existing \
         [profile …] sections as they are: sudo vi /root/.aws/config",
        "Restart the manager so the module retries straight away: sudo systemctl restart \
         wazuh-manager",
        "Confirm in /var/ossec/logs/ossec.log that wazuh-modulesd:aws-s3 no longer reports 'No \
         profile named'.",
    ];
    kwargs(vec![
        ("detected", PyValue::Bool(detected)),
        ("file_path", PyValue::Str("/root/.aws/config".into())),
        ("summary", PyValue::Str(summary.into())),
        (
            "steps",
            PyValue::List(steps.iter().map(|s| PyValue::Str((*s).into())).collect()),
        ),
        (
            "contents",
            PyValue::Str(format!("[default]\nregion = {region}\n")),
        ),
    ])
}

/// `ProvisionAwsResponse(...)`'s dump.
pub fn response(message: String, warnings: &[String], notice: PyValue) -> PyValue {
    kwargs(vec![
        ("success", PyValue::Bool(true)),
        ("message", PyValue::Str(message)),
        (
            "warnings",
            PyValue::List(warnings.iter().map(|w| PyValue::Str(w.clone())).collect()),
        ),
        ("aws_config", notice),
    ])
}
