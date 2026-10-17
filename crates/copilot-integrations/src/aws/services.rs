//! `app/integrations/aws/utils/services.py`: the AWS services CoPilot
//! provisions and the pure helpers built on that table — `SERVICES` parsed,
//! the S3 prefix a service's logs live under, Wazuh's `only_logs_after`
//! date, and the `service:id` pairs the metadata row stores per service.

use chrono::{Datelike, NaiveDate, Utc};

/// One entry of `AWS_SERVICES` (`AwsServiceDefinition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceDefinition {
    /// `key`: the value in `SERVICES`, `data_aws_source` and the index
    /// prefix.
    pub key: &'static str,
    /// `title`: the Graylog and Grafana titles' name.
    pub title: &'static str,
    /// `wazuh_type`: `<bucket type="…">`.
    pub wazuh_type: &'static str,
    /// `log_dir`: the directory under `AWSLogs/<account>/`.
    pub log_dir: &'static str,
    /// `account_field`: the Graylog field naming the account.
    pub account_field: &'static str,
    /// `timestamp_field`: the Graylog field holding the event's time.
    pub timestamp_field: &'static str,
    /// `supports_organization_id`.
    pub supports_organization_id: bool,
}

/// `AWS_SERVICES`, in the dict's order.
pub const AWS_SERVICES: &[ServiceDefinition] = &[
    ServiceDefinition {
        key: "cloudtrail",
        title: "CloudTrail",
        wazuh_type: "cloudtrail",
        log_dir: "CloudTrail",
        account_field: "data_aws_aws_account_id",
        timestamp_field: "data_aws_eventTime",
        supports_organization_id: true,
    },
    ServiceDefinition {
        key: "guardduty",
        title: "GuardDuty",
        wazuh_type: "guardduty",
        log_dir: "GuardDuty",
        account_field: "data_aws_accountId",
        timestamp_field: "data_aws_updatedAt",
        supports_organization_id: false,
    },
];

/// `KNOWN_UNSUPPORTED_SERVICES`.
pub const KNOWN_UNSUPPORTED_SERVICES: &[&str] = &[
    "vpcflow",
    "alb",
    "clb",
    "nlb",
    "server_access",
    "config",
    "waf",
];

/// `AWS_SERVICES[key]`.
pub fn definition(key: &str) -> Option<&'static ServiceDefinition> {
    AWS_SERVICES.iter().find(|d| d.key == key)
}

/// One entry of `SERVICES` (`AwsServiceConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// `definition`.
    pub definition: &'static ServiceDefinition,
    /// `prefix`: the S3 key prefix the service exports under.
    pub prefix: Option<String>,
}

impl ServiceConfig {
    /// `key`.
    pub fn key(&self) -> &'static str {
        self.definition.key
    }
}

fn supported() -> String {
    AWS_SERVICES
        .iter()
        .map(|d| d.key)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `str.strip(chars)` for one character.
fn strip_char(s: &str, c: char) -> &str {
    s.trim_matches(c)
}

/// `_PREFIX_PATTERN.match(prefix)` (`^[A-Za-z0-9!_.*'()/-]+$`, whose `$`
/// also matches before a final newline).
fn prefix_matches(prefix: &str) -> bool {
    let body = prefix.strip_suffix('\n').unwrap_or(prefix);
    !body.is_empty()
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!_.*'()/-".contains(c))
}

/// `parse_services(raw)`; `Err` is the `ValueError`'s text.
pub fn parse_services(raw: &str) -> Result<Vec<ServiceConfig>, String> {
    let empty = || format!("SERVICES is empty. Supported services: {}.", supported());
    if raw.is_empty() || crate::etree::py_strip(raw).is_empty() {
        return Err(empty());
    }
    let mut configs: Vec<ServiceConfig> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for entry in raw.split(',') {
        let entry = crate::etree::py_strip(entry);
        if entry.is_empty() {
            continue;
        }
        let (service, prefix) = match entry.split_once(':') {
            Some((s, p)) => (s, p),
            None => (entry, ""),
        };
        let service = crate::etree::py_strip(service).to_lowercase();
        let prefix = strip_char(crate::etree::py_strip(prefix), '/');
        let prefix = (!prefix.is_empty()).then(|| prefix.to_string());
        let Some(definition) = definition(&service) else {
            let hint = if KNOWN_UNSUPPORTED_SERVICES.contains(&service.as_str()) {
                " It is not supported yet."
            } else {
                ""
            };
            return Err(format!(
                "Unknown AWS service '{service}' in SERVICES.{hint} Supported services: {}.",
                supported()
            ));
        };
        if seen.contains(&service) {
            return Err(format!(
                "AWS service '{service}' is listed more than once in SERVICES."
            ));
        }
        if let Some(p) = &prefix {
            if !prefix_matches(p) {
                return Err(format!(
                    "The S3 prefix '{p}' for {service} contains characters S3 key prefixes do \
                     not use."
                ));
            }
        }
        seen.push(service);
        configs.push(ServiceConfig { definition, prefix });
    }
    if configs.is_empty() {
        return Err(empty());
    }
    Ok(configs)
}

/// `s3_log_prefix(config, account_id, organization_id)`:
/// `[<prefix>/]AWSLogs/[<org-id>/]<account>/<LogDir>/`.
pub fn s3_log_prefix(
    config: &ServiceConfig,
    account_id: &str,
    organization_id: Option<&str>,
) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(p) = config.prefix.as_deref().filter(|p| !p.is_empty()) {
        parts.push(p);
    }
    parts.push("AWSLogs");
    if let Some(org) = organization_id.filter(|o| !o.is_empty()) {
        if config.definition.supports_organization_id {
            parts.push(org);
        }
    }
    parts.push(account_id);
    parts.push(config.definition.log_dir);
    format!("{}/", parts.join("/"))
}

const MONTHS: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];

/// `wazuh_date(value)`: `YYYY-MMM-DD` with an English month abbreviation.
pub fn wazuh_date(value: NaiveDate) -> String {
    let month = usize::try_from(value.month0()).unwrap_or(0);
    format!(
        "{:04}-{}-{:02}",
        value.year(),
        MONTHS.get(month).copied().unwrap_or("JAN"),
        value.day()
    )
}

/// `default_only_logs_after()`: today in UTC.
pub fn default_only_logs_after() -> String {
    wazuh_date(Utc::now().date_naive())
}

/// CPython's `int()` of a run of Unicode decimal digits (`\d`).
fn digits_value(digits: &[char]) -> i64 {
    digits.iter().fold(0i64, |acc, c| {
        acc * 10 + i64::from(copilot_jinja::unicode::decimal_value(*c).unwrap_or(0))
    })
}

fn is_digit(c: char) -> bool {
    copilot_jinja::unicode::decimal_value(c).is_some()
}

/// `normalize_only_logs_after(value)`: the date upper-cased; `Err` is the
/// `ValueError`'s text.
pub fn normalize_only_logs_after(value: &str) -> Result<String, String> {
    let malformed =
        || format!("ONLY_LOGS_AFTER must look like 2026-OCT-08 (YYYY-MMM-DD), got '{value}'.");
    // `^(\d{4})-([A-Za-z]{3})-(\d{2})$` on `value.strip()` (stripped, so `$`
    // has no final newline to skip).
    let chars: Vec<char> = crate::etree::py_strip(value).chars().collect();
    if chars.len() != 4 + 1 + 3 + 1 + 2 {
        return Err(malformed());
    }
    let (year, rest) = chars.split_at(4);
    let (dash1, rest) = rest.split_at(1);
    let (month, rest) = rest.split_at(3);
    let (dash2, day) = rest.split_at(1);
    if !year.iter().all(|c| is_digit(*c))
        || dash1 != ['-']
        || !month.iter().all(char::is_ascii_alphabetic)
        || dash2 != ['-']
        || !day.iter().all(|c| is_digit(*c))
    {
        return Err(malformed());
    }
    let month_text: String = month.iter().collect::<String>().to_ascii_uppercase();
    let Some(index) = MONTHS.iter().position(|m| *m == month_text) else {
        return Err(malformed());
    };
    let (y, d) = (digits_value(year), digits_value(day));
    let real = i32::try_from(y)
        .ok()
        .filter(|y| (1..=9999).contains(y))
        .and_then(|y| {
            NaiveDate::from_ymd_opt(
                y,
                u32::try_from(index + 1).unwrap_or(1),
                u32::try_from(d).unwrap_or(0),
            )
        });
    if real.is_none() {
        return Err(format!("ONLY_LOGS_AFTER '{value}' is not a real date."));
    }
    Ok(format!(
        "{}-{month_text}-{}",
        year.iter().collect::<String>(),
        day.iter().collect::<String>()
    ))
}

/// `encode_service_ids(ids)`: `service:id` pairs, sorted by service, empty
/// ids left out.
pub fn encode_service_ids(ids: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = ids.iter().filter(|(_, v)| !v.is_empty()).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .iter()
        .map(|(s, v)| format!("{s}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `decode_service_ids(value)`: the pairs as a dict (a repeated service
/// keeps its first place and its last id).
pub fn decode_service_ids(value: Option<&str>) -> Vec<(String, String)> {
    let mut ids: Vec<(String, String)> = Vec::new();
    for entry in value.unwrap_or_default().split(',') {
        let entry = crate::etree::py_strip(entry);
        let Some((service, identifier)) = entry.split_once(':') else {
            continue;
        };
        if service.is_empty() || identifier.is_empty() {
            continue;
        }
        match ids.iter_mut().find(|(s, _)| s == service) {
            Some(slot) => slot.1 = identifier.to_string(),
            None => ids.push((service.to_string(), identifier.to_string())),
        }
    }
    ids
}

/// `dict.get(key)` on decoded pairs.
pub fn lookup<'a>(ids: &'a [(String, String)], key: &str) -> Option<&'a str> {
    ids.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}
