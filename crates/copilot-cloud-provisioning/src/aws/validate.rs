//! `app/integrations/aws/services/validate.py`: the instance's credentials
//! checked against AWS before anything is provisioned, with the four calls
//! of [`super::boto`]:
//!
//! 1. `sts:GetCallerIdentity` — the key works and is `AWS_ACCOUNT_ID`'s;
//! 2. `s3:HeadBucket` — the bucket exists (its region);
//! 3. `s3:ListObjectsV2` per service — the region prefixes, then the last
//!    three days of each, then the prefix itself;
//! 4. `s3:GetObject` of one recent object, one byte.
//!
//! A network failure is not fatal (a warning, the deployment goes ahead); a
//! credential or permission failure is ([`Failure::Invalid`], Python's
//! `AwsValidationError`). What escapes Python's `try` — a
//! `ResponseParserError`, a `KeyError` or `ValueError` from an odd listing,
//! the `AttributeError` of an error body that is text — escapes here too
//! ([`Failure::Exc`]).

use chrono::{Duration, NaiveDate};
use copilot_integrations::aws::services::{ServiceConfig, s3_log_prefix};
use copilot_upstream::py::PyExc;

use super::boto::{
    BotoError, Client, ClientError, Hooks, ListOutput, Operation, Output, Service, Transport,
};
use super::schema::AuthKeys;

const BAD_CREDENTIAL_CODES: [&str; 5] = [
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "UnrecognizedClientException",
    "InvalidAccessKeyId",
    "AuthFailure",
];
/// `_LIST_PAGE`.
const LIST_PAGE: i64 = 25;
/// `_RECENT_DAYS`.
const RECENT_DAYS: i64 = 3;
const ARCHIVED_STORAGE_CLASSES: [&str; 2] = ["GLACIER", "DEEP_ARCHIVE"];

/// `AwsValidationResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// `validated`.
    pub validated: bool,
    /// `bucket_region`.
    pub bucket_region: Option<String>,
    /// `warnings`.
    pub warnings: Vec<String>,
}

/// How a validation fails.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    /// `AwsValidationError(message)`.
    Invalid(String),
    /// An exception Python's `_validate` does not catch.
    Exc(PyExc),
}

/// Where the calls go and how they are timed.
#[derive(Clone)]
pub struct Env {
    /// The transport.
    pub transport: Transport,
    /// The clock, ids and delays.
    pub hooks: Hooks,
    /// STS's endpoint override.
    pub sts_endpoint: Option<String>,
    /// S3's endpoint override.
    pub s3_endpoint: Option<String>,
}

impl Env {
    /// The network, with botocore's endpoint variables.
    pub fn network(env: &copilot_core::cloud_env::CloudEnv) -> Self {
        Self {
            transport: Transport::Network,
            hooks: Hooks::default(),
            sts_endpoint: super::boto::endpoint_override(Service::Sts, env),
            s3_endpoint: super::boto::endpoint_override(Service::S3, env),
        }
    }
}

/// One step's way out of `_validate`'s `try`.
enum Step {
    Unreachable(String),
    Invalid(String),
    Core(String),
    Exc(PyExc),
}

fn invalid<T>(message: String) -> Result<T, Step> {
    Err(Step::Invalid(message))
}

/// What escapes a call that is not a `ClientError`: `_call`'s
/// `_Unreachable` for a network error, the `BotoCoreError` the outer
/// `except` turns into an `AwsValidationError`, anything else as raised.
fn escape(description: &str, e: BotoError) -> Step {
    match e {
        BotoError::Network(_, text) => Step::Unreachable(format!("{description}: {text}")),
        BotoError::Core(_, text) => Step::Core(text),
        BotoError::Parser(text) => Step::Exc(PyExc::Other("ResponseParserError", text)),
        BotoError::Value(text) => Step::Exc(PyExc::ValueError(text)),
        BotoError::Key(text) => Step::Exc(PyExc::KeyError(text)),
        BotoError::Attribute(text) => Step::Exc(PyExc::AttributeError(text)),
        BotoError::Client(_) => Step::Exc(PyExc::Other("ClientError", String::new())),
    }
}

/// `_error_code(err)`.
fn error_code(e: &ClientError) -> Result<String, Step> {
    e.code().map_err(|m| Step::Exc(PyExc::AttributeError(m)))
}

/// `_error_message(err)`: the message, or the code when it is empty.
fn error_message(e: &ClientError) -> Result<String, Step> {
    let message = e
        .message()
        .map_err(|m| Step::Exc(PyExc::AttributeError(m)))?;
    if message.is_empty() {
        error_code(e)
    } else {
        Ok(message)
    }
}

fn client(env: &Env, service: Service, region: &str, keys: &AuthKeys) -> Result<Client, Step> {
    let endpoint = match service {
        Service::Sts => env.sts_endpoint.clone(),
        Service::S3 => env.s3_endpoint.clone(),
    };
    Client::new(
        service,
        region,
        (&keys.access_key_id, &keys.secret_access_key),
        endpoint,
        env.transport.clone(),
        env.hooks.clone(),
    )
    .map_err(|e| match e {
        BotoError::Core(_, text) => Step::Core(text),
        other => escape("client", other),
    })
}

async fn check_identity(env: &Env, keys: &AuthKeys) -> Result<(), Step> {
    let sts = client(env, Service::Sts, "us-east-1", keys)?;
    let identity = match sts.call(&Operation::GetCallerIdentity).await {
        Ok(output) => output,
        Err(BotoError::Client(e)) => {
            let code = error_code(&e)?;
            if BAD_CREDENTIAL_CODES.contains(&code.as_str()) {
                return invalid(
                    "AWS rejected the access key: ACCESS_KEY_ID or SECRET_ACCESS_KEY is wrong, or \
                     the key is inactive."
                        .into(),
                );
            }
            return invalid(format!(
                "AWS refused sts:GetCallerIdentity: {}",
                error_message(&e)?
            ));
        }
        Err(other) => return Err(escape("sts:GetCallerIdentity", other)),
    };
    let actual = match identity {
        Output::Identity { account } => account,
        _ => None,
    };
    if actual.as_deref() != Some(keys.account_id.as_str()) {
        return invalid(format!(
            "The access key belongs to AWS account {}, not AWS_ACCOUNT_ID {}. Correct \
             AWS_ACCOUNT_ID or use a key from that account.",
            actual.as_deref().unwrap_or("None"),
            keys.account_id
        ));
    }
    Ok(())
}

async fn bucket_region(env: &Env, keys: &AuthKeys) -> Result<String, Step> {
    let s3 = client(env, Service::S3, "us-east-1", keys)?;
    let bucket = &keys.bucket_name;
    let op = Operation::HeadBucket {
        bucket: bucket.clone(),
    };
    match s3.call(&op).await {
        Ok(Output::Head { headers }) => Ok(headers
            .iter()
            .find(|(k, _)| k == "x-amz-bucket-region")
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "us-east-1".into())),
        Ok(_) => Ok("us-east-1".into()),
        Err(BotoError::Client(e)) => {
            let region = e.header("x-amz-bucket-region").map(str::to_string);
            let code = error_code(&e)?;
            if matches!(code.as_str(), "404" | "NoSuchBucket") {
                return invalid(format!(
                    "S3 bucket {bucket} does not exist. Check BUCKET_NAME."
                ));
            }
            if matches!(code.as_str(), "301" | "PermanentRedirect" | "400") {
                if let Some(r) = region.filter(|r| !r.is_empty()) {
                    return Ok(r);
                }
            }
            if matches!(code.as_str(), "403" | "AccessDenied") {
                return invalid(format!(
                    "The IAM user may not read S3 bucket {bucket} (s3:ListBucket denied). Check \
                     the bucket policy and the user's policy."
                ));
            }
            invalid(format!(
                "Could not reach S3 bucket {bucket}: {}",
                error_message(&e)?
            ))
        }
        Err(other) => Err(escape("s3:HeadBucket", other)),
    }
}

async fn list(
    s3: &Client,
    bucket: &str,
    prefix: &str,
    title: &str,
    delimiter: Option<&str>,
    max_keys: Option<i64>,
) -> Result<ListOutput, Step> {
    let op = Operation::ListObjectsV2 {
        bucket: bucket.to_string(),
        prefix: prefix.to_string(),
        delimiter: delimiter.map(str::to_string),
        max_keys,
    };
    match s3.call(&op).await {
        Ok(Output::List(out)) => Ok(out),
        Ok(_) => Ok(ListOutput::default()),
        Err(BotoError::Client(e)) => {
            if error_code(&e)? == "AccessDenied" {
                return invalid(format!(
                    "{title}: the IAM user may not list s3://{bucket}/{prefix} (s3:ListBucket \
                     denied for that prefix)."
                ));
            }
            invalid(format!(
                "{title}: listing s3://{bucket}/{prefix} failed: {}",
                error_message(&e)?
            ))
        }
        Err(other) => Err(escape(&format!("s3:ListObjectsV2 {prefix}"), other)),
    }
}

/// `_readable_object(response)`.
fn readable_object(out: &ListOutput) -> Result<Option<String>, Step> {
    for item in out.contents.as_deref().unwrap_or_default() {
        let Some(key) = &item.key else {
            return Err(Step::Exc(PyExc::KeyError("'Key'".into())));
        };
        if key.ends_with('/') || item.size.unwrap_or(0) == 0 {
            continue;
        }
        if item
            .storage_class
            .as_deref()
            .is_some_and(|c| ARCHIVED_STORAGE_CLASSES.contains(&c))
        {
            continue;
        }
        return Ok(Some(key.clone()));
    }
    Ok(None)
}

/// `_find_log_object(...)`: `(key, any_logs_at_all)`.
async fn find_log_object(
    s3: &Client,
    bucket: &str,
    prefix: &str,
    title: &str,
    today: NaiveDate,
) -> Result<(Option<String>, bool), Step> {
    let listing = list(s3, bucket, prefix, title, Some("/"), None).await?;
    let mut regions: Vec<String> = Vec::new();
    for p in listing.common_prefixes.as_deref().unwrap_or_default() {
        match p {
            Some(p) => regions.push(p.clone()),
            None => return Err(Step::Exc(PyExc::KeyError("'Prefix'".into()))),
        }
    }
    for days_back in 0..RECENT_DAYS {
        let day = today - Duration::days(days_back);
        for region in &regions {
            let day_prefix = format!("{region}{}/", day.format("%Y/%m/%d"));
            let out = list(s3, bucket, &day_prefix, title, None, Some(LIST_PAGE)).await?;
            if let Some(key) = readable_object(&out)? {
                return Ok((Some(key), true));
            }
        }
    }
    let out = list(s3, bucket, prefix, title, None, Some(LIST_PAGE)).await?;
    let any = out.contents.as_ref().is_some_and(|c| !c.is_empty());
    Ok((readable_object(&out)?, any))
}

/// `_check_readable(...)`.
async fn check_readable(s3: &Client, bucket: &str, key: &str, title: &str) -> Result<(), Step> {
    let op = Operation::GetObject {
        bucket: bucket.to_string(),
        key: key.to_string(),
        range: "bytes=0-0".into(),
    };
    match s3.call(&op).await {
        Ok(_) => Ok(()),
        Err(BotoError::Client(e)) => {
            let message = error_message(&e)?;
            let code = error_code(&e)?;
            if message.to_lowercase().contains("kms") || code.starts_with("KMS") {
                return invalid(format!(
                    "{title}: the IAM user may list the logs but not decrypt them (kms:Decrypt \
                     denied). Allow the user to use the KMS key in that key's policy. AWS said: \
                     {message}"
                ));
            }
            if code == "AccessDenied" {
                return invalid(format!(
                    "{title}: the IAM user may list the logs but not read them (s3:GetObject \
                     denied)."
                ));
            }
            invalid(format!(
                "{title}: reading s3://{bucket}/{key} failed: {message}"
            ))
        }
        Err(other) => Err(escape(&format!("s3:GetObject {key}"), other)),
    }
}

async fn checks(
    env: &Env,
    keys: &AuthKeys,
    services: &[ServiceConfig],
    today: NaiveDate,
    warnings: &mut Vec<String>,
) -> Result<String, Step> {
    check_identity(env, keys).await?;
    let region = bucket_region(env, keys).await?;
    let s3 = client(env, Service::S3, &region, keys)?;
    let bucket = &keys.bucket_name;
    for config in services {
        let title = config.definition.title;
        let prefix = s3_log_prefix(config, &keys.account_id, keys.organization_id.as_deref());
        let (key, any_logs) = find_log_object(&s3, bucket, &prefix, title, today).await?;
        if let Some(key) = key {
            check_readable(&s3, bucket, &key, title).await?;
        } else if any_logs {
            let kms = if title == "GuardDuty" {
                ", kms:Decrypt"
            } else {
                ""
            };
            warnings.push(format!(
                "{title}: logs exist under s3://{bucket}/{prefix} but none from the last \
                 {RECENT_DAYS} days, and the older ones are archived, so read access \
                 (s3:GetObject{kms}) could not be checked. If {title} has stopped exporting, the \
                 Wazuh manager will collect nothing."
            ));
        } else {
            return invalid(format!(
                "{title}: no logs found under s3://{bucket}/{prefix}. Check the account ID, the \
                 service's prefix in SERVICES, and that {title} exports to this bucket."
            ));
        }
    }
    Ok(region)
}

/// `validate_aws_access(keys, services)` with `today` as
/// `datetime.now(timezone.utc).date()`.
pub async fn validate_aws_access(
    env: &Env,
    keys: &AuthKeys,
    services: &[ServiceConfig],
    today: NaiveDate,
) -> Result<ValidationResult, Failure> {
    let mut warnings = Vec::new();
    match checks(env, keys, services, today, &mut warnings).await {
        Ok(region) => {
            tracing::info!(
                "AWS credentials for account {} validated against bucket {} ({region}).",
                keys.account_id,
                keys.bucket_name
            );
            Ok(ValidationResult {
                validated: true,
                bucket_region: Some(region),
                warnings,
            })
        }
        Err(Step::Unreachable(e)) => {
            tracing::warn!(
                "Could not reach AWS to validate account {}: {e}",
                keys.account_id
            );
            Ok(ValidationResult {
                validated: false,
                bucket_region: None,
                warnings: vec![format!(
                    "CoPilot could not reach AWS ({e}), so the credentials and bucket were not \
                     checked. The Wazuh manager reports any problem in ossec.log under \
                     wazuh-modulesd:aws-s3."
                )],
            })
        }
        Err(Step::Invalid(m)) => Err(Failure::Invalid(m)),
        Err(Step::Core(text)) => Err(Failure::Invalid(format!(
            "Could not check the AWS credentials: {text}"
        ))),
        Err(Step::Exc(e)) => Err(Failure::Exc(e)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::aws::boto::tests::{assert_requests, doc, hooks, script};

    #[test]
    fn validation_is_python_s() {
        let d = doc();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        for v in d["validate"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let raw: Vec<(String, Option<String>)> = v["keys"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string)))
                .collect();
            let keys = super::super::schema::parse_auth_keys(&raw).unwrap();
            let s = script(&v["answers"]);
            let endpoint = v["endpoint"].as_str().map(str::to_string);
            let env = Env {
                transport: Transport::Script(s.clone()),
                hooks: hooks(),
                sts_endpoint: endpoint.clone(),
                s3_endpoint: endpoint,
            };
            let outcome = rt.block_on(validate_aws_access(
                &env,
                &keys,
                &keys.service_configs(),
                today,
            ));
            let seen = s.lock().unwrap().seen.clone();
            assert_requests(name, &seen, &v["requests"]);
            let want = &v["result"];
            match outcome {
                Ok(r) => {
                    let ok = &want["ok"];
                    assert_eq!(
                        Some(r.validated),
                        ok["validated"].as_bool(),
                        "{name}: {want}"
                    );
                    assert_eq!(
                        r.bucket_region.as_deref(),
                        ok["bucket_region"].as_str(),
                        "{name}"
                    );
                    let warnings: Vec<&str> = ok["warnings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|w| w.as_str().unwrap())
                        .collect();
                    assert_eq!(r.warnings, warnings, "{name}");
                }
                Err(Failure::Invalid(m)) => {
                    assert_eq!(Some(m.as_str()), want["invalid"].as_str(), "{name}: {want}")
                }
                Err(Failure::Exc(e)) => {
                    let class = match &e {
                        PyExc::KeyError(_) => "KeyError",
                        PyExc::ValueError(_) => "ValueError",
                        PyExc::AttributeError(_) => "AttributeError",
                        PyExc::Other(c, _) => c,
                        other => panic!("{name}: {other:?}"),
                    };
                    assert_eq!(class, want["exception"][0].as_str().unwrap(), "{name}");
                    assert_eq!(e.text(), want["exception"][1].as_str().unwrap(), "{name}");
                }
            }
        }
    }
}
