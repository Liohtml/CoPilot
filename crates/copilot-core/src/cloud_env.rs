//! What the remaining provisioning (`copilot-cloud-provisioning`) reads from
//! the environment, raw as the Python libraries see it.

use crate::env::EnvFile;

/// Raw cloud-provisioning settings (`None` = unset).
#[derive(Debug, Clone, Default)]
pub struct CloudEnv {
    /// `AWS_ENDPOINT_URL`: botocore's endpoint override for every service
    /// (S3 then path-style) — what the AWS validation's calls honour.
    pub aws_endpoint_url: Option<String>,
    /// `AWS_ENDPOINT_URL_STS`: STS's own override.
    pub aws_endpoint_url_sts: Option<String>,
    /// `AWS_ENDPOINT_URL_S3`: S3's own override.
    pub aws_endpoint_url_s3: Option<String>,
    /// `COPILOT_AWS_PROFILE_CHECK_SECONDS` (`interval,timeout`) — tests
    /// only: how long the AWS provisioning watches the manager's log after a
    /// restart instead of 10 s / 60 s.
    pub aws_profile_check_seconds: Option<String>,
}

impl CloudEnv {
    /// Read the values the way `os.getenv` would see them.
    pub fn from_env(env: &EnvFile) -> Self {
        let read = |k: &str| env.get(k).filter(|v| !v.is_empty());
        Self {
            aws_endpoint_url: read("AWS_ENDPOINT_URL"),
            aws_endpoint_url_sts: read("AWS_ENDPOINT_URL_STS"),
            aws_endpoint_url_s3: read("AWS_ENDPOINT_URL_S3"),
            aws_profile_check_seconds: read("COPILOT_AWS_PROFILE_CHECK_SECONDS"),
        }
    }
}
