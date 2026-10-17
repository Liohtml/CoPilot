//! What the remaining provisioning (`copilot-cloud-provisioning`, the
//! collectors of `copilot-integration-provisioning`) reads from the
//! environment, raw as the Python libraries see it.

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
    /// `COPILOT_BACKEND_DATA_DIR`: the Python backend's `data/` directory
    /// (its `UPLOAD_FOLDER`), where the CrowdStrike, Defender for Endpoint
    /// and Bitdefender provisioning write their collectors' files —
    /// [`CloudEnv::DEFAULT_BACKEND_DATA_DIR`] when unset, the path the
    /// backend's image uses and `docker-compose.rust.yml` mounts.
    pub backend_data_dir: Option<String>,
    /// `COPILOT_BITDEFENDER_URL` — parity harness only, never production:
    /// replaces `https://cloud.gravityzone.bitdefender.com` in the
    /// Bitdefender provisioning's GravityZone call.
    pub bitdefender_url: Option<String>,
    /// `COPILOT_PROVISION_WORKER_PORT` — tests only: the port of each swarm
    /// node's provisioning worker instead of `5003` (the customer
    /// provisioning's Portainer deployment; the Sysmon deploy reads the same
    /// variable through `ResponseEnv`).
    pub provision_worker_port: Option<String>,
}

impl CloudEnv {
    /// The backend's `UPLOAD_FOLDER` in its image (`/opt/copilot/backend` +
    /// `data`).
    pub const DEFAULT_BACKEND_DATA_DIR: &'static str = "/opt/copilot/backend/data";

    /// The directory the collectors' files are written under.
    pub fn backend_data_dir(&self) -> &str {
        self.backend_data_dir
            .as_deref()
            .unwrap_or(Self::DEFAULT_BACKEND_DATA_DIR)
    }

    /// The port of a swarm node's provisioning worker.
    pub fn provision_worker_port(&self) -> &str {
        self.provision_worker_port.as_deref().unwrap_or("5003")
    }

    /// Read the values the way `os.getenv` would see them.
    pub fn from_env(env: &EnvFile) -> Self {
        let read = |k: &str| env.get(k).filter(|v| !v.is_empty());
        Self {
            aws_endpoint_url: read("AWS_ENDPOINT_URL"),
            aws_endpoint_url_sts: read("AWS_ENDPOINT_URL_STS"),
            aws_endpoint_url_s3: read("AWS_ENDPOINT_URL_S3"),
            aws_profile_check_seconds: read("COPILOT_AWS_PROFILE_CHECK_SECONDS"),
            backend_data_dir: read("COPILOT_BACKEND_DATA_DIR"),
            bitdefender_url: read("COPILOT_BITDEFENDER_URL"),
            provision_worker_port: env
                .get("COPILOT_PROVISION_WORKER_PORT")
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        }
    }
}
