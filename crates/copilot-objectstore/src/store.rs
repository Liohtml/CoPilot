//! `app/data_store/data_store_session.py`: the settings and `create_session()`.

use std::sync::Arc;
use std::time::Duration;

use copilot_core::config::MinioEnv;
use copilot_upstream::py::PyExc;

use crate::client::{Minio, Shared, TIMEOUT, user_agent};
use crate::endpoint::{self, Endpoint};
use crate::sigv4::Credentials;

/// marshmallow's `Boolean.truthy` / `falsy` (environs' `env.bool`).
const TRUTHY: [&str; 14] = [
    "1", "ON", "On", "T", "TRUE", "True", "Y", "YES", "Yes", "on", "t", "true", "y", "yes",
];
const FALSY: [&str; 14] = [
    "0", "F", "FALSE", "False", "N", "NO", "No", "OFF", "Off", "f", "false", "n", "no", "off",
];

/// The MinIO settings and the shared HTTP client; [`ObjectStore::session`]
/// is `create_session()`.
#[derive(Debug, Clone)]
pub struct ObjectStore {
    endpoint: Result<Arc<Shared>, String>,
}

impl ObjectStore {
    /// Read `MINIO_URL` (default `copilot-minio`), `MINIO_ROOT_USER`
    /// (`admin`), `MINIO_ROOT_PASSWORD` (`password`) and `MINIO_SECURE`
    /// (`false`) as `data_store_session.py` does. A `MINIO_SECURE` that is not
    /// one of marshmallow's spellings stops the Python backend at import;
    /// here it stops the binary. An endpoint `miniopy-async` refuses is
    /// every call's `ValueError`, as in Python.
    pub fn from_env(env: &MinioEnv) -> Result<Self, String> {
        let secure = match env.secure.as_deref() {
            None => false,
            Some(v) if TRUTHY.contains(&v) => true,
            Some(v) if FALSY.contains(&v) => false,
            Some(_) => {
                return Err(
                    "Environment variable \"MINIO_SECURE\" invalid: Not a valid boolean.".into(),
                );
            }
        };
        let url = env.url.clone().unwrap_or_else(|| "copilot-minio".into());
        let target = env
            .endpoint_override
            .clone()
            .unwrap_or_else(|| format!("{url}:9000"));
        let access_key = env.root_user.clone().unwrap_or_else(|| "admin".into());
        let secret_key = env
            .root_password
            .as_ref()
            .map_or_else(|| "password".to_string(), |s| s.expose().to_string());
        let credentials = (!access_key.is_empty()).then_some(Credentials {
            access_key,
            secret_key,
        });
        let endpoint = match endpoint::parse(&target, secure) {
            Ok(e) => Ok(Arc::new(Shared {
                http: http_client(&e).map_err(|e| e.to_string())?,
                endpoint: e,
                credentials,
                user_agent: user_agent(),
            })),
            Err(text) => Err(text),
        };
        Ok(Self { endpoint })
    }

    /// A store for an endpoint (tests).
    pub fn for_endpoint(
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self, String> {
        Self::from_env(&MinioEnv {
            url: None,
            root_user: Some(access_key.into()),
            root_password: Some(copilot_core::config::Secret::new(secret_key)),
            secure: None,
            endpoint_override: Some(endpoint.into()),
        })
    }

    /// `create_session()`: a fresh client (its own region cache), or the
    /// `ValueError` `Minio(...)` raises for this endpoint.
    pub fn session(&self) -> Result<Minio, PyExc> {
        match &self.endpoint {
            Ok(shared) => Ok(Minio::new(shared.clone())),
            Err(text) => Err(PyExc::ValueError(text.clone())),
        }
    }

    /// Where requests go (`None` when the endpoint is refused).
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref().ok().map(|s| &s.endpoint)
    }
}

/// aiohttp's session as miniopy-async builds it: 5-minute connect and read
/// timeouts, no proxy, certificates from `SSL_CERT_FILE` or the Mozilla
/// roots.
fn http_client(endpoint: &Endpoint) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(15))
        .no_proxy();
    if endpoint.https {
        if let Some(path) = std::env::var_os("SSL_CERT_FILE").filter(|p| !p.is_empty()) {
            builder = builder.tls_built_in_root_certs(false);
            if let Ok(pem) = std::fs::read(path) {
                for cert in reqwest::Certificate::from_pem_bundle(&pem).unwrap_or_default() {
                    builder = builder.add_root_certificate(cert);
                }
            }
        }
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(secure: Option<&str>, url: Option<&str>) -> MinioEnv {
        MinioEnv {
            url: url.map(str::to_string),
            root_user: None,
            root_password: None,
            secure: secure.map(str::to_string),
            endpoint_override: None,
        }
    }

    #[test]
    fn settings_read_like_environs() {
        let store = ObjectStore::from_env(&env(None, None)).unwrap();
        let e = store.endpoint().unwrap();
        assert_eq!((e.netloc.as_str(), e.https), ("copilot-minio:9000", false));
        assert!(
            ObjectStore::from_env(&env(Some("yes"), None))
                .unwrap()
                .endpoint()
                .unwrap()
                .https
        );
        assert_eq!(
            ObjectStore::from_env(&env(Some(""), None)).unwrap_err(),
            "Environment variable \"MINIO_SECURE\" invalid: Not a valid boolean."
        );
        assert!(ObjectStore::from_env(&env(Some("tRue"), None)).is_err());
        let bad = ObjectStore::from_env(&env(None, Some("http://minio"))).unwrap();
        assert_eq!(
            bad.session().unwrap_err(),
            PyExc::ValueError("path in endpoint is not allowed".into())
        );
    }
}
