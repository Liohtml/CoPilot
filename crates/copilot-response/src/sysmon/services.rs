//! `app/active_response/services/sysmon_config.py` and the Sysmon half of
//! `app/data_store/data_store_operations.py`: the configs live in MinIO's
//! `sysmon-configs` bucket as `{customer_code}/sysmon_config.xml`, each
//! operation on its own client (`create_session()`).

use bytes::Bytes;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_objectstore::ObjectStore;
use copilot_objectstore::ops;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::PyExc;

use crate::sysmon::schema::DEPLOYMENT_RESULT;
use crate::sysmon::worker::{Answer, WorkerHttp};

/// The bucket.
pub const BUCKET: &str = "sysmon-configs";

/// The object a customer's config is stored as.
pub fn object_name(customer_code: &str) -> String {
    format!("{customer_code}/sysmon_config.xml")
}

/// `download_sysmon_config` (`download_data_store`: the 404 when the
/// object cannot be read).
pub async fn download(store: &ObjectStore, customer_code: &str) -> Result<Bytes, PyExc> {
    ops::download_data_store(store, BUCKET, &object_name(customer_code)).await
}

/// `list_sysmon_configs`: the customer codes with a config. The bucket is
/// created when missing (and the list is then empty); any failure is an
/// empty list. Python collects the codes in a `set` and answers
/// `list(set)` — an order that follows the strings' hashes and changes
/// from one process to the next; here they come in listing order (§4).
pub async fn list(store: &ObjectStore) -> Vec<String> {
    let run = async {
        let client = store.session()?;
        if !client
            .bucket_exists(BUCKET)
            .await
            .map_err(|e| e.into_py())?
        {
            client.make_bucket(BUCKET).await.map_err(|e| e.into_py())?;
            return Ok::<_, PyExc>(Vec::new());
        }
        let mut codes: Vec<String> = Vec::new();
        for obj in client
            .list_objects(BUCKET, None, true)
            .await
            .map_err(|e| e.into_py())?
        {
            if obj.object_name.ends_with("sysmon_config.xml") {
                let code = obj
                    .object_name
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if !codes.contains(&code) {
                    codes.push(code);
                }
            }
        }
        Ok(codes)
    };
    match run.await {
        Ok(codes) => codes,
        Err(e) => {
            tracing::error!(
                "Error listing sysmon configs: returning empty list - {}",
                e.display()
            );
            Vec::new()
        }
    }
}

/// `validate_sysmon_config(xml_content)`: `ET.fromstring`, then the shape
/// a Sysmon config needs; each refusal is Python's 400.
pub fn validate_config(xml: &str) -> Result<(), PyExc> {
    let bad = |detail: &str| PyExc::Http(400, detail.to_string());
    let root = copilot_integrations::etree::fromstring(xml)
        .map_err(|e| PyExc::Http(400, format!("Invalid XML syntax: {e}")))?;
    if root.tag != "Sysmon" {
        return Err(bad("Root element must be 'Sysmon'"));
    }
    let Some(filtering) = root.find("EventFiltering") else {
        return Err(bad("Missing required 'EventFiltering' element"));
    };
    if filtering
        .text
        .as_deref()
        .is_some_and(|t| !t.trim_matches(char::is_whitespace).is_empty())
    {
        return Err(bad(
            "Invalid text content found directly in EventFiltering element",
        ));
    }
    let groups = filtering.findall("RuleGroup");
    if groups.is_empty() {
        return Err(bad("EventFiltering must contain at least one RuleGroup"));
    }
    for i in groups {
        let relation = filtering.children[i]
            .attrib
            .iter()
            .find(|(k, _)| k == "groupRelation")
            .map(|(_, v)| v.as_str());
        if relation.is_none_or(str::is_empty) {
            return Err(bad("RuleGroup must have 'groupRelation' attribute"));
        }
    }
    Ok(())
}

/// `check_config_exists(customer_code)`: the bucket made when missing (no
/// config then), else whether the object answers `stat_object`; a failure
/// of the bucket calls is the 500 `Error checking config existence: …`.
pub async fn config_exists(store: &ObjectStore, customer_code: &str) -> Result<bool, PyExc> {
    let checking = |e: PyExc| {
        PyExc::Http(
            500,
            format!("Error checking config existence: {}", e.display()),
        )
    };
    let client = store.session().map_err(checking)?;
    if !client
        .bucket_exists(BUCKET)
        .await
        .map_err(|e| checking(e.into_py()))?
    {
        tracing::info!("Bucket {BUCKET} doesn't exist. Creating it.");
        client
            .make_bucket(BUCKET)
            .await
            .map_err(|e| checking(e.into_py()))?;
        return Ok(false);
    }
    match client
        .stat_object(BUCKET, &object_name(customer_code))
        .await
    {
        Ok(_) => {
            tracing::info!("Found existing sysmon config for customer {customer_code}");
            Ok(true)
        }
        Err(e) => {
            tracing::info!(
                "No existing sysmon config found for customer {customer_code} - {}",
                e.into_py().display()
            );
            Ok(false)
        }
    }
}

/// `upload_sysmon_config(customer_code, file)`: the uploading client is
/// made first, `create_bucket_if_not_exists` runs on a client of its own,
/// then the object is put as `application/xml`.
pub async fn upload(store: &ObjectStore, customer_code: &str, data: &[u8]) -> Result<(), PyExc> {
    let client = store.session()?;
    let bucketing = store.session()?;
    if bucketing
        .bucket_exists(BUCKET)
        .await
        .map_err(|e| e.into_py())?
    {
        tracing::info!("Bucket {BUCKET} already exists");
    } else {
        bucketing
            .make_bucket(BUCKET)
            .await
            .map_err(|e| e.into_py())?;
        tracing::info!("Created bucket {BUCKET}");
    }
    tracing::info!("Uploading sysmon config for customer {customer_code}");
    client
        .fput_object(
            BUCKET,
            &object_name(customer_code),
            data,
            Some("application/xml"),
        )
        .await
        .map_err(|e| e.into_py())
}

/// `urlparse(url).netloc` as CPython 3.11's `urlsplit` finds it; `Err` is
/// the `ValueError` it raises.
pub fn netloc(url: &str) -> Result<String, String> {
    let url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    if let Some(i) = rest.find(':') {
        let scheme = &rest[..i];
        let first_ok = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii() && c.is_ascii_alphabetic());
        if i > 0
            && first_ok
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            rest = &rest[i + 1..];
        }
    }
    let Some(after) = rest.strip_prefix("//") else {
        return Ok(String::new());
    };
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let netloc = &after[..end];
    if netloc.contains('[') != netloc.contains(']') {
        return Err("Invalid IPv6 URL".into());
    }
    if netloc.contains('[') {
        let hostport = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
        if let Some((before, bracketed)) = hostport.split_once('[') {
            if !before.is_empty() {
                return Err("Invalid IPv6 URL".into());
            }
            let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return Err("Invalid IPv6 URL".into());
            }
            if let Some(v) = host.strip_prefix('v') {
                let valid = v.split_once('.').is_some_and(|(hex, tail)| {
                    !hex.is_empty()
                        && hex.chars().all(|c| c.is_ascii_hexdigit())
                        && !tail.is_empty()
                });
                if !valid {
                    return Err("IPvFuture address is invalid".into());
                }
            } else if host.parse::<std::net::Ipv4Addr>().is_ok() {
                return Err("An IPv4 address cannot be in brackets".into());
            } else if !copilot_ingest::py::is_ip_address(host) {
                return Err(format!(
                    "{} does not appear to be an IPv4 or IPv6 address",
                    copilot_auth::pyvalue::str_repr(host)
                ));
            }
        }
    }
    Ok(netloc.to_string())
}

fn result(customer_code: &str, pairs: Vec<(&str, PyValue)>) -> Result<PyValue, PyExc> {
    let mut all = vec![("customer_code", PyValue::Str(customer_code.into()))];
    all.extend(pairs);
    construct(&DEPLOYMENT_RESULT, &kwargs(all))
}

fn failure(customer_code: &str, message: String, detail: String) -> PyValue {
    result(
        customer_code,
        vec![
            ("success", PyValue::Bool(false)),
            ("message", PyValue::Str(message)),
            ("error_detail", PyValue::Str(detail)),
        ],
    )
    .unwrap_or(PyValue::None)
}

/// `response_data.get(key, default)` on whatever JSON the worker sent.
fn get(data: &PyValue, key: &str, default: PyValue) -> Result<PyValue, PyExc> {
    match data {
        PyValue::Dict(items) => Ok(items
            .iter()
            .find(|(k, _)| k == key)
            .map_or(default, |(_, v)| v.clone())),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            copilot_upstream::py::type_name(other)
        ))),
    }
}

/// `deploy_sysmon_config_to_worker(customer_code)`: the
/// `SysmonConfigDeploymentResult` dump (every failure is a result).
pub async fn deploy(
    store: &ObjectStore,
    connectors: &ConnectorCache,
    http: &WorkerHttp,
    worker_port: &str,
    customer_code: &str,
) -> PyValue {
    // Step 1: the config.
    let config = match download(store, customer_code).await {
        Ok(c) => {
            tracing::info!("Successfully fetched Sysmon config for {customer_code} from storage");
            c
        }
        Err(e) => {
            tracing::error!(
                "Failed to fetch Sysmon config for {customer_code}: {}",
                e.display()
            );
            return failure(
                customer_code,
                format!("Failed to fetch Sysmon config for {customer_code}"),
                e.display(),
            );
        }
    };
    // Step 3: the endpoint, from the manager connector's URL.
    let url = connectors
        .get("Wazuh-Manager")
        .await
        .map_err(|e| e.to_string())
        .map(|row| row.map(|r| r.connector_url));
    let host = match url {
        Err(e) => Err(e),
        Ok(None) => Err("a bytes-like object is required, not 'str'".to_string()),
        Ok(Some(url)) => netloc(&url).map(|n| n.split(':').next().unwrap_or_default().to_string()),
    };
    let host = match host {
        Ok(h) => h,
        Err(e) => {
            return failure(customer_code, "Failed to get Wazuh endpoint".into(), e);
        }
    };
    tracing::info!(
        "Constructed Wazuh API endpoint: http://{host}:{worker_port}/provision_worker/sysmon-config"
    );
    // Step 4: the upload.
    let outcome = async {
        match http
            .upload(&host, worker_port, customer_code, &config)
            .await?
        {
            Answer::Json(data) => {
                let worker_success = get(&data, "success", PyValue::Bool(true))?;
                let worker_message = get(
                    &data,
                    "message",
                    PyValue::Str("Deployed successfully".into()),
                )?;
                tracing::info!("Successfully deployed Sysmon config to Wazuh for {customer_code}");
                result(
                    customer_code,
                    vec![
                        ("success", PyValue::Bool(true)),
                        (
                            "message",
                            PyValue::Str(format!(
                                "Sysmon config successfully deployed for {customer_code}"
                            )),
                        ),
                        ("worker_success", worker_success),
                        ("worker_message", worker_message),
                    ],
                )
            }
            Answer::Text(text) => {
                tracing::error!("Failed to deploy Sysmon config to Wazuh: {text}");
                result(
                    customer_code,
                    vec![
                        ("success", PyValue::Bool(false)),
                        (
                            "message",
                            PyValue::Str(
                                "Error from Wazuh master when deploying Sysmon config".into(),
                            ),
                        ),
                        ("error_detail", PyValue::Str(text)),
                    ],
                )
            }
        }
    };
    match outcome.await {
        Ok(dump) => dump,
        Err(e) => {
            tracing::error!("Error deploying Sysmon config: {}", e.display());
            failure(
                customer_code,
                "Exception occurred during Sysmon config deployment".into(),
                e.display(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    /// `validate_sysmon_config` against Python's (`scripts/gen-expat-vectors.py`).
    #[test]
    fn configs_are_validated_as_python_validates_them() {
        #[derive(serde::Deserialize)]
        struct Probe {
            text: String,
            detail: Option<String>,
        }
        let v: Vec<Probe> = serde_json::from_str(include_str!("sysmon_vectors.json")).unwrap();
        for probe in v {
            let got = super::validate_config(&probe.text).err().map(|e| match e {
                super::PyExc::Http(400, d) => d,
                other => format!("{other:?}"),
            });
            assert_eq!(got, probe.detail, "{:?}", probe.text);
        }
    }

    use super::*;

    #[test]
    fn netloc_is_urlsplits() {
        for (url, want) in [
            ("https://wazuh:55000", Ok("wazuh:55000")),
            ("wazuh:55000", Ok("")),
            ("", Ok("")),
            ("https://u:p@h:1/x", Ok("u:p@h:1")),
            ("https://[::1]:55000", Ok("[::1]:55000")),
            ("HTTPS://Host:5", Ok("Host:5")),
            ("https://h?x", Ok("h")),
            ("https://h#f/x", Ok("h")),
            (" \thttps://h\n:1", Ok("h:1")),
            ("https://[::1:55000", Err("Invalid IPv6 URL")),
            (
                "https://[1.2.3.4]",
                Err("An IPv4 address cannot be in brackets"),
            ),
            ("//host:9/p", Ok("host:9")),
        ] {
            assert_eq!(
                netloc(url),
                want.map(str::to_string).map_err(str::to_string),
                "{url}"
            );
        }
    }
}
