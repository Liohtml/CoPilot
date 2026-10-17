//! `POST /api/aws/provision` — `app/integrations/aws/` (`routes/provision.py`,
//! `services/provision.py`): one AWS account (integration instance) of a
//! customer deployed, or re-synced when it already is.
//!
//! An instance has several services (CloudTrail, GuardDuty): per instance,
//! its `<bucket>` entries in the manager's aws-s3 wodle and one Graylog
//! stream per service; per customer and service, shared by the customer's
//! accounts, the `<service>-<code>` index set and its Grafana datasource;
//! per customer, the `AWS` Grafana folder. In Python's order:
//!
//! 1. before anything changes: the auth keys ([`schema::parse_auth_keys`]),
//!    the account's ownership (`ensure_account_is_free`, 400s), the
//!    credentials against AWS ([`validate`], a 400 on a failure the manager
//!    would share, a warning when AWS cannot be reached);
//! 2. inside one `try`: the manager's log markers, the instance's buckets
//!    reconciled on the manager (`copilot_integrations::aws::manager`, under
//!    the process's `WAZUH_CONFIG_LOCK`), the pipeline rules and pipeline,
//!    per service the index set (reused) and stream (kept), the folder and
//!    datasources (reused), the metadata row, `deployed` — any failure
//!    rolled back newest-first ([`Rollback`]) and answered `AWS deployment
//!    failed and was rolled back: …` with the failure's status;
//! 3. after it: the services a re-sync dropped removed from Graylog and
//!    Grafana (warnings), then, when the manager restarted, its log watched
//!    for the exit-23 error ([`notice`]).

pub mod boto;
pub mod notice;
pub mod schema;
pub mod validate;

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_integration_provisioning::grafana::{self as grafana_steps, Datasource};
use copilot_integration_provisioning::graylog::{self as graylog_steps, IndexSet};
use copilot_integration_provisioning::store as prov_store;
use copilot_integrations::aws::config::desired_buckets;
use copilot_integrations::aws::decommission::remove_service_resources;
use copilot_integrations::aws::manager::apply_instance_buckets;
use copilot_integrations::aws::services::{
    AWS_SERVICES, ServiceDefinition, decode_service_ids, encode_service_ids, lookup,
};
use copilot_integrations::etree::py_is_space;
use copilot_integrations::integrations::store as int_store;
use copilot_upstream::model::field;
use copilot_upstream::py::{PyExc, PyResult};

use crate::Tools;
use crate::graylog;
use crate::office365::{api_exc, customer_name, db, explore_links, set_deployed};
use crate::rollback::{Rollback, Style, Undo, detail_or_str, failure};
use schema::*;
use validate::{Env, Failure};

/// `GRAFANA_FOLDER_TITLE`.
pub const GRAFANA_FOLDER_TITLE: &str = "AWS";

fn unique(values: impl Iterator<Item = &'static str>) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for v in values {
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// `_fallback_chain(fields)`: `to_string($message.a, to_string($message.b))`.
fn fallback_chain(fields: &[&str]) -> String {
    let Some((last, rest)) = fields.split_last() else {
        return String::new();
    };
    let mut expression = format!("to_string($message.{last})");
    for name in rest.iter().rev() {
        expression = format!("to_string($message.{name}, {expression})");
    }
    expression
}

fn when_any(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| format!("has_field(\"{f}\")"))
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// `aws_rule_sources()`, in the dict's order.
pub fn aws_rule_sources() -> Vec<(&'static str, String)> {
    let timestamps = unique(AWS_SERVICES.iter().map(|d| d.timestamp_field));
    let accounts = unique(AWS_SERVICES.iter().map(|d| d.account_field));
    vec![
        (
            AWS_SYSLOG_TYPE,
            format!(
                "rule \"{AWS_SYSLOG_TYPE}\"\nwhen\n  to_string($message.data_integration) == \
                 \"aws\"\nthen\n  set_field(\"syslog_type\", \"aws\");\nend"
            ),
        ),
        (
            AWS_TIMESTAMP,
            format!(
                "rule \"{AWS_TIMESTAMP}\"\nwhen\n  {}\nthen\n  set_field(\"timestamp_utc\", \
                 {});\nend",
                when_any(&timestamps),
                fallback_chain(&timestamps)
            ),
        ),
        (
            AWS_ACCOUNT_ID,
            format!(
                "rule \"{AWS_ACCOUNT_ID}\"\nwhen\n  {}\nthen\n  set_field(\"aws_account_id\", \
                 {});\nend",
                when_any(&accounts),
                fallback_chain(&accounts)
            ),
        ),
    ]
}

/// `aws_pipeline_source()`.
pub fn aws_pipeline_source() -> String {
    let rules = PIPELINE_RULE_TITLES
        .iter()
        .map(|t| format!("rule \"{t}\""))
        .collect::<Vec<_>>()
        .join("\n");
    format!("pipeline \"{PIPELINE_TITLE}\"\nstage 0 match either\n{rules}\nend")
}

/// `_same_source(a, b)`: equal once whitespace runs are collapsed.
pub(crate) fn same_source(a: Option<&str>, b: &str) -> bool {
    let words = |s: &str| {
        s.split(py_is_space)
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    };
    words(a.unwrap_or_default()) == words(b)
}

/// The 502 of an update Graylog did not accept.
fn update_refused(what: &str, message: Option<String>) -> PyExc {
    PyExc::http(
        502,
        format!(
            "Could not update Graylog {what}: {}",
            message.unwrap_or_else(|| "None".into())
        ),
    )
}

/// `ensure_pipeline_rules()`.
async fn ensure_pipeline_rules(tools: Tools<'_>) -> PyResult<()> {
    let gl = tools.graylog;
    // `{rule.title: rule}`: a repeated title keeps the last rule.
    let rules = graylog::pipeline_rules(gl).await?;
    let existing = |title: &str| rules.iter().rev().find(|r| r.title == title);
    for title in &PIPELINE_RULE_TITLES[..4] {
        if existing(title).is_none() {
            tracing::info!("Creating pipeline rule {title}.");
            let source = graylog::wazuh_rule_source(title).unwrap_or_default();
            graylog::create_rule(gl, title, title, &source).await?;
        }
    }
    for (title, source) in aws_rule_sources() {
        match existing(title) {
            None => {
                tracing::info!("Creating pipeline rule {title}.");
                graylog::create_rule(gl, title, title, &source).await?;
            }
            Some(rule) if !same_source(Some(&rule.source), &source) => {
                tracing::info!("Updating pipeline rule {title}.");
                let description = rule
                    .description
                    .as_deref()
                    .filter(|d| !d.is_empty())
                    .unwrap_or(title);
                let (ok, message) = graylog::put_source(
                    gl,
                    &format!("/api/system/pipelines/rule/{}", rule.id),
                    title,
                    description,
                    &source,
                )
                .await?;
                if !ok {
                    return Err(update_refused(&format!("pipeline rule {title}"), message));
                }
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// `ensure_pipeline()`: the AWS PROCESSING PIPELINE's id.
async fn ensure_pipeline(tools: Tools<'_>) -> PyResult<String> {
    let gl = tools.graylog;
    let source = aws_pipeline_source();
    let found = graylog::pipelines(gl)
        .await?
        .into_iter()
        .find(|p| p.title == PIPELINE_TITLE);
    let pipeline = match found {
        None => {
            tracing::info!("Creating pipeline {PIPELINE_TITLE}.");
            graylog::create_pipeline(gl, PIPELINE_TITLE, PIPELINE_TITLE, &source).await?;
            graylog::pipelines(gl)
                .await?
                .into_iter()
                .find(|p| p.title == PIPELINE_TITLE)
                .ok_or_else(|| {
                    PyExc::http(
                        502,
                        format!("Graylog did not create the pipeline {PIPELINE_TITLE}."),
                    )
                })?
        }
        Some(p) => {
            if !same_source(Some(&p.source), &source) {
                tracing::info!("Updating pipeline {PIPELINE_TITLE}.");
                let description = p
                    .description
                    .as_deref()
                    .filter(|d| !d.is_empty())
                    .unwrap_or(PIPELINE_TITLE);
                let (ok, message) = graylog::put_source(
                    gl,
                    &format!("/api/system/pipelines/pipeline/{}", p.id),
                    PIPELINE_TITLE,
                    description,
                    &source,
                )
                .await?;
                if !ok {
                    return Err(update_refused(
                        &format!("pipeline {PIPELINE_TITLE}"),
                        message,
                    ));
                }
            }
            p
        }
    };
    Ok(pipeline.id)
}

/// `create_index_set(customer_code, definition, session)`: the index set's
/// id.
async fn create_index_set(
    tools: Tools<'_>,
    code: &str,
    definition: &ServiceDefinition,
) -> PyResult<String> {
    let name = customer_name(&tools.ctx.db, code).await?;
    let shards = grafana_steps::shard_number(tools.wazuh).await?;
    let lower = code.to_lowercase();
    let index_set = graylog_steps::index_set_config(&IndexSet {
        title: format!("{name} - AWS {}", definition.title),
        description: format!("{lower} - AWS {}", definition.title),
        index_prefix: format!("{}-{lower}", definition.key),
        max_indices: PyValue::Int("30".into()),
        shards,
        replicas: PyValue::Int("0".into()),
        creation_date: graylog_steps::creation_date(),
    })?;
    tracing::info!(
        "Creating Graylog index set {}-{lower} for customer {code}.",
        definition.key
    );
    let id = graylog_steps::create_index_set(
        tools.graylog,
        copilot_graylog::client::DEFAULT_CONNECTOR,
        index_set,
    )
    .await?;
    Ok(id.py_str())
}

/// `create_event_stream(...)`: the stream's id.
async fn create_event_stream(
    tools: Tools<'_>,
    code: &str,
    definition: &ServiceDefinition,
    keys: &AuthKeys,
    index_set_id: &str,
    instance: Option<&str>,
) -> PyResult<String> {
    let name = customer_name(&tools.ctx.db, code).await?;
    let mut title = format!("{name} - AWS {}", definition.title);
    if let Some(i) = instance.filter(|i| !i.is_empty()) {
        title.push_str(&format!(" - {i}"));
    }
    let stream = graylog_steps::event_stream_config(
        &title,
        &title,
        &PyValue::Str(index_set_id.to_string()),
        vec![
            ("data_aws_log_info_s3bucket", keys.bucket_name.clone()),
            ("data_aws_source", definition.key.to_string()),
            (definition.account_field, keys.account_id.clone()),
        ],
    )?;
    let id = graylog_steps::create_event_stream(
        tools.graylog,
        copilot_graylog::client::DEFAULT_CONNECTOR,
        stream,
    )
    .await?;
    Ok(id.py_str())
}

/// `connect_and_start_stream(stream_id, pipeline_id)`.
async fn connect_and_start_stream(
    tools: Tools<'_>,
    stream_id: &str,
    pipeline_id: &str,
) -> PyResult<()> {
    graylog_steps::connect_stream_to_pipeline(
        tools.graylog,
        copilot_graylog::client::DEFAULT_CONNECTOR,
        &PyValue::Str(stream_id.to_string()),
        &PyValue::List(vec![PyValue::Str(pipeline_id.to_string())]),
    )
    .await?;
    copilot_graylog::services::start_stream(tools.graylog, stream_id).await?;
    Ok(())
}

/// `create_grafana_datasource(...)`: the datasource's uid.
async fn create_grafana_datasource(
    tools: Tools<'_>,
    code: &str,
    definition: &ServiceDefinition,
    org: &str,
) -> PyResult<String> {
    let lower = code.to_lowercase();
    let name = format!("AWS {}", definition.title.to_uppercase());
    let api = tools
        .grafana
        .create(copilot_grafana::client::CONNECTOR)
        .await?;
    let links = explore_links(&tools.ctx.db, &name).await?;
    let uid = grafana_steps::create_datasource_on(
        &tools.ctx.db,
        tools.grafana,
        tools.wazuh,
        &api,
        org,
        &Datasource {
            name,
            database: format!("{}-{lower}*", definition.key),
            log_level_field: "syslog_level",
            log_message_field: "rule_description",
            data_links: Some(links),
        },
    )
    .await?;
    Ok(uid.py_str())
}

/// `ensure_account_is_free(...)`.
async fn ensure_account_is_free(
    pool: &Db,
    code: &str,
    instance: Option<&str>,
    keys: &AuthKeys,
) -> PyResult<()> {
    let account = &keys.account_id;
    let records = int_store::aws_instances(pool).await.map_err(db)?;
    for record in records {
        if record.customer_code == code && record.instance_name.as_deref() == instance {
            continue;
        }
        if record.account_id.as_deref() != Some(account.as_str()) {
            continue;
        }
        if record.customer_code != code {
            return Err(PyExc::http(
                400,
                format!(
                    "AWS account {account} is already configured for customer {}.",
                    record.customer_code
                ),
            ));
        }
        if record.bucket_name.as_deref() == Some(keys.bucket_name.as_str()) {
            return Err(PyExc::http(
                400,
                format!(
                    "AWS account {account} with bucket {} is already configured as this \
                     customer's '{}' AWS instance.",
                    keys.bucket_name,
                    record.instance_name.as_deref().unwrap_or("Default")
                ),
            ));
        }
    }
    Ok(())
}

/// The route's work once the body is read and the caller checked.
pub async fn provision(
    tools: Tools<'_>,
    code: &str,
    instance: Option<String>,
) -> PyResult<PyValue> {
    use copilot_integration_provisioning::integrations::integrations_of;
    let list = integrations_of(tools.ctx, code).await?;
    let instance = copilot_integrations::integrations::services::resolve_instance(
        tools.ctx,
        code,
        AWS_INTEGRATION_NAME,
        copilot_integrations::sql::normalize_instance_name(instance.as_deref()),
    )
    .await
    .map_err(api_exc)?;
    let found = list.iter().find(|ci| {
        ci.instance_name == instance
            && ci.subscriptions.iter().any(|s| {
                s.service
                    .as_ref()
                    .is_some_and(|v| v.service_name == AWS_INTEGRATION_NAME)
            })
    });
    let Some(ci) = found else {
        return Err(PyExc::http(
            404,
            format!(
                "AWS integration '{}' not found for customer {code}.",
                instance.as_deref().unwrap_or("Default")
            ),
        ));
    };
    let mut keys: Vec<(String, Option<String>)> = Vec::new();
    for sub in &ci.subscriptions {
        if sub
            .service
            .as_ref()
            .is_some_and(|v| v.service_name == AWS_INTEGRATION_NAME)
        {
            for k in &sub.keys {
                keys.push((k.auth_key_name.clone(), Some(k.auth_value.clone())));
            }
        }
    }
    if keys.is_empty() {
        return Err(PyExc::http(
            404,
            "No auth keys found for the AWS integration. Please create auth keys for the AWS \
             integration.",
        ));
    }
    let keys = parse_auth_keys(&keys).map_err(|detail| PyExc::http(400, detail))?;
    provision_aws(tools, code, &keys, instance.as_deref()).await
}

/// What the customer's metadata rows say exists already.
struct Shared<'a> {
    own_meta: Option<&'a int_store::Meta>,
    own_streams: &'a [(String, String)],
    shared_index_sets: &'a [(String, String)],
    shared_datasources: &'a [(String, String)],
    shared_folder: Option<&'a str>,
}

/// What the `try` hands to the code after it.
struct Deployed {
    restarted: bool,
    markers: (Option<serde_json::Value>, Option<serde_json::Value>),
    /// The ids the metadata row now holds.
    index_ids: Vec<(String, String)>,
    datasource_uids: Vec<(String, String)>,
    org: String,
}

/// `provision_aws(customer_code, keys, session, instance_name)`.
pub async fn provision_aws(
    tools: Tools<'_>,
    code: &str,
    keys: &AuthKeys,
    instance: Option<&str>,
) -> PyResult<PyValue> {
    let pool = &tools.ctx.db;
    let services = keys.service_configs();
    let mut wanted: Vec<String> = services.iter().map(|c| c.key().to_string()).collect();
    wanted.sort();
    wanted.dedup();
    tracing::info!(
        "Provisioning AWS for customer {code} (instance: {}, account {}, services {wanted:?}).",
        instance.unwrap_or("default"),
        keys.account_id
    );
    ensure_account_is_free(pool, code, instance, keys).await?;
    let today = chrono::Utc::now().date_naive();
    let validation =
        match validate::validate_aws_access(&Env::network(tools.env), keys, &services, today).await
        {
            Ok(v) => v,
            Err(Failure::Invalid(e)) => {
                return Err(PyExc::http(
                    400,
                    format!("AWS validation failed, nothing was changed: {e}"),
                ));
            }
            Err(Failure::Exc(e)) => return Err(e),
        };

    let metas = int_store::integration_metas(pool, code, AWS_INTEGRATION_NAME, None)
        .await
        .map_err(db)?;
    let own_index = metas
        .iter()
        .position(|m| m.instance_name.as_deref() == instance);
    let own_meta = own_index.map(|i| metas[i].clone());
    let siblings: Vec<int_store::Meta> = metas
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != own_index)
        .map(|(_, m)| m.clone())
        .collect();
    let own_streams = own_meta
        .as_ref()
        .map(|m| decode_service_ids(Some(&m.graylog_stream_id)))
        .unwrap_or_default();
    let mut shared_index_sets: Vec<(String, String)> = Vec::new();
    let mut shared_datasources: Vec<(String, String)> = Vec::new();
    for meta in &metas {
        for (service, id) in decode_service_ids(Some(&meta.graylog_index_id)) {
            if lookup(&shared_index_sets, &service).is_none() {
                shared_index_sets.push((service, id));
            }
        }
        for (service, uid) in decode_service_ids(meta.grafana_datasource_uid.as_deref()) {
            if lookup(&shared_datasources, &service).is_none() {
                shared_datasources.push((service, uid));
            }
        }
    }
    let shared_folder = metas
        .iter()
        .map(|m| m.grafana_dashboard_folder_id.clone())
        .find(|f| !f.is_empty());

    let mut rollback = Rollback::default();
    let mut warnings: Vec<String> = validation.warnings.clone();
    let shared = Shared {
        own_meta: own_meta.as_ref(),
        own_streams: &own_streams,
        shared_index_sets: &shared_index_sets,
        shared_datasources: &shared_datasources,
        shared_folder: shared_folder.as_deref(),
    };
    let outcome = deploy(
        tools,
        code,
        keys,
        instance,
        &shared,
        &mut rollback,
        &mut warnings,
    )
    .await;
    let deployed = match outcome {
        Ok(d) => d,
        Err(exc) => {
            tracing::error!(
                "AWS provisioning failed for customer {code}: {}. Rolling back.",
                detail_or_str(&exc)
            );
            let failures = rollback.run(tools, Style::Detail).await;
            let mut message = format!(
                "AWS deployment failed and was rolled back: {}",
                detail_or_str(&exc)
            );
            if !failures.is_empty() {
                message.push_str(" Some resources could not be removed automatically: ");
                message.push_str(&failures.join("; "));
                message.push('.');
            }
            return Err(failure(&exc, message));
        }
    };

    // Services a re-sync dropped: removed only now, after the new state is
    // recorded (a rollback could not undo these deletions). Python reads the
    // index sets, datasources and organization off `own_meta` here, which
    // `save_aws_meta` just rewrote in the same session (the identity map
    // hands it the same object): they no longer name a dropped service, so
    // only its stream goes — kept as it is (RUST_MIGRATION.md §4).
    let mut removed: Vec<String> = own_streams
        .iter()
        .map(|(s, _)| s.clone())
        .filter(|s| !wanted.contains(s))
        .collect();
    removed.sort();
    if !removed.is_empty() && own_meta.is_some() {
        let still_used = copilot_integrations::aws::decommission::services_in_use(&siblings);
        warnings.extend(
            remove_service_resources(
                tools.graylog,
                tools.grafana,
                &removed,
                &own_streams,
                &deployed.index_ids,
                &deployed.datasource_uids,
                Some(&deployed.org),
                &still_used,
            )
            .await,
        );
    }

    let detected = if deployed.restarted {
        notice::wait_for_profile_error(tools.wazuh, tools.env, &deployed.markers).await?
    } else {
        false
    };
    let suffix = match instance {
        Some(i) if !i.is_empty() => format!(" (instance {i})."),
        _ => ".".to_string(),
    };
    Ok(response(
        format!(
            "Successfully provisioned AWS {} for customer {code}{suffix}",
            wanted.join(", ")
        ),
        &warnings,
        aws_config_notice(detected, validation.bucket_region.as_deref()),
    ))
}

async fn deploy(
    tools: Tools<'_>,
    code: &str,
    keys: &AuthKeys,
    instance: Option<&str>,
    shared: &Shared<'_>,
    rollback: &mut Rollback,
    warnings: &mut Vec<String>,
) -> PyResult<Deployed> {
    let pool = &tools.ctx.db;
    let services = keys.service_configs();
    let markers = notice::log_markers(tools.wazuh).await?;

    // The manager: this instance's buckets in the aws-s3 wodle.
    let desired = desired_buckets(&services, &keys.bucket_keys(), &keys.only_logs_after());
    let reconcile = apply_instance_buckets(
        tools.wazuh,
        &desired,
        &keys.bucket_name,
        &keys.account_id,
        shared.own_meta.is_some(),
        keys.only_logs_after.is_none(),
    )
    .await?;
    let restarted = reconcile.changed;
    if reconcile.changed {
        rollback.add(
            format!(
                "the aws-s3 buckets for {} / account {}",
                keys.bucket_name, keys.account_id
            ),
            Undo::AwsBuckets {
                previous: reconcile.previous.clone(),
                bucket: keys.bucket_name.clone(),
                account: keys.account_id.clone(),
            },
        );
    }
    if reconcile.wodle_disabled {
        warnings.push(
            "The aws-s3 wodle on the Wazuh manager is disabled (<disabled>yes</disabled>). \
             CoPilot left that setting alone, so nothing is collected until it is enabled in \
             ossec.conf."
                .into(),
        );
    }

    // Graylog.
    ensure_pipeline_rules(tools).await?;
    let pipeline_id = ensure_pipeline(tools).await?;
    let mut index_ids: Vec<(String, String)> = Vec::new();
    let mut stream_ids: Vec<(String, String)> = Vec::new();
    for config in &services {
        let definition = config.definition;
        let reused_index =
            lookup(shared.shared_index_sets, definition.key).filter(|v| !v.is_empty());
        let index_id = match reused_index {
            Some(id) => {
                tracing::info!(
                    "Reusing this customer's AWS {} index set: {id}",
                    definition.title
                );
                id.to_string()
            }
            None => {
                let id = create_index_set(tools, code, definition).await?;
                rollback.add(
                    format!("Graylog index set {id}"),
                    Undo::IndexSet(id.clone()),
                );
                id
            }
        };
        set(&mut index_ids, definition.key, index_id.clone());
        let kept_stream = lookup(shared.own_streams, definition.key).filter(|v| !v.is_empty());
        let stream_id = match kept_stream {
            Some(id) => {
                tracing::info!(
                    "Keeping this instance's AWS {} stream: {id}",
                    definition.title
                );
                id.to_string()
            }
            None => {
                let id =
                    create_event_stream(tools, code, definition, keys, &index_id, instance).await?;
                rollback.add(format!("Graylog stream {id}"), Undo::Stream(id.clone()));
                connect_and_start_stream(tools, &id, &pipeline_id).await?;
                id
            }
        };
        set(&mut stream_ids, definition.key, stream_id);
    }

    // Grafana: the customer's folder, a datasource per service.
    let org = prov_store::grafana_org_id(pool, code).await?;
    let folder_id = match shared.shared_folder {
        Some(folder) => {
            tracing::info!("Reusing this customer's AWS Grafana folder {folder}.");
            folder.to_string()
        }
        None => {
            let folder =
                grafana_steps::create_folder(tools.grafana, &org, GRAFANA_FOLDER_TITLE).await?;
            let id = field(&folder, "id").py_str();
            rollback.add(
                format!("Grafana folder {id}"),
                Undo::Folder {
                    org: org.clone(),
                    folder: id.clone(),
                },
            );
            id
        }
    };
    let mut datasource_uids: Vec<(String, String)> = Vec::new();
    for config in &services {
        let definition = config.definition;
        let reused = lookup(shared.shared_datasources, definition.key).filter(|v| !v.is_empty());
        let uid = match reused {
            Some(uid) => uid.to_string(),
            None => {
                let uid = create_grafana_datasource(tools, code, definition, &org).await?;
                rollback.add(
                    format!("Grafana datasource {uid}"),
                    Undo::Datasource {
                        org: org.clone(),
                        uid: uid.clone(),
                    },
                );
                uid
            }
        };
        set(&mut datasource_uids, definition.key, uid);
    }

    // The metadata before `deployed`.
    let ids = MetaIds {
        index: &index_ids,
        stream: &stream_ids,
        org: &org,
        folder: &folder_id,
        datasource: &datasource_uids,
    };
    save_aws_meta(pool, code, instance, &ids).await?;
    set_deployed(pool, code, AWS_INTEGRATION_NAME, instance).await?;
    let saved = |pairs: &[(String, String)]| decode_service_ids(Some(&encode_service_ids(pairs)));
    Ok(Deployed {
        restarted,
        markers,
        index_ids: saved(&index_ids),
        datasource_uids: saved(&datasource_uids),
        org,
    })
}

/// `ids[key] = value` on an ordered dict.
fn set(ids: &mut Vec<(String, String)>, key: &str, value: String) {
    match ids.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => ids.push((key.to_string(), value)),
    }
}

/// What `save_aws_meta` records.
struct MetaIds<'a> {
    index: &'a [(String, String)],
    stream: &'a [(String, String)],
    org: &'a str,
    folder: &'a str,
    datasource: &'a [(String, String)],
}

/// `save_aws_meta(...)`: the instance's row created or updated.
async fn save_aws_meta(
    pool: &Db,
    code: &str,
    instance: Option<&str>,
    ids: &MetaIds<'_>,
) -> PyResult<()> {
    let clause = copilot_integrations::sql::instance_matches(
        "customer_integrations_meta.instance_name",
        instance,
    );
    let existing = int_store::integration_metas(pool, code, AWS_INTEGRATION_NAME, Some(&clause))
        .await
        .map_err(db)?;
    let (index, stream, uids) = (
        encode_service_ids(ids.index),
        encode_service_ids(ids.stream),
        encode_service_ids(ids.datasource),
    );
    match existing.first() {
        Some(meta) => {
            sqlx::query(
                "UPDATE customer_integrations_meta SET graylog_input_id=?, graylog_index_id=?, \
                 graylog_stream_id=?, grafana_org_id=?, grafana_dashboard_folder_id=?, \
                 grafana_datasource_uid=? WHERE customer_integrations_meta.id = ?",
            )
            .bind(None::<String>)
            .bind(&index)
            .bind(&stream)
            .bind(ids.org)
            .bind(ids.folder)
            .bind(&uids)
            .bind(meta.id)
            .execute(pool.pool())
            .await
            .map_err(db)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO customer_integrations_meta (customer_code, integration_name, \
                 graylog_input_id, graylog_index_id, graylog_stream_id, grafana_org_id, \
                 grafana_dashboard_folder_id, grafana_datasource_uid, instance_name) VALUES (?, \
                 ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(code)
            .bind(AWS_INTEGRATION_NAME)
            .bind(None::<String>)
            .bind(&index)
            .bind(&stream)
            .bind(ids.org)
            .bind(ids.folder)
            .bind(&uids)
            .bind(instance)
            .execute(pool.pool())
            .await
            .map_err(db)?;
        }
    }
    tracing::info!(
        "AWS integration meta saved for customer {code} (instance: {}).",
        instance.unwrap_or("default")
    );
    Ok(())
}
