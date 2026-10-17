//! `app/integrations/aws/services/decommission.py`: one AWS instance taken
//! out of the Wazuh manager, Graylog and Grafana.
//!
//! An AWS instance records one index set, stream and datasource *per
//! service* (`service:id` pairs, [`super::services`]): the stream always
//! goes, a service's index set and datasource only when no sibling instance
//! still collects that service, the Grafana folder with the customer's last
//! instance. Every failure is a warning.

use copilot_db::Db;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_upstream::py::PyExc;
use copilot_wazuh::WazuhState;

use crate::integrations::cleanup;
use crate::integrations::store::{self, Meta};
use crate::sql::instance_differs;

use super::manager::apply_instance_buckets;
use super::services::{decode_service_ids, lookup};

/// `remove_service_resources(services, stream_ids, index_ids,
/// datasource_uids, grafana_org_id, keep_shared)`: the warnings.
#[allow(clippy::too_many_arguments)]
pub async fn remove_service_resources(
    graylog: &GraylogClient,
    grafana: &GrafanaClient,
    services: &[String],
    stream_ids: &[(String, String)],
    index_ids: &[(String, String)],
    datasource_uids: &[(String, String)],
    grafana_org_id: Option<&str>,
    keep_shared: &[String],
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut attempt = |description: String, outcome: Result<(), PyExc>| {
        if let Err(e) = outcome {
            tracing::warn!("Failed to delete {description}: {}", e.display());
            warnings.push(format!(
                "Could not delete {description}: {}. Remove it manually if it still exists.",
                e.display()
            ));
        }
    };
    for service in services {
        if let Some(id) = lookup(stream_ids, service).filter(|v| !v.is_empty()) {
            attempt(
                format!("Graylog stream {id}"),
                cleanup::delete_stream(graylog, id).await,
            );
        }
        if keep_shared.contains(service) {
            continue;
        }
        if let Some(id) = lookup(index_ids, service).filter(|v| !v.is_empty()) {
            attempt(
                format!("Graylog index set {id}"),
                cleanup::delete_index(graylog, id).await,
            );
        }
        if let Some(org) = grafana_org_id.filter(|o| !o.is_empty()) {
            if let Some(uid) = lookup(datasource_uids, service).filter(|v| !v.is_empty()) {
                attempt(
                    format!("Grafana datasource {uid}"),
                    cleanup::delete_datasource(grafana, org, uid).await,
                );
            }
        }
    }
    warnings
}

/// `_sibling_metas(customer_code, instance_name)`: the customer's other AWS
/// instances' metadata rows.
pub async fn sibling_metas(
    db: &Db,
    code: &str,
    instance: Option<&str>,
) -> Result<Vec<Meta>, sqlx::Error> {
    let clause = instance_differs("customer_integrations_meta.instance_name", instance);
    store::integration_metas(db, code, crate::integrations::AWS, Some(&clause)).await
}

/// The services a set of metadata rows still collect (their streams).
pub fn services_in_use(metas: &[Meta]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in metas {
        for (service, _) in decode_service_ids(Some(&m.graylog_stream_id)) {
            if !out.contains(&service) {
                out.push(service);
            }
        }
    }
    out
}

/// `cleanup_aws_infrastructure(meta, customer_code, instance_name, session,
/// cleanup_warnings)`.
pub async fn cleanup_aws_infrastructure(
    db: &Db,
    graylog: &GraylogClient,
    grafana: &GrafanaClient,
    meta: &Meta,
    code: &str,
    instance: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<(), sqlx::Error> {
    let siblings = sibling_metas(db, code, instance).await?;
    let still_used = services_in_use(&siblings);
    let stream_ids = decode_service_ids(Some(&meta.graylog_stream_id));
    let mut services: Vec<String> = stream_ids.iter().map(|(s, _)| s.clone()).collect();
    services.sort();
    warnings.extend(
        remove_service_resources(
            graylog,
            grafana,
            &services,
            &stream_ids,
            &decode_service_ids(Some(&meta.graylog_index_id)),
            &decode_service_ids(meta.grafana_datasource_uid.as_deref()),
            Some(&meta.grafana_org_id),
            &still_used,
        )
        .await,
    );
    if !siblings.is_empty() {
        tracing::info!("Other AWS instances of {code} remain; keeping the AWS Grafana folder.");
        return Ok(());
    }
    if !meta.grafana_org_id.is_empty() && !meta.grafana_dashboard_folder_id.is_empty() {
        let folder = &meta.grafana_dashboard_folder_id;
        if let Err(e) = cleanup::delete_folder(grafana, &meta.grafana_org_id, folder).await {
            tracing::warn!("Failed to delete Grafana folder {folder}: {}", e.display());
            warnings.push(format!(
                "Could not delete Grafana folder {folder}: {}. Remove it manually if it still \
                 exists.",
                e.display()
            ));
        }
    }
    Ok(())
}

/// `decommission_aws_instance(bucket_name, account_id)`.
pub async fn decommission_aws_instance(
    st: &WazuhState,
    bucket_name: &str,
    account_id: &str,
) -> Result<(), PyExc> {
    let result = apply_instance_buckets(st, &[], bucket_name, account_id, true, true).await?;
    if !result.changed {
        tracing::info!(
            "No aws-s3 buckets for {bucket_name} / account {account_id} on the Wazuh manager; \
             nothing to remove."
        );
    }
    Ok(())
}
