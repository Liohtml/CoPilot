//! The AWS integration's Wazuh side — what the delete of a deployed AWS
//! instance shares with AWS provisioning (`copilot-cloud-provisioning`):
//!
//! - [`services`] — `app/integrations/aws/utils/services.py`: the services
//!   table, `SERVICES` parsed, S3 prefixes, `only_logs_after`, the
//!   `service:id` pairs of the metadata row;
//! - [`config`] — `services/wazuh_config.py`: the `aws-s3` wodle reconcile
//!   and its safety check, on [`crate::etree`];
//! - [`manager`] — `services/wazuh_manager.py`'s write path: read, re-read,
//!   write, validate, restore, restart, under [`manager::WAZUH_CONFIG_LOCK`];
//! - [`decommission`] — `services/decommission.py`.

pub mod config;
pub mod decommission;
pub mod manager;
pub mod services;
