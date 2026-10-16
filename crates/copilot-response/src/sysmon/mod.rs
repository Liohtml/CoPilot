//! `/api/sysmon_config`: customers' Sysmon configs in MinIO, deployed to the
//! Wazuh master's provisioning worker.

pub mod routes;
pub mod schema;
pub mod services;
pub mod worker;
