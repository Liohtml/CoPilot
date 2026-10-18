//! `verify_influxdb_connection(name)`: the row's URL is logged before the
//! `None` check (a missing row: no outcome), the client is built with
//! `get_influxdb_organization()` outside the `try` (its failure: no
//! outcome), then `client.ping()` (`GET /ping`, `copilot-influxdb`) and the
//! legacy `get_alerts()` — the `_monitoring` statuses of the last hour
//! through a fresh `create_influxdb_client("InfluxDB")`, each record built
//! into `InfluxDBAlert` from keys the model does not declare, so any record
//! is its `ValidationError` (`Failed to fetch alerts from InfluxDB: …`).
//! Whatever raises in the `try` is the failure naming `str(e)`.

use async_trait::async_trait;

use copilot_auth::pyvalue::PyValue;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_influxdb::InfluxClient;
use copilot_influxdb::client::FluxSession;
use copilot_influxdb::flux::{FluxValue, py_isoformat};
use copilot_influxdb::schema::INFLUXDB_ALERT;
use copilot_upstream::model::construct;
use copilot_upstream::py::{PyExc, PyResult};

use crate::outcome;

/// `BUCKET_NAME`.
pub const BUCKET_NAME: &str = "_monitoring";

/// `construct_query()`, as `str.format` leaves it.
pub fn construct_query() -> String {
    let lines = [
        format!("from(bucket: \"{BUCKET_NAME}\")"),
        "|> range(start: -1h, stop: now())".into(),
        "|> filter(fn: (r) => r._measurement == \"statuses\" and r._field == \"_message\")".into(),
        "|> filter(fn: (r) => exists r._check_id and exists r._value and exists r._check_name and \
         exists r._level)"
            .into(),
        "|> keep(columns: [\"_time\", \"_value\", \"_check_id\", \"_check_name\", \"_level\"])"
            .into(),
        "|> rename(columns: { \"_time\": \"time\", \"_value\": \"message\", \"_check_id\": \
         \"checkID\", \"_check_name\": \"checkName\", \"_level\": \"level\" })"
            .into(),
        "|> group()".into(),
        "|> sort(columns: [\"time\"], desc: true)".into(),
        "|> limit(n: 100, offset: 29)".into(),
    ];
    let mut out = String::from("\n");
    for line in &lines {
        out.push_str("        ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("    ");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_is_python_s() {
        let want = "\n        from(bucket: \"_monitoring\")\n        |> range(start: -1h, stop: now())\n        |> filter(fn: (r) => r._measurement == \"statuses\" and r._field == \"_message\")\n        |> filter(fn: (r) => exists r._check_id and exists r._value and exists r._check_name and exists r._level)\n        |> keep(columns: [\"_time\", \"_value\", \"_check_id\", \"_check_name\", \"_level\"])\n        |> rename(columns: { \"_time\": \"time\", \"_value\": \"message\", \"_check_id\": \"checkID\", \"_check_name\": \"checkName\", \"_level\": \"level\" })\n        |> group()\n        |> sort(columns: [\"time\"], desc: true)\n        |> limit(n: 100, offset: 29)\n    ";
        assert_eq!(construct_query(), want);
    }
}

/// The InfluxDB verifier.
#[derive(Debug, Clone)]
pub struct InfluxDbVerifier(pub InfluxClient);

fn value(v: Option<&FluxValue>) -> PyValue {
    v.map_or(PyValue::None, FluxValue::to_py)
}

/// `get_alerts()`: `HTTPException(500, …)` for any failure inside its
/// `try`, the client's own when it cannot be built.
async fn get_alerts(client: &InfluxClient) -> PyResult<()> {
    let session = client.create_client().await?;
    let inner: PyResult<()> = async {
        let org = client.organization().await?;
        let tables = client.query(&session, &construct_query(), &org).await?;
        for table in &tables {
            for record in &table.records {
                let time = match record.get("time") {
                    Some(FluxValue::Time(t)) => PyValue::Str(py_isoformat(t)),
                    Some(v) if v.truthy() => {
                        return Err(PyExc::AttributeError(format!(
                            "'{}' object has no attribute 'isoformat'",
                            v.type_name()
                        )));
                    }
                    _ => PyValue::None,
                };
                let kwargs = PyValue::Dict(vec![
                    ("time".into(), time),
                    ("message".into(), value(record.get("message"))),
                    ("checkID".into(), value(record.get("checkID"))),
                    ("checkName".into(), value(record.get("checkName"))),
                    ("level".into(), value(record.get("level"))),
                ]);
                construct(&INFLUXDB_ALERT, &kwargs)?;
            }
        }
        Ok(())
    }
    .await;
    inner.map_err(|e| {
        PyExc::http(
            500,
            format!("Failed to fetch alerts from InfluxDB: {}", e.display()),
        )
    })
}

#[async_trait]
impl ConnectorVerifier for InfluxDbVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = connectors.get(name).await.ok()??;
        let url = row.connector_url.clone();
        tracing::info!("Verifying the InfluxDB connection to {url}");
        // `org=await get_influxdb_organization()`, outside the `try`.
        self.0.organization().await.ok()?;
        let session = FluxSession {
            url: url.clone(),
            token: row.connector_api_key.clone(),
        };
        let result: PyResult<()> = async {
            self.0.ping(&session).await?;
            tracing::info!("Connection to {url} successful");
            get_alerts(&self.0).await
        }
        .await;
        match result {
            Ok(()) => outcome(true, "InfluxDB connection successful"),
            Err(e) => {
                let text = format!("Connection to {url} failed with error: {}", e.display());
                tracing::error!("{text}");
                outcome(false, text)
            }
        }
    }
}
