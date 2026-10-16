//! `app/connectors/influxdb/services/` — the alerts read from the
//! `_monitoring` bucket's `statuses` (`alerts.py`, #1118's current-state
//! rule) and the Telegraf metrics (`metrics.py`), line by line: the same
//! Flux text, the same order of queries, and the same answers when
//! something fails (most failures are a `success: false` answer carrying
//! `str(e)`, not an error status).

use std::collections::HashMap;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, PyResult};

use crate::client::{FluxSession, InfluxClient};
use crate::flux::{FluxRecord, FluxTable, FluxValue, py_isoformat, py_order, sort_desc};
use crate::schema::{HOSTS_RESPONSE, INFLUXDB_ALERT, INFLUXDB_CHECK_NAMES_RESPONSE};

/// The bucket the alerts are read from.
pub const MONITORING_BUCKET: &str = "_monitoring";
/// The org the alerts use when the connector's cannot be read.
pub const FALLBACK_ORG: &str = "SOCFORTRESS";

/// `STATE_TAGS`: tags whose value is the monitored state, not the thing.
pub const STATE_TAGS: [&str; 4] = ["active", "sub", "load", "mode"];

/// `RANGE_WINDOWS`: the `aggregateWindow` for an hour range (else `5m`).
pub const RANGE_WINDOWS: [(&str, &str); 9] = [
    ("1", "1m"),
    ("3", "2m"),
    ("6", "5m"),
    ("12", "10m"),
    ("24", "20m"),
    ("48", "30m"),
    ("72", "1h"),
    ("168", "2h"),
    ("720", "12h"),
];

/// Validated `/alerts` query parameters (`GetInfluxDBAlertQueryParams`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertParams {
    /// `days` (1–90).
    pub days: i64,
    /// `severity` (`SeverityFilter` values), `None` when not given.
    pub severity: Option<Vec<String>>,
    /// `check_name`.
    pub check_name: Option<String>,
    /// `sensor_type`.
    pub sensor_type: Option<String>,
    /// `status` (`active`, `cleared`, `all`).
    pub status: String,
    /// `latest_only`.
    pub latest_only: bool,
    /// `exclude_ok`.
    pub exclude_ok: bool,
    /// `limit` (1–1000).
    pub limit: Option<i64>,
}

impl Default for AlertParams {
    fn default() -> Self {
        Self {
            days: 7,
            severity: None,
            check_name: None,
            sensor_type: None,
            status: "all".into(),
            latest_only: false,
            exclude_ok: false,
            limit: Some(500),
        }
    }
}

/// `CancelledError` is a `BaseException`: no `except Exception` catches it.
fn uncaught(e: PyExc) -> PyResult<PyExc> {
    match e {
        PyExc::Other("CancelledError", _) => Err(e),
        other => Ok(other),
    }
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.into())
}

fn int(n: usize) -> PyValue {
    PyValue::Int(n.to_string())
}

// --- alerts -----------------------------------------------------------------------------------

/// `flux_string`: a Flux string literal (`\`, `"` and `${` escaped).
pub fn flux_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace("${", "\\${")
    )
}

/// `build_status_query`: the statuses every alert query starts from.
pub fn build_status_query(bucket: &str, p: &AlertParams) -> String {
    let mut lines = vec!["import \"regexp\"".to_string()];
    let mut filters = Vec::new();
    if let Some(name) = p.check_name.as_deref().filter(|n| !n.is_empty()) {
        lines.push(format!(
            "check_name_pattern = regexp.compile(v: regexp.quoteMeta(v: {}))",
            flux_string(name)
        ));
        filters.push("|> filter(fn: (r) => r._check_name =~ check_name_pattern)");
    }
    if let Some(sensor) = p.sensor_type.as_deref().filter(|n| !n.is_empty()) {
        lines.push(format!(
            "sensor_type_pattern = regexp.compile(v: regexp.quoteMeta(v: {}))",
            flux_string(sensor)
        ));
        filters.push("|> filter(fn: (r) => r._check_name =~ sensor_type_pattern)");
    }
    lines.push(format!("from(bucket: {})", flux_string(bucket)));
    lines.push(format!("    |> range(start: -{}d)", p.days));
    lines.push(
        "    |> filter(fn: (r) => r._measurement == \"statuses\" and r._field == \"_message\")"
            .into(),
    );
    lines.push(
        "    |> filter(fn: (r) => exists r._check_id and exists r._check_name and exists \
         r._level)"
            .into(),
    );
    lines.extend(filters.iter().map(|f| format!("    {f}")));
    lines.join("\n")
}

/// `LEVELS_BY_SEVERITY` over the requested severities, sorted (`None`: all).
pub fn selected_levels(p: &AlertParams) -> Option<Vec<String>> {
    let severity = p.severity.as_ref().filter(|s| !s.is_empty())?;
    let mut levels: Vec<String> = severity
        .iter()
        .map(|sev| {
            match sev.as_str() {
                "critical" | "error" => "crit",
                "warning" => "warn",
                "ok" => "ok",
                other => other,
            }
            .to_string()
        })
        .collect();
    levels.sort();
    levels.dedup();
    Some(levels)
}

/// `series_identity`: the check plus the tags naming the monitored thing.
pub type Identity = (String, Vec<(String, String)>);

/// `series_identity(record.values)`.
pub fn series_identity(record: &FluxRecord) -> Identity {
    let mut tags: Vec<(String, String)> = record
        .values
        .iter()
        .filter(|(k, v)| {
            !matches!(v, FluxValue::None)
                && !k.starts_with('_')
                && !STATE_TAGS.contains(&k.as_str())
                && k != "result"
                && k != "table"
        })
        .map(|(k, v)| (k.clone(), v.py_str()))
        .collect();
    tags.sort();
    let check = record
        .get("_check_id")
        .map_or_else(|| "unknown".to_string(), FluxValue::py_str);
    (check, tags)
}

/// `latest_by_identity`: the newest record per monitored thing, in the
/// order the things first appeared (an OK never hides a problem written at
/// the same instant).
pub fn latest_by_identity<'a>(
    records: impl Iterator<Item = &'a FluxRecord>,
) -> PyResult<Vec<(Identity, FluxRecord)>> {
    let mut latest: Vec<(Identity, FluxRecord)> = Vec::new();
    let mut index: HashMap<Identity, usize> = HashMap::new();
    for record in records {
        let identity = series_identity(record);
        match index.get(&identity) {
            None => {
                index.insert(identity.clone(), latest.len());
                latest.push((identity, record.clone()));
            }
            Some(&i) => {
                let current = &latest[i].1;
                let newer = py_order(">", record.time()?, current.time()?)?;
                let replace = newer
                    || (record.time()?.py_eq(current.time()?)
                        && current.value_or_none("_level").is_str("ok"));
                if replace {
                    latest[i].1 = record.clone();
                }
            }
        }
    }
    Ok(latest)
}

fn not_iterable(v: &FluxValue) -> PyExc {
    let name = match v {
        FluxValue::Time(_) => "datetime.datetime",
        other => other.type_name(),
    };
    PyExc::TypeError(format!("argument of type '{name}' is not iterable"))
}

/// `check_name.split()[0] if " " in check_name else check_name`.
fn sensor_type(check_name: &FluxValue) -> PyResult<FluxValue> {
    match check_name {
        FluxValue::Str(name) if name.contains(' ') => name
            .split(copilot_web::form::is_py_space)
            .find(|p| !p.is_empty())
            .map(|p| FluxValue::Str(p.to_string()))
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        FluxValue::Str(_) => Ok(check_name.clone()),
        FluxValue::Bytes(_) => Err(PyExc::TypeError(
            "a bytes-like object is required, not 'str'".into(),
        )),
        other => Err(not_iterable(other)),
    }
}

/// A cell as Pydantic receives it for a `datetime` field.
fn datetime_input(v: &FluxValue) -> PyValue {
    match v {
        FluxValue::Time(t) => PyValue::Str(py_isoformat(t)),
        other => other.to_py(),
    }
}

/// `build_alert(record, current_level)`: the `InfluxDBAlert` dump.
pub fn build_alert(record: &FluxRecord, current_level: &FluxValue) -> PyResult<PyValue> {
    let unknown = FluxValue::Str("unknown".into());
    let level = record.get("_level").unwrap_or(&unknown);
    let check_name = record.get("_check_name").unwrap_or(&unknown);
    let time = datetime_input(record.time()?);
    let sensor = sensor_type(check_name)?;
    let severity = match level {
        FluxValue::Str(l) if l == "crit" => s("critical"),
        FluxValue::Str(l) if l == "warn" => s("warning"),
        other => other.to_py(),
    };
    let message = record
        .get("_value")
        .map_or_else(|| s("No message"), FluxValue::to_py);
    let status = if !level.is_str("ok") && !current_level.is_str("ok") {
        "active"
    } else {
        "cleared"
    };
    let check_id = record
        .get("_check_id")
        .map_or_else(|| "unknown".to_string(), FluxValue::py_str);
    construct(
        &INFLUXDB_ALERT,
        &kwargs(vec![
            ("time", time),
            ("check_name", check_name.to_py()),
            ("sensor_type", sensor.to_py()),
            ("severity", severity),
            ("message", message),
            ("status", s(status)),
            ("check_id", PyValue::Str(check_id)),
        ]),
    )
}

/// An `InfluxDBAlertResponse` dump.
pub fn alert_response(
    success: bool,
    message: &str,
    alerts: Vec<PyValue>,
    counts: [usize; 4],
) -> PyValue {
    let [total, filtered, active, cleared] = counts;
    PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(success)),
        ("message".into(), s(message)),
        ("alerts".into(), PyValue::List(alerts)),
        ("total_count".into(), int(total)),
        ("filtered_count".into(), int(filtered)),
        ("active_alerts_count".into(), int(active)),
        ("cleared_alerts_count".into(), int(cleared)),
    ])
}

fn records(tables: &[FluxTable]) -> impl Iterator<Item = &FluxRecord> {
    tables.iter().flat_map(|t| t.records.iter())
}

async fn alerts_inner(
    client: &InfluxClient,
    session: &FluxSession,
    org: &str,
    p: &AlertParams,
) -> PyResult<PyValue> {
    let status_query = build_status_query(MONITORING_BUCKET, p);
    let state_query = format!("{status_query}\n    |> last()");
    let state_tables = client.query(session, &state_query, org).await?;
    let latest = latest_by_identity(records(&state_tables))?;
    let current_level: HashMap<Identity, FluxValue> = latest
        .iter()
        .map(|(id, r)| (id.clone(), r.value_or_none("_level").clone()))
        .collect();
    let levels = selected_levels(p);
    let limit = p.limit.filter(|l| *l != 0).unwrap_or(500);
    let wanted = |record: &FluxRecord| {
        let level = record.value_or_none("_level");
        if let Some(levels) = &levels {
            if !levels.iter().any(|l| level.is_str(l)) {
                return false;
            }
        }
        !(p.exclude_ok && level.is_str("ok"))
    };
    let rows: Vec<FluxRecord> = if p.latest_only {
        let mut keyed = Vec::new();
        for (_, record) in latest.into_iter().filter(|(_, r)| wanted(r)) {
            keyed.push((record.time()?.clone(), record));
        }
        sort_desc(&mut keyed)?;
        keyed.into_iter().map(|(_, r)| r).collect()
    } else {
        let mut rows_query = status_query.clone();
        if let Some(levels) = &levels {
            let alternatives: Vec<String> = levels
                .iter()
                .map(|l| format!("r._level == {}", flux_string(l)))
                .collect();
            rows_query.push_str(&format!(
                "\n    |> filter(fn: (r) => {})",
                alternatives.join(" or ")
            ));
        }
        if p.exclude_ok {
            rows_query.push_str("\n    |> filter(fn: (r) => r._level != \"ok\")");
        }
        rows_query.push_str(&format!(
            "\n    |> group()\n    |> sort(columns: [\"_time\"], desc: true)\n    |> limit(n: \
             {limit})"
        ));
        let tables = client.query(session, &rows_query, org).await?;
        records(&tables).cloned().collect()
    };
    let mut alerts = Vec::with_capacity(rows.len());
    for record in &rows {
        let identity = series_identity(record);
        let current = match current_level.get(&identity) {
            Some(level) => level.clone(),
            None => record
                .get("_level")
                .cloned()
                .unwrap_or_else(|| FluxValue::Str("unknown".into())),
        };
        alerts.push(build_alert(record, &current)?);
    }
    let status_of = |a: &PyValue| {
        a.get("status")
            .and_then(PyValue::as_str)
            .map(str::to_string)
    };
    match p.status.as_str() {
        "active" => alerts.retain(|a| status_of(a).as_deref() == Some("active")),
        "cleared" => alerts.retain(|a| status_of(a).as_deref() == Some("cleared")),
        _ => {}
    }
    alerts.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let total = alerts.len();
    let active = alerts
        .iter()
        .filter(|a| status_of(a).as_deref() == Some("active"))
        .count();
    let cleared = alerts
        .iter()
        .filter(|a| status_of(a).as_deref() == Some("cleared"))
        .count();
    Ok(alert_response(
        true,
        "Successfully retrieved InfluxDB alerts",
        alerts,
        [total, total, active, cleared],
    ))
}

/// `get_influxdb_alerts(query_params)`.
pub async fn alerts(client: &InfluxClient, p: &AlertParams) -> PyResult<PyValue> {
    let failed = |message: String| alert_response(false, &message, Vec::new(), [0; 4]);
    if client.row().await?.is_none() {
        return Ok(failed("InfluxDB connector not found".into()));
    }
    let org = client
        .organization()
        .await
        .unwrap_or_else(|_| FALLBACK_ORG.to_string());
    let session = match client.create_client().await {
        Ok(session) => session,
        Err(e) => {
            return Ok(failed(format!(
                "Failed to connect to InfluxDB: {}",
                e.display()
            )));
        }
    };
    match alerts_inner(client, &session, &org, p).await {
        Ok(answer) => Ok(answer),
        Err(e) => Ok(failed(format!(
            "Error querying InfluxDB: {}",
            uncaught(e)?.display()
        ))),
    }
}

/// The text of `get_influxdb_check_names`'s query (its indentation included).
pub fn check_names_query(bucket: &str) -> String {
    let (i8, i12) = (" ".repeat(8), " ".repeat(12));
    [
        String::new(),
        format!("{i8}from(bucket: \"{bucket}\")"),
        format!("{i12}|> range(start: -30d)"),
        format!(
            "{i12}|> filter(fn: (r) => r._measurement == \"statuses\" and r._field == \"_message\")"
        ),
        format!("{i12}|> filter(fn: (r) => exists r._check_name)"),
        format!("{i12}|> group(columns: [\"_check_name\"])"),
        format!("{i12}|> distinct(column: \"_check_name\")"),
        format!("{i12}|> keep(columns: [\"_check_name\"])"),
        i8,
    ]
    .join("\n")
}

/// `sorted(set(values))`: unique by Python equality, ascending.
fn sorted_unique(values: Vec<FluxValue>) -> PyResult<Vec<FluxValue>> {
    let mut unique: Vec<FluxValue> = Vec::new();
    for v in values {
        if !unique.iter().any(|u| u.py_eq(&v)) {
            unique.push(v);
        }
    }
    for pair in unique.windows(2) {
        py_order("<", &pair[1], &pair[0])?;
    }
    unique.sort_by(|a, b| {
        if py_order("<", a, b).unwrap_or(false) {
            std::cmp::Ordering::Less
        } else if py_order("<", b, a).unwrap_or(false) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    Ok(unique)
}

fn check_names_response(success: bool, message: &str, names: Vec<PyValue>) -> PyResult<PyValue> {
    let total = names.len();
    construct(
        &INFLUXDB_CHECK_NAMES_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(success)),
            ("message", s(message)),
            ("check_names", PyValue::List(names)),
            ("total_count", int(total)),
        ]),
    )
}

/// `get_influxdb_check_names()`.
pub async fn check_names(client: &InfluxClient) -> PyResult<PyValue> {
    if client.row().await?.is_none() {
        return check_names_response(false, "InfluxDB connector not found", Vec::new());
    }
    let org = client
        .organization()
        .await
        .unwrap_or_else(|_| FALLBACK_ORG.to_string());
    let session = match client.create_client().await {
        Ok(session) => session,
        Err(e) => {
            return check_names_response(
                false,
                &format!("Failed to connect to InfluxDB: {}", e.display()),
                Vec::new(),
            );
        }
    };
    let inner = async {
        let tables = client
            .query(&session, &check_names_query(MONITORING_BUCKET), &org)
            .await?;
        let names: Vec<FluxValue> = records(&tables)
            .filter_map(|r| r.get("_check_name"))
            .filter(|v| v.truthy())
            .cloned()
            .collect();
        let names = sorted_unique(names)?;
        check_names_response(
            true,
            "Successfully retrieved check names",
            names.iter().map(FluxValue::to_py).collect(),
        )
    };
    match inner.await {
        Ok(answer) => Ok(answer),
        Err(e) => check_names_response(
            false,
            &format!("Error querying InfluxDB: {}", uncaught(e)?.display()),
            Vec::new(),
        ),
    }
}

// --- metrics ----------------------------------------------------------------------------------

/// `_window(range_h)`.
pub fn window(range_h: &str) -> &'static str {
    RANGE_WINDOWS
        .iter()
        .find(|(h, _)| *h == range_h)
        .map_or("5m", |(_, w)| w)
}

/// What a metrics query ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    Last,
    Mean,
    RateMean,
}

/// One metrics query, in the shape every one in `metrics.py` has.
struct MetricQuery<'a> {
    measurement: &'a str,
    fields: &'a [&'a str],
    cpu_total: bool,
    tail: Tail,
}

impl MetricQuery<'_> {
    fn flux(&self, bucket: &str, host: &str, range_h: &str) -> String {
        let fields: Vec<String> = self
            .fields
            .iter()
            .map(|f| format!("r[\"_field\"] == \"{f}\""))
            .collect();
        let mut out = format!(
            "from(bucket: \"{bucket}\") |> range(start: -{range_h}h)\n  |> filter(fn: (r) => \
             r[\"_measurement\"] == \"{}\")\n  |> filter(fn: (r) => {})\n",
            self.measurement,
            fields.join(" or ")
        );
        if self.cpu_total {
            out.push_str("  |> filter(fn: (r) => r[\"cpu\"] == \"cpu-total\")\n");
        }
        out.push_str(&format!(
            "  |> filter(fn: (r) => r[\"host\"] == \"{host}\")\n"
        ));
        let mean = format!(
            "  |> aggregateWindow(every: {}, fn: mean, createEmpty: false)",
            window(range_h)
        );
        match self.tail {
            Tail::Last => out.push_str("  |> last()"),
            Tail::Mean => out.push_str(&mean),
            Tail::RateMean => {
                out.push_str("  |> derivative(unit: 1s, nonNegative: true)\n");
                out.push_str(&mean);
            }
        }
        out
    }
}

const fn q<'a>(
    measurement: &'a str,
    fields: &'a [&'a str],
    cpu_total: bool,
    tail: Tail,
) -> MetricQuery<'a> {
    MetricQuery {
        measurement,
        fields,
        cpu_total,
        tail,
    }
}

/// How a query's tables become a value of `data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `_parse_ts_series(result, label_field=…)`.
    Series(&'static str),
    /// `_last_value(result)`.
    Last,
    /// The sum of every finite `float(value)` (`disk_total`).
    Sum,
}

/// A metrics route: its queries (key, query, shape) and its messages.
pub struct Metrics {
    what: &'static str,
    queries: Vec<(&'static str, MetricQuery<'static>, Shape)>,
}

const FIELD: Shape = Shape::Series("_field");

impl Metrics {
    /// `get_summary`.
    pub fn summary() -> Self {
        Self {
            what: "summary",
            queries: vec![
                (
                    "uptime",
                    q("system", &["uptime"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "total_mem",
                    q("mem", &["total"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "cpus",
                    q("system", &["n_cpus"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "total_processes",
                    q("processes", &["total"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "cpu_idle",
                    q("cpu", &["usage_idle"], true, Tail::Last),
                    Shape::Last,
                ),
                (
                    "logged_on_users",
                    q("system", &["n_users"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "swap_free",
                    q("swap", &["free"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "load",
                    q("system", &["load1", "load5", "load15"], false, Tail::Mean),
                    FIELD,
                ),
            ],
        }
    }

    /// `get_cpu_metrics`.
    pub fn cpu() -> Self {
        Self {
            what: "CPU metrics",
            queries: vec![
                (
                    "cpu_usage_system",
                    q("cpu", &["usage_system"], true, Tail::Mean),
                    FIELD,
                ),
                (
                    "cpu_usage_user",
                    q("cpu", &["usage_user"], true, Tail::Mean),
                    FIELD,
                ),
                (
                    "cpu_iowait",
                    q("cpu", &["usage_iowait"], true, Tail::Mean),
                    FIELD,
                ),
                (
                    "cpu_softirq",
                    q("cpu", &["usage_softirq"], true, Tail::Mean),
                    FIELD,
                ),
            ],
        }
    }

    /// `get_memory_metrics`.
    pub fn memory() -> Self {
        Self {
            what: "memory metrics",
            queries: vec![
                (
                    "mem_used",
                    q("mem", &["used", "total"], false, Tail::Mean),
                    FIELD,
                ),
                (
                    "swap_total",
                    q("swap", &["total"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "swap_free",
                    q("swap", &["free"], false, Tail::Last),
                    Shape::Last,
                ),
            ],
        }
    }

    /// `get_kernel_metrics`.
    pub fn kernel() -> Self {
        Self {
            what: "kernel metrics",
            queries: vec![
                (
                    "interrupts",
                    q("kernel", &["interrupts"], false, Tail::RateMean),
                    FIELD,
                ),
                (
                    "processes_forked",
                    q("kernel", &["processes_forked"], false, Tail::RateMean),
                    FIELD,
                ),
            ],
        }
    }

    /// `get_disk_metrics`.
    pub fn disks() -> Self {
        Self {
            what: "disk metrics",
            queries: vec![
                (
                    "disk_total",
                    q("disk", &["total"], false, Tail::Last),
                    Shape::Sum,
                ),
                (
                    "disk_usage",
                    q("disk", &["used_percent"], false, Tail::Mean),
                    Shape::Series("path"),
                ),
                (
                    "disk_io",
                    q(
                        "diskio",
                        &["read_bytes", "write_bytes"],
                        false,
                        Tail::RateMean,
                    ),
                    Shape::Series("name"),
                ),
                (
                    "inodes",
                    q("disk", &["inodes_used", "inodes_total"], false, Tail::Mean),
                    Shape::Series("path"),
                ),
            ],
        }
    }

    /// `get_process_metrics`.
    pub fn processes() -> Self {
        let mut queries = vec![(
            "status",
            q(
                "processes",
                &["running", "sleeping", "zombies", "stopped", "blocked"],
                false,
                Tail::Mean,
            ),
            FIELD,
        )];
        for (key, field) in [
            ("running", &["running"]),
            ("sleeping", &["sleeping"]),
            ("unknown", &["unknown"]),
            ("zombies", &["zombies"]),
        ] {
            queries.push((key, q("processes", field, false, Tail::Last), Shape::Last));
        }
        Self {
            what: "process metrics",
            queries,
        }
    }

    /// `get_network_metrics`.
    pub fn network() -> Self {
        Self {
            what: "network metrics",
            queries: vec![
                (
                    "traffic",
                    q("net", &["bytes_recv", "bytes_sent"], false, Tail::RateMean),
                    Shape::Series("interface"),
                ),
                (
                    "tcp_established",
                    q("netstat", &["tcp_established"], false, Tail::Last),
                    Shape::Last,
                ),
                (
                    "interface_errors",
                    q("net", &["err_in", "err_out"], false, Tail::Mean),
                    Shape::Series("interface"),
                ),
            ],
        }
    }

    /// The Flux text of each query, in order.
    pub fn fluxes(&self, bucket: &str, host: &str, range_h: &str) -> Vec<(&'static str, String)> {
        self.queries
            .iter()
            .map(|(key, query, _)| (*key, query.flux(bucket, host, range_h)))
            .collect()
    }
}

/// `record.get_time().isoformat()`.
fn isoformat(v: &FluxValue) -> PyResult<String> {
    match v {
        FluxValue::Time(t) => Ok(py_isoformat(t)),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'isoformat'",
            other.type_name()
        ))),
    }
}

/// `_parse_ts_series(result, label_field)`.
pub fn parse_ts_series(tables: &[FluxTable], label_field: &str) -> PyResult<PyValue> {
    let mut series: Vec<(FluxValue, Vec<PyValue>)> = Vec::new();
    for record in records(tables) {
        let label = match record.get(label_field) {
            Some(v) => v.clone(),
            None => record
                .get("_field")
                .cloned()
                .unwrap_or_else(|| FluxValue::Str("unknown".into())),
        };
        let time = isoformat(record.time()?)?;
        let value = record.value()?.to_py();
        let point = PyValue::Dict(vec![
            ("time".into(), PyValue::Str(time)),
            ("value".into(), value),
        ]);
        match series.iter_mut().find(|(k, _)| k.py_eq(&label)) {
            Some((_, points)) => points.push(point),
            None => series.push((label, vec![point])),
        }
    }
    Ok(PyValue::Dict(
        series
            .into_iter()
            .map(|(k, points)| (k.json_key(), PyValue::List(points)))
            .collect(),
    ))
}

/// `_last_value(result)`.
pub fn last_value(tables: &[FluxTable]) -> PyResult<PyValue> {
    match records(tables).next() {
        Some(record) => Ok(record.value()?.to_py()),
        None => Ok(PyValue::None),
    }
}

/// `float(value)` where it succeeds (`disk_total` skips the rest).
fn as_float(v: &FluxValue) -> Option<f64> {
    match v {
        FluxValue::Float(f) => Some(*f),
        FluxValue::Int(i) => i.parse::<f64>().ok(),
        FluxValue::Bool(b) => Some(f64::from(u8::from(*b))),
        FluxValue::Str(t) => crate::flux::py_float(t).ok(),
        FluxValue::Bytes(b) => crate::flux::py_float(&String::from_utf8_lossy(b)).ok(),
        FluxValue::None | FluxValue::Time(_) => None,
    }
}

fn disk_total(tables: &[FluxTable]) -> PyResult<PyValue> {
    let mut total = 0.0_f64;
    for record in records(tables) {
        if let Some(v) = as_float(record.value()?) {
            if v.is_finite() {
                total += v;
            }
        }
    }
    Ok(PyValue::Float(total))
}

/// A `MetricsResponse` dump.
pub fn metrics_response(success: bool, message: &str, data: Vec<(String, PyValue)>) -> PyValue {
    PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(success)),
        ("message".into(), s(message)),
        ("data".into(), PyValue::Dict(data)),
    ])
}

/// `_get_influxdb_bucket(session)` (`ValueError`s) then
/// `get_influxdb_organization()`.
async fn bucket_and_org(client: &InfluxClient) -> PyResult<(String, String)> {
    let row = client
        .row()
        .await?
        .ok_or_else(|| PyExc::ValueError("No InfluxDB connector found in the database".into()))?;
    let extra = row.connector_extra_data.as_deref().ok_or_else(|| {
        PyExc::AttributeError("'NoneType' object has no attribute 'split'".into())
    })?;
    let parts: Vec<&str> = extra.split(',').collect();
    let Some(bucket) = parts.get(1) else {
        return Err(PyExc::ValueError(
            "Invalid connector_extra_data format for InfluxDB. Expected 'ORG,BUCKET'.".into(),
        ));
    };
    let bucket = copilot_web::form::py_strip(bucket).to_string();
    let org = client.organization().await?;
    Ok((bucket, org))
}

/// One metrics route (`get_summary`, `get_cpu_metrics`, …).
pub async fn metrics(
    client: &InfluxClient,
    route: &Metrics,
    host: &str,
    range_h: &str,
) -> PyResult<PyValue> {
    let (bucket, org) = match bucket_and_org(client).await {
        Ok(v) => v,
        Err(e) => return Ok(metrics_response(false, &e.display(), Vec::new())),
    };
    let session = client.create_client().await?;
    let mut data = Vec::new();
    for ((key, flux), (_, _, shape)) in route
        .fluxes(&bucket, host, range_h)
        .into_iter()
        .zip(&route.queries)
    {
        let result = async {
            let tables = client.query(&session, &flux, &org).await?;
            match shape {
                Shape::Series(label) => parse_ts_series(&tables, label),
                Shape::Last => last_value(&tables),
                Shape::Sum => disk_total(&tables),
            }
        };
        match result.await {
            Ok(value) => data.push((key.to_string(), value)),
            Err(e) => {
                return Ok(metrics_response(
                    false,
                    &format!("Error fetching {}: {}", route.what, uncaught(e)?.display()),
                    Vec::new(),
                ));
            }
        }
    }
    Ok(metrics_response(
        true,
        &format!("Successfully retrieved {}", route.what),
        data,
    ))
}

fn hosts_response(success: bool, message: &str, hosts: Vec<PyValue>) -> PyResult<PyValue> {
    construct(
        &HOSTS_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(success)),
            ("message", s(message)),
            ("hosts", PyValue::List(hosts)),
        ]),
    )
}

/// The Flux text of `get_hosts`.
pub fn hosts_query(bucket: &str) -> String {
    format!(
        "import \"influxdata/influxdb/schema\"\nschema.tagValues(bucket: \"{bucket}\", tag: \"host\")"
    )
}

/// `get_hosts()`.
pub async fn hosts(client: &InfluxClient) -> PyResult<PyValue> {
    if client.row().await?.is_none() {
        return hosts_response(false, "InfluxDB connector not found", Vec::new());
    }
    let (bucket, org) = match bucket_and_org(client).await {
        Ok(v) => v,
        Err(e) => return hosts_response(false, &e.display(), Vec::new()),
    };
    let session = client.create_client().await?;
    let inner = async {
        let tables = client.query(&session, &hosts_query(&bucket), &org).await?;
        let mut values = Vec::new();
        for record in records(&tables) {
            if record.value()?.truthy() {
                values.push(record.value()?.clone());
            }
        }
        let hosts = sorted_unique(values)?;
        hosts_response(
            true,
            "Successfully retrieved hosts",
            hosts.iter().map(FluxValue::to_py).collect(),
        )
    };
    match inner.await {
        Ok(answer) => Ok(answer),
        Err(e) => hosts_response(
            false,
            &format!("Error fetching hosts: {}", uncaught(e)?.display()),
            Vec::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flux::parse_tables;

    #[test]
    fn status_queries_match_the_python_text() {
        let p = AlertParams {
            check_name: Some("CPU \"x\" ${y} \\".into()),
            sensor_type: Some("Disk".into()),
            ..AlertParams::default()
        };
        assert_eq!(
            build_status_query("_monitoring", &p),
            "import \"regexp\"\ncheck_name_pattern = regexp.compile(v: regexp.quoteMeta(v: \"CPU \
             \\\"x\\\" \\${y} \\\\\"))\nsensor_type_pattern = regexp.compile(v: \
             regexp.quoteMeta(v: \"Disk\"))\nfrom(bucket: \"_monitoring\")\n    |> range(start: \
             -7d)\n    |> filter(fn: (r) => r._measurement == \"statuses\" and r._field == \
             \"_message\")\n    |> filter(fn: (r) => exists r._check_id and exists r._check_name \
             and exists r._level)\n    |> filter(fn: (r) => r._check_name =~ \
             check_name_pattern)\n    |> filter(fn: (r) => r._check_name =~ sensor_type_pattern)"
        );
        let p = AlertParams {
            severity: Some(vec!["error".into(), "critical".into(), "ok".into()]),
            ..AlertParams::default()
        };
        assert_eq!(selected_levels(&p), Some(vec!["crit".into(), "ok".into()]));
    }

    #[test]
    fn metric_queries_match_the_python_text() {
        let fluxes = Metrics::summary().fluxes("telegraf", "web-01", "3");
        assert_eq!(
            fluxes[4].1,
            "from(bucket: \"telegraf\") |> range(start: -3h)\n  |> filter(fn: (r) => \
             r[\"_measurement\"] == \"cpu\")\n  |> filter(fn: (r) => r[\"_field\"] == \
             \"usage_idle\")\n  |> filter(fn: (r) => r[\"cpu\"] == \"cpu-total\")\n  |> \
             filter(fn: (r) => r[\"host\"] == \"web-01\")\n  |> last()"
        );
        let fluxes = Metrics::network().fluxes("telegraf", "h", "999");
        assert_eq!(
            fluxes[0].1,
            "from(bucket: \"telegraf\") |> range(start: -999h)\n  |> filter(fn: (r) => \
             r[\"_measurement\"] == \"net\")\n  |> filter(fn: (r) => r[\"_field\"] == \
             \"bytes_recv\" or r[\"_field\"] == \"bytes_sent\")\n  |> filter(fn: (r) => \
             r[\"host\"] == \"h\")\n  |> derivative(unit: 1s, nonNegative: true)\n  |> \
             aggregateWindow(every: 5m, fn: mean, createEmpty: false)"
        );
        let keys: Vec<_> = Metrics::processes()
            .fluxes("b", "h", "1")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            ["status", "running", "sleeping", "unknown", "zombies"]
        );
    }

    const STATES: &str = "#datatype,string,long,dateTime:RFC3339,string,string,string,string,string\r\n\
        #group,false,false,false,true,true,true,true,true\r\n\
        #default,_result,,,,,,,\r\n\
        ,result,table,_time,_check_id,_check_name,_level,host,active\r\n\
        ,,0,2026-10-15T10:00:00Z,c1,CRITICAL SERVICES CHECK,crit,h1,failed\r\n\
        ,,1,2026-10-15T10:05:00Z,c1,CRITICAL SERVICES CHECK,ok,h1,active\r\n\
        ,,2,2026-10-15T10:05:00Z,c1,CRITICAL SERVICES CHECK,crit,h2,failed\r\n\
        ,,3,2026-10-15T10:05:00Z,c1,CRITICAL SERVICES CHECK,ok,h2,active\r\n\r\n";

    #[test]
    fn a_recovery_clears_the_failure_and_ok_never_hides_a_problem() {
        let tables = parse_tables(STATES).unwrap();
        let latest = latest_by_identity(records(&tables)).unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].0.1, vec![("host".to_string(), "h1".to_string())]);
        assert!(latest[0].1.value_or_none("_level").is_str("ok"));
        assert!(latest[1].1.value_or_none("_level").is_str("crit"));
        let alert = build_alert(&tables[0].records[0], &FluxValue::Str("ok".into())).unwrap();
        assert_eq!(
            copilot_upstream::json::pydantic_json(&alert),
            "{\"time\":\"2026-10-15T10:00:00Z\",\"check_name\":\"CRITICAL SERVICES \
             CHECK\",\"sensor_type\":\"CRITICAL\",\"severity\":\"critical\",\"message\":\"No \
             message\",\"status\":\"cleared\",\"check_id\":\"c1\"}"
        );
    }

    #[test]
    fn series_follow_the_label_and_fail_like_python() {
        let csv = "#datatype,string,long,dateTime:RFC3339,double,string,string\r\n\
            #group,false,false,false,false,true,true\r\n#default,_result,,,,,\r\n\
            ,result,table,_time,_value,_field,path\r\n\
            ,,0,2026-10-15T10:00:00Z,1.5,used_percent,/\r\n\
            ,,1,2026-10-15T10:00:00Z,NaN,used_percent,\r\n\r\n";
        let tables = parse_tables(csv).unwrap();
        assert_eq!(
            copilot_upstream::json::pydantic_json(&parse_ts_series(&tables, "path").unwrap()),
            "{\"/\":[{\"time\":\"2026-10-15T10:00:00+00:00\",\"value\":1.5}],\"None\":[{\"time\":\
             \"2026-10-15T10:00:00+00:00\",\"value\":null}]}"
        );
        assert_eq!(disk_total(&tables).unwrap(), PyValue::Float(1.5));
        let csv = "#datatype,string,long,string\r\n#group,false,false,true\r\n#default,_result,,\r\n\
            ,result,table,host\r\n,,0,a\r\n\r\n";
        let tables = parse_tables(csv).unwrap();
        assert_eq!(parse_ts_series(&tables, "x").unwrap_err().text(), "'_time'");
        assert_eq!(last_value(&tables).unwrap_err().text(), "'_value'");
    }

    #[test]
    fn sensor_types() {
        assert_eq!(
            sensor_type(&FluxValue::Str("CPU CHECK".into())).unwrap(),
            FluxValue::Str("CPU".into())
        );
        assert_eq!(
            sensor_type(&FluxValue::Str("   ".into()))
                .unwrap_err()
                .text(),
            "list index out of range"
        );
        assert_eq!(
            sensor_type(&FluxValue::None).unwrap_err().text(),
            "argument of type 'NoneType' is not iterable"
        );
    }
}
