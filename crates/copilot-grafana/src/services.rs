//! `app/connectors/grafana/services/` (`reporting.py`'s reads, `user.py`)
//! and the route bodies of `routes/reporting.py`, line by line: what each
//! service catches and wraps (`Failed to collect …: {e}`), and what the
//! routes leave to the handlers (a response model's `ValidationError` is the
//! `ValueError` handler's 400, a subscript's `KeyError` a bare 500).

use chrono::{Datelike, Local, NaiveDateTime, TimeZone, Timelike};
use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, getitem, iterate, py_eq};

use crate::client::{CONNECTOR, GrafanaClient};
use crate::schema::{
    GRAFANA_DASHBOARD_DETAILS_RESPONSE, GRAFANA_DASHBOARD_PANELS_RESPONSE,
    GRAFANA_DASHBOARD_RESPONSE, GRAFANA_GENERATE_IFRAME_LINKS_RESPONSE,
    GRAFANA_ORGANIZATIONS_RESPONSE, PANEL, USER_ORGANIZATION_ADD_RESPONSE,
};

fn s(v: &str) -> PyValue {
    PyValue::Str(v.into())
}

fn wrap(prefix: &str) -> impl Fn(PyExc) -> PyExc + '_ {
    move |e| PyExc::http(500, format!("{prefix}: {}", e.display()))
}

/// `GET /reporting/orgs`: `get_orgs()` then the response model.
pub async fn orgs(client: &GrafanaClient) -> PyResult<PyValue> {
    let orgs = async {
        let api = client.create(CONNECTOR).await?;
        client.list_organizations(&api).await
    }
    .await
    .map_err(wrap("Failed to collect organizations"))?;
    construct(
        &GRAFANA_ORGANIZATIONS_RESPONSE,
        &kwargs(vec![
            ("message", s("Organizations collected from Grafana")),
            ("orgs", orgs),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

/// `GET /reporting/dashboards/{org_id}`: the organization is switched to,
/// then searched (`get_dashboards`).
pub async fn dashboards(client: &GrafanaClient, org_id: &str) -> PyResult<PyValue> {
    let dashboards = async {
        let api = client.create(CONNECTOR).await?;
        client.switch_organization(&api, org_id).await?;
        client.search_dashboards(&api).await
    }
    .await
    .map_err(wrap("Failed to collect dashboards"))?;
    construct(
        &GRAFANA_DASHBOARD_RESPONSE,
        &kwargs(vec![
            ("message", s("Dashboards collected from Grafana")),
            ("dashboards", dashboards),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

/// `get_dashboard_details(uid)`: Grafana's answer, unvalidated.
async fn details(client: &GrafanaClient, uid: &str) -> PyResult<PyValue> {
    async {
        let api = client.create(CONNECTOR).await?;
        client.get_dashboard(&api, uid).await
    }
    .await
    .map_err(wrap("Failed to collect dashboard details"))
}

/// `GET /reporting/dashboard/{dashboard_uid}`.
pub async fn dashboard_details(client: &GrafanaClient, uid: &str) -> PyResult<PyValue> {
    let details = details(client, uid).await?;
    construct(
        &GRAFANA_DASHBOARD_DETAILS_RESPONSE,
        &kwargs(vec![
            ("message", s("Dashboard details collected from Grafana")),
            ("dashboard_details", details),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

/// `GET /reporting/dashboard_panels/{dashboard_uid}`: the dashboard's
/// top-level panels but rows, as `Panel(id=…, title=…)`.
pub async fn dashboard_panels(client: &GrafanaClient, uid: &str) -> PyResult<PyValue> {
    let details = details(client, uid).await?;
    let mut panels = Vec::new();
    for panel in iterate(getitem(getitem(&details, "dashboard")?, "panels")?)? {
        if !py_eq(getitem(&panel, "type")?, &s("row")) {
            let id = getitem(&panel, "id")?.clone();
            let title = getitem(&panel, "title")?.clone();
            panels.push(construct(
                &PANEL,
                &kwargs(vec![("id", id), ("title", title)]),
            )?);
        }
    }
    construct(
        &GRAFANA_DASHBOARD_PANELS_RESPONSE,
        &kwargs(vec![
            ("message", s("Panels collected from Grafana")),
            ("panels", PyValue::List(panels)),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

fn overflow() -> PyExc {
    PyExc::Other("OverflowError", "date value out of range".into())
}

/// `int(time.mktime(dt.timetuple()))`: a local wall-clock time, to the
/// second, as epoch seconds.
fn mktime(dt: NaiveDateTime) -> i64 {
    let dt = dt.with_nanosecond(0).unwrap_or(dt);
    match Local.from_local_datetime(&dt) {
        chrono::LocalResult::Single(t) | chrono::LocalResult::Ambiguous(t, _) => t.timestamp(),
        chrono::LocalResult::None => dt.and_utc().timestamp(),
    }
}

/// `calculate_unix_timestamps(time_range)`: `(from, to)` in milliseconds,
/// from `datetime.now()` (local time) and `now - timedelta(...)`.
pub fn unix_timestamps(value: &str, unit: &str, now: NaiveDateTime) -> PyResult<(i64, i64)> {
    let per_unit: i128 = match unit {
        "m" => 60,
        "h" => 3600,
        _ => 86_400,
    };
    let value: i128 = value.parse().map_err(|_| overflow())?;
    let seconds = value.checked_mul(per_unit).ok_or_else(overflow)?;
    // `timedelta` holds at most 999,999,999 days.
    if seconds.unsigned_abs() / 86_400 > 999_999_999 {
        return Err(overflow());
    }
    let delta = chrono::TimeDelta::try_seconds(i64::try_from(seconds).map_err(|_| overflow())?)
        .ok_or_else(overflow)?;
    let start = now.checked_sub_signed(delta).ok_or_else(overflow)?;
    if !(1..=9999).contains(&start.year()) {
        return Err(overflow());
    }
    Ok((mktime(start) * 1000, mktime(now) * 1000))
}

/// `POST /reporting/generate_iframe_links` (the route's own
/// `generate_panel_urls`, without `&theme=`). `request` is the validated
/// body.
pub async fn iframe_links(db: &Db, request: &PyValue) -> PyResult<PyValue> {
    let row = copilot_db::connectors::find_by_name(db, CONNECTOR)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .ok_or_else(|| {
            PyExc::AttributeError("'NoneType' object has no attribute 'connector_url'".into())
        })?;
    let range = field(request, "time_range");
    let (from, to) = unix_timestamps(
        &field(range, "value").py_str(),
        &field(range, "unit").py_str(),
        Local::now().naive_local(),
    )?;
    let panel_id = field(request, "panel_id").clone();
    let url = format!(
        "{}/d-solo/{}/{}?orgId={}&from={from}&to={to}&panelId={}",
        row.connector_url,
        field(request, "dashboard_uid").py_str(),
        field(request, "dashboard_title").py_str(),
        field(request, "org_id").py_str(),
        panel_id.py_str(),
    );
    construct(
        &GRAFANA_GENERATE_IFRAME_LINKS_RESPONSE,
        &kwargs(vec![
            ("message", s("Iframe links generated from Grafana")),
            (
                "links",
                PyValue::List(vec![kwargs(vec![
                    ("panel_id", panel_id),
                    ("panel_url", PyValue::Str(url)),
                ])]),
            ),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

/// `POST /user/user/organization/add` (`add_user_to_organization`). Its
/// answer builds `UserOrganizationAddResponse(message=…, status="success")`,
/// a model whose `success` is required: once Grafana has added the user,
/// that `ValidationError` is what the route answers (500, wrapped).
pub async fn add_user(client: &GrafanaClient, request: &PyValue) -> PyResult<PyValue> {
    let api = client.create(CONNECTOR).await?;
    let login = field(request, "loginorEmail").clone();
    let org = field(request, "organizationId").py_str();
    async {
        let user = kwargs(vec![
            ("loginorEmail", login.clone()),
            ("role", field(request, "role").clone()),
        ]);
        client.add_organization_user(&api, &org, user).await?;
        construct(
            &USER_ORGANIZATION_ADD_RESPONSE,
            &kwargs(vec![
                (
                    "message",
                    PyValue::Str(format!(
                        "User {} added to organization {org}",
                        login.py_str()
                    )),
                ),
                ("status", s("success")),
            ]),
        )
    }
    .await
    .map_err(wrap("Error adding user to organization"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_count_back_from_now() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 10, 15)
            .unwrap()
            .and_hms_micro_opt(10, 0, 0, 999_999)
            .unwrap();
        let (from, to) = unix_timestamps("7", "d", now).unwrap();
        assert_eq!(to - from, 7 * 86_400 * 1000);
        assert_eq!(to % 1000, 0);
        let (from, to) = unix_timestamps("-30", "m", now).unwrap();
        assert_eq!(from - to, 30 * 60 * 1000);
        assert_eq!(
            unix_timestamps("1000000000", "d", now).unwrap_err().text(),
            "date value out of range"
        );
        assert!(
            unix_timestamps("999999999", "d", now).is_err(),
            "before year 1"
        );
        assert!(unix_timestamps("99999999999999999999999", "m", now).is_err());
    }
}
