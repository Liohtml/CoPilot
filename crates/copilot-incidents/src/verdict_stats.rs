//! Triage-verdict statistics — port of `app/incidents/services/verdict_stats.py`
//! (`GET /incidents/db_operations/alerts/verdict-stats`).
//!
//! The grouped queries keep SQLAlchemy's shape (`GROUP BY`, `HAVING`, the
//! `ORDER BY` — or its absence), so MySQL orders tied groups the same way
//! for both backends; the sums are cast in the select list only (sqlx cannot
//! read MySQL's `DECIMAL` sum as an integer).

use std::collections::BTreeMap;

use chrono::{Datelike, NaiveDateTime};
use serde::Serialize;
use sqlx::{MySql, QueryBuilder};

use copilot_core::time::py_round;
use copilot_db::{Db, DbError};

use crate::store::push_list;

const FALSE_POSITIVE: &str = "FALSE_POSITIVE";
const TRUE_POSITIVE: &str = "TRUE_POSITIVE";

/// `FalsePositiveRuleStat`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuleStat {
    /// Alert title.
    pub alert_name: String,
    /// False positives.
    pub false_positive: i64,
    /// Reviewed.
    pub reviewed: i64,
    /// Percentage of reviewed.
    pub false_positive_rate: Option<f64>,
}

/// `FalsePositiveCustomerStat`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CustomerStat {
    /// Tenant.
    pub customer_code: String,
    /// False positives.
    pub false_positive: i64,
    /// Reviewed.
    pub reviewed: i64,
    /// Percentage of reviewed.
    pub false_positive_rate: Option<f64>,
}

/// `VerdictTrendPoint`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TrendPoint {
    /// `YYYY-MM`.
    pub month: String,
    /// False positives.
    pub false_positive: i64,
    /// True positives.
    pub true_positive: i64,
    /// Untriaged.
    pub untriaged: i64,
    /// Percentage of reviewed.
    pub false_positive_rate: Option<f64>,
}

/// `VerdictStatsResponse`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VerdictStats {
    /// Reviewed + untriaged.
    pub total: i64,
    /// True + false positives.
    pub reviewed: i64,
    /// No verdict.
    pub untriaged: i64,
    /// True positives.
    pub true_positive: i64,
    /// False positives.
    pub false_positive: i64,
    /// Percentage of reviewed.
    pub false_positive_rate: Option<f64>,
    /// Percentage triaged.
    pub coverage_rate: Option<f64>,
    /// `(reason, count)`, most common first.
    pub by_reason: Vec<(String, i64)>,
    /// The noisiest detections.
    pub by_alert_name: Vec<RuleStat>,
    /// Per tenant.
    pub by_customer: Vec<CustomerStat>,
    /// Per month.
    pub trend: Vec<TrendPoint>,
    /// Always true.
    pub success: bool,
    /// Message.
    pub message: String,
}

impl VerdictStats {
    /// The answer for "the requested customers resolve to nothing".
    pub fn empty() -> Self {
        Self {
            total: 0,
            reviewed: 0,
            untriaged: 0,
            true_positive: 0,
            false_positive: 0,
            false_positive_rate: None,
            coverage_rate: None,
            by_reason: Vec::new(),
            by_alert_name: Vec::new(),
            by_customer: Vec::new(),
            trend: Vec::new(),
            success: true,
            message: "No alerts found for the requested customers".into(),
        }
    }
}

fn rate(part: i64, whole: i64) -> Option<f64> {
    (whole != 0).then(|| py_round(part as f64 / whole as f64 * 100.0, 1))
}

fn push_window<'a>(
    qb: &mut QueryBuilder<'a, MySql>,
    codes: Option<&'a [String]>,
    from: NaiveDateTime,
    to: NaiveDateTime,
) {
    qb.push(" WHERE a.alert_creation_time >= ")
        .push_bind(from)
        .push(" AND a.alert_creation_time <= ")
        .push_bind(to);
    if let Some(codes) = codes.filter(|c| !c.is_empty()) {
        qb.push(" AND a.customer_code IN (");
        push_list(qb, codes.iter().map(String::as_str));
        qb.push(")");
    }
}

const FP_SUM: &str = "sum(CASE WHEN (a.verdict = 'FALSE_POSITIVE') THEN 1 ELSE 0 END)";
const REVIEWED_SUM: &str = "sum(CASE WHEN (a.verdict IS NOT NULL) THEN 1 ELSE 0 END)";

/// Every section of the statistics (`codes = None`: no tenant constraint).
pub async fn compute(
    db: &Db,
    codes: Option<&[String]>,
    from: NaiveDateTime,
    to: NaiveDateTime,
    alert_name_limit: i64,
) -> Result<VerdictStats, DbError> {
    // verdict_counts
    let mut qb =
        QueryBuilder::<MySql>::new("SELECT a.verdict, count(*) FROM incident_management_alert a");
    push_window(&mut qb, codes, from, to);
    qb.push(" GROUP BY a.verdict");
    let counts: Vec<(Option<String>, i64)> = qb.build_query_as().fetch_all(db.pool()).await?;
    let get = |want: Option<&str>| {
        counts
            .iter()
            .rev()
            .find(|(v, _)| v.as_deref() == want)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };
    let false_positive = get(Some(FALSE_POSITIVE));
    let true_positive = get(Some(TRUE_POSITIVE));
    let untriaged = get(None);
    let reviewed = false_positive + true_positive;
    let total = reviewed + untriaged;

    // false_positives_by_reason
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT a.verdict_reason, count(*) FROM incident_management_alert a",
    );
    push_window(&mut qb, codes, from, to);
    qb.push(" AND a.verdict = 'FALSE_POSITIVE' GROUP BY a.verdict_reason ORDER BY count(*) DESC");
    let by_reason: Vec<(Option<String>, i64)> = qb.build_query_as().fetch_all(db.pool()).await?;
    let by_reason = by_reason
        .into_iter()
        .map(|(r, n)| (r.unwrap_or_else(|| "UNSPECIFIED".into()), n))
        .collect();

    // top_false_positives_by_alert_name
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT a.alert_name, CAST({FP_SUM} AS SIGNED), CAST({REVIEWED_SUM} AS SIGNED) \
         FROM incident_management_alert a"
    ));
    push_window(&mut qb, codes, from, to);
    qb.push(format!(
        " GROUP BY a.alert_name HAVING {FP_SUM} > 0 ORDER BY {FP_SUM} DESC LIMIT "
    ));
    qb.push_bind(alert_name_limit);
    let rows: Vec<(Option<String>, Option<i64>, Option<i64>)> =
        qb.build_query_as().fetch_all(db.pool()).await?;
    let by_alert_name = rows
        .into_iter()
        .map(|(name, fp, rev)| {
            let (fp, rev) = (fp.unwrap_or(0), rev.unwrap_or(0));
            RuleStat {
                alert_name: name
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "Unknown".into()),
                false_positive: fp,
                reviewed: rev,
                false_positive_rate: rate(fp, rev),
            }
        })
        .collect();

    // false_positives_by_customer
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT a.customer_code, CAST({FP_SUM} AS SIGNED), CAST({REVIEWED_SUM} AS SIGNED) \
         FROM incident_management_alert a"
    ));
    push_window(&mut qb, codes, from, to);
    qb.push(format!(
        " GROUP BY a.customer_code HAVING {REVIEWED_SUM} > 0"
    ));
    let rows: Vec<(Option<String>, Option<i64>, Option<i64>)> =
        qb.build_query_as().fetch_all(db.pool()).await?;
    let mut by_customer: Vec<CustomerStat> = rows
        .into_iter()
        .map(|(code, fp, rev)| {
            let (fp, rev) = (fp.unwrap_or(0), rev.unwrap_or(0));
            CustomerStat {
                customer_code: code
                    .filter(|c| !c.is_empty())
                    .unwrap_or_else(|| "Unknown".into()),
                false_positive: fp,
                reviewed: rev,
                false_positive_rate: rate(fp, rev),
            }
        })
        .collect();
    // `rows.sort(key=lambda r: (r[3] or 0, r[1]), reverse=True)`: stable.
    by_customer.sort_by(|a, b| {
        let key = |s: &CustomerStat| (s.false_positive_rate.unwrap_or(0.0), s.false_positive);
        let (ka, kb) = (key(a), key(b));
        kb.0.partial_cmp(&ka.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(kb.1.cmp(&ka.1))
    });

    // false_positive_trend
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT a.alert_creation_time, a.verdict FROM incident_management_alert a",
    );
    push_window(&mut qb, codes, from, to);
    let rows: Vec<(Option<NaiveDateTime>, Option<String>)> =
        qb.build_query_as().fetch_all(db.pool()).await?;
    let mut buckets: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    for (created, verdict) in rows {
        let Some(created) = created else { continue };
        let key = format!("{:04}-{:02}", created.year(), created.month());
        let b = buckets.entry(key).or_default();
        match verdict.as_deref() {
            Some(FALSE_POSITIVE) => b.0 += 1,
            Some(TRUE_POSITIVE) => b.1 += 1,
            _ => b.2 += 1,
        }
    }
    let trend = buckets
        .into_iter()
        .map(|(month, (fp, tp, un))| TrendPoint {
            month,
            false_positive: fp,
            true_positive: tp,
            untriaged: un,
            false_positive_rate: rate(fp, fp + tp),
        })
        .collect();

    Ok(VerdictStats {
        total,
        reviewed,
        untriaged,
        true_positive,
        false_positive,
        false_positive_rate: rate(false_positive, reviewed),
        coverage_rate: rate(reviewed, total),
        by_reason,
        by_alert_name,
        by_customer,
        trend,
        success: true,
        message: "Verdict statistics retrieved successfully".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_round_like_python() {
        // round(1 / 3 * 100, 1) == 33.3; round(2 / 3 * 100, 1) == 66.7
        assert_eq!(rate(1, 3), Some(33.3));
        assert_eq!(rate(2, 3), Some(66.7));
        assert_eq!(rate(1, 0), None);
        assert_eq!(serde_json::to_string(&rate(3, 3)).unwrap(), "100.0");
    }
}
