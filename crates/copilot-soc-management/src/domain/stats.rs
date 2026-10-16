//! Duration statistics — port of `soc_management/domain/stats.py`.
//!
//! The headline figure is the **median**; the mean and the 90th percentile
//! are reported alongside. Every operation follows CPython's float
//! arithmetic step by step (left-to-right `sum`, the interpolation as
//! written, `round(x, 1)`), so the numbers — and their JSON — are the same.

use copilot_core::time::py_round;

/// `DurationStats`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DurationStats {
    /// How many values.
    pub count: i64,
    /// Mean, one decimal.
    pub mean: Option<f64>,
    /// Median, one decimal.
    pub median: Option<f64>,
    /// 90th percentile, one decimal.
    pub p90: Option<f64>,
}

/// `percentile(sorted_values, q)`: linear interpolation, `q` in [0, 100].
pub fn percentile(sorted: &[f64], q: i64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let position = ((sorted.len() as i64 - 1) * q) as f64 / 100.0;
    let lower = position.floor();
    let upper = position.ceil();
    let (lo, hi) = (lower as usize, upper as usize);
    if lo == hi {
        return Some(sorted[lo]);
    }
    let weight = position - lower;
    Some(sorted[lo] * (1.0 - weight) + sorted[hi] * weight)
}

/// `describe(seconds)`: `None` and negative values are ignored.
pub fn describe(seconds: impl IntoIterator<Item = Option<f64>>) -> DurationStats {
    let mut values: Vec<f64> = seconds
        .into_iter()
        .flatten()
        .filter(|v| *v >= 0.0)
        .collect();
    if values.is_empty() {
        return DurationStats::default();
    }
    values.sort_by(f64::total_cmp);
    let sum = values.iter().fold(0.0, |acc, v| acc + v);
    let n = values.len();
    DurationStats {
        count: n as i64,
        mean: Some(py_round(sum / n as f64, 1)),
        median: percentile(&values, 50).map(|v| py_round(v, 1)),
        p90: percentile(&values, 90).map(|v| py_round(v, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python() {
        // describe([60, 120, None, -5, 600]) in Python:
        // count=3 mean=260.0 median=120.0 p90=504.0
        let s = describe([Some(60.0), Some(120.0), None, Some(-5.0), Some(600.0)]);
        assert_eq!(s.count, 3);
        assert_eq!(s.mean, Some(260.0));
        assert_eq!(s.median, Some(120.0));
        assert_eq!(s.p90, Some(504.0));
        assert_eq!(describe([None]), DurationStats::default());
        // round(sum/len, 1) on a value that is not exact: (1+2+2)/3 = 1.666… → 1.7
        assert_eq!(describe([Some(1.0), Some(2.0), Some(2.0)]).mean, Some(1.7));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50), Some(2.5));
        assert_eq!(percentile(&[], 50), None);
    }
}
