//! Rows → response models: `build_alert_out`, `get_alert_by_id`,
//! `get_case_by_id` and the `CaseOut` loops of `services/db_operations.py`.
//!
//! The response models validate what they are built from: an IoC whose
//! stored `type` is not an `AlertIocValue` makes `IoCBase(...)` raise a
//! Pydantic `ValidationError`, which is a `ValueError` and therefore the
//! backend's 400 `{"success": false, "message": str(e)}` — on every route
//! that loads that alert, access checks included. [`ioc_out`] reproduces it.

use std::collections::HashMap;

use copilot_db::Db;
use copilot_web::ApiError;

use crate::schema::{
    AlertOut, AssetOut, CaseCommentOut, CaseOut, CommentOut, IOC_TYPES, IocOut, LinkedCaseOut,
    TagOut,
};
use crate::store::{self, AlertChildren, AlertRow, CaseRow, Include, IocRow};

/// Python's `repr()` of a `str` (an enum's `ValueError`, an f-string's
/// `{x!r}`).
pub fn py_str_repr(s: &str) -> String {
    copilot_auth::pyvalue::str_repr(s)
}

/// Pydantic's `input_value=`: the `repr()`, cut to its first 25 and last 24
/// UTF-8 bytes around `...` past 50 (the head floored, the tail's start
/// raised to a character boundary).
pub fn pydantic_input_value(repr: String) -> String {
    let len = repr.len();
    if len <= 50 {
        return repr;
    }
    let mut head = 25;
    while !repr.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = len - 24;
    while !repr.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}...{}", &repr[..head], &repr[tail..])
}

/// `IoCBase(**ioc.__dict__)`.
pub fn ioc_out(row: &IocRow) -> Result<IocOut, ApiError> {
    if !IOC_TYPES.contains(&row.kind.as_str()) {
        return Err(ApiError::bad_request(format!(
            "1 validation error for IoCBase\ntype\n  Input should be 'IP', 'DOMAIN', 'HASH' or \
             'URL' [type=enum, input_value={}, input_type=str]\n    For further information \
             visit https://errors.pydantic.dev/2.13/v/enum",
            pydantic_input_value(py_str_repr(&row.kind))
        )));
    }
    Ok(IocOut {
        value: row.value.clone(),
        kind: row.kind.clone(),
        description: row.description.clone(),
        id: row.ioc_id,
    })
}

/// `build_alert_out` with the relationships `inc` names.
pub fn alert_out(row: &AlertRow, ch: &AlertChildren, inc: Include) -> Result<AlertOut, ApiError> {
    let mut out = AlertOut::bare(row);
    let id = row.id;
    out.comments = ch
        .comments
        .get(&id)
        .map(|v| v.iter().map(CommentOut::from).collect())
        .unwrap_or_default();
    out.assets = ch
        .assets
        .get(&id)
        .map(|v| v.iter().map(AssetOut::from).collect())
        .unwrap_or_default();
    out.tags = ch
        .tags
        .get(&id)
        .map(|v| v.iter().map(TagOut::from).collect())
        .unwrap_or_default();
    if inc.iocs {
        out.iocs = ch
            .iocs
            .get(&id)
            .map(|v| v.iter().map(ioc_out).collect::<Result<Vec<_>, _>>())
            .transpose()?
            .unwrap_or_default();
    }
    if inc.cases {
        out.linked_cases = ch
            .cases
            .get(&id)
            .map(|v| v.iter().map(LinkedCaseOut::from).collect())
            .unwrap_or_default();
    }
    Ok(out)
}

/// Build the response models of a listing, in its order.
pub async fn alerts_out(
    db: &Db,
    rows: &[AlertRow],
    inc: Include,
) -> Result<Vec<AlertOut>, ApiError> {
    let ids: Vec<i32> = rows.iter().map(|r| r.id).collect();
    let children = store::alert_children(db, &ids, inc).await?;
    rows.iter().map(|r| alert_out(r, &children, inc)).collect()
}

/// An alert loaded with every relationship (`get_alert_by_id`'s query), not
/// yet built: Python checks tag access before it builds the response models.
#[derive(Debug)]
pub struct LoadedAlert {
    /// The row.
    pub row: AlertRow,
    children: AlertChildren,
}

impl LoadedAlert {
    /// The alert's tag ids.
    pub fn tag_ids(&self) -> Vec<i32> {
        self.children
            .tags
            .get(&self.row.id)
            .map(|t| t.iter().map(|t| t.tag_id).collect())
            .unwrap_or_default()
    }

    /// `build_alert_out` with every relationship.
    pub fn build(&self) -> Result<AlertOut, ApiError> {
        alert_out(&self.row, &self.children, Include::ALL)
    }
}

/// `get_alert_by_id`'s query: the alert with every relationship, or `None`.
pub async fn load_alert(db: &Db, id: i64) -> Result<Option<LoadedAlert>, ApiError> {
    let Some(row) = store::alert(db, id).await? else {
        return Ok(None);
    };
    let children = store::alert_children(db, &[row.id], Include::ALL).await?;
    Ok(Some(LoadedAlert { row, children }))
}

/// `CaseOut` for each case, its alerts carrying the relationships `inc`
/// names (the full set for `get_case_by_id` and the paged lists, comments /
/// assets / tags only for the by-assignee, by-asset and by-customer lists).
pub async fn cases_out(db: &Db, rows: &[CaseRow], inc: Include) -> Result<Vec<CaseOut>, ApiError> {
    let case_ids: Vec<i32> = rows.iter().map(|c| c.id).collect();
    let (links, comments) = store::case_children(db, &case_ids).await?;
    let alert_ids: Vec<i32> = links.values().flatten().copied().collect();
    let alerts: HashMap<i32, AlertRow> = store::alerts_by_ids(db, &alert_ids)
        .await?
        .into_iter()
        .map(|a| (a.id, a))
        .collect();
    let children = store::alert_children(db, &alert_ids, inc).await?;
    let mut out = Vec::with_capacity(rows.len());
    for c in rows {
        let mut case = CaseOut::bare(c);
        for alert_id in links.get(&c.id).into_iter().flatten() {
            if let Some(a) = alerts.get(alert_id) {
                case.alerts.push(alert_out(a, &children, inc)?);
            }
        }
        case.comments = comments
            .get(&c.id)
            .map(|v| v.iter().map(CaseCommentOut::from).collect())
            .unwrap_or_default();
        out.push(case);
    }
    Ok(out)
}

/// `get_case_by_id`: the case with every relationship; 404 `Case not found`.
pub async fn case_full(db: &Db, id: i64) -> Result<CaseOut, ApiError> {
    let row = store::case(db, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Case not found"))?;
    let mut cases = cases_out(db, &[row], Include::ALL).await?;
    cases
        .pop()
        .ok_or_else(|| ApiError::internal("case_full: no case built"))
}

#[cfg(test)]
mod tests {
    use super::*;

    trait PipeRepr {
        fn pipe_repr(&self) -> String;
    }
    impl PipeRepr for String {
        fn pipe_repr(&self) -> String {
            py_str_repr(self)
        }
    }

    #[test]
    fn repr_like_python() {
        assert_eq!(py_str_repr("ip"), "'ip'");
        assert_eq!(py_str_repr("it's"), "\"it's\"");
        assert_eq!(py_str_repr("a\"b"), "'a\"b'");
        assert_eq!(py_str_repr(&"x".repeat(60)).len(), 62);
        assert_eq!(
            pydantic_input_value(py_str_repr(&"x".repeat(100))),
            format!("'{}...{}'", "x".repeat(24), "x".repeat(23))
        );
        // Values captured from Pydantic 2.13.
        assert_eq!(
            pydantic_input_value(py_str_repr(&"é".repeat(60))),
            format!("'{}...{}'", "é".repeat(12), "é".repeat(11))
        );
        assert_eq!(
            pydantic_input_value(format!("{}{}", "a".repeat(30), "é".repeat(30)).pipe_repr()),
            format!("'{}...{}'", "a".repeat(24), "é".repeat(11))
        );
    }

    #[test]
    fn bad_ioc_type_is_the_pydantic_400() {
        let row = IocRow {
            alert_id: 1,
            ioc_id: 2,
            value: "1.2.3.4".into(),
            kind: "ip".into(),
            description: None,
        };
        let err = ioc_out(&row).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(
            err.to_string()
                .contains("input_value='ip', input_type=str]")
        );
    }
}
