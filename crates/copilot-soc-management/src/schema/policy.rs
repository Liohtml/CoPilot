//! SLA policy shapes — port of `soc_management/schema/policy.py`.

use chrono::NaiveDateTime;
use copilot_core::time::pydantic;
use copilot_sla::policy::{MatrixCell, PolicyOverride as Override, SlaEntity, StoredCell};
use copilot_sla::severity::SEVERITY_LEVELS;
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator};
use serde::Serialize;
use serde_json::{Map, Value};

/// `PolicyCell`: one resolved cell and where it comes from.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyCell {
    /// Entity.
    pub entity: &'static str,
    /// Severity.
    pub severity: &'static str,
    /// Acknowledge target.
    pub ack_minutes: Option<i64>,
    /// Resolve target.
    pub resolve_minutes: Option<i64>,
    /// Business hours.
    pub business_hours: bool,
    /// `customer` | `global` | `default`.
    pub source: &'static str,
}

/// `PolicyMatrix`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyMatrix {
    /// `None` for the global policy.
    pub customer_code: Option<String>,
    /// Every cell.
    pub cells: Vec<PolicyCell>,
}

impl PolicyMatrix {
    /// `_matrix(customer_code, rows)`.
    pub fn new(customer_code: Option<String>, cells: &[MatrixCell]) -> Self {
        Self {
            customer_code,
            cells: cells
                .iter()
                .map(|c| PolicyCell {
                    entity: c.entity.as_str(),
                    severity: c.severity,
                    ack_minutes: c.targets.ack_minutes,
                    resolve_minutes: c.targets.resolve_minutes,
                    business_hours: c.targets.business_hours,
                    source: c.source.as_str(),
                })
                .collect(),
        }
    }
}

/// `PolicyOverride`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyOverrideOut {
    /// Customer.
    pub customer_code: String,
    /// Overridden cells.
    pub cells: i64,
    /// Last edit.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub updated_at: Option<NaiveDateTime>,
    /// By whom.
    pub updated_by: Option<String>,
}

impl From<&Override> for PolicyOverrideOut {
    fn from(o: &Override) -> Self {
        Self {
            customer_code: o.customer_code.clone(),
            cells: o.cells,
            updated_at: o.updated_at,
            updated_by: o.updated_by.clone(),
        }
    }
}

/// `PolicyResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResponse {
    /// Always true.
    pub success: bool,
    /// What happened.
    pub message: String,
    /// The scope's matrix.
    pub policy: PolicyMatrix,
    /// Open items whose due times moved.
    pub retargeted: i64,
}

/// `PolicyOverridesResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyOverridesResponse {
    /// Always true.
    pub success: bool,
    /// Empty.
    pub message: String,
    /// Customers with overrides.
    pub overrides: Vec<PolicyOverrideOut>,
}

/// `PolicyCellIn` as validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCellIn {
    /// Entity.
    pub entity: SlaEntity,
    /// Severity.
    pub severity: String,
    /// Store nothing for the cell.
    pub inherit: bool,
    /// Acknowledge target.
    pub ack_minutes: Option<i64>,
    /// Resolve target.
    pub resolve_minutes: Option<i64>,
    /// Business hours.
    pub business_hours: bool,
}

/// `PolicyUpdateRequest` as validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUpdateRequest {
    /// `None` edits the global policy.
    pub customer_code: Option<String>,
    /// The whole matrix of the scope.
    pub cells: Vec<PolicyCellIn>,
    /// Re-target open items.
    pub apply_to_open: bool,
}

fn child(at: &Loc, key: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(key.into()));
    l
}

/// `Optional[int]` with `validate_minutes` as an after-validator.
fn minutes(v: &mut Validator, obj: &Map<String, Value>, at: &Loc, name: &str) -> Option<i64> {
    let before = v.errors().len();
    let n = v.opt_int(obj, at, name, IntRules::default());
    if v.errors().len() != before {
        return None;
    }
    let n = n?;
    match copilot_sla::policy::validate_minutes(n) {
        Ok(n) => Some(n),
        Err(msg) => {
            v.push(
                "value_error",
                child(at, name),
                format!("Value error, {msg}"),
            );
            None
        }
    }
}

fn read_cell(v: &mut Validator, value: &Value, at: &Loc) -> Option<PolicyCellIn> {
    // FastAPI validates with `from_attributes`: a non-object cell is
    // `model_attributes_type`, not `model_type`.
    let obj = v.object(value, at)?;
    let before = v.errors().len();
    let entity = v.req_enum(obj, at, "entity", &["alert", "case"]);
    let sev_before = v.errors().len();
    let severity = v.req_str(obj, at, "severity", StrRules::any());
    if v.errors().len() == sev_before && !SEVERITY_LEVELS.contains(&severity.as_str()) {
        v.push(
            "value_error",
            child(at, "severity"),
            format!(
                "Value error, Expected one of {}",
                SEVERITY_LEVELS.join(", ")
            ),
        );
    }
    let inherit = v.bool_or(obj, at, "inherit", false);
    let ack_minutes = minutes(v, obj, at, "ack_minutes");
    let resolve_minutes = minutes(v, obj, at, "resolve_minutes");
    let business_hours = v.bool_or(obj, at, "business_hours", false);
    if v.errors().len() != before {
        return None;
    }
    let entity = SlaEntity::parse(&entity)?;
    if let (false, Some(ack), Some(resolve)) = (inherit, ack_minutes, resolve_minutes) {
        if ack > resolve {
            v.push(
                "value_error",
                at.clone(),
                format!(
                    "Value error, {} {severity}: the acknowledge target cannot be longer \
                     than the resolve target",
                    entity.as_str()
                ),
            );
            return None;
        }
    }
    Some(PolicyCellIn {
        entity,
        severity,
        inherit,
        ack_minutes,
        resolve_minutes,
        business_hours,
    })
}

impl PolicyUpdateRequest {
    /// Read and validate like Pydantic (field errors in declaration order,
    /// the model validators only once every field is valid).
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let before = v.errors().len();
        let customer_code = v.opt_str(obj, at, "customer_code", StrRules::any());
        let mut cells = Vec::new();
        match obj.get("cells") {
            None => {}
            Some(Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    let mut il = child(at, "cells");
                    il.push(LocPart::Index(i));
                    if let Some(cell) = read_cell(v, item, &il) {
                        cells.push(cell);
                    }
                }
            }
            Some(_) => v.push(
                "list_type",
                child(at, "cells"),
                "Input should be a valid list",
            ),
        }
        let apply_to_open = v.bool_or(obj, at, "apply_to_open", false);
        if v.errors().len() == before {
            let mut seen: Vec<(SlaEntity, &str)> = Vec::new();
            for cell in &cells {
                let slot = (cell.entity, cell.severity.as_str());
                if seen.contains(&slot) {
                    v.push(
                        "value_error",
                        at.clone(),
                        format!(
                            "Value error, Duplicate cell {} / {}",
                            cell.entity.as_str(),
                            cell.severity
                        ),
                    );
                    break;
                }
                seen.push(slot);
            }
        }
        Self {
            customer_code,
            cells,
            apply_to_open,
        }
    }

    /// The cells to store: every cell that does not inherit, in order.
    pub fn stored_cells(&self) -> Vec<StoredCell> {
        self.cells
            .iter()
            .filter(|c| !c.inherit)
            .map(|c| StoredCell {
                entity: c.entity,
                severity: c.severity.clone(),
                ack_minutes: c.ack_minutes,
                resolve_minutes: c.resolve_minutes,
                business_hours: c.business_hours,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::validate::body_loc;
    use serde_json::json;

    fn errors(body: Value) -> Vec<(String, String, String)> {
        let mut v = Validator::new();
        let obj = body.as_object().unwrap().clone();
        PolicyUpdateRequest::read(&mut v, &obj, &body_loc());
        v.errors()
            .iter()
            .map(|e| {
                let item = e.to_item();
                (
                    item.field,
                    item.error_type,
                    item.message.unwrap_or_default(),
                )
            })
            .collect()
    }

    #[test]
    fn errors_match_pydantic() {
        let e = errors(
            json!({"cells": [{"entity": "x", "severity": "y", "ack_minutes": 0,
            "resolve_minutes": "abc"}]}),
        );
        assert_eq!(e.len(), 4);
        assert_eq!(e[0].1, "enum");
        assert_eq!(
            e[1].2,
            "cells.0.severity: Expected one of Informational, Low, Medium, High, Critical"
        );
        assert_eq!(
            e[2].2,
            "cells.0.ack_minutes: Targets must be greater than zero; leave a target empty for no promise"
        );
        assert_eq!(e[3].1, "int_parsing");
        let e = errors(json!({"cells": [{"entity": "alert", "severity": "High",
            "ack_minutes": 600, "resolve_minutes": 60}]}));
        assert_eq!(
            e,
            vec![(
                "0".into(),
                "value_error".into(),
                "cells.0: alert High: the acknowledge target cannot be longer than the resolve target"
                    .into()
            )]
        );
        let e = errors(json!({"cells": [{"entity": "alert", "severity": "High"},
            {"entity": "alert", "severity": "High"}]}));
        assert_eq!(
            e,
            vec![(
                "body".into(),
                "value_error".into(),
                "Duplicate cell alert / High".into()
            )]
        );
        let e = errors(json!({"cells": [5], "apply_to_open": "maybe", "customer_code": 5}));
        let kinds: Vec<_> = e.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(kinds, vec!["customer_code", "0", "apply_to_open"]);
        assert!(
            errors(json!({"cells": [{"entity": "alert", "severity": "High",
            "inherit": true, "ack_minutes": 600, "resolve_minutes": 60}]}))
            .is_empty()
        );
        assert_eq!(
            errors(json!({"cells": null}))[0].2,
            "cells: Input should be a valid list"
        );
    }
}
