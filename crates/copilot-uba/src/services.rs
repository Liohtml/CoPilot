//! One function per UBA endpoint — port of `services/uba.py`. Tenancy is the
//! routes' job (`verify_customer_code_access`); UBA checks its API key's
//! tenants again and answers 404 outside them.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, construct_star, kwargs};
use copilot_upstream::py::{self, PyExc};
use http::Method;

use crate::client::{Call, UbaClient, UbaError, UbaResult, path_segment};
use crate::schema::{CUSTOMER_STATUS, TENANT_STATUS, UBA_RESPONSE};

/// `UbaResponse`'s qualified name (the `**` `TypeError` names it).
const QUALNAME: &str = "app.connectors.uba.schema.uba.UbaResponse";

/// `_tenant(customer_code)`.
pub fn tenant(customer_code: &str) -> String {
    format!("/v1/tenants/{}", path_segment(customer_code))
}

/// `UbaResponse(**body)`.
pub fn uba_response(body: &PyValue) -> UbaResult<PyValue> {
    construct_star(&UBA_RESPONSE, QUALNAME, body).map_err(UbaError::Py)
}

/// A `params=` entry.
pub fn p(key: &str, value: PyValue) -> (String, PyValue) {
    (key.to_string(), value)
}

/// A `str` value.
pub fn s(value: &str) -> PyValue {
    PyValue::Str(value.to_string())
}

/// An `Optional[str]` value.
pub fn opt(value: Option<String>) -> PyValue {
    value.map_or(PyValue::None, PyValue::Str)
}

/// An `int` value from its decimal text.
pub fn int(text: &str) -> PyValue {
    PyValue::Int(text.to_string())
}

impl UbaClient {
    /// `_get(path, params)`.
    pub async fn get_response(
        &self,
        path: String,
        params: Vec<(String, PyValue)>,
    ) -> UbaResult<PyValue> {
        let body = self.request(Call::get(path).params(params)).await?;
        uba_response(&body)
    }

    /// `UbaResponse(**await uba_request(method, path, …))`.
    pub async fn write_response(&self, call: Call) -> UbaResult<PyValue> {
        let body = self.request(call).await?;
        uba_response(&body)
    }

    /// `get_customer_status`: UBA's `/v1/status` row of this tenant.
    pub async fn customer_status(&self, customer_code: &str) -> UbaResult<PyValue> {
        let body = self.request(Call::get("/v1/status")).await?;
        let tenants = py::get(&body, "tenants")?
            .cloned()
            .unwrap_or_else(|| PyValue::List(Vec::new()));
        // `next(t for t in tenants if t.get("tenant") == code)`: lazily, so
        // what follows the match is never looked at.
        let mut row = None;
        for t in py::iterate(&tenants)? {
            let tenant = py::get(&t, "tenant")?;
            if matches!(tenant, Some(PyValue::Str(x)) if x == customer_code) {
                row = Some(t);
                break;
            }
        }
        let version = py::get(&body, "version")?.cloned().unwrap_or_else(|| s(""));
        let status = match &row {
            Some(r) => construct(&TENANT_STATUS, r)?,
            None => PyValue::None,
        };
        let message = if row.as_ref().is_some_and(PyValue::truthy) {
            "UBA status".to_string()
        } else {
            format!("SOCFortress UBA has no data for {customer_code}")
        };
        Ok(construct(
            &CUSTOMER_STATUS,
            &kwargs(vec![
                ("success", PyValue::Bool(true)),
                ("message", PyValue::Str(message)),
                ("version", version),
                ("status", status),
            ]),
        )?)
    }

    /// `get_about`: a dict answer as it is, anything else the empty envelope.
    pub async fn about(&self) -> UbaResult<PyValue> {
        let body = self.request(Call::get("/v1/about")).await?;
        match body {
            PyValue::Dict(_) => uba_response(&body),
            _ => uba_response(&PyValue::Dict(Vec::new())),
        }
    }

    /// `list_rule_catalog`: `{"rules": [...]}` (a non-list answer is `[]`).
    pub async fn rule_catalog(&self) -> UbaResult<PyValue> {
        let rules = self.request(Call::get("/v1/rules")).await?;
        let rules = match rules {
            PyValue::List(_) => rules,
            _ => PyValue::List(Vec::new()),
        };
        uba_response(&PyValue::Dict(vec![("rules".into(), rules)]))
    }

    /// `list_alerts(customer_code, **params)`.
    pub async fn list_alerts(
        &self,
        customer_code: &str,
        params: Vec<(String, PyValue)>,
    ) -> UbaResult<PyValue> {
        self.get_response(format!("{}/alerts", tenant(customer_code)), params)
            .await
    }

    /// `get_alert(customer_code, alert_id)`.
    pub async fn get_alert(&self, customer_code: &str, alert_id: &str) -> UbaResult<PyValue> {
        self.get_response(
            format!(
                "{}/alerts/{}",
                tenant(customer_code),
                path_segment(alert_id)
            ),
            Vec::new(),
        )
        .await
    }

    /// `submit_feedback(customer_code, alert_id, body, actor)`.
    pub async fn submit_feedback(
        &self,
        customer_code: &str,
        alert_id: &str,
        body: PyValue,
        actor: &str,
    ) -> UbaResult<PyValue> {
        let path = format!(
            "{}/alerts/{}/feedback",
            tenant(customer_code),
            path_segment(alert_id)
        );
        self.write_response(Call::new(Method::POST, path).json(body).actor(actor))
            .await
    }
}

/// The extra fields of a `UbaResponse` dump (`model_extra`).
pub fn model_extra(dump: &PyValue) -> Vec<(String, PyValue)> {
    match dump {
        PyValue::Dict(items) => items
            .iter()
            .filter(|(k, _)| k != "success" && k != "message")
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// `UbaResponse(**result.model_dump(), incident=…)`: a `TypeError` when the
/// result already carries an `incident` field.
pub fn with_incident(result: &PyValue, incident: PyValue) -> UbaResult<PyValue> {
    let PyValue::Dict(items) = result else {
        return Err(UbaError::Py(PyExc::TypeError("not a dict".into())));
    };
    if items.iter().any(|(k, _)| k == "incident") {
        return Err(UbaError::Py(PyExc::TypeError(format!(
            "{QUALNAME}() got multiple values for keyword argument 'incident'"
        ))));
    }
    let mut out = items.clone();
    out.push(("incident".into(), incident));
    uba_response(&PyValue::Dict(out))
}
