//! The module collections: `collect_<name>_route` of
//! `app/integrations/modules/routes/{huntress,mimecast,duo,cato,carbonblack,
//! darktrace}.py` with their services.
//!
//! Each runs, inside the route's `try`: the customer's integrations (the 404
//! without any), the integration found by name, its auth keys
//! (`extract_auth_keys`, then the module's `*AuthKeys` model), the payload
//! model (the Graylog host and port from a connector row — by name
//! (`Event Shipper`) or by a fixed id (1, 10, 14), as each module reads
//! them), the licence where the module reads it, and one POST. Whatever
//! raises becomes `success: false` with `str(e)` ([`collect`]); the jobs
//! call the same function.

use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::HttpxError;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_web::AppContext;

use crate::ModulesState;
use crate::error::{Fail, FailResult};
use crate::lookups::{self, Column};
use crate::schema::{self, invoke_response};
use crate::upstream::{self, MODULE_TIMEOUT};

/// The modules [`collect`] serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    /// `copilot-huntress-module`.
    Huntress,
    /// `copilot-mimecast-module`.
    Mimecast,
    /// `copilot-duo-module`.
    Duo,
    /// `copilot-cato-module`.
    Cato,
    /// `copilot-carbonblack-module`.
    CarbonBlack,
    /// `copilot-darktrace-module`.
    Darktrace,
}

impl Module {
    /// The name the route's success message carries.
    fn label(self) -> &'static str {
        match self {
            Module::Huntress => "Huntress",
            Module::Mimecast => "Mimecast",
            Module::Duo => "Duo",
            Module::Cato => "Cato",
            Module::CarbonBlack => "CarbonBlack",
            Module::Darktrace => "Darktrace",
        }
    }

    /// The `service_name` its keys are filed under.
    fn service(self) -> &'static str {
        match self {
            Module::Huntress => "Huntress",
            Module::Mimecast => "Mimecast",
            Module::Duo => "DUO",
            Module::Cato => "CATO",
            Module::CarbonBlack => "CarbonBlack",
            Module::Darktrace => "Darktrace",
        }
    }
}

/// The route's answer: `success: true` and the module's message, or
/// `success: false` with `str(e)` of what raised.
pub async fn collect(
    st: &ModulesState,
    module: Module,
    customer_code: &str,
    integration_name: &str,
) -> PyValue {
    match run(st, module, customer_code, integration_name).await {
        Ok(()) => invoke_response(
            true,
            &format!("{} Events collected successfully.", module.label()),
        ),
        Err(e) => {
            tracing::error!(target: "copilot::integration_modules", module = module.label(),
                "Error during DB session: {}", e.message());
            invoke_response(false, &e.message())
        }
    }
}

async fn run(
    st: &ModulesState,
    module: Module,
    code: &str,
    integration_name: &str,
) -> FailResult<()> {
    let cis = lookups::integration_response(&st.ctx.db, code).await?;
    // Duo: `duo_request.integration_name = "DUO"` before the lookup.
    let name = if module == Module::Duo {
        "DUO"
    } else {
        integration_name
    };
    let ci = lookups::find_customer_integration(&cis, name)?;
    let keys = lookups::extract_auth_keys(ci, module.service())?;
    match module {
        Module::Huntress => huntress(st, code, &keys).await,
        Module::Mimecast => mimecast(st, code, &keys).await,
        Module::Duo => duo(st, code, &keys).await,
        Module::Cato => cato(st, code, &keys).await,
        Module::CarbonBlack => carbonblack(st, code, &keys).await,
        Module::Darktrace => darktrace(st, code, &keys).await,
    }
}

/// `str(e)` of what `client.post` raised, unwrapped.
fn raised(e: HttpxError) -> Fail {
    Fail::Py(e.into_py())
}

async fn event_shipper(ctx: &AppContext) -> FailResult<(PyValue, PyValue)> {
    Ok((
        lookups::connector_by_name(ctx, "Event Shipper", Column::Url).await?,
        lookups::connector_by_name(ctx, "Event Shipper", Column::ExtraData).await?,
    ))
}

async fn graylog_by_id(ctx: &AppContext, id: i64) -> FailResult<(PyValue, PyValue)> {
    Ok((
        lookups::connector_by_id(ctx, id, Column::Url).await?,
        lookups::connector_by_id(ctx, id, Column::ExtraData).await?,
    ))
}

fn str_of(v: &PyValue) -> PyValue {
    v.clone()
}

/// `post_to_copilot_huntress_module`: a connection failure is the
/// `RuntimeError` naming the optional container, a non-2xx answer
/// `raise_for_status()`'s `HTTPStatusError`.
async fn huntress(st: &ModulesState, code: &str, keys: &PyValue) -> FailResult<()> {
    let keys = construct(&schema::HUNTRESS_KEYS, keys)?;
    let (host, port) = event_shipper(&st.ctx).await?;
    let indexer_host = lookups::connector_by_id(&st.ctx, 1, Column::Url).await?;
    let indexer_user = lookups::connector_by_id(&st.ctx, 1, Column::Username).await?;
    let indexer_password = lookups::connector_by_id(&st.ctx, 1, Column::Password).await?;
    let payload = construct(
        &schema::COLLECT_HUNTRESS,
        &kwargs(vec![
            ("integration", PyValue::Str("huntress".into())),
            ("customer_code", PyValue::Str(code.into())),
            ("graylog_host", host),
            ("graylog_port", port),
            ("wazuh_indexer_host", indexer_host),
            ("wazuh_indexer_username", indexer_user),
            ("wazuh_indexer_password", indexer_password),
            ("api_key", str_of(field(&keys, "API_KEY"))),
            ("api_secret", str_of(field(&keys, "API_SECRET"))),
        ]),
    )?;
    tracing::info!(target: "copilot::integration_modules", "Collecting Huntress Events for {code}");
    let resp = st
        .upstream
        .post_json(upstream::HUNTRESS_URL, payload, &[], MODULE_TIMEOUT)
        .await
        .map_err(|e| {
            if e.class == "ConnectError" {
                Fail::other(
                    "RuntimeError",
                    format!(
                        "Could not reach the Huntress module at {} ({}). This container is \
                         optional and is not started by the default docker-compose stack — run \
                         ghcr.io/socfortress/copilot-huntress-module:latest on the same Docker \
                         network as copilot-backend to enable Huntress collection.",
                        upstream::HUNTRESS_URL,
                        e.message
                    ),
                )
            } else {
                raised(e)
            }
        })?;
    resp.raise_for_status().map_err(raised)?;
    Ok(())
}

/// `get_collect_mimecast_data` (Graylog by connector id 14), `get_license`,
/// `post_to_copilot_mimecast_module` (the answer is not read).
async fn mimecast(st: &ModulesState, code: &str, keys: &PyValue) -> FailResult<()> {
    let keys = construct(&schema::MIMECAST_KEYS, keys)?;
    let (host, port) = graylog_by_id(&st.ctx, 14).await?;
    let payload = construct(
        &schema::COLLECT_MIMECAST,
        &kwargs(vec![
            ("integration", PyValue::Str("mimecast".into())),
            ("customer_code", PyValue::Str(code.into())),
            ("graylog_host", host),
            ("graylog_port", port),
            ("app_id", str_of(field(&keys, "APP_ID"))),
            ("app_key", str_of(field(&keys, "APP_KEY"))),
            ("email_address", str_of(field(&keys, "EMAIL_ADDRESS"))),
            ("access_key", str_of(field(&keys, "ACCESS_KEY"))),
            ("secret_key", str_of(field(&keys, "SECRET_KEY"))),
            ("uri", str_of(field(&keys, "URI"))),
            ("time_range", PyValue::Str("15m".into())),
        ]),
    )?;
    lookups::license_key(&st.ctx.db).await?;
    st.upstream
        .post_json(upstream::MIMECAST_MODULE_URL, payload, &[], MODULE_TIMEOUT)
        .await
        .map_err(raised)?;
    Ok(())
}

/// `get_collect_duo_data` (the Event Shipper), `post_to_copilot_duo_module`.
async fn duo(st: &ModulesState, code: &str, keys: &PyValue) -> FailResult<()> {
    let keys = construct(&schema::DUO_KEYS, keys)?;
    let (host, port) = event_shipper(&st.ctx).await?;
    let payload = construct(
        &schema::COLLECT_DUO,
        &kwargs(vec![
            ("integration", PyValue::Str("duo".into())),
            ("customer_code", PyValue::Str(code.into())),
            ("graylog_host", host),
            ("graylog_port", port),
            ("integration_key", str_of(field(&keys, "INTEGRATION_KEY"))),
            ("secret_key", str_of(field(&keys, "SECRET_KEY"))),
            ("api_host", str_of(field(&keys, "API_HOSTNAME"))),
            (
                "api_endpoint",
                PyValue::Str("/admin/v2/logs/authentication".into()),
            ),
            ("range", PyValue::Str("15m".into())),
        ]),
    )?;
    st.upstream
        .post_json(upstream::DUO_URL, payload, &[], MODULE_TIMEOUT)
        .await
        .map_err(raised)?;
    Ok(())
}

/// `get_collect_cato_data` (Graylog by connector id 10, `int(ACCOUNT_ID)`),
/// `post_to_copilot_cato_module`.
async fn cato(st: &ModulesState, code: &str, keys: &PyValue) -> FailResult<()> {
    let keys = cato_keys(keys)?;
    let (host, port) = graylog_by_id(&st.ctx, 10).await?;
    let payload = construct(
        &schema::COLLECT_CATO,
        &kwargs(vec![
            ("integration", PyValue::Str("cato".into())),
            ("customer_code", PyValue::Str(code.into())),
            ("graylog_host", host),
            ("graylog_port", port),
            ("api_key", str_of(field(&keys, "API_KEY"))),
            ("account_id", str_of(field(&keys, "ACCOUNT_ID"))),
            ("event_types", str_of(field(&keys, "EVENT_TYPES"))),
            ("event_sub_types", str_of(field(&keys, "EVENT_SUB_TYPES"))),
        ]),
    )?;
    st.upstream
        .post_json(upstream::CATO_URL, payload, &[], MODULE_TIMEOUT)
        .await
        .map_err(raised)?;
    Ok(())
}

/// `CatoAuthKeys(**keys)`.
pub fn cato_keys(keys: &PyValue) -> PyResult<PyValue> {
    // pydantic-core takes `"5.0"` as 5 but refuses `"5."`, which the shared
    // lax engine accepts (`copilot_uba::params` does the same check).
    if let Some(PyValue::Str(id)) = keys.get("ACCOUNT_ID") {
        if id.trim().ends_with('.') {
            return Err(PyExc::Validation(cato_account_id_error(keys)));
        }
    }
    construct(&schema::CATO_KEYS, keys)
}

/// `CatoAuthKeys(**keys)` for an `ACCOUNT_ID` ending in a dot: its
/// `int_parsing` line, with the other fields' errors in declaration order.
fn cato_account_id_error(keys: &PyValue) -> String {
    use copilot_upstream::model::{Invalid, Loc, PyError, format_validation_error, validate};
    let mut patched = keys.clone();
    if let PyValue::Dict(items) = &mut patched {
        for (k, v) in items.iter_mut() {
            if k == "ACCOUNT_ID" {
                *v = PyValue::Int("0".into());
            }
        }
    }
    let mut errors = match validate(&schema::CATO_KEYS, &patched) {
        Err(Invalid::Errors(errors)) => errors,
        _ => Vec::new(),
    };
    let at = errors
        .iter()
        .position(|e| !matches!(e.loc.first(), Some(Loc::Key(k)) if k == "API_KEY"))
        .unwrap_or(errors.len());
    errors.insert(
        at,
        PyError {
            loc: vec![Loc::Key("ACCOUNT_ID".into())],
            kind: "int_parsing",
            msg: "Input should be a valid integer, unable to parse string as an integer".into(),
            input: keys.get("ACCOUNT_ID").cloned().unwrap_or(PyValue::None),
        },
    );
    // The patched input is not what Python saw: the missing-field lines
    // quote the dict as given.
    for e in &mut errors {
        if e.kind == "missing" {
            e.input = keys.clone();
        }
    }
    format_validation_error("CatoAuthKeys", &errors)
}

/// `get_carbonblack_auth_keys` (four subscripts — a missing key is the
/// `KeyError`), `get_collect_carbonblack_data` (the Event Shipper),
/// `get_license`, `post_to_copilot_carbonblack_module`.
async fn carbonblack(st: &ModulesState, code: &str, keys: &PyValue) -> FailResult<()> {
    let get = |k: &str| {
        keys.get(k)
            .cloned()
            .ok_or_else(|| Fail::Py(PyExc::key_error(k)))
    };
    let url = get("API_URL")?;
    let key = get("API_KEY")?;
    let id = get("API_ID")?;
    let org = get("ORGANIZATION_KEY")?;
    let auth = construct(
        &schema::CARBONBLACK_KEYS,
        &kwargs(vec![
            ("carbonblack_api_url", url),
            ("carbonblack_api_key", key),
            ("carbonblack_api_id", id),
            ("carbonblack_org_key", org),
        ]),
    )?;
    let (host, port) = event_shipper(&st.ctx).await?;
    let payload = construct(
        &schema::COLLECT_CARBONBLACK,
        &kwargs(vec![
            ("integration", PyValue::Str("carbonblack".into())),
            ("customer_code", PyValue::Str(code.into())),
            ("graylog_host", host),
            ("graylog_port", port),
            (
                "carbonblack_api_url",
                str_of(field(&auth, "carbonblack_api_url")),
            ),
            (
                "carbonblack_api_key",
                str_of(field(&auth, "carbonblack_api_key")),
            ),
            (
                "carbonblack_api_id",
                str_of(field(&auth, "carbonblack_api_id")),
            ),
            (
                "carbonblack_org_key",
                str_of(field(&auth, "carbonblack_org_key")),
            ),
            ("time_range", str_of(field(&auth, "time_range"))),
        ]),
    )?;
    lookups::license_key(&st.ctx.db).await?;
    st.upstream
        .post_json(upstream::CARBONBLACK_URL, payload, &[], MODULE_TIMEOUT)
        .await
        .map_err(raised)?;
    Ok(())
}

/// `get_collect_darktrace_data` (Graylog by connector id 14),
/// `post_to_copilot_darktrace_module`.
async fn darktrace(st: &ModulesState, code: &str, keys: &PyValue) -> FailResult<()> {
    let keys = construct(&schema::DARKTRACE_KEYS, keys)?;
    let (host, port) = graylog_by_id(&st.ctx, 14).await?;
    let payload = construct(
        &schema::COLLECT_DARKTRACE,
        &kwargs(vec![
            ("integration", PyValue::Str("darktrace".into())),
            ("customer_code", PyValue::Str(code.into())),
            ("graylog_host", host),
            ("graylog_port", port),
            ("public_token", str_of(field(&keys, "PUBLIC_TOKEN"))),
            ("private_token", str_of(field(&keys, "PRIVATE_TOKEN"))),
            ("darktrace_host", str_of(field(&keys, "HOST"))),
            ("darktrace_port", str_of(field(&keys, "PORT"))),
            ("timeframe", PyValue::Str("15m".into())),
        ]),
    )?;
    st.upstream
        .post_json(upstream::DARKTRACE_URL, payload, &[], MODULE_TIMEOUT)
        .await
        .map_err(raised)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_dot_account_id_is_pydantics_int_parsing() {
        let keys = PyValue::Dict(vec![
            ("API_KEY".into(), PyValue::Str("k".into())),
            ("ACCOUNT_ID".into(), PyValue::Str("5.".into())),
            ("EVENT_TYPES".into(), PyValue::Str("x".into())),
        ]);
        let text = cato_account_id_error(&keys);
        assert!(text.starts_with("2 validation errors for CatoAuthKeys\nACCOUNT_ID\n"));
        assert!(text.contains("input_value='5.', input_type=str"));
        assert!(text.contains("EVENT_SUB_TYPES\n  Field required"));
    }
}
