//! `/api/customer_portal/settings*` and `/branding*` — port of
//! `app/customer_portal/routes/settings.py` and `routes/branding.py`.
//!
//! | Route | Guard | Notes |
//! |---|---|---|
//! | `POST /settings` | admin | replaces every field (null = default) |
//! | `PATCH /settings` | admin | the fields sent, `reset` |
//! | `GET /settings` | public | global only, no logo bytes |
//! | `GET /settings/logo` | public | bytes, `ETag`, `Cache-Control: public` |
//! | `GET /settings/global` | admin, analyst | the inline logo, for the editor |
//! | `GET /settings/effective` | any user | per-customer when scoped to one |
//! | `GET /settings/effective/logo` | any user | `Cache-Control: private` |
//! | `GET /branding` | admin, analyst | the caller's customers' overrides |
//! | `GET /branding/{customer_code}` | admin, analyst + customer | |
//! | `PUT /branding/{customer_code}` | admin | 404 for an unknown customer |
//! | `DELETE /branding/{customer_code}` | admin | |
//!
//! Every write forgets this process's cached branding after its commit;
//! another process's write is seen within the change-check interval
//! (see [`super::cache`]).

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use http::{HeaderMap, StatusCode};

use copilot_auth::AccessScope;
use copilot_core::time::now_utc_micros;
use copilot_db::alerts;
use copilot_web::form::{latin1, py_strip};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, AnyUser, ApiError, ApiResult, Authorized, ScopedUser, WithJson,
};

use super::schema::{
    CustomerBrandingListItem, CustomerBrandingListResponse, CustomerBrandingOverride,
    CustomerBrandingResponse, EffectiveBranding, EffectiveBrandingResponse,
    PatchPortalSettingsRequest, PortalEffectiveBranding, PortalSettingsData,
    PortalSettingsResponse, PublicPortalSettingsData, PublicPortalSettingsResponse,
    UpdateCustomerBrandingRequest, UpdatePortalSettingsRequest, UpdatePortalSettingsResponse,
};
use super::services::{
    self, DEFAULT_TITLE, EFFECTIVE_LOGO_PATH, LOGO_PATH, OverrideRow, PortalLogo,
};
use crate::errors::internal_errors;
use crate::starlette;
use crate::state::PortalState;

/// `LOGO_MAX_AGE_SECONDS`.
const LOGO_MAX_AGE_SECONDS: u32 = 3600;

/// The routes, relative to `/api/customer_portal`.
pub fn router() -> Router<PortalState> {
    Router::new()
        .route(
            "/settings",
            get(public_settings)
                .post(update_settings)
                .patch(patch_settings),
        )
        .route("/settings/logo", get(global_logo))
        .route("/settings/global", get(global_settings))
        .route("/settings/effective", get(effective_settings))
        .route("/settings/effective/logo", get(effective_logo))
        .route("/branding", get(list_branding))
        .route(
            "/branding/{customer_code}",
            get(get_branding).put(put_branding).delete(delete_branding),
        )
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

fn updated() -> Response {
    json(UpdatePortalSettingsResponse {
        success: true,
        message: "Portal settings updated successfully".into(),
    })
}

// ---------------------------------------------------------------------------
// Global settings
// ---------------------------------------------------------------------------

async fn update_settings(
    State(st): State<PortalState>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let req = body.model(UpdatePortalSettingsRequest::read)?;
    internal_errors(
        "update portal settings",
        services::replace_global(&st.ctx.db, &req.fields, auth.id, now_utc_micros())
            .await
            .map_err(ApiError::from),
    )?;
    st.branding.invalidate_all();
    tracing::info!(user = %auth.username, id = auth.id, "portal settings updated");
    Ok(updated())
}

async fn patch_settings(
    State(st): State<PortalState>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let req = body.model(PatchPortalSettingsRequest::read)?;
    internal_errors(
        "update portal settings",
        services::patch_global(&st.ctx.db, &req, auth.id, now_utc_micros())
            .await
            .map_err(ApiError::from),
    )?;
    st.branding.invalidate_all();
    tracing::info!(user = %auth.username, id = auth.id, "portal settings patched");
    Ok(updated())
}

async fn public_settings(State(st): State<PortalState>) -> ApiResult {
    let row = internal_errors(
        "get portal settings",
        services::public_settings(&st.ctx.db)
            .await
            .map_err(ApiError::from),
    )?;
    let settings = match row {
        None => PublicPortalSettingsData {
            id: 0,
            title: DEFAULT_TITLE.into(),
            logo_url: None,
            logo_mime_type: None,
            brand_color: None,
            updated_at: None,
        },
        Some(r) => PublicPortalSettingsData {
            id: r.id,
            title: r.title,
            logo_url: (r.logo_length != 0)
                .then(|| format!("{LOGO_PATH}?v={}", services::logo_version(r.updated_at))),
            logo_mime_type: r.logo_mime_type,
            brand_color: r.brand_color,
            updated_at: Some(services::isoformat(r.updated_at)),
        },
    };
    Ok(json(PublicPortalSettingsResponse {
        success: true,
        message: "Portal settings retrieved successfully".into(),
        settings: Some(settings),
    }))
}

/// `Header(None)`: the first `If-None-Match`, as latin-1 text.
fn if_none_match(headers: &HeaderMap) -> Option<String> {
    headers
        .get(http::header::IF_NONE_MATCH)
        .map(|v| latin1(v.as_bytes()))
}

/// `logo_response`: the bytes with `ETag` revalidation; 404 without a logo.
fn logo_response(logo: Option<PortalLogo>, request: &HeaderMap, cache_scope: &str) -> ApiResult {
    let Some(logo) = logo else {
        return Err(ApiError::not_found("No portal logo configured"));
    };
    let headers = [
        ("ETag", logo.etag.clone()),
        (
            "Cache-Control",
            format!("{cache_scope}, max-age={LOGO_MAX_AGE_SECONDS}"),
        ),
        ("X-Content-Type-Options", "nosniff".to_string()),
        (
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; sandbox".to_string(),
        ),
    ];
    let matched = if_none_match(request)
        .filter(|v| !v.is_empty())
        .is_some_and(|v| v.split(',').any(|tag| py_strip(tag) == logo.etag));
    if matched {
        return starlette::response(
            StatusCode::NOT_MODIFIED,
            Vec::new(),
            None,
            &headers,
            request,
        );
    }
    starlette::response(
        StatusCode::OK,
        logo.content,
        Some(&logo.mime_type),
        &headers,
        request,
    )
}

async fn global_logo(State(st): State<PortalState>, headers: HeaderMap) -> ApiResult {
    let logo = services::global_logo(&st.ctx.db).await?;
    logo_response(logo, &headers, "public")
}

async fn global_settings(
    _auth: Authorized<AdminOrAnalyst>,
    State(st): State<PortalState>,
) -> ApiResult {
    let row = internal_errors(
        "get portal settings",
        services::global_settings(&st.ctx.db)
            .await
            .map_err(ApiError::from),
    )?;
    let settings = match row {
        Some(r) => PortalSettingsData {
            id: r.id,
            title: r.title,
            logo_base64: r.logo_base64,
            logo_mime_type: r.logo_mime_type,
            brand_color: r.brand_color,
            updated_at: services::isoformat(r.updated_at),
        },
        // `get_global_settings_or_default`: an unsaved row, `id=0`, stamped
        // with `now_utc()` (aware).
        None => PortalSettingsData {
            id: 0,
            title: DEFAULT_TITLE.into(),
            logo_base64: None,
            logo_mime_type: None,
            brand_color: None,
            updated_at: services::aware_now_isoformat(),
        },
    };
    Ok(json(PortalSettingsResponse {
        success: true,
        message: "Portal settings retrieved successfully".into(),
        settings: Some(settings),
    }))
}

// ---------------------------------------------------------------------------
// What a portal user resolves to
// ---------------------------------------------------------------------------

/// `resolve_branding_for_user`.
async fn branding_for_user(
    st: &PortalState,
    user: &copilot_web::CurrentUser,
) -> Result<EffectiveBranding, ApiError> {
    let accessible = user.access(&st.ctx).await?.to_python_list();
    let code = services::branding_customer(&accessible);
    Ok(services::resolve_effective(&st.ctx.db, &st.branding, code).await?)
}

async fn effective_settings(auth: ScopedUser<AnyUser>, State(st): State<PortalState>) -> ApiResult {
    let effective = internal_errors(
        "resolve portal branding",
        branding_for_user(&st, &auth).await,
    )?;
    let logo_url = effective
        .logo_base64
        .as_deref()
        .filter(|l| !l.is_empty())
        .map(|l| {
            format!(
                "{EFFECTIVE_LOGO_PATH}?v={}",
                services::logo_content_version(l)
            )
        });
    Ok(json(EffectiveBrandingResponse {
        success: true,
        message: "Portal branding resolved successfully".into(),
        settings: Some(PortalEffectiveBranding {
            title: effective.title,
            logo_url,
            logo_mime_type: effective.logo_mime_type,
            brand_color: effective.brand_color,
            source: effective.source,
            customer_code: effective.customer_code,
        }),
    }))
}

async fn effective_logo(
    auth: ScopedUser<AnyUser>,
    State(st): State<PortalState>,
    headers: HeaderMap,
) -> ApiResult {
    let effective = branding_for_user(&st, &auth).await?;
    logo_response(services::effective_logo(&effective), &headers, "private")
}

// ---------------------------------------------------------------------------
// Per-customer overrides
// ---------------------------------------------------------------------------

fn override_schema(row: OverrideRow) -> CustomerBrandingOverride {
    CustomerBrandingOverride {
        id: row.id,
        customer_code: row.customer_code,
        enabled: row.enabled,
        title: row.title,
        logo_base64: row.logo_base64,
        logo_mime_type: row.logo_mime_type,
        brand_color: row.brand_color,
        updated_at: services::isoformat(row.updated_at),
        updated_by: row.updated_by,
    }
}

/// `GET /branding`. Python lists every customer's override to any analyst;
/// here a scoped caller sees their customers' only (a difference by design:
/// the codes, titles and colours are other tenants' data).
async fn list_branding(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<PortalState>,
) -> ApiResult {
    let rows = internal_errors(
        "list customer branding overrides",
        async {
            let scope = match auth.access(&st.ctx).await? {
                AccessScope::All => None,
                AccessScope::Customers(codes) => Some(codes.clone()),
            };
            Ok::<_, ApiError>(services::list_overrides(&st.ctx.db, scope.as_deref()).await?)
        }
        .await,
    )?;
    Ok(json(CustomerBrandingListResponse {
        success: true,
        message: "Customer branding overrides retrieved successfully".into(),
        overrides: rows
            .into_iter()
            .map(
                |(customer_code, enabled, title, has_logo, brand_color, updated_at)| {
                    CustomerBrandingListItem {
                        customer_code,
                        enabled,
                        title,
                        has_logo,
                        brand_color,
                        updated_at: services::isoformat(updated_at),
                    }
                },
            )
            .collect(),
    }))
}

async fn get_branding(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<PortalState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &customer_code).await?;
    let (row, effective) = internal_errors(
        "get customer branding",
        async {
            let row = services::override_row(&st.ctx.db, &customer_code).await?;
            let effective =
                services::resolve_effective(&st.ctx.db, &st.branding, Some(&customer_code)).await?;
            Ok::<_, ApiError>((row, effective))
        }
        .await,
    )?;
    Ok(json(CustomerBrandingResponse {
        success: true,
        message: "Customer branding retrieved successfully".into(),
        override_row: row.map(override_schema),
        effective: Some(effective),
    }))
}

async fn put_branding(
    State(st): State<PortalState>,
    Path(customer_code): Path<String>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let req = body.model(UpdateCustomerBrandingRequest::read)?;
    if !alerts::customer_exists(&st.ctx.db, &customer_code).await? {
        return Err(ApiError::not_found(format!(
            "Customer {customer_code} not found"
        )));
    }
    let (row, effective) = internal_errors(
        "save customer branding",
        async {
            let row = services::upsert_override(
                &st.ctx.db,
                &customer_code,
                req.enabled,
                &req.fields,
                auth.id,
                now_utc_micros(),
            )
            .await?;
            st.branding.invalidate_all();
            let effective =
                services::resolve_effective(&st.ctx.db, &st.branding, Some(&customer_code)).await?;
            Ok::<_, ApiError>((row, effective))
        }
        .await,
    )?;
    tracing::info!(
        customer_code = %customer_code,
        enabled = req.enabled,
        "customer portal branding override saved"
    );
    Ok(json(CustomerBrandingResponse {
        success: true,
        message: "Customer branding override saved successfully".into(),
        override_row: Some(override_schema(row)),
        effective: Some(effective),
    }))
}

async fn delete_branding(
    _auth: Authorized<AdminOnly>,
    State(st): State<PortalState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    let (deleted, effective) = internal_errors(
        "delete customer branding",
        async {
            let deleted = services::delete_override(&st.ctx.db, &customer_code).await?;
            if deleted {
                st.branding.invalidate_all();
            }
            let effective =
                services::resolve_effective(&st.ctx.db, &st.branding, Some(&customer_code)).await?;
            Ok::<_, ApiError>((deleted, effective))
        }
        .await,
    )?;
    Ok(json(CustomerBrandingResponse {
        success: true,
        message: if deleted {
            "Customer branding override removed - inheriting global portal settings"
        } else {
            "No branding override configured - already inheriting global portal settings"
        }
        .into(),
        override_row: None,
        effective: Some(effective),
    }))
}
