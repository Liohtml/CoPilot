//! `/api/auth/sso/*` — `app/auth/routes/sso.py`.
//!
//! | Route | Guard |
//! |---|---|
//! | `GET /sso/status` | none |
//! | `GET`/`PUT /sso/settings`, `GET`/`POST /sso/allowed-emails`, `DELETE /sso/allowed-emails/{id}` | admin |
//! | `GET /sso/azure/login`, `/sso/google/login` | none — 307 to the provider |
//! | `GET /sso/azure/callback`, `/sso/google/callback` | none — 307 to `/sso-callback#token=…` or `/login?error_message=…` |
//! | `POST /sso/cloudflare/verify` | the `Cf-Access-Jwt-Assertion` header or `CF_Authorization` cookie |

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use copilot_auth::pyvalue::PyValue;
use copilot_db::sso::{self, SsoConfigRow};
use copilot_web::body::WithJson;
use copilot_web::pyurl::{cookie, header_latin1, quote, redirect_location};
use copilot_web::validate::{StrRules, Validator, path_int};
use copilot_web::{AdminOnly, ApiError, ApiResult, Authorized, QueryPairs};

use crate::IdentityState;
use crate::services::sso::{IdpError, ResolveError, issue_token, resolve_user};
use crate::sso_schema::{
    AllowedEmailCreated, AllowedEmailInput, AllowedEmailList, AllowedEmailOut, CloudflareToken,
    ConfigResponse, ConfigUpdate, Done, PublicStatus,
};

type Admin = Authorized<AdminOnly>;

/// The SSO routes, mounted under `/api/auth`.
pub fn router() -> Router<IdentityState> {
    Router::new()
        .route("/sso/status", get(public_status))
        .route("/sso/settings", get(get_settings).put(put_settings))
        .route("/sso/allowed-emails", get(list_allowed).post(add_allowed))
        .route("/sso/allowed-emails/{email_id}", delete(remove_allowed))
        .route("/sso/azure/login", get(azure_login))
        .route("/sso/azure/callback", get(azure_callback))
        .route("/sso/google/login", get(google_login))
        .route("/sso/google/callback", get(google_callback))
        .route("/sso/cloudflare/verify", post(cloudflare_verify))
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

/// `RedirectResponse(url)`: 307, the URL quoted as Starlette quotes it.
fn redirect(location: &str) -> Response {
    let mut resp = http::StatusCode::TEMPORARY_REDIRECT.into_response();
    if let Ok(value) = http::HeaderValue::from_str(location) {
        resp.headers_mut().insert(http::header::LOCATION, value);
    }
    resp
}

/// `_error_redirect(detail)`.
fn error_redirect(detail: &str) -> Response {
    redirect(&redirect_location(&format!(
        "/login?error_message={}",
        quote(detail, "/")
    )))
}

async fn config(st: &IdentityState) -> Result<Option<SsoConfigRow>, ApiError> {
    Ok(sso::config(&st.ctx.db).await?)
}

async fn public_status(State(st): State<IdentityState>) -> ApiResult {
    let status = match config(&st).await?.filter(|c| c.sso_enabled) {
        None => PublicStatus {
            sso_enabled: false,
            azure_enabled: false,
            google_enabled: false,
            cf_enabled: false,
            azure_authorization_url: None,
            google_authorization_url: None,
        },
        Some(cfg) => PublicStatus {
            sso_enabled: true,
            azure_enabled: cfg.azure_enabled,
            google_enabled: cfg.google_enabled,
            cf_enabled: cfg.cf_enabled,
            azure_authorization_url: None,
            google_authorization_url: None,
        },
    };
    Ok(json(status))
}

async fn get_settings(State(st): State<IdentityState>, _auth: Admin) -> ApiResult {
    Ok(json(match config(&st).await? {
        Some(cfg) => ConfigResponse::from_row(&cfg, "SSO configuration retrieved"),
        None => ConfigResponse::from_row(&SsoConfigRow::default(), "No SSO configuration found"),
    }))
}

async fn put_settings(
    State(st): State<IdentityState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let ConfigUpdate(mut update) = body.model(ConfigUpdate::read)?;
    // An empty or absent secret keeps the stored one.
    update.azure_client_secret = update.azure_client_secret.filter(|s| !s.is_empty());
    update.google_client_secret = update.google_client_secret.filter(|s| !s.is_empty());
    let cfg = sso::upsert_config(&st.ctx.db, &update).await?;
    tracing::info!(
        sso_enabled = cfg.sso_enabled,
        azure = cfg.azure_enabled,
        google = cfg.google_enabled,
        cf = cfg.cf_enabled,
        "SSO config updated"
    );
    Ok(json(ConfigResponse::from_row(
        &cfg,
        "SSO configuration updated successfully",
    )))
}

async fn list_allowed(State(st): State<IdentityState>, _auth: Admin) -> ApiResult {
    let emails = sso::allowed_emails(&st.ctx.db)
        .await?
        .into_iter()
        .map(|e| AllowedEmailOut {
            id: e.id,
            email: e.email,
            role_id: e.role_id,
            created_at: e.created_at,
        })
        .collect();
    Ok(json(AllowedEmailList {
        emails,
        message: "Allowed emails retrieved",
        success: true,
    }))
}

async fn add_allowed(
    State(st): State<IdentityState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let input = body.model(AllowedEmailInput::read)?;
    let email = input.email.to_lowercase();
    let id = sso::add_allowed_email(&st.ctx.db, &email, input.role_id)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request(format!("Email {email} is already in the allowlist"))
        })?;
    Ok((
        http::StatusCode::CREATED,
        Json(AllowedEmailCreated {
            message: format!("Email {} added to SSO allowlist", input.email),
            success: true,
            id,
        }),
    )
        .into_response())
}

async fn remove_allowed(
    State(st): State<IdentityState>,
    _auth: Admin,
    Path(raw): Path<String>,
) -> ApiResult {
    let email_id = path_int("email_id", &raw)?;
    if !sso::delete_allowed_email(&st.ctx.db, email_id).await? {
        return Err(ApiError::not_found("Email entry not found"));
    }
    Ok(json(Done {
        message: "Email removed from SSO allowlist",
        success: true,
    }))
}

async fn azure_login(State(st): State<IdentityState>) -> ApiResult {
    let cfg = config(&st)
        .await?
        .filter(|c| c.sso_enabled && c.azure_enabled)
        .ok_or_else(|| ApiError::bad_request("Azure SSO is not enabled"))?;
    Ok(redirect(&st.sso.azure_auth_location(&cfg)))
}

async fn google_login(State(st): State<IdentityState>) -> ApiResult {
    let cfg = config(&st)
        .await?
        .filter(|c| c.sso_enabled && c.google_enabled)
        .ok_or_else(|| ApiError::bad_request("Google SSO is not enabled"))?;
    Ok(redirect(&st.sso.google_auth_location(&cfg)))
}

/// `code`, `state`, `error`: `str = None` query parameters.
fn callback_params(q: &QueryPairs) -> Result<[Option<String>; 3], ApiError> {
    let mut v = Validator::new();
    let code = q.opt_str(&mut v, "code", StrRules::any());
    let state = q.opt_str(&mut v, "state", StrRules::any());
    let error = q.opt_str(&mut v, "error", StrRules::any());
    v.finish()?;
    Ok([code, state, error])
}

#[derive(Clone, Copy)]
enum Provider {
    Azure,
    Google,
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Provider::Azure => "Azure",
            Provider::Google => "Google",
        }
    }

    fn enabled(self, cfg: &SsoConfigRow) -> bool {
        cfg.sso_enabled
            && match self {
                Provider::Azure => cfg.azure_enabled,
                Provider::Google => cfg.google_enabled,
            }
    }

    /// The address and `email_verified` as each callback reads them.
    fn email(self, claims: &PyValue) -> (Option<PyValue>, bool) {
        let email = match self {
            Provider::Azure => claims
                .get("email")
                .filter(|e| e.truthy())
                .or_else(|| claims.get("preferred_username"))
                .cloned(),
            Provider::Google => claims.get("email").cloned(),
        };
        let default = matches!(self, Provider::Azure);
        let verified = claims
            .get("email_verified")
            .map_or(default, PyValue::truthy);
        (email.filter(PyValue::truthy), verified)
    }
}

async fn callback(st: &IdentityState, provider: Provider, q: &QueryPairs) -> ApiResult {
    let name = provider.name();
    let [code, state, error] = callback_params(q)?;
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return Ok(error_redirect(&format!("{name} auth error: {error}")));
    }
    let (Some(code), Some(state)) = (
        code.filter(|c| !c.is_empty()),
        state.filter(|s| !s.is_empty()),
    ) else {
        return Ok(error_redirect("Missing code or state parameter"));
    };
    let Some(cfg) = config(st).await?.filter(|c| provider.enabled(c)) else {
        return Ok(error_redirect(&format!("{name} SSO is not enabled")));
    };
    let exchanged = match provider {
        Provider::Azure => st.sso.exchange_azure(&code, &state, &cfg).await,
        Provider::Google => st.sso.exchange_google(&code, &state, &cfg).await,
    };
    let claims = match exchanged {
        Ok(claims) => claims,
        Err(IdpError::Value(message)) => return Ok(error_redirect(&message)),
        Err(IdpError::Other(cause)) => {
            tracing::error!(%cause, "{name} SSO error");
            return Ok(error_redirect(&format!("{name} authentication failed")));
        }
    };
    let (email, verified) = provider.email(&claims);
    let Some(email) = email else {
        return Ok(error_redirect(&format!(
            "No email claim in {name} ID token"
        )));
    };
    if !verified {
        return Ok(error_redirect(&format!(
            "{name} account email is not verified"
        )));
    }
    // `email.lower()` on a non-string claim is an AttributeError: a 500.
    let email = email
        .as_str()
        .ok_or_else(|| ApiError::internal("email claim is not a string"))?
        .to_lowercase();
    let user = match resolve_user(st, &email).await {
        Ok(user) => user,
        Err(ResolveError::NotAuthorized(message)) => return Ok(error_redirect(&message)),
        Err(ResolveError::Internal(e)) => return Err(e),
    };
    let (token, two_factor) = issue_token(st, &user).await?;
    tracing::info!(username = %user.username, %email, two_factor, "SSO {name} login");
    let mut url = format!("/sso-callback#token={token}");
    if two_factor {
        url.push_str("&requires_2fa=true");
    }
    Ok(redirect(&redirect_location(&url)))
}

async fn azure_callback(State(st): State<IdentityState>, q: QueryPairs) -> ApiResult {
    callback(&st, Provider::Azure, &q).await
}

async fn google_callback(State(st): State<IdentityState>, q: QueryPairs) -> ApiResult {
    callback(&st, Provider::Google, &q).await
}

async fn cloudflare_verify(State(st): State<IdentityState>, headers: HeaderMap) -> ApiResult {
    let cfg = config(&st)
        .await?
        .filter(|c| c.sso_enabled && c.cf_enabled)
        .ok_or_else(|| ApiError::bad_request("Cloudflare Access SSO is not enabled"))?;
    let token = header_latin1(&headers, "cf-access-jwt-assertion")
        .filter(|t| !t.is_empty())
        .or_else(|| {
            header_latin1(&headers, "cookie")
                .filter(|c| !c.is_empty())
                .and_then(|c| cookie(&c, "CF_Authorization"))
        })
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ApiError::unauthorized("No Cloudflare Access JWT found in request headers or cookies")
        })?;
    let claims = match st.sso.validate_cloudflare(&token, &cfg).await {
        Ok(claims) => claims,
        Err(IdpError::Value(message)) => return Err(ApiError::unauthorized(message)),
        Err(IdpError::Other(cause)) => {
            tracing::error!(%cause, "Cloudflare Access SSO error");
            return Err(ApiError::server_error("Cloudflare authentication failed"));
        }
    };
    let email = claims
        .get("email")
        .filter(|e| e.truthy())
        .ok_or_else(|| ApiError::bad_request("No email claim in Cloudflare JWT"))?;
    let email = email
        .as_str()
        .ok_or_else(|| ApiError::internal("email claim is not a string"))?
        .to_lowercase();
    let user = match resolve_user(&st, &email).await {
        Ok(user) => user,
        Err(ResolveError::NotAuthorized(message)) => return Err(ApiError::forbidden(message)),
        Err(ResolveError::Internal(e)) => return Err(e),
    };
    let (access_token, two_factor) = issue_token(&st, &user).await?;
    tracing::info!(username = %user.username, %email, two_factor, "SSO Cloudflare login");
    Ok(json(CloudflareToken {
        access_token,
        token_type: "bearer",
        message: "Cloudflare Access authentication successful",
        success: true,
        requires_2fa: two_factor.then_some(true),
    }))
}
