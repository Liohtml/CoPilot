//! The e2e harness shared by every `tests/e2e*.rs` suite: the production
//! router on a real MySQL at the Alembic head (`COPILOT_TEST_DATABASE_URL`).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use wiremock::MockServer;

use copilot::app::App;
use copilot_auth::JwtCodec;
use copilot_core::config::{CopilotConfig, Secret};
use copilot_core::env::EnvFile;
use copilot_db::Db;

pub const SECRET: &str = "e2e-secret-not-for-production-0123456789";

pub struct Harness {
    pub router: Router,
    pub db: Db,
    pub jwt: JwtCodec,
    pub suffix: String,
    pub app: App,
}

impl Harness {
    pub fn code(&self, base: &str) -> String {
        format!("{base}{}", self.suffix)
    }

    pub fn token(&self, username: &str, role: &str) -> String {
        self.jwt
            .encode_session(username, role, Duration::from_secs(600), None)
            .unwrap()
    }

    pub async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&v).unwrap()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, value)
    }

    /// A request with an arbitrary body and content type.
    pub async fn call_raw(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        content_type: Option<&str>,
        body: impl Into<Body>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        if let Some(ct) = content_type {
            b = b.header("content-type", ct);
        }
        let resp = self
            .router
            .clone()
            .oneshot(b.body(body.into()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, value)
    }

    /// `POST` an urlencoded login form.
    pub async fn login(&self, path: &str, username: &str, password: &str) -> (StatusCode, Value) {
        self.call_raw(
            "POST",
            path,
            None,
            Some("application/x-www-form-urlencoded"),
            format!("username={username}&password={password}"),
        )
        .await
    }

    /// Run a statement; returns its `LAST_INSERT_ID()`.
    pub async fn exec(&self, sql: &str) -> i64 {
        let res = sqlx::query(sql).execute(self.db.pool()).await.unwrap();
        i64::try_from(res.last_insert_id()).unwrap()
    }

    pub async fn scalar_i64(&self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }

    /// Customers `acme<sfx>` and `beta<sfx>`; users admin/analyst(acme)/
    /// responder(acme)/portal(acme); one alert per customer with an asset.
    /// Returns `(acme_alert, beta_alert)`.
    pub async fn seed(&self) -> (i64, i64) {
        let s = &self.suffix;
        for c in ["acme", "beta"] {
            self.exec(&format!(
                "INSERT INTO customers (customer_code, customer_name, created_at) \
                 VALUES ('{c}{s}', '{c} corp', UTC_TIMESTAMP())"
            ))
            .await;
        }
        for (name, role) in [
            ("admin", 1),
            ("analyst", 2),
            ("responder", 5),
            ("portal", 4),
        ] {
            self.exec(&format!(
                "INSERT INTO `user` (username, password, email, created_at, role_id) \
                 VALUES ('{name}{s}', 'x', '{name}@example.com', UTC_TIMESTAMP(), {role})"
            ))
            .await;
        }
        for name in ["analyst", "responder", "portal"] {
            self.exec(&format!(
                "INSERT INTO user_customer_access (user_id, customer_code, created_at) \
                 SELECT id, 'acme{s}', UTC_TIMESTAMP() FROM `user` WHERE username = '{name}{s}'"
            ))
            .await;
        }
        let mut alerts = Vec::new();
        for c in ["acme", "beta"] {
            let id = self
                .exec(&format!(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
                     alert_creation_time, customer_code, source, escalated) VALUES \
                     ('Mimikatz {c}', 'd', 'OPEN', UTC_TIMESTAMP(), '{c}{s}', 'wazuh', 0)"
                ))
                .await;
            let ctx = self
                .exec("INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')")
                .await;
            self.exec(&format!(
                "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, \
                 customer_code, index_name, index_id) VALUES ({id}, 'dc01-{c}', {ctx}, '{c}{s}', 'idx', 'doc')"
            ))
            .await;
            alerts.push(id);
        }
        (alerts[0], alerts[1])
    }
}

/// `extra` is appended to the `.env` the app is configured from.
pub async fn harness_env(legacy: Option<&MockServer>, extra: &str) -> Option<Harness> {
    let url = std::env::var("COPILOT_TEST_DATABASE_URL").ok()?;
    let mut env = format!(
        "JWT_SECRET={SECRET}\nCOPILOT_DATABASE_URL={url}\nCONNECTOR_CACHE_TTL_SECONDS=0\n\
         COPILOT_URL=https://copilot.example.com\n"
    );
    if let Some(l) = legacy {
        env.push_str(&format!("COPILOT_LEGACY_URL={}\n", l.uri()));
    }
    env.push_str(extra);
    let cfg = CopilotConfig::from_env(Path::new("."), &EnvFile::isolated(&env)).unwrap();
    let db = Db::connect(&cfg.database).await.unwrap();
    let app = App::new(&cfg, db.clone()).unwrap();
    let router = app.router(cfg.max_body_bytes);
    let suffix = format!("{:06x}", rand_suffix());
    Some(Harness {
        router,
        db,
        jwt: JwtCodec::new(&Secret::new(SECRET)),
        suffix,
        app,
    })
}

pub fn rand_suffix() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos ^ std::process::id()).wrapping_mul(2_654_435_761) & 0xff_ffff
}

macro_rules! harness_or_skip {
    ($legacy:expr) => {
        harness_or_skip!($legacy, "")
    };
    ($legacy:expr, $extra:expr) => {
        match harness_env($legacy, $extra).await {
            Some(h) => h,
            None => {
                eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
                return;
            }
        }
    };
}
