//! End-to-end tests of phase 5's schema and startup tasks (`copilot-migrate`,
//! `copilot-startup`) on a real MySQL: the runner on an empty database
//! compared with the e2e fixture, adoption, the refusals, pending and failed
//! migrations, two processes starting at once, every seeding step and its
//! idempotence, the PRODUCTION bootstrap through root, and doctor's lines.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13307/copilot \
//!   cargo test -p copilot --test e2e_startup -- --test-threads=1
//! ```
//!
//! Every test works on throwaway databases (`copilot_rs_e2e_startup_*`),
//! created and dropped by the user of `COPILOT_TEST_ADMIN_DATABASE_URL`
//! (default: `COPILOT_TEST_DATABASE_URL`'s, which needs the privilege to
//! create databases — a test says so and returns when it lacks it); the
//! shared database is never touched. The bootstrap test logs in as root at
//! the same server (`COPILOT_TEST_MYSQL_ROOT_PASSWORD`, default empty) and
//! creates and drops a throwaway database and user. The MinIO stand-in
//! listens on `STARTUP_E2E_S3_PORT` (6310).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use sqlx::{Connection, MySqlConnection, Row};

use copilot_core::config::{CopilotConfig, DatabaseConfig};
use copilot_core::env::EnvFile;
use copilot_db::Db;
use copilot_migrate::{Action, BASELINE, MIGRATIONS, MigrateError, Migration, Refusal};
use copilot_objectstore::ObjectStore;
use copilot_startup::{SeedDeps, Startup, StartupError};

const FIXTURE: &str = include_str!("fixtures/schema.sql");
const SECRET: &str = "e2e-startup-secret-not-for-production-0123";

fn admin_url() -> Option<url::Url> {
    let raw = std::env::var("COPILOT_TEST_ADMIN_DATABASE_URL")
        .or_else(|_| std::env::var("COPILOT_TEST_DATABASE_URL"))
        .ok()?;
    url::Url::parse(&raw).ok()
}

fn url_for(db: &str) -> String {
    let mut u = admin_url().unwrap();
    u.set_path(&format!("/{db}"));
    u.to_string()
}

fn cfg_for(db: &str, extra: &str) -> CopilotConfig {
    let env = format!(
        "JWT_SECRET={SECRET}\nCOPILOT_DATABASE_URL={}\n{extra}",
        url_for(db)
    );
    CopilotConfig::from_env(Path::new("."), &EnvFile::isolated(&env)).unwrap()
}

async fn server() -> MySqlConnection {
    let mut u = admin_url().unwrap();
    u.set_path("/");
    MySqlConnection::connect(u.as_str()).await.unwrap()
}

/// A fresh empty database, or `None` (with a message) when the test user may
/// not create one.
async fn fresh(name: &str) -> Option<DatabaseConfig> {
    admin_url()?;
    let mut conn = server().await;
    let _ = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS `{name}`"))
        .execute(&mut conn)
        .await;
    if let Err(e) = sqlx::raw_sql(&format!("CREATE DATABASE `{name}`"))
        .execute(&mut conn)
        .await
    {
        eprintln!(
            "skipped: cannot create a throwaway database ({e}); set \
             COPILOT_TEST_ADMIN_DATABASE_URL to a user that can"
        );
        return None;
    }
    Some(cfg_for(name, "").database)
}

async fn drop_db(name: &str) {
    let mut conn = server().await;
    sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS `{name}`"))
        .execute(&mut conn)
        .await
        .unwrap();
}

async fn conn_to(db: &DatabaseConfig) -> MySqlConnection {
    use sqlx::ConnectOptions;
    copilot_db::pool::connect_options(db)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

async fn exec(db: &DatabaseConfig, sql: &str) {
    let mut c = conn_to(db).await;
    sqlx::raw_sql(sql).execute(&mut c).await.unwrap();
}

async fn scalar(db: &DatabaseConfig, sql: &str) -> i64 {
    let mut c = conn_to(db).await;
    sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(&mut c)
        .await
        .unwrap()
}

/// `SHOW CREATE TABLE` of every table, the AUTO_INCREMENT counter removed.
async fn schema_of(db: &DatabaseConfig) -> BTreeMap<String, String> {
    let mut c = conn_to(db).await;
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT CAST(table_name AS CHAR CHARACTER SET utf8mb4) FROM information_schema.tables \
         WHERE table_schema = DATABASE()",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let mut out = BTreeMap::new();
    for n in names {
        let row = sqlx::query(&format!("SHOW CREATE TABLE `{n}`"))
            .fetch_one(&mut c)
            .await
            .unwrap();
        let ddl: String = row.get(1);
        out.insert(n, strip_auto_increment(&ddl));
    }
    out
}

fn strip_auto_increment(ddl: &str) -> String {
    let re = regex::Regex::new(r" AUTO_INCREMENT=\d+").unwrap();
    re.replace_all(ddl, "").into_owned()
}

/// The fixture's `CREATE TABLE` statements by table.
fn fixture_tables() -> BTreeMap<String, String> {
    copilot_migrate::sql::split_statements(FIXTURE)
        .into_iter()
        .filter_map(|s| {
            let ddl = &s[s.find("CREATE TABLE `")?..];
            let name = ddl["CREATE TABLE `".len()..].split('`').next()?.to_string();
            Some((name, ddl.to_string()))
        })
        .collect()
}

async fn migrate(db: &DatabaseConfig) -> Result<copilot_migrate::Report, StartupError> {
    copilot_startup::migrate_now(db).await
}

// --- the runner ----------------------------------------------------------------------------

#[tokio::test]
async fn the_runner_on_an_empty_database_creates_the_fixture() {
    let name = "copilot_rs_e2e_startup_empty";
    let Some(db) = fresh(name).await else { return };
    let report = migrate(&db).await.unwrap();
    assert!(matches!(
        report.actions.as_slice(),
        [Action::Applied { migration, .. }] if migration == "0001_baseline"
    ));
    let mut tables = schema_of(&db).await;
    let history = tables.remove(copilot_migrate::HISTORY_TABLE).unwrap();
    assert!(history.contains("`checksum` char(64) NOT NULL"));
    let expected = fixture_tables();
    assert_eq!(tables.len(), 116);
    assert_eq!(
        tables.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (t, ddl) in &tables {
        assert_eq!(ddl, &expected[t], "{t}");
    }
    // The rows `alembic upgrade head` leaves: its head and the five roles.
    let mut c = conn_to(&db).await;
    let rev: Vec<String> = sqlx::query_scalar("SELECT version_num FROM alembic_version")
        .fetch_all(&mut c)
        .await
        .unwrap();
    assert_eq!(rev, vec![copilot_migrate::ALEMBIC_HEAD.to_string()]);
    let roles: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id, name, description FROM role ORDER BY id")
            .fetch_all(&mut c)
            .await
            .unwrap();
    let fixture_roles: Vec<String> = FIXTURE
        .lines()
        .filter(|l| l.starts_with("INSERT INTO `role`"))
        .map(str::to_string)
        .collect();
    assert_eq!(roles.len(), fixture_roles.len());
    for ((id, n, d), line) in roles.iter().zip(&fixture_roles) {
        assert_eq!(
            line,
            &format!("INSERT INTO `role` VALUES ({id},'{n}','{d}');")
        );
    }
    let row: (i64, String, String, String, bool) = sqlx::query_as(
        "SELECT version, name, checksum, method, success FROM copilot_rs_schema_history",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            1,
            "baseline".into(),
            BASELINE.checksum(),
            "applied".into(),
            true
        )
    );
    // Again: nothing to do.
    assert!(migrate(&db).await.unwrap().actions.is_empty());
    drop_db(name).await;
}

#[tokio::test]
async fn a_database_at_the_alembic_head_is_adopted_untouched() {
    let name = "copilot_rs_e2e_startup_adopt";
    let Some(db) = fresh(name).await else { return };
    // What Python's Alembic leaves: the fixture, loaded statement by statement.
    let mut c = conn_to(&db).await;
    for stmt in copilot_migrate::sql::split_statements(FIXTURE) {
        sqlx::raw_sql(stmt).execute(&mut c).await.unwrap();
    }
    exec(&db, "INSERT INTO customers (customer_code, customer_name, created_at) VALUES ('kept', 'Kept', UTC_TIMESTAMP())").await;
    let before = schema_of(&db).await;
    let report = migrate(&db).await.unwrap();
    assert_eq!(
        report.actions,
        vec![Action::Adopted("0001_baseline".into())]
    );
    let mut after = schema_of(&db).await;
    after.remove(copilot_migrate::HISTORY_TABLE).unwrap();
    assert_eq!(before, after);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM customers").await, 1);
    let method: String = sqlx::query_scalar("SELECT method FROM copilot_rs_schema_history")
        .fetch_one(&mut c)
        .await
        .unwrap();
    assert_eq!(method, "adopted");
    assert!(migrate(&db).await.unwrap().actions.is_empty());
    drop_db(name).await;
}

#[tokio::test]
async fn databases_it_cannot_own_are_refused_untouched() {
    let name = "copilot_rs_e2e_startup_refused";
    let Some(db) = fresh(name).await else { return };
    let refusal = |r: Result<copilot_migrate::Report, StartupError>| match r {
        Err(StartupError::Migrate(MigrateError::Refused(r))) => r,
        other => panic!("not refused: {other:?}"),
    };
    // Tables, no version.
    exec(&db, "CREATE TABLE foo (id int)").await;
    let r = refusal(migrate(&db).await);
    assert_eq!(r, Refusal::Unversioned(vec!["foo".into()]));
    // An older Alembic revision: refused, naming it and what to do.
    exec(&db, "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, PRIMARY KEY (version_num)); INSERT INTO alembic_version VALUES ('c1219a2b3c4d')").await;
    let r = refusal(migrate(&db).await);
    assert_eq!(r, Refusal::OlderAlembic("c1219a2b3c4d".into()));
    let text = r.to_string();
    assert!(text.contains("c1219a2b3c4d") && text.contains("last release of the Python backend"));
    // An unknown one.
    exec(
        &db,
        "UPDATE alembic_version SET version_num = 'notcopilot01'",
    )
    .await;
    assert_eq!(
        refusal(migrate(&db).await),
        Refusal::UnknownAlembic("notcopilot01".into())
    );
    // An empty table.
    exec(&db, "DELETE FROM alembic_version").await;
    assert_eq!(refusal(migrate(&db).await), Refusal::EmptyAlembic);
    // Nothing was created by any of these.
    assert_eq!(
        scalar(
            &db,
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()"
        )
        .await,
        2,
        "a refused database is not touched: foo and alembic_version only"
    );
    drop_db(name).await;
}

#[tokio::test]
async fn the_history_is_checked_and_pending_migrations_run_once() {
    let name = "copilot_rs_e2e_startup_history";
    let Some(db) = fresh(name).await else { return };
    migrate(&db).await.unwrap();
    const EXTRA: Migration = Migration {
        version: 2,
        name: "e2e_extra",
        sql: "-- a later migration\nCREATE TABLE e2e_extra (id int NOT NULL, note varchar(9) \
              DEFAULT 'a;b', PRIMARY KEY (id));\nINSERT INTO e2e_extra (id) VALUES (1);\n",
    };
    const BROKEN: Migration = Migration {
        version: 3,
        name: "e2e_broken",
        sql: "CREATE TABLE e2e_broken (id int);\nTHIS IS NOT SQL;\n",
    };
    let mut lock = copilot_migrate::StartupLock::acquire(
        &copilot_db::pool::connect_options(&db).unwrap(),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let r = copilot_migrate::migrate(lock.conn(), &[BASELINE, EXTRA])
        .await
        .unwrap();
    assert!(
        matches!(r.actions.as_slice(), [Action::Applied { migration, .. }] if migration == "0002_e2e_extra")
    );
    assert!(
        copilot_migrate::migrate(lock.conn(), &[BASELINE, EXTRA])
            .await
            .unwrap()
            .actions
            .is_empty()
    );
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM e2e_extra").await, 1);
    // A failing migration stays recorded as unfinished, and the next run
    // refuses to go on.
    let e = copilot_migrate::migrate(lock.conn(), &[BASELINE, EXTRA, BROKEN])
        .await
        .unwrap_err();
    assert!(
        matches!(&e, MigrateError::Statement { migration, index: 2, .. } if migration == "0003_e2e_broken"),
        "{e}"
    );
    assert!(matches!(
        copilot_migrate::migrate(lock.conn(), &[BASELINE, EXTRA, BROKEN]).await,
        Err(MigrateError::Refused(Refusal::Unfinished(r))) if r.version == 3
    ));
    // A build without migration 2 refuses a database that has it.
    exec(
        &db,
        "DELETE FROM copilot_rs_schema_history WHERE version = 3",
    )
    .await;
    assert!(matches!(
        copilot_migrate::migrate(lock.conn(), MIGRATIONS).await,
        Err(MigrateError::Refused(Refusal::UnknownMigration(r))) if r.version == 2
    ));
    // An edited migration is refused.
    exec(
        &db,
        "UPDATE copilot_rs_schema_history SET checksum = REPEAT('0', 64) WHERE version = 2",
    )
    .await;
    assert!(matches!(
        copilot_migrate::migrate(lock.conn(), &[BASELINE, EXTRA]).await,
        Err(MigrateError::Refused(Refusal::ChecksumMismatch(r))) if r.version == 2
    ));
    lock.release().await;
    drop_db(name).await;
}

#[tokio::test]
async fn two_processes_starting_at_once_create_one_schema() {
    let name = "copilot_rs_e2e_startup_race";
    let Some(db) = fresh(name).await else { return };
    let (a, b) = tokio::join!(migrate(&db), migrate(&db));
    let mut actions: Vec<usize> = vec![a.unwrap().actions.len(), b.unwrap().actions.len()];
    actions.sort_unstable();
    assert_eq!(actions, vec![0, 1]);
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM copilot_rs_schema_history").await,
        1
    );
    drop_db(name).await;
}

// --- the startup tasks -----------------------------------------------------------------------

/// A MinIO with buckets: the bucket location, `HEAD` and `PUT` of a bucket,
/// recorded.
#[derive(Default)]
struct S3 {
    buckets: Mutex<Vec<String>>,
    seen: Mutex<Vec<String>>,
}

fn s3_port() -> u16 {
    std::env::var("STARTUP_E2E_S3_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(6310)
}

impl S3 {
    fn handle(&self, method: &Method, uri: &Uri) -> Response {
        let bucket = uri.path().trim_start_matches('/').to_string();
        let query = uri.query().unwrap_or("").to_string();
        self.seen.lock().unwrap().push(format!(
            "{method} {}{}",
            uri.path(),
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        ));
        let mut buckets = self.buckets.lock().unwrap();
        let exists = buckets.contains(&bucket);
        let missing = || {
            if *method == Method::HEAD {
                return StatusCode::NOT_FOUND.into_response();
            }
            (
                StatusCode::NOT_FOUND,
                [("Content-Type", "application/xml")],
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchBucket</Code>\
                     <Message>NoSuchBucket</Message><BucketName>{bucket}</BucketName><Resource>/{bucket}\
                     </Resource><RequestId>E2E</RequestId><HostId>e2e</HostId></Error>"
                ),
            )
                .into_response()
        };
        match (method.as_str(), query.as_str()) {
            ("GET", "location=") if exists => (
                StatusCode::OK,
                [("Content-Type", "application/xml")],
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint \
                 xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>",
            )
                .into_response(),
            ("GET", "location=") | ("HEAD", _) if !exists => missing(),
            ("HEAD", _) => StatusCode::OK.into_response(),
            ("PUT", "") => {
                buckets.push(bucket);
                StatusCode::OK.into_response()
            }
            _ => StatusCode::NOT_IMPLEMENTED.into_response(),
        }
    }
}

async fn s3() -> Arc<S3> {
    let s3 = Arc::new(S3::default());
    let mut tries = 0;
    let listener = loop {
        match tokio::net::TcpListener::bind(("127.0.0.1", s3_port())).await {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the S3 stand-in on {}: {e}", s3_port()),
        }
    };
    let served = s3.clone();
    tokio::spawn(async move {
        let app = axum::Router::new().fallback(move |m: Method, u: Uri| {
            let s = served.clone();
            async move { s.handle(&m, &u) }
        });
        axum::serve(listener, app).await.unwrap();
    });
    s3
}

fn store() -> ObjectStore {
    ObjectStore::for_endpoint(&format!("127.0.0.1:{}", s3_port()), "minio", "minio-secret").unwrap()
}

async fn baselined(name: &str) -> Option<(DatabaseConfig, Db)> {
    let db = fresh(name).await?;
    migrate(&db).await.unwrap();
    let pool = Db::connect(&db).await.unwrap();
    Some((db, pool))
}

const ENV: &str = "GRAYLOG_URL=http://graylog.e2e:9000\nGRAYLOG_USERNAME=\nGRAYLOG_PASSWORD=pw\n\
                   SHUFFLE_VERIFIED=false\nINFLUXDB_ORG_AND_BUCKET=SOCFORTRESS,telegraf\n";

#[tokio::test]
async fn the_startup_tasks_seed_once() {
    let name = "copilot_rs_e2e_startup_seed";
    if admin_url().is_none() {
        return;
    }
    let s3 = s3().await;
    let Some((db, pool)) = baselined(name).await else {
        return;
    };
    let store = store();
    let deps = SeedDeps {
        db: &pool,
        objectstore: &store,
        connectors: None,
    };
    let env = EnvFile::isolated(ENV);
    let first = copilot_startup::run_tasks(deps, &env).await.unwrap();
    assert_eq!(first.connectors_added.len(), 18);
    assert!(first.roles_added.is_empty(), "the baseline holds the roles");
    assert_eq!(first.integrations.added.len(), 13);
    assert_eq!(first.integrations.keys_added.len(), 53);
    assert_eq!(first.network_connectors.added.len(), 3);
    assert_eq!(first.network_connectors.keys_added.len(), 7);
    assert!(first.admin_created && first.scheduler_created && first.portal_settings_created);
    assert_eq!(first.templates_added, 9);
    assert_eq!(first.jobs_added.len(), 12);
    // MinIO: each bucket's region (a fresh client per bucket, as miniopy's;
    // `NoSuchBucket` there is `bucket_exists`' false), then its creation.
    let seen = std::mem::take(&mut *s3.seen.lock().unwrap());
    let expected: Vec<String> = copilot_startup::catalog::BUCKETS
        .iter()
        .flat_map(|b| [format!("GET /{b}?location="), format!("PUT /{b}")])
        .collect();
    assert_eq!(seen, expected);

    // The rows, in the catalog's order (ids ascending).
    let mut c = conn_to(&db).await;
    type ConnectorRow = (
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
        bool,
        Option<String>,
    );
    let rows: Vec<ConnectorRow> =
        sqlx::query_as(
            "SELECT connector_name, connector_url, connector_username, connector_password, \
             connector_verified, connector_accepts_extra_data, connector_extra_data FROM connectors \
             ORDER BY id",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    let catalog: Vec<&str> = copilot_startup::catalog::CONNECTORS
        .iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, catalog);
    let graylog = rows.iter().find(|r| r.0 == "Graylog").unwrap();
    assert_eq!(graylog.1, "http://graylog.e2e:9000");
    assert_eq!(graylog.2.as_deref(), Some(""), "an empty value is a value");
    assert_eq!(graylog.3.as_deref(), Some("pw"));
    let shuffle = rows.iter().find(|r| r.0 == "Shuffle").unwrap();
    assert!(shuffle.4, "bool(\"false\") is True");
    assert_eq!(shuffle.1, "", "a missing URL is stored empty");
    let influx = rows.iter().find(|r| r.0 == "InfluxDB").unwrap();
    assert!(influx.5);
    assert_eq!(influx.6.as_deref(), Some("SOCFORTRESS,telegraf"));
    let admin: (String, String, i64) =
        sqlx::query_as("SELECT password, email, role_id FROM `user` WHERE username = 'admin'")
            .fetch_one(&mut c)
            .await
            .unwrap();
    assert!(admin.0.starts_with("$2b$12$"));
    assert_eq!((admin.1.as_str(), admin.2), ("admin@admin.com", 1));
    let details: String = sqlx::query_scalar(
        "SELECT integration_details FROM available_integrations WHERE integration_name = 'SAP SIEM'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(
        details,
        copilot_startup::markdown::integration_details("SAP SIEM").unwrap()
    );
    let enabled: i64 = scalar(
        &db,
        "SELECT CAST(SUM(enabled) AS SIGNED) FROM scheduled_job_metadata",
    )
    .await;
    assert_eq!(enabled, 12);

    // Again: nothing changes, MinIO only asked.
    let counts = |tables: &[&str]| {
        tables
            .iter()
            .map(|t| format!("SELECT '{t}', COUNT(*) FROM `{t}`"))
            .collect::<Vec<_>>()
            .join(" UNION ALL ")
    };
    let all = counts(&[
        "connectors",
        "role",
        "user",
        "available_integrations",
        "available_integrations_auth_keys",
        "available_network_connectors",
        "available_network_connectors_keys",
        "notification_template",
        "customer_portal_settings",
        "scheduled_job_metadata",
    ]);
    let before: Vec<(String, i64)> = sqlx::query_as(&all).fetch_all(&mut c).await.unwrap();
    let again = copilot_startup::run_tasks(deps, &env).await.unwrap();
    assert_eq!(again, copilot_startup::Summary::default());
    let after: Vec<(String, i64)> = sqlx::query_as(&all).fetch_all(&mut c).await.unwrap();
    assert_eq!(before, after);
    let seen = std::mem::take(&mut *s3.seen.lock().unwrap());
    let expected: Vec<String> = copilot_startup::catalog::BUCKETS
        .iter()
        .flat_map(|b| [format!("GET /{b}?location="), format!("HEAD /{b}")])
        .collect();
    assert_eq!(seen, expected);

    // Python's updates: a connector that gained its extra field, an
    // integration left with the placeholder, a retired connector, a reset
    // interval (its `enabled` kept).
    exec(&db, "UPDATE connectors SET connector_accepts_extra_data = 0, connector_extra_data = 'kept' WHERE connector_name = 'OpenCTI'").await;
    exec(&db, "UPDATE available_integrations SET integration_details = 'No deployment instructions available.' WHERE integration_name = 'DUO'").await;
    exec(&db, "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, connector_configured, connector_verified, connector_accepts_host_only, connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, connector_accepts_extra_data, connector_enabled) VALUES ('cortex', '3', '', UTC_TIMESTAMP(), 1, 0, 0, 1, 0, 0, 0, 0)").await;
    exec(&db, "UPDATE scheduled_job_metadata SET time_interval = 99, enabled = 0 WHERE job_id = 'agent_sync'").await;
    exec(&db, "DELETE FROM role WHERE id = 4").await;
    let third = copilot_startup::run_tasks(deps, &env).await.unwrap();
    assert_eq!(
        third.connectors_deleted,
        vec!["Cortex"],
        "matched case-insensitively"
    );
    assert_eq!(third.integrations.refreshed, vec!["DUO"]);
    assert_eq!(third.roles_added, vec!["customer_user"]);
    let opencti: (bool, Option<String>) = sqlx::query_as(
        "SELECT connector_accepts_extra_data, connector_extra_data FROM connectors WHERE connector_name = 'OpenCTI'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(opencti, (true, Some("kept".into())));
    let job: (i64, bool) = sqlx::query_as(
        "SELECT time_interval, enabled FROM scheduled_job_metadata WHERE job_id = 'agent_sync'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(
        job,
        (15, false),
        "the interval is reset, a handed-over row stays disabled"
    );
    assert_eq!(
        scalar(&db, "SELECT id FROM role WHERE name = 'customer_user'").await,
        4
    );

    // Two rows for one job: `one_or_none()`'s error stops the start.
    exec(&db, "INSERT INTO scheduled_job_metadata (job_id, time_interval, enabled) VALUES ('prune_audit_log', 1440, 1)").await;
    let e = copilot_startup::run_tasks(deps, &env).await.unwrap_err();
    assert!(
        e.to_string()
            .contains("Multiple rows were found when one or none was required"),
        "{e}"
    );

    // The scheduler user is removed when the process stops.
    let startup = Startup::new(&EnvFile::isolated(""));
    startup.shutdown(&pool).await;
    assert_eq!(
        scalar(
            &db,
            "SELECT COUNT(*) FROM `user` WHERE username = 'scheduler'"
        )
        .await,
        0
    );
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM `user` WHERE username = 'admin'").await,
        1
    );
    pool.close().await;
    drop_db(name).await;
}

#[tokio::test]
async fn two_processes_seeding_at_once_seed_once() {
    let name = "copilot_rs_e2e_startup_seed_race";
    if admin_url().is_none() {
        return;
    }
    let _s3 = s3().await;
    let Some(db) = fresh(name).await else { return };
    let store = store();
    let run = || async {
        let startup = Startup::new(&EnvFile::isolated(ENV));
        let lock = startup.schema(&db).await.unwrap();
        let pool = Db::connect(&db).await.unwrap();
        startup
            .seed(
                lock,
                SeedDeps {
                    db: &pool,
                    objectstore: &store,
                    connectors: None,
                },
            )
            .await
            .unwrap();
        pool.close().await;
    };
    tokio::join!(run(), run());
    for (table, n) in [
        ("connectors", 18),
        ("`user`", 2),
        ("available_integrations", 13),
        ("available_integrations_auth_keys", 53),
        ("notification_template", 9),
        ("customer_portal_settings", 1),
        ("scheduled_job_metadata", 12),
        ("copilot_rs_schema_history", 1),
    ] {
        assert_eq!(
            scalar(&db, &format!("SELECT COUNT(*) FROM {table}")).await,
            n,
            "{table}"
        );
    }
    drop_db(name).await;
}

#[tokio::test]
async fn a_failing_minio_stops_the_start_and_the_switches_turn_the_tasks_off() {
    let name = "copilot_rs_e2e_startup_switches";
    let Some((db, pool)) = baselined(name).await else {
        return;
    };
    // Nothing listens there: create_buckets() fails, as Python's does.
    let closed = ObjectStore::for_endpoint("127.0.0.1:9", "minio", "minio-secret").unwrap();
    let e = copilot_startup::run_tasks(
        SeedDeps {
            db: &pool,
            objectstore: &closed,
            connectors: None,
        },
        &EnvFile::isolated(""),
    )
    .await
    .unwrap_err();
    assert!(matches!(e, StartupError::Buckets(_)), "{e}");
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM connectors").await, 0);
    // COPILOT_STARTUP_TASKS=false: no bootstrap, no rows, no lock needed
    // beyond the migrations; both off: nothing at all.
    let off = Startup::new(&EnvFile::isolated(
        "COPILOT_STARTUP_TASKS=false\nENVIRONMENT=PRODUCTION\n",
    ));
    off.bootstrap(&db).await.unwrap();
    let lock = off.schema(&db).await.unwrap();
    assert!(lock.is_some(), "the migrations still run under the lock");
    off.seed(
        lock,
        SeedDeps {
            db: &pool,
            objectstore: &closed,
            connectors: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM connectors").await, 0);
    let none = Startup::new(&EnvFile::isolated(
        "COPILOT_STARTUP_TASKS=false\nCOPILOT_RUN_MIGRATIONS=false\n",
    ));
    assert!(none.schema(&db).await.unwrap().is_none());
    // PRODUCTION without root's password stops the start.
    let prod = Startup::new(&EnvFile::isolated("ENVIRONMENT=PRODUCTION\n"));
    assert!(matches!(
        prod.bootstrap(&db).await,
        Err(StartupError::NoRootPassword)
    ));
    pool.close().await;
    drop_db(name).await;
}

// --- the PRODUCTION bootstrap -------------------------------------------------------------------

#[tokio::test]
async fn production_creates_the_database_and_its_user_through_root() {
    let Some(admin) = admin_url() else { return };
    let host = admin.host_str().unwrap().to_string();
    let port = admin.port().unwrap_or(3306);
    let root_password = std::env::var("COPILOT_TEST_MYSQL_ROOT_PASSWORD").unwrap_or_default();
    let root_url = format!(
        "mysql://root:{}@{host}:{port}/",
        url::form_urlencoded::byte_serialize(root_password.as_bytes()).collect::<String>()
    );
    let mut root = match MySqlConnection::connect(&root_url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "skipped: root cannot log in at {host}:{port} ({e}); set COPILOT_TEST_MYSQL_ROOT_PASSWORD"
            );
            return;
        }
    };
    let (db_name, user) = ("copilot_rs_e2e_startup_boot", "copilot_rs_e2e_boot");
    let cleanup = format!("DROP DATABASE IF EXISTS `{db_name}`; DROP USER IF EXISTS '{user}'@'%'");
    sqlx::raw_sql(&cleanup).execute(&mut root).await.unwrap();
    let env = format!(
        "JWT_SECRET={SECRET}\nENVIRONMENT=PRODUCTION\nMYSQL_URL={host}:{port}\nMYSQL_USER={user}\n\
         MYSQL_PASSWORD=it's a \\ pass\nMYSQL_DATABASE={db_name}\nMYSQL_ROOT_PASSWORD={root_password}\n"
    );
    let env = EnvFile::isolated(&env);
    let cfg = CopilotConfig::from_env(Path::new("."), &env).unwrap();
    let startup = Startup::new(&env);
    startup.bootstrap(&cfg.database).await.unwrap();
    // The new user reaches the new database, and only it.
    let mut c = conn_to(&cfg.database).await;
    let current: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&mut c)
        .await
        .unwrap();
    assert_eq!(current, db_name);
    let grants: Vec<String> = sqlx::query_scalar(&format!("SHOW GRANTS FOR '{user}'@'%'"))
        .fetch_all(&mut root)
        .await
        .unwrap();
    assert!(
        grants
            .iter()
            .any(|g| g == &format!("GRANT ALL PRIVILEGES ON `{db_name}`.* TO `{user}`@`%`")),
        "{grants:?}"
    );
    // Then the schema and the rows, on the database root just made.
    let lock = startup.schema(&cfg.database).await.unwrap();
    lock.unwrap().release().await;
    assert_eq!(
        scalar(
            &cfg.database,
            "SELECT COUNT(*) FROM copilot_rs_schema_history"
        )
        .await,
        1
    );
    // Again: both exist, nothing changes (an existing user keeps its grants).
    startup.bootstrap(&cfg.database).await.unwrap();
    // A wrong root password stops the start.
    let bad = EnvFile::isolated(&format!(
        "JWT_SECRET={SECRET}\nENVIRONMENT=PRODUCTION\nMYSQL_URL={host}:{port}\nMYSQL_PASSWORD=x\n\
         MYSQL_ROOT_PASSWORD=certainly-not-roots-password\n"
    ));
    let bad_cfg = CopilotConfig::from_env(Path::new("."), &bad).unwrap();
    let e = Startup::new(&bad)
        .bootstrap(&bad_cfg.database)
        .await
        .unwrap_err();
    assert!(matches!(e, StartupError::RootConnect { .. }), "{e}");
    drop(c);
    sqlx::raw_sql(&cleanup).execute(&mut root).await.unwrap();
}

// --- doctor --------------------------------------------------------------------------------------

#[tokio::test]
async fn doctor_reports_the_migration_state_and_the_preconditions() {
    let name = "copilot_rs_e2e_startup_doctor";
    let Some(db) = fresh(name).await else { return };
    let lines = copilot_startup::doctor::migrations(&db).await;
    assert!(lines[0].0.starts_with("warn empty database"), "{lines:?}");
    exec(&db, "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, PRIMARY KEY (version_num)); INSERT INTO alembic_version VALUES ('c1219a2b3c4d')").await;
    let lines = copilot_startup::doctor::migrations(&db).await;
    assert!(
        lines[0].1 && lines[0].0.contains("c1219a2b3c4d"),
        "{lines:?}"
    );
    exec(&db, "DROP TABLE alembic_version").await;
    migrate(&db).await.unwrap();
    let lines = copilot_startup::doctor::migrations(&db).await;
    assert!(
        lines[0]
            .0
            .starts_with("ok   history: 0001_baseline (applied"),
        "{lines:?}"
    );
    assert_eq!(lines[1].0, "ok   no migration pending");

    let closed = ObjectStore::for_endpoint("127.0.0.1:9", "minio", "minio-secret").unwrap();
    let dev = Startup::new(&EnvFile::isolated("ENVIRONMENT=DEVELOPMENT\n"));
    let lines = copilot_startup::doctor::preconditions(&dev, &db, &closed).await;
    assert_eq!(
        lines[0],
        (
            "ok   tasks on (COPILOT_STARTUP_TASKS), migrations on (COPILOT_RUN_MIGRATIONS)".into(),
            false
        )
    );
    assert!(lines[1].0.contains("no root bootstrap"));
    assert!(
        lines[2].1 && lines[2].0.starts_with("FAIL MinIO at 127.0.0.1:9"),
        "{lines:?}"
    );
    let prod = Startup::new(&EnvFile::isolated("ENVIRONMENT=PRODUCTION\n"));
    let lines = copilot_startup::doctor::preconditions(&prod, &db, &closed).await;
    assert!(
        lines[1].1 && lines[1].0.contains("MYSQL_ROOT_PASSWORD is not set"),
        "{lines:?}"
    );
    drop_db(name).await;
}
