//! What `copilot doctor` reports about the startup: the switches, root's
//! login for the PRODUCTION bootstrap, MinIO for `create_buckets()`, and the
//! schema's migration state.

use copilot_core::config::DatabaseConfig;
use copilot_migrate::MIGRATIONS;
use copilot_objectstore::ObjectStore;
use sqlx::{ConnectOptions, Connection};

use crate::Startup;
use crate::bootstrap::{Target, connect_root};
use crate::catalog::BUCKETS;

/// One line (the text after `startup     `) and whether it is a failure.
pub type Line = (String, bool);

fn on(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// The startup's preconditions; they need no database.
pub async fn preconditions(
    startup: &Startup,
    db: &DatabaseConfig,
    objectstore: &ObjectStore,
) -> Vec<Line> {
    let env = startup.env();
    let mut out = vec![(
        format!(
            "ok   tasks {} (COPILOT_STARTUP_TASKS), migrations {} (COPILOT_RUN_MIGRATIONS)",
            on(env.tasks),
            on(env.migrations)
        ),
        false,
    )];
    if !env.tasks {
        return out;
    }
    if env.production() {
        match (&env.root_password, Target::of(db)) {
            (_, Err(e)) => out.push((format!("FAIL {e}"), true)),
            (None, _) => out.push((
                "FAIL ENVIRONMENT=PRODUCTION and MYSQL_ROOT_PASSWORD is not set: the bootstrap \
                 (database and user through root) cannot run"
                    .to_string(),
                true,
            )),
            (Some(root), Ok(target)) => match connect_root(&target, root, 1).await {
                Ok(conn) => {
                    let _ = conn.close().await;
                    out.push((
                        format!(
                            "ok   ENVIRONMENT=PRODUCTION: root logs in at {}:{} (the database \
                             {:?} and the user {:?} are made sure of through it)",
                            target.host, target.port, target.database, target.user
                        ),
                        false,
                    ));
                }
                Err(e) => out.push((
                    format!(
                        "FAIL ENVIRONMENT=PRODUCTION: root cannot log in at {}:{}: {e}",
                        target.host, target.port
                    ),
                    true,
                )),
            },
        }
    } else {
        out.push((
            format!(
                "ok   ENVIRONMENT={:?}: no root bootstrap (the database and its user must exist)",
                env.environment
            ),
            false,
        ));
    }
    let endpoint = objectstore
        .endpoint()
        .map(|e| e.netloc.clone())
        .unwrap_or_else(|| "?".into());
    let listed = match objectstore.session() {
        Ok(client) => client.list_buckets().await.map_err(|e| e.into_py().text()),
        Err(e) => Err(e.text()),
    };
    match listed {
        Ok(buckets) => {
            let present = BUCKETS
                .iter()
                .filter(|b| buckets.iter().any(|x| x == *b))
                .count();
            out.push((
                format!(
                    "ok   MinIO reachable at {endpoint} ({present} of the {} startup buckets exist; \
                     the start creates the others)",
                    BUCKETS.len()
                ),
                false,
            ));
        }
        Err(e) => out.push((
            format!("FAIL MinIO at {endpoint} (the start's create_buckets() stops on it): {e}"),
            true,
        )),
    }
    out
}

/// The schema's migration state, read on a connection of its own.
pub async fn migrations(db: &DatabaseConfig) -> Vec<Line> {
    let options = match copilot_db::pool::connect_options(db) {
        Ok(o) => o,
        Err(e) => return vec![(format!("FAIL {e}"), true)],
    };
    let mut conn = match options.connect().await {
        Ok(c) => c,
        Err(e) => return vec![(format!("FAIL {e}"), true)],
    };
    let lines = match copilot_migrate::status(&mut conn, MIGRATIONS).await {
        Ok((state, decision)) => copilot_migrate::describe(&state, &decision),
        Err(e) => vec![(format!("FAIL {e}"), true)],
    };
    let _ = conn.close().await;
    lines
}
