//! End-to-end tests of the scheduler's completion (`copilot-scheduler`): the
//! write routes under both modes, APScheduler's part handed to the Python
//! hook (a recorder here) under the hand-over, the ownership
//! (`COPILOT_SCHEDULER_OWNER=rust`) running jobs from the rows on
//! APScheduler's arithmetic, Mimecast's scheduler routes, the tenancy of
//! `/provisioning_jobs`, the six jobs this wave made Rust-capable and the
//! doctor's APScheduler check.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_scheduler_owner -- --test-threads=1
//! ```
//!
//! Real job ids are used (the routes and the ownership know only
//! `get_function_by_name`'s keys): each test removes their rows first and
//! last. Customers and users carry a random suffix.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_scheduler::doctor::{self, Liveness};
use copilot_scheduler::{JobError, JobSpec, Mode, OptIn, Owner, Scheduler, SchedulerOptions};

#[macro_use]
mod common;
use common::*;

const PRUNE: &str = "prune_audit_log";
const HUNTRESS: &str = "invoke_huntress_integration_collect";
const MIMECAST: &str = "invoke_mimecast_integration";
const MIMECAST_TTP: &str = "invoke_mimecast_integration_ttp";
const CATO: &str = "invoke_cato_integration_collect";
const CARBONBLACK: &str = "invoke_carbonblack_integration_collection";
const SIDEBAR_HEALTH: &str = "refresh_sidebar_health";

/// A minimal APScheduler job state (`version`, `id`, `name`, `func`, an aware
/// UTC `next_run_time` or `None`).
fn job_state(id: &str, name: &str, next: Option<[u32; 7]>) -> Vec<u8> {
    fn s(out: &mut Vec<u8>, v: &str) {
        out.push(0x8c);
        out.push(u8::try_from(v.len()).unwrap());
        out.extend_from_slice(v.as_bytes());
    }
    let mut p = vec![0x80, 4, b'}', b'('];
    s(&mut p, "version");
    p.extend_from_slice(&[b'K', 1]);
    for (k, v) in [("id", id), ("name", name), ("func", &format!("m:{name}"))] {
        s(&mut p, k);
        s(&mut p, v);
    }
    s(&mut p, "next_run_time");
    match next {
        None => p.push(b'N'),
        Some([y, mo, d, h, mi, se, us]) => {
            p.extend_from_slice(b"cdatetime\ndatetime\n");
            p.push(b'C');
            p.push(10);
            p.extend_from_slice(&[
                u8::try_from(y / 256).unwrap(),
                u8::try_from(y % 256).unwrap(),
                u8::try_from(mo).unwrap(),
                u8::try_from(d).unwrap(),
                u8::try_from(h).unwrap(),
                u8::try_from(mi).unwrap(),
                u8::try_from(se).unwrap(),
                u8::try_from(us >> 16).unwrap(),
                u8::try_from((us >> 8) & 0xff).unwrap(),
                u8::try_from(us & 0xff).unwrap(),
            ]);
            p.extend_from_slice(b"cdatetime\ntimezone\ncdatetime\ntimedelta\n");
            p.extend_from_slice(&[b'K', 0, b'K', 0, b'K', 0, 0x87, b'R', 0x85, b'R']);
            p.extend_from_slice(&[0x86, b'R']);
        }
    }
    p.extend_from_slice(b"u.");
    p
}

async fn ensure_job_store(h: &Harness) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS apscheduler_jobs (id VARCHAR(191) NOT NULL, \
         next_run_time DOUBLE NULL, job_state BLOB NOT NULL, PRIMARY KEY (id), \
         KEY ix_apscheduler_jobs_next_run_time (next_run_time))",
    )
    .execute(h.db.pool())
    .await
    .unwrap();
}

async fn put_job(h: &Harness, id: &str, name: &str, at: Option<f64>) {
    ensure_job_store(h).await;
    sqlx::query("DELETE FROM apscheduler_jobs WHERE id = ?")
        .bind(id)
        .execute(h.db.pool())
        .await
        .unwrap();
    let next = at.map(|_| [2030, 1, 1, 0, 0, 0, 0]);
    sqlx::query("INSERT INTO apscheduler_jobs (id, next_run_time, job_state) VALUES (?, ?, ?)")
        .bind(id)
        .bind(at)
        .bind(job_state(id, name, next))
        .execute(h.db.pool())
        .await
        .unwrap();
}

async fn put_meta(h: &Harness, job_id: &str, enabled: bool, minutes: i32) -> i64 {
    let res = sqlx::query(
        "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, \
         enabled, job_description) VALUES (?, NULL, ?, NULL, ?, 'e2e')",
    )
    .bind(job_id)
    .bind(minutes)
    .bind(enabled)
    .execute(h.db.pool())
    .await
    .unwrap();
    i64::try_from(res.last_insert_id()).unwrap()
}

async fn forget(h: &Harness, job_id: &str) {
    ensure_job_store(h).await;
    for sql in [
        "DELETE FROM apscheduler_jobs WHERE id = ?",
        "DELETE FROM scheduled_job_metadata WHERE job_id = ?",
    ] {
        sqlx::query(sql)
            .bind(job_id)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
}

/// `(enabled, time_interval, extra_data)` of every row of `job_id`, by id.
async fn rows(h: &Harness, job_id: &str) -> Vec<(bool, i32, Option<String>)> {
    sqlx::query_as(
        "SELECT enabled, time_interval, extra_data FROM scheduled_job_metadata WHERE job_id = ? \
         ORDER BY id",
    )
    .bind(job_id)
    .fetch_all(h.db.pool())
    .await
    .unwrap()
}

async fn user(h: &Harness, name: &str, role: i32) -> i64 {
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES \
         ('{name}', 'x', 'u@example.com', UTC_TIMESTAMP(), {role})"
    ))
    .await
}

fn seconds_ahead(body: &Value) -> i64 {
    let at = body["next_run_time"].as_str().unwrap();
    assert!(at.ends_with('Z'), "{at}");
    let at = chrono::DateTime::parse_from_rfc3339(at).unwrap();
    (at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds()
}

fn ok(message: &str) -> Value {
    json!({"success": true, "message": message})
}

fn not_found() -> Value {
    json!({"success": false, "message": "Job not found"})
}

#[tokio::test]
async fn the_ownership_runs_the_schedule_from_the_rows() {
    // A century: the manual prune below deletes nothing another suite keeps.
    let h = harness_or_skip!(
        None,
        "COPILOT_SCHEDULER_OWNER=rust\nAUDIT_LOG_RETENTION_DAYS=36500\n"
    );
    assert_eq!(h.app.scheduler.mode(), Mode::Rust);
    let s = h.suffix.clone();
    for id in [PRUNE, MIMECAST, MIMECAST_TTP] {
        forget(&h, id).await;
    }
    user(&h, &format!("oadmin{s}"), 1).await;
    let admin = h.token(&format!("oadmin{s}"), "admin");
    put_meta(&h, PRUNE, true, 1440).await;

    // The rows are the job store: a job with a row is listed, its function's
    // name beside it, scheduled one interval from now (APScheduler's grid).
    let (st, body) = h
        .call("GET", "/api/scheduler?search=prune", Some(&admin), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["jobs"],
        json!([{"id": PRUNE, "name": PRUNE, "enabled": true, "time_interval": 1440,
            "last_success": null, "description": "e2e"}])
    );
    let next = format!("/api/scheduler/next_run/{PRUNE}");
    let (st, body) = h.call("GET", &next, Some(&admin), None).await;
    assert_eq!(st, 200, "{body}");
    assert!((86_390..=86_400).contains(&seconds_ahead(&body)), "{body}");

    // Pause: the row alone; a paused job has no next run (Python's 400).
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/scheduler/pause/{PRUNE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job paused successfully")));
    assert!(!rows(&h, PRUNE).await[0].0);
    assert_eq!(h.app.scheduler.owner(PRUNE).await.unwrap(), Owner::Paused);
    let (st, body) = h.call("GET", &next, Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!(copilot_scheduler::schema::PAUSED_NEXT_RUN_ERROR))
    );
    // Start: resumed on its grid (still ahead: its start date).
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/scheduler/start/{PRUNE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job started successfully")));
    assert_eq!(h.app.scheduler.owner(PRUNE).await.unwrap(), Owner::Rust);
    let (_, body) = h.call("GET", &next, Some(&admin), None).await;
    assert!((86_380..=86_400).contains(&seconds_ahead(&body)), "{body}");

    // Update: a new trigger from now, the first row's interval and extra data.
    let (st, body) = h
        .call(
            "PUT",
            &format!("/api/scheduler/update/{PRUNE}?time_interval=5&extra_data=k%3Dv"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job updated successfully")));
    assert_eq!(rows(&h, PRUNE).await, [(true, 5, Some("k=v".into()))]);
    let (_, body) = h.call("GET", &next, Some(&admin), None).await;
    assert!((290..=300).contains(&seconds_ahead(&body)), "{body}");
    // Without extra data the column is cleared, as Python's setattr does.
    let (st, _) = h
        .call(
            "PUT",
            &format!("/api/scheduler/update/{PRUNE}?time_interval=6"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(rows(&h, PRUNE).await, [(true, 6, None)]);

    // Not found (exact id), FastAPI's 422s, the interval checks.
    let (st, body) = h
        .call(
            "PUT",
            "/api/scheduler/update/PRUNE_AUDIT_LOG?time_interval=5",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, not_found()));
    let (st, body) = h
        .call(
            "PUT",
            &format!("/api/scheduler/update/{PRUNE}?time_interval=x"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 422, "{body}");
    assert_eq!(body["details"][0]["field"], "time_interval");
    let (st, body) = h
        .call(
            "PUT",
            &format!("/api/scheduler/update/{PRUNE}?time_interval=-5"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!(copilot_scheduler::trigger::NEGATIVE_INTERVAL))
    );
    let (st, _) = h
        .call(
            "PUT",
            &format!("/api/scheduler/update/{PRUNE}?time_interval=1440000000000"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500, "timedelta's OverflowError is uncaught in Python");
    assert_eq!(rows(&h, PRUNE).await, [(true, 6, None)]);

    // A manual run, found as the store's collation finds it.
    let (st, body) = h
        .call(
            "POST",
            "/api/scheduler/jobs/run/PRUNE_AUDIT_LOG",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Job executed successfully", "result": null})
        )
    );

    // Delete: the first row, then the job is gone.
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/scheduler/{PRUNE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job deleted successfully")));
    assert!(rows(&h, PRUNE).await.is_empty());
    let (st, _) = h.call("GET", &next, Some(&admin), None).await;
    assert_eq!(st, 404);
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/scheduler/{PRUNE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, not_found()));

    // Add: a new row, enabled, scheduled from now; a job under another id is
    // refused (the rows keep no function); an unknown function is the 400.
    let add = |q: &str| format!("/api/scheduler/add?{q}");
    let (st, body) = h
        .call(
            "POST",
            &add("job_id=prune_audit_log&function_name=prune_audit_log&time_interval=7"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job added successfully")));
    assert_eq!(rows(&h, PRUNE).await, [(true, 7, None)]);
    let (_, body) = h.call("GET", &next, Some(&admin), None).await;
    assert!((410..=420).contains(&seconds_ahead(&body)), "{body}");
    let (st, body) = h
        .call(
            "POST",
            &add("job_id=x&function_name=prune_audit_log&time_interval=7"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(copilot_scheduler::writes::ID_IS_NOT_THE_FUNCTION)
        )
    );
    let (st, body) = h
        .call(
            "POST",
            &add("job_id=x&function_name=nope&time_interval=7"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(copilot_scheduler::functions::unknown_function("nope"))
        )
    );
    let (st, body) = h.call("POST", &add("job_id=x"), Some(&admin), None).await;
    assert_eq!(st, 422, "{body}");
    assert_eq!(body["details"].as_array().unwrap().len(), 2);
    let (st, _) = h
        .call(
            "POST",
            &add("job_id=x&function_name=y&time_interval=1"),
            None,
            None,
        )
        .await;
    assert_eq!(st, 401);

    // Mimecast's two routes: the SIEM job, and the TTP job under its own id
    // (Python replaced the SIEM job's function with the TTP one).
    let (st, body) = h
        .call(
            "POST",
            "/api/mimecast/invoke/scheduler/siem?time_interval=9",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (200, ok("Mimecast integration scheduled."))
    );
    let (st, _) = h
        .call(
            "POST",
            "/api/mimecast/invoke/scheduler/ttp?time_interval=11",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(rows(&h, MIMECAST).await, [(true, 9, None)]);
    assert_eq!(rows(&h, MIMECAST_TTP).await, [(true, 11, None)]);
    let (st, _) = h
        .call("POST", "/api/mimecast/invoke/scheduler/ttp", None, None)
        .await;
    assert_eq!(st, 401);
    let (st, _) = h
        .call(
            "POST",
            "/api/mimecast/invoke/scheduler/ttp",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 422);

    // The hook is Python's: never reachable through this service.
    let (st, _) = h
        .call(
            "POST",
            "/api/scheduler/apscheduler_ops",
            Some(&admin),
            Some(json!({"ops": []})),
        )
        .await;
    assert_eq!(st, 404);

    for id in [PRUNE, MIMECAST, MIMECAST_TTP] {
        forget(&h, id).await;
    }
}

#[tokio::test]
async fn provisioning_jobs_check_the_customer_each_job_names() {
    let h = harness_or_skip!(None, "COPILOT_SCHEDULER_OWNER=rust\n");
    let s = h.suffix.clone();
    forget(&h, HUNTRESS).await;
    let code = format!("pj{s}");
    h.exec(&format!(
        "INSERT INTO customers (customer_code, customer_name, created_at) VALUES ('{code}', \
         'PJ {s}', UTC_TIMESTAMP())"
    ))
    .await;
    user(&h, &format!("padmin{s}"), 1).await;
    let analyst_id = user(&h, &format!("panalyst{s}"), 2).await;
    h.exec(&format!(
        "INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES \
         ({analyst_id}, '{code}', UTC_TIMESTAMP())"
    ))
    .await;
    let admin = h.token(&format!("padmin{s}"), "admin");
    let analyst = h.token(&format!("panalyst{s}"), "analyst");
    let job = |extra: Value| {
        let mut j = json!({"function_name": HUNTRESS, "job_id": HUNTRESS, "time_interval": 5});
        if let Value::Object(m) = extra {
            for (k, v) in m {
                j[k] = v;
            }
        }
        json!({"jobs": [j]})
    };
    let route = "/api/scheduler/provisioning_jobs";

    // Not a provisioning job: the route's 400 first.
    let (st, body) = h
        .call(
            "POST",
            route,
            Some(&analyst),
            Some(json!({"jobs": [{"function_name": PRUNE, "job_id": PRUNE, "time_interval": 5}]})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(format!(
                "Job {PRUNE} is not an integration provisioning job"
            ))
        )
    );
    // A scoped caller registers only for one of their customers.
    let (st, body) = h
        .call("POST", route, Some(&analyst), Some(job(json!({}))))
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to job {HUNTRESS}")))
    );
    let (st, body) = h
        .call(
            "POST",
            route,
            Some(&analyst),
            Some(job(json!({"customer_code": "someone-else"}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (403, json!("Access denied to customer someone-else"))
    );
    assert!(rows(&h, HUNTRESS).await.is_empty());
    let (st, body) = h
        .call(
            "POST",
            route,
            Some(&analyst),
            Some(job(json!({"customer_code": code}))),
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Jobs added successfully")));
    assert_eq!(rows(&h, HUNTRESS).await, [(true, 5, None)]);
    // An admin registers any; `add_job_metadata` updates the one row.
    let (st, _) = h
        .call(
            "POST",
            route,
            Some(&admin),
            Some(json!({"jobs": [{"function_name": HUNTRESS, "job_id": HUNTRESS, "time_interval": "1_5"}]})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(rows(&h, HUNTRESS).await, [(true, 15, None)]);
    // Two rows: `one_or_none()`'s MultipleResultsFound, a bare 500.
    put_meta(&h, HUNTRESS, true, 5).await;
    let (st, _) = h
        .call("POST", route, Some(&admin), Some(job(json!({}))))
        .await;
    assert_eq!(st, 500);
    // The body as Pydantic reads it.
    let (st, body) = h
        .call(
            "POST",
            route,
            Some(&admin),
            Some(json!({"jobs": [{"job_id": 1}]})),
        )
        .await;
    assert_eq!(st, 422, "{body}");

    forget(&h, HUNTRESS).await;
    h.exec(&format!(
        "DELETE FROM user_customer_access WHERE user_id = {analyst_id}"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM customers WHERE customer_code = '{code}'"
    ))
    .await;
}

/// The hook's call for one operation.
fn hook(ops: Value, found: Value) -> Mock {
    Mock::given(method("POST"))
        .and(path("/api/scheduler/apscheduler_ops"))
        .and(body_json(json!({"ops": ops})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"success": true, "found": found})),
        )
}

#[tokio::test]
async fn the_hand_over_hands_apscheduler_s_part_to_python() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    assert_eq!(h.app.scheduler.mode(), Mode::Handover);
    let s = h.suffix.clone();
    let renamed = format!("e2e_renamed_{s}");
    for id in [PRUNE, HUNTRESS, MIMECAST_TTP, renamed.as_str()] {
        forget(&h, id).await;
    }
    user(&h, &format!("hadmin{s}"), 1).await;
    let admin = h.token(&format!("hadmin{s}"), "admin");

    // /add: APScheduler's add_job (its defaults), then a new row here.
    hook(
        json!([{"op": "add", "job_id": PRUNE, "function_name": PRUNE, "time_interval": 9, "defaults": true}]),
        json!([true]),
    )
    .expect(1)
    .mount(&legacy)
    .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/scheduler/add?job_id=prune_audit_log&function_name=prune_audit_log&time_interval=9&extra_data=e",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job added successfully")));
    assert_eq!(rows(&h, PRUNE).await, [(true, 9, Some("e".into()))]);
    // A job under another id: APScheduler keeps the function (only it can).
    hook(
        json!([{"op": "add", "job_id": renamed, "function_name": "agent_sync", "time_interval": 3, "defaults": true}]),
        json!([true]),
    )
    .expect(1)
    .mount(&legacy)
    .await;
    let (st, _) = h
        .call(
            "POST",
            &format!(
                "/api/scheduler/add?job_id={renamed}&function_name=agent_sync&time_interval=3"
            ),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);

    // /update: APScheduler's find_job_by_id (the stored ids), its
    // reschedule, then the first row.
    let update = format!("/api/scheduler/update/{PRUNE}?time_interval=4");
    let (st, body) = h.call("PUT", &update, Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body),
        (200, not_found()),
        "not in the store yet"
    );
    put_job(&h, PRUNE, PRUNE, Some(1_893_456_000.0)).await;
    hook(
        json!([{"op": "reschedule", "job_id": PRUNE, "time_interval": 4}]),
        json!([true]),
    )
    .expect(1)
    .mount(&legacy)
    .await;
    let (st, body) = h.call("PUT", &update, Some(&admin), None).await;
    assert_eq!((st.as_u16(), body), (200, ok("Job updated successfully")));
    assert_eq!(rows(&h, PRUNE).await, [(true, 4, None)]);

    // /provisioning_jobs and Mimecast: `add_scheduler_jobs` (coalesce, one
    // instance), the one row updated or inserted.
    hook(
        json!([{"op": "add", "job_id": HUNTRESS, "function_name": HUNTRESS, "time_interval": 5}]),
        json!([true]),
    )
    .expect(1)
    .mount(&legacy)
    .await;
    let (st, _) = h
        .call(
            "POST",
            "/api/scheduler/provisioning_jobs",
            Some(&admin),
            Some(json!({"jobs": [{"function_name": HUNTRESS, "job_id": HUNTRESS, "time_interval": 5}]})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(rows(&h, HUNTRESS).await, [(true, 5, None)]);
    hook(
        json!([{"op": "add", "job_id": MIMECAST_TTP, "function_name": MIMECAST_TTP, "time_interval": 15}]),
        json!([true]),
    )
    .expect(1)
    .mount(&legacy)
    .await;
    let (st, _) = h
        .call(
            "POST",
            "/api/mimecast/invoke/scheduler/ttp?time_interval=15",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(rows(&h, MIMECAST_TTP).await, [(true, 15, None)]);

    // /delete: APScheduler's remove_job, then the first row.
    hook(json!([{"op": "remove", "job_id": PRUNE}]), json!([true]))
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/scheduler/{PRUNE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, ok("Job deleted successfully")));
    assert!(rows(&h, PRUNE).await.is_empty());

    // APScheduler's own failure there is the bare 500 it is in Python.
    Mock::given(method("POST"))
        .and(path("/api/scheduler/apscheduler_ops"))
        .and(body_json(
            json!({"ops": [{"op": "pause", "job_id": HUNTRESS}]}),
        ))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&legacy)
        .await;
    let (st, _) = h
        .call(
            "POST",
            &format!("/api/scheduler/pause/{HUNTRESS}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500);
    assert!(rows(&h, HUNTRESS).await[0].0, "nothing was written");

    for id in [PRUNE, HUNTRESS, MIMECAST_TTP, renamed.as_str()] {
        forget(&h, id).await;
    }
}

#[tokio::test]
async fn without_python_the_hand_over_cannot_write() {
    let h = harness_or_skip!(None);
    let s = h.suffix.clone();
    forget(&h, PRUNE).await;
    user(&h, &format!("nadmin{s}"), 1).await;
    let admin = h.token(&format!("nadmin{s}"), "admin");
    let (st, _) = h
        .call(
            "POST",
            "/api/scheduler/add?job_id=prune_audit_log&function_name=prune_audit_log&time_interval=9",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500, "APScheduler is the Python backend's");
    assert!(rows(&h, PRUNE).await.is_empty());
}

#[tokio::test]
async fn the_six_jobs_run_here() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let s = h.suffix.clone();
    for id in [CATO, CARBONBLACK, SIDEBAR_HEALTH] {
        assert!(h.app.scheduler.knows(id), "{id}");
    }
    for id in [
        "refresh_catalog_caches",
        "refresh_wazuh_rules_cache",
        "refresh_sidebar_indicators",
    ] {
        assert!(h.app.scheduler.knows(id), "{id}");
    }
    let renamed = format!("e2e_cb_{s}");
    let unknown = format!("e2e_unknown_{s}");
    for id in [CATO, SIDEBAR_HEALTH, renamed.as_str(), unknown.as_str()] {
        forget(&h, id).await;
    }
    user(&h, &format!("jadmin{s}"), 1).await;
    let admin = h.token(&format!("jadmin{s}"), "admin");
    let run = |id: &str| format!("/api/scheduler/jobs/run/{id}");

    // Cato: run here (its customers by the service name CATO — none with a
    // test row), stamping last_success itself, a manual run included.
    put_job(&h, CATO, CATO, Some(1_893_456_000.0)).await;
    put_meta(&h, CATO, true, 5).await;
    let (st, body) = h.call("POST", &run(CATO), Some(&admin), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["result"], ok("cato integration invoked."));
    let stamped: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT last_success FROM scheduled_job_metadata WHERE job_id = ?")
            .bind(CATO)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert!(stamped.is_some());

    // A sidebar refresher: this process's value, nothing in Python.
    put_job(&h, SIDEBAR_HEALTH, SIDEBAR_HEALTH, Some(1_893_456_000.0)).await;
    let (st, body) = h
        .call("POST", &run(SIDEBAR_HEALTH), Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Job executed successfully", "result": null})
        )
    );

    // A stored CarbonBlack job: its callable is no key of
    // get_function_by_name, so Python's manual run always failed; found here.
    put_job(
        &h,
        &renamed,
        "invoke_carbonblack_integration_collect",
        Some(1_893_456_000.0),
    )
    .await;
    let (st, body) = h.call("POST", &run(&renamed), Some(&admin), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["result"], ok("Carbonblack integration invoked."));
    // A callable no table knows: Python's 500 with the ValueError text.
    put_job(&h, &unknown, "fn_nowhere", Some(1_893_456_000.0)).await;
    let (st, body) = h.call("POST", &run(&unknown), Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            500,
            json!(copilot_scheduler::functions::unknown_function("fn_nowhere"))
        )
    );
    assert!(legacy.received_requests().await.unwrap().is_empty());

    for id in [CATO, SIDEBAR_HEALTH, renamed.as_str(), unknown.as_str()] {
        forget(&h, id).await;
    }
}

#[tokio::test]
async fn the_timers_leave_a_handed_over_owned_or_paused_job_to_it() {
    let h = harness_or_skip!(None);
    let rust = harness_or_skip!(None, "COPILOT_SCHEDULER_OWNER=rust\n");
    forget(&h, SIDEBAR_HEALTH).await;
    // No row: the timer refreshes, under both modes.
    assert!(h.app.scheduler.timer_runs(SIDEBAR_HEALTH).await);
    assert!(rust.app.scheduler.timer_runs(SIDEBAR_HEALTH).await);
    // Enabled: APScheduler's under the hand-over (refreshing Python's copy;
    // the timer keeps this one warm), the job's under the ownership.
    let row = put_meta(&h, SIDEBAR_HEALTH, true, 6).await;
    assert!(h.app.scheduler.timer_runs(SIDEBAR_HEALTH).await);
    assert!(!rust.app.scheduler.timer_runs(SIDEBAR_HEALTH).await);
    // Disabled: handed over or paused — the job decides.
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 0 WHERE id = ?")
        .bind(row)
        .execute(h.db.pool())
        .await
        .unwrap();
    assert!(!h.app.scheduler.timer_runs(SIDEBAR_HEALTH).await);
    assert!(!rust.app.scheduler.timer_runs(SIDEBAR_HEALTH).await);
    forget(&h, SIDEBAR_HEALTH).await;
}

fn counting(id: &'static str) -> (JobSpec, Arc<AtomicUsize>) {
    let runs = Arc::new(AtomicUsize::new(0));
    let counter = runs.clone();
    let spec = JobSpec::new(id, 5, move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1500)).await;
            Ok::<(), JobError>(())
        }
    });
    (spec, runs)
}

#[tokio::test]
async fn the_dispatcher_runs_enabled_rows_on_apscheduler_s_grid() {
    let h = harness_or_skip!(None);
    let id: &'static str = Box::leak(format!("e2e_owned_{}", h.suffix).into_boxed_str());
    forget(&h, id).await;
    let (spec, runs) = counting(id);
    let scheduler = Scheduler::with_options(
        h.db.clone(),
        OptIn::default(),
        vec![spec],
        SchedulerOptions {
            mode: Mode::Rust,
            legacy: None,
        },
    );
    // A zero interval is APScheduler's one second; each run lasts 1.5 s, so
    // one instance at a time skips every other grid point.
    let row = put_meta(&h, id, true, 0).await;
    let cancel = CancellationToken::new();
    let handle = scheduler.spawn(cancel.clone());
    tokio::time::sleep(Duration::from_millis(5300)).await;
    let n = runs.load(Ordering::SeqCst);
    assert!((2..=3).contains(&n), "{n} runs in 5.3 s");
    let stamped: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT last_success FROM scheduled_job_metadata WHERE id = ?")
            .bind(row)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert!(stamped.is_some());

    // Paused by its row (another process, say): seen at the next re-read
    // or write; a write's refresh applies it at once.
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 0 WHERE id = ?")
        .bind(row)
        .execute(h.db.pool())
        .await
        .unwrap();
    scheduler.refresh(id, false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1700)).await;
    let paused_at = runs.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(runs.load(Ordering::SeqCst), paused_at);
    assert_eq!(scheduler.next_run(id), None);

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(15), handle)
        .await
        .expect("stops")
        .unwrap();
    forget(&h, id).await;
}

#[tokio::test]
async fn doctor_reads_apscheduler_from_its_store() {
    let h = harness_or_skip!(None);
    let id = format!("e2e_doctor_{}", h.suffix);
    // A scheduled job far behind the clock: APScheduler is not running.
    let behind = chrono::Utc::now().timestamp() as f64 - 3600.0;
    put_job(&h, &id, "agent_sync", Some(behind)).await;
    match doctor::apscheduler_liveness(&h.db, false).await.unwrap() {
        Liveness::Idle(_, secs) => assert!(secs >= 3000, "{secs}"),
        other => panic!("{other:?}"),
    }
    let live = doctor::apscheduler_liveness(&h.db, false).await.unwrap();
    assert!(!doctor::verdict(Mode::Rust, &live).failure);
    assert!(doctor::verdict(Mode::Handover, &live).failure);
    let report = doctor::report(&h.app.scheduler, false).await;
    assert!(report[0].text.starts_with("owner=handover"), "{report:?}");
    assert!(report.iter().any(|l| l.failure));
    forget(&h, &id).await;
}

#[tokio::test]
async fn doctor_flags_a_cato_row_an_older_release_left_disabled() {
    let h = harness_or_skip!(None, "COPILOT_SCHEDULER_OWNER=rust\n");
    let cato = doctor::CATO_JOB;
    forget(&h, cato).await;
    // The stored job APScheduler kept running, the row an older start disabled.
    let ahead = chrono::Utc::now().timestamp() as f64 + 3600.0;
    put_job(&h, cato, cato, Some(ahead)).await;
    put_meta(&h, cato, false, 5).await;
    let report = doctor::report(&h.app.scheduler, false).await;
    assert!(
        report
            .iter()
            .any(|l| l.text == doctor::CATO_WARNING && !l.failure),
        "{report:?}"
    );
    // Enabled again (Start), or paused here (no stored job scheduled): no warning.
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 1 WHERE job_id = ?")
        .bind(cato)
        .execute(h.db.pool())
        .await
        .unwrap();
    let report = doctor::report(&h.app.scheduler, false).await;
    assert!(
        !report.iter().any(|l| l.text == doctor::CATO_WARNING),
        "{report:?}"
    );
    put_job(&h, cato, cato, None).await;
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 0 WHERE job_id = ?")
        .bind(cato)
        .execute(h.db.pool())
        .await
        .unwrap();
    let report = doctor::report(&h.app.scheduler, false).await;
    assert!(
        !report.iter().any(|l| l.text == doctor::CATO_WARNING),
        "{report:?}"
    );
    // The hand-over repairs the row at a Python start instead: no warning there.
    let handover = harness_or_skip!(None);
    put_job(&h, cato, cato, Some(ahead)).await;
    let report = doctor::report(&handover.app.scheduler, false).await;
    assert!(
        !report.iter().any(|l| l.text == doctor::CATO_WARNING),
        "{report:?}"
    );
    forget(&h, cato).await;
}
