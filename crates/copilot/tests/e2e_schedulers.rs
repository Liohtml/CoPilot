//! End-to-end tests of the scheduler port (`copilot-scheduler`): the job
//! runner's hand-over rule and lock against a real MySQL, and
//! `/api/scheduler` through the production router, the Python backend
//! replaced by a recorder.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_schedulers -- --test-threads=1
//! ```
//!
//! Job ids carry a random suffix, except `prune_audit_log` (a real job id the
//! routes look up), whose rows these tests replace and remove again.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_db::scheduler::{self as sdb, JobLock};
use copilot_scheduler::runner::{ManualRun, Tick};
use copilot_scheduler::{JobError, JobSpec, OptIn, Owner, Scheduler};

#[macro_use]
mod common;
use common::*;

/// A minimal APScheduler job state: what the routes read of one (`version`,
/// `id`, `name`, `func`, `next_run_time` as an aware UTC `datetime`).
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
            // datetime.timezone(datetime.timedelta(0))
            p.extend_from_slice(b"cdatetime\ntimezone\ncdatetime\ntimedelta\n");
            p.extend_from_slice(&[b'K', 0, b'K', 0, b'K', 0, 0x87, b'R', 0x85, b'R']);
            p.extend_from_slice(&[0x86, b'R']);
        }
    }
    p.extend_from_slice(b"u.");
    p
}

/// APScheduler's own table (`SQLAlchemyJobStore` creates it at the Python
/// scheduler's first start; Alembic's fixture does not have it).
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

async fn put_job(h: &Harness, id: &str, name: &str, next: Option<[u32; 7]>, at: Option<f64>) {
    ensure_job_store(h).await;
    sqlx::query("DELETE FROM apscheduler_jobs WHERE id = ?")
        .bind(id)
        .execute(h.db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO apscheduler_jobs (id, next_run_time, job_state) VALUES (?, ?, ?)")
        .bind(id)
        .bind(at)
        .bind(job_state(id, name, next))
        .execute(h.db.pool())
        .await
        .unwrap();
}

async fn put_meta(
    h: &Harness,
    job_id: &str,
    enabled: bool,
    minutes: i32,
    description: &str,
) -> i64 {
    let res = sqlx::query(
        "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, \
         enabled, job_description) VALUES (?, NULL, ?, NULL, ?, ?)",
    )
    .bind(job_id)
    .bind(minutes)
    .bind(enabled)
    .bind(description)
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

async fn last_success(h: &Harness, row_id: i64) -> Option<chrono::NaiveDateTime> {
    sqlx::query_scalar("SELECT last_success FROM scheduled_job_metadata WHERE id = ?")
        .bind(row_id)
        .fetch_one(h.db.pool())
        .await
        .unwrap()
}

async fn enabled_of(h: &Harness, row_id: i64) -> bool {
    sqlx::query_scalar("SELECT enabled FROM scheduled_job_metadata WHERE id = ?")
        .bind(row_id)
        .fetch_one(h.db.pool())
        .await
        .unwrap()
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// A job that counts its runs and fails when told to.
fn counting_job(id: &'static str, fail: Arc<AtomicUsize>) -> (JobSpec, Arc<AtomicUsize>) {
    let runs = Arc::new(AtomicUsize::new(0));
    let counter = runs.clone();
    let spec = JobSpec::new(id, 5, move || {
        let counter = counter.clone();
        let fail = fail.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            if fail.load(Ordering::SeqCst) > 0 {
                Err(JobError("boom".into()))
            } else {
                Ok(())
            }
        }
    });
    (spec, runs)
}

#[tokio::test]
async fn a_job_runs_here_only_while_handed_over() {
    let h = harness_or_skip!(None);
    let id = leak(format!("e2e_job_{}", h.suffix));
    let fail = Arc::new(AtomicUsize::new(0));
    let (spec, runs) = counting_job(id, fail.clone());
    let opted_in = Scheduler::new(
        h.db.clone(),
        OptIn::parse(Some(id), false),
        vec![spec.clone()],
    );
    let not_opted_in = Scheduler::new(h.db.clone(), OptIn::default(), vec![spec]);

    // No metadata row: APScheduler runs a job regardless, so this side never does.
    assert!(matches!(
        opted_in.tick(id).await,
        Tick::NotOwned(Owner::Legacy)
    ));
    // Row enabled: APScheduler's.
    let row = put_meta(&h, id, true, 5, "d").await;
    assert!(matches!(
        opted_in.tick(id).await,
        Tick::NotOwned(Owner::Legacy)
    ));
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    // Disabled but not opted in here: paused.
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 0 WHERE id = ?")
        .bind(row)
        .execute(h.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        not_opted_in.tick(id).await,
        Tick::NotOwned(Owner::Paused)
    ));
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    // Disabled and opted in: runs, and stamps last_success.
    assert!(last_success(&h, row).await.is_none());
    assert!(matches!(opted_in.tick(id).await, Tick::Ran(Ok(()))));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    let stamped = last_success(&h, row).await.expect("stamped");
    let age = copilot_core::time::now_utc_naive() - stamped;
    assert!(age.num_seconds().abs() <= 2, "{stamped}");
    // A failed run is not a success.
    sqlx::query("UPDATE scheduled_job_metadata SET last_success = NULL WHERE id = ?")
        .bind(row)
        .execute(h.db.pool())
        .await
        .unwrap();
    fail.store(1, Ordering::SeqCst);
    assert!(matches!(opted_in.tick(id).await, Tick::Ran(Err(_))));
    assert!(last_success(&h, row).await.is_none());
    fail.store(0, Ordering::SeqCst);

    // A later, enabled duplicate row does not decide: the lowest id does.
    let dup = put_meta(&h, id, true, 5, "dup").await;
    assert!(matches!(opted_in.tick(id).await, Tick::Ran(Ok(()))));
    assert!(last_success(&h, row).await.is_some());
    assert!(
        last_success(&h, dup).await.is_none(),
        "only the deciding row is stamped"
    );

    // The run lock held by another session (APScheduler running it): skipped.
    let other = JobLock::acquire(&h.db, id, Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    let before = runs.load(Ordering::SeqCst);
    assert!(matches!(opted_in.tick(id).await, Tick::Busy));
    assert_eq!(runs.load(Ordering::SeqCst), before);
    other.release().await;
    assert!(!sdb::lock_in_use(&h.db, id).await.unwrap());
    assert!(matches!(opted_in.tick(id).await, Tick::Ran(Ok(()))));

    // Ownership as `copilot jobs` reports it.
    let status = opted_in.status().await;
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].owner, Some(Owner::Rust));
    assert_eq!(status[0].interval_minutes, Some(5));

    // A manual run of a job this side does not own is not run here.
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 1 WHERE id = ?")
        .bind(row)
        .execute(h.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        opted_in.run_now(id).await.unwrap(),
        ManualRun::NotOwned(Owner::Legacy)
    ));
    forget(&h, id).await;
}

#[tokio::test]
async fn a_dropped_lock_never_goes_back_to_the_pool() {
    let h = harness_or_skip!(None);
    let id = format!("e2e_lock_{}", h.suffix);
    let lock = JobLock::acquire(&h.db, &id, Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    assert!(sdb::lock_in_use(&h.db, &id).await.unwrap());
    // A second session cannot take it.
    assert!(
        JobLock::acquire(&h.db, &id, Duration::ZERO)
            .await
            .unwrap()
            .is_none()
    );
    // Dropped unreleased (a cancelled run): the connection is closed, MySQL
    // drops the lock with the session.
    drop(lock);
    let mut freed = false;
    for _ in 0..40 {
        if !sdb::lock_in_use(&h.db, &id).await.unwrap() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed, "the lock outlived its run");
    let again = JobLock::acquire(&h.db, &id, Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    again.release().await;
}

#[tokio::test]
async fn the_runner_stops_with_the_server() {
    let h = harness_or_skip!(None);
    let id = leak(format!("e2e_loop_{}", h.suffix));
    let (spec, runs) = counting_job(id, Arc::new(AtomicUsize::new(0)));
    let scheduler = Scheduler::new(h.db.clone(), OptIn::parse(Some(id), false), vec![spec]);
    // Last run two minutes ago (by APScheduler, say), every five minutes.
    let row = put_meta(&h, id, true, 5, "d").await;
    sqlx::query(
        "UPDATE scheduled_job_metadata SET last_success = UTC_TIMESTAMP() - INTERVAL 2 MINUTE \
         WHERE id = ?",
    )
    .bind(row)
    .execute(h.db.pool())
    .await
    .unwrap();
    let cancel = CancellationToken::new();
    let handle = scheduler.spawn(cancel.clone());
    // The rhythm continues from the last success: three minutes from now.
    let mut next = None;
    for _ in 0..40 {
        next = scheduler.next_run(id);
        if next.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let until = (next.unwrap() - chrono::Utc::now()).num_seconds();
    assert!((176..=181).contains(&until), "{until}");
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("stops promptly")
        .unwrap();
    assert_eq!(scheduler.next_run(id), None);
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    forget(&h, id).await;
}

#[tokio::test]
async fn scheduler_reads_answer_from_the_job_store() {
    let h = harness_or_skip!(None);
    let s = h.suffix.clone();
    let (a, b, p, bare) = (
        format!("sch{s}_a"),
        format!("sch{s}_b"),
        format!("sch{s}_paused"),
        format!("sch{s}_bare"),
    );
    // Stored out of order; MySQL orders by next_run_time, paused last.
    put_job(
        &h,
        &b,
        "fn_b",
        Some([2031, 1, 1, 0, 0, 0, 0]),
        Some(1_924_992_000.0),
    )
    .await;
    put_job(&h, &p, "fn_p", None, None).await;
    put_job(
        &h,
        &a,
        "fn_a",
        Some([2030, 6, 1, 12, 30, 5, 250]),
        Some(1_906_547_405.0),
    )
    .await;
    put_job(
        &h,
        &bare,
        "fn_bare",
        Some([2032, 1, 1, 0, 0, 0, 0]),
        Some(1_956_528_000.0),
    )
    .await;
    put_meta(&h, &a, true, 15, "A job").await;
    let pmeta = put_meta(&h, &p, false, 60, "Paused job").await;
    sqlx::query(
        "UPDATE scheduled_job_metadata SET last_success = '2026-01-02 03:04:05' WHERE id = ?",
    )
    .bind(pmeta)
    .execute(h.db.pool())
    .await
    .unwrap();
    put_meta(&h, &b, true, 5, "B job").await;

    let admin = h.token(&format!("sadmin{s}"), "admin");
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES \
         ('sadmin{s}', 'x', 'a@example.com', UTC_TIMESTAMP(), 1), \
         ('sportal{s}', 'x', 'p@example.com', UTC_TIMESTAMP(), 4)"
    ))
    .await;

    let (st, body) = h
        .call(
            "GET",
            &format!("/api/scheduler?search=SCH{s}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "Jobs successfully retrieved.");
    assert_eq!(
        body["jobs"],
        json!([
            {"id": a, "name": "fn_a", "enabled": true, "time_interval": 15, "last_success": null, "description": "A job"},
            {"id": b, "name": "fn_b", "enabled": true, "time_interval": 5, "last_success": null, "description": "B job"},
            {"id": bare, "name": "fn_bare", "enabled": true, "time_interval": 0, "last_success": null, "description": null},
            {"id": p, "name": "fn_p", "enabled": false, "time_interval": 60, "last_success": "2026-01-02T03:04:05", "description": "Paused job"},
        ])
    );
    // The search also matches the name; limit cuts.
    let (_, body) = h
        .call(
            "GET",
            "/api/scheduler?search=fn_p&limit=1",
            Some(&admin),
            None,
        )
        .await;
    assert!(
        body["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|j| j["name"] == "fn_p")
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/scheduler?search={s}&limit=2"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(body["jobs"].as_array().unwrap().len(), 2);
    let (st, body) = h
        .call("GET", "/api/scheduler?limit=0", Some(&admin), None)
        .await;
    assert_eq!(st, 422, "{body}");
    assert_eq!(body["details"][0]["field"], "limit");

    // Auth first.
    let (st, body) = h.call("GET", "/api/scheduler", None, None).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (401, json!("Not authenticated"))
    );
    let portal = h.token(&format!("sportal{s}"), "customer_user");
    let (st, body) = h
        .call("GET", &format!("/api/scheduler/{a}"), Some(&portal), None)
        .await;
    assert_eq!(st, 403, "{body}");

    // One job.
    let (st, body) = h
        .call("GET", &format!("/api/scheduler/{p}"), Some(&admin), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["job"]["description"], "Paused job");
    assert_eq!(body["message"], "Job successfully retrieved.");
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/scheduler/{}", a.to_uppercase()),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (404, json!({"success": false, "message": "Job not found"})),
        "find_job_by_id compares ids exactly"
    );

    // Next run: rendered like Pydantic; paused is Python's ValidationError 400.
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/scheduler/next_run/{a}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"next_run_time": "2030-06-01T12:30:05.000250Z", "success": true,
            "message": "Next run time successfully retrieved."})
        )
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/scheduler/next_run/{b}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["next_run_time"].clone()),
        (200, json!("2031-01-01T00:00:00Z"))
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/scheduler/next_run/{p}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 400);
    assert_eq!(
        body["message"],
        copilot_scheduler::schema::PAUSED_NEXT_RUN_ERROR
    );
    let (st, _) = h
        .call(
            "GET",
            "/api/scheduler/next_run/no-such-job",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 404);

    // Unported writes have no route here (and no legacy backend in this test).
    let (st, _) = h
        .call(
            "POST",
            "/api/scheduler/add?job_id=x&function_name=y&time_interval=1",
            Some(&admin),
            None,
        )
        .await;
    assert!(st == 404 || st == 405, "{st}");

    for id in [&a, &b, &p, &bare] {
        forget(&h, id).await;
    }
}

const PRUNE: &str = "prune_audit_log";

async fn audit_rows(h: &Harness, marker: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT DATE_FORMAT(timestamp, '%Y') FROM audit_log WHERE entity_id = ? ORDER BY id",
    )
    .bind(marker)
    .fetch_all(h.db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn prune_audit_log_keeps_the_retention_window() {
    let h = harness_or_skip!(None);
    let marker = format!("window{}", h.suffix);
    for ts in ["1900-01-01 00:00:00", "2000-01-01 00:00:00"] {
        h.exec(&format!(
            "INSERT INTO audit_log (timestamp, actor_username, action, entity_type, entity_id, \
             result) VALUES ('{ts}', 'e2e', 'case.create', 'case', '{marker}', 'success')"
        ))
        .await;
    }
    use copilot_scheduler::jobs::prune_audit_log;
    // `<= 0` keeps everything.
    assert_eq!(prune_audit_log(&h.db, Some("0")).await.unwrap(), 0);
    assert_eq!(audit_rows(&h, &marker).await, ["1900", "2000"]);
    // What `timedelta` refuses fails the run, as the Python job raises.
    assert_eq!(
        prune_audit_log(&h.db, Some("1000000000"))
            .await
            .unwrap_err()
            .0,
        "days=1000000000; must have magnitude <= 999999999"
    );
    // A century: the 1900 row goes, the 2000 row stays.
    assert!(prune_audit_log(&h.db, Some("36500")).await.unwrap() >= 1);
    assert_eq!(audit_rows(&h, &marker).await, ["2000"]);
    sqlx::query("DELETE FROM audit_log WHERE entity_id = ?")
        .bind(&marker)
        .execute(h.db.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn prune_audit_log_runs_here_when_handed_over() {
    let legacy = MockServer::start().await;
    // A century: only the seeded 1900 row is old enough.
    let h = harness_or_skip!(
        Some(&legacy),
        "COPILOT_RS_JOBS=prune_audit_log\nAUDIT_LOG_RETENTION_DAYS=36500\n"
    );
    let s = h.suffix.clone();
    let marker = format!("prune{s}");
    forget(&h, PRUNE).await;
    for ts in ["1900-01-01 00:00:00", "2000-01-01 00:00:00"] {
        h.exec(&format!(
            "INSERT INTO audit_log (timestamp, actor_username, action, entity_type, entity_id, \
             result) VALUES ('{ts}', 'e2e', 'case.create', 'case', '{marker}', 'success')"
        ))
        .await;
    }
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES \
         ('padmin{s}', 'x', 'a@example.com', UTC_TIMESTAMP(), 1)"
    ))
    .await;
    let admin = h.token(&format!("padmin{s}"), "admin");
    let run = format!("/api/scheduler/jobs/run/{PRUNE}");

    // Not in APScheduler's store: Python's 404.
    let (st, body) = h.call("POST", &run, Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body),
        (404, json!({"success": false, "message": "Job not found"}))
    );

    put_job(
        &h,
        PRUNE,
        PRUNE,
        Some([2030, 1, 1, 0, 0, 0, 0]),
        Some(1_893_456_000.0),
    )
    .await;
    let row = put_meta(&h, PRUNE, true, 1440, "Prunes audit_log").await;

    // APScheduler owns it (row enabled): forwarded to Python.
    Mock::given(method("POST"))
        .and(path(format!("/api/scheduler/jobs/run/{PRUNE}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": true, "message": "Job executed successfully", "result": null, "by": "python"})),
        )
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, body) = h.call("POST", &run, Some(&admin), None).await;
    assert_eq!((st.as_u16(), body["by"].clone()), (200, json!("python")));
    assert_eq!(audit_rows(&h, &marker).await, ["1900", "2000"]);

    // Handed over (row disabled, opted in): runs here, no last_success (the
    // Python function does not stamp on a manual run either).
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 0 WHERE id = ?")
        .bind(row)
        .execute(h.db.pool())
        .await
        .unwrap();
    let (st, body) = h.call("POST", &run, Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Job executed successfully", "result": null})
        )
    );
    assert_eq!(audit_rows(&h, &marker).await, ["2000"]);
    assert!(last_success(&h, row).await.is_none());

    // Its next run is this service's while its loop runs.
    let cancel = CancellationToken::new();
    let loops = h.app.scheduler.spawn(cancel.clone());
    for _ in 0..40 {
        if h.app.scheduler.next_run(PRUNE).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/scheduler/next_run/{PRUNE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let at = body["next_run_time"].as_str().unwrap();
    assert!(at.ends_with('Z'), "{at}");
    let at = chrono::DateTime::parse_from_rfc3339(at).unwrap();
    let ahead = (at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_minutes();
    assert!((1438..=1440).contains(&ahead), "{ahead}");
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loops).await;

    // Running elsewhere for longer than a manual run waits: Python's message.
    let other = JobLock::acquire(&h.db, PRUNE, Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    let (st, body) = h.call("POST", &run, Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body),
        (
            500,
            json!({"success": false,
            "message": "Job prune_audit_log is already running; try again when it has finished"})
        )
    );
    other.release().await;

    sqlx::query("DELETE FROM audit_log WHERE entity_id = ?")
        .bind(&marker)
        .execute(h.db.pool())
        .await
        .unwrap();
    forget(&h, PRUNE).await;
}

#[tokio::test]
async fn pause_and_start_carry_the_hand_over_flag() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy), "COPILOT_RS_JOBS=prune_audit_log\n");
    let s = h.suffix.clone();
    forget(&h, PRUNE).await;
    let row = put_meta(&h, PRUNE, true, 1440, "Prunes audit_log").await;
    let other = format!("other{s}");
    let other_row = put_meta(&h, &other, true, 5, "not ours").await;
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES \
         ('hadmin{s}', 'x', 'a@example.com', UTC_TIMESTAMP(), 2)"
    ))
    .await;
    let analyst = h.token(&format!("hadmin{s}"), "analyst");
    let ok =
        |m: &str| ResponseTemplate::new(200).set_body_json(json!({"success": true, "message": m}));

    Mock::given(method("POST"))
        .and(path(format!("/api/scheduler/pause/{PRUNE}")))
        .respond_with(ok("Job paused successfully"))
        .mount(&legacy)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/scheduler/pause/{other}")))
        .respond_with(ok("Job paused successfully"))
        .mount(&legacy)
        .await;

    // Pause: APScheduler pauses it (Python's answer, passed through) and the
    // row is disabled — the job is now this service's.
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/scheduler/pause/{PRUNE}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Job paused successfully"})
        )
    );
    assert!(!enabled_of(&h, row).await);
    assert_eq!(h.app.scheduler.owner(PRUNE).await.unwrap(), Owner::Rust);
    // A job this build cannot run: forwarded, its row untouched.
    let (st, _) = h
        .call(
            "POST",
            &format!("/api/scheduler/pause/{other}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert!(enabled_of(&h, other_row).await);

    // Start refused by Python (not in its store): the flag is restored.
    let refused = Mock::given(method("POST"))
        .and(path(format!("/api/scheduler/start/{PRUNE}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": false, "message": "Job not found"})),
        )
        .up_to_n_times(1)
        .mount_as_scoped(&legacy)
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/scheduler/start/{PRUNE}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body["success"].clone()), (200, json!(false)));
    assert!(!enabled_of(&h, row).await);
    drop(refused);

    // Start: handed back to APScheduler.
    Mock::given(method("POST"))
        .and(path(format!("/api/scheduler/start/{PRUNE}")))
        .respond_with(ok("Job started successfully"))
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/scheduler/start/{PRUNE}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Job started successfully"})
        )
    );
    assert!(enabled_of(&h, row).await);
    assert_eq!(h.app.scheduler.owner(PRUNE).await.unwrap(), Owner::Legacy);

    // The unported writes go to Python untouched.
    Mock::given(method("PUT"))
        .and(path(format!("/api/scheduler/update/{PRUNE}")))
        .respond_with(ok("Job updated successfully"))
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call(
            "PUT",
            &format!("/api/scheduler/update/{PRUNE}?time_interval=5"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (200, json!("Job updated successfully"))
    );

    forget(&h, PRUNE).await;
    forget(&h, &other).await;
}
