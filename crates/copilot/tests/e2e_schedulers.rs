//! End-to-end tests of the scheduler port (`copilot-scheduler`): the job
//! runner's hand-over rule and lock, and the DB-only jobs, against a real
//! MySQL.
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

use tokio_util::sync::CancellationToken;

use copilot_db::scheduler::{self as sdb, JobLock};
use copilot_scheduler::runner::{ManualRun, Tick};
use copilot_scheduler::{JobError, JobSpec, OptIn, Owner, Scheduler};

#[macro_use]
mod common;
use common::*;

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
    for sql in ["DELETE FROM scheduled_job_metadata WHERE job_id = ?"] {
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
