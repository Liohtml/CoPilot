//! # copilot — the SOCFortress CoPilot backend, in Rust
//!
//! Runs in front of (and, module by module, instead of) the Python backend:
//! see `docs/architecture/RUST_MIGRATION.md`.
//!
//! ```text
//! copilot serve           serve the API (default)
//! copilot doctor          check configuration, database, schema, Talon, legacy backend
//! copilot routes          list the route prefixes this build serves itself
//! copilot jobs            list the scheduled jobs this build can run, and who runs them
//!                         (`doctor` also checks APScheduler against COPILOT_SCHEDULER_OWNER)
//! copilot palace drain    run one palace-lesson drainer tick now
//! copilot palace sweep    run one one-off-lesson sweeper tick now
//! ```

#![warn(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

use copilot_core::config::CopilotConfig;
use copilot_core::env::EnvFile;
use copilot_db::Db;
use copilot_db::schema::{TESTED_ALEMBIC_HEAD, alembic_revision, missing_columns};

use copilot::app::{App, PORTED_PREFIXES, schema_requirements};
use copilot::logging;

#[derive(Parser)]
#[command(
    name = "copilot",
    version,
    about = "SOCFortress CoPilot backend (Rust)"
)]
struct Cli {
    /// Repository root holding `.env` (default: current directory).
    #[arg(long, env = "COPILOT_ROOT", global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the API.
    Serve,
    /// Check configuration and every dependency, then exit.
    Doctor,
    /// Print the route prefixes this build answers itself.
    Routes,
    /// List the scheduled jobs this build can take over and who runs each now.
    Jobs,
    /// Run one palace job tick now.
    Palace {
        #[command(subcommand)]
        job: PalaceJob,
    },
}

#[derive(Subcommand)]
enum PalaceJob {
    /// POST pending lessons to Talon.
    Drain,
    /// Forget expired one-off lessons.
    Sweep,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = match cli.root {
        Some(r) => r,
        None => std::env::current_dir().context("current directory")?,
    };
    let env = EnvFile::load(&root);
    let mut secrets: Vec<String> = [
        "JWT_SECRET",
        "MYSQL_PASSWORD",
        "MYSQL_ROOT_PASSWORD",
        "TOTP_ENCRYPTION_KEY",
        "SSO_STATE_SECRET",
        "SMTP_PASSWORD",
    ]
    .iter()
    .filter_map(|k| env.get(k))
    .collect();
    secrets.extend(env.get("COPILOT_DATABASE_URL"));
    logging::init(
        env.get("COPILOT_LOG_FORMAT")
            .is_some_and(|f| f.trim().eq_ignore_ascii_case("json")),
        env.get("LOG_LEVEL").as_deref(),
        logging::Redactor::new(secrets),
    );
    let command = cli.command.unwrap_or(Command::Serve);
    if let Command::Routes = command {
        for p in PORTED_PREFIXES {
            println!("{p}");
        }
        return Ok(());
    }
    let cfg = CopilotConfig::from_env(&root, &env).context("configuration")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("copilot")
        .build()
        .context("tokio runtime")?;
    runtime.block_on(async move {
        match command {
            Command::Serve => serve(cfg).await,
            Command::Doctor => doctor(cfg).await,
            Command::Palace { job } => palace(cfg, job).await,
            Command::Jobs => jobs(cfg).await,
            Command::Routes => Ok(()),
        }
    })
}

/// Wait for MySQL (it may still be starting), then verify the schema.
async fn connect_and_check(cfg: &CopilotConfig) -> anyhow::Result<Db> {
    let db = Db::connect_lazy(&cfg.database).context("database configuration")?;
    let mut attempt = 0u32;
    loop {
        match db.ping().await {
            Ok(()) => break,
            Err(e) if attempt < 30 => {
                attempt += 1;
                tracing::warn!(attempt, err = %e, "database not reachable yet; retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e).context("database unreachable"),
        }
    }
    let missing = missing_columns(&db, &schema_requirements()).await?;
    if !missing.is_empty() {
        bail!(
            "the database schema lacks {} column(s) this build needs ({}). The schema is owned by \
             the Python backend's Alembic migrations: start it once (or run `alembic upgrade head`) \
             before starting this service.",
            missing.len(),
            missing.join(", ")
        );
    }
    match alembic_revision(&db).await? {
        Some(rev) if rev == TESTED_ALEMBIC_HEAD => {}
        Some(rev) => tracing::warn!(revision = %rev, tested = TESTED_ALEMBIC_HEAD,
            "database is at a different Alembic revision than this build was tested against"),
        None => tracing::warn!("no alembic_version table: the schema was not created by Alembic"),
    }
    Ok(db)
}

async fn serve(cfg: CopilotConfig) -> anyhow::Result<()> {
    let db = connect_and_check(&cfg).await?;
    let app = App::new(&cfg, db.clone())?;
    let router = app.router(cfg.max_body_bytes);
    let cancel = CancellationToken::new();

    // The scheduler (copilot-scheduler): the opted-in jobs while handed over,
    // or every job with an enabled row under COPILOT_SCHEDULER_OWNER=rust.
    let jobs = app.scheduler.spawn(cancel.clone());
    // This process's catalog caches and sidebar indicators: warmed now, then
    // refreshed off-request by their own timers while their jobs do not.
    copilot_searches::refresher::spawn(
        app.searches.clone(),
        cancel.clone(),
        Some(app.scheduler.clone()),
    );
    copilot_status::sidebar::refresher::spawn(
        app.sidebar.clone(),
        cancel.clone(),
        Some(app.scheduler.clone()),
    );
    // This process's runtime-lag watchdog (`/api/performance`).
    copilot_status::performance::monitor::spawn(cancel.clone());
    // ScoutSuite's report directory, as copilot.py creates it at startup.
    copilot_scoutsuite::ensure_report_dir(&app.scoutsuite);

    let addr = SocketAddr::new(cfg.bind, cfg.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, legacy = ?cfg.legacy_url.as_ref().map(url::Url::as_str),
        ported = ?PORTED_PREFIXES, "CoPilot (Rust) listening");

    let shutdown = cancel.clone();
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("shutdown requested");
        shutdown.cancel();
    });
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.clone().cancelled_owned())
    .await
    .context("server")?;

    // A run in progress gets copilot_scheduler::runner::SHUTDOWN_GRACE.
    let _ = tokio::time::timeout(Duration::from_secs(15), jobs).await;
    db.close().await;
    tracing::info!("stopped");
    Ok(())
}

async fn wait_for_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
}

async fn doctor(cfg: CopilotConfig) -> anyhow::Result<()> {
    let mut failures = 0;
    println!("config      ok (bind {}:{})", cfg.bind, cfg.port);
    let db = Db::connect_lazy(&cfg.database)?;
    match db.ping().await {
        Ok(()) => println!("database    ok"),
        Err(e) => {
            println!("database    FAIL {e}");
            bail!("database unreachable");
        }
    }
    match alembic_revision(&db).await? {
        Some(rev) => println!(
            "alembic     {rev}{}",
            if rev == TESTED_ALEMBIC_HEAD {
                ""
            } else {
                " (untested revision)"
            }
        ),
        None => println!("alembic     none"),
    }
    let missing = missing_columns(&db, &schema_requirements()).await?;
    if missing.is_empty() {
        println!("schema      ok");
    } else {
        failures += 1;
        println!("schema      FAIL missing {}", missing.join(", "));
    }
    let app = App::new(&cfg, db)?;
    match app.talon.endpoint().await {
        Ok(ep) => println!("talon       configured ({ep:?})"),
        Err(e) => println!("talon       not configured: {e}"),
    }
    match copilot_talon::services::status(&app.talon).await {
        Ok(_) => println!("talon       reachable"),
        Err(e) => println!("talon       unreachable ({e})"),
    }
    match &app.legacy {
        Some(p) => {
            let url = p.upstream_url("/");
            match p
                .client()
                .get(&url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(r) => println!("legacy      {} → {}", p.base(), r.status()),
                Err(e) => {
                    failures += 1;
                    println!("legacy      FAIL {} ({e})", p.base());
                }
            }
        }
        None => println!("legacy      none (unported routes answer 404)"),
    }
    for line in copilot_scheduler::doctor::report(&app.scheduler, true).await {
        if line.failure {
            failures += 1;
        }
        println!("scheduler   {}", line.text);
    }
    for line in job_lines(&app.scheduler).await {
        println!("job         {line}");
    }
    if failures > 0 {
        bail!("{failures} check(s) failed");
    }
    Ok(())
}

async fn palace(cfg: CopilotConfig, job: PalaceJob) -> anyhow::Result<()> {
    let db = connect_and_check(&cfg).await?;
    let app = App::new(&cfg, db)?;
    // Serialized with every scheduled run of the job, here or in APScheduler
    // (the job's run lock), like a manual run.
    let lock = match job {
        PalaceJob::Drain => copilot_ai_analyst::palace_jobs::DRAINER_JOB_ID,
        PalaceJob::Sweep => copilot_ai_analyst::palace_jobs::SWEEPER_JOB_ID,
    };
    let Some(held) = copilot_db::scheduler::JobLock::acquire(
        &app.ctx.db,
        lock,
        copilot_scheduler::runner::MANUAL_LOCK_WAIT,
    )
    .await?
    else {
        bail!("{lock} is running (here or in APScheduler); try again when it has finished");
    };
    let outcome = match job {
        PalaceJob::Drain => copilot_ai_analyst::palace_jobs::drain_once(&app.ctx, &app.talon)
            .await
            .map(|r| format!("ingested={} failed={}", r.ingested, r.failed)),
        PalaceJob::Sweep => copilot_ai_analyst::palace_jobs::sweep_once(&app.ctx, &app.talon)
            .await
            .map(|r| {
                format!(
                    "forgotten={} forget_failed={}",
                    r.forgotten, r.forget_failed
                )
            }),
    };
    held.release().await;
    println!("{}", outcome?);
    Ok(())
}

/// One line per job: id, opt-in, owner, interval, next run here.
async fn job_lines(scheduler: &copilot_scheduler::Scheduler) -> Vec<String> {
    scheduler
        .status()
        .await
        .into_iter()
        .map(|j| {
            format!(
                "{:<30} opted-in={:<3} owner={:<7} every={}{}",
                j.id,
                if j.opted_in { "yes" } else { "no" },
                j.owner.map_or("unknown", |o| o.as_str()),
                j.interval_minutes
                    .map_or_else(|| "-".to_string(), |m| format!("{m}m")),
                j.next_run
                    .map(|t| format!(" next={}", t.to_rfc3339()))
                    .unwrap_or_default(),
            )
        })
        .collect()
}

async fn jobs(cfg: CopilotConfig) -> anyhow::Result<()> {
    let db = connect_and_check(&cfg).await?;
    let app = App::new(&cfg, db)?;
    println!("owner: {}", app.scheduler.mode().as_str());
    for id in app.scheduler.opt_in().unknown(&app.scheduler.job_ids()) {
        println!("warning: COPILOT_RS_JOBS names {id:?}, which this build cannot run");
    }
    for line in job_lines(&app.scheduler).await {
        println!("{line}");
    }
    Ok(())
}
