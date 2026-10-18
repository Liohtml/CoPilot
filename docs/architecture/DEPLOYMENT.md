# Deployment (AI Agent View)

Source of truth: `docker-compose.yml` (and its two overlays, below). For the
operator's procedures — install, upgrade, rollback, what changed — see
[Running CoPilot on the Rust backend](../getting-started/rust-backend.md).

## Runtime Services

| Service | Compose Name | Purpose | Exposed Ports | Persistent Storage |
|---|---|---|---|---|
| Backend API | `copilot-backend` | the Rust binary `copilot` (`crates/copilot`, image `ghcr.io/socfortress/copilot-rs`): every `/api/*` route, the schema migrations, the startup tasks, the scheduler | `5000:5000` | `./data/data:/opt/copilot/backend/data`, volume `scoutsuite-reports:/opt/copilot/backend/scoutsuite-report` |
| Backend init (one-shot) | `copilot-backend-init` | hands the data directory (MinIO's `minio-data/` aside) and ScoutSuite's reports to the image's uid 10001, then exits; `copilot-backend` waits for it | none | the same two mounts |
| Python backend (opt-in) | `copilot-backend-legacy` | FastAPI (`backend/`, image `ghcr.io/socfortress/copilot-backend`), the reference implementation; profile `legacy` | none (the rollback overlay publishes `5000`) | `./data/copilot-backend-data/logs:/opt/logs`, the same data directory and reports volume |
| Frontend (Nginx) | `copilot-frontend` | UI + TLS termination + reverse proxy to backend | `80:80`, `443:443` | none by default |
| MySQL | `copilot-mysql` | Primary relational DB | `3306:3306` | named volume `mysql-data:/var/lib/mysql` |
| MinIO | `copilot-minio` | Object storage for case/artifact files | `9000:9000` (S3 API), container also uses `9001` console | `./data/data/minio-data:/data` |
| Nuclei module | `copilot-nuclei-module` | External module container | none | none |
| MCP service | `copilot-mcp` | MCP/OpenAI-adjacent service + optional subservers | none exposed by compose | `./data/copilot-mcp/api.config.yaml:/app/velociraptor-config.yaml:ro` |
| Inspection plane | `inspector-runner`, `docker-socket-proxy` | File Analysis' Tier 1 inspector (see `CLAUDE.md`, File Analysis) | `9100:9000` | none |
| Customer portal (optional) | `copilot-customer-portal` | Separate customer-facing UI | example `8443:443` (commented) | none by default |

## Layouts

| Command | Backend serving | Schedule | Python backend |
|---|---|---|---|
| `docker compose up -d` | Rust | Rust (`COPILOT_SCHEDULER_OWNER=rust`, fixed in the file) | not started |
| `docker compose --profile legacy up -d` | Rust | Rust | standby next to it: same database and data, not published, `COPILOT_PY_SCHEDULER=false` |
| `docker compose -f docker-compose.yml -f docker-compose.rust.yml up -d` (staged rollout) | Rust in front, `COPILOT_LEGACY_URL=http://copilot-backend-legacy:5000` | APScheduler (the hand-over: `COPILOT_RS_JOBS` names what moves), or Rust when `.env` sets `COPILOT_SCHEDULER_OWNER=rust` | behind Rust, APScheduler on unless the owner is Rust |
| `docker compose -f docker-compose.yml -f docker-compose.legacy.yml up -d` (rollback) | Python, as `copilot-backend` on `5000` | APScheduler | in the Rust backend's place (the Rust service and its init step are not started) |

`scripts/check-compose.py` (CI: `rust.yml`, job `deployment`) resolves all of
them with `docker compose config` and `.env.example` as the `.env`, and fails
unless exactly one service answers to `copilot-backend` and publishes `5000`,
exactly one scheduler owns the schedule (a Rust service in the hand-over must
reach a Python backend through `COPILOT_LEGACY_URL`), the Rust service gets
every variable it needs (and its own `environment:` sets only variables it
reads, no test-only stand-in anywhere), every volume exists and the data
directory and the reports are mounted where the binary looks for them,
read-write and shared with the Python backend, and the images are the ones
`docker.yml` pushes. It also checks that every variable the Rust sources read
is in `crates/copilot-core/src/env_vars.rs` and that `.env.example` documents
them, and that the image copies every file the release build embeds from
`backend/`.

## Networking and Request Path

- Browser -> `copilot-frontend` :443
- `copilot-frontend` proxies `/api` and `/scoutsuite-report` to `http://copilot-backend:5000` (see `frontend/build/etc/nginx/sites-enabled/default.conf`; the Customer Portal's nginx likewise)
- Graylog's webhooks, Talon's write-backs and the MCP tools call `http://<host>:5000/api/...`
- Backend connects internally to:
  - MySQL via env (`MYSQL_URL`, defaults to `copilot-mysql`)
  - MinIO via env (`MINIO_URL`, defaults to `copilot-minio`; port 9000)
  - the inspector runner (`INSPECTOR_URL`), the module containers (`http://copilot-<name>-module`), `copilot-mcp`

## Environment Variable Overview

Primary env file: `.env` (template: `.env.example`, which documents every
variable the Rust backend reads, grouped; the test harnesses' stand-ins —
`COPILOT_*_URL`, `COPILOT_MINIO_ENDPOINT`, … — are left out on purpose).
`crates/copilot-core/src/env_vars.rs` is the list the binary knows;
`copilot doctor` lists any other variable it finds (a typo, an older
release's), any obsolete one and any test-only one.

- Process: `SERVER_IP` / `COPILOT_BIND`, `COPILOT_PORT`, `LOG_LEVEL`, `RUST_LOG`, `COPILOT_LOG_FORMAT`, `ENVIRONMENT`, `COPILOT_LEGACY_URL`
- Schema and startup tasks: `COPILOT_RUN_MIGRATIONS`, `COPILOT_STARTUP_TASKS` (both on), `MYSQL_ROOT_PASSWORD` (the PRODUCTION bootstrap)
- MySQL: `MYSQL_URL`, `MYSQL_ROOT_PASSWORD`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`, `DB_POOL_*`
- MinIO: `MINIO_URL`, `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `MINIO_SECURE`
- Secrets: `JWT_SECRET` (required), `SSO_STATE_SECRET`, `TOTP_ENCRYPTION_KEY`, `WAF_TOKEN_ENCRYPTION_KEY`, `COPILOT_API_KEY` (carried by the image)
- Connector bootstrap values (seeds): `<NAME>_URL`, `_USERNAME`, `_PASSWORD`, `_API_KEY` for each connector of `db_populate.py`'s list (e.g. `WAZUH_INDEXER_URL`, `GRAYLOG_URL`, `GRAFANA_URL`), read only to create a missing connector row
- Header/shared-secret style values: `GRAYLOG_API_HEADER_VALUE`, `VELOCIRAPTOR_API_HEADER_VALUE`, `GRAFANA_API_HEADER_VALUE`
- Scheduler: `COPILOT_SCHEDULER_OWNER` (fixed by the Compose files), `COPILOT_RS_JOBS`, `COPILOT_RS_PALACE_JOBS` (the hand-over), `AUDIT_LOG_RETENTION_DAYS`; `COPILOT_PY_SCHEDULER` on the Python backend
- Paths (fixed by `docker-compose.yml` to the Python backend's own): `COPILOT_BACKEND_DATA_DIR`, `COPILOT_SCOUTSUITE_DIR`, `COPILOT_MIMECAST_DIR`
- MCP/OpenAI values (the `copilot-mcp` service): `OPENAI_API_KEY`, `OPENAI_MODEL`, `MCP_*`, `OPENSEARCH_*`, `WAZUH_PROD_*`, `VELOCIRAPTOR_*`

## TLS

Frontend TLS behavior is implemented in:
- `frontend/build/docker-entrypoint.d/90-copilot-ssl.sh`
- `frontend/build/etc/nginx/sites-enabled/default.conf`

Behavior:
- If `TLS_CERT_PATH`/`TLS_KEY_PATH` files exist, Nginx uses them.
- If missing, startup script auto-generates self-signed certs (365 days).
- Port 80 redirects to HTTPS (443).

## Persistence Model

- MySQL durable data:
  - Docker named volume `mysql-data`.
- MinIO durable objects:
  - Host path `./data/data/minio-data`.
- Backend local files:
  - `./data/data`, mounted at `/opt/copilot/backend/data` (the Python backend's `UPLOAD_FOLDER`, so connector rows that hold a file path stay valid across a rollback): the Velociraptor connector's `api.config.yaml`, the CrowdStrike / Defender for Endpoint / Bitdefender collectors' files (`<customer>/…`), Mimecast's checkpoints and downloads (`mimecast/`).
  - Volume `scoutsuite-reports`: ScoutSuite's reports, written by the scans the Rust backend runs, served under `/scoutsuite-report`.
  - Owner: uid 10001, the Rust image's user. `copilot-backend-init` (the Rust image as root, `find … ! -user 10001 -exec chown -h 10001:10001`) hands over what a root process (the Python backend) left, before every start: idempotent, never following a symbolic link, pruning `minio-data/`. A failure (a read-only or root-squashed mount) stops `copilot-backend` from starting; its log says why.
  - Logs: the Rust backend logs to stdout (`docker compose logs copilot-backend`); the Python backend keeps writing `./data/copilot-backend-data/logs`.
- Buckets auto-created at startup:
  - `copilot-cases`, `copilot-case-report-templates`, `sysmon-configs`, `velociraptor-artifacts` (Python's `backend/app/data_store/data_store_setup.py`; the Rust startup tasks create the same).

## The Rust image

`crates/copilot/Dockerfile`, built from the repository root (context filtered
by `crates/copilot/Dockerfile.dockerignore`, an allowlist: the Cargo workspace
and the `backend/` templates the binary compiles in). `docker.yml` builds it
natively for `linux/amd64` and `linux/arm64`, pushes each by digest, checks the
uncompressed size against its budget (2560 MiB; ScoutSuite's venv is about
1 GiB) and joins them as `ghcr.io/socfortress/copilot-rs:latest`. The runtime is
`debian:bookworm-slim` as uid 10001 with the binary, the ScoutSuite CLI
(`scoutsuite==5.9.1` in its own venv), wkhtmltopdf, DejaVu Sans and the
Chromium headless shell of Playwright 1.59; `COPILOT_API_KEY` is a build
argument, as in the Python image. `HEALTHCHECK` probes `/_copilot/health`
(503 while MySQL is unreachable).

## Startup Initialization Hooks (Deployment-Relevant)

The Rust backend's `copilot serve` performs, in Python's order (each step
idempotent; `COPILOT_RUN_MIGRATIONS` / `COPILOT_STARTUP_TASKS` turn them off):
- DB creation/user bootstrap in production (root credentials)
- the schema migrations: a database at the last Alembic revision is adopted,
  an older one refused (run the last Python release once), later changes are
  Rust migrations
- MinIO bucket creation
- connector + integration + network-connector seed data, roles
- admin/scheduler user ensure, built-in templates, the portal's default settings
- the scheduler (every job whose `scheduled_job_metadata` row is enabled), the
  catalog and sidebar warm-ups, the Office 365 pipeline-rule check

`backend/copilot.py`'s lifespan does the same for the Python backend (the
reference implementation; see `CLAUDE.md`). Both take one MySQL named lock
(`GET_LOCK(CONCAT('copilot_startup:', SHA1(DATABASE())), 600)`) around these
steps, so two processes starting together run them one after the other.

Who runs them, per layout: the Rust backend in every layout where it runs
(migrations and startup tasks on — it owns the schema: a migration after the
Alembic baseline is only Rust's). Where the Python backend runs too (the
`legacy` standby, the staged rollout) its lifespan runs Python's own startup as
well — Alembic finds nothing to do at the frozen head, the seeding is
idempotent — under the same lock; the Python backend has no switch for it. In
the rollback only Python runs it. Two consequences: with
`ENVIRONMENT=PRODUCTION` (the default) the Rust backend needs
`MYSQL_ROOT_PASSWORD` at every start (`scripts/check-compose.py` requires it in
`.env.example`), and an unreachable MinIO fails a start (as in Python;
`restart: always` tries again). Each process removes the `scheduler` user when
it stops and the next start of either creates it again; nothing reads that row
in the Rust backend, and in the Python one only an unused helper.

If deployment seems healthy but features fail, validate this startup chain first
(`docker compose exec copilot-backend copilot doctor`).

## What each backend keeps in memory

The two backends share MySQL, MinIO and the tokens; what one process keeps for
itself is safe when both run (the staged rollout, the `legacy` standby)
because of the rule given for each:

| State (Rust process) | Why both may run |
|---|---|
| connector rows cache | every process re-reads the table at most every `CONNECTOR_CACHE_CHECK_SECONDS` (5 s) and drops what changed |
| resolved portal branding | the same check on the branding tables' fingerprint (`BRANDING_CACHE_CHECK_SECONDS`) |
| the Detections Catalog's caches, the sidebar indicators, the Atomic Red Team listings, the case-template library | read-only copies of external sources; each process refreshes its own |
| the 2FA brute-force counter | every `/api/auth` route is Rust's in every layout, so one process counts |
| the Graylog version probe (5 min), the Wazuh manager tokens (per connector row) | a changed row is never sent the old token; versions are re-probed |
| the ossec.conf edit lock (`WAZUH_CONFIG_LOCK`) | per process; across processes the edit re-reads the file before writing |
| `/api/performance`'s metrics | describe the process that answers |
| the scheduler's grid | only the owner runs a job, under one MySQL named lock per job |
