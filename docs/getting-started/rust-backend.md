# Running CoPilot on the Rust backend

Since this release CoPilot's backend is a single Rust binary, `copilot`
(image `ghcr.io/socfortress/copilot-rs`). It answers every API route itself,
applies the database schema and the startup tasks the Python backend used to
run, and owns the scheduled jobs. The Python backend
(`ghcr.io/socfortress/copilot-backend`) is no longer started; it stays
available for a rollback.

Nothing changes for the frontends, the Customer Portal, Graylog's webhooks,
Talon or any other caller: the Rust service keeps the Python service's name
(`copilot-backend`), host port (5000), API, JSON and tokens.

!!! warning "Before you upgrade"
    The Rust backend adopts a database that the Python backend's migrations
    brought to their **last revision** (Alembic `d15ab1ed7e1e`) and refuses an
    older one. If your CoPilot has not been updated for a while, follow
    [Upgrade an existing deployment](#upgrade-an-existing-deployment) — it runs
    the last Python release once to bring the database up to date.

---

## Fresh install

```bash
git clone https://github.com/socfortress/CoPilot.git
cd CoPilot
cp .env.example .env
nano .env            # at least JWT_SECRET, the MySQL and MinIO passwords, SERVER_HOST
docker compose pull
docker compose up -d
```

On its first start the backend creates the schema, the MinIO buckets, the
connector and integration catalogs and the `admin` user, whose password it
logs once:

```bash
docker compose logs copilot-backend | grep "Admin user password"
```

`docker compose ps` shows `copilot-backend` as *healthy* once it answers
`/_copilot/health` (the first start, which creates the schema, can take a few
minutes). Check the configuration at any time with:

```bash
docker compose exec copilot-backend copilot doctor
```

`doctor` checks the database, the schema, Talon and the scheduler, and lists
any variable in the environment it does not know — a typo, or a variable an
older release used.

## Upgrade an existing deployment

From your CoPilot directory, after a backup of the database and of `data/`:

```bash
# 0. Back up (adjust the names to your setup)
docker compose exec -T copilot-mysql sh -c 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" copilot' > copilot-backup.sql
tar czf copilot-data-backup.tgz data/

# 1. The new Compose files and images
git pull                     # or download docker-compose*.yml and .env.example of the release
docker compose pull

# 2. Bring the database to the last Python schema (does nothing if it is there)
docker compose --profile legacy up -d copilot-backend-legacy
docker compose logs -f copilot-backend-legacy    # wait for "Application startup complete", then Ctrl-C
docker compose rm -sf copilot-backend-legacy

# 3. Start the Rust backend
docker compose up -d
```

Step 2 runs the last Python release (the `legacy` profile, with its scheduler
off) so that its Alembic migrations bring an older database up to date; a
database that is already there is left as it is. If you skip it and the
database is older, `copilot-backend` refuses to start and its log names the
revision it found — run step 2, then `docker compose up -d` again.

What else happens on the first start of the Rust backend:

- **The data directory changes owner.** The Rust image runs as the
  unprivileged uid 10001, while the Python backend ran as root. A one-shot
  service, `copilot-backend-init`, hands `./data/data` (the uploaded connector
  files, the collectors' files) and ScoutSuite's reports to that user before
  every start of the backend. MinIO's objects (`./data/data/minio-data`) are
  not touched, nor are symbolic links followed.
- **The scheduler moves.** The jobs (`scheduled_job_metadata`) run in the Rust
  backend. Pause and Start in *Platform → Scheduler* work as before.
- **Your `.env` keeps working.** The Rust backend reads the same variables.
  Compare it with the new `.env.example`, which documents every variable the
  backend reads, and let `copilot doctor` point out the ones it does not know.

## Roll back

Two levels, both on the same database.

**Give the schedule back to APScheduler** (the Python scheduler), with the Rust
backend still serving — the staged-rollout layout of the migration:

```bash
docker compose -f docker-compose.yml -f docker-compose.rust.yml up -d
```

The Python backend then runs behind the Rust one, with APScheduler on (unless
`.env` sets `COPILOT_SCHEDULER_OWNER=rust`). Run plain `docker compose up -d`
and `docker compose rm -sf copilot-backend-legacy` to return.

**Put the Python backend back in the Rust backend's place:**

```bash
docker compose rm -sf copilot-backend
docker compose -f docker-compose.yml -f docker-compose.legacy.yml up -d
```

The Python backend takes port 5000 and the `copilot-backend` name, and
APScheduler runs the jobs. Keep `-f docker-compose.legacy.yml` on every later
`docker compose` command. To return to the Rust backend:

```bash
docker compose -f docker-compose.yml -f docker-compose.legacy.yml rm -sf copilot-backend-legacy
docker compose up -d
```

A rollback needs a database the Python release understands. The Rust backend
keeps Alembic's head in `alembic_version`, so the Python backend finds nothing
to migrate; schema changes made by later Rust releases are additive and are not
undone. Restore your backup if you roll back across a release whose notes say
otherwise.

## What changed for operators

The API is the same, field for field — the parity suites send the same requests
to both backends and compare every answer. The deliberate differences are
listed, each with its reason, in
[Differences by design](../architecture/RUST_MIGRATION.md#4-differences-by-design).
Most of them close **tenant leaks**: a user scoped to some customers (an
analyst or responder with assigned customers, a portal user) no longer reaches
another customer's data through a route that Python did not check. In short:

- **Lists and searches are narrowed to the caller's customers** where Python
  showed every tenant's: the AI analyst's alerts with reports; alerts by
  status, source, asset, assignee, title, IoC or tag (customers *and* tag
  RBAC); an alert's context; case files; customer-scoped case templates and
  Sigma exclusion rules; the all-cases CSV export; the outdated-agent lists;
  the integrations' and network connectors' lists and the auth-key lookup; an
  agent's vulnerability rows and the package search; the Detections Catalog's
  custom rules and repositories; a scoped analyst's portal branding overrides;
  the GitHub audit's configurations and reports; File Analysis' agent list;
  the case-template suggestions' usage counts; and the Wazuh indexer's alert
  and MITRE alert searches (only the indices named after the caller's
  customers).
- **A customer named in a request must be one of the caller's** (403
  otherwise): the AI-trigger and Shuffle-notification switches, dispatching a
  notification, the scheduler's provisioning jobs, enabling a SIEM dashboard,
  filing a custom dashboard or an event source, every provisioning route
  (network connectors, integrations, collectors, customers and their Wazuh
  worker, Office 365) and network-connector decommissioning, creating or
  deleting an integration, the integration modules and Mimecast, the SAP SIEM
  analyses (through the IRIS customer id), the Shuffle workflow invoke, the
  Detections Catalog's backtest, publish and repository test, a GitHub audit
  configuration, the background vulnerability report, File Analysis'
  endpoints, the Grafana organization of a dashboard upload, and the data-store
  upload (its object path must start with one of the caller's customer codes or
  agent ids).
- **An object addressed by its own id is checked against its owner**: an
  existing AI analyst job, an alert's Talon jobs, the alert an AI comment is
  written on, a case's DOCX or PDF report, a GitHub audit configuration,
  report, exclusion or baseline, the host of a vulnerability sync, the agents
  a CoPilot Action runs on.

Administrators stay deployment-wide everywhere, as before.

Other changes you may notice:

- The backend logs to its container's output (`docker compose logs
  copilot-backend`); `COPILOT_LOG_FORMAT=json` gives one JSON object per line.
  It writes no performance session files (`PERF_LOG_*` are the Python
  backend's); `/api/performance` reports the Rust process.
- Errors that Python answered with a bare 500 on *every* request — routes that
  never worked — now work (they are marked "Python fails, Rust works" in the
  table).
- The image no longer carries placeholder connector addresses: a connector
  whose `<NAME>_URL` is missing from `.env` at the first start gets an empty URL
  (set it on the Connectors page) instead of the Python image's `1.1.1.1`
  placeholders.

## Troubleshooting

| Symptom | Look at |
|---|---|
| `copilot-backend` restarts, its log names an Alembic revision | the database is older than the last Python schema: run step 2 of the upgrade |
| `copilot-backend` never starts, `copilot-backend-init` exited non-zero | `docker compose logs copilot-backend-init`: the data directory could not be handed to uid 10001 (a read-only or root-squashed mount) |
| a connector file upload or a collector's provisioning fails with a permission error | the data directory is not writable by uid 10001: run `docker compose up -d` again (the init step fixes it), or check the mount |
| a licensed feature reports itself disabled | `COPILOT_API_KEY`: the published image carries it; a locally built image needs `--build-arg COPILOT_API_KEY=…` |
| something else | `docker compose exec copilot-backend copilot doctor` |

More detail: [Deployment](../architecture/DEPLOYMENT.md) (services, layouts,
variables, what each process keeps in memory) and
[Rust Migration](../architecture/RUST_MIGRATION.md).
