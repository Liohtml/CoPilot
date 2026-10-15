# CoPilot → Rust

CoPilot's backend is being rewritten in Rust so that it matches **Talon 2.0**
([liohtml/talahon](https://github.com/liohtml/talahon)), the AI analyst it
works with: one toolchain, one lint set, one dependency stack, one way of
handling configuration, errors, audit and secrets — and a typed contract
between the two services instead of two hand-written JSON parsers.

The rewrite is incremental. Nothing about a deployment changes until an
operator opts in, and every step can be rolled back by removing one compose
file.

---

## 1. Strategy: strangler fig

```text
                       ┌────────────── copilot (Rust, :5000) ──────────────┐
 frontend / portal ───►│ /api/ai_analyst/*   copilot-ai-analyst            │
                       │ /api/customer_portal/ai_reports/*                  │
                       │                     copilot-customer-portal        │
                       │ GET /api/customers/*         copilot-customers     │
                       │ GET /api/healthcheck/*       copilot-healthchecks  │
                       │ /api/version/*, /api/audit/* copilot-platform      │
 Talon MCP tools  ───►│ /api/talon/*        copilot-talon ───────────────────► Talon :3100
                       │ /_copilot/health                                   │
                       │ anything else ──►   copilot-gateway (stream) ────────► Python backend
                       └────────────────────────────────────────────────────┘        │
                                         │ same MySQL, same JWT_SECRET               │
                                         └──────────────── MySQL ◄───────────────────┘
```

- The Rust service owns port **5000**, the port the frontend, the Customer
  Portal and Talon's `copilot` MCP server already call. Routes it implements
  it answers itself; every other path **or method** is streamed unchanged to
  the Python backend (`COPILOT_LEGACY_URL`): bodies, SSE, downloads,
  status codes and headers pass through, nothing is buffered or re-encoded.
- **Same database.** Both services use the same MySQL. **Alembic stays the
  only owner of the schema** until the Python backend is retired: the Rust
  service never creates or alters a table, and refuses to start when a column
  it needs is missing (`copilot_db::schema`, `copilot doctor`).
- **Same tokens.** Tokens issued by the Python backend (`/api/auth/token`)
  are accepted by the Rust service and vice versa (HS256 over the raw
  `JWT_SECRET`, PyJWT's claim rules — `copilot_auth::jwt`).
- **Same wire format.** Ported routes return the same JSON, in the same field
  order, with the same error envelopes and 422 texts. This is not a goal on
  paper: `backend/tests/e2e/rust_parity_e2e.py` sends identical requests to
  both implementations on one database and compares the answers
  (181 checks, all equal; see §5).

Enable it:

```bash
docker compose -f docker-compose.yml -f docker-compose.rust.yml up -d
```

Roll back: run compose without the second file.

---

## 2. Workspace

Rust lives at the repository root (`Cargo.toml`, `crates/`), next to
`backend/`, `frontend/` and `customer-portal/`. Toolchain and conventions are
Talon's: edition 2024, `rust-version = 1.85`, `unsafe_code = "forbid"`,
`clippy::unwrap_used` denied outside tests, `#![warn(missing_docs)]`,
rustfmt `max_width = 100`, and the same pinned versions of tokio, axum,
tower-http, reqwest (rustls), serde, thiserror, tracing, sha2/hmac/base64.

| Crate | Python counterpart | Role |
|---|---|---|
| `copilot-core` | `settings.py`, `app/auth/models/users.py` (roles), `app/time_utils.py`, notification events | contract: config, `.env` reader (vendored from `talon-core`), roles/scopes, audit records, notification events, time helpers |
| `copilot-db` | `app/db/db_session.py`, `universal_models.py` (`AiAnalyst*`, `CustomerPortalAi*`), `connectors` + cache, `audit_log`, `log_entries`, `alert_visibility_filters_for_user` | sqlx MySQL pool, cross-cutting tables, schema checks, alert visibility as SQL (`visibility.rs`) |
| `copilot-auth` | `app/auth/utils.py`, `app/middleware/customer_access.py`, `app/incidents/middleware/tag_access.py` | JWT (HS256), bcrypt, `AccessScope` (tenant decisions), tag RBAC (`tags.rs`) |
| `copilot-web` | `exception_handlers.py`, `require_any_scope`, Pydantic validation | axum glue: error envelope, Pydantic-lax validator and 422 report, auth extractors, middleware |
| `copilot-talon` | `app/connectors/talon/` | **the Talon contract** (`contract.rs`), client, `/api/talon/*` |
| `copilot-ai-analyst` | `app/ai_analyst/`, palace drainer/sweeper jobs | `/api/ai_analyst/*` (25 routes), consolidation digest, CPython-exact `difflib` |
| `copilot-customer-portal` | `app/customer_portal/` (`ai_reports`, `ai_requests`) | `/api/customer_portal/ai_reports/*` (6 routes); every other portal path is still proxied |
| `copilot-customers` | `app/customers/` (reads) | `GET /api/customers/*` (7 routes); creating, changing and deleting customers provisions Graylog/Grafana/Wazuh and stays in Python |
| `copilot-healthchecks` | `app/healthchecks/agents/` (database half) | `GET /api/healthcheck/*` (4 routes); the classification is shared with the customer routes. `POST /logs` (Wazuh indexer) stays in Python |
| `copilot-platform` | `app/version/`, `app/audit/` (reads) | `GET /api/version/check` (PEP 440 compare; `COPILOT_VERSION_CHECK_URL` points it at a mirror), `GET /api/audit`, `/actions`, `/{id}` |
| `copilot-gateway` | — | legacy proxy and notification bridge; deleted when the migration ends |
| `copilot` | `copilot.py` | binary: `serve`, `doctor`, `routes`, `palace drain|sweep` |

Each module keeps CoPilot's `routes / services / schema` split.

```bash
cargo build --workspace
cargo test --workspace                                   # unit tests, no services
cargo clippy --workspace --all-targets -- -D warnings    # CI gate
cargo fmt --all
cargo run -p copilot -- doctor                           # check a configuration
```

---

## 3. Contracts the Rust service keeps

**HTTP.** Paths, methods, scopes, status codes and bodies of the ported
routes. Errors: `{"success": false, "message": …}` for `HTTPException`s;
`{"message", "details": [{field, error_type, message}]}` for validation
errors, with Pydantic's lax coercions (`"12"` → 12, `"yes"` → true) and the
canned texts of `app/utils.py:ErrorType`; FastAPI's `{"detail": "Not Found"}`
for unknown routes. Every handled error writes the same `log_entries` row the
Python handlers write. Check order is FastAPI's dependency order: token →
path → tenancy → query → body.

**Auth.** `require_any_scope` messages and order (`Not authenticated`,
`Expired signature`, `Invalid token`, the 2FA text, `User not found`,
`Insufficient permissions. Required one of: …`) — `copilot_web::Authorized`.
Routes guarded by `Security(get_current_user, scopes=[…])` instead need
*every* scope and word failures differently (`Could not decode token: 401:
Expired signature`, `Insufficient permissions. Required scope: admin`) —
`copilot_web::ScopedUser`. A token without `sub` is a bare 500 either way:
Python's exception handler decodes the token again and fails. A responder's token carries
`["responder", "analyst"]`. Route gating follows the token's scopes; tenancy
follows the user's live `role_id` and `user_customer_access`, fail-closed
(`enforce_owned_object_access`: an object with no resolvable owner is a 403 for
scoped callers).

**Database.** No schema change. Timestamps are written as MySQL stores
Python's `datetime.utcnow()` (rounded to the second), so a row reads back
identically whichever service wrote it. Same-second ties are broken
explicitly: lists by ascending id (what MySQL returns for the Python queries),
"latest" lookups (`LIMIT 1`, the portal's recent reports) by the newest id —
Python leaves the latter to MySQL's plan (§4).

Where a Python query has no `ORDER BY` (the customer list, a customer's
agents, the healthcheck fleet), the Rust query keeps its exact shape —
filters in the same order, no ordering added — so MySQL picks the same plan
and the same row order.

**Request values.** `datetime` query and body fields parse with the crate
Pydantic itself uses, `speedate`, pinned to pydantic-core's version
(`copilot_web::datetime`): the same accepted forms (ISO 8601, date only,
unix seconds or milliseconds) and the same `datetime_from_date_parsing`
messages. The value used in SQL is the wall clock without its offset,
because that is what `pymysql` sends. Vectors generated from pydantic
(`scripts/gen-pydantic-datetime-vectors.py`) and from `packaging`
(`scripts/gen-pep440-vectors.py`, the version compare) pin both; re-run them
after upgrading either Python package.

**Alert visibility.** One definition, as in Python:
`copilot_db::visibility::AlertVisibility` (customer scoping *and* tag RBAC,
`alert_visibility_filters_for_user`) for lists and counts, and
`can_user_access_alert` for a single alert. The two tag rules differ where
Python's do — `default_tag` with no tag configured allows one untagged alert
but keeps untagged alerts out of lists — and `copilot_auth::tags` pins the
table. Admins, the scheduler and portal users bypass tag RBAC; a responder
gets the analyst role's tags.

**Talon.** `crates/copilot-talon/src/contract.rs` types every request and
response of Talon's HTTP channel (`talon-http`): `/investigate`,
`/investigations`, `/message` (SSE frames), `/session/reset`, `/status`,
`/templates`, `/palace/lesson|search|forget`, `{"error"}` bodies, and Talon's
own validation rules (customer code, template names). Tests pin the exact
JSON in both directions. CoPilot authenticates with `x-api-key`, as before.

**Notifications.** The notification pipeline is still Python. A ported module
builds the exact `NotificationEvent` the Python builders build
(`copilot_core::notify`, pinned against `event_builders.py` by
`backend/tests/test_notification_rust_bridge.py`) and hands it to
`POST /api/notifications/events` with the caller's token. That endpoint
accepts only the AI-analyst triggers, checks the alert's customer, and
re-derives the dedupe key and link (`app/notifications/services/bridge.py`).

**Scheduled jobs.** A job moves to Rust only by explicit hand-over: the Rust
loop runs it when `COPILOT_RS_PALACE_JOBS=true` **and** the job's
`scheduled_job_metadata` row is disabled (Scheduler UI), and stamps
`last_success` so the UI stays truthful. Status flips are guarded on the
previous status, so a lesson is never ingested or expired twice.

**Connector cache.** The Python backend invalidates its connector cache after
each write but cannot reach the Rust process, so while a legacy backend is
configured the Rust TTL is capped at 60 s.

---

## 4. Differences by design

Each is covered by a test and listed in the parity harness.

| Where | Python | Rust | Why |
|---|---|---|---|
| `GET /ai_analyst/alerts_with_reports` | passes `customer_codes` through; a scoped analyst sending none sees **every tenant** | intersects with the caller's customers (`scoped_customer_codes`), `[]` → empty list | tenant leak |
| `GET /talon/jobs/{alert_id}` | no tenancy check | `verify_alert_access` | tenant leak |
| `POST /ai_analyst/jobs` on an existing id | relabels any job | also checks the existing job's owner | a scoped caller could relabel another tenant's job |
| `POST /ai_analyst/reports/{id}/review` (edit) | answer lists the IOC reviews it just deleted | answers with what is stored | Python identity-map artefact |
| concurrent first review | unique-key 500 | retried as an edit | race |
| `POST …/replay` template | Python's regex only; Talon then 400s → 500 | Talon's rule (no `..`, not hidden), same 422 text | fail early |
| `/talon/*` upstream failure text | `requests` exception text | status plus Talon's `{"error"}` text | actionable |
| palace search hits | numeric `id` → 400 | stringified | robustness |
| "latest" row on a same-second tie (`alerts_with_reports/{alert_id}`, portal recent reports) | whichever row MySQL's plan reaches first — varies with the data | the newest id, the rule the portal's `MAX(id)` already uses | deterministic |
| agent healthcheck clock | `datetime.now()`: the process's local time (UTC in the image) | UTC | the `*_last_seen` columns hold UTC; equal in the shipped image |

---

## 5. Testing

| Layer | Where | Needs |
|---|---|---|
| unit | every crate | nothing |
| contract | `copilot-talon/src/contract.rs`, `copilot-core/src/notify.rs`, `backend/tests/test_notification_rust_bridge.py` | nothing |
| end-to-end | `crates/copilot/tests/e2e.rs` — the production router against MySQL at the Alembic head, Talon and Python replaced by recorders | MySQL |
| parity | `backend/tests/e2e/rust_parity_e2e.py` via `scripts/rust-parity.sh` — real FastAPI routers vs. the running Rust binary, one database; Talon and GitHub's release API are local stubs both backends call; an unhandled Python error compares as the bare 500 uvicorn sends | MySQL + Python venv |

```bash
# disposable MySQL on 13306, schema from the fixture (or `alembic upgrade head`)
mysql -h127.0.0.1 -P13306 -uroot copilot < crates/copilot/tests/fixtures/schema.sql
COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13306/copilot \
  cargo test -p copilot --test e2e -- --test-threads=1

MYSQL_PASSWORD=copilot scripts/rust-parity.sh     # Python venv in backend/.venv
```

`crates/copilot/tests/fixtures/schema.sql` is the schema at the Alembic head
(`scripts/dump-schema.sh`). CI (`.github/workflows/rust.yml`) runs fmt,
clippy, tests, an MSRV check on 1.85, and the end-to-end suite on a MySQL
service loaded from the fixture; `scripts/check-alembic-head.py` fails the
build when a migration lands without a regenerated fixture.

---

## 6. Phases

Python backend today: ~200 k lines in 930 files.

| Phase | Modules (Python lines) | Notes |
|---|---|---|
| **0 — done** | foundation; `ai_analyst` (2.4 k), `connectors/talon` | the Talon integration surface |
| **1 — done** | `customer_portal` AI reports + requests (`copilot-customer-portal`), alert visibility (customer + tag RBAC), `customers` reads (`copilot-customers`), agent healthchecks (`copilot-healthchecks`), `version` and `audit` reads (`copilot-platform`) | read-mostly. `status/sidebar` moved to phase 4: its indicators read Wazuh, InfluxDB, the licence, MinIO and caches that live in the Python process |
| 2 | `auth` (5 k): `/auth/token`, 2FA (TOTP, Fernet key compatible), refresh, users, SSO, passkeys | the Rust service starts issuing tokens |
| 3 | `notifications` (7.2 k) — retires the bridge; `schedulers` (2.6 k) — APScheduler → tokio, job by job via the `enabled` hand-over; `incidents` (21 k) incl. ingest | ingest then triggers Talon from Rust |
| 4 | `agents` (9.8 k), `soc_management` (4.4 k), `customer_waf`, `file_analysis`, `customer_provisioning`, `stack_provisioning`, then `connectors` (29.6 k: Wazuh, Graylog, Velociraptor gRPC, …) and `integrations` (37.5 k), one vendor at a time; `status/sidebar` and `POST /healthcheck/logs` once the connectors they read are ported | largest surface; each is independent |
| 5 | schema ownership → sqlx migrations (baseline = Alembic head), Python retired, `copilot-gateway` deleted | |

The Vue frontends (`frontend/`, `customer-portal/`) are not part of the
rewrite: they talk to the same API.

### Porting a module — checklist

1. Write the spec from the Python code (routes, scopes, tenancy, schemas,
   service logic, side effects, status codes and texts).
2. Tables: rows and queries in `copilot-db` (or the module crate), with a
   `TableRequirement` list added to `app::schema_requirements()`.
3. `schema.rs` / `services.rs` / `routes.rs` on `copilot-web`; handlers check
   in FastAPI's order.
4. Mount it in `crates/copilot/src/app.rs` and add the prefix to
   `PORTED_PREFIXES` (`GET /api/…` when only that method is ported: other
   methods on those paths are 405s the binary forwards to Python).
5. Extend the e2e suite and the parity harness; every intentional difference
   goes in §4 with a test.
6. Background work: hand over through `scheduled_job_metadata`, never run in
   both services.
