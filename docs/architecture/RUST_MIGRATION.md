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
                       │ /api/auth/token*, /refresh, /2fa/*, /login,        │
                       │   /register, /users*, /reset-password*, /delete/*, │
                       │   /me/customers, /sso/*, /passkey/*,               │
                       │   /security/*             copilot-identity         │
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
- **Same tokens.** Since phase 2 the Rust service issues them too (login,
  refresh, 2FA, SSO, passkeys). A token from either backend is accepted by
  the other (HS256 over the raw `JWT_SECRET`, PyJWT's claims and rules —
  `copilot_auth::jwt`), and so are the 2FA temp token, the stored TOTP
  secrets, an SSO `state` and a passkey challenge token.
- **Same wire format.** Ported routes return the same JSON, in the same field
  order, with the same error envelopes and 422 texts. This is not a goal on
  paper: `backend/tests/e2e/rust_parity_e2e.py` sends identical requests to
  both implementations on one database and compares the answers
  (481 checks, all equal; see §5).

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
| `copilot-auth` | `app/auth/utils.py`, `app/auth/services/totp.py` (crypto), `app/middleware/customer_access.py`, `app/incidents/middleware/tag_access.py`, PyJWT's RS256 path | JWT (HS256, incl. the 2FA temp token), RS256 identity-provider tokens and JWKS (`jws.rs`, `rsa.rs`), bcrypt, Fernet, pyotp-compatible TOTP, CPython's lenient base64 (`pybase64.rs`) and `json.loads` values (`pyvalue.rs`), `AccessScope` (tenant decisions), tag RBAC (`tags.rs`) |
| `copilot-web` | `exception_handlers.py`, `require_any_scope`, Pydantic validation (incl. `EmailStr`), FastAPI/Starlette body reading | axum glue: error envelope, Pydantic-lax validator and 422 report, `EmailStr` (`email.rs`, email-validator), JSON and form bodies read before the dependencies (`body.rs`, `form.rs`, `pyjson.rs`), `urllib` quoting, Starlette redirects and cookies (`pyurl.rs`), auth extractors, middleware |
| `copilot-jinja` | Jinja2 3.1.6 `SandboxedEnvironment(undefined=StrictUndefined)`, MarkupSafe 3.0, `app/notifications/services/rendering.py` | the template language operators write (today the temporary-password email): lexer, parser, a compiler with Jinja's scoping and constant folding, a VM with Python 3.11 value semantics, and the renderer's 64 KiB output cap; `jinja_vectors.json` (`scripts/gen-jinja-vectors.py`) pins 642 renders and errors |
| `copilot-talon` | `app/connectors/talon/` | **the Talon contract** (`contract.rs`), client, `/api/talon/*` |
| `copilot-ai-analyst` | `app/ai_analyst/`, palace drainer/sweeper jobs | `/api/ai_analyst/*` (25 routes), consolidation digest, CPython-exact `difflib` |
| `copilot-customer-portal` | `app/customer_portal/` (`ai_reports`, `ai_requests`) | `/api/customer_portal/ai_reports/*` (6 routes); every other portal path is still proxied |
| `copilot-customers` | `app/customers/` (reads) | `GET /api/customers/*` (7 routes); creating, changing and deleting customers provisions Graylog/Grafana/Wazuh and stays in Python |
| `copilot-incidents` | `app/incidents/` (`routes/db_operations.py` and its services, `services/case_events.py`, `customer_reply.py`, `status_cascade.py`, the template half of `case_tasks.py`, `notification_enrichment.py`, `middleware/tag_access.py`'s single-alert rule, `services/verdict_stats.py`), the incident builders of `notifications/services/event_builders.py` | `/api/incidents/db_operations`: every `GET` (35) and the writes — alert creation, status (one and bulk), verdict, verdict state, escalation, assignment (one and bulk), comments, contexts, assets, IoCs, tags, deletion (one, bulk, by title); case creation (from scratch, from an alert), links, comments, status with the alert cascade, escalation, severity, assignment, customer move; the AI-trigger and Shuffle rows; the field dictionaries; the case-task writes and the manual template apply. `/api/incidents/case_templates`: the template and template-task CRUD. `/api/incidents/tag_access`: settings, user and role tags, `/me`. `/api/incidents/alerts`: the Velociraptor Sigma exclusion rules (create with the link comment, list, read, edit, toggle, delete). `/api/incidents/report`: the CSV case exports. `/api/incidents/customer_reports`: the report list and the visibility switch. Still Python: the three Wazuh-indexer reads, the MinIO routes (case files, report templates, `DELETE /case/{id}`), `POST /case/notification` (Shuffle), the template library and `/case_templates/suggest`, the rest of `/alerts` (creation and Sigma ingest read the indexer or Graylog; the exclusion draft and dry-run share the ingest's event flattening and matcher), the DOCX/PDF case reports and the customer report generation, download and deletion (MinIO, docxtpl, wkhtmltopdf) |
| `copilot-sla` | `app/soc_management/` (`domain/{lifecycle,policy,calendar}.py`, `services/lifecycle.py`, the reads of `services/{policy,calendars}.py`), `app/incidents/services/alert_severity.py` | the SLA lifecycle recorder the incidents routes call (#1187): tracking rows opened with snapshotted targets, guarded write-once milestones, pause/resume on `PENDING_CUSTOMER`, re-targeting on case severity and link changes; 24/7 and business-hours clocks (IANA zones via `chrono-tz`) |
| `copilot-healthchecks` | `app/healthchecks/agents/` (database half) | `GET /api/healthcheck/*` (4 routes); the classification is shared with the customer routes. `POST /logs` (Wazuh indexer) stays in Python |
| `copilot-platform` | `app/version/`, `app/audit/` (reads) | `GET /api/version/check` (PEP 440 compare; `COPILOT_VERSION_CHECK_URL` points it at a mirror), `GET /api/audit`, `/actions`, `/{id}` |
| `copilot-identity` | `app/auth/routes/auth.py`, `routes/totp.py`, `routes/customer_users.py`, `routes/sso.py`, `routes/passkey.py`, `routes/security_admin.py`, `services/totp.py`, `services/customer_assignment.py`, `services/sso.py`, `services/passkey.py`, `services/security_admin.py`, `services/temp_password_email.py`; the branding merge of `app/customer_portal/services/branding.py` and the palette of `customer_report_branding.py` | login (`/token`, `/token/customer-portal`, the deprecated JSON `/login`), `/refresh`, the six `/2fa/*` routes, user management (`/register`, `/users`, `/users/{id}`, `/reset-password`, `/reset-password/me`, `/delete/{id}`, `/users/{id}/role/by-name`, `/users/{id}/customers`, `/me/customers`), SSO (`/sso/*`: settings, allowlist, Azure, Google, Cloudflare Access), passkeys (`/passkey/*`), the admin Security tab (`/security/*`: users, SMTP status, 2FA reset, the temporary-password email's templates, preview and send over SMTP); the enrolment QR code, the 2FA brute-force counter |
| `copilot-webauthn` | `webauthn` (py_webauthn 2.8), `cbor2`, the origin helpers of `app/auth/services/passkey.py` | registration and assertion verification (attestation `none`, `packed`, `fido-u2f`; py_webauthn's default algorithms ES256, ES512, EdDSA, RS256/384/512, PS256/384/512), cbor2-exact CBOR, options JSON, the relying-party/origin rules |
| `copilot-notifications` | `app/notifications/` (routes, services, channels, schemas); `app/customer_portal/services/branding.py` merge and the report palette (moved here from `copilot-identity`, which re-exports them) | every notification route (customer and internal routes, Shuffle integrations, the dispatch log, channel catalog, Resend quota, named templates and preview, manual send, Talon's dispatch, `POST /notifications/events`); the dispatch pipeline and its log; the webhook, Teams, Resend and Shuffle providers; `DispatchingSink`, the in-process `NotificationSink` |
| `copilot-markdown` | `app/notifications/utils/markdown_html.py` (markdown-it-py 4.2 `gfm-like`, `html=False`; mdurl; CPython punycode) | Markdown → inline-styled HTML for emails, a line-by-line port pinned by `markdown_vectors.json` (`scripts/gen-markdown-vectors.py`; character tables by `gen-markdown-tables.py`) |
| `copilot-scheduler` | `app/schedulers/` (`scheduler.py`, `routes/scheduler.py`, `utils/universal.py:record_job_success`), `app/audit/services/retention.py` | the job runner (APScheduler's interval semantics on tokio: fixed grid, coalesce, one instance, 1 s misfire grace), the hand-over rule and run lock, `/api/scheduler/*` (reads from APScheduler's `apscheduler_jobs` store through a read-only pickle decoder pinned by `apscheduler_vectors.json`, `scripts/gen-apscheduler-vectors.py`; run/start/pause), `prune_audit_log`; the palace jobs register from `copilot-ai-analyst`; `copilot jobs` and `doctor` list each job's owner |
| `copilot-upstream` | what the connector helpers did with a tool's answers: `requests`/`niquests` (`PreparedRequest`, urllib3's URL parsing and error texts), CPython's `json` (`dumps`, `JSONDecodeError`), Pydantic models, FastAPI's `serialize_json` | shared by the connector crates: a `requests`-like client (`http.rs`), a Pydantic engine (`model.rs`: lax coercion, smart unions, aliases, defaults, validators, `ValidationError` text, JSON-mode dumps; `model_vectors.json` pins 905 probes, `scripts/gen-connector-model-vectors.py`), Python exceptions as values (`py.rs`: `KeyError`, `TypeError`, … and what the handlers make of them), pydantic-core's JSON writer and FastAPI's 422 (`respond.rs`) |
| `copilot-graylog` | `app/connectors/graylog/` (routes, services, schema, `utils/universal.py`, `utils/routing.py`), `app/connectors/event_shipper/` and `app/integrations/utils/event_shipper.py` (GELF over TCP) | `/api/graylog/*` (21 routes); `GraylogClient` for later ports: the four helpers with Python's error behaviour, the 6.x/7.x version probe and `EntityKind` (the four wrapped creation endpoints), the URL allowlist fallback |
| `copilot-influxdb` | `app/connectors/influxdb/` (routes, services, schema, `utils/universal.py`), the Flux side of `influxdb_client` 1.50 (`InfluxDBClientAsync` over aiohttp, `FluxCsvParser`) | `/api/influxdb/*` (10 routes: alerts, check names, hosts, seven metrics views); `InfluxClient` for later ports: Flux queries with the library's request, timeout and error texts, the v2 REST helpers (`_influxdb_request`, the org-id lookup) for the checks provisioning |
| `copilot-gateway` | — | legacy proxy (its notification bridge sink is no longer wired); deleted when the migration ends |
| `copilot` | `copilot.py` | binary: `serve`, `doctor`, `routes`, `jobs`, `palace drain|sweep` |

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
Python handlers write. Check order is FastAPI's: the body is *read* first —
malformed JSON (with a JSON content type) is a 422 `json_invalid` at CPython's
error position, a body that is not UTF-8 a 400 `{"detail": …}`, both even
without a token — then token → path → tenancy → query → body *validation*.
A body sent without a JSON content type never matches a model, as in FastAPI.
Handlers take `WithJson(auth, body)` for this (`copilot_web::body`).

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

**Login and 2FA.** `OAuth2PasswordRequestForm` is read the way Starlette and
python-multipart read it (`copilot_web::form`): urlencoded and multipart
(what the frontends' `FormData` sends), the last value of a repeated field,
an empty value as absent, a part that is never closed dropped, Starlette's
400s for a missing boundary or part name. `customer_user` accounts log in only
at `/token/customer-portal` and every token they get carries
`customer_codes`; a user with 2FA gets the 5-minute temp token and finishes
at `/2fa/validate`. Logins, refusals and failed second factors write the same
`auth.login` / `auth.login_failed` audit rows; `last_login_at` is stamped on
success. TOTP secrets are Fernet tokens under `TOTP_ENCRYPTION_KEY` or, when
unset, the key derived from `JWT_SECRET` — the same resolution, so secrets
enrolled under either backend work on both, and a malformed key stops the
binary at startup as it stops Python. Codes are pyotp's (SHA-1, 6 digits,
30 s, ±1 step, NFKC comparison); a time step is accepted once; backup codes
are checked as `upper().strip()` against bcrypt hashes, with bcrypt 5's
errors passed through (`Invalid salt`, the 72-byte message). Five failed
checks within 15 minutes lock a user out of every 2FA check; the counter is
in memory per process, which is why all six 2FA routes moved together.
`ACCESS_TOKEN_EXPIRE_MINUTES` is read like Python's `int()`. Vectors from
cryptography/pyotp (`scripts/gen-auth-vectors.py`) and from Starlette and
CPython's `json` (`scripts/gen-form-vectors.py`) pin the Fernet tokens byte
for byte, the codes, URIs, form parsing and JSON error positions.

**User management.** Registration compares usernames and emails exactly, as
Python does in memory (MySQL alone would ignore case), and stores the address
`EmailStr` normalizes it to: `copilot_web::email` ports pydantic's
`validate_email` over email-validator 2.3 — the `Name <addr>` form, the
special-use domains (`.local`, `.test`, …), the RFC 2142 role mailboxes,
every sentence of its refusals (`scripts/gen-email-vectors.py`). The password
rule is 8–72 characters and nothing else: the models' `regex=` is not applied
by SQLModel under Pydantic 2, and the Rust side does not invent it. Every
write of a user's customers follows #1219 (an analyst or responder keeps at
least one, an admin gets none, every code must exist — compared exactly,
although MySQL matched it case-insensitively). bcrypt's `Invalid salt` for an
unreadable stored hash surfaces as Python's global `ValueError` 400 where
Python lets it escape (the JSON `/login`, `current_password`). Deleting a
user whom another row still references (tag access, SMTP settings) fails
whole with `Error deleting user`. Audit events carry the same before/after
values; an absent one is stored as JSON `null`, as SQLAlchemy stores it.

**SSO.** `sso_config` (one row) and `sso_allowed_email` are read and written
as Python does: a blank client secret on `PUT /sso/settings` keeps the stored
one, secrets are never returned, and the allowlist admits the SOC roles only
(admin, analyst, responder). The OAuth `state` is `<nonce>:<ts>:<hmac>`,
HMAC-SHA256 under `SSO_STATE_SECRET` (else `JWT_SECRET`), valid for ten
minutes and kept nowhere, so a login started on one backend completes on the
other. Azure and Google callbacks exchange the code and verify the ID token
with PyJWT's RS256 rules (`copilot_auth::jws`: its segment splitting, lenient
base64, header checks, `iat`/`nbf`/`exp`/`iss`/`aud` semantics and every
message) against the provider's JWKS, cached for an hour; an unknown `kid`
refetches once for Azure and Google, never for Cloudflare. Cloudflare Access
reads the `Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie
the way Starlette parses cookies. A `ValueError` text reaches the user (in
the `/login?error_message=…` redirect, or Cloudflare's 401); anything else is
a generic message. A user is found by email (lowest id) or, when the address
is allowlisted, created with the allowlist's role, no customers and the email's
local part as username (`alice1`, `alice2`, … on a collision). The token
carries no `customer_codes`, a user with 2FA gets the temp token, and, as in
Python, neither an audit row nor `last_login_at` is written. Redirects are
Starlette's: 307, `Location` quoted with its safe set (`copilot_web::pyurl`).
`COPILOT_SSO_IDP_URL` sends every provider call to one test server; it exists
for the parity harness and is never set in production.

**Passkeys.** `user_passkey` and `webauthn_challenge` as Python uses them:
a challenge row (64 random bytes, five minutes, one flow, one user or none)
is addressed by a UUID token that either backend can redeem, and is consumed
under a row lock; an expired challenge is deleted, one presented by another
user is kept. `copilot-webauthn` verifies registrations and assertions as
py_webauthn 2.8 does — CBOR read and re-encoded the way cbor2 does (py_webauthn
re-encodes the COSE key, and the re-encoded length decides where the
authenticator data continues), CPython's base64url decoding, client data,
RP ID hash, flags, attestation `none` / `packed` / `fido-u2f`, the signature
check of every default algorithm, the sign counter — and maps its exceptions
as CoPilot's routes do: a rejected credential is the route's 400 (register)
or 401 (login) with py_webauthn's own sentence, anything py_webauthn would
raise outside its error classes is a 500. The relying party comes from
`WEBAUTHN_ORIGINS` (else `WEBAUTHN_ORIGIN`; an empty value counts as set),
`WEBAUTHN_RP_ID` and `WEBAUTHN_RP_NAME`, with the request's `Origin` resolved
by Python's rules (`urlsplit` included: its hostname, port and errors).
Options are the JSON `options_to_json` produces, in its key order. A portal
user's passkey login is a 403; a user with 2FA gets the temp token. Vectors
from py_webauthn, cbor2, cryptography and CoPilot's own helpers
(`scripts/gen-webauthn-vectors.py`) pin ~230 registrations and assertions,
the CBOR round trips, the base64 decoder, the origin resolution and the
options byte for byte.

**Security tab.** `GET /security/customers/{code}/users` keeps Python's join
without `ORDER BY` (and its de-duplication of a user listed twice), so MySQL
returns the users in the same order. The `SMTP_*` settings are read as set and
interpreted per request like `_smtp_config()`: a malformed `SMTP_PORT` is that
request's `ValueError` 400 with CPython's `int()` sentence, a literal too large
for a port still counts as configured. The template picker resolves the user's
customer and ranks `notification_template` rows exactly as
`list_available_templates` does (this customer's, shared, built-in; another
customer's never). Its query is SQLAlchemy's, column list included, so
MySQL's filesort orders same-second ties for both backends alike. A forced
2FA reset writes the same `user.update` audit row.

**Temporary-password email.** Preview and send resolve the customer and the
template as the picker does and render through `copilot-jinja` with the
variables of `build_extra_context`; `branding` is built only when the source
names it, from the portal's field-by-field merge and the report palette. Send
keeps Python's order: render, rotate, mail, audit. A template error is a 400
that leaves the password alone; a refused delivery is a 502 after the
rotation, with no audit row. What a recipient reads is smtplib's message:
the plaintext first and the HTML as its `multipart/alternative`, each text
part's lines ended as `EmailMessage.set_content` ends them, and no blank lines
after a single-part body (lettre ends a message with a CRLF of its own and
the DATA terminator with another; the message goes out with `send_raw`
without them). The parity harness runs an SMTP stand-in and compares both
backends' mails decoded, the password masked and then checked against the
stored hash.

**Alert visibility.** One definition, as in Python:
`copilot_db::visibility::AlertVisibility` (customer scoping *and* tag RBAC,
`alert_visibility_filters_for_user`) for lists and counts, and
`can_user_access_alert` for a single alert. The two tag rules differ where
Python's do — `default_tag` with no tag configured allows one untagged alert
but keeps untagged alerts out of lists — and `copilot_auth::tags` pins the
table. Admins, the scheduler and portal users bypass tag RBAC; a responder
gets the analyst role's tags.

**Incidents.** `copilot-incidents` answers `/api/incidents/db_operations`
but for the paths and methods it does not route, which fall through to
Python: `/available-source/*`, `/available-indices/*` and `/mappings/*` read
the Wazuh indexer; the case files and report templates (`/case/data-store/*`
uploads, deletes and downloads, `/case-report-template*`, `DELETE
/case/{id}`) live in MinIO — and the Python client dials `MINIO_URL:9000`
whatever the environment, so no MinIO stand-in can sit beside the parity
harness to prove a port; `POST /case/notification` calls Shuffle.
`copilot-incidents` also answers `/api/incidents/case_templates` (the
template CRUD; the library, fetched from GitHub into that process's cache,
and `/suggest` stay Python — the binary routes those static paths to the
legacy backend so `/{template_id}` cannot capture them) and
`/api/incidents/tag_access`. A list sorted on a non-unique column
(`ORDER BY created_at DESC` on templates) is issued as SQLAlchemy's exact
statement, column list included: MySQL's sort leaves ties in no stable order,
and only the same query gets the same one. Responses are the Pydantic models in their field
order, including the two timestamp renderings (`AlertOut`'s
`…T03:04:05.000Z`, the SQLModel rows' `…T03:04:05`), and a write answers with
what the ORM holds after its commit — the stored row plus what was just set,
so a fresh `utcnow()` (`time_closed`, `verdict_at`, a comment's `created_at`)
keeps its microseconds while MySQL rounds them away, and a comment's
`created_at` sent with an offset is echoed with it (`PyDateTime`). The
relationships SQLAlchemy `selectinload`s come back in the order MySQL scans
them — comments and assets by id, tags and IoCs by their link table's key,
linked cases by case id — and the loaders use those keys; a joined listing
is not de-duplicated (an alert with two matching assets is listed and counted
twice), as the ORM query is not. Every listing and count goes through
`AlertVisibility`; one alert is checked with `check_alert_tag_access` (the
*list* rule on its tags, before the customer check), cases by customer only.
An IoC whose stored type is not an `AlertIocValue` makes Pydantic raise in
`IoCBase(...)`: the backend's `ValueError` 400 with Pydantic's own text, on
every route that loads that alert, and so it is here (in a bulk loop it fails
the request, while a 403/404 only skips the alert).

Writes keep Python's side effects in Python's order: the case timeline
(`incident_management_case_event`, one short transaction per emit, never
failing the request), the audit rows (`alert.verdict_set|clear`,
`case.create`), the case-template auto-apply on a link or a case from an
alert (field-match templates fetch the raw event from the Wazuh indexer; any
failure falls back to the tier picker, as in Python), the customer-reply
hand-back of a waiting alert or case, and the `alert_assigned` /
`case_assigned` / `case_task_assigned` notifications (on a change only),
built by `copilot_core::notify`'s builders, emitted through
`ctx.notifications` (the binary's `DispatchingSink`) and pinned in
`copilot-incidents`' `notify.rs` against the Python builders' output. `IntegrityError`s Python maps to a 400
(`… already exists`) are mapped the same way; everything else is a bare 500,
including Python's own 500s, kept on purpose because they write the same
rows first: a duplicated dictionary entry (`scalar_one_or_none`), `PUT
/fields-assets-title-and-timefield` without `ioc_field_names` (four commits,
then a `TypeError`), `DELETE /delete-fields-assets-title-and-timefield` with
IoC names (a `TypeError` before the commit), deleting a tag or IoC another
alert still uses (FK). The deprecated single-name deletes answer `null` and
commit nothing, as in Python.

Of `/api/incidents/alerts` only the Velociraptor Sigma exclusion rules are
Rust: their CRUD and toggle, each answering with the row as the service's
`refresh()` reads it back (`field_matches` in MySQL's JSON key order; a
`None` stored as JSON `null`, an edit writing only the attributes whose value
changed, compared with Python's `==`), and the `Exclusion rule created from
this alert: …` comment a rule created in context leaves on its alert
(best-effort, after the commit, through the comments service). The rest stays
Python, and not for want of time: alert creation (`/create/manual`, `/auto`,
`/threshold`) and the Sigma ingest (`/create/velo-sigma`) read the alert from
the Wazuh indexer or Graylog, and `/alert/details`, `/alert/timeline`,
`/index/names`, `/alerts/not-created` are indexer reads; the exclusion draft
and dry-run are built on `extract_event_fields` (attributes of Pydantic event
models, read through `dir()`) and `_matches_exclusion` (Python `re` patterns
from the rule), the one flattening and the one matcher the ingest uses to
decide what is suppressed — a Rust copy beside a Python ingest would be a
second definition free to drift, so they move with the ingest.

Of the reports, what reads and writes only the database is Rust: the CSV
case exports (`POST /api/incidents/report/generate-report-csv[/{customer}]`,
`csv.DictWriter`'s dialect — a field quoted for `,` `"` `\r` `\n`, quotes
doubled — over the cases and links in the ORM's load order, the file named
after the process's local time like `datetime.now()`) and, of
`/api/incidents/customer_reports`, the list (CoPilot and the portal: the
caller's customers narrowed by `customer_codes`, a portal user's own and
shared reports, `generated_at DESC` issued as SQLAlchemy's statement for the
same tie order, `filters_json` read with `json.loads`' grammar) and the
portal-visibility switch. The case DOCX/PDF reports and customer report
generation, download and deletion stay Python: their templates and files
live in MinIO (see above), and they render through docxtpl, the Jinja report
templates and wkhtmltopdf.

**SLA clocks.** `copilot-sla` is the recorder the routes call where Python
calls `SlaLifecycleRecorder` — after the change is committed, on its own
transaction, awaited, errors logged and never returned. Opening snapshots the
targets (customer cell → global → built-in) on the cell's clock; actions are
guarded `UPDATE … WHERE <milestone> IS [NOT] NULL`; `PENDING_CUSTOMER` stamps
`paused_at` and any later status change resumes, extending the running clocks
by the pause measured on their basis. Business hours follow
`domain/calendar.py` to the microsecond (`timedelta` rounding, local windows
converted per day with `zoneinfo`'s fold-0 rules). As in Python, only admins
and analysts (role ids 1 and 2) acknowledge: a responder's action does not.
The dashboard, the policy and calendar editors and `notify_sla_transitions`
stay in Python and read the same rows.

**Talon.** `crates/copilot-talon/src/contract.rs` types every request and
response of Talon's HTTP channel (`talon-http`): `/investigate`,
`/investigations`, `/message` (SSE frames), `/session/reset`, `/status`,
`/templates`, `/palace/lesson|search|forget`, `{"error"}` bodies, and Talon's
own validation rules (customer code, template names). Tests pin the exact
JSON in both directions. CoPilot authenticates with `x-api-key`, as before.

**Notifications.** `copilot-notifications` serves every route of
`app/notifications/routes/notifications.py` and dispatches every event
in-process. A ported module builds the exact `NotificationEvent` the Python
builders build (`copilot_core::notify`: the AI-analyst, `alert_created` and
assignment builders) and emits it through `NotificationSink`; the binary's
`DispatchingSink` runs `dispatch_event` on a task of its own with a 60 s cap,
logged and never the caller's failure, as `emit.py` does. The two AI-analyst
triggers keep the retired bridge's checks — the alert exists and belongs to
the event's customer, a caller's token may see that customer, the dedupe key
and link are re-derived — so a notification goes out exactly when the bridge
would have forwarded it; `POST /notifications/events` is the same check over
HTTP. The pipeline keeps Python's semantics rather than fixing them: send,
then log (a `(route, dedupe_key)` already `sent` refuses the log write, not
the delivery — SLA notices and assignment re-notification rely on it), any
integrity error read as "already dispatched", the AI opt-out gate on
customer-facing routes, legacy `severity_critical_or_high` routes. Providers
send the bytes httpx sent (CPython's `json.dumps`, key order, `ensure_ascii`
where Python used it) and fail with httpx's and h11's texts (header checks
included); a provider that "raised" is logged as `Dispatcher exception: …`
without a latency. Channel configs are pinned by `config_vectors.json`, Teams
cards by `teams_vectors.json`, Markdown email bodies by `copilot-markdown`
(markdown-it-py's `IndexError`s included). The parity suite
`rust_parity_notifications_e2e.py` points webhook, Resend and Shuffle at one
recorder and compares every outbound request, response and dispatch-log row;
Teams URLs must be `https://`, so its deliveries are compared through their
failure. The SLA notifier (`notify_sla_transitions`) still runs in Python.

**Scheduled jobs.** A job moves to Rust only by explicit hand-over, and never
runs in both schedulers. Rust runs a job when the operator opted in
(`COPILOT_RS_JOBS`: job ids or `all`; `COPILOT_RS_PALACE_JOBS=true` names the
two palace jobs) **and** the job's deciding `scheduled_job_metadata` row (the
lowest id) exists and is **disabled**; APScheduler runs it only while that row
is enabled or absent. The Python half (`app/schedulers/handover.py`) is a guard
on the job function itself, so it holds whichever `apscheduler_jobs` entry
fires it — a disabled row alone never took a job out of APScheduler's store,
and `initialize_job_metadata` used to re-enable every row at startup (it no
longer does for these jobs). Both sides take the MySQL named lock
`copilot_job:<SHA1(database/job)>` for the whole run and re-read the row under
it: a scheduled tick that finds the lock held or the row not its own is
skipped (Python returns `JOB_SKIPPED`, which the listener does not stamp), a
manual run waits ten seconds and then answers 500 "already running" on either
side; a run that dies drops the lock with its connection. Hand over with
*Pause* in the Scheduler UI — through the Rust service, which forwards it to
APScheduler and then disables the row; hand back with *Start* (the row is
enabled first, and restored if Python refuses). Pausing a job Rust is not
opted in for simply pauses it. Rust stamps `last_success` on the deciding row
after each successful run of its own (a manual run only where the Python
function stamps it, i.e. the palace jobs). Its runner follows APScheduler's
interval semantics, with one change: the first run continues from the job's
`last_success` (one interval after it, or a minute from now when overdue)
instead of one interval after the process started, so a daily job on a host
restarted daily still runs. Ported: `prune_audit_log`,
`invoke_palace_lesson_drainer`, `invoke_palace_lesson_sweeper` (status flips
guarded on the previous status, so a lesson is never ingested or expired
twice). Run a single Rust instance with the opt-in.

**Connectors (Graylog).** `copilot-graylog` answers every route of
`app/connectors/graylog/routes/` but `POST /api/graylog/invoke` (the
active-response webhook, another module). A connector route is a call to the
tool, subscripts into its JSON, Pydantic models and an answer, and each of
those is reproduced rather than approximated: the request is `requests`'
(`f"{connector_url}{endpoint}"`, urllib3's URL normalisation, `params=`
appended with `urlencode`, HTTP Basic over latin-1 with `None` sent as
`"None"`, `X-Requested-By: CoPilot`, `Content-Length: 0` on a bodiless
non-GET, `json=` as `json.dumps`), certificates are not verified (Python's
`verify=False`: Graylog in a SOCFortress stack serves a self-signed
certificate), and every failure is worded as the library words it — URL
errors (`MissingSchema`, `InvalidSchema`, `InvalidURL`), urllib3's
connection errors, CPython's `JSONDecodeError`, a subscript's `KeyError` /
`TypeError`, a model's `ValidationError` — and handled where Python catches it
(a helper's `HTTPException`, a service's `except KeyError` then `except
Exception`, or nobody: the `ValueError` handler's 400 or a bare 500). The
models (`copilot_upstream::model`) follow Pydantic 2's lax mode and smart
unions and are serialized as FastAPI 0.136 does it, through pydantic-core's
`serialize_json` (its float format is `serde_json`'s, `NaN` is `null`); 33
samples of Graylog 6.1 and 7.0 answers and 1,440 mutations of them pin each
model (`copilot-graylog/src/model_vectors.json`). One Python quirk the models
keep: `typing` caches `Dict[str, Union[…]]` by set equality, so the member
order of a union — and the order of its errors in a 422 — is whatever the
first importing module spelled; Rust follows `copilot.py`'s import order
(`AlertQuery.filter`: `str` before `list[str]`). Graylog 7.0 is handled as
in Python: `EntityKind` names the four creation endpoints 7.0 wraps in a
`CreateEntityRequest` (`/api/streams`, `/api/events/definitions`,
`/api/events/notifications`, content-pack installation), wrapped only when
`GET /api/system` reports 7 or more (cached five minutes per connector; a
failed probe counts as 6, cached too), and the URL allowlist is read from
`/api/system/urlallowlist`, else `/urlwhitelist`. The receiver ships one GELF
frame per request to the Event Shipper exactly as asyncgelf builds it
(`socket.getfqdn()` as the host); as in asyncgelf, an unreachable shipper
is not an error. `rust_parity_graylog_e2e.py` runs both backends against a
Graylog stand-in with a 6.x and a 7.x personality and a GELF listener, and
compares status, response bytes and every request sent to Graylog.

**Connectors (InfluxDB).** `copilot-influxdb` answers all ten routes of
`app/connectors/influxdb/routes/`. Python reaches InfluxDB through
`influxdb_client`'s async client, so that is what is reproduced: `POST
{connector_url minus one trailing /}/api/v2/query?org=…` (the org
`urlencode`d, then requoted as yarl does), `Authorization: Token <key>` only
for a non-empty key, the library's `User-Agent`, `Accept-Encoding: gzip,
deflate` (answers decompressed), the `{"extern", "query", "dialect"}` body
with `json.dumps` spacing, a 10 s whole-request timeout and no certificate
verification (`verify_ssl=False`, as in Python). The annotated-CSV answer is
parsed as `FluxCsvParser` does in tables mode (Python's `csv` rules, a table
per annotation block and per change of the `table` column, `#default`
values, the typed cells, an `error,reference` table raised as
`FluxQueryException`). The services keep their texts and their order —
Flux queries character for character, the alerts' two queries (current state
by `last()` per series, then the rows; #1118's identity without the
`STATE_TAGS`), metrics queried one after the other, a failure answered as
`success: false` with `str(e)`: the library's `ApiException` (status, the
status line's reason, aiohttp's header repr, the body's `bytes` repr), aiohttp's
connection, DNS, URL and timeout errors, `KeyError`s for missing columns,
`ValidationError`s. A body that stalls past the timeout after its headers
arrived is aiohttp's `CancelledError`, which no `except Exception` catches:
a bare 500, in both. `rust_parity_graylog_e2e.py` (section `influxdb`) runs
both backends against an InfluxDB 2.7 stand-in that answers CoPilot's Flux
queries from sample `statuses` and Telegraf series.

**Connector cache.** The Python backend invalidates its connector cache after
each write but cannot reach the Rust process, so while a legacy backend is
configured the Rust TTL is capped at 60 s.

---

## 4. Differences by design

Each is covered by a test — the parity harness or, for the passkey
verifier, the WebAuthn vectors — unless the row says otherwise; races are
not provoked.

| Where | Python | Rust | Why |
|---|---|---|---|
| `GET /ai_analyst/alerts_with_reports` | passes `customer_codes` through; a scoped analyst sending none sees **every tenant** | intersects with the caller's customers (`scoped_customer_codes`), `[]` → empty list | tenant leak |
| `GET /talon/jobs/{alert_id}` | no tenancy check | `verify_alert_access` | tenant leak |
| `POST /ai_analyst/jobs` on an existing id | relabels any job | also checks the existing job's owner | a scoped caller could relabel another tenant's job |
| `POST /ai_analyst/reports/{id}/review` (edit) | answer lists the IOC reviews it just deleted | answers with what is stored | Python identity-map artefact |
| concurrent first review | unique-key 500 | retried as an edit | race |
| `POST …/replay` template | Python's regex only; Talon then 400s → 500 | Talon's rule (no `..`, not hidden), same 422 text | fail early |
| `/talon/*` upstream failure text | `requests` exception text | status plus Talon's `{"error"}` text | actionable |
| TLS to Talon | `verify=False` | verified; `TALON_VERIFY_TLS=false` opts out | the request carries Talon's API key |
| `triggered_by` of an investigation a person starts (analyst, replay, portal request) | not sent: Talon records the job as `webhook` | `manual` (Talon registers it so, Liohtml/talahon#4) | the job says who started it |
| scoped branch of `GET /incidents/db_operations/alerts/{status,source,asset,assigned-to,title}/…`, `/alert/{ioc,tag}/…` | customer codes only, no tag RBAC; a scope that resolves to no customer (an unassigned analyst, a subset of foreign codes) passes `customer_codes=[]`, which the filter reads as "no filter": **every tenant's alerts** | the one alert visibility (customers *and* tags); nothing visible → an empty page; the counts follow the same visibility | tenant leak (and tag RBAC bypass) |
| `GET /incidents/db_operations/alert/context/{id}` | any analyst reads any tenant's context | owner = the customer of the alert its asset belongs to, fail-closed (`Access denied to alert context {id}`) | tenant leak |
| `GET /incidents/db_operations/case/data-store` | every tenant's case files | the caller's customers' only | tenant leak |
| `/incidents/case_templates` (list, read, edit, delete, tasks, reorder) and `POST /incidents/db_operations/case/{id}/apply-template/{template_id}` | any analyst lists, reads, edits, deletes and applies every tenant's customer-scoped templates, and creates templates for any customer | a scoped caller sees shared templates (NULL customer) and their customers' only — another tenant's reads as `Template id=… not found` (lists keep their order without it; an apply copies nothing); naming another tenant's customer in a create or an update is a 403 | tenant leak (as `custom_dashboard_templates`, #1050) |
| `/incidents/alerts/create/velo-sigma/exclusion*` and `POST …/velo-sigma/exclusion/{id}/toggle` | any analyst lists, reads, edits, toggles and deletes every tenant's customer-scoped exclusion rules, and creates rules for any customer — suppressing that tenant's alerts | a scoped caller sees shared rules (NULL or empty customer, which the matcher applies to everyone) and their customers' only — another tenant's reads as `Exclusion rule not found` (lists drop it, `total` counts what is listed); naming another tenant's customer in a create or an edit is a 403. Shared rules stay editable by any analyst, as in Python | tenant leak (as `custom_dashboard_templates`, #1050) |
| `POST /incidents/report/generate-report-csv` | any analyst exports every tenant's cases, alerts, assets, tags and comments | the export holds the caller's customers' cases only (an unassigned analyst gets the header row); the per-customer export already checked the customer | tenant leak |
| `PUT /incidents/db_operations/ai_trigger`, `PUT …/notification` | checks only that the `customer_code` *query* parameter names an existing customer, then writes the *body*'s customer's row: a scoped analyst switches another tenant's AI investigations or Shuffle workflow on or off | the body's customer must also be the caller's (`Access denied to customer {code} - insufficient customer permissions`) | tenant leak |
| `GET /talon/jobs/{alert_id}/verdict` | — | Talon's structured verdict for the newest of the alert's jobs, tenancy-checked like `/jobs/{alert_id}` | Rust-only addition |
| `POST /scheduler/pause/{id}`, `/start/{id}` of a job Rust can run | pauses/resumes APScheduler's job only; `scheduled_job_metadata.enabled` keeps its value (the Scheduler UI shows a paused job enabled again after a reload) | forwarded to Python, then `enabled` set to 0/1 | the flag is the hand-over switch; the UI's `enabled` becomes truthful |
| `GET /scheduler/next_run/{id}` of a job Rust runs | APScheduler's copy, paused: the `ValidationError` 400 | Rust's next run | the job runs there |
| a manual run of a job Rust runs that fails | 500 with `str()` of the Python exception | 500 with the Rust error's text | the driver's words (not provoked) |
| palace search hits | numeric `id` → 400 | stringified | robustness |
| "latest" row on a same-second tie (`alerts_with_reports/{alert_id}`, portal recent reports) | whichever row MySQL's plan reaches first — varies with the data | the newest id, the rule the portal's `MAX(id)` already uses | deterministic |
| agent healthcheck clock | `datetime.now()`: the process's local time (UTC in the image) | UTC | the `*_last_seen` columns hold UTC; equal in the shipped image |
| `/auth/token*` with an unknown username | answered without hashing | one bcrypt verification against a dummy hash | response time no longer tells which usernames exist |
| `/2fa/validate`, same code twice at once | read-then-write: both requests can log in | the time step is claimed with a guarded `UPDATE` | replay race |
| backup code used twice at once | both requests can log in | spent under a row lock | replay race |
| token bytes for a non-ASCII username | PyJWT escapes it (`\u00e4`) in the payload | raw UTF-8 | both are valid JSON and decode to the same claims |
| `user.created_at` of a registered user | the process start time (the model's default is evaluated at import) | the time of registration | Python bug; the column is not in any response |
| why an internationalized email domain is refused | the `idna` package's wording | a shorter sentence with the same opening | valid addresses normalize identically; ASCII addresses match word for word |
| passkey attestation `tpm`, `android-key`, `android-safetynet`, `apple` | verified against the vendors' roots | 400 `Unsupported attestation type "…"` | CoPilot asks for attestation `none`, so browsers send `none` (or `packed` self-attestation); both are verified |
| a malformed attestation certificate | 400 with cryptography's ASN.1 text | 400 with x509-cert's text | same status; only the parser's sentence differs |
| an EC attestation certificate on a curve other than P-256/384/521 | verified | 500 | no authenticator uses one (not covered by the vectors) |
| one passkey challenge redeemed twice at once | read, check, delete: both requests can pass | consumed under a row lock | replay race |
| passkey login with a non-zero number as the credential id | looked up as given, so MySQL compares the column as a number | 500 | malformed client; credential ids are base64url strings |
| an identity provider answering with something that is no token response or JWKS | sometimes the parser's or `ValueError`'s text (Cloudflare: 401) | the generic message (Cloudflare: 500) | an upstream failure, not the user's |
| SSO `state` timestamp | `datetime.utcnow().timestamp()`, read as local time | the Unix epoch | identical on a UTC host (the image) |
| semantic CBOR tags (dates, decimals, …) inside a credential | converted by cbor2 | kept as tags | no authenticator sends them |
| `POST /security/users/{id}/send-temp-password`, delivery refused | 502, the reason being `str()` of the smtplib exception (`{'a@b.example': (550, b'…')}`) | 502, the same sentence up to the colon, then lettre's text (`permanent error (550): …`) | the reason is the SMTP library's |
| temporary-password email `branding`, a logo but no brand colour | the colour Pillow derives from the logo | the SOCFortress orange (`#fc862e`), with a warning in the log | Pillow's decoders and median-cut quantizer are not ported; a brand colour gives both the same palette |
| a template that loops or recurses without end | runs until the worker gives up, or `RecursionError` at Python's frame limit | `RuntimeError` after 5,000,000 loop iterations and macro calls; `RecursionError` near, not exactly at, the same depth; a value over 64 MiB is a `MemoryError` before it is built | a template cannot hold a worker (`copilot-jinja`'s `tests/limits.rs`) |
| a template Jinja compiles into invalid Python (`{{ x[1:2, 3] }}`) | `SyntaxError: invalid syntax (<template>, line N)`, N a line of the generated module | `SyntaxError: invalid syntax (<template>)` | there is no generated module (`tests/limits.rs`) |
| `POST /notifications/dispatch` | dispatches for any customer the body names | 403 unless the caller may see the body's `customer_code` | tenant leak |
| an AI-analyst event emitted without a token | (the bridge answered 401: nothing sent) | dispatched: CoPilot acting on its own; a request's emit always carries the caller's token, which is checked | the bridge's caller check needs a caller; no token-less emitter exists today |
| a delivery with an invalid header (webhook `headers`, a Shuffle `Org-Id`, an API key) to an unreachable host | h11 checks headers after connecting: the connection error | checked before connecting: the header error | same texts whenever the host answers |
| a header value with a control character other than tab | sent (h11 allows `\x01`–`\x08`, `\x0e`–`\x1f`) | `LocalProtocolError: Illegal header value …` | the `http` crate cannot carry them |
| an `xn--` autolink host that decodes to a lone surrogate | the surrogate in the link text | the label left encoded | a Rust string cannot hold one |
| a connector call that cannot connect (`/graylog/*`) | urllib3's text with the address of a Python object (`<urllib3.connection.HTTPConnection object at 0x7f…>`) | the same text with `0x7f0000000000` | the address differs between any two processes; the parity suite masks it |
| `GET /graylog/metrics` when both Graylog calls fail | the error of whichever `asyncio.gather` call failed first (timing) | the `/api/system/metrics` call's error | deterministic; both are sent, as in Python |
| `GET /graylog/event/definitions` against a Graylog that never reaches its own `total` | pages for ever | stops after 20,000 pages | a request cannot hold a worker (not provoked) |
| `/influxdb/*` when InfluxDB answers an error through something other than InfluxDB | aiohttp prints a header it does not know in the case it arrived in | Go's canonical case (`X-Influxdb-Build`; aiohttp's own spelling for the headers it knows) — `http` keeps names lower-cased | identical for InfluxDB, a Go server (not provoked) |
| `/influxdb/*` with a connector host that resolves to several addresses, all refusing | `Multiple exceptions: …` naming each | `Connect call failed` naming the first | one address is the usual case (not provoked) |
| `/influxdb/*` with an org name holding `'` | `'` sent as is (yarl) | `%27` (the URL crate's query set) | InfluxDB decodes both to the same org (not provoked) |
| `/influxdb/*` when a cell holds a date-time InfluxDB never writes (no offset, a date alone) | `datetime.fromisoformat` reads it (a naive datetime) | `Invalid isoformat string: …` | InfluxDB writes RFC 3339 with `Z` (not provoked) |
| the position in a `UnicodeDecodeError` of an InfluxDB answer longer than one network read | relative to the chunk aiohttp was decoding | relative to the body | not provoked |
| the GELF `host` of `POST /graylog/receiver` when the host name is only in DNS | `socket.getfqdn()` asks DNS for the canonical name | the host name (`/etc/hosts` is read, DNS is not) | equal in a container, where `/etc/hosts` names the host (not provoked) |
| an Event Shipper port that is a service name (`http`) | resolved by `getaddrinfo` | not a port: nothing is sent (still answered as forwarded) | only numeric ports are configured (not provoked) |

---

## 5. Testing

| Layer | Where | Needs |
|---|---|---|
| unit | every crate | nothing |
| vectors | `crates/*/src/*_vectors.json`, recorded from the Python implementations (CPython difflib; and through `scripts/gen-*-vectors.py`: pydantic datetimes, PEP 440, Starlette forms and CPython JSON, email-validator, Fernet/TOTP, py_webauthn/cbor2) | nothing; Python to regenerate |
| contract | `copilot-talon/src/contract.rs`, `copilot-core/src/notify.rs`, `backend/tests/test_notification_rust_bridge.py` | nothing |
| end-to-end | `crates/copilot/tests/e2e.rs` and one `tests/e2e_<module>.rs` per later module, on the shared harness in `tests/common/mod.rs` — the production router against MySQL at the Alembic head, Talon and Python replaced by recorders | MySQL |
| parity | `backend/tests/e2e/rust_parity_e2e.py`, then every `rust_parity_<module>_e2e.py` (or `PARITY_SUITES`), via `scripts/rust-parity.sh` — real FastAPI routers vs. the running Rust binary, one database; Talon, GitHub's release API and an identity provider (token endpoint, JWKS, signing key) are local stubs both backends call, and a software authenticator registers and logs in on both; an unhandled Python error compares as the bare 500 uvicorn sends | MySQL + Python venv |

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
| **2 — done** | `auth` (5 k), every `/api/auth` route (`copilot-identity`, `copilot-webauthn`): login, refresh and all of `/2fa/*` — the Rust service issues tokens; user management (register, list, detail, password resets, delete, role change, customer assignment, `/me/customers`, the deprecated JSON login); SSO (settings, allowlist, Azure, Google, Cloudflare Access); passkeys; the Security tab, the temporary-password email included (templates rendered by `copilot-jinja`, SMTP) | the login slice moved as one so the 2FA counter lives in one process. `copilot-jinja` is the renderer phase 3's notification templates will use |
| **3 — done** (what needs the indexer, Graylog, MinIO or a PDF renderer moves with phase 4) | `notifications` (7.2 k) — **done**: `copilot-notifications`, `copilot-markdown`, the bridge retired (in-process `DispatchingSink`); `schedulers` (2.6 k) — APScheduler → tokio, job by job via the `enabled` hand-over; `incidents` (21 k) incl. ingest | ingest then triggers Talon from Rust. Schedulers: the runner, `/api/scheduler` (reads; run/start/pause, forwarding what acts on APScheduler) and the DB-only jobs (`prune_audit_log`, the palace jobs) are ported; the jobs that call connectors (`agent_sync`, `resize_wazuh_index_fields`, `invoke_snapshot_schedules`, the `invoke_*` integrations) and the in-process cache refreshers stay in APScheduler until phase 4; `invoke_alert_creation_collect` moves with incidents, `notify_sla_transitions` with `soc_management`. Incidents so far: `/db_operations` but for its Wazuh-indexer, MinIO and Shuffle routes, `/case_templates` but the library and `/suggest`, `/tag_access`, the exclusion rules of `/alerts`, the CSV exports of `/report`, the list and visibility switch of `/customer_reports` (`copilot-incidents`, SLA recorder `copilot-sla`, `rust_parity_incidents_e2e.py`); alert creation and the Sigma ingest (and with them the exclusion draft and dry-run) wait for an indexer port, the DOCX/PDF reports and customer report generation, download and deletion for MinIO and a PDF renderer |
| 4 | the phase-3 remainder: alert creation and the Sigma ingest (with the exclusion draft and dry-run), the incidents' MinIO routes and DOCX/PDF reports, the connector-bound scheduler jobs; `agents` (9.8 k), `soc_management` (4.4 k), `customer_waf`, `file_analysis`, `customer_provisioning`, `stack_provisioning`, then `connectors` (29.6 k: Wazuh, Graylog, Velociraptor gRPC, …) and `integrations` (37.5 k), one vendor at a time — **Graylog and InfluxDB done** (`copilot-graylog`, `copilot-influxdb` on `copilot-upstream`, `rust_parity_graylog_e2e.py`); `status/sidebar` and `POST /healthcheck/logs` once the connectors they read are ported | largest surface; each is independent |
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
5. Extend the e2e suite and the parity harness — a new module gets its own
   `crates/copilot/tests/e2e_<module>.rs` (`mod common;`) and
   `backend/tests/e2e/rust_parity_<module>_e2e.py`; every intentional
   difference goes in §4 with a test.
6. Background work: hand over through `scheduled_job_metadata`, never run in
   both services.
