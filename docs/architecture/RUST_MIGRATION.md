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
                       │ /api/customer_portal/* (but /sla)                  │
                       │                     copilot-customer-portal        │
                       │ /api/customers/*             copilot-customers     │
                       │ /api/healthcheck/*           copilot-healthchecks  │
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
| `copilot-customer-portal` | `app/customer_portal/` (routes, services, schema, `utils/validators.py`) but `sla` (`copilot-soc-management`'s); Starlette's `Response` through `GZipMiddleware` for a one-message body, Pydantic's lax `bool` and query `int`, CPython's strict base64 (`binascii.a2b_base64(strict_mode=True)`, in `copilot_auth::pybase64`) and `csv.writer` | `/api/customer_portal/*`: the AI reports (6 routes), the global settings (`POST`/`PATCH`/`GET /settings`, `/settings/global`, `/settings/logo`), the branding overrides and what a user resolves to (`/branding*`, `/settings/effective`, `/settings/effective/logo`), the Overview and the dashboard counters, the agents page and its CSV, `/me`; a per-process branding cache checked against the tables (`BRANDING_CACHE_CHECK_SECONDS`); `portal_vectors.json` (`scripts/gen-customer-portal-vectors.py`) |
| `copilot-customers` | `app/customers/` (`routes/customers.py`, `schema/customers.py`), `mssp_license_check` | `/api/customers/*` (13 routes): the reads, and — admin only — creating (the MSSP seat check through `copilot-license`), updating and deleting customers (the ORM's flush: agents and the meta row unlinked first) and the deprecated meta create, update and delete; database only, as in Python |
| `copilot-incidents` | `app/incidents/` (`routes/db_operations.py` and its services, `services/case_events.py`, `customer_reply.py`, `status_cascade.py`, the template half of `case_tasks.py`, `notification_enrichment.py`, `middleware/tag_access.py`'s single-alert rule, `services/verdict_stats.py`), the incident builders of `notifications/services/event_builders.py` | `/api/incidents/db_operations`: every `GET` (35) and the writes — alert creation, status (one and bulk), verdict, verdict state, escalation, assignment (one and bulk), comments, contexts, assets, IoCs, tags, deletion (one, bulk, by title); case creation (from scratch, from an alert), links, comments, status with the alert cascade, escalation, severity, assignment, customer move; the AI-trigger and Shuffle rows; the field dictionaries; the case-task writes and the manual template apply. `/api/incidents/case_templates`: the template and template-task CRUD. `/api/incidents/tag_access`: settings, user and role tags, `/me`. `/api/incidents/alerts`: the Velociraptor Sigma exclusion rules (create with the link comment, list, read, edit, toggle, delete). `/api/incidents/report`: the CSV case exports. `/api/incidents/customer_reports`: the report list, the visibility switch, the download and the delete. The MinIO routes (case files, report templates, `DELETE /case/{id}`, the report download and delete) are the `datastore` module, on `copilot-objectstore`. `POST /case-report-template/default-template` uploads the default templates compiled in from `backend/app/incidents/templates/` (`datastore::default_templates`). The template library and `/case_templates/suggest` are `copilot-case-templates`'. Still Python: the DOCX/PDF case reports and the customer report generation (docxtpl, wkhtmltopdf); the rest of `/alerts` and the three Wazuh-indexer reads of `/db_operations` are `copilot-ingest`'s, `POST /case/notification` `copilot-shuffle`'s |
| `copilot-ingest` | `app/incidents/routes/incident_alert.py` but the exclusion CRUD, and its services (`services/incident_alert.py`, `alert_collection.py`, `threshold_alert.py`, `velo_sigma.py`'s ingest, draft and dry-run, `mdr_forwarder.py`, `config/threshold_index_mapping.py`), the schemas they validate (`schema/incident_alert.py`, `alert_collection.py`, `velo_sigma.py`, `active_response/schema/graylog.py`'s threshold notification), the Shuffle workflow execution of `connectors/shuffle/services/integrations.py`, the three indexer reads of `routes/db_operations.py` (`wazuh_indexer/utils/universal.py`), `schedulers/services/invoke_alert_creation.py` | `/api/incidents/alerts`: `/create/manual`, `/create/auto`, `/create/threshold` (`graylog` header), `/create/velo-sigma` (`velociraptor` header), `/alert/details`, `/alert/timeline`, `/index/names`, `/alerts/not-created`, the exclusion draft and dry-run; `/api/incidents/db_operations/available-source/{index}`, `/available-indices/{source}`, `/mappings/fields-assets-title-and-timefield`; the `invoke_alert_creation_collect` job; one Rust `extract_event_fields` and `_matches_exclusion` (`sigma::fields`, `sigma::matcher`) for the ingest, the draft and the dry-run; CPython's `datetime.fromisoformat`, `str` methods, `ipaddress` and `json.dumps(indent=2)` (`py.rs`, `py_vectors.json`) |
| `copilot-sla` | `app/soc_management/` (`domain/{lifecycle,policy,calendar,sla}.py`, `services/lifecycle.py`, `services/{policy,calendars}.py`, `retarget_open`), `app/incidents/services/alert_severity.py` | the SLA lifecycle recorder the incidents routes call (#1187): tracking rows opened with snapshotted targets, guarded write-once milestones, pause/resume on `PENDING_CUSTOMER`, re-targeting on case severity and link changes and on a policy or calendar save (`retarget.rs`); SLA evaluation and compliance (`evaluate.rs`); policy and calendar storage, stored rows read with Python's semantics; 24/7 and business-hours clocks (IANA zones via `chrono-tz`) |
| `copilot-soc-management` | `app/soc_management/` (`routes/`, `schema/`, `domain/{analytics,stats,periods,notices}.py`, `services/{datasets,metrics,policy,calendars,notifier}.py`), `app/customer_portal/{routes,services,schema}/sla.py`, the SLA builder of `notifications/services/event_builders.py` | `/api/soc_management/*` (11 of its 12 routes: dashboard, sources, attention, item clocks, policies and overrides, calendars; not the PDF `GET /report`); `/api/customer_portal/sla/*` (4 routes); the `notify_sla_transitions` job |
| `copilot-healthchecks` | `app/healthchecks/agents/` (routes, services, schema), `LogsQueryBuilder` | `/api/healthcheck/*` (5 routes); the classification is shared with the customer routes; `POST /logs` asks the Wazuh indexer through `copilot-wazuh` (`logs.rs`) |
| `copilot-platform` | `app/version/`, `app/audit/` (reads) | `GET /api/version/check` (PEP 440 compare; `COPILOT_VERSION_CHECK_URL` points it at a mirror), `GET /api/audit`, `/actions`, `/{id}` |
| `copilot-identity` | `app/auth/routes/auth.py`, `routes/totp.py`, `routes/customer_users.py`, `routes/sso.py`, `routes/passkey.py`, `routes/security_admin.py`, `services/totp.py`, `services/customer_assignment.py`, `services/sso.py`, `services/passkey.py`, `services/security_admin.py`, `services/temp_password_email.py`; the branding merge of `app/customer_portal/services/branding.py` and the palette of `customer_report_branding.py` | login (`/token`, `/token/customer-portal`, the deprecated JSON `/login`), `/refresh`, the six `/2fa/*` routes, user management (`/register`, `/users`, `/users/{id}`, `/reset-password`, `/reset-password/me`, `/delete/{id}`, `/users/{id}/role/by-name`, `/users/{id}/customers`, `/me/customers`), SSO (`/sso/*`: settings, allowlist, Azure, Google, Cloudflare Access), passkeys (`/passkey/*`), the admin Security tab (`/security/*`: users, SMTP status, 2FA reset, the temporary-password email's templates, preview and send over SMTP); the enrolment QR code, the 2FA brute-force counter |
| `copilot-webauthn` | `webauthn` (py_webauthn 2.8), `cbor2`, the origin helpers of `app/auth/services/passkey.py` | registration and assertion verification (attestation `none`, `packed`, `fido-u2f`; py_webauthn's default algorithms ES256, ES512, EdDSA, RS256/384/512, PS256/384/512), cbor2-exact CBOR, options JSON, the relying-party/origin rules |
| `copilot-notifications` | `app/notifications/` (routes, services, channels, schemas); `app/customer_portal/services/branding.py` merge (`build_effective_branding` in full, source and customer included: `copilot-customer-portal` calls it) and the report palette (moved here from `copilot-identity`, which re-exports them) | every notification route (customer and internal routes, Shuffle integrations, the dispatch log, channel catalog, Resend quota, named templates and preview, manual send, Talon's dispatch, `POST /notifications/events`); the dispatch pipeline and its log; the webhook, Teams, Resend and Shuffle providers; `DispatchingSink`, the in-process `NotificationSink` |
| `copilot-markdown` | `app/notifications/utils/markdown_html.py` (markdown-it-py 4.2 `gfm-like`, `html=False`; mdurl; CPython punycode) | Markdown → inline-styled HTML for emails, a line-by-line port pinned by `markdown_vectors.json` (`scripts/gen-markdown-vectors.py`; character tables by `gen-markdown-tables.py`) |
| `copilot-scheduler` | `app/schedulers/` (`scheduler.py`, `routes/scheduler.py`, `utils/universal.py:record_job_success`), `app/audit/services/retention.py` | the job runner (APScheduler's interval semantics on tokio: fixed grid, coalesce, one instance, 1 s misfire grace), the hand-over rule and run lock, `/api/scheduler/*` (reads from APScheduler's `apscheduler_jobs` store through a read-only pickle decoder pinned by `apscheduler_vectors.json`, `scripts/gen-apscheduler-vectors.py`; run/start/pause), `prune_audit_log`; the palace jobs register from `copilot-ai-analyst`; `copilot jobs` and `doctor` list each job's owner |
| `copilot-connectors` | `app/connectors/{routes,services,schema,utils,cache}.py` | `/api/connectors`: the list, one row with `history_logs`, the update (write, verification, `connector.update` audit) and `POST /verify/{id}`; the verifier registry tool crates plug into (`ConnectorVerifier`; today `Wazuh-Indexer` and `Wazuh-Manager` from `copilot-wazuh`, `Velociraptor` from `copilot-velociraptor`, `SOCFortress UBA` from `copilot-uba`) — a connector without a Rust verifier is updated and verified by Python; the YAML upload (`upload.rs`: werkzeug 3.1's `secure_filename`, the file in `COPILOT_BACKEND_DATA_DIR`, the verification in Rust or by Python's `POST /verify/{id}`, the whole request Python's when the directory is not writable here) |
| `copilot-wazuh` | `app/connectors/wazuh_indexer/` and `app/connectors/wazuh_manager/` (routes, services, schema, `utils/universal.py`), the elasticsearch7 7.10.1 and `requests` 2.33 clients | the Wazuh indexer: `/api/alerts` (9 routes), `/api/wazuh_indexer` (7), `/api/snapshots` (10, the schedule CRUD on `index_snapshot_schedules` included); the Wazuh manager: `/api/wazuh_manager` rules, rule files and the rule-file upload, groups and the group configuration, the six MITRE listings, the restart (15 routes; the rule switches, `/rule/exclude` and the Atomic Red Team routes are `copilot-wazuh-rules`', the two MITRE alert searches stay in Python); an elasticsearch7-exact HTTP client (`es.rs`: the sync client's own HTTP/1.1 exchange with urllib3's headers — no `Accept`, `Accept-Encoding: identity` — in `urllib3.rs`, the async client's aiohttp headers and gzip/deflate decoding), `requests`' URL preparation and texts (`requests.rs`, `requests_vectors.json`), Pydantic-exact response models for upstream data (`pymodel.rs`), Python's dict/list/str semantics on upstream JSON (`pyops.rs`); CPython's `json` error texts and urllib3's object address are `copilot-upstream`'s; the `invoke_snapshot_schedules` and `resize_wazuh_index_fields` jobs; the connector verifiers |
| `copilot-case-templates` | `app/incidents/services/{template_library,template_suggestions}.py`, the library and `/suggest` routes of `routes/case_templates.py`, httpx 0.28 for GitHub | `/api/incidents/case_templates/library*` (4 routes) and `/suggest`, merged into `copilot-incidents`' router: the library cache per process (`library.rs`), the normalisation and the Pydantic models over YAML values, the import through `create_template`; the scorer (`suggest.rs`) and Python's `re`/`str` on its texts (`text.rs`); vectors `case_templates_vectors.json` (`scripts/gen-case-templates-vectors.py`) |
| `copilot-wazuh-rules` | `app/connectors/wazuh_manager/routes/{rules,mitre}.py`'s `/rule/*` and Atomic Red Team routes and their services (`process_rule`, `set_rule_level`, `convert_to_xml`, `post_to_copilot_ai_module`, `AtomicRedTeamService`), `models/rules.py` (`disabledrule`), xmltodict 1.0.4's `unparse`, aiohttp 3.13 / yarl 1.23 for a `GET` | `/api/wazuh_manager/rule/{disabled,disable,enable,exclude}`, `/api/wazuh_manager/mitre/atomic-tests`, `/api/wazuh_manager/mitre/techniques/{id}/atomic-tests` (6 routes): the rule switches through `copilot-wazuh`'s manager client (the file's JSON edited, written back as XML — `xmltodict.rs` —, the manager restarted, the `disabledrule` row), the AI module's exclusion over `copilot_threat_intel::httpx`, the listings from GitHub (`aiohttp.rs`: yarl's URL requoting, aiohttp's headers, retry and texts) with Python's per-process 24 h caches; vectors `wazuh_rules_vectors.json` (`scripts/gen-wazuh-rules-vectors.py`) |
| `copilot-upstream` | what the connector helpers did with a tool's answers: `requests`/`niquests` (`PreparedRequest`, urllib3's URL parsing and error texts), CPython's `json` (`dumps`, `JSONDecodeError`), Pydantic models, FastAPI's `serialize_json` | shared by the connector crates: a `requests`-like client (`http.rs`), a Pydantic engine (`model.rs`: lax coercion, smart unions, aliases, defaults, validators, `str` and `int` enums, `ValidationError` text, JSON-mode dumps; `model_vectors.json` pins 905 probes, `scripts/gen-connector-model-vectors.py`), Python exceptions as values (`py.rs`: `KeyError`, `TypeError`, … and what the handlers make of them), pydantic-core's JSON writer and FastAPI's 422 (`respond.rs`) |
| `copilot-objectstore` | `app/data_store/` (`data_store_session.py`, `data_store_operations.py`, `data_store_routes.py`), miniopy-async 1.23.5 (`Minio`, `signer.py`, `helpers.py`'s `BaseURL`, `error.py`) over aiohttp 3.13 and `aiohttp_retry`, Starlette's `StreamingResponse` and `GZipMiddleware` | the S3 client (`client.rs`: requests, region discovery, retries, multipart, ListObjectsV2; `sigv4.rs`; `endpoint.rs`; `xml.rs`, the ElementTree subset it reads answers with; `error.rs`, the library's exceptions and texts), `create_session()` from Python's variables (`store.rs`), the data-store operations line by line (`ops.rs`), multipart bodies read before the guard, downloads and path decoding (`web.rs`); `/api/agent_data_store` (5 routes) |
| `copilot-graylog` | `app/connectors/graylog/` (routes, services, schema, `utils/universal.py`, `utils/routing.py`), `app/connectors/event_shipper/` and `app/integrations/utils/event_shipper.py` (GELF over TCP) | `/api/graylog/*` (21 routes); `GraylogClient` for later ports: the four helpers with Python's error behaviour, the 6.x/7.x version probe and `EntityKind` (the four wrapped creation endpoints), the URL allowlist fallback; the services on either connector (`event_definitions_on`); the Event Shipper (`gelf.rs`: asyncgelf's frame, the port as asyncio resolves it) |
| `copilot-influxdb` | `app/connectors/influxdb/` (routes, services, schema, `utils/universal.py`), the Flux side of `influxdb_client` 1.50 (`InfluxDBClientAsync` over aiohttp, `FluxCsvParser`) | `/api/influxdb/*` (10 routes: alerts, check names, hosts, seven metrics views); `InfluxClient` for later ports: Flux queries with the library's request, timeout and error texts, the v2 REST helpers (`_influxdb_request`, the org-id lookup) for the checks provisioning |
| `copilot-grafana` | `app/connectors/grafana/` (`routes/reporting.py` but `/generate-report`, `routes/user.py`, `services/reporting.py`'s reads, `services/user.py`, `schema/reporting.py`, `schema/user.py`, `utils/universal.py`), `grafana_client` 5.1 (`GrafanaApi.from_url`, `GrafanaClient` over niquests) | `/api/reporting/orgs`, `/dashboards/{org_id}`, `/dashboard/{uid}`, `/dashboard_panels/{uid}`, `POST /generate_iframe_links`, `POST /api/user/user/organization/add`; `GrafanaClient` for later ports (organizations, the org switch, search, dashboards, folders). Still Python: `POST /api/reporting/generate-report` (Playwright, the licence check); `POST /api/grafana/dashboards` is `copilot-grafana-dashboards`' |
| `copilot-grafana-dashboards` | `app/connectors/grafana/` (`routes/dashboards.py`, `services/dashboards.py`, `schema/dashboards.py`, the templates under `dashboards/`), `POST /customer_provisioning/provision/dashboards` and `ProvisionDashboardRequest` | `POST /api/grafana/dashboards`, `POST /api/customer_provisioning/provision/dashboards`; `provision_dashboards` for the Rust provisioning flows; the 70 dashboard templates compiled in from the backend's own tree (`build.rs`, no copy), the dashboard enums, `load_dashboard_json`'s two edits; pinned by `grafana_dashboard_vectors.json` (`scripts/gen-grafana-dashboard-vectors.py`) |
| `copilot-integration-provisioning` | `app/stack_provisioning/graylog/{routes,services,schema}/{fortinet,sonicwall,sentinelone}.py`, `services/provision.py`'s network-connector content packs, `app/integrations/{huntress,darktrace,duo,cato,carbonblack,mimecast,sap_siem,socfortress_mdr}/` (`/provision`), `customer_provisioning/schema/{graylog,grafana}.py` and the index-set, stream, pipeline, datasource, folder and OpenSearch-version helpers of `customer_provisioning/services/{graylog,grafana}.py`, `connectors/graylog/services/collector.py`'s id lookups and `streams.assign_stream_to_index` | `POST /api/stack_provisioning/graylog/provision/{fortinet,sonicwall,sentinelone}` (one data table, `network.rs`); `POST /api/{huntress,darktrace,duo,cato,carbonblack,mimecast,sap_siem}/provision` (a second one, `integrations.rs`; the APScheduler jobs handed to Python's `POST /api/scheduler/provisioning_jobs`) and `POST /api/socfortress_mdr/provision`; the Graylog steps on a named connector (`graylog.rs`), the Grafana and indexer steps (`grafana.rs`); models, content-pack rendering, the integrations' index sets, streams, jobs and request bodies pinned by `integration_provisioning_vectors.json` (`scripts/gen-integration-provisioning-vectors.py`); `POST /api/{crowdstrike,defender_for_endpoint,bitdefender}/provision` (a third table, `collectors.rs`, from `app/integrations/{crowdstrike,defender_for_endpoint,bitdefender}/`: the Graylog and Grafana objects, the collectors' docker-compose and configuration files under `COPILOT_BACKEND_DATA_DIR` from the templates compiled in from `backend/`, Bitdefender's GravityZone push; pinned by `collector_vectors.json`, `scripts/gen-remaining-provisioning-vectors.py`); `POST /api/customer_provisioning/provision`, `/provision/wazuh_worker` and `POST /api/portainer/create-wazuh-customer-stack` (`customer/`, from `app/customer_provisioning/{routes,services,schema}/provision.py`, `services/{wazuh_manager,grafana}.py`'s provisioning half, `schema/{wazuh_worker,grafana}.py`, `connectors/portainer/services/stack.py`'s creation: the tools verified, Graylog, the Wazuh groups, the Grafana organization, datasource, folder and dashboards, the rows, the worker, HAProxy and the Portainer stack; the agent-group and stack templates compiled in from `backend/`; pinned by `customer_vectors.json`). Office365 and AWS are `copilot-cloud-provisioning`'s |
| `copilot-portainer` | `app/connectors/portainer/` (routes, services, schema, `utils/universal.py`) | `/api/portainer/node-details`, `/stacks`, `/stack-details`, `/get-customer-stack-id`, `POST /start-wazuh-customer-stack`, `/stop-…`, `/update-customer-stack-id`, `DELETE /delete-wazuh-customer-stack`; `PortainerClient` (the JWT login and the GET/POST/DELETE helpers), `swarm_id` and `create_stack` for the stack creation, whose route (`POST /create-wazuh-customer-stack`) is `copilot-integration-provisioning`'s, with the customer provisioning schema and template |
| `copilot-waf` | `app/customer_waf/` (routes, services, schema, `utils/universal.py`), CPython 3.11's `ipaddress`, OpenSSL's CA loading (`ssl.create_default_context(cadata=…)`) | `/api/customer_waf/*` (16 routes: instances, the connection check, sites / events / stats / threat intel, IP blocks, event forwarding into Graylog with rollback); the two WAF monitoring alerts `SOCFORTRESS_WAF_BLOCKED` / `SOCFORTRESS_WAF_BRUTE_FORCE` (`alerts.rs`, called by `copilot-monitoring-alerts`); an httpx-shaped WAF client (`client.rs`), `ipaddress` (`ip.rs`) and the CA check (`pem.rs`) pinned by `waf_vectors.json` (`scripts/gen-waf-vectors.py`) |
| `copilot-monitoring-alerts` | `app/integrations/monitoring_alert/` (`routes/provision.py`, `schema/provision.py`, `services/provision.py`), `app/connectors/graylog/services/management.get_system_info`, `app/stack_provisioning/graylog/services/utils.get_graylog_version`, `app/integrations/utils/event_shipper.py` | `/api/monitoring_alert/*` (4 routes: the catalog, `POST /provision` for every alert — the 49 event-definition functions as one data table (`catalog.rs`), the two WAF alerts through `copilot-waf` —, `/provision/custom`, `/provision/testing` to the Event Shipper); request bodies with CPython's `json` values (`body.rs`); every body, both request models, the custom alert and the GELF frame pinned by `monitoring_alert_vectors.json` (`scripts/gen-monitoring-alert-vectors.py`) |
| `copilot-provisioning` | `app/stack_provisioning/` (`graylog/` and `influxdb/` routes, schema, services and templates), the Graylog connector's `content_packs.py`, `management.get_system_info` and pipeline-rule services, the InfluxDB v2 REST helpers of `app/connectors/influxdb/utils/universal.py`, `customer_provisioning/services/{graylog,grafana}.py`'s content-pack and Grafana deletes | `GET /api/stack_provisioning/graylog/available/content_packs`, `POST …/graylog/provision/content_pack`, `/api/stack_provisioning/influxdb/*` (the four checks), `/api/stack_decommissioning/*` (an InfluxDB check, a network connector); the templates compiled in (`templates/`, pinned to the backend's files by a test); models, enums and rendering pinned by `provisioning_vectors.json` (`scripts/gen-provisioning-vectors.py`); and of `app/customer_provisioning/` the default settings, `GET /provision/dashboards`, `/provision/subscriptions`, `/provision/{customer_code}`, `PUT /update/office365_org_id/{customer_code}`, `GET /edr_install_commands/{customer_code}` and `POST /decommission` (`customer/`). `POST /provision/dashboards` is `copilot-grafana-dashboards`', `POST /provision` and `/provision/wazuh_worker` and the network-connector provisioning `copilot-integration-provisioning`'s (on the content packs here) |
| `copilot-velociraptor` | `app/connectors/velociraptor/` (`routes/{artifacts,flows}.py`, `services/{artifacts,flows}.py` with the two MinIO collections, `schema/`, `utils/universal.py`: `UniversalService` — `create_vql_request`, `execute_query`, `watch_flow_completion`, `read_collection_results`, `get_server_version`, the connection check —, `utils/validation.py`), pyvelociraptor 0.1 (`LoadConfigFile`, `api_pb2`), grpcio's secure channel | `/api/artifacts` (9 routes: the definitions, by OS, by name, a parameter prefix, a host's artifacts, `POST /collect` and `/collect/file/agent/{agent_id}` — the flow's download pack read in base64 chunks, stored in MinIO through `copilot-objectstore` (`upload_agent_artifact_file`) and recorded in `agent_datastore`, `services/collections.rs` —, `/command`, `/quarantine`) and `/api/flows` (a host's flows, `/retrieve`). Velociraptor's API without Python: `VQLCollectorArgs`/`VQLResponse` encoded field by field as protobuf does (`proto.rs`), one server-streaming `proto.API/Query` over HTTP/2 and mutual TLS (`grpc.rs`: the `VelociraptorServer` target name, BoringSSL's partial chain in `pinned.rs`, the deadline as grpc-core encodes `grpc-timeout`, grpc's 4 MiB receive limit, grpc-core's failure texts and `_MultiThreadedRendezvous`), `api.config.yaml` read as PyYAML reads it (`config.rs`, CPython's file and decode errors), the VQL identifier validators, the flow-wait allowance (`VELOCIRAPTOR_MAX_CONCURRENT_FLOW_WAITS`); the `Velociraptor` connector verifier; a gRPC stand-in for tests (`testing`) |
| `copilot-agents` | `app/agents/` (`routes/agents.py`, `services/`, `schema/agents.py`, `wazuh/services/{agents,vulnerabilities,sca}.py`, `velociraptor/services/agents.py`, `velociraptor/utils/matching.py`), `app/threat_intel/services/epss.py:collect_epss_scores`, `app/schedulers/services/agent_sync.py` | `/api/agents/*` (24 routes: lists, one agent, the Grafana dashboard list, cases by hostname, critical/non-critical, the Velociraptor id pin, vulnerabilities from the manager API or the 4.8+ indexer states, one CVE, SCA, both CSV exports with EPSS, the Wazuh upgrade, the outdated-agent lists, deletion one by one, in bulk and by filter, the Wazuh + Velociraptor sync, the per-customer vulnerability sync to the Event Shipper); the `agent_sync` job; the single-CVE EPSS lookup of the vulnerability search (`EpssClient::score_for_cve`, httpx's request) |
| `copilot-agent-reports` | `app/agents/vulnerabilities/`, `app/agents/sca/` (with `models/sca_package_registry.py`) and `app/agents/wazuh/syscollector/` (routes, services, schema), `app/threat_intel/services/epss.py:{invoke_epss_api,collect_epss_score}`, `data_store_operations.py:{store_file_in_minio,retrieve_file_from_minio,delete_file_from_minio}`, httpx 0.28 (GitHub) | `/api/vulnerabilities` (13 routes: the indexer sync into `agent_vulnerabilities` — all agents, one customer, one host; batch and bulk mode —, the deletion by filter, one agent's rows, statistics, the indexer search with EPSS, the CSV reports in MinIO inline or in the background, their list, download and delete), `/api/sca` (12: the overview from the manager and its SSE stream, statistics, the CSV reports, the CoPilot-SCA policies on GitHub, the package registry and its indexer lookup), `/api/syscollector` (2: an agent's packages, the indexer package search); an httpx-shaped client (`httpx.rs`: httpx's headers, `raise_for_status` and error texts); `COPILOT_SCA_REPO_URL` for the parity harness |
| `copilot-cloud-provisioning` | `app/integrations/office365/` (`routes/provision.py`, `schema/provision.py`, `services/provision.py`: the `ossec.conf` edits, the pipeline rules and pipeline, the index set, stream, datasource, folder and dashboards, `_ProvisioningRollback`), xml.dom.minidom's `toprettyxml`; `app/integrations/aws/` (`routes/provision.py`, `schema/provision.py`, `services/{provision,validate}.py`, `services/wazuh_manager.py`'s log watch), botocore 1.43.6's STS and S3 calls | `POST /api/office365/provision`: the tenant's `<api_auth>` block (a new `<office365>` block, or appended to the existing one), the manager restart, the six pipeline rules (the UTC rule repaired) and the pipeline, the per-customer index set and Grafana objects reused for a further tenant, the per-tenant stream, the meta row, `deployed` and the legacy tenant column, every externally-visible step undone newest-first on a failure (`rollback.rs`); `POST /api/aws/provision`: the keys, the account's ownership, the credentials checked against AWS (`aws/boto.rs`, `aws/validate.rs`), the instance's buckets reconciled on the manager, the rules and pipeline, per service the index set, stream and datasource, the folder, the meta row and `deployed`, rolled back the same way, the exit-23 watch (`aws/notice.rs`); the edits and rule sources pinned by `cloud_provisioning_vectors.json`, botocore's requests and readings, the validation, the wodle reconcile, the keys and the rules by `aws_vectors.json` (both `scripts/gen-remaining-provisioning-vectors.py`) |
| `copilot-integrations` | `app/integrations/routes.py` (but `/modules/*`, `copilot-integration-modules`; the multi-instance helpers, `_cleanup_integration_infrastructure`), `app/integrations/office365/services/{decommission,tenant_lookup}.py`, `app/integrations/aws/services/account_lookup.py`, `app/integrations/alert_creation_settings/`, `app/network_connectors/` (routes, schema, models), `xml.etree.ElementTree` (CPython 3.11) | `/api/integrations/*` (14 routes: the catalog, customer integrations and their metadata, create, update, delete with the decommission, the auth-key lookup, `meta_auto`, `update_meta_auto`), `/api/api/v1/alert_settings/*` (6), `/api/network_connectors/*` (12); an ElementTree subset for `ossec.conf` (`etree.rs`, pinned with the decommission's edit by `etree_vectors.json`, `scripts/gen-integrations-vectors.py`; expat's refusals — its texts and positions —, the comment-keeping parser, `tostring`'s ASCII charrefs, `ET.indent` and C14N 2.0's comparison by `etree_expat_vectors.json`, `scripts/gen-remaining-provisioning-vectors.py`, and expat 2.6's refusal texts, lines and columns by `expat_vectors.json` (`scripts/gen-expat-vectors.py`)); SQLModel table models as request bodies (`table_model.rs`). The AWS integration's Wazuh side (`aws/`: `utils/services.py`, `services/wazuh_config.py`, `wazuh_manager.py`'s write path with its `WAZUH_CONFIG_LOCK`, `decommission.py`) serves the delete of a deployed AWS instance and AWS provisioning (`copilot-cloud-provisioning`). The integrations' provisioning is `copilot-integration-provisioning`'s (on `create_meta_validated`) and, for Office365 and AWS, `copilot-cloud-provisioning`'s (on the decommission, the instance helpers and `aws/` here) |
| `copilot-integration-modules` | `app/integrations/modules/` (routes, schema, services: Huntress, Mimecast, Duo, Cato, CarbonBlack, Darktrace, SAP SIEM), `app/integrations/mimecast/` (`routes/mimecast.py`, `services/mimecast.py`, `schema/mimecast.py`; not `/provision`), `app/integrations/utils/collection.py:send_post_request`, `app/schedulers/services/invoke_{huntress,duo,darktrace,carbonblack,mimecast,sap_siem}.py` | `/api/integrations/modules/{huntress,mimecast,duo,cato,sap_siem}` and the seven SAP SIEM analyses, `POST /api/mimecast/invoke` and `/ttp/urls`, `GET /api/carbonblack/test` (the CarbonBlack job run as Python's route runs its guarded function): the customer's keys through `copilot-integrations`' statements, the payload models, the Graylog host and port from the connector rows (by name or by Python's fixed ids), the licence, one httpx 0.28 POST to the module container (`copilot_threat_intel::httpx`; `COPILOT_INTEGRATION_MODULES_URL` points every one at a stand-in — tests only); 16 hand-over jobs (`jobs.rs`: every `invoke_*` collection but Cato's), which answer a manual run with what the Python function returns (`JobSpec::returning`); `integration_modules_vectors.json` (`scripts/gen-integration-modules-vectors.py`: the models, `set_time_bounds` and the `time_range` pattern, `base64.b64decode`, `HttpUrl`). Still Python: Mimecast's and SAP SIEM's provisioning (`/provision`, `/invoke/scheduler/{siem,ttp}`: they add APScheduler jobs), the Cato job |
| `copilot-siem` | `app/siem/` (routes, services, schema, `dashboard_templates/`), `AlertsQueryBuilder`'s time window (`wazuh_indexer/utils/universal.py`), the AsyncElasticsearch 7.10.1 calls of `services/{dashboards,events}.py`, `fnmatch.fnmatchcase` | `/api/siem/dashboards/*` (15 routes: the built-in templates by category, the enabled dashboards, enable / disable, the custom-template CRUD with import, export and the builder's preview, panel data), `/api/siem/event_sources/*` (4), `/api/siem/events/*` (3: the search with its scroll, one document, the field names); `execute_panels`, the one panel executor panel data and the preview share (the `.keyword` and unsorted fallbacks, every panel's failure as its `error`); the built-in templates compiled in (`templates/`, pinned to the backend's files by a test) |
| `copilot-threat-intel` | `app/threat_intel/` (`routes/{epss,socfortress}.py`, `services/`, `schema/`), of `app/integrations/copilot_mcp/` `MCPService.execute_query` (every server's: `copilot-mcp` calls it) and `query_mcp` for `cyber-news`, httpx 0.28's `AsyncClient` | `/api/threat_intel/*` (11 routes: `POST /epss`, `/socfortress`, `/process_name`, `/virustotal`, `/virustotal/file/submit`, `/virustotal/file/analyze`, `GET /virustotal/analysis/{id}`, `/virustotal/file/{id}`, `POST /ai/analyze-alert`, `/ai/wazuh-exclusion-rule`, `/ai/velociraptor-artifact-recommendation`); an httpx-shaped client (`httpx.rs`: URL handling, default headers, multipart, exception texts) and the licence check through `copilot-license` |
| `copilot-response` | `app/active_response/` (`routes/active_response.py`, `routes/graylog.py`, `routes/sysmon_config.py`, `services/sysmon_config.py`, `schema/`), the Sysmon half of `app/data_store/data_store_operations.py`, aiohttp 3.13's `FormData` POST, `app/integrations/copilot_action/` (routes, `CopilotActionService` over httpx 0.28, schema) with the `run_artifact_collection` / `fetch_file_from_filestore` / `upload_agent_artifact_file` chain its invoke runs | `/api/active_response/*` (4 routes: the supported responses, by agent, a script's description, the Wazuh invoke with its body-field tenancy), the Graylog webhook `POST /api/graylog/invoke`, `/api/sysmon_config` (list, content, download, deploy, the upload with `validate_sysmon_config` on `copilot-integrations`' expat-exact parser), `/api/copilot_action/*` (the inventory, its count, one action, the metrics, the technologies, the invoke); `InvokeActiveResponseRequest`'s `create_alert` validator (#960) as Pydantic runs it; the provisioning worker's aiohttp client (`sysmon/worker.rs`); the CoPilot Action service's httpx client (`copilot_action/client.rs`) |
| `copilot-shuffle` | `app/connectors/shuffle/` (`routes`, `services`, `schema` of workflows, integrations, organizations and Singul; `utils/universal.py`'s `requests` helpers and `verify_shuffle_credentials`), the case notification of `app/incidents/routes/db_operations.py` with `services/incident_case.py` and `increment_case_notification_count` | `/api/workflows` (the list, the executions, an execution and its results), `/api/shuffle/integrations/*` (credentials, execute, invoke-workflow), `/api/shuffle/organizations/organizations*`, `/api/shuffle/singul/execute`, `POST /api/incidents/db_operations/case/notification`; the `Shuffle` connector's verifier; Pydantic's `UUID4` with pydantic-core 2.46's `uuid` messages (`uuid4.rs`) |
| `copilot-intel-connectors` | `app/connectors/opencti/` (routes, schema, `services/opencti.py`, `services/queries.py`, `utils/universal.py`), `app/connectors/cortex/` (routes, schema, services, `utils/universal.py`), cortex4py 2.1 (`Api`, the analyzer and job controllers, `Analyzer`/`Job`) | `/api/opencti/*` (6 routes: availability, about, the one-IOC search, the batch lookup, indicators, entities) over the GraphQL transport (`send_graphql_request`, `paginate_graphql`; httpx through `copilot_threat_intel::httpx`), `/api/analyzers` (the list, `POST /run` with the job polling) over cortex4py's requests (`PyHttp::with_exact_headers`); the `OpenCTI` and `Cortex` connector verifiers; `intel_vectors.json` (`scripts/gen-intel-connectors-vectors.py`). Sublime (`/api/sublime`) is `copilot-sublime` |
| `copilot-uba` | `app/connectors/uba/` (`routes/uba.py`, `schema/uba.py`, `schema/provision.py`, `services/uba.py`, `services/incident_verdict.py`, `services/provision.py`, `services/rollback.py`, `services/ownership.py`, `utils/universal.py`), httpx 0.28's `AsyncClient` (through `copilot-threat-intel`'s `httpx`), `str.format` (`pyfmt.rs`) | `/api/uba/*`: availability, status, entities, risk history, timeline, signals and evidence, alerts, the verdict and its write-back onto the linked incident alert (#1239, through `copilot-incidents`' verdict update, audited, on the SLA clock), suppressions, identities (review, search, merge, reviewed, candidate dismissal), identity sources (list, test, sync), about, the rule catalog, stats and settings, the risk policy, native-rule scores, backtests; setup (Graylog through `copilot-graylog`'s `GraylogClient`, 6.x and 7.x, the Wazuh rules through `copilot-wazuh`, `uba_provisioned_resource`), the mode, the rollback (#1241: plan, steps, checks, `uba_rollback`), each behind `ops.rs`'s traits so Python's own fixtures pin the plan and the step order; the `SOCFortress UBA` connector verifier; the routes' parameters as FastAPI validates them (`params.rs`), pinned with httpx's query encoding and `str.format` by `uba_vectors.json` (`scripts/gen-uba-vectors.py`) |
| `copilot-yaml` | PyYAML 6.0.3's pure-Python `yaml.safe_load` (`reader`, `scanner`, `parser`, `composer`, `resolver`, `SafeConstructor`, `YAMLError`) | the loader every catalog rule goes through: Python's values (dates, unbounded ints, YAML 1.1 bools, merge keys, `!!set`/`!!omap`/`!!binary`), their `repr()`/`str()`/`==` and pydantic's JSON, PyYAML's first error with its text; pinned by `yaml_vectors.json` (`scripts/gen-yaml-vectors.py`) |
| `copilot-searches` | `app/integrations/copilot_searches/` (routes, schema, services: `copilot_searches.py`, `cache_support.py`, `mitre_coverage.py`, `wazuh_rules_cache.py`, `wazuh_firing_stats_cache.py`, `detection_catalog.py`, `rule_linter.py`, `backtest.py`, `graylog_search.py`, `publish.py`, `custom_repos.py`), `app/schedulers/services/refresh_{catalog_caches,wazuh_rules_cache}.py`, the monitoring-alert `provision_alert_definition` call it makes | `/api/copilot_searches/*` (38 routes: the rule lists and lookups, MITRE coverage, the rule search, the Graylog query and event-definition provisioning, the Detection Catalog views and logtest, the editor's validate / backtest / publish, the custom-repo pointers); the four caches as state of this process and its own refresher |
| `copilot-assessments` | `app/integrations/github_audit/` (`model.py`, routes, schema, `services/github_audit.py`), `app/integrations/nuclei/` (routes, schema, services), httpx 0.28's `AsyncClient` (through `copilot-threat-intel`'s `httpx`) | `/api/github-audit/*` (19 routes: configurations, the audit from a configuration, its summary and the ad-hoc audit, reports, check exclusions, baselines, the check catalog) on the four `github_audit_*` tables, the audit's GitHub calls and checks with Python's value semantics, the repositories ten at a time as `asyncio.gather` runs them; `/api/nuclei/*` (4 routes) to the `copilot-nuclei-module` container; both routed on the decoded path (`paths.rs`); pinned by `assessments_vectors.json` (`scripts/gen-assessments-vectors.py`) |
| `copilot-license` | `app/middleware/license.py` (the 12 routes of `license_router`, `get_license`, `is_feature_enabled` and the `license_cache` bookkeeping, `send_post_request` / `send_get_request`) | `/api/license/*` (12 routes) and the one licence check every Rust module calls (the threat-intel routes, the sidebar's licence indicator); the licence server over `copilot_upstream::http::PyHttp` (`requests`' header order) |
| `copilot-status` | `app/utils.py:logs_router`; `app/status/` with `schedulers/services/refresh_sidebar_{indicators,health}.py`; `app/performance/`, `app/middleware/performance.py`, `app/db/query_metrics.py` | `/api/logs/*` (6 routes); `GET /api/status/sidebar` (its deployment-wide indicators held and refreshed by the process, `refresher.rs`); `/api/performance/*` (6 routes) on the process's own request timer (`performance::middleware`, the outermost layer), runtime-lag watchdog and query metrics (`QueryMetricsLayer`, fed by sqlx's `sqlx::query` events) |
| `copilot-patch-tuesday` | `app/integrations/microsoft_patch_tuesday/` (routes, services, schema) | `/api/patch-tuesday/*` (6 routes: the full cycle, the summary, the cycles, the CVE search, by priority, the KEV items): MSRC's CVRF documents, FIRST's EPSS scores and CISA's KEV catalog fetched as `fetch_json` does over httpx 0.28 (`copilot_threat_intel::httpx`), Python's readers and prioritisation on whatever JSON came back; `patch_tuesday_vectors.json` (`scripts/gen-patch-tuesday-vectors.py`) |
| `copilot-mcp` | `app/integrations/copilot_mcp/` (routes, `services/copilot_mcp.py`, `services/example_questions.py`, schema) | `/api/copilot_mcp/*` (5 routes: the servers, one server, the example questions, their categories, `POST /query` to the local `copilot-mcp` container or SOCFortress's cloud behind the licence); the query is `copilot-threat-intel`'s `execute_query`, shared with `/threat_intel/process_name`; `mcp_vectors.json` (`scripts/gen-copilot-mcp-vectors.py`) |
| `copilot-sublime` | `app/connectors/sublime/` (routes, `services/alerts.py`, schema, the model, `utils/universal.py`'s `send_get_request` and `verify_sublime_credentials`) | `/api/sublime/*` (2 routes: the alert webhook `POST /alert` — the alert and its five kinds of child rows in the ORM's statements and order, the sender and first recipient read from Sublime's `GET /v0/messages/{id}` over `requests` (`PyHttp::with_exact_headers`), SQLAlchemy's and pymysql's failures — and the listing `GET /alerts` with `selectinload`'s statements and `SublimeAlertsSchema`); the `Sublime` connector verifier; on the tables Alembic `d6c01a2b3c4d` creates; `sublime_vectors.json` (`scripts/gen-sublime-vectors.py`) |
| `copilot-scoutsuite` | `app/integrations/scoutsuite/` (routes, `services/scoutsuite.py`, schema), `copilot.py`'s creation of `scoutsuite-report` | `/api/scoutsuite/*` (6 routes: the report options, the reports on disk and their delete, the AWS, Azure and GCP scans — the `scout` command line Python runs, in the same working directory (`COPILOT_SCOUTSUITE_DIR`), started after the answer; the GCP key in a `mkdtemp` directory removed after the scan); `json.loads(bytes)` is `copilot-patch-tuesday`'s; `scoutsuite_vectors.json` (`scripts/gen-scoutsuite-vectors.py`). The static `/scoutsuite-report` mount stays Python's (`copilot.py`; the frontend's nginx sends it to `copilot-backend`) |
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
but for the paths and methods it does not route: `/available-source/*`,
`/available-indices/*` and `/mappings/*` read the Wazuh indexer and are
`copilot-ingest`'s (below); `POST /case/notification` (Shuffle) is
`copilot-shuffle`'s (see **Shuffle** below). `POST
/case-report-template/default-template` uploads the templates shipped under
`backend/app/incidents/templates`, which the binary compiles in from the
backend's tree (`datastore::default_templates`; the Dockerfile copies the
directory, a test fails when the list differs from it): each name refused
with Python's 400 when a row holds it, then validated and uploaded with the
type `mimetypes` guesses (`.docx`, `.html`), the row written without one.
Python takes its directory's order, which the file system decides; Rust
takes name order (§4). The case files and report templates
(`/case/data-store/*` uploads, deletes and downloads, `/case-report-template*`,
`DELETE /case/{id}`) are `copilot-incidents`' `datastore` module over
`copilot-objectstore` (see **MinIO** below).
`copilot-incidents` also answers `/api/incidents/case_templates` (the
template CRUD; the library — fetched from GitHub into each process's own
cache — and `/suggest` are `copilot-case-templates`', whose router the
binary merges into this one, axum preferring their static paths to
`/{template_id}`) and `/api/incidents/tag_access`. A list sorted on a non-unique column
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

Of `/api/incidents/alerts`, `copilot-incidents` answers the Velociraptor
Sigma exclusion rules: their CRUD and toggle, each answering with the row as
the service's `refresh()` reads it back (`field_matches` in MySQL's JSON key
order; a `None` stored as JSON `null`, an edit writing only the attributes
whose value changed, compared with Python's `==`), and the `Exclusion rule
created from this alert: …` comment a rule created in context leaves on its
alert (best-effort, after the commit, through the comments service).

**Alert creation and ingest.** `copilot-ingest` answers the rest of
`/api/incidents/alerts` and the three indexer reads of `/db_operations`, on
`copilot-wazuh`'s elasticsearch7 client (the sync or the async client's
headers, as each Python service uses one; bodies in `JSONSerializer.dumps`'
exact text through `Es::perform_raw`, so a float in a replayed `group_by`
value reads `2.5e-05` on both sides). What a route validates is validated
with Pydantic's texts: the request models, `GenericAlertModel` and
`GenericSourceModel` over the indexer's document (numbers stringified,
declared fields first, then the extras, `KeyError`/`TypeError` texts in the
400 `Failed to collect alert details: …`), `CreatedAlertPayload`, the Graylog
threshold notification (a numeric datetime is a unix timestamp, as
pydantic-core reads it) and the Sigma event union, whose `Dict[str, Any]`
member always wins for an object: the event is parsed into `SysmonEvent`,
`DefenderEvent`, `PowerShellEvent` or `GenericEvent` by channel and provider
only afterwards, as `get_parsed_event` does. Creation keeps Python's order —
configured source, customer code (the six keys; the Office365 tenant and AWS
account owners through their integration auth keys, `DISTINCT` and refusing
an account two customers claim), `is_customer_code_valid`, the payload
(field dictionaries, the comma-separated asset fields, the time field's
fallbacks, `clean_alert_title`, rule level and severity, the IoC with its
composite-value rule) — then merges into an OPEN alert of the same title
(`update_alert_creation_time` from `fromisoformat`, else now; the document
write-back with its write-block retry; the asset and IoC only when new) or
creates it: the row and `SlaRecorder::alert_opened`, the context, the asset
(its agent by hostname), the IoC, the legacy Shuffle workflow and the MDR
forward (best-effort, `requests`'/httpx's bytes), the Talon trigger (gated by
`incident_management_ai_analyst_trigger_enabled`, on a task of its own, the
body `requests` sends), `alert_created` through `ctx.notifications`, and the
write-back for a document alert. A threshold alert resolves its event with
the replay query (`THRESHOLD_SOURCE_INDEX_MAPPING`, the built-ins, the
`<source>-*` fallback) and keeps it for its timeline. The Sigma ingest checks
the enabled exclusion rules in table order (`resolve_customer_code` through
the agents, failing closed to `None`; the statistics `UPDATE`), looks for the
Wazuh copy of the event (the last hour, `size=1`, `timeout=1m`), and creates
the alert from it with the `Velociraptor Sigma: <title> | <channel>` and
`Full Event Payload:` comments, or the fallback alert from the event itself
with its comment block and tags. The draft and dry-run read those comments
back with the same prefixes and run the same flattening and matcher — one
Rust definition each. Python's own oddities are kept where they show: a
Sigma alert that was created answers `success: false` (its response model
refuses the int id, and says so in `message`), `add_alert_tag_if_not_exists`
skips a tag text that exists anywhere, the fallback without a client id is
the `UnboundLocalError` text, `/alerts/not-created` is a 500 (its handler
returns a tuple), and one malformed Graylog event empties its whole batch.
`invoke_alert_creation_collect` is a hand-over job (`COPILOT_RS_JOBS`; the
function stamps `last_success` itself, a manual run included). The parity
suite (`rust_parity_ingest_e2e.py`) runs every write on twin customers and
compares the answers, the rows left behind and every request sent to the
indexer, Shuffle, the MDR server and Talon.

Of the reports, what reads and writes only the database is Rust: the CSV
case exports (`POST /api/incidents/report/generate-report-csv[/{customer}]`,
`csv.DictWriter`'s dialect — a field quoted for `,` `"` `\r` `\n`, quotes
doubled — over the cases and links in the ORM's load order, the file named
after the process's local time like `datetime.now()`) and, of
`/api/incidents/customer_reports`, the list (CoPilot and the portal: the
caller's customers narrowed by `customer_codes`, a portal user's own and
shared reports, `generated_at DESC` issued as SQLAlchemy's statement for the
same tie order, `filters_json` read with `json.loads`' grammar), the
portal-visibility switch and, over MinIO, the download (a portal user only a
shared report or their own, a report not `completed` the 409, a file MinIO
cannot give the bare 500 of the `RuntimeError`) and the delete (an admin or
the creator; a file MinIO cannot remove is logged, the row deleted all the
same). The case DOCX/PDF reports and customer report generation stay
Python: they render through docxtpl, the Jinja report templates and
wkhtmltopdf.

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
The dashboard, the policy and calendar editors, the portal's SLA page and
`notify_sla_transitions` are `copilot-soc-management`'s. Every figure comes
from one snapshot per request, loaded with SQLAlchemy's statement shapes (no
`ORDER BY` where Python has none, so MySQL's row order breaks a
`Counter.most_common` tie the same way), and is rendered with CPython's float
`repr`; periods stay in Python's `datetime` range (`OverflowError` a bare 500,
`year 10000 is out of range` the 400). A stored calendar or policy cell the API
never writes is read with Python's semantics (`dict()`, `iter()`,
`int()`, `date.fromisoformat`): a `ValueError` is the 400 with its text, a
`TypeError` a bare 500, and a write whose re-targeting reads it fails inside
its `try` (the route's 500). `apply_to_open` goes through `copilot_sla::retarget`,
the definition the recorder uses. The notifier claims a stamp with a guarded
`UPDATE` and sends only what it won, settles the at-risk stamp on a breach and
stamps a breach older than 24 h silently; its events are
`copilot_core::notify::sla_event`'s, emitted through `ctx.notifications`. The
SOC operations PDF (`GET /report`) and the customer report's SLA section
(`customer_sla_context`) stay in Python with the rest of the PDF reports:
matplotlib draws their charts and wkhtmltopdf renders them. The parity suite
`rust_parity_soc_e2e.py` seeds a month of history (a Rome business-hours
calendar across both DST changes, paused, breached, at-risk, reopened and
untracked items, a tag-restricted analyst), freezes Python's clock at the
instant Rust answered, and compares the writes on twin customers and the
notifier's stamps, deliveries and dispatch log.

**Customer Portal.** `copilot-customer-portal` answers every
`/api/customer_portal` route but the SLA page. Branding resolves through one
definition (`copilot_notifications::branding::resolve`, Python's
`build_effective_branding`) and is cached per process, as
`services/branding_cache.py` caches it: every write route forgets the
process's entries after its commit, the TTL (`BRANDING_CACHE_TTL_SECONDS`,
600 s) is a backstop. With both backends running neither can reach the
other's cache, so each **checks**: before serving a cached entry, a process
whose last check began more than `BRANDING_CACHE_CHECK_SECONDS` (5 s) ago
reads the two tables' fingerprint — one statement, the same text in both:
every row's id, customer, switch, title, MIME type, colour, save time and the
logo's length and CRC-32, computed by MySQL — and drops every entry when it
changed; a load that began before entries were dropped is not stored. A save
through either backend (or in a MySQL shell) is served by the other within
the interval plus one query, Python's branded PDF reports included; the
check is Python's one coexistence change here. The cache is the only state
the Rust process keeps on its own; the global settings, the logos and the
override rows are read from MySQL on every request, as in Python. Logos and
the agents CSV leave as Starlette's `Response` through `GZipMiddleware`
(latin-1 headers, `; charset=utf-8` on `text/*`, `Vary: Accept-Encoding`
from 1000 bytes, gzip for images too). The Overview reads alert visibility
once and costs 11 statements for a portal user or an analyst, as Python
(budget 12, `customer_portal_overview_e2e.py`); an `"*"` in the requested
`customer_codes` reads as no filter, as Python reads its list. A path with
an encoded `/` is streamed to Python, since Starlette routes the decoded
path (the AI reports' routes included). The parity
suite `rust_parity_customer_portal_e2e.py` compares every route, the logo
and CSV bytes and headers, the rows of every write, both statement counts,
and the two caches' behaviour (writes through either backend, two writes in
one second, a MySQL edit).

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
failure. The SLA notifier (`notify_sla_transitions`) is a hand-over job (below).

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
twice), `notify_sla_transitions` (every 2 minutes, from `copilot-soc-management`),
`invoke_snapshot_schedules` (every 15 minutes: each enabled schedule's hour,
minute, weekday and interval gates, the write-index skip, the snapshot request,
the schedule row's `DEFERRED`/`SKIPPED`/`SUCCESS`/`FAILED` status) and
`resize_wazuh_index_fields` (every minute, while the `Wazuh-Indexer` connector
is verified), both from `copilot-wazuh`; the connectors parity suite runs each
on both sides against the indexer stand-in. The integrations' collection jobs
(`copilot-integration-modules`: Huntress, Duo, Darktrace, CarbonBlack, Mimecast
and its TTP job, the SAP SIEM collection and its nine analysis jobs) keep
their functions' semantics — which customer's failure fails the run, which
ones stamp `last_success` themselves (all but Huntress, a manual run
included), the window read from the row's `time_interval` or `extra_data` —
and a manual run answers `result` with what the function returned, as
`run_job_manually` does (`null` for the other jobs). `invoke_cato_integration_collect`
stays in APScheduler: `schedule_enabled_jobs` disables its row at every
Python start while APScheduler keeps running it, so a disabled row does not
mean "handed over" for that job. Run a single Rust instance with the opt-in.

**Connector cache.** Both backends cache `connectors` rows in-process and
neither can reach the other's cache, so each one *checks*: before serving a
cached row, a process whose last look at the table is older than
`CONNECTOR_CACHE_CHECK_SECONDS` (5 s, both sides) reads every row once (one
statement) and drops the cached rows that differ or are gone. A row is served
only if MySQL confirmed it — by its load or by a check — no earlier than the
last check began; a failed check drops everything. The guarantee: after a
committed write to `connectors` by either backend, the startup sync or by hand,
the writer forgets the row at once and every other process within 5 s plus one
query (`e2e_connectors.rs`, `test_connector_cache.py`, and the parity suite,
which rotates a row behind each process's back). While a legacy backend is
configured the Rust TTL stays capped at 60 s as a second bound.
`copilot-connectors` serves `GET /api/connectors` and `/{id}` (`history_logs`
read as `selectinload` reads them), `PUT /{id}` and `POST /verify/{id}`. An
update writes the row, answers with it as the ORM held it after the commit
(the old `connector_verified`, the fresh timestamp with its microseconds),
then verifies the connector and records `connector.update`, in Python's
order. Verification needs the tool's client, so a crate registers a
`ConnectorVerifier` under its connector names (`copilot-wazuh`: the indexer's
`cluster.health()`, the manager's authenticate call). A connector Python
verifies and no Rust crate does is handed to Python whole — after the same
404 and validation checks — and this process forgets its cached row when
Python has answered; without a legacy backend it is updated here and its
`connector_verified` left alone. The YAML upload (`upload.rs`) keeps
`upload_yaml_file`'s order: FastAPI's form and token, the identifier as
`int()` reads it (any `ValueError` makes it a name, and every failure of the
name lookup — no row, several, an id other than 5 or 6 — is the 404 Python's
`except Exception` re-wraps it into), the `.yaml` check, then
`save_file`: the file at `{COPILOT_BACKEND_DATA_DIR}/{secure_filename}`
(werkzeug 3.1's, POSIX), the row's `connector_configured` and path, the
cached row forgotten, then `verify_connector_by_id` — the Rust verifier, or
Python's `POST /api/connectors/verify/{id}` with the caller's
`Authorization` (Sublime), its answer unread as Python ignores it; any
failure of the write is the 500 `Failed to upload file`. The image runs as
uid 10001 and `docker-compose.rust.yml` mounts the backend's `data/`
read-only, so in that deployment the write is refused before anything is
written and the request is handed to Python whole; given the directory, Rust
writes it.

**Wazuh indexer.** `copilot-wazuh` answers the three indexer routers
(`/api/alerts`, `/api/wazuh_indexer`, `/api/snapshots`) and talks to the
indexer the way elasticsearch7 7.10.1 does: the same paths (`quote(safe=",*")`),
query strings, compact JSON bodies, `Basic` auth (latin-1, as urllib3), the
sync client's headers or `AsyncElasticsearch`'s (`Accept: */*`), ten immediate
retries on a connection error or a 502/503/504 and none on a timeout, and
`TransportError`'s classes and texts (`RequestError(400, '…', …)`,
`ConnectionError(<urllib3…>: Failed to establish a new connection: …)`), so
the 500 an analyst sees reads the same. Certificates are not verified, as
Python's `verify_certs=False` (indexers ship self-signed certificates). What
Python validates upstream answers with (`ClusterHealth`, `SnapshotStatus`, …)
is validated with the same models and error texts (`pymodel.rs`). The parity
suite (`rust_parity_connectors_e2e.py`) puts a recording stand-in in front of
both backends and compares, besides the responses, every request each one
sends. Tenancy: `/indices`, `/indices/size-per-customer` and the Graylog alert
routes narrow to the caller's customers as in Python; the other alert routes
(all, by host, by index, the three aggregations, by id), which in Python read
every tenant's indices, narrow the same way here — a scoped caller searches
only the indices named after one of their customers (`index_matches_customer`),
another tenant's index reads as unmanaged and another tenant's alert as
missing (§4). Shared indices that name no customer (`wazuh-alerts-*`) are
admins' only; scoping those would take a filter on `agent_labels_customer`.

**Wazuh manager.** `copilot-wazuh` answers the manager routes CoPilot's UI
uses (rules, rule files and their upload, groups and the group
configuration, the MITRE listings, the restart) as `requests` 2.33 does on
the wire: the URL through urllib3's `parse_url` and `requote_uri` (621
vectors), `str()` of each parameter (`True`/`False`), Basic auth in Latin-1
for the token, `Bearer` after, the helpers' dicts with their keys, order
and messages (`404 Client Error: Not Found for url: …`, urllib3's `Max
retries exceeded` sentence), and each service's Python semantics on odd
answers (`'list' object has no attribute 'get'`). Tokens live 10 minutes
less 30 s as in Python, but per connector row: a changed URL or credential
authenticates again at once, where Python, keyed by name, would send the old
host's token to the new one. Certificates are not verified, as Python's
`verify=False`; connections are pooled where `requests.get` opens one per
call (not observable on the wire). The rule switches (`/rule/disabled|
disable|enable`, whose `disabledrule` table Python never created), the
exclusion `/rule/exclude` and the Atomic Red Team routes are
`copilot-wazuh-rules`' (wave 6, §2 and §4); the two MITRE alert searches
are still Python. A request whose path carries an encoded `/` goes to Python
from every Wazuh router: Starlette routes the decoded path, axum would
not.

**Connectors (Graylog).** `copilot-graylog` answers every route of
`app/connectors/graylog/routes/`; `POST /api/graylog/invoke` (the
active-response webhook, another module) is `copilot-response`'s. A connector route is a call to the
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
(`socket.getfqdn()` as the host, `json.dumps` with `NaN` allowed); as in
asyncgelf, an unreachable shipper is not an error. The port is
`str(connector_extra_data)` as `asyncio.open_connection` reads it: `int()`
for an IP-literal host (outside 0–65535 the connect raises, nothing is sent),
for a host name glibc's `getaddrinfo` — `strtoul` (leading blanks and a sign,
the value cut to 16 bits by `htons`), else a service name from
`/etc/services`. `rust_parity_graylog_e2e.py` runs both backends against a
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

**Connectors (Grafana).** `copilot-grafana` answers the reporting reads, the
iframe links and adding a user to an organization. Python reaches Grafana
through `grafana_client` over niquests, which `copilot-upstream`'s client
reproduces as a second flavour (`Flavor::Niquests`: `json=` sent as
`application/json;charset=utf-8`, Basic credentials over UTF-8; both
libraries run on the urllib3-future the backend installs, so they fail with
the same texts). `create_grafana_client` is kept to the letter: the
credentials spliced into every `http://` of the URL (`None` printed as
`None`), `?verify=false` appended — so certificates are **not verified**, as
in Python, and a URL with a query of its own turns verification back on —
and `urlparse` reading it back (the API root is `{scheme}://{host}[:{port}]/
{path}api`, so `/grafana` gives `/grafanaapi`; an empty user name sends no
credentials). The answers are read as `_extract_from_response` does (`Server
Error N`, ``Bad Input: `…` ``, `Unauthorized`, `Client Error N`, `text/*`
as text, JSON otherwise), wrapped by each service (`Failed to collect …: …`)
and then validated by the route's response model, whose `ValidationError` is
the `ValueError` handler's 400 — as is the one `POST
/user/user/organization/add` raises after Grafana added the user (its
response model requires a `success` the route never passes: a 500, in both).
FastAPI validates request bodies with `from_attributes=True`, so a nested
model given a non-object is `model_attributes_type`
(`copilot_upstream::model::validate_body`). The iframe links count back from
`datetime.now()` in local time through `time.mktime`; `generate-report`
(Playwright) stays in Python; `POST /api/grafana/dashboards` is
`copilot-grafana-dashboards`' (below).

**Connectors (Portainer).** `copilot-portainer` answers every route of
`routes/portainer.py` but the stack creation, which
`copilot-integration-provisioning` answers with the customer provisioning
(below) on this crate's client. Each helper logs in first
(`POST urljoin(connector_url, "/api/auth")`, `raise_for_status` — its
`HTTPError` text, reason phrase and final URL included — then `["jwt"]`),
then sends the request with the JWT, TLS unverified as in Python; the
helpers keep their quirks: a GET's answer is data whatever its status, a
POST that fails in transit is the `UnboundLocalError` of its own `except`
clause (a bare 500), a DELETE with a blank body has succeeded. `int(Id)` of
the `local`/`primary` environment is CPython's (`ValueError` → 400). The
stack-id routes read and write `customersmeta` by customer name
(`scalar_one_or_none`: two rows of one name are a 500). The `requests` and
`niquests` flavours of `copilot-upstream`'s client honour `HTTP(S)_PROXY` /
`NO_PROXY` as both libraries do (`trust_env`); aiohttp (InfluxDB) does not,
and neither does its port.

**Customer WAF.** `copilot-waf` answers every route of
`app/customer_waf/routes/customer_waf.py`, and provisions the two WAF
monitoring alerts for `POST /api/monitoring_alert/provision`
(`copilot-monitoring-alerts`, below). The WAF is called as httpx 0.28 calls it — base URL
plus `/api/v1/…`, `params=` encoded like `urlencode` (`True` as `true`),
`json=` as compact UTF-8 JSON, `Content-Length: 0` on a bodiless `POST`/`PUT`,
`Accept: application/json`, the decrypted token as a Bearer header, no
redirects followed, 15 s (30 s for rule and forwarder writes, 5 s for
`/health`) — and its failures are the module's own `{"detail", "reason",
"success": false}` `JSONResponse`s (no `log_entries` row): `token_rejected`,
`insufficient_role` (the WAF's `detail` quoted), `not_found` (404),
`upstream_error`, `bad_response`, `unreachable` (timeout, refused, or the
httpx class name of another transport failure), `tls_error`, `disabled`
(409). TLS is unverified unless the row says `verify_tls`; then only the
row's CA is trusted, else the bundled roots. Tokens are Fernet under
`WAF_TOKEN_ENCRYPTION_KEY` with no fallback (`token_crypto` 400 without a
usable key, 409 for a token the key cannot decrypt) and appear in no response
or log line. A CA upload is checked the way CPython's `_add_ca_certs` loads
it (no certificate, a broken one after a good one, non-ASCII text — a bare
500 — with OpenSSL's sentences and the `_ssl.c` lines of the CPython 3.11
build the backend runs). Blocks parse targets with a port of 3.11's
`ipaddress` (netmask and hostmask forms, IPv4-mapped addresses printed as
`::ffff:1.2.3.4`, zones, the `is_private` tables with their exceptions), and
read the WAF's rules with Python's dict and string semantics (a subscript's
`KeyError`, an `AttributeError` on a non-dict, all bare 500s; Pydantic's
`ValidationError` the 400). Forwarding sends Graylog what Python sends,
through `GraylogClient` (`create_entity` for the stream only), and unwinds
newest-first exactly where Python's `except (HTTPException, WafRequestError,
ForwardingError, KeyError, TypeError)` catches — anything else leaves what
was made, as in Python. The settings Python reads per call from
`os.environ` (`WAF_TOKEN_ENCRYPTION_KEY`, `WAF_SYSLOG_PORT_RANGE`,
`WAF_SYSLOG_DEFAULT_HOST`, `ALERT_FORWARDING_IP`, `GRAYLOG_API_HEADER_VALUE`)
are read once at startup (`CopilotConfig::provisioning`), which is the same
for a container. `rust_parity_provisioning_e2e.py` runs both backends
against a WAF stand-in over HTTP and over HTTPS with a certificate from a
test CA, and a Graylog stand-in with a 6.x and a 7.x personality.

**Monitoring alerts.** `copilot-monitoring-alerts` answers the four routes
of `app/integrations/monitoring_alert/routes/provision.py`. `GET /available`
lists `AvailableMonitoringAlerts` (51 members, declaration order).
`POST /provision` validates `ProvisionMonitoringAlertRequest` as FastAPI does
— its validators raise `HTTPException`, so a `0` window or interval (`Invalid
value: 0. …`) or an unknown name (`replace(" ", "_").upper()`, CPython's
`str.upper`, then `Invalid alert name: … Must be one of: …`) is a 400 that
ends validation, whatever else failed; negative windows pass —, then routes
every Graylog call of the request to one connector, as
`set_graylog_context` does: `Graylog`, or `Graylog-Network` for
`graylog_instance: "network"`, except the two WAF alerts
(`PINNED_TO_DEFAULT_GRAYLOG`). `check_if_event_definition_exists` reads every
page of the definitions and refuses (400) the name with spaces — not the
definition's title, which differs for 44 of the 49 (`PALOALTO_ALERT` creates
`PALO ALTO - HIGH SEVERITY EVENTS`). The 49 functions that create one event
definition differ only in data (`catalog.rs`); the body is built through the
`GraylogAlertProvision*` models (`model_dump` order, `seconds * 1000` of a
Python int of any size), `get_system_info`'s version is compared with `"5.2"`
as a string (below it — `5.1.9`, but also `10.0.0` — `event_limit` is deleted
from the config), and the definition goes through `create_entity`, wrapped
for Graylog 7. The WAF alerts are `copilot-waf`'s functions. `POST
/provision/custom` builds its definition from the request (title as given,
the check on it with spaces; never pinned) — `streams: null` passes the
request model and fails `GraylogAlertProvisionConfig` (the `ValueError`
handler's 400) after the existence check; `alert_priority` is a plain int
`Enum` (`2.0` and `true` select a member, `"2"` does not). `POST
/provision/testing` ships `EventShipperPayload(customer_code="00002",
integration="testing", version="1.0", **request).to_dict()` to the Event
Shipper (a body naming one of those three keys is Python's `TypeError`, a
bare 500). Bodies keep CPython's `json` values (integers of any size, `NaN`,
`Infinity`), since both are sent on as given; a lone surrogate escape becomes
U+FFFD, the one thing a Rust string cannot hold. No route is tenant-scoped,
as in Python: event definitions are deployment-wide configuration, and a
custom alert's `custom_fields` (its `CUSTOMER_CODE` included) are validated
and then not used. The only state is `copilot-graylog`'s: the connector cache
and the major version per connector (five minutes), the two caches the
Python process keeps too; no route writes either. `get_customer_meta` (with
the Office 365 and AWS owner lookups) is not ported: nothing calls it but a
comment. `rust_parity_monitoring_alert_e2e.py` runs both backends against a
Graylog stand-in with a 6.x personality on `Graylog` and a 7.x one on
`Graylog-Network`, and a GELF input, and compares every request, header,
frame and `log_entries` row.

**Stack provisioning.** `copilot-provisioning` answers the content-pack
listing and provisioning, the InfluxDB checks and both decommissioning
routes; the three network-connector provisioning routes are
`copilot-integration-provisioning`'s (below), on the content packs and the
connector-aware insert and install here. The request models'
custom `__init__`s run before any field is validated: the enum lookup is
the 400 (`Content pack None is not available…` for a missing name, the
`str()` of any hashable value), an unhashable name the `TypeError` of
`Enum.__getitem__` (a bare 500), a non-string truthy network connector the
`AttributeError` of `.upper()`; the fields are then validated inside
`__init__`, so a nested `keywords` is `model_type`. Content packs follow
Python's `try` blocks statement by statement (`get_content_packs` wraps
everything, the GET's own `HTTPException` as `"{status}: {detail}"`;
`insert_content_pack` lets Graylog's "already found" pass only for a
`PROCESSING_PIPELINE` pack; `install_content_pack` wraps every failure) and
install through `send_post_request_create_entity`'s 6.x/7.x rule; the
version check is `packaging` (`copilot_platform::pep440`). The InfluxDB REST
helpers are httpx's — a client per call with `INFLUXDB_VERIFY_SSL` read each
time, `Authorization: Token …`, httpx's `User-Agent`, `Accept-Encoding` and
query encoding, `Failed to reach InfluxDB: …` / `InfluxDB request failed
({status}): …` — and the checks are rendered as Python renders them,
`json.dumps` of the template, `str.replace` of the placeholders, `json.loads`
(an org id that breaks the JSON fails with `json`'s own message, a non-string
one with `str.replace`'s `TypeError`). The templates are compiled in:
`crates/copilot-provisioning/templates/` are copies of the backend's files,
and a test fails when a copy differs (Python reads them from disk on every
call, so an edit to one must go to both). The parity suite's stand-ins are
one port for Graylog (`/graylog`), InfluxDB (`/influx`) and Grafana
(`/grafanaapi`), each with its own recorder.

**Customer provisioning.** `copilot-provisioning::customer` answers
`/api/customer_provisioning` but the provisioning `POST`s: `POST
/provision/dashboards` is `copilot-grafana-dashboards`', and `POST /provision`
and `/provision/wazuh_worker` are `copilot-integration-provisioning`'s (see
"Customer provisioning itself" below); it also answers `GET
/provision/wazuh_worker`, now a static path, as FastAPI routes it.
The default settings body is a SQLModel *table* model, which Pydantic does
not validate: any JSON object is accepted with its values' JSON types (a
one-item list is the scalar PyMySQL renders it as), the EDR repo fields
default to `None`, and MySQL refuses what does not fit (a bare 500); a created
row answers with the values as sent and the id MySQL gave last, an updated
one with the row re-read. Decommissioning keeps Python's order and failure
points: the Wazuh manager helpers never raise (agents that do not read are no
agents; an agent id that is not a string fails the answer's validation, after
the row is gone), a Graylog `DELETE` answered with an error is its 404, the
Grafana org id goes through `int()`, the organization delete is retried once
after switching to org 1, the worker and HAProxy calls are `requests.post`
(answers ignored; a URL `requests` refuses — no worker row is `None/…` — is a
`ValueError`'s 400, any other transport failure a bare 500), and on a
Portainer deployment the stack is stopped and deleted, its id cleared and
every swarm node's `:5003` called. The parity suite's decommissioning
stand-ins share the Graylog port by prefix (`/wazuh`, `/worker`, `/haproxy`,
Portainer at the root).

**Grafana dashboards.** `copilot-grafana-dashboards` answers `POST
/api/grafana/dashboards` and `POST /api/customer_provisioning/provision/dashboards`
and is the `provision_dashboards` the Rust provisioning flows call. The
templates have one source: `build.rs` embeds every JSON file of
`backend/app/connectors/grafana/dashboards/` from the backend's own tree (an
`include_str!` table with `cargo:rerun-if-changed` per file), so there is no
copy under `crates/`; the Rust image's `Dockerfile` copies that directory into
the build context (its `.dockerignore` allowlists it) and Rust CI runs on a
change to it. Python reads a template from disk on every call and Rust at
build time, so an edited template reaches Rust at its next build; phase 5
moves the directory under the crate. A unit test checks that every file is
embedded and that every enum member (`templates.rs`, in `valid_dashboards`'
order) maps to the file Python reads. The upload is Python's byte for byte —
the `json.load` values, the two edits (`replace_uid_value` on `"uid":
"replace_datasource_uid"`, `replace_grafana_url` on `url`s starting with
`https://grafana.company.local`, every occurrence replaced), and per dashboard
a fresh client, the organization switch and `POST /dashboards/db` with
`{"dashboard", "folderId", "overwrite": true}` as niquests writes `json=` —
pinned by the SHA-256 of every dashboard's bytes in
`grafana_dashboard_vectors.json`. Failures keep Python's double wrap
(`Error updating dashboard: 500: Error updating dashboard: …`; the dashboards
before the failing one stay uploaded) and Grafana's answer is validated
outside the `except` (`GrafanaDashboard(**answer)`: a `ValidationError` is the
400, a non-mapping the `TypeError`'s bare 500). Neither route is
tenant-scoped, as in Python and as the Grafana connector's other routes: the
body names a Grafana organization and folder, not a customer.
`rust_parity_grafana_provisioning_e2e.py` compares every request the Grafana
stand-in receives, headers and dashboard bytes included.

**Network connectors.** `copilot-integration-provisioning` answers the
Fortinet, SonicWall and SentinelOne stack provisioning, one data table over
shared steps, every Graylog call on `Graylog-Network` (the routes set
`GraylogContext.NETWORK`; the 7.x probe too). Python's order is kept and
nothing is rolled back. The request models' `mode="before"` validator
assigns `integration_name` into the input, so a body that is not an object —
a list, a string, a number, bytes sent without a JSON content type — is its
`TypeError`, a bare 500 (no body is the 422). Then the customer's network
connectors (404 `Customer integration settings not found.` without any), the
first holding the service (`None.network_connectors_subscriptions` is the
`AttributeError` when none does), its keys in dict order (404 without any),
Fortinet's protocol (400 for both or neither), the keys read in the details'
keyword order (TLS certificate and key before the port: a missing one is the
`KeyError`'s bare 500, a port `int()` refuses the `ValueError`'s 400), the
meta row's Grafana organization (404). The content packs are the
`AvailableContentPacks` members naming the connector, in declaration order,
the other protocol's input left out (SentinelOne names none: its template is
not a member, so it installs nothing and its stream and input must exist).
Each is skipped when a content pack named after the *customer* exists (a 400
unless that name holds `PROCESSING_PIPELINE`), else rendered as
`process_content_pack` renders it — `ReplaceContentPackKeywords`' dump
replaced key by key with `str.replace` in string values only (a customer
name holding another keyword is replaced again), two fresh `uuid4()`s per
pack, `convert_port_value_to_int` — inserted (Graylog's "already found" for a
processing pipeline skips the install) and installed. Then the stream the
pack made (`None` when there is none: the `PUT /api/streams/None` is
Graylog's 404), the index set (`<prefix>-<code>`, daily rotation, the body's
retention and replicas, one shard per indexer node — the cluster health
failing is `Exception`'s bare 500), the two packs' ids, the input, the
pipeline (a description that is `None` is the `AttributeError`), the stream
moved (`send_put_request`'s `success: false` is the 500 naming both ids) and
connected (`StreamConnectionToPipelineResponse(**answer)`: a 204 is the
model's 400), the OpenSearch datasource — on **connector id 1**, read three
times as Python's `get_connector_attribute(connector_id=1, …)`, so a missing
row is the datasource model's 400 after the indexer was asked its version —,
the folder, `provision_dashboards` with the meta's organization validated as
an `int`, the `customer_network_connectors_meta` row (a `NULL` in a `NOT
NULL` column is MySQL's refusal) and `deployed` on the first matching row.
One difference by design (§4): the body's `customer_code` must be one of the
caller's customers, checked after the body's validation. The parity suite's
Graylog stand-in is stateful (an install creates the pack's streams, inputs
and pipelines; index sets, moves and connections are kept and compared);
UUIDs are numbered by first appearance on each side and `creation_date`
masked.

**Integrations.** The same crate answers `POST /api/{huntress,darktrace,
duo,cato,carbonblack,mimecast,sap_siem}/provision` (a second data table) and
`POST /api/socfortress_mdr/provision`, on the default `Graylog`. The request
models force `integration_name` as the network ones do (a non-object body is
the `TypeError`'s bare 500); `time_interval` is required, defaults to 15
(Darktrace, Duo) or is absent (Mimecast). In Python's order: the customer's
integrations (404 without any); the index set — titled with `get_customer`'s
name (404 for a code no `customers` row holds: the integrations' code is a
plain string), described with the code, 30 indices, no replica, one shard per
indexer node or one (Mimecast, SAP SIEM), Darktrace's and Duo's prefixes
lower-casing the code (`str.lower`) —, the event stream (`integration`, then
`customer_code` rule, through `create_entity`), the resume, the datasource
(its own log fields for Mimecast and SAP SIEM), folder and dashboards, then
`create_integration_meta` as Python calls the route function: the customer,
its meta row and an existing row are checked *after* every Graylog and
Grafana object was made (the 400), an insert MySQL refuses would be
swallowed, then `deployed`. The scheduler jobs are the one step Rust cannot
take: APScheduler lives in the Python process. They are handed to `POST
/api/scheduler/provisioning_jobs` (added to `app/schedulers/routes/scheduler.py`
for this: admin/analyst, the caller's token, only `PROVISIONING_JOBS` — the
jobs these routes register, pinned to their source by
`tests/test_scheduler_provisioning_jobs.py` and to Rust's table by the
vectors), which calls `add_scheduler_jobs` for each, in the route's order
(Mimecast's two fixed intervals, SAP SIEM's three jobs). A refusal there —
an interval APScheduler overflows on, a scheduler error — or no
`COPILOT_LEGACY_URL` is the bare 500 Python's own failure is. SOCFortress MDR
reads the `COLLECTOR_UUID` key of the first integration holding the body's
`integration_name` (`None` is the `AttributeError`), under the SOCFortress MDR
service only (404 without one), refuses one that `str.strip()` leaves empty
(400; CPython's whitespace includes U+001C–U+001F) and sets `deployed`.
The body's `customer_code` is checked against the caller's customers (403,
§4).

**CrowdStrike, Defender for Endpoint, Bitdefender.** A third data table
(`collectors.rs`) answers their `POST /provision` on the default Graylog,
in Python's order and with nothing rolled back: the customer's integrations
(404), the one holding the service (the `AttributeError` of `None`), its keys
(404 without any) read as the `Provision<X>AuthKeys` model (400), `int()` of
the syslog port (`SYSLOG_PORT`, Bitdefender's `GRAYLOG_PORT`; the 400), the
`<X>CustomerDetails` model (a `null` retention or replica count is its 400),
the name's spaces made `_`, the Grafana organization (404), the content packs
(TCP, `Tcp` for Bitdefender), the stream they made, a new index set
(`crowdstrike-` / `defender-for-endpoint-` / `bitdefender-<code>`, the body's
retention and replicas, one shard per indexer node), the two packs' ids, the
input, CrowdStrike's processing pipeline (the others store `not_set` /
`NONE`), the stream moved to the index set (and CrowdStrike's connected to the
pipeline), the OpenSearch datasource, folder and dashboards, the
`customer_network_connectors_meta` row (Defender stores the folder's id, the
others its uid). Then the files Python writes under its `UPLOAD_FOLDER` —
`COPILOT_BACKEND_DATA_DIR` here, `/opt/copilot/backend/data` by default, the
path of the backend's image, which `docker-compose.rust.yml` now mounts
read-write (the image's uid 10001 must be able to write there): the
customer's directory created when missing (Defender's `data/` too), the
docker-compose file, then `cs.falconhoseclient.cfg`, `filebeat.yml` or
`config.json` (`json.dumps(indent=4)`, where the webserver port's `int()` is
the 400 after the compose file), the syslog target being connector id 3's URL
with `https://`, `http://` and `:9000` taken out (`None` without that row).
The templates are compiled in from `backend/app/integrations/*/templates/`
(`include_str!`: one source; the Dockerfile copies the three directories and
Rust CI runs on a change to them), and `collector_vectors.json` pins every file
Python's own functions write. Then `deployed`, and Bitdefender's push to
GravityZone as httpx 0.28 sends it (`COPILOT_BITDEFENDER_URL` replaces its host
for the parity harness only): the answer's JSON is read and dropped, a text
that is not JSON the `JSONDecodeError`'s 400 after every step was done. Two
differences by design: the body's customer is checked (403), and a customer
name holding a `/` or a NUL, or `..`, is refused with a 400 before anything is
created (§4). `rust_parity_remaining_provisioning_e2e.py`'s `collectors`
section points both backends at one data directory, emptied before each side,
and compares every file written there (and next to it) byte for byte, with
every request to Graylog 6 and 7, Grafana, the indexer and GravityZone.

**Customer provisioning itself.** `copilot-integration-provisioning::customer`
answers `POST /api/customer_provisioning/provision`, `/provision/wazuh_worker`
and `POST /api/portainer/create-wazuh-customer-stack` (admin only), in
Python's order and with nothing rolled back. `/provision` takes
`check_customer_exists`' `customer_code` from the query: missing, it is one
422 with the body's errors (FastAPI collects a dependency's errors with the
body's); unknown, the 404 before the body is validated. Then the ports, when a
worker is asked for — each port against the three port columns of every meta
row, a `None` port being SQLAlchemy's `IS NULL` (it matches any row without
one) — and `only_insert_into_db`, which inserts the row from the body and
answers the ORM instance as it is (its attributes in the order they were set,
then the id; the unset columns absent; MySQL refusing a `NULL` Graylog id or
organization is the bare 500). Otherwise: Graylog, the Wazuh manager and
Grafana verified as their connectors verify (Graylog's roles of its user, the
manager's token, a Grafana test user created then deleted — the 500 names the
first that fails; a missing row is the `TypeError`'s bare 500, a Grafana URL
without a scheme the `ValueError`'s 400), the `Wazuh` pipeline, the index set
(the body's prefix, retention, shards and replicas), the stream (`OR` of the
agents' customer label and the worker's node name, through `create_entity`),
connected and resumed (`start_stream` answers a model, so its "failed" branch
is unreachable, as in Python), the three Wazuh groups created and configured
from the backend's `customer_provisioning/templates/*.conf` (`REPLACE` is the
group code's last `_`-separated part, `CLUSTER_NAME` the cluster or
`YOUR_PATH`; each failure only logged), the Grafana organization, the WAZUH
datasource (the `Wazuh-Indexer` connector's credentials read *by name*, the
CVE and `_id` data links), the `EDR` folder and the body's dashboards,
`CustomerProvisionMeta` validated, the `customersmeta` and
`custom_alert_creation_settings` rows; the answer is the row's `model_dump()`
validated again (the id first, the organization an `int`, the unset columns
absent). The worker and HAProxy follow when asked (their models built from the
body: a `None` port is their `ValidationError`'s 400 after everything else);
either failing still answers 200 with Python's "but … failed" message. The
worker is the `Wazuh Worker Provisioning` service (`requests.post`, the
manager's `api_version` added), or — the Portainer connector verified — each
swarm node's provisioning worker on `:5003` (`COPILOT_PROVISION_WORKER_PORT`,
tests only), then the stack (the backend's `wazuh_worker_stack.yml`,
`str.replace`d in `_prepare_template_variables`' order — a value that is not a
`str` is the `TypeError`'s bare 500 —, the endpoint and swarm ids, `POST
/api/stacks?type=1&method=string&endpointId=…`) and its id written on the row
of that customer *name* (404 without one, `MultipleResultsFound` with two).
The templates are `include_str!`s of the backend's files. Differences by
design (§4): the query's and the body's customer, and the worker body's, must
be the caller's (403). `copilot-upstream`'s `requests` emulation no longer
adds a second `Content-Type` when the caller names one (Portainer's helpers
do; Python's `prepare_body` keeps the caller's). The parity suite's `customer`
section masks the new row's id in the answers. In the parity suite the Python side and the Rust
instances' legacy backend are one uvicorn app over a paused `AsyncIOScheduler`
on `apscheduler_jobs`; the stored jobs and `scheduled_job_metadata` rows are
compared with the rest.

**Office 365.** `copilot-cloud-provisioning` answers `POST
/api/office365/provision` (admin/analyst). The request model forces
`integration_name` as the integrations' do (a non-object body is the
`TypeError`'s bare 500). Then, as the Python route: the customer's
integrations (404 without any), the instance — `normalize_instance_name`'s
strip, the one instance when none is named, the 400 naming them when there
are several —, the instance's record (404 naming it), its keys flattened and
read as `ProvisionOffice365AuthKeys` (a missing one is the `ValidationError`'s
400). The deployment keeps Python's order and its rollback: the manager's
`ossec.conf` read raw, the tenant refused when any `<tenant_id>` already
holds it (400), then the edit — a new `<office365>` block appended to the
`<ossec_config>` root (`office365_template_with_api_type`, written as
`minidom.toprettyxml` writes it, the empty lines dropped) or an `<api_auth>`
block inserted before the existing block's `<subscriptions>`
(`add_api_auth_to_office365_block`; two `<ossec_config>` blocks, or one
without `<subscriptions>`, are its 500) — and pushed (`PUT
/manager/configuration`; refused, it is pushed again without `<api_type>`),
the restart, the six pipeline rules (created when missing; the UTC rule
repaired when it still reads `data_office_365_CreationTime`) and the pipeline,
the index set (`office365-<code>`, one per customer: a further tenant reuses
the meta row's), the tenant's stream (its two rules, `create_entity`), the
pipeline connection (`get_pipeline_id`: a `None` description is the
`AttributeError`) and the resume, the datasource, folder and dashboards
(reused when the meta row holds them), the meta row, `deployed` and the
legacy `customer_meta_office365_organization_id` claimed only while empty.
Python reads its edit back from a file next to its module; Rust keeps it in
memory and reads it back as universal newlines would (§4). Every
externally-visible step registers its undo (the tenant's block taken out
again through `copilot-integrations`' decommission and a restart, the index
set, the stream, the datasource, the folder); a failure undoes them
newest-first, each failed undo named in the answer, and the answer's status
is `getattr(exc, "status_code", 500)` — an `HTTPException`'s, a
`grafana_client` exception's or an elasticsearch-py `TransportError`'s. An
elasticsearch-py `ConnectionError`'s `"N/A"` is Python's log row and bare
500, kept; a `GrafanaTimeoutError`'s `0` is §4. The body's `customer_code` is
checked against the caller's customers (403, §4).
`rust_parity_remaining_provisioning_e2e.py` drives both backends against a
manager that keeps and rewrites `ossec.conf`, stateful Graylog 6 and 7
stand-ins, Grafana and the indexer, and compares every request, the manager's
configuration, Graylog's and Grafana's objects and the rows.

**AWS.** `copilot-cloud-provisioning` answers `POST /api/aws/provision`
(admin/analyst; Python's own check of the body's customer first, its texts).
The route's steps are Python's: the customer's integrations, the instance,
its record (404 naming `'Default'`), its keys (404 without any) read as
`parse_aws_auth_keys` reports them — `blank_means_unset`, then each field's
validator in declaration order, `"; "`-joined `loc: msg` problems in one 400.
`provision_aws` then refuses an account another customer configured, or the
bucket and account another instance of the customer collects (400), and
checks the credentials against AWS as `_validate` does, with botocore
1.43.6's four calls reproduced (`aws/boto.rs`): STS regional and S3
virtual-hosted endpoints (path-style for a dotted bucket or an
`AWS_ENDPOINT_URL[_STS|_S3]` override, as botocore reads them), SigV4 over
botocore's canonical request (S3 `UNSIGNED-PAYLOAD`), the headers in its
order (`amz-sdk-invocation-id`, `amz-sdk-request` with the retry TTL a
`Date` answer gives), standard-mode retries (three attempts: transient and
throttling codes, 500/502/503/504, transport errors), S3's region redirector
(a HEAD's 301/400 with `x-amz-bucket-region`, `PermanentRedirect`,
`AuthorizationHeaderMalformed`'s `Region`, a nested HEAD), S3's 200 with an
error body counted as a 500, the query and rest-xml readings
(`ResponseParserError`, the generic errors, `encoding-type=url`, `int()`'s
`ValueError`, a missing `Key`'s `KeyError`, an `Error` that parsed as text
the retry handler's `AttributeError`) and the exception texts; a credential
or permission failure is the 400 `AWS validation failed, nothing was
changed: …`, AWS unreachable a warning, what Python's `try` lets through
escapes as there (a bare 500, `ValueError`'s 400). Inside one `try`, rolled
back newest-first as Office 365's (`Detail` style: `getattr(exc, "detail",
None) or exc`): the manager's log markers (`GET /manager/logs`), the
instance's `<bucket>` entries reconciled in the aws-s3 wodle
(`copilot-integrations`' `aws/config.rs` — refusals, the wodle created or
dropped, `ET.indent`, `verify_only_instance_changed` — and `aws/manager.rs`
— read, re-read before writing, write, `GET /manager/configuration/validation`,
the original restored, the restart —, under `WAZUH_CONFIG_LOCK`), the four
shared WAZUH rules and the three AWS rules (a stale AWS rule rewritten by a
flat `PUT`, a refusal the 502), the AWS PROCESSING PIPELINE, per service the
customer's `<service>-<code>` index set (reused) and the instance's stream
(kept), the `AWS` folder and per service the datasource (reused), the meta
row (`service:id` pairs) and `deployed`. After the `try`, a re-sync's
dropped services are removed — only their streams: Python reads the index
sets and datasources off the row `save_aws_meta` just rewrote in the same
session, which no longer names them, and so does Rust — and after a restart
the manager's log is watched for the exit-23 error (10 s steps up to 60 s;
`COPILOT_AWS_PROFILE_CHECK_SECONDS` shortens them for the e2e and parity
suites only). The delete of a deployed AWS instance moved with it
(`copilot-integrations`): the streams, the index sets and datasources no
sibling instance still collects, the folder with the last instance, then the
`<bucket>` entries off the manager — the metadata row stays, as Python
leaves it (flagged: a later deployment of the same instance reuses its
deleted ids). `WAZUH_CONFIG_LOCK` is the one piece of process state: a
tokio mutex, as Python's `asyncio.Lock` is one per process; across the two
processes the re-read before each write keeps one from undoing the other's
edit. `rust_parity_remaining_provisioning_e2e.py`'s AWS section drives both
backends through `AWS_ENDPOINT_URL` at an AWS stand-in (STS, the bucket's
HEAD, listings, the one-byte read) and compares every request — the signing
time, signature, invocation id, TTL, the interpreter's patch version and the
`m/` order masked —, the answers, the manager's configuration, Graylog's
and Grafana's objects and the rows.

**MinIO.** `copilot-objectstore` is miniopy-async 1.23.5 over aiohttp, not a
generic S3 client. It reads Python's variables — the endpoint
`{MINIO_URL}:9000` (Python hard-codes the port), `MINIO_ROOT_USER` and
`MINIO_ROOT_PASSWORD` (an empty user is anonymous), `MINIO_SECURE` with
environs' boolean spellings (anything else stops the binary, as it stops
Python's import) — and `COPILOT_MINIO_ENDPOINT`, which replaces the endpoint
for the e2e and parity suites only. Every operation opens its own client, as
`create_session()` does, so it starts with the bucket's `GET ?location=`
(signed for `us-east-1`). The requests are the library's, path-style:
`Host`, the `User-Agent`, `Content-Length` when there is a body, the body's
SHA-256 as `x-amz-content-sha256` (`UNSIGNED-PAYLOAD` and `Content-MD5` over
HTTPS), `x-amz-date`, SigV4 over all but `User-Agent`, then aiohttp's own
`Accept`, `Accept-Encoding`, `Content-Length: 0` and default
`Content-Type`. An answer of 500 or more is asked again, five attempts in
all (`aiohttp_retry`'s `ExponentialRetry`); a transport error is not. A file
over 5 MiB goes up in parts, three at a time, and the upload is aborted
when one fails. A listing is ListObjectsV2 with `encoding-type=url`, and
its later pages carry the token as both `continuation-token` and
`start-after` (the library reuses its variable). A download is `stat_object`
then `get_object(bucket, object, session)` — the session lands in `offset`,
so the request carries `Range: bytes=<aiohttp.client.ClientSession object at
0x…>-`, which MinIO ignores; it is sent here with `0x7f0000000000`.
Failures are the library's exceptions with their texts (`S3Error` from an
XML body, or from the status of a `HEAD`; `InvalidResponseError`;
`ServerError`; aiohttp's `Cannot connect to host H:P ssl:default [Connect
call failed ('ip', P)]`; the bucket- and object-name `ValueError`s), and
`ops.rs` keeps what `data_store_operations.py` makes of them: a download
that fails lists the bucket (for the log) and is the 404 `File {object} not
found in bucket {bucket}`, a delete that fails is that 404 too, the report
helpers return the error text. TLS is verified (against `SSL_CERT_FILE`, else
the Mozilla roots), and no proxy is used (`trust_env=False`).

The routes read FastAPI's way: the multipart body first (Starlette's 400 for
a body that does not parse, before the token), then the token, the path (as
uvicorn decodes it: an invalid escape is U+FFFD, not a 400), the case's,
report's or agent's owner, the query, the form (`UploadFile` missing, or a
text field where a file belongs, are Pydantic's 422 texts). A path with an
encoded `/` is handed to Python, which routes the decoded path.
`/api/agent_data_store`'s upload writes any bucket and object for any
admin or analyst — no tenant prefix, as in Python (portal users were shut
out by GHSA-6j26-wcv6-gp3f); whether it should be admin-only or confined to
a tenant's prefix is a product decision, not a port's. The artifact routes
check the agent's owner (`verify_agent_id_access`, fail-closed) and address
the object as `velociraptor-artifacts/{agent}/{flow}/{file}`, not the row's
key, as Python does. `DELETE /case/{id}` runs Python's statements in
Python's order: comments, alert links, tasks and timeline, then per file
(`delete_file_from_case`) the object, the row and a commit — which also
commits the earlier deletes — a MinIO failure only logged; then the case. A
file whose object cannot be removed keeps its row, so the case's foreign key
fails the last statement: Python's 500 `Failed to delete case:
(pymysql.err.IntegrityError) (1451, …)` with SQLAlchemy's `[SQL: …]
[parameters: …]` lines, after the first file's commit took the comments
with it. An upload answers with the created row in SQLModel's order (the
given fields, then `id` and `upload_time` with its microseconds).

Downloads are `StreamingResponse(BytesIO(data))` as they leave copilot.py:
the headers latin-1 (a file name that is not makes Starlette raise
`UnicodeEncodeError`, the `ValueError` handler's 400), a `text/*` type gains
`; charset=utf-8`, no `Content-Length` but the artifact's, chunked. Then
`GZipMiddleware(minimum_size=1000)`, whose streaming branch ignores the
minimum: a non-empty download gains `Vary: Accept-Encoding` and, when the
request's `Accept-Encoding` holds `gzip` (a substring test — `gzip;q=0`
too), is gzipped at level 9 whatever its size or type, images included, its
`Content-Length` dropped; an empty one and a `text/event-stream` one pass
untouched. The compression layer's rules (1000 bytes, never images) are not
these, so a download carries `copilot_web::middleware::Uncompressed` and the
layer leaves it alone.

The default templates and the Sysmon config upload are Rust too (see
**Incidents** and **Response routes**). Still Python, each for a reason: the
DOCX/PDF case reports and the customer report generation (docxtpl,
wkhtmltopdf), the `file_analysis` state store and the startup `create_buckets()` (the
sidebar's MinIO indicator moved with the sidebar). The parity suite (`rust_parity_objectstore_e2e.py`)
points both backends at one recording S3 stand-in, verifies every
request's signature with the shared secret and compares the canonical
requests (method, path, query, headers, payload hash) rather than the
signatures, which carry the time.

**Response routes.** `copilot-response` answers `/api/active_response`
and the Graylog webhook `POST /api/graylog/invoke`. The invoke body is read
the way Pydantic reads `InvokeActiveResponseRequest`: its `create_alert`
validator (`mode="before"`) runs first — an `alert` that is truthy but not an
object is the root `ValueError`, a command that is no value and no name
(compared lower-cased, `_missing_`) is its `HTTPException(400)`, and the
command's alert model fails with *its* errors at the root (Pydantic re-raises
a validator's `ValidationError` as its own lines) or passes as its JSON dump
(the stripped IP, CPython 3.11's `ipaddress` from `copilot_ingest::py`) — then
the fields (`Literal`s included: `custom` accepts `true`, `1` and `1.0`). The
tenancy is on the body: a caller without deployment-wide access must name its
targets (`agents_list` absent, `[]` or `["*"]` — the model's `[]` — is the
403, since Wazuh reads it as every agent) and own each one
(`enforce_agent_access`, fail-closed), before anything is sent. The request
is the one `send_put_request` sends (`copilot_wazuh::manager::client::send_put`):
`data=json.dumps(…)` as a string (the form-encoding footgun avoided at the
call site, as in Python), `wait_for_complete` as `"true"`/`"false"`, a list
parameter as one pair per item and an empty one as none; a failure is the 502
naming Wazuh's own `detail`/`message`, a missing manager row the 503. The
describe route reads `scripts/{family}/{name}.md` like Python, so only the
exact lower-case spelling finds the one script (a copy compiled in,
`templates/windows_firewall.md`, pinned to the backend's file by a test);
another spelling of a member is Python's `FileNotFoundError`, a bare 500.
The webhook checks its `graylog` header against `GRAYLOG_API_HEADER_VALUE`
(fail closed) before validating `GraylogEventNotification`
(`copilot_upstream::model`: datetimes, the `COMMAND` pattern, `additional_fields`
by alias and, without it, by name), sends `wait_for_complete=True` and the one
agent, and answers success whatever Wazuh says. `/api/sysmon_config` (admin
and responder; a path's customer checked first, the list narrowed to the
caller's customers) reads MinIO's `sysmon-configs` bucket with
`copilot-objectstore`'s client and operations (`download_data_store`'s 404
and its listing; the list creates a missing bucket and swallows any failure
as Python does). The deploy is audited (`response.sysmon_deploy`) before
anything is fetched, then POSTs the config to the Wazuh master's provisioning
worker at `http://{host}:5003/provision_worker/sysmon-config`, the host taken
as CPython 3.11's `urlsplit` takes the manager connector's netloc (its
`ValueError`s and the `TypeError` of a missing row included), exactly as
aiohttp sends a `FormData`: a `multipart/form-data` body under a
`uuid4().hex` boundary, each part's `Content-Type` before its
`Content-Disposition`, aiohttp's headers, no proxy; the answer is read as
aiohttp reads it (`response.json()`'s `ContentTypeError`, `None` for an empty
body, `json.loads`; `response.text()` otherwise) and every outcome is a
`SysmonConfigDeploymentResult` (its `ValidationError` text when the worker's
`success`/`message` do not fit). `COPILOT_PROVISION_WORKER_PORT` replaces
the port for the parity harness only. The upload (admin; the body's
customer is checked against the caller's customers, which the admins the
route admits always pass) refuses a name not ending in `.xml` and a file
that is not UTF-8, then runs `validate_sysmon_config` on
`copilot_integrations::etree`'s parser: ElementTree's `ParseError` is
expat's text with its line and column (`not well-formed (invalid token):
line 2, column 20`), reproduced for expat 2.6 — each error at the position
expat reports it (a token's start, the offending character, a tag's start
for the namespace and entity errors found after its attributes), columns in
characters — and pinned by `expat_vectors.json` (150 documents) and
`sysmon_vectors.json` (`scripts/gen-expat-vectors.py`; regenerate after a
Python or pyexpat upgrade); then the root, `EventFiltering` and `RuleGroup`
checks, `check_config_exists` (a missing bucket created: not overwritten)
and the upload. `rust_parity_objectstore_e2e.py` compares it (the S3
stand-in's requests and objects included). `rust_parity_response_e2e.py` compares both backends
against a recording Wazuh manager, a provisioning worker and the S3 stand-in
of the objectstore suite (signatures verified), every header of every request
included.

**CoPilot Actions.** `copilot-response` also answers `/api/copilot_action`
(admin and responder). The inventory routes ask the CoPilot Action service
(`https://copilot-action.socfortress.co`; `COPILOT_ACTION_URL` for the
tests only) the way `CopilotActionService` does — one httpx 0.28 client per
call: its four default headers, the module's `x-api-key` (`COPILOT_API_KEY`,
read as `os.getenv` reads it: unset or empty is the 500 after the query is
validated), `module-version` and `Accept`, `params` encoded as httpx
encodes them and left out when falsy or at their default, an action's name
in the path as httpx quotes and normalizes it, no redirect followed, gzip
and deflate decoded, HTTP/1.1 only — and keep its outcomes: every failure of
the inventory and the metrics is a model with httpx's text
(`raise_for_status()`'s two lines with MDN's link, `All connection attempts
failed`, …), a total read off the message with the module's four patterns,
the pagination fields computed as Python computes them, and Pydantic's
`ValidationError` wherever the service's answer does not fit
(`ActiveResponseItem`'s icon default included). One action is the 404
`Action '…' not found` for an HTTP 404 and, for anything else that fails,
the 500 `Error fetching action details: ` + the `ValidationError` of
`ActionDetailResponse(copilot_action=None, …)`, which every one of Python's
fallbacks raises. The invoke reads `InvokeCopilotActionBody`, refuses an
empty `agent_names` (400), checks each hostname's tenant
(`enforce_hostname_access`: the first agent of that name decides, none is a
403 for a scoped caller), writes the `response.copilot_action_invoke` audit
row, then runs Python's sequence: the agents by hostname (the 404 naming the
missing ones), the action's details, `ScriptURL` from its `repo_url`, the
parameter checks, and per agent the OS's artifact and
`run_artifact_collection` — the identifier validators, the agent by client
id, the `collect_client` VQL with its `env=dict(…)` (quotes escaped as
Python escapes them), the flow id from the first row, the flow wait, the
results, then `fetch_file_from_filestore` (the hostname, the download pack,
the 1 MiB `read_file` chunks decoded as `base64.b64decode` decodes them, the
`velociraptor-artifacts` upload and the `agent_datastore` row — all
best-effort, as in Python). A failing agent is a failed
`CollectArtifactResponse` whose message nests the `HTTPException`s the way
`str()` prints them; the answer counts successes and failures with Python's
three messages. A scoped caller's invoke runs only on the agents of a
hostname that belong to its customers (§4).

The parity suite adds a recording CoPilot Action service and the grpcio
Velociraptor of the agents suite (each `VQLCollectorArgs` and its deadline)
for these routes, and compares the `agent_datastore` rows each backend
writes.

**Shuffle.** `copilot-shuffle` answers the Shuffle connector's routes and
the case notification. Every request is the one `utils/universal.py`
sends with `requests` (the connector row through the cache, `Authorization:
Bearer {key}`, `verify=False`, 60 s, `json=` as `requests` serializes it,
`Connection: keep-alive` written as `requests` writes it), and every helper
keeps its outcomes: `send_get_request` answers `data` whatever the status
and fails with the 500 `Failed to send GET request to {endpoint} with
error: {e}`; `send_post_request` folds a status of 400 or more and an
in-body `success: false` (its `reason`) into `success`, turns a JSON that
does not parse into the 500 `Failed to send POST request …`, and — since
its `except` logs a `response` never assigned — turns a request that
failed into its own `UnboundLocalError`, which each caller meets as Python
does (`/integrations/execute` and `/workflows/execute`: the bare 500;
`/invoke-workflow` and the case notification: the 502 `Failed to reach
Shuffle while executing workflow {id}: cannot access local variable
'response' …`). The services are ported with CPython's own failures on
odd answers (`"actions" in workflow`, `workflow["actions"]`,
`action.pop("large_image", None)`, `executions[0]["status"]`, `**data`)
and their wrapping texts; `ExecuteWorklow`'s `UUID4` fields read as
pydantic-core 2.46 reads them (its `uuid` release words errors with 1-based
positions and parses a braced or URN input's inner part, `uuid4.rs`), and
the results are polled ten times `2**i` seconds apart, as in Python. A
returned dict goes through `jsonable_encoder` (a key starting with `_sa`
is dropped). `/invoke-workflow` checks `execution_arguments.customer_code`
(`ExecuteWorkflowRequest`'s model validator: the 400 `customer_code is
required`), then — a difference by design (§4) — that the code is one of
the caller's customers. `/singul/execute` validates its body, then Python
calls `exit(0)`: uvicorn's bare 500, which Rust answers too. The
organizations read the connector named by `?connector_name=` (MySQL's
collation decides the match) and keep `Organization` /
`DetailedOrganization` (its `manager_orgs` validator) as Pydantic reads
them, an organization that does not fit skipped. The case notification
is `get_case_by_id` and its tenant check (`copilot_incidents::access`), one
`CreatedAlertPayload` per linked alert (the first asset's context read as
Python's `json.loads` reads MySQL's text, `extract_rule_level`,
`severity_from_rule_level`, the IoCs as a dict), the customer's first
notification row (400 when none is enabled), `ExecuteWorkflowRequest` with
the primary alert's fields at the root, then `notification_invoked_number`
+ 1. The `Shuffle` connector verifies in Rust. `rust_parity_response_e2e.py`
runs every route against a recording Shuffle stand-in.

**OpenCTI and Cortex.** `copilot-intel-connectors` answers `/api/opencti`
and `/api/analyzers`; neither connector holds tenant data, so, as in
Python, no route is tenant-scoped (admin and analyst only). OpenCTI is
GraphQL over httpx 0.28 (`copilot_threat_intel::httpx`): `POST
<url>/graphql` (the stored URL with or without `/graphql`), `Authorization:
Bearer <key>`, `Content-Type` and `Accept` JSON, the body
`{"query", "variables"}` compact, headers in httpx's order and spelling
(`Host` first, a caller's header replacing a default at the end), no
certificate check, 30 s (15 s for the connector check). The envelope is
Python's: an `errors` array — which OpenCTI answers with HTTP 200 for a
revoked token — is a failure (`OpenCTI GraphQL error: <message> (<code>);
…`, checked before the status), then an HTTP error, a body that is not
JSON or not an object, and every `httpx.HTTPError` as `Failed to reach
OpenCTI at <url>: <repr>` — `UnsupportedProtocol` for a URL without a
scheme or a host (httpx makes it relative), h11's `LocalProtocolError` for
the `Bearer ` of a row without a key once the connection is open; an
`InvalidURL` is a bare 500, a non-ASCII key the `UnicodeEncodeError` 400.
The services flatten the answers as Python does (`or {}`/`or []`, the
falsy labels and markings dropped, `_global_count`) into the Pydantic
models, whose `ValidationError` is the `ValueError` handler's 400 with its
text; the batch lookup maps observables back to the requested values on
`value` and every hash, lower-cased as `str.lower`; `/availability`
resolves the public URL with `urlparse` (its `ValueError` a 400). The
documents are `queries.py`'s text, pinned by a test that reads it;
`paginate_graphql` (unused by the routes) is ported and pinned by
vectors. Cortex is cortex4py 2.1 over `requests` 2.33
(`PyHttp::with_exact_headers`: requests' header order and spelling, one
`Content-Type`, latin-1 values; no timeout): `POST {url}/api/analyzer/_search?range=all`,
the analyzer by name (`range=0-1`, `{"query": {"_field": "name", …}}`),
`POST analyzer/{id}/run?force=1` (`dataType, tlp, pap, message, data`),
`GET job/{id}` every 5 s until `Success` (a `Failure` ends it with
`errorMessage`; the 61st look is `Job timed out`), `GET job/{id}/report`.
Failures carry cortex4py's own texts (`Resource not found`, `Authentication
error`, `Authorization error`, `Invalid input exception`, `Cortex service is
unavailable`, `Cortex request exception`, `Unexpected exception`), and an
odd answer fails where the library's objects fail (`_wrap`: a dict is an
`Analyzer`/`Job`, a list a list of them, `None` the class defaults; an
attribute or an iteration CPython refuses), inside the routes' own
wrapping texts. Python runs these synchronous calls and `time.sleep(5)` on
its event loop, so the whole backend waits while a job is polled; the Rust
task sleeps alone. The `Cortex` check reads cortex4py's `api.status`
without calling it: no request, a row without an API key the one failure.
A handled error whose URL (Starlette's: the decoded path) does not fit
`log_entries.route` (256 characters) or whose message does not fit
`message` (5024) is a bare 500 on both backends: Python's handler fails
writing the row (`copilot_web::middleware`). `/api/sublime` is
`copilot-sublime` (below).
Neither connector keeps state in the process beyond the shared connector
cache: both send their key with every request (no session, no token), so
the two backends can answer side by side.
`rust_parity_intel_connectors_e2e.py` runs every route against recording
OpenCTI and Cortex stand-ins (HTTP and HTTPS with a self-signed
certificate), every outbound header compared in order.

**Sublime.** `copilot-sublime` answers both `/api/sublime` routes. Their
tables were never created: the model was not imported by `alembic/env.py`,
so every deployment answered both routes with a 500. Migration
`d6c01a2b3c4d` creates exactly the six tables the model declares
(`sublimealerts`, `flaggedrule`, `mailbox`, `triggeredaction`, `sender`,
`recipient`, each child with a plain FK to the alert), and the Rust module
requires them. `POST /alert` is the ORM's work statement by statement: the
alert's `INSERT` at the `flush()`, the two `GET /v0/messages/{id}` lookups
(sender, then recipient) with the transaction open, then at the `commit()`
the child rows in the unit of work's order — the tables sorted by name,
which is why a too-long recipient email fails before a too-long sender's
and a too-long mailbox id before a triggered action. A failure is rolled
back and is the 500 `Failed to store alert {id} in the database: {e}`, `e`
being SQLAlchemy's text (`(pymysql.err.DataError) (1406, …)
[SQL: …]

[parameters: …]
(Background …)`, each parameter's `repr()` cut to 300
characters), `requests`' and `json`'s texts inside the lookup's
`HTTPException` (`500: Failed to get Sublime Alert …`) or CPython's
subscript errors on whatever Sublime answered. An email is written as
pymysql writes it: a number as its digits, `True` as `1`, a list as a
tuple MySQL stores, refuses or cannot parse; a dict or a NaN is refused
before the statement is sent. `GET /alerts` reads the alerts and each
relationship with `selectinload`'s statements and validates every alert
against `SublimeAlertsSchema` (a name MySQL holds as `NULL` is the 500 with
Pydantic's text). The routes are not tenant-scoped, as in Python: an alert
names no customer. `rust_parity_ext_tools_e2e.py` (a recording Sublime
stand-in) compares every request and header, the rows each backend wrote and
every failure above.

**ScoutSuite.** `copilot-scoutsuite` answers the six `/api/scoutsuite`
routes. A scan is the `scout` command line `construct_*_command` builds
(the credentials as arguments, as Python passes them), run with stdout and
stderr piped and this process's environment in the working directory
`COPILOT_SCOUTSUITE_DIR` (default: the process's own), started once the
answer is built — FastAPI's background task — and never waited for; a
failure is only logged, as in Python. ScoutSuite writes its report under
that directory's `scoutsuite-report/`, which the listing reads (the `.html`
entries in the directory's own order) and the delete edits (the report,
then its exceptions and results scripts, `os.path.splitext`'s base; a
directory of that name is `os.remove`'s bare 500). The GCP route checks the
upload as Python does (`json.loads` of the bytes: a `JSONDecodeError` is the
400 `Invalid JSON file - …`, a `UnicodeDecodeError` the `ValueError`
handler's 400; `GCPScoutSuiteJSON(**data)`'s `TypeError` or
`ValidationError` the 400 naming it), writes the key into a fresh `0700`
directory as `tempfile.mkdtemp(prefix="scoutsuite-gcp-cred-")` makes it
(the first usable of `TMPDIR`, `TEMP`, `TMP`, `/tmp`, `/var/tmp`,
`/usr/tmp`, the working directory) under its real path, and removes the
directory once the scan ends, however it ends. The binary creates
`scoutsuite-report` at startup, as `copilot.py` does. Python's static mount
`/scoutsuite-report` keeps serving the reports: under Compose the two
containers share that directory as the `scoutsuite-reports` volume
(`docker-compose.rust.yml`), and the Rust image carries the ScoutSuite CLI
(`scoutsuite==5.9.1`, the backend's pin). No route is tenant-scoped, as in
Python. `rust_parity_ext_tools_e2e.py` puts a recording `scout` first on
both processes' `PATH` and compares every scan's arguments, working
directory, environment variable, credential (its directory's shape, mode
and removal) and the report tree each delete leaves.

**Detections Catalog.** `copilot-searches` answers all 38 routes of
`/api/copilot_searches`, dispatched on the decoded path in declaration order
as Starlette routes them (`{name:path}` matches across `/`, `$` before a
final newline; a path or method no route takes goes to Python). It keeps the
catalog's rule: no table, no column — the only row it reads is a customer's
Graylog stream (`customersmeta`, for the backtest). The four caches are
state of the process, with `cache_support.py`'s contract: the rules from
GitHub (the catalog repository first, then each enabled custom repository
named in MinIO; a tree listing then the raw files twelve at a time, a client
per repository, the first copy of an id kept, a source's failure kept in its
status), the ATT&CK STIX bundle (24 h), the Wazuh ruleset (`get_rules`
with `limit=100000`, 1 h) and the firing counts (one terms aggregation on the
wildcard-and-exclusion pattern, the rule-id field fallback and the winning
field kept, 15 min); the per-customer slice is never cached. A route that
`ensure_loaded`s waits; one that refreshes `ensure_fresh_nonblocking` starts
at most one background refresh per cache and answers from the snapshot
(`loading` in `/catalog/stats` and `/catalog/stories`). Two refreshes queue
on the cache's lock and both run, as in Python; a failure leaves the
previous snapshot (`unavailable_reason` for the Wazuh caches, a refresh time
stamped so the next request does not retry at once). The process refreshes
its copies itself — warm-up at startup, `refresh_catalog_caches` every 15
minutes (TTL-aware, so the bundle is fetched once a day) and the Wazuh
ruleset every 30 — a process-local task, not a hand-over job: each backend
serves from its own caches (the sidebar's Wazuh catalog indicator reads its
process's: `copilot-status` reads Rust's), and both refreshing read-only upstream data is what Python's
per-worker caches already did. `COPILOT_CATALOG_REFRESH=false` turns that
off (the caches then load on demand, as Python's would without its warm-up
and jobs): every parity suite but the catalog's starts its Rust instance so,
because their Python side never warms its caches, and a Rust process that
did would hold a Wazuh token or send requests the comparisons do not
expect. Rule values are `copilot-yaml`'s, and every
operation the services make on them is Python's (`py.rs`: `.get` on a
non-dict, iteration, `join`, hashing as dict keys, `int()`/`float()`,
`round`), so a rule of an odd shape fails where Python fails — an
`AttributeError` in a route's `try` becomes its 503 text, a model that
refuses a value is Pydantic's 400 text (`pyd.rs`, lax mode, the
`ValidationError` text of 2.13), anything else the bare 500. The upstreams
are reached as the Python libraries reach them: GitHub and the bundle over
httpx 0.28 (`copilot_threat_intel::httpx`), the indexer through
AsyncElasticsearch (`copilot_wazuh::es`), the manager through its
`requests` port (logtest as `send_put` of a `json.dumps` string), Graylog
through `GraylogClient` (the event definition goes through
`copilot_monitoring_alerts::services::provision_alert_definition`, the
function Python's catalog imports from the monitoring alerts: the version
compared with `"5.2"` as a string, then the one `create_entity`, wrapped
for 7.x) and the backtest's search API as its own `requests.post` (`X-Requested-By`,
`Accept: application/json`, Basic, 60 s, TLS unverified), MinIO through
`copilot-objectstore`. The linter runs Python's fallback schema check,
since `jsonschema` is not a backend requirement (were it added, its
`Draft7Validator` would need porting). Tenancy: the routes that name a
customer check it (`verify_customer_code_access`, the optional customer of
`/catalog/wazuh-rules`), and four routes differ by design (§4). Kept as in
Python and flagged: every tenant's custom rules show in every rule list,
count and coverage for any analyst or portal user. `GITHUB_TOKEN` and the
switches are `copilot_core::catalog_env`'s (the `.env` file included, as
`os.getenv` sees it after environs' `read_env`). `COPILOT_GITHUB_API_URL`,
`COPILOT_GITHUB_RAW_URL` and `COPILOT_MITRE_STIX_URL` point the three public
URLs at stand-ins — parity harness only, never production.
`rust_parity_catalog_e2e.py` compares both backends after each loaded the
same corpus (GitHub, the bundle, the manager, the indexer, Graylog 6 and 7,
MinIO with SigV4 verified; rules of odd shapes; a cold start with Wazuh
failing).

**Licence and error log.** `copilot-license` answers the 12 routes of
`/api/license` (`require_any_scope("admin", "analyst")`, as in Python) and is
the one Rust definition of the licence check the rest of the backend imports
from `app/middleware/license.py`: `get_license` (the first `license` row;
`No license found. A license must be created first.`) and
`is_feature_enabled` (a fresh `license_cache` row, else `POST
/verify-license`, every named data object re-cached for an hour) —
`copilot-threat-intel` and the sidebar call it. The licence server is
reached as `send_post_request` / `send_get_request` reach it, over
`requests` (10 s, TLS verified, requests' header order, `module-version:
1.0`, `x-api-key` the text `None` when `COPILOT_API_KEY` is unset): a 204 is
`{"success": true, "message": "No content"}`, a non-JSON answer its text, a
5xx the 502 `License server error: …` (its `message`, else its `detail`),
any other failure the 500 naming the endpoint. Python's operations run on
whatever JSON came back (`normalize_api_response`, `extract_license_payload`,
`cache_license_features` with `json.dumps`' `NaN`), so a malformed answer
fails with Python's text: a missing key is the `KeyError`'s bare 500, a
model's `ValidationError` the `ValueError` handler's 400 — after the writes
that precede it — and a disabled feature that 400, since
`IsFeatureEnabledResponse(status_code=400, …)` misses two required fields. A
non-string `HTTPException` detail is rendered as Starlette renders it (`None`
is the status phrase). `COPILOT_LICENSE_URL` points the server at a stand-in
— parity harness only. `copilot-status` serves the six routes of `/api/logs`
(`Security(get_current_user, scopes=["admin"])`): the `log_entries` rows in
MySQL's order, `TimeRangeModel` with its validator (its own
`RequestValidationError` and canned message, the `IndexError` bare 500 of an
empty string, Pydantic's union errors), the window in days whatever the unit
and opened from the local `datetime.now()`, the purges by primary key in one
transaction, Starlette's routing (`GET /timerange` is `GET /{user_id}`'s
422, an id beyond 64 bits a 404). On every ported route a handled error's
`log_entries.route` is Starlette's `str(request.url)`, the percent-decoded
path (`copilot_web::middleware`). Models and validators are pinned by
`license_vectors.json` and `platform_vectors.json`
(`scripts/gen-platform-vectors.py`). Parity: `rust_parity_platform_e2e.py`
sections A and B (a recording licence server, every header in order, a
closed port, the error rows each backend logs).

**Sidebar.** `copilot-status` answers `GET /api/status/sidebar`
(`require_any_scope("admin", "analyst", "customer_user")`) with
`build_sidebar_context`'s sixteen indicators. Two are per user and computed
on every request: the caller's unassigned open alerts (through
`AlertVisibility`, §4) and their open cases. Fourteen are deployment-wide,
each with its audience tag (`analyst` for the SOC roles; `customer` for
portal users — the Wazuh catalog only; `admin` for the connectors, the
licence and the platform storage), held in process memory and served while
younger than 600 s; the InfluxDB health value has its own 600 s cache
("Checking InfluxDB healthchecks…" while cold) and the version fields are
cached for 30 minutes (the release check of `/api/version/check`, so
`COPILOT_VERSION_CHECK_URL`; a non-string `html_url` is
`SidebarContextResponse`'s `ValidationError`, the 400). A request never
waits for the shared set: a cold or stale one starts one background refresh
and the answer carries what is known; a refresh runs alone (Python's
`asyncio.Lock`, checked with `locked()`). Like Python's
`refresh_sidebar_indicators` and `refresh_sidebar_health` jobs, the process
refreshes them itself — after a warm-up Python does not do (the InfluxDB
value first, so the first set carries it), every 4 and 6 minutes; a
process-local task, not a hand-over job: the data is deployment-wide, so
each backend computing its own is the same answer.
`COPILOT_SIDEBAR_REFRESH` turns it off; unset, it follows
`COPILOT_CATALOG_REFRESH`, so every parity suite that starts its Rust
instance with the catalog refresher off has this one off too (the catalog
suite keeps its refresher on and sets `COPILOT_SIDEBAR_REFRESH=false`). Each builder
is Python's: the same statements (the counts, the `LIMIT 1` reads, one `IN`
over the scheduled job ids), thresholds and texts; a builder that raises
leaves its indicator out (`safe_build`). The scheduler and agent-sync
indicators read APScheduler's store as `SQLAlchemyJobStore.get_all_jobs`
lists it (by `next_run_time`, paused jobs moved last, decoded with
`copilot_scheduler::jobstore`) and `scheduled_job_metadata` (the later row
of one job id wins, as `{job_id: row}` does). A job handed over to Rust has
a disabled row, so it reads as disabled there — on both backends; whether
the sidebar should report a handed-over job as running is a product
decision. The Wazuh catalog indicator reads the Detections Catalog's own
ruleset cache (`copilot-searches`, as it stands before
`ensure_fresh_nonblocking`'s refresh runs); the Wazuh indexer indicator
`cluster_healthcheck` through `copilot-wazuh`; the InfluxDB one
`get_influxdb_alerts` through `copilot-influxdb`; the licence one the
newest `license_cache` row of the licence (`_parse_license_expiry`:
`strptime`'s regexes, then `fromisoformat` with the offset dropped, pinned
by `platform_vectors.json`); the platform storage `SELECT 1` and MinIO's
`list_buckets` within 5 s (`copilot-objectstore`, the exception's class
name). Parity: `rust_parity_platform_e2e.py` section C — four scenarios
(healthy, degraded, down, odd), each with Python's set refreshed in-process
and a fresh Rust instance's warm-up, every request to the InfluxDB,
indexer, MinIO, manager and GitHub stand-ins compared, then the route for
every role.

Python's catalog and sidebar jobs (`refresh_catalog_caches`,
`refresh_wazuh_rules_cache`, `refresh_sidebar_indicators`,
`refresh_sidebar_health`) and `copilot.py`'s `warm_catalog_caches()` keep
warming caches that no route of the Python process serves once the Rust
service is in front: a GitHub corpus every 15 minutes, a Wazuh ruleset
download every 30 (80–110 s against a real manager), a Flux query every 6.
**Proposal (not implemented):** a `@rust_served` guard on those four job
functions — `@rust_handover`'s shape without an owner row — returning
`JOB_SKIPPED` while a switch set only by `docker-compose.rust.yml` for the
Python container (say `COPILOT_RUST_FRONT=true`) says Rust answers
`/api/copilot_searches` and `/api/status`, the same switch skipping
`warm_catalog_caches()` at startup; rolling back (compose without the
second file) brings them back. Pausing the four jobs in the Scheduler UI
works today but leaves the startup warm-up.

**Performance.** `copilot-status` answers the six routes of
`/api/performance` (`require_any_scope("admin")`) and they describe **the
Rust process**, as Python's described the Python process. The choice: with
the Rust service in front it is the outermost process, so its timer
measures what the client waited for — a proxied request's time in Python
included —, which is what `RequestTimingMiddleware` measured when Python was
outermost; left in Python, the route would have shown only the requests
Python still serves, from behind the proxy. Ported: the request timer
(`performance::middleware`, `Router::layer` on the whole application, so it
runs after routing: the template is axum's matched path — `{*rest}` written
`{rest}` — and an unmatched path is `_normalise_path`'s; a request is
recorded when its body ends, one dropped before (the client gone) counts as
a disconnect; every answer carries `X-Process-Time-Ms`, the time to its
head with one decimal, and `X-Request-Id`, a proxied answer's own pair
replaced), the lag watchdog (tokio's scheduling delay every
`PERF_LAG_SAMPLE_INTERVAL`; a sample above `PERF_LAG_STALL_THRESHOLD_MS` is
a stall, attributed to the running and just-finished requests that
overlapped it), and the query metrics (`QueryMetricsLayer` reads sqlx's
`sqlx::query` events — statement text and elapsed time — and is enabled for
that target alone in the binary's subscriber, next to the log lines'
filter; the pool's occupancy is sampled on read and every minute).
Buffers, caps, the `PERF_*` / `DB_*` settings, the rounding, `_percentile`'s
rank, the sorts (stable, descending, an unknown key `stalled_ms`), the
verdict texts, the query validation and the reset (in-flight requests kept,
both registries zeroed) are Python's. Not ported: the session log files
(`backend/logs/performance/`); the Python process keeps writing its own —
with Rust in front, the one place its loop's numbers stay visible. Parity:
`rust_parity_platform_e2e.py` section D compares the guards, the 422s, the
shapes and units, the ordering rules, the counts a reset and a known
sequence of requests produce on each backend, and the reset; the timings
themselves are each process's (§4).

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
| `customers.created_at` of a customer created through `POST /customers` | the process start time (`Customers.created_at`'s default is evaluated at import) | the time of creation | Python bug; the column is not in any response (not compared) |
| `POST /wazuh_manager/rule/disable`, `/rule/enable` | every call fails: the manager endpoints `rules` and `rules/files/…` lack their `/` (`{url}rules`, a malformed URL against any connector URL that does not end in `/` — every working one —, then the `KeyError` of the failure answer: a bare 500), the rule file goes up as `application/json`, which the manager refuses, and until `d15ab1ed7e1e` the `disabledrule` table did not exist | `/rules…`, and the file as `application/octet-stream` with `overwrite=true` (the rule-file upload route's request): the rule is switched, the manager restarted, the row written or deleted | Python fails, Rust works (parity: both answers; Rust's requests checked against Python's own `set_rule_level` + `convert_to_xml`) |
| `GET /wazuh_manager/rule/disabled` with a stored row | 400: `AllDisabledRule` has no `from_attributes`, so any ORM row fails the response model | the rows, as `AllDisabledRule` declares them | Python fails, Rust works |
| `disabledrule.date_disabled` | the process start time (the model's default is evaluated at import) | the time of the disable | Python bug; not in any response (not compared) |
| `categories` of a technique the Atomic Red Team listing reads from its YAML (the fallback when the markdown index is not a 200) | a `set`'s iteration order, which for strings follows the per-process hash seed | first-seen order | Python's order is not reproducible; parity compares them sorted |
| a `'` in the query part of a technique's URL (`/mitre/techniques/{id}/atomic-tests` with a `?` and a `'` in the id) | yarl keeps the `'` | `%27`, the url crate's query encoding | a request target no technique has (not compared) |
| `POST /incidents/db_operations/case-report-template/default-template`: which templates, in which order | the files of `backend/app/incidents/templates/` in `Path.iterdir()` order (the file system's), read from disk at every call — so the files stored before a name that exists ends the loop with the 400 depend on that order | the same eight files, compiled in, in name order (an edited template reaches Rust at its next build; a test fails when the compiled list differs from the directory) | Python's order is not reproducible; parity compares the answer's list as a set |
| the default templates' `.docx` content type | `mimetypes.guess_type`: the wordprocessingml type when the host has a `mime.types` file, none without one | always the wordprocessingml type | what Python's image answers (`.html` is in `mimetypes`' own table) |
| `POST /connectors/upload/{connector_identifier}` when this process may not write the backend's data directory (`PermissionDenied`, a read-only mount — the shipped `docker-compose.rust.yml` mounts it `:ro`, the image runs as uid 10001) | — | the request is handed to Python whole: nothing was written yet, and Python's container writes the directory as root | keeps the upload working without widening the Rust container's rights; with the directory writable here, Rust writes it (e2e: `connector_yaml_upload_is_python_s_when_the_directory_is_not_writable`) |
| `GET /incidents/case_templates/suggest?alert_id=` for an alert the caller may not see (another customer's, or tags their RBAC hides) | ranks the templates against it: its customer's scoped templates, tags, MITRE ids, rule groups and title in the reasons | `success: false`, `Alert id=N not found` — the answer of a missing alert | tenant leak |
| `GET /incidents/case_templates/suggest?customer_code=` naming a customer that is not the caller's (no `alert_id`) | ranks that customer's scoped templates and counts its cases | 403 `Access denied to customer … - insufficient customer permissions` | tenant leak |
| `GET /incidents/case_templates/suggest` without a customer, for a scoped caller | the usage history (`Applied to N case(s)`) counts every tenant's cases | counts the caller's customers' cases only (an admin's stays deployment-wide) | cross-tenant aggregate |
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
| `POST /alerts`, `/alerts/host`, `/alerts/hosts/all`, `/alerts/rules/all`, `/alerts/rules/hosts/all`, `/alerts/index`, `/alerts/by-id` for a scoped caller | every managed index is searched: any analyst reads every tenant's Wazuh alerts, and any index or document they name | only the indices named after one of the caller's customers (the `/wazuh_indexer/indices` rule); another tenant's index is the 400 of an unmanaged one, another tenant's alert the not-found answer, without asking the indexer; admins unchanged | tenant leak |
| a snapshot index pattern Python's `re` and Rust's `regex` disagree on (a broken one, a look-around, a back-reference) | `re.error`'s text, or a match | `regex`'s text in `Failed to create snapshot: …` | a different regex engine; the `*` patterns operators write match alike (`re.match(f"^{p}$")` is reproduced, alternations included) |
| the Wazuh manager's token after its connector row changes (URL, user or password) | reused, keyed by the connector name, for up to 10 minutes: sent to a new URL, it is answered 401 and only then replaced | a token is reused only for the row it was issued against: the first call after a change authenticates | a credential is never sent to a host that did not issue it |
| a raw manager answer whose Content-Type names a charset other than UTF-8 or Latin-1, or none for a type that is neither `text/*` nor JSON | that codec, or charset_normalizer's guess | UTF-8, invalid bytes replaced | Wazuh answers in UTF-8 (not provoked) |
| `connectors.connector_last_updated` written by an update or a verification | `datetime.now()`: the process's local time (UTC in the image) | UTC | as the agent healthcheck clock; equal in the shipped image (not provoked) |
| a snapshot schedule's timezone the zone database does not know | `ZoneInfo` on the host: an unknown name falls back to UTC, a malformed key (`../x`) is a `ValueError` and the schedule `FAILED` | the IANA database compiled into chrono-tz: anything it does not know falls back to UTC | as the SOC calendars' row above; names the API accepts read alike (not provoked) |
| a connector call that cannot connect (`/graylog/*`, the Wazuh indexer and manager) | urllib3's text with the address of a Python object (`<urllib3.connection.HTTPConnection object at 0x7f…>`) | the same text with `0x7f0000000000` | the address differs between any two processes; the parity suite masks it |
| `GET /graylog/metrics` when both Graylog calls fail | the error of whichever `asyncio.gather` call failed first (timing) | the `/api/system/metrics` call's error | deterministic; both are sent, as in Python |
| `GET /graylog/event/definitions` against a Graylog that never reaches its own `total` | pages for ever | stops after 20,000 pages | a request cannot hold a worker (not provoked) |
| `/influxdb/*` when InfluxDB answers an error through something other than InfluxDB | aiohttp prints a header it does not know in the case it arrived in | Go's canonical case (`X-Influxdb-Build`; aiohttp's own spelling for the headers it knows) — `http` keeps names lower-cased | identical for InfluxDB, a Go server (not provoked) |
| `/influxdb/*` with a connector host that resolves to several addresses, all refusing | `Multiple exceptions: …` naming each | `Connect call failed` naming the first | one address is the usual case (not provoked) |
| `GET /influxdb/metrics/hosts` when the host tags hold a NaN beside other values | `sorted(set(…))`: NaN hashes by identity, so the set's order changes from one process to the next, and `sorted` never moves a NaN | the order InfluxDB sent, then sorted | Python response artefact; the parity suite accepts either order |
| `/influxdb/*` with an org name holding `'` | `'` sent as is (yarl) | `%27` (the URL crate's query set) | InfluxDB decodes both to the same org (not provoked) |
| `/influxdb/*` when a cell holds a date-time InfluxDB never writes (no offset, a date alone) | `datetime.fromisoformat` reads it (a naive datetime) | `Invalid isoformat string: …` | InfluxDB writes RFC 3339 with `Z` (not provoked) |
| a Grafana `text/*` answer without a charset that is not ASCII | niquests guesses the charset (charset_normalizer) | ISO-8859-1, `requests`' rule | Grafana names its charset (not provoked) |
| `POST /reporting/generate_iframe_links` in a local time zone, in the hour a DST change repeats | `time.mktime` picks per platform | the earlier of the two instants | containers run in UTC (not provoked) |
| the position in a `UnicodeDecodeError` of an InfluxDB answer longer than one network read | relative to the chunk aiohttp was decoding | relative to the body | not provoked |
| the GELF `host` of `POST /graylog/receiver` and `POST /monitoring_alert/provision/testing` when the host name is only in DNS | `socket.getfqdn()` asks DNS for the canonical name | the host name (`/etc/hosts` is read, DNS is not) | equal in a container, where `/etc/hosts` names the host (not provoked) |
| an Event Shipper port that is a service name (`http`) | resolved by `getaddrinfo` | not a port: nothing is sent (still answered as forwarded) | only numeric ports are configured (not provoked) |
| `POST /customer_waf/{code}/{id}/blocks` with a target whose canonical network keeps an IPv6 zone (`fe80::1%eth0`, `2001:db8::1%x",ctl:ruleEngine=Off,"`) | `ipaddress` accepts any text after the `%`, and it reaches the SecLang rule text verbatim — the module's documented injection boundary does not hold | 422 `invalid_target` (`'…' is not an IPv4/IPv6 address or CIDR range`); a zone dropped with the host bits (`fe80::1%eth0/64`) is accepted as in Python | the rule text must come only from a parsed network (`blocks.py`'s own contract) |
| a WAF transport failure other than a timeout, a refused connection or a certificate (`Request to WAF '…' failed: <class>`) | httpx's exception class (`RemoteProtocolError`, `ReadError`, …) | the class httpx raises for the same failure, as far as hyper's error tells it (`RemoteProtocolError` for a connection closed early, `ReadError` for a body cut short) | the class name is all the message carries (not provoked) |
| a CA upload OpenSSL's `d2i_X509` and `x509-cert` disagree on | OpenSSL's verdict | `x509-cert`'s | the two agree on certificates; the vectors cover the shapes operators paste (not provoked) |
| `POST /stack_provisioning/graylog/provision/{fortinet,sonicwall,sentinelone}` | no tenant check on the body's `customer_code`: any analyst provisions content packs, an index set, a Grafana datasource, folder and dashboards for another tenant's network connector | `enforce_customer_access` on it after the body is validated (403), before any tool is asked | tenant leak |
| `POST /{huntress,darktrace,duo,cato,carbonblack,mimecast,sap_siem,socfortress_mdr}/provision` | no tenant check on the body's `customer_code`: any analyst provisions another tenant's integration (its index set, stream, Grafana objects, meta row, `deployed`) | `enforce_customer_access` on it after the body is validated (403), before any lookup | tenant leak |
| `POST /stack_decommissioning/graylog/decommission/network_connector` | no tenant check on the body's `customer_code`: any analyst can tear down another tenant's network connector (its content packs, Grafana folder and datasource, and rows) | `enforce_customer_access` on it after the body is validated (403) | tenant leak |
| the default settings (`GET`, `PUT`, `DELETE /customer_provisioning/default_settings`) and a customer's meta (`GET /customer_provisioning/provision/{customer_code}`) | the table model's keys in the order SQLAlchemy loaded its attributes, which differs between Python processes | the model's declaration order | Python response artefact (the parity suite compares these answers' values) |
| an InfluxDB REST call that fails on the certificate (`INFLUXDB_VERIFY_SSL=true`) | OpenSSL's sentence for the failure | `[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1006)` whatever rustls rejected | rustls does not tell an unknown issuer from a self-signed leaf the way OpenSSL words them (not provoked) |
| a calendar's timezone name (`PUT /soc_management/calendars`) | whatever `zoneinfo` finds on the host: its zoneinfo files, else the `tzdata` package — a host without the backward links refuses `US/Eastern` or `Asia/Calcutta`, and a file such as `localtime` or `posixrules` passes | the IANA database compiled into chrono-tz 0.10: every canonical and backward name, nothing else (422 `Unknown timezone '…'`) | the same names on every host; rules follow chrono-tz's IANA release, not the host's (only the Rust side is asserted, the Python side depends on the host) |
| an exclusion rule's `regex:` value, or an `/incidents/db_operations/available-indices/{source}` pattern, that Python's `re` and Rust's `regex` read differently (a look-around, a back-reference, a possessive quantifier) | `re`'s match, or `re.error` (the rule does not match; the listing is `[]`) | does not compile: the rule does not match, the listing is `[]` | a different regex engine; `$` and `IGNORECASE` behave as in `re`, the patterns operators write match alike (not provoked) |
| an integer beyond 64 bits in a webhook or indexer JSON body (a Sigma `EventRecordID`, a document field) | kept exact | read as the nearest float | the JSON reader is serde_json's, without arbitrary precision; no tool sends one (not provoked) |
| a database error on one alert of a `/create/auto` batch (and of the job) | the session is left in its failed transaction: every later alert of the batch fails too | each alert stands alone | a SQLAlchemy session artefact (not provoked) |
| a customer code that is not a string in a document (`agent_labels_customer: 5`) | compared as SQLAlchemy binds it; a later string operation may raise | the same comparisons; the alert is filed under its text | no pipeline writes one (not provoked) |
| `GET /agents/wazuh/outdated`, `GET /agents/velociraptor/outdated` | any analyst lists every tenant's outdated agents | the caller's customers' only (admins unchanged; an unassigned analyst gets an empty list) | tenant leak |
| the field order of an agent row (every `/agents` answer that carries one) | the order the ORM loaded the attributes in, which follows Python's string hashes: it changes from one process to the next | `Agents`' declaration order | Python response artefact; the parity suite compares rows key by key and checks Rust's order |
| `POST /siem/dashboards/enable` | checks only that the body's customer exists: any analyst enables a dashboard for any tenant, on any tenant's event source | the body's customer and the event source's must be the caller's (403 `Access denied to customer …`) | tenant leak |
| `POST /siem/dashboards/custom`, `POST …/custom/import`, `PUT …/custom/{key}` | a scoped analyst files a template under another tenant (the body's `customer_code`), and an import with `overwrite` replaces another tenant's template | the customer the template is filed under, and for an overwrite the template it replaces, must be the caller's | tenant leak |
| `POST /siem/event_sources`, `PUT /siem/event_sources/{id}` | any analyst creates an event source for any tenant and rewrites any tenant's | the body's customer, and the customer of the source updated, must be the caller's (`Access denied to customer …` / `… to event source {id}`) | tenant leak |
| `POST /threat_intel/ai/analyze-alert`, `POST /threat_intel/ai/wazuh-exclusion-rule` | the alert in `alert_id` is not checked: an analyst sends any tenant's document to SOCFortress AI and comments on any tenant's alert (an unknown id is a 404 after the analysis) | for a scoped caller, `ensure_alert` first (`Access denied to alert {id} - insufficient customer permissions`, or `Alert not found`) — nothing is read or sent; admins unchanged | tenant leak |
| a VirusTotal file or analysis id (`GET /threat_intel/virustotal/file/{id}`, `…/analysis/{id}`) holding a `\` or an encoded dot segment (`%2E%2E`) | httpx sends both as they are (`/api/v3/files/a\b`, `/api/v3/files/%2E%2E`) | the URL type under reqwest (`url`, WHATWG) sends the `\` as `/` and resolves the segment (`/api/v3/files/a/b`, `/api/v3/`) | no Rust HTTP client sends a raw `\`; the id is the analyst's own and the request stays on VirusTotal with the same key (not provoked by the UI) |
| a built-in `library_card` / `template_id` that walks out of `dashboard_templates/` (`../../…`) to another JSON file of the backend | read from disk: enabled (200), its panel data the response model's 400 | only the compiled-in templates exist: 404 (`Dashboard template … not found in category …`, `Dashboard template file not found`) | the Rust image carries no backend files; reading arbitrary JSON by path is not a feature |
| `str()` of a gRPC error in the Velociraptor connection check | grpc-core prints `debug_error_string`'s two keys in hash order, which varies from one error to the next | `grpc_status` first | Python's text is not reproducible; the parity suite orders Python's |
| an `api.config.yaml` that is not YAML | `Unable to parse config file from <path>: ` and PyYAML's description (`while parsing a flow sequence\n  in "<unicode string>", line 1, column 17: …`) | the same opening, then libyaml's (`did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 17`) | PyYAML's parser is not ported; the check fails alike |
| the `grpc-timeout` a Velociraptor call carries | grpc-core's encoding of the time left when the call starts, which its clock usually reads a millisecond over the timeout: 300 s goes as `301S`, 5 s as `5010m` | the same encoding of the timeout itself: `5M`, `5S` (what grpcio sends when its clock reads it exactly) | a clock artefact; the server's deadline differs by under a second (the parity stand-in compares deadlines to the nearest 5 s) |
| a `MINIO_URL` naming Amazon S3 or Aliyun OSS (`*.amazonaws.com`, `*.aliyuncs.com`) | virtual-hosted-style requests, the region taken from the host | every operation refused with a `ValueError` naming the endpoint | CoPilot deploys MinIO; the AWS addressing rules are not ported (not provoked) |
| a bucket name Python's `re.IGNORECASE` matches through a non-ASCII case fold (U+212A, the Kelvin sign, for `k`; U+017F for `s`) | passes the name check; MinIO refuses it | `invalid bucket name …` before any request | only ASCII names exist (not provoked) |
| an S3 answer that is not well-formed XML | expat's `ParseError` text | the same exception, its text close to expat's (`not well-formed (invalid token): line L, column C`) | no S3 server sends one (not provoked) |
| a listing whose server never stops paging | pages for ever | stops after 100,000 pages | a request cannot hold a worker (not provoked) |
| the download's `Range` | the address of the aiohttp session (`0x7f…`) | `0x7f0000000000` | the address differs between any two processes; MinIO ignores the header; the parity suite masks it |
| a multipart upload whose part fails | the parts still running finish (`asyncio.gather`), then the abort | the parts still running are dropped, then the abort | same error, same abort; fewer requests (not provoked) |
| a MinIO answer that times out, or a certificate MinIO's TLS presents that does not verify | aiohttp's and `ssl`'s texts | the same exceptions, texts close to theirs | the libraries' words (not provoked) |
| `GET /sysmon_config` | `list(set)` of the customer codes: an order that follows the strings' hashes and changes from one process to the next | the codes in listing order (S3's key order) | Python response artefact; the parity suite compares them sorted and checks Rust's order |
| `POST /copilot_action/invoke` by a caller without deployment-wide access | the action runs on every agent with the named hostname — another tenant's agent of the same name included, once the first agent of that name is the caller's | the agents of that hostname are narrowed to the caller's customers | tenant leak: a hostname is no tenant key (#1256) |
| `POST /copilot_action/invoke`: the 404 of missing hostnames and the 400s of the parameter checks | `list(set)`: an order that follows the strings' hashes and changes from one process to the next | the names in the order they come (the body's, the action's parameters', `ScriptURL` last) | Python response artefact; the parity suite compares them sorted |
| a CoPilot Action name holding a `\` | httpx sends it as it is | `%5C` (the url crate reads a `\` in an http(s) path as `/`) | the same name to the service; inventory names have none (not provoked) |
| `POST /shuffle/integrations/invoke-workflow` by a caller without deployment-wide access | runs the workflow for whatever `execution_arguments.customer_code` names | 403 `Access denied to customer {code}` unless the code is one of the caller's customers | tenant leak: the body names the tenant |
| `SSL_CERT_FILE` set only in the `.env` file | read: environs' `read_env` puts the file in `os.environ` | not read: the process environment only | compose's `env_file` puts it in the environment (not provoked) |
| `POST /integrations/create_integration`, `/create_integration_meta`, `DELETE /integrations/delete_integration`, `PUT /integrations/update_meta_auto`, `POST /network_connectors/create_network_connector`, `/create_network_connector_meta`, `DELETE /network_connectors/delete_network_connector`, `/delete_network_connector_meta` | any analyst creates, changes and deletes any tenant's integrations, metadata and network connectors (the customer is in the body) | the body's customer is checked against the caller's after the body's validation: `Access denied to customer …` (403) | tenant leak |
| `GET /integrations/customer_integrations`, `/customer_integrations_meta`, `GET /network_connectors/customer_network_connectors`, `/customer_network_connectors_meta` | every tenant's rows, auth keys included | the caller's customers' only (admins unchanged; an unassigned analyst gets an empty list) | tenant leak |
| `GET /integrations/integration_customer/{integration}/{key}/{value}` | names any tenant's customer | another tenant's customer reads as not found (404) | tenant leak (cross-tenant probing by key value) |
| `POST /api/v1/alert_settings/create` (the created row) and `GET /integrations/meta_auto/{code}/{name}` (`data`) | a table model's keys in the order SQLAlchemy loaded its attributes, which differs between Python processes | the model's declaration order | Python response artefact (the parity suite compares the values and checks Rust's order) |
| an Office365 tenant's decommission (`DELETE /integrations/delete_integration`) | also writes the edited `ossec.conf` next to its module (`wazuh_decommission_config.xml`) | writes no copy | the file holds every tenant's client secret, on the Python host; the Rust service has no `backend/` tree |
| `POST /office365/provision` | any analyst provisions any customer's tenant | the body's `customer_code` must be one of the caller's customers (403) | tenant leak |
| `POST /office365/provision` | writes the edited `ossec.conf` next to its module (`wazuh_config.xml`) and reads it back | keeps it in memory, read back as universal newlines would | the file holds every tenant's client secret, on the Python host; the Rust service has no `backend/` tree |
| `POST /office365/provision` failing on a `GrafanaTimeoutError` | `HTTPException(status_code=0)`: uvicorn starts the response, cannot write its status line and closes the connection without an answer | answers 500 with the rolled-back message | Python fails, Rust works |
| `POST /aws/provision`: botocore's `User-Agent` | names the interpreter's patch version (`lang/python#3.11.17`) and lists its `m/` features in a set's order (process-dependent) | `lang/python#3.11`, the features sorted | the Rust process has no interpreter; the parity suite masks both |
| `POST /{crowdstrike,defender_for_endpoint,bitdefender}/provision` | any analyst provisions any customer | the body's `customer_code` must be one of the caller's customers (403) | tenant leak |
| `POST /{crowdstrike,defender_for_endpoint,bitdefender}/provision` with a customer name (spaces made `_`) holding a `/` or a NUL, or `..` | provisions Graylog and Grafana and inserts the meta row, then fails writing the docker-compose file, whose name holds the customer's (`FileNotFoundError`, a bare 500); `..` (or an absolute path) writes the files outside the data directory | 400 `Customer name '<name>' cannot name a directory under the backend's data directory.`, before anything is created | the file paths are built from a stored name; refused rather than guessed |
| `POST /customer_provisioning/provision` | any analyst provisions any customer: the query's customer is only looked up, the body's is the one provisioned | both must be the caller's customers (403; the query's before it is looked up, the body's after it is validated) | tenant leak |
| `POST /customer_provisioning/provision/wazuh_worker` | any analyst provisions any customer's worker | the body's `customer_code` must be one of the caller's customers (403) | tenant leak |
| `POST /aws/provision`: AWS behind a proxy | botocore honours `HTTP(S)_PROXY` / `NO_PROXY` from the environment | AWS is reached directly | not provoked by any deployment CoPilot documents; a proxied deployment reports AWS unreachable (a warning, the deployment goes on) |
| `GET /vulnerabilities/agent/{agent_id}` | any analyst lists any agent's vulnerability rows | the rows of the caller's customers only (another tenant's agent: an empty list, `Retrieved 0 vulnerabilities for agent …`) | tenant leak |
| `POST /vulnerabilities/sync/agent/{agent_name}` | syncs any tenant's host for any analyst (with `?customer_code=` one of theirs, files that host's vulnerabilities under the caller's customer) | the host's tenant checked first (`enforce_hostname_access`, fail-closed: 403 `Access denied to host …`) | tenant leak |
| `GET /syscollector/search/packages` | searches every tenant's packages for any analyst | a scoped caller's search carries a `terms` filter on the agent ids of their customers; with none, an empty answer and no indexer request | tenant leak |
| `GET /sca/packages/registry/{key}/agents` | `matched_agents` and `total` drop other tenants' agents, the `message` counts them (`Found N agent-package combinations for '…'`) | the message counts the caller's agents too | tenant leak (how many of another tenant's hosts run a package) |
| `POST /artifacts/collect`, `/collect/file/agent/{agent_id}` | the download pack is written to a file named after it in the process's working directory, then uploaded and removed: an unwritable directory, or a Velociraptor host name with a `/`, fails the collection, and two collections of one flow share the file | the bytes stay in memory | no file on the Python host (not provoked) |
| an OpenCTI connector without an API key (`Bearer `, which h11 refuses) whose HTTPS URL fails its TLS handshake | `ConnectError` from the handshake | `LocalProtocolError` once TCP connects (the TLS handshake is not attempted) | h11's check reproduced without a second TLS client (not provoked) |
| `/uba/{code}/provision`, `…/rollback` with Graylog objects whose `id` (or, for a recorded or set-up object, `title`) is not a string, or UBA object names (`graylog.sources`' keys, `alerts_input`, a rules file name) that are not strings | the dict and string operations run on whatever came back: some answers work, others end in a `TypeError`, an `AttributeError` or the response model's `ValidationError` | refused as an unsupported answer: the bare 500 (`Failed to roll UBA back` for `POST …/rollback`) | Graylog sends Mongo ids and titles as strings, UBA its names as strings (not provoked) |
| `POST /copilot_searches/backtest`, `POST /copilot_searches/publish`, `POST /copilot_searches/custom-repos/test` | the body's `customer_code` is not checked: an analyst backtests against any tenant's Graylog stream, commits to any tenant's custom repository with its stored write token, and tests a repository with any tenant's stored read token | a non-empty body customer must be one of the caller's (403 `Access denied to customer …`), before anything is sent | tenant leak |
| `GET /copilot_searches/custom-repos` | every tenant's pointer (repository, branch, whether a token is stored, its last fetch status) for any analyst | a scoped caller's customers' only (admins unchanged; an unassigned analyst gets an empty list), the count in `message` theirs | tenant leak |
| a rule YAML (catalog, custom repository or the editor's body) with a lone surrogate escape (`"\ud800"`), a `!!set`, or nested deeper than `copilot_yaml::MAX_DEPTH` | PyYAML keeps the surrogate; a set's order follows string hashes; `RecursionError` at a depth that depends on the caller's stack | U+FFFD; insertion order; `RecursionError` at a fixed depth | a Rust string holds no surrogate, the other two are process artefacts (not provoked) |
| `GET /customer_portal/branding` | any admin or analyst lists every customer's override (code, title, colour, whether it has a logo) | a scoped analyst lists their customers' only (none without an assignment); admins unchanged | tenant leak |
| `PATCH /customer_portal/settings` naming several fields `null` | the 422 names whichever field its `set` iterates first, which follows the process's string hashes | the first in declaration order (`title`, `logo_base64`, `logo_mime_type`, `brand_color`) | Python response artefact |
| the field order of an agent row in `GET /customer_portal/agents` | the order the ORM loaded the attributes in (changes between processes) | `Agents`' declaration order | Python response artefact; the parity suite compares rows key by key and checks Rust's order |
| a gzipped logo or agents CSV (`Accept-Encoding: gzip`, 1000 bytes or more) | zlib's level-9 stream, its `Content-Length` | flate2's level-9 stream: other compressed bytes, so another `Content-Length` | the decoded bytes and every other header are the same (compared); not provoked otherwise |
| `POST /integrations/modules/{huntress,mimecast,duo,cato,sap_siem}`, `POST /mimecast/invoke`, `POST /mimecast/ttp/urls` | any analyst starts a collection with any tenant's stored keys (the customer is in the body) | the body's `customer_code` is checked against the caller's after the body's validation: `Access denied to customer …` (403) | tenant leak |
| `POST /integrations/modules/sap_siem/{analysis}` (the seven analyses) | any analyst sends any `iris_customer_id` to the SAP module | the customers whose metadata carries that IRIS id must all be the caller's; an id no customer carries is refused (403 `Access denied to IRIS customer …`; admins unchanged) | tenant leak: the IRIS id names the tenant |
| `POST /mimecast/invoke` and the `invoke_mimecast_integration` job, once the region discovery answered | before failing (`HttpUrl + str`), create the customer's empty checkpoint file and log directory next to the Python module | write nothing | no file on the Python host; the download that would use them is unreachable (not compared) |
| a module collection whose database read fails inside the route's `try` | `success: false` with SQLAlchemy's exception text | `success: false` with sqlx's text | driver texts (not provoked) |
| `GET /status/sidebar`: the open-alerts indicator of a caller under tag RBAC | customer scoping only: alerts whose tags the caller may not see — and untagged ones under `admin_only` — are counted | through `AlertVisibility` (customer scoping and tag RBAC), the definition every alert list uses | the count named alerts the caller cannot open (the parity suite checks `admin_only` and `visible_to_all`) |
| `GET /status/sidebar`: an `apscheduler_jobs` row APScheduler cannot restore | `get_jobs()` deletes it from the store and leaves it out | listed as a scheduled job and left in the store | a read must not repair APScheduler's store (not provoked) |
| `GET /github-audit/config` | every tenant's configurations (tokens masked) for any analyst; `customer_codes` passed through | `scoped_customer_codes`: a scoped caller's customers only (an unassigned analyst gets an empty list; admins unchanged) | tenant leak |
| `GET`/`PUT /github-audit/config/{id}`, `POST …/audit`, `…/audit/summary`, `POST`/`GET …/exclusions`, `POST`/`GET …/baselines`, `PUT /exclusions/{id}`, `GET /reports/{id}` (the deletes are admin-only, so deployment-wide in both) | no owner check: any analyst reads, changes or audits (with the stored GitHub token) another tenant's object by its id | the object's customer must be one of the caller's, checked where Python resolves the object: 403 `Access denied to GitHub audit configuration …` (`report`, `exclusion`, `baseline`); an id that does not exist is the same 403 for a scoped caller, Python's 404 (or empty list) for an admin | tenant leak; fail closed |
| `POST /github-audit/config` | files a configuration under any customer for any analyst | the body's `customer_code` must be one of the caller's (403 `Access denied to customer …`), after the body's validation | tenant leak |
| `GET /github-audit/reports` | the page is the caller's customers', but `total_count` and the message count every tenant's matching reports | both the caller's customers' | tenant leak (how many audits another tenant ran) |
| `POST /github-audit/config/{id}/baselines` naming another tenant's `baseline_report_id` | copies that report's check results into the caller's baseline | 403 `Access denied to GitHub audit report …` | tenant leak |
| the field order of a GitHub audit configuration, report, exclusion or baseline | the order the ORM loaded the attributes in (changes between processes) | declaration order | Python response artefact; the parity suite compares them key by key and checks Rust's order |
| a GitHub audit in which one repository's checks raise | `asyncio.gather` raises the first error; the batch's other repositories run on until `async with` closes the client, so whether their remaining requests are sent depends on timing | the batch's requests are all sent, then the first error (by completion) is answered | timing artefact: same answer and rows (the parity suite compares those, not that audit's requests) |
| `/api/performance/*` | the Python process: its requests, event-loop lag, statements (`%s` placeholders) and SQLAlchemy pool (`size()` = `pool_size`, with overflow); FastAPI's route templates | the Rust process: every request it serves or proxies, tokio's scheduling delay, sqlx's statements (`?` placeholders) and pool (`size` = `max_connections`, `overflow` 0); axum's templates (`/api/logs/{segment}` where FastAPI names `{user_id}` and `{event_type}`) | each describes its own process; with Rust in front, Rust's is the one the client waits on (the parity suite compares guards, 422s, shapes, units, ordering, the counts after a reset and the reset) |
| `/patch-tuesday` items whose EPSS score or CVSS base is NaN (a feed's `"nan"`) | `list.sort` over keys with NaN in them: no total order, so the result follows timsort's comparisons | a stable sort that takes NaN as equal to every score | the order of the NaN-scored items only; the feeds send numbers (not provoked) |
| `POST /sublime/alert`: the stored alert's `timestamp` | the model's class default `datetime.datetime.now()`, evaluated once when the module is imported: every alert a process stores carries that process's start time | the time the alert arrived (`datetime.now()`, local time) | Python fails, Rust works: the column says when the alert came in |
| `POST /sublime/alert` with a sender or recipient email that is a list holding an empty list before a string (`[[], "a"]`) | MySQL's syntax error quotes the rest of the statement with the string as pymysql escaped it (`near '),'a'), …`) | the string is a bound parameter and is quoted as `?` | no client-side escaping of Sublime's strings into SQL (not provoked) |
| the environment of the `scout` process (`POST /scoutsuite/generate-{aws,azure,gcp}-report`) outside Docker | the backend's `os.environ`, which holds the repository's `.env` (`load_dotenv`) | this process's environment: the binary reads `.env` without exporting it to child processes | `.env`'s secrets (`JWT_SECRET`, `MYSQL_PASSWORD`, …) are not handed to a third-party CLI; under Compose `env_file` puts them into both processes' environment, so the two scans see the same (not provoked) |
| `POST /scoutsuite/generate-gcp-report` when the key cannot be written | the `mkdtemp` directory stays, with whatever was written of the key | the directory is removed before the 400 | no credential left on disk (not provoked) |
| the cloud MCP request (`POST /copilot_mcp/query` for a cloud server, `POST /threat_intel/process_name`) | httpx writes its own header names title-cased and the module's `x-api-key` lower-cased | every name lower-cased (hyper writes one case per request) | header names are case-insensitive; values and order are httpx's (compared lower-cased) |

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
| **3 — done** (what needs the indexer, Graylog, MinIO or a PDF renderer moves with phase 4) | `notifications` (7.2 k) — **done**: `copilot-notifications`, `copilot-markdown`, the bridge retired (in-process `DispatchingSink`); `schedulers` (2.6 k) — APScheduler → tokio, job by job via the `enabled` hand-over; `incidents` (21 k) incl. ingest | ingest then triggers Talon from Rust. Schedulers: the runner, `/api/scheduler` (reads; run/start/pause, forwarding what acts on APScheduler) and the DB-only jobs (`prune_audit_log`, the palace jobs) are ported; the jobs that call connectors (`agent_sync`, `resize_wazuh_index_fields`, `invoke_snapshot_schedules`, the `invoke_*` integrations) and the in-process cache refreshers stay in APScheduler until phase 4; `invoke_alert_creation_collect` moves with incidents, `notify_sla_transitions` with `soc_management`. Incidents so far: `/db_operations` but for its Wazuh-indexer and Shuffle routes, `/case_templates` but the library and `/suggest`, `/tag_access`, the exclusion rules of `/alerts`, the CSV exports of `/report`, the list and visibility switch of `/customer_reports` (`copilot-incidents`, SLA recorder `copilot-sla`, `rust_parity_incidents_e2e.py`); alert creation and the Sigma ingest (with the exclusion draft and dry-run) moved in phase 4, the DOCX/PDF reports and customer report generation for a PDF renderer (the MinIO routes moved in phase 4) |
| 4 | the phase-3 remainder: alert creation and the Sigma ingest (with the exclusion draft and dry-run) and the three indexer reads of `/db_operations` — **done** (`copilot-ingest`, `rust_parity_ingest_e2e.py`) —, the incidents' MinIO routes — **done** (`copilot-objectstore`: case files, report templates, `DELETE /case/{id}`, the customer reports' download and delete, `/api/agent_data_store`; `rust_parity_objectstore_e2e.py`; the default-template upload and the Sysmon config upload in wave 6; `file_analysis` still Python; Velociraptor's collection upload and the agents' report files moved with their modules) — and DOCX/PDF reports, the connector-bound scheduler jobs (`invoke_snapshot_schedules`, `resize_wazuh_index_fields`, `invoke_alert_creation_collect` and `agent_sync` **done**); `agents` (9.8 k) — **done** (`/api/agents`: `copilot-agents` on `copilot-velociraptor`, the `agent_sync` job, `rust_parity_agents_e2e.py`; `/api/vulnerabilities`, `/api/sca` and `/api/syscollector`: `copilot-agent-reports`, `rust_parity_agent_reports_e2e.py`) —, `soc_management` (4.4 k) — **done** but its PDF report (`copilot-soc-management`: dashboard, policies, calendars, the portal's SLA page, `notify_sla_transitions`; `rust_parity_soc_e2e.py`), the rest of `customer_portal` (2.1 k) — **done** (`copilot-customer-portal`: the global settings and branding with their logos and a branding cache each process checks against the tables, the Overview, the dashboard counters, the agents page and CSV, `/me`; `rust_parity_customer_portal_e2e.py`), `customer_waf` — **done** (`copilot-waf`; `rust_parity_provisioning_e2e.py`), the monitoring-alert catalog — **done** (`copilot-monitoring-alerts`: every alert, custom alerts, the Event Shipper test, on both Graylogs; `rust_parity_monitoring_alert_e2e.py`), the response routes — `/api/active_response`, the Graylog webhook, `/api/sysmon_config` (its upload in wave 6) and `/api/copilot_action` **done** (`copilot-response`, `rust_parity_response_e2e.py`) —, the Shuffle connector with the case notification **done** (`copilot-shuffle`, the same suite) —, `siem` (1.7 k) — **done** (`copilot-siem`: dashboards, custom templates, panel data, event sources, the event search; `rust_parity_siem_e2e.py`), `threat_intel` (2.1 k) — **done** (`copilot-threat-intel`: EPSS, SOCFortress intel and AI, the process-name analysis, VirusTotal lookups and file analysis, the licence check; `rust_parity_siem_e2e.py`), `file_analysis`, `customer_provisioning` — **done** (the provisioning itself in waves 5 and 6: `/provision/dashboards` `copilot-grafana-dashboards`, `POST /provision` and `/provision/wazuh_worker` `copilot-integration-provisioning`, `rust_parity_remaining_provisioning_e2e.py`), `stack_provisioning` — **done** (`copilot-provisioning`; the Fortinet / SonicWall / SentinelOne provisioning in wave 5: `copilot-integration-provisioning`, `rust_parity_grafana_provisioning_e2e.py`), then `connectors` (29.6 k: Wazuh — the connector reads, the cross-process cache check, the indexer, the manager routes the UI uses and the two indexer jobs **done** (`copilot-connectors`, `copilot-wazuh`) —, Graylog, Velociraptor — `/api/artifacts` with its two MinIO collections and `/api/flows` **done** (`copilot-velociraptor`) —, …) and `integrations` (37.5 k), one vendor at a time — **Graylog, InfluxDB, Grafana and Portainer done** (`copilot-graylog`, `copilot-influxdb`, `copilot-grafana`, `copilot-portainer` on `copilot-upstream`, `rust_parity_graylog_e2e.py`; Grafana's PDF report still Python, Portainer's stack creation **done** in wave 6 with the customer provisioning; the dashboard provisioning — `POST /api/grafana/dashboards`, `POST /api/customer_provisioning/provision/dashboards` — **done** in wave 5: `copilot-grafana-dashboards`, the templates compiled in from `backend/`, `rust_parity_grafana_provisioning_e2e.py`); the integrations core — `/api/integrations` but `/modules/*`, the alert creation settings and `/api/network_connectors` — **done** (`copilot-integrations`, `rust_parity_integrations_e2e.py`; the delete of a deployed AWS instance moved with AWS provisioning in wave 6), the integrations' provisioning — **done** in wave 5 but CrowdStrike, Defender for Endpoint, Bitdefender, Office365 and AWS (`copilot-integration-provisioning`, the scheduler jobs handed to Python; `rust_parity_grafana_provisioning_e2e.py`); Office365's and AWS's, with the delete of a deployed AWS instance — **done** in wave 6 (`copilot-cloud-provisioning`, `rust_parity_remaining_provisioning_e2e.py`); CrowdStrike's, Defender for Endpoint's and Bitdefender's, their collectors' files included — **done** in wave 6 (`copilot-integration-provisioning`'s `collectors.rs`, the same suite); OpenCTI and Cortex — **done** (`copilot-intel-connectors`, `rust_parity_intel_connectors_e2e.py`); the integration modules — `/api/integrations/modules/*` (Huntress, Mimecast, Duo, Cato, SAP SIEM and its analyses), Mimecast's `/invoke` and `/ttp/urls` and the collection jobs but Cato's — **done** (`copilot-integration-modules`, `rust_parity_integration_modules_e2e.py`; Mimecast and SAP SIEM provisioning still Python); Sublime — **done** in wave 6 (its tables created by migration `d6c01a2b3c4d`; `copilot-sublime`, `rust_parity_ext_tools_e2e.py`); ScoutSuite — **done** in wave 6 but the static `/scoutsuite-report` mount (`copilot-scoutsuite`, the CLI in the Rust image, the reports a shared volume; `rust_parity_ext_tools_e2e.py`); the SOCFortress UBA connector — `/api/uba`, setup, mode and rollback included — **done** (`copilot-uba`, `rust_parity_uba_e2e.py`); `integrations/copilot_searches` (the Detections Catalog, 7.7 k) — **done** (`copilot-searches` on `copilot-yaml`, `rust_parity_catalog_e2e.py`; its caches refreshed by each process for itself); the GitHub organization audit and the Nuclei scans — `/api/github-audit`, `/api/nuclei` — **done** (`copilot-assessments`, `rust_parity_github_audit_e2e.py`; no scheduled audits exist to port: `auto_audit_enabled` and `audit_schedule_cron` are stored only); the platform's own surfaces — `/api/logs`, `/api/license` (the licence check shared with `threat_intel`), `status/sidebar` and `/api/performance` (reporting the Rust process) — **done** (`copilot-status`, `copilot-license`, `rust_parity_platform_e2e.py`); Microsoft Patch Tuesday — **done** in wave 6 (`copilot-patch-tuesday`, `rust_parity_ext_tools_e2e.py`); CoPilot MCP — **done** in wave 6 (`copilot-mcp` on `copilot-threat-intel`'s query, the same suite); `POST /healthcheck/logs` once the connectors it reads are ported (**done** in wave 6, below); the core leftovers (wave 6) — the customer writes (`copilot-customers`) **done**, the Wazuh rule switches, the exclusion and the Atomic Red Team listings (`copilot-wazuh-rules`) **done**, `POST /api/healthcheck/logs` and `GET /api/carbonblack/test` **done** (`GET /api/graylog/pipelines` was already `copilot-graylog`'s) (`rust_parity_core_leftovers_e2e.py`), the uploads — the connector YAML file (`copilot-connectors`; Python's when the data directory is not writable here), the default case report templates (`copilot-incidents`) and the Sysmon config (`copilot-response`, on an expat-exact parser) — **done** (`rust_parity_core_leftovers_e2e.py` section 4, `rust_parity_objectstore_e2e.py`), the case-template library and `/suggest` (`copilot-case-templates`) **done** (`rust_parity_core_leftovers_e2e.py` section 5) | largest surface; each is independent |
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
