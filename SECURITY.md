# Security policy

This document covers [Liohtml/CoPilot](https://github.com/Liohtml/CoPilot), the Rust port of SOCFortress CoPilot. It is the private channel for a vulnerability in **this** tree. Do not file one as a public issue, pull request, or chat message.

## Supported lines

Security fixes for this port land on the **`main`** branch. There is no separate long-term support branch.

The version the application reports (`CURRENT_VERSION` in `crates/copilot-platform/src/version.rs`, `0.1.98` at the time of writing) is the upstream SOCFortress release this tree is built from. It is not a support promise for older upstream tags or for older commits of this repository. Run current `main`.

| Line | Security fixes from this repository |
| --- | --- |
| `main` | Yes |
| Any other branch, tag, or older commit | No |

## Scope

**Report here** (this port):

- The Rust backend under `crates/` (the `copilot` binary and the image built from `crates/copilot/Dockerfile`).
- Deployment files in this repository: `docker-compose.yml`, `docker-compose.rust.yml`, `docker-compose.legacy.yml`, `.env.example`, and `inspector-runner/docker-compose.fragment.yml`.
- Scripts and defaults shipped here that change who can reach customer data, incident data, or connector credentials.

**Report upstream, not here:**

- The Vue frontends (`frontend/`, `customer-portal/`) and the published images `ghcr.io/socfortress/copilot-frontend` and `ghcr.io/socfortress/copilot-customer-portal`. Those components are SOCFortress's. Use [socfortress/CoPilot](https://github.com/socfortress/CoPilot).
- The Python tree under `backend/` is the upstream reference kept for parity tests and rollback. A flaw that exists because this port's Rust code mishandles a request is in scope here. A flaw in the upstream Python application, in a SOCFortress image, or in behavior this port reproduces on purpose from upstream, belongs with SOCFortress.
- Wazuh, Graylog, Velociraptor, Grafana, InfluxDB, MinIO, MySQL, Nuclei, and the other products CoPilot connects to.
- A deployment's own secrets, TLS certificates, reverse proxy, or host configuration, except where a default file in this repository publishes a service or ships a default credential.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

<https://github.com/Liohtml/CoPilot/security/advisories/new>

Include:

- What is affected (component, commit or version string, and whether a default Compose install is enough).
- What an attacker gains, and what they must already be able to do.
- Steps or a proof of concept that reproduces it. Describe customer or incident data; do not attach a live export.
- Whether you want to be credited.

A repository admin has to enable **Private vulnerability reporting** (Settings → Code security and analysis) before that form accepts a report. If the page says the feature is turned off, do not switch to a public issue. There is no separate mailbox or PGP key for this port. The address on the SOCFortress site is for that project, not for vulnerabilities in this tree.

## What happens next

- We acknowledge a report within **3 business days**.
- We send a further update at least every **7 days** while it is open.
- If we accept it, we fix it on `main` and coordinate what becomes public. We credit the reporter in the GitHub advisory unless they ask not to be named.
- If we decline it, we say why: out of scope (see above), not reproducible, or not a vulnerability in this port.
