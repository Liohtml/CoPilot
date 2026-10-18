<h1 align="center">

<a href="https://www.socfortress.co"><img src="frontend/src/assets/images/socfortress_logo_default_dark.svg" width="300" height="200"></a>

SOCFortress CoPilot

[![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://socfortress.medium.com/)
[![YouTube](https://img.shields.io/badge/YouTube-26K%2B%20Subscribers-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://www.youtube.com/@taylorwalton_socfortress?sub_confirmation=1)
[![Discord Shield](https://discordapp.com/api/guilds/871419379999469568/widget.png?style=shield)](https://discord.gg/UN3pNBzaEQ)
[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/taylorwalton)

[![Get in Touch](https://img.shields.io/badge/📧%20Get%20in%20Touch-Friendly%20Support%20Awaits!-blue?style=for-the-badge)](https://www.socfortress.co/contact_form.html)

</h1>

<h4 align="center">

[SOCFortress CoPilot](https://www.socfortress.co) focuses on providing a single pane of glass for all your security operations needs. Simplify your open source security stack with a single platform focused on making open source security tools easier to use and more accessible.

![demo_timeline](frontend/src/assets/images/copilot_gif.gif)

## Table of contents

- [Getting Started](#getting-started)
  - [Install / Upgrade](#install--upgrade)
  - [The Rust backend](#the-rust-backend)
- [Connectors](#connectors)
- [Help](#help)
- [License](#license)
- [Sponsoring](#sponsoring)

## Getting started

📚 **Documentation:** https://docs.socfortress.co

CoPilot's true power comes from the ability to integrate with your existing security stack. We have built-in integrations with the following tools:

- [Wazuh](https://wazuh.com/)
- [Graylog](https://www.graylog.org/)
- [Velociraptor](https://docs.velociraptor.app/)
- [Grafana](https://grafana.com/)
- [InfluxDB](https://www.influxdata.com/)

❗️ **Note:** CoPilot is currently in beta. We are actively working on adding more integrations and features. If you have any suggestions or feedback, please let us know!

### Install / Upgrade

All install + upgrade instructions live in the docs site (so the README doesn’t drift):

- **Docs home:** https://docs.socfortress.co
- **Install / Upgrade:** https://docs.socfortress.co/getting-started/install-upgrade
- (Source file) [`docs/getting-started/install-upgrade.mdx`](docs/getting-started/install-upgrade.mdx)

Quick upgrade reminder (from your CoPilot directory):

```bash
docker compose pull
docker compose up -d
```

### The Rust backend

CoPilot's backend is a Rust service (`crates/`, image `ghcr.io/socfortress/copilot-rs`), still `copilot-backend` on port 5000 in `docker-compose.yml`: the same API, the same database, the same tokens. It runs the schema migrations, the startup tasks and the scheduled jobs that the Python backend (`backend/`) used to run; the Python backend stays in the repository as the reference implementation the parity tests compare against, and as an opt-in Compose profile for a rollback.

- **Run / upgrade / roll back:** [`docs/getting-started/rust-backend.md`](docs/getting-started/rust-backend.md). Upgrading a deployment whose database predates the last Python schema takes one extra step (the last Python release runs once).
- **What changed for operators:** the same page, and the [differences by design](docs/architecture/RUST_MIGRATION.md#4-differences-by-design) — most of them close tenant leaks.
- **Layouts:** `docker compose up -d` (Rust alone) · `--profile legacy` (the Python backend as a standby) · `-f docker-compose.rust.yml` (staged rollout: Rust in front of Python) · `-f docker-compose.legacy.yml` (rollback: Python in Rust's place). See [`docs/architecture/DEPLOYMENT.md`](docs/architecture/DEPLOYMENT.md).
- **Check a deployment:** `docker compose exec copilot-backend copilot doctor`.

## Connectors

CoPilot is designed to be a single pane of glass for your security operations. Think of it as a hub for all your security tools. CoPilot Connectors are the glue that binds your security tools to CoPilot. We take advantage of the APIs and webhooks provided by your security tools to provide a seamless integration.

## Help

You can reach us on [Discord](https://discord.gg/UN3pNBzaEQ) or by [📧](mailto:info@socfortress.co) if you have any question, issue or idea!

Check out our full video tutorial series on [![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://www.youtube.com/watch?v=qQbex2zAhWI&list=PLB6hQ_WpB6U0e5oSLXJMcxmSzz7n3zvD-&ab_channel=TaylorWalton)

## License

The contents of this repository is available under [AGPL-3.0 license](LICENSE.txt).

## Sponsoring

If you like this project and want to support it, you can consider becoming a sponsor to help us continue maintaining it and adding new features.

[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/taylorwalton)
