# CoPilot backend, Rust (ghcr.io/socfortress/copilot-rs)
#
# Build with the REPOSITORY ROOT as context (same convention as Talon's
# container/Dockerfile):
#
#   docker build -f crates/copilot/Dockerfile -t copilot-rs:latest .
#
# The context is filtered by crates/copilot/Dockerfile.dockerignore (allowlist:
# only the Cargo workspace and the backend templates the binary embeds — never
# .env, data/, the rest of backend/ or target/; scripts/check-compose.py fails
# when an embedded file is not copied below or not allowed there).
#
# Runtime: debian:bookworm-slim, non-root (uid 10001), one static-ish binary
# (and the ScoutSuite CLI its scans run, wkhtmltopdf and the Chromium headless
# shell the reports print with). docker-compose.yml runs it as copilot-backend:
# it listens on :5000 (COPILOT_PORT) and reads the environment .env documents
# (.env.example; the same variables the Python backend read). Size budget:
# 2560 MiB uncompressed per architecture (checked by .github/workflows/docker.yml;
# ScoutSuite's venv is about 1 GiB of it). See docs/architecture/DEPLOYMENT.md.

ARG RUST_IMAGE=rust:1-bookworm
ARG DEBIAN_IMAGE=debian:bookworm-slim

# hadolint ignore=DL3006
FROM ${RUST_IMAGE} AS rust-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml clippy.toml ./
COPY crates ./crates
# copilot-grafana-dashboards' build.rs embeds the templates from the Python
# backend's tree (one source until Python is retired), as
# copilot-integration-provisioning embeds the collectors' file templates, the
# Wazuh agent-group configurations and the Portainer worker stack.
COPY backend/app/connectors/grafana/dashboards ./backend/app/connectors/grafana/dashboards
COPY backend/app/integrations/crowdstrike/templates ./backend/app/integrations/crowdstrike/templates
COPY backend/app/integrations/defender_for_endpoint/templates ./backend/app/integrations/defender_for_endpoint/templates
COPY backend/app/integrations/bitdefender/templates ./backend/app/integrations/bitdefender/templates
COPY backend/app/customer_provisioning/templates ./backend/app/customer_provisioning/templates
COPY backend/app/connectors/portainer/templates ./backend/app/connectors/portainer/templates
# copilot-incidents compiles in the default case report templates;
# copilot-reports these, the SOC operations report's and the Grafana report's.
COPY backend/app/incidents/templates ./backend/app/incidents/templates
COPY backend/app/soc_management/templates ./backend/app/soc_management/templates
COPY backend/app/connectors/grafana/reporting ./backend/app/connectors/grafana/reporting
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    cargo build --release --locked --bin copilot; \
    install -D -m 0755 target/release/copilot /out/copilot

# hadolint ignore=DL3006
FROM ${DEBIAN_IMAGE} AS runtime
# The ScoutSuite CLI the /api/scoutsuite scans run (copilot-scoutsuite), pinned
# to the backend's requirements.txt (scoutsuite==5.9.1), in a venv of its own on
# the image's Python 3.11 (built with the compilers the backend image has, which
# are removed again); `scout` on PATH, as subprocess finds it in Python.
# /opt/copilot/backend is the scans' working directory (COPILOT_SCOUTSUITE_DIR in
# docker-compose.yml): its scoutsuite-report/ is the reports volume, served
# under /scoutsuite-report; Docker gives an empty volume the owner of the
# directory it is mounted on, here the copilot user. data/ is the bind-mounted
# data directory (copilot-backend-init hands an existing one to this user).
ARG SCOUTSUITE_VERSION=5.9.1
# Debian's packages are not pinned (as in the Python backend's image): bookworm's
# security updates land at every rebuild.
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl tzdata python3 python3-venv; \
    apt-get install -y --no-install-recommends build-essential python3-dev; \
    python3 -m venv /opt/scoutsuite; \
    /opt/scoutsuite/bin/pip install --no-cache-dir "scoutsuite==${SCOUTSUITE_VERSION}"; \
    ln -s /opt/scoutsuite/bin/scout /usr/local/bin/scout; \
    apt-get purge -y --auto-remove build-essential python3-dev; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin copilot; \
    install -d -o copilot -g copilot -m 0755 /opt/copilot/backend/scoutsuite-report \
        /opt/copilot/backend/data
# The reports (copilot-reports): wkhtmltopdf as the Python image installs it
# (pdfkit's binary: the case, customer, SOC and File Analysis PDFs, run from
# /usr/bin as pdfkit does), DejaVu Sans for the
# charts the binary draws, and the Chromium headless shell the Grafana report
# drives — the build Python's Playwright (requirements.txt: 1.59.0) runs,
# installed with its system libraries by Playwright's own CLI from a throwaway
# venv into PLAYWRIGHT_BROWSERS_PATH, where the binary looks for it.
ARG PLAYWRIGHT_VERSION=1.59.0
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends wkhtmltopdf fonts-dejavu-core; \
    python3 -m venv /tmp/playwright; \
    /tmp/playwright/bin/pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}"; \
    /tmp/playwright/bin/playwright install --with-deps --only-shell chromium; \
    rm -rf /tmp/playwright /var/lib/apt/lists/*; \
    chmod -R a+rX "${PLAYWRIGHT_BROWSERS_PATH}"
COPY --from=rust-builder /out/copilot /usr/local/bin/copilot
# The SOCFortress licence server's key, carried by the image exactly as the
# Python backend's image carries it (docker.yml passes the same secret to both):
# without it every licence check is sent `x-api-key: None` and the licensed
# features stay off. An operator's COPILOT_API_KEY in .env overrides it.
ARG COPILOT_API_KEY
ENV COPILOT_API_KEY=${COPILOT_API_KEY}
USER copilot
WORKDIR /tmp
ENV COPILOT_BIND=0.0.0.0 COPILOT_PORT=5000
EXPOSE 5000
# 503 while MySQL is unreachable. The first start of a new deployment applies the
# schema and seeds the catalogs before it listens, hence the long start period.
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/_copilot/health || exit 1
ENTRYPOINT ["/usr/local/bin/copilot", "--root", "/nonexistent"]
CMD ["serve"]
