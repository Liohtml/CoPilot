# CoPilot backend, Rust (ghcr.io/socfortress/copilot-rs)
#
# Build with the REPOSITORY ROOT as context (same convention as Talon's
# container/Dockerfile):
#
#   docker build -f crates/copilot/Dockerfile -t copilot-rs:latest .
#
# The context is filtered by crates/copilot/Dockerfile.dockerignore (allowlist:
# only the Cargo workspace and the Grafana dashboard templates the binary
# embeds — never .env, data/, the rest of backend/ or target/).
#
# Runtime: debian:bookworm-slim, non-root, one static-ish binary (and the
# ScoutSuite CLI its scans run). The service
# listens on :5000 (COPILOT_PORT) and reads the same environment as the
# Python backend (MYSQL_*, JWT_SECRET, …); see docs/architecture/RUST_MIGRATION.md.

ARG RUST_IMAGE=rust:1-bookworm
ARG DEBIAN_IMAGE=debian:bookworm-slim

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
# copilot-incidents compiles in the default case report templates.
COPY backend/app/incidents/templates ./backend/app/incidents/templates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    cargo build --release --locked --bin copilot; \
    install -D -m 0755 target/release/copilot /out/copilot

FROM ${DEBIAN_IMAGE} AS runtime
# The ScoutSuite CLI the /api/scoutsuite scans run (copilot-scoutsuite), pinned
# to the backend's requirements.txt (scoutsuite==5.9.1), in a venv of its own on
# the image's Python 3.11 (built with the compilers the backend image has, which
# are removed again); `scout` on PATH, as subprocess finds it in Python.
# /opt/copilot/backend is the scans' working directory (COPILOT_SCOUTSUITE_DIR in
# docker-compose.rust.yml): its scoutsuite-report/ is the volume shared with the
# Python backend, which serves the reports; Docker gives an empty volume the
# owner of the directory it is mounted on, here the copilot user.
ARG SCOUTSUITE_VERSION=5.9.1
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
    install -d -o copilot -g copilot -m 0755 /opt/copilot/backend/scoutsuite-report
COPY --from=rust-builder /out/copilot /usr/local/bin/copilot
USER copilot
WORKDIR /tmp
ENV COPILOT_BIND=0.0.0.0 COPILOT_PORT=5000
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/_copilot/health || exit 1
ENTRYPOINT ["/usr/local/bin/copilot", "--root", "/nonexistent"]
CMD ["serve"]
