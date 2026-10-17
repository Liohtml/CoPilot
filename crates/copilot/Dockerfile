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
# Runtime: debian:bookworm-slim, non-root, one static-ish binary. The service
# listens on :5000 (COPILOT_PORT) and reads the same environment as the
# Python backend (MYSQL_*, JWT_SECRET, …); see docs/architecture/RUST_MIGRATION.md.

ARG RUST_IMAGE=rust:1-bookworm
ARG DEBIAN_IMAGE=debian:bookworm-slim

FROM ${RUST_IMAGE} AS rust-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml clippy.toml ./
COPY crates ./crates
# copilot-grafana-dashboards' build.rs embeds the templates from the Python
# backend's tree (one source until Python is retired).
COPY backend/app/connectors/grafana/dashboards ./backend/app/connectors/grafana/dashboards
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    cargo build --release --locked --bin copilot; \
    install -D -m 0755 target/release/copilot /out/copilot

FROM ${DEBIAN_IMAGE} AS runtime
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl tzdata; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin copilot
COPY --from=rust-builder /out/copilot /usr/local/bin/copilot
USER copilot
WORKDIR /tmp
ENV COPILOT_BIND=0.0.0.0 COPILOT_PORT=5000
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/_copilot/health || exit 1
ENTRYPOINT ["/usr/local/bin/copilot", "--root", "/nonexistent"]
CMD ["serve"]
