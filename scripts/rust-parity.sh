#!/usr/bin/env bash
# Parity check: the Rust service vs. the Python routers, same disposable MySQL.
#
#   MYSQL on 127.0.0.1:13306, migrated to the Alembic head (see
#   backend/tests/e2e/analyst_object_scoping_e2e.py), then:
#
#   MYSQL_USER=copilot MYSQL_PASSWORD=... scripts/rust-parity.sh
#
# Builds `copilot`, starts it on 127.0.0.1:5199 without a legacy backend, runs
# backend/tests/e2e/rust_parity_e2e.py against both, and stops it again.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${MYSQL_URL:=127.0.0.1:13306}"
: "${MYSQL_USER:=copilot}"
: "${MYSQL_PASSWORD:?set MYSQL_PASSWORD}"
: "${JWT_SECRET:=e2e-test-secret-not-the-default}"
: "${PYTHON:=backend/.venv/bin/python}"
PORT="${RUST_PARITY_PORT:-5199}"
# The harness serves a GitHub "latest release" stand-in here for /api/version/check.
RELEASE_STUB_PORT="${RELEASE_STUB_PORT:-5198}"
# ... and an identity-provider stand-in here for the SSO flows (COPILOT_SSO_IDP_URL).
IDP_STUB_PORT="${IDP_STUB_PORT:-5197}"
# ... and an SMTP server stand-in here for the temporary-password email.
SMTP_STUB_PORT="${SMTP_STUB_PORT:-5196}"
# ... and an api.first.org stand-in here for the EPSS column of the CSV exports.
EPSS_STUB_PORT="${EPSS_STUB_PORT:-5732}"
# Both backends read these two.
: "${GRAFANA_API_HEADER_VALUE:=parity-grafana-header}"
: "${VELOCIRAPTOR_QUERY_TIMEOUT:=5}"

cargo build -q -p copilot
env -i PATH="$PATH" HOME="$HOME" \
  COPILOT_DATABASE_URL="mysql://${MYSQL_USER}:${MYSQL_PASSWORD}@${MYSQL_URL}/copilot" \
  JWT_SECRET="$JWT_SECRET" COPILOT_BIND=127.0.0.1 COPILOT_PORT="$PORT" \
  COPILOT_CATALOG_REFRESH=false \
  WEBAUTHN_ORIGINS=http://localhost:5173 WEBAUTHN_RP_ID=localhost \
  COPILOT_SSO_IDP_URL="http://127.0.0.1:${IDP_STUB_PORT}" \
  SMTP_HOST=127.0.0.1 SMTP_PORT="$SMTP_STUB_PORT" SMTP_USE_TLS=false SMTP_FROM=copilot@parity.test \
  COPILOT_URL=https://copilot.parity.test/ \
  COPILOT_VERSION_CHECK_URL="http://127.0.0.1:${RELEASE_STUB_PORT}/releases/latest" \
  COPILOT_EPSS_URL="http://127.0.0.1:${EPSS_STUB_PORT}/data/v1/epss" \
  GRAFANA_API_HEADER_VALUE="$GRAFANA_API_HEADER_VALUE" VELOCIRAPTOR_QUERY_TIMEOUT="$VELOCIRAPTOR_QUERY_TIMEOUT" \
  RUST_LOG="${RUST_LOG:-warn}" ./target/debug/copilot --root /nonexistent serve &
RS_PID=$!
trap 'kill $RS_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${PORT}/_copilot/health" >/dev/null 2>&1 && break
  sleep 0.2
done

# Every suite (`rust_parity_e2e.py`, then one `rust_parity_<module>_e2e.py` per
# ported module), or only those named in PARITY_SUITES.
PY="${PYTHON_ABS:-$PWD/$PYTHON}"
cd backend
shopt -s nullglob
module_suites=(tests/e2e/rust_parity_*_e2e.py)
suites="${PARITY_SUITES:-tests/e2e/rust_parity_e2e.py ${module_suites[*]}}"
status=0
for suite in $suites; do
  echo "=== $suite"
  MYSQL_URL="$MYSQL_URL" MYSQL_USER="$MYSQL_USER" MYSQL_PASSWORD="$MYSQL_PASSWORD" \
    MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-unused}" JWT_SECRET="$JWT_SECRET" \
    RUST_BASE_URL="http://127.0.0.1:${PORT}" RELEASE_STUB_PORT="$RELEASE_STUB_PORT" IDP_STUB_PORT="$IDP_STUB_PORT" \
    SMTP_STUB_PORT="$SMTP_STUB_PORT" EPSS_STUB_PORT="$EPSS_STUB_PORT" GRAFANA_API_HEADER_VALUE="$GRAFANA_API_HEADER_VALUE" \
    VELOCIRAPTOR_QUERY_TIMEOUT="$VELOCIRAPTOR_QUERY_TIMEOUT" PYTHONPATH="$PWD" \
    "$PY" "$suite" || status=1
done
exit $status
