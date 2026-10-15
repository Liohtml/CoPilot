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

cargo build -q -p copilot
env -i PATH="$PATH" HOME="$HOME" \
  COPILOT_DATABASE_URL="mysql://${MYSQL_USER}:${MYSQL_PASSWORD}@${MYSQL_URL}/copilot" \
  JWT_SECRET="$JWT_SECRET" COPILOT_BIND=127.0.0.1 COPILOT_PORT="$PORT" \
  RUST_LOG="${RUST_LOG:-warn}" ./target/debug/copilot --root /nonexistent serve &
RS_PID=$!
trap 'kill $RS_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${PORT}/_copilot/health" >/dev/null 2>&1 && break
  sleep 0.2
done

cd backend
MYSQL_URL="$MYSQL_URL" MYSQL_USER="$MYSQL_USER" MYSQL_PASSWORD="$MYSQL_PASSWORD" \
  MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-unused}" JWT_SECRET="$JWT_SECRET" \
  RUST_BASE_URL="http://127.0.0.1:${PORT}" PYTHONPATH="$PWD" \
  "${PYTHON_ABS:-$OLDPWD/$PYTHON}" tests/e2e/rust_parity_e2e.py
