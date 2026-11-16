#!/usr/bin/env bash
# devtest.sh — one-shot full test run (real PostgreSQL): Docker starts PG -> fresh pojun_ci database ->
# POJUN_PG_DSN=... go test -p 1 ./... -count=1.
#
# Why a fresh database is mandatory: tests contain fixed-name fixtures (unique keys); running multiple rounds
# against a shared database collides on those keys and produces false failures.
# Why -p 1: cross-package parallelism deadlocks (AGENTS.md §1).
#
# Usage:
#   ./scripts/devtest.sh                                # full run (creates a new pojun_ci by default)
#   ./scripts/devtest.sh ./agent/ -run TestGraphOverview
#   SKIP_FRESH=1 ./scripts/devtest.sh ./server/         # reuse the existing database (fast iteration, may produce false failures)
set -euo pipefail
cd "$(dirname "$0")/.."

CONTAINER=pojun-devtest-pg
PORT=15432
DSN="postgres://pojun:pojuntest@127.0.0.1:${PORT}/pojun_ci?sslmode=disable"

fail() { echo "[devtest] $*" >&2; exit 1; }

# 1) Docker availability
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 \
  || fail "Docker unavailable (a local Docker Desktop/daemon must be running). Alternatively start a database by hand and set POJUN_PG_DSN to run go test directly."

# 2) Container: absent -> create; present but stopped -> start; running -> reuse
if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "[devtest] creating container $CONTAINER (postgres:16-alpine :$PORT)"
  docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=pojuntest -e POSTGRES_USER=pojun \
    -e POSTGRES_DB=pojun -p "${PORT}:5432" postgres:16-alpine >/dev/null \
    || fail "docker run failed"
elif [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]; then
  echo "[devtest] starting the existing container $CONTAINER"
  docker start "$CONTAINER" >/dev/null || fail "docker start failed"
fi

# 3) Wait for PG to be ready (bounded polling, no sleep guessing)
ready=0
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" pg_isready -U pojun -d pojun >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || fail "PG still not ready after 30 polls (check docker logs $CONTAINER for the reason)"

# 4) Fresh database (default) -- kill lingering connections before DROP, otherwise the drop is blocked by them
if [ "${SKIP_FRESH:-0}" != "1" ]; then
  echo "[devtest] recreating pojun_ci (fresh database)"
  docker exec "$CONTAINER" psql -U pojun -d postgres -q \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='pojun_ci'" >/dev/null
  docker exec "$CONTAINER" psql -U pojun -d postgres -q -c "DROP DATABASE IF EXISTS pojun_ci" >/dev/null
  docker exec "$CONTAINER" psql -U pojun -d postgres -q -c "CREATE DATABASE pojun_ci OWNER pojun" >/dev/null \
    || fail "recreating pojun_ci failed"
fi

# 5) Run tests (package/args passed through; defaults to a full run)
PKGS=("$@")
if [ ${#PKGS[@]} -eq 0 ]; then PKGS=(./...); fi
echo "[devtest] go test -p 1 ${PKGS[*]} -count=1  (DSN=pojun_ci@127.0.0.1:$PORT)"
POJUN_PG_DSN="$DSN" go test -p 1 "${PKGS[@]}" -count=1
