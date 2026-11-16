#!/usr/bin/env bash
# Dev mode: run the backend (:8787) + traffic proxy (:8788) together with the
# frontend `next dev` (:5173).
# The frontend reverse-proxies /api to the backend; Ctrl-C stops everything.
#
# For the single-binary mode (embedded frontend) see the "single binary" section
# of the README — that flow does not use this script.
set -euo pipefail
cd "$(dirname "$0")"

# On exit, kill every child process in this process group (backend + frontend).
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Backend (plain `go run`, no embedded frontend); the concurrent worker-agent
# count is configured under "System Settings".
go run ./cmd/pojun -addr :8787 -proxy 127.0.0.1:8788 &

# Frontend hot reload (Vite/Next dev server; /api is proxied to :8787).
( cd web && npm run dev ) &

echo "[dev] backend :8787 / proxy :8788 / frontend http://localhost:5173  (Ctrl-C to quit)"
wait
