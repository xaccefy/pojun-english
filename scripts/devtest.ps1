#!/usr/bin/env pwsh
# devtest.ps1 — one-shot full test run (real PostgreSQL): Docker starts PG -> fresh artex_ci database ->
# ARTEX_PG_DSN=... go test -p 1 ./... -count=1.
#
# Why a fresh database is mandatory: tests contain fixed-name fixtures (unique keys); running multiple rounds
# against a shared database collides on those keys and produces false failures.
# Why -p 1: cross-package parallelism deadlocks (AGENTS.md §1).
#
# Usage:
#   .\scripts\devtest.ps1                      # full run (creates a new artex_ci by default)
#   .\scripts\devtest.ps1 -Run TestGraphOverview -Packages ./agent/
#   .\scripts\devtest.ps1 -SkipFresh           # reuse the existing database (fast iteration, may produce false failures)
param(
    [switch]$SkipFresh,
    [string[]]$Packages = @("./..."),
    [string]$Run = ""
)
# Note: in Windows PowerShell 5.1 a native command writing to stderr becomes a NativeCommandError, which
# combined with ErrorActionPreference=Stop terminates the script outright -- docker/psql routinely write normal
# notices to stderr. So native calls all go through cmd /c + $LASTEXITCODE checks rather than exceptions.
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")

$Container = "artex-devtest-pg"
$Port = 15432
$Dsn = "postgres://artex:artextest@127.0.0.1:$Port/artex_ci?sslmode=disable"

function Fail($msg) { Write-Host "[devtest] $msg" -ForegroundColor Red; exit 1 }

# 1) Docker availability
docker version --format '{{.Server.Version}}' 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "Docker unavailable (a local Docker Desktop/daemon must be running). Alternatively start a database by hand and set ARTEX_PG_DSN to run go test directly."
}

# 2) Container: absent -> create; present but stopped -> start; running -> reuse
$state = (docker inspect -f '{{.State.Running}}' $Container 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $state) {
    Write-Host "[devtest] creating container $Container (postgres:16-alpine :$Port)"
    docker run -d --name $Container -e POSTGRES_PASSWORD=artextest -e POSTGRES_USER=artex `
        -e POSTGRES_DB=artex -p "${Port}:5432" postgres:16-alpine | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "docker run failed" }
}
elseif ($state.Trim() -ne "true") {
    Write-Host "[devtest] starting the existing container $Container"
    docker start $Container | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "docker start failed" }
}

# 3) Wait for PG to be ready (bounded polling, no sleep guessing)
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    docker exec $Container pg_isready -U artex -d artex 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $ready) { Fail "PG still not ready after 30 polls (check docker logs $Container for the reason)" }

# 4) Fresh database (default) -- kill lingering connections before DROP, otherwise the drop is blocked by them
if (-not $SkipFresh) {
    Write-Host "[devtest] recreating artex_ci (fresh database)"
    docker exec $Container psql -U artex -d postgres -q -c `
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='artex_ci'" | Out-Null
    docker exec $Container psql -U artex -d postgres -q -c "DROP DATABASE IF EXISTS artex_ci" | Out-Null
    docker exec $Container psql -U artex -d postgres -q -c "CREATE DATABASE artex_ci OWNER artex" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "recreating artex_ci failed" }
}

# 5) Run tests
$env:ARTEX_PG_DSN = $Dsn
$goArgs = @("test", "-p", "1") + $Packages + @("-count=1")
if ($Run) { $goArgs += @("-run", $Run) }
Write-Host "[devtest] go $($goArgs -join ' ')  (DSN=artex_ci@127.0.0.1:$Port)"
& go @goArgs
exit $LASTEXITCODE
