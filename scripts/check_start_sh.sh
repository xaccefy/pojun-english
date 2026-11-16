#!/usr/bin/env bash
# Checks for start.sh's crash handling and install.sh's systemd unit properties.
#
# Background (hit on a real machine on 2026-10-22): with a broken config (e.g. mismatched database password),
# pojun would crash and restart repeatedly, and start.sh's unbounded self-relaunch plus systemd's Restart=always
# compounded into:
#
#   - systemctl status showing **active (running)** -- what was alive was the start.sh wrapper
#     script while pojun itself was crashing;
#   - the web UI unreachable but status looking perfectly healthy, sending troubleshooting in the wrong direction;
#   - logs flooded by the same error line, burying the root cause.
#
# Two lines of defence: start.sh's crash limit + systemd's StartLimit.
set -uo pipefail

# Under MSYS (Git Bash) path conversion mangles ".." in Windows paths awkwardly,
# so use paths relative to the repo root directly: the script is in scripts/, the targets are one level up.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
START="${1:-$REPO_ROOT/start.sh}"
INSTALL="${2:-$REPO_ROOT/install.sh}"
if [ ! -f "$START" ]; then START="./start.sh"; fi
if [ ! -f "$INSTALL" ]; then INSTALL="./install.sh"; fi

fail=0
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '[ok]   %s\n' "$desc"
  else
    printf '[FAIL] %s\n' "$desc"
    fail=$((fail+1))
  fi
}

printf '=== checking start.sh ===\n'

# 1) There must be a consecutive-crash cap.
check "start.sh has a consecutive-crash cap" \
  grep -q 'MAX_CRASHES=' "$START"

# 2) The crash counter must be incremented in the "abnormal exit" branch (not merely defined elsewhere).
#    The criterion uses line-number relations rather than pattern matching: in awk regexes the $ of $code is an
#    end-of-line anchor, so matching by literal text would misfire. Instead: "after crashes=0 and before
#    crashes=...+1 there must be the case's abnormal branch".
check "start.sh increments the crash counter in the abnormal-exit branch" \
  bash -c '
    reset_line=$(grep -n "crashes=0" "'"$START"'" | tail -1 | cut -d: -f1)
    inc_line=$(grep -n "crashes=\$((crashes + 1))" "'"$START"'" | head -1 | cut -d: -f1)
    [ -n "$reset_line" ] && [ -n "$inc_line" ] && [ "$inc_line" -gt "$reset_line" ]
  '

# 3) Reaching the cap must exit (the script must not keep restarting forever).
check "exit the script once the crash cap is reached" \
  grep -q 'exit "\$code"' "$START"

# 4) The crash cap must be neither too small (a normal brief failure would be declared fatal) nor too large
#    (otherwise it lingers "half-dead" for too long).
check "crash cap is between 3 and 10" \
  bash -c '
    n=$(grep -oE "^MAX_CRASHES=[0-9]+" "'"$START"'" | cut -d= -f2)
    [ -n "$n" ] && [ "$n" -ge 3 ] && [ "$n" -le 10 ]
  '

# 5) "Restart requested" (75) must not count as a crash -- that is the normal flow when a user clicks one-click update.
#    Criterion: after the RESTART_CODE branch there must be crashes=0 (resetting the counter).
check "program-requested restart (75) is not counted as a crash" \
  bash -c '
    reset_line=$(grep -n "crashes=0" "'"$START"'" | tail -1 | cut -d: -f1)
    case_line=$(grep -n "RESTART_CODE" "'"$START"'" | tail -1 | cut -d: -f1)
    [ -n "$reset_line" ] && [ -n "$case_line" ] && [ "$reset_line" -gt "$case_line" ]
  '

# 6) The script is syntactically valid.
check "start.sh is syntactically valid (sh -n)" sh -n "$START"

printf '\n=== checking install.sh systemd unit ===\n'

# 7) The unit must carry StartLimit (otherwise systemd restarts forever and status is always running).
check "systemd unit sets StartLimitBurst" \
  grep -q 'StartLimitBurst=' "$INSTALL"

check "systemd unit sets StartLimitIntervalSec" \
  grep -q 'StartLimitIntervalSec=' "$INSTALL"

# 8) StartLimit must be in the [Unit] section (where modern systemd expects it) --
#    placing it in [Service] makes systemd ignore it.
#    The criterion uses line numbers: StartLimitBurst must fall between [Unit] and the next [ section.
check "StartLimit is inside the [Unit] section" \
  bash -c '
    unit_line=$(grep -n "^\[Unit\]" "'"$INSTALL"'" | head -1 | cut -d: -f1)
    burst_line=$(grep -n "StartLimitBurst=" "'"$INSTALL"'" | head -1 | cut -d: -f1)
    next_sec=$(awk -v s="$unit_line" "NR>s && /^\\[/ { print NR; exit }" "'"$INSTALL"'")
    [ -n "$unit_line" ] && [ -n "$burst_line" ] && [ -n "$next_sec" ] \
      && [ "$burst_line" -gt "$unit_line" ] && [ "$burst_line" -lt "$next_sec" ]
  '

if [ "$fail" -gt 0 ]; then
  printf '\n=== %d checks failed ===\n' "$fail"
  exit 1
fi
printf '\n=== all checks passed ===\n'
