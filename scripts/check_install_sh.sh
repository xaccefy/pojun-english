#!/usr/bin/env bash
# Static property checks for install.sh.
#
# During a fresh install on a real server (Kali 2026.3) on 2026-10-22, all four of these
# exposed problems -- the kind of "you can't see it by running locally, it only blows up on a real install":
#
#  1. curl's --retry by default does **not retry SSL interruptions** (--retry only covers transient errors:
#     timeout/429/5xx). Downloading the 17MB release package through a proxy had the connection cut
#     (SSL_read: unexpected eof) and curl gave up immediately -- the retry flags were useless.
#  2. A failed download **did not die**, the script kept going and finally reported "extraction failed (need unzip)",
#     misdirecting a network problem into a corrupt-package problem.
#  3. When SHA256SUMS could not be fetched it only warned and then **skipped verification** -- failing to fetch the
#     checksum file equals no verification, which is a supply-chain defect.
#  4. No resumable downloads: a 17MB transfer dying at 90% had to start over.
#
# These can be asserted statically with grep; no need to actually install.
set -uo pipefail

# Under MSYS (Git Bash) pwd returns /d/... form, which bash -n and grep cannot read;
# convert to a Windows absolute path before handing it to child processes.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -W 2>/dev/null || cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$SCRIPT_DIR/install.sh}"

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

printf '=== checking %s ===\n' "$TARGET"

# 1) curl must carry --retry-all-errors (otherwise SSL interruptions are not retried).
#    The criterion must exclude comment lines -- the explanation at the top of this very file mentions
#    "--retry-all-errors", so without excluding comments grep would match the comment and the criterion
#    would always be ok (false positive).
check "curl carries --retry-all-errors (retry even on SSL interruption)" \
  bash -c '
    grep -v "^[[:space:]]*#" "'"$TARGET"'" | grep -q -- "--retry-all-errors"
  '

# 2) A failed release-package download must die, not be deferred to extraction time.
#    The criterion must be strict: the **complete statement** containing the curl call that fetches the release
#    package (including \ line continuations) must carry || die.
#    (It used to be written as "there is a die within the next 3 lines" -- those 3 lines happened to contain
#    another if branch's die, so the criterion passed falsely. A wrong test is worse than no test.)
check "die immediately when the release-package download fails (not deferred to extraction)" \
  bash -c '
    awk "
      /releases\/download\/\\\$VERSION\/\\\$zip/ && !/SHA256SUMS/ { hit=1 }
      hit { printf \"%s\\n\", \$0 }
      hit && !/\\\\$/ { exit }
    " "'"$TARGET"'" | grep -q "|| die"
  '

# 3) A failed SHA256SUMS fetch must die, not merely warn and let it through degraded.
#    Criterion: the **complete statement** containing the curl call that fetches SHA256SUMS (including \
#    continuations) must carry || die. We look for the curl call itself, not some message string -- messages get
#    rewritten by fixes, and a criterion bound to wording misfires.
check "die when SHA256SUMS cannot be fetched (no degraded pass-through)" \
  bash -c '
    awk "
      /^[[:space:]]*#/ { next }
      /SHA256SUMS/ && !/grep / { hit=1 }
      hit { printf \"%s\\n\", \$0 }
      hit && !/\\\\$/ { exit }
    " "'"$TARGET"'" | grep -q "|| die"
  '

# 4) Large downloads must support resuming (-C -). Also excludes comment lines.
check "release-package download supports resuming (-C -)" \
  bash -c '
    grep -v "^[[:space:]]*#" "'"$TARGET"'" | grep -q -- "-C -"
  '

# 5) The script itself is syntactically correct (bash -n).
check "install.sh is syntactically valid (bash -n)" bash -n "$TARGET"

# 6) The script starts with set -euo pipefail (stop on error).
check "install.sh enables set -euo pipefail" \
  grep -q 'set -euo pipefail' "$TARGET"

# 7) When the database role already exists the password must be synced.
#
# The pitfall (real install, 2026-10-22): with a leftover old pojun role on the machine, the script took the
# "already exists -> skip creation" branch while config.json held a **newly generated** password ->
# the service started and then repeatedly exited on SASL auth failures, with errors pointing nowhere near the cause.
check "sync the password when the role already exists (ALTER ROLE)" \
  bash -c '
    grep -v "^[[:space:]]*#" "'"$TARGET"'" | grep -q "ALTER ROLE pojun LOGIN PASSWORD"
  '

if [ "$fail" -gt 0 ]; then
  printf '\n=== %d checks failed ===\n' "$fail"
  exit 1
fi
printf '\n=== all checks passed ===\n'
