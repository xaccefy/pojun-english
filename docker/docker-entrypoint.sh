#!/bin/sh
# Container entrypoint: start the privileged install helper hostd in the background +
# preinstall tools in the background on first boot, then hand control to
# start.sh (the pojun daemon).
#
# Why layered this way (v0.4.69, following the "decouple main program from tool environment" deployment idea):
#   - The main image only carries runtime deps and core tools, staying lean (fast publish/pull);
#   - All 90 catalog items are **preinstalled in the background on first boot**, not blocking the main
#     service, and without inflating the image by another 1-2GB; a marker file is written when done, so
#     restarts don't repeat it;
#   - The "System -> Host Environment" page can inspect/repair installs at any time (via the resident hostd).
# Environment variables:
#   POJUN_PREINSTALL_TOOLS=0   disable first-boot preinstall
#   POJUN_PREINSTALL_TOOLS=1   default: preinstall in background on first boot
#   POJUN_PREINSTALL_TOOLS=force  force a re-run (for re-checking tools after a binary upgrade)
set -u

HOSTD_SOCK="/run/pojun/hostd.sock"
PREINSTALL_MARK="/app/data/.tools-preinstall-done"
PREINSTALL_LOG="/app/data/tools-preinstall.log"
mkdir -p "$(dirname "$HOSTD_SOCK")" /app/data

# -- hostd: resident unix socket, backing one-click install/reinstall from the "Host Environment" page --
if [ -x /app/pojun-hostd ]; then
  if [ ! -S "$HOSTD_SOCK" ]; then
    /app/pojun-hostd -socket "$HOSTD_SOCK" >>/app/data/hostd.log 2>&1 &
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -S "$HOSTD_SOCK" ] && break
      sleep 0.3
    done
    if [ -S "$HOSTD_SOCK" ]; then
      echo "[entrypoint] hostd ready -> $HOSTD_SOCK (one-click tool install available on the host environment page)"
    else
      echo "[entrypoint] warn: hostd not ready (page one-click install unavailable, everything else works)"
    fi
  fi

  # -- preinstall the full tool catalog in the background on first boot (idempotent; failures can be retried on the host environment page) --
  mode="${POJUN_PREINSTALL_TOOLS:-1}"
  if [ "$mode" != "0" ]; then
    if [ "$mode" = "force" ] || [ ! -f "$PREINSTALL_MARK" ]; then
      (
        echo "[preinstall] $(date '+%F %T') starting catalog preinstall (background, main service unaffected)" >>"$PREINSTALL_LOG"
        if /app/pojun-hostd -install-all >>"$PREINSTALL_LOG" 2>&1; then
          echo "[preinstall] $(date '+%F %T') done (see the [fail] lines above for failures)" >>"$PREINSTALL_LOG"
          touch "$PREINSTALL_MARK"
        else
          echo "[preinstall] $(date '+%F %T') some items failed, completion marker not written (retried on next boot; can also reinstall on the host environment page)" >>"$PREINSTALL_LOG"
        fi
      ) &
      echo "[entrypoint] background tool preinstall started -> data/tools-preinstall.log (progress visible on the host environment page)"
    fi
  fi
else
  echo "[entrypoint] warn: /app/pojun-hostd not found (page one-click install unavailable)"
fi

# exec makes start.sh the replacement process for PID 1, so docker stop's SIGTERM goes straight to pojun.
exec /app/start.sh "$@"
