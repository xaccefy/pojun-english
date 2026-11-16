#!/bin/sh
# POJUN watchdog start script (Linux / macOS / Docker ENTRYPOINT)
#
# Usage:
#   ./start.sh                       run in foreground (Ctrl-C to stop)
#   nohup ./start.sh >pojun.log 2>&1 &   run as a background daemon
#   ./start.sh -addr :9000           extra args are passed through to pojun verbatim
#
# It does exactly one thing: run pojun, then decide from the exit code whether
# to launch it again.
#
#   0      clean user stop        -> exit the loop
#   75     program asked restart  -> rerun immediately (user clicked
#                                  "one-click update" or "rollback" in the UI)
#   other  crash                  -> rerun after backoff (1->2->4... up to 60s)
#
# Deliberately no download, SHA256 verification or binary swap here: that logic
# would have to be written twice (sh and bat), and it is precisely the part
# that must never go wrong — if a broken binary were swapped in, this script
# would faithfully keep relaunching it and the user would have to fix the box
# by hand. So all verification/swap stays in Go (the selfupdate package), done
# by pojun itself at startup; this script stays deliberately dumb.
set -u

cd "$(dirname "$0")" || exit 1

BIN=./pojun
[ -x "$BIN" ] || { echo "[pojun] executable $BIN not found" >&2; exit 1; }

RESTART_CODE=75
MAX_DELAY=60
# Give up relaunching after this many consecutive crashes.
#
# Why a cap: when the crash is caused by [bad configuration] it is permanent
# (wrong database password, schema migration failure, port already in use).
# Restarting forever then has two downsides —
#   1) the log is flooded with the same error line, burying the real cause;
#   2) **systemctl status shows active (running)** — because what is alive is
#      the start.sh wrapper while the pojun binary itself keeps crash-looping.
#      Ops reads the status, thinks the service is fine, and goes down a
#      completely wrong debugging path when the web UI won't open (this
#      actually happened on a real machine on 2026-10-22).
#
# After giving up, the script exits non-zero; systemd's Restart=always takes
# over and marks the unit failed once StartLimit is hit — only then does
# status reflect the real fault. A "program-requested restart" (75) does not
# count as a crash: it is the user clicking "one-click update", a normal flow.
MAX_CRASHES=5
crashes=0

child=0
stopping=0

# Forward stop signals to the pojun process.
#
# Required under Docker: `docker stop` only sends SIGTERM to PID 1 (this
# script), never to the child. Without forwarding, pojun never sees the
# signal, cannot shut down gracefully, and gets SIGKILLed after 10 seconds —
# running tasks would be cut off mid-flight.
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# A signal interrupts `wait`, which then returns >128. At that point the
	# child may still be doing graceful shutdown; wait a second time to get its
	# real exit code.
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[pojun] stopped"
		exit 0
	fi

	case "$code" in
		0)
			echo "[pojun] exited normally"
			exit 0
			;;
		"$RESTART_CODE")
			# Update/rollback is staged: rerunning pojun completes the swap at
			# startup (see selfupdate.Bootstrap).
			echo "[pojun] restart requested (applying new version)..."
			delay=1
			crashes=0
			;;
		*)
			crashes=$((crashes + 1))
			if [ "$crashes" -ge "$MAX_CRASHES" ]; then
				echo "[pojun] ${crashes} consecutive abnormal exits, giving up auto-restart (exit code $code)." >&2
				echo "[pojun] This is usually a configuration or environment problem (wrong database password," >&2
				echo "[pojun] port in use, missing dependency, ...). After fixing it run: sudo systemctl restart pojun" >&2
				exit "$code"
			fi
			echo "[pojun] abnormal exit (code=$code), restarting in ${delay}s (attempt ${crashes}/${MAX_CRASHES})" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
