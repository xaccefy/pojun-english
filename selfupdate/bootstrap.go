package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// smokeEnv makes a child process spawned by the smoke test skip Bootstrap entirely.
//
// Strictly speaking it would be fine without it: the child's os.Executable() is
// pojun.new, so every derived path carries the .new prefix and cannot touch the real
// upgrade files. But relying on that coincidence is too fragile; an explicit
// short-circuit is obvious and saves the child one pointless disk probe.
const smokeEnv = "POJUN_SELFUPDATE_SMOKE"

// Action is the instruction Bootstrap hands back to main.
type Action int

const (
	// Continue: start the server as usual.
	Continue Action = iota
	// Restart: exit immediately with ExitRestart so the supervisor script relaunches us.
	Restart
)

// State describes the upgrade state at this startup, so /api/update/check can tell the
// frontend truthfully whether "the last upgrade succeeded or was rolled back".
type State struct {
	Pending     bool   // swapped in but not yet confirmed stable
	RolledBack  bool   // an automatic rollback just ran during this startup
	FailedStage bool   // the staged file failed verification/smoke test and was discarded
	Detail      string // one user-facing sentence explaining what happened
}

// Bootstrap runs at the very top of main and must be called before listening on any
// port or opening the database.
//
// Three situations:
//
//  1. a staged pojun.new exists → verify + smoke test; on success swap it in and ask
//     for a restart, on failure discard it and keep running the old version
//  2. only the marker file is left → a swap just happened; count one attempt and roll
//     back once there have been enough consecutive failures
//  3. neither exists → start normally
func Bootstrap() (Action, State) {
	if os.Getenv(smokeEnv) != "" {
		return Continue, State{}
	}
	p, err := ResolvePaths()
	if err != nil {
		log.Printf("[update] skipping bootstrap: %v", err)
		return Continue, State{}
	}

	if _, err := os.Stat(p.New); err == nil {
		return applyStaged(p)
	}

	m, ok := readMarker(p.Marker)
	if !ok {
		return Continue, State{}
	}
	return confirmOrRollback(p, m)
}

// applyStaged handles the "a staged file exists" case: swap it in when verification
// passes, discard it when it fails.
//
// This is the only place in the whole upgrade chain that overwrites the executable, and
// the last gate — the smoke test blocks corrupt downloads, wrong architecture and
// missing dynamic libraries. Once a binary that cannot start is let through, the
// supervisor script will tirelessly relaunch it while no Go code ever gets to run, so
// automatic rollback never gets a chance either.
func applyStaged(p Paths) (Action, State) {
	m, _ := readMarker(p.Marker)

	if err := verifyStaged(p); err != nil {
		log.Printf("[update] the staged new version failed verification and was discarded; continuing with the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "the new version failed verification and was discarded: " + err.Error()}
	}

	if err := swap(p); err != nil {
		log.Printf("[update] swap failed, continuing with the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "swap failed: " + err.Error()}
	}

	// Swap succeeded. Keep the marker so the next startup (which runs the new version)
	// can confirm stability.
	m.Attempts = 0
	if m.StagedAt == 0 {
		m.StagedAt = time.Now().Unix()
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to write the upgrade marker (automatic rollback is no longer possible): %v", err)
	}
	log.Printf("[update] swapped in %s, exiting to restart (exit %d)", orUnknown(m.To), ExitRestart)
	return Restart, State{Pending: true}
}

// confirmOrRollback handles "a startup after a swap": count attempts and restore the
// old version once the limit is exceeded.
//
// The counter only increments once Go code is running, so it covers failures of the
// "executes but crashes during init" kind (incompatible config, port taken, DB
// migration blew up); "cannot even exec" is blocked by the pre-swap smoke test. The
// two together are what makes this complete.
func confirmOrRollback(p Paths, m marker) (Action, State) {
	m.Attempts++
	if m.Attempts > maxAttempts {
		if err := rollback(p); err != nil {
			// If even the rollback failed, do not restart again or we end up in an endless
			// restart loop. Clear the marker and let the process start in its current state —
			// if it cannot start, the user can at least see why in the logs.
			log.Printf("[update] the new version failed to start %d times in a row and the rollback failed: %v", maxAttempts, err)
			_ = os.Remove(p.Marker)
			return Continue, State{Detail: "the new version failed to start and the rollback failed: " + err.Error()}
		}
		log.Printf("[update] the new version failed to start %d times in a row, rolled back to %s, exiting to restart (exit %d)",
			maxAttempts, orUnknown(m.From), ExitRestart)
		_ = os.Remove(p.Marker)
		return Restart, State{RolledBack: true, Detail: fmt.Sprintf("the new version failed to start; rolled back to %s", orUnknown(m.From))}
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to update the upgrade marker: %v", err)
	}
	log.Printf("[update] new version starting up (attempt %d/%d); the upgrade is confirmed once it runs stably",
		m.Attempts, maxAttempts)
	return Continue, State{Pending: true}
}

// Settle confirms the new version is running stably and clears the upgrade marker.
//
// main calls it after a delay once the HTTP listener is up: surviving that window is
// what counts, otherwise the marker stays in place and the next startup keeps counting
// attempts until a rollback is triggered.
func Settle() {
	p, err := ResolvePaths()
	if err != nil {
		return
	}
	settle(p)
}

func settle(p Paths) {
	if _, ok := readMarker(p.Marker); !ok {
		return // not a post-upgrade startup, nothing to do
	}
	if err := os.Remove(p.Marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[update] failed to clear the upgrade marker: %v", err)
		return
	}
	log.Printf("[update] the new version is running stably, upgrade complete (previous version kept as %s)", p.Old)
}

// SettleDelay is how long the new version must run to count as "survived".
const SettleDelay = 30 * time.Second

// verifyStaged verifies the staged file: compare SHA256 first, then actually launch it
// once.
func verifyStaged(p Paths) error {
	want, err := os.ReadFile(p.Sum)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}
	got, err := fileSHA256(p.New)
	if err != nil {
		return fmt.Errorf("compute checksum: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(want)), got) {
		return errors.New("SHA256 mismatch (corrupt download or tampering)")
	}
	return smokeTest(p.New)
}

// smokeTest launches the new binary with -h to confirm it can really execute on this
// system. That blocks a whole class of problems: truncated downloads, wrong
// architecture (exec format error), missing dependencies.
func smokeTest(bin string) error {
	return smokeTestWithArgs(bin, []string{"-h"})
}

// swap replaces the current binary with the staged new version.
//
// Both Unix and Windows allow renaming a running executable (what Windows forbids is
// deleting and overwriting, not renaming), so no per-platform branch is needed here and
// we do not have to stop ourselves first.
func swap(p Paths) error {
	// Windows rename does not overwrite an existing target, so the .old left by the
	// previous upgrade must be removed first.
	if err := os.Remove(p.Old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clean up old backup %s: %w", p.Old, err)
	}
	if err := os.Rename(p.Current, p.Old); err != nil {
		return fmt.Errorf("back up current version: %w", err)
	}
	if err := os.Rename(p.New, p.Current); err != nil {
		// The swap failed but the current version has already been moved away; it must be
		// put back as-is or the next startup has no executable.
		if rerr := os.Rename(p.Old, p.Current); rerr != nil {
			return fmt.Errorf("failed to install the new version (%v) and failed to restore the current version: %w", err, rerr)
		}
		return fmt.Errorf("install new version: %w", err)
	}
	_ = os.Remove(p.Sum)
	return nil
}

// rollback restores the old version backed up by swap.
func rollback(p Paths) error {
	if _, err := os.Stat(p.Old); err != nil {
		return fmt.Errorf("no backup to roll back to at %s: %w", p.Old, err)
	}
	// Move the version that cannot start to .failed for investigation instead of deleting
	// it outright.
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(p.Current, failed); err != nil {
		return fmt.Errorf("move away the failed version: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		return fmt.Errorf("restore old version: %w", err)
	}
	return nil
}

// Rollback implements /api/update/rollback: explicitly go back to the previous version.
// It only performs the swap; restarting is likewise left to the supervisor script (the
// caller then exits with ExitRestart).
func Rollback() error {
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Old); err != nil {
		return errors.New("no previous version to roll back to (" + p.Old + " does not exist)")
	}
	cleanStaged(p)
	if err := smokeTest(p.Old); err != nil {
		return fmt.Errorf("the previous version cannot execute, refusing to roll back: %w", err)
	}
	// Swap current and backup: after rolling back we can still roll forward again.
	tmp := p.Current + ".swap"
	_ = os.Remove(tmp)
	if err := os.Rename(p.Current, tmp); err != nil {
		return fmt.Errorf("move away current version: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		_ = os.Rename(tmp, p.Current)
		return fmt.Errorf("install previous version: %w", err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		log.Printf("[update] failed to tidy up backups after the rollback (does not affect running): %v", err)
	}
	_ = os.Remove(p.Marker)
	return nil
}

// HasBackup reports whether a previous version is available to roll back to, so the
// frontend can decide whether to show the rollback button.
func HasBackup() bool {
	p, err := ResolvePaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(p.Old)
	return err == nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown version"
	}
	return s
}
