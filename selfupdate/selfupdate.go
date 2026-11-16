// Package selfupdate implements POJUN's one-click update from the UI: pull the new
// binary from a GitHub Release, verify it, stage it, and swap it in atomically on the
// next startup.
//
// Division of labor (see start.sh / start.bat):
//
//	startup script = a dumb supervisor loop whose only job is "after the process exits,
//	                 decide from the exit code whether to relaunch it"
//	this package   = all the error-prone logic (download / SHA256 verification / smoke
//	                 test / swap / rollback on failure)
//
// The swap lives in Go rather than the script because SHA256 verification and the smoke
// test would have to be written twice for sh and bat (sha256sum / shasum / certutil),
// and this is precisely the step that must not go wrong — install a binary that cannot
// start and the supervisor faithfully relaunches it forever, leaving the user to rescue
// the machine by hand.
//
// A complete upgrade goes through three process startups:
//
//  1. the old server receives /api/update/apply → download+verify → stage pojun.new →
//     exit 75
//  2. the script relaunches the old version → Bootstrap finds pojun.new → verify+smoke
//     test → swap → exit 75
//  3. the script relaunches, now the new version → Bootstrap records one attempt → the
//     marker is cleared once startup succeeds
//
// Any failing step falls back to the old version: if step 2 fails verification the staged
// file is deleted and the old version keeps running; if step 3 fails to survive until the
// marker is cleared 3 times in a row (it starts and then crashes), pojun.old is swapped
// back automatically.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ExitRestart is the exit code meaning "supervisor, relaunch me" (EX_TEMPFAIL). The
// startup script reruns immediately on seeing it, without counting it as crash backoff. 0
// means the user stopped normally (the script leaves its loop); anything else is a crash.
const ExitRestart = 75

// maxAttempts is how many startup attempts are allowed after a swap. The new version
// increments the counter on every startup and clears the marker once it survives
// settleDelay; crashing maxAttempts times in a row means it cannot start at all and is
// rolled back automatically.
const maxAttempts = 3

// Paths holds every file involved in an upgrade, all anchored under the **directory of
// the executable**. CWD is deliberately not used: when run as a service the working
// directory may be / or anything else, and using CWD would drop the staged file
// elsewhere and break the swap logic outright.
type Paths struct {
	Dir     string // directory of the executable
	Current string // currently running binary     pojun      / pojun.exe
	New     string // staged new version           pojun.new  / pojun.new.exe
	Sum     string // sha256 of the new version (hex) pojun.new.sha256 / pojun.new.exe.sha256
	Old     string // old version backed up before the swap pojun.old / pojun.old.exe
	Marker  string // upgrade state marker         pojun.upgrade.json
}

// ResolvePaths derives every upgrade path from the current executable.
//
// On Windows .new/.old must also carry the .exe suffix, otherwise both the smoke test and
// execution after the swap fail, so the extension is stripped first and re-appended; that
// keeps the naming symmetrical across the two platforms.
func ResolvePaths() (Paths, error) {
	exe, err := os.Executable()
	if err != nil {
		return Paths{}, fmt.Errorf("locate executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	name := filepath.Base(exe)
	ext := filepath.Ext(name) // ".exe" on Windows, usually empty on Unix
	stem := strings.TrimSuffix(name, ext)

	join := func(suffix string) string { return filepath.Join(dir, stem+suffix+ext) }
	return Paths{
		Dir:     dir,
		Current: exe,
		New:     join(".new"),
		Sum:     join(".new") + ".sha256",
		Old:     join(".old"),
		Marker:  filepath.Join(dir, stem+".upgrade.json"),
	}, nil
}

// marker records the progress of one swap and triggers automatic rollback when the new
// version cannot start.
type marker struct {
	From     string `json:"from"`     // version before the upgrade
	To       string `json:"to"`       // target version
	Attempts int    `json:"attempts"` // startup attempts since the swap
	StagedAt int64  `json:"staged_at"`
}

func readMarker(path string) (marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

func writeMarker(path string, m marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cleanStaged removes the staged file. A successful swap, a failed verification and a user
// cancellation all go through it, so a leftover pojun.new is not retried on the next
// startup.
func cleanStaged(p Paths) {
	_ = os.Remove(p.New)
	_ = os.Remove(p.Sum)
}

// versionTagRe only accepts a clean three-part version number (optionally v-prefixed).
var versionTagRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// ValidVersionTag reports whether the string is an allowed version form. hostd's
// /self-upgrade uses it for input validation — that argument eventually gets spliced into
// a GitHub API URL, so the shape must be narrow. It deliberately **does not TrimSpace**:
// input with whitespace is rejected outright rather than silently corrected and used.
func ValidVersionTag(s string) bool { return versionTagRe.MatchString(s) }

// CompareVersions compares two version numbers and returns -1/0/1 (a<b / a==b / a>b).
// ok=false means at least one side is not a comparable version (e.g. "dev" from a local
// development build, or "0.3.7-2-gabc1234-dirty" produced by git describe); in that case
// the caller should disable one-click update, otherwise a development build would be
// "upgraded" to the stable release and uncommitted changes would be overwritten.
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion parses a "v0.3.7" / "0.3.7" style version into a [3]int.
//
// Only the clean three-part form is accepted: on non-tag builds build.sh uses git
// describe, producing suffixed versions such as "0.3.7-2-gabc1234", and those must be
// judged incomparable rather than treated as 0.3.7 — otherwise a development build is
// misread as "already up to date" or gets overwritten by the stable release.
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker reports whether the process runs in a container. Under Docker the swap writes
// to the container's writable layer, and `docker compose up -d` recreating the container
// reverts to the version bundled in the image — that is expected behavior (the user is
// pulling a new image at that point), but the frontend needs to be able to say so
// clearly.
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}
