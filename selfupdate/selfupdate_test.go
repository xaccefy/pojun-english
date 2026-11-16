package selfupdate

import (
	"archive/zip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testPaths builds an isolated upgrade directory. ResolvePaths() cannot be used
// directly — it would point at the test binary itself, and running it would rename the
// go test executable.
func testPaths(t *testing.T) Paths {
	t.Helper()
	dir := t.TempDir()
	return Paths{
		Dir:     dir,
		Current: filepath.Join(dir, "pojun"),
		New:     filepath.Join(dir, "pojun.new"),
		Sum:     filepath.Join(dir, "pojun.new.sha256"),
		Old:     filepath.Join(dir, "pojun.old"),
		Marker:  filepath.Join(dir, "pojun.upgrade.json"),
	}
}

// fakeBin writes an executable shell script impersonating pojun. smokeTest only launches
// it with -h to look at the exit code, so a script is entirely sufficient and far faster
// than compiling a real binary.
func fakeBin(t *testing.T, path, marker string, exitCode int) {
	t.Helper()
	script := "#!/bin/sh\necho " + marker + "\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary %s: %v", path, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return string(rune('0' + n))
}

// stage sets bin up as "staged and awaiting a swap": write pojun.new plus its checksum.
func stage(t *testing.T, p Paths, marker string, exitCode int) {
	t.Helper()
	fakeBin(t, p.New, marker, exitCode)
	sum, err := fileSHA256(p.New)
	if err != nil {
		t.Fatalf("compute checksum: %v", err)
	}
	if err := os.WriteFile(p.Sum, []byte(sum), 0o644); err != nil {
		t.Fatalf("write checksum: %v", err)
	}
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func requireUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake binary is a sh script, which cannot run on Windows")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b       string
		want       int
		comparable bool
	}{
		{"0.3.7", "0.3.8", -1, true},
		{"0.3.8", "0.3.7", 1, true},
		{"0.3.7", "0.3.7", 0, true},
		{"v0.3.7", "0.3.8", -1, true}, // build.sh strips the v, tags carry it; both must be accepted
		{"0.3.7", "v0.3.7", 0, true},
		{"0.9.0", "0.10.0", -1, true}, // compared numerically, not lexicographically
		{"1.0.0", "0.99.99", 1, true},
		// A development build must be judged incomparable, or the stable release would
		// overwrite uncommitted changes.
		{"dev", "0.3.8", 0, false},
		{"0.3.7-2-gabc1234", "0.3.8", 0, false},
		{"0.3.7-dirty", "0.3.8", 0, false},
		{"0.3", "0.3.8", 0, false},
		{"", "0.3.8", 0, false},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.a, c.b)
		if ok != c.comparable {
			t.Errorf("CompareVersions(%q,%q) comparable=%v, want %v", c.a, c.b, ok, c.comparable)
			continue
		}
		if ok && got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestResolvePathsNaming(t *testing.T) {
	p, err := ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	// Key invariant: every upgrade file sits next to the executable. Landing in CWD would
	// break the swap outright when running as a service (where the working directory may
	// be /).
	for name, path := range map[string]string{"New": p.New, "Sum": p.Sum, "Old": p.Old, "Marker": p.Marker} {
		if filepath.Dir(path) != p.Dir {
			t.Errorf("%s is not in the executable directory: %s (want %s)", name, path, p.Dir)
		}
	}
	// On Windows .new/.old must keep .exe, otherwise both the smoke test and execution
	// after the swap fail.
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(p.New, ".exe") || !strings.HasSuffix(p.Old, ".exe") {
			t.Errorf("on Windows .new/.old must end with .exe: new=%s old=%s", p.New, p.Old)
		}
	}
}

func TestVerifyStagedRejectsTamperedBinary(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	stage(t, p, "new", 0)

	// Modify the file after the checksum was written, simulating a corrupt download / swap.
	fakeBin(t, p.New, "tampered", 0)
	if err := verifyStaged(p); err == nil {
		t.Fatal("expected the SHA256 mismatch to be rejected, but it passed")
	}
}

func TestVerifyStagedRejectsUnrunnableBinary(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	stage(t, p, "broken", 1) // executes but exits non-zero

	if err := verifyStaged(p); err == nil {
		t.Fatal("expected the smoke test failure to be rejected, but it passed")
	}
}

func TestApplyStagedHappyPath(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "old", 0)
	stage(t, p, "new", 0)
	if err := writeMarker(p.Marker, marker{From: "0.3.7", To: "0.3.8"}); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	action, st := applyStaged(p)
	if action != Restart {
		t.Fatalf("expected Restart, got %v", action)
	}
	if !st.Pending {
		t.Error("state should be Pending after the swap")
	}
	if !strings.Contains(readAll(t, p.Current), "new") {
		t.Error("pojun should have been replaced by the new version")
	}
	if !strings.Contains(readAll(t, p.Old), "old") {
		t.Error("the old version should be backed up to pojun.old")
	}
	if _, err := os.Stat(p.New); !os.IsNotExist(err) {
		t.Error("pojun.new should be gone after the swap")
	}
	if _, err := os.Stat(p.Sum); !os.IsNotExist(err) {
		t.Error("the checksum file should be cleaned up after the swap")
	}
	// The marker must stay; the next startup (running the new version) counts on it and
	// rolls back when needed.
	if _, ok := readMarker(p.Marker); !ok {
		t.Error("the upgrade marker should be kept after the swap")
	}
}

func TestApplyStagedKeepsCurrentWhenVerifyFails(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "old", 0)
	stage(t, p, "new", 0)
	fakeBin(t, p.New, "tampered", 0) // break the checksum

	action, st := applyStaged(p)
	if action != Continue {
		t.Fatalf("expected Continue when verification fails, got %v", action)
	}
	if !st.FailedStage {
		t.Error("state should be marked FailedStage")
	}
	if !strings.Contains(readAll(t, p.Current), "old") {
		t.Fatal("the current version must not be touched when verification fails")
	}
	if _, err := os.Stat(p.New); !os.IsNotExist(err) {
		t.Error("a staged file that failed verification should be cleaned up, or the next startup retries it")
	}
}

func TestSwapOverwritesPreviousBackup(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "v2", 0)
	fakeBin(t, p.Old, "v1", 0) // backup left by the previous upgrade
	stage(t, p, "v3", 0)

	if err := swap(p); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if !strings.Contains(readAll(t, p.Current), "v3") {
		t.Error("should swap in v3")
	}
	if !strings.Contains(readAll(t, p.Old), "v2") {
		t.Error("the backup should be updated to the just-replaced v2")
	}
}

func TestConfirmCountsAttemptsThenRollsBack(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "broken-new", 0)
	fakeBin(t, p.Old, "good-old", 0)
	m := marker{From: "0.3.7", To: "0.3.8"}

	// The first maxAttempts startups only count attempts, giving the new version a chance
	// to settle.
	for i := 1; i <= maxAttempts; i++ {
		action, st := confirmOrRollback(p, m)
		if action != Continue {
			t.Fatalf("attempt %d: expected Continue, got %v", i, action)
		}
		if !st.Pending {
			t.Errorf("attempt %d: state should be Pending", i)
		}
		got, ok := readMarker(p.Marker)
		if !ok || got.Attempts != i {
			t.Fatalf("after attempt %d attempts=%d (ok=%v), want %d", i, got.Attempts, ok, i)
		}
		m = got
	}

	// One more crash exceeds the limit and the old version is swapped back automatically.
	action, st := confirmOrRollback(p, m)
	if action != Restart {
		t.Fatalf("expected Restart when the attempt limit is exceeded, got %v", action)
	}
	if !st.RolledBack {
		t.Error("state should be marked RolledBack")
	}
	if !strings.Contains(readAll(t, p.Current), "good-old") {
		t.Fatal("should have rolled back to the old version")
	}
	if _, err := os.Stat(p.Marker); !os.IsNotExist(err) {
		t.Error("the marker should be cleared after a rollback, otherwise it rolls back forever")
	}
	// Keep the version that cannot start for investigation instead of deleting it.
	if _, err := os.Stat(p.Current + ".failed"); err != nil {
		t.Error("the failed version should be kept as .failed for investigation")
	}
}

func TestManualRollbackIsReversible(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "v2", 0)
	fakeBin(t, p.Old, "v1", 0)

	// Rollback() goes through ResolvePaths(), so test the underlying swap semantics
	// directly here.
	tmp := p.Current + ".swap"
	if err := os.Rename(p.Current, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readAll(t, p.Current), "v1") {
		t.Error("the current version should be v1 after the rollback")
	}
	if !strings.Contains(readAll(t, p.Old), "v2") {
		t.Error("the backup should become v2 after the rollback, so we can roll forward again")
	}
}

func TestParseSums(t *testing.T) {
	const (
		linuxSum = "1111111111111111111111111111111111111111111111111111111111111111"
		winSum   = "ABCDEF0000000000000000000000000000000000000000000000000000000000"
	)
	// sha256sum output is separated by two spaces; shasum -a 256 in binary mode prefixes
	// the file name with *.
	raw := linuxSum + "  pojun-0.3.8-linux-amd64.zip\n" +
		winSum + " *pojun-0.3.8-windows-amd64.zip\n" +
		"\n" +
		"garbage line\n" + // exactly two fields, but the first is not a digest
		"deadbeef  pojun-0.3.8-darwin-arm64.zip\n" // wrong digest length

	out := parseSums(raw)
	if out["pojun-0.3.8-linux-amd64.zip"] != linuxSum {
		t.Errorf("wrong parse of the linux entry: %v", out)
	}
	// Digests are lowercased so a case difference is not misread as a mismatch.
	if got := out["pojun-0.3.8-windows-amd64.zip"]; got != strings.ToLower(winSum) {
		t.Errorf("wrong windows entry (the * prefix should be stripped and the digest lowercased): %q", got)
	}
	if len(out) != 2 {
		t.Errorf("empty lines, non-digest lines and wrong-length lines should be ignored, got %v", out)
	}
}

func TestExtractBinaryFindsNestedEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the base name inside the bundle is pojun.exe on Windows; this case is built with Unix naming")
	}
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// Structure of a real release bundle: pojun-<version>-<os>-<arch>/pojun plus some
	// distractor files.
	for name, body := range map[string]string{
		"pojun-0.3.8-linux-amd64/README.md":           "readme",
		"pojun-0.3.8-linux-amd64/skills/a.md":         "skill",
		"pojun-0.3.8-linux-amd64/pojun":               "#!/bin/sh\nexit 0\n",
		"pojun-0.3.8-linux-amd64/config.example.json": "{}",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dst := filepath.Join(dir, "out")
	if err := extractBinary(zipPath, dst); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if got := readAll(t, dst); !strings.Contains(got, "exit 0") {
		t.Errorf("the extracted file is not the pojun executable: %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Error("the extracted binary must carry the executable bit")
	}
}

func TestExtractBinaryMissingEntry(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("pojun-0.3.8-linux-amd64/README.md")
	_, _ = w.Write([]byte("readme"))
	_ = zw.Close()
	f.Close()

	if err := extractBinary(zipPath, filepath.Join(dir, "out")); err == nil {
		t.Fatal("it should error when the bundle has no executable")
	}
}

func TestCheckURLRejectsNonGitHub(t *testing.T) {
	bad := []string{
		"http://github.com/x",           // not HTTPS
		"https://evil.com/pojun.zip",    // domain not on the whitelist
		"https://github.com.evil.com/x", // suffix disguise
		"https://raw.githubusercontent.com.evil.com/x",
	}
	for _, raw := range bad {
		u := mustParse(t, raw)
		if err := checkURL(u); err == nil {
			t.Errorf("checkURL(%q) should be rejected", raw)
		}
	}
	good := []string{
		"https://api.github.com/repos/x/releases/latest",
		"https://objects.githubusercontent.com/blah",
		"https://GitHub.com/x", // domains are case-insensitive
	}
	for _, raw := range good {
		u := mustParse(t, raw)
		if err := checkURL(u); err != nil {
			t.Errorf("checkURL(%q) should be allowed but errored: %v", raw, err)
		}
	}
}

func TestAssetNameMatchesBuildScript(t *testing.T) {
	// build.sh's package_binary uses pojun-<version>-<os>-<arch>.zip and strips the v
	// prefix from the version. One wrong character here and one-click update cannot find
	// the asset on any platform.
	if got := AssetName("v0.3.8", "linux", "amd64"); got != "pojun-0.3.8-linux-amd64.zip" {
		t.Errorf("AssetName = %q", got)
	}
	if got := AssetName("0.3.8", "windows", "amd64"); got != "pojun-0.3.8-windows-amd64.zip" {
		t.Errorf("AssetName = %q", got)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestSettleClearsMarkerAndStopsRollback(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "new", 0)
	fakeBin(t, p.Old, "old", 0)
	if err := writeMarker(p.Marker, marker{From: "0.3.7", To: "0.3.8", Attempts: 2}); err != nil {
		t.Fatal(err)
	}

	settle(p)

	if _, err := os.Stat(p.Marker); !os.IsNotExist(err) {
		t.Fatal("the upgrade marker must be cleared once stability is confirmed")
	}
	// With the marker gone, later normal restarts no longer count attempts or trigger a
	// spurious rollback.
	if _, ok := readMarker(p.Marker); ok {
		t.Error("reading the marker should fail")
	}
	// The backup must stay so the user can still roll back manually.
	if _, err := os.Stat(p.Old); err != nil {
		t.Error("the previous version backup should still be kept after stability is confirmed")
	}
}

func TestSettleIsNoopWithoutMarker(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "cur", 0)
	settle(p) // normal startup path: must not panic and must not touch any file
	if _, err := os.Stat(p.Current); err != nil {
		t.Error("settle should not affect any file when there is no marker")
	}
}
