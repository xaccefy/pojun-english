package selfupdate

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// This file provides two atomic operations: "download and verify a release bundle"
// and "extract one file out of the bundle".
//
// They are factored out so the **companion binary** (pojun-hostd) can reuse the same
// security checks: it runs as root from /usr/local/bin, the main service cannot write
// there, and only it can replace itself; if it grew its own download-verification
// logic, one side would eventually skip a check.
//
// The verification chain is identical to the main program: release asset name → digest
// listed in SHA256SUMS → compare against the computed digest.

// FetchVerifiedZip downloads the release bundle for the current platform/architecture
// from rel, verifies it against SHA256SUMS and returns the local path. The caller is
// responsible for deleting the returned file.
//
// The file lands under dir rather than /tmp: /tmp is often a separate mount point and a
// cross-device rename fails.
func FetchVerifiedZip(ctx context.Context, c *http.Client, rel *Release, dir string, prog Progress) (string, error) {
	if rel == nil {
		return "", fmt.Errorf("missing release information")
	}
	if prog == nil {
		prog = func(Phase, int, string) {}
	}
	name := AssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	asset, ok := rel.FindAsset(name)
	if !ok {
		return "", fmt.Errorf("this version provides no bundle for %s/%s (missing %s)", runtime.GOOS, runtime.GOARCH, name)
	}

	prog(PhaseDownload, 0, "Fetching checksum list…")
	sums, err := fetchSums(ctx, c, rel)
	if err != nil {
		return "", err
	}
	want, ok := sums[name]
	if !ok {
		return "", fmt.Errorf("%s does not list %s; refusing to install an unverified binary", sumsAsset, name)
	}

	zipPath := filepath.Join(dir, name+".part")
	prog(PhaseDownload, 0, fmt.Sprintf("Downloading %s (%s)…", name, humanSize(asset.Size)))
	got, err := download(ctx, c, asset, zipPath, prog)
	if err != nil {
		_ = os.Remove(zipPath)
		return "", err
	}

	prog(PhaseVerify, -1, "Verifying SHA256…")
	if !strings.EqualFold(got, want) {
		_ = os.Remove(zipPath)
		return "", fmt.Errorf("SHA256 mismatch: expected %s, got %s (corrupt download or tampering)", short(want), short(got))
	}
	return zipPath, nil
}

// ExtractMember extracts the file whose **base name** is baseName from the release
// bundle and writes it to dst (0755).
//
// Matching by base name rather than building the full path: the directory name inside
// the bundle carries the version, so one wrong character fails the whole thing; looking
// it up by base name is more resilient and unaffected by extra nesting in the bundle.
func ExtractMember(zipPath, baseName, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open release bundle: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Base(entry.Name), baseName) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name, err)
		}
		defer rc.Close()

		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("write %s: %w", baseName, err)
		}
		defer f.Close()

		n, err := io.Copy(f, io.LimitReader(rc, maxBinarySize+1))
		if err != nil {
			return fmt.Errorf("extract %s: %w", entry.Name, err)
		}
		if n > maxBinarySize {
			return fmt.Errorf("%s inside the bundle exceeds %s; refusing to extract", baseName, humanSize(maxBinarySize))
		}
		if n == 0 {
			return fmt.Errorf("%s inside the bundle is an empty file", baseName)
		}
		return f.Sync()
	}
	return fmt.Errorf("%s was not found in the release bundle", baseName)
}

// ReplaceBinary atomically installs newPath at target (keeping the old version as
// target+".prev").
//
// Used by the companion binary to replace itself: a same-directory rename is atomic,
// and keeping a copy of the old version allows a manual revert if the new one will not
// start.
func ReplaceBinary(newPath, target string) error {
	prev := target + ".prev"
	_ = os.Remove(prev)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, prev); err != nil {
			return fmt.Errorf("back up current version: %w", err)
		}
	}
	if err := os.Rename(newPath, target); err != nil {
		// If the install fails, put the old one back or the next restart has no executable.
		if rerr := os.Rename(prev, target); rerr != nil {
			return fmt.Errorf("failed to install the new version (%v) and failed to restore the old version: %w", err, rerr)
		}
		return fmt.Errorf("install new version: %w", err)
	}
	_ = os.Chmod(target, 0o755)
	return nil
}

// SmokeTestBinary launches a binary with -h to confirm it can really execute on this
// system. It blocks truncated downloads, wrong architecture (exec format error) and
// missing dynamic libraries.
func SmokeTestBinary(bin string, args ...string) error {
	if len(args) == 0 {
		args = []string{"-h"}
	}
	return smokeTestWithArgs(bin, args)
}

// Timeout constant reused by SmokeTestBinary.
const smokeTimeout = 30 * time.Second

// smokeTestWithArgs is the smoke test implementation, letting the caller pick the probe
// arguments (pojun uses -h; pojun-hostd uses -version because its -h also exits 0 but
// prints less).
func smokeTestWithArgs(bin string, args []string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("make executable: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("smoke test timed out (the new binary did not respond)")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("smoke test failed: %v: %s", err, snippet)
	}
	return nil
}
