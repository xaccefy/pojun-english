package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chu0119/pojun/selfupdate"
)

// ValidVersionTag reports whether tag is an allowed version form. The validation lives in
// selfupdate, next to the "fetch the Release by version" logic, so the rule cannot drift
// between two places.
func ValidVersionTag(tag string) bool { return selfupdate.ValidVersionTag(tag) }

// UpgradeSelf replaces the helper itself with the given Release version.
//
// Why the helper must do it itself: it is installed in root-owned /usr/local/bin, and the
// main service cannot write there because of ProtectSystem=strict.
//
// Why "download it yourself" rather than "accept a file handed over by the main service":
// the main service only runs with the business user's privileges, and if it were
// compromised, having the helper install any binary it names would hand over root
// execution. So the helper insists on pulling the bundle from the official Release,
// verifying it against SHA256SUMS and smoke testing it itself; the main service can only
// influence "which published version gets installed", never "what content gets installed".
func (s *Server) UpgradeSelf(ctx context.Context, tag, proxy string) error {
	tag = strings.TrimSpace(tag)
	if !ValidVersionTag(tag) {
		return fmt.Errorf("invalid version format: %q", tag)
	}
	if s.SelfPath == "" {
		return fmt.Errorf("own path is unknown, cannot self-upgrade")
	}
	dir := filepath.Dir(s.SelfPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("prepare target directory %s: %w", dir, err)
	}

	c := selfupdate.NewClient(proxy)
	rel, err := selfupdate.FetchByTag(ctx, c, tag)
	if err != nil {
		return err
	}
	// Both the zip and the temp binary land in the target directory: a cross-filesystem
	// rename fails, and /tmp is often a separate mount point.
	zipPath, err := selfupdate.FetchVerifiedZip(ctx, c, rel, dir, nil)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(zipPath) }()

	tmp := filepath.Join(dir, ".pojun-hostd.new")
	defer func() { _ = os.Remove(tmp) }()
	if err := selfupdate.ExtractMember(zipPath, "pojun-hostd", tmp); err != nil {
		return fmt.Errorf("the release bundle has no pojun-hostd: %w", err)
	}
	if err := selfupdate.SmokeTestBinary(tmp, "-version"); err != nil {
		return fmt.Errorf("the new version cannot run on this system: %w", err)
	}
	if err := selfupdate.ReplaceBinary(tmp, s.SelfPath); err != nil {
		return err
	}
	return nil
}
