// Package docpreview samples Office / PDF documents captured during a task and
// renders them into images: Office files (doc/xls/ppt/csv) are first converted to
// PDF by LibreOffice, then poppler's pdftoppm renders the first N pages as JPEG.
// It only performs stateless conversion; persistence and queueing are the caller's
// responsibility.
package docpreview

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrSofficeMissing / ErrPdftoppmMissing let callers distinguish "dependency not
// installed" from "the document is broken".
var (
	ErrSofficeMissing  = errors.New("LibreOffice (soffice) is not installed")
	ErrPdftoppmMissing = errors.New("poppler-utils (pdftoppm) is not installed")
)

// DefaultPages is the maximum number of pages sampled per document.
const DefaultPages = 3

// Upper time bound for a single conversion: a cold LibreOffice start plus a large
// document can be slow, but it must not hang forever.
const convertTimeout = 120 * time.Second

// KindFor infers the document kind from the extension; an empty string means
// preview is not supported. The naming is aligned with the server's artifact
// kind: document/spreadsheet/presentation/pdf.
func KindFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".doc", ".docx", ".odt", ".rtf":
		return "document"
	case ".xls", ".xlsx", ".ods", ".csv":
		return "spreadsheet"
	case ".ppt", ".pptx", ".odp":
		return "presentation"
	case ".pdf":
		return "pdf"
	}
	return ""
}

// Supports reports whether a preview can be generated for this file.
func Supports(name string) bool { return KindFor(name) != "" }

// Generate renders src into outDir/page-1.jpg..., up to maxPages pages, and returns
// the actual page count. outDir is created (existing page files with the same name
// are overwritten); temporary files are cleaned up automatically.
func Generate(ctx context.Context, src, outDir string, maxPages int) (int, error) {
	if maxPages <= 0 {
		maxPages = DefaultPages
	}
	if st, err := os.Stat(src); err != nil || !st.Mode().IsRegular() {
		return 0, fmt.Errorf("source file is not readable")
	}
	if !Supports(src) {
		return 0, fmt.Errorf("unsupported file type: %s", filepath.Ext(src))
	}
	tmp, err := os.MkdirTemp("", "pojun-preview-")
	if err != nil {
		return 0, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	pdf := src
	if KindFor(src) != "pdf" {
		pdf, err = officeToPDF(ctx, src, tmp)
		if err != nil {
			return 0, err
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, fmt.Errorf("create preview dir: %w", err)
	}
	// Clear the previous page files so a retry does not leave extra pages behind.
	if olds, _ := filepath.Glob(filepath.Join(outDir, "page-*.jpg")); len(olds) > 0 {
		for _, f := range olds {
			_ = os.Remove(f)
		}
	}
	return pdfToJPEGs(ctx, pdf, outDir, maxPages)
}

// officeToPDF converts to PDF with headless LibreOffice. UserInstallation is
// isolated so concurrent runs do not fight over the same user profile; HOME also
// points at the temp dir so nothing is written into the service user's home.
func officeToPDF(ctx context.Context, src, tmp string) (string, error) {
	bin, err := findSoffice()
	if err != nil {
		return "", err
	}
	profile := filepath.ToSlash(filepath.Join(tmp, "lo-profile"))
	profileURL := "file://" + profile
	if !strings.HasPrefix(profile, "/") {
		profileURL = "file:///" + profile // Windows: file:///C:/...
	}
	runCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()
	args := []string{
		"--headless", "--norestore", "--nologo", "--nolockcheck", "--nodefault",
		"-env:UserInstallation=" + profileURL,
		"--convert-to", "pdf", "--outdir", tmp, src,
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+tmp)
	// cwd must be an accessible directory: the soffice wrapper script cds back to the
	// directory it was started from (e.g. started as root from /root and then run via
	// sudo -u pojun, where pojun cannot enter /root and fails outright).
	cmd.Dir = tmp
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("LibreOffice conversion timed out (%s)", convertTimeout)
		}
		if msg != "" {
			return "", fmt.Errorf("LibreOffice conversion failed: %v (%s)", runErr, msg)
		}
		return "", fmt.Errorf("LibreOffice conversion failed: %v", runErr)
	}
	matches, _ := filepath.Glob(filepath.Join(tmp, "*.pdf"))
	if len(matches) == 0 {
		return "", fmt.Errorf("LibreOffice produced no PDF")
	}
	// Prefer the PDF with the same name, otherwise take the first one (LibreOffice may
	// normalize file names).
	want := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src)) + ".pdf"
	for _, m := range matches {
		if strings.EqualFold(filepath.Base(m), want) {
			return m, nil
		}
	}
	return matches[0], nil
}

// pdfToJPEGs renders the first maxPages pages. Output page names are normalized to
// page-1.jpg... so pdftoppm zero-padding by total page count (page-01.jpg) does not
// make the frontend's URL construction unstable.
//
// pdftoppm writes into a temp subdirectory inside outDir and then renames: /tmp and
// the data disk are often on different filesystems, and a cross-device rename fails
// with EXDEV (observed on Kali).
func pdfToJPEGs(ctx context.Context, pdf, outDir string, maxPages int) (int, error) {
	bin, err := findPdftoppm()
	if err != nil {
		return 0, err
	}
	stage, err := os.MkdirTemp(outDir, ".stage-")
	if err != nil {
		return 0, fmt.Errorf("create preview staging dir: %w", err)
	}
	defer os.RemoveAll(stage)
	prefix := filepath.Join(stage, "page")
	runCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()
	args := []string{
		"-jpeg", "-jpegopt", "quality=82", "-r", "110", "-scale-to", "1600",
		"-f", "1", "-l", strconv.Itoa(maxPages), pdf, prefix,
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Dir = stage
	out, runErr := cmd.CombinedOutput()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return 0, fmt.Errorf("PDF rendering timed out (%s)", convertTimeout)
	}
	if runErr != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if msg != "" {
			return 0, fmt.Errorf("PDF rendering failed: %v (%s)", runErr, msg)
		}
		return 0, fmt.Errorf("PDF rendering failed: %v", runErr)
	}
	files, _ := filepath.Glob(prefix + "-*.jpg")
	if len(files) == 0 {
		return 0, fmt.Errorf("PDF produced no page images (the file may be encrypted or corrupt)")
	}
	sort.Slice(files, func(i, j int) bool {
		return pageNo(files[i]) < pageNo(files[j])
	})
	if len(files) > maxPages {
		files = files[:maxPages]
	}
	for i, f := range files {
		dst := filepath.Join(outDir, fmt.Sprintf("page-%d.jpg", i+1))
		if err := os.Rename(f, dst); err != nil {
			return 0, fmt.Errorf("write preview page: %w", err)
		}
		_ = os.Chmod(dst, 0o644) // must stay readable by the service user even when maint runs as root
	}
	return len(files), nil
}

func pageNo(path string) int {
	base := strings.TrimSuffix(filepath.Base(path), ".jpg")
	i := strings.LastIndex(base, "-")
	if i < 0 {
		return 0
	}
	n, _ := strconv.Atoi(base[i+1:])
	return n
}

func findSoffice() (string, error) {
	if p, err := lookFirst([]string{"soffice", "libreoffice"},
		`C:\Program Files\LibreOffice\program\soffice.exe`,
		`C:\Program Files (x86)\LibreOffice\program\soffice.exe`,
		"/Applications/LibreOffice.app/Contents/MacOS/soffice",
	); err == nil {
		return p, nil
	}
	return "", ErrSofficeMissing
}

func findPdftoppm() (string, error) {
	if p, err := lookFirst([]string{"pdftoppm"},
		`C:\Program Files\poppler\Library\bin\pdftoppm.exe`,
		`C:\Program Files\poppler\bin\pdftoppm.exe`,
		"/opt/homebrew/bin/pdftoppm",
	); err == nil {
		return p, nil
	}
	return "", ErrPdftoppmMissing
}

// lookFirst checks PATH first, then the common install locations (GUI installers on
// Windows/macOS usually do not touch PATH).
func lookFirst(names []string, candidates ...string) (string, error) {
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("not found")
}

// Available reports whether both dependencies are present (for the host
// environment page and troubleshooting).
func Available() (soffice, pdftoppm bool) {
	_, err1 := findSoffice()
	_, err2 := findPdftoppm()
	return err1 == nil, err2 == nil
}
