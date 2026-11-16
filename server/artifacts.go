package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/docpreview"
)

// evidence-attachment limits (v0.5.0). Default 'sample policy': workers keep only
// evidentiary samples — bulk data stays in the task workdir, not distributed with the
// report. The limits guard against storing full PII/oversized files by mistake.
const (
	maxArtifactFileBytes = 20 << 20  // 20MB per file
	maxTaskArtifactCount = 300       // max 300 per task (real tasks often exceed 100 evidence items)
	maxTaskArtifactBytes = 500 << 20 // 500MB total per task
)

// artifactKindByExt infers the attachment kind from the extension (for sectioned
// display in reports).
func artifactKindByExt(name string) (kind, mime string) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image", "image/png"
	case ".jpg", ".jpeg":
		return "image", "image/jpeg"
	case ".gif":
		return "image", "image/gif"
	case ".webp":
		return "image", "image/webp"
	case ".json":
		return "data", "application/json"
	case ".csv":
		return "spreadsheet", "text/csv"
	case ".txt", ".log":
		return "log", "text/plain"
	case ".html", ".htm":
		return "html", "text/html"
	case ".xml":
		return "data", "application/xml"
	case ".pdf":
		return "pdf", "application/pdf"
	case ".doc":
		return "document", "application/msword"
	case ".docx":
		return "document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".odt":
		return "document", "application/vnd.oasis.opendocument.text"
	case ".rtf":
		return "document", "application/rtf"
	case ".xls":
		return "spreadsheet", "application/vnd.ms-excel"
	case ".xlsx":
		return "spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".ods":
		return "spreadsheet", "application/vnd.oasis.opendocument.spreadsheet"
	case ".ppt":
		return "presentation", "application/vnd.ms-powerpoint"
	case ".pptx":
		return "presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case ".odp":
		return "presentation", "application/vnd.oasis.opendocument.presentation"
	}
	return "other", "application/octet-stream"
}

// sanitizeArtifactName strips path separators and control chars, and clamps length.
func sanitizeArtifactName(name string) string {
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "artifact"
	}
	if len([]rune(name)) > 120 {
		name = string([]rune(name)[:120])
	}
	return name
}

// taskArtifactsDir is the task's attachment dir (data/tasks/<taskID>/artifacts).
func (s *Server) taskArtifactsDir(taskID string) string {
	return filepath.Join(s.m.dir, "tasks", taskID, "artifacts")
}

// RecordArtifact registers a file from the task workdir as an evidence attachment:
// validate path bounds and limits → sha256 (per-task dedupe) → copy into the task
// artifacts dir → persist. relPath is relative to runDir (the worker's workdir) and must
// stay inside tasks/<taskID>/.
func (s *Server) RecordArtifact(taskID, findingID int64, runDir, relPath, name, kind, sourceURL, note string) (*db.TaskArtifact, error) {
	pg := s.m.PG()
	if pg == nil {
		return nil, fmt.Errorf("PG unavailable")
	}
	taskKey := strconv.FormatInt(taskID, 10)
	if strings.TrimSpace(relPath) == "" {
		return nil, fmt.Errorf("path must not be empty")
	}
	clean := filepath.Clean(relPath)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("path must be relative to the workdir")
	}
	abs := filepath.Join(runDir, clean)
	// path bounds: must stay under tasks/<taskID>/ (no traversal into other tasks or
	// other data areas). Symlinks are resolved on both sides before comparing, so links
	// can't escape the task dir.
	taskRoot := filepath.Join(s.m.dir, "tasks", taskKey)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if resolved, err := filepath.EvalSymlinks(taskRoot); err == nil {
		taskRoot = resolved
	}
	relToTask, err := filepath.Rel(taskRoot, abs)
	if err != nil || strings.HasPrefix(relToTask, "..") {
		return nil, fmt.Errorf("path escapes the task directory")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("file missing or unreadable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("only regular files supported")
	}
	if info.Size() <= 0 {
		return nil, fmt.Errorf("file is empty")
	}
	if info.Size() > maxArtifactFileBytes {
		return nil, fmt.Errorf("file exceeds the per-attachment cap (20MB): %d bytes", info.Size())
	}
	if count, total, err := pg.CountTaskArtifacts(taskKey); err == nil {
		if count >= maxTaskArtifactCount {
			return nil, fmt.Errorf("this task already has the max %d attachments — merge or delete before adding", maxTaskArtifactCount)
		}
		if total+info.Size() > maxTaskArtifactBytes {
			return nil, fmt.Errorf("this task's attachments would exceed the 500MB total cap")
		}
	}

	return s.recordArtifactAbs(abs, taskKey, findingID, name, kind, sourceURL, note, info.Size())
}

// listTaskArtifacts lists task attachments (no storage paths).
func (s *Server) listTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG unavailable")
		return
	}
	list, err := pg.ListTaskArtifacts(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []db.TaskArtifact{}
	}
	writeJSON(w, 200, map[string]any{"artifacts": list})
}

// patchTaskArtifact changes an attachment's owner (v0.4.20). body {finding_id}:
// 0 = back to task-level; non-zero must be a finding of this task.
func (s *Server) patchTaskArtifact(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil || aid <= 0 {
		writeErr(w, 400, "bad artifact id")
		return
	}
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG unavailable")
		return
	}
	a, err := pg.GetTaskArtifact(aid)
	if err != nil || a == nil || a.TaskID != taskID {
		writeErr(w, 404, "artifact not found")
		return
	}
	var req struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if req.FindingID < 0 {
		writeErr(w, 400, "finding_id must not be negative")
		return
	}
	if req.FindingID > 0 {
		f, err := pg.GetFinding(req.FindingID)
		if err != nil || f == nil || f.TaskID == nil || strconv.FormatInt(*f.TaskID, 10) != taskID {
			writeErr(w, 400, "finding does not belong to this task")
			return
		}
	}
	updated, err := pg.UpdateTaskArtifactFinding(aid, req.FindingID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"artifact": updated})
}

// serveTaskArtifact serves one attachment:
//   - images default to inline (frontend <img> previews directly); ?download=1 forces
//     download;
//   - ?thumb=1 returns a 480px-long-edge JPEG thumbnail (disk-cached .thumb.jpg) — list
//     pages use thumbs so dozens of 3MB originals don't fail to load;
//   - non-images always download as attachment.
func (s *Server) serveTaskArtifact(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid artifact id")
		return
	}
	a, err := pg.GetTaskArtifact(id)
	if err != nil || a == nil || a.TaskID != r.PathValue("id") {
		writeErr(w, 404, "artifact not found")
		return
	}
	abs := filepath.Join(s.m.dir, a.Storage)
	if _, err := os.Stat(abs); err != nil {
		writeErr(w, 404, "attachment file missing")
		return
	}
	// MIME may be empty (historical registrations / scan backfills) — then judge by
	// kind, else images get treated as plain attachment downloads and the browser
	// errors (v0.4.16 fix).
	isImage := a.Kind == "image" || strings.HasPrefix(strings.ToLower(a.Mime), "image/")
	q := r.URL.Query()
	switch {
	case isImage && q.Get("thumb") != "":
		thumb := abs + ".thumb.jpg"
		if _, err := os.Stat(thumb); err != nil {
			if err := writeThumbnail(abs, thumb, 480); err != nil {
				// on thumbnail failure fall back to the original — at least it displays.
				w.Header().Set("Content-Type", a.Mime)
				w.Header().Set("Cache-Control", "private, max-age=300")
				http.ServeFile(w, r, abs)
				return
			}
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		http.ServeFile(w, r, thumb)
	case isImage && q.Get("download") == "":
		w.Header().Set("Content-Type", a.Mime)
		w.Header().Set("Content-Disposition", "inline")
		w.Header().Set("Cache-Control", "private, max-age=600")
		http.ServeFile(w, r, abs)
	default:
		w.Header().Set("Content-Type", a.Mime)
		w.Header().Set("Content-Disposition", attachmentDisposition(sanitizeArtifactName(a.Name)))
		http.ServeFile(w, r, abs)
	}
}

// writeThumbnail produces a JPEG thumbnail (long edge maxEdge), disk-cached.
// Prefers ImageMagick (4K images in milliseconds; per-pixel Go rescaling was slow
// enough to time out requests — measured 1–2s for one 3072x4096 image, many failures
// when the frontend loaded 6–12 concurrently — v0.4.16 fix). Falls back to the pure-Go
// implementation when ImageMagick is unavailable or fails.
func writeThumbnail(src, dst string, maxEdge int) error {
	if bin := findImageMagick(); bin != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, src,
			"-auto-orient",
			"-resize", fmt.Sprintf("%dx%d>", maxEdge, maxEdge),
			"-quality", "82",
			dst)
		if err := cmd.Run(); err == nil {
			if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
				return nil
			}
		}
		_ = os.Remove(dst)
	}
	return writeThumbnailGo(src, dst, maxEdge)
}

// findImageMagick returns a usable ImageMagick command path (empty = unavailable).
// -version output must be verified: Windows' built-in convert.exe is a disk-utility —
// same name, definitely not ImageMagick (misuse risks disk damage).
func findImageMagick() string {
	for _, name := range []string{"magick", "convert"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out, err := exec.Command(p, "-version").Output()
		if err != nil || !strings.Contains(string(out), "ImageMagick") {
			continue
		}
		return p
	}
	return ""
}

// writeThumbnailGo is the pure-Go fallback (bilinear scaling).
func writeThumbnailGo(src, dst string, maxEdge int) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	img, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		return err
	}
	b := img.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 0 || sh <= 0 {
		return fmt.Errorf("empty image")
	}
	scale := math.Min(float64(maxEdge)/float64(sw), float64(maxEdge)/float64(sh))
	if scale >= 1 {
		scale = 1
	}
	tw, th := int(float64(sw)*scale), int(float64(sh)*scale)
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}
	out := image.NewRGBA(image.Rect(0, 0, tw, th))
	for y := 0; y < th; y++ {
		sy := (float64(y)+0.5)*float64(sh)/float64(th) - 0.5
		y0 := int(math.Floor(sy))
		fy := sy - float64(y0)
		if y0 < 0 {
			y0 = 0
			fy = 0
		}
		y1 := y0 + 1
		if y1 >= sh {
			y1 = sh - 1
		}
		for x := 0; x < tw; x++ {
			sx := (float64(x)+0.5)*float64(sw)/float64(tw) - 0.5
			x0 := int(math.Floor(sx))
			fx := sx - float64(x0)
			if x0 < 0 {
				x0 = 0
				fx = 0
			}
			x1 := x0 + 1
			if x1 >= sw {
				x1 = sw - 1
			}
			r0, g0, b0, _ := img.At(b.Min.X+x0, b.Min.Y+y0).RGBA()
			r1, g1, b1, _ := img.At(b.Min.X+x1, b.Min.Y+y0).RGBA()
			r2, g2, b2, _ := img.At(b.Min.X+x0, b.Min.Y+y1).RGBA()
			r3, g3, b3, _ := img.At(b.Min.X+x1, b.Min.Y+y1).RGBA()
			topR := float64(r0)*(1-fx) + float64(r1)*fx
			topG := float64(g0)*(1-fx) + float64(g1)*fx
			topB := float64(b0)*(1-fx) + float64(b1)*fx
			botR := float64(r2)*(1-fx) + float64(r3)*fx
			botG := float64(g2)*(1-fx) + float64(g3)*fx
			botB := float64(b2)*(1-fx) + float64(b3)*fx
			out.SetRGBA(x, y, color.RGBA{
				R: uint8((topR*(1-fy) + botR*fy) / 257),
				G: uint8((topG*(1-fy) + botG*fy) / 257),
				B: uint8((topB*(1-fy) + botB*fy) / 257),
				A: 255,
			})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: 80}); err != nil {
		return err
	}
	return os.WriteFile(dst, buf.Bytes(), 0o644)
}

// exportTaskArtifacts zips all task attachments: artifacts/<name> + manifest.json.
// The manifest records source URL, capture time, sha256, and notes — required for SRC
// forensic submission.
func (s *Server) exportTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG unavailable")
		return
	}
	list, err := pg.ListTaskArtifacts(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(list) == 0 {
		writeErr(w, 404, "this task has no evidence attachments")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="task-%s-artifacts.zip"`, taskID))
	zw := zip.NewWriter(w)
	defer zw.Close()
	manifest := make([]map[string]any, 0, len(list))
	seen := map[string]int{}
	for _, a := range list {
		abs := filepath.Join(s.m.dir, a.Storage)
		data, err := os.ReadFile(abs)
		if err != nil {
			continue // registrations whose files are lost get skipped — honestly absent from the manifest
		}
		name := a.Name
		if n := seen[name]; n > 0 {
			ext := filepath.Ext(name)
			name = strings.TrimSuffix(name, ext) + fmt.Sprintf("-%d", n+1) + ext
		}
		seen[a.Name]++
		fw, err := zw.Create("artifacts/" + name)
		if err != nil {
			continue
		}
		_, _ = fw.Write(data)
		manifest = append(manifest, map[string]any{
			"id": a.ID, "finding_id": a.FindingID, "file": "artifacts/" + name, "name": a.Name, "kind": a.Kind,
			"mime": a.Mime, "size_bytes": a.SizeBytes, "sha256": a.SHA256,
			"source_url": a.SourceURL, "note": a.Note,
			"created_at": a.CreatedAt.Format(time.RFC3339),
		})
	}
	mf, _ := json.MarshalIndent(map[string]any{
		"task_id":     taskID,
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"policy":      "Evidence policy (v0.4.34): first-party submission to the vendor — attachments are kept verbatim, unmasked and unredacted; large datasets may be kept whole (cap 300 items / 500MB), with key samples and the manifest prioritized past the cap.",
		"artifacts":   manifest,
	}, "", "  ")
	if fw, err := zw.Create("manifest.json"); err == nil {
		_, _ = fw.Write(mf)
	}
}

// artifactImageData reads one image attachment (for embedding in report docx).
func (s *Server) artifactImageData(a *db.TaskArtifact) ([]byte, bool) {
	if a == nil || a.Kind != "image" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(s.m.dir, a.Storage))
	if err != nil {
		return nil, false
	}
	return data, true
}

// artifactListJSON feeds the attachment list into the report's 'Attachments' section.
func artifactListJSON(list []db.TaskArtifact) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]any{
			"id": a.ID, "finding_id": a.FindingID, "name": a.Name, "kind": a.Kind, "size_bytes": a.SizeBytes,
			"note": a.Note, "source_url": a.SourceURL,
		})
	}
	return out
}

// recordArtifactAbs registers an attachment by absolute path (the caller already did
// the path-bounds check).
func (s *Server) recordArtifactAbs(abs, taskKey string, findingID int64, name, kind, sourceURL, note string, size int64) (*db.TaskArtifact, error) {
	pg := s.m.PG()
	if pg == nil {
		return nil, fmt.Errorf("PG unavailable")
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	// dedupe: same task + same content returns the existing registration without
	// re-writing. v0.4.20: screenshots often happen before report_finding (no
	// finding_id yet); on a later re-registration of the same file, dedupe must not
	// drop the ownership — backfill the binding when the old row is still task-level;
	// never steal a row already bound to another finding (don't move A's evidence to B).
	if list, err := pg.ListTaskArtifacts(taskKey); err == nil {
		for i := range list {
			if list[i].SHA256 == sha && list[i].SizeBytes == size {
				existing := &list[i]
				if findingID > 0 && existing.FindingID == 0 {
					if updated, uerr := pg.UpdateTaskArtifactBinding(existing.ID, findingID, note, sourceURL); uerr == nil {
						s.enqueueArtifactPreview(updated, false)
						return updated, nil
					}
				}
				s.enqueueArtifactPreview(existing, false)
				return existing, nil
			}
		}
	}

	if strings.TrimSpace(name) == "" {
		name = filepath.Base(abs)
	}
	name = sanitizeArtifactName(name)
	autoKind, autoMime := artifactKindByExt(name)
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" || kind == "auto" {
		kind = autoKind
	}
	dir := s.taskArtifactsDir(taskKey)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create the artifacts dir: %w", err)
	}
	storage := filepath.Join("tasks", taskKey, "artifacts",
		fmt.Sprintf("%d-%s", time.Now().UnixNano(), name))
	dst := filepath.Join(s.m.dir, storage)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write the attachment: %w", err)
	}
	a := &db.TaskArtifact{
		TaskID: taskKey, FindingID: findingID, Name: name, Kind: kind, Mime: autoMime,
		SizeBytes: int64(len(data)), SHA256: sha, SourceURL: sourceURL,
		Note: note, Storage: storage,
	}
	if docpreview.Supports(name) {
		a.PreviewState = "pending" // frontend immediately shows 'generating'; the worker overwrites it
	}
	if err := pg.InsertTaskArtifact(context.Background(), a); err != nil {
		_ = os.Remove(dst)
		return nil, fmt.Errorf("failed to register the attachment: %w", err)
	}
	// Office/PDF attachments get an async sampled preview (v0.4.21) — doesn't block
	// save_evidence.
	s.enqueueArtifactPreview(a, false)
	return a, nil
}

// scanTaskArtifactDir scans a task workdir for historical images and back-fills
// registrations (v0.4.10). Scenario: old tasks captured photos into the workdir before
// the attachments feature shipped — make them appear in the frontend and reports.
// Limit 60, skip existing (sha256 dedupe), skip the artifacts dir itself.
func (s *Server) scanTaskArtifactDir(taskID string) (added, skipped, truncated int, err error) {
	pg := s.m.PG()
	if pg == nil {
		return 0, 0, 0, fmt.Errorf("PG unavailable")
	}
	root := filepath.Join(s.m.dir, "tasks", taskID)
	artifactsDir := s.taskArtifactsDir(taskID)
	existing := map[string]bool{}
	if list, e := pg.ListTaskArtifacts(taskID); e == nil {
		for _, a := range list {
			existing[a.SHA256] = true
		}
	}
	const limit = 60
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if path == artifactsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".png", ".jpg", ".jpeg", ".gif", ".webp",
			".pdf", ".doc", ".docx", ".odt", ".rtf",
			".xls", ".xlsx", ".ods", ".csv",
			".ppt", ".pptx", ".odp":
		default:
			return nil
		}
		if added >= limit {
			truncated++
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() <= 0 || info.Size() > maxArtifactFileBytes {
			return nil
		}
		// sha256 pre-check (avoid reading a big file just to find a dup)
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil {
			f.Close()
			return nil
		}
		f.Close()
		sum := hex.EncodeToString(h.Sum(nil))
		if existing[sum] {
			skipped++
			return nil
		}
		// URL-decode the filename (historical photos often look like %E7%AD%BE) so the
		// caption stays readable.
		base := filepath.Base(path)
		if decoded, e := url.QueryUnescape(base); e == nil && decoded != "" {
			base = decoded
		}
		rel, _ := filepath.Rel(root, path)
		_, e = s.recordArtifactAbs(path, taskID, 0, base, "auto", "", "workdir historical file: "+rel, info.Size())
		if e != nil {
			return nil
		}
		existing[sum] = true
		added++
		return nil
	})
	return added, skipped, truncated, walkErr
}

// scanTaskArtifacts scans a task workdir for historical images and back-fills
// registrations (v0.4.10).
// POST /api/tasks/{id}/artifacts/scan
func (s *Server) scanTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	added, skipped, truncated, err := s.scanTaskArtifactDir(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"added": added, "skipped": skipped, "truncated": truncated,
		"note": "Images and documents (Word/Excel/PPT/PDF) in the task workdir were back-registered as evidence attachments (max 60 per call); best run after the task ends so temp files aren't swept in.",
	})
}
