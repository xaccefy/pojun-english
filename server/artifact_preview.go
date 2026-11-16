package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/docpreview"
)

// Document previews (v0.4.21): Word/Excel/PPT/PDF sampled and rendered to images for
// task evidence cards and reports. Previews are sidecar files
// (artifacts/previews/<id>/page-N.jpg) — not stored in the DB, not counted against the
// 100-attachment cap; protected separately by a 100MB per-task cap.
const (
	maxPreviewPages      = docpreview.DefaultPages
	maxTaskPreviewBytes  = 100 << 20
	previewQueueCapacity = 64
)

// ensurePreviewWorker lazily starts the single worker. Concurrent LibreOffice
// conversions fight over the profile lock, so the whole process runs one conversion at a
// time (serial queue) — slow but stable.
func (s *Server) ensurePreviewWorker() {
	s.previewOnce.Do(func() {
		s.previewQ = make(chan int64, previewQueueCapacity)
		go func() {
			for id := range s.previewQ {
				s.generateArtifactPreview(id)
			}
		}()
	})
}

// enqueueArtifactPreview queues a document attachment for preview. force=true is for
// manual retries and overwrites ready previews; by default ready/pending records are
// skipped.
func (s *Server) enqueueArtifactPreview(a *db.TaskArtifact, force bool) {
	if a == nil || a.ID <= 0 || !docpreview.Supports(a.Name) {
		return
	}
	// skip only ready ones; pending must still be delivered — new attachments are marked
	// pending before Insert, so treating pending as 'already queued' would wedge them
	// forever (measured v0.4.22). True duplicate delivery is blocked by the in-flight
	// previewIDs table below.
	if !force && a.PreviewState == "ready" {
		return
	}
	pg := s.m.PG()
	if pg == nil {
		return
	}
	s.ensurePreviewWorker()
	s.previewMu.Lock()
	if s.previewIDs == nil {
		s.previewIDs = make(map[int64]bool)
	}
	if s.previewIDs[a.ID] {
		s.previewMu.Unlock()
		return
	}
	s.previewIDs[a.ID] = true
	s.previewMu.Unlock()
	_ = pg.SetTaskArtifactPreview(a.ID, "pending", 0, "")
	go func() {
		defer func() {
			s.previewMu.Lock()
			delete(s.previewIDs, a.ID)
			s.previewMu.Unlock()
		}()
		select {
		case s.previewQ <- a.ID:
		case <-time.After(5 * time.Second):
			_ = pg.SetTaskArtifactPreview(a.ID, "failed", 0, "preview queue busy — retry manually later")
		}
	}()
}

// recoverPendingPreviews re-queues previews unfinished when the process last exited
// (v0.4.23). Otherwise pending records stay stuck at 'generating'.
func (s *Server) recoverPendingPreviews() {
	pg := s.m.PG()
	if pg == nil {
		return
	}
	list, err := pg.ListPendingPreviewArtifacts()
	if err != nil || len(list) == 0 {
		return
	}
	log.Printf("[artifact-preview] recovered %d unfinished previews", len(list))
	for i := range list {
		s.enqueueArtifactPreview(&list[i], false)
	}
}

// generateArtifactPreview performs the actual conversion (called serially by the
// worker).
func (s *Server) generateArtifactPreview(id int64) {
	pg := s.m.PG()
	if pg == nil {
		return
	}
	a, err := pg.GetTaskArtifact(id)
	if err != nil || a == nil {
		return
	}
	if !docpreview.Supports(a.Name) {
		_ = pg.SetTaskArtifactPreview(id, "skipped", 0, "not a document type — no preview needed")
		return
	}
	if s.taskPreviewBytes(a.TaskID) > maxTaskPreviewBytes {
		_ = pg.SetTaskArtifactPreview(id, "skipped", 0, "this task's preview total hit the 100MB cap — clean up and retry")
		return
	}
	src := filepath.Join(s.m.dir, a.Storage)
	outDir := s.previewDir(a.TaskID, id)
	pages, err := docpreview.Generate(context.Background(), src, outDir, maxPreviewPages)
	if err != nil {
		state, msg := "failed", err.Error()
		if errors.Is(err, docpreview.ErrSofficeMissing) || errors.Is(err, docpreview.ErrPdftoppmMissing) {
			state = "skipped"
			msg += "; install libreoffice + poppler-utils via one-click install or the 'Host environment' page"
		}
		_ = pg.SetTaskArtifactPreview(id, state, 0, msg)
		log.Printf("[artifact-preview] #%d %s: %v", id, a.Name, err)
		return
	}
	_ = pg.SetTaskArtifactPreview(id, "ready", pages, "")
}

func (s *Server) previewDir(taskID string, artifactID int64) string {
	return filepath.Join(s.taskArtifactsDir(taskID), "previews", strconv.FormatInt(artifactID, 10))
}

// taskPreviewBytes totals this task's generated previews (no unbounded disk use).
func (s *Server) taskPreviewBytes(taskID string) int64 {
	root := filepath.Join(s.taskArtifactsDir(taskID), "previews")
	var total int64
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// serveArtifactPreview serves preview pages (page-1.jpg…): inline images, cacheable.
func (s *Server) serveArtifactPreview(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil || aid <= 0 {
		writeErr(w, 400, "bad artifact id")
		return
	}
	page, err := strconv.Atoi(r.PathValue("page"))
	if err != nil || page <= 0 {
		writeErr(w, 400, "bad page")
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
	if a.PreviewState != "ready" || page > a.PreviewPages {
		writeErr(w, 404, "preview not ready")
		return
	}
	file := filepath.Join(s.previewDir(taskID, aid), fmt.Sprintf("page-%d.jpg", page))
	if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "preview file missing")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeFile(w, r, file)
}

// regenerateArtifactPreview manually retries (or first-generates) a document preview.
func (s *Server) regenerateArtifactPreview(w http.ResponseWriter, r *http.Request) {
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
	if !docpreview.Supports(a.Name) {
		writeErr(w, 400, "this attachment isn't a document type — no preview to generate")
		return
	}
	s.enqueueArtifactPreview(a, true)
	writeJSON(w, 202, map[string]any{"state": "pending", "artifact_id": aid})
}
