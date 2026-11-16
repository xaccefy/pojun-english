package db

import (
	"context"
	"strconv"
	"time"
)

// TaskArtifact is a task-level evidence attachment (v0.5.0): data samples, screenshots and logs a worker
// scrapes are written to the task directory and registered here, then exported with the report as an evidence pack. By default only
// "proof samples" are stored (the first N rows of sensitive data); the full data stays in the task working directory and is not distributed with the report (compliance).
type TaskArtifact struct {
	ID     int64  `json:"id"`
	TaskID string `json:"task_id"`
	// FindingID is optional: which finding this image/sample proves (set when registering after the worker reports the finding).
	// 0 = task-level material (e.g. a screenshot of the target home page), which does not appear on a single finding's detail page.
	FindingID int64  `json:"finding_id,omitempty"`
	Name      string `json:"name"` // display name (including the extension)
	Kind      string `json:"kind"` // image|data|log|html|other
	Mime      string `json:"mime,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256,omitempty"`
	SourceURL string `json:"source_url,omitempty"`
	Note      string `json:"note,omitempty"` // report caption / attachment description
	// Document preview (v0.4.21): Office/PDF samples are rendered into an image, with a sidecar on disk that does not count against the attachment quota.
	// state: "" (not a document / unprocessed) | pending | ready | failed | skipped
	PreviewState string    `json:"preview_state,omitempty"`
	PreviewPages int       `json:"preview_pages,omitempty"`
	PreviewError string    `json:"preview_error,omitempty"`
	Storage      string    `json:"-"` // path relative to the data directory (not exposed)
	CreatedAt    time.Time `json:"created_at"`
}

// EnsureTaskArtifactsTable creates the table idempotently (called at service startup).
func (d *DB) EnsureTaskArtifactsTable() error {
	_, err := d.Exec(`
CREATE TABLE IF NOT EXISTS task_artifacts (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'other',
    mime        TEXT,
    size_bytes  BIGINT NOT NULL DEFAULT 0,
    sha256      TEXT,
    source_url  TEXT,
    note        TEXT,
    storage_path TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_artifacts_task ON task_artifacts(task_id);
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS finding_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_task_artifacts_finding ON task_artifacts(finding_id);
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS preview_state TEXT;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS preview_pages INT NOT NULL DEFAULT 0;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS preview_error TEXT;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS previewed_at TIMESTAMPTZ;
`)
	return err
}

// InsertTaskArtifact registers an attachment (the file has already been written by the host).
func (d *DB) InsertTaskArtifact(ctx context.Context, a *TaskArtifact) error {
	return d.QueryRowContext(ctx, `
INSERT INTO task_artifacts(task_id,finding_id,name,kind,mime,size_bytes,sha256,source_url,note,storage_path,preview_state)
VALUES ($1,NULLIF($2,0),$3,$4,NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10,NULLIF($11,''))
RETURNING id, created_at`,
		a.TaskID, a.FindingID, a.Name, a.Kind, a.Mime, a.SizeBytes, a.SHA256, a.SourceURL, a.Note, a.Storage, a.PreviewState).
		Scan(&a.ID, &a.CreatedAt)
}

// ListTaskArtifacts lists a task's attachments by time.
func (d *DB) ListTaskArtifacts(taskID string) ([]TaskArtifact, error) {
	rows, err := d.Query(`
SELECT id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
       COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at
FROM task_artifacts WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskArtifact
	for rows.Next() {
		var a TaskArtifact
		if err := rows.Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetTaskArtifact fetches a single attachment's metadata (used for export/embedding images in reports).
func (d *DB) GetTaskArtifact(id int64) (*TaskArtifact, error) {
	var a TaskArtifact
	err := d.QueryRow(`
SELECT id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
       COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at
FROM task_artifacts WHERE id=$1`, id).
		Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CountTaskArtifacts returns a task's attachment count and total bytes (for quota checks).
func (d *DB) CountTaskArtifacts(taskID string) (count int, bytes int64, err error) {
	err = d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes),0) FROM task_artifacts WHERE task_id=$1`, taskID).
		Scan(&count, &bytes)
	return
}

// UpdateTaskArtifactFinding changes an attachment's owner (v0.4.20): findingID=0 means task-level.
// Returns the updated full metadata, reused by the PATCH endpoint and by dedup rebinding.
func (d *DB) UpdateTaskArtifactFinding(id int64, findingID int64) (*TaskArtifact, error) {
	var a TaskArtifact
	err := d.QueryRow(`
UPDATE task_artifacts SET finding_id=NULLIF($2,0) WHERE id=$1
RETURNING id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
          COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at`, id, findingID).
		Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateTaskArtifactBinding rebinds ownership and fills empty fields (used by the v0.4.20 dedup path):
// note/source_url are written only when the old value is empty, so the description from the first registration is not overwritten.
func (d *DB) UpdateTaskArtifactBinding(id int64, findingID int64, note, sourceURL string) (*TaskArtifact, error) {
	var a TaskArtifact
	err := d.QueryRow(`
UPDATE task_artifacts SET finding_id=NULLIF($2,0),
       note=COALESCE(NULLIF(note,''),NULLIF($3,'')),
       source_url=COALESCE(NULLIF(source_url,''),NULLIF($4,''))
WHERE id=$1
RETURNING id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
          COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at`, id, findingID, note, sourceURL).
		Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListPendingPreviewArtifacts returns every pending document preview (used by the startup recovery queue).
func (d *DB) ListPendingPreviewArtifacts() ([]TaskArtifact, error) {
	rows, err := d.Query(`
SELECT id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
       COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at
FROM task_artifacts WHERE preview_state='pending' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskArtifact
	for rows.Next() {
		var a TaskArtifact
		if err := rows.Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetTaskArtifactPreview updates the document preview state (v0.4.21).
func (d *DB) SetTaskArtifactPreview(id int64, state string, pages int, errMsg string) error {
	_, err := d.Exec(`
UPDATE task_artifacts
SET preview_state=$2, preview_pages=$3, preview_error=NULLIF($4,''), previewed_at=now()
WHERE id=$1`, id, state, pages, errMsg)
	return err
}

// ListArtifactTaskIDs returns the task IDs that have evidence attachments (for offline preview backfill).
func (d *DB) ListArtifactTaskIDs() ([]string, error) {
	rows, err := d.Query(`SELECT DISTINCT task_id FROM task_artifacts ORDER BY task_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RetroBindIntentEvidence binds every unassigned piece of evidence under the given intent run directory to the finding in one go.
// Trigger: after report_finding is persisted -- a worker saves evidence first and reports the finding afterwards during intent
// execution, so at that point every piece of evidence saved under that intent with an empty finding_id belongs to this finding.
// Returns how many were actually bound. The caller (report_finding) needs no extra confirmation -- the same intent directory is a
// natural provenance boundary and evidence of other intents will not be bound by mistake.
func (d *DB) RetroBindIntentEvidence(taskID string, intentID int64, findingID int64) (int, error) {
	pattern := "%/i" + strconv.FormatInt(intentID, 10) + "/%"
	res, err := d.Exec(`
UPDATE task_artifacts
SET finding_id=$3
WHERE task_id=$1 AND finding_id IS NULL AND storage_path LIKE $2`,
		taskID, pattern, findingID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
