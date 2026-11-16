package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/notify"
)

var (
	ErrEvidenceConflict = errors.New("traffic evidence has changed; refresh and try again")
	ErrFindingNotFound  = errors.New("finding does not exist")
	ErrEvidenceNotFound = errors.New("traffic evidence not found")
)

// This lock covers the evidence filesystem as well as its SQL references. All
// processes sharing the database use it, including readers, exports and GC.
const findingEvidenceLockKey int64 = 7337741004

func (d *DB) WithEvidenceTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type TrafficRef struct {
	TrafficID string `json:"traffic_id"`
	Role      string `json:"role"`
	Note      string `json:"note"`
}

func NormalizeTrafficRefs(refs []TrafficRef) ([]TrafficRef, error) {
	out := make([]TrafficRef, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref.TrafficID = strings.TrimSpace(ref.TrafficID)
		if ref.TrafficID == "" {
			return nil, errors.New("traffic_id must not be empty")
		}
		if ref.Role == "" {
			ref.Role = "supporting"
		}
		if !ValidTrafficRole(ref.Role) {
			return nil, fmt.Errorf("invalid traffic role %q", ref.Role)
		}
		if !seen[ref.TrafficID] {
			out = append(out, ref)
			seen[ref.TrafficID] = true
		}
	}
	return out, nil
}

func ValidTrafficRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

type TrafficEvidenceSnapshot struct {
	ID              string    `json:"id"`
	SourceTrafficID string    `json:"source_traffic_id"`
	CapturedAt      int64     `json:"captured_at"`
	URL             string    `json:"url"`
	Method          string    `json:"method"`
	Status          int       `json:"status"`
	ContentType     string    `json:"content_type"`
	ReqHead         string    `json:"req_head,omitempty"`
	RespHead        string    `json:"resp_head,omitempty"`
	ReqHash         string    `json:"req_hash"`
	RespHash        string    `json:"resp_hash"`
	ReqLen          int64     `json:"req_len"`
	RespLen         int64     `json:"resp_len"`
	CreatedAt       time.Time `json:"created_at"`
}

type FindingTrafficBinding struct {
	ID         int64                   `json:"id,string"`
	FindingID  int64                   `json:"finding_id,string"`
	SnapshotID string                  `json:"snapshot_id"`
	Role       string                  `json:"role"`
	Note       string                  `json:"note"`
	Position   int                     `json:"position"`
	CreatedAt  time.Time               `json:"created_at"`
	Snapshot   TrafficEvidenceSnapshot `json:"snapshot"`
}

type FindingTraffic struct {
	FindingID     int64                   `json:"finding_id,string"`
	Version       int64                   `json:"version"`
	ReportVersion int64                   `json:"report_version"`
	Bindings      []FindingTrafficBinding `json:"bindings"`
	// SkippedRefs holds traffic references that could not be resolved in this request. Binding is best-effort: valid
	// ones are attached as usual, invalid ones are recorded here, and existing bindings are unaffected.
	SkippedRefs []TrafficRef `json:"skipped_traffic_refs,omitempty"`
}

type PreparedTrafficEvidence struct {
	Ref      TrafficRef
	Snapshot TrafficEvidenceSnapshot
}

// Normalize makes the snapshot's text columns safe for PostgreSQL. URL and the
// head blocks come straight off the wire, so a target answering with a non-UTF-8
// header (a GBK `Content-Disposition: filename=…`, a NUL byte) would otherwise
// abort the INSERT and roll back the whole finding — losing a confirmed finding
// over a malformed response header. Applied before hashing so the ID always
// matches the bytes that actually land in the table.
func (s TrafficEvidenceSnapshot) Normalize() TrafficEvidenceSnapshot {
	s.SourceTrafficID = utf8Clean(s.SourceTrafficID)
	s.URL = utf8Clean(s.URL)
	s.Method = utf8Clean(s.Method)
	s.ContentType = utf8Clean(s.ContentType)
	s.ReqHead = utf8Clean(s.ReqHead)
	s.RespHead = utf8Clean(s.RespHead)
	return s
}

func TrafficSnapshotID(snapshot TrafficEvidenceSnapshot) string {
	snapshot = snapshot.Normalize()
	snapshot.ID = ""
	snapshot.CreatedAt = time.Time{}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LockTaskEvidenceTx serializes writes with archive queueing (which locks the
// same task row). Once queued, its snapshot must not acquire new evidence.
func LockTaskEvidenceTx(tx *sql.Tx, taskID int64) error {
	if taskID == 0 {
		return nil
	}
	var deleted sql.NullTime
	if err := tx.QueryRow(`SELECT deleted_at FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&deleted); err != nil {
		return err
	}
	if deleted.Valid {
		return ErrTaskArchiveState
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1`, taskID).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && state != ArchiveFailed {
		return ErrTaskArchiveState
	}
	return nil
}

func LockFindingEvidenceTx(tx *sql.Tx, findingID int64, version *int64) error {
	var taskID sql.NullInt64
	if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, findingID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if version != nil && *version != current {
		return ErrEvidenceConflict
	}
	return nil
}

func InsertEvidenceSnapshotTx(tx *sql.Tx, s TrafficEvidenceSnapshot) error {
	if s.ID != TrafficSnapshotID(s) {
		return errors.New("evidence snapshot metadata hash mismatch")
	}
	// The ID was computed over the normalized form; store those same bytes.
	id := s.ID
	s = s.Normalize()
	s.ID = id
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO traffic_evidence_snapshots
(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.SourceTrafficID, s.CapturedAt, s.URL, s.Method, s.Status, s.ContentType, s.ReqHead, s.RespHead, s.ReqHash, s.RespHash, s.ReqLen, s.RespLen, s.CreatedAt)
	return err
}

func AddFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence) error {
	var position int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_traffic_bindings WHERE finding_id=$1`, findingID).Scan(&position); err != nil {
		return err
	}
	changed := false
	for _, item := range prepared {
		if err := InsertEvidenceSnapshotTx(tx, item.Snapshot); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots SET unreferenced_at=NULL WHERE id=$1`, item.Snapshot.ID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, findingID, item.Snapshot.ID, item.Ref.Role, item.Ref.Note, position)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			changed = true
			position++
		}
	}
	if changed {
		return bumpEvidenceVersionTx(tx, findingID)
	}
	return nil
}

func bumpEvidenceVersionTx(tx *sql.Tx, findingID int64) error {
	_, err := tx.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, findingID)
	return err
}

func FindingTrafficTx(tx *sql.Tx, findingID int64) (*FindingTraffic, error) {
	out := &FindingTraffic{FindingID: findingID, Bindings: []FindingTrafficBinding{}}
	if err := tx.QueryRow(`SELECT evidence_version,report_evidence_version FROM findings WHERE id=$1`, findingID).Scan(&out.Version, &out.ReportVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	rows, err := tx.Query(`SELECT b.id,b.finding_id,b.snapshot_id,b.role,b.note,b.position,b.created_at,to_jsonb(s)
FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1 ORDER BY b.position,b.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b FindingTrafficBinding
		var raw []byte
		if err := rows.Scan(&b.ID, &b.FindingID, &b.SnapshotID, &b.Role, &b.Note, &b.Position, &b.CreatedAt, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.Snapshot); err != nil {
			return nil, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingTraffic(ctx context.Context, findingID int64) (out *FindingTraffic, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = FindingTrafficTx(tx, findingID); return e })
	return
}

func (d *DB) EditFindingTraffic(ctx context.Context, findingID, bindingID, version int64, role, note *string, remove bool, order []int64) error {
	if role != nil && !ValidTrafficRole(*role) {
		return errors.New("invalid traffic role")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		if order != nil {
			current, err := FindingTrafficTx(tx, findingID)
			if err != nil {
				return err
			}
			if len(order) != len(current.Bindings) {
				return ErrEvidenceConflict
			}
			ids := map[int64]bool{}
			for _, b := range current.Bindings {
				ids[b.ID] = true
			}
			for position, id := range order {
				if !ids[id] {
					return ErrEvidenceConflict
				}
				delete(ids, id)
				if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id); err != nil {
					return err
				}
			}
		} else {
			var res sql.Result
			var err error
			if remove {
				res, err = tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2`, findingID, bindingID)
			} else {
				res, err = tx.Exec(`UPDATE finding_traffic_bindings SET role=COALESCE($3,role),note=COALESCE($4,note) WHERE finding_id=$1 AND id=$2`, findingID, bindingID, role, note)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceNotFound
			}
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

type RecordFindingInput struct {
	TaskID, ExplorationID, IntentID                      int64
	VulnClass, Name, Severity, Summary, Evidence, Worker string
	AssetIDs                                             []int64
	// v0.9 multi-key dedup: different exploitation surfaces/data extensions of the same root cause should pass the same RootCauseKey;
	// MergeIntoFindingID explicitly names the merge target (highest priority); SurfaceNote describes this
	// exploitation surface and is written to the update log. Endpoint/HTTPMethod/Parameter are optional and used to generate endpoint/parameter keys.
	RootCauseKey       string
	MergeIntoFindingID int64
	SurfaceNote        string
	Endpoint           string
	HTTPMethod         string
	Parameter          string
	// CrossTaskNotifyDedup (v0.6.18): when a finding with the same fingerprint already exists in another task, no push event
	// is inserted for this duplicate record of this task (customer feedback: cross-task duplicate findings "kept being announced"). The finding itself
	// is stored as usual -- each task's findings are independent, it just does not disturb the user again.
	CrossTaskNotifyDedup bool
}

type RecordedFinding struct {
	FindingID int64           `json:"finding_id,string"`
	NodeID    int64           `json:"finding_node_id,string"`
	Traffic   *FindingTraffic `json:"traffic"`
	// Duplicate=true means this report hit an existing same-fingerprint finding in the same task, and the evidence was merged
	// into the original record (rather than creating a new one); the caller should use this to tell the model to stop reporting duplicates.
	Duplicate bool `json:"-"`
	// CrossTaskDupTasks (v0.6.18): non-empty = a same-fingerprint finding already exists in other tasks too (this notification
	// was suppressed by CrossTaskNotifyDedup). The caller uses this to tell the model "cross-task duplicate" in the receipt.
	CrossTaskDupTasks []int64 `json:"-"`
	// SkippedRefs holds references that could not be resolved in this submission (traffic id missing / body unreadable).
	// The finding itself is stored as usual -- guessing one id wrong should not throw away a confirmed finding -- but the caller must
	// return these ids to the model verbatim so it knows which evidence was not attached.
	SkippedRefs []TrafficRef `json:"skipped_traffic_refs,omitempty"`
	// MergeCandidates holds weak-key "possibly duplicate" records (not auto-merged), for manual review on the page.
	MergeCandidates []int64 `json:"merge_candidates,omitempty"`
}

// FindingFingerprint normalizes (vulnclass, name, sorted asset_ids) into the report fingerprint.
// Normalization: lowercase, collapse whitespace; assets sorted by id to remove report-order differences.
// normalizeFindingName strips bracketed noise and punctuation/whitespace differences from the finding name, as part of the fingerprint.
// Measured in production (task #11 delivery review): the same finding with a different
// suffix such as "(full evidence)" / "(updated evidence)" / " (SQLite)" bypassed the fingerprint, and 14 of 22 reports were reskinned duplicates of the same finding -- the report page was flooded
// and it looked terrible to the customer. The display name stays as-is; only the fingerprint uses the normalized name.
func normalizeFindingName(name string) string {
	s := findingBrackets.ReplaceAllString(name, " ")
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

var findingBrackets = regexp.MustCompile(`[(([\[][^))]\]]*[))]\]]`)

// findingLocator extracts a "locator key" (CVE, URL path, port) from the name/evidence for the fingerprint.
// Without an asset anchor the old fingerprint degenerated to "class|name", merging same-class findings on different endpoints/parameters;
// a locator key distinguishes them while still merging "the same finding reported again with different evidence".
var (
	findingCVERe  = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	findingURLRe  = regexp.MustCompile(`(?i)https?://[^\s"'<>),,]+`)
	findingPathRe = regexp.MustCompile(`(/[a-zA-Z0-9_\-./]{3,})`)
	findingPortRe = regexp.MustCompile(`(?i)(?:port|port)\s*[:=]?\s*(\d{1,5})`)
)

func findingLocator(in RecordFindingInput) string {
	text := in.Name + " " + in.Summary + " " + in.Evidence
	if m := findingCVERe.FindString(text); m != "" {
		return strings.ToUpper(m)
	}
	if m := findingURLRe.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil && u.Host != "" {
			return strings.ToLower(u.Host + u.EscapedPath())
		}
		return strings.ToLower(m)
	}
	if m := findingPathRe.FindString(text); m != "" {
		return strings.ToLower(strings.TrimRight(m, "/."))
	}
	if m := findingPortRe.FindStringSubmatch(text); len(m) == 2 {
		return "port:" + m[1]
	}
	return ""
}

func FindingFingerprint(in RecordFindingInput) string {
	norm := func(s string) string { return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ") }
	ids := append([]int64{}, in.AssetIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, len(ids))
	for i, v := range ids {
		parts[i] = strconv.FormatInt(v, 10)
	}
	loc := findingLocator(in)
	// No asset anchor and no locator key: the fingerprint is only "class|name", and merging would fold real findings
	// on different endpoints into one by mistake. Returning an empty string = do not take part in dedup (RecordFindingTx skips merging).
	if len(ids) == 0 && loc == "" {
		return ""
	}
	namePart := normalizeFindingName(in.Name)
	// The title of the same CVE is often reworded ("Apache RCE" / "Apache RCE second confirmation"), so the CVE wins
	// and the name does not enter the fingerprint, so the same finding is not opened as duplicate rows.
	if strings.HasPrefix(loc, "CVE-") {
		namePart = ""
	}
	raw := norm(in.VulnClass) + "|" + namePart + "|" + strings.Join(parts, ",") + "|" + loc
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16]) // 128 bits is plenty; avoids a long index key
}

// ctx is passed in by the caller for this transaction (rather than taking context.Background internally):
// the push-event write added inside the transaction must also be subject to the caller's cancellation and timeout.
func RecordFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
		return nil, err
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("the finding's task does not match the exploration record")
		}
	}
	if in.IntentID > 0 {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, in.ExplorationID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("intent_id must be an intent of this task (linked-task intents are read-only)")
		}
	}
	// ── Same-task fingerprint dedup: the same (vulnclass,name,assets) is treated as a duplicate report of the same finding,
	// and the evidence is merged into the existing record instead of inserting another row -- "report A, then report A again" is
	// hard-blocked at the write layer rather than relying on the model's self-discipline.
	// v0.6.22: **an asset anchor is no longer required**. Measured in production (delivery review task #11): workers
	// generally report findings without asset_ids (0 assets written back), so the old logic skipped dedup entirely and the same
	// fingerprint inserted 4-7 rows in one task. The fingerprint itself already includes the asset set (an empty set is hashed too), so the same fingerprint means
	// the same (class, name, asset set) triple; when there is no anchor, the "same-name findings on different ports" ambiguity accepts merging
	// (evidence is only ever added, never lost), because duplicate flooding hurts the customer far more.
	// resolved/fixed/false_positive/ignored are already terminal states or human conclusions and do not take part in merging
	// (a re-appearance after a fix = worth a new row; a false positive later confirmed = an overturn).
	// vulnclass normalization (variant spelling -> canonical class): normalized on write, so the aggregate view and fingerprint dedup
	// both work off the canonical value -- SQLi and its Chinese spelling are the same class and the same fingerprint from then on.
	in.VulnClass = NormalizeVulnClass(in.VulnClass)
	fp := FindingFingerprint(in)
	keys := FindingDedupKeys(in, fp)
	// v0.9: multi-key merging. Samples with an empty name do not take part in auto-merging: with an empty name + empty assets only the class remains,
	// which would wrongly merge "two genuinely different findings in the same class" (measured in the v0.6.22 full test run).
	if in.TaskID > 0 && strings.TrimSpace(in.Name) != "" {
		targetID, err := findFindingMergeTargetTx(tx, in, fp, keys)
		if err != nil {
			return nil, err
		}
		if targetID > 0 {
			out, err := mergeReportIntoTargetTx(ctx, tx, targetID, in, prepared, keys)
			if err != nil {
				return nil, err
			}
			return out, nil
		}
	}
	// No strong key hit: still fall back to the old fingerprint (historical rows may lack finding_keys), and return the weak-key candidates
	// to the caller as a "possibly duplicate" hint, without auto-merging.
	var mergeCandidates []int64
	payload, _ := json.Marshal(map[string]any{"vulnclass": in.VulnClass, "name": in.Name, "severity": in.Severity, "summary": in.Summary, "evidence": map[string]any{"by": in.Worker, "poc": in.Evidence}})
	out := &RecordedFinding{}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Worker).Scan(&out.NodeID); err != nil {
		return nil, err
	}
	for _, asset := range in.AssetIDs {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, out.NodeID, asset); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, in.ExplorationID, in.IntentID, RelYields, out.NodeID); err != nil {
			return nil, err
		}
	}
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)
	rootKey := normalizeRootCauseKey(in.RootCauseKey)
	if err := tx.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,fingerprint,root_cause_key)
VALUES(NULLIF($1,0),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`, in.TaskID, out.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Worker, string(raw), fp, rootKey).Scan(&out.FindingID); err != nil {
		return nil, err
	}
	if err := insertFindingKeysTx(tx, out.FindingID, keys); err != nil {
		return nil, err
	}
	if err := insertFindingUpdateTx(tx, out.FindingID, "initial", 0, in, in.Summary, in.Evidence, prepared); err != nil {
		return nil, err
	}
	mergeCandidates = weakFindingCandidatesTx(tx, out.FindingID, keys)
	out.MergeCandidates = mergeCandidates
	// Record a push event in the **same transaction**: committing guarantees "the finding is stored" and "the push job exists"
	// are atomically consistent, with no window where the commit succeeds but nothing is queued and the message is lost forever.
	// A failure here is isolated by a savepoint and does not affect the finding write (see the function comment), so the return value is ignored.
	// v0.6.18 cross-task dedup: when a same-fingerprint finding already exists in another non-deleted task, do not push again
	// (customer feedback that cross-task duplicate findings "kept being announced"); the finding record itself is kept as usual.
	if in.CrossTaskNotifyDedup {
		var dupTasks []int64
		dupRows, dupErr := tx.Query(`SELECT f.task_id FROM findings f
JOIN tasks t ON t.id=f.task_id AND t.deleted_at IS NULL
WHERE f.fingerprint=$1 AND f.task_id<>$2
  AND EXISTS (SELECT 1 FROM findings f2 WHERE f2.task_id=f.task_id AND f2.fingerprint=$1
              AND f2.status IN ('pending','in_progress','confirmed'))
GROUP BY f.task_id ORDER BY f.task_id`, fp, in.TaskID)
		if dupErr == nil {
			for dupRows.Next() {
				var tid int64
				if _ = dupRows.Scan(&tid); tid > 0 {
					dupTasks = append(dupTasks, tid)
				}
			}
			_ = dupRows.Close()
		}
		if len(dupTasks) > 0 {
			out.CrossTaskDupTasks = dupTasks
		}
	}
	if in.CrossTaskNotifyDedup && len(out.CrossTaskDupTasks) > 0 {
		// Suppress the push: a cross-task duplicate no longer disturbs the user (the record itself is kept and visible on the page).
	} else {
		RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, out.FindingID, notify.Snapshot{
			Kind:      notify.EventFindingCreated,
			FindingID: out.FindingID,
			TaskID:    in.TaskID,
			VulnClass: in.VulnClass,
			Name:      in.Name,
			Severity:  in.Severity,
			Summary:   in.Summary,
			AssetIDs:  assets,
		})
	}
	if err := AddFindingTrafficTx(tx, out.FindingID, prepared); err != nil {
		return nil, err
	}
	var err error
	out.Traffic, err = FindingTrafficTx(tx, out.FindingID)
	return out, err
}

// RecordFinding is the atomic legacy/no-recorder path used by tools and tests.
func (s *ExplorationStore) RecordFinding(ctx context.Context, in RecordFindingInput) (out *RecordedFinding, err error) {
	in.ExplorationID = s.expID
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = RecordFindingTx(ctx, tx, in, nil); return e })
	return
}

func (d *DB) FindingIDByNodeID(nodeID int64) (id int64, err error) {
	err = d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
	return
}

// PopulateFindingTrafficIDs only enriches already-visible nodes. It performs no
// discovery or ID guessing, and leaves the legacy node ID unchanged.
func (s *ExplorationStore) PopulateFindingTrafficIDs(nodes []*Node) error {
	byID := map[int64]*Node{}
	var args []any
	var placeholders []string
	for _, n := range nodes {
		if n == nil || n.Kind != KindFinding || byID[n.ID] != nil {
			continue
		}
		byID[n.ID] = n
		args = append(args, n.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT f.id,f.node_id,(SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id) FROM findings f WHERE f.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var findingID, nodeID int64
		var count int
		if err := rows.Scan(&findingID, &nodeID, &count); err != nil {
			return err
		}
		n := byID[nodeID]
		n.FindingID, n.FindingNodeID, n.TrafficCount = findingID, nodeID, count
	}
	return rows.Err()
}

// SetFindingReportVersionByNodeID writes the finding report. The argument may be either an exploration node ID or a
// findings table primary key -- the model has both (report_finding's first line is the node ID, the JSON carries the
// record ID), and in production the reporter tried the record ID first and then corrected to the node ID, wasting a round for nothing.
// Resolution order: match node_id exactly first; if that misses, treat the argument as findings.id and look up node_id.
func (d *DB) SetFindingReportVersionByNodeID(ctx context.Context, nodeID int64, report string, version *int64) (n int64, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var id int64
		errLookup := tx.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
		if errors.Is(errLookup, sql.ErrNoRows) {
			// Compatibility with "a findings.id was passed": reverse-look-up its node_id and continue using node semantics.

			var realNode sql.NullInt64
			if err := tx.QueryRow(`SELECT id,node_id FROM findings WHERE id=$1`, nodeID).Scan(&id, &realNode); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			if realNode.Valid {
				nodeID = realNode.Int64
			}
		} else if errLookup != nil {
			return errLookup
		}
		if err := LockFindingEvidenceTx(tx, id, version); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE findings SET report=$2,report_evidence_version=COALESCE($3::bigint,CASE WHEN evidence_version=0 THEN 0 ELSE -1 END) WHERE id=$1`, id, report, version)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return
}
