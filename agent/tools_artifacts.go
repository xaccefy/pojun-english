package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
)

// ArtifactRecorder is implemented by the host (server): validates path bounds and quotas, copies into the
// task attachments dir and writes the DB. The agent only 'hands over files from the work dir' — no direct attachment writes.
type ArtifactRecorder interface {
	RecordArtifact(taskID, findingID int64, runDir, relPath, name, kind, sourceURL, note string) (*db.TaskArtifact, error)
}

// ListTaskArtifacts is the host-injected attachment list reader (for agent tools). nil = unavailable.
var ListTaskArtifacts func(taskID string) ([]db.TaskArtifact, error)

// FindingTaskID is host-injected: reverse-lookup of a vuln's owning task (v0.4.20).
// The reporter's chat toolset has no task context — it locates the task via the finding_id the model passes.
var FindingTaskID func(findingID int64) (string, error)

// artifactGuidance is injected into the worker system prompt: timing discipline for screenshots and evidence
// archiving (v0.5.0). Reports 'having photos' depends on the worker screenshotting and registering at the right moments.
const artifactGuidance = `

━━ Evidence attachments (screenshots / data samples / logs) ━━
After confirming a vuln or landing key evidence, register the **raw material proving the conclusion** as task attachments:
- Screenshots: use the browser/playwright tools to capture target pages (logged-in data lists, admin panels, IDOR pages, upload/download results, command-echo pages), or fall back to chromium headless:
  ` + "`chromium --headless --disable-gpu --screenshot=<path-inside-workdir>.png --window-size=1440,900 '<URL>'`" + `
  After capturing, register via save_evidence — note states 'which system, which page, what it proves' (this becomes the report caption).
- Data samples (v0.4.34 plaintext-fidelity policy): we are first-party, first-hand reporters to the vendor — **evidence must be kept verbatim: no masking/blurring/smearing/overwriting of any field** (ID numbers, faces, phone numbers, accounts, passwords, credentials — all kept in plaintext). Masking breaks traceability and vuln judgment. Samples should keep enough rows to prove the surface (e.g. first 100 or all key fields); key datasets (exported CSV/JSON/Excel) can be stored whole in the work dir and registered as attachments (task attachment cap: 300 items/500MB — if exceeded, prioritize key samples + inventory).
- **Plaintext is a hard requirement**: when reporter writes reports and worker writes facts/evidence, cite real data values (field values may be excerpted) — never replace with '***'; what's secret is the platform's own LLM/FOFA keys and ops config, not target data.
- **Datasets must land on disk (v0.4.41)**: after confirming an unauthorized data endpoint, save the [full raw response] into this intent's work dir (curl -o dataset.json; if >20MB, paginate/time-window it into multiple files or gzip), and register via save_evidence kind=data — the note states record count, field list, time coverage. The old habit of grabbing a few sample rows without landing the full set is deprecated: 'got the most data' literally means these dataset files. Reports cite them with ![dataset](artifact:<id>).
- Data files are [readable online] under the page's 'Evidence Attachments → Data' tab (JSON/CSV auto-rendered as tables) — no longer download-only.
- Logs/HTML/JSON: command output, raw endpoint responses, page source — save as .txt/.json/.html then register.
- Register at least 1 key screenshot per vuln (when capturable); when impossible (no browser/non-HTTP), skip and note why in evidence — don't fake it.
- Pass finding_id on registration (the standalone vuln ID returned by report_finding): only then does the vuln's detail page and per-vuln report show the image; task-level material (target homepage etc.) doesn't get it.

━━ Bucket / file-read / upload-class vulns: photos ARE the evidence ━━
Writing 'got the bucket / can read files' isn't proof — **the captured files themselves must be kept as evidence**:
1. Download 5–9 key file samples from the bucket/endpoint (photos preferred: payment receipts, approval forms, expense forms, chat screenshots, ID photos), store in the work dir (URL-decode encoded filenames into readable names).
2. Choose the presentation yourself (**minimize montage, keep aspect, high-res**; a 3×3 tiny-cell grid is unreadable — don't use it):
   - 1 image and clear → register at original resolution (note states bucket/path + filename + what it proves).
   - 2 images → one side-by-side montage (each scaled to height 1000 keeping aspect).
   - 3–4 images → one 2×2 montage (each scaled to height 800).
   - More than 4 → multiple montages (2–4 per image, named montage-1.png, montage-2.png…) — to prove 'bulk', also attach a file listing (ls output saved as .txt).
   - Tall thin screenshots (aspect < 1:1.6, mostly text) → register alone or 2 side-by-side; use the enlarged tier for montages (height 1200), don't squeeze into small cells.
   - Overlay **real-filename watermarks** at each image's bottom (URL-decode first; Chinese font: ` + "`/usr/share/fonts/gongwen/Fangsong_GB2312.ttf`" + `):
   Example command (2 side-by-side; 3–4 same idea: pairwise +append then -append):
font=/usr/share/fonts/gongwen/Fangsong_GB2312.ttf
for f in a.jpg b.jpg; do
  label=$(basename "$f")
  magick "$f" -auto-orient -resize x1000     -gravity south -background '#000000a8' -splice 0x36     -fill white -pointsize 22 -font "$font"     -annotate +0+9 "$label" "wm_$(basename "$f")"
done
magick wm_a.jpg wm_b.jpg +append montage.png
   - Single-image watermark:
     ` + "`magick in.jpg -gravity south -background '#000000a8' -splice 0x36 -fill white -pointsize 22 -font /usr/share/fonts/gongwen/Fangsong_GB2312.ttf -annotate +0+9 'filename.jpg' out.png`" + `
   - **No blurring/masking** (v0.4.34): ID cards, faces, phone numbers, credentials — sensitive info is key to the vendor verifying the vuln; register verbatim. Compress to original resolution only when the sample file itself is huge (content unchanged).
3. Register with source_url (the bucket object URL) and finding_id; note states the sample count. Reports cite via ![caption](artifact:<id>); captions state bucket/file and 'N samples'.`

// saveEvidence registers a work-dir file as a task attachment.
func (t *ToolSet) saveEvidence() actool.CoreTool {
	return writeTool("save_evidence",
		"Registers evidence files from the work dir as task attachments (screenshots / data samples / logs / HTML / JSON), exported with reports as the evidence bundle. Evidence kept verbatim in plaintext (no masking — first-party submission for vendor review); large datasets may register whole (attachment cap 300 items/500MB). Re-registering the same file dedupes.",
		obj(map[string]any{
			"path":       str("relative path inside the work dir (e.g. shots/login-userlist.png)"),
			"name":       str("optional: display name (with extension); defaults to filename"),
			"kind":       str("optional: image|data|log|html|auto (default inferred from extension)"),
			"source_url": str("optional: collection source URL"),
			"note":       str("note: what it proves (becomes the report caption for screenshots — be specific)"),
			"finding_id": map[string]any{"type": "integer", "description": "optional: which vuln this evidence proves (the finding_id returned by report_finding). With it, the vuln's detail page and per-vuln report show this image"},
		}, "path"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path, Name, Kind, SourceURL, Note string
				FindingID                         int64 `json:"finding_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.artifactRecorder == nil {
				return actool.Errorf("evidence attachment store unavailable (not enabled in this runtime)"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("save_evidence requires task context"), nil
			}
			if t.runDir == "" {
				return actool.Errorf("save_evidence requires the current run dir (not injected internally)"), nil
			}
			rec, err := t.artifactRecorder.RecordArtifact(t.taskID, a.FindingID, t.runDir, a.Path, a.Name, a.Kind, a.SourceURL, a.Note)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, _ := json.Marshal(map[string]any{
				"artifact_id": rec.ID, "name": rec.Name, "kind": rec.Kind,
				"size_bytes": rec.SizeBytes, "note": rec.Note,
			})
			return actool.Text(fmt.Sprintf("evidence saved: artifact %d\n%s\nCite it in the report as ![caption](artifact:%d).", rec.ID, out, rec.ID)), nil
		})
}

// listArtifacts lists this task's registered evidence attachments (worker reviews, reporter cites).
// The reporter has no task context — pass finding_id so the tool reverse-looks-up the owning task (v0.4.20).
func (t *ToolSet) listArtifacts() actool.CoreTool {
	return readTool("list_artifacts",
		"Lists this task's registered evidence attachments (id/name/type/size/note/source). In reports embed images via ![caption](artifact:<id>). Reporters may pass finding_id to locate the owning task's attachments.",
		obj(map[string]any{
			"finding_id": map[string]any{"type": "integer", "description": "optional: current vuln ID; reporters use it to locate the owning task's attachment list"},
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64 `json:"finding_id"`
			}
			_ = json.Unmarshal(in, &a)
			taskID := t.taskID
			if taskID <= 0 && a.FindingID > 0 && FindingTaskID != nil {
				if tid, err := FindingTaskID(a.FindingID); err == nil && tid != "" {
					if n, err := strconv.ParseInt(tid, 10, 64); err == nil {
						taskID = n
					}
				}
			}
			if ListTaskArtifacts == nil || taskID <= 0 {
				return actool.Text("[]"), nil
			}
			list, err := ListTaskArtifacts(fmt.Sprint(taskID))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, _ := json.Marshal(map[string]any{"artifacts": list})
			return actool.Text(string(out)), nil
		})
}
