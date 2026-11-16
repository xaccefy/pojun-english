// pojun-maint is an offline maintenance tool (v0.4.13): it performs one-off data
// repairs on existing deployments without going through Web login. Two kinds of
// operations:
//
//	pojun-maint scan-artifacts  --config /opt/pojun/config.json
//	 Scan historical images in all task working directories and register them as
//	 evidence attachments (same logic as the v0.4.10
//	 POST /api/tasks/{id}/artifacts/scan, used to bulk-fill older tasks).
//
//	pojun-maint reset-prompts --config /opt/pojun/config.json [--force]
//	 Update built-in agent prompts to the version embedded in the current binary
//	 (old databases still have the prompts from first install; new versions do
//	 not overwrite them automatically). By default only reports differences;
//	 --force performs the write-back (overwrites that agent's custom edits — use
//	 with care).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/docpreview"
)

const (
	maxFileBytes = 20 << 20
	maxTaskCount = 300 // Consistent with the server limit (300 items / 500MB since v0.4.23)
	maxTaskBytes = 500 << 20
	maxPerRun    = 60 // Max additions per single scan, to avoid pulling in all temp files at once
	artifactsDir = "artifacts"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pojun-maint <scan-artifacts|previews|reset-prompts|fix-permissions|scope-audit> --config <config.json> [--force] [--out file]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "/opt/pojun/config.json", "Path to POJUN config.json")
	dataDir := fs.String("data", "", "Data directory (defaults to data/ under the config directory)")
	force := fs.Bool("force", false, "reset-prompts: overwrite custom edits; previews: regenerate previews that are already ready")
	taskID := fs.Int64("task", 0, "previews: only process the specified task ID")
	all := fs.Bool("all", false, "previews: process all tasks")
	outPath := fs.String("out", "", "scope-audit: write the per-row results to a JSON file (read-only, deletes no data)")
	_ = fs.Parse(os.Args[2:])

	dsn, err := loadDSN(*cfgPath)
	if err != nil {
		fail(err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		fail(fmt.Errorf("failed to connect to database: %w", err))
	}
	if *dataDir == "" {
		*dataDir = filepath.Join(filepath.Dir(*cfgPath), "data")
	}
	if err := pg.EnsureTaskArtifactsTable(); err != nil {
		fail(fmt.Errorf("failed to create table: %w", err))
	}

	switch cmd {
	case "scan-artifacts":
		scanArtifacts(pg, *dataDir)
	case "previews":
		generatePreviews(pg, *dataDir, *taskID, *all, *force)
	case "reset-prompts":
		resetPrompts(pg, *force)
	case "fix-permissions":
		fixArtifactPermissions(*dataDir)
	case "scope-audit":
		auditAutoScope(pg, *outPath)
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		os.Exit(2)
	}
}


// auditAutoScope replays source=auto scope rows against the automatic scope
// attribution rules and outputs a "keep / recommended cleanup" list. Read-only —
// any deletion must first be backed up with pg_dump and confirmed manually.
func auditAutoScope(pg *db.DB, outPath string) {
	items, err := pg.Assets().AuditAutoScope()
	if err != nil {
		fail(fmt.Errorf("audit failed: %w", err))
	}
	byReason := map[string]int{}
	tasks := map[int64]bool{}
	bad := 0
	for _, it := range items {
		byReason[it.Reason]++
		tasks[it.TaskID] = true
		if !it.Allowed {
			bad++
		}
	}
	fmt.Printf("auto scope rows %d (across %d tasks): keep %d, recommended cleanup %d\n", len(items), len(tasks), len(items)-bad, bad)
	for _, reason := range []string{"ok", "no-baseline", "infra-blacklist", "outside-baseline"} {
		if n := byReason[reason]; n > 0 {
			fmt.Printf("  %-18s %d\n", reason, n)
		}
	}
	if bad > 0 {
		fmt.Println("\nRecommended cleanup (only the first 50 shown; --out gives the full JSON):")
		shown := 0
		for _, it := range items {
			if it.Allowed {
				continue
			}
			target := it.Domain
			if target == "" {
				target = it.Net
			}
			fmt.Printf("  task=%d kind=%s value=%s reason=%s\n", it.TaskID, it.Kind, target, it.Reason)
			shown++
			if shown >= 50 {
				break
			}
		}
	}
	if outPath != "" {
		raw, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(outPath, raw, 0o600); err != nil {
			fail(err)
		}
		fmt.Printf("\nFull list written to %s (0600)\n", outPath)
	}
	fmt.Println("\nNote: this command is read-only and deletes no scope rows; cleanup requires a backup and manual confirmation first.")
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "[x] %v\n", err)
	os.Exit(1)
}

// loadDSN builds a DSN from the database section of config.json (same source as the server).
func loadDSN(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}
	var c struct {
		Database struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			User     string `json:"user"`
			Password string `json:"password"`
			DBName   string `json:"dbname"`
			SSLMode  string `json:"sslmode"`
		} `json:"database"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", err
	}
	d := c.Database
	if d.Host == "" || d.User == "" || d.DBName == "" {
		return "", fmt.Errorf("config.json is missing the database configuration")
	}
	if d.Port == 0 {
		d.Port = 5432
	}
	if d.SSLMode == "" {
		d.SSLMode = "disable"
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode), nil
}

// scanArtifacts scans all task directories and registers images (deduplicated / limited / ignores artifacts itself).
func scanArtifacts(pg *db.DB, dataDir string) {
	tasks, err := pg.ListTasks()
	if err != nil {
		fail(fmt.Errorf("failed to read tasks: %w", err))
	}
	totalAdded, totalSkipped := 0, 0
	for _, t := range tasks {
		taskID := strconv.FormatInt(t.ID, 10)
		root := filepath.Join(dataDir, "tasks", taskID)
		artDir := filepath.Join(root, artifactsDir)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		existing := map[string]bool{}
		if list, e := pg.ListTaskArtifacts(taskID); e == nil {
			for _, a := range list {
				existing[a.SHA256] = true
			}
		}
		count, bytesUsed, _ := pg.CountTaskArtifacts(taskID)
		added, skipped := 0, 0
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				if path == artDir {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".png", ".jpg", ".jpeg", ".gif", ".webp",
				".pdf", ".doc", ".docx", ".odt", ".rtf",
				".xls", ".xlsx", ".ods", ".csv",
				".ppt", ".pptx", ".odp":
			default:
				return nil
			}
			info, e := d.Info()
			if e != nil || info.Size() <= 0 || info.Size() > maxFileBytes {
				return nil
			}
			if added >= maxPerRun || count+added >= maxTaskCount {
				return nil
			}
			if bytesUsed+info.Size() > maxTaskBytes {
				return nil
			}
			sha, e := fileSHA(path)
			if e != nil {
				return nil
			}
			if existing[sha] {
				skipped++
				return nil
			}
			if e := register(pg, dataDir, taskID, path, root, sha, info.Size()); e != nil {
				fmt.Printf("  [warn] task %s %s: %v\n", taskID, filepath.Base(path), e)
				return nil
			}
			existing[sha] = true
			bytesUsed += info.Size()
			added++
			return nil
		})
		if added > 0 || skipped > 0 {
			fmt.Printf("[task %s] registered %d, skipped %d duplicates\n", taskID, added, skipped)
		}
		totalAdded += added
		totalSkipped += skipped
	}
	fmt.Printf("\nDone: registered %d in total, skipped %d\n", totalAdded, totalSkipped)
}

// generatePreviews generates sampling previews for historical Office/PDF
// attachments (v0.4.21).
// Usage: --task <id> or --all; --force regenerates those already ready.
func generatePreviews(pg *db.DB, dataDir string, onlyTask int64, all, force bool) {
	fmt.Printf("[previews] LibreOffice/pdftoppm availability: soffice=%v pdftoppm=%v\n", func() bool {
		s, _ := docpreview.Available()
		return s
	}(), func() bool {
		_, p := docpreview.Available()
		return p
	}())
	var taskIDs []string
	if onlyTask > 0 {
		taskIDs = []string{strconv.FormatInt(onlyTask, 10)}
	} else if all {
		ids, err := pg.ListArtifactTaskIDs()
		if err != nil {
			fail(err)
		}
		taskIDs = ids
	} else {
		fail(fmt.Errorf("previews requires --task <id> or --all"))
	}
	totalReady, totalSkip, totalFail := 0, 0, 0
	for _, taskID := range taskIDs {
		list, err := pg.ListTaskArtifacts(taskID)
		if err != nil {
			fmt.Printf("[task %s] failed to read artifacts: %v\n", taskID, err)
			continue
		}
		for _, a := range list {
			if !docpreview.Supports(a.Name) {
				continue
			}
			if !force && a.PreviewState == "ready" && a.PreviewPages > 0 {
				totalSkip++
				continue
			}
			src := filepath.Join(dataDir, a.Storage)
			outDir := filepath.Join(dataDir, "tasks", taskID, "artifacts", "previews", strconv.FormatInt(a.ID, 10))
			pages, err := docpreview.Generate(context.Background(), src, outDir, docpreview.DefaultPages)
			if err != nil {
				state := "failed"
				if errors.Is(err, docpreview.ErrSofficeMissing) || errors.Is(err, docpreview.ErrPdftoppmMissing) {
					state = "skipped"
				}
				_ = pg.SetTaskArtifactPreview(a.ID, state, 0, err.Error())
				fmt.Printf("[task %s] #%d %s → %s: %v\n", taskID, a.ID, a.Name, state, err)
				totalFail++
				continue
			}
			_ = pg.SetTaskArtifactPreview(a.ID, "ready", pages, "")
			fmt.Printf("[task %s] #%d %s → ready (%d pages)\n", taskID, a.ID, a.Name, pages)
			totalReady++
		}
	}
	fmt.Printf("\nDone: generated %d, skipped %d, failed %d\n", totalReady, totalSkip, totalFail)
}

func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func register(pg *db.DB, dataDir, taskID, path, taskRoot, sha string, size int64) error {
	base := filepath.Base(path)
	name := base
	if decoded, err := url.QueryUnescape(base); err == nil && decoded != "" {
		name = decoded
	}
	rel, _ := filepath.Rel(taskRoot, path)
	dstRel := filepath.Join("tasks", taskID, artifactsDir,
		fmt.Sprintf("%d-%s", time.Now().UnixNano(), sanitize(name)))
	dst := filepath.Join(dataDir, dstRel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// 0644: when pojun-maint runs as root, 0600 makes the files unreadable by the
	// service process (pojun user), and http.ServeFile returns a 403 "image cannot
	// be opened" — fixed in v0.4.18.
	// The directory itself is 700 owned by pojun; files at 0644 are not exposed to
	// other users.
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	kind, mime := kindByExt(name)
	a := &db.TaskArtifact{
		TaskID: taskID, Name: name, Kind: kind, Mime: mime,
		SizeBytes: size, SHA256: sha, Note: "Working-directory historical file: " + rel,
		Storage: dstRel,
	}
	if err := pg.InsertTaskArtifact(context.Background(), a); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

func sanitize(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return name
}

func kindByExt(name string) (string, string) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image", "image/png"
	case ".jpg", ".jpeg":
		return "image", "image/jpeg"
	case ".gif":
		return "image", "image/gif"
	case ".webp":
		return "image", "image/webp"
	}
	return "other", "application/octet-stream"
}

// resetPrompts compares built-in agent prompts with the current binary version,
// optionally writing back.
func resetPrompts(pg *db.DB, force bool) {
	seeds := agent.BuiltinPromptSeeds()
	// reporter / retester are not in BuiltinPromptSeeds (the server seeds their own
	// constants on first insert); include them in comparison and write-back during
	// maintenance.
	seeds["reporter"] = agent.ReporterDefaultPrompt
	seeds["retester"] = agent.RetesterDefaultPrompt
	list, err := pg.ListAgents()
	if err != nil {
		fail(fmt.Errorf("failed to read agents: %w", err))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	changed := 0
	for _, a := range list {
		tmpl, ok := seeds[a.Key]
		if !ok {
			continue
		}
		cur, err := pg.CurrentPrompt(a.ID)
		if err != nil {
			cur = ""
		}
		if cur == tmpl {
			fmt.Printf("[%s] already up to date\n", a.Key)
			continue
		}
		changed++
		if !force {
			fmt.Printf("[%s] differs from the built-in version (current %d bytes, built-in %d bytes); add --force to write back\n",
				a.Key, len(cur), len(tmpl))
			continue
		}
		ver, err := pg.ResetPromptToDefault(a.ID, tmpl)
		if err != nil {
			fmt.Printf("[%s] write-back failed: %v\n", a.Key, err)
			continue
		}
		fmt.Printf("[%s] updated to built-in version v%d\n", a.Key, ver)
	}
	fmt.Printf("\nDone: %d agents have differences\n", changed)
}

// fixArtifactPermissions repairs historical artifact permissions (v0.4.18):
// early pojun-maint wrote artifacts as 0600 as root, which the service process
// (pojun user) could not read → images 403. Standardize on directory 0750 /
// files 0644 (the artifacts directory itself is under the task directory and is
// not served externally).
func fixArtifactPermissions(dataDir string) {
	root := filepath.Join(dataDir, "tasks")
	fixed := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == artifactsDir {
				_ = os.Chmod(path, 0o750)
			}
			return nil
		}
		if filepath.Base(filepath.Dir(path)) != artifactsDir {
			return nil
		}
		if err := os.Chmod(path, 0o644); err == nil {
			fixed++
		}
		return nil
	})
	fmt.Printf("Done: fixed permissions on %d artifact files (directory 0750 / files 0644)\n", fixed)
}
