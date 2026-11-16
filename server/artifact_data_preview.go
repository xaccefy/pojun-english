package server

// Inline data-file viewing (v0.4.41): 60%+ of task_artifacts are json/csv/txt/log data
// evidence that used to be download-only — the key gap in 'exfiltrate the data and show
// it'. This parses data files into structured previews (JSON arrays→table rows,
// CSV/TSV→table, JSONL→line by line, everything else→text) for the frontend
// ArtifactDataViewer to render directly.
//
// Limits: read ≤20MB (matching the per-attachment cap); JSON rows/CSV rows/text lines
// each capped, with truncated flagged in the response — the raw evidence is always
// available in full via download.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	dataPreviewMaxBytes = 20 << 20
	dataPreviewMaxRows  = 100
	dataPreviewMaxLines = 200
	dataPreviewMaxValue = 300
)

func dataPreviewKind(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	switch ext {
	case "gz":
		return "gz"
	case "zip":
		return "zip"
	case "json":
		return "json"
	case "jsonl", "ndjson":
		return "jsonl"
	case "csv":
		return "csv"
	case "tsv":
		return "tsv"
	default:
		return "text"
	}
}

// dataParseResult is the parsed preview payload.
type dataParseResult struct {
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	BoundFinding int64    `json:"bound_finding"`
	TotalRows    int      `json:"total_rows"`
	Truncated    bool     `json:"truncated"`
	Columns      []string `json:"columns,omitempty"`
	Rows         [][]any  `json:"rows,omitempty"`
	Text         string   `json:"text,omitempty"`
	TotalSize    int64    `json:"total_size"`
	Envelope     string   `json:"envelope,omitempty"`
}

func parseDataPreview(kind, raw string) *dataParseResult {
	switch kind {
	case "json":
		return parseJSONPreview(raw)
	case "jsonl":
		return parseJSONLPreview(raw)
	case "csv", "tsv":
		return parseCSVPreview(raw, kind)
	default:
		return parseTextPreview(raw)
	}
}

func parseJSONPreview(raw string) *dataParseResult {
	res := &dataParseResult{Type: "json"}
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &v); err != nil {
		return parseTextPreview(raw)
	}
	// API envelope drilling (v0.4.41): responses like {code,msg,data:[...]} auto-pick the
	// array field as the row source (data/rows/list/result/records preferred).
	if obj, ok := v.(map[string]any); ok {
		for _, k := range []string{"data", "rows", "list", "result", "records"} {
			if inner, ok2 := obj[k].([]any); ok2 && len(inner) > 0 {
				res2 := parseJSONPreviewItems(inner)
				res2.Envelope = k
				res2.TotalRows = len(inner)
				res2.Truncated = len(inner) > dataPreviewMaxRows
				return res2
			}
		}
	}
	switch arr := v.(type) {
	case []any:
		*res = *parseJSONPreviewItems(arr)
		res.TotalRows = len(arr)
		res.Truncated = len(arr) > dataPreviewMaxRows
	case map[string]any:
		res.TotalRows = 1
		keys := []string{}
		for k := range arr {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		res.Columns = keys
		cells := make([]any, 0, len(keys))
		for _, k := range keys {
			cells = append(cells, clipValue(arr[k]))
		}
		res.Rows = append(res.Rows, cells)
	default:
		res.Text = strings.TrimSpace(raw)
	}
	return res
}

// dataRowCells flattens a record into cells aligned with columns; new keys backfill
// existing rows.
func dataRowCells(item any, cols *[]string, colSet map[string]bool) []any {
	obj, ok := item.(map[string]any)
	if !ok {
		return []any{clipValue(item)}
	}
	for k := range obj {
		if !colSet[k] && len(*cols) < 30 {
			colSet[k] = true
			*cols = append(*cols, k)
		}
	}
	cells := make([]any, 0, len(*cols))
	for _, c := range *cols {
		if v, ok := obj[c]; ok {
			cells = append(cells, clipValue(v))
		} else {
			cells = append(cells, nil)
		}
	}
	return cells
}

func clipValue(v any) any {
	s, ok := v.(string)
	if !ok {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		s = string(b)
	}
	s = strings.TrimSpace(s)
	if len(s) > dataPreviewMaxValue {
		s = s[:dataPreviewMaxValue] + "…"
	}
	return s
}

// parseJSONPreviewItems flattens array elements into table rows (shares column
// collection with the []any branch).
func parseJSONPreviewItems(arr []any) *dataParseResult {
	res := &dataParseResult{Type: "json"}
	colSet := map[string]bool{}
	n := len(arr)
	if n > dataPreviewMaxRows {
		n = dataPreviewMaxRows
	}
	for _, item := range arr[:n] {
		if obj, ok := item.(map[string]any); ok {
			for k := range obj {
				if !colSet[k] && len(colSet) < 30 {
					colSet[k] = true
				}
			}
		}
	}
	cols := make([]string, 0, len(colSet))
	for k := range colSet {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	res.Columns = cols
	for _, item := range arr[:n] {
		res.Rows = append(res.Rows, dataRowCells(item, &cols, colSet))
	}
	return res
}

func parseJSONLPreview(raw string) *dataParseResult {
	res := &dataParseResult{Type: "jsonl"}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	colSet := map[string]bool{}
	cols := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		res.TotalRows++
		if len(res.Rows) >= dataPreviewMaxRows {
			res.Truncated = true
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			res.Rows = append(res.Rows, []any{clipValue(line)})
			continue
		}
		res.Rows = append(res.Rows, dataRowCells(obj, &cols, colSet))
	}
	res.Columns = cols
	return res
}

func parseCSVPreview(raw string, kind string) *dataParseResult {
	res := &dataParseResult{Type: "csv"}
	sep := ','
	if kind == "tsv" {
		sep = '	'
	}
	r := csv.NewReader(strings.NewReader(raw))
	r.Comma = sep
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		return parseTextPreview(raw)
	}
	res.Columns = records[0]
	body := records[1:]
	res.TotalRows = len(body)
	res.Truncated = len(body) > dataPreviewMaxRows
	for i, rec := range body {
		if i >= dataPreviewMaxRows {
			break
		}
		cells := make([]any, 0, len(rec))
		for _, c := range rec {
			cells = append(cells, strings.TrimSpace(c))
		}
		res.Rows = append(res.Rows, cells)
	}
	return res
}

func parseTextPreview(raw string) *dataParseResult {
	res := &dataParseResult{Type: "text"}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	// drop trailing blank lines (files normally end with a newline — that's not row N).
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	res.TotalRows = len(lines)
	res.Truncated = len(lines) > dataPreviewMaxLines
	keep := lines
	if len(keep) > dataPreviewMaxLines {
		keep = keep[:dataPreviewMaxLines]
	}
	res.Text = strings.Join(keep, "\n")
	return res
}

func (s *Server) serveArtifactDataPreview(w http.ResponseWriter, r *http.Request) {
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
	abs := filepath.Join(s.m.dir, a.Storage)
	st, err := os.Stat(abs)
	if err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "artifact file missing")
		return
	}
	raw, innerName, zipRes, err := expandArtifact(abs, a.Name)
	if err != nil {
		writeErr(w, 500, "parse failed: "+err.Error())
		return
	}
	var res *dataParseResult
	if zipRes != nil {
		res = zipRes
	} else {
		res = parseDataPreview(dataPreviewKind(innerName), raw)
	}
	res.TotalSize = st.Size()
	res.Name = a.Name
	res.Kind = a.Kind
	res.BoundFinding = a.FindingID
	writeJSON(w, 200, res)
}

// Parsing unit tests live in artifact_data_preview_test.go.

// v0.4.42 extension: gzip unpacking, zip listings, xml/yaml/sql/html as text — more
// file types get 'actively converted' into readable form.

// innerPreviewName strips the .gz suffix, returning the unpacked real filename.
func innerPreviewName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".gz")
}

// expandArtifact reads a file and unpacks as needed: .gz auto-gunzips; .zip returns an
// entry listing. Returns (content, inner filename, zip entries, error).
func expandArtifact(abs string, name string) (string, string, *dataParseResult, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", "", nil, err
	}
	defer f.Close()
	if strings.HasSuffix(strings.ToLower(name), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return "", "", nil, err
		}
		defer zr.Close()
		raw, err := io.ReadAll(io.LimitReader(zr, dataPreviewMaxBytes))
		if err != nil {
			return "", "", nil, err
		}
		return string(raw), innerPreviewName(name), nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, dataPreviewMaxBytes))
	if err != nil {
		return "", "", nil, err
	}
	if strings.HasSuffix(strings.ToLower(name), ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(raw), st64(abs))
		if err != nil {
			// not a valid zip → treat as text
			return string(raw), name, nil, nil
		}
		res := &dataParseResult{Type: "zip", Columns: []string{"filename", "size", "modified"}}
		res.TotalRows = len(zr.File)
		res.Truncated = len(zr.File) > dataPreviewMaxRows
		n := len(zr.File)
		if n > dataPreviewMaxRows {
			n = dataPreviewMaxRows
		}
		for _, zf := range zr.File[:n] {
			mt := zf.Modified.Format("2006-01-02 15:04")
			res.Rows = append(res.Rows, []any{zf.Name, fmtBytes64(zf.UncompressedSize64), mt})
		}
		return "", name, res, nil
	}
	return string(raw), name, nil, nil
}

func fmtBytes64(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func st64(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}
