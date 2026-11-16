package agent

// Tool-output ledger and verbatim evidence re-verification (v0.4.29, peer-comparison analysis P0b #2).
//
// Source: PentestGPT's new-agent evidence_excerpt mechanism (MIT, mechanism re-implemented) —
// an executor's evidence citation must be a verbatim contiguous substring of this episode's real command
// output; if its source can't be found in the append-only trace, validation fails. Fabricated evidence is
// the biggest source of false positives / credibility loss in SRC scenarios — harder than any 'please review' prompt.
//
// Our landing is 'observe first, intercept later' three-tier (anti-regression):
//   off   — don't verify (explicit opt-out beyond the default)
//   warn  — only cross-check and append a note to the report_finding return, never blocks (default)
//   block — critical/high where no evidence line traces to this run's tool output → reject
//
// Matching rewritten per PentestGPT's two-level leniency: whitespace-normalized per-line substring match;
// short evidence lines (<20 chars) don't count toward the denominator — generic lines like 'GET /api' shouldn't skew the verdict.

import (
	"context"
	"regexp"
	"strings"
	"sync"
)

// EvidenceVerifyMode is the evidence re-verification tier.
type EvidenceVerifyMode int

const (
	EvidenceVerifyOff EvidenceVerifyMode = iota
	EvidenceVerifyWarn
	EvidenceVerifyBlock
)

// EvidenceVerifyModeFromString parses the setting (unknown values fall back to warn — better warn than block).
func EvidenceVerifyModeFromString(v string) EvidenceVerifyMode {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "false", "0":
		return EvidenceVerifyOff
	case "block", "strict":
		return EvidenceVerifyBlock
	default:
		return EvidenceVerifyWarn
	}
}

type toolOutputCtxKey struct{}

type toolOutputsCtx struct {
	ledger *ToolOutputLedger
	mode   EvidenceVerifyMode
}

// WithToolOutputs attaches this run's tool-output ledger and verification tier to ctx; report_finding
// reads it from ctx (the agent package doesn't depend on the DB settings layer).
func WithToolOutputs(ctx context.Context, ledger *ToolOutputLedger, mode EvidenceVerifyMode) context.Context {
	if ledger == nil {
		return ctx
	}
	return context.WithValue(ctx, toolOutputCtxKey{}, toolOutputsCtx{ledger: ledger, mode: mode})
}

// ToolOutputsFromContext reads the ledger and tier (ledger=nil when unwired).
func ToolOutputsFromContext(ctx context.Context) (*ToolOutputLedger, EvidenceVerifyMode) {
	v, ok := ctx.Value(toolOutputCtxKey{}).(toolOutputsCtx)
	if !ok || v.ledger == nil {
		return nil, EvidenceVerifyOff
	}
	return v.ledger, v.mode
}

const (
	toolOutputLedgerMaxEntries = 200
	toolOutputLedgerMaxBytes   = 4 << 20 // 4MB normalized text cap
	toolOutputLedgerEntryCap   = 16 << 10
)

// ToolOutputLedger is the tool-echo text the model actually saw this run (post-truncation content —
// which is also exactly all the text the model could cite). addFinding uses it to verify evidence provenance.
type ToolOutputLedger struct {
	mu      sync.Mutex
	entries []string // normalized outputs
	bytes   int
}

// NewToolOutputLedger builds an empty ledger.
func NewToolOutputLedger() *ToolOutputLedger { return &ToolOutputLedger{} }

var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// normalizeForMatch strips ANSI control sequences and squashes in-line whitespace to single spaces.
func normalizeForMatch(s string) string {
	s = ansiEscapeRe.ReplaceAllString(s, "")
	if !strings.ContainsAny(s, " \t\r\f\v") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch r {
		case ' ', '\t', '\r', '\f', '\v':
			space = true
			continue
		case '\n':
			space = false
			b.WriteRune('\n')
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Add appends one tool echo (post-truncation text).
func (l *ToolOutputLedger) Add(text string) {
	if l == nil || strings.TrimSpace(text) == "" {
		return
	}
	if len(text) > toolOutputLedgerEntryCap {
		text = text[:toolOutputLedgerEntryCap]
	}
	norm := normalizeForMatch(text)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, norm)
	l.bytes += len(norm)
	for len(l.entries) > toolOutputLedgerMaxEntries || l.bytes > toolOutputLedgerMaxBytes {
		l.bytes -= len(l.entries[0])
		l.entries = l.entries[1:]
	}
}

// VerifyEvidence counts how many 'meaningful lines' (≥20 bytes after whitespace removal) of the evidence
// can be found verbatim in tool echoes. Returns (hit lines, counted lines). total=0 means evidence too
// short / no valid lines — the caller should skip judging.
func (l *ToolOutputLedger) VerifyEvidence(evidence string) (matched, total int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	joined := strings.Join(l.entries, "\n")
	l.mu.Unlock()
	if joined == "" {
		return 0, 0
	}
	for _, line := range strings.Split(evidence, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 20 {
			continue
		}
		total++
		if strings.Contains(joined, normalizeForMatch(line)) {
			matched++
		}
	}
	return matched, total
}

// evidenceVerdict buckets hits into three tiers; total<2 is undecidable (returns good — don't disturb).
func evidenceVerdict(matched, total int) string {
	if total < 2 {
		return "good"
	}
	if matched == 0 {
		return "none"
	}
	if matched*2 >= total {
		return "good"
	}
	return "partial"
}

// String returns the setting form (off|warn|block) — for display.
func (m EvidenceVerifyMode) String() string {
	switch m {
	case EvidenceVerifyOff:
		return "off"
	case EvidenceVerifyBlock:
		return "block"
	default:
		return "warn"
	}
}
