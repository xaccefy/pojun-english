package agent

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/chu0119/pojun/db"
)

// fakeProvider is a controllable fake provider: records each call's MaxTokens and input length,
// and returns content or an empty body per script.
//
// calls is mutex-protected: sub-block compaction is **concurrent** (see compressChunked's comment) —
// unlocked, concurrent tests trip -race, and call order stops being deterministic (under concurrency,
// call numbers don't naturally map to sub-block numbers).
type fakeProvider struct {
	mu    sync.Mutex
	calls []fakeCall
	// reply is the body returned per call; empty = simulate 'model only thought, no body'.
	reply func(call int, maxTokens int, input string) string
	// stop is the stop reason returned
	stop func(call int) string
}

type fakeCall struct {
	MaxTokens int
	Input     string
}

func (f *fakeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {}
}

func (f *fakeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	in := ""
	for _, m := range req.Messages {
		in += m.Text()
	}
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{MaxTokens: req.MaxTokens, Input: in})
	idx := len(f.calls) - 1
	f.mu.Unlock()
	body := ""
	if f.reply != nil {
		body = f.reply(idx, req.MaxTokens, in)
	}
	stop := ""
	if f.stop != nil {
		stop = f.stop(idx)
	}
	msg := llm.Message{}
	if body != "" {
		msg.Content = []llm.ContentBlock{llm.TextBlock(body)}
	}
	return msg, stop, llm.Usage{InputTokens: 100, OutputTokens: 50}, nil
}

// callCount returns issued call count (thread-safe).
func (f *fakeProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// snapshotCalls returns a copy of the call records (thread-safe).
func (f *fakeProvider) snapshotCalls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// The compaction output budget must be **generous**.
//
// Regression background: MaxTokens was once hardcoded to 1500. Measured: models with forced adaptive
// thinking (MiniMax-M3.1) inflate thinking length linearly with that budget — 1500/2048/4096/8192 all
// yielded 'thinking burned out, empty body', 97.5% of compactions failed; only 32768 produced bodies.
// So the default must be large enough, and overridable by callers.
func TestCompressOutputBudgetIsGenerous(t *testing.T) {
	prov := &fakeProvider{reply: func(int, int, string) string { return "summary body" }}
	c := NewCompactor(prov, "test-model")

	if c.outTokens < 32768 {
		t.Errorf("default output budget too small: %d (thinking models need headroom)", c.outTokens)
	}
	if c.maxDur < 10*time.Minute {
		t.Errorf("default wall-clock cap too small: %v (thinking models on long inputs run long)", c.maxDur)
	}
	// Per-block cap must be small enough: measured 26 nodes/block always fails, 9 nodes/block fails 1-in-3,
	// 6 nodes/block is stable. Default takes the measured most-stable value.
	if c.maxBlockMembers != 6 {
		t.Errorf("default per-block cap %d, should be 6 (measured most stable)", c.maxBlockMembers)
	}
}

// After SetOutputTokens override, compress must actually use the new budget.
func TestCompressUsesConfiguredOutputBudget(t *testing.T) {
	prov := &fakeProvider{reply: func(int, int, string) string { return "summary body" }}
	c := NewCompactor(prov, "test-model")
	c.SetOutputTokens(65536)

	g := &coldGraph{}
	b := block{Members: []int64{1, 2}}
	body, err := c.compress(context.Background(), g, b, map[int64]*db.Node{})
	if err != nil {
		t.Fatalf("compress failed: %v", err)
	}
	if body != "summary body" {
		t.Errorf("body mismatch: %q", body)
	}
	if prov.callCount() != 1 {
		t.Fatalf("should call once, got %d", prov.callCount())
	}
	if prov.snapshotCalls()[0].MaxTokens != 65536 {
		t.Errorf("configured output budget not used: %d", prov.snapshotCalls()[0].MaxTokens)
	}
}

// SetOutputTokens(0) restores default; SetMaxDuration same.
func TestCompactorSettersFallBackToDefaults(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	c.SetOutputTokens(1234)
	c.SetMaxDuration(3 * time.Minute)
	if c.outTokens != 1234 {
		t.Errorf("SetOutputTokens ineffective: %d", c.outTokens)
	}
	if c.maxDur != 3*time.Minute {
		t.Errorf("SetMaxDuration ineffective: %v", c.maxDur)
	}
	c.SetOutputTokens(0)
	c.SetMaxDuration(0)
	if c.outTokens != defaultCompactionTokens {
		t.Errorf("0 should restore default budget, got %d", c.outTokens)
	}
	if c.maxDur != defaultCompactionDuration {
		t.Errorf("0 should restore default duration, got %v", c.maxDur)
	}
}

// Empty body must surface diagnostics.
// Regression background: it used to return just 'empty body from model' — debugging was impossible:
// couldn't tell stop=length (truncated) from thinking-only-no-body.
func TestCompressEmptyBodyCarriesDiagnostics(t *testing.T) {
	prov := &fakeProvider{
		reply: func(int, int, string) string { return "" },
		stop:  func(int) string { return "length" },
	}
	c := NewCompactor(prov, "test-model")
	g := &coldGraph{}
	b := block{Members: []int64{1}}
	_, err := c.compress(context.Background(), g, b, map[int64]*db.Node{})
	if err == nil {
		t.Fatal("empty body should error")
	}
	msg := err.Error()
	for _, want := range []string{"empty body", "length", "in=", "out="} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

// Oversized single blocks must auto-split into sub-blocks compacted separately.
//
// Regression background: a measured 26-node connected block (3084 prompt tokens) drives thinking models
// into endless thinking — 32768 budget burned out, 211s with no body. 3 nodes (743 tokens) close
// normally. Whether the model can close depends on **single-request input size**, not budget size.
// So oversized blocks must be split so each request lands inside what the model can handle.
func TestCompressSplitsOversizedBlock(t *testing.T) {
	var prov fakeProvider
	prov.reply = func(call int, maxTokens int, input string) string {
		return fmt.Sprintf("subblock%d", call)
	}
	c := NewCompactor(&prov, "test-model")
	c.SetMaxBlockMembers(4) // small threshold for the test

	// 10-member block → should split into 3 (4+4+2)
	members := make([]int64, 10)
	nodeByID := map[int64]*db.Node{}
	for i := range members {
		members[i] = int64(i + 1)
		nodeByID[members[i]] = &db.Node{ID: members[i], Kind: db.KindFact, State: "confirmed"}
	}
	g := &coldGraph{}
	b := block{Members: members}
	bodies, err := c.compressChunked(context.Background(), g, b, nodeByID)
	if err != nil {
		t.Fatalf("compressChunked failed: %v", err)
	}
	if len(bodies) != 3 {
		t.Errorf("10 members split by 4 should give 3 blocks, got %d", len(bodies))
	}
	if prov.callCount() != 3 {
		t.Errorf("should issue 3 calls, got %d", prov.callCount())
	}
	// Each call's input stays within the threshold
	for i, call := range prov.snapshotCalls() {
		n := strings.Count(call.Input, "\n- #")
		if n > 4 {
			t.Errorf("call %d has %d members, over threshold 4", i, n)
		}
	}
}

// Threshold 0 / negative = restore default (12), not 'no split'.
// Deliberately no 'no-split' option: measured oversized connected blocks reliably drive thinking models into endless thinking.
func TestCompressThresholdZeroRestoresDefault(t *testing.T) {
	prov := &fakeProvider{reply: func(int, int, string) string { return "x" }}
	c := NewCompactor(prov, "m")
	c.SetMaxBlockMembers(4)
	c.SetMaxBlockMembers(0)
	if c.maxBlockMembers != defaultCompactionMaxMembers {
		t.Errorf("0 should restore default threshold, got %d", c.maxBlockMembers)
	}
}

// Node summaries must carry through into the compaction input correctly (node text may contain quotes/newlines).
func TestBuildCompressionInputEscapesNodeText(t *testing.T) {
	nodeByID := map[int64]*db.Node{
		1: {ID: 1, Kind: db.KindFact, State: "confirmed", Payload: []byte(`{"summary":"has \"quotes\" and\nnewline"}`)},
	}
	g := &coldGraph{}
	in := buildCompressionInput(g, block{Members: []int64{1}}, nodeByID)
	if !strings.Contains(in, `has "quotes"`) {
		t.Errorf("node summary didn't carry through: %s", in)
	}
}

// Sub-blocks must compact **concurrently** — serial hits the background-compaction wall-clock cap.
//
// Regression background: a measured 200-node connected block splits into 32 sub-blocks at 6 nodes/block,
// each ~124s. Serial is 32×124 ≈ 66 min vs the 20-min cap for one background compaction
// (defaultCompactionDuration) — guaranteed context deadline exceeded. Production hit exactly this:
// one block failed 'sub-block 15/32 compaction failed' after the first 14 had already burned 30
// minutes of LLM time — whole block wasted.
//
// Concurrency cap is compactionSubConcurrency (4): 32-way would crush the shared rate-limited gateway
// and fail everything; 4-way squeezes 66 min into ~17 min, safely inside the cap.
func TestCompressChunkedRunsSubBlocksConcurrently(t *testing.T) {
	const (
		members  = 40 // 40 members
		limit    = 4  // 4 per block → 10 sub-blocks
		wantSubs = members / limit
	)
	var (
		mu      sync.Mutex
		inFlt   = 0
		maxSeen = 0
	)
	prov := &fakeProvider{}
	prov.reply = func(call int, maxTokens int, input string) string {
		// Track in-flight sub-block count.
		mu.Lock()
		inFlt++
		if inFlt > maxSeen {
			maxSeen = inFlt
		}
		mu.Unlock()
		// Stretch each call so the concurrency window is observable.
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		inFlt--
		mu.Unlock()
		return fmt.Sprintf("subblock%d", call)
	}

	c := NewCompactor(prov, "test-model")
	c.SetMaxBlockMembers(limit)

	ms := make([]int64, members)
	nodeByID := map[int64]*db.Node{}
	for i := range ms {
		ms[i] = int64(i + 1)
		nodeByID[ms[i]] = &db.Node{ID: ms[i], Kind: db.KindFact, State: "confirmed"}
	}
	bodies, err := c.compressChunked(context.Background(), &coldGraph{}, block{Members: ms}, nodeByID)
	if err != nil {
		t.Fatalf("compressChunked failed: %v", err)
	}
	if len(bodies) != wantSubs {
		t.Fatalf("should get %d sub-block summaries, got %d", wantSubs, len(bodies))
	}
	if prov.callCount() != wantSubs {
		t.Fatalf("should issue %d calls, got %d", wantSubs, prov.callCount())
	}
	mu.Lock()
	observed := maxSeen
	mu.Unlock()
	if observed < 2 {
		t.Errorf("sub-blocks should run concurrently, but max in-flight was %d (concurrency not working)", observed)
	}
	if observed > compactionSubConcurrency {
		t.Errorf("in-flight sub-blocks %d exceed concurrency cap %d", observed, compactionSubConcurrency)
	}
}
