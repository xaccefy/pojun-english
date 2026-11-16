package agent

// cold-digest §4/§5/§7: the Compactor ties the pure algorithms (coldgraph.go)
// to the store (db/digest.go) and the LLM. It runs in two modes:
//
//	maintain — cheap, synchronous, once per planner round: bump round_no,
//	           recompute hot/cold, stamp/clear cold_since_round (§2.3). This is
//	           the bookkeeping the planner does anyway; it never calls the LLM.
//	minor/major — background, off the planner hot path (§7): group cold nodes
//	           and compress each ≥2 block into a digest via the LLM. minor folds
//	           only the not-yet-covered cold set (tiered append); major re-derives
//	           the whole grouping from source and merges fragments (§5.1/§5.2),
//	           reusing bodies whose signature is unchanged (§5.3).
//
// Concurrency: one compaction per task at a time (mutex), ≥cooldown between runs,
// and a commit-time liveness recheck drops any member that revived while the body
// was being generated so a digest never covers a hot node.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/db"
)

// Compactor performs background cold-node compaction for many explorations.
type Compactor struct {
	prov     llm.Provider
	model    string
	params   coldParams
	n, m     int           // minor / major thresholds (§7 N=20, M=8)
	cooldown time.Duration // min gap between compactions per task (§7 60s)
	maxDur   time.Duration // hard cap on one background compaction
	// outTokens is the output budget for one compaction call (thinking + body share it). 0 = use defaultCompactionTokens.
	//
	// Why a small value won't work: adaptive-thinking models (MiniMax-M3.1 etc., forced thinking) **keep thinking
	// up to the max_tokens budget** — the smaller the budget, the longer it thinks and the body never comes: measured on the same
	// 26-node input, budget 1500 → thinking burned all 1500, body 0 chars; budget 2048 → body still 0;
	// budget 32768 → ~2000 thinking tokens then it wrapped and emitted a normal body. So an undersized budget
	// isn't 'output truncated' — the model **never reaches the body at all**.
	outTokens int
	// maxBlockMembers is the member-node cap per compaction request. 0 = unlimited.
	//
	// Why cap it: measured — **whether a run wraps depends on single-request input size, not budget size**: 3 nodes
	// (743 prompt tokens) wrapped normally under a 32768 budget (~2000 thinking tokens), while 26 nodes
	// (3084 prompt tokens) burned the whole 32768 and ran 211s without a body.
	// So oversized connected blocks must be split, keeping each request's size inside what the model can handle.
	maxBlockMembers int

	mu      sync.Mutex
	running map[int64]bool
	lastRun map[int64]time.Time
	// consecFails records how many consecutive rounds of compaction failed per exploration, for failure backoff (see cooldownForLocked).
	consecFails map[int64]int
}

// defaultCompactionTokens is the default output budget for a compaction call.
//
// Why 65536: measured — 6 nodes/block wrapped normally in 124s under a 65536 budget (11733
// tokens used); 9 nodes/block saw 1 of 3 blocks burn out a 32768 budget and fail. A generous budget
// markedly improves the success rate — thinking models think up to the max_tokens budget; a bigger budget means
// longer thinking, but also a better chance of thinking itself to a conclusion.
//
// 65536 is still shared between 'thinking + body'; too small and the model thinks forever, never reaching the body
// (see the outTokens field comment).
const defaultCompactionTokens = 65536

// defaultCompactionDuration is the wall-clock cap for one background compaction.
//
// Compaction runs in a **background goroutine**, parallel to workers claiming intents (logs show compaction interleaved
// with 'claimed intent' entries); waiting longer doesn't hold up the main flow — cold-node compaction just lands later. 5 minutes is
// clearly too short for adaptive-thinking models on long inputs (measured: 26 nodes need 10+ minutes), hence relaxed.
const defaultCompactionDuration = 20 * time.Minute

// defaultCompactionMaxMembers is the member-node cap per compaction request.
//
// Why 6 (measured on the same real 26-node input, split tier by tier):
//   - 26 nodes/block: burned out the whole budget even at max_tokens 65536 — no body after 10 minutes.
//   - 9 nodes/block: 2 of 3 succeeded (194s / 324s), 1 failed (burned 32768).
//   - 6 nodes/block: wrapped normally in 124s, using 11733 tokens.
//
// So the finer the split, the easier the model wraps and the less time it takes. 6 balances 'success rate' against
// 'don't shred the digest too fine (shredded pieces lose the point of synthesis)'.
const defaultCompactionMaxMembers = 6

// compactionSubConcurrency is the concurrency for sub-block compaction inside one block.
//
// Why 4: a measured single sub-block (6 nodes) takes ~124s. A 200-node connected block split at 6 nodes/block
// yields 32 sub-blocks — serial would be 32×124 ≈ 66 min, far over the 20-min wall-clock cap for one background
// compaction — a guaranteed context deadline exceeded. 4-way concurrency squeezes it to ~17 min, well inside the cap.
//
// Why not higher: the upstream is a shared rate-limited gateway — 32-way concurrency would crush it and everything fails.
// 4 balances 'don't hit the wall clock' against 'don't crush upstream'.
const compactionSubConcurrency = 4

// NewCompactor builds a compactor. prov/model are used for the §4 body LLM call
// (same model the agent runs on, per §4). A nil Compactor is a safe no-op.
func NewCompactor(prov llm.Provider, model string) *Compactor {
	return &Compactor{
		prov:      prov,
		model:     model,
		params:    defaultColdParams(),
		n:         20,
		m:         8,
		cooldown:  60 * time.Second,
		maxDur:    defaultCompactionDuration,
		outTokens: defaultCompactionTokens,
		// The maxBlockMembers default split: oversized connected blocks trap thinking models into endless thinking.
		maxBlockMembers: defaultCompactionMaxMembers,
		running:         map[int64]bool{},
		lastRun:         map[int64]time.Time{},
		consecFails:     map[int64]int{},
	}
}

// SetOutputTokens sets the compaction call's output budget. 0 = back to default.
// Lets deployers tune 'how big a budget thinking models need' instead of editing constants in code.
func (c *Compactor) SetOutputTokens(n int) {
	if c == nil {
		return
	}
	if n <= 0 {
		n = defaultCompactionTokens
	}
	c.outTokens = n
}

// SetMaxDuration sets the wall-clock cap for one background compaction. <=0 = back to default.
func (c *Compactor) SetMaxDuration(d time.Duration) {
	if c == nil {
		return
	}
	if d <= 0 {
		d = defaultCompactionDuration
	}
	c.maxDur = d
}

// SetMaxBlockMembers sets the member-node cap per compaction request. <=0 = back to default.
// Deliberately no 'don't split' option: measured — oversized connected blocks inevitably trap thinking models,
// so splitting is a precondition for compaction landing, not an optional optimization.
func (c *Compactor) SetMaxBlockMembers(n int) {
	if c == nil {
		return
	}
	if n <= 0 {
		n = defaultCompactionMaxMembers
	}
	c.maxBlockMembers = n
}

// OnPlannerRound is the single entry the planner calls each wake-up. It bumps the
// round, maintains the cold stamps synchronously, then (if a threshold is hit and
// no compaction is running / cooling down) launches a background compaction that
// outlives this planner round.
func (c *Compactor) OnPlannerRound(ctx context.Context, ts *db.ExplorationStore) {
	if c == nil || c.prov == nil || ts == nil {
		return
	}
	round, uncompressed, activeDigests, err := c.maintain(ts)
	if err != nil {
		log.Printf("[compaction] maintain exp=%d: %v", ts.ID(), err)
		return
	}
	needMinor := uncompressed >= c.n
	needMajor := activeDigests >= c.m
	if !needMinor && !needMajor {
		return
	}
	if !c.tryStart(ts.ID()) {
		return // already running, or within cooldown — derived-state eventual consistency, retry next round
	}
	go func() {
		defer c.finish(ts.ID())
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.maxDur)
		defer cancel()
		// Compaction is a bare provider call (prov.Complete inside compress) — it doesn't go through agentcore's
		// session loop, so the ctx carries no session id; gateways doing session-id-header prompt caching/sticky
		// routing (opencode zen 400s without x-opencode-session) wouldn't get that header.
		// Here we supply an exploration-stable id: all compaction requests of one exploration share it — the header goes out,
		// and llmrec can attribute this call's tokens back to the exploration (previously unrecordable).
		bg = transcript.WithSessionID(bg, fmt.Sprintf("exp%d-compactor", ts.ID()))
		if needMajor {
			c.major(bg, ts)
		} else {
			c.minor(bg, ts)
		}
	}()
	_ = round
}

// maintain bumps round_no, recomputes hot/cold over the whole graph, and applies
// the cold_since_round stamp/clear ops (§2.3). Returns the new round plus the
// counts that drive the trigger: how many eligible-cold nodes are not yet covered
// (minor) and how many active digests exist (major).
func (c *Compactor) maintain(ts *db.ExplorationStore) (round int64, uncompressed, activeDigests int, err error) {
	round, err = ts.BumpRound()
	if err != nil {
		return
	}
	g, _, err := loadColdGraph(ts)
	if err != nil {
		return
	}
	stamps, err := ts.ColdStamps()
	if err != nil {
		return
	}
	hot := g.hotSet()
	structCold := g.structuralCold(hot)
	ops := computeStampOps(structCold, stamps, round)
	if err = ts.ApplyStampOps(toDBStampOps(ops)); err != nil {
		return
	}
	applyStampsInPlace(stamps, ops)
	elig := g.eligibleCold(structCold, stamps, round, c.params)
	covered, err := ts.CoveredMembers()
	if err != nil {
		return
	}
	for id := range elig {
		if _, ok := covered[id]; !ok {
			uncompressed++
		}
	}
	ad, err := ts.ActiveDigests()
	if err != nil {
		return
	}
	activeDigests = len(ad)
	return
}

// minor folds the not-yet-covered eligible-cold set into new digest segments
// (tiered append, §5). Existing digests are untouched.
func (c *Compactor) minor(ctx context.Context, ts *db.ExplorationStore) {
	round, err := ts.RoundNo()
	if err != nil {
		return
	}
	g, nodeByID, err := loadColdGraph(ts)
	if err != nil {
		return
	}
	stamps, err := ts.ColdStamps()
	if err != nil {
		return
	}
	cvers, err := ts.ContentVersions()
	if err != nil {
		return
	}
	covered, err := ts.CoveredMembers()
	if err != nil {
		return
	}
	hot := g.hotSet()
	elig := g.eligibleCold(g.structuralCold(hot), stamps, round, c.params)
	uncompressed := map[int64]bool{}
	for id := range elig {
		if _, ok := covered[id]; !ok {
			uncompressed[id] = true
		}
	}
	blocks := g.group(uncompressed, c.params)
	if len(blocks) == 0 {
		return // this batch has no ≥2 connected/shared-parent block — nothing to fold (§7)
	}
	allOK := true
	for _, b := range blocks {
		if !c.foldBlock(ctx, ts, g, b, nodeByID, cvers, c.generationFor(b, nil)) {
			allOK = false
		}
	}
	c.recordResult(ts.ID(), allOK)
	// A minor may have pushed the segment count over M → merge in the same run.
	if ad, e := ts.ActiveDigests(); e == nil && len(ad) >= c.m {
		c.major(ctx, ts)
	}
}

// major re-derives the whole grouping from source over ALL eligible-cold nodes
// (§5.1 source re-compression), then reconciles against the active digests by signature:
// unchanged blocks keep their digest (no LLM), stale digests are superseded, and
// new/changed blocks are compressed afresh. This is where tiered fragments of one
// direction merge and where "later became connected" blocks unify (§5.2).
func (c *Compactor) major(ctx context.Context, ts *db.ExplorationStore) {
	round, err := ts.RoundNo()
	if err != nil {
		return
	}
	g, nodeByID, err := loadColdGraph(ts)
	if err != nil {
		return
	}
	stamps, err := ts.ColdStamps()
	if err != nil {
		return
	}
	cvers, err := ts.ContentVersions()
	if err != nil {
		return
	}
	active, err := ts.ActiveDigests()
	if err != nil {
		return
	}
	hot := g.hotSet()
	elig := g.eligibleCold(g.structuralCold(hot), stamps, round, c.params)
	blocks := g.group(elig, c.params)

	bySig := map[string]*db.Node{}
	for _, d := range active {
		sig, _ := digestSigGen(d)
		bySig[sig] = d
	}
	desired := map[string]bool{}
	var toCreate []block
	for _, b := range blocks {
		sig := blockSignature(b, cvers)
		desired[sig] = true
		if _, ok := bySig[sig]; ok {
			continue // unchanged → reuse the existing digest, skip LLM (§5.3)
		}
		toCreate = append(toCreate, b)
	}
	// Supersede stale digests FIRST (atomic drop of their covers edges) so a member
	// is never covered by both an old and a new digest (§5.1 one-member-one-digest).
	var stale []int64
	for _, d := range active {
		sig, _ := digestSigGen(d)
		if !desired[sig] {
			stale = append(stale, d.ID)
		}
	}
	if err := ts.SupersedeDigests(stale); err != nil {
		log.Printf("[compaction] supersede exp=%d: %v", ts.ID(), err)
	}
	allOK := true
	for _, b := range toCreate {
		if !c.foldBlock(ctx, ts, g, b, nodeByID, cvers, c.generationFor(b, active)) {
			allOK = false
		}
	}
	c.recordResult(ts.ID(), allOK)
}

// foldBlock compresses one block and writes its digest — with a commit-time
// liveness recheck (§ concurrency): between grouping and write the graph may have
// changed, so any member that has since gone hot (revived) is dropped from the
// covers set. If the block dissolves below K it is skipped.
//
// Returns whether it succeeded (no error in either compression or digest write), for the caller's failure backoff.
func (c *Compactor) foldBlock(ctx context.Context, ts *db.ExplorationStore, g *coldGraph, b block, nodeByID map[int64]*db.Node, cvers map[int64]int, generation int) bool {
	// Oversized blocks are split into sub-blocks compressed separately (see compressChunked's comment: whether a
	// thinking model wraps depends on single-request input size). Multi-part bodies get joined into one — semantically equivalent.
	bodies, err := c.compressChunked(ctx, g, b, nodeByID)
	if err != nil {
		log.Printf("[compaction] compress exp=%d block=%v: %v", ts.ID(), b.Members, err)
		return false
	}
	body := strings.Join(bodies, "\n\n")
	// Re-read fresh state and drop any member that revived while we compressed.
	fresh, _, err := loadColdGraph(ts)
	if err != nil {
		return false
	}
	freshHot := fresh.hotSet()
	members := make([]int64, 0, len(b.Members))
	for _, mID := range b.Members {
		if !freshHot[mID] {
			members = append(members, mID)
		}
	}
	if len(members) < c.params.K {
		return true // block revived out from under us — leave those nodes hot, don't fold
	}
	final := block{Members: members, Anchors: b.Anchors}
	payload := digestPayload(body, final, nodeByID, generation, blockSignature(final, cvers))
	if _, err := ts.AddDigest(payload, members); err != nil {
		log.Printf("[compaction] add digest exp=%d: %v", ts.ID(), err)
		return false
	}
	return true
}

// generationFor computes a digest's re-distillation generation (§1): 1 for a fresh fold; for a major
// merge, max(generation) over the active digests that overlap this block's
// members, +1.
func (c *Compactor) generationFor(b block, active []*db.Node) int {
	if len(active) == 0 {
		return 1
	}
	memberSet := make(map[int64]bool, len(b.Members))
	for _, m := range b.Members {
		memberSet[m] = true
	}
	best := 0
	for _, d := range active {
		_, gen := digestSigGen(d)
		for _, m := range digestMemberIDs(d) {
			if memberSet[m] {
				if gen > best {
					best = gen
				}
				break
			}
		}
	}
	return best + 1
}

// tryStart acquires the per-task compaction lock, honoring the cooldown.
//
// Failure backoff: on consecutive failures this exploration's cooldown grows exponentially. The reasoning is practical —
// a failed compaction burns hundreds of seconds of LLM time (measured thinking models think 300s+ on long inputs
// before giving up), and a 60s cooldown would become a 'burn 5 minutes every minute' loop.
// Compaction failure doesn't block the main flow (without a digest the planner reads raw nodes directly), so backoff
// only saves resources — it doesn't protect functionality.
func (c *Compactor) tryStart(expID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running[expID] {
		return false
	}
	// cooldownForLocked, not cooldownFor: this method already holds c.mu, and
	// sync.Mutex is NOT reentrant — calling cooldownFor here would try to lock
	// c.mu a second time and self-deadlock forever.
	//
	// How it stayed hidden so long: the branch is only reached once
	// c.lastRun[expID] exists, and lastRun is only set by finish() when a
	// compaction goroutine completes. So the first compaction of an exploration
	// is fine; the next planner round after it completed deadlocks — and
	// because a deadlocked mutex ignores ctx cancellation, the planner's
	// wall-clock timeout could not break it either. Symptom: the task goes
	// permanently silent (no new intents, no planner log at all) while the
	// service keeps running. A service restart cleared it, which is why it
	// looked like an upstream/LLM problem.
	if t, ok := c.lastRun[expID]; ok && time.Since(t) < c.cooldownForLocked(expID) {
		return false
	}
	c.running[expID] = true
	return true
}

// cooldownFor returns this exploration's current cooldown (base on success, exponential backoff on consecutive failures).
//
// This is the entry for **lock-free** callers; a caller already holding c.mu must use cooldownForLocked
// (sync.Mutex isn't reentrant — locking again is a self-deadlock).
func (c *Compactor) cooldownFor(expID int64) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cooldownForLocked(expID)
}

// cooldownForLocked returns this exploration's current cooldown (base on success, exponential backoff on consecutive failures).
//
// It must be the Locked variant: a caller holding c.mu calling a same-named locking function self-deadlocks
// (sync.Mutex isn't reentrant), and ctx cancellation can't save it — a deadlocked goroutine never returns,
// so the planner's wall-clock cap dies with it. The hot path tryStart uses exactly this one.
func (c *Compactor) cooldownForLocked(expID int64) time.Duration {
	fails := c.consecFails[expID]
	if fails <= 0 {
		return c.cooldown
	}
	// Exponential backoff, capped at 30 minutes.
	d := c.cooldown
	for i := 0; i < fails && d < 30*time.Minute; i++ {
		d *= 2
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

func (c *Compactor) finish(expID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running[expID] = false
	c.lastRun[expID] = time.Now()
}

// recordResult records one compaction round's outcome: success clears the consecutive-failure count, failure increments it.
func (c *Compactor) recordResult(expID int64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		delete(c.consecFails, expID)
		return
	}
	c.consecFails[expID]++
}

// --- helpers: db ↔ coldgraph ---

// loadColdGraph reads the exploration's nodes + edges and builds the cold-graph
// view plus an id→node index (for summaries/payload during compression).
func loadColdGraph(ts *db.ExplorationStore) (*coldGraph, map[int64]*db.Node, error) {
	// Compaction must see the WHOLE graph, not the default row caps — pass a very
	// high limit so the LIMIT clause is effectively unbounded for real task sizes.
	const allRows = 1 << 30
	nodes, err := ts.Nodes(allRows)
	if err != nil {
		return nil, nil, err
	}
	edges, err := ts.Edges(allRows)
	if err != nil {
		return nil, nil, err
	}
	cgNodes := make([]cgNode, 0, len(nodes))
	byID := make(map[int64]*db.Node, len(nodes))
	for _, n := range nodes {
		cgNodes = append(cgNodes, cgNode{ID: n.ID, Kind: n.Kind, State: n.State})
		byID[n.ID] = n
	}
	cgEdges := make([]cgEdge, 0, len(edges))
	for _, e := range edges {
		cgEdges = append(cgEdges, cgEdge{From: e.From, Rel: e.Rel, To: e.To})
	}
	return newColdGraph(cgNodes, cgEdges), byID, nil
}

func toDBStampOps(ops []stampOp) []db.StampOp {
	out := make([]db.StampOp, len(ops))
	for i, o := range ops {
		out[i] = db.StampOp{ID: o.ID, Set: o.Set, Round: o.Round}
	}
	return out
}

// applyStampsInPlace folds the just-applied ops into the in-memory stamp map so
// eligibility can be computed immediately without a re-read.
func applyStampsInPlace(stamps map[int64]*int64, ops []stampOp) {
	for _, o := range ops {
		if o.Set {
			r := o.Round
			stamps[o.ID] = &r
		} else {
			stamps[o.ID] = nil
		}
	}
}

// --- helpers: digest payload ---

// digestPayload builds the digest node payload (cold-digest §1): the body, the
// member ids split by kind (restore cache; source of truth is the covers edges),
// the anchor ids, the generation, and the change-detection signature.
func digestPayload(body string, b block, nodeByID map[int64]*db.Node, generation int, signature string) map[string]any {
	var facts, intents []int64
	for _, m := range b.Members {
		if n := nodeByID[m]; n != nil && n.Kind == db.KindIntent {
			intents = append(intents, m)
		} else {
			facts = append(facts, m)
		}
	}
	return map[string]any{
		"body":       body,
		"member_ids": map[string]any{"facts": facts, "intents": intents},
		"anchor_ids": b.Anchors,
		"generation": generation,
		"signature":  signature,
	}
}

func digestSigGen(n *db.Node) (string, int) {
	var p struct {
		Signature  string `json:"signature"`
		Generation int    `json:"generation"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.Signature, p.Generation
}

func digestMemberIDs(n *db.Node) []int64 {
	var p struct {
		MemberIDs struct {
			Facts   []int64 `json:"facts"`
			Intents []int64 `json:"intents"`
		} `json:"member_ids"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return append(append([]int64{}, p.MemberIDs.Facts...), p.MemberIDs.Intents...)
}

// --- helpers: compression input + LLM (§4) ---

func nodeSummary(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok {
			return s
		}
		if t, ok := p["text"].(string); ok {
			return t
		}
	}
	return ""
}

func nodeConfidence(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if c, ok := p["confidence"].(string); ok {
			return c
		}
	}
	return ""
}

// buildCompressionInput renders the connected sub-graph for the §4 prompt:
// member nodes (summary + id + kind + state + confidence), the internal blood
// edges among members, and — for a §3.1 shared-parent group — the anchor parents
// as context ("common parent #p"), which are NOT members.
func buildCompressionInput(g *coldGraph, b block, nodeByID map[int64]*db.Node) string {
	memberSet := make(map[int64]bool, len(b.Members))
	for _, m := range b.Members {
		memberSet[m] = true
	}
	var sb strings.Builder
	sb.WriteString("[Member nodes (to compress)]:\n")
	for _, m := range b.Members {
		n := nodeByID[m]
		kind := "fact"
		if n != nil && n.Kind == db.KindIntent {
			kind = "intent"
		}
		state := ""
		if n != nil {
			state = n.State
		}
		line := fmt.Sprintf("- #%d [%s/%s] %s", m, kind, state, nodeSummary(n))
		if conf := nodeConfidence(n); conf != "" {
			line += fmt.Sprintf(" (confidence=%s)", conf)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	// internal edges among members
	var edgeLines []string
	for _, m := range b.Members {
		for _, to := range g.children[m] {
			if memberSet[to] {
				edgeLines = append(edgeLines, fmt.Sprintf("- #%d yields/derives→ #%d", m, to))
			}
		}
	}
	if len(edgeLines) > 0 {
		sb.WriteString("\n[Lineage edges between members (parent→child)]:\n")
		sort.Strings(edgeLines)
		sb.WriteString(strings.Join(edgeLines, "\n"))
		sb.WriteByte('\n')
	}
	if len(b.Anchors) > 0 {
		sb.WriteString("\n[Common parents / context anchors (not members — only for understanding which intent probed these results)]:\n")
		for _, a := range b.Anchors {
			n := nodeByID[a]
			state := ""
			if n != nil {
				state = n.State
			}
			fmt.Fprintf(&sb, "- #%d [%s] %s\n", a, state, nodeSummary(n))
		}
	}
	return sb.String()
}

// compress runs the §4 body LLM call on one block. Uses the same model the agent
// runs on; thinking is left to the model/gateway (a pure summarization step —
// but models like MiniMax-M3.1 with **forced adaptive thinking** reject an explicit
// thinking.type=disabled — so the field isn't sent here).
func (c *Compactor) compress(ctx context.Context, g *coldGraph, b block, nodeByID map[int64]*db.Node) (string, error) {
	tokens := c.outTokens
	if tokens <= 0 {
		tokens = defaultCompactionTokens
	}
	req := llm.CompletionRequest{
		System: []string{compressionSystemPrompt},
		// MaxTokens is shared between thinking and body — undersize it and the model thinks forever, never reaching the body (see
		// the outTokens field comment). Generous headroom here.
		Messages:  []llm.Message{llm.UserText(buildCompressionInput(g, b, nodeByID))},
		MaxTokens: tokens,
	}
	msg, stop, usage, err := c.prov.Complete(ctx, req)
	if err != nil {
		return "", err
	}
	body := strings.TrimSpace(msg.Text())
	if body == "" {
		// An empty body must carry diagnostics out — otherwise all you get is 'empty body from model' with
		// no way to locate the cause. This used to drop the stop reason and usage — debugging was guesswork.
		// Two root causes measured in production:
		//   - stop="length": output truncated by max_tokens (adaptive-thinking models
		//     burn a long thinking stretch first, and the body never gets its turn before the cap).
		//   - thinking blocks but no text block: the model did think, but the body is empty.
		return "", fmt.Errorf("empty body from model (stop=%q blocks=%d in=%d out=%d thinking=%d)",
			stop, len(msg.Content), usage.InputTokens, usage.OutputTokens, countThinking(msg))
	}
	return body, nil
}

// compressChunked compresses a block, splitting oversized ones into sub-blocks first, compressed one by one.
//
// Why split: measured — whether a thinking model wraps depends on **single-request input size**, unrelated to output budget:
// 3 nodes (743 prompt tokens) wrapped normally at 32768; 26 nodes (3084 prompt
// tokens) burned the whole 32768 and ran 211s with no body. Oversized connected blocks (a
// connected component can hold dozens of nodes) really look like this in practice — so splitting is mandatory.
//
// Splitting keeps the original semantics: each block is still 'a group of interrelated nodes', just smaller. The returned
// bodies get joined by the caller into one digest (with separators) — semantically equivalent to one body.
//
// Sub-blocks are compressed **concurrently** (serial would hit the wall-clock cap): a 200-node connected block at 6 nodes/block
// yields 32 sub-blocks, ~124s each measured. Serial would be 32×124 ≈ 66 min, while one background
// compaction's wall-clock cap is 20 min (defaultCompactionDuration) — a guaranteed
// context deadline exceeded. Production hit exactly this shape: a block reported 'sub-block 15/32
// compression failed' after the first 14 had already burned 30 minutes of LLM time for nothing — the whole block discarded.
//
// Concurrency is 4, not all 32: upstream is a shared rate-limited gateway — 32-way would crush it and fail everything;
// 4-way squeezes 66 min to ~17 min, comfortably inside the 20-min cap.
// A single failed sub-block still fails the whole block (better retry than write a half digest), but **successful sub-block
// results are kept** — a retry doesn't start from zero.
func (c *Compactor) compressChunked(ctx context.Context, g *coldGraph, b block, nodeByID map[int64]*db.Node) ([]string, error) {
	limit := c.maxBlockMembers
	if limit <= 0 || len(b.Members) <= limit {
		body, err := c.compress(ctx, g, b, nodeByID)
		if err != nil {
			return nil, err
		}
		return []string{body}, nil
	}
	// Sub-block count: split by limit; the last block may be short.
	nSubs := (len(b.Members) + limit - 1) / limit
	type subResult struct {
		body string
		err  error
	}
	subs := make([]subResult, nSubs)

	// Run concurrently with a bounded degree.
	sem := make(chan struct{}, compactionSubConcurrency)
	var wg sync.WaitGroup
	for k := 0; k < nSubs; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			i := k * limit
			j := i + limit
			if j > len(b.Members) {
				j = len(b.Members)
			}
			sub := block{Members: b.Members[i:j], Anchors: b.Anchors}
			body, err := c.compress(ctx, g, sub, nodeByID)
			subs[k] = subResult{body: body, err: err}
		}(k)
	}
	wg.Wait()

	out := make([]string, 0, nSubs)
	for k, s := range subs {
		if s.err != nil {
			// A failed sub-block fails the whole block (better retry than a half digest).
			return nil, fmt.Errorf("sub-block %d/%d compression failed: %w", k+1, nSubs, s.err)
		}
		out = append(out, s.body)
	}
	return out, nil
}

// countThinking counts thinking blocks in a message. Used to distinguish 'model only thought, no body'
// from 'model returned nothing at all'.
func countThinking(msg llm.Message) int {
	n := 0
	for _, b := range msg.Content {
		if b.Type == llm.BlockThinking {
			n++
		}
	}
	return n
}

// compressionSystemPrompt is the §4 body prompt.
const compressionSystemPrompt = `You are compressing a group of [interrelated] exploration nodes into one synthesized conclusion (body), letting the planner quickly grasp "what this area has already established".

The input is a connected subgraph:
- Nodes: each is an intent's or a fact's summary (one sentence), carrying id, kind (intent/fact), state, confidence (if any).
- Relations: lineage edges between nodes (A derives from B / A yields B), showing how they chain.
- If nodes have no direct lineage edges but share one upstream intent (given separately as "common parent #p"), synthesize them as "what this intent (#p) probed" — the common parent is just a context anchor, not a member to compress.

Write the body accordingly:
1. Synthesize, don't list: weave the causality along the relations (which fact spawned which intent, which intent produced which conclusion) into "what this exploration area established" — don't copy each summary.
2. Keep distinctions: genuinely different conclusions are stated separately — don't blur them into one generic sentence.
3. Keep evidence strength: conclusions carrying confidence are marked observed / inferred; inferred negative/suspect conclusions are noted as inference only, re-checkable — don't write them as verdicts.
4. Carry ids: mark source node ids after each conclusion (e.g. "… (#12,#28)") so the planner can restore the original nodes by id.
5. Positive statements only, write only what the input has: no imagination, no judgments absent from the input.
6. Length adapts to content: few conclusions → short; many distinct ones → write enough — but overall markedly shorter than the sum of all input summaries.
7. Keep terminal-state semantics: for intent members, keep their state and wrap-up meaning — exhausted is either 'techniques exhausted, direction has no increment' or 'cut off by step/time budget, unfinished but not a dead end' (copy the stop_reason verbatim when present); blocked is marked as an external failure. The planner uses it to judge 'can this direction be continued' — compressing this bit away = continuation decisions lose their basis.

Output only the body text itself.`
