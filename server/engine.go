package server

import (
	"context"
	"path/filepath"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/intercept"
	"github.com/jackc/pgx/v5/pgconn"
)

// isFKViolation reports whether err is a Postgres foreign-key violation (SQLSTATE
// 23503) — e.g. an activity insert whose exploration_id has no parent row.
func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// dropReason classifies why an activity write was dropped, so the log can be
// grouped/analysed by cause rather than by raw error text.
func dropReason(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return "fk_violation(23503, parent exploration does not exist)"
		case "23505":
			return "unique_violation(23505)"
		default:
			return "pg_error(" + pgErr.Code + ")"
		}
	}
	return "write_error"
}

// bumpDrop increments and returns the running count of dropped (unpersistable)
// activity records for a task. Concurrent planner + worker emits race here, so the
// counter is an atomic behind sync.Map. The count in the log shows loss scale at a
// glance instead of forcing a grep-and-count.
func (e *Engine) bumpDrop(taskID string) int64 {
	v, _ := e.dropCnt.LoadOrStore(taskID, new(int64))
	return atomic.AddInt64(v.(*int64), 1)
}

// preview collapses newlines and trims s to a short rune-safe snippet for one-line
// log output (avoids dumping a multi-KB summary/detail into the log).
func preview(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// model_error (provider/API failure: LLM-layer instant retries exhausted, or the stream broke mid-way)
// isn't 'tried but unfinished' nor real failure — it's external turbulence. Marking it permanently
// blocked wastes an intent, so this terminal state gets a few extra reruns with backoff in between,
// giving the provider time to recover; during retries, pause/stop/cancel yields to those branches.
const (
	modelErrorRetries      = 2               // extra reruns after a model_error wrap-up
	modelErrorRetryBackoff = 3 * time.Second // backoff before each retry
	workControlWaitTimeout = 30 * time.Second
)

var errWorkControlConflict = errors.New("work control conflict")

// retryableWorkerModelError excludes errors already handled by the task router.
// In particular, a quota error after partial streaming advances the task cursor
// for the next LLM call but must not replay this whole intent on the backup.
func retryableWorkerModelError(reason harness.TerminalReason, err error) bool {
	return reason == harness.ReasonModelError && !isTaskLLMRuntimeError(err)
}

// isTransientContextCanceled: the worker run wrapped up with err carrying context canceled while the
// task-level ctx is still alive — the cancel happened inside the run (provider stream/inner sub-ctx),
// not a user pause or planner kill. Task 5 measured 6 intents ending as blocked(error: context canceled)
// all this way. Same treatment as model_error: backoff-rerun inside runIntent's retry loop; only after
// retries exhaust does it land blocked — an internal cancel no longer wastes the whole intent.
func isTransientContextCanceled(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled")
}

// Engine drives the event-driven exploration loop with real LLM agents
// (docs §4.3/§4.4): on asset/exploration-graph change (debounced) it wakes the
// planner, which reads the route, queries assets, judges goals and emits intents;
// N concurrent work agents claim intents and execute them. There is no
// simulation mode — an LLM provider is required. The planner/worker can be
// (re)installed at runtime (LLM configured from the UI); the loops always run
// but idle until an LLM is set.
type Engine struct {
	m        *Manager
	debounce time.Duration

	bc *Broadcaster // live activity pub/sub (SSE)

	started  sync.Map // taskID -> bool, so Run is idempotent per task
	lastAct  sync.Map // taskID -> int64 unix, last planner/worker activity (heartbeat)
	llmCalls sync.Map // taskID -> *int64, actual planner/worker/main-agent LLM calls
	paused   sync.Map // taskID -> bool, user-paused (planner + workers idle but loops alive)
	deleting sync.Map // taskID -> bool, delete barrier (no new task-owned writes)
	dropCnt  sync.Map // taskID -> *int64, running count of dropped (unpersistable) activity records
	// autoTrack: taskID -> *autopilotTrack — the autopilot watchdog's in-memory state.
	autoTrack sync.Map

	// deleteMu makes installing the delete barrier atomic with registering a new
	// task operation. Once BeginDelete returns, every admitted writer is reflected
	// in inflight and every later writer is rejected.
	deleteMu sync.RWMutex

	// Every long-lived task goroutine (planner, workers and deadline coordinator)
	// runs under one task-scoped context. Successful deletion cancels that context,
	// waits for all goroutines, then releases every task-level Engine reference.
	runtimeMu sync.Mutex
	runtimes  map[string]*taskRuntime

	// per-task execution context: each planner.Plan / worker.Execute runs under it,
	// so pausing can CANCEL an in-flight run (not just skip the next one). Recreated
	// on resume since cancelling is one-shot. Every cancellation carries a named
	// cause so the activity trace can identify the initiating control path.
	execMu     sync.Mutex
	execCancel map[string]context.CancelCauseFunc
	execCtx    map[string]context.Context

	// Per-work control lets the planner kill a worker and lets the UI pause/cancel
	// one intent without pausing the whole task. The done channel closes only after
	// runWorkerStep has stopped writing and committed its final state.
	workMu sync.Mutex
	work   map[int64]*workExecution

	// steerBox queues planner course-corrections for a running work (keyed by intent
	// id). The worker's PreToolUse hook drains it before its next tool call and hands
	// the message to the model (blocking that call) so it re-plans — no kill needed.
	steerMu  sync.Mutex
	steerBox map[int64][]string

	plannerRound sync.Map // taskID -> int, planner round counter (for UI round separators)

	// Task-level timeout (see docs/task-timeout-design doc):
	settling     sync.Map // taskID -> bool: task entered wrap-up sequence (stop dispatching/claiming new intents)
	deadline     sync.Map // taskID -> int64 unix: absolute deadline (stamped on first run; 0/unset = unlimited)
	stamped      sync.Map // taskID -> bool: whether first_run_at was stamped (once per process)
	inflight     sync.Map // taskID -> *int64: in-flight planner.Plan + worker.Execute count (for drain)
	coordStarted sync.Map // taskID -> bool: whether the deadline coordinator started (dedup across Run/reload)

	// resolve returns a task's dedicated planner/worker (wired by the server as the
	// authoritative task-router). nil,nil means this task is deliberately unavailable
	// (for example an exhausted failover chain) — there is no global-pair fallback.
	resolve              func(t *Task) (*agent.Planner, *agent.Worker)
	resolveAuthoritative bool
	// readiness reports whether a global LLM provider is configured — the signal behind
	// Ready()/the llm_configured indicator. Wired once at startup; nil → not ready.
	readiness func() bool
}

type taskRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type workExecution struct {
	cancel context.CancelCauseFunc
	done   chan error
	action string // user action: pause | cancel
}

// nextPlannerRound returns the next planner round number for a task (1-based).
func (e *Engine) nextPlannerRound(taskID string) int {
	v, _ := e.plannerRound.LoadOrStore(taskID, 0)
	n := v.(int) + 1
	e.plannerRound.Store(taskID, n)
	return n
}

// Pause stops a task: marks it paused AND cancels any in-flight planner/worker run
// for it (a long worker.Execute would otherwise keep going until it finishes).
func (e *Engine) Pause(taskID string, cause error) {
	e.paused.Store(taskID, true)
	e.cancelExec(taskID, cause)
}

// BeginDelete installs an execution barrier before task data/files are removed.
// The temporary pause is not a user pause. The server serializes this transition
// with lifecycle admission and tells AbortDelete whether the persisted task is
// paused/queued if cleanup fails.
func (e *Engine) BeginDelete(taskID string) bool {
	e.deleteMu.Lock()
	if _, loaded := e.deleting.LoadOrStore(taskID, true); loaded {
		e.deleteMu.Unlock()
		return false
	}
	e.paused.Store(taskID, true)
	e.deleteMu.Unlock()
	e.cancelExec(taskID, agent.AbortTaskDeleted)
	return true
}

func (e *Engine) AbortDelete(taskID string, keepPaused bool) {
	e.deleteMu.Lock()
	if !e.IsDeleting(taskID) {
		e.deleteMu.Unlock()
		return
	}
	e.deleting.Delete(taskID)
	if !keepPaused {
		e.paused.Delete(taskID)
	}
	e.deleteMu.Unlock()
	if !keepPaused && e.m != nil {
		if t, ok := e.m.Task(taskID); ok {
			t.Notify()
		}
	}
}

func (e *Engine) IsDeleting(taskID string) bool {
	_, ok := e.deleting.Load(taskID)
	return ok
}

// registerTaskRoutines reserves count goroutines in the task runtime. Callers
// hold deleteMu for reading so StopTask cannot race WaitGroup.Add with Wait.
func (e *Engine) registerTaskRoutines(parent context.Context, taskID string, count int) *taskRuntime {
	e.runtimeMu.Lock()
	defer e.runtimeMu.Unlock()
	rt := e.runtimes[taskID]
	if rt == nil {
		ctx, cancel := context.WithCancel(parent)
		rt = &taskRuntime{ctx: ctx, cancel: cancel}
		e.runtimes[taskID] = rt
	}
	rt.wg.Add(count)
	return rt
}

func runTaskRoutine(rt *taskRuntime, fn func(context.Context)) {
	go func() {
		defer rt.wg.Done()
		fn(rt.ctx)
	}()
}

// StopTask permanently stops every long-lived goroutine and removes all Engine
// state for a successfully deleted task. The delete barrier remains installed
// until cleanup finishes, so no new task operation can race the teardown.
func (e *Engine) StopTask(taskID string) {
	// Jobs shouldn't keep hitting the target after delete/stop (job processes outlive runs — kill explicitly).
	if e.m != nil {
		if n := agent.KillJobsForTaskDir(filepath.Join(e.m.dir, "tasks", taskID)); n > 0 {
			log.Printf("[engine] task %s cleaned up %d background jobs on stop", taskID, n)
		}
	}
	e.deleteMu.Lock()
	e.deleting.Store(taskID, true)
	e.deleteMu.Unlock()

	e.cancelExec(taskID, agent.AbortTaskDeleted)
	e.runtimeMu.Lock()
	rt := e.runtimes[taskID]
	if rt != nil {
		rt.cancel()
	}
	e.runtimeMu.Unlock()
	if rt != nil {
		rt.wg.Wait()
	}

	e.execMu.Lock()
	if cancel := e.execCancel[taskID]; cancel != nil {
		cancel(agent.AbortTaskDeleted)
	}
	delete(e.execCancel, taskID)
	delete(e.execCtx, taskID)
	e.execMu.Unlock()

	e.runtimeMu.Lock()
	if e.runtimes[taskID] == rt {
		delete(e.runtimes, taskID)
	}
	e.runtimeMu.Unlock()

	e.started.Delete(taskID)
	e.lastAct.Delete(taskID)
	e.llmCalls.Delete(taskID)
	e.paused.Delete(taskID)
	e.dropCnt.Delete(taskID)
	e.plannerRound.Delete(taskID)
	e.settling.Delete(taskID)
	e.deadline.Delete(taskID)
	e.stamped.Delete(taskID)
	e.inflight.Delete(taskID)
	e.coordStarted.Delete(taskID)
	e.deleteMu.Lock()
	e.deleting.Delete(taskID)
	e.deleteMu.Unlock()
}

// cancelExec cancels a task's current per-task exec context (any in-flight
// planner.Plan / worker.Execute), if present. Shared by Pause and the settle
// sequence's hard-drain backstop.
func (e *Engine) cancelExec(taskID string, cause error) {
	e.execMu.Lock()
	if cancel := e.execCancel[taskID]; cancel != nil {
		cancel(cause)
	}
	e.execMu.Unlock()
}

// Resume un-pauses a task and nudges a fresh planning round. The next exec under
// it gets a fresh (uncancelled) context.
func (e *Engine) Resume(t *Task) {
	// BeginDelete owns the pause barrier once deletion starts. A concurrent
	// resume must never clear it and let a planner/worker re-enter while cleanup
	// is waiting for task operations to drain.
	if t == nil {
		return
	}
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(t.ID) {
		return
	}
	e.paused.Delete(t.ID)
	t.Notify()
}

// execContextFor returns a live per-task context derived from parent, recreating
// it if a prior pause cancelled it.
func (e *Engine) execContextFor(parent context.Context, taskID string) context.Context {
	e.execMu.Lock()
	defer e.execMu.Unlock()
	if e.IsPaused(taskID) {
		// never hand out a live context while paused (guards the claim→Execute race)
		c, cancel := context.WithCancelCause(parent)
		cancel(agent.AbortPausedRaceGuard)
		return c
	}
	if c := e.execCtx[taskID]; c != nil && c.Err() == nil {
		return c
	}
	c, cancel := context.WithCancelCause(parent)
	e.execCtx[taskID] = c
	e.execCancel[taskID] = cancel
	return c
}

// IsPaused reports whether a task is user-paused.
func (e *Engine) IsPaused(taskID string) bool {
	v, ok := e.paused.Load(taskID)
	return ok && v.(bool)
}

// Started reports whether the engine loops are running for a task.
func (e *Engine) Started(taskID string) bool {
	_, ok := e.started.Load(taskID)
	return ok
}

// LastActivity returns the unix time of the last planner/worker activity for a
// task (0 if none yet).
func (e *Engine) LastActivity(taskID string) int64 {
	if v, ok := e.lastAct.Load(taskID); ok {
		return v.(int64)
	}
	return 0
}

// BeginLLMCall/EndLLMCall track actual provider calls separately from the
// scheduler's task-operation counter. A task can have live loops while all of
// them are waiting for a trigger; that state must remain idle in the UI.
func (e *Engine) BeginLLMCall(taskID string) {
	v, _ := e.llmCalls.LoadOrStore(taskID, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

func (e *Engine) EndLLMCall(taskID string) {
	if v, ok := e.llmCalls.Load(taskID); ok {
		p := v.(*int64)
		if atomic.AddInt64(p, -1) <= 0 {
			atomic.StoreInt64(p, 0)
		}
	}
}

func (e *Engine) ActiveLLMCalls(taskID string) int64 {
	if v, ok := e.llmCalls.Load(taskID); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}

func (e *Engine) touch(taskID string) { e.lastAct.Store(taskID, time.Now().Unix()) }

// autoAttributeCompany auto-attributes a company on the task's first run (v0.4.40).
// Data background: companies and assets.company_id both hold attribution, but task company scopes were all
// empty — tasks were 'ownerless' on the company axis, ungroupable/unreportable.
// Rule (conservative): 100% of in-scope assets belong to one company AND that company's total assets ≤
// 3×scope+20 (company ≈ this customer) → auto-write company scope + snapshot assets; otherwise only suggest in the activity stream.
func (e *Engine) autoAttributeCompany(t *Task) {
	if e.m == nil || e.m.pg == nil {
		return
	}
	tid, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || tid <= 0 {
		return
	}
	has, err := e.m.pg.HasCompanyScope(tid)
	if err != nil || has {
		return
	}
	dist, total, err := e.m.pg.ScopeCompanyDistribution(tid)
	if err != nil || total == 0 {
		return
	}
	var cid int64
	others := 0
	for id, n := range dist {
		if id <= 0 || n == 0 {
			continue
		}
		if cid == 0 {
			cid = id
		} else if id != cid {
			others++
		}
	}
	if cid == 0 {
		return
	}
	if others == 0 {
		compTotal, err := e.m.pg.CompanyScopeAssetCount(cid)
		if err != nil {
			return
		}
		if compTotal <= 3*total+20 {
			reason := fmt.Sprintf("auto-attribution: all %d in-scope assets belong to this company (company has %d assets — snapshotted into scope; undo in task scope settings)", total, compTotal)
			if err := e.m.pg.AddCompanyScopeAuto(tid, cid, reason); err == nil {
				log.Printf("[task %s] auto-attributed company #%d (scope assets %d, company assets %d)", t.ID, cid, total, compTotal)
				e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
					Summary: fmt.Sprintf("task auto-attributed to company #%d: all %d in-scope assets belong to it and its existing %d assets joined the test scope; adjust in task scope settings if needed.", cid, total, compTotal)})
				return
			}
		}
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("attribution suggestion: all %d in-scope assets belong to company #%d, but that company has %d assets total (well beyond this scope) — attach the company manually in task scope settings to test them too.", total, cid, compTotal)})
		return
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("attribution note: in-scope assets span multiple companies (primary #%d). Attach companies in task scope settings to organize by company.", cid)})
}

func NewEngine(m *Manager) *Engine {
	return &Engine{m: m, debounce: 800 * time.Millisecond, bc: NewBroadcaster(),
		execCancel: map[string]context.CancelCauseFunc{}, execCtx: map[string]context.Context{},
		work: map[int64]*workExecution{}, steerBox: map[int64][]string{},
		runtimes: map[string]*taskRuntime{}}
}

// registerWork records the cancel for the work currently running intentID.
func (e *Engine) registerWork(intentID int64, cancel context.CancelCauseFunc) {
	e.workMu.Lock()
	e.work[intentID] = &workExecution{cancel: cancel, done: make(chan error, 1)}
	e.workMu.Unlock()
}

// detachWork removes the live control handle once Execute has returned. complete
// must be called after the final intent state write so a waiting cancel handler can
// safely delete the worker's blackboard output without racing a late write.
func (e *Engine) detachWork(intentID int64) (action string, complete func(error)) {
	e.workMu.Lock()
	run := e.work[intentID]
	if run != nil {
		delete(e.work, intentID)
		action = run.action
		run.cancel(agent.AbortWorkFinished) // release resources (no-op if already cancelled)
	}
	e.workMu.Unlock()
	e.steerMu.Lock()
	delete(e.steerBox, intentID) // drop any undelivered steering for a finished work
	e.steerMu.Unlock()
	if run == nil {
		return action, func(error) {}
	}
	return action, func(err error) { run.done <- err }
}

// ControlWork requests a user-visible pause or cancellation and waits until the
// worker has fully stopped writing. Cancellation cleanup is performed by the API
// handler after this returns; pause state is committed by runWorkerStep itself.
func (e *Engine) ControlWork(ctx context.Context, intentID int64, action string) error {
	if action != "pause" && action != "cancel" {
		return fmt.Errorf("unsupported work action %q", action)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.workMu.Lock()
	run := e.work[intentID]
	if run == nil {
		e.workMu.Unlock()
		return fmt.Errorf("%w: intent %d has no running work right now (finished or unclaimed)", errWorkControlConflict, intentID)
	}
	if run.action != "" {
		e.workMu.Unlock()
		return fmt.Errorf("%w: intent %d is executing a %s operation", errWorkControlConflict, intentID, run.action)
	}
	run.action = action
	done := run.done
	cause := error(agent.AbortWorkPausedByUser)
	if action == "cancel" {
		cause = agent.AbortWorkCancelledByUser
	}
	run.cancel(cause)
	e.workMu.Unlock()

	timer := time.NewTimer(workControlWaitTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		e.releaseWorkControl(intentID, run, action)
		return fmt.Errorf("waiting for intent %d's %s wrap-up: %w", intentID, action, ctx.Err())
	case <-timer.C:
		e.releaseWorkControl(intentID, run, action)
		return fmt.Errorf("waiting for intent %d's %s wrap-up: %w", intentID, action, context.DeadlineExceeded)
	}
}

// releaseWorkControl drops only this caller's reservation after its wait is
// cancelled. The work context stays cancelled; runWorkerStep recognizes the
// named cancellation cause and settles the intent into the recoverable paused
// state even if the HTTP caller has gone away.
func (e *Engine) releaseWorkControl(intentID int64, run *workExecution, action string) {
	e.workMu.Lock()
	if current := e.work[intentID]; current == run && current.action == action {
		current.action = ""
	}
	e.workMu.Unlock()
}

// truncateStopReason keeps the stored reason short and single-line so the UI can
// show it in a tooltip without a wall of text.
func truncateStopReason(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// transitionIntentState atomically moves an intent from expected to state.
// A transient PG error can't orphan a terminal-state write: a stuck running row blocks task wrap-up forever
// (HasActiveIntent stays true, UI pause/delete 409s, planner can't retire). Retry 3 times — covers failover/
// connection resets/serialization conflicts; real state conflicts aren't retried.
func transitionIntentState(store *db.ExplorationStore, intentID int64, expected, state string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		changed, err := store.CompareAndSetIntentState(intentID, expected, state)
		if err == nil {
			if changed {
				return nil
			}
			return fmt.Errorf("%w: intent %d is no longer in %s state", db.ErrIntentStateConflict, intentID, expected)
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return lastErr
}

// retryIntentTerminalAsync backstops terminal-state write failures: auto-rewrite after a short DB fault —
// keeps intents from parking at running forever (HasActiveIntent stays true, task can't wrap up, UI 409s).
func (e *Engine) retryIntentTerminalAsync(store *db.ExplorationStore, intentID int64, state, stopReason string) {
	go func() {
		for attempt := 0; attempt < 12; attempt++ {
			time.Sleep(5 * time.Second)
			err := transitionIntentState(store, intentID, "running", state)
			if err == nil {
				if stopReason != "" {
					_ = store.SetIntentStopReason(intentID, stopReason)
				}
				log.Printf("[worker] intent #%d terminal state %s backfilled in background", intentID, state)
				return
			}
			if errors.Is(err, db.ErrIntentStateConflict) {
				return // another path already changed the state — don't overwrite
			}
		}
		log.Printf("[worker] intent #%d terminal state %s backfill failed (12 retries)", intentID, state)
	}()
}

// canceledByGoalMet says whether a cancel came from the planner's goal_met wrap-up.
func canceledByGoalMet(ctx context.Context) bool {
	if ctx == nil || ctx.Err() == nil {
		return false
	}
	var abort *agent.AbortCause
	return errors.As(context.Cause(ctx), &abort) && abort.Code == "goal_met"
}

func addWriteCounts(dst, src agent.WriteCounts) agent.WriteCounts {
	dst.Facts += src.Facts
	dst.Assets += src.Assets
	dst.Findings += src.Findings
	return dst
}

// SteerWork queues a mid-run course-correction for the work running intentID (the
// planner's steer_work tool). The worker delivers it before its next tool call and
// re-plans — no kill. Errors if no work is currently running that intent.
func (e *Engine) SteerWork(intentID int64, msg string) error {
	if strings.TrimSpace(msg) == "" {
		return fmt.Errorf("steering message must not be empty")
	}
	e.workMu.Lock()
	running := e.work[intentID] != nil
	e.workMu.Unlock()
	if !running {
		return fmt.Errorf("intent %d has no running work right now (finished or unclaimed)", intentID)
	}
	e.steerMu.Lock()
	e.steerBox[intentID] = append(e.steerBox[intentID], msg)
	e.steerMu.Unlock()
	return nil
}

// drainSteer pops the oldest queued steering message for intentID (FIFO), if any.
func (e *Engine) drainSteer(intentID int64) (string, bool) {
	e.steerMu.Lock()
	defer e.steerMu.Unlock()
	q := e.steerBox[intentID]
	if len(q) == 0 {
		return "", false
	}
	msg := q[0]
	if len(q) == 1 {
		delete(e.steerBox, intentID)
	} else {
		e.steerBox[intentID] = q[1:]
	}
	return msg, true
}

// steerHooks wraps the guard's hook runner so the planner can steer a running work:
// before each tool call it drains a queued course-correction (if any) and blocks the
// call, handing the message back to the model — which re-plans its next step instead
// of running the tool. No queued message → the guard behaves exactly as before.
// It handles both 'idle-turn' continuation (Stop) and 'repeat-call' interception (PreToolUse, v0.4.28).
type steerHooks struct {
	inner harness.HookRunner
	drain func() (string, bool)
	// nudges counts this intent's injected idle-turn continuations, capped at limit. Pointer: harness holds
	// a value copy of steerHooks — the counter must share one backing store.
	nudges *atomic.Int64
	// limit caps idle-turn continuations, resolved by Engine.emptyTurnNudgeLimit() from 'empty-response
	// retries'. <=0 = don't intervene (user explicitly disabled this layer).
	limit int
	// label like "worker-1 · #42" — logs only.
	label string
	// repeats is the duplicate-call detector (v0.4.28, PentAGI mechanism re-implemented): same tool + byte-
	// identical input ≥3 consecutive times → intercept and feed a correction; each streak is blocked at most
	// twice then let through. nil = don't intervene.
	repeats *repeatTracker
}

// Default idle-turn (thinking only — no body, no tool calls) continuation count, matching the SDK
// empty-response retry's built-in default (norma/llm/openai.go's emptyResponseRetries) — two layers share
// one knob; unconfigured behavior should align. Resolution: Engine.emptyTurnNudgeLimit.
//
// Note this number is 'per-intent total', not 'consecutive count': harness's own stopHookActive already
// limits consecutive idle turns to one push — if still idle after that pushed round, the Stop hook isn't
// called again and the run wraps; only a real tool round refreshes the quota (norma/harness/query.go:534).
// So this gate stops the 'tool → idle → push → tool → idle' pathological loop from burning the intent budget.
const defaultEmptyTurnNudges = 2

// emptyTurnNudge is the continuation instruction injected on an idle turn.
//
// To the harness such a turn is a natural end (stop_reason=end_turn, no tool_use) — none of the five LLM
// retry layers apply: it's not an error, it's 'the model thought but didn't act'. The SDK's empty-response
// retry can't reach it either: it judges emptiness by 'any event yielded', and thinking deltas are events
// (norma/llm/openai.go's SEThinkingDelta), so thinking-only isn't empty. That layer would also resend the
// whole prompt verbatim — for context-shape-caused idling that just makes the model re-think. Here we append
// an instruction instead, so it continues with the thinking it already produced — different input, different behavior.
const emptyTurnNudge = "[Idle-turn notice] your last round emitted only thinking — no body text and no tool call — " +
	"so it produced nothing. Go straight to the next step you just planned: call a tool or write the conclusion. Don't re-think."

// isThinkingOnlyTurn reports whether the latest assistant turn produced neither
// text nor a tool call — i.e. the model spent the whole round thinking.
func isThinkingOnlyTurn(messages []llm.Message) bool {
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		return strings.TrimSpace(m.Text()) == "" && len(m.ToolUses()) == 0
	}
	return false
}

func (h steerHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	// Duplicate-call detection (v0.4.28): interception priority below steer corrections — queued human/planner
	// instructions speak first, then repeats get checked.
	if h.repeats != nil {
		if streak, block := h.repeats.observe(name, input); block {
			log.Printf("[work %s] repeat-call interception: %s hit %d identical-input calls in a row", h.label, name, streak)
			return true, repeatBlockText(streak), nil
		}
	}
	if msg, ok := h.drain(); ok {
		return true, "[Planner live-steer] " + msg +
			"\n(This is the planner's real-time instruction to this intent; the tool call did NOT execute — adjust your next step accordingly. If it conflicts with what you planned, this wins.)", nil
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h steerHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

// Stop adds an 'idle-turn' continuation layer on top of guard's semantics: when the model emitted only
// thinking (no body, no tools), harness treats it as a natural end and wraps with an empty summary (query.go's
// ReasonCompleted + asst.Text()) — an unfinished intent dies mid-way. Inject a continuation instead so the
// model continues with the thinking it already has.
func (h steerHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	var (
		prevent  bool
		blocking []string
		msg      string
	)
	if h.inner != nil {
		prevent, blocking, msg = h.inner.Stop(ctx, messages)
	}
	// inner already decided a hard stop, or wants to inject its own continuation → respect it, don't stack.
	// limit<=0 = user set 'empty-response retries' to -1 — explicitly disabled this layer.
	if prevent || len(blocking) > 0 || h.nudges == nil || h.limit <= 0 || !isThinkingOnlyTurn(messages) {
		return prevent, blocking, msg
	}
	n := h.nudges.Add(1)
	if n > int64(h.limit) {
		log.Printf("[work %s] idle turns (thinking only, no body/tools) hit continuation cap %d — letting it wrap", h.label, h.limit)
		return prevent, blocking, msg
	}
	log.Printf("[work %s] idle turn (thinking only, no body/tools) — injecting continuation (%d/%d)", h.label, n, h.limit)
	return false, []string{emptyTurnNudge}, ""
}

// KillWork cancels the in-flight work running intentID (planner's kill_work tool).
// The work's agent-core session honors ctx cancellation and aborts promptly.
func (e *Engine) KillWork(intentID int64) error {
	e.workMu.Lock()
	run := e.work[intentID]
	e.workMu.Unlock()
	if run == nil {
		return fmt.Errorf("intent %d has no running work right now (finished or unclaimed)", intentID)
	}
	run.cancel(agent.AbortKilledByPlanner)
	return nil
}

// Broadcaster exposes the engine's live activity pub/sub (used by the SSE handler).
func (e *Engine) Broadcaster() *Broadcaster { return e.bc }

// emitActivity persists one captured step AND fans it out to live subscribers,
// from a single point so storage and the SSE stream never diverge.
func (e *Engine) emitActivity(t *Task, r db.Activity) db.Activity {
	id, err := e.appendActivity(t, r)
	if err != nil {
		// NO LONGER SILENT: dropping a record breaks command↔result pairing in the
		// trace — a tool_use whose tool_result was lost shows as 'executing' forever, and
		// a lost 'result'/'round' record leaves the session with no summary ('no summary').
		// Everything needed to analyze the root cause goes into ONE error-level line: reason class,
		// summary preview, running drop count for this task, and — on the FK case — a
		// live probe of WHY the parent exploration is unreachable.
		n := e.bumpDrop(t.ID)
		diag := ""
		// On the FK-parent failure (23503) probe the live DB so the log records WHY the
		// exploration is unreachable (row gone / wrong expID) instead of just that it is.
		if isFKViolation(err) {
			storeID := t.Store.ID()
			if exists, refs, maxID, dErr := e.m.pg.ExplorationDiag(storeID); dErr != nil {
				diag = fmt.Sprintf(" | FK diag query failed (store.expID=%d task.ExpID=%d): %v", storeID, t.ExpID, dErr)
			} else {
				diag = fmt.Sprintf(" | FK diag: store.expID=%d task.ExpID=%d exploration_exists=%v referencing_tasks=%d MAX(exploration.id)=%d",
					storeID, t.ExpID, exists, refs, maxID)
			}
		}
		log.Printf("[activity] task %s dropping activity record (task's %d-th so far) worker=%s kind=%s tool=%s tuid=%s reason=%s summary=%q: %v%s",
			t.ID, n, r.Worker, r.Kind, r.Tool, r.ToolUseID, dropReason(err), preview(r.Summary, 80), err, diag)
		e.touch(t.ID)
		return r
	}
	r.ID = id
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	e.bc.Publish(t.ID, r)
	e.touch(t.ID)
	return r
}

// appendActivity persists one activity row, retrying briefly on write failure.
// Concurrent planner + worker inserts into the same exploration's activity log
// occasionally fail; a couple of quick retries recover most. Crucially, every
// failure is now LOGGED (it used to be swallowed by an `if err == nil`), so the
// underlying DB error is finally visible for diagnosis.
func (e *Engine) appendActivity(t *Task, r db.Activity) (int64, error) {
	var id int64
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if id, err = t.Store.AppendActivity(r); err == nil {
			if attempt > 1 {
				log.Printf("[activity] task %s write succeeded on retry %d (worker=%s kind=%s tool=%s)",
					t.ID, attempt, r.Worker, r.Kind, r.Tool)
			}
			return id, nil
		}
		log.Printf("[activity] task %s write failed (attempt %d/3, worker=%s kind=%s tool=%s expID=%d): %v",
			t.ID, attempt, r.Worker, r.Kind, r.Tool, t.Store.ID(), err)
		time.Sleep(time.Duration(attempt) * 25 * time.Millisecond)
	}
	return 0, err
}

// SetReadiness wires the global "an LLM provider is configured" predicate (read by
// Ready() / the llm_configured indicator). Called once at startup.
func (e *Engine) SetReadiness(fn func() bool) { e.readiness = fn }

// SetAgentResolver installs a per-task planner/worker resolver (wired by the server).
// Called once at startup before any task loop runs, so no lock is needed on reads.
func (e *Engine) SetAgentResolver(fn func(t *Task) (*agent.Planner, *agent.Worker)) {
	e.resolve = fn
	e.resolveAuthoritative = false
}

// SetAuthoritativeAgentResolver installs a resolver whose nil result must not
// fall through to the global provider. Task-level failover chains use this so a
// fully exhausted chain cannot silently bypass its configured boundary.
func (e *Engine) SetAuthoritativeAgentResolver(fn func(t *Task) (*agent.Planner, *agent.Worker)) {
	e.resolve = fn
	e.resolveAuthoritative = true
}

// snapshotFor returns the planner/worker a task should run on, from the task-router
// resolver. nil,nil means the task is deliberately unavailable (e.g. an exhausted
// failover chain); there is no global-pair fallback.
func (e *Engine) snapshotFor(t *Task) (*agent.Planner, *agent.Worker) {
	if e.resolve != nil {
		p, w := e.resolve(t)
		if (p != nil && w != nil) || e.resolveAuthoritative {
			return p, w
		}
	}
	return nil, nil
}

// Ready reports whether a global LLM provider is configured (via the readiness
// predicate wired at startup).
func (e *Engine) Ready() bool {
	return e.readiness != nil && e.readiness()
}

// ReadyFor reports whether a specific task can resolve a planner/worker pair.
// An explicit task profile chain can be runnable even when no global default
// provider is configured, so task status must not rely on Ready alone.
func (e *Engine) ReadyFor(t *Task) bool {
	p, w := e.snapshotFor(t)
	return p != nil && w != nil
}

// Run starts the planner loop + N worker loops for a task. The loops always run
// but no-op until an LLM is configured (so a task created while idle picks up
// automatically once LLM is set from the UI).
func (e *Engine) Run(ctx context.Context, t *Task) {
	workers := e.m.Workers()
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.started.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		t.Notify() // already running — just nudge a planning round
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1+workers)
	e.deleteMu.RUnlock()
	// created→running: the status column must match reality once the task truly starts running (bootstrap
	// admission used to not write running — live tasks ran for hours while DB said created). Only write on
	// paused/done states.
	if t.Status == "created" {
		if err := e.m.SetTaskStatus(t.ID, "running"); err == nil {
			t.Status = "running"
		}
		// Task company attribution (v0.4.40): when 100% of in-scope assets belong to one company of similar
		// size, auto-write company scope + snapshot assets; otherwise only suggest in the activity stream.
		e.autoAttributeCompany(t)
		// Narrow-scope kick-off note (v0.4.57 retro): warns the operator when in-scope assets <10.
		e.warnNarrowScope(t)
	}
	// Autopilot watchdog: one per process, exits with the engine ctx (scans every 60s).
	startAutopilotLoopOnce.Do(func() {
		go e.startAutopilotLoop(ctx)
	})
	e.touch(t.ID)
	runTaskRoutine(rt, func(loopCtx context.Context) { e.plannerLoop(loopCtx, t) })
	for i := 0; i < workers; i++ {
		name := fmt.Sprintf("work#%d", i+1)
		runTaskRoutine(rt, func(loopCtx context.Context) { e.workerLoop(loopCtx, t, name) })
	}
	e.startDeadlineCoordinator(ctx, t) // task-level timeout timer (timeout>0 only; deduped)
	// Kick round one ONLY when there's literally no active intent (open+running). Seeded tasks: the seed is
	// already open, or a just-started worker claimed it running — both count as 'has work', so skip the first
	// planner round; the worker claims the seed directly and NotifyDone/heartbeat wakes the planner later.
	// ⚠️ Can't use Frontier (open-only): the worker's claim (open→running) races this check → false kicks.
	// On restart-recovery only running intents may remain — skip there too.
	if has, _ := t.Store.HasActiveIntent(); !has {
		t.Notify() // kick the first planning round (acted on once LLM is ready)
	}
}

// startAutopilotLoopOnce guarantees a single watchdog goroutine per process (starts on first task Run).
var startAutopilotLoopOnce sync.Once

// plannerRoundTimeout is a **single plan round**'s own wall-clock cap (unrelated to the task deadline).
//
// Why it's required (measured incident 2026-10-20 production):
//
//	planner's MaxDuration = clampMaxDuration(deadline, 0) — without a task deadline it's 0 = unlimited;
//	the SDK's MaxDuration only checks at turn boundaries and only constrains **tool execution** (LLM
//	calls use the deadline-free l.ctx). One upstream half-open connection (connected, never returns)
//	makes Plan() never return.
//
//	And runRound is **serial**: until it returns, every later wake (edge + 10-min heartbeat) is stuck
//	behind it → planner permanently silent.
//
//	Measured symptom: after a 14:30 start, the planner emitted no rounds past 14:42 (task 3) / 15:45
//	(task 4); workers drained remaining intents (last exhausted 16:53); then 6 hours of zero plan
//	rounds and zero new intents — 'Running Workers' stuck at 0, task still 'running' yet idle.
//	Restarting the service recovered instantly.
//
//	Why 15 minutes: a measured round (1M context + dozens of tool calls) is 3–5 min — 15 min is 3×
//	headroom AND bounds 'upstream hung' waste at 15 min before self-healing. No more indefinite silence.
const plannerRoundTimeout = 15 * time.Minute

// plannerRoundTimeoutOverride lets tests verify 'a stuck plan round doesn't kill the planner loop' with
// second-level caps. Production never sets it (keeps plannerRoundTimeout).
var plannerRoundTimeoutOverride time.Duration

// plannerRoundLimit returns this round's effective wall-clock cap.
func plannerRoundLimit() time.Duration {
	if plannerRoundTimeoutOverride > 0 {
		return plannerRoundTimeoutOverride
	}
	return plannerRoundTimeout
}

// plannerRoundOutcome is one plan round's result.
type plannerRoundOutcome struct {
	met    bool
	reason string
	err    error
}

// runPlannerRound runs a plan round on its own goroutine and **abandons the round** on ctx end rather
// than waiting for it.
//
// Why not just call Plan: Plan can hang **anywhere** that ignores ctx — worst case a deadlock (a
// deadlocked goroutine never returns; ctx cancel can't touch it). And the planner's runRound is serial:
// while it doesn't return, every later wake (edge + heartbeat) queues behind — the planner goes silent
// forever: service alive, task 'running', no logs.
//
// Measured (2026-10-21): the planner was silent for 1h05m; the goroutine dump showed it stuck on a
// self-deadlock in agent/compaction.go. The 15-minute wall-clock cap on plan rounds was **useless**
// against it (ctx cancel can't reach a deadlock).
//
// Abandoning a round costs one leaked goroutine (Go can't kill goroutines). Versus 'planner permanently
// silent', a leaked goroutine is a far smaller price.
func runPlannerRound(ctx context.Context, plan func(context.Context) (bool, string, error)) plannerRoundOutcome {
	type result struct {
		met    bool
		reason string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		met, reason, err := plan(ctx)
		done <- result{met: met, reason: reason, err: err}
	}()
	select {
	case r := <-done:
		return plannerRoundOutcome{met: r.met, reason: r.reason, err: r.err}
	case <-ctx.Done():
		return plannerRoundOutcome{err: ctx.Err()}
	}
}

// plannerHeartbeatInterval resolves the task's planner heartbeat interval. db.CreateTask already
// normalizes (values <600 get raised to 600); this is a backstop against in-memory anomalies.
func plannerHeartbeatInterval(t *Task) time.Duration {
	sec := t.PlanHeartbeatSeconds
	if sec < db.MinPlanHeartbeatSeconds { // floor = default = 600 (10min)
		sec = db.MinPlanHeartbeatSeconds
	}
	return time.Duration(sec) * time.Second
}

// resetPlannerTimer safely re-arms a possibly-fired Timer (standard Stop→drain→Reset pattern).
func resetPlannerTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

// warnNarrowScope notes a narrow asset surface at task start (v0.4.57 retro: thin sites like tasks 16/17
// ran the full flow but yielded little — set expectations early so operators can adjust goal/budget/timeout).
// Sent once, alongside autoAttributeCompany, only on the created→running first start.
func (e *Engine) warnNarrowScope(t *Task) {
	if e.m == nil || e.m.pg == nil || e.m.assets == nil {
		return
	}
	tid, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || tid <= 0 {
		return
	}
	cov, err := e.m.assets.TaskCoverageWithSources(tid)
	if err != nil || cov == nil || !cov.Enabled {
		return
	}
	if cov.Denominator == 0 || cov.Denominator >= 10 {
		return
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("kick-off note: only %d assets in scope — a narrow surface with limited expected yield; consider widening scope or lowering this task's budget/timeout", cov.Denominator)})
}

// warnFindingsWithoutReport checks for 'reported but detail-report empty' vulns before the task settles.
// No workers get dispatched after the endgame — these gaps can only prompt a human to fill reports on the
// vuln page: at export time one empty-report vuln drags deliverable quality (v0.4.56 retro: 7 reportless vulns across 12 tasks).
func (e *Engine) warnFindingsWithoutReport(t *Task) {
	if e.m == nil || e.m.pg == nil {
		return
	}
	fs, _, err := e.m.pg.ListFindingsPage(db.FindingFilter{TaskID: t.ID}, 1, 500)
	if err != nil {
		return
	}
	var missing []string
	for _, f := range fs {
		if strings.TrimSpace(f.Report) == "" {
			title := strings.TrimSpace(f.Name)
			if title == "" {
				title = strings.TrimSpace(f.VulnClass)
			}
			if title == "" {
				title = "unclassified"
			}
			missing = append(missing, fmt.Sprintf("#%d %s", f.ID, title))
			if len(missing) >= 5 {
				break
			}
		}
	}
	if len(missing) == 0 {
		return
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("wrap-up check: %d vulns lack a detailed report (%s…) — fill them on the vuln page before exporting", len(missing), strings.Join(missing, ", "))})
}

func (e *Engine) plannerLoop(ctx context.Context, t *Task) {
	interval := plannerHeartbeatInterval(t)
	// The heartbeat timer arms at loop entry = measured from task start: even seed tasks that skip round one
	// (Run doesn't kick when frontier is non-empty) and block here still get their first plan round at
	// 'task start + interval'. Every later wake (edge/heartbeat) re-arms = time since any plan trigger.
	heartbeat := time.NewTimer(interval)
	defer heartbeat.Stop()

	// runRound runs one plan round (debounce merge + guards). src only labels the trigger source in logs.
	runRound := func(src string) {
		// Pending settle: try settling first; unmet (goal_met still has running intents) → wait for the next wake,
		// don't plan — else new intents after goal_met keep the task running forever.
		// Exception: a user just added a goal/hint → cancel the non-hard-cap settle and keep planning (max_rounds is a hard cap).
		if reason, _ := t.peekSettle(); reason != "" {
			if suppressAutopilotSettle(t, reason) {
				// Autopilot: after clearing the pending reason, **continue this plan round**. Never return here —
				// the reason would stay set, every wake would take this branch, and the planner deadlocks.
				t.clearSettle()
				log.Printf("[autopilot] task %s ignoring settle criterion %s — continuing to plan", t.ID, reason)
				_ = e.m.pg.InsertAutopilotEvent(t.ID, "settle_suppressed", "autopilot: ignored settle criterion "+reason)
			} else if reason != "auto_rounds" && t.hasPendingFreshDirection() {
				t.clearSettle()
				if err := e.m.pg.ResetTaskProgress(t.ID); err != nil {
					log.Printf("[auto-finish] task %s new-goal progress reset failed: %v", t.ID, err)
				}
			} else {
				e.maybePendingSettle(ctx, t)
				return
			}
		}
		// debounce: coalesce a burst of changes into one planning round
		timer := time.NewTimer(e.debounce)
	drain:
		for {
			select {
			case <-t.notify:
			case <-timer.C:
				break drain
			}
		}
		planner, _ := e.snapshotFor(t)
		if planner == nil {
			return // idle until LLM configured
		}
		if e.IsPaused(t.ID) {
			return // user-paused: don't plan
		}
		if e.IsDeleting(t.ID) {
			return
		}
		// terminal task (goals all met → done, or failed): the run is over. A
		// resume/nudge — e.g. auto-resume of the active task on restart — must NOT
		// re-plan (it would burn an LLM round and re-confirm a settled result).
		if isTerminalStatus(t.lifecycleSnapshot().Status) {
			return
		}
		// Task-timeout wrap-up in progress: drop normal wakes — worker wrap-up write-backs and Resume Notifies
		// no longer trigger plan rounds; the endgame round is driven directly by the coordinator (settleTask), not here.
		if e.isSettling(t.ID) {
			return
		}
		// The goalless (human direct-dispatch) branch: with no open goals left, planner doesn't run — running
		// would re-judge met→cancelExec and kill intents the user direct-dispatched via the main agent. Whether
		// to end is frontier's call: open/running intents left → stay running, wait quietly; all drained → done.
		// The whole branch is pure Go — no LLM calls, no plan-round marker.
		if open, err := t.Store.HasOpenGoal(); err == nil && !open {
			// Autopilot: though all goals are met, if work remains (untested assets / unclosed high-sev / last wave
			// produced new facts), refill the next goal layer and return to the planner — else this falls to the
			// goalless branch straight to done.
			if t.AutopilotEnabled() && e.maybeExtendAutopilot(t) {
				log.Printf("[autopilot] task %s all goals met but work remains — auto-refill instead of wrapping", t.ID)
				return
			}
			t.drainTriggers() // drop accumulated done/finding triggers — avoid unbounded growth in a long goalless session
			if active, err := t.Store.HasActiveIntent(); err == nil && !active {
				// name reportless vulns before landing done (see warnFindingsWithoutReport).
				e.warnFindingsWithoutReport(t)
				// frontier drained AND nothing running → wrap up. Use the Guarded variant for CAS — avoids racing
				// concurrent pause/delete/timeout-wrap-up transitions.
				if won, err := e.m.SetTaskStatusGuarded(t.ID, "done"); err != nil {
					log.Printf("[goalless] task %s failed to land done: %v", t.ID, err)
				} else if won {
					// done is terminal too: background jobs (long scans via job_start) mustn't keep hitting the
					// target outside the authorization window. The goalless branch skips settleTaskWithReason — clean up separately.
					if n := agent.KillJobsForTaskDir(filepath.Join(e.m.dir, "tasks", t.ID)); n > 0 {
						log.Printf("[goalless] task %s cleaned up %d background jobs on done", t.ID, n)
					}
					e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
						Summary: "all goals achieved and direct-dispatch intents executed — task complete"})
				}
			}
			return // the goalless branch never enters planner.Plan
		}
		if !e.beginTaskOperation(t.ID) {
			return
		}
		defer e.decInflight(t.ID)
		e.stampFirstRun(t) // first real plan round → stamp first_run_at + compute deadline (timeout tasks only)
		e.touch(t.ID)
		emit := func(r db.Activity) { e.emitActivity(t, r) }
		ectx := e.clockCtx(e.execContextFor(ctx, t.ID), t, false, "") // cancellable by Pause; carries the task deadline
		if ectx.Err() != nil || e.IsDeleting(t.ID) {
			return
		}
		// the plan round's own wall-clock cap (unrelated to the task deadline).
		//
		// Why required: planner's MaxDuration comes from clampMaxDuration(deadline, 0) — no task deadline means
		// 0 = **unlimited**; the SDK's MaxDuration only checks at **turn boundaries** and constrains **tool
		// execution** — LLM calls use the deadline-free l.ctx. One upstream half-open connection (connected but
		// never returns) makes Plan() never return, runRound never ends, and runRound is **serial**: every later
		// wake (edge + heartbeat) queues behind it.
		// all stuck inside the same runRound and couldn't return.
		//
		// Measured fallout (production 2026-10-20): after a 14:30 start, the planner stopped emitting rounds
		// at 14:42/15:45 while workers drained the remaining intents (last exhausted at 16:53) — then 6 hours
		// of zero plan rounds and zero new intents. 'Running Workers' stayed 0; the task looked running but did
		// nothing. Restarting the service recovered it.
		//
		// Why 15 minutes: a measured plan round (1M context + dozens of tool calls) takes 3–5 min; 15 min gives
		// 3× headroom AND bounds 'upstream hung' waste to 15 min before self-healing — no more indefinite silence.
		// won't silently stall for hours like before.
		roundCtx, roundCancel := context.WithTimeout(ectx, plannerRoundLimit())
		defer roundCancel()
		log.Printf("[planner] task %s planning…(%s triggered)", t.ID, src)
		// round marker: each Plan() is one planner round; emit a boundary so the
		// UI can separate rounds in the transcript (kind='round').
		round := e.nextPlannerRound(t.ID)
		e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round",
			Summary: fmt.Sprintf("plan round %d", round)})
		// what fired this round (worker done / finding; may be several — debounce
		// coalesces a burst; empty for time/heartbeat wakes).
		triggers := t.drainTriggers()
		taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
		e.BeginLLMCall(t.ID)
		// Plan runs on its own goroutine so that NOTHING it can get stuck on can
		// stop the planner loop.
		//
		// Why this matters (2026-10-21 real incident): the planner went silent
		// for over an hour while the service kept running. The goroutine dump
		// showed it blocked on a self-deadlock inside the compactor
		// (agent/compaction.go: tryStart held c.mu and called a lock-taking
		// cooldownFor). A deadlocked goroutine never returns, so **ctx
		// cancellation cannot break it** — the wall-clock deadline below was
		// powerless against it, and the planner's serial runRound kept every
		// later wake-up (edge + heartbeat) stuck behind it.
		//
		// Selecting on the result channel means the loop gives up on a stuck
		// round after plannerRoundTimeout and keeps serving wake-ups. The stuck
		// goroutine leaks (Go cannot kill one), which is the lesser evil: one
		// leaked goroutine per stuck round versus a permanently mute planner.
		res := runPlannerRound(roundCtx, func(ctx context.Context) (bool, string, error) {
			return planner.Plan(ctx, taskIDInt, e.m.assets, t.Store, t.Goal, triggers, emit)
		})
		e.EndLLMCall(t.ID)
		switch {
		case res.err != nil && roundCtx.Err() != nil && ectx.Err() == nil:
			// Plan-round timeout (this round's own wall-clock cap — not the task deadline).
			//
			// This branch MUST stay reachable: on timeout the round is voided, runRound ends normally and the
			// planner responds again — the next wake plans another round. It must NOT fall into the 'planning
			// error' branch below and get swallowed silently — that would regress to 'permanently silent'.
			log.Printf("[planner] task %s plan round timed out (%s) — round voided, retrying on next wake", t.ID, plannerRoundLimit())
		case res.err != nil && ectx.Err() == nil:
			log.Printf("[planner] task %s planning error: %v", t.ID, res.err)
		case res.met:
			// Autopilot refill: when all goals are met, first ask 'is there anything left'. Untested assets /
			// high-sev vulns remaining AND waves unused → auto-append the next goal layer; this round doesn't
			// cancel workers or settle — treat as 'unfinished' and keep planning.
			if e.maybeExtendAutopilot(t) {
				res.met = false
				break
			}
			log.Printf("[planner] task %s judged goal met: %s", t.ID, res.reason)
			// Task judged done → immediately cancel running workers: their in-flight intents' output is moot.
			// Next worker loop hits the terminal gate and stops claiming; the cancelled batch lands in the
			// 'task finished' branch below as stopped (not blocked).
			e.cancelExec(t.ID, agent.AbortGoalMet)
		default:
			log.Printf("[planner] task %s planning done", t.ID)
		}
		// Auto-wrap-up decision (v0.5.0): only record the reason — the actual settle runs in plannerLoop after
		// this round's inflight drains (avoids drain waiting on itself).
		if res.err == nil && ectx.Err() == nil && !e.isSettling(t.ID) {
			if res.met {
				t.requestSettle("goal_met", "planner judged the goal achieved")
			} else {
				e.recordAndEvaluateAutoFinish(t, int64(round), triggers)
			}
		}
		// Coverage-matrix / depth-gap nudge (v0.4.63): when prompt constraints can't hold weak models, the
		// engine deterministically adds a layer. Doesn't require res.err==nil — timeouts/model faults nudge too.
		if ectx.Err() == nil && !e.isSettling(t.ID) {
			e.nudgeCoverageGaps(t)
			e.nudgeDepthGaps(t)
		}
		e.touch(t.ID)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.notify:
			runRound("edge") // worker end / finding / kill / resume / seed first-round
			e.maybePendingSettle(ctx, t)
		case <-heartbeat.C:
			// Periodic backstop: deadlock backstop + waking to supervise in-flight workers (steer/kill) + periodic review.
			// Skip pure-heartbeat plan rounds at full backlog: the plan would only get add_intent rejected — burned tokens.
			// Edge triggers (worker end/finding) are unaffected.
			if !e.intentBacklogFull(t) {
				runRound("heartbeat")
			}
			e.maybePendingSettle(ctx, t)
		}
		// Re-arm the heartbeat after every wake (edge or heartbeat): any plan trigger restarts this idle timer.
		resetPlannerTimer(heartbeat, interval)
	}
}

func (e *Engine) workerLoop(ctx context.Context, t *Task, name string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, worker := e.snapshotFor(t)
		if worker == nil {
			if sleepCtx(ctx, 1500*time.Millisecond) {
				return
			}
			continue
		}
		if e.IsPaused(t.ID) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // user-paused: don't claim/execute intents
		}
		if e.IsDeleting(t.ID) {
			return
		}
		if e.isSettling(t.ID) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // task-timeout wrap-up in progress: stop claiming new intents (running ones wrap themselves; the coordinator waits for drain)
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // task terminal (done/failed/timeout): stop claiming leftover intents — don't spin on frontier after completion
		}
		if !e.beginTaskOperation(t.ID) {
			return
		}
		claimed := e.runWorkerStep(ctx, t, name, worker)
		e.decInflight(t.ID)
		if !claimed && sleepCtx(ctx, 800*time.Millisecond) {
			return
		}
	}
}

// runWorkerStep claims one intent from the frontier and fully settles it via
// runIntent. Returns false when nothing was claimable. The pool worker loop is its
// only caller.
func (e *Engine) runWorkerStep(ctx context.Context, t *Task, name string, worker *agent.Worker) bool {
	intent := e.claimNext(t, name)
	if intent == nil {
		return false
	}
	log.Printf("[worker %s] task %s claimed intent #%d", name, t.ID, intent.ID)
	return e.runIntent(ctx, t, name, worker, intent, "", "")
}

// runIntent executes and fully settles one already-claimed (state=running) intent.
// Both the pool worker loop (via runWorkerStep) and the human-message handler (via
// runDetachedIntent, a dedicated goroutine outside the worker pool) call it, so the
// execute/retry/state-write logic lives in exactly one place. A non-empty message
// is injected as this turn's input through ExecuteWithMessage; requestID keys the
// transcript marker that dedups re-injection across model_error retries. The caller
// must already hold one task-operation admission for the whole sequence so a delete
// cannot observe quiescence between the LLM return and the final DB writes.
func (e *Engine) runIntent(ctx context.Context, t *Task, name string, worker *agent.Worker, intent *db.Node, requestID, message string) bool {
	hasChatMessage := message != ""
	e.stampFirstRun(t) // first real execution → stamp first_run_at + compute deadline (timeout tasks only)
	e.touch(t.ID)
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	ectx := e.clockCtx(e.execContextFor(ctx, t.ID), t, false, "") // cancellable by Pause; carries the task deadline
	if ectx.Err() != nil || e.IsDeleting(t.ID) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s intent #%d post-claim rollback failed: %v", name, t.ID, intent.ID, err)
		}
		return true
	}
	// per-work child context so the planner's kill_work can stop just this work.
	workCtx, workCancel := context.WithCancelCause(ectx)
	e.registerWork(intent.ID, workCancel)
	// wrap the guard hooks so steer_work can inject a mid-run course-correction
	// for THIS intent (drained before the worker's next tool call).
	iid := intent.ID
	taskEmit := func(a db.Activity) {
		nid := iid
		a.NodeID, a.Worker = &nid, name
		emit(a)
	}
	label := fmt.Sprintf("%s · #%d", name, iid)
	workCtx = intercept.WithTaskContext(workCtx, t.ID, label, taskEmit)
	workCtx = intercept.WithAutopilot(workCtx, t.AutopilotEnabled) // autopilot prompt tail (worker)
	// Intent-level soft budget (v0.4.28): usage activity's cumulative tokens hit the cap → steer injects a
	// wrap-up nudge (soft — no kill, once only); the duplicate-call detector hangs on steerHooks. Both are settings-togglable.
	if bw := intentBudgetWatcher(intentBudgetFromPG(e.m.pg), func(msg string) error {
		return e.SteerWork(iid, msg)
	}, label); bw != nil {
		inner := emit
		emit = func(a db.Activity) {
			bw(a)
			inner(a)
		}
	}
	// Evidence re-verify ledger + injection warning (v0.4.29, P0b #2/#4): a tool_result's Detail IS the echo
	// text the model actually saw (post SDK on-disk truncation) — the ledger collects it for report_finding's
	// verbatim check; high-precision injection-pattern hits raise a 'data, not instructions' steer before the next tool call.
	ledger := agent.NewToolOutputLedger()
	workCtx = agent.WithToolOutputs(workCtx, ledger, evidenceVerifyModeFromPG(e.m.pg))
	if injectionGuardFromPG(e.m.pg) {
		var injAlerts atomic.Int64
		inner := emit
		emit = func(a db.Activity) {
			if a.Kind == "tool_result" && a.Detail != "" {
				ledger.Add(a.Detail)
				if pat := scanInjection(a.Detail); pat != "" && injAlerts.Add(1) <= 3 {
					if err := e.SteerWork(iid, injectionAlertText(pat)); err != nil {
						log.Printf("[injection %s] warning enqueue failed: %v", label, err)
					} else {
						log.Printf("[injection %s] tool output hit injection pattern %q — model reminded to treat as data", label, pat)
					}
				}
			}
			inner(a)
		}
	} else {
		inner := emit
		emit = func(a db.Activity) {
			if a.Kind == "tool_result" && a.Detail != "" {
				ledger.Add(a.Detail)
			}
			inner(a)
		}
	}
	// nudges intentionally live OUTSIDE the model_error rerun loop: the idle-turn continuation cap is a
	// per-intent total — a rerun mustn't reset the counter.
	hooks := steerHooks{
		inner:   t.Guard.Hooks(),
		drain:   func() (string, bool) { return e.drainSteer(iid) },
		nudges:  &atomic.Int64{},
		limit:   e.emptyTurnNudgeLimit(),
		label:   label,
		repeats: newRepeatTracker(),
	}
	wTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	runStart := time.Now() // intent wall-clock start (cumulative across model_error retries), settles into payload
	e.BeginLLMCall(t.ID)
	var reason harness.TerminalReason
	var wrote agent.WriteCounts
	var err error
	// Every Execute is a fresh ToolSet — its return reflects only that one run; retries must accumulate,
	// else a first round writing 4 facts and a retry writing 0 gets recorded as 'zero write-back' — breaking logs/retros.
	accWrote := func(w agent.WriteCounts) { wrote = addWriteCounts(wrote, w) }
	var w agent.WriteCounts
	if hasChatMessage {
		reason, w, err = worker.ExecuteWithMessage(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding, requestID, message, workCancel)
	} else {
		reason, w, err = worker.Execute(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding, workCancel)
	}
	accWrote(w)
	e.EndLLMCall(t.ID)
	// model_error wrap-up → a few extra reruns (retry after backoff). Only while the intent still belongs to
	// this work AND the task isn't paused/terminated/cancelled [or settling]; otherwise yield to that branch
	// (no retries during settlement — backoff would squeeze other workers' graceful wrap-up window).
	maxRetries, retryBackoff := e.modelErrorRetryPolicy()
	for attempt := 1; attempt <= maxRetries &&
		(retryableWorkerModelError(reason, err) || isTransientContextCanceled(err)) &&
		workCtx.Err() == nil && ectx.Err() == nil && !e.IsPaused(t.ID) && !e.isSettling(t.ID); attempt++ {
		log.Printf("[worker %s] task %s intent #%d transient-failure wrap-up (%v), retrying in %v (%d/%d)",
			name, t.ID, intent.ID, preview(fmt.Sprint(err), 80), retryBackoff, attempt, maxRetries)
		if sleepCtx(workCtx, retryBackoff) {
			break // cancelled during backoff (terminate/pause) → hand to a branch below
		}
		e.BeginLLMCall(t.ID)
		var rw agent.WriteCounts
		if hasChatMessage {
			reason, rw, err = worker.ExecuteWithMessage(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding, requestID, message, workCancel)
		} else {
			reason, rw, err = worker.Execute(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding, workCancel)
		}
		accWrote(rw)
		e.EndLLMCall(t.ID)
	}
	// Capture kill state before detachWork cancels workCtx. kill = this work's
	// ctx was cancelled (planner kill_work) while the TASK ctx kept running; a
	// pause cancels the task ctx (ectx) instead. Checking workCtx.Err() AFTER
	// unregister would always be true (unregister cancels it) → every completed
	// work would be wrongly marked stopped.
	workCause := context.Cause(workCtx)
	// idle-stop is a self wrap-up, not a planner termination — excluded, then falls to exhausted splitting below.
	killed := workCtx.Err() != nil && ectx.Err() == nil && !errors.Is(workCause, agent.AbortIdleStop)
	action, completeWork := e.detachWork(intent.ID)
	// A caller may stop waiting and release its in-memory reservation before the
	// agent honors cancellation. The named context cause remains authoritative and
	// still settles the stopped run into a recoverable state.
	if action == "" {
		switch {
		case errors.Is(workCause, agent.AbortWorkPausedByUser):
			action = "pause"
		case errors.Is(workCause, agent.AbortWorkCancelledByUser):
			action = "cancel"
		}
	}
	var controlErr error
	defer func() { completeWork(controlErr) }()
	if action == "pause" {
		controlErr = transitionIntentState(t.Store, intent.ID, "running", "paused")
		if controlErr != nil {
			log.Printf("[worker %s] task %s intent #%d paused-state write failed: %v", name, t.ID, intent.ID, controlErr)
			return true
		}
		log.Printf("[worker %s] task %s intent #%d paused", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	if action == "cancel" {
		// Park the stopped run in paused before handing cleanup to the API. If the
		// request disconnects after cancellation, the intent remains recoverable and
		// a later cancel can finish cleanup instead of leaving a phantom running row.
		controlErr = transitionIntentState(t.Store, intent.ID, "running", "paused")
		if controlErr != nil {
			log.Printf("[worker %s] task %s intent #%d cancel-fence write failed: %v", name, t.ID, intent.ID, controlErr)
			return true
		}
		log.Printf("[worker %s] task %s intent #%d stopped, awaiting cancel cleanup", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// if a pause cancelled this run mid-flight, return the intent to the frontier
	// so it is re-claimed on resume — the worker will resume the prior LLM
	// conversation from its transcript instead of restarting from scratch.
	if ectx.Err() != nil && taskExecutionPaused(context.Cause(ectx)) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s intent #%d task-pause rollback failed: %v", name, t.ID, intent.ID, err)
		}
		return true
	}
	// Task-timeout wrap-up's hard backstop cancel (not pause, not kill) cancelled this run → count as
	// exhausted (already wrapped), don't mislabel blocked. The worker usually already wrote results in settlement.
	if ectx.Err() != nil && e.isSettling(t.ID) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "exhausted"); err != nil {
			log.Printf("[worker %s] task %s intent #%d timeout-wrap-up write failed: %v", name, t.ID, intent.ID, err)
		} else {
			_ = t.Store.SetIntentStopReason(intent.ID, db.IntentStopTaskTimeout)
		}
		log.Printf("[worker %s] task %s intent #%d ended by task-timeout wrap-up (exhausted), wrote back %s", name, t.ID, intent.ID, wrote)
		e.touch(t.ID)
		return true
	}
	// goal_met: the planner judged goals met and cancelled running workers. Task status may not be terminal yet
	// (settling unset too); without its own recognition it falls into 'service stopped' below — bounced to open,
	// immediately re-claimed and re-run, while the pending goal_met wrap-up never sees HasActiveIntent=false.
	if canceledByGoalMet(ectx) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s intent #%d goal_met-stop write failed: %v", name, t.ID, intent.ID, err)
		} else {
			_ = t.Store.SetIntentStopReason(intent.ID, db.IntentStopTaskDone)
		}
		log.Printf("[worker %s] task %s intent #%d cancelled on goal-met (stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// Task judged done (via normal path) → cancelExec above cancelled this run. The intent's result is moot —
	// mark stopped (not blocked); don't pollute a finished task's intent states.
	if ectx.Err() != nil && isTerminalStatus(e.m.TaskStatus(t.ID)) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s intent #%d terminal-stop write failed: %v", name, t.ID, intent.ID, err)
		} else {
			_ = t.Store.SetIntentStopReason(intent.ID, db.IntentStopTaskDone)
		}
		log.Printf("[worker %s] task %s intent #%d cancelled on task completion (stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// Service stop / task-scope cancel (not pause, not settling, not terminal, not kill): this run was cancelled
	// by the process-level ctx — not the worker's fault. Return the intent to open for re-claiming after recovery —
	// otherwise every deploy restart burns intents (measured: 5 tasks accrued 29 blocked=context canceled).
	if ectx.Err() != nil && !e.isSettling(t.ID) && !isTerminalStatus(e.m.TaskStatus(t.ID)) && !killed {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s intent #%d service-stop rollback failed: %v", name, t.ID, intent.ID, err)
		} else {
			_ = t.Store.SetIntentStopReason(intent.ID, db.IntentStopShutdown)
		}
		log.Printf("[worker %s] task %s intent #%d back to open on service stop (re-claimed after recovery)", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// killed by the planner: mark stopped (don't write back results, don't auto-reclaim).
	if killed {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s intent #%d planner-stop write failed: %v", name, t.ID, intent.ID, err)
		} else {
			_ = t.Store.SetIntentStopReason(intent.ID, db.IntentStopKilled)
		}
		log.Printf("[worker %s] task %s intent #%d terminated (stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		t.Notify()
		return true
	}
	if err != nil {
		log.Printf("[worker %s] intent %d: %v", name, intent.ID, err)
	}
	// terminal split: hitting the step cap ≠ done. max_turns→exhausted (the planner learns this direction was
	// tried but not truly finished — switch angles rather than skip it forever as 'covered'); error→blocked; normal→done.
	//
	// Every path writes a reason code into blocked_reason: previously exhausted/blocked/stopped reasons
	// never persisted — the UI showed a bare state ('a bunch of subtasks interrupted abnormally') with no why.
	// The planner uses it to decide whether to retry.
	state := "done"
	stopReason := ""
	switch {
	case errors.Is(workCause, agent.AbortIdleStop) || errors.Is(err, agent.AbortIdleStop):
		// no-increment auto wrap-up (issue #2): the direction hit its boundary — not failure, not completion.
		state = "exhausted"
		stopReason = db.IntentStopIdleStop
		log.Printf("[worker %s] intent %d no-increment auto wrap-up (exhausted/idle_stop), wrote back %s", name, intent.ID, wrote)
	case reason == harness.ReasonStopHookPrevented:
		// Stop-hook wrap-up (fires when the model stops calling tools) — also recorded as idle_stop.
		state = "exhausted"
		stopReason = db.IntentStopIdleStop
		log.Printf("[worker %s] intent %d no-increment auto wrap-up (exhausted/idle_stop, Stop hook), wrote back %s", name, intent.ID, wrote)
	case err != nil:
		state = "blocked"
		stopReason = db.IntentStopError
		if isTaskLLMChainExhausted(err) {
			stopReason = db.IntentBlockedLLMQuota
		}
		stopReason = stopReason + ": " + truncateStopReason(err.Error())
	case reason == harness.ReasonMaxTurns:
		state = "exhausted"
		stopReason = db.IntentStopMaxTurns
		log.Printf("[worker %s] intent %d hit step cap (exhausted), wrote back %s", name, intent.ID, wrote)
	case reason == harness.ReasonTimeout:
		state = "exhausted"
		stopReason = db.IntentStopTimeout
		log.Printf("[worker %s] intent %d ran out of time (exhausted), wrote back %s after wrap-up", name, intent.ID, wrote)
	}
	if state == "blocked" && isTaskLLMChainExhausted(err) {
		_ = t.Store.SetIntentBlockedReason(intent.ID, db.IntentBlockedLLMQuota)
	} else {
		if stateErr := transitionIntentState(t.Store, intent.ID, "running", state); stateErr != nil {
			log.Printf("[worker %s] task %s intent #%d terminal state %s write failed (background retry scheduled): %v", name, t.ID, intent.ID, state, stateErr)
			e.retryIntentTerminalAsync(t.Store, intent.ID, state, stopReason)
		} else if stopReason != "" {
			if err := t.Store.SetIntentStopReason(intent.ID, stopReason); err != nil {
				log.Printf("[worker %s] task %s intent #%d terminal-reason write failed: %v", name, t.ID, intent.ID, err)
			}
		}
	}
	log.Printf("[worker %s] task %s intent #%d finished: %s (wrote back %s)", name, t.ID, intent.ID, state, wrote)
	// Intent wall-clock telemetry (v0.4.27): wall_ms lands in the intent payload; the planner's compactIntents
	// carries it — 'how long this direction burned' becomes auditable on the graph, not just in activity.
	if err := t.Store.MergeIntentPayload(intent.ID, map[string]any{
		"wall_ms":  time.Since(runStart).Milliseconds(),
		"terminal": state,
	}); err != nil {
		log.Printf("[worker %s] task %s intent #%d wall-clock telemetry write failed: %v", name, t.ID, intent.ID, err)
	}
	// B2: exhausted with zero write-back = 'burned a whole round, left no fact/asset/vuln'. Not a normal
	// wrap-up — send this direction's last few step summaries to the planner with the review trigger so it can
	// retrospect and write a fact (lineage derived_from → that intent), instead of letting the attempt evaporate.
	// Placed after the terminal-state write: ActivityTraceTailTerminalIntent is only visible for terminal intents.
	if state == "exhausted" && wrote.Total() == 0 {
		var tail string
		if acts, aErr := t.Store.ActivityTraceTailTerminalIntent(intent.ID, 3); aErr == nil && len(acts) > 0 {
			parts := make([]string, 0, len(acts))
			for _, a := range acts {
				s := strings.TrimSpace(a.Summary)
				if s == "" {
					s = strings.TrimSpace(a.Tool)
				}
				if s == "" {
					s = strings.TrimSpace(a.Kind)
				}
				// each step's summary clipped to ~200 bytes — 3 steps won't bloat the trigger block.
				if len(s) > 200 {
					s = s[:200]
				}
				parts = append(parts, s)
			}
			tail = strings.Join(parts, ";")
		}
		t.NotifyReview(intent.ID, tail)
		log.Printf("[worker %s] task %s intent #%d exhausted with zero write-back — review requested", name, t.ID, intent.ID)
	}
	e.touch(t.ID)
	t.NotifyDone(intent.ID) // results changed the graph -> wake the planner (with the just-finished intent id)
	return true
}

// runDetachedIntent runs one paused intent OUTSIDE the worker pool in its own
// goroutine — the human-message path. It transitions the intent paused->running
// itself (never through 'open'), so the pool, which only claims 'open', can never
// race it; the "at most one run per intent" invariant still holds because winning
// the CAS is the sole entry and work[intentID] was cleared when the pause settled.
// Because it does not compete for a frontier slot, a user message continues the
// worker immediately even when all pool slots are busy (mirroring how the
// main-agent chat handler starts its run directly). The spawned goroutine owns one
// task-operation admission for the whole run and roots its context at ctx (pass the
// server root, never the HTTP request, so a disconnect cannot strand the run while
// task pause/delete/shutdown still stops it). Returns an error if the run could not
// be started; the intent is left untouched in that case.
func (e *Engine) runDetachedIntent(ctx context.Context, t *Task, intentID int64, requestID, message, agentMessage string) error {
	if !e.beginTaskOperation(t.ID) {
		return fmt.Errorf("task is being deleted")
	}
	release := true
	defer func() {
		if release {
			e.decInflight(t.ID)
		}
	}()
	_, worker := e.snapshotFor(t)
	if worker == nil {
		return fmt.Errorf("worker not ready yet")
	}
	node, err := t.Store.GetNode(intentID)
	if err != nil {
		return err
	}
	if node == nil || node.Kind != db.KindIntent {
		return fmt.Errorf("intent not found")
	}
	changed, err := t.Store.CompareAndSetIntentState(intentID, "paused", "running")
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("%w: intent is no longer paused", db.ErrIntentStateConflict)
	}
	node.State, node.Owner = "running", "chat"
	// Record the human turn as a visible activity BEFORE the run starts, so it is
	// ordered ahead of any worker step and never appears without the run happening.
	// Keep the UI copy concise; ExecuteWithMessage writes the server-resolved
	// reference snapshot into the intent transcript as the LLM input.
	uid := intentID
	e.emitActivity(t, db.Activity{NodeID: &uid, Worker: "user", Kind: "user", Summary: message, Detail: message})
	release = false // ownership of the admission passes to the goroutine
	go func() {
		defer e.decInflight(t.ID)
		e.runIntent(ctx, t, "chat", worker, node, requestID, agentMessage)
	}()
	return nil
}

func taskExecutionPaused(cause error) bool {
	var abort *agent.AbortCause
	if !errors.As(cause, &abort) {
		return false
	}
	switch abort.Code {
	case "paused_by_user", "paused_by_orchestrator", "paused_on_reload", "paused_race_guard",
		"queued_for_admission", "llm_unavailable_queued", "task_deleted":
		return true
	default:
		return false
	}
}

func sleepCtx(ctx context.Context, d time.Duration) (done bool) {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(d):
		return false
	}
}

func (e *Engine) claimNext(t *Task, name string) *db.Node {
	fr, _ := t.Store.Frontier(20)
	// Serial pre-gate (default off): intents carrying requires_intents must wait for all prerequisites to reach terminal.
	gate := intentRequiresGateFromPG(e.m.pg)
	for _, in := range fr {
		if gate && e.intentRequiresPending(t, in) {
			continue
		}
		if ok, _ := t.Store.ClaimIntent(in.ID, name); ok {
			return in
		}
	}
	return nil
}

// intentRequiresPending says whether the intent's requires_intents still has non-terminal prerequisites.
func (e *Engine) intentRequiresPending(t *Task, in *db.Node) bool {
	var p struct {
		Requires []int64 `json:"requires_intents"`
	}
	if len(in.Payload) == 0 {
		return false
	}
	if err := json.Unmarshal(in.Payload, &p); err != nil || len(p.Requires) == 0 {
		return false
	}
	states, err := t.Store.NodeStates(p.Requires)
	if err != nil {
		return false // query failure doesn't block claiming (the gate is an optional optimization)
	}
	for _, id := range p.Requires {
		st, ok := states[id]
		if !ok {
			return true // prerequisite gone (deleted) → treat as non-terminal; avoid running on a broken chain
		}
		if st != "done" && st != "failed" && st != "deleted" && st != "met" {
			return true
		}
	}
	return false
}
