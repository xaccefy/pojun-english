package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "user paused the task",
		"The user paused the task via the task-control API (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was actively cancelled; running intents return to frontier(open) and get re-claimed and re-run from scratch after resume")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "orchestration agent paused the task",
		"The orchestration agent called the pause_task tool to pause this task. This Planner/Worker run was actively cancelled; running intents return to frontier(open) and re-execute after resume")
	AbortTaskDeleted = cause("task_deleted", "task deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the delete barrier cancelled this task's running Planner, Worker and main agent; this run's results will not be used")
	AbortPausedOnReload = cause("paused_on_reload", "backend restored the task's paused state",
		"On startup the backend restored the task pause persisted in the database. This run was cancelled; normally no agents are running during the restore phase")
	AbortGoalMet = cause("goal_met", "planner judged the task goal achieved",
		"The planner judged the task goal achieved and marked the task done, then cancelled still-running Workers; those intents get marked stopped, not failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "task-timeout wrap-up wait exhausted",
		"After the task reached timeout, waiting for running Workers to wrap up gracefully exceeded the 90-second drain grace — a hard cancel followed; intents get marked exhausted and facts/assets already written during wrap-up are kept")

	// Per-work context.
	AbortIdleStop = cause("idle_stop", "no-increment auto wrap-up",
		"This intent had no write-back (fact/asset/vuln/evidence) for many consecutive rounds — output rate hit zero; the system first nudged for write-back and stopping, and with still no write-back it ended the round proactively. Everything written back is kept; the intent is recorded as exhausted(idle_stop) so the planner judges whether this direction is worth continuing from another angle")
	AbortKilledByPlanner = cause("killed_by_planner", "planner terminated this intent",
		"The planner called kill_work to terminate this intent — usually meaning the direction drifted or lost value; the intent gets marked stopped and won't be re-claimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "user paused this Worker intent",
		"The user paused a running Worker. This call was cancelled and the intent turned paused; all registered intents, facts, vulns and activity records are kept — it re-executes from scratch on resume")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "user deleted this Worker intent",
		"The user deleted a running Worker. This call was cancelled; after the Worker exits the write zone, the server handles the intent per the user's chosen delete mode — soft-delete only marks it deleted keeping all output, hard-delete cascades removing the intent and downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished; context released",
		"The Worker ended normally; the engine released its context resources in detachWork. This is not an interruption — if it shows up in interrupt messages, the cancel raced the wrap-up event")
	AbortPausedRaceGuard = cause("paused_race_guard", "new run refused while task paused",
		"While the task is paused the engine refuses to issue a new execution context — prevents a claim-vs-pause race from letting a Worker keep starting; already-claimed intents return to frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "user stopped this conversation turn",
		"The user clicked stop, actively aborting the current main-agent or chat-agent run. Activity already produced is kept; the next message can be sent normally")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "task pause aborted the main-agent chat",
		"When the user paused the task, the running main-agent conversation was cancelled too. Activity produced is kept; resuming the task doesn't auto-replay this turn")
	AbortChatTurnFinished = cause("chat_turn_finished", "chat turn finished; context released",
		"This conversation turn ended normally; the server is releasing its context resources. Not an interruption — if it appears in interrupt messages, the cancel raced the wrap-up event")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating or closing. All running agents get cancelled; after restart, leftover running intents reset to open and re-execute")
	AbortRunHardTimeout = cause("run_hard_timeout", "single-run hard timeout hit",
		"A single run exceeded the soft wall-clock budget plus extra grace — a model request or a tool didn't return for a long time, so the normal turn-boundary wrap-up couldn't run. Check the last unreturned tool call before the interrupt")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "upstream context reached its deadline",
			"upstream context reached its deadline, but the setter attached no named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "cancel side attached no named cause",
			"upstream context was cancelled without a named cause via context.WithCancelCause; register the cause in agent/cancelcause.go and wire it at that cancel site", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
