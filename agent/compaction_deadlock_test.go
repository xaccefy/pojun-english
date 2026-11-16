package agent

import (
	"testing"
	"time"
)

// Compactor.tryStart self-deadlock.
//
// Regression background (2026-10-21 live incident): the planner went **permanently silent** after
// its 23rd plan round — no new intents, no planner logs, service otherwise healthy. The goroutine
// dump (SIGQUIT) showed the stack:
//
//	Planner.Plan (planner.go:370)
//	  → Compactor.OnPlannerRound (compaction.go:179)
//	    → Compactor.tryStart (compaction.go:435)
//	      → Compactor.cooldownFor (compaction.go:444)
//	        → sync.Mutex.Lock   ← blocked forever
//
// tryStart already held c.mu, yet called cooldownFor which locks again. sync.Mutex isn't
// reentrant → self-deadlock.
//
// Why it stayed hidden so long: this branch requires c.lastRun[expID] to exist, and lastRun is only
// written when the compaction goroutine finishes. So an exploration's **first** compaction is fine;
// the **next plan round** after compaction finishes dies.
//
// Why ctx timeout can't save it: the deadlocked goroutine never returns — ctx cancel is ineffective.
// The wall-clock cap v0.3.61 added to plan rounds was therefore decorative — same symptom (task
// silence), completely different root cause from an unresponsive upstream. Restarting fixed it, so it kept being misdiagnosed as upstream/network.
func TestCompactorTryStartDoesNotSelfDeadlock(t *testing.T) {
	c := &Compactor{
		cooldown: 60 * time.Second,
		running:   map[int64]bool{},
		lastRun:   map[int64]time.Time{},
		consecFails: map[int64]int{},
	}
	const expID = int64(7)

	// First: no lastRun — never reaches the cooldown branch; should acquire successfully.
	if !c.tryStart(expID) {
		t.Fatal("first tryStart must succeed")
	}
	c.finish(expID) // simulate the compaction goroutine ending: writes lastRun

	// Second: lastRun exists within the cooldown window → must return false, not deadlock.
	// Assert 'no deadlock' via goroutine + timeout — a deadlock would time the test out rather than
	// fail, so select gives a clear message.
	done := make(chan bool, 1)
	go func() { done <- c.tryStart(expID) }()
	select {
	case got := <-done:
		if got {
			t.Error("tryStart must respect the cooldown and return false")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tryStart deadlocked: it called a lock-taking method while holding c.mu")
	}

	// After the cooldown window it should acquire again (cooldown backs off by consecFails; none here).
	c.lastRun[expID] = time.Now().Add(-2 * c.cooldown)
	done2 := make(chan bool, 1)
	go func() { done2 <- c.tryStart(expID) }()
	select {
	case got := <-done2:
		if !got {
			t.Error("tryStart must succeed after the cooldown expired")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tryStart deadlocked on the cooldown path")
	}
}

// Consecutive failures exponentially back off the cooldown (capped at 30 min) and **must not** introduce a second lock.
func TestCompactorCooldownBackoff(t *testing.T) {
	c := &Compactor{
		cooldown:    60 * time.Second,
		running:     map[int64]bool{},
		lastRun:     map[int64]time.Time{},
		consecFails: map[int64]int{},
	}
	const expID = int64(1)
	// Test the Locked variant directly (the only locking entry).
	c.consecFails[expID] = 0
	if got := c.cooldownForLocked(expID); got != 60*time.Second {
		t.Errorf("no failures → cooldown = %v, want 60s", got)
	}
	c.consecFails[expID] = 1
	if got := c.cooldownForLocked(expID); got != 120*time.Second {
		t.Errorf("1 failure → cooldown = %v, want 120s", got)
	}
	c.consecFails[expID] = 10
	if got := c.cooldownForLocked(expID); got != 30*time.Minute {
		t.Errorf("many failures → cooldown = %v, want 30m (capped)", got)
	}
}
