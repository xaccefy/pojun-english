// Short-term circuit-breaking for MCP connect failures.
//
// wireAgentAugment connects every 'enabled and visible to this agent' MCP on each agent
// run. One unreachable MCP (say browser launching via `npx @playwright/mcp` on a host
// without Node) logs an error **on every worker start** — a few dozen rounds in, the log
// is all it and real problems drown, plus each attempt forks a process to wait for the
// failure.
//
// This remembers 'last failure time' per MCP name and skips it for a while after a
// failure. One success clears it and the next round reconnects normally (so after
// installing npx, no service restart needed — at most wait one window).
package server

import (
	"sync"
	"time"
)

const defaultMCPFailureCooldown = 10 * time.Minute

var (
	mcpFailMu   sync.Mutex
	mcpFailures = map[string]time.Time{}
)

// markMCPFailed records a connection failure; the MCP is skipped until the
// cooldown expires.
func markMCPFailed(name string, cooldown time.Duration) {
	if name == "" {
		return
	}
	if cooldown <= 0 {
		cooldown = defaultMCPFailureCooldown
	}
	mcpFailMu.Lock()
	mcpFailures[name] = time.Now().Add(cooldown)
	mcpFailMu.Unlock()
}

// mcpFailedUntil reports the cooldown deadline for a previously failed MCP.
// The second return is false when there is no recorded failure (or it expired).
func mcpFailedUntil(name string) (time.Time, bool) {
	mcpFailMu.Lock()
	defer mcpFailMu.Unlock()
	until, ok := mcpFailures[name]
	if !ok || time.Now().After(until) {
		if ok {
			delete(mcpFailures, name)
		}
		return time.Time{}, false
	}
	return until, true
}

// clearMCPFailure forgets a recorded failure so the next run reconnects at once.
func clearMCPFailure(name string) {
	mcpFailMu.Lock()
	delete(mcpFailures, name)
	mcpFailMu.Unlock()
}
