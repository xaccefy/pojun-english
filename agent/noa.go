package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is norma v0.4.0's 'model-driven context compaction' mechanism — exposed as a platform experimental
// feature toggled in system settings. It's mutually exclusive with built-in compaction: noaadapter.Enable
// is the only entry — it mounts a context Compactor, the Compress tool and three resident prompt sections;
// not calling Enable = off (built-in compaction keeps working). The switch resolves via each agent's
// injected noaEnabledFn, read once per run — toggles only affect later runs, no agent rebuild needed.

// enableNoa wires noa into opts when the resolver reports on. archiveRoot is the persistent base dir for
// compacted originals (uses global workDir — all agents land under <workDir>/noa uniformly, not scattered
// across task/intent dirs); sessionID names its archive subdir (globally unique — no collisions within a base).
//
// noa is experimental: wiring failure must not break a real task. On error, report via onWarn and fall back
// to built-in compaction. On success, clear opts.Compaction — agentcore warns on 'two context managers set'.
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("noa compaction failed to enable — falling back to built-in: " + err.Error())
		}
		return
	}
	// Compactor overrides Compaction, but with both set agentcore warns every time — clear explicitly.
	opts.Compaction = nil
}
