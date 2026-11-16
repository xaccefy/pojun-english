package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chu0119/pojun/listener"

	actool "github.com/Autumn-27/norma/tool"
)

// Callback receiver tools (the C2 prerequisite of a red-team kill chain): catch reverse shells / OOB callbacks with evidence.
// Design boundary in the listener package comment — this toolset only handles 'catch + see sessions';
// interactive shells are done by the agent via nc/socat in Bash.
//
// Approval semantics: start/stop goes through the intercept rule '[Built-in] Start/stop reverse-connection receiver'
// (ask — human confirm, since opening local ports is a platform capability-boundary change); session queries are read-only and unguarded.

var listenerMgr *listener.Manager

// ConnectBack is the callback params given to the agent (the payload's LHOST/LPORT).
type ConnectBack struct {
	Mode  string `json:"mode"`
	LHOST string `json:"lhost"`
	LPORT int    `json:"lport"`
	Via   string `json:"via,omitempty"`
}

// connectBackFn is server-injected: resolves the listen port into the address the target should dial
// (direct=local NIC; ssh/manual=public relay). nil=not injected (falls back to 127.0.0.1).
var connectBackFn func(port int) ConnectBack

// SetConnectBackResolver wires the C2 egress resolver.
func SetConnectBackResolver(fn func(port int) ConnectBack) { connectBackFn = fn }

// resolveConnectBack resolves the callback address; conservative fallback when uninjected.
func resolveConnectBack(port int) ConnectBack {
	if connectBackFn != nil {
		return connectBackFn(port)
	}
	return ConnectBack{Mode: "direct", LHOST: "127.0.0.1", LPORT: port,
		Via: "no C2 egress configured — fell back to 127.0.0.1 (only same-machine tests can reach)"}
}

// SetListenerManager wires the process-wide callback-listener manager.
func SetListenerManager(m *listener.Manager) { listenerMgr = m }

func listenerUnavailable() (actool.Result, bool) {
	if listenerMgr == nil {
		return actool.Errorf("callback receiver not enabled (server not initialized)"), true
	}
	return actool.Result{}, false
}

// listenerStart starts a listener (the ask gate lives at the intercept-rule layer).
func (t *ToolSet) listenerStart() actool.CoreTool {
	return writeTool(
		"listener_start",
		"Starts a [TCP callback receiver]: opens a local port to catch reverse shells / OOB callbacks, recording each session's source, time and captured content (first 64KB). Good for: starting the listener before triggering a callback after RCE, OOB blind-injection verification, multi-session collection. Ports limited to 1024-65535. For interactive shells pair with nc/socat in Bash (this tool only catches and evidences).",
		obj(map[string]any{
			"name": str("listener name (alphanumeric -_., globally unique), e.g. task1-shell"),
			"port": intp("listen port (1024-65535), e.g. 4444"),
		}, "name", "port"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := listenerUnavailable(); un {
				return r, nil
			}
			var a struct {
				Name string `json:"name"`
				Port int    `json:"port"`
			}
			_ = json.Unmarshal(in, &a)
			l, err := listenerMgr.Start(strings.TrimSpace(a.Name), a.Port)
			if err != nil {
				return actool.Errorf("start failed: " + err.Error()), nil
			}
			cb := resolveConnectBack(l.Port)
			return jsonResult(map[string]any{
				"name":         l.Name,
				"port":         l.Port,
				"started_at":   l.StartedAt,
				"connect_back": cb,
				"note": "listener is up. When triggering the target callback use LHOST=" + cb.LHOST +
					", LPORT=" + fmt.Sprint(cb.LPORT) +
					" (authoritative — don't use a local address); after the callback use listener_sessions to view sessions; for interactive ops use nc/socat in Bash to the local port.",
			})
		},
	)
}

// listenerStop stops a listener and returns its final session snapshot.
func (t *ToolSet) listenerStop() actool.CoreTool {
	return writeTool(
		"listener_stop",
		"Stops a callback receiver, returning all its session records (source/time/captured content) — for wrap-up archival or port switching.",
		obj(map[string]any{
			"name": str("listener name to stop"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := listenerUnavailable(); un {
				return r, nil
			}
			var a struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			sessions, err := listenerMgr.Stop(strings.TrimSpace(a.Name))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"stopped":  a.Name,
				"sessions": sessions,
			})
		},
	)
}

// listenerSessions views a listener's captured sessions (read-only).
func (t *ToolSet) listenerSessions() actool.CoreTool {
	return readTool(
		"listener_sessions",
		"Views a callback receiver's captured session list: each callback's source IP:port, connect time, byte count and content preview. After landing a session, go deeper via Bash (socat/nc takeover) and report key content as evidence.",
		obj(map[string]any{
			"name": str("listener name"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := listenerUnavailable(); un {
				return r, nil
			}
			var a struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			sessions, ok := listenerMgr.Get(strings.TrimSpace(a.Name))
			if !ok {
				return actool.Errorf(fmt.Sprintf("listener %q does not exist (start it via listener_start first)", a.Name)), nil
			}
			return jsonResult(map[string]any{
				"name":     a.Name,
				"sessions": sessions,
				"note":     "preview is each session's first 64KB captured; interactive takeover via Bash nc/socat to the local port",
			})
		},
	)
}
