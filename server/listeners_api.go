// Connect-back listener REST API: list/start/stop/query sessions. Authorization matches
// every business API (JWT); agent-side approval for start/stop is handled by the
// intercept rule '[Built-in] Start/stop reverse-connection receiver' (ask).
package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/chu0119/pojun/listener"
)

type listenerView struct {
	Name      string             `json:"name"`
	Port      int                `json:"port"`
	StartedAt string             `json:"started_at"`
	Sessions  []listener.Session `json:"sessions"`
}

// GET /api/listeners — all running listeners (each with its session snapshot).
func (s *Server) listenerList(w http.ResponseWriter, r *http.Request) {
	if s.listeners == nil {
		writeJSON(w, 200, map[string]any{"listeners": []listenerView{}})
		return
	}
	out := []listenerView{}
	for _, l := range s.listeners.List() {
		out = append(out, listenerView{
			Name:      l.Name,
			Port:      l.Port,
			StartedAt: l.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Sessions:  l.Snapshot(),
		})
	}
	writeJSON(w, 200, map[string]any{"listeners": out})
}

// POST /api/listeners — start {"name","port"}.
func (s *Server) listenerStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if s.listeners == nil {
		writeErr(w, 503, "connect-back listener not initialized")
		return
	}
	l, err := s.listeners.Start(strings.TrimSpace(req.Name), req.Port)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// ssh relay mode: manage an SSH reverse tunnel for this listener (failure doesn't
	// roll back the listener — the local port is already receiving; the tunnel can be
	// fixed later; the error rides along in the response).
	cb := s.ResolveConnectBack(l.Port)
	if s.c2RelayConfig().Mode == "ssh" {
		if terr := s.startRelayTunnel(l.Name, l.Port); terr != nil {
			cb.Via = "relay tunnel setup failed: " + terr.Error()
		}
	}
	writeJSON(w, 200, map[string]any{
		"name": l.Name, "port": l.Port, "started_at": l.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"connect_back": cb,
	})
}

// GET /api/listeners/{name} — session snapshot.
func (s *Server) listenerSessions(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sessions, ok := s.listeners.Get(name)
	if !ok {
		writeErr(w, 404, "listener does not exist: "+name)
		return
	}
	writeJSON(w, 200, map[string]any{"name": name, "sessions": sessions})
}

// POST /api/listeners/{name}/stop — stop and return the final snapshot.
func (s *Server) listenerStop(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sessions, err := s.listeners.Stop(name)
	stopRelayTunnel(name) // the ssh relay tunnel goes with the listener (no-op when none)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"stopped": name, "sessions": sessions})
}
