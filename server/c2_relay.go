// C2 egress config (optional feature): solves 'what to put in the connect-back
// address'. Three network shapes:
//
//	direct — the POJUN host can reach the target network (public IP or same
//	         intranet): LHOST = local NIC address (net_context already has it),
//	         LPORT = listener port.
//	ssh    — the POJUN host has no public IP but the user owns a public relay host:
//	         POJUN builds an SSH reverse tunnel automatically (ssh -R
//	         relay-port→local-listen-port); LHOST/LPORT use the relay's public
//	         address. The tunnel is platform-managed (auto-reconnect), torn down when
//	         the listener stops.
//	manual — the user already configured port forwarding on a public host by hand:
//	         the platform only shows the relay address in connect-back info, no tunnel
//	         management.
//
// Everything optional: unconfigured ≡ direct (falls back to net_context's local
// address).
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// netInterfaceAddrs lists a NIC's addresses (CIDR form).
func netInterfaceAddrs(name string) ([]string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out, nil
}

// netDialUDP builds a packet-less UDP 'connection' to learn the default-route source
// address.
func netDialUDP(target string) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, raddr)
}

// C2 egress setting keys.
const (
	settingC2RelayMode  = "c2_relay_mode"  // direct | ssh | manual (default direct)
	settingC2RelayHost  = "c2_relay_host"  // relay host public address (connect-back LHOST)
	settingC2RelaySSH   = "c2_relay_ssh"   // SSH reverse-tunnel target "user@host:port"
	settingC2RelayPass  = "c2_relay_pass"  // SSH password (empty = use key); redacted on echo
	settingC2RelayKey   = "c2_relay_key"   // SSH private-key path (optional, beats password)
	settingC2RelayIface = "c2_relay_iface" // direct-mode NIC (empty = auto-pick default-route NIC)
)

// ConnectBack is the connect-back parameter for agents (what to put in the payload's
// LHOST/LPORT).
type ConnectBack struct {
	Mode  string `json:"mode"`  // direct | ssh | manual
	LHOST string `json:"lhost"` // the address targets should connect to
	LPORT int    `json:"lport"` // the port targets should connect to
	Via   string `json:"via,omitempty"`
}

// c2RelayCfg is the parsed current config.
type c2RelayCfg struct {
	Mode  string
	Host  string
	SSH   string
	Pass  string
	Key   string
	Iface string
}

func (s *Server) c2RelayConfig() c2RelayCfg {
	cfg := c2RelayCfg{Mode: "direct"}
	if s.m == nil || s.m.pg == nil {
		return cfg
	}
	if v, _, _ := s.m.pg.GetSetting(settingC2RelayMode); strings.TrimSpace(v) != "" {
		cfg.Mode = strings.TrimSpace(v)
	}
	cfg.Host, _, _ = s.m.pg.GetSetting(settingC2RelayHost)
	cfg.SSH, _, _ = s.m.pg.GetSetting(settingC2RelaySSH)
	cfg.Pass, _, _ = s.m.pg.GetSetting(settingC2RelayPass)
	cfg.Key, _, _ = s.m.pg.GetSetting(settingC2RelayKey)
	cfg.Iface, _, _ = s.m.pg.GetSetting(settingC2RelayIface)
	return cfg
}

// ResolveConnectBack resolves the listen port into the address targets should connect
// to. ssh mode: LPORT = local listen port (the tunnel forwards 1:1 to the same relay
// port — trivial rule, no lookup table for agent or human troubleshooting); LHOST =
// relay host public address.
func (s *Server) ResolveConnectBack(listenerPort int) ConnectBack {
	cfg := s.c2RelayConfig()
	switch strings.TrimSpace(cfg.Mode) {
	case "ssh", "manual":
		if strings.TrimSpace(cfg.Host) != "" {
			return ConnectBack{Mode: cfg.Mode, LHOST: strings.TrimSpace(cfg.Host), LPORT: listenerPort,
				Via: "relay " + strings.TrimSpace(cfg.Host)}
		}
	}
	return ConnectBack{Mode: "direct", LHOST: s.localIPFor(cfg.Iface), LPORT: listenerPort}
}

// localIPFor returns the local egress address (a compact version of the net_context
// tool's approach): a specified NIC's address if given; otherwise a UDP 'dial' to
// 8.8.8.8:80 yields the default-route source (no packets sent); on total failure falls
// back to 127.0.0.1.
func (s *Server) localIPFor(iface string) string {
	if strings.TrimSpace(iface) != "" {
		if addrs, err := netInterfaceAddrs(iface); err == nil {
			for _, a := range addrs {
				if ip := strings.Split(a, "/")[0]; ip != "" && ip != "127.0.0.1" {
					return ip
				}
			}
		}
	}
	c, err := netDialUDP("8.8.8.8:80")
	if err == nil {
		defer func() { _ = c.Close() }()
		if addr := c.LocalAddr().String(); strings.Contains(addr, ":") {
			if ip := strings.Split(addr, ":")[0]; ip != "" {
				return ip
			}
		}
	}
	return "127.0.0.1"
}

// ── SSH reverse-tunnel management ──────────────────────────────────

// relayTunnels manages one SSH reverse-tunnel process per listener.
type relayTunnels struct {
	mu      sync.Mutex
	byName  map[string]*exec.Cmd
	cancels map[string]context.CancelFunc
}

var relayTunnelMgr = &relayTunnels{byName: map[string]*exec.Cmd{}, cancels: map[string]context.CancelFunc{}}

// startRelayTunnel builds a listener's SSH reverse tunnel: relay :port → local
// 127.0.0.1:port. ExitOnForwardFailure + ServerAlive keepalive; on process exit a
// goroutine reconnects with exponential backoff until the listener stops (ctx
// cancelled).
func (s *Server) startRelayTunnel(name string, port int) error {
	cfg := s.c2RelayConfig()
	if strings.TrimSpace(cfg.SSH) == "" {
		return fmt.Errorf("ssh relay not configured (c2_relay_ssh = user@host:port)")
	}
	userHost, sshPort := cfg.SSH, "22"
	if i := strings.LastIndex(cfg.SSH, ":"); i > 0 {
		userHost, sshPort = cfg.SSH[:i], cfg.SSH[i+1:]
	}
	key, pass := strings.TrimSpace(cfg.Key), strings.TrimSpace(cfg.Pass)
	// rebuild Cmd on every reconnect: a used exec.Cmd can't be reused (or copied by
	// value).
	build := func() *exec.Cmd {
		args := []string{
			"-N", "-T",
			"-o", "ExitOnForwardFailure=yes",
			"-o", "ServerAliveInterval=15",
			"-o", "ServerAliveCountMax=4",
			"-o", "StrictHostKeyChecking=accept-new",
			"-p", sshPort,
			"-R", fmt.Sprintf("0.0.0.0:%d:127.0.0.1:%d", port, port),
		}
		var cmd *exec.Cmd
		switch {
		case key != "":
			args = append(args, "-i", key, "-o", "BatchMode=yes", userHost)
			cmd = exec.Command("ssh", args...)
		case pass != "":
			// password auth goes through sshpass (apt install sshpass on Kali/Ubuntu).
			args = append(args, userHost)
			cmd = exec.Command("sshpass", append([]string{"-e"}, args...)...)
			cmd.Env = append(cmd.Environ(), "SSHPASS="+pass)
		default:
			args = append(args, userHost)
			cmd = exec.Command("ssh", args...)
		}
		cmd.WaitDelay = time.Second
		return cmd
	}

	first := build()
	if err := first.Start(); err != nil {
		return fmt.Errorf("failed to start the SSH relay: %w", err)
	}
	// the tunnel's lifecycle follows the listener, not the HTTP request context (a
	// request-end cancel would kill the tunnel).
	tunnelCtx, cancel := context.WithCancel(context.Background())

	relayTunnelMgr.mu.Lock()
	relayTunnelMgr.byName[name] = first
	relayTunnelMgr.cancels[name] = cancel
	relayTunnelMgr.mu.Unlock()

	go func() {
		cmd := first
		backoff := 3 * time.Second
		for {
			waitErr := cmd.Wait()
			if tunnelCtx.Err() != nil {
				return // listener stopped: normal exit
			}
			log.Printf("[c2] SSH relay tunnel dropped (%s :%d): %v — reconnecting in %s", name, port, waitErr, backoff)
			for {
				select {
				case <-tunnelCtx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < time.Minute {
					backoff *= 2
				}
				next := build()
				if err := next.Start(); err != nil {
					log.Printf("[c2] SSH relay reconnect failed (%s :%d): %v", name, port, err)
					continue
				}
				cmd = next
				relayTunnelMgr.mu.Lock()
				relayTunnelMgr.byName[name] = cmd
				relayTunnelMgr.mu.Unlock()
				break
			}
		}
	}()
	log.Printf("[c2] SSH relay tunnel up (%s): relay :%d -> local 127.0.0.1:%d", name, port, port)
	return nil
}

// stopRelayTunnel tears down a listener's tunnel: cancel reconnects first, then end
// the current process. Cancel-without-kill leaves ssh holding the reverse tunnel (the
// port never frees and a reconnected old process fights the new one).
func stopRelayTunnel(name string) {
	relayTunnelMgr.mu.Lock()
	cancel := relayTunnelMgr.cancels[name]
	cmd := relayTunnelMgr.byName[name]
	delete(relayTunnelMgr.byName, name)
	delete(relayTunnelMgr.cancels, name)
	relayTunnelMgr.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// ── REST ────────────────────────────────────────────────────────────

// GET /api/c2/config — echoes the current C2 egress config (password redacted).
func (s *Server) c2ConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.c2RelayConfig()
	writeJSON(w, 200, map[string]any{
		"mode":     cfg.Mode,
		"host":     cfg.Host,
		"ssh":      cfg.SSH,
		"key":      cfg.Key,
		"iface":    cfg.Iface,
		"has_pass": cfg.Pass != "",
	})
}

// PUT /api/c2/config — saves the C2 egress config. nil fields keep their values; mode
// accepts only direct/ssh/manual; send an empty string to clear password.
func (s *Server) c2ConfigPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  *string `json:"mode"`
		Host  *string `json:"host"`
		SSH   *string `json:"ssh"`
		Pass  *string `json:"password"`
		Key   *string `json:"key"`
		Iface *string `json:"iface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Mode != nil {
		m := strings.TrimSpace(*req.Mode)
		if m != "direct" && m != "ssh" && m != "manual" {
			writeErr(w, 400, "mode must be direct/ssh/manual")
			return
		}
		if err := s.m.pg.SetSetting(settingC2RelayMode, m); err != nil {
			writeErr(w, 500, "failed to save mode: "+err.Error())
			return
		}
	}
	// a failed save must report an error — a 200 on a lost write leaves the user with
	// the wrong connect-back address on the next reconnect.
	put := func(key string, v *string) error {
		if v == nil {
			return nil
		}
		return s.m.pg.SetSetting(key, *v)
	}
	for _, kv := range []struct {
		key string
		val *string
	}{
		{settingC2RelayHost, req.Host},
		{settingC2RelaySSH, req.SSH},
		{settingC2RelayPass, req.Pass},
		{settingC2RelayKey, req.Key},
		{settingC2RelayIface, req.Iface},
	} {
		if err := put(kv.key, kv.val); err != nil {
			writeErr(w, 500, "failed to save "+kv.key+": "+err.Error())
			return
		}
	}
	s.c2ConfigGet(w, r)
}
