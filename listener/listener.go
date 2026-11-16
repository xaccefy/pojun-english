// Package listener implements TCP callback receivers for red team
// operations: catch reverse-shell callbacks and OOB connections while the agent
// does other work, and record every session as evidence.
//
// Design boundaries (deliberately out of scope):
//   - No interactive shell manager (that is a C2 framework's job; Sliver/Mythic are
//     integration targets, not competitors). The listener only "catches the
//     connection + preserves evidence"; interactive work is done by the agent with
//     nc/socat from Bash.
//   - Capture is bounded (64KB preview per session) so a target cannot use the
//     listener as a data pump and exhaust memory.
//   - The port whitelist defaults to 1024-65535 (binding low ports needs root, which
//     the service user does not have; for real 80/443 use hostd or port forwarding).
//
// Concurrency model: one accept goroutine per listener + one reader goroutine per
// connection; Manager.mu guards the listeners map. Stop shuts down gracefully
// (close accept, close every connection).
package listener

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// MaxCapturePerSession is the per-session capture byte limit (flood protection).
	MaxCapturePerSession = 64 * 1024
	// MaxSessionsPerListener is the per-listener session cap. Listeners are exposed to
	// the internet by design; without a cap a single scanner could pile session list
	// entries and goroutines up until memory is exhausted.
	MaxSessionsPerListener = 2000
	// MinPort/MaxPort is the port range that may be bound.
	MinPort = 1024
	MaxPort = 65535
)

// Session is the record of one callback.
type Session struct {
	ID          string    `json:"id"`
	Remote      string    `json:"remote"`
	ConnectedAt time.Time `json:"connected_at"`
	LastActive  time.Time `json:"last_active"`
	BytesIn     int64     `json:"bytes_in"`
	// Preview is the first MaxCapturePerSession bytes captured (UTF-8 tolerant decode).
	// The reverse shell's initial output, OOB request lines and banners all land here.
	Preview string `json:"preview"`
	Open    bool   `json:"open"`

	conn net.Conn // used to close an evicted session so its reader goroutine exits naturally
}

// Listener is a running callback receiver.
type Listener struct {
	Name      string     `json:"name"`
	Port      int        `json:"port"`
	StartedAt time.Time  `json:"started_at"`
	Sessions  []*Session `json:"sessions"`

	mu   sync.Mutex
	ln   net.Listener
	ctx  context.Context
	stop context.CancelFunc
}

// appendSession records a new connection; when the session cap is reached it first
// evicts the oldest closed session, and if all are still open it evicts the oldest
// one and closes it, keeping the session list bounded.
func (l *Listener) appendSession(s *Session) {
	var evicted *Session
	l.mu.Lock()
	if len(l.Sessions) >= MaxSessionsPerListener {
		drop := 0
		for i := range l.Sessions {
			if !l.Sessions[i].Open {
				drop = i
				break
			}
		}
		evicted = l.Sessions[drop]
		l.Sessions = append(l.Sessions[:drop], l.Sessions[drop+1:]...)
	}
	l.Sessions = append(l.Sessions, s)
	l.mu.Unlock()
	if evicted != nil && evicted.conn != nil {
		_ = evicted.conn.Close()
	}
}

// Snapshot returns a copy of the session list (newest connection first).
func (l *Listener) Snapshot() []Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Session, 0, len(l.Sessions))
	for i := len(l.Sessions) - 1; i >= 0; i-- {
		out = append(out, *l.Sessions[i])
	}
	return out
}

// Manager manages all listeners (a process-level singleton owned by server).
type Manager struct {
	mu        sync.Mutex
	listeners map[string]*Listener
}

// NewManager constructs a Manager.
func NewManager() *Manager {
	return &Manager{listeners: map[string]*Listener{}}
}

// validateName validates a listener name (guards against path-like injection; it is
// only ever used as a key).
func validateName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("name must be 1-64 characters")
	}
	for _, r := range name {
		ok := r == '-' || r == '_' || r == '.' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return fmt.Errorf("name may only contain letters, digits and -_.")
		}
	}
	return nil
}

// Start starts a listener. The port must be within MinPort-MaxPort; a duplicate name
// is an error.
func (m *Manager) Start(name string, port int) (*Listener, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if port < MinPort || port > MaxPort {
		return nil, fmt.Errorf("port must be within %d-%d (low ports need privileges; use port forwarding)", MinPort, MaxPort)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.listeners[name]; ok {
		return nil, fmt.Errorf("listener %q already exists", name)
	}
	// Two listeners competing for the same port fail naturally at net.Listen, so no
	// extra duplicate check is needed.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to bind :%d: %w", port, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	l := &Listener{Name: name, Port: port, StartedAt: time.Now(), ln: ln, ctx: ctx, stop: stop}
	m.listeners[name] = l
	go l.acceptLoop()
	return l, nil
}

// acceptLoop accepts callbacks, one reader goroutine per connection.
func (l *Listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // listener already closed
		}
		if l.ctx.Err() != nil {
			_ = conn.Close()
			return
		}
		go l.handleConn(conn)
	}
}

// handleConn captures one session: remote address, timestamps, bounded preview. The
// connection stays open (a callback shell/banner usually keeps it open) and is
// finished when the remote closes or the listener stops.
func (l *Listener) handleConn(conn net.Conn) {
	s := &Session{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Remote:      conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
		Open:        true,
		conn:        conn,
	}
	l.appendSession(s)
	defer func() {
		// Field writes must share the lock with Snapshot's reads, otherwise reads dangle
		// (-race reports it).
		l.mu.Lock()
		s.Open = false
		l.mu.Unlock()
		_ = conn.Close()
	}()
	buf := make([]byte, 4096)
	var captured int
	for {
		if l.ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			l.mu.Lock()
			s.LastActive = time.Now()
			s.BytesIn += int64(n)
			if captured < MaxCapturePerSession {
				take := n
				if captured+take > MaxCapturePerSession {
					take = MaxCapturePerSession - captured
				}
				s.Preview += string(buf[:take])
				// Coarse handling of non-printable garbage is left to serialization (JSON
				// escapes it); no scrubbing here.
				captured += take
			}
			l.mu.Unlock()
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // a read timeout is not a close: a callback shell may stay silent for a long time
			}
			return // remote closed
		}
	}
}

// Stop stops a listener and returns its final session snapshot.
func (m *Manager) Stop(name string) ([]Session, error) {
	m.mu.Lock()
	l, ok := m.listeners[name]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("listener %q does not exist", name)
	}
	delete(m.listeners, name)
	m.mu.Unlock()
	l.stop()
	_ = l.ln.Close()
	// Give the reader goroutines a moment to finish and mark Open=false.
	time.Sleep(200 * time.Millisecond)
	return l.Snapshot(), nil
}

// Get returns a listener's session snapshot.
func (m *Manager) Get(name string) ([]Session, bool) {
	m.mu.Lock()
	l, ok := m.listeners[name]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	return l.Snapshot(), true
}

// List returns all running listeners (sorted by name).
func (m *Manager) List() []*Listener {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
