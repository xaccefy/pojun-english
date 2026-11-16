package listener

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// Once the session cap is reached, sessions must be evicted rather than growing
// without bound; closed sessions are evicted first.
func TestAppendSessionCapsAndEvictsClosed(t *testing.T) {
	l := &Listener{}
	for i := 0; i < MaxSessionsPerListener; i++ {
		l.appendSession(&Session{ID: fmt.Sprintf("s%d", i), Open: false})
	}
	l.appendSession(&Session{ID: "newest", Open: true})
	snap := l.Snapshot()
	if len(snap) != MaxSessionsPerListener {
		t.Fatalf("sessions=%d, should always be %d", len(snap), MaxSessionsPerListener)
	}
	if snap[0].ID != "newest" {
		t.Fatalf("the snapshot should be newest-first, first entry was %q", snap[0].ID)
	}
	for _, s := range snap {
		if s.ID == "s0" {
			t.Fatal("the oldest closed session should be evicted first")
		}
	}
}

// When all are still open, evict the oldest and close its connection so neither
// sessions nor goroutines leak.
func TestAppendSessionEvictsOpenAndClosesConn(t *testing.T) {
	l := &Listener{}
	peer, openConn := net.Pipe()
	defer peer.Close()
	victim := &Session{ID: "victim", Open: true, conn: openConn}
	l.appendSession(victim) // the oldest one, and it carries a connection
	for i := 0; i < MaxSessionsPerListener-1; i++ {
		l.appendSession(&Session{ID: fmt.Sprintf("open%d", i), Open: true})
	}
	l.appendSession(&Session{ID: "newest", Open: true})

	// The evicted session's connection must be closed: a peer read then fails at once
	// instead of blocking forever.
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err == nil {
		t.Fatal("the evicted session's connection should be closed")
	}
	snap := l.Snapshot()
	if len(snap) != MaxSessionsPerListener {
		t.Fatalf("sessions=%d, should always be %d", len(snap), MaxSessionsPerListener)
	}
	for _, s := range snap {
		if s.ID == "victim" {
			t.Fatal("the oldest open session should be evicted")
		}
	}
}
