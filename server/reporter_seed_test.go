package server

import (
	"testing"

	"github.com/chu0119/pojun/db"
)

// The reporter's seed uses a settings flag as a 'once only' guard. Returning immediately
// when flag=true means an **agent present but triggers missing** state can never be
// repaired.
//
// Hit in practice (2026-10-21 full reset): TRUNCATE ... CASCADE also cleared
// agent_triggers, the reporter's report_finding trigger vanished while the flag stayed
// true. Result: vuln reports no longer auto-triggered the report agent → nobody verified
// and bound traffic evidence → HTTP evidence missing throughout reports
// (traffic_evidence_snapshots / finding_traffic_bindings both at 0 rows).
//
// Fix: even with flag=true, run a 'fill in missing items' pass without overwriting what
// exists.
func TestSeedReporterAgentRepairsMissingTrigger(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// isolation: back up the reporter's triggers and flag, restore after.
	origTriggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	origFlag, _, _ := pg.GetSetting("reporter_agent_seed_v1")
	t.Cleanup(func() {
		for _, tr := range origTriggers {
			_ = pg.DeleteTrigger(tr.ID)
		}
		for _, tr := range origTriggers {
			_, _ = pg.CreateTrigger(&db.AgentTrigger{
				AgentKey:        tr.AgentKey,
				Enabled:         tr.Enabled,
				IntervalSec:     tr.IntervalSec,
				OnToolCall:      tr.OnToolCall,
				ToolNames:       tr.ToolNames,
				ToolCallMessage: tr.ToolCallMessage,
			})
		}
		_ = pg.SetSetting("reporter_agent_seed_v1", origFlag)
	})

	// setup: reporter agent exists, flag=true, all triggers deleted
	if _, err := pg.GetAgentByKey("reporter"); err != nil {
		t.Skipf("reporter agent missing (%v) — skipping", err)
	}
	for _, tr := range origTriggers {
		if err := pg.DeleteTrigger(tr.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.SetSetting("reporter_agent_seed_v1", "true"); err != nil {
		t.Fatal(err)
	}
	if list, _ := pg.ListTriggersFor("reporter"); len(list) != 0 {
		t.Fatalf("precondition: triggers should be empty, got %d", len(list))
	}

	// run seed — the flag is already true; the old implementation returned immediately
	// (triggers unrecoverable)
	s := &Server{m: &Manager{pg: pg}}
	s.seedReporterAgent()

	list, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tr := range list {
		if tr.OnToolCall && containsString(tr.ToolNames, "report_finding") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("report_finding trigger was not repaired: %+v", list)
	}
}
