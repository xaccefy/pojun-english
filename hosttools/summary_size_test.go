package hosttools

import (
	"encoding/json"
	"strings"
	"testing"
)

// The tool list with purposes inside graph_overview must not blow up the context — it
// goes into the prompt every turn.
func TestSummaryStaysCompact(t *testing.T) {
	s := Summary()
	b, _ := json.Marshal(s)
	if len(b) > 4000 {
		t.Errorf("tool list is %d bytes, too large and will blow up the per-turn prompt", len(b))
	}
	// Every entry must carry its purpose (the model needs to know what the tool is for)
	avail, _ := s["available"].([]string)
	withPurpose := 0
	for _, a := range avail {
		if strings.Contains(a, ": ") {
			withPurpose++
		}
	}
	if len(avail) > 0 && withPurpose < len(avail) {
		t.Errorf("only %d/%d entries carry a purpose", withPurpose, len(avail))
	}
	t.Logf("available=%d missing=%d bytes=%d", len(avail), len(s["missing"].([]string)), len(b))
}
