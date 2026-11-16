// Server-side wiring for asset-graph linkage: after a vulnintel sync, attach new CVE
// hits against asset fingerprints as hints on affected tasks' exploration graphs. Kept
// in its own file, not mixed into manager.go.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/vulnintel"
)

// linkVulnIntelAssets runs after each vulnintel sync pass: newly synced CVEs
// are matched against service assets' technology fingerprints; every affected
// task gets ONE hint per asset (aggregated CVE list), linked (anchored) to the
// asset so the planner reads it next round and the lineage is explicit.
// Best-effort: errors are logged, never fatal to the sync.
func (m *Manager) linkVulnIntelAssets() {
	m.mu.RLock()
	vi := m.vulnintel
	m.mu.RUnlock()
	if vi == nil {
		return
	}
	ctx := context.Background()
	since := time.Now().Add(-7 * 24 * time.Hour) // overlaps the incremental window to avoid misses
	res, err := vi.LinkAssetsToVulns(ctx, since)
	if err != nil {
		log.Printf("[vulnintel] asset-link query failed: %v", err)
		return
	}
	if len(res.Matches) == 0 {
		return
	}
	// aggregate task → asset → matches; fetch exploration ids in bulk.
	perTask := map[int64]map[int64][]vulnintel.AssetVulnMatch{}
	taskIDs := []int64{}
	seenTask := map[int64]bool{}
	for _, mt := range res.Matches {
		if mt.TaskID <= 0 {
			continue
		}
		if !seenTask[mt.TaskID] {
			seenTask[mt.TaskID] = true
			taskIDs = append(taskIDs, mt.TaskID)
		}
		if perTask[mt.TaskID] == nil {
			perTask[mt.TaskID] = map[int64][]vulnintel.AssetVulnMatch{}
		}
		perTask[mt.TaskID][mt.AssetID] = append(perTask[mt.TaskID][mt.AssetID], mt)
	}
	expOf := map[int64]int64{}
	rows, err := m.pg.Query(`SELECT id, exploration_id FROM tasks WHERE id = ANY($1)`, taskIDs)
	if err != nil {
		log.Printf("[vulnintel] asset-link task fetch failed: %v", err)
		return
	}
	for rows.Next() {
		var id, exp int64
		if err := rows.Scan(&id, &exp); err == nil {
			expOf[id] = exp
		}
	}
	rows.Close()

	added := 0
	for taskID, perAsset := range perTask {
		exp, ok := expOf[taskID]
		if !ok || exp <= 0 {
			continue
		}
		ts := m.pg.Exploration(exp)
		// debounce: every 6h sync round re-hits the same assets — skip when the last 24h
		// of hints already contain the same asset segment ("asset(id=N)"). Hint count is
		// bounded per task (cap 500).
		recent, err := ts.ListByKind(db.KindHint, 500)
		if err != nil {
			log.Printf("[vulnintel] task %d hint read failed (skipping debounce): %v", taskID, err)
			recent = nil
		}
		alerted := map[int64]bool{}
		day := time.Now().Add(-24 * time.Hour)
		for _, n := range recent {
			var p struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			if !strings.HasPrefix(p.Text, intelHintPrefix) {
				continue
			}
			if !n.CreatedAt.IsZero() && n.CreatedAt.Before(day) {
				continue
			}
			for _, mt := range res.Matches {
				if strings.Contains(p.Text, assetTag(mt.AssetID)) {
					alerted[mt.AssetID] = true
				}
			}
		}
		for assetID, ms := range perAsset {
			if alerted[assetID] {
				continue
			}
			text := intelHintPrefix + vulnintel.FormatHint(ms, assetID)
			// "human" author slot = platform-injected hint, visible from the same source as
			// manual add_hint in the UI.
			if _, err := ts.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", "human", []int64{assetID}); err != nil {
				log.Printf("[vulnintel] task %d intel hint attach failed: %v", taskID, err)
				continue
			}
			added++
		}
	}
	log.Printf("[vulnintel] asset link: %d assets hit, %d hints attached (%d tasks)",
		res.MatchedAssets, added, len(perTask))
}

// intelHintPrefix is the linkage hint's dedupe prefix (FormatHint's body starts with
// "[intel link]"; the prefix is added in the same place, and debounce matching uses
// it).
const intelHintPrefix = "[intel link]"

// assetTag returns the substring FormatHint writes for one asset, used for
// dedup matching against existing hints' text.
func assetTag(assetID int64) string {
	return fmt.Sprintf("asset(id=%d)", assetID)
}
