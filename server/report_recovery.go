package server

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"
)

// Back-fills empty reports (v0.4.63: boot scan + standing sweep).
//
// Hit twice in production: the backend restarted (one-click update/deploy) while the
// reporter was mid-write, the session got interrupted, and the finding's report was
// left empty — task #5's finding#24 was exactly this (log: 'run interrupted: backend
// process shutting down; stopped at model output stage'). Triggered reporters only
// queue at the report_finding moment — after a restart nothing remembers this vuln
// still lacks a report; a reporter crash or empty model reply leaves it empty too.
//
// First sweep 45s after boot, then every 15 minutes: findings with empty reports, an
// undeleted task, and age >20 minutes get a fresh reporter session each; the same
// finding is retried with exponential backoff (1/2/4/8h), at most reportRecoverMaxTries
// times (count and last-attempt stored in settings) so restart storms don't flood;
// past the cap, auto-retry stops and one alert is emitted (v0.4.63).

// reportRecoverMaxTries is the per-finding auto-backfill attempt cap.
const reportRecoverMaxTries = 6

func (s *Server) recoverEmptyFindingReports() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	time.Sleep(45 * time.Second) // let the engine restore tasks and schedulers get ready — don't fight startup
	for {
		s.recoverEmptyReportsOnce()
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(15 * time.Minute):
			// standing sweep: not just at boot — a reporter can crash mid-run, the model
			// can answer empty, or a user can delete a report; the 15-minute round is
			// the backstop (same finding isn't re-triggered within an hour).
		}
	}
}

func (s *Server) recoverEmptyReportsOnce() {
	rows, err := s.m.pg.Query(`
SELECT f.id, f.node_id, f.severity, left(f.name, 80), f.task_id
FROM findings f JOIN tasks t ON t.id = f.task_id
WHERE length(f.report) = 0 AND t.deleted_at IS NULL
  AND f.created_at > now() - interval '7 days'
  -- only back-fill the genuinely interrupted: findings under 20 minutes old may still
  -- have their triggered reporter writing — don't double-trigger
  AND f.created_at < now() - interval '20 minutes'
ORDER BY f.created_at DESC LIMIT 20`)
	if err != nil {
		log.Printf("[reporter] empty-report backfill: query failed: %v", err)
		return
	}
	type item struct {
		findingID int64
		// nodeID can be NULL: findings.node_id is nulled when the exploration node is
		// deleted (ON DELETE SET NULL). These vulns still need reports — they just get
		// triggered without a node id.
		nodeID   sql.NullInt64
		taskID   int64
		severity string
		name     string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.findingID, &it.nodeID, &it.severity, &it.name, &it.taskID); err != nil {
			log.Printf("[reporter] empty-report backfill: row scan failed: %v", err)
			continue
		}
		items = append(items, it)
	}
	_ = rows.Close()
	triggered := 0
	for _, it := range items {
		nodeID := it.nodeID.Int64
		key := fmt.Sprintf("report_recover_%d", it.findingID)
		triesKey := fmt.Sprintf("report_recover_tries_%d", it.findingID)
		tries := 0
		if v, ok, _ := s.m.pg.GetSetting(triesKey); ok {
			tries, _ = strconv.Atoi(v)
		}
		// v0.4.63: attempt cap + exponential backoff. Production measurement
		// (finding#143): while the LLM config was broken it got triggered hourly ~20
		// times in a row, all wasted tokens — and once the model was fixed it back-
		// filled itself. Cap 6 tries + 1/2/4/8h backoff; past the cap, stop auto-
		// backfilling, alert once, hand to a human.
		if tries >= reportRecoverMaxTries {
			if tries == reportRecoverMaxTries {
				log.Printf("[reporter] finding #%d hit the %d-try auto-backfill cap, stopping retries (report still empty — check the model config or write it manually)", it.findingID, tries)
				_ = s.m.pg.SetSetting(triesKey, strconv.Itoa(tries+1)) // alert only once
			}
			continue
		}
		backoff := time.Hour << uint(min(tries, 3)) // 1h -> 2h -> 4h -> 8h ceiling
		if v, ok, _ := s.m.pg.GetSetting(key); ok {
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil && time.Since(time.Unix(ts, 0)) < backoff {
				continue
			}
		}
		_ = s.m.pg.SetSetting(key, strconv.FormatInt(time.Now().Unix(), 10))
		_ = s.m.pg.SetSetting(triesKey, strconv.Itoa(tries+1))
		where := fmt.Sprintf("finding #%d", it.findingID)
		if nodeID > 0 {
			where = fmt.Sprintf("finding #%d, exploration node %d", it.findingID, nodeID)
		}
		msg := fmt.Sprintf("[Report backfill] the report for vuln %s (%s) is still empty — the previous write was interrupted (backend restart / session crash). "+
			"Review the existing evidence/traffic, then call update_finding_report(finding_id=%d, report=<full Markdown>) to finish it; "+
			"even with insufficient evidence, finish and honestly note it under 'unverified scope'.",
			it.severity, where, it.findingID)
		triggered++
		log.Printf("[reporter] backfilling empty report: finding #%d (node %d)", it.findingID, nodeID)
		// the public StartTriggeredRun has no findingNodeID param: the finding anchor is
		// already in the message (update_finding_report only takes finding_id) — the
		// triggered reporter writes by finding_id.
		s.StartTriggeredRun("reporter", fmt.Sprintf("Report backfill · finding#%d", it.findingID), msg, it.taskID, false, "", "")
	}
	if len(items) > 0 {
		log.Printf("[reporter] empty-report sweep: %d candidates, %d triggered this round", len(items), triggered)
	}
}
