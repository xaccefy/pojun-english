package vulnintel

// StatusSnapshot aggregates the data the status page needs: the sync watermark of each
// source plus the row counts in the database. One query covers it, so the frontend does not
// have to stitch several requests together.
import (
	"context"
	"strings"
	"time"
)

func (s *Store) StatusSnapshot(ctx context.Context) map[string]any {
	sources := []SyncState{}
	rows, err := s.db.QueryContext(ctx, `SELECT source,
		COALESCE(to_char(last_sync_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),''),
		cursor, total_synced, last_error, enabled FROM vuln_sync_state ORDER BY source`)
	if err == nil {
		for rows.Next() {
			var st SyncState
			var last string
			if err := rows.Scan(&st.Source, &last, &st.Cursor, &st.TotalSynced, &st.LastError, &st.Enabled); err == nil {
				if t, e := time.Parse(time.RFC3339, last); e == nil {
					st.LastSyncAt = &t
				}
				sources = append(sources, st)
			}
		}
		rows.Close()
	}
	counts := map[string]int64{}
	for table, q := range map[string]string{
		"cves": `SELECT count(*) FROM vuln_cves`,
		"kev":  `SELECT count(*) FROM vuln_cves WHERE kev`,
		"pocs": `SELECT count(*) FROM vuln_pocs`,
		"ghsa": `SELECT count(*) FROM vuln_cves WHERE source='ghsa'`,
	} {
		var n int64
		_ = s.db.QueryRowContext(ctx, q).Scan(&n)
		counts[table] = n
	}
	return map[string]any{
		"sources": sources,
		"counts":  counts,
	}
}

// EgressHint reads the user-configured note on callback-reachable addresses
// (settings.egress_hint).
func (s *Store) EgressHint(ctx context.Context) string {
	var v string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='egress_hint'`).Scan(&v)
	return strings.TrimSpace(v)
}

// EgressPortMap reads the port mapping note (settings.egress_port_map), e.g.
// "4444-4450:4444-4450".
func (s *Store) EgressPortMap(ctx context.Context) string {
	var v string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='egress_port_map'`).Scan(&v)
	return strings.TrimSpace(v)
}
