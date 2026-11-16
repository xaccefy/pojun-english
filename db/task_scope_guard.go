package db

import (
	"fmt"
	"strings"
)

// === v0.4.63: authorization boundary guard (hardening layer 4 of the four lines of defense against cross-task asset leakage) ===
//
// Production retrospective (customer environment, task 4): tasks 1/2/3 were testing dkfvtg.cn while new task 4 was testing aibuji.com,
// but a worker attached a JeecgBoot lead from a parallel task's context to aibuji.com (fact #1901 written as
// observed/confirmed), the planner then dispatched in cascade based on that unverified fact, and finally the finding's asset_ids
// carried dkfvtg's assets -- the authorization boundary was a soft constraint from start to finish.
//
// These queries turn "what relation does an asset have to a task" into a deterministic answer, for the write-back gate:
//   own    -- matches this task's own task_scope, or the asset was discovered/registered by this task (task_ids contains this task)
//   source -- only matches the scope of a source/inherited task (task_relations), or was only registered by the source task
//   foreign-- neither (fully out of bounds)
//
// Semantics (the write-back gate, see server/asset_scope_guard.go):
//   own    -> writable;
//   source -> denied by default (inherited scope being read-only is the consistent rule of the dual-graph design; when it really is
//             this task's authorization, include it explicitly with add_task_scope, or have the user enable scope_inherit_writes);
//   foreign-> always denied.

// ownScopeTargetCTE only looks at the scope this task itself declared (not source tasks).
const ownScopeTargetCTE = `
own_scope_assets AS (
  SELECT DISTINCT a.id
  FROM assets a
  JOIN task_scope ts ON (
       (ts.kind='company'     AND a.company_id = ts.company_id)
    OR (ts.kind='root_domain' AND a.root_domain = ts.domain)
    OR (ts.kind='subdomain'   AND a.domain = ts.domain)
    OR (ts.kind IN ('ip','cidr') AND (ts.net >>= try_inet(a.ip) OR ts.net >>= try_inet(a.domain)))
    OR (ts.kind='icp' AND (
         lower(regexp_replace(COALESCE(a.icp,''), '[[:space:]]+', '', 'g')) = ts.value
         OR lower(regexp_replace(COALESCE(a.app_icp,''), '[[:space:]]+', '', 'g')) = ts.value
       ))
  )
  WHERE ts.task_id=$1
)`

// sourceScopeTargetCTE only looks at the scope declared by source/inherited tasks (task_relations).
const sourceScopeTargetCTE = `
source_scope_assets AS (
  SELECT DISTINCT a.id
  FROM assets a
  JOIN task_scope ts ON (
       (ts.kind='company'     AND a.company_id = ts.company_id)
    OR (ts.kind='root_domain' AND a.root_domain = ts.domain)
    OR (ts.kind='subdomain'   AND a.domain = ts.domain)
    OR (ts.kind IN ('ip','cidr') AND (ts.net >>= try_inet(a.ip) OR ts.net >>= try_inet(a.domain)))
    OR (ts.kind='icp' AND (
         lower(regexp_replace(COALESCE(a.icp,''), '[[:space:]]+', '', 'g')) = ts.value
         OR lower(regexp_replace(COALESCE(a.app_icp,''), '[[:space:]]+', '', 'g')) = ts.value
       ))
  )
  JOIN task_relations relation ON relation.source_task_id = ts.task_id
  WHERE relation.task_id=$1
)`

// AssetScopeClass is the attribution class of a single asset with respect to a task.
type AssetScopeClass string

const (
	ScopeClassOwn     AssetScopeClass = "own"
	ScopeClassSource  AssetScopeClass = "source"
	ScopeClassForeign AssetScopeClass = "foreign"
)

// ClassifyAssetsForTask classifies ids into own/source/foreign. It returns an error on query failure and the
// caller decides the failure policy (the gate should fail-open but log, so normal tasks are not all blocked).
func (s *AssetStore) ClassifyAssetsForTask(taskID int64, ids []int64) (own, source, foreign []int64, err error) {
	if len(ids) == 0 {
		return nil, nil, nil, nil
	}
	ph := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, taskID)
	for i, id := range ids {
		ph[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	q := `WITH ` + ownScopeTargetCTE + `, ` + sourceScopeTargetCTE + `
SELECT id,
  CASE
    WHEN id IN (SELECT id FROM own_scope_assets) OR $1::bigint = ANY(task_ids) THEN 'own'
    WHEN id IN (SELECT id FROM source_scope_assets)
      OR EXISTS (SELECT 1
                 FROM unnest(task_ids) u
                 JOIN tasks st ON st.id = u AND st.deleted_at IS NULL
                 JOIN task_relations relation ON relation.source_task_id = st.id
                 WHERE relation.task_id = $1)
      THEN 'source'
    ELSE 'foreign'
  END AS cls
FROM assets WHERE id IN (` + strings.Join(ph, ",") + `)`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var cls string
		if err := rows.Scan(&id, &cls); err != nil {
			return nil, nil, nil, err
		}
		switch AssetScopeClass(cls) {
		case ScopeClassOwn:
			own = append(own, id)
		case ScopeClassSource:
			source = append(source, id)
		default:
			foreign = append(foreign, id)
		}
	}
	return own, source, foreign, rows.Err()
}

// FindForeignAssetForTask uses identity fields (domain/IP/URL prefix) before "insert/claim asset" to reverse-look-up:
// whether an existing asset exists that "does not belong to this task" (task_ids does not contain this task) and "is not in this task's own scope".
// A hit means this insert would silently claim someone else's asset into this task (layer-4 leak in the customer environment's
// cross-asset issue); returns that asset's id and owning task ids; nil when nothing matches.
func (s *AssetStore) FindForeignAssetForTask(taskID int64, domains, ips, urls []string) (id int64, ownerTasks string, err error) {
	if len(domains) == 0 && len(ips) == 0 && len(urls) == 0 {
		return 0, "", nil
	}
	if len(domains) > 16 {
		domains = domains[:16]
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	if len(urls) > 16 {
		urls = urls[:16]
	}
	q := `WITH ` + ownScopeTargetCTE + `
SELECT a.id, COALESCE(array_to_string(a.task_ids, ','), '')
FROM assets a
WHERE NOT ($1::bigint = ANY(a.task_ids))
  AND a.id NOT IN (SELECT id FROM own_scope_assets)
  AND (
        COALESCE(a.domain,'') = ANY($2::text[])
     OR COALESCE(a.root_domain,'') = ANY($2::text[])
     OR (cardinality($3::text[]) > 0 AND COALESCE(a.ip,'') <> ''
         AND EXISTS (SELECT 1 FROM unnest($3::text[]) u WHERE try_inet(a.ip) = try_inet(u)))
     OR EXISTS (SELECT 1 FROM unnest($4::text[]) u
                WHERE u<>'' AND COALESCE(a.url,'')<>''
                  AND (left(a.url, length(u))=u OR left(u, length(a.url))=a.url))
  )
ORDER BY a.id LIMIT 1`
	err = s.db.QueryRow(q, taskID, domains, ips, urls).Scan(&id, &ownerTasks)
	if err != nil {
		return 0, "", nil // no row -> no hit, not treated as an error
	}
	return id, ownerTasks, nil
}
