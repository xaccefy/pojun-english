package notify

// Snapshot is the contract of the notification_events.snapshot JSONB column. Writers are the
// db layer's vuln-insert transactions; readers are the server layer's delivery engine and
// filter matcher. It lives here because it is the 'notification domain' payload: db only
// serializes it without understanding the fields.
//
// Why store vuln fields redundantly instead of re-reading at render time: a vuln may be
// renamed, re-leveled or re-stated later, while the push must reflect the conclusion **at
// event time** — re-reading could misleadingly report 'later changed to low'. It also frees
// fan-out and rendering from JOINing findings/tasks/assets.
type Snapshot struct {
	// Event kind: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Non-empty only for kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is a vuln awaiting push, for channel rendering.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets holds resolved asset display names (e.g. domain/IP). Filled by the server layer —
	// this package never touches the database, so it can't look up names.
	Assets []string
	// DetailURL is the vuln-detail deep link; empty means public_base_url unset — omitted at render.
	DetailURL string
	// Status-change events only; when both are set they render as "Pending → Fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether the item is a status-change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the item's display title: prefer the human-given name, fall back to the
// vulnclass, and use a placeholder when both are empty — never emit an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(unnamed vuln)"
}

// Message is the full content of one channel send.
type Message struct {
	// Length 1 for a realtime push; a whole batch for a digest push.
	// An empty slice is invalid — the caller must supply at least one.
	Items []Item
	// Batch=true renders a digest message (different title, with window and count).
	Batch bool
	// WindowMinutes is the digest period in minutes, used only when Batch=true for the
	// 'last N minutes' phrasing. Passed in explicitly rather than computed via time.Since at
	// render — keeps rendering deterministic and testable.
	WindowMinutes int
	// HomeURL is the platform panel address (global public_base_url); empty = no panel link.
	HomeURL string
}
