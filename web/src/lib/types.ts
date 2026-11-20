// POJUN domain model — types used across the UI.
// Derived from the functional spec (section 7: key data shapes).

export type TaskStatus = "created" | "queued" | "running" | "paused" | "done" | "failed" | "timeout";
export type EngineMode = "exploring" | "paused" | "stalled" | "idle";

export interface Task {
  id: string;
  name?: string; // optional task name; empty/absent = unnamed, display falls back to the description
  category_id?: number;
  category_name?: string;
  pinned?: boolean;
  pinned_at?: string | null;
  description: string;
  goal: string;
  status: TaskStatus;
  created_at: string;
  created_unix?: number; // created_at as unix seconds (run-duration calc)
  completed_at?: string; // RFC3339 finish time (done/failed); "" if unfinished
  completed_unix?: number; // completed_at as unix seconds (0/undef if unfinished)
  last_activity_unix?: number; // unix seconds of the last activity (0/undef if none)
  paused?: boolean;
  autopilot?: boolean;
  queued?: boolean;
  active?: boolean;
  in_flight?: number;
  findings?: { critical: number; high: number; medium: number; low: number }; // registered findings count (bucketed by severity)
  last_activity?: string;
  stalled?: boolean;
  goals_total?: number;
  goals_met?: number;
  engine_mode?: EngineMode;
  tokens?: TokenTotal; // whole-task token consumption
  llm_profile_id?: number; // LLM profile used; absent = default profile
  llm_profile_ids?: number[]; // ordered task-level failover chain
  active_llm_profile_id?: number; // profile used by the next LLM call
  llm_failover_state?: "default" | "ready" | "chain_exhausted" | string;
  llm_failover_reason?: string;
  source_task_ids?: string[]; // directly related tasks inherited as read-only context
  archive_blocked_by_task_id?: string; // live direct dependent that must be archived first
  company_ids?: number[]; // associated company scopes; current company assets join the task at creation
  coverage_enabled?: boolean; // asset coverage feature switch (fixed at creation, on by default); false = do not compute/show coverage
  // Task-level login credentials (masked view; omitted when unconfigured)
  auth_config?: TaskAuthConfigView;
}

export interface TaskCategory {
  id: number;
  name: string;
  task_count: number;
  created_at: string;
  updated_at: string;
}

export interface TaskTemplate {
  id: number;
  name: string;
  description: string;
  goal: string;
  category_id?: number | null; // preset category; null/absent = none
  intercept_rules?: AssetInterceptRuleInput[]; // preset task-level intercept/allow rules
  created_at: string;
  updated_at: string;
}

export interface DeleteTaskOptions {
  delete_assets: boolean;
  delete_traffic: boolean;
  delete_files: boolean;
  delete_findings: boolean;
  delete_llm_records: boolean;
}

export interface DeleteTaskResult {
  deleted: string;
  assets_deleted: number;
  assets_detached: number;
  traffic_deleted: number;
  files_deleted: boolean;
  findings_deleted: number;
  llm_records_deleted: number;
  cleanup_warning?: string;
}

export type TaskArchiveState =
  | "archive_queued"
  | "archiving"
  | "archive_failed"
  | "ready"
  | "restore_queued"
  | "restoring"
  | "restore_failed"
  | "delete_queued"
  | "deleting"
  | "delete_failed";

export interface TaskArchiveTokenStats {
  calls?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface TaskArchive {
  id: number;
  task_id: number;
  state: TaskArchiveState;
  phase: string;
  progress: number;
  error?: string;
  warnings?: string[];
  format_version: number;
  sha256?: string;
  original_size: number;
  compressed_size: number;
  task_name: string;
  task_description: string;
  task_goal: string;
  original_status: TaskStatus;
  category_id?: number;
  category_name?: string;
  source_task_ids: number[];
  remaining_timeout_seconds: number;
  data_counts: Record<string, number>;
  aggregate_stats: {
    tokens?: TaskArchiveTokenStats;
    skills?: Record<string, number>;
    tools?: Record<string, number>;
    findings?: Record<string, number>;
  };
  archived_at?: string;
  requested_at: string;
  created_at: string;
  updated_at: string;
}

export interface TaskArchivePage {
  items: TaskArchive[];
  total: number;
  page: number;
  size: number;
}

export interface ArchiveBatchItem {
  id: string;
  archive_id?: number;
  ok: boolean;
  queued: boolean;
  error?: string;
}

// ---- Asset graph (global, shared across tasks) ----
export type AssetType =
  | "company"
  | "domain"
  | "ip"
  | "port"
  | "service"
  | "site"
  | "endpoint"
  | "parameter"
  | "tech"
  | "credential"
  | "data";

export type NodeState = "observed" | "confirmed" | "tombstoned";

export interface AssetNode {
  id: string;
  type: AssetType;
  name: string;
  key: string; // nkey
  value?: string;
  company_id?: string; // owning company asset id; empty = unowned
  state: NodeState;
  confidence: number; // 0..1
  attrs?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export type AssetRel =
  | "owns"
  | "resolves"
  | "exposes"
  | "runs"
  | "serves"
  | "has_endpoint"
  | "has_param"
  | "fingerprinted"
  | "authenticates_as"
  | "reachable"
  | "has_subdomain";

export interface Edge {
  src: string;
  dst: string;
  rel: AssetRel | ExploreRel;
}

// Task asset view — server-side enriched, paginated.
export interface TaskAssetRef {
  id: string;
  name?: string;
  key: string;
  attrs?: Record<string, unknown>;
}

export interface TaskAssetItem extends AssetNode {
  techs?: TaskAssetRef[];
  auth?: TaskAssetRef[];
  params?: TaskAssetRef[];
}

export interface TaskAssetView {
  counts: Record<string, number>;
  total: number;
  items: TaskAssetItem[];
}

// ---- New unified asset model (new backend) ----
export type NewAssetType = "root_domain" | "ip" | "subdomain" | "app" | "service" | "endpoint";

export interface Asset {
  id: number;
  type: NewAssetType;
  company_id?: number;
  task_ids: number[];
  domain?: string;
  root_domain?: string;
  ip?: string;
  c_segment?: string;
  port?: number;
  icp?: string;
  bound_domains?: string[];
  open_ports?: { port: number; service?: string }[];
  record_type?: string;
  record_value?: string[] | string;
  bundle_id?: string;
  app_name?: string;
  category?: string;
  app_description?: string;
  app_icp?: string;
  url?: string;
  service_type?: string;
  service_name?: string;
  favicon_mmh3?: string;
  status_code?: number;
  content_length?: number;
  page_title?: string;
  technologies?: string[];
  auth?: Record<string, unknown>[];
  method?: string;
  params?: Record<string, unknown>[];
  extra?: Record<string, unknown>;
  last_seen: string;
  task_source?: string;
  task_source_summary?: string;
  task_source_node_id?: number;
}

export interface IntentAsset {
  intent_id: number | string;
  asset_id: number;
  type: NewAssetType;
  label: string;
  source: string;
  source_summary: string;
  source_node_id?: number;
  source_task_id: number;
  inherited: boolean;
}

export interface TaskAssetMutation {
  requested: number;
  attached: number;
  existing: number;
}

export interface TaskAssetScopeMutation {
  requested: number;
  assets_linked: number;
  assets_existing: number;
  scopes_added: number;
  scopes_existing: number;
}

// ---- Asset coverage graph (per task) ----
// One node of the force-directed "asset coverage graph". key is unique: asset="a:<id>", company="c:<id>",
// root domain without an asset row="r:<domain>". in_scope=false marks grey context nodes used only for edges.
export interface CoverageGraphNode {
  key: string;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";
  label: string;
  tested: boolean;
  in_scope: boolean;
  asset_id?: number;
  company_id?: number;
  domain?: string;
  root_domain?: string;
  ip?: string;
  url?: string;
  port?: number;
  service_type?: string;
  app_name?: string;
  page_title?: string;
  status_code?: number;
}

export interface CoverageGraphEdge {
  src: string;
  dst: string;
}

export interface CoverageGraphData {
  nodes: CoverageGraphNode[];
  edges: CoverageGraphEdge[];
}

// The intents/facts/findings this asset links to in this task's exploration graph (for the coverage node drawer).
export interface CoverageAssetRef {
  id: number;
  kind: string;
  state: string;
  summary: string;
  source_task_id?: string;
  inherited?: boolean;
}
export interface CoverageAssetRefs {
  intents: CoverageAssetRef[];
  facts: CoverageAssetRef[];
  findings: CoverageAssetRef[];
}

// ---- Workspace file manager (workDir) ----
export interface WorkspaceEntry {
  name: string;
  path: string; // workspace-relative, forward slashes
  dir: boolean;
  size: number;
  mtime: number; // unix millis
}
export interface WorkspaceListing {
  path: string;
  entries: WorkspaceEntry[];
}
export interface WorkspaceFile {
  path: string;
  size: number;
  binary: boolean;
  too_large?: boolean;
  content?: string;
}

// One entry of a task's test scope (the coverage denominator + the authorization boundary).
export interface TaskScopeRow {
  id: number;
  task_id: number;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "cidr" | "icp" | "keyword";
  company_id?: number;
  company_name?: string; // resolved by a backend JOIN on companies, only set when kind=company
  domain?: string;
  net?: string;
  value?: string;
  source: "auto" | "agent" | "manual";
  reason?: string;
}

export type CompanyScopeKind = "domain" | "ip" | "cidr" | "icp" | "keyword";

// Structured asset-scope rules submitted when creating a company.
export interface CompanyScopeRule {
  kind: CompanyScopeKind;
  value: string;
}

// Result of writing asset scope. errors are the invalid lines in this submission; warnings are pre-existing
// data problems unrelated to this submission that would still skew ownership (e.g. an asset whose ip field holds a hostname).
export interface CompanyScopeMutation {
  added: number;
  skipped: number;
  invalid: number;
  errors?: string[];
  warnings?: string[];
}

// One entry of a company's asset-scope rules (the single source of truth for ownership).
export interface ScopeRow {
  id: number;
  company_id: number;
  kind: CompanyScopeKind;
  domain?: string; // set when kind=domain
  net?: string; // set when kind=ip|cidr
  value?: string; // for kind=icp|keyword the backend may return it directly
  raw: string; // original user input, used for display and refill
  reason?: string;
}

// Company: an asset node with type=company + icon + asset count + asset-scope rules.
export interface Company {
  id: number;
  name: string;
  logo?: string; // remote icon URL; empty means the front end uses the name's initials
  asset_count: number;
  scope?: ScopeRow[];
}

// ---- Exploration graph (per task) ----
export type ExploreKind = "task" | "begin" | "goal" | "intent" | "fact" | "finding" | "hint" | "digest";
export type GoalState = "open" | "met" | "abandoned";
export type IntentState = "open" | "running" | "paused" | "done" | "blocked" | "exhausted" | "stopped";
export type FindingState = "confirmed" | "dismissed";
export type HintState = "active" | "consumed";
export type ExploreRel = "spawns" | "derived_from" | "yields" | "proves" | "covers";

export interface TaskNode {
  id: string;
  type: ExploreKind;
  payload?: string;
  priority: number; // 0..10
  state: string; // GoalState | IntentState | FindingState | HintState
  origin: string;
  ts: string;
  source_task_id?: string;
  inherited?: boolean;
  delete_reason?: string; // why the intent was soft-deleted (state='deleted')
  blocked_reason?: string; // why the intent stopped (step cap hit / run timeout / task wrap-up / terminated / error)
}

// One broadcast board page: nodes paged in creation order + the edges touching this page + the nodes at the
// other end of those edges (refs, indexed by id), so each broadcast can explain "where it came from and what
// it produced" without pulling the whole graph down.
export interface ExplorationNodePage {
  items: TaskNode[];
  total: number;
  page: number;
  size: number;
  edges: Edge[];
  refs: Record<string, TaskNode>;
  // node id -> the asset that node is anchored to (shown alongside when a broadcast is expanded, incl. this page's nodes and their neighbours).
  assets: Record<string, FindingAsset[]>;
}

export interface ExplorationNodeQuery {
  page?: number;
  size?: number;
  kinds?: ExploreKind[];
  states?: string[];
  q?: string;
  order?: "asc" | "desc";
}

// A goal for the goal-management card (the backend already split payload into text/vulnclass).
export interface TaskGoal {
  id: string;
  text: string;
  vulnclass?: string;
  state: string; // GoalState
  origin?: string;
  ts: string;
}

// An operating constraint for the constraint-management card (allow=permitted / deny=forbidden).
export type ConstraintKind = "allow" | "deny";
export interface TaskConstraint {
  id: string;
  kind: ConstraintKind;
  text: string;
  origin?: string;
  ts?: string;
}

// ---- Findings ----
export type Severity = "critical" | "high" | "medium" | "low";

// Finding handling status: pending / in progress / confirmed / resolved / fixed / false positive / ignored / duplicate / risk accepted.
export type FindingStatus =
  | "pending"
  | "in_progress"
  | "confirmed"
  | "resolved"
  | "fixed"
  | "false_positive"
  | "ignored"
  | "duplicate"
  | "risk_accepted";

// FindingAsset is an asset a finding is bound to (label pre-rendered by the backend).
export interface FindingAsset {
  id: string;
  type: string;
  label: string;
}

export interface Finding {
  traffic_count?: number;
  evidence_version?: number;
  report_evidence_version?: number;
  report_stale?: boolean;
  id: string;
  finding_id?: string; // row id in the standalone findings table, the handle for status updates (old in-task nodes may be missing)
  vulnclass: string;
  name?: string; // finding name; display falls back to vulnclass when empty
  severity: Severity;
  status: FindingStatus;
  summary: string;
  evidence: string;
  report?: string; // detailed report (Markdown); only returned by the detail endpoint, empty in lists
  intent_id?: string;
  param_id?: string;
  task_id?: string;
  task_description?: string;
  source_task_id?: string;
  inherited?: boolean;
  assets?: FindingAsset[];
  ts: string;
}

// FindingsPage is the server-side paged response for the findings list.
export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingGroup {
  task_id: string | number | null;
  task_name?: string; // optional task name; empty/absent = unnamed
  task_description: string;
  task_status: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingGroupsPage {
  items: FindingGroup[];
  total: number;
  finding_total: number;
  page: number;
  page_size: number;
}

export interface FindingDeepenResponse {
  task_id: string;
  intent_id: string;
  state: IntentState;
  queued: boolean;
}

// FindingStats is the whole-table findings aggregate (stat cards + vuln-type dropdown), computed server-side, unaffected by paging.
export interface FindingStats {
  total: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  vulnclasses: string[];
  tasks: FindingTaskOption[];
}

// FindingTaskOption is one entry of the findings page "by task" filter dropdown: a task that has findings (an empty
// description means the task was deleted and the front end falls back to showing the id) plus its finding count.
export interface FindingTaskOption {
  id: string | number;
  name?: string; // optional task name; empty/absent = unnamed
  description: string;
  count: number;
}

// FindingQuery is the paging/filter/sort parameters for the findings list.
export interface FindingQuery {
  page: number;
  pageSize: number;
  severity?: "all" | Severity;
  status?: "all" | FindingStatus;
  vulnclass?: string;
  task?: string; // task id; "all"/empty = do not filter by task
  query?: string;
  sort?: "severity" | "time";
  // Asset tree node key; selecting a node selects its whole subtree. Empty = do not filter by asset.
  assetScope?: string;
}

// ---- Findings by asset (asset view) ----
export type FindingAssetKind = "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint" | "none";

// FindingAssetNode is one node of the asset tree. key looks like a:<id> (asset), c:<id> (company),
// r:<domain> (a root domain with no asset row in the DB), __none__ (no linked asset).
export interface FindingAssetNode {
  key: string;
  parent?: string;
  kind: FindingAssetKind;
  label: string;
  asset_id?: number;
  company_id?: number;
  self: number; // findings attached directly to this asset
  total: number; // includes descendants, de-duplicated by finding
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingAssetTree {
  nodes: FindingAssetNode[];
  finding_total: number;
  truncated: boolean;
  dropped_kinds?: string[];
}

// FINDING_UNASSIGNED_ASSET corresponds to the backend db.FindingUnassignedAsset.
export const FINDING_UNASSIGNED_ASSET = "__none__";

// ---- Activity / sessions ----
export type ActivityKind =
  | "tool_use"
  | "tool_result"
  | "text"
  | "thinking"
  | "result"
  | "user"
  | "intent" // LLM-generated exploration objective leading a worker session (UI-synthesized)
  | "round" // planner round boundary marker (engine-emitted)
  | "usage" // live cumulative token usage (per model turn); not rendered
  | "llm_switch" // automatic/manual task-level LLM switch
  | "llm_failover" // task-level provider switch / chain exhaustion audit event
  | "intercept_request"; // user-approval request from the intercept layer

// ChatAttachment is one uploaded file: path is relative to that conversation/task working directory (i.e. the agent's CWD).
export interface ChatAttachment {
  name: string;
  path: string;
  size: number;
  abs?: string; // absolute path (returned for scope=staging uploads; write it into the description before creating the task)
}

export interface Activity {
  seq: number;
  intent_id?: string;
  worker: string; // session owner: planner | mainagent | work#1 ...
  ts: string;
  kind: ActivityKind;
  tool?: string;
  tool_use_id?: string;
  is_error?: boolean;
  summary: string;
  detail?: string;
  metadata?: {
    llm_transition?: LLMTransition;
  };
  source_task_id?: string;
  inherited?: boolean;
  main_seg?: number; // main-agent conversation segment (present only on worker="mainagent" rows)
  // token usage (present only on kind='result')
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface LLMAuditProfile {
  id: number;
  name: string;
  format: string;
  model: string;
}

export interface LLMTransition {
  mode: "automatic" | "manual" | "exhausted";
  reason: string;
  previous?: LLMAuditProfile;
  next?: LLMAuditProfile;
}

export interface TaskLLMResolution {
  profile_id?: number;
  name: string;
  format: string;
  model: string;
  source: "task_chain" | "agent_binding" | "global_profile" | "environment" | "global";
  available: boolean;
  reason?: string;
}

export interface TaskLLMResolutions {
  mainagent: TaskLLMResolution;
  planner: TaskLLMResolution;
  worker: TaskLLMResolution;
}

// ---- Agent triggers (P3 scheduling, custom agents only) ----
export interface AgentTrigger {
  id: number;
  agent_key: string;
  enabled: boolean;
  interval_sec: number; // schedule: every N seconds (0 = not scheduled)
  on_finding: boolean; // fire when any task finds a finding
  on_goal_met: boolean; // fire when any task meets its goal
  on_task_timeout: boolean; // fire when any task times out
  on_tool_call: boolean; // fire when a selected tool is invoked (and finishes)
  on_task_create: boolean; // fire when any task is created
  interval_message: string; // per-trigger user message
  finding_message: string;
  goal_message: string;
  task_timeout_message: string;
  tool_call_message: string;
  task_create_message: string;
  tool_names: string[]; // tool keys selected for on_tool_call (at least one)
  last_fire?: string;
}

// ---- Conversations (chat page) ----
export interface ActiveFindingRetest {
  id: number;
  finding_id: string;
  conversation_id: number;
  status: "pending" | "running";
}

export interface FindingRetest {
  id: number;
  finding_id: number;
  conversation_id: number | null;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
  notes: string;
  summary: string;
  evidence: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

// Bulk retest (v0.4.27): candidate list entries + each finding's latest retest status.
export interface RetestCandidate {
  id: number;
  vulnclass: string;
  name: string;
  severity: Severity;
  summary: string;
}

// Online data-file preview (v0.4.41): the backend parses JSON/JSONL/CSV/TSV/text by extension.
export interface DataPreviewPayload {
  type: "json" | "jsonl" | "csv" | "text";
  name: string;
  kind: string;
  bound_finding: number;
  total_rows: number;
  truncated: boolean;
  columns?: string[];
  rows?: unknown[][];
  text?: string;
  total_size: number;
}

export interface RetestState {
  finding_id: number;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
}

export interface Conversation {
  id: number;
  running?: boolean; // live server state, returned with the conversation list
  agent_key: string;
  title: string;
  llm_profile_id?: number;
  pinned?: boolean;
  pinned_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---- Backend logs (/logs page) ----
export interface LogLine {
  seq: number;
  db_id?: number; // server_logs.id; present for DB-persisted lines
  ts: string;
  level: "info" | "warn" | "error";
  tag: string;
  text: string;
}

export type SessionRole = "mainagent" | "planner" | "worker" | "system";
export type SessionStatus = "running" | "paused" | "done" | "blocked" | "exhausted" | "pending" | "stopped" | "deleted";

// Daily token aggregate bucket (GET /api/tokens/daily).
export interface DailyTokenBucket {
  date: string; // "YYYY-MM-DD"
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Per-worker token usage (GET /api/exploration/tokens).
export interface TokenUsage {
  worker: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface SessionTokenUsage {
  session: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface BatchControlItem {
  id: string;
  ok: boolean;
  status?: string;
  queued?: boolean;
  error?: string;
}

// Per-task result of a bulk category change. The only possible failure is that the task was deleted; the category write itself is atomic.
export interface BatchCategoryItem {
  id: string;
  ok: boolean;
  error?: string;
}

// Whole-task (all agents) token aggregate.
export interface TokenTotal {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Task-level evidence attachments (v0.4.9): screenshots/data samples/logs, exported with the report as an evidence bundle.
export interface TaskArtifact {
  id: number;
  task_id: string;
  finding_id?: number;
  name: string;
  kind: string; // image|document|spreadsheet|presentation|pdf|data|log|html|other
  mime?: string;
  size_bytes: number;
  sha256?: string;
  source_url?: string;
  note?: string;
  // Document preview (v0.4.21): status and page count for sampling Office/PDF into images.
  preview_state?: "pending" | "ready" | "failed" | "skipped" | "";
  preview_pages?: number;
  preview_error?: string;
  created_at: string;
}

// Task-level target login credentials (entered at creation; the API only returns a view, password/TOTP are never returned).
export interface TaskAuthConfigInput {
  enabled: boolean;
  login_url: string;
  method: "POST" | "GET";
  content_type: "json" | "form";
  username_field?: string;
  password_field?: string;
  username?: string;
  password?: string;
  totp_secret?: string;
  extra_fields?: Record<string, string>;
  headers?: Record<string, string>;
  success_status?: number;
  success_contains?: string;
}

// The masked view the API returns: has_password / has_totp mean "configured", contents are not exposed.
export interface TaskAuthConfigView {
  enabled: boolean;
  login_url: string;
  method: string;
  content_type: string;
  username_field?: string;
  password_field?: string;
  username?: string;
  has_password?: boolean;
  has_totp?: boolean;
  extra_fields?: Record<string, string>;
  headers?: Record<string, string>;
  success_status?: number;
  success_contains?: string;
}

// Login self-check result (POST /api/tasks/{id}/auth-check).
export interface AuthCheckResult {
  ok: boolean;
  status_code?: number;
  matched: boolean;
  detail: string;
  elapsed_ms: number;
  used_totp?: boolean;
  checked_at: string;
}

// Single-task cost estimate (GET /api/tokens/cost?task=). Amounts are converted at built-in reference prices,
// for relative comparison only; a non-empty unpriced_models means some models are missing from the price table and cost is underestimated.
export interface TaskCostEstimate {
  task: { task_id: string; calls: number; input_tokens: number; output_tokens: number };
  cost_usd: number;
  unpriced_models: string[];
  pricing_note: string;
}

// Global per-profile token spend from the llm_usage ledger (GET /api/tokens/usage).
export interface ProfileUsage {
  profile_name: string;
  calls: number;
  tasks: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// One (profile, UTC day) token bucket for the dashboard's daily chart (new source).
export interface ProfileDayUsage {
  profile_name: string;
  date: string; // YYYY-MM-DD
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
}

// Response of GET /api/tokens/usage — the dashboard's "new" (llm_usage) token view.
export interface UsageStats {
  by_profile: ProfileUsage[];
  daily: ProfileDayUsage[];
}

// Per-model token usage for one task (GET /api/llm/records/by-model), from the
// always-on llm_usage metering ledger. calls = number of LLM calls on this model.
export interface ModelTokenStat {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface Session {
  id: string;
  role: SessionRole;
  title: string;
  status: SessionStatus;
  live: boolean;
  last_activity: string;
  intent_id?: string;
  source_task_id?: string;
  inherited?: boolean;
  seg?: number; // main-agent session: which conversation segment (0 = original)
}

// ---- Security ----
export interface AuditEntry {
  ts: string;
  tool: string;
  action: "allow" | "block";
  reason?: string;
  command?: string;
}

export interface Audit {
  entries?: AuditEntry[];
  attributions?: Record<string, number>;
}

// ---- Traffic ----
export interface TrafficExchange {
  id: string;
  ts: string;
  host: string;
  method: string;
  url: string;
  status: number;
  content_type: string;
  resp_len: number;
}

export interface TrafficResp {
  enabled: boolean;
  proxy?: string;
  count?: number; // global total (unfiltered)
  total?: number; // rows matching the current filter (for pagination)
  page?: number;
  size?: number;
  exchanges?: TrafficExchange[];
}

// Full raw request/response of one exchange (lazy-loaded on row select).
export interface TrafficDetail {
  req: string;
  resp: string;
}

// One distinct recorded host with its exchange count (target picker).
export interface TrafficHost {
  host: string;
  count: number;
}

// ---- App settings (runtime toggles) ----
export interface Settings {
  traffic_capture: boolean;
  agent_traffic_binding: boolean; // agents auto-bind traffic evidence, off by default; does not affect manual binding
  llm_record: boolean; // LLM recording switch (off by default); when off no LLM call is recorded
  // Web search. brave_key_set / tavily_key_set reflect whether a key is stored
  // (the values are never returned). On PUT, send the corresponding field to set/clear.
  web_search_enabled: boolean;
  web_search_backend: string; // "ddgs" | "brave-free" | "tavily" | "deepseek"
  brave_key_set: boolean;
  tavily_key_set: boolean;
  // write-only: only sent on PUT to store/clear the key.
  brave_search_api_key?: string;
  tavily_search_api_key?: string;
  // Standalone egress proxy (http/https/socks5) used to reach search endpoints; unrelated to the MITM proxy that records traffic. Empty = direct.
  web_search_proxy?: string;
  // Global egress proxy (http/https/socks5, may include user:pass); all target traffic goes through it. Acts as the
  // MITM upstream when traffic capture is on; injected straight into the agent's bash/WebFetch when capture is off. Empty = direct.
  global_proxy?: string;
  // Installer proxy (http/https/socks5), used for host-tool installs, program updates and other maintenance requests.
  // Fully independent of the target-traffic proxy, search proxy and LLM proxy. Empty = may come from POJUN_INSTALL_PROXY.
  // Empty = direct.
  install_proxy?: string;
  python_interpreter?: string; // python interpreter path for custom script tools (empty = detected at runtime)
  workers?: number; // number of concurrent worker agents (default 3); applies to tasks started afterwards
  // Output budget (thinking + body share it) and per-call wall-clock timeout for cold-node compaction. 0 = use the default
  // (32768 tokens / 1200 seconds). A thinking model's reasoning length grows linearly with this budget;
  // give it too little and the model thinks forever without emitting a single word of body text.
  compaction_max_tokens?: number;
  compaction_timeout_seconds?: number;
  // Max member nodes per compaction request. Whether a thinking model can wrap up depends on the size of a single
  // input (measured: 9 nodes fine, 26 nodes burned the whole 32768 budget without producing body text), so we split.
  compaction_max_members?: number;
  // B10: LLM profile id the compactor is pinned to. 0/unset = follow the planner profile on the task chain (legacy behaviour);
  // >0 = compaction calls always run on the given profile and do not take part in task-chain rotation.
  compactor_profile_id?: number;
  // Task concurrency cap: the max number of tasks "running" at once. Off = unlimited; when on, new tasks over the cap queue up and start automatically when a slot frees.
  task_concurrency_enabled?: boolean; // default false
  task_concurrency_limit?: number; // default 5 when enabled
  // Automatic task wrap-up (v0.5.0): consecutive rounds with no new findings / coverage target met / max planning rounds.
  auto_finish_enabled?: boolean; // default true
  auto_finish_idle_rounds?: number; // default 3, range 2-20
  auto_finish_min_rounds?: number; // default 5, range 1-50
  auto_finish_coverage_pct?: number; // default 0 = off, 1-100
  auto_finish_max_rounds?: number; // default 80, 0 = unlimited
  // Intent-level soft budget (v0.4.28): once one intent's cumulative tokens hit the cap, inject a wrap-up nudge (does not kill the process).
  intent_budget_enabled?: boolean; // default true
  intent_budget_tokens?: number; // default 3000000, range 500000-20000000
  // Verbatim evidence re-check (v0.4.29): off = disabled / warn = warn only (default) / block = reject critical/high findings with no citation.
  finding_evidence_verify?: "off" | "warn" | "block";
  // Tool-output injection warning (v0.4.29): when high-precision injection signatures match, remind the model to "treat data as data, not instructions".
  tool_output_injection_guard?: boolean; // default true
  // LLM rotation (failover). Off by default; when on, an agent with "no model specified" automatically
  // switches to the next profile when the current one is unavailable (insufficient balance/invalid key/rate limited/service error).
  llm_pool_enabled?: boolean; // default false
  // Whether an agent/task bound to a specific profile also falls back to the rotation chain when it fails. Default false = binding is exclusive.
  llm_pool_bind_fallback?: boolean;
  // Operating-constraint injection scope (all on by default): splice the task's allow/deny constraints into the matching agent's system prompt.
  constraints_inject_planner?: boolean;
  constraints_inject_worker?: boolean;
  // Experimental: noa model-driven context compaction (off by default). When on, the platform's four agent kinds (planner/
  // worker/main agent/chat) hand context compaction to noa instead of the built-in compaction; read once per run, effective
  // for runs started afterwards.
  noa_compaction?: boolean;
  // ---- Finding IM push (channels are independent resources, see /api/notify/*; only three global settings live here) ----
  notify_enabled?: boolean; // master push switch, on by default; a one-click stop-the-bleeding for maintenance windows
  notify_public_base_url?: string; // externally reachable address for finding detail back-links; empty = messages carry no back-link
  notify_digest_interval_min?: number; // digest mode period (minutes), default 30
  // ---- Vuln intel / call-back (read and shown to the agent by the net_context tool) ----
  egress_hint?: string; // description of externally reachable addresses (public IP/host LAN address, etc., free text)
  egress_port_map?: string; // port mapping description (container port -> host port)
}

// ---- Finding IM push ----

// NotificationFilter is a channel's filter conditions; every field is optional and absent means no filtering.
// The backend validates nothing: a malformed config is treated as a "hit" (rather over-push than miss).
export interface NotificationFilter {
  min_severity?: string; // "" | low | medium | high | critical
  task_ids?: number[]; // empty = any; non-empty requires an overlap with the finding's task
  asset_ids?: number[]; // empty = any; non-empty requires an overlap with the asset the finding is anchored to
  vulnclass_include?: string[]; // empty = accept all; non-empty requires the vuln class to match any keyword (case-insensitive substring)
  vulnclass_exclude?: string[]; // a match on any keyword excludes it (exclude wins over include)
  on_status_change?: boolean; // also receive finding handling-status change events
}

// NotificationChannel is one channel instance. config fields vary by kind,
// and credential fields come back as masked values starting with "__masked__" — echoing them back unchanged means "leave it alone".
export interface NotificationChannel {
  id: number;
  name: string;
  kind: string;
  enabled: boolean;
  mode: "realtime" | "digest";
  config: Record<string, unknown>;
  filter: NotificationFilter;
  rate_per_min: number;
  created_at: string;
  updated_at: string;
  // secret_keys are provided by the backend per channel kind; the front end uses them to render password inputs and the
  // "leave blank to keep unchanged" hint without hard-coding any channel knowledge.
  secret_keys: string[];
}

// NotificationKind is the channel-kind metadata returned by /api/notify/meta.
export interface NotificationKind {
  kind: string;
  default_rate_per_min: number;
  secret_keys: string[];
}

export interface NotificationMeta {
  kinds: NotificationKind[];
  enabled: boolean;
  public_base_url: string;
  digest_interval_min: string;
  defaults: { digest_interval_min: number };
  stats: {
    channels: number;
    channels_on: number;
    pending: number;
    failed: number;
    sent_today: number;
    backlog_age_ms: number;
  };
}

// NotificationDelivery is one delivery record, used for delivery history and failed resends.
export interface NotificationDelivery {
  id: number;
  finding_id: string;
  event_kind: string; // finding_created | finding_status_changed
  channel_id: number;
  channel_name: string;
  channel_kind: string;
  state: "pending" | "sending" | "sent" | "failed" | "skipped";
  attempts: number;
  last_error: string;
  batch_id?: number;
  created_at: string;
  sent_at?: string;
  next_attempt_at: string;
  title: string;
  severity: string;
}

// ---- LLM config ----
export interface LLMProfile {
  id: string;
  name: string;
  format: "openai" | "anthropic" | "openai-responses";
  base_url?: string;
  proxy?: string;
  model: string;
  api_key_hint?: string;
  rate_per_second: number;
  rate_per_minute: number;
  context_window_k?: number;
  // Thinking switch (thinking.type): "" = do not send (default) | "disabled" = off | "enabled" = on
  thinking_type?: string;
  // Thinking effort: "" = do not send (default) | "low"/"medium"/"high"/"xhigh"/"max"
  reasoning_effort?: string;
  is_default: boolean;
  // Rotation rank: higher is picked first. The active profile is always chain head regardless of this value.
  priority?: number;
  // true = never used as a failover target (an agent/task can still bind it explicitly).
  pool_exclude?: boolean;
  // true (default) = streaming (SSE) | false = truly non-streaming (stream:false, returned in one shot).
  streaming?: boolean;
  // Output cap per reply (tokens). 0 = do not send the field, let the server default decide.
  // Note the difference from context_window_k: that is the model's total capacity, used locally only for the compaction threshold.
  max_tokens?: number;
  // Which request field name carries the cap; only meaningful for format="openai":
  // ""=max_tokens (default) | "max_completion_tokens" (OpenAI reasoning models only accept this)
  max_tokens_field?: string;
  // Custom session header name: when non-empty, every request carries this HTTP header with the current conversation/intent session id.
  // "" = do not send. For gateways that do prompt caching/sticky routing on a session-id header.
  session_header_key?: string;
  // User-Agent for LLM requests: non-empty replaces the UA on every model request; ""=keep the SDK/Go default.
  // For gateways/WAFs that reject the default Go-http-client UA outright.
  user_agent?: string;
  // This profile's overrides for retries (connect/empty response/same-provider safety window). Blank/all 0 = follow the global policy.
  retry?: LLMRetryOverride;
}

// ---- LLM retry policy ----
// The two knobs of one retry layer. Both mean "0 = not configured":
//   attempts    0 = use the default count | -1 = disable retries for this layer | >0 = retry count
//   interval_ms 0 = use the default exponential backoff | >0 = use this fixed millisecond interval
export interface LLMRetryRule {
  attempts: number;
  interval_ms: number;
}

// The three layers a single LLM profile can override (all are retries that "follow the endpoint").
export interface LLMRetryOverride {
  connect: LLMRetryRule; // connect retry: connection reset/timeout/429/5xx, before the stream starts
  empty: LLMRetryRule; // empty-response retry: completed but produced no content (openai format only)
  stream: LLMRetryRule; // same-provider safety-window retry: replay a dropped stream before any output was delivered
}

// Global policy = defaults for the three layers above + two layers that only exist globally:
//   breaker rotation circuit breaker (attempts = how many consecutive transient failures trip it, interval_ms = fixed cooldown)
//   intent  intent re-run (re-run the whole intent after a worker ends with model_error)
export interface LLMRetryPolicy extends LLMRetryOverride {
  breaker: LLMRetryRule;
  intent: LLMRetryRule;
}

// ---- LLM rotation (failover) ----
// A profile's position and health in the rotation chain. state:
//   ok       healthy
//   degraded has consecutive failures but below the breaker threshold
//   tripped  tripped; skipped during cooldown (cooldown_secs is the remaining seconds)
export interface LLMPoolMember {
  profile_id: string;
  name: string;
  model: string;
  format: string;
  priority: number;
  active: boolean; // whether this is the active profile (always chain head)
  excluded: boolean; // pool_exclude: not part of rotation
  state: "ok" | "degraded" | "tripped";
  fails: number;
  trips: number;
  cooldown_secs: number;
  last_error?: string;
  last_at?: string;
}

export interface LLMPoolStatus {
  enabled: boolean;
  bind_fallback: boolean;
  chain: LLMPoolMember[];
}

// ---- Agents ----
export interface Agent {
  id: string;
  key: string; // built-ins are goals/planner/mainagent/worker; custom ones use a user-defined key
  name: string;
  description?: string;
  role: string;
  builtin: boolean;
  enabled: boolean;
  llm_profile_id?: number | null; // bound LLM profile; null/absent = follow task/conversation/global
  max_turns?: number; // 0 = unlimited
  run_seconds?: number; // wall-clock cap for one worker run (seconds); 0 = unlimited
  web_search?: boolean; // whether web search is enabled (gated by the global system switch)
  interactive_shell?: boolean; // whether the interactive shell is enabled (persistent PTY session tool family)
  local_exec?: boolean; // whether it may run commands/write files on this host (Bash/Write/Edit); false = it can only operate the platform through tools (e.g. dispatch tasks)
  // Post-trigger handling policy (only meaningful for custom agents)
  trigger_run_mode?: "serial" | "parallel"; // serial queueing / one concurrent session per trigger
  trigger_merge_mode?: "by_task" | "all" | "none"; // serial only: merge within a task / merge everything / no merge
  trigger_max_parallel?: number; // parallel only: concurrency cap per agent; 0 = unlimited
  // Binding counts (list endpoint only): visible MCP / visible Skills / bound tools
  mcp_count?: number;
  skill_count?: number;
  tool_count?: number;
}

export interface PromptVar {
  name: string;
  description: string;
  example: string;
  source: "exploration" | "runtime" | "distilled";
}

export interface PromptVersion {
  version: number;
  ts: string;
  note: string;
  template_text: string;
}

export interface AgentDetail {
  agent: Agent;
  prompt: string;
  variables: PromptVar[];
  versions: PromptVersion[];
  visibility: { mcp: number[]; skill: string[] };
  // LLM profiles that can be bound (for the "default model" dropdown); the current binding is agent.llm_profile_id
  llm_profiles?: { id: number; name: string; model: string; is_default: boolean }[];
  wrapup_prompt?: string; // saved wrap-up prompt (empty = use the built-in default)
  wrapup_default?: string; // built-in default wrap-up prompt (placeholder/restore default)
  wrapup_max_turns?: number; // saved wrap-up turn count (0 = use the built-in default)
  wrapup_max_turns_default?: number; // built-in default wrap-up turn count (for the "0 = default N" hint)
  // Task-level timeout wrap-up text (worker/planner only; this section only shows when task_timeout_wrapup_supported=true)
  task_timeout_wrapup_supported?: boolean;
  task_timeout_wrapup_prompt?: string;
  task_timeout_wrapup_default?: string;
  task_timeout_wrapup_max_turns?: number;
  task_timeout_wrapup_max_turns_default?: number;
}

// ---- MCP ----
export interface MCPServer {
  id: number;
  name: string;
  transport: "stdio" | "http" | "sse";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  enabled: boolean;
  insecure?: boolean; // http: skip TLS cert verification (self-signed servers)
  tools?: string[]; // mcp_tools_cache (names only, for the count)
}

export interface MCPTool {
  name: string;
  description: string;
}

// ---- Skills ----
// Fields align with the agentskills.io open specification.
// description covers both "what the skill does" and "when to use it".
// SkillTags are a skill's normalized tags (the tags block of SKILL.md frontmatter).
// cwe / attack are MITRE framework ids, class is the platform's internal category.
export interface SkillTags {
  cwe?: string[];
  attack?: string[];
  class?: string[];
}

export interface SkillItem {
  name: string; // unique key = directory name
  description?: string; // required per spec; covers what + when to use
  license?: string; // optional: SPDX identifier or free text
  compatibility?: string; // optional: environment requirements
  mcps?: string[]; // MCP server names this skill unlocks on load
  tags?: SkillTags; // normalized tags (CWE/ATT&CK/category) — the entry point for the capability matrix and search by class
  files: string[]; // files in the skill directory
  // Usage stats (the skill_usage ledger). For a skill never invoked: calls=0, last_used absent.
  calls: number;
  tasks: number; // number of tasks that loaded it (chat conversations do not count)
  usage_agents: string[]; // agent keys that loaded it
  last_used?: string;
}

// SkillCall is one Skill() invocation (the recent-call list of a single skill).
export interface SkillCall {
  ts: string;
  agent_key: string;
  task_id: number; // 0 = non-task context (chat conversation)
  session_id: string;
  args_len: number;
}

// MissingSkill is a skill that was named but does not exist — a "wanted but unavailable" gap.
export interface MissingSkill {
  skill: string;
  calls: number;
  agents: string[];
  last_used?: string;
}

// ---- Tools (built-in tool catalogue) ----
// key + handler live in Go; only these fields are page-editable. system tools lock
// the key and the parameter *structure* (name/type/required) — the per-param
// description/default and the agent binding are what move.
export interface Tool {
  key: string;
  system: boolean;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema: Record<string, any>; // full JSON-Schema (object with properties)
  agents: string[]; // bound agent keys
  enabled: boolean;
  kind?: "builtin" | "shell" | "command" | "script" | "http"; // custom tool type
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec?: Record<string, any>; // custom tool execution spec (kind!=builtin)
  deferred?: boolean; // schema deferred (SearchExtraTools/ExecuteExtraTool)
  calls?: number; // persistent runtime invocation count (older APIs may omit it)
}

// ---- Stats ----
export interface Stats {
  assets: number;
  engine_mode: EngineMode;
  llm_configured: boolean;
  roe_enabled: boolean;
  findings_confirmed: number;
  active_task?: Partial<Task>;
}

// ---- Intercept Rules ----
export type InterceptAction = "allow" | "deny" | "ask" | "judge";
export type InterceptMatchTarget = "tool_name" | "tool_input";
export type InterceptMatchType = "string" | "regex";

export interface InterceptRule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_target: InterceptMatchTarget;
  match_type: InterceptMatchType;
  // Tool names this rule applies to; empty array/absent = any tool. Only meaningful for match_target=tool_input.
  tool_scope?: string[];
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
  created_at: string;
  updated_at: string;
}

// ---- Asset Intercept Rules (asset intercept: global blacklist) ----
export type AssetInterceptKind =
  | "exact_domain"
  | "exact_ip"
  | "exact_url"
  | "fuzzy_domain"
  | "fuzzy_ip"
  | "fuzzy_url"
  | "cidr";

// action only applies to task-level rules: block=intercept (forbid testing) allow=permit (whitelist).
export type AssetInterceptAction = "block" | "allow";

// An entry of task-level asset intercept/allow rules (used when creating a task and when editing task details).
export interface AssetInterceptRuleInput {
  action: AssetInterceptAction;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  enabled: boolean;
}

export interface AssetInterceptRule {
  id: number;
  enabled: boolean;
  action?: AssetInterceptAction; // global rules omit this field (always intercept); task-level rules distinguish block/allow
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface InterceptPending {
  decision_source?: "rule" | "model" | "unknown" | "";
  id: number;
  rule_id?: number;
  conversation_id?: number;
  task_id?: string;
  agent_name: string;
  tool_name: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool_input: Record<string, any>;
  status: "pending" | "allowed" | "denied" | "timeout";
  reason: string; // the rule message or the model's rationale (model decisions carry a [model] prefix)
  decided_at?: string;
  created_at: string;
}

// JudgeConfig: global settings for model fallback approval (the model decides only when no intercept rule matched).
export interface JudgeConfig {
  enabled: boolean;
  profile_id: number; // 0 = follow the active/default profile
  prompt: string; // judge prompt; when unset, GET backfills the full built-in template
  timeout_seconds: number; // model call timeout
  fail_action: "allow" | "ask" | "deny"; // fallback when the model errors/times out/is unparseable
  ask_timeout_seconds: number; // approval wait timeout after the model decides ask and it goes to a human
  ask_timeout_action: "allow" | "deny"; // default action when approval times out
}

// JudgeUsage: cumulative token usage of model fallback approval (the judge channel) + a daily series for the last N days.
export interface JudgeDayUsage {
  date: string; // YYYY-MM-DD (UTC)
  calls: number;
  input_tokens: number;
  output_tokens: number;
}
export interface JudgeUsage {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  daily: JudgeDayUsage[];
}

export interface InterceptApprovalFilter {
  status?: InterceptPending["status"];
  decision_source?: "rule" | "model" | "unknown";
}

// InterceptApprovalRow enriches InterceptPending with conversation/task and rule context.
export interface InterceptApprovalRow extends InterceptPending {
  conv_title: string; // "" if no linked conversation
  conv_agent_key: string; // "" if no linked conversation
  rule_name: string; // "" if rule was deleted
}

// ── Asset sync (ScopeSentry data source) ──────────────────────────────────────
export interface SSProject {
  id: string; // MongoDB ObjectID — used as filter.project
  name: string;
  logo?: string;
  AssetCount?: number;
  tag?: string;
}

export interface SSTask {
  id: string;
  name: string; // used as filter.task
  status?: number;
  progress?: number;
  creatTime?: string;
  endTime?: string;
}

// ConvTokenSummary — one conversation's token total (+ profile/date) for merging
// chat usage into the dashboard token stats. GET /api/tokens/conversations.
export interface ConvTokenSummary {
  llm_profile_id: number | null;
  created_at: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// ---- Command recording (Bash execution history) ----
export interface CommandRecord {
  id: number;
  exploration_id: number;
  worker: string;
  tool: string;
  command: string; // raw tool input (JSON)
  output: string;
  is_error: boolean;
  created_at: string;
}

// Invocation stats for a single tool (/commands/stats); errors is how many of them failed.
export interface ToolStat {
  tool: string;
  total: number;
  errors: number;
}

// ---- LLM recording ----
export interface LLMRecordItem {
  id: number;
  ts: string;
  model: string;
  profile_name: string;
  session_id: string;
  task_id: string;
  worker: string;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read: number;
  cache_write: number;
  status: string;
  error?: string;
}

export interface LLMRecordDetail extends LLMRecordItem {
  request_body: string;
  response_body: string;
  // The raw HTTP the provider actually sent and received: the request is the full body buildBody() emitted (including the tool
  // schemas), the response is the raw SSE frames. request_body/response_body above are the normalized view that drops the
  // tool schemas and tool_use blocks. Empty for old records.
  raw_request?: string;
  raw_response?: string;
}

// One distinct task with its LLM-record count (task picker on the records page).
export interface LLMTask {
  task_id: string;
  count: number;
}

// The exact JSON sent to the review model, retained for all model verdicts.
export interface InterceptReviewInput {
  version: number;
  background?: {
    // worker_summary is retained only for immutable v2/v3 snapshots.
    source: "user_message" | "worker_summary";
    text: string;
    truncated?: boolean;
  };
  // Version 1 snapshots are immutable and remain readable in historical audits.
  task?: {
    task_id: number;
    description: string;
    goal: string;
    constraints: { id: number; kind: string; text: string; origin: string; created_at: number }[];
    truncated?: boolean;
  };
  working_directory?: string;
  worker_intent?: string;
  turn_input?: string;
  background_truncated?: boolean;
  // Legacy v1/v2 snapshots only; v3 never sends execution history.
  history?: {
    tool_use_id: string;
    tool: string;
    arguments_preview: string;
    result: string;
    status: "succeeded" | "failed";
    truncated?: boolean;
  }[];
  history_truncated?: boolean;
  correlation?: "exact" | "ambiguous" | "unavailable";
  tool_name: string;
  arguments: Record<string, unknown>;
}

// Immutable review snapshot plus separately recorded execution outcome.
export interface InterceptAudit {
  model_input?: InterceptReviewInput;
  model_input_digest?: string;
  run_id?: string;
  tool_use_id?: string;
  correlation: "exact" | "ambiguous" | "unavailable";
  input_digest: string;
  user_message: string;
  user_truncated?: boolean;
  context:
    | { kind: string; tool?: string; tool_use_id?: string; text: string; is_error?: boolean; truncated?: boolean }[]
    | null;
  context_truncated?: boolean;
  captured_at: string;
  model_fallback?: boolean;
  initial_action: "allow" | "ask" | "deny";
  initial_reason: string;
  effective_action?: "allow" | "deny";
  decision_reason?: string;
  rule_name?: string;
  config_digest?: string;
  profile_id?: number;
  execution_status: "not_started" | "not_executed" | "awaiting_result" | "succeeded" | "failed" | "unknown";
  output?: string;
  output_truncated?: boolean;
  execution_ended_at?: string;
}
export interface InterceptDetail extends InterceptApprovalRow {
  audit: InterceptAudit | null;
}

export type TrafficEvidenceRole = "baseline" | "proof" | "verification" | "supporting";
export interface TrafficEvidenceRef {
  traffic_id: string;
  role?: TrafficEvidenceRole;
  note?: string;
}
export interface TrafficEvidenceSnapshot {
  id: string;
  source_traffic_id: string;
  captured_at: number;
  url: string;
  method: string;
  status: number;
  content_type: string;
  req_head?: string;
  resp_head?: string;
  req_hash: string;
  resp_hash: string;
  req_len: number;
  resp_len: number;
}
export interface FindingTrafficBinding {
  id: string;
  finding_id: string;
  snapshot_id: string;
  role: TrafficEvidenceRole;
  note: string;
  position: number;
  created_at: string;
  snapshot: TrafficEvidenceSnapshot;
}
export interface FindingTraffic {
  finding_id: string;
  version: number;
  report_version: number;
  bindings: FindingTrafficBinding[];
}
export interface EvidenceBodyPreview {
  content: string;
  offset: number;
  total: number;
  next_offset: number;
  truncated: boolean;
  binary: boolean;
}
export interface FindingTrafficDetail {
  binding: FindingTrafficBinding;
  request: EvidenceBodyPreview;
  response: EvidenceBodyPreview;
}

/** GET /api/update/check — the comparison of the current version against the latest GitHub release. */
export interface UpdateCheck {
  /** The currently running version; "dev" for development builds, or git describe with a suffix. */
  current: string;
  /** Run form. Under docker a swap only affects the container's writable layer; rebuilding the container reverts to the image version. */
  mode: "docker" | "binary";
  os: string;
  arch: string;
  repo: string;
  /** Whether there is a previous version that can be rolled back to (pojun.old). */
  has_backup: boolean;
  /** The conclusion of the self-update bootstrap at this startup (swap failed / already rolled back, etc.); empty when nothing happened. */
  boot_notice?: string;
  rolled_back?: boolean;
  /** The reason given when querying GitHub fails; none of the fields below exist in that case. */
  error?: string;
  latest?: string;
  notes?: string;
  html_url?: string;
  published_at?: string;
  /** The release package name for the current platform, and whether that Release actually includes it. */
  asset?: string;
  asset_available?: boolean;
  size?: number;
  has_update?: boolean;
  /** Whether the two version numbers are comparable; false for development builds, which disables one-click update. */
  comparable?: boolean;
  /** Explanation shown when comparable is false. */
  reason?: string;
}

/** One update progress event pushed by /api/update/stream. */
export interface UpdateProgress {
  phase: "idle" | "downloading" | "verifying" | "extracting" | "staged" | "failed";
  /** Only meaningful during the download phase (0-100); -1 in other phases. */
  percent: number;
  message: string;
  version?: string;
  error?: string;
}

// Original execution selected from an approval, never submitted to the reviewer.
export interface InterceptExecution {
  conversation_id: number | null;
  task_id: string | null;
  session: string;
  seq: number;
  items: Activity[];
}

// ── Host environment: tool health check + one-click install ───────────────────

/** One health-check result. installable=false means the vendor only ships an interactive installer (e.g. msfconsole). */
export interface HostTool {
  id: string;
  name: string;
  bin: string;
  available: boolean;
  installable: boolean;
  purpose: string;
  install?: string;
  kind: "apt" | "github" | "pip" | "manual";
  /** Attack-surface category; the page groups by it. */
  category: "network" | "dns" | "web" | "cred" | "code" | "pivot" | "oob" | "exploit" | "material" | "runtime" | "middleware" | "";
}

export type InstallSourcePreset = "" | "tencent" | "tuna";

export interface HostInstallSources {
  apt: InstallSourcePreset;
  pypi: InstallSourcePreset;
}

/** Whether one-click install is available; depends on the privileged helper pojun-hostd being online (not online under Docker). */
export interface HostenvInstaller {
  available: boolean;
  reason: string;
  /** Helper version; empty string = an old version that does not report it (before 0.3.22). */
  version?: string;
  /** Old helpers neither report a version nor can swap themselves; re-run install.sh once to bootstrap. */
  upgrade_required?: boolean;
  socket: string;
  proxy: string;
  sources?: HostInstallSources;
  sources_supported?: boolean;
}

export interface HostenvStatus {
  tools: HostTool[];
  deploy_mode: "docker" | "host";
  installer: HostenvInstaller;
}

/**
 * Proxy self-test result. ok=false means "tested and it does not work" — not an API error.
 * hint is an actionable fix suggestion (protocol mismatch/missing auth/timeout, etc.).
 */
export interface ProxyCheckResult {
  ok: boolean;
  proxy: string;
  scheme?: string;
  latency_ms: number;
  status: number;
  /** Egress IP; used to confirm traffic really went through the proxy. */
  exit_ip?: string;
  error?: string;
  hint?: string;
}

/** One install job. log is accumulated output that grows as polling continues. */
export interface InstallJob {
  id: string;
  tool_id: string;
  tool_name: string;
  state: "queued" | "running" | "done" | "failed" | "cancelled";
  exit_code: number;
  error?: string;
  started_at: string;
  ended_at?: string;
  log: string;
}

/** Bulk install result: started entries are in the helper's queue (executed serially), skipped entries carry a rejection reason. */
export interface InstallBatchResult {
  started: { job_id: string; tool_id: string }[];
  skipped: { tool_id: string; reason: string }[];
}

/** Proxy pool: a persisted entry for one upstream proxy. */
export interface ProxyPoolEntry {
  url: string;
  name: string;
  enabled: boolean;
  weight: number;
}

/** Proxy pool runtime state: breaker count, last success/failure time, remaining breaker seconds. */
export interface ProxyPoolRunning {
  url: string;
  name: string;
  failures: number;
  weight?: number;
  last_ok?: string;
  last_fail?: string;
  break_remaining?: number;
}

export interface ProxyPoolState {
  entries: ProxyPoolEntry[];
  strategy: string;
  /** Master switch: when false the entries take no part in exit selection (fall back to the global proxy/direct). */
  enabled: boolean;
  running: ProxyPoolRunning[];
  /** number of entries not tripped (0 = none currently usable). */
  usable?: number;
  total?: number;
  /** number of entries actually taking part in exit selection (after the socks5 policy filter). */
  effective_total?: number;
  socks5_blocked?: number;
  socks5_allowed?: boolean;
  capturing: boolean;
  /** Strict egress: with a pool configured but fully unusable, direct fallback is forbidden (on by default). */
  strict?: boolean;
  check_target?: string;
  health_minutes?: number;
  health_cooldown?: number;
  last_check?: { at: string; target: string; count: number; ok_count: number; auto?: boolean } | null;
}

/** Vuln intel sync config (credentials are already masked on read, only the *_set booleans come back). */
export interface VulnIntelConfig {
  enabled: boolean;
  nvd_api_key: string;
  nvd_key_set: boolean;
  github_token: string;
  github_token_set: boolean;
  proxy: string;
  poc_enabled: boolean;
  backfill_days: number;
  max_runtime_minutes: number;
  maintenance_proxy: string;
}

/** Save vuln intel config: omitting a credential field keeps it unchanged, passing "-" clears it. */
export interface VulnIntelConfigPatch {
  enabled?: boolean;
  nvd_api_key?: string;
  github_token?: string;
  proxy?: string;
  poc_enabled?: boolean;
  backfill_days?: number;
  max_runtime_minutes?: number;
}

export interface VulnIntelSource {
  source: string;
  last_sync_at?: string;
  cursor: string;
  total_synced: number;
  last_error: string;
  enabled: boolean;
  error_hint?: string;
  ok?: boolean;
}

export interface VulnIntelStatus {
  enabled: boolean;
  nuclei_templates_dir: string;
  sources: VulnIntelSource[];
  counts: { cves: number; kev: number; pocs: number };
  config?: VulnIntelConfig;
  sync_running?: boolean;
  sync_started_at?: number;
  /** Description of the current round's phase (e.g. "syncing vuln intel (CVE / KEV / GHSA / PoC)"; empty = not running). */
  sync_phase?: string;
  next_tick_hint?: string;
  nuclei?: {
    dir: string;
    exists: boolean;
    is_git: boolean;
    templates: number;
    updated_at?: string;
    hint: string;
  };
}

/** Call-back receiver: one captured session (backend listener.Session). */
export interface ListenerSession {
  id: string;
  remote: string;
  connected_at: string;
  last_active: string;
  bytes_in: number;
  /** The first 64KB captured (fault-tolerant UTF-8 decoding) — reverse shell initial output / OOB request line / banner. */
  preview: string;
  open: boolean;
}

/** Call-back receiver view (a GET /api/listeners row). */
export interface ListenerView {
  name: string;
  port: number;
  started_at: string;
  sessions: ListenerSession[];
}

/** Listener start response: connect_back is the only trustworthy source for the payload call-back address. */
export interface ListenerStartResp {
  name: string;
  port: number;
  started_at: string;
  connect_back: ConnectBack;
}

/** C2 egress resolution result: where the target should connect is decided by the platform (direct/ssh relay/manual). */
export interface ConnectBack {
  mode: "direct" | "ssh" | "manual" | string;
  lhost: string;
  lport: number;
  via?: string;
}

/** C2 egress config (GET /api/c2/config; the password is masked, only has_pass comes back). */
export interface C2Config {
  mode: "direct" | "ssh" | "manual" | string;
  host: string;
  ssh: string;
  key: string;
  iface: string;
  has_pass: boolean;
}

/** C2 config save body: fields left undefined stay unchanged on the backend; password "" clears it. */
export interface C2ConfigPatch {
  mode?: string;
  host?: string;
  ssh?: string;
  password?: string;
  key?: string;
  iface?: string;
}

export interface ProxyPoolSubscription {
  format: "uri" | "clash";
  supported: string[];
  text: string;
  unsupported: number;
  invalid: number;
  /** non-node info lines mixed into the subscription (remaining quota/expiry/homepage etc.), ignored. */
  ignored?: number;
  note?: string;
  /** format=clash only: the full YAML (with node credentials; the frontend only uses it to start mihomo). */
  clash_yaml?: string;
  proxies?: number;
  direct_nodes?: number;
  local_ports?: number[];
  proxy_groups?: number;
  group_names?: string[];
  proxy_providers?: number;
  /** Clash node: name and type only, no account/address. */
  nodes?: { name: string; type: string }[];
  /** Clash group: name, type and member node names (for the node management page). */
  groups?: { name: string; type: string; members?: string[] }[];
}

export interface LocalProxyCandidate {
  url: string;
  port: number;
  ok: boolean;
  latency_ms: number;
  exit_ip?: string;
  error?: string;
  source: string;
}

export interface MihomoStatus {
  running: boolean;
  installed: boolean;
  port: number;
  pid: number;
  binary: string;
  config_path: string;
  log_path: string;
  started_at?: string;
  version?: string;
  last_error?: string;
  /** the outbound actually in effect in the config file (derived from the rules MATCH). */
  outbound?: string;
  /** group/node/load-balance/url-test/fallback */
  mode?: string;
  /** node names the outbound group contains (a single one when a node is named directly). */
  nodes?: string[];
  /** external-controller port for this start (loopback-bound only, used for node delay tests). */
  controller_port?: number;
}

export interface SSHProvider {
  id: number;
  name: string;
  host: string;
  port: number;
  user: string;
  credential_id?: number;
  created_at?: string;
  status?: string;
  socks_addr?: string;
  started_at?: string;
}

