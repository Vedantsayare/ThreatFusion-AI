// Types mirror the FastAPI response models (api/models.py, api/incidents.py,
// guardrails/*.py). Keep field names identical to the backend.

export type Priority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'ESCALATED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'REVOKED' | 'EXECUTED';

export interface Principal { name: string; role: 'viewer' | 'analyst' | 'approver' | 'admin'; }

export interface Paginated<T> { items: T[]; total: number; page: number; page_size: number; total_pages: number; }

export interface AlertSummary {
  alert_id: string;
  finding_id?: string | null;
  title: string;
  priority: Priority;
  score: number;
  severity: string;
  workflow_status: string;
  received_at: number;
  event_time?: number | null;
  duration_ms: number;
  asset_name?: string | null;
  username?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  mitre_techniques: string[];
  pending_approvals_count: number;
  incident_id?: string | null;
  source?: string | null;
  synthetic: boolean;
}

export interface ScoreContribution { factor: string; points: number; detail: string; evidence_ref?: string | null; }

export interface TriageResult {
  finding_id: string;
  title: string;
  priority: Priority;
  score: number;
  severity: string;
  reasons: string[];
  score_breakdown: ScoreContribution[];
  priority_rule?: string | null;
  mitre_techniques: string[];
  uncertainties: string[];
  recommended_steps: string[];
  has_missing_data: boolean;
  policy_version: string;
}

export interface Finding {
  time: number;
  severity: string;
  severity_id: number;
  message?: string | null;
  finding_info: { uid: string; title: string; desc?: string | null; types: string[]; src_url?: string | null };
  metadata: { original_time?: string | null; product: { name: string } };
  device?: { name?: string | null; uid?: string | null; ip?: string | null } | null;
  src_endpoint?: { ip?: string | null; port?: number | null; protocol_name?: string | null; domain?: string | null } | null;
  dst_endpoint?: { ip?: string | null; port?: number | null; protocol_name?: string | null; domain?: string | null } | null;
  user?: { name: string } | null;
  process?: { name?: string | null; cmd_line?: string | null; pid?: number | null } | null;
  attacks: { tactic?: { name: string } | null; technique?: { uid: string; name?: string | null } | null }[];
  raw_data: Record<string, unknown>;
  unmapped: Record<string, unknown>;
}

export interface SourceVerdict { source: string; verdict: string; detail: string; available: boolean; synthetic: boolean; }
export interface IndicatorVerdict {
  indicator: string;
  indicator_type: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  rationale: string;
  sources: SourceVerdict[];
  conflicting: boolean;
  synthetic: boolean;
  role?: string;
}

export interface Enrichment {
  indicator_verdicts?: Record<string, IndicatorVerdict>;
  cmdb_asset?: { asset_id: string; hostname?: string; criticality: string; environment?: string; owner_team?: string; tags: string[]; source: string } | null;
  iam_identity?: { username: string; full_name?: string; department?: string; is_privileged: boolean; status: string; source: string } | null;
  sources?: Record<string, string>;
  enriched_at?: number;
}

export interface GuardrailResult {
  decision: 'ALLOW' | 'REQUIRE_APPROVAL' | 'DENY' | 'ERROR';
  action_proposal: { action_name: string; category: string; target_entities: string[]; rationale: string; proposed_by: string };
  action_hash: string;
  reason: string;
  violations: { rule_name: string; reason: string; severity: string }[];
  required_approvals: string[];
  audit_event_id?: string | null;
}

export interface StageRecord { stage_name: string; status: string; duration_ms: number; message?: string | null; error?: string | null; retry_count: number; }

export interface AlertDetail {
  alert_id: string;
  workflow_status: string;
  is_valid: boolean;
  source: string;
  received_at: number;
  duration_ms: number;
  completed_stages: string[];
  stage_records: Record<string, StageRecord>;
  finding?: Finding | null;
  graph_persisted: boolean;
  persisted_nodes_count: number;
  persisted_edges_count: number;
  investigation_context?: {
    graph_available: boolean;
    historical_finding_count: number;
    observed_facts: { fact_type: string; source: string; description: string }[];
    inferences: { inference_type: string; rationale: string; confidence: number }[];
    missing_evidence: string[];
  } | null;
  triage_result?: TriageResult | null;
  guardrail_results: GuardrailResult[];
  pending_approvals: string[];
  uncertainties: string[];
  errors: string[];
  enrichment?: Enrichment | null;
  incident_id?: string | null;
  source_provenance: Record<string, unknown>;
  deduplicated: boolean;
}

export interface CorrelationLink { alert_id: string; matched_key?: string | null; basis: string; confidence: number; }
export interface HistoryEntry { at: number; actor: string; action: string; detail: string; from_status?: string | null; to_status?: string | null; }
export interface Note { note_id: string; author: string; text: string; created_at: number; }

export interface Narrative {
  mode: string;
  provider?: string | null;
  model?: string | null;
  summary: string;
  observed_facts: { text: string; evidence: string[] }[];
  hypotheses: { text: string; confidence: string; evidence: string[] }[];
  uncertainties: string[];
  investigation_questions: string[];
  evidence: { id: string; kind: string; ref: string; text: string }[];
  warnings: string[];
  generated_at: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  status: IncidentStatus;
  priority: Priority;
  risk_score: number;
  risk_breakdown: { factor: string; points: number; detail: string }[];
  alert_ids: string[];
  correlation: CorrelationLink[];
  hosts: string[];
  users: string[];
  indicators: string[];
  mitre_techniques: string[];
  tactics: string[];
  first_seen?: number | null;
  last_seen?: number | null;
  created_at: number;
  updated_at: number;
  notes: Note[];
  history: HistoryEntry[];
  narrative?: Narrative | null;
  synthetic: boolean;
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  status: IncidentStatus;
  priority: Priority;
  risk_score: number;
  alert_count: number;
  hosts: string[];
  users: string[];
  tactics: string[];
  first_seen?: number | null;
  last_seen?: number | null;
  updated_at: number;
  synthetic: boolean;
}

export interface Approval {
  request_id: string;
  action_hash: string;
  action_name: string;
  target_entities: string[];
  parameters: Record<string, unknown>;
  reason: string;
  evidence_refs: string[];
  created_at: number;
  expires_at: number;
  expires_in_seconds: number;
  status: ApprovalStatus;
  proposed_by: string;
  context: { incident_id?: string; alert_id?: string };
  reviewer_id?: string | null;
  decision_at?: number | null;
  decision_reason?: string | null;
  executed_at?: number | null;
  executed_by?: string | null;
  execution_outcome?: string | null;
  simulated: boolean;
}

export interface ActionSpec { action_name: string; label: string; category: string; target_kind: 'host' | 'ip' | 'user' | 'incident'; description: string; }

export interface AuditEvent {
  event_id: string;
  timestamp: number;
  iso_time: string;
  actor: string;
  operation: string;
  decision: string;
  outcome: string;
  approval_id?: string | null;
  evidence_refs: string[];
  metadata: Record<string, unknown>;
  prev_event_hash: string;
  event_hash: string;
}

export interface IncidentBundle {
  incident: Incident;
  alerts: AlertSummary[];
  approvals: Approval[];
  audit_events: AuditEvent[];
  available_actions: ActionSpec[];
  narrative_mode: { provider: string; model?: string | null; mode: string };
}

export interface ServiceHealth { name: string; status: 'ok' | 'degraded' | 'down' | 'unknown'; detail: string; }

export interface Dashboard {
  stats: Record<string, number>;
  top_hosts: { name: string; count: number }[];
  top_users: { name: string; count: number }[];
  top_tactics: { name: string; count: number }[];
  alert_trend: ({ bucket_start: number } & Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW', number>)[];
  trend_bucket_hours: number;
  priority_incidents: IncidentSummary[];
  recent_alerts: AlertSummary[];
  pending_approvals: Approval[];
  recent_audit: AuditEvent[];
  services: ServiceHealth[];
  synthetic_data_present: boolean;
  generated_at: number;
}

export interface GraphNode { id: string; label: string; name: string; confidence?: number | null; alert_id?: string; incident_id?: string | null; }
export interface GraphEdge { id: string; source: string; target: string; type: string; confidence?: number | null; provenance?: string | null; valid_from?: string | null; last_seen?: string | null; }
export interface GraphData { source: 'neo4j' | 'workflow_resolution'; persisted: boolean; note: string; centers: string[]; nodes: GraphNode[]; edges: GraphEdge[]; }

export interface Scenario { scenario_id: string; name: string; description: string; expected_outcome: string; alert_count: number; synthetic: boolean; }

export interface IntegrationsStatus {
  wazuh: { enabled: boolean; status: string; endpoint?: string };
  neo4j: { enabled: boolean; database?: string; detail?: string };
  misp: { enabled: boolean; base_url?: string; verify_ssl?: boolean };
  cmdb: { enabled: boolean; provider?: string; synthetic?: boolean };
  persistence: { backend: string };
  llm: { provider: string; model?: string | null; mode: string };
  auth: { configured: boolean; mode: string };
  demo_mode: boolean;
}
