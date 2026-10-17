export interface InvestigationSummary {
  alert_id: string;
  finding_id?: string | null;
  title: string;
  priority: 'P1' | 'P2' | 'P3' | 'P4' | 'UNKNOWN';
  score: number;
  severity: string;
  workflow_status: string;
  received_at: number;
  duration_ms: number;
  asset_name?: string | null;
  username?: string | null;
  mitre_techniques: string[];
  pending_approvals_count: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface MISPIndicatorMatch {
  indicator: string;
  indicator_type: string;
  category: string;
  threat_level: string;
  event_id: string;
  event_info: string;
  tags: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  confidence: number;
}

export interface AssetContextRecord {
  asset_id: string;
  hostname: string;
  fqdn?: string | null;
  ip_addresses: string[];
  mac_addresses: string[];
  os_family?: string | null;
  os_version?: string | null;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  environment: string;
  owner_email?: string | null;
  department?: string | null;
  is_isolated: boolean;
  business_impact?: string | null;
}

export interface IdentityContextRecord {
  user_id: string;
  username: string;
  email?: string | null;
  display_name?: string | null;
  department?: string | null;
  job_title?: string | null;
  roles: string[];
  is_privileged: boolean;
  account_status: 'ACTIVE' | 'DISABLED' | 'LOCKED' | 'SUSPENDED' | 'EXPIRED' | 'UNKNOWN';
  mfa_enabled: boolean;
  manager_email?: string | null;
}

export interface InvestigationDetail {
  alert_id: string;
  workflow_status: string;
  is_valid: boolean;
  source: string;
  received_at: number;
  completed_at: number;
  duration_ms: number;
  completed_stages: string[];
  finding?: Record<string, any> | null;
  resolution?: Record<string, any> | null;
  graph_persisted: boolean;
  persisted_nodes_count: number;
  persisted_edges_count: number;
  investigation_context?: Record<string, any> | null;
  triage_result?: {
    priority: 'P1' | 'P2' | 'P3' | 'P4';
    score: number;
    rule_id: string;
    description: string;
    reasons: string[];
    mitre_techniques: string[];
    recommended_actions: string[];
    risk_factors: Record<string, any>;
  } | null;
  guardrail_results: Array<{
    decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_HUMAN_APPROVAL';
    proposed_action: {
      action_type: string;
      target_type: string;
      target_id: string;
      risk_level: string;
      reason: string;
      is_reversible: boolean;
    };
    violations: string[];
    approval_request_id?: string | null;
    timestamp: number;
  }>;
  pending_approvals: string[];
  audit_event_ids: string[];
  uncertainties: string[];
  errors: string[];
  enrichment?: {
    misp_indicators?: Record<string, {
      status: string;
      match?: MISPIndicatorMatch | null;
      error?: string | null;
      is_confirmed_safe: boolean;
    }>;
    cmdb_asset?: AssetContextRecord | null;
    iam_identity?: IdentityContextRecord | null;
    enriched_at?: number;
  } | null;
}

export interface DashboardStats {
  total_investigations: number;
  priority_p1: number;
  priority_p2: number;
  priority_p3: number;
  priority_p4: number;
  pending_approvals: number;
  critical_threats: number;
}

export interface IntegrationsStatus {
  wazuh: { enabled: boolean; endpoint?: string };
  neo4j: { enabled: boolean; database?: string };
  misp: { enabled: boolean; base_url?: string; verify_ssl?: boolean };
  cmdb: { enabled: boolean; provider?: string };
}
