import React, { useState } from 'react';
import {
  ShieldAlert,
  Database,
  Globe,
  UserCheck,
  Server,
  Zap,
  CheckCircle,
  AlertTriangle,
  FileText,
  Lock,
} from 'lucide-react';
import { InvestigationDetail as IInvestigationDetail } from '../types.ts';
import { ApprovalModal } from './ApprovalModal.tsx';

interface InvestigationDetailProps {
  detail: IInvestigationDetail | null;
  isLoading: boolean;
  onEnrich: (alertId: string) => Promise<void>;
  onSubmitApproval: (
    requestId: string,
    decision: 'APPROVE' | 'REJECT',
    reviewerId: string,
    reason: string
  ) => Promise<void>;
}

export const InvestigationDetail: React.FC<InvestigationDetailProps> = ({
  detail,
  isLoading,
  onEnrich,
  onSubmitApproval,
}) => {
  const [activeModalRequest, setActiveModalRequest] = useState<{ id: string; action: string } | null>(null);
  const [isEnriching, setIsEnriching] = useState(false);

  if (isLoading && !detail) {
    return (
      <div className="panel detail-card">
        <div className="empty-state">
          <div className="spinner" />
          <span>Loading investigation details...</span>
        </div>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="panel detail-card">
        <div className="empty-state">
          <ShieldAlert size={48} color="var(--text-muted)" />
          <h3>Select an investigation to view details</h3>
          <p>Choose an alert from the list on the left to inspect triage, graph context, MISP intel, and approvals.</p>
        </div>
      </div>
    );
  }

  const triage = detail.triage_result;
  const finding = detail.finding;
  const enrichment = detail.enrichment;
  const mispIndicators = enrichment?.misp_indicators || {};
  const cmdbAsset = enrichment?.cmdb_asset;
  const iamUser = enrichment?.iam_identity;
  const llmContext = detail.investigation_context;

  const handleEnrichClick = async () => {
    setIsEnriching(true);
    try {
      await onEnrich(detail.alert_id);
    } finally {
      setIsEnriching(false);
    }
  };

  return (
    <div className="detail-view" id="investigation-detail-container">
      {/* Header Card */}
      <div className="detail-card">
        <div className="detail-header">
          <div className="detail-title-group">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
              <span className={`priority-pill ${triage?.priority || 'P3'}`}>
                {triage?.priority || 'UNKNOWN'} • Score: {triage?.score ?? 0}/100
              </span>
              <span className="status-badge">
                <span className="status-dot active" />
                <span>{detail.workflow_status}</span>
              </span>
            </div>
            <h2>{finding?.finding_info?.title || 'Security Investigation Detail'}</h2>
            <div className="detail-sub-meta">
              <span className="mono">Alert ID: {detail.alert_id}</span>
              <span>•</span>
              <span>Source: {detail.source}</span>
              <span>•</span>
              <span>Execution Time: {detail.duration_ms.toFixed(1)}ms</span>
            </div>
          </div>

          <div className="action-bar">
            <button
              className="btn btn-primary"
              onClick={handleEnrichClick}
              disabled={isEnriching}
              id="btn-enrich-alert"
            >
              <Globe size={14} className={isEnriching ? 'spinner' : ''} />
              <span>{isEnriching ? 'Enriching...' : 'Enrich MISP & CMDB'}</span>
            </button>
          </div>
        </div>

        {/* Pending Approval Banner */}
        {detail.pending_approvals.length > 0 && (
          <div className="approval-alert-box" style={{ marginBottom: '1.25rem' }}>
            <div className="approval-alert-header">
              <AlertTriangle size={18} />
              <span>Action Blocked by Safety Guardrails — Human Approval Required</span>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
              A high-risk containment action has been proposed. Guardrail policy requires authorized human review before execution.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {detail.pending_approvals.map((reqId) => {
                const gr = detail.guardrail_results.find((g) => g.approval_request_id === reqId);
                const actionDesc = gr ? `${gr.proposed_action.action_type} on ${gr.proposed_action.target_id}` : reqId;
                return (
                  <button
                    key={reqId}
                    className="btn btn-warning"
                    style={{ background: 'var(--warning)', color: 'black', fontWeight: 600 }}
                    onClick={() => setActiveModalRequest({ id: reqId, action: actionDesc })}
                  >
                    Review Approval: {actionDesc}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Triage & Investigation Assessment */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div className="section-title">
            <Zap size={16} />
            <span>Deterministic Triage Evaluation</span>
          </div>

          {triage ? (
            <div className="two-col-grid">
              <div className="sub-panel">
                <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                  Rule: {triage.rule_id}
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                  {triage.description}
                </div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                  Assessment Factors:
                </div>
                <ul className="reasons-list">
                  {triage.reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>

              <div className="sub-panel">
                <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                  Recommended Response Actions:
                </div>
                <ul className="reasons-list" style={{ marginBottom: '0.75rem' }}>
                  {triage.recommended_actions.map((act, i) => (
                    <li key={i}>{act}</li>
                  ))}
                </ul>

                <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                  MITRE ATT&CK Techniques:
                </div>
                <div className="tag-container">
                  {triage.mitre_techniques.length > 0 ? (
                    triage.mitre_techniques.map((tech) => (
                      <span key={tech} className="tag-pill mitre">
                        {tech}
                      </span>
                    ))
                  ) : (
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>None identified</span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="sub-panel" style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              No deterministic triage evaluation produced for this alert.
            </div>
          )}
        </div>

        {/* External Threat Intelligence (MISP) */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div className="section-title">
            <Globe size={16} />
            <span>Threat Intelligence Context (MISP)</span>
          </div>

          <div className="sub-panel">
            {Object.keys(mispIndicators).length === 0 ? (
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                No external MISP indicator query performed yet. Click &quot;Enrich MISP & CMDB&quot; to look up observed IP/domain indicators.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {Object.entries(mispIndicators).map(([indicator, data]) => {
                  return (
                    <div key={indicator} style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                        <span className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                          {indicator}
                        </span>
                        <span
                          className={`priority-pill ${data.match ? 'P1' : 'P4'}`}
                          style={{ fontSize: '0.65rem' }}
                        >
                          {data.status}
                        </span>
                      </div>

                      {data.match ? (
                        <div className="key-value-list">
                          <div className="kv-item">
                            <span className="kv-label">Threat Level:</span>
                            <span className="kv-val" style={{ color: 'var(--p1-crit)' }}>{data.match.threat_level}</span>
                          </div>
                          <div className="kv-item">
                            <span className="kv-label">Event:</span>
                            <span className="kv-val">{data.match.event_info} (ID: {data.match.event_id})</span>
                          </div>
                          <div className="kv-item">
                            <span className="kv-label">Confidence:</span>
                            <span className="kv-val">{data.match.confidence}%</span>
                          </div>
                          {data.match.tags.length > 0 && (
                            <div className="tag-container">
                              {data.match.tags.map((t) => (
                                <span key={t} className="tag-pill">{t}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                          No known threat intelligence match. (Principle of Explicit Uncertainty: Missing intel != confirmed safe).
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* IAM & CMDB Context */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div className="section-title">
            <UserCheck size={16} />
            <span>Asset & Identity Context (IAM / CMDB)</span>
          </div>

          <div className="two-col-grid">
            <div className="sub-panel">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                <Server size={14} color="var(--accent-cyan)" />
                <span>Device / Host Context</span>
              </div>
              {cmdbAsset ? (
                <div className="key-value-list">
                  <div className="kv-item">
                    <span className="kv-label">Hostname:</span>
                    <span className="kv-val mono">{cmdbAsset.hostname}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Criticality:</span>
                    <span className="kv-val" style={{ color: cmdbAsset.criticality === 'CRITICAL' ? 'var(--p1-crit)' : 'var(--accent-cyan)' }}>
                      {cmdbAsset.criticality}
                    </span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Environment:</span>
                    <span className="kv-val">{cmdbAsset.environment}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Owner:</span>
                    <span className="kv-val">{cmdbAsset.owner_email || 'Unassigned'}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Impact:</span>
                    <span className="kv-val">{cmdbAsset.business_impact || 'Standard'}</span>
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  No host record found in CMDB.
                </div>
              )}
            </div>

            <div className="sub-panel">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                <Lock size={14} color="var(--accent-blue)" />
                <span>Identity / User Context</span>
              </div>
              {iamUser ? (
                <div className="key-value-list">
                  <div className="kv-item">
                    <span className="kv-label">Username:</span>
                    <span className="kv-val mono">{iamUser.username}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Account Status:</span>
                    <span className="kv-val">{iamUser.account_status}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Privileged Account:</span>
                    <span className="kv-val" style={{ color: iamUser.is_privileged ? 'var(--warning)' : 'var(--text-secondary)' }}>
                      {iamUser.is_privileged ? 'YES (Admin)' : 'No'}
                    </span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Department:</span>
                    <span className="kv-val">{iamUser.department || 'N/A'}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">MFA Enabled:</span>
                    <span className="kv-val">{iamUser.mfa_enabled ? 'Enforced' : 'Disabled'}</span>
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  No identity record found in IAM provider.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Temporal Knowledge Graph Context */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div className="section-title">
            <Database size={16} />
            <span>Temporal Knowledge Graph (Neo4j)</span>
          </div>

          <div className="sub-panel">
            <div className="key-value-list">
              <div className="kv-item">
                <span className="kv-label">Graph Persistence Status:</span>
                <span className="kv-val">{detail.graph_persisted ? 'Persisted to Neo4j' : 'Memory / Skipped'}</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Nodes Created / Merged:</span>
                <span className="kv-val">{detail.persisted_nodes_count}</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Temporal Relationships:</span>
                <span className="kv-val">{detail.persisted_edges_count}</span>
              </div>
            </div>
          </div>
        </div>

        {/* LLM Agent Investigation Summary if present */}
        {llmContext && (
          <div style={{ marginBottom: '1.25rem' }}>
            <div className="section-title">
              <FileText size={16} />
              <span>LLM Orchestration Context</span>
            </div>
            <div className="sub-panel">
              <pre className="mono" style={{ fontSize: '0.75rem', whiteSpace: 'pre-wrap', color: 'var(--text-secondary)' }}>
                {JSON.stringify(llmContext, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* Audit & Guardrail Trail */}
        <div>
          <div className="section-title">
            <CheckCircle size={16} />
            <span>Safety Guardrail Decisions & Audit Trail</span>
          </div>

          <div className="sub-panel">
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
              Tamper-evident SHA-256 Audit Records: {detail.audit_event_ids.length} recorded
            </div>
            {detail.guardrail_results.map((gr, idx) => (
              <div key={idx} style={{ padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.8rem' }}>
                <span style={{ fontWeight: 600, color: gr.decision === 'ALLOW' ? 'var(--success)' : gr.decision === 'BLOCK' ? 'var(--danger)' : 'var(--warning)' }}>
                  [{gr.decision}]
                </span>{' '}
                Action: <span className="mono">{gr.proposed_action.action_type}</span> on <span className="mono">{gr.proposed_action.target_id}</span>
                {gr.violations.length > 0 && (
                  <div style={{ color: 'var(--danger)', fontSize: '0.75rem', marginTop: '0.2rem' }}>
                    Violations: {gr.violations.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Approval Modal */}
      {activeModalRequest && (
        <ApprovalModal
          requestId={activeModalRequest.id}
          actionSummary={activeModalRequest.action}
          isOpen={true}
          onClose={() => setActiveModalRequest(null)}
          onSubmit={async (reqId, decision, reviewerId, reason) => {
            await onSubmitApproval(reqId, decision, reviewerId, reason);
            setActiveModalRequest(null);
          }}
        />
      )}
    </div>
  );
};
