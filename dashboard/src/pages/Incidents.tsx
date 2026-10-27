import React, { useState } from 'react';
import { Download, Search, Sparkles } from 'lucide-react';
import { api, downloadJson, patch, post } from '../api.ts';
import { href, navigate } from '../router.ts';
import { GraphData, IncidentBundle, IncidentStatus, IncidentSummary, Narrative, Paginated, Principal } from '../types.ts';
import { GraphCanvas } from '../components/GraphCanvas.tsx';
import { ApprovalActions } from './Approvals.tsx';
import { Async, Badge, duration, Empty, ErrorBox, fmtTime, Panel, Score, SyntheticBadge, timeAgo, useLoad } from '../components/ui.tsx';

const STATUSES: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'];

export const IncidentsPage: React.FC = () => {
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState('');
  const [page, setPage] = useState(1);
  const list = useLoad(() => {
    const q = new URLSearchParams({ page: String(page), page_size: '25' });
    if (status) q.set('status', status);
    if (applied) q.set('search', applied);
    return api<Paginated<IncidentSummary>>(`/api/v1/incidents?${q}`);
  }, [status, applied, page]);

  return (
    <Panel title="Incidents" sub={list.data ? `${list.data.total} total · open first, then risk` : undefined} flush
      right={
        <form className="row" onSubmit={(e) => { e.preventDefault(); setPage(1); setApplied(search); }}>
          <div className="segmented" role="group" aria-label="Status filter">
            <button type="button" className={status === '' ? 'on' : ''} onClick={() => { setPage(1); setStatus(''); }}>All</button>
            {STATUSES.map((s) => <button type="button" key={s} className={status === s ? 'on' : ''} onClick={() => { setPage(1); setStatus(s); }}>{s.replace('_', ' ').toLowerCase()}</button>)}
          </div>
          <input className="input" placeholder="Search title, host, user, indicator" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search incidents" />
          <button className="btn" type="submit"><Search size={14} /></button>
        </form>
      }>
      <Async state={list}>
        {(d) => d.items.length === 0 ? <Empty title="No incidents" hint="Incidents are opened when alerts triaged MEDIUM or above arrive, or when alerts correlate." /> : (
          <>
            <table className="table">
              <thead><tr><th>Incident</th><th>Priority</th><th className="num">Risk</th><th>Status</th><th className="num">Alerts</th><th>Hosts / accounts</th><th>Tactics</th><th>Last activity</th></tr></thead>
              <tbody>
                {d.items.map((i) => (
                  <tr key={i.incident_id} className="click" onClick={() => navigate('incidents', i.incident_id)}>
                    <td><div className="cell-title truncate" title={i.title}>{i.title}</div><div className="cell-sub mono">{i.incident_id} {i.synthetic && <SyntheticBadge />}</div></td>
                    <td><Badge kind={i.priority} /></td>
                    <td className="num"><Score score={i.risk_score} priority={i.priority} /></td>
                    <td><Badge kind={i.status} /></td>
                    <td className="num">{i.alert_count}</td>
                    <td className="small">{i.hosts.join(', ') || '—'}<div className="muted">{i.users.join(', ')}</div></td>
                    <td className="small">{i.tactics.join(' → ') || '—'}</td>
                    <td className="small muted">{timeAgo(i.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="row" style={{ padding: '10px 16px', justifyContent: 'flex-end' }}>
              <button className="btn sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
              <span className="small muted">Page {d.page} of {d.total_pages}</span>
              <button className="btn sm" disabled={page >= d.total_pages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </>
        )}
      </Async>
    </Panel>
  );
};

const NarrativeView: React.FC<{ n: Narrative }> = ({ n }) => {
  const cite = (ids: string[]) => ids.map((id) => <span key={id} className="evidence-ref" title={n.evidence.find((e) => e.id === id)?.text}>{id}</span>);
  return (
    <div className="stack">
      <div className="row">
        <Badge kind={n.mode.startsWith('llm') ? 'warn' : 'neutral'}>{n.mode.startsWith('llm') ? `AI-generated · ${n.model}` : 'Deterministic template'}</Badge>
        <span className="small muted">generated {timeAgo(n.generated_at)}</span>
      </div>
      {n.warnings.map((w, i) => <div key={i} className="alert-box warn small">{w}</div>)}
      <p>{n.summary}</p>
      <div className="grid g-2">
        <div><h3 className="small" style={{ marginBottom: 6 }}>Observed facts</h3>
          <ul style={{ paddingLeft: 16 }} className="small">{n.observed_facts.map((f, i) => <li key={i} style={{ marginBottom: 4 }}>{f.text}{cite(f.evidence)}</li>)}</ul></div>
        <div className="stack">
          <div><h3 className="small" style={{ marginBottom: 6 }}>Hypotheses (unconfirmed)</h3>
            {n.hypotheses.length === 0 ? <p className="small muted">None — insufficient evidence for a hypothesis.</p> :
              <ul style={{ paddingLeft: 16 }} className="small">{n.hypotheses.map((h, i) => <li key={i} style={{ marginBottom: 4 }}><Badge kind="neutral">{h.confidence}</Badge> {h.text}{cite(h.evidence)}</li>)}</ul>}</div>
          <div><h3 className="small" style={{ marginBottom: 6 }}>Uncertainty</h3><ul style={{ paddingLeft: 16 }} className="small muted">{n.uncertainties.map((u, i) => <li key={i}>{u}</li>)}</ul></div>
          <div><h3 className="small" style={{ marginBottom: 6 }}>Questions to investigate</h3><ol style={{ paddingLeft: 16 }} className="small">{n.investigation_questions.map((q, i) => <li key={i}>{q}</li>)}</ol></div>
        </div>
      </div>
      <details><summary className="small muted" style={{ cursor: 'pointer' }}>Evidence index ({n.evidence.length})</summary>
        <table className="table" style={{ marginTop: 8 }}><tbody>{n.evidence.map((e) => <tr key={e.id}><td className="mono small">{e.id}</td><td className="small">{e.kind}</td><td className="small">{e.text}</td><td className="mono small muted">{e.ref}</td></tr>)}</tbody></table>
      </details>
    </div>
  );
};

type Tab = 'overview' | 'timeline' | 'graph' | 'narrative' | 'response' | 'notes';

export const IncidentWorkspace: React.FC<{ incidentId: string; who: Principal; onChanged: () => void }> = ({ incidentId, who, onChanged }) => {
  const state = useLoad(() => api<IncidentBundle>(`/api/v1/incidents/${encodeURIComponent(incidentId)}`), [incidentId]);
  const [tab, setTab] = useState<Tab>('overview');
  const [graphKey, setGraphKey] = useState(0);
  const graph = useLoad(() => (tab === 'graph' ? api<GraphData>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/graph`) : Promise.resolve(null)), [incidentId, tab, graphKey]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [statusReason, setStatusReason] = useState('');
  const [nextStatus, setNextStatus] = useState<IncidentStatus>('INVESTIGATING');
  const [note, setNote] = useState('');
  const [action, setAction] = useState({ action_name: '', target: '', rationale: '' });
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const analyst = who.role !== 'viewer';

  const run = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setErr(null);
    try {
      await fn();
      await state.reload();
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Async state={state} loadingLabel="Loading incident…">
      {(b) => {
        const inc = b.incident;
        // The select never offers the current status; resolve stale state to a valid option.
        const selectedNext: IncidentStatus = nextStatus !== inc.status ? nextStatus : (STATUSES.find((s) => s !== inc.status) as IncidentStatus);
        const spec = b.available_actions.find((s) => s.action_name === action.action_name);
        const targets = !spec ? [] : spec.target_kind === 'host' ? inc.hosts : spec.target_kind === 'ip' ? inc.indicators : spec.target_kind === 'user' ? inc.users : [inc.incident_id];
        return (
          <>
            <div className="panel">
              <div className="panel-head" style={{ flexWrap: 'wrap', gap: 10 }}>
                <Badge kind={inc.priority} />
                <h2 style={{ fontSize: 16 }}>{inc.title}</h2>
                <Badge kind={inc.status} />
                {inc.synthetic && <SyntheticBadge />}
                <div className="right">
                  <button className="btn sm" onClick={() => void downloadJson(`/api/v1/incidents/${inc.incident_id}/report`, `${inc.incident_id}-report.json`).catch((e) => setErr((e as Error).message))}>
                    <Download size={13} /> Export JSON report
                  </button>
                </div>
              </div>
              <div className="panel-body">
                <div className="row small muted" style={{ gap: 16 }}>
                  <span className="mono">{inc.incident_id}</span>
                  <span>Risk <strong style={{ color: 'var(--text)' }}>{inc.risk_score}/100</strong></span>
                  <span>{inc.alert_ids.length} alerts</span>
                  <span>First seen {fmtTime(inc.first_seen)}</span>
                  <span>Last seen {fmtTime(inc.last_seen)}</span>
                </div>
                {analyst && (
                  <form className="row" style={{ marginTop: 10 }} onSubmit={(e) => { e.preventDefault(); void run('status', () => patch(`/api/v1/incidents/${inc.incident_id}/status`, { status: selectedNext, reason: statusReason })).then(() => setStatusReason('')); }}>
                    <label className="small muted" htmlFor="ns">Set status</label>
                    <select id="ns" className="select" value={selectedNext} onChange={(e) => setNextStatus(e.target.value as IncidentStatus)}>
                      {STATUSES.filter((s) => s !== inc.status).map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                    </select>
                    <input className="input" style={{ flex: 1, minWidth: 200 }} placeholder="Reason (required, recorded in audit log)" value={statusReason} onChange={(e) => setStatusReason(e.target.value)} />
                    <button className="btn" disabled={busy !== null || statusReason.trim().length < 3}>{busy === 'status' ? 'Saving…' : 'Update'}</button>
                  </form>
                )}
              </div>
              <div className="tabs" role="tablist">
                {([['overview', 'Overview'], ['timeline', `Timeline (${b.alerts.length})`], ['graph', 'Graph'], ['narrative', 'Investigation summary'],
                  ['response', `Response (${b.approvals.filter((a) => a.status === 'PENDING').length} pending)`], ['notes', `Notes & history (${inc.notes.length})`]] as [Tab, string][]).map(([k, label]) => (
                  <button key={k} role="tab" aria-selected={tab === k} className={`tab${tab === k ? ' on' : ''}`} onClick={() => setTab(k)}>{label}</button>
                ))}
              </div>
            </div>
            {err && <ErrorBox message={err} />}

            {tab === 'overview' && (
              <div className="grid g-main-side">
                <div className="stack">
                  <Panel title="Risk explanation" sub="deterministic; LLM output never changes it">
                    <div className="breakdown">
                      {inc.risk_breakdown.map((r, i) => (
                        <div key={i} className="breakdown-row"><span className={`pts${i > 0 && r.points > 0 ? ' pos' : ''}`}>{i > 0 && r.points > 0 ? '+' : ''}{r.points}</span><span><strong>{r.factor.replace(/_/g, ' ')}</strong> — <span className="muted">{r.detail}</span></span></div>
                      ))}
                      <div className="breakdown-row"><span className="pts">= {inc.risk_score}</span><span className="small muted">Priority {inc.priority} (≥80 CRITICAL, ≥60 HIGH, ≥35 MEDIUM; never below the highest alert priority). Open an alert for its factor-level breakdown.</span></div>
                    </div>
                  </Panel>
                  <Panel title="Correlation basis" sub="why each alert belongs here" flush>
                    <table className="table">
                      <thead><tr><th>Alert</th><th>Basis</th><th className="num">Confidence</th></tr></thead>
                      <tbody>{inc.correlation.map((c) => (
                        <tr key={c.alert_id}><td className="mono small"><a href={href('alerts', c.alert_id)}>{c.alert_id}</a></td>
                          <td className="small">{c.basis}{c.matched_key && <div><span className="tag">{c.matched_key}</span></div>}</td>
                          <td className="num mono">{c.confidence.toFixed(2)}</td></tr>
                      ))}</tbody>
                    </table>
                  </Panel>
                </div>
                <div className="stack">
                  <Panel title="Affected entities">
                    <dl className="kv" style={{ gridTemplateColumns: '90px 1fr' }}>
                      <dt>Hosts</dt><dd>{inc.hosts.map((h) => <div key={h}><a href={`${href('alerts')}?host=${encodeURIComponent(h)}`}>{h}</a></div>)}{inc.hosts.length === 0 && '—'}</dd>
                      <dt>Accounts</dt><dd>{inc.users.join(', ') || '—'}</dd>
                      <dt>Indicators</dt><dd>{inc.indicators.map((i) => <div key={i} className="mono small"><a href={`${href('intel')}?q=${encodeURIComponent(i)}`}>{i}</a></div>)}{inc.indicators.length === 0 && '—'}</dd>
                    </dl>
                  </Panel>
                  <Panel title="MITRE ATT&CK" sub="from detection rules">
                    {inc.mitre_techniques.length === 0 ? <Empty title="No techniques mapped" /> : (
                      <div className="stack" style={{ gap: 6 }}>
                        <div className="small muted">Tactics observed: {inc.tactics.join(' → ') || 'unknown'}</div>
                        <div className="row">{inc.mitre_techniques.map((t) => <span key={t} className="tag">{t}</span>)}</div>
                        <div className="small muted">Mappings are asserted by the source rules, not inferred by AI. See each alert for the supporting detection.</div>
                      </div>
                    )}
                  </Panel>
                </div>
              </div>
            )}

            {tab === 'timeline' && (
              <Panel title="Alert timeline" sub="ordered by event time">
                <div className="timeline">
                  {b.alerts.map((a) => (
                    <div key={a.alert_id} className={`tl-item ${a.priority}`}>
                      <div className="tl-time">{fmtTime(a.event_time)}</div>
                      <div className="row"><Badge kind={a.priority} /><a href={href('alerts', a.alert_id)} className="cell-title">{a.title}</a><span className="small muted">score {a.score}</span></div>
                      <div className="small muted">{a.asset_name ?? 'unknown host'}{a.username ? ` · ${a.username}` : ''}{a.src_ip ? ` · ${a.src_ip}` : ''}{a.dst_ip ? ` → ${a.dst_ip}` : ''} {a.mitre_techniques.map((t) => <span key={t} className="tag" style={{ marginLeft: 4 }}>{t}</span>)}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {tab === 'graph' && (
              <Panel title="Entity graph" sub={graph.data ? graph.data.note : undefined} flush
                right={<>{graph.data && <Badge kind={graph.data.persisted ? 'ok' : 'warn'}>{graph.data.persisted ? 'Neo4j' : 'not persisted'}</Badge>}<button className="btn sm" onClick={() => setGraphKey(graphKey + 1)}>Reload</button></>}>
                {graph.error ? <div className="panel-body"><ErrorBox message={graph.error} /></div> : !graph.data ? <div className="state"><div className="spinner" />Loading graph…</div> : <GraphCanvas graph={graph.data} />}
              </Panel>
            )}

            {tab === 'narrative' && (
              <Panel title="Investigation summary" sub={`mode: ${b.narrative_mode.mode}`}
                right={analyst && (
                  <>
                    <button className="btn sm" disabled={busy !== null} onClick={() => void run('narr', () => post<Narrative>(`/api/v1/incidents/${inc.incident_id}/narrative`, { use_llm: false }))}>Generate (template)</button>
                    <button className="btn sm primary" disabled={busy !== null || !b.narrative_mode.mode.startsWith('llm')} title={b.narrative_mode.mode.startsWith('llm') ? '' : 'No LLM provider configured'}
                      onClick={() => void run('narr', () => post<Narrative>(`/api/v1/incidents/${inc.incident_id}/narrative`, { use_llm: true }))}><Sparkles size={13} /> Generate with AI</button>
                  </>
                )}>
                {busy === 'narr' ? <div className="state"><div className="spinner" />Generating…</div> : inc.narrative ? <NarrativeView n={inc.narrative} /> :
                  <Empty title="No summary generated yet" hint="The template summary uses only numbered evidence. AI mode is available when an LLM provider is configured." />}
              </Panel>
            )}

            {tab === 'response' && (
              <div className="grid g-main-side">
                <Panel title="Response actions" sub="human approval required · all actions simulated" flush>
                  {b.approvals.length === 0 ? <Empty title="No actions proposed" /> : (
                    <table className="table">
                      <thead><tr><th>Action</th><th>Status</th><th>Proposed by</th><th>Expires</th><th>Decision</th></tr></thead>
                      <tbody>{b.approvals.map((a) => (
                        <tr key={a.request_id}>
                          <td><strong>{a.action_name}</strong><div className="cell-sub mono">{a.request_id} · {a.target_entities.join(', ')}</div><div className="small muted">{a.reason}</div></td>
                          <td><Badge kind={a.status} /></td>
                          <td className="small">{a.proposed_by}</td>
                          <td className="small muted">{a.status === 'PENDING' || a.status === 'APPROVED' ? duration(a.expires_in_seconds) : '—'}</td>
                          <td><ApprovalActions approval={a} who={who} onDone={() => { void state.reload(); onChanged(); }} /></td>
                        </tr>
                      ))}</tbody>
                    </table>
                  )}
                </Panel>
                <Panel title="Propose action">
                  {!analyst ? <p className="small muted">Analyst role required.</p> : (
                    <form className="stack" onSubmit={(e) => {
                      e.preventDefault();
                      void run('act', async () => {
                        const r = await post<{ guardrail: { decision: string; reason: string } }>(`/api/v1/incidents/${inc.incident_id}/actions`, action);
                        setActionMsg(`Guardrail: ${r.guardrail.decision} — ${r.guardrail.reason}`);
                        setAction({ action_name: '', target: '', rationale: '' });
                      });
                    }}>
                      <div className="field"><label htmlFor="an">Action</label>
                        <select id="an" className="select" value={action.action_name} onChange={(e) => setAction({ ...action, action_name: e.target.value, target: '' })}>
                          <option value="">Select…</option>
                          {b.available_actions.map((s) => <option key={s.action_name} value={s.action_name}>{s.label} — {s.category}</option>)}
                        </select>
                        {spec && <span className="small muted">{spec.description}</span>}
                      </div>
                      <div className="field"><label htmlFor="at">Target ({spec?.target_kind ?? '—'})</label>
                        <select id="at" className="select" value={action.target} disabled={!spec} onChange={(e) => setAction({ ...action, target: e.target.value })}>
                          <option value="">Select…</option>{targets.map((t) => <option key={t}>{t}</option>)}
                        </select>
                      </div>
                      <div className="field"><label htmlFor="ar">Rationale</label>
                        <textarea id="ar" className="textarea" rows={3} style={{ fontFamily: 'var(--font)' }} value={action.rationale} onChange={(e) => setAction({ ...action, rationale: e.target.value })} placeholder="Evidence-based reason for this action" />
                      </div>
                      <button className="btn primary" disabled={busy !== null || !action.action_name || !action.target || action.rationale.trim().length < 5}>Submit for guardrail evaluation</button>
                      {actionMsg && <div className="alert-box info small">{actionMsg}</div>}
                      <p className="small muted">The guardrail binds approval to a SHA-256 hash of the exact action. Proposers cannot approve their own actions. Execution is simulated and recorded in the audit log.</p>
                    </form>
                  )}
                </Panel>
              </div>
            )}

            {tab === 'notes' && (
              <div className="grid g-2">
                <Panel title="Analyst notes">
                  <div className="stack">
                    {inc.notes.length === 0 && <p className="small muted">No notes yet.</p>}
                    {inc.notes.map((n) => <div key={n.note_id} className="panel" style={{ padding: 10 }}><div className="small muted">{n.author} · {fmtTime(n.created_at)}</div><div style={{ whiteSpace: 'pre-wrap' }}>{n.text}</div></div>)}
                    {analyst && (
                      <form className="stack" onSubmit={(e) => { e.preventDefault(); void run('note', () => post(`/api/v1/incidents/${inc.incident_id}/notes`, { text: note })).then(() => setNote('')); }}>
                        <textarea className="textarea" rows={3} style={{ fontFamily: 'var(--font)' }} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note…" aria-label="New note" />
                        <button className="btn" disabled={busy !== null || !note.trim()}>Add note</button>
                      </form>
                    )}
                  </div>
                </Panel>
                <Panel title="History" sub="status changes, correlation, response actions" flush>
                  <ul className="list" style={{ padding: '0 16px' }}>{[...inc.history].reverse().map((h, i) => (
                    <li key={i}><div className="row small"><strong>{h.action.replace(/_/g, ' ')}</strong>{h.to_status && <Badge kind={h.to_status} />}<span className="muted">{h.actor} · {fmtTime(h.at)}</span></div><div className="small muted">{h.detail}</div></li>
                  ))}</ul>
                </Panel>
              </div>
            )}
          </>
        );
      }}
    </Async>
  );
};
