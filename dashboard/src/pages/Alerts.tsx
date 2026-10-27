import React, { useState } from 'react';
import { Play, Search, Upload } from 'lucide-react';
import { api, post } from '../api.ts';
import { href, navigate, Route } from '../router.ts';
import { AlertDetail, AlertSummary, IndicatorVerdict, Paginated, Principal, Scenario } from '../types.ts';
import { Async, Badge, Empty, ErrorBox, fmtTime, Panel, Score, SyntheticBadge, timeAgo, useLoad } from '../components/ui.tsx';

const EXAMPLE = JSON.stringify(
  {
    id: 'manual-0001',
    timestamp: new Date().toISOString(),
    rule: { id: '5712', level: 10, description: 'SSH brute force against admin account', mitre: { id: ['T1110.001'] } },
    agent: { id: '001', name: 'web-server-01', ip: '192.168.1.50' },
    data: { srcip: '203.0.113.195', dstip: '192.168.1.50', dstuser: 'admin' },
  },
  null,
  2,
);

const canWrite = (who: Principal) => who.role !== 'viewer';

const IngestPanel: React.FC<{ who: Principal; onDone: () => void }> = ({ who, onDone }) => {
  const scenarios = useLoad(() => api<{ demo_mode: boolean; scenarios: Scenario[] }>('/api/v1/demo/scenarios'), []);
  const [text, setText] = useState(EXAMPLE);
  const [source, setSource] = useState('manual');
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'error' | 'info'; text: React.ReactNode } | null>(null);

  const submit = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      setMsg({ kind: 'error', text: `Invalid JSON: ${(err as Error).message}` });
      return;
    }
    const alerts = Array.isArray(parsed) ? parsed : [parsed];
    if (alerts.some((a) => typeof a !== 'object' || a === null || Array.isArray(a))) {
      setMsg({ kind: 'error', text: 'Each alert must be a JSON object.' });
      return;
    }
    setBusy('manual');
    setMsg(null);
    try {
      if (alerts.length === 1) {
        const res = await post<AlertDetail>('/api/v1/alerts/ingest', { raw_alert: alerts[0], source });
        setMsg({
          kind: res.deduplicated ? 'info' : 'ok',
          text: <>{res.deduplicated ? 'Duplicate — existing alert returned: ' : 'Ingested: '}<a href={href('alerts', res.alert_id)}>{res.alert_id}</a>
            {' '}({res.triage_result?.priority ?? res.workflow_status}){res.incident_id && <> → <a href={href('incidents', res.incident_id)}>{res.incident_id}</a></>}</>,
        });
      } else {
        const res = await post<{ results: { result: string }[] }>('/api/v1/alerts/ingest/batch', { alerts, source });
        const c = (r: string) => res.results.filter((x) => x.result === r).length;
        setMsg({ kind: 'ok', text: `Batch: ${c('created')} created, ${c('deduplicated')} duplicates, ${c('failed')} failed.` });
      }
      onDone();
    } catch (err) {
      setMsg({ kind: 'error', text: (err as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const load = async (s: Scenario) => {
    setBusy(s.scenario_id);
    setMsg(null);
    try {
      const res = await post<{ results: { result: string; incident_id?: string | null }[] }>(`/api/v1/demo/scenarios/${s.scenario_id}/load`);
      const created = res.results.filter((r) => r.result === 'created').length;
      const incidents = [...new Set(res.results.map((r) => r.incident_id).filter(Boolean))] as string[];
      setMsg({
        kind: 'ok',
        text: <>Loaded “{s.name}”: {created} new alert(s), {res.results.length - created} already present.
          {incidents.length > 0 && <> Incidents: {incidents.map((i) => <a key={i} href={href('incidents', i)} style={{ marginRight: 6 }}>{i}</a>)}</>}</>,
      });
      onDone();
    } catch (err) {
      setMsg({ kind: 'error', text: (err as Error).message });
    } finally {
      setBusy(null);
    }
  };

  if (!canWrite(who)) return <div className="alert-box info">Your role ({who.role}) is read-only. Analyst role is required to ingest alerts.</div>;

  return (
    <div className="grid g-2">
      <Panel title="Synthetic demo scenarios" sub={<SyntheticBadge />}>
        <Async state={scenarios}>
          {(d) => !d.demo_mode ? <div className="alert-box warn">Demo mode is disabled (DEMO_MODE=false).</div> : (
            <ul className="list">
              {d.scenarios.map((s) => (
                <li key={s.scenario_id} className="row" style={{ flexWrap: 'nowrap', alignItems: 'flex-start' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div><strong>{s.name}</strong> <span className="muted small">· {s.alert_count} alerts</span></div>
                    <div className="small muted">{s.description}</div>
                    <div className="small" style={{ color: 'var(--text-2)' }}>Expected: {s.expected_outcome}</div>
                  </div>
                  <button className="btn sm primary" disabled={busy !== null} onClick={() => void load(s)}>
                    <Play size={12} /> {busy === s.scenario_id ? 'Loading…' : 'Load'}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Async>
      </Panel>
      <Panel title="Submit alert JSON" sub="Wazuh-style object, or an array (max 100)">
        <div className="stack">
          <textarea className="textarea" rows={11} value={text} onChange={(e) => setText(e.target.value)} aria-label="Alert JSON" spellCheck={false} />
          <div className="row">
            <label className="small muted" htmlFor="src">Source</label>
            <input id="src" className="input" style={{ width: 140 }} value={source} onChange={(e) => setSource(e.target.value)} maxLength={64} />
            <span className="spacer" />
            <button className="btn primary" disabled={busy !== null} onClick={() => void submit()}><Upload size={14} /> {busy === 'manual' ? 'Processing…' : 'Ingest'}</button>
          </div>
        </div>
      </Panel>
      {msg && <div style={{ gridColumn: '1 / -1' }} className={`alert-box ${msg.kind === 'error' ? 'error' : msg.kind === 'info' ? 'info' : 'ok'}`}>{msg.text}</div>}
    </div>
  );
};

export const AlertsPage: React.FC<{ route: Route; who: Principal; onChanged: () => void }> = ({ route, who, onChanged }) => {
  const [search, setSearch] = useState(route.query.get('search') ?? '');
  const [applied, setApplied] = useState(search);
  const [priority, setPriority] = useState('');
  const [page, setPage] = useState(1);
  const host = route.query.get('host') ?? '';
  const list = useLoad(() => {
    const q = new URLSearchParams({ page: String(page), page_size: '25' });
    if (applied) q.set('search', applied);
    if (priority) q.set('priority', priority);
    if (host) q.set('host', host);
    return api<Paginated<AlertSummary>>(`/api/v1/alerts?${q}`);
  }, [page, applied, priority, host]);

  return (
    <>
      <IngestPanel who={who} onDone={() => { void list.reload(); onChanged(); }} />
      <Panel title="Alerts" sub={list.data ? `${list.data.total} total` : undefined} flush
        right={
          <form className="row" onSubmit={(e) => { e.preventDefault(); setPage(1); setApplied(search); }}>
            {host && <a className="badge info" href={href('alerts')} title="Clear host filter">host: {host} ✕</a>}
            <select className="select" value={priority} onChange={(e) => { setPage(1); setPriority(e.target.value); }} aria-label="Priority filter">
              <option value="">All priorities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((p) => <option key={p}>{p}</option>)}
            </select>
            <input className="input" placeholder="Search title, host, user, IP, technique" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search alerts" style={{ width: 280 }} />
            <button className="btn" type="submit"><Search size={14} /> Search</button>
          </form>
        }>
        <Async state={list}>
          {(d) => d.items.length === 0 ? <Empty title="No alerts match" hint="Load a demo scenario or submit an alert above." /> : (
            <>
              <table className="table">
                <thead><tr><th>Alert</th><th>Priority</th><th className="num">Score</th><th>Host</th><th>Account</th><th>Techniques</th><th>Incident</th><th>Received</th></tr></thead>
                <tbody>
                  {d.items.map((a) => (
                    <tr key={a.alert_id} className="click" onClick={() => navigate('alerts', a.alert_id)}>
                      <td><div className="cell-title truncate" title={a.title}>{a.title}</div>
                        <div className="cell-sub mono">{a.alert_id} · {a.source} {a.synthetic && <SyntheticBadge />} {a.workflow_status !== 'COMPLETED' && <Badge kind="warn">{a.workflow_status}</Badge>}</div></td>
                      <td><Badge kind={a.priority} /></td>
                      <td className="num"><Score score={a.score} priority={a.priority} /></td>
                      <td>{a.asset_name ?? '—'}</td>
                      <td>{a.username ?? '—'}</td>
                      <td>{a.mitre_techniques.slice(0, 2).map((t) => <span key={t} className="tag" style={{ marginRight: 4 }}>{t}</span>)}</td>
                      <td>{a.incident_id ? <a href={href('incidents', a.incident_id)} onClick={(e) => e.stopPropagation()}>{a.incident_id}</a> : <span className="muted small">none</span>}</td>
                      <td className="small muted">{timeAgo(a.received_at)}</td>
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
    </>
  );
};

export const VerdictTable: React.FC<{ verdicts?: Record<string, IndicatorVerdict> }> = ({ verdicts }) => {
  const rows = Object.values(verdicts ?? {});
  if (rows.length === 0) return <Empty title="No network indicators in this alert" />;
  return (
    <table className="table">
      <thead><tr><th>Indicator</th><th>Verdict</th><th>Rationale</th><th>Sources</th></tr></thead>
      <tbody>
        {rows.map((v) => (
          <tr key={v.indicator}>
            <td className="mono">{v.indicator}<div className="cell-sub">{v.indicator_type}{v.role ? ` · ${v.role}` : ''}</div></td>
            <td><Badge kind={v.verdict} /> {v.synthetic && <SyntheticBadge />}</td>
            <td className="small">{v.rationale}</td>
            <td className="small">{v.sources.map((s) => (
              <div key={s.source}>{s.source}: {s.available ? s.verdict : 'unavailable'}{s.synthetic ? ' (synthetic)' : ''}</div>
            ))}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

export const AlertDetailPage: React.FC<{ alertId: string }> = ({ alertId }) => {
  const state = useLoad(() => api<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(alertId)}`), [alertId]);
  const [tab, setTab] = useState<'overview' | 'pipeline' | 'raw'>('overview');
  return (
    <Async state={state} loadingLabel="Loading alert…">
      {(a) => {
        const f = a.finding;
        const t = a.triage_result;
        return (
          <>
            <div className="panel">
              <div className="panel-head" style={{ flexWrap: 'wrap' }}>
                {t && <Badge kind={t.priority} />}
                <h2 style={{ fontSize: 16 }}>{f?.finding_info.title ?? 'Unparsed alert'}</h2>
                {Boolean(a.source_provenance.synthetic) && <SyntheticBadge />}
                <div className="right">
                  {a.incident_id ? <a className="btn sm primary" href={href('incidents', a.incident_id)}>Open incident {a.incident_id}</a>
                    : <span className="small muted">Not part of an incident (LOW and uncorrelated, or not triaged)</span>}
                </div>
              </div>
              <div className="tabs" role="tablist">
                {(['overview', 'pipeline', 'raw'] as const).map((k) => (
                  <button key={k} role="tab" aria-selected={tab === k} className={`tab${tab === k ? ' on' : ''}`} onClick={() => setTab(k)}>
                    {k === 'overview' ? 'Overview' : k === 'pipeline' ? 'Pipeline & guardrails' : 'Raw & normalized'}
                  </button>
                ))}
              </div>
            </div>
            {a.errors.length > 0 && <ErrorBox message={a.errors.join(' · ')} />}

            {tab === 'overview' && (
              <div className="grid g-main-side">
                <div className="stack">
                  <Panel title="Normalized finding" sub="OCSF Security Finding (project subset)">
                    {!f ? <Empty title="Normalization failed" /> : (
                      <dl className="kv">
                        <dt>Event time</dt><dd>{fmtTime(f.time / 1000)} <span className="muted small mono">{f.metadata.original_time}</span></dd>
                        <dt>Severity</dt><dd>{f.severity} (OCSF {f.severity_id})</dd>
                        <dt>Host</dt><dd>{f.device ? <>{f.device.name ?? '—'} <span className="muted mono small">agent {f.device.uid ?? '—'} · {f.device.ip ?? 'no ip'}</span></> : <span className="muted">not reported</span>}</dd>
                        <dt>Account</dt><dd>{f.user?.name ?? <span className="muted">not reported</span>}</dd>
                        <dt>Process</dt><dd>{f.process ? <code>{f.process.cmd_line ?? f.process.name}</code> : <span className="muted">not reported</span>}</dd>
                        <dt>Source</dt><dd className="mono">{f.src_endpoint ? `${f.src_endpoint.ip ?? ''}${f.src_endpoint.port ? ':' + f.src_endpoint.port : ''}` : '—'}</dd>
                        <dt>Destination</dt><dd className="mono">{f.dst_endpoint ? `${f.dst_endpoint.ip ?? ''}${f.dst_endpoint.port ? ':' + f.dst_endpoint.port : ''} ${f.dst_endpoint.domain ?? ''}` : '—'}</dd>
                        <dt>ATT&CK</dt><dd>{f.attacks.length === 0 ? <span className="muted">none mapped by the source rule</span> : f.attacks.map((x, i) => (
                          <div key={i}><span className="tag">{x.technique?.uid}</span> {x.technique?.name} <span className="muted">· {x.tactic?.name}</span></div>
                        ))}
                          {Array.isArray(f.unmapped.mitre_reference_labels) && <div className="small muted">Names/tactics for {(f.unmapped.mitre_reference_labels as string[]).join(', ')} filled from the static ATT&CK reference (IDs came from the alert).</div>}
                        </dd>
                        <dt>Log</dt><dd className="small mono">{f.message ?? '—'}</dd>
                      </dl>
                    )}
                  </Panel>
                  <Panel title="Threat intelligence" sub="absence of intel = UNKNOWN, never safe" flush>
                    <VerdictTable verdicts={a.enrichment?.indicator_verdicts} />
                  </Panel>
                  {a.investigation_context && (
                    <Panel title="Investigation context" sub={a.investigation_context.graph_available ? 'graph memory available' : 'graph memory unavailable'}>
                      <ul className="list">
                        {a.investigation_context.observed_facts.map((x, i) => <li key={i}><Badge kind="neutral">fact</Badge> <span className="small">{x.description}</span></li>)}
                        {a.investigation_context.inferences.map((x, i) => <li key={`i${i}`}><Badge kind="warn">inference</Badge> <span className="small">{x.rationale} (conf {x.confidence})</span></li>)}
                        {a.investigation_context.missing_evidence.map((x, i) => <li key={`m${i}`}><Badge kind="neutral">missing</Badge> <span className="small muted">{x}</span></li>)}
                      </ul>
                    </Panel>
                  )}
                </div>
                <div className="stack">
                  <Panel title="Deterministic triage" sub={t ? `policy v${t.policy_version}` : undefined}>
                    {!t ? <Empty title="Not triaged" /> : (
                      <div className="stack">
                        <div className="row"><Badge kind={t.priority} /><Score score={t.score} priority={t.priority} /></div>
                        <div className="breakdown">
                          {t.score_breakdown.map((c, i) => (
                            <div key={i} className="breakdown-row"><span className={`pts${c.factor !== 'base_severity' && c.points > 0 ? ' pos' : ''}`}>{c.factor === 'base_severity' ? '' : c.points > 0 ? '+' : ''}{c.points}</span>
                              <span><strong>{c.factor.replace(/_/g, ' ')}</strong> — <span className="muted">{c.detail}</span></span></div>
                          ))}
                          <div className="breakdown-row"><span className="pts">= {t.score}</span><span className="small muted">{t.priority_rule}</span></div>
                        </div>
                        {t.uncertainties.length > 0 && (
                          <div className="alert-box warn"><div><strong>Uncertainties</strong><ul style={{ paddingLeft: 16 }}>{t.uncertainties.map((u, i) => <li key={i} className="small">{u}</li>)}</ul></div></div>
                        )}
                      </div>
                    )}
                  </Panel>
                  <Panel title="Asset & identity context">
                    <dl className="kv" style={{ gridTemplateColumns: '100px 1fr' }}>
                      <dt>CMDB asset</dt><dd>{a.enrichment?.cmdb_asset ? <>{a.enrichment.cmdb_asset.hostname} · <Badge kind={a.enrichment.cmdb_asset.criticality === 'CRITICAL' ? 'CRITICAL' : a.enrichment.cmdb_asset.criticality === 'HIGH' ? 'HIGH' : 'neutral'}>{a.enrichment.cmdb_asset.criticality}</Badge> <span className="small muted">({a.enrichment.cmdb_asset.source})</span></> : <span className="muted">not in CMDB</span>}</dd>
                      <dt>IAM identity</dt><dd>{a.enrichment?.iam_identity ? <>{a.enrichment.iam_identity.username} {a.enrichment.iam_identity.is_privileged && <Badge kind="warn">privileged</Badge>} <span className="small muted">({a.enrichment.iam_identity.source})</span></> : <span className="muted">not in IAM</span>}</dd>
                    </dl>
                  </Panel>
                  <Panel title="Recommended investigation steps" sub="advisory">
                    <ol style={{ paddingLeft: 18 }} className="small">{t?.recommended_steps.map((s, i) => <li key={i} style={{ marginBottom: 4 }}>{s}</li>)}</ol>
                  </Panel>
                </div>
              </div>
            )}

            {tab === 'pipeline' && (
              <div className="grid g-2">
                <Panel title="LangGraph stages" sub={`${a.workflow_status} in ${a.duration_ms.toFixed(0)} ms`} flush>
                  <table className="table">
                    <thead><tr><th>Stage</th><th>Status</th><th className="num">ms</th><th>Detail</th></tr></thead>
                    <tbody>{a.completed_stages.map((s) => {
                      const r = a.stage_records[s];
                      return <tr key={s}><td className="mono small">{s}</td><td><Badge kind={r?.status === 'SUCCESS' ? 'ok' : r?.status === 'FAILED' ? 'bad' : 'neutral'}>{r?.status}</Badge></td>
                        <td className="num mono small">{r?.duration_ms.toFixed(1)}</td><td className="small">{r?.error ?? r?.message}{r?.retry_count ? ` (retries: ${r.retry_count})` : ''}</td></tr>;
                    })}</tbody>
                  </table>
                  <div className="panel-body small muted">Graph persistence: {a.graph_persisted ? `${a.persisted_nodes_count} nodes / ${a.persisted_edges_count} edges written to Neo4j` : 'not persisted (Neo4j unavailable or disabled)'}</div>
                </Panel>
                <Panel title="Guardrail decisions" sub="deterministic policy engine" flush>
                  {a.guardrail_results.length === 0 ? <Empty title="No actions proposed by triage" /> : (
                    <ul className="list" style={{ padding: '0 16px' }}>{a.guardrail_results.map((g, i) => (
                      <li key={i}><div className="row"><Badge kind={g.decision} /><strong>{g.action_proposal.action_name}</strong><span className="small muted">{g.action_proposal.category}</span></div>
                        <div className="small">{g.reason}</div>
                        {g.required_approvals.map((r) => <a key={r} className="small mono" href={`${href('approvals')}?focus=${r}`}>{r}</a>)}</li>
                    ))}</ul>
                  )}
                </Panel>
              </div>
            )}

            {tab === 'raw' && (
              <div className="grid g-2">
                <Panel title="Original alert (preserved verbatim)"><pre className="json">{JSON.stringify(f?.raw_data ?? null, null, 2)}</pre></Panel>
                <Panel title="Provenance & unmapped fields"><pre className="json">{JSON.stringify({ provenance: a.source_provenance, unmapped: f?.unmapped }, null, 2)}</pre></Panel>
              </div>
            )}
          </>
        );
      }}
    </Async>
  );
};
