import React, { useState } from 'react';
import { Search, ShieldCheck, ShieldX } from 'lucide-react';
import { api } from '../api.ts';
import { href, Route } from '../router.ts';
import { AuditEvent, GraphData, IndicatorVerdict, IntegrationsStatus, Principal, ServiceHealth } from '../types.ts';
import { GraphCanvas } from '../components/GraphCanvas.tsx';
import { Async, Badge, Empty, ErrorBox, fmtTime, Panel, SyntheticBadge, timeAgo, useLoad } from '../components/ui.tsx';

// ── Audit log ───────────────────────────────────────────────────────────────

interface Verify { verified: boolean; error: string | null; event_count: number; head_hash: string | null; checked_at: number; note: string; }

export const AuditPage: React.FC = () => {
  const [page, setPage] = useState(1);
  const [op, setOp] = useState('');
  const [applied, setApplied] = useState('');
  const list = useLoad(() => api<{ items: AuditEvent[]; total: number; total_pages: number; page: number }>(
    `/api/v1/audit?page=${page}&page_size=50${applied ? `&operation=${encodeURIComponent(applied)}` : ''}`), [page, applied]);
  const verify = useLoad(() => api<Verify>('/api/v1/audit/verify'), []);
  return (
    <>
      <Panel title="Hash-chain verification" right={<button className="btn sm" onClick={() => void verify.reload()}>Verify now</button>}>
        <Async state={verify}>
          {(v) => (
            <div className="stack">
              <div className={`alert-box ${v.verified ? 'ok' : 'error'}`}>
                {v.verified ? <ShieldCheck size={16} /> : <ShieldX size={16} />}
                <div>{v.verified ? `Chain intact: ${v.event_count} events verified` : `Integrity failure: ${v.error}`} · checked {timeAgo(v.checked_at)}
                  {v.head_hash && <div className="hash">head {v.head_hash}</div>}</div>
              </div>
              <p className="small muted">{v.note}</p>
            </div>
          )}
        </Async>
      </Panel>
      <Panel title="Audit events" sub={list.data ? `${list.data.total} total, newest first` : undefined} flush right={
        <form className="row" onSubmit={(e) => { e.preventDefault(); setPage(1); setApplied(op); }}>
          <input className="input" placeholder="Filter operation" value={op} onChange={(e) => setOp(e.target.value)} aria-label="Filter by operation" />
          <button className="btn" type="submit"><Search size={14} /></button>
        </form>
      }>
        <Async state={list}>
          {(d) => d.items.length === 0 ? <Empty title="No audit events" /> : (
            <>
              <table className="table">
                <thead><tr><th>Time</th><th>Actor</th><th>Operation</th><th>Decision</th><th>Outcome</th><th>Hash</th></tr></thead>
                <tbody>{d.items.map((e) => (
                  <tr key={e.event_id}>
                    <td className="small mono">{fmtTime(e.timestamp)}</td>
                    <td className="small">{e.actor}</td>
                    <td className="small mono">{e.operation}</td>
                    <td><Badge kind={e.decision} /></td>
                    <td className="small" style={{ maxWidth: 520 }}>{e.outcome}
                      {typeof e.metadata.incident_id === 'string' && <> · <a href={href('incidents', e.metadata.incident_id)}>{e.metadata.incident_id}</a></>}
                      {e.approval_id && <> · <a href={`${href('approvals')}?focus=${e.approval_id}`}>{e.approval_id}</a></>}</td>
                    <td className="hash" title={`prev ${e.prev_event_hash}\nthis ${e.event_hash}`}>{e.event_hash.slice(0, 10)}…</td>
                  </tr>
                ))}</tbody>
              </table>
              <div className="row" style={{ padding: '10px 16px', justifyContent: 'flex-end' }}>
                <button className="btn sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Newer</button>
                <span className="small muted">Page {d.page} of {d.total_pages}</span>
                <button className="btn sm" disabled={page >= d.total_pages} onClick={() => setPage(page + 1)}>Older</button>
              </div>
            </>
          )}
        </Async>
      </Panel>
    </>
  );
};

// ── Graph explorer ──────────────────────────────────────────────────────────

export const GraphPage: React.FC<{ route: Route }> = ({ route }) => {
  const initial = route.query.get('entity') ?? '';
  const [input, setInput] = useState(initial);
  const [depth, setDepth] = useState(1);
  const entity = initial;
  const graph = useLoad(() => (entity ? api<GraphData>(`/api/v1/graph/entities/${encodeURIComponent(entity)}?depth=${depth}`) : Promise.resolve(null)), [entity, depth]);
  const go = (id: string) => { window.location.hash = `${href('graph').slice(1)}?entity=${encodeURIComponent(id)}`; };
  return (
    <>
      <Panel title="Explore an entity" sub="canonical IDs: asset:agent:001, identity:user:admin@web-server-01, ioc:ip:203.0.113.195, ttp:mitre:T1110.001">
        <form className="row" onSubmit={(e) => { e.preventDefault(); if (input.trim()) go(input.trim()); }}>
          <input className="input" style={{ flex: 1, minWidth: 260 }} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Entity ID" aria-label="Entity ID" />
          <div className="segmented" role="group" aria-label="Depth">{[1, 2].map((d) => <button type="button" key={d} className={depth === d ? 'on' : ''} onClick={() => setDepth(d)}>depth {d}</button>)}</div>
          <button className="btn primary" type="submit">Explore</button>
        </form>
        <p className="small muted" style={{ marginTop: 8 }}>Tip: open an incident's Graph tab and click any node, then “Explore neighborhood”.</p>
      </Panel>
      {entity && (
        <Panel title={<span className="mono">{entity}</span>} sub={graph.data?.note} flush right={graph.data && <Badge kind={graph.data.persisted ? 'ok' : 'warn'}>{graph.data.persisted ? 'Neo4j' : 'not persisted'}</Badge>}>
          {graph.error ? <div className="panel-body"><ErrorBox message={graph.error} /></div> : !graph.data ? <div className="state"><div className="spinner" />Loading…</div> : <GraphCanvas graph={graph.data} tall />}
        </Panel>
      )}
    </>
  );
};

// ── Threat intel ────────────────────────────────────────────────────────────

interface ObservedIndicator { indicator: string; indicator_type: string; verdict: string; rationale: string; synthetic: boolean; alert_ids: string[]; incident_ids: string[]; last_seen: number; sources: IndicatorVerdict['sources']; }

export const IntelPage: React.FC<{ route: Route; who: Principal }> = ({ route, who }) => {
  const observed = useLoad(() => api<{ items: ObservedIndicator[]; sources: Record<string, string> }>('/api/v1/intel/indicators'), []);
  const [q, setQ] = useState(route.query.get('q') ?? '');
  const [result, setResult] = useState<IndicatorVerdict | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const filter = route.query.get('q') ?? '';
  const lookup = async () => {
    setBusy(true); setErr(null); setResult(null);
    try { setResult(await api<IndicatorVerdict>(`/api/v1/intel/lookup?indicator=${encodeURIComponent(q.trim())}`)); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <>
      <div className="grid g-2">
        <Panel title="Indicator lookup" sub="MISP (if configured) + synthetic demo feed">
          {who.role === 'viewer' ? <p className="small muted">Analyst role required.</p> : (
            <div className="stack">
              <form className="row" onSubmit={(e) => { e.preventDefault(); void lookup(); }}>
                <input className="input" style={{ flex: 1 }} value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP address or domain" aria-label="Indicator" />
                <button className="btn primary" disabled={busy || q.trim().length < 3}>{busy ? 'Looking up…' : 'Look up'}</button>
              </form>
              {err && <ErrorBox message={err} />}
              {result && (
                <div className="stack" style={{ gap: 6 }}>
                  <div className="row"><span className="mono">{result.indicator}</span><Badge kind={result.verdict} />{result.synthetic && <SyntheticBadge />}{result.conflicting && <Badge kind="warn">sources disagree</Badge>}</div>
                  <div className="small">{result.rationale}</div>
                  {result.sources.map((s) => <div key={s.source} className="small muted">{s.source}: {s.available ? s.verdict : 'unavailable'} — {s.detail}</div>)}
                </div>
              )}
            </div>
          )}
        </Panel>
        <Panel title="Verdict policy">
          <ul className="small" style={{ paddingLeft: 16 }}>
            <li><Badge kind="MALICIOUS" /> a source explicitly reports it malicious (MISP high threat level).</li>
            <li><Badge kind="SUSPICIOUS" /> a source reports it with medium/low/undefined threat level.</li>
            <li><Badge kind="BENIGN" /> a source explicitly allow-lists it and no source disagrees.</li>
            <li><Badge kind="UNKNOWN" /> no information, or lookups failed. <strong>Never treated as safe.</strong></li>
          </ul>
          {observed.data && <p className="small muted" style={{ marginTop: 8 }}>Sources: {Object.entries(observed.data.sources).map(([k, v]) => `${k} — ${v}`).join(' · ')}</p>}
        </Panel>
      </div>
      <Panel title="Indicators observed in alerts" flush>
        <Async state={observed}>
          {(d) => {
            const items = filter ? d.items.filter((i) => i.indicator.includes(filter)) : d.items;
            return items.length === 0 ? <Empty title="No indicators observed yet" /> : (
              <table className="table">
                <thead><tr><th>Indicator</th><th>Verdict</th><th>Rationale</th><th className="num">Alerts</th><th>Incidents</th><th>Last seen</th></tr></thead>
                <tbody>{items.map((i) => (
                  <tr key={i.indicator}>
                    <td className="mono">{i.indicator}<div className="cell-sub">{i.indicator_type}</div></td>
                    <td><Badge kind={i.verdict} /> {i.synthetic && <SyntheticBadge />}</td>
                    <td className="small">{i.rationale}</td>
                    <td className="num">{i.alert_ids.length}</td>
                    <td className="small">{i.incident_ids.map((x) => <div key={x}><a href={href('incidents', x)}>{x}</a></div>)}{i.incident_ids.length === 0 && '—'}</td>
                    <td className="small muted">{timeAgo(i.last_seen)}</td>
                  </tr>
                ))}</tbody>
              </table>
            );
          }}
        </Async>
      </Panel>
    </>
  );
};

// ── Integrations & settings ─────────────────────────────────────────────────

export const SettingsPage: React.FC<{ who: Principal }> = ({ who }) => {
  const status = useLoad(() => api<IntegrationsStatus>('/api/v1/integrations/status'), []);
  const health = useLoad(() => api<{ status: string; services: ServiceHealth[] }>('/health'), []);
  return (
    <div className="grid g-2">
      <Panel title="Integrations" sub="configuration only — no credentials are ever returned">
        <Async state={status}>
          {(s) => (
            <dl className="kv">
              <dt>Wazuh poller</dt><dd><Badge kind={s.wazuh.enabled ? 'ok' : 'neutral'}>{s.wazuh.status}</Badge></dd>
              <dt>Neo4j graph</dt><dd><Badge kind={s.neo4j.enabled ? 'ok' : 'warn'}>{s.neo4j.enabled ? 'connected' : 'unavailable'}</Badge> <span className="small muted">{s.neo4j.detail}</span></dd>
              <dt>MISP</dt><dd><Badge kind={s.misp.enabled ? 'ok' : 'neutral'}>{s.misp.enabled ? 'configured' : 'not configured'}</Badge> {s.misp.enabled && <span className="small mono">{s.misp.base_url}</span>}</dd>
              <dt>CMDB / IAM</dt><dd>{s.cmdb.provider} {s.cmdb.synthetic && <SyntheticBadge />}</dd>
              <dt>Persistence</dt><dd><Badge kind={s.persistence.backend === 'memory' ? 'warn' : 'ok'}>{s.persistence.backend}</Badge></dd>
              <dt>LLM narrative</dt><dd>{s.llm.mode}{s.llm.model && <span className="small mono"> · {s.llm.model}</span>}</dd>
              <dt>Demo mode</dt><dd>{s.demo_mode ? 'enabled (synthetic scenarios + demo intel feed)' : 'disabled'}</dd>
              <dt>Auth</dt><dd>API keys {s.auth.configured ? 'configured' : 'NOT configured'} · you are <strong>{who.name}</strong> ({who.role})</dd>
            </dl>
          )}
        </Async>
      </Panel>
      <Panel title="Live health checks" right={<button className="btn sm" onClick={() => void health.reload()}>Re-check</button>}>
        <Async state={health}>
          {(h) => (
            <ul className="list">{h.services.map((svc) => (
              <li key={svc.name} className="row" style={{ flexWrap: 'nowrap', alignItems: 'flex-start' }}>
                <span className={`dot ${svc.status}`} style={{ marginTop: 6 }} />
                <div><strong>{svc.name}</strong> <span className="small muted">{svc.status}</span><div className="small muted">{svc.detail}</div></div>
              </li>
            ))}</ul>
          )}
        </Async>
      </Panel>
    </div>
  );
};
