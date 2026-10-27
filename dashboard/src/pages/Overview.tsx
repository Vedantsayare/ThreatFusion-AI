import React from 'react';
import { api } from '../api.ts';
import { href } from '../router.ts';
import { Dashboard } from '../types.ts';
import { Async, Badge, duration, Empty, fmtTime, Loaded, Panel, Score, SyntheticBadge, timeAgo, useLoad } from '../components/ui.tsx';

const PRIORITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
const COLORS: Record<string, string> = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };

const TrendChart: React.FC<{ data: Dashboard['alert_trend']; bucketHours: number }> = ({ data, bucketHours }) => {
  if (data.length === 0) return <Empty title="No alert activity yet" />;
  const W = 640, H = 170, pad = 24;
  const max = Math.max(1, ...data.map((d) => PRIORITIES.reduce((s, p) => s + d[p], 0)));
  const bw = Math.max(4, Math.min(36, (W - pad * 2) / data.length - 4));
  const step = (W - pad * 2) / data.length;
  return (
    <figure>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img"
        aria-label={`Alerts per ${bucketHours}h by priority across ${data.length} time buckets`}>
        <line x1={pad} x2={W - pad} y1={H - pad} y2={H - pad} stroke="var(--border)" />
        <text x={pad} y={12} fill="var(--text-3)" fontSize="10">{max} alerts</text>
        {data.map((d, i) => {
          let y = H - pad;
          const x = pad + i * step + (step - bw) / 2;
          return (
            <g key={d.bucket_start}>
              <title>{`${fmtTime(d.bucket_start)}: ${PRIORITIES.map((p) => `${p} ${d[p]}`).join(', ')}`}</title>
              {PRIORITIES.slice().reverse().map((p) => {
                const h = (d[p] / max) * (H - pad * 2);
                y -= h;
                return h > 0 ? <rect key={p} x={x} y={y} width={bw} height={h} fill={COLORS[p]} rx={2} /> : null;
              })}
              {(i === 0 || i === data.length - 1) && (
                <text x={x + bw / 2} y={H - 8} fill="var(--text-3)" fontSize="10" textAnchor="middle">
                  {new Date(d.bucket_start * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="row small muted" style={{ gap: 12 }}>
        {PRIORITIES.map((p) => <span key={p} className="row" style={{ gap: 4 }}><span className="dot" style={{ background: COLORS[p] }} />{p}</span>)}
        <span>· bucketed by event time</span>
      </figcaption>
    </figure>
  );
};

const Bars: React.FC<{ rows: { name: string; count: number }[]; link?: (name: string) => string }> = ({ rows, link }) => {
  if (rows.length === 0) return <Empty title="No data yet" />;
  const max = Math.max(...rows.map((r) => r.count));
  return (
    <div className="bars">
      {rows.map((r) => (
        <div key={r.name} className="bar-row">
          <span className="truncate" title={r.name}>{link ? <a href={link(r.name)}>{r.name}</a> : r.name}</span>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${(r.count / max) * 100}%` }} /></div>
          <span className="mono muted" style={{ textAlign: 'right' }}>{r.count}</span>
        </div>
      ))}
    </div>
  );
};

export const OverviewPage: React.FC<{ state: Loaded<Dashboard> }> = ({ state }) => (
  <Async state={state} loadingLabel="Loading SOC overview…">
    {(d) => {
      const s = d.stats;
      const empty = s.total_alerts === 0;
      return (
        <>
          {d.synthetic_data_present && (
            <div className="alert-box info">Dashboard includes <SyntheticBadge /> demo telemetry loaded from built-in scenarios. It is simulated, not real activity.</div>
          )}
          {empty && (
            <div className="panel"><Empty title="No alerts ingested yet"
              hint={<>Load a synthetic scenario or submit an alert from the <a href={href('alerts')}>Alerts</a> page.</>} /></div>
          )}
          <div className="kpis">
            <div className="kpi"><div className="kpi-label">Alerts</div><div className="kpi-value">{s.total_alerts}</div><div className="kpi-foot">{s.failed} failed processing</div></div>
            <div className="kpi"><div className="kpi-label">Incidents</div><div className="kpi-value">{s.total_incidents}</div>
              <div className="kpi-foot">{s.incidents_open} open · {s.incidents_investigating} investigating</div></div>
            <div className="kpi crit"><div className="kpi-label">Critical alerts</div><div className="kpi-value">{s.critical}</div><div className="kpi-foot">{s.high} high</div></div>
            <div className="kpi high"><div className="kpi-label">Medium / Low</div><div className="kpi-value">{s.medium} / {s.low}</div><div className="kpi-foot">{s.unscored} unscored</div></div>
            <div className="kpi"><div className="kpi-label">Escalated · Resolved</div><div className="kpi-value">{s.incidents_escalated} · {s.incidents_resolved}</div>
              <div className="kpi-foot">{s.incidents_false_positive} false positive</div></div>
            <div className="kpi"><div className="kpi-label">Pending approvals</div><div className="kpi-value">{s.pending_approvals}</div>
              <div className="kpi-foot"><a href={href('approvals')}>Review queue</a></div></div>
          </div>

          <div className="grid g-main-side">
            <Panel title="Incidents requiring attention" sub="open, highest risk first" flush
              right={<a className="btn sm" href={href('incidents')}>All incidents</a>}>
              {d.priority_incidents.length === 0 ? <Empty title="No open incidents" /> : (
                <table className="table">
                  <thead><tr><th>Incident</th><th>Priority</th><th className="num">Risk</th><th>Status</th><th>Hosts</th><th>Last activity</th></tr></thead>
                  <tbody>
                    {d.priority_incidents.map((i) => (
                      <tr key={i.incident_id} className="click" onClick={() => { window.location.hash = href('incidents', i.incident_id).slice(1); }}>
                        <td><div className="cell-title truncate">{i.title}</div><div className="cell-sub mono">{i.incident_id} · {i.alert_count} alerts {i.synthetic && <SyntheticBadge />}</div></td>
                        <td><Badge kind={i.priority} /></td>
                        <td className="num"><Score score={i.risk_score} priority={i.priority} /></td>
                        <td><Badge kind={i.status} /></td>
                        <td className="small">{i.hosts.join(', ') || '—'}</td>
                        <td className="small muted">{timeAgo(i.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Panel>
            <Panel title="Service health" sub="live checks">
              <ul className="list">
                {d.services.map((svc) => (
                  <li key={svc.name} className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
                    <span className={`dot ${svc.status}`} style={{ marginTop: 6 }} aria-hidden="true" />
                    <div style={{ minWidth: 0 }}>
                      <div><strong>{svc.name}</strong> <span className="muted small">{svc.status}</span></div>
                      <div className="small muted" style={{ overflowWrap: 'anywhere' }}>{svc.detail}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>

          <div className="grid g-3">
            <Panel title="Alert trend" sub={`per ${d.trend_bucket_hours}h`}><TrendChart data={d.alert_trend} bucketHours={d.trend_bucket_hours} /></Panel>
            <Panel title="Most affected hosts"><Bars rows={d.top_hosts} link={(n) => `${href('alerts')}?host=${encodeURIComponent(n)}`} /></Panel>
            <Panel title="Most involved accounts"><Bars rows={d.top_users} link={(n) => `${href('alerts')}?search=${encodeURIComponent(n)}`} /></Panel>
          </div>

          <div className="grid g-3">
            <Panel title="Recent alerts" flush right={<a className="btn sm" href={href('alerts')}>All alerts</a>}>
              {d.recent_alerts.length === 0 ? <Empty title="No alerts" /> : (
                <ul className="list" style={{ padding: '0 16px' }}>
                  {d.recent_alerts.map((a) => (
                    <li key={a.alert_id}>
                      <div className="row"><Badge kind={a.priority} /><a className="truncate" href={href('alerts', a.alert_id)} style={{ maxWidth: 240 }}>{a.title}</a></div>
                      <div className="small muted">{a.asset_name ?? 'unknown host'} · {timeAgo(a.received_at)}</div>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Pending approvals" flush right={<a className="btn sm" href={href('approvals')}>Queue</a>}>
              {d.pending_approvals.length === 0 ? <Empty title="Nothing awaiting approval" /> : (
                <ul className="list" style={{ padding: '0 16px' }}>
                  {d.pending_approvals.map((a) => (
                    <li key={a.request_id}>
                      <div className="row"><strong>{a.action_name}</strong><span className="small muted">expires in {duration(a.expires_in_seconds)}</span></div>
                      <div className="small muted truncate">{a.target_entities.join(', ')}</div>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Recent audit activity" flush right={<a className="btn sm" href={href('audit')}>Audit log</a>}>
              <ul className="list" style={{ padding: '0 16px' }}>
                {d.recent_audit.map((e) => (
                  <li key={e.event_id}>
                    <div className="row"><Badge kind={e.decision} /><span className="small">{e.operation}</span></div>
                    <div className="small muted truncate" title={e.outcome}>{e.actor} · {e.outcome}</div>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </>
      );
    }}
  </Async>
);

export function useDashboard(): Loaded<Dashboard> {
  return useLoad(() => api<Dashboard>('/api/v1/dashboard'), []);
}
