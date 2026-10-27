import React, { useState } from 'react';
import { Check, Play, X } from 'lucide-react';
import { api, post } from '../api.ts';
import { href, Route } from '../router.ts';
import { Approval, ApprovalStatus, Principal } from '../types.ts';
import { Async, Badge, duration, Empty, fmtTime, Panel, useLoad } from '../components/ui.tsx';

/** Approve / reject / execute controls bound to one approval request. */
export const ApprovalActions: React.FC<{ approval: Approval; who: Principal; onDone: () => void }> = ({ approval, who, onDone }) => {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const approver = who.role === 'approver' || who.role === 'admin';
  const own = approval.proposed_by === who.name;

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      setOpen(false);
      setReason('');
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (approval.status === 'EXECUTED') return <div className="small"><Badge kind="EXECUTED">executed (simulated)</Badge><div className="muted">{approval.executed_by} · {fmtTime(approval.executed_at)}</div></div>;
  if (approval.status !== 'PENDING' && approval.status !== 'APPROVED') {
    return <div className="small muted">{approval.reviewer_id ? `${approval.reviewer_id}: ${approval.decision_reason ?? ''}` : '—'}</div>;
  }
  if (!approver) return <span className="small muted">Approver role required</span>;

  if (approval.status === 'APPROVED') {
    return (
      <div className="stack" style={{ gap: 4 }}>
        <span className="small muted">Approved by {approval.reviewer_id}</span>
        <button className="btn sm success" disabled={busy} onClick={() => void act(() => post(`/api/v1/approvals/${approval.request_id}/execute`))}>
          <Play size={12} /> {busy ? 'Executing…' : 'Execute (simulated)'}
        </button>
        {err && <span className="small" style={{ color: 'var(--crit)' }}>{err}</span>}
      </div>
    );
  }

  if (own) return <span className="small muted" title="Separation of duties">You proposed this; another approver must decide</span>;

  return (
    <div className="stack" style={{ gap: 6, minWidth: 220 }}>
      {!open ? (
        <button className="btn sm" onClick={() => setOpen(true)}>Review…</button>
      ) : (
        <>
          <input className="input" placeholder="Decision reason" value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Decision reason" />
          <div className="row">
            <button className="btn sm success" disabled={busy || reason.trim().length < 3} onClick={() => void act(() => post(`/api/v1/approvals/${approval.request_id}/decide`, { decision: 'APPROVE', reason }))}><Check size={12} /> Approve</button>
            <button className="btn sm danger" disabled={busy || reason.trim().length < 3} onClick={() => void act(() => post(`/api/v1/approvals/${approval.request_id}/decide`, { decision: 'REJECT', reason }))}><X size={12} /> Reject</button>
            <button className="btn sm ghost" onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </>
      )}
      {err && <span className="small" style={{ color: 'var(--crit)' }}>{err}</span>}
    </div>
  );
};

const FILTERS: (ApprovalStatus | '')[] = ['PENDING', 'APPROVED', 'EXECUTED', 'REJECTED', 'EXPIRED', ''];

export const ApprovalsPage: React.FC<{ route: Route; who: Principal; onChanged: () => void }> = ({ route, who, onChanged }) => {
  const [status, setStatus] = useState<ApprovalStatus | ''>('PENDING');
  const focus = route.query.get('focus');
  const list = useLoad(() => api<{ items: Approval[] }>(`/api/v1/approvals${status ? `?status=${status}` : ''}`), [status]);
  return (
    <>
      <div className="alert-box info small"><div>
        Every containment or remediation proposal needs a human decision. Approvals are bound to the exact action hash, expire, can be used once,
        and cannot be self-approved. <strong>All actions are simulated</strong>: execution records an audit event and contacts no external system.
      </div></div>
      <Panel title="Approval queue" flush right={
        <div className="segmented" role="group" aria-label="Status filter">
          {FILTERS.map((s) => <button key={s || 'all'} className={status === s ? 'on' : ''} onClick={() => setStatus(s)}>{s ? s.toLowerCase() : 'all'}</button>)}
        </div>
      }>
        <Async state={list}>
          {(d) => d.items.length === 0 ? <Empty title={`No ${status ? status.toLowerCase() : ''} requests`} /> : (
            <table className="table">
              <thead><tr><th>Action</th><th>Status</th><th>Incident</th><th>Proposed</th><th>Expires</th><th>Binding</th><th>Decision</th></tr></thead>
              <tbody>{d.items.map((a) => (
                <tr key={a.request_id} style={focus === a.request_id ? { background: 'var(--accent-soft)' } : undefined}>
                  <td><strong>{a.action_name}</strong><div className="cell-sub mono">{a.request_id}</div><div className="small">{a.target_entities.join(', ')}</div><div className="small muted truncate" title={a.reason}>{a.reason}</div></td>
                  <td><Badge kind={a.status} /></td>
                  <td className="small">{a.context.incident_id ? <a href={href('incidents', a.context.incident_id)}>{a.context.incident_id}</a> : a.context.alert_id ? <a href={href('alerts', a.context.alert_id)}>{a.context.alert_id}</a> : '—'}</td>
                  <td className="small">{a.proposed_by}<div className="muted">{fmtTime(a.created_at)}</div></td>
                  <td className="small muted">{a.status === 'PENDING' || a.status === 'APPROVED' ? duration(a.expires_in_seconds) : '—'}</td>
                  <td className="hash" title={a.action_hash}>{a.action_hash.slice(0, 12)}…</td>
                  <td><ApprovalActions approval={a} who={who} onDone={() => { void list.reload(); onChanged(); }} /></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Async>
      </Panel>
    </>
  );
};
