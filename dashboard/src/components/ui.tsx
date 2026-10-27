import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Inbox } from 'lucide-react';
import { ApiError } from '../api.ts';

// ── Data loading ────────────────────────────────────────────────────────────

export interface Loaded<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Loads data from `fn`; re-runs when `deps` change. Keeps stale data while reloading. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): Loaded<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);

  const reload = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const result = await run();
      if (my === seq.current) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (my === seq.current) setError(err instanceof ApiError || err instanceof Error ? err.message : String(err));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [run]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { data, error, loading, reload };
}

// ── Formatting ──────────────────────────────────────────────────────────────

export function fmtTime(ts?: number | null): string {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function timeAgo(ts?: number | null): string {
  if (!ts) return '—';
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(seconds: number): string {
  if (seconds <= 0) return 'expired';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

const PRIORITY_COLOR: Record<string, string> = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
export const priorityColor = (p: string) => PRIORITY_COLOR[p] ?? 'var(--text-3)';

// ── Small components ────────────────────────────────────────────────────────

export const Badge: React.FC<{ kind: string; children?: React.ReactNode; title?: string }> = ({ kind, children, title }) => (
  <span className={`badge ${kind}`} title={title}>{children ?? kind.replace('_', ' ')}</span>
);

export const SyntheticBadge: React.FC = () => (
  <span className="badge synthetic" title="Simulated demo data — not real activity">synthetic</span>
);

export const Score: React.FC<{ score: number; priority: string }> = ({ score, priority }) => (
  <span className="mono" title={`Deterministic triage score ${score}/100`}>
    {score}
    <span className="score-bar" aria-hidden="true"><span style={{ width: `${score}%`, background: priorityColor(priority) }} /></span>
  </span>
);

export const Loading: React.FC<{ label?: string }> = ({ label = 'Loading…' }) => (
  <div className="state" role="status"><div className="spinner" />{label}</div>
);

export const Empty: React.FC<{ title: string; hint?: React.ReactNode }> = ({ title, hint }) => (
  <div className="state"><Inbox size={22} aria-hidden="true" /><strong>{title}</strong>{hint && <div className="small">{hint}</div>}</div>
);

export const ErrorBox: React.FC<{ message: string; onRetry?: () => void }> = ({ message, onRetry }) => (
  <div className="alert-box error" role="alert">
    <AlertTriangle size={16} aria-hidden="true" style={{ flex: 'none', marginTop: 2 }} />
    <div style={{ flex: 1 }}>{message}</div>
    {onRetry && <button className="btn sm" onClick={onRetry}>Retry</button>}
  </div>
);

export const Panel: React.FC<{ title: React.ReactNode; sub?: React.ReactNode; right?: React.ReactNode; flush?: boolean; children: React.ReactNode }> = ({ title, sub, right, flush, children }) => (
  <section className="panel">
    <div className="panel-head">
      <h2>{title}</h2>
      {sub && <span className="sub">{sub}</span>}
      {right && <div className="right">{right}</div>}
    </div>
    <div className={`panel-body${flush ? ' flush' : ''}`}>{children}</div>
  </section>
);

/** Renders loading / error / content for a `useLoad` result. */
export function Async<T>({ state, children, loadingLabel }: { state: Loaded<T>; children: (data: T) => React.ReactNode; loadingLabel?: string }) {
  if (state.error && !state.data) return <ErrorBox message={state.error} onRetry={() => void state.reload()} />;
  if (!state.data) return <Loading label={loadingLabel} />;
  return (
    <>
      {state.error && <ErrorBox message={`Refresh failed: ${state.error}`} onRetry={() => void state.reload()} />}
      {children(state.data)}
    </>
  );
}
