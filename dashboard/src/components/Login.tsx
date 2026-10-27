import React, { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api } from '../api.ts';
import { Principal } from '../types.ts';
import { ErrorBox } from './ui.tsx';

export const Login: React.FC<{ onSignedIn: (key: string, who: Principal) => void }> = ({ onSignedIn }) => {
  const [key, setKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const who = await api<Principal>('/api/v1/auth/me', {}, key.trim());
      onSignedIn(key.trim(), who);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="panel login-card" onSubmit={submit}>
        <div className="panel-head">
          <div className="brand-mark"><ShieldCheck size={16} /></div>
          <h2>ThreatFusion AI — sign in</h2>
        </div>
        <div className="panel-body stack">
          <p className="muted small">
            Paste an API key from your <code>.env</code> (<code>API_KEYS</code>). Run{' '}
            <code>python scripts/bootstrap_env.py</code> to generate viewer, analyst, and approver keys.
            The key is kept in this browser tab's session storage only.
          </p>
          <div className="field">
            <label htmlFor="apikey">API key</label>
            <input id="apikey" className="input" type="password" autoComplete="off" value={key}
              onChange={(e) => setKey(e.target.value)} placeholder="tfa_…" autoFocus />
          </div>
          {error && <ErrorBox message={error} />}
          <button className="btn primary" type="submit" disabled={busy || key.trim().length < 8}>
            {busy ? 'Checking…' : 'Sign in'}
          </button>
        </div>
      </form>
    </div>
  );
};
