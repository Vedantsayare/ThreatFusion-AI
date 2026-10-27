import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api, getToken, setToken, setUnauthorizedHandler } from './api.ts';
import { href, useRoute } from './router.ts';
import { Principal } from './types.ts';
import { Layout } from './components/Layout.tsx';
import { Login } from './components/Login.tsx';
import { Loading } from './components/ui.tsx';
import { OverviewPage, useDashboard } from './pages/Overview.tsx';
import { AlertDetailPage, AlertsPage } from './pages/Alerts.tsx';
import { IncidentsPage, IncidentWorkspace } from './pages/Incidents.tsx';
import { ApprovalsPage } from './pages/Approvals.tsx';
import { AuditPage, GraphPage, IntelPage, SettingsPage } from './pages/Other.tsx';

const TITLES: Record<string, string> = {
  overview: 'SOC Overview', alerts: 'Alerts', incidents: 'Incidents', graph: 'Knowledge Graph',
  intel: 'Threat Intelligence', approvals: 'Response Approvals', audit: 'Audit Log', settings: 'Integrations & Settings',
};

const Console: React.FC<{ who: Principal; onSignOut: () => void }> = ({ who, onSignOut }) => {
  const route = useRoute();
  const dashboard = useDashboard();
  const [tick, setTick] = useState(0);
  const section = TITLES[route.path[0]] ? route.path[0] : 'overview';
  const id = route.path[1];
  const refresh = useCallback(() => { void dashboard.reload(); }, [dashboard]);
  const pending = dashboard.data?.stats.pending_approvals ?? 0;

  let title: React.ReactNode = TITLES[section];
  let crumbs: React.ReactNode = null;
  let body: React.ReactNode;
  switch (section) {
    case 'alerts':
      if (id) { crumbs = <><a href={href('alerts')}>Alerts</a> / <span className="mono">{id}</span></>; title = 'Alert investigation'; body = <AlertDetailPage key={`${id}${tick}`} alertId={id} />; }
      else body = <AlertsPage key={`${route.query.toString()}${tick}`} route={route} who={who} onChanged={refresh} />;
      break;
    case 'incidents':
      if (id) { crumbs = <><a href={href('incidents')}>Incidents</a> / <span className="mono">{id}</span></>; title = 'Investigation workspace'; body = <IncidentWorkspace key={`${id}${tick}`} incidentId={id} who={who} onChanged={refresh} />; }
      else body = <IncidentsPage key={tick} />;
      break;
    case 'graph': body = <GraphPage key={`${route.query.toString()}${tick}`} route={route} />; break;
    case 'intel': body = <IntelPage key={`${route.query.toString()}${tick}`} route={route} who={who} />; break;
    case 'approvals': body = <ApprovalsPage key={`${route.query.toString()}${tick}`} route={route} who={who} onChanged={refresh} />; break;
    case 'audit': body = <AuditPage key={tick} />; break;
    case 'settings': body = <SettingsPage key={tick} who={who} />; break;
    default: body = <OverviewPage state={dashboard} />;
  }

  return (
    <Layout section={section} title={title} crumbs={crumbs} who={who} pendingApprovals={pending} onSignOut={onSignOut}
      actions={<button className="btn sm" onClick={() => { setTick(tick + 1); refresh(); }} aria-label="Refresh data"><RefreshCw size={13} /> Refresh</button>}>
      {body}
    </Layout>
  );
};

export const App: React.FC = () => {
  const [who, setWho] = useState<Principal | null>(null);
  const [checking, setChecking] = useState(Boolean(getToken()));

  const signOut = useCallback(() => {
    setToken(null);
    setWho(null);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(signOut);
    if (!getToken()) return;
    api<Principal>('/api/v1/auth/me')
      .then(setWho)
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
  }, [signOut]);

  if (checking) return <Loading label="Restoring session…" />;
  if (!who) return <Login onSignedIn={(key, p) => { setToken(key); setWho(p); }} />;
  return <Console who={who} onSignOut={signOut} />;
};

export default App;
