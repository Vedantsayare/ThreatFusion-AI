import React from 'react';
import {
  Activity, Bell, CheckSquare, FileClock, Globe, LayoutDashboard, LogOut, Network, Settings, ShieldAlert, ShieldCheck,
} from 'lucide-react';
import { href } from '../router.ts';
import { Principal } from '../types.ts';

const NAV = [
  { id: 'overview', label: 'SOC Overview', icon: LayoutDashboard },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
  { id: 'graph', label: 'Knowledge Graph', icon: Network },
  { id: 'intel', label: 'Threat Intel', icon: Globe },
  { id: 'approvals', label: 'Response Approvals', icon: CheckSquare },
  { id: 'audit', label: 'Audit Log', icon: FileClock },
  { id: 'settings', label: 'Integrations', icon: Settings },
];

export const Layout: React.FC<{
  section: string;
  title: React.ReactNode;
  crumbs?: React.ReactNode;
  actions?: React.ReactNode;
  who: Principal;
  pendingApprovals: number;
  onSignOut: () => void;
  children: React.ReactNode;
}> = ({ section, title, crumbs, actions, who, pendingApprovals, onSignOut, children }) => (
  <div className="shell">
    <aside className="sidebar" aria-label="Primary">
      <div className="brand">
        <div className="brand-mark"><ShieldCheck size={16} /></div>
        <div>
          <div className="brand-name">ThreatFusion AI</div>
          <div className="brand-sub">Agentic SOC copilot</div>
        </div>
      </div>
      <nav className="nav">
        {NAV.map(({ id, label, icon: Icon }) => (
          <a key={id} href={href(id)} className={`nav-item${section === id ? ' active' : ''}`} aria-current={section === id ? 'page' : undefined}>
            <Icon size={16} aria-hidden="true" />
            {label}
            {id === 'approvals' && pendingApprovals > 0 && <span className="count" aria-label={`${pendingApprovals} pending`}>{pendingApprovals}</span>}
          </a>
        ))}
      </nav>
      <div className="sidebar-foot">
        <div className="row"><Activity size={13} aria-hidden="true" /> Signed in as <strong style={{ color: 'var(--text-2)' }}>{who.name}</strong></div>
        <div>Role: {who.role}</div>
        <button className="btn sm ghost" onClick={onSignOut}><LogOut size={13} /> Sign out</button>
      </div>
    </aside>
    <div className="main">
      <header className="topbar">
        <h1>{title}</h1>
        {crumbs && <span className="crumbs">{crumbs}</span>}
        <div className="topbar-actions">{actions}</div>
      </header>
      <main className="content">{children}</main>
    </div>
  </div>
);
