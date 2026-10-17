import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, ShieldAlert, Activity } from 'lucide-react';
import { DashboardStats } from '../types.ts';

interface StatsBarProps {
  stats: DashboardStats | null;
}

export const StatsBar: React.FC<StatsBarProps> = ({ stats }) => {
  if (!stats) return null;

  return (
    <div className="stats-grid" id="stats-overview-bar">
      <div className="stat-card">
        <div className="stat-header">
          <span>Total Alerts</span>
          <Activity size={16} color="var(--accent-cyan)" />
        </div>
        <div className="stat-value">{stats.total_investigations}</div>
      </div>

      <div className="stat-card crit">
        <div className="stat-header">
          <span>Critical (P1)</span>
          <ShieldAlert size={16} color="var(--p1-crit)" />
        </div>
        <div className="stat-value">{stats.priority_p1}</div>
      </div>

      <div className="stat-card p2">
        <div className="stat-header">
          <span>High (P2)</span>
          <AlertTriangle size={16} color="var(--p2-high)" />
        </div>
        <div className="stat-value">{stats.priority_p2}</div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span>Med / Low (P3/P4)</span>
          <CheckCircle2 size={16} color="var(--accent-blue)" />
        </div>
        <div className="stat-value">{stats.priority_p3 + stats.priority_p4}</div>
      </div>

      <div className={`stat-card ${stats.pending_approvals > 0 ? 'warning' : ''}`}>
        <div className="stat-header">
          <span>Pending Approvals</span>
          <AlertCircle size={16} color={stats.pending_approvals > 0 ? 'var(--warning)' : 'var(--text-muted)'} />
        </div>
        <div className="stat-value">{stats.pending_approvals}</div>
      </div>
    </div>
  );
};
