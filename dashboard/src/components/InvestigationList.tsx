import React from 'react';
import { Search, Server, User, ChevronLeft, ChevronRight, AlertOctagon } from 'lucide-react';
import { InvestigationSummary } from '../types.ts';

interface InvestigationListProps {
  items: InvestigationSummary[];
  selectedId: string | null;
  onSelect: (alertId: string) => void;
  search: string;
  onSearchChange: (val: string) => void;
  priorityFilter: string | null;
  onPriorityChange: (val: string | null) => void;
  currentPage: number;
  totalPages: number;
  onPageChange: (newPage: number) => void;
  isLoading: boolean;
}

export const InvestigationList: React.FC<InvestigationListProps> = ({
  items,
  selectedId,
  onSelect,
  search,
  onSearchChange,
  priorityFilter,
  onPriorityChange,
  currentPage,
  totalPages,
  onPageChange,
  isLoading,
}) => {
  const priorities = ['ALL', 'P1', 'P2', 'P3', 'P4'];

  const formatTime = (ts: number) => {
    if (!ts) return 'Unknown';
    const date = new Date(ts * 1000);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <div className="panel" id="investigations-list-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span>Security Investigations</span>
        </div>
      </div>

      <div className="search-filter-box">
        <div className="search-input-wrapper">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search by title, host, user, or alert ID..."
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            id="input-search-investigations"
          />
        </div>

        <div className="filters-row">
          {priorities.map((p) => {
            const isActive = (p === 'ALL' && !priorityFilter) || priorityFilter === p;
            return (
              <button
                key={p}
                className={`filter-btn ${isActive ? 'active' : ''}`}
                onClick={() => onPriorityChange(p === 'ALL' ? null : p)}
              >
                {p}
              </button>
            );
          })}
        </div>
      </div>

      <div className="investigations-list">
        {isLoading && items.length === 0 ? (
          <div className="empty-state">
            <div className="spinner" />
            <span>Loading investigations...</span>
          </div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <AlertOctagon size={32} />
            <span>No matching investigations found.</span>
          </div>
        ) : (
          items.map((item) => {
            const isSelected = selectedId === item.alert_id;
            return (
              <div
                key={item.alert_id}
                className={`investigation-card ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelect(item.alert_id)}
                id={`card-${item.alert_id}`}
              >
                <div className="card-top">
                  <span className={`priority-pill ${item.priority}`}>
                    {item.priority} • {item.score}
                  </span>
                  <span className="card-time">{formatTime(item.received_at)}</span>
                </div>

                <div className="card-title">{item.title}</div>

                <div className="card-meta">
                  {item.asset_name && (
                    <div className="meta-item" title="Asset">
                      <Server size={12} />
                      <span>{item.asset_name}</span>
                    </div>
                  )}
                  {item.username && (
                    <div className="meta-item" title="User">
                      <User size={12} />
                      <span>{item.username}</span>
                    </div>
                  )}
                  {item.pending_approvals_count > 0 && (
                    <span className="badge-approval">
                      {item.pending_approvals_count} Approval{item.pending_approvals_count > 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {totalPages > 1 && (
        <div className="panel-header" style={{ justifyContent: 'center', gap: '1rem', padding: '0.75rem' }}>
          <button
            className="btn btn-secondary"
            disabled={currentPage <= 1}
            onClick={() => onPageChange(currentPage - 1)}
          >
            <ChevronLeft size={14} /> Prev
          </button>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Page {currentPage} of {totalPages}
          </span>
          <button
            className="btn btn-secondary"
            disabled={currentPage >= totalPages}
            onClick={() => onPageChange(currentPage + 1)}
          >
            Next <ChevronRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
};
