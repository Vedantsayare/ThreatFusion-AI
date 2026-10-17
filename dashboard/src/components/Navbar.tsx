import React from 'react';
import { Shield, RefreshCw } from 'lucide-react';
import { IntegrationsStatus } from '../types.ts';

interface NavbarProps {
  status: IntegrationsStatus | null;
  onRefresh: () => void;
  isLoading: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ status, onRefresh, isLoading }) => {
  return (
    <header className="navbar">
      <div className="navbar-brand">
        <div className="logo-icon">
          <Shield size={20} />
        </div>
        <div>
          <span>ThreatFusion </span>
          <span className="brand-gradient">AI</span>
        </div>
      </div>

      <div className="navbar-status">
        {status && (
          <>
            <div className="status-badge" title={status.wazuh.enabled ? 'Wazuh Ingestion Connected' : 'Wazuh Disconnected'}>
              <span className={`status-dot ${status.wazuh.enabled ? 'active' : 'inactive'}`} />
              <span>Wazuh</span>
            </div>
            <div className="status-badge" title={status.neo4j.enabled ? 'Neo4j Graph Active' : 'Neo4j Offline'}>
              <span className={`status-dot ${status.neo4j.enabled ? 'active' : 'inactive'}`} />
              <span>Neo4j</span>
            </div>
            <div className="status-badge" title={status.misp.enabled ? 'MISP Intel Connected' : 'MISP Disabled'}>
              <span className={`status-dot ${status.misp.enabled ? 'active' : 'inactive'}`} />
              <span>MISP</span>
            </div>
            <div className="status-badge" title={status.cmdb.enabled ? `CMDB (${status.cmdb.provider}) Active` : 'CMDB Inactive'}>
              <span className={`status-dot ${status.cmdb.enabled ? 'active' : 'inactive'}`} />
              <span>CMDB/IAM</span>
            </div>
          </>
        )}

        <button
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={isLoading}
          title="Refresh All Data"
          id="btn-refresh-all"
        >
          <RefreshCw size={14} className={isLoading ? 'spinner' : ''} />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
};
