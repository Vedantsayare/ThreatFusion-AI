import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar.tsx';
import { StatsBar } from './components/StatsBar.tsx';
import { InvestigationList } from './components/InvestigationList.tsx';
import { InvestigationDetail } from './components/InvestigationDetail.tsx';
import {
  DashboardStats,
  IntegrationsStatus,
  InvestigationSummary,
  InvestigationDetail as IInvestigationDetail,
  PaginatedResponse,
} from './types.ts';

export const App: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [integrations, setIntegrations] = useState<IntegrationsStatus | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<IInvestigationDetail | null>(null);

  const [search, setSearch] = useState('');
  const [priorityFilter, setPriorityFilter] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const [isLoadingList, setIsLoadingList] = useState(false);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // 1. Fetch Integration Status
  const fetchIntegrations = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/integrations/status');
      if (res.ok) {
        const data = await res.json();
        setIntegrations(data);
      }
    } catch {
      // Offline or mock
      setIntegrations({
        wazuh: { enabled: true, endpoint: '/alerts' },
        neo4j: { enabled: true, database: 'neo4j' },
        misp: { enabled: false, base_url: 'not configured' },
        cmdb: { enabled: true, provider: 'MockIAMCMDBProvider' },
      });
    }
  }, []);

  // 2. Fetch Stats
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch {
      // Fallback
      setStats({
        total_investigations: investigations.length,
        priority_p1: investigations.filter((i) => i.priority === 'P1').length,
        priority_p2: investigations.filter((i) => i.priority === 'P2').length,
        priority_p3: investigations.filter((i) => i.priority === 'P3').length,
        priority_p4: investigations.filter((i) => i.priority === 'P4').length,
        pending_approvals: investigations.reduce((acc, cur) => acc + cur.pending_approvals_count, 0),
        critical_threats: investigations.filter((i) => i.priority === 'P1').length,
      });
    }
  }, [investigations]);

  // 3. Fetch Investigations
  const fetchInvestigations = useCallback(
    async (page = 1, priority = priorityFilter, query = search) => {
      setIsLoadingList(true);
      try {
        const params = new URLSearchParams();
        params.set('page', page.toString());
        params.set('page_size', '15');
        if (priority) params.set('priority', priority);
        if (query.trim()) params.set('search', query.trim());

        const res = await fetch(`/api/v1/investigations?${params.toString()}`);
        if (res.ok) {
          const data: PaginatedResponse<InvestigationSummary> = await res.json();
          setInvestigations(data.items);
          setTotalPages(data.total_pages);
          setCurrentPage(data.page);

          // Select first item if nothing selected or current selection missing
          if (data.items.length > 0 && (!selectedAlertId || !data.items.find((i) => i.alert_id === selectedAlertId))) {
            setSelectedAlertId(data.items[0].alert_id);
          }
        }
      } catch (err) {
        console.error('Failed to fetch investigations:', err);
      } finally {
        setIsLoadingList(false);
      }
    },
    [priorityFilter, search, selectedAlertId]
  );

  // 4. Fetch Detail for Selected Alert
  const fetchDetail = useCallback(async (alertId: string) => {
    setIsLoadingDetail(true);
    try {
      const res = await fetch(`/api/v1/investigations/${alertId}`);
      if (res.ok) {
        const data: IInvestigationDetail = await res.json();
        setSelectedDetail(data);
      }
    } catch (err) {
      console.error('Failed to fetch detail for alert:', alertId, err);
    } finally {
      setIsLoadingDetail(false);
    }
  }, []);

  // Initial Load
  useEffect(() => {
    fetchIntegrations();
    fetchStats();
    fetchInvestigations(1, null, '');
  }, []);

  // Update detail when selectedAlertId changes
  useEffect(() => {
    if (selectedAlertId) {
      fetchDetail(selectedAlertId);
    } else {
      setSelectedDetail(null);
    }
  }, [selectedAlertId, fetchDetail]);

  // Handle Search & Filter changes
  const handleSearchChange = (val: string) => {
    setSearch(val);
    fetchInvestigations(1, priorityFilter, val);
  };

  const handlePriorityChange = (val: string | null) => {
    setPriorityFilter(val);
    fetchInvestigations(1, val, search);
  };

  const handlePageChange = (newPage: number) => {
    fetchInvestigations(newPage, priorityFilter, search);
  };

  // On-demand MISP & CMDB enrichment
  const handleEnrich = async (alertId: string) => {
    try {
      const res = await fetch(`/api/v1/investigations/${alertId}/enrich`, { method: 'POST' });
      if (res.ok) {
        await fetchDetail(alertId);
      }
    } catch (err) {
      console.error('Enrichment failed:', err);
    }
  };

  // Submit human approval decision
  const handleSubmitApproval = async (
    requestId: string,
    decision: 'APPROVE' | 'REJECT',
    reviewerId: string,
    reason: string
  ) => {
    const res = await fetch(`/api/v1/approvals/${requestId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reviewer_id: reviewerId, decision, reason }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(err.detail || 'Failed to submit approval decision');
    }

    // Refresh detail and stats
    if (selectedAlertId) {
      await fetchDetail(selectedAlertId);
    }
    await fetchStats();
    await fetchInvestigations(currentPage, priorityFilter, search);
  };

  const handleRefreshAll = async () => {
    setIsRefreshing(true);
    await Promise.all([
      fetchIntegrations(),
      fetchStats(),
      fetchInvestigations(currentPage, priorityFilter, search),
      selectedAlertId ? fetchDetail(selectedAlertId) : Promise.resolve(),
    ]);
    setIsRefreshing(false);
  };

  return (
    <div className="app-container">
      <Navbar status={integrations} onRefresh={handleRefreshAll} isLoading={isRefreshing} />

      <main className="main-content">
        <StatsBar stats={stats} />

        <div className="dashboard-grid">
          <InvestigationList
            items={investigations}
            selectedId={selectedAlertId}
            onSelect={(id) => setSelectedAlertId(id)}
            search={search}
            onSearchChange={handleSearchChange}
            priorityFilter={priorityFilter}
            onPriorityChange={handlePriorityChange}
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
            isLoading={isLoadingList}
          />

          <InvestigationDetail
            detail={selectedDetail}
            isLoading={isLoadingDetail}
            onEnrich={handleEnrich}
            onSubmitApproval={handleSubmitApproval}
          />
        </div>
      </main>
    </div>
  );
};

export default App;
