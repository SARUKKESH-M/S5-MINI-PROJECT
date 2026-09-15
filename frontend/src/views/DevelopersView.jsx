import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getDeveloperAnalytics,
  getAnalyticsSummary,
  getAnalyses,
} from '../services/apiClient';
import PageHeader from '../components/common/PageHeader';
import LoadingState from '../components/common/LoadingState';
import EmptyState from '../components/common/EmptyState';
import ErrorState from '../components/common/ErrorState';
import StatusBadge from '../components/StatusBadge';
import {
  DevelopersIcon,
  RepositoriesIcon,
  ShieldLogo,
  AnalyzeIcon,
  ReviewsIcon,
} from '../components/dashboard/Icons';

/**
 * Sanitize error message to prevent exposure of filesystem paths or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred while loading developer analytics.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

/**
 * Format ISO datetime string to localized date string.
 */
function formatActivityDate(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return '—';
  }
}

export default function DevelopersView() {
  const navigate = useNavigate();

  // Loading / Refresh / Error State
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Authoritative Backend Data
  const [developerData, setDeveloperData] = useState([]);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [summaryData, setSummaryData] = useState(null);

  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [repositoryFilter, setRepositoryFilter] = useState('ALL');
  const [postureFilter, setPostureFilter] = useState('ALL'); // 'ALL' | 'BLOCK' | 'REVIEW' | 'ALLOW'
  const [severityFilter, setSeverityFilter] = useState('ALL'); // 'ALL' | 'CRITICAL' | 'HIGH'
  const [sortBy, setSortBy] = useState('findings-desc');

  // Inspection Modal State
  const [selectedDeveloper, setSelectedDeveloper] = useState(null);
  const modalCloseBtnRef = useRef(null);
  const previousFocusRef = useRef(null);

  // Anti-Duplicate Refresh Guard
  const isRefreshingRef = useRef(false);

  /**
   * Load authoritative developer telemetry from backend.
   */
  const loadDeveloperTelemetry = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      if (isRefreshingRef.current) return;
      isRefreshingRef.current = true;
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      const [devRes, summaryRes, analysesRes] = await Promise.allSettled([
        getDeveloperAnalytics({ limit: 100 }),
        getAnalyticsSummary({ timeWindow: 'all' }),
        getAnalyses({ limit: 10, offset: 0 }),
      ]);

      if (devRes.status === 'fulfilled' && devRes.value && Array.isArray(devRes.value.developers)) {
        setDeveloperData(devRes.value.developers);
      } else {
        setDeveloperData([]);
      }

      if (summaryRes.status === 'fulfilled' && summaryRes.value) {
        setSummaryData(summaryRes.value.data || summaryRes.value);
      } else {
        setSummaryData(null);
      }

      if (analysesRes.status === 'fulfilled' && analysesRes.value && Array.isArray(analysesRes.value.analyses)) {
        setRecentAnalyses(analysesRes.value.analyses);
      } else {
        setRecentAnalyses([]);
      }
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to load developer telemetry.'));
    } finally {
      setLoading(false);
      setRefreshing(false);
      isRefreshingRef.current = false;
    }
  };

  useEffect(() => {
    loadDeveloperTelemetry(false);
  }, []);

  // Keyboard escape listener and focus trap for developer detail modal
  useEffect(() => {
    if (!selectedDeveloper) return;

    previousFocusRef.current = document.activeElement;
    const timer = setTimeout(() => {
      modalCloseBtnRef.current?.focus();
    }, 50);

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setSelectedDeveloper(null);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('keydown', handleKeyDown);
      if (previousFocusRef.current && typeof previousFocusRef.current.focus === 'function') {
        previousFocusRef.current.focus();
      }
    };
  }, [selectedDeveloper]);

  // Derive unique repositories across all developer records
  const availableRepositories = useMemo(() => {
    const repos = new Set();
    developerData.forEach((d) => {
      if (Array.isArray(d.repositories)) {
        d.repositories.forEach((r) => repos.add(r));
      }
    });
    return Array.from(repos).sort();
  }, [developerData]);

  // Compute Authoritative Overview Metrics
  const metrics = useMemo(() => {
    const totalDevelopers = developerData.length;
    let totalAnalyses = 0;
    let totalFindings = 0;
    let criticalCount = 0;
    let highCount = 0;
    const uniqueRepos = new Set();

    developerData.forEach((d) => {
      totalAnalyses += Number(d.total_analyses) || 0;
      totalFindings += Number(d.total_findings) || 0;
      criticalCount += Number(d.critical_count) || 0;
      highCount += Number(d.high_count) || 0;
      if (Array.isArray(d.repositories)) {
        d.repositories.forEach((r) => uniqueRepos.add(r));
      }
    });

    return {
      totalDevelopers,
      totalAnalyses,
      totalFindings,
      criticalCount,
      highCount,
      totalRepositories: uniqueRepos.size,
    };
  }, [developerData]);

  // Client-side Filtered and Sorted Developer Records
  const filteredAndSortedDevelopers = useMemo(() => {
    let list = [...developerData];

    // 1. Repository Filter
    if (repositoryFilter !== 'ALL') {
      list = list.filter((d) => Array.isArray(d.repositories) && d.repositories.includes(repositoryFilter));
    }

    // 2. Posture Filter
    if (postureFilter === 'BLOCK') {
      list = list.filter((d) => (d.block_count || 0) > 0);
    } else if (postureFilter === 'REVIEW') {
      list = list.filter((d) => (d.review_count || 0) > 0);
    } else if (postureFilter === 'ALLOW') {
      list = list.filter((d) => (d.allow_count || 0) > 0 && (d.block_count || 0) === 0);
    }

    // 3. Severity Filter
    if (severityFilter === 'CRITICAL') {
      list = list.filter((d) => (d.critical_count || 0) > 0);
    } else if (severityFilter === 'HIGH') {
      list = list.filter((d) => (d.high_count || 0) > 0);
    }

    // 4. Search Query (Client-side fast search across developer name & repos)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter((d) => {
        const name = (d.developer || '').toLowerCase();
        const repos = Array.isArray(d.repositories) ? d.repositories.join(' ').toLowerCase() : '';
        return name.includes(q) || repos.includes(q);
      });
    }

    // 5. Deterministic Sorting
    list.sort((a, b) => {
      if (sortBy === 'findings-desc') {
        const diff = (b.total_findings || 0) - (a.total_findings || 0);
        if (diff !== 0) return diff;
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'findings-asc') {
        const diff = (a.total_findings || 0) - (b.total_findings || 0);
        if (diff !== 0) return diff;
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'crit-desc') {
        const diff = (b.critical_count || 0) - (a.critical_count || 0);
        if (diff !== 0) return diff;
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'crit-asc') {
        const diff = (a.critical_count || 0) - (b.critical_count || 0);
        if (diff !== 0) return diff;
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'high-desc') {
        const diff = (b.high_count || 0) - (a.high_count || 0);
        if (diff !== 0) return diff;
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'high-asc') {
        const diff = (a.high_count || 0) - (b.high_count || 0);
        if (diff !== 0) return diff;
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'dev-asc') {
        return (a.developer || '').localeCompare(b.developer || '');
      }
      if (sortBy === 'dev-desc') {
        return (b.developer || '').localeCompare(a.developer || '');
      }
      if (sortBy === 'date-desc') {
        const dA = new Date(a.last_activity || 0).getTime();
        const dB = new Date(b.last_activity || 0).getTime();
        return dB - dA;
      }
      if (sortBy === 'date-asc') {
        const dA = new Date(a.last_activity || 0).getTime();
        const dB = new Date(b.last_activity || 0).getTime();
        return dA - dB;
      }
      return 0;
    });

    return list;
  }, [developerData, repositoryFilter, postureFilter, severityFilter, searchQuery, sortBy]);

  const isFiltered = Boolean(
    searchQuery.trim() ||
    repositoryFilter !== 'ALL' ||
    postureFilter !== 'ALL' ||
    severityFilter !== 'ALL'
  );

  const handleResetFilters = () => {
    setSearchQuery('');
    setRepositoryFilter('ALL');
    setPostureFilter('ALL');
    setSeverityFilter('ALL');
    setSortBy('findings-desc');
  };

  return (
    <div className="cs-developers-workspace" style={{ paddingBottom: '32px' }}>
      {/* 1. Page Header */}
      <PageHeader
        title="Developers"
        description="Developer security attribution and posture telemetry aggregated from authoritative analysis records."
        icon={<DevelopersIcon size={22} />}
        primaryAction={
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => loadDeveloperTelemetry(true)}
            disabled={loading || refreshing}
            aria-label="Refresh developer telemetry"
            title="Refresh developer telemetry"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <span style={{ display: 'inline-block', animation: refreshing ? 'cs-spin 0.8s linear infinite' : 'none' }}>
              ↻
            </span>
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        }
      />

      {/* 2. Loading State */}
      {loading && (
        <LoadingState
          message="Loading developer telemetry..."
          subtext="Aggregating author attribution and security gate telemetry from CodeSentinel engine."
          minHeight="240px"
        />
      )}

      {/* 3. Error State */}
      {!loading && error && (
        <ErrorState
          title="Unable to Load Developer Telemetry"
          error={error}
          onRetry={() => loadDeveloperTelemetry(false)}
          retryLabel="Retry Retrieval"
        />
      )}

      {/* 4. Main Content when Loaded */}
      {!loading && !error && (
        <>
          {/* Authoritative Metric Cards Overview (6 Cards) */}
          <div
            className="cs-metrics-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '12px',
              marginBottom: '20px',
            }}
          >
            {/* Attributed Developers */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #6366F1',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Attributed Developers
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.totalDevelopers}
              </span>
            </div>

            {/* Total Analyses */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #3B82F6',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#3B82F6', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Total Analyses
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.totalAnalyses}
              </span>
            </div>

            {/* Total Findings */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #F59E0B',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#F59E0B', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Total Findings
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.totalFindings}
              </span>
            </div>

            {/* Critical Findings */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #EF4444',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#EF4444', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Critical Findings
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#EF4444', marginTop: '4px' }}>
                {metrics.criticalCount}
              </span>
            </div>

            {/* High Findings */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #F97316',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#F97316', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                High Findings
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#F97316', marginTop: '4px' }}>
                {metrics.highCount}
              </span>
            </div>

            {/* Monitored Repositories */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #10B981',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#10B981', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Repositories
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.totalRepositories}
              </span>
            </div>
          </div>

          {/* If there is genuinely zero developer attribution metadata */}
          {developerData.length === 0 ? (
            <EmptyState
              icon="👤"
              title="No Author Attribution Recorded"
              description="Analyses in this scope do not contain author attribution metadata. When analyses are executed with author or commit metadata, developer-level security telemetry will be reported here. CodeSentinel strictly reports authoritative data and does not fabricate developer metrics, velocity formulas, or commit counts."
              actionText="Open Analysis Studio"
              onAction={() => navigate('/analyze')}
              secondaryActionText="Audit Repositories"
              onSecondaryAction={() => navigate('/repositories')}
            />
          ) : (
            <>
              {/* Filter Bar */}
              <div
                className="card"
                style={{
                  padding: '16px',
                  marginBottom: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
                aria-label="Developer Telemetry Filters"
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px',
                  }}
                >
                  {/* Search Input */}
                  <div style={{ flex: '1 1 240px', minWidth: '200px' }}>
                    <input
                      type="search"
                      className="form-control"
                      placeholder="Search developer author or repository..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      aria-label="Search developer attribution"
                      style={{
                        width: '100%',
                        fontSize: '13px',
                        padding: '8px 12px',
                        borderRadius: '6px',
                      }}
                    />
                  </div>

                  {/* Clear Filters Action */}
                  {isFiltered && (
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={handleResetFilters}
                      style={{ fontSize: '12px' }}
                    >
                      Clear Filters
                    </button>
                  )}
                </div>

                {/* Filter Dropdowns */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                    gap: '10px',
                  }}
                >
                  {/* Repository Filter */}
                  <div>
                    <label
                      htmlFor="filter-repo"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Repository
                    </label>
                    <select
                      id="filter-repo"
                      className="form-control"
                      value={repositoryFilter}
                      onChange={(e) => setRepositoryFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Repositories ({availableRepositories.length})</option>
                      {availableRepositories.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Posture Filter */}
                  <div>
                    <label
                      htmlFor="filter-posture"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Gate Posture
                    </label>
                    <select
                      id="filter-posture"
                      className="form-control"
                      value={postureFilter}
                      onChange={(e) => setPostureFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Postures</option>
                      <option value="BLOCK">Has Block Verdicts</option>
                      <option value="REVIEW">Has Review Verdicts</option>
                      <option value="ALLOW">Allow Verdicts Only</option>
                    </select>
                  </div>

                  {/* Severity Filter */}
                  <div>
                    <label
                      htmlFor="filter-severity"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Finding Severity
                    </label>
                    <select
                      id="filter-severity"
                      className="form-control"
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Has Critical Findings</option>
                      <option value="HIGH">Has High Findings</option>
                    </select>
                  </div>

                  {/* Sort Selector */}
                  <div>
                    <label
                      htmlFor="filter-sort"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Sort Order
                    </label>
                    <select
                      id="filter-sort"
                      className="form-control"
                      value={sortBy}
                      onChange={(e) => setSortBy(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="findings-desc">Findings: Highest First</option>
                      <option value="findings-asc">Findings: Lowest First</option>
                      <option value="crit-desc">Critical: Highest First</option>
                      <option value="crit-asc">Critical: Lowest First</option>
                      <option value="high-desc">High: Highest First</option>
                      <option value="high-asc">High: Lowest First</option>
                      <option value="dev-asc">Developer: A → Z</option>
                      <option value="dev-desc">Developer: Z → A</option>
                      <option value="date-desc">Activity: Newest First</option>
                      <option value="date-asc">Activity: Oldest First</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Developer Attribution Table */}
              {filteredAndSortedDevelopers.length === 0 ? (
                <EmptyState
                  icon="🔍"
                  title="No Matching Developer Records"
                  description="No developer attribution records match the current filter criteria or search query."
                  actionText="Reset Filters"
                  onAction={handleResetFilters}
                />
              ) : (
                <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: '24px' }}>
                  <div
                    style={{
                      padding: '12px 16px',
                      borderBottom: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '12.5px',
                      color: 'var(--text-muted)',
                      backgroundColor: 'var(--bg-surface-elevated)',
                    }}
                  >
                    <div>
                      Showing <strong style={{ color: 'var(--text-primary)' }}>{filteredAndSortedDevelopers.length}</strong> of{' '}
                      <strong>{developerData.length}</strong> attributed developers
                    </div>
                  </div>

                  <div className="table-container" style={{ margin: 0, border: 'none' }}>
                    <table className="data-table" aria-label="Developer Attribution Explorer">
                      <thead>
                        <tr>
                          <th scope="col">Developer</th>
                          <th scope="col">Associated Repositories</th>
                          <th scope="col" style={{ textAlign: 'center' }}>Analyses</th>
                          <th scope="col" style={{ textAlign: 'center' }}>Total Findings</th>
                          <th scope="col">Critical / High</th>
                          <th scope="col">Gate Distribution (Block / Rev / Allow)</th>
                          <th scope="col">Last Activity</th>
                          <th scope="col" style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAndSortedDevelopers.map((dev) => {
                          const fCount = dev.total_findings || 0;
                          const crit = dev.critical_count || 0;
                          const high = dev.high_count || 0;

                          return (
                            <tr
                              key={dev.developer}
                              style={{ cursor: 'pointer' }}
                              onClick={() => setSelectedDeveloper(dev)}
                            >
                              {/* Developer Name */}
                              <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <div
                                    style={{
                                      width: '26px',
                                      height: '26px',
                                      borderRadius: '50%',
                                      backgroundColor: 'rgba(99, 102, 241, 0.12)',
                                      color: '#4F46E5',
                                      display: 'flex',
                                      alignItems: 'center',
                                      justifyContent: 'center',
                                      fontSize: '12px',
                                      fontWeight: 700,
                                      flexShrink: 0,
                                    }}
                                  >
                                    {(dev.developer || 'D').charAt(0).toUpperCase()}
                                  </div>
                                  <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                                    {dev.developer}
                                  </span>
                                </div>
                              </td>

                              {/* Repositories */}
                              <td>
                                <div style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '200px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                  {Array.isArray(dev.repositories) && dev.repositories.length > 0
                                    ? dev.repositories.join(', ')
                                    : '—'}
                                </div>
                              </td>

                              {/* Analyses */}
                              <td style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '12.5px' }}>
                                {dev.total_analyses}
                              </td>

                              {/* Total Findings */}
                              <td style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: 700, color: fCount > 0 ? '#EF4444' : '#10B981', fontSize: '13px' }}>
                                {fCount}
                              </td>

                              {/* Critical / High */}
                              <td>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                                  <span style={{ color: '#EF4444', fontWeight: 700 }}>{crit}</span> /{' '}
                                  <span style={{ color: '#F97316', fontWeight: 600 }}>{high}</span>
                                </span>
                              </td>

                              {/* Gate Distribution */}
                              <td>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                                  <span style={{ color: '#EF4444', fontWeight: 600 }}>{dev.block_count || 0}</span> /{' '}
                                  <span style={{ color: '#F59E0B', fontWeight: 600 }}>{dev.review_count || 0}</span> /{' '}
                                  <span style={{ color: '#10B981', fontWeight: 600 }}>{dev.allow_count || 0}</span>
                                </span>
                              </td>

                              {/* Last Activity */}
                              <td>
                                <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                                  {formatActivityDate(dev.last_activity)}
                                </span>
                              </td>

                              {/* Action */}
                              <td style={{ textAlign: 'right' }}>
                                <button
                                  type="button"
                                  className="btn btn-secondary btn-sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedDeveloper(dev);
                                  }}
                                  aria-label={`Inspect developer: ${dev.developer}`}
                                  style={{ padding: '3px 8px', fontSize: '11.5px' }}
                                >
                                  Inspect
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Section: Recent Security Activity Feed (Compact) */}
          <div className="card" style={{ padding: '20px' }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '14px',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  Recent Security Activity
                </h3>
                <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                  Latest verified security audits and gate decisions across all repositories
                </span>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => navigate('/history')}
                style={{ fontSize: '11.5px' }}
              >
                View Audit History →
              </button>
            </div>

            {recentAnalyses.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 16px', color: 'var(--text-dim)' }}>
                <div style={{ fontSize: '24px', marginBottom: '6px' }}>🛡️</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>No Recent Audits Available</div>
                <div style={{ fontSize: '12px' }}>Run a scan in Analyze Studio to initiate an audit trail.</div>
              </div>
            ) : (
              <div className="table-container" style={{ margin: 0, border: 'none' }}>
                <table className="data-table" aria-label="Recent Security Audits">
                  <thead>
                    <tr>
                      <th scope="col">Analysis ID</th>
                      <th scope="col">Repository</th>
                      <th scope="col">Date</th>
                      <th scope="col" style={{ textAlign: 'center' }}>Findings</th>
                      <th scope="col">Gate Verdict</th>
                      <th scope="col" style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAnalyses.slice(0, 5).map((item) => {
                      const repoName = item.summary?._repository?.repository ||
                        item.summary?._repository?.name ||
                        item.query ||
                        'Source Inspection';
                      const fCount = item.finding_count ?? item.summary?.total_findings ?? 0;
                      const gate = (item.summary?._review_status || 'ALLOW').toUpperCase();

                      return (
                        <tr key={item.analysis_id}>
                          <td>
                            <code style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: '#4F46E5' }}>
                              {String(item.analysis_id).slice(0, 8)}
                            </code>
                          </td>
                          <td style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: '12.5px' }}>
                            {repoName}
                          </td>
                          <td style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                            {formatActivityDate(item.created_at)}
                          </td>
                          <td style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: 700, color: fCount > 0 ? '#EF4444' : '#10B981' }}>
                            {fCount}
                          </td>
                          <td>
                            <StatusBadge status={gate} />
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <div style={{ display: 'inline-flex', gap: '6px' }}>
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                onClick={() => navigate(`/history?id=${item.analysis_id}`)}
                                style={{ fontSize: '11px', padding: '2px 7px' }}
                              >
                                Audit
                              </button>
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                onClick={() => navigate(`/reviews?analysis_id=${item.analysis_id}`)}
                                style={{ fontSize: '11px', padding: '2px 7px', color: '#4F46E5', borderColor: '#C7D2FE' }}
                              >
                                Review
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {/* 5. Developer Detail Modal */}
      {selectedDeveloper && (
        <div
          className="cs-modal-backdrop"
          onClick={() => setSelectedDeveloper(null)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="cs-dev-modal-title"
        >
          <div
            className="cs-modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '600px' }}
          >
            {/* Modal Header */}
            <div className="cs-modal-header">
              <div className="cs-modal-header-left" style={{ gap: '10px', alignItems: 'center' }}>
                <h3 id="cs-dev-modal-title" className="cs-modal-title">
                  Developer Attribution Details
                </h3>
              </div>
              <button
                ref={modalCloseBtnRef}
                type="button"
                className="cs-modal-close-btn"
                onClick={() => setSelectedDeveloper(null)}
                aria-label="Close developer details modal"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="cs-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Identity Header */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '12px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '50%',
                    backgroundColor: 'rgba(99, 102, 241, 0.15)',
                    color: '#4F46E5',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '18px',
                    fontWeight: 700,
                  }}
                >
                  {(selectedDeveloper.developer || 'D').charAt(0).toUpperCase()}
                </div>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                    {selectedDeveloper.developer}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Last Activity: {formatActivityDate(selectedDeveloper.last_activity)}
                  </div>
                </div>
              </div>

              {/* Associated Repositories */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
                  Associated Repositories
                </div>
                {Array.isArray(selectedDeveloper.repositories) && selectedDeveloper.repositories.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {selectedDeveloper.repositories.map((repo) => (
                      <button
                        key={repo}
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => {
                          setSelectedDeveloper(null);
                          navigate('/repositories', { state: { repo } });
                        }}
                        style={{ fontSize: '12px', padding: '4px 8px' }}
                      >
                        <RepositoriesIcon size={13} />
                        <span>{repo}</span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>No associated repositories recorded.</div>
                )}
              </div>

              {/* Authoritative Gate Distribution */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
                  Security Gate Decisions
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, 1fr)',
                    gap: '8px',
                    textAlign: 'center',
                  }}
                >
                  <div style={{ padding: '10px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#EF4444' }}>BLOCK</div>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: '#EF4444', marginTop: '2px' }}>
                      {selectedDeveloper.block_count || 0}
                    </div>
                  </div>
                  <div style={{ padding: '10px', borderRadius: '6px', backgroundColor: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#F59E0B' }}>REVIEW</div>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: '#F59E0B', marginTop: '2px' }}>
                      {selectedDeveloper.review_count || 0}
                    </div>
                  </div>
                  <div style={{ padding: '10px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#10B981' }}>ALLOW</div>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: '#10B981', marginTop: '2px' }}>
                      {selectedDeveloper.allow_count || 0}
                    </div>
                  </div>
                </div>
              </div>

              {/* Findings Breakdown */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
                  Findings Severity Breakdown
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(4, 1fr)',
                    gap: '8px',
                    textAlign: 'center',
                  }}
                >
                  <div style={{ padding: '8px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '10.5px', color: '#EF4444', fontWeight: 600 }}>Critical</div>
                    <div style={{ fontSize: '16px', fontWeight: 700, color: '#EF4444', marginTop: '2px' }}>
                      {selectedDeveloper.critical_count || 0}
                    </div>
                  </div>
                  <div style={{ padding: '8px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '10.5px', color: '#F97316', fontWeight: 600 }}>High</div>
                    <div style={{ fontSize: '16px', fontWeight: 700, color: '#F97316', marginTop: '2px' }}>
                      {selectedDeveloper.high_count || 0}
                    </div>
                  </div>
                  <div style={{ padding: '8px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '10.5px', color: '#F59E0B', fontWeight: 600 }}>Medium</div>
                    <div style={{ fontSize: '16px', fontWeight: 700, color: '#F59E0B', marginTop: '2px' }}>
                      {selectedDeveloper.medium_count || 0}
                    </div>
                  </div>
                  <div style={{ padding: '8px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '10.5px', color: '#06B6D4', fontWeight: 600 }}>Low</div>
                    <div style={{ fontSize: '16px', fontWeight: 700, color: '#06B6D4', marginTop: '2px' }}>
                      {selectedDeveloper.low_count || 0}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="cs-modal-footer">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedDeveloper(null)}
              >
                Close
              </button>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setSelectedDeveloper(null);
                    navigate('/history');
                  }}
                >
                  Audit History →
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setSelectedDeveloper(null);
                    navigate('/vulnerabilities');
                  }}
                  style={{ color: '#4F46E5', borderColor: '#C7D2FE' }}
                >
                  Explore Vulnerabilities →
                </button>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => {
                    setSelectedDeveloper(null);
                    navigate('/analytics');
                  }}
                >
                  Full Analytics →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
