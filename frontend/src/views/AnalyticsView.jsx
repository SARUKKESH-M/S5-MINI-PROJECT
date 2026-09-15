import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import {
  getAnalyticsSummary,
  getRepositoryAnalytics,
  getVulnerabilityAnalytics,
  getSuppressionAnalytics,
  getAnalyses,
  getDeveloperAnalytics,
} from '../services/apiClient';
import StatusBadge from '../components/StatusBadge';
import {
  AnalyticsIcon,
  RepositoriesIcon,
  AnalyzeIcon,
  VulnerabilitiesIcon,
  ShieldAlertIcon,
  TrendingUpIcon,
  ReviewsIcon,
} from '../components/dashboard/Icons';

/**
 * Sanitize error messages to prevent leakage of internal paths or secrets.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred during analytics retrieval.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

const TIME_WINDOWS = [
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
  { value: '90d', label: 'Last 90 Days' },
  { value: 'all', label: 'All Time' },
];

const SEVERITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#06B6D4',
  info: '#64748B',
};

const GATE_COLORS = {
  block: '#EF4444',
  review: '#F59E0B',
  allow: '#10B981',
  unknown: '#94A3B8',
};

export default function AnalyticsView() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Filters
  const timeWindow = searchParams.get('window') || '30d';
  const repositoryFilter = searchParams.get('repo') || '';

  // State
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Authoritative data from backend
  const [summaryData, setSummaryData] = useState(null);
  const [repositoriesData, setRepositoriesData] = useState([]);
  const [vulnerabilitiesData, setVulnerabilitiesData] = useState([]);
  const [suppressionsData, setSuppressionsData] = useState(null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [developerData, setDeveloperData] = useState([]);

  const isRefreshingRef = useRef(false);

  // Load all analytics data concurrently
  const loadAnalytics = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      if (isRefreshingRef.current) return;
      isRefreshingRef.current = true;
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      const summaryParams = { timeWindow };
      if (repositoryFilter) summaryParams.repositoryId = repositoryFilter;

      const vulnParams = { timeWindow, limit: 30 };
      if (repositoryFilter) vulnParams.repositoryId = repositoryFilter;

      const suppParams = { timeWindow };
      if (repositoryFilter) suppParams.repositoryId = repositoryFilter;

      const devParams = { time_window: timeWindow, limit: 20 };
      if (repositoryFilter) devParams.repository = repositoryFilter;

      const [summaryRes, repoRes, vulnRes, suppRes, analysesRes, devRes] = await Promise.allSettled([
        getAnalyticsSummary(summaryParams),
        getRepositoryAnalytics({ timeWindow, limit: 50 }),
        getVulnerabilityAnalytics(vulnParams),
        getSuppressionAnalytics(suppParams),
        getAnalyses({ limit: 100, offset: 0 }),
        getDeveloperAnalytics(devParams),
      ]);

      if (summaryRes.status === 'fulfilled' && summaryRes.value) {
        setSummaryData(summaryRes.value.data || summaryRes.value);
      } else {
        setSummaryData(null);
      }

      if (repoRes.status === 'fulfilled' && repoRes.value) {
        setRepositoriesData(Array.isArray(repoRes.value.repositories) ? repoRes.value.repositories : []);
      } else {
        setRepositoriesData([]);
      }

      if (vulnRes.status === 'fulfilled' && vulnRes.value) {
        setVulnerabilitiesData(Array.isArray(vulnRes.value.vulnerabilities) ? vulnRes.value.vulnerabilities : []);
      } else {
        setVulnerabilitiesData([]);
      }

      if (suppRes.status === 'fulfilled' && suppRes.value) {
        setSuppressionsData(suppRes.value.data || suppRes.value);
      } else {
        setSuppressionsData(null);
      }

      if (analysesRes.status === 'fulfilled' && analysesRes.value) {
        setRecentAnalyses(Array.isArray(analysesRes.value.analyses) ? analysesRes.value.analyses : []);
      } else {
        setRecentAnalyses([]);
      }

      if (devRes.status === 'fulfilled' && devRes.value && Array.isArray(devRes.value.developers)) {
        setDeveloperData(devRes.value.developers);
      } else {
        setDeveloperData([]);
      }
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to load security analytics.'));
    } finally {
      setLoading(false);
      setRefreshing(false);
      isRefreshingRef.current = false;
    }
  };

  useEffect(() => {
    loadAnalytics(false);
  }, [timeWindow, repositoryFilter]);

  const handleTimeWindowChange = (newWindow) => {
    const next = new URLSearchParams(searchParams);
    next.set('window', newWindow);
    setSearchParams(next);
  };

  const handleRepoFilterChange = (newRepo) => {
    const next = new URLSearchParams(searchParams);
    if (newRepo) {
      next.set('repo', newRepo);
    } else {
      next.delete('repo');
    }
    setSearchParams(next);
  };

  const handleManualRefresh = () => {
    loadAnalytics(true);
  };

  // Authoritative Metric Calculations
  const totalAnalyses = summaryData?.total_analyses ?? 0;
  const totalFindings = summaryData?.total_findings ?? 0;
  const totalRepositories = repositoriesData.length;

  const gateDistribution = summaryData?.review_status_distribution || {
    allow: 0,
    review: 0,
    block: 0,
    unknown: 0,
  };

  const blockedCount = gateDistribution.block || 0;
  const reviewCount = gateDistribution.review || 0;
  const allowCount = gateDistribution.allow || 0;

  const severities = summaryData?.severities || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  // Severity Pie Chart Data
  const severityChartData = useMemo(() => {
    return [
      { name: 'Critical', value: severities.critical || 0, color: SEVERITY_COLORS.critical },
      { name: 'High', value: severities.high || 0, color: SEVERITY_COLORS.high },
      { name: 'Medium', value: severities.medium || 0, color: SEVERITY_COLORS.medium },
      { name: 'Low', value: severities.low || 0, color: SEVERITY_COLORS.low },
      { name: 'Info', value: severities.info || 0, color: SEVERITY_COLORS.info },
    ].filter((item) => item.value > 0);
  }, [severities]);

  // Security Gate Chart Data
  const gateChartData = useMemo(() => {
    return [
      { name: 'Block', value: blockedCount, color: GATE_COLORS.block },
      { name: 'Review', value: reviewCount, color: GATE_COLORS.review },
      { name: 'Allow', value: allowCount, color: GATE_COLORS.allow },
    ].filter((item) => item.value > 0);
  }, [blockedCount, reviewCount, allowCount]);

  // Historical Analysis & Finding Trend Time Series
  const { trendData, isSparseTrend } = useMemo(() => {
    if (!Array.isArray(recentAnalyses) || recentAnalyses.length === 0) {
      return { trendData: [], isSparseTrend: true };
    }

    const dayMap = new Map();

    for (const item of recentAnalyses) {
      if (!item.created_at) continue;

      // Filter by repository if filter is active
      if (repositoryFilter) {
        const repoMeta = item.summary?._repository;
        let rId = '';
        if (typeof repoMeta === 'string') rId = repoMeta;
        else if (repoMeta && typeof repoMeta === 'object') {
          rId = repoMeta.repository || repoMeta.name || '';
        }
        if (!rId.toLowerCase().includes(repositoryFilter.toLowerCase())) {
          continue;
        }
      }

      try {
        const d = new Date(item.created_at);
        if (isNaN(d.getTime())) continue;

        const dateKey = d.toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          timeZone: 'UTC',
        });

        const findingCount = typeof item.finding_count === 'number'
          ? item.finding_count
          : (Number(item.summary?.total_findings) || 0);

        if (!dayMap.has(dateKey)) {
          dayMap.set(dateKey, {
            date: dateKey,
            timestamp: d.getTime(),
            analyses: 0,
            findings: 0,
          });
        }

        const entry = dayMap.get(dateKey);
        entry.analyses += 1;
        entry.findings += findingCount;
      } catch {
        // ignore parse error
      }
    }

    if (dayMap.size < 2) {
      return { trendData: Array.from(dayMap.values()), isSparseTrend: true };
    }

    const sorted = Array.from(dayMap.values())
      .sort((a, b) => a.timestamp - b.timestamp)
      .map((entry) => ({
        date: entry.date,
        analyses: entry.analyses,
        findings: entry.findings,
      }));

    return { trendData: sorted, isSparseTrend: false };
  }, [recentAnalyses, repositoryFilter]);

  // Top Repositories by Findings
  const topReposByFindings = useMemo(() => {
    return [...repositoriesData]
      .filter((r) => r.finding_count > 0)
      .sort((a, b) => b.finding_count - a.finding_count)
      .slice(0, 4);
  }, [repositoriesData]);

  // Top Repositories by Blocked Analyses
  const topReposByBlocked = useMemo(() => {
    return [...repositoriesData]
      .filter((r) => (r.review_status_distribution?.block || 0) > 0)
      .sort((a, b) => (b.review_status_distribution?.block || 0) - (a.review_status_distribution?.block || 0))
      .slice(0, 4);
  }, [repositoriesData]);

  // Max finding count among vulnerabilities for relative bar visualization
  const maxVulnCount = useMemo(() => {
    if (!vulnerabilitiesData.length) return 1;
    return Math.max(...vulnerabilitiesData.map((v) => v.finding_count || 0), 1);
  }, [vulnerabilitiesData]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* 1. Header & Controls Bar */}
      <div className="cs-breadcrumb-bar">
        <div className="cs-breadcrumb-left" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AnalyticsIcon size={20} color="#6366F1" />
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
              Analytics & Security Intelligence
            </h2>
          </div>
          <span style={{ color: '#CBD5E1' }}>|</span>
          <span style={{ fontSize: '12px', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
            CodeSentinel v1.1.0
          </span>
        </div>

        {/* Action Controls & Navigation */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleManualRefresh}
            disabled={refreshing || loading}
            title="Refresh analytics dataset directly from SQLite"
          >
            ↻ {refreshing ? 'Refreshing...' : 'Refresh Analytics'}
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate('/reviews')}
            title="Go to Security Review workspace"
          >
            Security Review →
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate('/repositories')}
            title="Go to Repository Workspace"
          >
            Repositories
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate('/history')}
            title="Go to Analysis History"
          >
            History
          </button>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => navigate('/analyze')}
            title="Run fresh security audit in Analyze Studio"
          >
            Analyze Studio
          </button>
        </div>
      </div>

      {/* 2. Filter Bar */}
      <div
        className="card"
        style={{
          padding: '12px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          backgroundColor: '#FFFFFF',
          border: '1px solid #E2E8F0',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          {/* Time Window Tabs */}
          <div>
            <span
              style={{
                display: 'block',
                fontSize: '11px',
                fontWeight: 600,
                color: '#64748B',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '4px',
              }}
            >
              Time Window Filter
            </span>
            <div style={{ display: 'inline-flex', borderRadius: '6px', border: '1px solid #CBD5E1', overflow: 'hidden' }}>
              {TIME_WINDOWS.map((win) => {
                const isActive = timeWindow === win.value;
                return (
                  <button
                    key={win.value}
                    type="button"
                    style={{
                      padding: '5px 12px',
                      fontSize: '12px',
                      fontWeight: 600,
                      border: 'none',
                      backgroundColor: isActive ? '#0F172A' : '#FFFFFF',
                      color: isActive ? '#FFFFFF' : '#475569',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                    }}
                    onClick={() => handleTimeWindowChange(win.value)}
                  >
                    {win.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Repository Selector Filter */}
          {repositoriesData.length > 0 && (
            <div>
              <span
                style={{
                  display: 'block',
                  fontSize: '11px',
                  fontWeight: 600,
                  color: '#64748B',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  marginBottom: '4px',
                }}
              >
                Repository Filter
              </span>
              <select
                className="cs-select"
                value={repositoryFilter}
                onChange={(e) => handleRepoFilterChange(e.target.value)}
                style={{ minWidth: '220px', fontSize: '12.5px' }}
                aria-label="Filter analytics by repository"
              >
                <option value="">All Repositories ({totalRepositories})</option>
                {repositoriesData.map((r) => (
                  <option key={r.repository_id} value={r.repository_id}>
                    {r.repository_id} ({r.analysis_count} scans, {r.finding_count} findings)
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {/* Active Filter Indication */}
        <div style={{ fontSize: '12px', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
          Scope:{' '}
          <strong style={{ color: '#0F172A' }}>
            {repositoryFilter ? repositoryFilter : 'Global (All Repositories)'}
          </strong>{' '}
          · Window:{' '}
          <strong style={{ color: '#0F172A' }}>
            {TIME_WINDOWS.find((w) => w.value === timeWindow)?.label || timeWindow}
          </strong>
        </div>
      </div>

      {/* 3. Error Banner */}
      {error && (
        <div
          style={{
            padding: '14px 18px',
            backgroundColor: '#FEF2F2',
            border: '1px solid #FECACA',
            borderRadius: '8px',
            color: '#B91C1C',
            fontSize: '13px',
          }}
        >
          <strong>Analytics Loading Error:</strong> {error}
        </div>
      )}

      {/* 4. Loading State */}
      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: '60px 24px' }}>
          <div style={{ fontSize: '28px', marginBottom: '12px' }}>📊</div>
          <div style={{ color: '#0F172A', fontWeight: 600, fontSize: '15px', marginBottom: '6px' }}>
            Aggregating Security Analytics...
          </div>
          <div style={{ color: '#64748B', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
            Querying persistent analysis storage, severity metrics, and repository risk distributions
          </div>
        </div>
      )}

      {/* 5. Loaded Analytics Workspace */}
      {!loading && (
        <>
          {/* Section A: 6 Key Overview Metric Cards */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '14px',
            }}
          >
            {/* Repositories */}
            <div
              className="card cs-metric-card cs-metric-card-interactive"
              style={{ padding: '16px', borderLeft: '4px solid #6366F1' }}
              onClick={() => navigate('/repositories')}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigate('/repositories');
                }
              }}
              role="button"
              tabIndex={0}
              title="Navigate to Repositories"
              aria-label={`Repositories: ${totalRepositories} scanned & active`}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>
                  Repositories
                </span>
                <RepositoriesIcon size={16} color="#6366F1" />
              </div>
              <div style={{ fontSize: '26px', fontWeight: 800, color: '#0F172A', margin: '6px 0 2px' }}>
                {totalRepositories}
              </div>
              <span style={{ fontSize: '11px', color: '#64748B' }}>Scanned & active</span>
            </div>

            {/* Total Analyses */}
            <div
              className="card cs-metric-card cs-metric-card-interactive"
              style={{ padding: '16px', borderLeft: '4px solid #3B82F6' }}
              onClick={() => navigate('/history')}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigate('/history');
                }
              }}
              role="button"
              tabIndex={0}
              title="Navigate to Analysis History"
              aria-label={`Total Analyses: ${totalAnalyses} persistent scan runs`}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>
                  Total Analyses
                </span>
                <AnalyzeIcon size={16} color="#3B82F6" />
              </div>
              <div style={{ fontSize: '26px', fontWeight: 800, color: '#0F172A', margin: '6px 0 2px' }}>
                {totalAnalyses}
              </div>
              <span style={{ fontSize: '11px', color: '#64748B' }}>Persistent scan runs</span>
            </div>

            {/* Total Findings */}
            <div
              className="card cs-metric-card cs-metric-card-interactive"
              style={{ padding: '16px', borderLeft: '4px solid #F59E0B' }}
              onClick={() => navigate('/reviews')}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigate('/reviews');
                }
              }}
              role="button"
              tabIndex={0}
              title="Navigate to Security Review"
              aria-label={`Total Findings: ${totalFindings} detected vulnerabilities`}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>
                  Total Findings
                </span>
                <VulnerabilitiesIcon size={16} color="#F59E0B" />
              </div>
              <div style={{ fontSize: '26px', fontWeight: 800, color: totalFindings > 0 ? '#EF4444' : '#10B981', margin: '6px 0 2px' }}>
                {totalFindings}
              </div>
              <span style={{ fontSize: '11px', color: '#64748B' }}>Detected vulnerabilities</span>
            </div>

            {/* Blocked Analyses */}
            <div
              className="card cs-metric-card cs-metric-card-interactive"
              style={{ padding: '16px', borderLeft: '4px solid #EF4444' }}
              onClick={() => navigate('/history')}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigate('/history');
                }
              }}
              role="button"
              tabIndex={0}
              title="Inspect blocked scans in history"
              aria-label={`Blocked Gates: ${blockedCount} scans`}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>
                  Blocked Gates
                </span>
                <ShieldAlertIcon size={16} color="#EF4444" />
              </div>
              <div style={{ fontSize: '26px', fontWeight: 800, color: blockedCount > 0 ? '#EF4444' : '#10B981', margin: '6px 0 2px' }}>
                {blockedCount}
              </div>
              <span style={{ fontSize: '11px', color: '#64748B' }}>
                {totalAnalyses > 0 ? `${Math.round((blockedCount / totalAnalyses) * 100)}% of scans` : '0%'}
              </span>
            </div>

            {/* Review Analyses */}
            <div
              className="card cs-metric-card"
              style={{ padding: '16px', borderLeft: '4px solid #F59E0B' }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>
                  Review Gates
                </span>
                <ReviewsIcon size={16} color="#F59E0B" />
              </div>
              <div style={{ fontSize: '26px', fontWeight: 800, color: '#F59E0B', margin: '6px 0 2px' }}>
                {reviewCount}
              </div>
              <span style={{ fontSize: '11px', color: '#64748B' }}>
                {totalAnalyses > 0 ? `${Math.round((reviewCount / totalAnalyses) * 100)}% of scans` : '0%'}
              </span>
            </div>

            {/* Allowed Analyses */}
            <div
              className="card cs-metric-card"
              style={{ padding: '16px', borderLeft: '4px solid #10B981' }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>
                  Allowed Gates
                </span>
                <span style={{ color: '#10B981', fontSize: '14px', fontWeight: 700 }}>✓</span>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 800, color: '#10B981', margin: '6px 0 2px' }}>
                {allowCount}
              </div>
              <span style={{ fontSize: '11px', color: '#64748B' }}>
                {totalAnalyses > 0 ? `${Math.round((allowCount / totalAnalyses) * 100)}% of scans` : '0%'}
              </span>
            </div>
          </div>

          {/* Section B: 3 Analytics Visualizations (Severity Distribution, Gate Distribution, Trend) */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 290px), 1fr))',
              gap: '16px',
            }}
          >
            {/* 1. Severity Distribution Card */}
            <div className="card cs-analytics-card" style={{ padding: '20px' }}>
              <div className="cs-analytics-card-header" style={{ marginBottom: '14px' }}>
                <h3 className="cs-analytics-card-title">Finding Severity Breakdown</h3>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                  Total: {totalFindings}
                </span>
              </div>

              {totalFindings === 0 ? (
                <div style={{ textAlign: 'center', padding: '36px 12px', color: '#94A3B8' }}>
                  <div style={{ fontSize: '28px', marginBottom: '8px' }}>🛡️</div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>No Findings Reported</div>
                  <div style={{ fontSize: '12px' }}>Zero security vulnerabilities in this scope.</div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ height: '170px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Tooltip
                          content={({ active, payload }) => {
                            if (active && payload && payload.length) {
                              const item = payload[0];
                              const pct = totalFindings > 0 ? Math.round((item.value / totalFindings) * 100) : 0;
                              return (
                                <div className="cs-chart-tooltip">
                                  <span className="cs-tooltip-swatch" style={{ background: item.payload.color }} />
                                  <span className="cs-tooltip-label">{item.name}:</span>
                                  <span className="cs-tooltip-val">{item.value} ({pct}%)</span>
                                </div>
                              );
                            }
                            return null;
                          }}
                        />
                        <Pie
                          data={severityChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={48}
                          outerRadius={70}
                          paddingAngle={3}
                          dataKey="value"
                          strokeWidth={0}
                        >
                          {severityChartData.map((entry, idx) => (
                            <Cell key={`sev-cell-${idx}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Textual Distribution Bar */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', fontSize: '12px', borderTop: '1px solid #F1F5F9', paddingTop: '10px' }}>
                    <span style={{ color: SEVERITY_COLORS.critical }}>
                      <strong>{severities.critical}</strong> Critical
                    </span>
                    <span style={{ color: SEVERITY_COLORS.high }}>
                      <strong>{severities.high}</strong> High
                    </span>
                    <span style={{ color: SEVERITY_COLORS.medium }}>
                      <strong>{severities.medium}</strong> Medium
                    </span>
                    <span style={{ color: SEVERITY_COLORS.low }}>
                      <strong>{severities.low}</strong> Low
                    </span>
                    <span style={{ color: SEVERITY_COLORS.info }}>
                      <strong>{severities.info}</strong> Info
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* 2. Security Gate Distribution Card */}
            <div className="card cs-analytics-card" style={{ padding: '20px' }}>
              <div className="cs-analytics-card-header" style={{ marginBottom: '14px' }}>
                <h3 className="cs-analytics-card-title">Security Gate Verdicts</h3>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                  Total: {totalAnalyses} Scans
                </span>
              </div>

              {totalAnalyses === 0 ? (
                <div style={{ textAlign: 'center', padding: '36px 12px', color: '#94A3B8' }}>
                  <div style={{ fontSize: '28px', marginBottom: '8px' }}>🔍</div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>No Analyses Performed</div>
                  <div style={{ fontSize: '12px' }}>Run a scan in Analyze Studio to generate gate data.</div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ height: '170px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Tooltip
                          content={({ active, payload }) => {
                            if (active && payload && payload.length) {
                              const item = payload[0];
                              const pct = totalAnalyses > 0 ? Math.round((item.value / totalAnalyses) * 100) : 0;
                              return (
                                <div className="cs-chart-tooltip">
                                  <span className="cs-tooltip-swatch" style={{ background: item.payload.color }} />
                                  <span className="cs-tooltip-label">{item.name}:</span>
                                  <span className="cs-tooltip-val">{item.value} ({pct}%)</span>
                                </div>
                              );
                            }
                            return null;
                          }}
                        />
                        <Pie
                          data={gateChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={48}
                          outerRadius={70}
                          paddingAngle={3}
                          dataKey="value"
                          strokeWidth={0}
                        >
                          {gateChartData.map((entry, idx) => (
                            <Cell key={`gate-cell-${idx}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Gate counts breakdown */}
                  <div style={{ display: 'flex', justifyContent: 'space-around', fontSize: '12px', borderTop: '1px solid #F1F5F9', paddingTop: '10px' }}>
                    <span style={{ color: GATE_COLORS.block, fontWeight: 600 }}>
                      BLOCK: {blockedCount}
                    </span>
                    <span style={{ color: GATE_COLORS.review, fontWeight: 600 }}>
                      REVIEW: {reviewCount}
                    </span>
                    <span style={{ color: GATE_COLORS.allow, fontWeight: 600 }}>
                      ALLOW: {allowCount}
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* 3. Analysis & Finding Activity Trend */}
            <div className="card cs-analytics-card" style={{ padding: '20px' }}>
              <div className="cs-analytics-card-header" style={{ marginBottom: '14px' }}>
                <h3 className="cs-analytics-card-title">Activity Trend Over Time</h3>
                <div style={{ display: 'flex', gap: '8px', fontSize: '11px' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#6366F1' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '2px', backgroundColor: '#6366F1' }} />
                    Analyses
                  </span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#F59E0B' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#F59E0B' }} />
                    Findings
                  </span>
                </div>
              </div>

              {isSparseTrend ? (
                <div
                  style={{
                    padding: '28px 14px',
                    textAlign: 'center',
                    backgroundColor: '#F8FAFC',
                    borderRadius: '6px',
                    border: '1px dashed #CBD5E1',
                    height: '170px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'center',
                    alignItems: 'center',
                  }}
                >
                  <span style={{ fontSize: '24px', marginBottom: '6px' }}>📈</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
                    Sparse Historical Trend
                  </div>
                  <p style={{ fontSize: '12px', color: '#64748B', maxWidth: '300px', margin: '4px 0 0', lineHeight: 1.4 }}>
                    Fewer than 2 distinct calendar days of scan history are recorded. As additional scans are performed across days, a continuous trend curve will emerge.
                  </p>
                </div>
              ) : (
                <div style={{ height: '170px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <ComposedChart data={trendData} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
                      <XAxis dataKey="date" tickLine={false} axisLine={{ stroke: '#E2E8F0' }} tick={{ fill: '#64748B', fontSize: 10 }} />
                      <YAxis tickLine={false} axisLine={false} tick={{ fill: '#94A3B8', fontSize: 10 }} />
                      <Tooltip />
                      <Bar dataKey="analyses" fill="#6366F1" radius={[3, 3, 0, 0]} maxBarSize={28} />
                      <Line type="monotone" dataKey="findings" stroke="#F59E0B" strokeWidth={2.5} dot={{ r: 3, fill: '#F59E0B' }} />
                    </ComposedChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>

          {/* Section C: Risk Rankings & Vulnerability Category Intelligence */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))',
              gap: '16px',
            }}
          >
            {/* Dominant Vulnerability Categories (From GET /analytics/vulnerabilities) */}
            <div className="card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
                    Dominant Vulnerability Categories
                  </h3>
                  <span style={{ fontSize: '11.5px', color: '#64748B' }}>
                    Ranked by frequency and risk severity
                  </span>
                </div>
                <span style={{ fontSize: '11.5px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                  {vulnerabilitiesData.length} categories
                </span>
              </div>

              {vulnerabilitiesData.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '36px 16px', color: '#94A3B8' }}>
                  <div style={{ fontSize: '24px', marginBottom: '6px' }}>🛡️</div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>No Category Intelligence</div>
                  <div style={{ fontSize: '12px' }}>No vulnerabilities detected in this filter scope.</div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {vulnerabilitiesData.slice(0, 7).map((item, idx) => {
                    const pct = Math.round(((item.finding_count || 0) / maxVulnCount) * 100);
                    return (
                      <div
                        key={item.category || idx}
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '4px',
                          padding: '8px 10px',
                          backgroundColor: '#F8FAFC',
                          borderRadius: '6px',
                          border: '1px solid #E2E8F0',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>
                            {item.category}
                          </span>
                          <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#4F46E5' }}>
                            {item.finding_count} findings
                          </span>
                        </div>

                        {/* Relative bar */}
                        <div style={{ width: '100%', height: '6px', backgroundColor: '#E2E8F0', borderRadius: '3px', overflow: 'hidden' }}>
                          <div
                            style={{
                              width: `${pct}%`,
                              height: '100%',
                              backgroundColor: (item.critical_count || 0) > 0 ? '#EF4444' : (item.high_count || 0) > 0 ? '#F97316' : '#6366F1',
                              borderRadius: '3px',
                            }}
                          />
                        </div>

                        {/* Sub-counts */}
                        <div style={{ display: 'flex', gap: '8px', fontSize: '11px', color: '#64748B' }}>
                          {item.critical_count > 0 && <span style={{ color: '#EF4444', fontWeight: 600 }}>{item.critical_count} Critical</span>}
                          {item.high_count > 0 && <span style={{ color: '#F97316', fontWeight: 600 }}>{item.high_count} High</span>}
                          {item.medium_count > 0 && <span style={{ color: '#F59E0B' }}>{item.medium_count} Medium</span>}
                          {item.low_count > 0 && <span style={{ color: '#06B6D4' }}>{item.low_count} Low</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Top Risk Repositories (Ranked by findings and blocked analyses) */}
            <div className="card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
                    Repository Risk Intelligence
                  </h3>
                  <span style={{ fontSize: '11.5px', color: '#64748B' }}>
                    Repositories requiring review attention
                  </span>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate('/repositories')}
                  style={{ fontSize: '11px' }}
                >
                  Workspace →
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {/* 1. Most Security Findings */}
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
                    Top Repositories by Findings
                  </div>
                  {topReposByFindings.length === 0 ? (
                    <div style={{ fontSize: '12px', color: '#94A3B8', fontStyle: 'italic' }}>
                      No repositories with security findings in this scope.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {topReposByFindings.map((r) => (
                        <div
                          key={r.repository_id}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '8px 12px',
                            backgroundColor: '#F8FAFC',
                            borderRadius: '6px',
                            border: '1px solid #E2E8F0',
                            cursor: 'pointer',
                          }}
                          onClick={() => navigate('/repositories', { state: { repo: r.repository_id } })}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              navigate('/repositories', { state: { repo: r.repository_id } });
                            }
                          }}
                          role="button"
                          tabIndex={0}
                          aria-label={`Inspect repository ${r.repository_id}, ${r.finding_count} findings`}
                          title={`Inspect ${r.repository_id}`}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <RepositoriesIcon size={14} color="#6366F1" />
                            <span style={{ fontSize: '12.5px', fontWeight: 600, color: '#0F172A' }}>
                              {r.repository_id}
                            </span>
                          </div>
                          <span
                            style={{
                              fontSize: '12px',
                              fontWeight: 700,
                              fontFamily: 'var(--font-mono)',
                              color: '#EF4444',
                              backgroundColor: '#FEF2F2',
                              padding: '2px 8px',
                              borderRadius: '4px',
                            }}
                          >
                            {r.finding_count} findings
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 2. Most Blocked Analyses */}
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
                    Top Repositories by Blocked Analyses
                  </div>
                  {topReposByBlocked.length === 0 ? (
                    <div style={{ fontSize: '12px', color: '#94A3B8', fontStyle: 'italic' }}>
                      No blocked analyses across monitored repositories.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {topReposByBlocked.map((r) => (
                        <div
                          key={`block-${r.repository_id}`}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '8px 12px',
                            backgroundColor: '#FEF2F2',
                            borderRadius: '6px',
                            border: '1px solid #FECACA',
                            cursor: 'pointer',
                          }}
                          onClick={() => navigate('/repositories', { state: { repo: r.repository_id } })}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              navigate('/repositories', { state: { repo: r.repository_id } });
                            }
                          }}
                          role="button"
                          tabIndex={0}
                          aria-label={`Inspect repository ${r.repository_id}, ${r.review_status_distribution?.block || 0} blocked analyses`}
                          title={`Inspect ${r.repository_id}`}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <ShieldAlertIcon size={14} color="#EF4444" />
                            <span style={{ fontSize: '12.5px', fontWeight: 600, color: '#991B1B' }}>
                              {r.repository_id}
                            </span>
                          </div>
                          <span
                            style={{
                              fontSize: '12px',
                              fontWeight: 700,
                              fontFamily: 'var(--font-mono)',
                              color: '#B91C1C',
                            }}
                          >
                            {r.review_status_distribution?.block || 0} blocked
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Section D: Multi-Repository Security Telemetry Table */}
          <div className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
                  Multi-Repository Security Analytics
                </h3>
                <span style={{ fontSize: '11.5px', color: '#64748B' }}>
                  Aggregated risk metrics per monitored repository identity
                </span>
              </div>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                Showing {repositoriesData.length} repositories
              </span>
            </div>

            {repositoriesData.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '36px 16px', color: '#94A3B8' }}>
                <div style={{ fontSize: '24px', marginBottom: '6px' }}>📁</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>No Repository Analytics Available</div>
                <div style={{ fontSize: '12px' }}>Connect and scan repositories to populate telemetry.</div>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="cs-table" style={{ width: '100%', fontSize: '13px' }}>
                  <thead>
                    <tr>
                      <th scope="col">Repository</th>
                      <th scope="col">Total Scans</th>
                      <th scope="col">Findings</th>
                      <th scope="col">Gate Breakdown (Block / Rev / Allow)</th>
                      <th scope="col">Critical / High</th>
                      <th scope="col">Last Analysis</th>
                      <th scope="col">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {repositoriesData.map((repo) => {
                      const rBlock = repo.review_status_distribution?.block || 0;
                      const rRev = repo.review_status_distribution?.review || 0;
                      const rAllow = repo.review_status_distribution?.allow || 0;

                      return (
                        <tr key={repo.repository_id}>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, color: '#0F172A' }}>
                              <RepositoriesIcon size={14} color="#6366F1" />
                              <span>{repo.repository_id}</span>
                            </div>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{repo.analysis_count}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: repo.finding_count > 0 ? '#EF4444' : '#10B981' }}>
                            {repo.finding_count}
                          </td>
                          <td>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                              <span style={{ color: '#EF4444', fontWeight: 600 }}>{rBlock}</span> /{' '}
                              <span style={{ color: '#F59E0B', fontWeight: 600 }}>{rRev}</span> /{' '}
                              <span style={{ color: '#10B981', fontWeight: 600 }}>{rAllow}</span>
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                            <span style={{ color: '#EF4444', fontWeight: 600 }}>{repo.critical_count || 0}</span> /{' '}
                            <span style={{ color: '#F97316', fontWeight: 600 }}>{repo.high_count || 0}</span>
                          </td>
                          <td style={{ fontSize: '11.5px', color: '#64748B' }}>
                            {repo.last_analysis_timestamp ? new Date(repo.last_analysis_timestamp).toLocaleDateString() : '—'}
                          </td>
                          <td>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => navigate('/repositories', { state: { repo: repo.repository_id } })}
                              style={{ fontSize: '11px', padding: '3px 8px' }}
                              aria-label={`Inspect repository ${repo.repository_id} in workspace`}
                            >
                              Inspect →
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Section E: Developer Security Telemetry & Attribution */}
          <div className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
                  Developer Security Telemetry & Attribution
                </h3>
                <span style={{ fontSize: '11.5px', color: '#64748B' }}>
                  Authoritative security findings and gate decisions aggregated from analysis author records
                </span>
              </div>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                {developerData.length > 0 ? `${developerData.length} attributed developers` : 'Authoritative Attribution Only'}
              </span>
            </div>

            {developerData.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '32px 16px', color: '#94A3B8' }}>
                <div style={{ fontSize: '24px', marginBottom: '6px' }}>👤</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>No Author Attribution Recorded</div>
                <div style={{ fontSize: '12px', maxWidth: '520px', margin: '4px auto 0', lineHeight: 1.4, color: '#64748B' }}>
                  Analyses in this scope do not contain author attribution metadata. When analyses are executed with author or commit metadata, developer-level security telemetry will be reported here.
                </div>
                <div style={{ fontSize: '11px', color: '#94A3B8', marginTop: '6px', fontStyle: 'italic' }}>
                  CodeSentinel strictly reports authoritative data and does not fabricate developer metrics, velocity formulas, or commit counts.
                </div>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="cs-table" style={{ width: '100%', fontSize: '13px' }}>
                  <thead>
                    <tr>
                      <th scope="col">Developer</th>
                      <th scope="col">Total Analyses</th>
                      <th scope="col">Total Findings</th>
                      <th scope="col">Gate Distribution (Block / Rev / Allow)</th>
                      <th scope="col">Critical / High</th>
                      <th scope="col">Associated Repositories</th>
                      <th scope="col">Last Activity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {developerData.map((dev) => (
                      <tr key={dev.developer}>
                        <td style={{ fontWeight: 600, color: '#0F172A' }}>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{dev.developer}</span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{dev.total_analyses}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: dev.total_findings > 0 ? '#EF4444' : '#10B981' }}>
                          {dev.total_findings}
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                            <span style={{ color: '#EF4444', fontWeight: 600 }}>{dev.block_count || 0}</span> /{' '}
                            <span style={{ color: '#F59E0B', fontWeight: 600 }}>{dev.review_count || 0}</span> /{' '}
                            <span style={{ color: '#10B981', fontWeight: 600 }}>{dev.allow_count || 0}</span>
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                          <span style={{ color: '#EF4444', fontWeight: 600 }}>{dev.critical_count || 0}</span> /{' '}
                          <span style={{ color: '#F97316', fontWeight: 600 }}>{dev.high_count || 0}</span>
                        </td>
                        <td style={{ fontSize: '12px', color: '#475569' }}>
                          {Array.isArray(dev.repositories) && dev.repositories.length > 0
                            ? dev.repositories.join(', ')
                            : '—'}
                        </td>
                        <td style={{ fontSize: '11.5px', color: '#64748B' }}>
                          {dev.last_activity ? new Date(dev.last_activity).toLocaleDateString() : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Section F: Recent Security Activity Feed */}
          <div className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
                  Recent Security Activity
                </h3>
                <span style={{ fontSize: '11.5px', color: '#64748B' }}>
                  Latest verified security audits and gate decisions
                </span>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => navigate('/history')}
                style={{ fontSize: '11.5px' }}
              >
                View All History →
              </button>
            </div>

            {recentAnalyses.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '36px 16px', color: '#94A3B8' }}>
                <div style={{ fontSize: '24px', marginBottom: '6px' }}>🛡️</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A' }}>No Recent Audits</div>
                <div style={{ fontSize: '12px' }}>Run a scan in Analyze Studio to initiate an audit trail.</div>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="cs-table" style={{ width: '100%', fontSize: '13px' }}>
                  <thead>
                    <tr>
                      <th>Analysis ID</th>
                      <th>Repository</th>
                      <th>Timestamp (UTC)</th>
                      <th>Findings</th>
                      <th>Gate Verdict</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAnalyses.slice(0, 8).map((item) => {
                      const repoName = item.summary?._repository?.repository ||
                        item.summary?._repository?.name ||
                        item.query ||
                        'Source Inspection';
                      const fCount = item.finding_count ?? item.summary?.total_findings ?? 0;
                      const gate = (item.summary?._review_status || 'ALLOW').toUpperCase();

                      return (
                        <tr key={item.analysis_id}>
                          <td>
                            <code style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#475569' }}>
                              {item.analysis_id}
                            </code>
                          </td>
                          <td style={{ fontWeight: 600, color: '#0F172A' }}>{repoName}</td>
                          <td style={{ fontSize: '11.5px', color: '#64748B' }}>
                            {item.created_at ? new Date(item.created_at).toLocaleString() : '—'}
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: fCount > 0 ? '#EF4444' : '#10B981' }}>
                            {fCount}
                          </td>
                          <td>
                            <StatusBadge status={gate} />
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '6px' }}>
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                onClick={() => navigate(`/history?id=${item.analysis_id}`)}
                                style={{ fontSize: '11px', padding: '3px 8px' }}
                              >
                                Audit →
                              </button>
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                onClick={() => navigate(`/reviews?analysis_id=${item.analysis_id}`)}
                                style={{ fontSize: '11px', padding: '3px 8px', color: '#4F46E5', borderColor: '#C7D2FE' }}
                              >
                                Review →
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
    </div>
  );
}
