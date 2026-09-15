import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getAnalyticsSummary,
  getVulnerabilityAnalytics,
  getRepositoryAnalytics,
  getAnalyses,
  getAnalysisFindings,
} from '../services/apiClient';
import PageHeader from '../components/common/PageHeader';
import LoadingState from '../components/common/LoadingState';
import EmptyState from '../components/common/EmptyState';
import ErrorState from '../components/common/ErrorState';
import StatusBadge from '../components/StatusBadge';
import FindingPreviewModal from '../components/dashboard/FindingPreviewModal';
import {
  VulnerabilitiesIcon,
  CodeFileIcon,
  RepositoriesIcon,
} from '../components/dashboard/Icons';

/**
 * Sanitize error message to prevent exposure of filesystem paths or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred while loading vulnerabilities.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

/**
 * Extract normalized repository identifier string from metadata.
 */
function getRepoIdentifier(repoMeta) {
  if (!repoMeta) return 'SARUKKESH-M/S5-MINI-PROJECT';
  if (typeof repoMeta === 'string') return repoMeta;
  const owner = repoMeta.owner || '';
  const name = repoMeta.repository || repoMeta.name || '';
  if (owner && name) return `${owner}/${name}`;
  return name || owner || 'SARUKKESH-M/S5-MINI-PROJECT';
}

/**
 * Format ISO datetime string to human-readable date.
 */
function formatAuditDate(isoString) {
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

const SEVERITY_WEIGHTS = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export default function VulnerabilitiesView() {
  const navigate = useNavigate();

  // State: Loading / Error / Data
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Authoritative Backend Data
  const [summaryData, setSummaryData] = useState(null);
  const [findingsList, setFindingsList] = useState([]);
  const [knownCategories, setKnownCategories] = useState([]);
  const [knownRepos, setKnownRepos] = useState([]);

  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [repositoryFilter, setRepositoryFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL' | 'OPEN' | 'SUPPRESSED'
  const [sortBy, setSortBy] = useState('sev-desc');

  // Inspection Modal State
  const [inspectingFinding, setInspectingFinding] = useState(null);

  // Duplicate Refresh Guard Ref
  const isRefreshingRef = useRef(false);

  /**
   * Load authoritative vulnerability data from backend APIs.
   */
  const loadVulnerabilitiesData = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      if (isRefreshingRef.current) return;
      isRefreshingRef.current = true;
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      // 1. Concurrently fetch summary, category aggregations, repo aggregations, and analyses list
      const [summaryRes, vulnAnalyticsRes, repoAnalyticsRes, analysesRes] = await Promise.allSettled([
        getAnalyticsSummary({ timeWindow: 'all' }),
        getVulnerabilityAnalytics({ timeWindow: 'all', limit: 100 }),
        getRepositoryAnalytics({ timeWindow: 'all', limit: 100 }),
        getAnalyses({ limit: 50, offset: 0 }),
      ]);

      // Process summary
      let rawSummary = null;
      if (summaryRes.status === 'fulfilled' && summaryRes.value) {
        rawSummary = summaryRes.value.data || summaryRes.value;
        setSummaryData(rawSummary);
      }

      // Process known categories from analytics
      const categorySet = new Set();
      if (vulnAnalyticsRes.status === 'fulfilled' && Array.isArray(vulnAnalyticsRes.value?.vulnerabilities)) {
        vulnAnalyticsRes.value.vulnerabilities.forEach((v) => {
          if (v.category) categorySet.add(v.category);
        });
      }

      // Process known repos from analytics
      const repoSet = new Set();
      if (repoAnalyticsRes.status === 'fulfilled' && Array.isArray(repoAnalyticsRes.value?.repositories)) {
        repoAnalyticsRes.value.repositories.forEach((r) => {
          const rId = r.repository_id || r.repository;
          if (rId) repoSet.add(rId);
        });
      }

      // Process analyses and extract findings
      let analyses = [];
      if (analysesRes.status === 'fulfilled' && Array.isArray(analysesRes.value?.analyses)) {
        analyses = analysesRes.value.analyses;
      }

      // If we have analyses, fetch findings for analyses that have finding_count > 0 or all recent
      const findingsPromises = analyses.map(async (a) => {
        const repoName = getRepoIdentifier(a.repository || a.summary?._repository);
        repoSet.add(repoName);

        // Fetch findings for this analysis
        try {
          const findingsRes = await getAnalysisFindings(a.analysis_id);
          const rawItems = Array.isArray(findingsRes?.findings) ? findingsRes.findings : [];

          return rawItems.map((f, idx) => {
            const cat = f.category || f.rule_id || 'Security Finding';
            if (cat) categorySet.add(cat);

            const firstEv = Array.isArray(f.evidence) && f.evidence.length > 0 ? f.evidence[0] : null;
            const rawFile = f.file_path || f.file || firstEv?.document_id || '—';
            const lineStart = f.line_number ?? f.line ?? firstEv?.line_start ?? null;
            const lineEnd = firstEv?.line_end ?? null;
            const colStart = f.column ?? firstEv?.column_start ?? null;
            const fileLocation = rawFile !== '—'
              ? `${rawFile}${lineStart ? `:${lineStart}${lineEnd && lineEnd !== lineStart ? `-${lineEnd}` : ''}${colStart ? `:${colStart}` : ''}` : ''}`
              : '—';

            return {
              ...f,
              uniqueRowKey: `${a.analysis_id}-${f.finding_id || idx}`,
              analysis_id: a.analysis_id,
              analysis_created_at: a.created_at,
              repository: repoName,
              branch: a.branch || a.repository?.branch || a.summary?._repository?.branch || 'main',
              fileLocation,
              review_status: a.review_status || a.summary?._review_status || null,
            };
          });
        } catch {
          return [];
        }
      });

      const findingsSettled = await Promise.all(findingsPromises);
      const allExtractedFindings = findingsSettled.flat();

      setFindingsList(allExtractedFindings);
      setKnownCategories(Array.from(categorySet).sort());
      setKnownRepos(Array.from(repoSet).sort());
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to load vulnerabilities.'));
    } finally {
      setLoading(false);
      setRefreshing(false);
      isRefreshingRef.current = false;
    }
  };

  useEffect(() => {
    loadVulnerabilitiesData(false);
  }, []);

  // Compute Authoritative Metric Counts (Real values, legitimate 0 remains 0)
  const metrics = useMemo(() => {
    const severities = summaryData?.severities || {};

    // If summary data exists, use server-aggregated numbers
    if (summaryData && typeof summaryData.total_findings === 'number') {
      return {
        total: summaryData.total_findings,
        critical: Number(severities.critical) || 0,
        high: Number(severities.high) || 0,
        medium: Number(severities.medium) || 0,
        low: Number(severities.low) || 0,
        info: Number(severities.info) || 0,
      };
    }

    // Fallback to counting from loaded findings
    const crit = findingsList.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
    const high = findingsList.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length;
    const med = findingsList.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length;
    const low = findingsList.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;
    const inf = findingsList.filter((f) => (f.severity || '').toUpperCase() === 'INFO').length;

    return {
      total: findingsList.length,
      critical: crit,
      high,
      medium: med,
      low,
      info: inf,
    };
  }, [summaryData, findingsList]);

  // Client-side Filtered and Sorted Findings
  const filteredAndSortedFindings = useMemo(() => {
    let list = [...findingsList];

    // 1. Severity Filter
    if (severityFilter !== 'ALL') {
      list = list.filter((f) => (f.severity || '').toUpperCase() === severityFilter);
    }

    // 2. Category Filter
    if (categoryFilter !== 'ALL') {
      list = list.filter((f) => (f.category || f.rule_id) === categoryFilter);
    }

    // 3. Repository Filter
    if (repositoryFilter !== 'ALL') {
      list = list.filter((f) => f.repository === repositoryFilter);
    }

    // 4. Status Filter
    if (statusFilter === 'OPEN') {
      list = list.filter((f) => !f.is_false_positive);
    } else if (statusFilter === 'SUPPRESSED') {
      list = list.filter((f) => Boolean(f.is_false_positive));
    }

    // 5. Search Query (Client-side fast search across title, id, category, desc, file, repo)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter((f) => {
        const title = (f.title || f.name || '').toLowerCase();
        const fId = (f.finding_id || '').toLowerCase();
        const cat = (f.category || f.rule_id || '').toLowerCase();
        const desc = (f.description || '').toLowerCase();
        const file = (f.fileLocation || f.file_path || '').toLowerCase();
        const repo = (f.repository || '').toLowerCase();
        return (
          title.includes(q) ||
          fId.includes(q) ||
          cat.includes(q) ||
          desc.includes(q) ||
          file.includes(q) ||
          repo.includes(q)
        );
      });
    }

    // 6. Deterministic Sorting
    list.sort((a, b) => {
      if (sortBy === 'sev-desc') {
        const wA = SEVERITY_WEIGHTS[(a.severity || '').toUpperCase()] || 0;
        const wB = SEVERITY_WEIGHTS[(b.severity || '').toUpperCase()] || 0;
        if (wB !== wA) return wB - wA;
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'sev-asc') {
        const wA = SEVERITY_WEIGHTS[(a.severity || '').toUpperCase()] || 0;
        const wB = SEVERITY_WEIGHTS[(b.severity || '').toUpperCase()] || 0;
        if (wA !== wB) return wA - wB;
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'title-asc') {
        return (a.title || a.name || '').localeCompare(b.title || b.name || '');
      }
      if (sortBy === 'title-desc') {
        return (b.title || b.name || '').localeCompare(a.title || a.name || '');
      }
      if (sortBy === 'conf-desc') {
        const cA = typeof a.confidence === 'number' ? a.confidence : 0;
        const cB = typeof b.confidence === 'number' ? b.confidence : 0;
        return cB - cA;
      }
      if (sortBy === 'date-desc') {
        const dA = new Date(a.analysis_created_at || 0).getTime();
        const dB = new Date(b.analysis_created_at || 0).getTime();
        return dB - dA;
      }
      if (sortBy === 'date-asc') {
        const dA = new Date(a.analysis_created_at || 0).getTime();
        const dB = new Date(b.analysis_created_at || 0).getTime();
        return dA - dB;
      }
      return 0;
    });

    return list;
  }, [findingsList, severityFilter, categoryFilter, repositoryFilter, statusFilter, searchQuery, sortBy]);

  // Check if any filter is active
  const isFiltered = Boolean(
    searchQuery.trim() ||
    severityFilter !== 'ALL' ||
    categoryFilter !== 'ALL' ||
    repositoryFilter !== 'ALL' ||
    statusFilter !== 'ALL'
  );

  const handleResetFilters = () => {
    setSearchQuery('');
    setSeverityFilter('ALL');
    setCategoryFilter('ALL');
    setRepositoryFilter('ALL');
    setStatusFilter('ALL');
    setSortBy('sev-desc');
  };

  return (
    <div className="cs-vulnerabilities-workspace" style={{ paddingBottom: '32px' }}>
      {/* 1. Standardized Page Header */}
      <PageHeader
        title="Vulnerabilities"
        description="Consolidated security findings detected by CodeSentinel across monitored repositories and code analyses."
        icon={<VulnerabilitiesIcon size={22} />}
        primaryAction={
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => loadVulnerabilitiesData(true)}
            disabled={loading || refreshing}
            aria-label="Refresh vulnerability findings"
            title="Refresh vulnerability findings"
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
          message="Loading security findings..."
          subtext="Retrieving authoritative vulnerability records and analytics from CodeSentinel engine."
          minHeight="240px"
        />
      )}

      {/* 3. Error State */}
      {!loading && error && (
        <ErrorState
          title="Unable to Load Vulnerabilities"
          error={error}
          onRetry={() => loadVulnerabilitiesData(false)}
          retryLabel="Retry Retrieval"
        />
      )}

      {/* 4. Main Content when Data is Loaded */}
      {!loading && !error && (
        <>
          {/* Security Metric Cards Overview (6 Cards) */}
          <div
            className="cs-metrics-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '12px',
              marginBottom: '20px',
            }}
          >
            {/* Total Findings */}
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
                Total Findings
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.total}
              </span>
            </div>

            {/* Critical */}
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
                Critical
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#EF4444', marginTop: '4px' }}>
                {metrics.critical}
              </span>
            </div>

            {/* High */}
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
                High
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#F97316', marginTop: '4px' }}>
                {metrics.high}
              </span>
            </div>

            {/* Medium */}
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
                Medium
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#F59E0B', marginTop: '4px' }}>
                {metrics.medium}
              </span>
            </div>

            {/* Low */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #06B6D4',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#06B6D4', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Low
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#06B6D4', marginTop: '4px' }}>
                {metrics.low}
              </span>
            </div>

            {/* Info */}
            <div
              className="card"
              style={{
                padding: '16px',
                borderLeft: '4px solid #64748B',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Info
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.info}
              </span>
            </div>
          </div>

          {/* If the backend has genuinely zero findings recorded */}
          {findingsList.length === 0 && (
            <EmptyState
              icon="🛡️"
              title="No Security Findings Recorded"
              description="No vulnerabilities or security findings have been detected yet. Run an analysis on a repository or code snippet to populate this workspace."
              actionText="Open Analysis Studio"
              onAction={() => navigate('/analyze')}
              secondaryActionText="Audit Repositories"
              onSecondaryAction={() => navigate('/repositories')}
            />
          )}

          {/* When findings exist, display Interactive Filter Bar & Findings Table */}
          {findingsList.length > 0 && (
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
                aria-label="Vulnerability Filters"
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
                      placeholder="Search title, ID, category, file, or repository..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      aria-label="Search vulnerability findings"
                      style={{
                        width: '100%',
                        fontSize: '13px',
                        padding: '8px 12px',
                        borderRadius: '6px',
                      }}
                    />
                  </div>

                  {/* Reset Filters Action */}
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
                    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                    gap: '10px',
                  }}
                >
                  {/* Severity Filter */}
                  <div>
                    <label
                      htmlFor="filter-severity"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Severity
                    </label>
                    <select
                      id="filter-severity"
                      className="form-control"
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                      <option value="INFO">Info</option>
                    </select>
                  </div>

                  {/* Category Filter */}
                  <div>
                    <label
                      htmlFor="filter-category"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Category
                    </label>
                    <select
                      id="filter-category"
                      className="form-control"
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Categories ({knownCategories.length})</option>
                      {knownCategories.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Repository Filter */}
                  <div>
                    <label
                      htmlFor="filter-repository"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Repository
                    </label>
                    <select
                      id="filter-repository"
                      className="form-control"
                      value={repositoryFilter}
                      onChange={(e) => setRepositoryFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Repositories ({knownRepos.length})</option>
                      {knownRepos.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Status Filter */}
                  <div>
                    <label
                      htmlFor="filter-status"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Status
                    </label>
                    <select
                      id="filter-status"
                      className="form-control"
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Statuses</option>
                      <option value="OPEN">Open Only</option>
                      <option value="SUPPRESSED">Suppressed (False Positive)</option>
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
                      <option value="sev-desc">Severity: Critical → Info</option>
                      <option value="sev-asc">Severity: Info → Critical</option>
                      <option value="title-asc">Title: A → Z</option>
                      <option value="title-desc">Title: Z → A</option>
                      <option value="conf-desc">Confidence: Highest</option>
                      <option value="date-desc">Date: Newest First</option>
                      <option value="date-asc">Date: Oldest First</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Table / Results Container */}
              {filteredAndSortedFindings.length === 0 ? (
                <EmptyState
                  icon="🔍"
                  title="No Matching Vulnerabilities"
                  description="No vulnerabilities match the current filter criteria or search query. Try broadening your filters or clearing search terms."
                  actionText="Reset Filters"
                  onAction={handleResetFilters}
                />
              ) : (
                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                  {/* Results Count Bar */}
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
                      Showing <strong style={{ color: 'var(--text-primary)' }}>{filteredAndSortedFindings.length}</strong> of{' '}
                      <strong>{findingsList.length}</strong> findings
                    </div>
                  </div>

                  {/* Responsive Data Table */}
                  <div className="table-container" style={{ margin: 0, border: 'none' }}>
                    <table className="data-table" aria-label="Vulnerabilities Explorer">
                      <thead>
                        <tr>
                          <th scope="col" style={{ width: '110px' }}>Severity</th>
                          <th scope="col">Finding &amp; ID</th>
                          <th scope="col">Category</th>
                          <th scope="col">Location</th>
                          <th scope="col">Repository</th>
                          <th scope="col">Analysis</th>
                          <th scope="col" style={{ width: '110px' }}>Status</th>
                          <th scope="col" style={{ width: '90px', textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAndSortedFindings.map((finding) => {
                          const sev = (finding.severity || 'Medium').toUpperCase();
                          const title = finding.title || finding.name || 'Security Finding';
                          const cat = finding.category || finding.rule_id || '—';
                          const isSuppressed = Boolean(finding.is_false_positive);

                          return (
                            <tr
                              key={finding.uniqueRowKey}
                              style={{ cursor: 'pointer' }}
                              onClick={() => setInspectingFinding(finding)}
                            >
                              {/* Severity Badge */}
                              <td>
                                <StatusBadge status={sev} />
                              </td>

                              {/* Finding Title & Finding ID */}
                              <td>
                                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>
                                  {title}
                                </div>
                                {finding.finding_id && (
                                  <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginTop: '2px' }}>
                                    ID: {finding.finding_id}
                                  </div>
                                )}
                              </td>

                              {/* Category */}
                              <td>
                                <span
                                  style={{
                                    display: 'inline-block',
                                    fontSize: '11px',
                                    fontFamily: 'var(--font-mono)',
                                    color: 'var(--text-muted)',
                                    backgroundColor: 'var(--bg-void)',
                                    padding: '2px 6px',
                                    borderRadius: '4px',
                                    border: '1px solid var(--border-subtle)',
                                    maxWidth: '160px',
                                    whiteSpace: 'nowrap',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                  }}
                                  title={cat}
                                >
                                  {cat}
                                </span>
                              </td>

                              {/* File Location */}
                              <td>
                                <div
                                  style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    fontSize: '12px',
                                    fontFamily: 'var(--font-mono)',
                                    color: 'var(--text-muted)',
                                    maxWidth: '180px',
                                    whiteSpace: 'nowrap',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                  }}
                                  title={finding.fileLocation}
                                >
                                  <CodeFileIcon size={13} color="var(--text-dim)" />
                                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {finding.fileLocation}
                                  </span>
                                </div>
                              </td>

                              {/* Repository */}
                              <td>
                                <div
                                  style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    fontSize: '12px',
                                    color: 'var(--text-primary)',
                                    fontWeight: 500,
                                  }}
                                >
                                  <RepositoriesIcon size={13} />
                                  <span
                                    style={{
                                      maxWidth: '150px',
                                      overflow: 'hidden',
                                      textOverflow: 'ellipsis',
                                      whiteSpace: 'nowrap',
                                    }}
                                    title={finding.repository}
                                  >
                                    {finding.repository}
                                  </span>
                                </div>
                              </td>

                              {/* Analysis ID & Audit Date */}
                              <td>
                                <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#4F46E5', fontWeight: 600 }}>
                                  #{finding.analysis_id ? String(finding.analysis_id).slice(0, 8) : '—'}
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>
                                  {formatAuditDate(finding.analysis_created_at)}
                                </div>
                              </td>

                              {/* Status */}
                              <td>
                                {isSuppressed ? (
                                  <span
                                    style={{
                                      fontSize: '10.5px',
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: 700,
                                      color: '#4338CA',
                                      backgroundColor: 'rgba(99, 102, 241, 0.1)',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(99, 102, 241, 0.25)',
                                    }}
                                  >
                                    ✓ SUPPRESSED
                                  </span>
                                ) : (
                                  <span
                                    style={{
                                      fontSize: '10.5px',
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: 700,
                                      color: '#DC2626',
                                      backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(239, 68, 68, 0.25)',
                                    }}
                                  >
                                    ● OPEN
                                  </span>
                                )}
                              </td>

                              {/* Inspect Action */}
                              <td style={{ textAlign: 'right' }}>
                                <button
                                  type="button"
                                  className="btn btn-secondary btn-sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setInspectingFinding(finding);
                                  }}
                                  aria-label={`Inspect finding: ${title}`}
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
        </>
      )}

      {/* 5. Deep Inspection Modal */}
      {inspectingFinding && (
        <FindingPreviewModal
          isOpen={Boolean(inspectingFinding)}
          onClose={() => setInspectingFinding(null)}
          finding={inspectingFinding}
        />
      )}
    </div>
  );
}
