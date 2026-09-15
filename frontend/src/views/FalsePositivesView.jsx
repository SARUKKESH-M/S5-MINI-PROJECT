import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getSuppressionAnalytics,
  getAnalyses,
  getAnalysis,
  revokeFalsePositive,
} from '../services/apiClient';
import PageHeader from '../components/common/PageHeader';
import LoadingState from '../components/common/LoadingState';
import EmptyState from '../components/common/EmptyState';
import ErrorState from '../components/common/ErrorState';
import ConfirmDialog from '../components/common/ConfirmDialog';
import StatusBadge from '../components/StatusBadge';
import { useToast } from '../components/common/ToastContext';
import {
  FalsePositivesIcon,
  ReviewsIcon,
  CodeFileIcon,
  RepositoriesIcon,
} from '../components/dashboard/Icons';

/**
 * Sanitize error message to prevent exposure of filesystem paths or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred during operation.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

/**
 * Format ISO datetime string to human-readable date.
 */
function formatDate(isoString) {
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

const REASON_LABELS = {
  FALSE_POSITIVE: 'False Positive (Scanner Artifact)',
  ACCEPTED_RISK: 'Accepted Risk (Approved by Security Team)',
  TEST_OR_MOCK: 'Test or Mock Code (Test Fixture)',
  EXTERNAL_SANITIZATION: 'External Sanitization (Upstream Guard)',
  OTHER: 'Other Justification',
};

const SEVERITY_WEIGHTS = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export default function FalsePositivesView() {
  const navigate = useNavigate();
  const toast = useToast();

  // State: Loading / Refresh / Error
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Authoritative Data
  const [suppressionTelemetry, setSuppressionTelemetry] = useState(null);
  const [suppressionItems, setSuppressionItems] = useState([]);

  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL' | 'ACTIVE' | 'EXPIRED' | 'REVOKED'
  const [repositoryFilter, setRepositoryFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [reasonFilter, setReasonFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('created-desc');

  // Inspection & Revocation Modals
  const [inspectingItem, setInspectingItem] = useState(null);
  const [revokingItem, setRevokingItem] = useState(null);
  const [isRevoking, setIsRevoking] = useState(false);

  // Refs for modal focus & duplicate guards
  const isRefreshingRef = useRef(false);
  const isSubmittingRef = useRef(false);
  const detailCloseBtnRef = useRef(null);
  const previousFocusRef = useRef(null);

  /**
   * Load authoritative suppression analytics and records.
   */
  const loadSuppressionData = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      if (isRefreshingRef.current) return;
      isRefreshingRef.current = true;
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      // 1. Fetch suppression telemetry summary
      const [suppRes, analysesRes] = await Promise.allSettled([
        getSuppressionAnalytics({ timeWindow: 'all' }),
        getAnalyses({ limit: 50, offset: 0 }),
      ]);

      if (suppRes.status === 'fulfilled' && suppRes.value) {
        setSuppressionTelemetry(suppRes.value.data || suppRes.value);
      } else {
        setSuppressionTelemetry(null);
      }

      let analyses = [];
      if (analysesRes.status === 'fulfilled' && analysesRes.value && Array.isArray(analysesRes.value.analyses)) {
        analyses = analysesRes.value.analyses;
      }

      // 2. Fetch full analyses to extract findings with feedback/suppression records
      const fullAnalysesPromises = analyses.map(async (a) => {
        try {
          const detail = await getAnalysis(a.analysis_id);
          const fullRecord = detail.analysis || detail;
          const rawFindings = Array.isArray(fullRecord?.findings) ? fullRecord.findings : [];
          const repoMeta = fullRecord?.repository || fullRecord?.summary?._repository || a.repository;
          let repoName = 'SARUKKESH-M/S5-MINI-PROJECT';
          if (typeof repoMeta === 'string') repoName = repoMeta;
          else if (repoMeta && typeof repoMeta === 'object') {
            const owner = repoMeta.owner || '';
            const rName = repoMeta.repository || repoMeta.name || '';
            repoName = owner && rName ? `${owner}/${rName}` : (rName || owner || repoName);
          }

          // Filter to findings that have suppression info or is_false_positive
          const suppressedFindings = rawFindings.filter((f) => Boolean(f.feedback) || Boolean(f.is_false_positive));

          return suppressedFindings.map((f, idx) => {
            const fb = f.feedback || {};
            const rawStatus = String(fb.status || (f.is_false_positive ? 'ACTIVE' : 'REVOKED')).toUpperCase();
            let effectiveStatus = rawStatus;
            if (rawStatus === 'ACTIVE') {
              if (fb.is_expired) {
                effectiveStatus = 'EXPIRED';
              } else if (fb.expires_at) {
                const expDate = new Date(fb.expires_at).getTime();
                if (!isNaN(expDate) && expDate <= Date.now()) {
                  effectiveStatus = 'EXPIRED';
                }
              }
            }

            const firstEv = Array.isArray(f.evidence) && f.evidence.length > 0 ? f.evidence[0] : null;
            const rawPath = f.file_path || f.file || firstEv?.document_id || '—';
            const lineStart = f.line_number ?? f.line ?? firstEv?.line_start ?? null;
            const lineEnd = firstEv?.line_end ?? null;
            const fileLocation = rawPath !== '—'
              ? `${rawPath}${lineStart ? `:${lineStart}${lineEnd && lineEnd !== lineStart ? `-${lineEnd}` : ''}` : ''}`
              : '—';

            return {
              key: `${a.analysis_id}-${f.finding_id || idx}`,
              analysis_id: a.analysis_id,
              finding_id: f.finding_id,
              title: f.title || f.name || 'Security Finding',
              severity: (f.severity || 'Medium').toUpperCase(),
              category: f.category || f.rule_id || 'Security Finding',
              fileLocation,
              repository: repoName,
              branch: fullRecord?.repository?.branch || 'main',
              status: effectiveStatus,
              reason_code: fb.reason_code || 'FALSE_POSITIVE',
              reason: fb.reason || 'No justification note provided.',
              created_at: fb.created_at || a.created_at,
              expires_at: fb.expires_at || null,
              revoked_at: fb.revoked_at || null,
              confidence: f.confidence,
              evidence: f.evidence,
              ast_signal: f.ast_signal || firstEv?.signal_name || null,
              sink_name: firstEv?.sink_name || null,
              scope: firstEv?.scope || firstEv?.function_name || null,
              remediation: f.remediation || f.recommendation || null,
              description: f.description || null,
              is_false_positive: Boolean(f.is_false_positive),
            };
          });
        } catch {
          return [];
        }
      });

      const settledResults = await Promise.all(fullAnalysesPromises);
      const allExtracted = settledResults.flat();
      setSuppressionItems(allExtracted);
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to load false positive records.'));
    } finally {
      setLoading(false);
      setRefreshing(false);
      isRefreshingRef.current = false;
    }
  };

  useEffect(() => {
    loadSuppressionData(false);
  }, []);

  // Keyboard escape listener for Detail Modal
  useEffect(() => {
    if (!inspectingItem) return;

    previousFocusRef.current = document.activeElement;
    const timer = setTimeout(() => {
      detailCloseBtnRef.current?.focus();
    }, 50);

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setInspectingItem(null);
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
  }, [inspectingItem]);

  // Derived unique repositories
  const availableRepositories = useMemo(() => {
    const repos = new Set();
    suppressionItems.forEach((item) => {
      if (item.repository) repos.add(item.repository);
    });
    return Array.from(repos).sort();
  }, [suppressionItems]);

  // Authoritative Overview Metrics
  const metrics = useMemo(() => {
    if (suppressionTelemetry && typeof suppressionTelemetry.total_suppressions === 'number') {
      return {
        total: suppressionTelemetry.total_suppressions,
        active: Number(suppressionTelemetry.active_count) || 0,
        expired: Number(suppressionTelemetry.expired_count) || 0,
        revoked: Number(suppressionTelemetry.revoked_count) || 0,
      };
    }

    // Fallback counting from loaded records
    const act = suppressionItems.filter((i) => i.status === 'ACTIVE').length;
    const exp = suppressionItems.filter((i) => i.status === 'EXPIRED').length;
    const rev = suppressionItems.filter((i) => i.status === 'REVOKED').length;

    return {
      total: suppressionItems.length,
      active: act,
      expired: exp,
      revoked: rev,
    };
  }, [suppressionTelemetry, suppressionItems]);

  // Handle Revoke Action
  const handleConfirmRevoke = async () => {
    if (!revokingItem || isSubmittingRef.current || isRevoking) return;

    isSubmittingRef.current = true;
    setIsRevoking(true);

    try {
      await revokeFalsePositive(revokingItem.analysis_id, revokingItem.finding_id);

      // Close modal
      setRevokingItem(null);
      if (inspectingItem && inspectingItem.finding_id === revokingItem.finding_id) {
        setInspectingItem(null);
      }

      if (toast && typeof toast.success === 'function') {
        toast.success(`Suppression revoked for finding '${revokingItem.title}'. Finding re-enters security review.`);
      }

      // Refresh authoritative telemetry
      await loadSuppressionData(false);
    } catch (err) {
      const errClean = sanitizeErrorMessage(err.message || 'Failed to revoke suppression.');
      if (toast && typeof toast.error === 'function') {
        toast.error(errClean);
      } else {
        alert(errClean);
      }
    } finally {
      isSubmittingRef.current = false;
      setIsRevoking(false);
    }
  };

  // Client-side Filtered and Sorted Records
  const filteredAndSortedItems = useMemo(() => {
    let list = [...suppressionItems];

    // 1. Status Filter
    if (statusFilter !== 'ALL') {
      list = list.filter((i) => i.status === statusFilter);
    }

    // 2. Repository Filter
    if (repositoryFilter !== 'ALL') {
      list = list.filter((i) => i.repository === repositoryFilter);
    }

    // 3. Severity Filter
    if (severityFilter !== 'ALL') {
      list = list.filter((i) => i.severity === severityFilter);
    }

    // 4. Reason Filter
    if (reasonFilter !== 'ALL') {
      list = list.filter((i) => i.reason_code === reasonFilter);
    }

    // 5. Search Query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter((i) => {
        const title = (i.title || '').toLowerCase();
        const fId = (i.finding_id || '').toLowerCase();
        const cat = (i.category || '').toLowerCase();
        const repo = (i.repository || '').toLowerCase();
        const reason = (i.reason || '').toLowerCase();
        const rCode = (i.reason_code || '').toLowerCase();
        const aId = (i.analysis_id || '').toLowerCase();
        return (
          title.includes(q) ||
          fId.includes(q) ||
          cat.includes(q) ||
          repo.includes(q) ||
          reason.includes(q) ||
          rCode.includes(q) ||
          aId.includes(q)
        );
      });
    }

    // 6. Deterministic Sorting
    list.sort((a, b) => {
      if (sortBy === 'created-desc') {
        const dA = new Date(a.created_at || 0).getTime();
        const dB = new Date(b.created_at || 0).getTime();
        return dB - dA;
      }
      if (sortBy === 'created-asc') {
        const dA = new Date(a.created_at || 0).getTime();
        const dB = new Date(b.created_at || 0).getTime();
        return dA - dB;
      }
      if (sortBy === 'expires-asc') {
        const dA = a.expires_at ? new Date(a.expires_at).getTime() : Infinity;
        const dB = b.expires_at ? new Date(b.expires_at).getTime() : Infinity;
        return dA - dB;
      }
      if (sortBy === 'expires-desc') {
        const dA = a.expires_at ? new Date(a.expires_at).getTime() : -Infinity;
        const dB = b.expires_at ? new Date(b.expires_at).getTime() : -Infinity;
        return dB - dA;
      }
      if (sortBy === 'sev-desc') {
        const wA = SEVERITY_WEIGHTS[a.severity] || 0;
        const wB = SEVERITY_WEIGHTS[b.severity] || 0;
        if (wB !== wA) return wB - wA;
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'sev-asc') {
        const wA = SEVERITY_WEIGHTS[a.severity] || 0;
        const wB = SEVERITY_WEIGHTS[b.severity] || 0;
        if (wA !== wB) return wA - wB;
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'title-asc') {
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'title-desc') {
        return (b.title || '').localeCompare(a.title || '');
      }
      return 0;
    });

    return list;
  }, [suppressionItems, statusFilter, repositoryFilter, severityFilter, reasonFilter, searchQuery, sortBy]);

  const isFiltered = Boolean(
    searchQuery.trim() ||
    statusFilter !== 'ALL' ||
    repositoryFilter !== 'ALL' ||
    severityFilter !== 'ALL' ||
    reasonFilter !== 'ALL'
  );

  const handleResetFilters = () => {
    setSearchQuery('');
    setStatusFilter('ALL');
    setRepositoryFilter('ALL');
    setSeverityFilter('ALL');
    setReasonFilter('ALL');
    setSortBy('created-desc');
  };

  return (
    <div className="cs-false-positives-workspace" style={{ paddingBottom: '32px' }}>
      {/* 1. Page Header */}
      <PageHeader
        title="False Positives"
        description="Audit and manage security findings marked or suppressed according to the CodeSentinel false-positive workflow."
        icon={<FalsePositivesIcon size={22} />}
        primaryAction={
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => loadSuppressionData(true)}
            disabled={loading || refreshing}
            aria-label="Refresh false positive suppressions"
            title="Refresh false positive suppressions"
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
          message="Loading false positive telemetry..."
          subtext="Retrieving authoritative suppression records and reason distributions from CodeSentinel engine."
          minHeight="240px"
        />
      )}

      {/* 3. Error State */}
      {!loading && error && (
        <ErrorState
          title="Unable to Load False Positives"
          error={error}
          onRetry={() => loadSuppressionData(false)}
          retryLabel="Retry Retrieval"
        />
      )}

      {/* 4. Main Content when Data is Loaded */}
      {!loading && !error && (
        <>
          {/* Suppression Overview Metric Cards (4 Cards) */}
          <div
            className="cs-metrics-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '12px',
              marginBottom: '20px',
            }}
          >
            {/* Active Suppressions */}
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
                Active Suppressions
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#10B981', marginTop: '4px' }}>
                {metrics.active}
              </span>
            </div>

            {/* Expired Suppressions */}
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
                Expired
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: '#F59E0B', marginTop: '4px' }}>
                {metrics.expired}
              </span>
            </div>

            {/* Revoked Suppressions */}
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
                Revoked
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.revoked}
              </span>
            </div>

            {/* Total Recorded */}
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
                Total Recorded
              </span>
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                {metrics.total}
              </span>
            </div>
          </div>

          {/* If the backend has genuinely zero suppressions */}
          {suppressionItems.length === 0 && (
            <EmptyState
              icon="🛡️"
              title="No False Positives Recorded"
              description="No findings have been marked as false positive or suppressed yet. Findings can be reviewed and suppressed directly in Security Review."
              actionText="Open Security Review"
              onAction={() => navigate('/reviews')}
              secondaryActionText="View Vulnerabilities"
              onSecondaryAction={() => navigate('/vulnerabilities')}
            />
          )}

          {/* When suppression records exist */}
          {suppressionItems.length > 0 && (
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
                aria-label="False Positive Filters"
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
                      placeholder="Search finding, ID, reason, repository, or analysis..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      aria-label="Search false positives"
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
                    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                    gap: '10px',
                  }}
                >
                  {/* Status Filter */}
                  <div>
                    <label
                      htmlFor="filter-status"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Suppression Status
                    </label>
                    <select
                      id="filter-status"
                      className="form-control"
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Statuses</option>
                      <option value="ACTIVE">Active</option>
                      <option value="EXPIRED">Expired</option>
                      <option value="REVOKED">Revoked</option>
                    </select>
                  </div>

                  {/* Reason / Taxonomy Filter */}
                  <div>
                    <label
                      htmlFor="filter-reason"
                      style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}
                    >
                      Reason / Taxonomy
                    </label>
                    <select
                      id="filter-reason"
                      className="form-control"
                      value={reasonFilter}
                      onChange={(e) => setReasonFilter(e.target.value)}
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px', borderRadius: '4px' }}
                    >
                      <option value="ALL">All Taxonomies</option>
                      <option value="FALSE_POSITIVE">False Positive</option>
                      <option value="ACCEPTED_RISK">Accepted Risk</option>
                      <option value="TEST_OR_MOCK">Test / Mock Code</option>
                      <option value="EXTERNAL_SANITIZATION">External Sanitization</option>
                      <option value="OTHER">Other Justification</option>
                    </select>
                  </div>

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
                      <option value="created-desc">Created: Newest First</option>
                      <option value="created-asc">Created: Oldest First</option>
                      <option value="expires-asc">Expires: Soonest First</option>
                      <option value="expires-desc">Expires: Latest First</option>
                      <option value="sev-desc">Severity: Critical → Info</option>
                      <option value="sev-asc">Severity: Info → Critical</option>
                      <option value="title-asc">Finding: A → Z</option>
                      <option value="title-desc">Finding: Z → A</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Explorer Table */}
              {filteredAndSortedItems.length === 0 ? (
                <EmptyState
                  icon="🔍"
                  title="No Matching False Positives"
                  description="No false-positive records match the current filter criteria or search query."
                  actionText="Reset Filters"
                  onAction={handleResetFilters}
                />
              ) : (
                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
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
                      Showing <strong style={{ color: 'var(--text-primary)' }}>{filteredAndSortedItems.length}</strong> of{' '}
                      <strong>{suppressionItems.length}</strong> suppression records
                    </div>
                  </div>

                  <div className="table-container" style={{ margin: 0, border: 'none' }}>
                    <table className="data-table" aria-label="False Positives Explorer">
                      <thead>
                        <tr>
                          <th scope="col" style={{ width: '100px' }}>Status</th>
                          <th scope="col" style={{ width: '100px' }}>Severity</th>
                          <th scope="col">Finding &amp; ID</th>
                          <th scope="col">Reason / Taxonomy</th>
                          <th scope="col">Repository</th>
                          <th scope="col">Created</th>
                          <th scope="col">Expires</th>
                          <th scope="col" style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAndSortedItems.map((item) => {
                          const isActive = item.status === 'ACTIVE';
                          const isExpired = item.status === 'EXPIRED';
                          const isRevoked = item.status === 'REVOKED';

                          return (
                            <tr
                              key={item.key}
                              style={{ cursor: 'pointer' }}
                              onClick={() => setInspectingItem(item)}
                            >
                              {/* Suppression Status */}
                              <td>
                                {isActive && (
                                  <span
                                    style={{
                                      fontSize: '10.5px',
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: 700,
                                      color: '#059669',
                                      backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(16, 185, 129, 0.25)',
                                    }}
                                  >
                                    ✓ ACTIVE
                                  </span>
                                )}
                                {isExpired && (
                                  <span
                                    style={{
                                      fontSize: '10.5px',
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: 700,
                                      color: '#D97706',
                                      backgroundColor: 'rgba(245, 158, 11, 0.1)',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(245, 158, 11, 0.25)',
                                    }}
                                  >
                                    ⏳ EXPIRED
                                  </span>
                                )}
                                {isRevoked && (
                                  <span
                                    style={{
                                      fontSize: '10.5px',
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: 700,
                                      color: '#64748B',
                                      backgroundColor: 'rgba(100, 116, 139, 0.1)',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(100, 116, 139, 0.25)',
                                    }}
                                  >
                                    ✕ REVOKED
                                  </span>
                                )}
                              </td>

                              {/* Finding Severity */}
                              <td>
                                <StatusBadge status={item.severity} />
                              </td>

                              {/* Finding Title & Finding ID */}
                              <td>
                                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>
                                  {item.title}
                                </div>
                                <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginTop: '2px' }}>
                                  ID: {item.finding_id}
                                </div>
                              </td>

                              {/* Reason / Taxonomy Code */}
                              <td>
                                <span
                                  style={{
                                    display: 'inline-block',
                                    fontSize: '11px',
                                    fontFamily: 'var(--font-mono)',
                                    color: '#4F46E5',
                                    backgroundColor: 'rgba(99, 102, 241, 0.08)',
                                    padding: '2px 6px',
                                    borderRadius: '4px',
                                    border: '1px solid rgba(99, 102, 241, 0.2)',
                                  }}
                                  title={REASON_LABELS[item.reason_code] || item.reason_code}
                                >
                                  {item.reason_code}
                                </span>
                              </td>

                              {/* Repository */}
                              <td>
                                <div style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 500 }}>
                                  {item.repository}
                                </div>
                              </td>

                              {/* Created Date */}
                              <td>
                                <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                                  {formatDate(item.created_at)}
                                </span>
                              </td>

                              {/* Expiration Date */}
                              <td>
                                <span style={{ fontSize: '11.5px', color: item.expires_at ? 'var(--text-muted)' : 'var(--text-dim)' }}>
                                  {item.expires_at ? formatDate(item.expires_at) : 'Never'}
                                </span>
                              </td>

                              {/* Actions */}
                              <td style={{ textAlign: 'right' }}>
                                <div style={{ display: 'inline-flex', gap: '6px' }}>
                                  <button
                                    type="button"
                                    className="btn btn-secondary btn-sm"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setInspectingItem(item);
                                    }}
                                    style={{ fontSize: '11px', padding: '2px 8px' }}
                                    aria-label={`Inspect finding: ${item.title}`}
                                  >
                                    Inspect
                                  </button>
                                  {isActive && (
                                    <button
                                      type="button"
                                      className="btn btn-secondary btn-sm"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setRevokingItem(item);
                                      }}
                                      style={{ fontSize: '11px', padding: '2px 8px', color: '#DC2626', borderColor: 'rgba(239, 68, 68, 0.3)' }}
                                      aria-label={`Revoke suppression for: ${item.title}`}
                                    >
                                      Revoke
                                    </button>
                                  )}
                                </div>
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

      {/* 5. Detail Modal */}
      {inspectingItem && (
        <div
          className="cs-modal-backdrop"
          onClick={() => setInspectingItem(null)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="cs-fp-modal-title"
        >
          <div
            className="cs-modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '640px' }}
          >
            {/* Modal Header */}
            <div className="cs-modal-header">
              <div className="cs-modal-header-left" style={{ gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <h3 id="cs-fp-modal-title" className="cs-modal-title">
                  Suppression Inspection
                </h3>
                <StatusBadge status={inspectingItem.severity} />
                <span
                  style={{
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    color: inspectingItem.status === 'ACTIVE' ? '#059669' : inspectingItem.status === 'EXPIRED' ? '#D97706' : '#64748B',
                    backgroundColor: inspectingItem.status === 'ACTIVE' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    border: '1px solid rgba(100, 116, 139, 0.25)',
                  }}
                >
                  {inspectingItem.status}
                </span>
              </div>
              <button
                ref={detailCloseBtnRef}
                type="button"
                className="cs-modal-close-btn"
                onClick={() => setInspectingItem(null)}
                aria-label="Close suppression details modal"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="cs-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Finding Title & ID */}
              <div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {inspectingItem.title}
                </div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginTop: '2px' }}>
                  Finding ID: <code style={{ color: 'var(--text-muted)' }}>{inspectingItem.finding_id}</code> | Analysis:{' '}
                  <code style={{ color: '#4F46E5' }}>#{String(inspectingItem.analysis_id).slice(0, 8)}</code>
                </div>
              </div>

              {/* Suppression Metadata Box */}
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(99, 102, 241, 0.05)',
                  border: '1px solid rgba(99, 102, 241, 0.2)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#4F46E5', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Authoritative Suppression Feedback
                </div>
                <div style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>
                  <strong>Taxonomy Code:</strong>{' '}
                  <span style={{ fontFamily: 'var(--font-mono)', color: '#4F46E5' }}>{inspectingItem.reason_code}</span> (
                  {REASON_LABELS[inspectingItem.reason_code] || inspectingItem.reason_code})
                </div>
                <div style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>
                  <strong>Justification Note:</strong>
                  <div
                    style={{
                      marginTop: '4px',
                      padding: '8px 10px',
                      backgroundColor: 'var(--bg-card, #FFFFFF)',
                      borderRadius: '4px',
                      border: '1px solid var(--border-subtle)',
                      fontStyle: 'italic',
                      fontSize: '12px',
                      color: 'var(--text-muted)',
                      lineHeight: 1.45,
                    }}
                  >
                    {inspectingItem.reason}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px', flexWrap: 'wrap' }}>
                  <div>
                    <strong>Created:</strong> {formatDate(inspectingItem.created_at)}
                  </div>
                  <div>
                    <strong>Expires:</strong> {inspectingItem.expires_at ? formatDate(inspectingItem.expires_at) : 'Never (Indefinite)'}
                  </div>
                  {inspectingItem.revoked_at && (
                    <div style={{ color: '#DC2626' }}>
                      <strong>Revoked At:</strong> {formatDate(inspectingItem.revoked_at)}
                    </div>
                  )}
                </div>
              </div>

              {/* Location & Repository */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '8px',
                  padding: '8px 12px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                  <CodeFileIcon size={14} color="var(--text-dim)" />
                  <span style={{ color: '#0284C7', fontWeight: 600 }}>{inspectingItem.fileLocation}</span>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Repo: <strong style={{ color: 'var(--text-primary)' }}>{inspectingItem.repository}</strong>
                </div>
              </div>

              {/* AST Evidence */}
              {(inspectingItem.ast_signal || inspectingItem.sink_name || inspectingItem.scope) && (
                <div
                  style={{
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-muted)',
                    backgroundColor: 'var(--bg-surface-elevated)',
                    padding: '10px 14px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    AST Evidence Metadata
                  </div>
                  {inspectingItem.ast_signal && <div>Rule / Signal: {inspectingItem.ast_signal}</div>}
                  {inspectingItem.sink_name && <div>Sink: {inspectingItem.sink_name}</div>}
                  {inspectingItem.scope && <div>Scope: {inspectingItem.scope}</div>}
                </div>
              )}

              {/* Remediation */}
              {inspectingItem.remediation && (
                <div
                  style={{
                    backgroundColor: 'rgba(56, 189, 248, 0.08)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                    borderRadius: '6px',
                    padding: '10px 14px',
                  }}
                >
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#0284C7', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
                    Remediation Guidance
                  </div>
                  <div style={{ fontSize: '12.5px', color: 'var(--text-primary)', lineHeight: 1.45 }}>
                    {inspectingItem.remediation}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="cs-modal-footer">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setInspectingItem(null)}
              >
                Close
              </button>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {inspectingItem.status === 'ACTIVE' && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      const target = inspectingItem;
                      setRevokingItem(target);
                    }}
                    style={{ color: '#DC2626', borderColor: 'rgba(239, 68, 68, 0.3)' }}
                  >
                    Revoke Suppression
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setInspectingItem(null);
                    navigate('/reviews', { state: { analysisId: inspectingItem.analysis_id } });
                  }}
                  style={{ color: '#4F46E5', borderColor: '#C7D2FE' }}
                >
                  Security Review →
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setInspectingItem(null);
                    navigate('/history', { state: { analysisId: inspectingItem.analysis_id } });
                  }}
                >
                  Audit History →
                </button>
                {inspectingItem.repository && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setInspectingItem(null);
                      navigate('/repositories', { state: { repo: inspectingItem.repository } });
                    }}
                  >
                    Repository →
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => {
                    setInspectingItem(null);
                    navigate('/vulnerabilities');
                  }}
                >
                  Vulnerabilities →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 6. Confirm Revocation Dialog */}
      {revokingItem && (
        <ConfirmDialog
          isOpen={Boolean(revokingItem)}
          title="Revoke False Positive Suppression"
          message={`Are you sure you want to revoke the false positive suppression for '${revokingItem.title}' (ID: ${revokingItem.finding_id})? Once revoked, this finding will immediately re-enter active security review and affect security gate evaluations.`}
          confirmLabel="Revoke Suppression"
          cancelLabel="Cancel"
          isDestructive={true}
          isProcessing={isRevoking}
          onConfirm={handleConfirmRevoke}
          onCancel={() => setRevokingItem(null)}
        />
      )}
    </div>
  );
}
