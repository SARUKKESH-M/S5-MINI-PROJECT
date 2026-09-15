import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import {
  getAnalyses,
  getAnalysis,
  markFalsePositive,
  revokeFalsePositive,
} from '../services/apiClient';
import FindingPreviewModal from '../components/dashboard/FindingPreviewModal';
import StatusBadge from '../components/StatusBadge';
import {
  CodeFileIcon,
  RepositoriesIcon,
  AnalyzeIcon,
  ReviewsIcon,
} from '../components/dashboard/Icons';

/**
 * Sanitize error messages to prevent leakage of internal filesystem or token patterns.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred during operation.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

const REASON_CODES = [
  { code: 'FALSE_POSITIVE', label: 'False Positive (Scanner Artifact / Benign Pattern)' },
  { code: 'ACCEPTED_RISK', label: 'Accepted Risk (Known Risk Approved by Security Team)' },
  { code: 'TEST_OR_MOCK', label: 'Test or Mock Code (Test Fixture / Non-Production File)' },
  { code: 'EXTERNAL_SANITIZATION', label: 'External Sanitization (Validated by Upstream Guard)' },
  { code: 'OTHER', label: 'Other Justification (Detailed Explanatory Note Required)' },
];

const EXPIRATION_OPTIONS = [
  { value: '', label: 'Never (Indefinite)' },
  { value: '30d', label: '30 Days' },
  { value: '60d', label: '60 Days' },
  { value: '90d', label: '90 Days' },
  { value: '180d', label: '180 Days' },
];

function computeExpiresAtIso(optionValue) {
  if (!optionValue) return null;
  const days = parseInt(optionValue, 10);
  if (isNaN(days) || days <= 0) return null;
  const now = new Date();
  const future = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
  return future.toISOString();
}

export default function SecurityReviewView() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  // Analyses listing state for switcher
  const [analysesList, setAnalysesList] = useState([]);
  const [listLoading, setListLoading] = useState(false);

  // Selected analysis details state
  const [selectedAnalysisId, setSelectedAnalysisId] = useState(null);
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);

  // Filtering & search state
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL' | 'OPEN' | 'SUPPRESSED'
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('severity-desc');

  // Inspection & Action Modals state
  const [inspectingFinding, setInspectingFinding] = useState(null);
  const [suppressingFinding, setSuppressingFinding] = useState(null);
  const [revokingFinding, setRevokingFinding] = useState(null);

  // Suppression form fields
  const [reasonCode, setReasonCode] = useState('FALSE_POSITIVE');
  const [reasonComment, setReasonComment] = useState('');
  const [expirationOption, setExpirationOption] = useState('');
  const [actionError, setActionError] = useState(null);
  const [actionSubmitting, setActionSubmitting] = useState(false);
  const isSubmittingRef = useRef(false);

  // 1. Fetch recent analyses list for switcher
  const fetchAnalysesList = async () => {
    setListLoading(true);
    try {
      const res = await getAnalyses({ limit: 25, offset: 0 });
      const items = Array.isArray(res.analyses) ? res.analyses : [];
      setAnalysesList(items);
      return items;
    } catch {
      return [];
    } finally {
      setListLoading(false);
    }
  };

  // 2. Fetch specific analysis by ID
  const fetchAnalysis = async (analysisId) => {
    if (!analysisId) return;
    setLoading(true);
    setError(null);
    setErrorStatus(null);
    try {
      const res = await getAnalysis(analysisId);
      const record = res.analysis || res;
      setAnalysisData(record);
      setSelectedAnalysisId(analysisId);
    } catch (err) {
      setErrorStatus(err.status || null);
      setError(sanitizeErrorMessage(err.message || `Analysis '${analysisId}' not found.`));
      setAnalysisData(null);
    } finally {
      setLoading(false);
    }
  };

  // Initial load: parse URL param, navigation state, or fetch newest analysis
  useEffect(() => {
    let isMounted = true;

    async function initialize() {
      const targetId = searchParams.get('analysis_id') || searchParams.get('id') || location.state?.analysisId;
      const list = await fetchAnalysesList();

      if (!isMounted) return;

      if (targetId) {
        fetchAnalysis(targetId);
      } else if (list.length > 0) {
        const newestId = list[0].analysis_id;
        setSearchParams({ analysis_id: newestId }, { replace: true });
        fetchAnalysis(newestId);
      } else {
        setLoading(false);
      }
    }

    initialize();

    return () => {
      isMounted = false;
    };
  }, []);

  // Handle URL change
  useEffect(() => {
    const targetId = searchParams.get('analysis_id') || searchParams.get('id');
    if (targetId && targetId !== selectedAnalysisId) {
      fetchAnalysis(targetId);
    }
  }, [searchParams]);

  // Keyboard escape listener for suppress & revoke modals
  useEffect(() => {
    if (!suppressingFinding && !revokingFinding) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && !actionSubmitting) {
        if (suppressingFinding) handleCloseSuppressModal();
        if (revokingFinding) handleCloseRevokeModal();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [suppressingFinding, revokingFinding, actionSubmitting]);

  // Switch analysis
  const handleSelectAnalysis = (newId) => {
    if (!newId || newId === selectedAnalysisId) return;
    setSearchParams({ analysis_id: newId });
    setSearchQuery('');
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setCategoryFilter('ALL');
  };

  // Refresh current analysis
  const handleRefresh = () => {
    if (selectedAnalysisId) {
      fetchAnalysis(selectedAnalysisId);
      fetchAnalysesList();
    }
  };

  // Authoritative extraction
  const summary = analysisData?.summary || {};
  const rawFindings = Array.isArray(analysisData?.findings) ? analysisData.findings : [];

  // Authoritative Step 6O Security Gate
  const authoritativeGate = analysisData?.review_status || summary._review_status || (
    (summary.critical_count > 0 || summary.high_count > 0) ? 'BLOCK' :
    (summary.medium_count > 0) ? 'REVIEW' : 'ALLOW'
  );

  // Authoritative counts
  const totalFindings = rawFindings.length;
  const suppressedCount = rawFindings.filter((f) => Boolean(f.is_false_positive)).length;
  const openCount = totalFindings - suppressedCount;

  const critCount = rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const medCount = rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;
  const infoCount = rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'INFO').length;

  // Available unique categories
  const availableCategories = useMemo(() => {
    const cats = new Set();
    rawFindings.forEach((f) => {
      const c = f.category || f.rule_id;
      if (c) cats.add(c);
    });
    return Array.from(cats).sort();
  }, [rawFindings]);

  // Available unique files
  const availableFiles = useMemo(() => {
    const files = new Set();
    rawFindings.forEach((f) => {
      const doc = f.file_path || f.file || f.evidence?.[0]?.document_id;
      if (doc) files.add(doc);
    });
    return Array.from(files).sort();
  }, [rawFindings]);

  // Client-side Filtered & Sorted Findings
  const filteredFindings = useMemo(() => {
    let result = [...rawFindings];

    // Status Filter (Open vs Suppressed)
    if (statusFilter === 'OPEN') {
      result = result.filter((f) => !f.is_false_positive);
    } else if (statusFilter === 'SUPPRESSED') {
      result = result.filter((f) => Boolean(f.is_false_positive));
    }

    // Severity Filter
    if (severityFilter !== 'ALL') {
      result = result.filter(
        (f) => (f.severity || '').toUpperCase() === severityFilter
      );
    }

    // Category Filter
    if (categoryFilter !== 'ALL') {
      result = result.filter((f) => (f.category || f.rule_id) === categoryFilter);
    }

    // Search Query (Client-side, 0 requests while typing)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter((f) => {
        const title = (f.title || f.name || '').toLowerCase();
        const fId = (f.finding_id || '').toLowerCase();
        const cat = (f.category || f.rule_id || '').toLowerCase();
        const desc = (f.description || '').toLowerCase();
        const docId = (f.file_path || f.file || f.evidence?.[0]?.document_id || '').toLowerCase();
        const reason = (f.feedback?.reason || '').toLowerCase();
        const rCode = (f.feedback?.reason_code || '').toLowerCase();
        return (
          title.includes(q) ||
          fId.includes(q) ||
          cat.includes(q) ||
          desc.includes(q) ||
          docId.includes(q) ||
          reason.includes(q) ||
          rCode.includes(q)
        );
      });
    }

    // Sorting
    const sevRank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    result.sort((a, b) => {
      if (sortBy === 'severity-desc') {
        const rankA = sevRank[(a.severity || '').toUpperCase()] || 0;
        const rankB = sevRank[(b.severity || '').toUpperCase()] || 0;
        if (rankB !== rankA) return rankB - rankA;
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'severity-asc') {
        const rankA = sevRank[(a.severity || '').toUpperCase()] || 0;
        const rankB = sevRank[(b.severity || '').toUpperCase()] || 0;
        if (rankA !== rankB) return rankA - rankB;
        return (a.title || '').localeCompare(b.title || '');
      }
      if (sortBy === 'file-asc') {
        const fileA = a.file_path || a.file || a.evidence?.[0]?.document_id || '';
        const fileB = b.file_path || b.file || b.evidence?.[0]?.document_id || '';
        const cmp = fileA.localeCompare(fileB);
        if (cmp !== 0) return cmp;
        const lineA = a.line_number ?? a.line ?? a.evidence?.[0]?.line_start ?? 0;
        const lineB = b.line_number ?? b.line ?? b.evidence?.[0]?.line_start ?? 0;
        return lineA - lineB;
      }
      if (sortBy === 'status-open-first') {
        const statA = a.is_false_positive ? 1 : 0;
        const statB = b.is_false_positive ? 1 : 0;
        if (statA !== statB) return statA - statB;
        return (b.severity || '').localeCompare(a.severity || '');
      }
      if (sortBy === 'title-asc') {
        return (a.title || a.name || '').localeCompare(b.title || b.name || '');
      }
      return 0;
    });

    return result;
  }, [rawFindings, statusFilter, severityFilter, categoryFilter, searchQuery, sortBy]);

  const isFiltered = Boolean(
    searchQuery.trim() ||
    severityFilter !== 'ALL' ||
    statusFilter !== 'ALL' ||
    categoryFilter !== 'ALL'
  );

  const handleResetFilters = () => {
    setSearchQuery('');
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setCategoryFilter('ALL');
    setSortBy('severity-desc');
  };

  const suppressTriggerRef = useRef(null);
  const revokeTriggerRef = useRef(null);

  // Escape key handler for active modals
  useEffect(() => {
    if (!suppressingFinding && !revokingFinding) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && !actionSubmitting) {
        e.preventDefault();
        if (suppressingFinding) handleCloseSuppressModal();
        if (revokingFinding) handleCloseRevokeModal();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [suppressingFinding, revokingFinding, actionSubmitting]);

  // Open Suppression Modal
  const handleOpenSuppressModal = (finding, e) => {
    if (e) e.stopPropagation();
    suppressTriggerRef.current = e?.currentTarget || document.activeElement;
    setSuppressingFinding(finding);
    setReasonCode('FALSE_POSITIVE');
    setReasonComment('');
    setExpirationOption('');
    setActionError(null);
  };

  // Close Suppression Modal
  const handleCloseSuppressModal = () => {
    if (actionSubmitting) return;
    setSuppressingFinding(null);
    setActionError(null);
    setTimeout(() => {
      if (suppressTriggerRef.current && typeof suppressTriggerRef.current.focus === 'function') {
        suppressTriggerRef.current.focus();
      }
    }, 50);
  };

  // Open Revoke Modal
  const handleOpenRevokeModal = (finding, e) => {
    if (e) e.stopPropagation();
    revokeTriggerRef.current = e?.currentTarget || document.activeElement;
    setRevokingFinding(finding);
    setActionError(null);
  };

  // Close Revoke Modal
  const handleCloseRevokeModal = () => {
    if (actionSubmitting) return;
    setRevokingFinding(null);
    setActionError(null);
    setTimeout(() => {
      if (revokeTriggerRef.current && typeof revokeTriggerRef.current.focus === 'function') {
        revokeTriggerRef.current.focus();
      }
    }, 50);
  };

  // Submit Suppression
  const handleSubmitSuppression = async (e) => {
    if (e) e.preventDefault();
    if (!suppressingFinding || !selectedAnalysisId) return;

    // Check duplicate action protection
    if (isSubmittingRef.current || actionSubmitting) return;

    // Client-side validation: reason comment length requirements from backend model
    const trimmedComment = reasonComment.trim();
    if (['ACCEPTED_RISK', 'EXTERNAL_SANITIZATION', 'OTHER'].includes(reasonCode)) {
      if (trimmedComment.length < 5) {
        setActionError(`Reason code '${reasonCode}' requires an explanatory comment of at least 5 characters.`);
        return;
      }
    }
    if (trimmedComment.length > 1000) {
      setActionError('Comment exceeds maximum allowed length of 1000 characters.');
      return;
    }

    isSubmittingRef.current = true;
    setActionSubmitting(true);
    setActionError(null);

    const repoId = analysisData?.repository_id ||
      analysisData?.repository?.repository ||
      analysisData?.repository?.repo_name ||
      summary._repository?.repository ||
      null;

    const expiresAt = computeExpiresAtIso(expirationOption);

    try {
      await markFalsePositive(
        selectedAnalysisId,
        suppressingFinding.finding_id,
        trimmedComment,
        repoId,
        reasonCode,
        expiresAt
      );

      // Close modal
      setSuppressingFinding(null);

      // Authoritative Refresh
      await fetchAnalysis(selectedAnalysisId);
    } catch (err) {
      setActionError(sanitizeErrorMessage(err.message || 'Failed to record finding suppression.'));
    } finally {
      isSubmittingRef.current = false;
      setActionSubmitting(false);
    }
  };

  // Submit Revocation
  const handleSubmitRevocation = async (e) => {
    if (e) e.preventDefault();
    if (!revokingFinding || !selectedAnalysisId) return;

    if (isSubmittingRef.current || actionSubmitting) return;

    isSubmittingRef.current = true;
    setActionSubmitting(true);
    setActionError(null);

    try {
      await revokeFalsePositive(
        selectedAnalysisId,
        revokingFinding.finding_id
      );

      // Close modal
      setRevokingFinding(null);

      // Authoritative Refresh
      await fetchAnalysis(selectedAnalysisId);
    } catch (err) {
      setActionError(sanitizeErrorMessage(err.message || 'Failed to revoke finding suppression.'));
    } finally {
      isSubmittingRef.current = false;
      setActionSubmitting(false);
    }
  };

  const repoName = analysisData?.repository?.repository ||
    analysisData?.repository?.repo_name ||
    summary._repository?.repository ||
    analysisData?.repository_id ||
    'SARUKKESH-M/S5-MINI-PROJECT';

  const branchName = analysisData?.repository?.branch || summary._repository?.branch || 'main';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* 1. Header & Quick Navigation Bar */}
      <div className="cs-breadcrumb-bar">
        <div className="cs-breadcrumb-left" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ReviewsIcon size={20} color="#6366F1" />
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#0F172A', margin: 0 }}>
              Security Review & Finding Management
            </h2>
          </div>
          <span style={{ color: '#CBD5E1' }}>|</span>
          <span style={{ fontSize: '12px', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
            CodeSentinel v1.1.0
          </span>
        </div>

        {/* Cross-workspace Navigation */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate('/history', { state: { analysisId: selectedAnalysisId } })}
            title="Inspect historical records in Analysis History"
          >
            All Analyses →
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate('/repositories')}
            title="Navigate to Repository Workspace"
          >
            Repositories
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate('/pull-requests')}
            title="Navigate to Pull Request Audits"
          >
            Pull Requests
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

      {/* 2. Analysis Switcher & Context Bar */}
      <div
        className="card"
        style={{
          padding: '14px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          backgroundColor: '#FFFFFF',
          border: '1px solid #E2E8F0',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
          <div>
            <label
              htmlFor="cs-analysis-selector"
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
              Audited Analysis Record
            </label>
            <select
              id="cs-analysis-selector"
              className="cs-select"
              value={selectedAnalysisId || ''}
              onChange={(e) => handleSelectAnalysis(e.target.value)}
              disabled={listLoading || analysesList.length === 0}
              style={{ minWidth: '260px', fontFamily: 'var(--font-mono)', fontSize: '12.5px' }}
            >
              {analysesList.length === 0 && (
                <option value="">{listLoading ? 'Loading analyses...' : 'No analyses available'}</option>
              )}
              {analysesList.map((item) => {
                const aRepo = item.summary?._repository?.repository || item.query || 'Source Inspection';
                const count = item.finding_count ?? item.summary?.total_findings ?? 0;
                return (
                  <option key={item.analysis_id} value={item.analysis_id}>
                    {item.analysis_id} ({aRepo} — {count} findings)
                  </option>
                );
              })}
            </select>
          </div>

          {analysisData && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap', paddingTop: '16px' }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
                <RepositoriesIcon size={15} color="#64748B" />
                <span style={{ fontWeight: 600, color: '#0F172A' }}>{repoName}</span>
                <span style={{ fontSize: '11.5px', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
                  ({branchName})
                </span>
              </div>

              {analysisData.pr_number && (
                <span
                  style={{
                    fontSize: '11.5px',
                    fontFamily: 'var(--font-mono)',
                    backgroundColor: '#EEF2FF',
                    color: '#4F46E5',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontWeight: 600,
                    border: '1px solid #C7D2FE',
                  }}
                >
                  PR #{analysisData.pr_number}
                </span>
              )}

              {analysisData.head_sha && (
                <span style={{ fontSize: '11.5px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                  Commit: <code>{analysisData.head_sha.substring(0, 8)}</code>
                </span>
              )}

              <span style={{ fontSize: '12px', color: '#94A3B8' }}>
                {analysisData.created_at ? new Date(analysisData.created_at).toLocaleString() : '—'}
              </span>
            </div>
          )}
        </div>

        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={handleRefresh}
          disabled={loading || !selectedAnalysisId}
          title="Refresh authoritative analysis from SQLite backend"
        >
          ↻ Refresh Record
        </button>
      </div>

      {/* 3. Loading State */}
      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: '56px 24px' }}>
          <div style={{ fontSize: '28px', marginBottom: '12px' }}>🛡️</div>
          <div style={{ color: '#0F172A', fontWeight: 600, fontSize: '15px', marginBottom: '6px' }}>
            Loading Security Review Workspace...
          </div>
          <div style={{ color: '#64748B', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
            Retrieving authoritative findings and suppression telemetry from persistent storage
          </div>
        </div>
      )}

      {/* 4. Error / 404 State */}
      {!loading && error && (
        <div className="card" style={{ padding: '36px 24px', textAlign: 'center' }}>
          <div style={{ fontSize: '32px', marginBottom: '12px' }}>
            {errorStatus === 404 ? '🔍' : '⚠️'}
          </div>
          <h3 style={{ fontSize: '17px', fontWeight: 700, color: '#0F172A', marginBottom: '6px' }}>
            {errorStatus === 404 ? 'Analysis Record Not Found' : 'Unable to Load Security Review'}
          </h3>
          <p style={{ fontSize: '13px', color: '#64748B', maxWidth: '480px', margin: '0 auto 16px', lineHeight: 1.5 }}>
            {error}
          </p>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => navigate('/history')}
            >
              Browse History
            </button>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => navigate('/analyze')}
            >
              Start New Analysis
            </button>
          </div>
        </div>
      )}

      {/* 5. Loaded Workspace */}
      {!loading && !error && analysisData && (
        <>
          {/* Review Posture Summary Card */}
          <div className="cs-analysis-summary-card">
            <div className="cs-analysis-summary-header">
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B', textTransform: 'uppercase' }}>
                  Authoritative Security Review Posture
                </span>
                <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#0F172A', margin: '2px 0 0' }}>
                  Audit Review for {repoName}
                </h3>
              </div>

              {/* Authoritative Security Gate */}
              <div className="cs-gate-highlight">
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '2px' }}>
                  <span className="cs-gate-label">Authoritative Gate:</span>
                  <StatusBadge status={authoritativeGate} size="large" />
                </div>
              </div>
            </div>

            {/* Step 6O Protection Notice */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 14px',
                backgroundColor: 'rgba(99, 102, 241, 0.05)',
                border: '1px solid rgba(99, 102, 241, 0.2)',
                borderRadius: '6px',
                fontSize: '12.5px',
                color: '#334155',
              }}
            >
              <span style={{ fontSize: '15px' }}>ℹ️</span>
              <span>
                <strong>Step 6O Policy:</strong> The security gate (<code>{authoritativeGate}</code>) is strictly backend-authoritative.
                Review and suppression actions record persistent audit feedback for future scans and cannot override the historical analysis gate.
              </span>
            </div>

            {/* Metric Counters Grid */}
            <div className="cs-summary-grid">
              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Total Findings</span>
                <span className="cs-summary-stat-value" style={{ color: totalFindings > 0 ? '#0F172A' : '#10B981' }}>
                  {totalFindings}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Open (Need Review)</span>
                <span className="cs-summary-stat-value" style={{ color: openCount > 0 ? '#EF4444' : '#10B981' }}>
                  {openCount}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Suppressed / False Pos</span>
                <span className="cs-summary-stat-value" style={{ color: suppressedCount > 0 ? '#6366F1' : '#64748B' }}>
                  {suppressedCount}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Critical</span>
                <span className="cs-summary-stat-value" style={{ color: '#EF4444' }}>
                  {critCount}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">High</span>
                <span className="cs-summary-stat-value" style={{ color: '#F97316' }}>
                  {highCount}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Medium</span>
                <span className="cs-summary-stat-value" style={{ color: '#F59E0B' }}>
                  {medCount}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Low</span>
                <span className="cs-summary-stat-value" style={{ color: '#06B6D4' }}>
                  {lowCount}
                </span>
              </div>

              <div className="cs-summary-stat-box">
                <span className="cs-summary-stat-label">Info</span>
                <span className="cs-summary-stat-value" style={{ color: '#64748B' }}>
                  {infoCount}
                </span>
              </div>
            </div>
          </div>

          {/* Finding Explorer & Review Workspace */}
          <div className="cs-findings-explorer-card">
            <div>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#0F172A', margin: '0 0 4px' }}>
                Finding Review Explorer
              </h3>
              <p style={{ fontSize: '12.5px', color: '#64748B', margin: 0 }}>
                Triage findings, review AST evidence, inspect remediation, and manage suppression feedback.
              </p>
            </div>

            {/* Interactive Filters & Search Toolbar */}
            <div className="cs-explorer-toolbar">
              <div className="cs-explorer-controls-left" style={{ flexWrap: 'wrap', gap: '10px' }}>
                {/* Search Box */}
                <div className="cs-explorer-search-wrapper" style={{ minWidth: '240px' }}>
                  <span className="cs-explorer-search-icon">🔍</span>
                  <input
                    type="text"
                    className="cs-explorer-search-input"
                    placeholder="Search title, rule, file, finding ID..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    aria-label="Search findings"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      className="cs-explorer-search-clear"
                      onClick={() => setSearchQuery('')}
                      aria-label="Clear search"
                    >
                      ✕
                    </button>
                  )}
                </div>

                {/* Status Filter Tabs (All / Open / Suppressed) */}
                <div style={{ display: 'inline-flex', borderRadius: '6px', border: '1px solid #CBD5E1', overflow: 'hidden' }}>
                  <button
                    type="button"
                    style={{
                      padding: '6px 12px',
                      fontSize: '12px',
                      fontWeight: 600,
                      border: 'none',
                      backgroundColor: statusFilter === 'ALL' ? '#0F172A' : '#FFFFFF',
                      color: statusFilter === 'ALL' ? '#FFFFFF' : '#475569',
                      cursor: 'pointer',
                    }}
                    onClick={() => setStatusFilter('ALL')}
                  >
                    All ({totalFindings})
                  </button>
                  <button
                    type="button"
                    style={{
                      padding: '6px 12px',
                      fontSize: '12px',
                      fontWeight: 600,
                      borderLeft: '1px solid #CBD5E1',
                      backgroundColor: statusFilter === 'OPEN' ? '#EF4444' : '#FFFFFF',
                      color: statusFilter === 'OPEN' ? '#FFFFFF' : '#475569',
                      cursor: 'pointer',
                    }}
                    onClick={() => setStatusFilter('OPEN')}
                  >
                    Open ({openCount})
                  </button>
                  <button
                    type="button"
                    style={{
                      padding: '6px 12px',
                      fontSize: '12px',
                      fontWeight: 600,
                      borderLeft: '1px solid #CBD5E1',
                      backgroundColor: statusFilter === 'SUPPRESSED' ? '#6366F1' : '#FFFFFF',
                      color: statusFilter === 'SUPPRESSED' ? '#FFFFFF' : '#475569',
                      cursor: 'pointer',
                    }}
                    onClick={() => setStatusFilter('SUPPRESSED')}
                  >
                    Suppressed ({suppressedCount})
                  </button>
                </div>

                {/* Severity Dropdown */}
                <select
                  className="cs-select"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={{ fontSize: '12px', padding: '6px 10px' }}
                  aria-label="Filter by severity"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical ({critCount})</option>
                  <option value="HIGH">High ({highCount})</option>
                  <option value="MEDIUM">Medium ({medCount})</option>
                  <option value="LOW">Low ({lowCount})</option>
                  <option value="INFO">Info ({infoCount})</option>
                </select>

                {/* Category Dropdown */}
                {availableCategories.length > 1 && (
                  <select
                    className="cs-select"
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    style={{ fontSize: '12px', padding: '6px 10px', maxWidth: '220px' }}
                    aria-label="Filter by category"
                  >
                    <option value="ALL">All Categories ({availableCategories.length})</option>
                    {availableCategories.map((cat) => (
                      <option key={cat} value={cat}>
                        {cat}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Sorting & Reset */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <select
                  className="cs-select"
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  style={{ fontSize: '12px', padding: '6px 10px' }}
                  aria-label="Sort findings"
                >
                  <option value="severity-desc">Severity: High → Low</option>
                  <option value="severity-asc">Severity: Low → High</option>
                  <option value="status-open-first">Status: Open First</option>
                  <option value="file-asc">File & Line</option>
                  <option value="title-asc">Title: A → Z</option>
                </select>

                {isFiltered && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleResetFilters}
                    style={{ fontSize: '12px' }}
                  >
                    Reset Filters
                  </button>
                )}
              </div>
            </div>

            {/* Counts Bar */}
            <div className="cs-explorer-counts-bar">
              <span>
                {isFiltered ? (
                  <>
                    Showing <strong>{filteredFindings.length}</strong> of <strong>{totalFindings}</strong> findings{' '}
                    <span style={{ fontSize: '11px', color: '#0284C7', fontWeight: 600 }}>(Filtered)</span>
                  </>
                ) : (
                  <>
                    Total Findings: <strong>{totalFindings}</strong> ({openCount} open, {suppressedCount} suppressed)
                  </>
                )}
              </span>
            </div>

            {/* Findings List */}
            {rawFindings.length === 0 ? (
              <div className="cs-filter-empty-box" style={{ padding: '48px 20px' }}>
                <div style={{ fontSize: '32px' }}>🛡️</div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A' }}>
                  No Security Findings Reported
                </div>
                <p style={{ fontSize: '13px', color: '#64748B', maxWidth: '460px', margin: 0, lineHeight: 1.5 }}>
                  This scan completed with an authoritative <code>ALLOW</code> verdict. No vulnerabilities were detected in this analysis.
                </p>
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="cs-filter-empty-box">
                <div style={{ fontSize: '28px' }}>🔍</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: '#0F172A' }}>
                  No findings match your filters
                </div>
                <p style={{ fontSize: '12.5px', color: '#64748B', margin: 0 }}>
                  Adjust your search terms, severity level, or status filters to view findings.
                </p>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleResetFilters}
                  style={{ marginTop: '6px' }}
                >
                  Reset All Filters
                </button>
              </div>
            ) : (
              <div className="cs-findings-list">
                {filteredFindings.map((finding, idx) => {
                  const fTitle = finding.title || finding.name || 'Security Finding';
                  const fSeverity = (finding.severity || 'INFO').toUpperCase();
                  const fCategory = finding.category || finding.rule_id || null;
                  const primaryEv = Array.isArray(finding.evidence) && finding.evidence.length > 0 ? finding.evidence[0] : null;
                  const fFile = finding.file_path || finding.file || primaryEv?.document_id || null;
                  const fLine = finding.line_number ?? finding.line ?? primaryEv?.line_start ?? null;
                  const fLocation = fFile ? `${fFile}${fLine ? `:${fLine}` : ''}` : null;
                  const fConfidence = finding.confidence !== undefined ? (
                    typeof finding.confidence === 'number'
                      ? `${Math.round(finding.confidence * 100)}%`
                      : String(finding.confidence)
                  ) : null;
                  const fAst = finding.ast_signal || (
                    primaryEv?.signal_name
                      ? `${primaryEv.signal_name}${primaryEv.signal_type ? ` (${primaryEv.signal_type})` : ''}`
                      : null
                  );
                  const isSuppressed = Boolean(finding.is_false_positive);
                  const feedback = finding.feedback || null;

                  return (
                    <div
                      key={finding.finding_id || idx}
                      className="cs-finding-row-card"
                      style={{
                        backgroundColor: isSuppressed ? '#F8FAFC' : '#FFFFFF',
                        borderLeft: isSuppressed ? '4px solid #818CF8' : undefined,
                      }}
                    >
                      {/* Row Top Header */}
                      <div className="cs-finding-row-top">
                        <div className="cs-finding-row-meta" style={{ flexWrap: 'wrap', gap: '8px' }}>
                          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#94A3B8' }}>
                            #{idx + 1}
                          </span>
                          <StatusBadge status={fSeverity} />

                          {/* Review Status Badge */}
                          {isSuppressed ? (
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                fontFamily: 'var(--font-mono)',
                                color: '#4338CA',
                                backgroundColor: '#EEF2FF',
                                border: '1px solid #C7D2FE',
                                padding: '2px 8px',
                                borderRadius: '4px',
                              }}
                            >
                              ✓ SUPPRESSED / FALSE POSITIVE
                            </span>
                          ) : (
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                fontFamily: 'var(--font-mono)',
                                color: '#B91C1C',
                                backgroundColor: '#FEF2F2',
                                border: '1px solid #FECACA',
                                padding: '2px 8px',
                                borderRadius: '4px',
                              }}
                            >
                              ● OPEN
                            </span>
                          )}

                          <h4 className="cs-finding-row-title" style={{ margin: 0 }}>
                            {fTitle}
                          </h4>

                          {fCategory && (
                            <span
                              style={{
                                fontSize: '11px',
                                fontFamily: 'var(--font-mono)',
                                color: '#64748B',
                                backgroundColor: '#F1F5F9',
                                padding: '2px 6px',
                                borderRadius: '3px',
                                border: '1px solid #E2E8F0',
                              }}
                            >
                              {fCategory}
                            </span>
                          )}
                        </div>

                        {/* Action Buttons */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <button
                            type="button"
                            className="cs-finding-inspect-btn"
                            onClick={() => setInspectingFinding(finding)}
                            aria-label={`Inspect evidence & remediation for ${fTitle}`}
                          >
                            Inspect Details →
                          </button>

                          {isSuppressed ? (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={(e) => handleOpenRevokeModal(finding, e)}
                              style={{ fontSize: '11.5px', color: '#B91C1C', borderColor: '#FECACA' }}
                              title="Revoke suppression for this finding"
                            >
                              Revoke Suppression
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={(e) => handleOpenSuppressModal(finding, e)}
                              style={{ fontSize: '11.5px', color: '#4F46E5', borderColor: '#C7D2FE' }}
                              title="Mark this finding as a false positive or suppressed risk"
                            >
                              Suppress Finding
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Location & AST Signal Metadata */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap', fontSize: '12px' }}>
                        {fLocation && (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', color: '#0284C7' }}>
                            <CodeFileIcon size={14} color="#64748B" />
                            <span>{fLocation}</span>
                          </div>
                        )}
                        {finding.finding_id && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#64748B' }}>
                            ID: <code style={{ color: '#475569' }}>{finding.finding_id}</code>
                          </span>
                        )}
                        {fConfidence && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#64748B' }}>
                            Confidence: <strong>{fConfidence}</strong>
                          </span>
                        )}
                        {fAst && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#64748B' }}>
                            Signal: <strong style={{ color: '#475569' }}>{fAst}</strong>
                          </span>
                        )}
                        {primaryEv?.sink_name && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#64748B' }}>
                            Sink: <strong style={{ color: '#475569' }}>{primaryEv.sink_name}</strong>
                          </span>
                        )}
                      </div>

                      {/* Risk Description */}
                      {finding.description && (
                        <p style={{ margin: 0, fontSize: '12.5px', color: '#475569', lineHeight: 1.45 }}>
                          {finding.description}
                        </p>
                      )}

                      {/* Active Suppression Audit Details */}
                      {isSuppressed && feedback && (
                        <div
                          style={{
                            padding: '10px 14px',
                            backgroundColor: '#EEF2FF',
                            border: '1px solid #C7D2FE',
                            borderRadius: '6px',
                            fontSize: '12px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '4px',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                            <div style={{ fontWeight: 700, color: '#3730A3', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.5px' }}>
                              Suppression Audit Record: {feedback.reason_code || 'FALSE_POSITIVE'}
                            </div>
                            <span style={{ fontSize: '11px', color: '#6366F1', fontFamily: 'var(--font-mono)' }}>
                              Status: {feedback.status || 'ACTIVE'}
                              {feedback.expires_at ? ` (Expires: ${new Date(feedback.expires_at).toLocaleDateString()})` : ' (No expiration)'}
                            </span>
                          </div>
                          {feedback.reason && (
                            <div style={{ color: '#4338CA', fontStyle: 'italic' }}>
                              "{feedback.reason}"
                            </div>
                          )}
                          <div style={{ fontSize: '10.5px', color: '#6B7280', fontFamily: 'var(--font-mono)' }}>
                            Recorded: {feedback.created_at ? new Date(feedback.created_at).toLocaleString() : '—'}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {/* 6. Finding Inspection Modal (Reusing Phase 6 FindingPreviewModal) */}
      <FindingPreviewModal
        isOpen={Boolean(inspectingFinding)}
        onClose={() => setInspectingFinding(null)}
        finding={inspectingFinding}
      />

      {/* 7. Controlled Suppression Modal */}
      {suppressingFinding && (
        <div
          className="cs-modal-backdrop"
          onClick={handleCloseSuppressModal}
          role="dialog"
          aria-modal="true"
          aria-labelledby="cs-suppress-modal-title"
        >
          <div
            className="cs-modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '580px' }}
          >
            {/* Modal Header */}
            <div className="cs-modal-header">
              <div className="cs-modal-header-left">
                <h3 id="cs-suppress-modal-title" className="cs-modal-title">
                  Suppress Finding / False Positive
                </h3>
              </div>
              <button
                type="button"
                className="cs-modal-close-btn"
                onClick={handleCloseSuppressModal}
                disabled={actionSubmitting}
                aria-label="Close suppression modal"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <form onSubmit={handleSubmitSuppression}>
              <div className="cs-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Target Finding Summary */}
                <div
                  style={{
                    padding: '12px 14px',
                    backgroundColor: '#F8FAFC',
                    border: '1px solid #E2E8F0',
                    borderRadius: '6px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <StatusBadge status={(suppressingFinding.severity || 'Medium').toUpperCase()} />
                    <strong style={{ fontSize: '13.5px', color: '#0F172A' }}>
                      {suppressingFinding.title || suppressingFinding.name}
                    </strong>
                  </div>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                    Finding ID: <code>{suppressingFinding.finding_id}</code>
                  </div>
                  <div style={{ fontSize: '11.5px', color: '#475569' }}>
                    Location: {suppressingFinding.file_path || suppressingFinding.file || suppressingFinding.evidence?.[0]?.document_id || '—'}
                  </div>
                </div>

                {/* Policy Notice */}
                <div
                  style={{
                    padding: '10px 12px',
                    backgroundColor: '#FEF3C7',
                    border: '1px solid #FDE68A',
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: '#92400E',
                    lineHeight: 1.45,
                  }}
                >
                  <strong>Notice:</strong> Suppressing this finding will record an authoritative suppression rule in the persistent database.
                  It will exclude this finding in future analyses, but does not alter the historical security gate for this record.
                </div>

                {/* Reason Code Select */}
                <div>
                  <label
                    htmlFor="cs-suppress-reason-code"
                    style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}
                  >
                    Reason Taxonomy Code *
                  </label>
                  <select
                    id="cs-suppress-reason-code"
                    className="cs-select"
                    value={reasonCode}
                    onChange={(e) => setReasonCode(e.target.value)}
                    style={{ width: '100%', fontSize: '13px' }}
                    disabled={actionSubmitting}
                  >
                    {REASON_CODES.map((rc) => (
                      <option key={rc.code} value={rc.code}>
                        {rc.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Explanatory Comment */}
                <div>
                  <label
                    htmlFor="cs-suppress-comment"
                    style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}
                  >
                    Explanatory Rationale / Comment {['ACCEPTED_RISK', 'EXTERNAL_SANITIZATION', 'OTHER'].includes(reasonCode) && <span style={{ color: '#DC2626' }}>* (Min 5 chars)</span>}
                  </label>
                  <textarea
                    id="cs-suppress-comment"
                    className="cs-textarea"
                    rows={3}
                    placeholder="Provide technical justification for suppressing this finding..."
                    value={reasonComment}
                    onChange={(e) => setReasonComment(e.target.value)}
                    maxLength={1000}
                    disabled={actionSubmitting}
                    style={{ width: '100%', fontSize: '12.5px', resize: 'vertical' }}
                  />
                  <div style={{ display: 'flex', justifyContent: 'flex-end', fontSize: '10.5px', color: '#94A3B8', marginTop: '2px' }}>
                    {reasonComment.length} / 1000 characters
                  </div>
                </div>

                {/* Expiration Option */}
                <div>
                  <label
                    htmlFor="cs-suppress-expiry"
                    style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}
                  >
                    Suppression Lifespan
                  </label>
                  <select
                    id="cs-suppress-expiry"
                    className="cs-select"
                    value={expirationOption}
                    onChange={(e) => setExpirationOption(e.target.value)}
                    style={{ width: '100%', fontSize: '13px' }}
                    disabled={actionSubmitting}
                  >
                    {EXPIRATION_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Error Banner */}
                {actionError && (
                  <div
                    style={{
                      padding: '10px 12px',
                      backgroundColor: '#FEF2F2',
                      border: '1px solid #FECACA',
                      borderRadius: '6px',
                      fontSize: '12px',
                      color: '#B91C1C',
                    }}
                  >
                    {actionError}
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="cs-modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleCloseSuppressModal}
                  disabled={actionSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={actionSubmitting}
                  style={{ backgroundColor: '#4F46E5', borderColor: '#4F46E5' }}
                >
                  {actionSubmitting ? 'Recording Suppression...' : 'Confirm Suppression'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 8. Controlled Revoke Modal */}
      {revokingFinding && (
        <div
          className="cs-modal-backdrop"
          onClick={handleCloseRevokeModal}
          role="dialog"
          aria-modal="true"
          aria-labelledby="cs-revoke-modal-title"
        >
          <div
            className="cs-modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '520px' }}
          >
            <div className="cs-modal-header">
              <div className="cs-modal-header-left">
                <h3 id="cs-revoke-modal-title" className="cs-modal-title">
                  Revoke Finding Suppression
                </h3>
              </div>
              <button
                type="button"
                className="cs-modal-close-btn"
                onClick={handleCloseRevokeModal}
                disabled={actionSubmitting}
                aria-label="Close revoke modal"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmitRevocation}>
              <div className="cs-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div
                  style={{
                    padding: '12px 14px',
                    backgroundColor: '#FEF2F2',
                    border: '1px solid #FECACA',
                    borderRadius: '6px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <StatusBadge status={(revokingFinding.severity || 'Medium').toUpperCase()} />
                    <strong style={{ fontSize: '13.5px', color: '#991B1B' }}>
                      {revokingFinding.title || revokingFinding.name}
                    </strong>
                  </div>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#B91C1C' }}>
                    Finding ID: <code>{revokingFinding.finding_id}</code>
                  </div>
                </div>

                <p style={{ margin: 0, fontSize: '13px', color: '#475569', lineHeight: 1.5 }}>
                  Are you sure you want to revoke suppression for this finding?
                  Revoking will restore this finding as an <strong>OPEN</strong> vulnerability in the security review audit and reactivate detection in future scans.
                </p>

                {/* Error Banner */}
                {actionError && (
                  <div
                    style={{
                      padding: '10px 12px',
                      backgroundColor: '#FEF2F2',
                      border: '1px solid #FECACA',
                      borderRadius: '6px',
                      fontSize: '12px',
                      color: '#B91C1C',
                    }}
                  >
                    {actionError}
                  </div>
                )}
              </div>

              <div className="cs-modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleCloseRevokeModal}
                  disabled={actionSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-danger btn-sm"
                  disabled={actionSubmitting}
                >
                  {actionSubmitting ? 'Revoking Suppression...' : 'Confirm Revocation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
