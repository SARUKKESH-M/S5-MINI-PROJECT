import React, { useState, useEffect, useMemo } from 'react';
import { useLocation, useSearchParams } from 'react-router-dom';
import { getAnalyses, getAnalysis, deleteAnalysis } from '../services/apiClient';
import FindingPreviewModal from '../components/dashboard/FindingPreviewModal';
import StatusBadge from '../components/StatusBadge';
import { CodeFileIcon } from '../components/dashboard/Icons';

export default function HistoryView() {
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  // Analyses list state
  const [analyses, setAnalyses] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pagination state
  const [offset, setOffset] = useState(0);
  const limit = 15;

  // Selected analysis detail state
  const [selectedId, setSelectedId] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [detailError, setDetailError] = useState(null);
  const [detailStatus, setDetailStatus] = useState(null);

  // Findings explorer state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [sortBy, setSortBy] = useState('severity-desc');
  const [inspectingFinding, setInspectingFinding] = useState(null);

  const fetchHistory = async (currentOffset = 0) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAnalyses({ limit, offset: currentOffset });
      const items = Array.isArray(res.analyses) ? res.analyses : [];
      setAnalyses(items);
      setTotalCount(res.total_count ?? items.length);
    } catch (err) {
      setError(err.message || 'Failed to retrieve analysis history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory(offset);
  }, [offset]);

  // Load a specific analysis by ID
  const fetchAnalysisDetail = async (analysisId) => {
    if (!analysisId) return;

    setSelectedId(analysisId);
    setDetailLoading(true);
    setDetailError(null);
    setDetailStatus(null);

    try {
      const res = await getAnalysis(analysisId);
      setSelectedRecord(res.analysis || res);
    } catch (err) {
      setDetailStatus(err.status || null);
      setDetailError(err.message || 'Failed to load analysis details.');
    } finally {
      setDetailLoading(false);
    }
  };

  // Deep-link: inspect analysis if requested in URL or navigation state
  useEffect(() => {
    const targetId = searchParams.get('id') || location.state?.analysisId;
    if (targetId && targetId !== selectedId) {
      fetchAnalysisDetail(targetId);
    } else if (!targetId && selectedId) {
      setSelectedId(null);
      setSelectedRecord(null);
      setDetailError(null);
    }
  }, [searchParams, location.state]);

  const handleSelectRecord = (analysisId) => {
    if (selectedId === analysisId) {
      // Deselect
      handleCloseDetails();
      return;
    }
    setSearchParams({ id: analysisId });
  };

  const handleCloseDetails = () => {
    setSearchParams({});
    setSelectedId(null);
    setSelectedRecord(null);
    setDetailError(null);
    setDetailStatus(null);
    setSearchQuery('');
    setSelectedSeverity('ALL');
    setSortBy('severity-desc');
  };

  const handleDeleteRecord = async (analysisId, e) => {
    if (e) e.stopPropagation();
    if (!window.confirm(`Are you sure you want to delete analysis '${analysisId}'?`)) {
      return;
    }

    try {
      await deleteAnalysis(analysisId);
      if (selectedId === analysisId) {
        handleCloseDetails();
      }
      fetchHistory(offset);
    } catch (err) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const handlePrev = () => {
    if (offset >= limit) {
      setOffset(offset - limit);
    }
  };

  const handleNext = () => {
    if (offset + limit < totalCount) {
      setOffset(offset + limit);
    }
  };

  // Authoritative extraction from selectedRecord
  const summary = selectedRecord?.summary || {};
  const rawFindings = Array.isArray(selectedRecord?.findings) ? selectedRecord.findings : [];

  // Security gate: authoritative backend verdict
  const authoritativeGate = selectedRecord?.review_status || summary._review_status || (
    (summary.critical_count > 0 || summary.high_count > 0) ? 'BLOCK' :
    (summary.medium_count > 0) ? 'REVIEW' : 'ALLOW'
  );

  // Authoritative counts
  const totalFindings = selectedRecord?.finding_count ?? summary.total_findings ?? rawFindings.length;
  const critCount = summary.critical_count ?? rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = summary.high_count ?? rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const medCount = summary.medium_count ?? rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = summary.low_count ?? rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;
  const infoCount = summary.info_count ?? rawFindings.filter((f) => (f.severity || '').toUpperCase() === 'INFO').length;

  // Derived client-side filtered & sorted findings
  const filteredFindings = useMemo(() => {
    if (!Array.isArray(rawFindings)) return [];

    let result = [...rawFindings];

    // Severity Filter
    if (selectedSeverity !== 'ALL') {
      result = result.filter(
        (f) => (f.severity || '').toUpperCase() === selectedSeverity
      );
    }

    // Text search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter((f) => {
        const title = (f.title || f.name || '').toLowerCase();
        const fId = (f.finding_id || '').toLowerCase();
        const cat = (f.category || f.rule_id || '').toLowerCase();
        const desc = (f.description || '').toLowerCase();
        const docId = (f.file_path || f.file || f.evidence?.[0]?.document_id || '').toLowerCase();
        return (
          title.includes(q) ||
          fId.includes(q) ||
          cat.includes(q) ||
          desc.includes(q) ||
          docId.includes(q)
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
      if (sortBy === 'title-asc') {
        return (a.title || a.name || '').localeCompare(b.title || b.name || '');
      }
      return 0;
    });

    return result;
  }, [rawFindings, selectedSeverity, searchQuery, sortBy]);

  const isFiltered = Boolean(searchQuery.trim() || selectedSeverity !== 'ALL');

  const handleResetFilters = () => {
    setSearchQuery('');
    setSelectedSeverity('ALL');
    setSortBy('severity-desc');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* If an analysis is selected, render the Analysis Details & Findings Explorer */}
      {selectedId ? (
        <div className="cs-analysis-details-view">
          {/* Top Breadcrumb & Action Bar */}
          <div className="cs-breadcrumb-bar">
            <div className="cs-breadcrumb-left">
              <button
                type="button"
                className="cs-back-btn"
                onClick={handleCloseDetails}
                aria-label="Return to analysis list"
              >
                ← All Analyses
              </button>
              <span style={{ color: '#94A3B8' }}>/</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#0F172A' }}>
                {selectedId}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => fetchAnalysisDetail(selectedId)}
                disabled={detailLoading}
              >
                ↻ Refresh Analysis
              </button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={(e) => handleDeleteRecord(selectedId, e)}
              >
                Delete
              </button>
            </div>
          </div>

          {/* Loading State for Analysis Details */}
          {detailLoading && (
            <div className="card" style={{ textAlign: 'center', padding: '48px' }}>
              <div style={{ fontSize: '24px', marginBottom: '10px' }}>🛡️</div>
              <div style={{ color: '#0F172A', fontWeight: 600, marginBottom: '4px' }}>
                Loading Analysis Details...
              </div>
              <div style={{ color: '#64748B', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                Retrieving audit record and verified findings for {selectedId}
              </div>
            </div>
          )}

          {/* Error / 404 State for Analysis Details */}
          {!detailLoading && detailError && (
            <div className="card" style={{ padding: '32px', textAlign: 'center' }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>
                {detailStatus === 404 || String(detailError).toLowerCase().includes('not found') ? '🔍' : '⚠️'}
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#0F172A', marginBottom: '6px' }}>
                {detailStatus === 404 || String(detailError).toLowerCase().includes('not found')
                  ? 'Analysis Not Found'
                  : 'Unable to Load Analysis Details'}
              </h3>
              <p style={{ fontSize: '13px', color: '#64748B', maxWidth: '520px', margin: '0 auto 16px', lineHeight: 1.5 }}>
                {detailStatus === 404 || String(detailError).toLowerCase().includes('not found')
                  ? `No analysis record exists with ID '${selectedId}'. It may have been deleted or the link is invalid.`
                  : detailError}
              </p>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleCloseDetails}
              >
                ← Back to History List
              </button>
            </div>
          )}

          {/* Loaded Analysis Details */}
          {!detailLoading && !detailError && selectedRecord && (
            <>
              {/* Section 1: Summary & Authoritative Security Gate */}
              <div className="cs-analysis-summary-card">
                <div className="cs-analysis-summary-header">
                  <div>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B', textTransform: 'uppercase' }}>
                      Security Audit Summary
                    </span>
                    <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#0F172A', margin: '2px 0 0' }}>
                      {selectedRecord.repository?.repository ||
                        selectedRecord.repository?.repo_name ||
                        summary._repository?.repository ||
                        selectedRecord.query ||
                        'Source Code Inspection'}
                    </h2>
                  </div>

                  {/* Authoritative Security Gate Badge */}
                  <div className="cs-gate-highlight">
                    <span className="cs-gate-label">Authoritative Gate:</span>
                    <StatusBadge status={authoritativeGate} size="large" />
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="cs-summary-grid">
                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Repository</span>
                    <span className="cs-summary-stat-value">
                      {selectedRecord.repository?.repository || selectedRecord.repository?.repo_name || summary._repository?.repository || '—'}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Branch</span>
                    <span className="cs-summary-stat-value">
                      {selectedRecord.repository?.branch || summary._repository?.branch || '—'}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Analysis ID</span>
                    <span className="cs-summary-stat-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
                      {selectedRecord.analysis_id || selectedId}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Status</span>
                    <span className="cs-summary-stat-value" style={{ textTransform: 'capitalize' }}>
                      {selectedRecord.status || 'completed'}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Files Analyzed</span>
                    <span className="cs-summary-stat-value">
                      {summary.analyzed_files ?? summary.total_files ?? '—'}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Total Findings</span>
                    <span className="cs-summary-stat-value" style={{ color: totalFindings > 0 ? '#EF4444' : '#10B981' }}>
                      {totalFindings}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Timestamp</span>
                    <span className="cs-summary-stat-value" style={{ fontSize: '12px', fontWeight: 500 }}>
                      {selectedRecord.created_at ? new Date(selectedRecord.created_at).toLocaleString() : '—'}
                    </span>
                  </div>

                  <div className="cs-summary-stat-box">
                    <span className="cs-summary-stat-label">Duration</span>
                    <span className="cs-summary-stat-value" title="Duration is not tracked by backend">
                      —
                    </span>
                  </div>
                </div>
              </div>

              {/* Section 2: Severity Breakdown Bar */}
              <div className="cs-severity-breakdown-bar">
                <button
                  type="button"
                  className={`cs-severity-card-btn cs-sev-card-crit ${selectedSeverity === 'CRITICAL' ? 'active' : ''}`}
                  onClick={() => setSelectedSeverity(selectedSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
                  title="Filter Critical findings"
                >
                  <span className="cs-severity-card-num" style={{ color: '#EF4444' }}>{critCount}</span>
                  <span className="cs-severity-card-lbl">Critical</span>
                </button>

                <button
                  type="button"
                  className={`cs-severity-card-btn cs-sev-card-high ${selectedSeverity === 'HIGH' ? 'active' : ''}`}
                  onClick={() => setSelectedSeverity(selectedSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
                  title="Filter High findings"
                >
                  <span className="cs-severity-card-num" style={{ color: '#F97316' }}>{highCount}</span>
                  <span className="cs-severity-card-lbl">High</span>
                </button>

                <button
                  type="button"
                  className={`cs-severity-card-btn cs-sev-card-med ${selectedSeverity === 'MEDIUM' ? 'active' : ''}`}
                  onClick={() => setSelectedSeverity(selectedSeverity === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
                  title="Filter Medium findings"
                >
                  <span className="cs-severity-card-num" style={{ color: '#F59E0B' }}>{medCount}</span>
                  <span className="cs-severity-card-lbl">Medium</span>
                </button>

                <button
                  type="button"
                  className={`cs-severity-card-btn cs-sev-card-low ${selectedSeverity === 'LOW' ? 'active' : ''}`}
                  onClick={() => setSelectedSeverity(selectedSeverity === 'LOW' ? 'ALL' : 'LOW')}
                  title="Filter Low findings"
                >
                  <span className="cs-severity-card-num" style={{ color: '#06B6D4' }}>{lowCount}</span>
                  <span className="cs-severity-card-lbl">Low</span>
                </button>

                <button
                  type="button"
                  className={`cs-severity-card-btn cs-sev-card-info ${selectedSeverity === 'INFO' ? 'active' : ''}`}
                  onClick={() => setSelectedSeverity(selectedSeverity === 'INFO' ? 'ALL' : 'INFO')}
                  title="Filter Info findings"
                >
                  <span className="cs-severity-card-num" style={{ color: '#64748B' }}>{infoCount}</span>
                  <span className="cs-severity-card-lbl">Info</span>
                </button>
              </div>

              {/* Section 3: Findings Explorer */}
              <div className="cs-findings-explorer-card">
                <div>
                  <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#0F172A', margin: '0 0 4px' }}>
                    Findings Explorer
                  </h3>
                  <p style={{ fontSize: '12.5px', color: '#64748B', margin: 0 }}>
                    Search, filter, and inspect verified vulnerabilities identified in this audit.
                  </p>
                </div>

                {/* Toolbar */}
                <div className="cs-explorer-toolbar">
                  <div className="cs-explorer-controls-left">
                    {/* Search Box */}
                    <div className="cs-explorer-search-wrapper">
                      <input
                        type="text"
                        className="cs-explorer-search-input"
                        placeholder="Search by title, rule, category, file, description..."
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

                    {/* Severity Filter */}
                    <select
                      className="cs-explorer-select"
                      value={selectedSeverity}
                      onChange={(e) => setSelectedSeverity(e.target.value)}
                      aria-label="Filter by severity"
                    >
                      <option value="ALL">All Severities ({totalFindings})</option>
                      <option value="CRITICAL">Critical ({critCount})</option>
                      <option value="HIGH">High ({highCount})</option>
                      <option value="MEDIUM">Medium ({medCount})</option>
                      <option value="LOW">Low ({lowCount})</option>
                      <option value="INFO">Info ({infoCount})</option>
                    </select>

                    {/* Sort Selector */}
                    <select
                      className="cs-explorer-select"
                      value={sortBy}
                      onChange={(e) => setSortBy(e.target.value)}
                      aria-label="Sort findings"
                    >
                      <option value="severity-desc">Severity: Highest First</option>
                      <option value="severity-asc">Severity: Lowest First</option>
                      <option value="file-asc">File & Line: A to Z</option>
                      <option value="title-asc">Title: A to Z</option>
                    </select>
                  </div>

                  {/* Reset Filters */}
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

                {/* Counter Bar */}
                <div className="cs-explorer-counts-bar">
                  <span>
                    {isFiltered ? (
                      <>
                        Showing <strong>{filteredFindings.length}</strong> of <strong>{totalFindings}</strong> findings{' '}
                        <span style={{ fontSize: '11px', color: '#0284C7', fontWeight: 600 }}>(Filtered)</span>
                      </>
                    ) : (
                      <>
                        Total Findings: <strong>{totalFindings}</strong>
                      </>
                    )}
                  </span>
                </div>

                {/* Findings Results */}
                {rawFindings.length === 0 ? (
                  <div className="cs-filter-empty-box" style={{ padding: '40px 20px' }}>
                    <div style={{ fontSize: '32px' }}>🛡️</div>
                    <div style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A' }}>
                      No Security Findings Reported
                    </div>
                    <p style={{ fontSize: '13px', color: '#64748B', maxWidth: '440px', margin: 0, lineHeight: 1.5 }}>
                      This scan completed with an authoritative <code>ALLOW</code> verdict. No vulnerabilities were detected.
                    </p>
                  </div>
                ) : filteredFindings.length === 0 ? (
                  <div className="cs-filter-empty-box">
                    <div style={{ fontSize: '28px' }}>🔍</div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: '#0F172A' }}>
                      No findings match your filters
                    </div>
                    <p style={{ fontSize: '12.5px', color: '#64748B', margin: 0 }}>
                      No findings matched your search query or selected severity level.
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

                      return (
                        <div key={finding.finding_id || idx} className="cs-finding-row-card">
                          <div className="cs-finding-row-top">
                            <div className="cs-finding-row-meta">
                              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#94A3B8' }}>
                                #{idx + 1}
                              </span>
                              <StatusBadge status={fSeverity} />
                              <h4 className="cs-finding-row-title">{fTitle}</h4>
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

                            <button
                              type="button"
                              className="cs-finding-inspect-btn"
                              onClick={() => setInspectingFinding(finding)}
                              aria-label={`Inspect details for ${fTitle}`}
                            >
                              Inspect Details →
                            </button>
                          </div>

                          {/* Location & AST Signal */}
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', fontSize: '12px' }}>
                            {fLocation && (
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', color: '#0284C7' }}>
                                <CodeFileIcon size={14} color="#64748B" />
                                <span>{fLocation}</span>
                              </div>
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
                          </div>

                          {/* Brief Description */}
                          {finding.description && (
                            <p style={{ margin: 0, fontSize: '12.5px', color: '#475569', lineHeight: 1.45 }}>
                              {finding.description}
                            </p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </>
          )}

          {/* Finding Inspection Modal */}
          <FindingPreviewModal
            isOpen={Boolean(inspectingFinding)}
            onClose={() => setInspectingFinding(null)}
            finding={inspectingFinding}
          />
        </div>
      ) : (
        /* Historical Audit Trail List */
        <>
          {/* Header */}
          <div className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
                  Security Analysis History & Audit Trail
                </h1>
                <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
                  Permanent record of past code scans, repository analyses, and security gate verdicts.
                </p>
              </div>

              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => fetchHistory(offset)}
                disabled={loading}
              >
                ↻ Refresh History
              </button>
            </div>
          </div>

          {error && (
            <div className="alert-box alert-error">
              <div>
                <strong>Error:</strong> {error}
              </div>
            </div>
          )}

          {/* Main Table or Empty State */}
          {loading ? (
            <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
              <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Loading audit records from persistent store...
              </div>
            </div>
          ) : analyses.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">📋</div>
              <div className="empty-state-title">No analyses yet</div>
              <p className="empty-state-desc">
                No historical records found. Run a code analysis or scan a repository to populate the audit log.
              </p>
            </div>
          ) : (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Analysis ID</th>
                      <th>Date / Time</th>
                      <th>Target / Query</th>
                      <th>Findings</th>
                      <th>Verdict</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analyses.map((item) => {
                      const id = item.analysis_id;
                      const s = item.summary || {};
                      const findingsCount = item.finding_count ?? s.total_findings ?? 0;
                      const verdict = item.review_status || s._review_status || (
                        (s.critical_count > 0 || s.high_count > 0) ? 'BLOCK' :
                        (s.medium_count > 0) ? 'REVIEW' : 'ALLOW'
                      );

                      return (
                        <tr
                          key={id}
                          onClick={() => handleSelectRecord(id)}
                          style={{
                            cursor: 'pointer',
                          }}
                        >
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#0284C7' }}>
                            {id}
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Recent'}
                          </td>
                          <td style={{ fontSize: '13px' }}>
                            {item.query || 'Source Code Analysis'}
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>
                            {findingsCount} {findingsCount === 1 ? 'finding' : 'findings'}
                          </td>
                          <td>
                            <StatusBadge status={verdict} />
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {item.status || 'completed'}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              style={{ marginRight: '6px' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                handleSelectRecord(id);
                              }}
                            >
                              Details →
                            </button>
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={(e) => handleDeleteRecord(id, e)}
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 16px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  borderTop: '1px solid var(--border-subtle)',
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                <span style={{ color: 'var(--text-muted)' }}>
                  Showing {offset + 1} - {Math.min(offset + limit, totalCount)} of {totalCount} records
                </span>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handlePrev}
                    disabled={offset === 0}
                  >
                    ← Prev
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleNext}
                    disabled={offset + limit >= totalCount}
                  >
                    Next →
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
