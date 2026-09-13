import React, { useState, useEffect } from 'react';
import { getAnalyses, getAnalysis, deleteAnalysis } from '../services/apiClient';
import FindingCard from '../components/FindingCard';
import StatusBadge from '../components/StatusBadge';

export default function HistoryView() {
  const [analyses, setAnalyses] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pagination state
  const [offset, setOffset] = useState(0);
  const limit = 15;

  // Selected analysis for detail drawer / modal
  const [selectedId, setSelectedId] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [detailError, setDetailError] = useState(null);

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

  const handleSelectRecord = async (analysisId) => {
    if (selectedId === analysisId) {
      // Toggle off
      setSelectedId(null);
      setSelectedRecord(null);
      return;
    }

    setSelectedId(analysisId);
    setDetailLoading(true);
    setDetailError(null);

    try {
      const res = await getAnalysis(analysisId);
      setSelectedRecord(res.analysis || res);
    } catch (err) {
      setDetailError(err.message || 'Failed to load analysis details.');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleDeleteRecord = async (analysisId, e) => {
    e.stopPropagation();
    if (!window.confirm(`Are you sure you want to delete analysis '${analysisId}'?`)) {
      return;
    }

    try {
      await deleteAnalysis(analysisId);
      if (selectedId === analysisId) {
        setSelectedId(null);
        setSelectedRecord(null);
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Security Analysis History & Audit Trail
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
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
                  const isSelected = selectedId === id;

                  return (
                    <tr
                      key={id}
                      onClick={() => handleSelectRecord(id)}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: isSelected ? 'var(--bg-surface-active)' : undefined,
                      }}
                    >
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-blue)' }}>
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
                          {isSelected ? 'Hide' : 'Details'}
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

      {/* Selected Analysis Detail Section */}
      {selectedId && (
        <div className="card" style={{ padding: '20px', borderColor: 'var(--border-default)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                INSPECTING RECORD: {selectedId}
              </div>
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Detailed Analysis Findings
              </h3>
            </div>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                setSelectedId(null);
                setSelectedRecord(null);
              }}
            >
              Close Details ✕
            </button>
          </div>

          {detailLoading ? (
            <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
              Loading findings for {selectedId}...
            </div>
          ) : detailError ? (
            <div className="alert-box alert-error">
              <div>{detailError}</div>
            </div>
          ) : selectedRecord ? (
            <div>
              {/* Findings */}
              {Array.isArray(selectedRecord.findings) && selectedRecord.findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {selectedRecord.findings.map((finding, idx) => (
                    <FindingCard key={finding.finding_id || idx} finding={finding} index={idx} />
                  ))}
                </div>
              ) : (
                <div className="alert-box alert-success" style={{ margin: 0 }}>
                  <div>
                    No vulnerabilities were recorded for this analysis. Gate decision: <code>ALLOW</code>.
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
