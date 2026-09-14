import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getAnalyses,
  getAnalysis,
  getPlatformInfo,
  getPlatformHealth,
} from '../services/apiClient';
import FindingCard from '../components/FindingCard';
import StatusBadge from '../components/StatusBadge';
import { CodeFileIcon, PullRequestsIcon } from '../components/dashboard/Icons';

/**
 * Sanitize error messages to avoid displaying local filesystem paths,
 * database paths, environment variables, or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred during Pull Request operation.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

/**
 * Normalize repository identifier from repo metadata.
 */
function getRepoIdentifier(repoMeta) {
  if (!repoMeta) return 'SARUKKESH-M/S5-MINI-PROJECT';
  if (typeof repoMeta === 'string') return repoMeta;
  const owner = repoMeta.owner || '';
  const name = repoMeta.repository || repoMeta.name || '';
  if (owner && name) return `${owner}/${name}`;
  return name || owner || 'SARUKKESH-M/S5-MINI-PROJECT';
}

export default function PullRequestsView() {
  const navigate = useNavigate();

  // PR Analyses & Telemetry State
  const [prAnalyses, setPrAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [platformInfo, setPlatformInfo] = useState(null);
  const [isHealthy, setIsHealthy] = useState(true);

  // Selected PR Detail State
  const [selectedPrId, setSelectedPrId] = useState(null);
  const [selectedPrDetail, setSelectedPrDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  // Client-side search filter
  const [searchQuery, setSearchQuery] = useState('');

  // Quick PR Branch Scan Inputs
  const [quickRepoUrl, setQuickRepoUrl] = useState('https://github.com/SARUKKESH-M/S5-MINI-PROJECT');
  const [quickBranch, setQuickBranch] = useState('main');
  const [scanFormError, setScanFormError] = useState(null);

  // Double-submission protection ref
  const isSubmittingRef = useRef(false);

  // Load all analyses and filter for PR records
  const loadPrData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [analysesRes, infoRes, healthRes] = await Promise.allSettled([
        getAnalyses({ limit: 100 }),
        getPlatformInfo(),
        getPlatformHealth(),
      ]);

      if (infoRes.status === 'fulfilled' && infoRes.value) {
        setPlatformInfo(infoRes.value);
      }

      if (healthRes.status === 'fulfilled' && healthRes.value) {
        setIsHealthy(String(healthRes.value.status).toLowerCase() === 'healthy');
      }

      if (analysesRes.status === 'fulfilled' && Array.isArray(analysesRes.value?.analyses)) {
        const rawList = analysesRes.value.analyses;

        // Filter for analyses associated with PRs or PR branches
        const prList = rawList.filter((item) => {
          const summary = item.summary || {};
          const repoMeta = summary._repository || item.repository || {};
          const branch = String(repoMeta.branch || '').toLowerCase();
          const hasPrNum = Boolean(
            repoMeta.pr_number ||
            summary.pr_number ||
            item.pr_number
          );
          const hasPrBranch = branch.startsWith('pr/') || branch.startsWith('pull/') || branch.includes('/pr/');
          return hasPrNum || hasPrBranch;
        });

        setPrAnalyses(prList);

        // Auto-select first item if none selected and records exist
        if (prList.length > 0 && !selectedPrId) {
          handleSelectPr(prList[0].analysis_id);
        }
      } else {
        setPrAnalyses([]);
      }
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to retrieve Pull Request records.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPrData();
  }, []);

  // Fetch full details of a selected PR analysis
  const handleSelectPr = async (analysisId) => {
    if (!analysisId) return;
    if (selectedPrId === analysisId && selectedPrDetail) return;

    setSelectedPrId(analysisId);
    setDetailLoading(true);
    setDetailError(null);

    try {
      const res = await getAnalysis(analysisId);
      setSelectedPrDetail(res.analysis || res);
    } catch (err) {
      setDetailError(sanitizeErrorMessage(err.message || 'Failed to load Pull Request details.'));
    } finally {
      setDetailLoading(false);
    }
  };

  // Filtered PR list based on search query
  const filteredPrs = useMemo(() => {
    if (!searchQuery.trim()) return prAnalyses;
    const q = searchQuery.toLowerCase().trim();
    return prAnalyses.filter((item) => {
      const summary = item.summary || {};
      const repoMeta = summary._repository || item.repository || {};
      const repoName = getRepoIdentifier(repoMeta).toLowerCase();
      const prNum = String(repoMeta.pr_number || summary.pr_number || item.pr_number || '');
      const branch = String(repoMeta.branch || '').toLowerCase();
      const author = String(repoMeta.author || summary.author || item.author || '').toLowerCase();
      const gate = String(summary._review_status || item.review_status || '').toLowerCase();
      return (
        repoName.includes(q) ||
        prNum.includes(q) ||
        branch.includes(q) ||
        author.includes(q) ||
        gate.includes(q)
      );
    });
  }, [prAnalyses, searchQuery]);

  // Navigate to Analyze Studio for PR branch scan
  const handleQuickScan = (e) => {
    e.preventDefault();
    if (isSubmittingRef.current) return;

    const cleanUrl = quickRepoUrl.trim();
    const cleanBranch = quickBranch.trim();

    if (!cleanUrl) {
      setScanFormError('Repository URL is required.');
      return;
    }
    if (!cleanUrl.startsWith('https://github.com/')) {
      setScanFormError('Only GitHub HTTPS URLs (https://github.com/owner/repo) are supported.');
      return;
    }
    if (!cleanBranch) {
      setScanFormError('PR branch/ref name cannot be empty.');
      return;
    }

    isSubmittingRef.current = true;
    setScanFormError(null);

    navigate('/analyze', {
      state: {
        repo: cleanUrl,
        repoUrl: cleanUrl,
        repository_url: cleanUrl,
        branch: cleanBranch,
      },
    });
  };

  // Selected PR metadata helper
  const activePrMeta = useMemo(() => {
    if (!selectedPrDetail) return null;
    const summary = selectedPrDetail.summary || {};
    const repoMeta = selectedPrDetail.repository || summary._repository || {};
    const owner = repoMeta.owner || selectedPrDetail.owner || '';
    const repo = repoMeta.repository || selectedPrDetail.repository_id || '';
    const prNumber = repoMeta.pr_number || summary.pr_number || selectedPrDetail.pr_number || null;
    const headSha = repoMeta.head_sha || selectedPrDetail.head_sha || null;
    const baseSha = repoMeta.base_sha || selectedPrDetail.base_sha || null;
    const branch = repoMeta.branch || 'main';
    const author = repoMeta.author || summary.author || selectedPrDetail.author || '—';
    const gate = String(selectedPrDetail.review_status || summary._review_status || 'ALLOW').toUpperCase();
    const findings = Array.isArray(selectedPrDetail.findings) ? selectedPrDetail.findings : [];

    return {
      repoName: owner && repo ? `${owner}/${repo}` : getRepoIdentifier(repoMeta),
      owner,
      repo,
      prNumber: prNumber ? `#${prNumber}` : '—',
      headSha: headSha ? headSha.slice(0, 8) : '—',
      fullHeadSha: headSha,
      baseSha: baseSha ? baseSha.slice(0, 8) : '—',
      branch,
      author,
      gate,
      findings,
      summary,
      created_at: selectedPrDetail.created_at
        ? new Date(selectedPrDetail.created_at).toLocaleString()
        : '—',
    };
  }, [selectedPrDetail]);

  return (
    <div className="cs-pr-workspace-view">
      {/* Header Card */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
              GitHub &amp; Pull Request Security Integration
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
              Audit Pull Requests, inspect webhook deliveries, and enforce automated CI/CD security gate policies.
            </p>
          </div>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={loadPrData}
            disabled={loading}
          >
            ↻ Refresh PR Telemetry
          </button>
        </div>

        {/* Webhook Ingress Architecture & Status Ribbon */}
        <div
          className="cs-pr-webhook-card"
          style={{ marginTop: '16px' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '18px' }}>⚡</span>
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#0F172A' }}>
                  GitHub Webhook Ingress Active
                </div>
                <div style={{ fontSize: '11.5px', color: '#64748B' }}>
                  Ingress Endpoint: <span className="cs-pr-endpoint-pill">POST /github/webhook</span>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className="cs-pr-tag">HMAC-SHA256 Enforced</span>
              <span className="cs-pr-tag">Diff-Scoped AST</span>
              <StatusBadge status={isHealthy ? 'ONLINE' : 'REVIEW'} />
            </div>
          </div>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: prAnalyses.length > 0 ? '1fr 1.6fr' : '1fr', gap: '20px' }}>
        {/* Left Column: PR Audits List */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Pull Request Security Records ({prAnalyses.length})
              </h3>
            </div>

            <input
              type="text"
              className="cs-explorer-search-input"
              style={{ width: '180px', fontSize: '12px', padding: '5px 10px' }}
              placeholder="Search PRs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {error && (
            <div className="alert-box alert-error" style={{ marginBottom: '14px' }}>
              <div>{error}</div>
            </div>
          )}

          {loading ? (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
              Loading Pull Request records...
            </div>
          ) : filteredPrs.length === 0 ? (
            prAnalyses.length === 0 ? (
              <div className="empty-state" style={{ padding: '36px 16px', textAlign: 'center' }}>
                <div className="empty-state-icon" style={{ fontSize: '32px', marginBottom: '10px' }}>🔀</div>
                <div className="empty-state-title" style={{ fontSize: '15px', fontWeight: 700 }}>
                  No Pull Request Records Found
                </div>
                <p className="empty-state-desc" style={{ fontSize: '12.5px', maxWidth: '340px', margin: '6px auto 16px' }}>
                  CodeSentinel automatically evaluates Pull Requests via GitHub webhooks (<code>POST /github/webhook</code>) or when PR branches are scanned in the studio.
                </p>
              </div>
            ) : (
              <div className="empty-state" style={{ padding: '24px 16px', textAlign: 'center' }}>
                <div className="empty-state-icon" style={{ fontSize: '24px' }}>🔍</div>
                <div className="empty-state-title" style={{ fontSize: '13.5px' }}>No Matching Pull Requests</div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ marginTop: '8px' }}
                  onClick={() => setSearchQuery('')}
                >
                  Clear Filter
                </button>
              </div>
            )
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {filteredPrs.map((item) => {
                const summary = item.summary || {};
                const repoMeta = summary._repository || item.repository || {};
                const repoName = getRepoIdentifier(repoMeta);
                const prNum = repoMeta.pr_number || summary.pr_number || item.pr_number;
                const prLabel = prNum ? `PR #${prNum}` : (repoMeta.branch || 'PR Review');
                const gate = String(summary._review_status || item.review_status || 'ALLOW').toUpperCase();
                const isSelected = selectedPrId === item.analysis_id;

                return (
                  <div
                    key={item.analysis_id}
                    onClick={() => handleSelectPr(item.analysis_id)}
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      border: isSelected ? '1.5px solid #6366F1' : '1px solid #E2E8F0',
                      backgroundColor: isSelected ? 'rgba(99, 102, 241, 0.04)' : '#FFFFFF',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 700, color: '#0F172A', fontFamily: 'var(--font-mono)' }}>
                        {prLabel}
                      </span>
                      <StatusBadge status={gate} />
                    </div>

                    <div style={{ fontSize: '12px', color: '#0284C7', fontWeight: 600, wordBreak: 'break-all' }}>
                      {repoName}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '6px', fontSize: '11px', color: '#64748B' }}>
                      <span>
                        Findings: <strong style={{ color: (item.finding_count ?? 0) > 0 ? '#EF4444' : '#10B981' }}>{item.finding_count ?? 0}</strong>
                      </span>
                      <span>
                        {item.created_at ? new Date(item.created_at).toLocaleDateString() : '—'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Quick Manual PR Scan Form */}
          <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid #E2E8F0' }}>
            <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 4px' }}>
              Scan PR Branch in Studio
            </h4>
            <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', margin: '0 0 12px' }}>
              Trigger an immediate security scan of a pull request head branch or ref.
            </p>

            <form onSubmit={handleQuickScan} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div>
                <label className="form-label" style={{ fontSize: '11px' }}>Repository HTTPS URL</label>
                <input
                  type="text"
                  className="form-input"
                  style={{ fontSize: '12px', padding: '6px 10px' }}
                  value={quickRepoUrl}
                  onChange={(e) => setQuickRepoUrl(e.target.value)}
                  placeholder="https://github.com/owner/repo"
                />
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '11px' }}>PR Branch / Ref Name</label>
                <input
                  type="text"
                  className="form-input"
                  style={{ fontSize: '12px', padding: '6px 10px' }}
                  value={quickBranch}
                  onChange={(e) => setQuickBranch(e.target.value)}
                  placeholder="e.g. pr/12 or feature-branch"
                />
              </div>

              {scanFormError && (
                <div style={{ color: '#EF4444', fontSize: '11px', fontWeight: 600 }}>
                  {scanFormError}
                </div>
              )}

              <button
                type="submit"
                className="btn btn-primary btn-sm"
                style={{ marginTop: '4px' }}
              >
                Scan Branch in Studio →
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Selected PR Details */}
        <div className="card" style={{ padding: '20px' }}>
          {!selectedPrId ? (
            <div className="empty-state" style={{ padding: '60px 20px', textAlign: 'center' }}>
              <div className="empty-state-icon" style={{ fontSize: '36px' }}>📋</div>
              <div className="empty-state-title">Select a Pull Request</div>
              <p className="empty-state-desc" style={{ maxWidth: '320px', margin: '6px auto' }}>
                Select a Pull Request from the left panel to inspect its metadata, security gate verdict, and diff-scoped findings.
              </p>
            </div>
          ) : detailLoading ? (
            <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Loading Pull Request analysis details...
            </div>
          ) : detailError ? (
            <div className="alert-box alert-error">
              <div>{detailError}</div>
            </div>
          ) : activePrMeta ? (
            <div>
              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', marginBottom: '16px' }}>
                <div>
                  <div style={{ fontSize: '11px', color: '#64748B', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
                    {activePrMeta.repoName}
                  </div>
                  <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#0F172A', margin: '2px 0 0' }}>
                    {activePrMeta.prNumber} Security Audit
                  </h2>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '12px', color: '#64748B', fontWeight: 600 }}>GATE VERDICT:</span>
                  <StatusBadge status={activePrMeta.gate} size="large" />
                </div>
              </div>

              {/* PR Metadata Grid */}
              <div className="cs-pr-meta-grid">
                <div className="cs-pr-meta-box">
                  <span className="cs-pr-meta-label">Target Repository</span>
                  <span className="cs-pr-meta-value" style={{ fontSize: '12px' }}>{activePrMeta.repoName}</span>
                </div>

                <div className="cs-pr-meta-box">
                  <span className="cs-pr-meta-label">PR Branch</span>
                  <span className="cs-pr-meta-value" style={{ fontSize: '12px' }}>{activePrMeta.branch}</span>
                </div>

                <div className="cs-pr-meta-box">
                  <span className="cs-pr-meta-label">Head Commit SHA</span>
                  <span className="cs-pr-meta-value" style={{ fontSize: '12px' }}>{activePrMeta.headSha}</span>
                </div>

                <div className="cs-pr-meta-box">
                  <span className="cs-pr-meta-label">Author</span>
                  <span className="cs-pr-meta-value" style={{ fontSize: '12px' }}>{activePrMeta.author}</span>
                </div>

                <div className="cs-pr-meta-box">
                  <span className="cs-pr-meta-label">Analysis Timestamp</span>
                  <span className="cs-pr-meta-value" style={{ fontSize: '11px' }}>{activePrMeta.created_at}</span>
                </div>

                <div className="cs-pr-meta-box">
                  <span className="cs-pr-meta-label">Analysis Identifier</span>
                  <code className="cs-pr-meta-value" style={{ fontSize: '11px', color: '#0284C7' }}>{selectedPrId}</code>
                </div>
              </div>

              {/* Severity Counters Bar */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(5, minmax(0, 1fr))',
                  gap: '8px',
                  padding: '12px',
                  backgroundColor: 'var(--bg-void)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  textAlign: 'center',
                  margin: '18px 0',
                }}
              >
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)' }}>CRIT</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-critical)' }}>{activePrMeta.summary.critical_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-high)', fontFamily: 'var(--font-mono)' }}>HIGH</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-high)' }}>{activePrMeta.summary.high_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-medium)', fontFamily: 'var(--font-mono)' }}>MED</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-medium)' }}>{activePrMeta.summary.medium_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-low)', fontFamily: 'var(--font-mono)' }}>LOW</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-low)' }}>{activePrMeta.summary.low_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-info)', fontFamily: 'var(--font-mono)' }}>INFO</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-info)' }}>{activePrMeta.summary.info_count ?? 0}</strong>
                </div>
              </div>

              {/* Findings & Evidence */}
              <div style={{ marginBottom: '20px' }}>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                  Diff-Scoped Findings ({activePrMeta.findings.length})
                </div>

                {activePrMeta.findings.length === 0 ? (
                  <div className="alert-box alert-success">
                    <div>
                      <strong>✓ Clean Pull Request:</strong> No vulnerabilities detected in the changed file diffs. Gate verdict: <code>ALLOW</code>.
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {activePrMeta.findings.map((finding, idx) => (
                      <FindingCard key={finding.finding_id || idx} finding={finding} index={idx} />
                    ))}
                  </div>
                )}
              </div>

              {/* Action Navigation Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', paddingTop: '16px', borderTop: '1px solid #E2E8F0' }}>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate(`/history?id=${encodeURIComponent(selectedPrId)}`)}
                >
                  View Full Audit in History →
                </button>

                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate('/repositories', {
                    state: {
                      repo: activePrMeta.repoName,
                      branch: activePrMeta.branch,
                    },
                  })}
                >
                  Open in Repository Workspace →
                </button>

                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate('/analyze', {
                    state: {
                      repo: activePrMeta.repoName,
                      branch: activePrMeta.branch,
                    },
                  })}
                >
                  Scan Branch in Studio →
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
