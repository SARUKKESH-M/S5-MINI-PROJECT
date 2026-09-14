import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  getPlatformHealth,
  getPlatformReadiness,
  getPlatformReleaseReadiness,
  getPlatformInfo,
  getPlatformPolicies,
  getPlatformMetrics,
} from '../services/apiClient';
import StatusBadge from '../components/StatusBadge';
import {
  ToolsIcon,
  AnalyzeIcon,
  RepositoriesIcon,
  PullRequestsIcon,
  ReviewsIcon,
  AnalyticsIcon,
  ShieldLogo,
} from '../components/dashboard/Icons';

/**
 * Sanitize error messages to avoid displaying local filesystem paths,
 * database paths, environment variables, or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred while executing tool operation.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

const TOOL_CATEGORIES = [
  { id: 'ALL', label: 'All Tools' },
  { id: 'DIAGNOSTICS', label: 'Diagnostics & Release' },
  { id: 'SECURITY', label: 'Security & Policies' },
  { id: 'ANALYSIS', label: 'Analysis Engines' },
  { id: 'INTEGRATION', label: 'GitHub & CI/CD' },
];

export default function ToolsView() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Data states
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [platformInfo, setPlatformInfo] = useState(null);
  const [platformHealth, setPlatformHealth] = useState(null);
  const [platformReadiness, setPlatformReadiness] = useState(null);
  const [releaseReadiness, setReleaseReadiness] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [metrics, setMetrics] = useState(null);

  // Active Tool UI states
  const [selectedPolicyName, setSelectedPolicyName] = useState('default');
  const [probingReadiness, setProbingReadiness] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Active category from URL or default
  const activeCategory = searchParams.get('category')?.toUpperCase() || 'ALL';

  const setCategory = (cat) => {
    if (cat === 'ALL') {
      searchParams.delete('category');
      setSearchParams(searchParams, { replace: true });
    } else {
      setSearchParams({ ...Object.fromEntries(searchParams.entries()), category: cat.toLowerCase() }, { replace: true });
    }
  };

  // Fetch all supported backend diagnostics and telemetry
  const loadPlatformData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [infoRes, healthRes, readinessRes, releaseRes, policiesRes, metricsRes] = await Promise.allSettled([
        getPlatformInfo(),
        getPlatformHealth(),
        getPlatformReadiness(),
        getPlatformReleaseReadiness(),
        getPlatformPolicies(),
        getPlatformMetrics(),
      ]);

      if (infoRes.status === 'fulfilled' && infoRes.value) setPlatformInfo(infoRes.value);
      if (healthRes.status === 'fulfilled' && healthRes.value) setPlatformHealth(healthRes.value);
      if (readinessRes.status === 'fulfilled' && readinessRes.value) setPlatformReadiness(readinessRes.value);
      if (releaseRes.status === 'fulfilled' && releaseRes.value) setReleaseReadiness(releaseRes.value);

      if (policiesRes.status === 'fulfilled' && Array.isArray(policiesRes.value)) {
        setPolicies(policiesRes.value);
        if (policiesRes.value.length > 0 && !selectedPolicyName) {
          setSelectedPolicyName(policiesRes.value[0].name || 'default');
        }
      }

      if (metricsRes.status === 'fulfilled' && metricsRes.value) setMetrics(metricsRes.value);
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to initialize platform tools.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPlatformData();
  }, []);

  // Re-run Release Readiness verification on demand
  const handleProbeReadiness = async () => {
    setProbingReadiness(true);
    try {
      const res = await getPlatformReleaseReadiness();
      setReleaseReadiness(res);
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Readiness verification probe failed.'));
    } finally {
      setProbingReadiness(false);
    }
  };

  // Currently selected policy profile object
  const activePolicy = useMemo(() => {
    if (!Array.isArray(policies) || policies.length === 0) return null;
    return policies.find((p) => p.name === selectedPolicyName) || policies[0];
  }, [policies, selectedPolicyName]);

  // Catalog of supported tools
  const toolCatalog = useMemo(() => {
    return [
      {
        id: 'release-verifier',
        name: 'Platform Release Readiness Verifier',
        category: 'DIAGNOSTICS',
        description: 'Evaluates platform release readiness across configuration, health diagnostics, policy engine, Step 6O security gate, and static non-execution boundary.',
        inputs: 'None (Direct server-side subsystem diagnostic probe)',
        outputs: 'Structured subsystem verification statuses (PASS/FAIL) and release readiness status',
        authority: 'Backend Release Engine (Step 6W-16)',
        status: releaseReadiness?.release_ready ? 'READY' : 'DEGRADED',
        type: 'INTERACTIVE_READINESS',
      },
      {
        id: 'policy-inspector',
        name: 'Security Policy Profile Inspector',
        category: 'SECURITY',
        description: 'Inspect authoritative security analysis policy profiles, severity thresholds, max file scopes, and blocking rules enforced by the Step 6O security gate.',
        inputs: 'Policy profile selection (default, strict, ci, developer)',
        outputs: 'Severity thresholds, enabled vulnerability categories, file limits, and blocking actions',
        authority: 'Backend Policy Engine (Read-Only)',
        status: 'AVAILABLE',
        type: 'INTERACTIVE_POLICIES',
      },
      {
        id: 'platform-telemetry',
        name: 'Telemetry & Observability Metrics',
        category: 'DIAGNOSTICS',
        description: 'Live observability counters tracking total analyses requested, gate decision distributions (ALLOW / REVIEW / BLOCK), cache performance, and analysis durations.',
        inputs: 'None (Server-side metrics collector)',
        outputs: 'Execution counts, gate decision breakdown, cache hit/miss ratio, and average duration',
        authority: 'Backend Metrics Engine',
        status: 'AVAILABLE',
        type: 'INTERACTIVE_METRICS',
      },
      {
        id: 'source-analysis',
        name: 'Source Code Security Analysis',
        category: 'ANALYSIS',
        description: 'Execute deterministic AST static analysis on submitted Python code snippets with hybrid RAG knowledge matching and Step 6O security gate evaluation.',
        inputs: 'Source code snippet (UTF-8 Python)',
        outputs: 'Structured security findings, AST signals, line locations, and security gate decision',
        authority: 'Analysis Engine & Step 6O',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'Open Analysis Studio →',
        onAction: () => navigate('/analyze'),
      },
      {
        id: 'repository-analysis',
        name: 'Repository Intake & Workspace Analysis',
        category: 'ANALYSIS',
        description: 'Ingest and acquire multi-file GitHub repositories into isolated workspaces to analyze full project dependencies and directory structures without source exposure.',
        inputs: 'GitHub HTTPS repository URL and branch reference',
        outputs: 'Repository intake metadata, file inventory, and multi-file vulnerability scan',
        authority: 'Repository Orchestrator',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'Open Repository Workspace →',
        onAction: () => navigate('/repositories'),
      },
      {
        id: 'pr-integration',
        name: 'GitHub Pull Request Security Gate',
        category: 'INTEGRATION',
        description: 'Audit Pull Requests and inspect incoming webhook deliveries with HMAC-SHA256 signature verification and diff-scoped changed-line AST evaluation.',
        inputs: 'GitHub webhook deliveries or PR branch refs',
        outputs: 'Diff-scoped findings and authoritative merge gate decisions (ALLOW / REVIEW / BLOCK)',
        authority: 'PR Orchestrator & Diff Scope',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'Open Pull Requests →',
        onAction: () => navigate('/pull-requests'),
      },
      {
        id: 'security-review',
        name: 'Security Finding Review & False Positives',
        category: 'SECURITY',
        description: 'Investigate detected vulnerabilities, inspect code evidence and AST signals, and record auditable false-positive suppressions with reason taxonomy.',
        inputs: 'Analysis ID and finding identifier with structured justification',
        outputs: 'Persistent suppression audit trail and adjusted repository posture',
        authority: 'AnalysisStore (Persistent)',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'Open Security Review →',
        onAction: () => navigate('/reviews'),
      },
      {
        id: 'analytics-v2',
        name: 'Security Intelligence & Trend Analytics',
        category: 'SECURITY',
        description: 'Consolidated vulnerability analytics across CWE categories, historical security trends, repository risk benchmarking, and false-positive telemetry.',
        inputs: 'Time window filter (7d, 30d, 90d, all) and repository selector',
        outputs: 'Category breakdown, MTTR metrics, severity distributions, and repository risk ranks',
        authority: 'Security Analytics V2',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'Open Analytics Workspace →',
        onAction: () => navigate('/analytics'),
      },
      {
        id: 'audit-history',
        name: 'Security Audit Trail & History',
        category: 'DIAGNOSTICS',
        description: 'Permanent chronological archive of past repository scans, pull request evaluations, and security gate verdicts with complete finding records.',
        inputs: 'Analysis ID or date query',
        outputs: 'Immutable audit records, execution timestamps, and comprehensive finding manifests',
        authority: 'AnalysisStore History',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'View Audit History →',
        onAction: () => navigate('/history'),
      },
      {
        id: 'system-diagnostics',
        name: 'System Health & Component Probes',
        category: 'DIAGNOSTICS',
        description: 'Deep diagnostic dashboard for low-level health checks, readiness probes, and database storage status.',
        inputs: 'None (Real-time polling)',
        outputs: 'Database probe, memory stats, and service uptime status',
        authority: 'Platform Core Health',
        status: 'AVAILABLE',
        type: 'WORKSPACE',
        actionLabel: 'View System Diagnostics →',
        onAction: () => navigate('/system'),
      },
    ];
  }, [releaseReadiness, navigate]);

  // Filtered tools list based on active category and search query
  const filteredTools = useMemo(() => {
    return toolCatalog.filter((tool) => {
      // Category filter
      if (activeCategory !== 'ALL' && tool.category !== activeCategory) {
        return false;
      }
      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matches =
          tool.name.toLowerCase().includes(q) ||
          tool.description.toLowerCase().includes(q) ||
          tool.inputs.toLowerCase().includes(q) ||
          tool.authority.toLowerCase().includes(q);
        if (!matches) return false;
      }
      return true;
    });
  }, [toolCatalog, activeCategory, searchQuery]);

  return (
    <div className="cs-tools-view" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Banner */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <ToolsIcon size={20} color="#6366F1" />
              <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                CodeSentinel Operational &amp; Security Tools
              </h1>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
              Central hub for automated release verification, security policy profile inspection, and direct access to integrated analysis capabilities.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Version: <strong>{platformInfo?.version || 'v1.1.0'}</strong>
            </span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={loadPlatformData}
              disabled={loading}
              aria-label="Refresh tools and diagnostic telemetry"
            >
              ↻ Refresh Tools
            </button>
          </div>
        </div>

        {/* Global Subsystem Telemetry Quick Ribbon */}
        {metrics && (
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '10px',
              padding: '12px',
              backgroundColor: 'var(--bg-void)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '6px',
              marginTop: '16px',
              textAlign: 'center',
            }}
          >
            <div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Analyses Scanned</div>
              <strong style={{ fontSize: '16px', color: 'var(--text-primary)' }}>{metrics.analysis_requests_total ?? 0}</strong>
            </div>
            <div>
              <div style={{ fontSize: '10.5px', color: '#10B981', fontWeight: 600, textTransform: 'uppercase' }}>Gate Allowed</div>
              <strong style={{ fontSize: '16px', color: '#10B981' }}>{metrics.decisions_allow_total ?? 0}</strong>
            </div>
            <div>
              <div style={{ fontSize: '10.5px', color: '#F59E0B', fontWeight: 600, textTransform: 'uppercase' }}>Gate Review</div>
              <strong style={{ fontSize: '16px', color: '#F59E0B' }}>{metrics.decisions_review_total ?? 0}</strong>
            </div>
            <div>
              <div style={{ fontSize: '10.5px', color: '#EF4444', fontWeight: 600, textTransform: 'uppercase' }}>Gate Blocked</div>
              <strong style={{ fontSize: '16px', color: '#EF4444' }}>{metrics.decisions_block_total ?? 0}</strong>
            </div>
            <div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Health Probes</div>
              <strong style={{ fontSize: '16px', color: '#6366F1' }}>{metrics.health_checks_total ?? 0}</strong>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="alert-box alert-error" role="alert">
          <div>{error}</div>
        </div>
      )}

      {/* Category Navigation & Search Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        {/* Category Filter Pills */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }} role="tablist" aria-label="Tool Categories">
          {TOOL_CATEGORIES.map((cat) => {
            const isSelected = activeCategory === cat.id;
            return (
              <button
                key={cat.id}
                type="button"
                role="tab"
                aria-selected={isSelected}
                onClick={() => setCategory(cat.id)}
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  padding: '6px 12px',
                  borderRadius: '6px',
                  border: isSelected ? '1px solid #6366F1' : '1px solid var(--border-subtle)',
                  background: isSelected ? '#6366F1' : 'var(--bg-card)',
                  color: isSelected ? '#FFFFFF' : 'var(--text-muted)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {cat.label}
              </button>
            );
          })}
        </div>

        {/* Search Filter */}
        <input
          type="text"
          className="cs-explorer-search-input"
          style={{ width: '220px', fontSize: '12px', padding: '6px 12px' }}
          placeholder="Filter tools by capability..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          aria-label="Filter available tools"
        />
      </div>

      {/* Loading state */}
      {loading ? (
        <div className="card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Loading platform capabilities and tools...
        </div>
      ) : filteredTools.length === 0 ? (
        <div className="card empty-state" style={{ padding: '40px 20px', textAlign: 'center' }}>
          <div className="empty-state-icon" style={{ fontSize: '32px' }} aria-hidden="true">🛠️</div>
          <div className="empty-state-title" style={{ fontSize: '15px', fontWeight: 700 }}>No Tools Found</div>
          <p className="empty-state-desc" style={{ fontSize: '12.5px', maxWidth: '320px', margin: '6px auto 14px' }}>
            No tools matched your current category or search filter.
          </p>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => {
              setCategory('ALL');
              setSearchQuery('');
            }}
          >
            Reset Filters
          </button>
        </div>
      ) : (
        /* Tools List / Grid */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {filteredTools.map((tool) => {
            return (
              <div key={tool.id} className="card" style={{ padding: '20px' }}>
                {/* Tool Header */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', marginBottom: '10px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                        {tool.name}
                      </h2>
                      <span
                        style={{
                          fontSize: '10.5px',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          backgroundColor: 'rgba(99, 102, 241, 0.08)',
                          color: '#4F46E5',
                          border: '1px solid rgba(99, 102, 241, 0.2)',
                          textTransform: 'uppercase',
                        }}
                      >
                        {tool.category}
                      </span>
                    </div>
                    <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: '4px 0 0', lineHeight: 1.45 }}>
                      {tool.description}
                    </p>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <StatusBadge status={tool.status} />
                  </div>
                </div>

                {/* Tool Contract Metadata Grid */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                    gap: '10px',
                    padding: '10px 14px',
                    backgroundColor: 'var(--bg-void)',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                    margin: '12px 0',
                    fontSize: '11.5px',
                  }}
                >
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>Input Required:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{tool.inputs}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>Output Produced:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{tool.outputs}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>Governing Authority:</span>
                    <span style={{ color: '#0284C7', fontWeight: 600 }}>{tool.authority}</span>
                  </div>
                </div>

                {/* Specific Tool Content: Interactive Release Readiness Tool */}
                {tool.type === 'INTERACTIVE_READINESS' && (
                  <div style={{ marginTop: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        Subsystem Verification Statuses ({releaseReadiness ? Object.keys(releaseReadiness.subsystems || {}).length : 0})
                      </span>

                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={handleProbeReadiness}
                        disabled={probingReadiness}
                      >
                        {probingReadiness ? 'Evaluating Subsystems...' : '⚡ Run Verification Probe'}
                      </button>
                    </div>

                    {releaseReadiness?.subsystems ? (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
                        {Object.entries(releaseReadiness.subsystems).map(([key, sub]) => (
                          <div
                            key={key}
                            style={{
                              padding: '10px 12px',
                              borderRadius: '6px',
                              border: '1px solid var(--border-subtle)',
                              backgroundColor: 'var(--bg-card)',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '4px',
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                              <strong style={{ fontSize: '12px', color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                                {key.replace(/_/g, ' ')}
                              </strong>
                              <StatusBadge status={sub.status || (sub.ready ? 'PASS' : 'FAIL')} />
                            </div>
                            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              {sub.details || 'Operational'}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                        Readiness verification data unavailable.
                      </div>
                    )}
                  </div>
                )}

                {/* Specific Tool Content: Interactive Policy Profile Inspector */}
                {tool.type === 'INTERACTIVE_POLICIES' && (
                  <div style={{ marginTop: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        Select Policy Profile:
                      </span>
                      {policies.map((p) => (
                        <button
                          key={p.name}
                          type="button"
                          onClick={() => setSelectedPolicyName(p.name)}
                          className={`btn btn-sm ${selectedPolicyName === p.name ? 'btn-primary' : 'btn-secondary'}`}
                          style={{ fontSize: '11px', padding: '3px 10px' }}
                        >
                          {p.name.toUpperCase()}
                        </button>
                      ))}
                    </div>

                    {activePolicy && (
                      <div
                        style={{
                          padding: '14px',
                          borderRadius: '6px',
                          border: '1px solid var(--border-subtle)',
                          backgroundColor: 'var(--bg-card)',
                        }}
                      >
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '10px', marginBottom: '12px' }}>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Severity Threshold</span>
                            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                              {String(activePolicy.severity_threshold).toUpperCase()}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Max File Scope</span>
                            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                              {activePolicy.max_files} files
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Review Action</span>
                            <div style={{ fontSize: '13px', fontWeight: 700, color: '#F59E0B' }}>
                              {String(activePolicy.review_action).toUpperCase()}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Block Action</span>
                            <div style={{ fontSize: '13px', fontWeight: 700, color: '#EF4444' }}>
                              {String(activePolicy.block_action).toUpperCase()}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Block On Critical</span>
                            <div style={{ fontSize: '13px', fontWeight: 700, color: activePolicy.block_on_critical ? '#EF4444' : '#10B981' }}>
                              {activePolicy.block_on_critical ? 'YES (Enforced)' : 'NO'}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Block On High</span>
                            <div style={{ fontSize: '13px', fontWeight: 700, color: activePolicy.block_on_high ? '#EF4444' : '#10B981' }}>
                              {activePolicy.block_on_high ? 'YES (Enforced)' : 'NO'}
                            </div>
                          </div>
                        </div>

                        <div>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
                            Enabled Vulnerability Categories ({activePolicy.enabled_categories?.length || 0}):
                          </span>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {(activePolicy.enabled_categories || []).map((cat) => (
                              <span
                                key={cat}
                                style={{
                                  fontSize: '11px',
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  backgroundColor: 'var(--bg-void)',
                                  border: '1px solid var(--border-subtle)',
                                  color: 'var(--text-primary)',
                                  fontFamily: 'var(--font-mono)',
                                }}
                              >
                                {cat}
                              </span>
                            ))}
                          </div>
                        </div>

                        <p style={{ fontSize: '11px', color: 'var(--text-muted)', margin: '10px 0 0', fontStyle: 'italic' }}>
                          ℹ️ Read-only policy inspector. Security policies are authoritative server configurations evaluated deterministically by the Step 6O Security Gate.
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* Specific Tool Content: Interactive Metrics Telemetry */}
                {tool.type === 'INTERACTIVE_METRICS' && metrics && (
                  <div style={{ marginTop: '12px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                      <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                        <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Analysis Requests</span>
                        <div style={{ fontSize: '15px', fontWeight: 700 }}>{metrics.analysis_requests_total ?? 0} total</div>
                        <div style={{ fontSize: '11px', color: '#10B981' }}>✓ {metrics.analysis_success_total ?? 0} successful</div>
                      </div>

                      <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                        <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Gate Decisions Breakdown</span>
                        <div style={{ fontSize: '11.5px', marginTop: '2px' }}>
                          <span style={{ color: '#10B981' }}>ALLOW: {metrics.decisions_allow_total ?? 0}</span> |{' '}
                          <span style={{ color: '#F59E0B' }}>REVIEW: {metrics.decisions_review_total ?? 0}</span> |{' '}
                          <span style={{ color: '#EF4444' }}>BLOCK: {metrics.decisions_block_total ?? 0}</span>
                        </div>
                      </div>

                      <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                        <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Deterministic Cache</span>
                        <div style={{ fontSize: '12px', marginTop: '2px' }}>
                          Hits: <strong>{metrics.cache_hits_total ?? 0}</strong> / Misses: <strong>{metrics.cache_misses_total ?? 0}</strong>
                        </div>
                      </div>

                      <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                        <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Last Scan Duration</span>
                        <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                          {(metrics.last_analysis_duration_ms || 0).toFixed(1)} ms
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Workspace Launcher Actions (Step 4 & 8) */}
                {tool.type === 'WORKSPACE' && (
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={tool.onAction}
                    >
                      {tool.actionLabel}
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
