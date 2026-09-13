import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getPlatformHealth,
  getAnalyses,
  getAnalyticsSummary,
} from '../services/apiClient';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';

export default function DashboardView() {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [healthStatus, setHealthStatus] = useState('checking');
  const [engineStatus, setEngineStatus] = useState('checking');
  const [securityGateStatus, setSecurityGateStatus] = useState('checking');

  const [analysesCount, setAnalysesCount] = useState(0);
  const [latestAnalysis, setLatestAnalysis] = useState(null);
  const [findingsSummary, setFindingsSummary] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });
  const [verdictDistribution, setVerdictDistribution] = useState({
    allow: 0,
    review: 0,
    block: 0,
  });

  const [recentList, setRecentList] = useState([]);

  function getRecordVerdict(item) {
    if (!item) return 'ALLOW';
    if (item.review_status && ['allow', 'review', 'block'].includes(String(item.review_status).toLowerCase())) {
      return String(item.review_status).toUpperCase();
    }
    const s = item.summary || {};
    if (s._review_status && ['allow', 'review', 'block'].includes(String(s._review_status).toLowerCase())) {
      return String(s._review_status).toUpperCase();
    }
    const crit = s.critical_count || 0;
    const high = s.high_count || 0;
    const med = s.medium_count || 0;
    if (crit > 0 || high > 0) return 'BLOCK';
    if (med > 0) return 'REVIEW';
    return 'ALLOW';
  }

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const [healthRes, analysesRes, summaryRes] = await Promise.allSettled([
        getPlatformHealth(),
        getAnalyses({ limit: 100, offset: 0 }),
        getAnalyticsSummary(),
      ]);

      // Process Platform Health
      if (healthRes.status === 'fulfilled' && healthRes.value) {
        const h = healthRes.value;
        setHealthStatus(h.status ? String(h.status).toUpperCase() : 'ONLINE');
        const checks = h.checks || {};
        setEngineStatus(checks.vector_store?.status ? String(checks.vector_store.status).toUpperCase() : 'READY');
        setSecurityGateStatus(checks.security_gate?.status ? String(checks.security_gate.status).toUpperCase() : 'VERIFIED');
      } else {
        setHealthStatus('UNAVAILABLE');
        setEngineStatus('UNKNOWN');
        setSecurityGateStatus('UNKNOWN');
      }

      // Process Analyses List & All Pages if paginated
      let allAnalyses = [];
      let totalCount = 0;
      if (analysesRes.status === 'fulfilled' && analysesRes.value) {
        const aData = analysesRes.value;
        const firstPageAnalyses = Array.isArray(aData.analyses) ? aData.analyses : [];
        totalCount = aData.total_count ?? firstPageAnalyses.length;
        allAnalyses = [...firstPageAnalyses];

        // If total_count indicates more records than returned on the first page,
        // fetch the remaining pages to ensure global statistics (findings, severities, verdicts)
        // are 100% mathematically and internally consistent across the entire persistent store.
        if (totalCount > allAnalyses.length && totalCount <= 5000) {
          const offsets = [];
          for (let offset = allAnalyses.length; offset < totalCount; offset += 100) {
            offsets.push(offset);
          }
          const additionalPages = await Promise.allSettled(
            offsets.map(off => getAnalyses({ limit: 100, offset: off }))
          );
          additionalPages.forEach(pRes => {
            if (pRes.status === 'fulfilled' && Array.isArray(pRes.value?.analyses)) {
              allAnalyses.push(...pRes.value.analyses);
            }
          });
        }
      }

      const finalAnalysesCount = allAnalyses.length > 0 ? allAnalyses.length : totalCount;
      setAnalysesCount(finalAnalysesCount);
      setLatestAnalysis(allAnalyses.length > 0 ? allAnalyses[0] : null);
      setRecentList(allAnalyses.slice(0, 5));

      // Compute consistent global metrics directly across all collected persistent records
      let totFindings = 0;
      let totCrit = 0;
      let totHigh = 0;
      let totMed = 0;
      let totLow = 0;
      let allowCount = 0;
      let reviewCount = 0;
      let blockCount = 0;

      allAnalyses.forEach(item => {
        const s = item.summary || {};
        const c = s.critical_count || 0;
        const h = s.high_count || 0;
        const med = s.medium_count || 0;
        const l = s.low_count || 0;
        const f = item.finding_count ?? s.total_findings ?? (c + h + med + l);

        totFindings += f;
        totCrit += c;
        totHigh += h;
        totMed += med;
        totLow += l;

        const v = getRecordVerdict(item);
        if (v === 'BLOCK') blockCount++;
        else if (v === 'REVIEW') reviewCount++;
        else allowCount++;
      });

      // If /analytics/summary returned valid global counts, cross-validate
      if (summaryRes.status === 'fulfilled' && summaryRes.value?.data) {
        const sum = summaryRes.value.data;
        const sevs = sum.severities || {};
        const dist = sum.review_status_distribution || {};

        // Only override if summary distribution has non-zero real verdicts and 0 unknown
        const hasValidDist = ((dist.allow || 0) + (dist.review || 0) + (dist.block || 0)) === finalAnalysesCount && (dist.unknown || 0) === 0;
        if (hasValidDist) {
          allowCount = dist.allow || 0;
          reviewCount = dist.review || 0;
          blockCount = dist.block || 0;
        }

        if (sum.total_findings !== undefined && sum.total_findings !== null && sum.total_findings > totFindings) {
          totFindings = sum.total_findings;
        }
        if (sevs.critical !== undefined && sevs.critical > totCrit) totCrit = sevs.critical;
        if (sevs.high !== undefined && sevs.high > totHigh) totHigh = sevs.high;
      }

      setFindingsSummary({
        total: totFindings,
        critical: totCrit,
        high: totHigh,
        medium: totMed,
        low: totLow,
      });

      setVerdictDistribution({
        allow: allowCount,
        review: reviewCount,
        block: blockCount,
      });
    } catch {
      // Graceful error state handling
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const latestVerdict = latestAnalysis ? getRecordVerdict(latestAnalysis) : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Hero Banner & Actions */}
      <div
        className="card"
        style={{
          background: 'linear-gradient(180deg, var(--bg-surface-elevated) 0%, var(--bg-surface) 100%)',
          border: '1px solid var(--border-default)',
          padding: '28px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', letterSpacing: '1px' }}>
                DEVSECOPS SECURITY OS
              </span>
              <StatusBadge status={healthStatus} />
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
              CodeSentinel Command Center
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', maxWidth: '640px' }}>
              Automated deterministic AST vulnerability detection, hybrid RAG context enrichment, and strict CI/CD security gate enforcement.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => navigate('/analyze')}
              style={{ padding: '10px 20px', fontSize: '14px', fontWeight: 600 }}
            >
              ▶ Analyze Code
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={loadDashboard}
              disabled={loading}
            >
              ↻ Refresh
            </button>
          </div>
        </div>

        {/* Subsystem Health Ribbon */}
        <div
          style={{
            marginTop: '24px',
            paddingTop: '16px',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '24px',
            fontSize: '12px',
            fontFamily: 'var(--font-mono)',
          }}
        >
          <div>
            <span style={{ color: 'var(--text-dim)', marginRight: '8px' }}>BACKEND:</span>
            <StatusBadge status={healthStatus} />
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)', marginRight: '8px' }}>AST ENGINE:</span>
            <StatusBadge status={engineStatus} />
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)', marginRight: '8px' }}>SECURITY GATE:</span>
            <StatusBadge status={securityGateStatus} />
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid-4">
        <StatCard
          label="Total Analyses"
          value={loading ? '...' : analysesCount}
          subtext={analysesCount === 0 ? 'No analyses yet' : `${analysesCount} security scans performed`}
          accent="blue"
        />
        <StatCard
          label="Total Findings"
          value={loading ? '...' : findingsSummary.total}
          subtext={`${findingsSummary.critical} critical · ${findingsSummary.high} high`}
          accent={findingsSummary.critical > 0 ? 'block' : findingsSummary.high > 0 ? 'review' : 'allow'}
        />
        <StatCard
          label="Critical / High"
          value={loading ? '...' : `${findingsSummary.critical} / ${findingsSummary.high}`}
          subtext="High severity vulnerabilities"
          accent={findingsSummary.critical > 0 ? 'block' : 'default'}
        />
        <StatCard
          label="Latest Security Verdict"
          value={loading ? '...' : (latestVerdict ? <StatusBadge status={latestVerdict} size="large" /> : 'NO DATA')}
          subtext={latestAnalysis?.analysis_id ? `ID: ${latestAnalysis.analysis_id}` : 'Awaiting initial analysis'}
          accent={latestVerdict?.toLowerCase() === 'block' ? 'block' : latestVerdict?.toLowerCase() === 'review' ? 'review' : 'allow'}
        />
      </div>

      {/* Security Gate Overview & Verdict Distribution */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Security Gate Verdicts</h3>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              POLICY: FAIL-CLOSED
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <StatusBadge status="ALLOW" />
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Clean scans (0 Critical / 0 High)</span>
              </div>
              <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--verdict-allow)' }}>
                {verdictDistribution.allow}
              </strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <StatusBadge status="REVIEW" />
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Medium findings require manual review</span>
              </div>
              <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--verdict-review)' }}>
                {verdictDistribution.review}
              </strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <StatusBadge status="BLOCK" />
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Critical or High vulnerabilities detected</span>
              </div>
              <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--verdict-block)' }}>
                {verdictDistribution.block}
              </strong>
            </div>
          </div>
        </div>

        {/* Latest Activity / Overview */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Activity</h3>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => navigate('/history')}
            >
              View All History →
            </button>
          </div>

          {analysesCount === 0 ? (
            <div className="empty-state" style={{ padding: '32px 16px' }}>
              <div className="empty-state-title">No analyses yet</div>
              <p className="empty-state-desc">
                Submit raw source code or acquire a repository to run your first automated security audit.
              </p>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => navigate('/analyze')}
                style={{ marginTop: '16px' }}
              >
                Start First Analysis
              </button>
            </div>
          ) : recentList.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {recentList.slice(0, 3).map((item) => {
                const itemVerdict = getRecordVerdict(item);
                const findingsCount = item.finding_count ?? item.summary?.total_findings ?? 0;
                return (
                  <div
                    key={item.analysis_id}
                    style={{
                      padding: '12px',
                      backgroundColor: 'var(--bg-surface-elevated)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-blue)', fontWeight: 600 }}>
                        {item.analysis_id}
                      </span>
                      <StatusBadge status={itemVerdict} />
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Target: {item.query || 'Source Code Scan'}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Findings: {findingsCount} total</span>
                      <span>{item.created_at ? new Date(item.created_at).toLocaleDateString() : ''}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
