import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import SeverityBadge from '../components/SeverityBadge';
import ReviewStatusBanner from '../components/ReviewStatusBanner';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';
import SeverityDistributionChart from '../components/SeverityDistributionChart';
import TopVulnerabilitiesChart from '../components/TopVulnerabilitiesChart';
import {
  getAnalyses,
  getAnalysisFindings,
  getPlatformMetrics,
  getPlatformHealth,
  getDeveloperAnalytics
} from '../services/apiClient';

export default function CommandCenterPage() {
  const navigate = useNavigate();

  // Loading & refreshing state
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState('');

  // 1. Health data from GET /platform/health
  const [healthChecks, setHealthChecks] = useState({
    status: 'unknown',
    configuration: 'unknown',
    security_controls: 'unknown',
    vector_store: 'unknown',
    llm_service: 'unknown',
    security_gate: 'unknown',
    error: null
  });

  // 2. Telemetry data from GET /platform/metrics
  const [telemetry, setTelemetry] = useState({
    requestsTotal: null,
    requestsSuccess: 0,
    requestsFailed: 0,
    decisionsAllow: 0,
    decisionsBlock: 0,
    decisionsReview: 0,
    cacheHits: 0,
    cacheMisses: 0,
    lastDurationMs: 0,
    isAvailable: false,
    error: null
  });

  // 3. Analyses list and aggregated metrics from GET /analyses
  const [analysesList, setAnalysesList] = useState([]);
  const [totalAnalysesCount, setTotalAnalysesCount] = useState(0);
  const [analysesError, setAnalysesError] = useState(null);

  // 4. Aggregated findings & visualizations data
  const [severityData, setSeverityData] = useState([]);
  const [topVulnsData, setTopVulnsData] = useState([]);
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] = useState(true);
  const [vulnerabilitiesError, setVulnerabilitiesError] = useState(null);

  // 5. Repository risk aggregated data
  const [repositoryRiskList, setRepositoryRiskList] = useState([]);

  // 6. Developer security analytics data (P1 #4)
  const [developerAnalytics, setDeveloperAnalytics] = useState([]);

  // Load all dashboard analytics
  const fetchDashboardData = async (isManualRefresh = false) => {
    if (isManualRefresh) setIsRefreshing(true);
    const nowTime = new Date().toLocaleTimeString();

    try {
      // 1. Concurrently fetch health, metrics, recent analyses, and developer analytics
      const [healthRes, metricsRes, analysesRes, devRes] = await Promise.allSettled([
        getPlatformHealth(),
        getPlatformMetrics(),
        getAnalyses({ limit: 25, offset: 0 }),
        getDeveloperAnalytics({ limit: 15 })
      ]);

      // Process Health
      if (healthRes.status === 'fulfilled' && healthRes.value) {
        const h = healthRes.value;
        const checks = h.checks || {};
        setHealthChecks({
          status: h.status || 'healthy',
          configuration: checks.configuration?.status || 'unknown',
          security_controls: checks.security_controls?.status || 'unknown',
          vector_store: checks.vector_store?.status || 'unknown',
          llm_service: checks.llm_service?.status || 'unknown',
          security_gate: checks.security_gate?.status || 'unknown',
          error: null
        });
      } else {
        setHealthChecks(prev => ({
          ...prev,
          status: 'unavailable',
          error: healthRes.reason?.message || 'Health probe failed'
        }));
      }

      // Process Metrics
      if (metricsRes.status === 'fulfilled' && metricsRes.value) {
        const m = metricsRes.value;
        setTelemetry({
          requestsTotal: m.analysis_requests_total ?? 0,
          requestsSuccess: m.analysis_success_total ?? 0,
          requestsFailed: m.analysis_failed_total ?? 0,
          decisionsAllow: m.decisions_allow_total ?? 0,
          decisionsBlock: m.decisions_block_total ?? 0,
          decisionsReview: m.decisions_review_total ?? 0,
          cacheHits: m.cache_hits_total ?? 0,
          cacheMisses: m.cache_misses_total ?? 0,
          lastDurationMs: m.last_analysis_duration_ms ?? 0,
          isAvailable: true,
          error: null
        });
      } else {
        setTelemetry(prev => ({
          ...prev,
          isAvailable: false,
          error: metricsRes.reason?.message || 'Metrics unavailable'
        }));
      }

      // Process Analyses
      let fetchedAnalyses = [];
      if (analysesRes.status === 'fulfilled' && analysesRes.value) {
        const resData = analysesRes.value;
        fetchedAnalyses = Array.isArray(resData.analyses) ? resData.analyses : [];
        setAnalysesList(fetchedAnalyses);
        setTotalAnalysesCount(resData.total_count ?? fetchedAnalyses.length);
        setAnalysesError(null);
      } else {
        setAnalysesError(analysesRes.reason?.message || 'Failed to retrieve analysis records');
        setAnalysesList([]);
      }

      // Aggregate Severity & Top Vulnerability Types from analyses + findings
      if (fetchedAnalyses.length > 0) {
        setVulnerabilitiesLoading(true);

        // Calculate severity totals directly from analysis summaries
        let critTotal = 0;
        let highTotal = 0;
        let medTotal = 0;
        let lowTotal = 0;
        let infoTotal = 0;

        // Group repository risks
        const repoMap = new Map();

        fetchedAnalyses.forEach(a => {
          const s = a.summary || {};
          critTotal += (s.critical_count || 0);
          highTotal += (s.high_count || 0);
          medTotal += (s.medium_count || 0);
          lowTotal += (s.low_count || 0);
          infoTotal += (s.info_count || 0);

          const repoInfo = s._repository || {};
          const repoKey = (repoInfo.owner && repoInfo.repository)
            ? `${repoInfo.owner}/${repoInfo.repository}`
            : (a.query?.replace('Repository Analysis: ', '') || 'workspace');

          if (!repoMap.has(repoKey)) {
            repoMap.set(repoKey, {
              repoName: repoKey,
              branch: repoInfo.branch || 'main',
              analysisCount: 0,
              totalFindings: 0,
              criticalCount: 0,
              highCount: 0,
              latestGate: (s._review_status || 'allow').toUpperCase(),
              latestTimestamp: a.created_at
            });
          }

          const existing = repoMap.get(repoKey);
          existing.analysisCount += 1;
          existing.totalFindings += (a.finding_count || 0);
          existing.criticalCount += (s.critical_count || 0);
          existing.highCount += (s.high_count || 0);
        });

        setSeverityData([
          { name: 'Critical', value: critTotal, color: '#ff3b30' },
          { name: 'High', value: highTotal, color: '#feb700' },
          { name: 'Medium', value: medTotal, color: '#00f0ff' },
          { name: 'Low', value: lowTotal, color: '#34c759' },
          { name: 'Info', value: infoTotal, color: '#b9cacb' }
        ]);

        setRepositoryRiskList(Array.from(repoMap.values()));

        // Fetch detailed findings for analyses that have findings to build Top Vulnerabilities
        const analysesWithFindings = fetchedAnalyses.filter(a => (a.finding_count || 0) > 0).slice(0, 10);
        
        if (analysesWithFindings.length > 0) {
          try {
            const findingsResponses = await Promise.allSettled(
              analysesWithFindings.map(a => getAnalysisFindings(a.analysis_id))
            );

            const vulnCounts = {};
            findingsResponses.forEach(fr => {
              if (fr.status === 'fulfilled' && fr.value?.findings) {
                fr.value.findings.forEach(f => {
                  const vulnType = f.title || f.category || 'Security Risk';
                  vulnCounts[vulnType] = (vulnCounts[vulnType] || 0) + 1;
                });
              }
            });

            const sortedVulns = Object.entries(vulnCounts)
              .map(([name, count]) => ({ name, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 6);

            setTopVulnsData(sortedVulns);
            setVulnerabilitiesError(null);
          } catch (err) {
            setVulnerabilitiesError('Failed aggregating findings details');
          }
        } else {
          setTopVulnsData([]);
          setVulnerabilitiesError(null);
        }

        setVulnerabilitiesLoading(false);
      } else {
        setSeverityData([]);
        setTopVulnsData([]);
        setRepositoryRiskList([]);
        setVulnerabilitiesLoading(false);
      }

      // Process Developer Security Analytics (P1 #4)
      if (devRes.status === 'fulfilled' && devRes.value?.developers) {
        setDeveloperAnalytics(Array.isArray(devRes.value.developers) ? devRes.value.developers : []);
      } else {
        setDeveloperAnalytics([]);
      }

      setLastRefreshed(nowTime);
    } catch {
      setLastRefreshed(nowTime);
    } finally {
      setLoading(false);
      if (isManualRefresh) {
        setTimeout(() => setIsRefreshing(false), 300);
      }
    }
  };

  useEffect(() => {
    fetchDashboardData(false);
  }, []);

  // Compute total findings from severity data
  const totalFindingsCount = severityData.reduce((acc, d) => acc + (d.value || 0), 0);
  const criticalFindingsCount = severityData.find(d => d.name === 'Critical')?.value || 0;
  const highFindingsCount = severityData.find(d => d.name === 'High')?.value || 0;

  // Most recent analysis record for review banner
  const latestAnalysis = analysesList[0] || null;
  const latestReviewStatus = latestAnalysis?.summary?._review_status || 'allow';
  const latestRepo = latestAnalysis?.summary?._repository;
  const latestRepoStr = (latestRepo?.owner && latestRepo?.repository)
    ? `${latestRepo.owner}/${latestRepo.repository} (${latestRepo.branch || 'main'})`
    : (latestAnalysis?.query || 'Workspace');

  // Repositories for Global Risk Orbit radar
  const monitoredRepos = repositoryRiskList.slice(0, 4);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Header & Diagnostics Refresh Bar */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                DEVSECOPS SECURITY OS — COMMAND CENTER
              </LabelCaps>
              <StatusPip status={healthChecks.status === 'healthy' ? 'green' : 'amber'} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--status-green)' }}>
                {healthChecks.status === 'healthy' ? 'SYSTEM ONLINE' : 'DIAGNOSTICS DEGRADED'}
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              Command Center
            </h1>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-on-surface-variant)' }}>
              Centralized security telemetry, real-time vulnerability distribution, and repository audit intelligence.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <PrimaryButton icon="autorenew" onClick={() => fetchDashboardData(true)} disabled={isRefreshing}>
              {isRefreshing ? 'REFRESHING...' : 'REFRESH DASHBOARD'}
            </PrimaryButton>
            <SecondaryButton icon="health_and_safety" onClick={() => navigate('/system-health')}>
              SYSTEM HEALTH
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. System Subsystems Status Bar (Real backend checks from /platform/health) */}
      <div style={{
        padding: '12px 20px',
        backgroundColor: 'var(--panel-bg)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-xs)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <StatusPip status={healthChecks.status === 'healthy' ? 'green' : 'amber'} />
          <LabelCaps style={{ fontSize: '11px', color: 'var(--text-on-surface)' }}>
            CORE SUBSYSTEM STATUS
          </LabelCaps>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '20px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
          <div>
            <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>CONFIG:</span>
            <span style={{ color: healthChecks.configuration === 'healthy' ? 'var(--status-green)' : 'var(--secondary-amber)', fontWeight: 600 }}>
              {healthChecks.configuration.toUpperCase()}
            </span>
          </div>
          <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '20px' }}>
            <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>SECURITY CONTROLS:</span>
            <span style={{ color: healthChecks.security_controls === 'healthy' ? 'var(--status-green)' : 'var(--secondary-amber)', fontWeight: 600 }}>
              {healthChecks.security_controls === 'healthy' ? 'ACTIVE' : healthChecks.security_controls.toUpperCase()}
            </span>
          </div>
          <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '20px' }}>
            <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>VECTOR STORE:</span>
            <span style={{ color: healthChecks.vector_store === 'healthy' ? 'var(--primary-cyan)' : 'var(--secondary-amber)', fontWeight: 600 }}>
              {healthChecks.vector_store === 'healthy' ? 'READY' : healthChecks.vector_store.toUpperCase()}
            </span>
          </div>
          <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '20px' }}>
            <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>LLM SERVICE:</span>
            <span style={{ color: healthChecks.llm_service === 'healthy' ? 'var(--primary-cyan)' : 'var(--secondary-amber)', fontWeight: 600 }}>
              {healthChecks.llm_service === 'healthy' ? 'READY' : healthChecks.llm_service.toUpperCase()}
            </span>
          </div>
          <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '20px' }}>
            <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>SECURITY GATE:</span>
            <span style={{ color: healthChecks.security_gate === 'healthy' ? 'var(--status-green)' : 'var(--secondary-amber)', fontWeight: 600 }}>
              {healthChecks.security_gate === 'healthy' ? 'VERIFIED' : healthChecks.security_gate.toUpperCase()}
            </span>
          </div>
        </div>

        {lastRefreshed && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
            Updated: {lastRefreshed}
          </div>
        )}
      </div>

      {/* 3. Real KPI Metric Cards (Step 5) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        <MetricCard
          label="TOTAL AUDITED ANALYSES"
          value={loading ? 'LOADING...' : (telemetry.isAvailable ? String(telemetry.requestsTotal) : String(totalAnalysesCount))}
          delta={telemetry.isAvailable ? `${telemetry.requestsSuccess} SUCCEEDED · ${telemetry.requestsFailed} FAILED` : `${totalAnalysesCount} Recorded`}
          accentColor="cyan"
        />
        <MetricCard
          label="SECURITY GATE VERDICTS"
          value={telemetry.isAvailable ? `${telemetry.decisionsAllow} ALLOW` : (analysesList.length > 0 ? `${analysesList.filter(a => a.summary?._review_status === 'allow').length} ALLOW` : 'NO DATA')}
          delta={telemetry.isAvailable ? `${telemetry.decisionsBlock} BLOCK · ${telemetry.decisionsReview} REVIEW` : 'Backend verified verdicts'}
          accentColor="green"
        />
        <MetricCard
          label="TOTAL FINDINGS"
          value={loading ? 'LOADING...' : String(totalFindingsCount)}
          delta={`${criticalFindingsCount} CRITICAL · ${highFindingsCount} HIGH`}
          accentColor={criticalFindingsCount > 0 ? 'critical' : highFindingsCount > 0 ? 'amber' : 'green'}
        />
        <MetricCard
          label="LAST ANALYSIS DURATION"
          value={telemetry.isAvailable ? `${telemetry.lastDurationMs} ms` : '0 ms'}
          delta={telemetry.isAvailable ? `${telemetry.cacheHits} Cache Hits · ${telemetry.cacheMisses} Misses` : 'Deterministic pipeline'}
          accentColor="dim"
        />
      </div>

      {/* 4. Visualizations Row: Severity Distribution Donut + Top Vulnerabilities Bar Chart (Steps 6, 7, 8) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '16px' }}>
        {/* Severity Distribution Donut Chart */}
        <DataPanel
          title="SEVERITY DISTRIBUTION"
          status="amber"
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
              <span>BREAKDOWN BY SEVERITY</span>
            </div>
          }
        >
          <SeverityDistributionChart
            data={severityData}
            loading={vulnerabilitiesLoading}
            error={vulnerabilitiesError}
          />
        </DataPanel>

        {/* Top Vulnerability Types Bar Chart */}
        <DataPanel
          title="TOP VULNERABILITY TYPES"
          status="cyan"
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
              <span>FREQUENCY RANKED</span>
            </div>
          }
        >
          <TopVulnerabilitiesChart
            data={topVulnsData}
            loading={vulnerabilitiesLoading}
            error={vulnerabilitiesError}
          />
        </DataPanel>
      </div>

      {/* 5. Global Risk Orbit & Repository Telemetry (Step 10) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Left Column: Global Risk Orbit Radar (8 cols) */}
        <div style={{ gridColumn: 'span 8', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <DataPanel
            title="GLOBAL RISK ORBIT"
            status="cyan"
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
                <span>LATENCY: {telemetry.lastDurationMs} ms</span>
                <StatusPip status={telemetry.lastDurationMs > 0 ? 'cyan' : 'dim'} />
              </div>
            }
            style={{ height: '340px', position: 'relative' }}
          >
            {/* Concentric Orbit Visual Radar Container */}
            <div style={{
              flex: 1,
              position: 'relative',
              backgroundColor: 'var(--bg-void-lowest)',
              borderRadius: 'var(--radius-xs)',
              overflow: 'hidden',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '1px solid var(--border-subtle)'
            }}>
              {/* Concentric Orbit Rings */}
              <div style={{ position: 'absolute', width: '220px', height: '220px', border: '1px solid var(--border-default)', borderRadius: '50%', opacity: 0.3 }} />
              <div style={{ position: 'absolute', width: '340px', height: '340px', border: '1px solid var(--border-default)', borderRadius: '50%', opacity: 0.2 }} />
              <div style={{ position: 'absolute', width: '460px', height: '460px', border: '1px solid var(--border-default)', borderRadius: '50%', opacity: 0.1 }} />

              {/* Center Hub Node */}
              <div style={{
                position: 'relative',
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                border: '1px solid var(--primary-cyan)',
                backgroundColor: 'var(--panel-bg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--primary-cyan)',
                zIndex: 2,
                boxShadow: '0 0 16px rgba(0, 240, 255, 0.2)'
              }}>
                <span className="material-symbols-outlined" style={{ fontSize: '28px' }}>hub</span>
              </div>

              {/* Dynamic Orbital Risk Nodes from real audited repositories */}
              {monitoredRepos.length > 0 ? (
                monitoredRepos.map((repo, idx) => {
                  const positions = [
                    { top: '22%', left: '26%' },
                    { top: '65%', left: '68%' },
                    { top: '32%', left: '74%' },
                    { top: '70%', left: '24%' }
                  ];
                  const pos = positions[idx % positions.length];
                  const isBlock = repo.latestGate === 'BLOCK';
                  const isReview = repo.latestGate === 'REVIEW';
                  const pipColor = isBlock ? 'status-pip status-pip-red' : isReview ? 'status-pip status-pip-amber' : 'status-pip status-pip-green';
                  const textColor = isBlock ? 'var(--critical-red)' : isReview ? 'var(--secondary-amber)' : 'var(--status-green)';
                  const borderColor = isBlock ? 'var(--critical-red)' : isReview ? 'var(--secondary-amber)' : 'var(--border-subtle)';

                  return (
                    <div
                      key={repo.repoName}
                      style={{
                        position: 'absolute',
                        top: pos.top,
                        left: pos.left,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        zIndex: 3
                      }}
                    >
                      <span className={pipColor} style={{ width: '8px', height: '8px' }} />
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '10px',
                        color: textColor,
                        backgroundColor: 'var(--panel-bg-high)',
                        padding: '2px 6px',
                        border: `1px solid ${borderColor}`,
                        borderRadius: 'var(--radius-xs)',
                        whiteSpace: 'nowrap'
                      }}>
                        {repo.repoName} ({repo.latestGate})
                      </span>
                    </div>
                  );
                })
              ) : (
                <div style={{ position: 'absolute', zIndex: 2, textAlign: 'center', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  AWAITING REPOSITORY SCANS
                </div>
              )}

              {/* Monitored Repos Overlay Badge */}
              <div style={{
                position: 'absolute',
                bottom: '12px',
                left: '12px',
                backgroundColor: 'rgba(35, 43, 44, 0.9)',
                border: '1px solid var(--border-default)',
                padding: '6px 12px',
                borderRadius: 'var(--radius-xs)',
                display: 'flex',
                flexDirection: 'column',
                gap: '2px',
                zIndex: 2
              }}>
                <LabelCaps style={{ fontSize: '9px' }}>MONITORED REPOS</LabelCaps>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
                  {repositoryRiskList.length}
                </span>
              </div>
            </div>
          </DataPanel>
        </div>

        {/* Right Column: Telemetry & Vulnerability Breakdown Summary (4 cols) */}
        <div style={{ gridColumn: 'span 4', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Critical Telemetry Panel */}
          <DataPanel title="SECURITY PIPELINE SUMMARY" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', paddingBottom: '10px', borderBottom: '1px solid var(--border-subtle)' }}>
                <div>
                  <LabelCaps style={{ fontSize: '10px' }}>ANALYSIS VOLUME</LabelCaps>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px', marginTop: '2px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '32px', fontWeight: 700, color: 'var(--primary-cyan)' }}>
                      {totalAnalysesCount}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)' }}>
                      RECORDS
                    </span>
                  </div>
                </div>
                <div style={{
                  backgroundColor: 'rgba(0, 240, 255, 0.1)',
                  border: '1px solid var(--primary-cyan)',
                  color: 'var(--primary-cyan)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-xs)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>check_circle</span>
                  {telemetry.requestsSuccess} CLEAN
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--text-dim)' }}>Deterministic Cache</span>
                <span style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>{telemetry.cacheHits} Hits</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--text-dim)' }}>Deterministic Latency</span>
                <span style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>{telemetry.lastDurationMs} ms</span>
              </div>
            </div>
          </DataPanel>

          {/* Active Vulnerabilities Severity Bars Panel */}
          <DataPanel title="ACTIVE SEVERITY PROFILE" status="amber">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {/* Critical */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="critical" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: `${totalFindingsCount > 0 ? (criticalFindingsCount / totalFindingsCount) * 100 : 0}%`, height: '100%', backgroundColor: 'var(--critical-red)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {criticalFindingsCount}
                </span>
              </div>

              {/* High */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="high" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: `${totalFindingsCount > 0 ? (highFindingsCount / totalFindingsCount) * 100 : 0}%`, height: '100%', backgroundColor: 'var(--secondary-amber)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {highFindingsCount}
                </span>
              </div>

              {/* Medium */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="medium" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: `${totalFindingsCount > 0 ? ((severityData.find(d => d.name === 'Medium')?.value || 0) / totalFindingsCount) * 100 : 0}%`, height: '100%', backgroundColor: 'var(--primary-cyan)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {severityData.find(d => d.name === 'Medium')?.value || 0}
                </span>
              </div>

              {/* Low */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="low" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: `${totalFindingsCount > 0 ? ((severityData.find(d => d.name === 'Low')?.value || 0) / totalFindingsCount) * 100 : 0}%`, height: '100%', backgroundColor: 'var(--status-green)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {severityData.find(d => d.name === 'Low')?.value || 0}
                </span>
              </div>
            </div>
          </DataPanel>

        </div>
      </div>

      {/* 6. Review Contract Banner for Latest Analysis (Step 3) */}
      {latestAnalysis ? (
        <ReviewStatusBanner
          reviewStatus={latestReviewStatus}
          title={`LATEST PULL REQUEST AUDIT: ${latestReviewStatus.toUpperCase()}`}
          details={`Repository: ${latestRepoStr} — ${latestAnalysis.finding_count || 0} finding(s) detected across ${latestAnalysis.summary?.analyzed_files || 0} file(s)`}
        />
      ) : (
        <ReviewStatusBanner
          reviewStatus="allow"
          title="ANALYSIS PIPELINE STANDBY"
          details="No pull requests or repository audits recorded. System is ready for scan intake."
        />
      )}

      {/* 7. Repository Security Risk Table (Step 9 — replaces OLD developer blame table) */}
      <DataPanel
        title="REPOSITORY SECURITY RISK AUDIT"
        status="cyan"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
            <StatusPip status="green" />
            <span>REAL-TIME AUDIT SUMMARY</span>
          </div>
        }
      >
        {repositoryRiskList.length > 0 ? (
          <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '2fr 100px 100px 100px 120px 140px 80px',
              gap: '12px',
              padding: '8px 16px',
              backgroundColor: 'var(--bg-void-low)',
              borderBottom: '1px solid var(--border-subtle)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--text-dim)',
              fontWeight: 700
            }}>
              <div>REPOSITORY</div>
              <div style={{ textAlign: 'center' }}>BRANCH</div>
              <div style={{ textAlign: 'center' }}>SCANS</div>
              <div style={{ textAlign: 'center' }}>FINDINGS</div>
              <div style={{ textAlign: 'center' }}>CRITICAL / HIGH</div>
              <div style={{ textAlign: 'center' }}>LATEST GATE</div>
              <div style={{ textAlign: 'right' }}>ACTION</div>
            </div>

            {repositoryRiskList.map((repo) => {
              const isBlocked = repo.latestGate === 'BLOCK';
              const isReview = repo.latestGate === 'REVIEW';
              return (
                <div
                  key={repo.repoName}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '2fr 100px 100px 100px 120px 140px 80px',
                    gap: '12px',
                    padding: '12px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    alignItems: 'center',
                    backgroundColor: isBlocked ? 'rgba(255, 59, 48, 0.04)' : 'transparent'
                  }}
                >
                  <div style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>
                    {repo.repoName}
                  </div>
                  <div style={{ textAlign: 'center', color: 'var(--text-dim)', fontSize: '11px' }}>
                    {repo.branch}
                  </div>
                  <div style={{ textAlign: 'center', color: 'var(--primary-cyan)' }}>
                    {repo.analysisCount}
                  </div>
                  <div style={{ textAlign: 'center', color: repo.totalFindings > 0 ? 'var(--secondary-amber)' : 'var(--status-green)', fontWeight: 600 }}>
                    {repo.totalFindings}
                  </div>
                  <div style={{ textAlign: 'center', color: repo.criticalCount > 0 ? 'var(--critical-red)' : repo.highCount > 0 ? 'var(--secondary-amber)' : 'var(--text-dim)' }}>
                    {repo.criticalCount} / {repo.highCount}
                  </div>
                  <div style={{ textAlign: 'center' }}>
                    <span style={{
                      backgroundColor: isBlocked ? 'rgba(255, 59, 48, 0.1)' : isReview ? 'rgba(254, 183, 0, 0.1)' : 'rgba(52, 199, 89, 0.1)',
                      color: isBlocked ? 'var(--critical-red)' : isReview ? 'var(--secondary-amber)' : 'var(--status-green)',
                      border: `1px solid ${isBlocked ? 'var(--critical-red)' : isReview ? 'var(--secondary-amber)' : 'var(--status-green)'}`,
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-xs)'
                    }}>
                      {repo.latestGate}
                    </span>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <SecondaryButton
                      icon="visibility"
                      onClick={() => navigate('/pr-review')}
                      style={{ padding: '4px 8px', fontSize: '11px' }}
                    >
                      VIEW
                    </SecondaryButton>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{
            padding: '32px',
            textAlign: 'center',
            backgroundColor: 'var(--bg-void-lowest)',
            border: '1px dashed var(--border-subtle)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-dim)'
          }}>
            NO REPOSITORIES SCANNED YET. Run a repository analysis to populate repository security risk metrics.
          </div>
        )}
      </DataPanel>

      {/* Developer Security Activity Panel (P1 #4) */}
      <DataPanel
        title="DEVELOPER SECURITY ACTIVITY &amp; AUDIT INTELLIGENCE"
        status="cyan"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
            <StatusPip status={developerAnalytics.length > 0 ? 'green' : 'amber'} />
            <span>{developerAnalytics.length} CONTRIBUTOR(S) RECORDED</span>
          </div>
        }
      >
        {developerAnalytics.length > 0 ? (
          <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '2fr 100px 100px 140px 120px 2fr 140px',
              gap: '12px',
              padding: '8px 16px',
              backgroundColor: 'var(--bg-void-low)',
              borderBottom: '1px solid var(--border-subtle)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--text-dim)',
              fontWeight: 700
            }}>
              <div>DEVELOPER</div>
              <div style={{ textAlign: 'center' }}>ANALYSES</div>
              <div style={{ textAlign: 'center' }}>FINDINGS</div>
              <div style={{ textAlign: 'center' }}>CRITICAL / HIGH</div>
              <div style={{ textAlign: 'center' }}>GATE BLOCKS</div>
              <div>REPOSITORIES</div>
              <div style={{ textAlign: 'right' }}>LAST ACTIVITY</div>
            </div>

            {developerAnalytics.map((dev) => (
              <div
                key={dev.developer}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '2fr 100px 100px 140px 120px 2fr 140px',
                  gap: '12px',
                  padding: '12px 16px',
                  borderBottom: '1px solid var(--border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  alignItems: 'center',
                  backgroundColor: dev.critical_count > 0 ? 'rgba(255, 59, 48, 0.03)' : 'transparent'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-on-surface)', fontWeight: 600 }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--primary-cyan)' }}>
                    account_circle
                  </span>
                  <span>{dev.developer}</span>
                </div>
                <div style={{ textAlign: 'center', color: 'var(--primary-cyan)' }}>
                  {dev.total_analyses}
                </div>
                <div style={{ textAlign: 'center', color: dev.total_findings > 0 ? 'var(--secondary-amber)' : 'var(--status-green)', fontWeight: 600 }}>
                  {dev.total_findings}
                </div>
                <div style={{ textAlign: 'center', color: dev.critical_count > 0 ? 'var(--critical-red)' : dev.high_count > 0 ? 'var(--secondary-amber)' : 'var(--text-dim)' }}>
                  {dev.critical_count} / {dev.high_count}
                </div>
                <div style={{ textAlign: 'center' }}>
                  {dev.block_count > 0 ? (
                    <span style={{
                      backgroundColor: 'rgba(255, 59, 48, 0.1)',
                      color: 'var(--critical-red)',
                      border: '1px solid var(--critical-red)',
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-xs)'
                    }}>
                      {dev.block_count} BLOCKS
                    </span>
                  ) : (
                    <span style={{ color: 'var(--status-green)', fontSize: '11px' }}>
                      0 BLOCKS
                    </span>
                  )}
                </div>
                <div style={{ color: 'var(--text-dim)', fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={Array.isArray(dev.repositories) ? dev.repositories.join(', ') : ''}>
                  {Array.isArray(dev.repositories) && dev.repositories.length > 0 ? dev.repositories.join(', ') : '—'}
                </div>
                <div style={{ textAlign: 'right', color: 'var(--text-dim)', fontSize: '11px' }}>
                  {dev.last_activity ? new Date(dev.last_activity).toLocaleDateString() : '—'}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{
            padding: '24px',
            textAlign: 'center',
            backgroundColor: 'var(--bg-void-lowest)',
            border: '1px dashed var(--border-subtle)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-dim)'
          }}>
            NO DEVELOPER SECURITY ACTIVITY RECORDED YET. PR webhooks and scans with author attribution will populate here automatically.
          </div>
        )}
      </DataPanel>

      {/* 8. Live Event Stream (AI Verdicts) Table Panel (Step 11 — Real recent analysis events) */}
      <DataPanel
        title="LIVE EVENT STREAM (AI VERDICTS)"
        status="cyan"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
            <StatusPip status="cyan" />
            <span>LISTENING FOR PR WEBHOOKS &amp; AUDITS</span>
          </div>
        }
      >
        {analysesList.length > 0 ? (
          <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '150px 180px 1fr 140px 80px',
              gap: '12px',
              padding: '8px 16px',
              backgroundColor: 'var(--bg-void-low)',
              borderBottom: '1px solid var(--border-subtle)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--text-dim)',
              fontWeight: 700
            }}>
              <div>TIMESTAMP</div>
              <div>TARGET REPO</div>
              <div>ANALYSIS CONTEXT</div>
              <div>VERDICT</div>
              <div style={{ textAlign: 'right' }}>ACTION</div>
            </div>

            {analysesList.slice(0, 8).map((a) => {
              const reviewStatus = (a.summary?._review_status || 'allow').toLowerCase();
              const isBlocked = reviewStatus === 'block';
              const isReview = reviewStatus === 'review';
              const repoInfo = a.summary?._repository;
              const target = (repoInfo?.owner && repoInfo?.repository)
                ? `${repoInfo.owner}/${repoInfo.repository}`
                : (a.query?.replace('Repository Analysis: ', '') || 'workspace');
              const timeStr = a.created_at
                ? (a.created_at.includes('T') ? a.created_at.substring(11, 19) + 'Z' : a.created_at)
                : 'Just now';

              return (
                <div
                  key={a.analysis_id}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '150px 180px 1fr 140px 80px',
                    gap: '12px',
                    padding: '12px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
                    backgroundColor: isBlocked ? 'rgba(255, 59, 48, 0.04)' : 'transparent',
                    borderLeft: isBlocked ? '3px solid var(--critical-red)' : isReview ? '3px solid var(--secondary-amber)' : '3px solid transparent',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    alignItems: 'center'
                  }}
                >
                  <div style={{ color: 'var(--text-dim)' }}>{timeStr}</div>
                  <div style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>{target}</div>
                  <div style={{ color: 'var(--text-on-surface-variant)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {`Scanned ${a.summary?.analyzed_files || 0} files — ${a.finding_count || 0} finding(s) identified (${a.analysis_id})`}
                  </div>
                  <div>
                    {isBlocked ? (
                      <span style={{
                        backgroundColor: 'rgba(255, 59, 48, 0.1)',
                        color: 'var(--critical-red)',
                        border: '1px solid var(--critical-red)',
                        fontSize: '10px',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)'
                      }}>
                        BLOCK ({a.summary?.critical_count || 0} CRITICAL)
                      </span>
                    ) : isReview ? (
                      <span style={{
                        backgroundColor: 'rgba(254, 183, 0, 0.1)',
                        color: 'var(--secondary-amber)',
                        border: '1px solid var(--secondary-amber)',
                        fontSize: '10px',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)'
                      }}>
                        REVIEW ({a.summary?.high_count || 0} HIGH)
                      </span>
                    ) : (
                      <span style={{
                        backgroundColor: 'rgba(52, 199, 89, 0.1)',
                        color: 'var(--status-green)',
                        border: '1px solid var(--status-green)',
                        fontSize: '10px',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)'
                      }}>
                        ALLOW (CLEAN)
                      </span>
                    )}
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <SecondaryButton
                      icon="visibility"
                      onClick={() => navigate('/pr-review')}
                      style={{ padding: '4px 8px', fontSize: '11px' }}
                    >
                      VIEW
                    </SecondaryButton>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{
            padding: '32px',
            textAlign: 'center',
            backgroundColor: 'var(--bg-void-lowest)',
            border: '1px dashed var(--border-subtle)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-dim)'
          }}>
            NO RECENT ANALYSIS EVENTS. Run an analysis via CLI or API to stream events.
          </div>
        )}
      </DataPanel>

    </div>
  );
}
