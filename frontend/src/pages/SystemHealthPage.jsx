import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';
import {
  getPlatformHealth,
  getPlatformReadiness,
  getPlatformInfo,
  getPlatformPolicies,
  getPlatformMetrics
} from '../services/apiClient';

export default function SystemHealthPage() {
  const navigate = useNavigate();

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastChecked, setLastChecked] = useState('Initiating...');

  // 1. Health state from GET /platform/health
  const [healthData, setHealthData] = useState({
    status: 'unknown',
    service: 'CodeSentinel',
    version: '1.0.0',
    environment: 'development',
    checks: null,
    error: null
  });

  // 2. Readiness state from GET /platform/readiness
  const [readinessData, setReadinessData] = useState({
    state: 'UNKNOWN', // 'READY' | 'NOT READY' | 'UNKNOWN'
    ready: null,
    status: 'unknown',
    timestampReady: null,
    error: null
  });

  // 3. Platform info state from GET /platform/info
  const [platformInfo, setPlatformInfo] = useState({
    service: 'CodeSentinel',
    version: '1.0.0',
    apiVersion: 'v1',
    capabilities: [],
    supportedModes: [],
    supportedLanguages: [],
    gateOutcomes: [],
    error: null
  });

  // 4. Platform policies state from GET /platform/policies
  const [policies, setPolicies] = useState([]);
  const [policiesError, setPoliciesError] = useState(null);

  // 5. Telemetry metrics state from GET /platform/metrics
  const [metrics, setMetrics] = useState({
    requestsTotal: 0,
    requestsSuccess: 0,
    requestsFailed: 0,
    decisionsAllow: 0,
    decisionsBlock: 0,
    decisionsReview: 0,
    cacheHits: 0,
    cacheMisses: 0,
    healthChecksTotal: 0,
    lastDurationMs: 0,
    isAvailable: false,
    error: null
  });

  // Operational event logs stream
  const [eventLogs, setEventLogs] = useState([
    {
      id: 1,
      time: new Date().toISOString().substring(11, 23) + 'Z',
      component: 'BOOTSTRAP',
      level: 'INFO',
      msg: 'CodeSentinel frontend initializing real telemetry connectors.'
    }
  ]);

  // Comprehensive refresh action
  const handleRefreshHealth = async () => {
    setIsRefreshing(true);
    const nowTime = new Date().toLocaleTimeString();

    try {
      const [healthRes, readinessRes, infoRes, policiesRes, metricsRes] = await Promise.allSettled([
        getPlatformHealth(),
        getPlatformReadiness(),
        getPlatformInfo(),
        getPlatformPolicies(),
        getPlatformMetrics()
      ]);

      const newLogs = [];

      // Process GET /platform/health
      if (healthRes.status === 'fulfilled' && healthRes.value) {
        const h = healthRes.value;
        setHealthData({
          status: h.status || 'healthy',
          service: h.service || 'CodeSentinel',
          version: h.version || '1.0.0',
          environment: h.environment || 'development',
          checks: h.checks || null,
          error: null
        });
        newLogs.push({
          id: Date.now() + 1,
          time: new Date().toISOString().substring(11, 23) + 'Z',
          component: 'PLATFORM_HEALTH',
          level: h.status === 'healthy' ? 'INFO' : 'WARN',
          msg: `Health check reported status: ${h.status?.toUpperCase()} (${Object.keys(h.checks || {}).length} checks evaluated)`
        });
      } else {
        const err = healthRes.reason?.message || 'Health endpoint unreachable';
        setHealthData(prev => ({ ...prev, status: 'unavailable', error: err }));
        newLogs.push({
          id: Date.now() + 1,
          time: new Date().toISOString().substring(11, 23) + 'Z',
          component: 'PLATFORM_HEALTH',
          level: 'ERROR',
          msg: `Health diagnostics failed: ${err}`
        });
      }

      // Process GET /platform/readiness
      if (readinessRes.status === 'fulfilled' && readinessRes.value) {
        const r = readinessRes.value;
        const isReady = r.ready === true;
        setReadinessData({
          state: isReady ? 'READY' : 'NOT READY',
          ready: isReady,
          status: r.status || 'healthy',
          timestampReady: r.timestamp_ready ?? null,
          error: null
        });
        newLogs.push({
          id: Date.now() + 2,
          time: new Date().toISOString().substring(11, 23) + 'Z',
          component: 'PLATFORM_READINESS',
          level: isReady ? 'INFO' : 'WARN',
          msg: `Readiness verified: ${isReady ? 'READY' : 'NOT READY'}`
        });
      } else {
        const err = readinessRes.reason?.message || 'Readiness probe unreachable';
        setReadinessData(prev => ({ ...prev, state: 'UNKNOWN', ready: null, error: err }));
        newLogs.push({
          id: Date.now() + 2,
          time: new Date().toISOString().substring(11, 23) + 'Z',
          component: 'PLATFORM_READINESS',
          level: 'WARN',
          msg: `Readiness state indeterminate: ${err}`
        });
      }

      // Process GET /platform/info
      if (infoRes.status === 'fulfilled' && infoRes.value) {
        const inf = infoRes.value;
        setPlatformInfo({
          service: inf.service || 'CodeSentinel',
          version: inf.version || '1.0.0',
          apiVersion: inf.api_version || 'v1',
          capabilities: Array.isArray(inf.enabled_capabilities) ? inf.enabled_capabilities : [],
          supportedModes: Array.isArray(inf.supported_analysis_modes) ? inf.supported_analysis_modes : [],
          supportedLanguages: Array.isArray(inf.supported_languages) ? inf.supported_languages : [],
          gateOutcomes: Array.isArray(inf.security_gate_outcomes) ? inf.security_gate_outcomes : [],
          error: null
        });
      } else {
        setPlatformInfo(prev => ({
          ...prev,
          error: infoRes.reason?.message || 'Metadata endpoint unavailable'
        }));
      }

      // Process GET /platform/policies
      if (policiesRes.status === 'fulfilled' && Array.isArray(policiesRes.value)) {
        setPolicies(policiesRes.value);
        setPoliciesError(null);
      } else {
        setPoliciesError(policiesRes.reason?.message || 'Security policies unavailable');
      }

      // Process GET /platform/metrics
      if (metricsRes.status === 'fulfilled' && metricsRes.value) {
        const m = metricsRes.value;
        setMetrics({
          requestsTotal: m.analysis_requests_total ?? 0,
          requestsSuccess: m.analysis_success_total ?? 0,
          requestsFailed: m.analysis_failed_total ?? 0,
          decisionsAllow: m.decisions_allow_total ?? 0,
          decisionsBlock: m.decisions_block_total ?? 0,
          decisionsReview: m.decisions_review_total ?? 0,
          cacheHits: m.cache_hits_total ?? 0,
          cacheMisses: m.cache_misses_total ?? 0,
          healthChecksTotal: m.health_checks_total ?? 0,
          lastDurationMs: m.last_analysis_duration_ms ?? 0,
          isAvailable: true,
          error: null
        });
      } else {
        setMetrics(prev => ({
          ...prev,
          isAvailable: false,
          error: metricsRes.reason?.message || 'Metrics telemetry unavailable'
        }));
      }

      // Append new event logs
      if (newLogs.length > 0) {
        setEventLogs(prev => [...newLogs, ...prev].slice(0, 10));
      }

      setLastChecked(nowTime);
    } catch {
      setLastChecked(nowTime);
    } finally {
      setTimeout(() => setIsRefreshing(false), 300);
    }
  };

  useEffect(() => {
    handleRefreshHealth();
  }, []);

  // Format checks map into displayable component items
  const checkComponents = healthData.checks
    ? Object.entries(healthData.checks).map(([key, check]) => {
        const isHealthy = check.status === 'healthy';
        const formattedName = key.replace(/_/g, ' ').toUpperCase();
        return {
          id: key,
          name: formattedName,
          status: isHealthy ? 'green' : 'amber',
          detail: check.details || 'Status evaluated by backend health check',
          response: isHealthy ? 'OPERATIONAL' : (check.status?.toUpperCase() || 'DEGRADED')
        };
      })
    : [
        { id: 'config', name: 'CONFIGURATION', status: 'dim', detail: 'Awaiting backend diagnostics...', response: 'PENDING' },
        { id: 'sec_ctrl', name: 'SECURITY CONTROLS', status: 'dim', detail: 'Awaiting backend diagnostics...', response: 'PENDING' },
        { id: 'vector', name: 'VECTOR STORE', status: 'dim', detail: 'Awaiting backend diagnostics...', response: 'PENDING' },
        { id: 'llm', name: 'LLM SERVICE', status: 'dim', detail: 'Awaiting backend diagnostics...', response: 'PENDING' },
        { id: 'gate', name: 'SECURITY GATE', status: 'dim', detail: 'Awaiting backend diagnostics...', response: 'PENDING' }
      ];

  const isHealthy = healthData.status === 'healthy';
  const readinessColor = readinessData.state === 'READY' ? 'var(--status-green)' : readinessData.state === 'NOT READY' ? 'var(--critical-red)' : 'var(--secondary-amber)';
  const readinessPip = readinessData.state === 'READY' ? 'green' : readinessData.state === 'NOT READY' ? 'red' : 'amber';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Page Context & Header */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                SYSTEM HEALTH &amp; INFRASTRUCTURE DIAGNOSTICS
              </LabelCaps>
              <StatusPip status={isHealthy ? 'green' : 'amber'} title={`Health: ${healthData.status}`} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--status-green)' }}>
                v{healthData.version}
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              System Health &amp; Telemetry
            </h1>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-on-surface-variant)' }}>
              Real-time platform readiness, core subsystem health checks, and runtime telemetry provided by the CodeSentinel backend.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <PrimaryButton icon="autorenew" onClick={handleRefreshHealth} disabled={isRefreshing}>
              {isRefreshing ? 'REFRESHING...' : 'REFRESH DIAGNOSTICS'}
            </PrimaryButton>
            <SecondaryButton icon="dashboard" onClick={() => navigate('/command-center')}>
              COMMAND CENTER
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Overall System Health & Readiness Status Banner */}
      <div style={{
        padding: '16px 20px',
        backgroundColor: isHealthy ? 'rgba(52, 199, 89, 0.08)' : 'rgba(254, 183, 0, 0.08)',
        border: `1px solid ${isHealthy ? 'var(--status-green)' : 'var(--secondary-amber)'}`,
        borderRadius: 'var(--radius-xs)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        fontWeight: 700,
        color: isHealthy ? 'var(--status-green)' : 'var(--secondary-amber)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <StatusPip status={isHealthy ? 'green' : 'amber'} />
            <span>PLATFORM HEALTH: {healthData.status.toUpperCase()} ({healthData.environment?.toUpperCase() || 'DEVELOPMENT'})</span>
          </div>

          <div style={{ borderLeft: '1px solid var(--border-subtle)', height: '18px' }} />

          {/* Explicit Readiness state (Step 4) */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <StatusPip status={readinessPip} />
            <span style={{ color: readinessColor }}>
              READINESS: {readinessData.state}
            </span>
          </div>
        </div>

        <div style={{ fontSize: '11px', opacity: 0.85, textTransform: 'none', color: 'var(--text-dim)' }}>
          Last Checked: {lastChecked} | Service: {healthData.service}
        </div>
      </div>

      {/* 3. Core Component Health Grid (Real components reported by /platform/health) */}
      <DataPanel title="CORE SUBSYSTEM HEALTH CHECKS" status={isHealthy ? 'green' : 'amber'}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
          {checkComponents.map((svc) => (
            <div
              key={svc.id}
              style={{
                padding: '14px 16px',
                backgroundColor: 'var(--bg-void-lowest)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <StatusPip status={svc.status} />
                  <LabelCaps style={{ fontSize: '11px', color: 'var(--text-on-surface)' }}>
                    {svc.name}
                  </LabelCaps>
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '10px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                  backgroundColor: svc.status === 'green' ? 'rgba(52, 199, 89, 0.1)' : 'rgba(254, 183, 0, 0.1)',
                  color: svc.status === 'green' ? 'var(--status-green)' : 'var(--secondary-amber)',
                  border: `1px solid ${svc.status === 'green' ? 'var(--status-green)' : 'var(--secondary-amber)'}`
                }}>
                  {svc.response}
                </span>
              </div>
              <p style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                {svc.detail}
              </p>
            </div>
          ))}
        </div>
      </DataPanel>

      {/* 4. Real Telemetry Bento Grid (Real backend metrics from /platform/metrics) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        <MetricCard
          label="ANALYSIS REQUESTS"
          value={metrics.isAvailable ? String(metrics.requestsTotal) : 'UNAVAILABLE'}
          delta={metrics.isAvailable ? `${metrics.requestsSuccess} SUCCEEDED · ${metrics.requestsFailed} FAILED` : 'Telemetry offline'}
          accentColor="cyan"
        />
        <MetricCard
          label="SECURITY GATE VERDICTS"
          value={metrics.isAvailable ? `${metrics.decisionsAllow} ALLOW` : 'UNAVAILABLE'}
          delta={metrics.isAvailable ? `${metrics.decisionsBlock} BLOCK · ${metrics.decisionsReview} REVIEW` : 'Backend gate stats'}
          accentColor="green"
        />
        <MetricCard
          label="ANALYSIS CACHE"
          value={metrics.isAvailable ? `${metrics.cacheHits} HITS` : 'UNAVAILABLE'}
          delta={metrics.isAvailable ? `${metrics.cacheMisses} MISSES RECORDED` : 'Deterministic cache'}
          accentColor="dim"
        />
        <MetricCard
          label="LAST ANALYSIS DURATION"
          value={metrics.isAvailable ? `${metrics.lastDurationMs} ms` : '0 ms'}
          delta={metrics.isAvailable ? `${metrics.healthChecksTotal} Health Checks Counted` : 'Telemetry offline'}
          accentColor="green"
        />
      </div>

      {/* 5. Platform Capabilities & Runtime Metadata Panel (from /platform/info) */}
      <DataPanel title="PLATFORM RUNTIME CAPABILITIES &amp; METADATA" status="cyan">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
            <div style={{ padding: '10px 14px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
              <LabelCaps style={{ fontSize: '10px', color: 'var(--text-dim)' }}>SERVICE NAME</LabelCaps>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600, color: 'var(--primary-cyan)', marginTop: '4px' }}>
                {platformInfo.service}
              </div>
            </div>

            <div style={{ padding: '10px 14px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
              <LabelCaps style={{ fontSize: '10px', color: 'var(--text-dim)' }}>API VERSION</LabelCaps>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600, color: 'var(--status-green)', marginTop: '4px' }}>
                {platformInfo.apiVersion.toUpperCase()} (v{platformInfo.version})
              </div>
            </div>

            <div style={{ padding: '10px 14px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
              <LabelCaps style={{ fontSize: '10px', color: 'var(--text-dim)' }}>SUPPORTED MODES</LabelCaps>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface)', marginTop: '4px' }}>
                {platformInfo.supportedModes.length > 0 ? platformInfo.supportedModes.join(', ').toUpperCase() : 'FULL, INCREMENTAL'}
              </div>
            </div>

            <div style={{ padding: '10px 14px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
              <LabelCaps style={{ fontSize: '10px', color: 'var(--text-dim)' }}>SUPPORTED LANGUAGES</LabelCaps>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface)', marginTop: '4px' }}>
                {platformInfo.supportedLanguages.length > 0 ? platformInfo.supportedLanguages.join(', ').toUpperCase() : 'PYTHON'}
              </div>
            </div>
          </div>

          <div>
            <LabelCaps style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '8px', display: 'block' }}>
              ACTIVE PIPELINE CAPABILITIES (REPORTED BY BACKEND)
            </LabelCaps>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {platformInfo.capabilities.length > 0 ? (
                platformInfo.capabilities.map((cap) => (
                  <span
                    key={cap}
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      padding: '4px 10px',
                      borderRadius: 'var(--radius-xs)',
                      backgroundColor: 'rgba(0, 240, 255, 0.08)',
                      border: '1px solid var(--primary-cyan)',
                      color: 'var(--primary-cyan)'
                    }}
                  >
                    ✓ {cap.toUpperCase()}
                  </span>
                ))
              ) : (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
                  Loading capabilities from platform...
                </span>
              )}
            </div>
          </div>
        </div>
      </DataPanel>

      {/* 6. Platform Security Policy Profiles (from /platform/policies) */}
      <DataPanel title="SECURITY POLICY PROFILES (READ-ONLY ENFORCEMENT CONFIGURATION)" status="green">
        {policiesError ? (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--secondary-amber)' }}>
            Policy configuration unavailable: {policiesError}
          </div>
        ) : policies.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
            {policies.map((p) => (
              <div
                key={p.name}
                style={{
                  padding: '12px 14px',
                  backgroundColor: 'var(--bg-void-lowest)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
                    PROFILE: {p.name.toUpperCase()}
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: 'var(--radius-xs)',
                    backgroundColor: 'rgba(0, 240, 255, 0.1)',
                    color: 'var(--primary-cyan)',
                    border: '1px solid var(--primary-cyan)'
                  }}>
                    {p.severity_threshold}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                  <div>Max Files: {p.max_files}</div>
                  <div>Review Action: {p.review_action} | Block Action: {p.block_action}</div>
                  <div style={{ color: p.block_on_critical ? 'var(--critical-red)' : 'var(--text-dim)' }}>
                    Block on Critical: {p.block_on_critical ? 'ENABLED' : 'DISABLED'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)' }}>
            Awaiting policy profile configurations from backend...
          </div>
        )}
      </DataPanel>

      {/* 7. DevSecOps Analysis Pipeline Operational Stages */}
      <DataPanel title="DEVSECOPS ANALYSIS PIPELINE OPERATIONAL STAGES" status="cyan">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
          
          <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--status-green)' }}>
              <StatusPip status="green" />
              <LabelCaps style={{ fontSize: '9px' }}>1. INTAKE</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>URL Validation</span>
          </div>

          <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--status-green)' }}>
              <StatusPip status="green" />
              <LabelCaps style={{ fontSize: '9px' }}>2. ACQUISITION</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>Workspace Isolation</span>
          </div>

          <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--status-green)' }}>
              <StatusPip status="green" />
              <LabelCaps style={{ fontSize: '9px' }}>3. AST ENGINE</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>Python AST Parser</span>
          </div>

          <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--primary-cyan)' }}>
              <StatusPip status="cyan" />
              <LabelCaps style={{ fontSize: '9px' }}>4. RAG GROUNDING</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>ChromaDB Retrieval</span>
          </div>

          <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--primary-cyan)' }}>
              <StatusPip status="cyan" />
              <LabelCaps style={{ fontSize: '9px' }}>5. AI REASONING</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>Provider Pipeline</span>
          </div>

          <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--status-green)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--status-green)' }}>
              <StatusPip status="green" />
              <LabelCaps style={{ fontSize: '9px' }}>6. REPORT CONTRACT</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--status-green)' }}>Step 6O Format</span>
          </div>

        </div>
      </DataPanel>

      {/* 8. System Operational Events Log Table */}
      <DataPanel title="SYSTEM OPERATIONAL EVENTS LOG" status="green">
        <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
          {/* Header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '150px 180px 90px 1fr',
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
            <div>COMPONENT</div>
            <div>LEVEL</div>
            <div>EVENT DESCRIPTION</div>
          </div>

          {/* Log Rows */}
          {eventLogs.map((log) => (
            <div
              key={log.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '150px 180px 90px 1fr',
                gap: '12px',
                padding: '10px 16px',
                borderBottom: '1px solid var(--border-subtle)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                alignItems: 'center'
              }}
            >
              <div style={{ color: 'var(--text-dim)' }}>{log.time}</div>
              <div style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>{log.component}</div>
              <div>
                <span style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                  backgroundColor: log.level === 'INFO' ? 'rgba(52, 199, 89, 0.1)' : log.level === 'WARN' ? 'rgba(254, 183, 0, 0.1)' : 'rgba(255, 59, 48, 0.1)',
                  color: log.level === 'INFO' ? 'var(--status-green)' : log.level === 'WARN' ? 'var(--secondary-amber)' : 'var(--critical-red)',
                  border: `1px solid ${log.level === 'INFO' ? 'var(--status-green)' : log.level === 'WARN' ? 'var(--secondary-amber)' : 'var(--critical-red)'}`
                }}>
                  {log.level}
                </span>
              </div>
              <div style={{ color: 'var(--text-on-surface)' }}>{log.msg}</div>
            </div>
          ))}
        </div>
      </DataPanel>

    </div>
  );
}
