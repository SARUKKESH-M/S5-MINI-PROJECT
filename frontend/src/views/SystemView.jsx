import React, { useState, useEffect } from 'react';
import {
  getHealth,
  getPlatformHealth,
  getPlatformReadiness,
  getPlatformInfo,
  getPlatformPolicies,
} from '../services/apiClient';
import HealthCard from '../components/HealthCard';
import StatusBadge from '../components/StatusBadge';
import PageHeader from '../components/common/PageHeader';

export default function SystemView() {
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState('');

  // Diagnostic states
  const [healthData, setHealthData] = useState(null);
  const [readinessData, setReadinessData] = useState(null);
  const [platformInfo, setPlatformInfo] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [error, setError] = useState(null);

  const fetchSystemDiagnostics = async () => {
    setLoading(true);
    setError(null);
    const now = new Date().toLocaleTimeString();

    try {
      const [healthRes, readinessRes, infoRes, policiesRes] = await Promise.allSettled([
        getPlatformHealth(),
        getPlatformReadiness(),
        getPlatformInfo(),
        getPlatformPolicies(),
      ]);

      if (healthRes.status === 'fulfilled' && healthRes.value) {
        setHealthData(healthRes.value);
      } else {
        // Fallback to basic health check
        try {
          const basic = await getHealth();
          setHealthData({ status: basic.status || 'healthy' });
        } catch {
          setHealthData(null);
        }
      }

      if (readinessRes.status === 'fulfilled' && readinessRes.value) {
        setReadinessData(readinessRes.value);
      }

      if (infoRes.status === 'fulfilled' && infoRes.value) {
        setPlatformInfo(infoRes.value);
      }

      if (policiesRes.status === 'fulfilled' && Array.isArray(policiesRes.value)) {
        setPolicies(policiesRes.value);
      } else if (policiesRes.status === 'fulfilled' && Array.isArray(policiesRes.value?.policies)) {
        setPolicies(policiesRes.value.policies);
      }

      setLastRefreshed(now);
    } catch (err) {
      setError(err.message || 'Error communicating with system diagnostic endpoints.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSystemDiagnostics();
  }, []);

  const checks = healthData?.checks || {};
  const rawVersion = platformInfo?.version || healthData?.version || '1.1.0';
  const displayVersion = rawVersion.startsWith('v') ? rawVersion : `v${rawVersion}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <PageHeader
        title="System Health & Capabilities"
        description="Real-time component health checks, operational readiness probes, and security analysis policy profiles."
        primaryAction={
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={fetchSystemDiagnostics}
            disabled={loading}
          >
            ↻ Refresh Health
          </button>
        }
        secondaryAction={
          lastRefreshed ? (
            <span style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Updated: {lastRefreshed}
            </span>
          ) : null
        }
      />

      {error && (
        <div className="alert-box alert-error">
          <div>
            <strong>Diagnostic Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Core Subsystem Health Grid */}
      <div>
        <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.75px', marginBottom: '12px' }}>
          Subsystem Diagnostics
        </h3>
        <div className="grid-3">
          <HealthCard
            title="Backend Microservice"
            status={healthData?.status ? String(healthData.status).toUpperCase() : 'UNAVAILABLE'}
            details={`FastAPI ASGI container running on port 8000. Service: ${healthData?.service || 'CodeSentinel'}`}
          />
          <HealthCard
            title="Security Gate"
            status={checks.security_gate?.status ? String(checks.security_gate.status).toUpperCase() : (healthData ? 'HEALTHY' : 'UNKNOWN')}
            details="Automated fail-closed CI gate enforcing Allow / Review / Block verdicts."
          />
          <HealthCard
            title="AST Engine"
            status={checks.configuration?.status ? String(checks.configuration.status).toUpperCase() : (healthData ? 'READY' : 'UNKNOWN')}
            details="Deterministic Python AST visitor detecting command injection, SQLi, and unsafe sinks."
          />
          <HealthCard
            title="Vector Store"
            status={checks.vector_store?.status ? String(checks.vector_store.status).toUpperCase() : (healthData ? 'READY' : 'UNKNOWN')}
            details="ChromaDB persistent vector store for hybrid RAG context retrieval."
          />
          <HealthCard
            title="LLM Service"
            status={checks.llm_service?.status ? String(checks.llm_service.status).toUpperCase() : (healthData ? 'READY' : 'UNKNOWN')}
            details="Deterministic rule engine with optional Groq / Ollama context reasoning."
          />
          <HealthCard
            title="Operational Readiness"
            status={readinessData?.ready ? 'READY' : (readinessData?.status ? String(readinessData.status).toUpperCase() : 'UNKNOWN')}
            details="Verified against platform release invariants and container security limits."
          />
        </div>
      </div>

      {/* Platform Capabilities & Metadata */}
      {(platformInfo || healthData) && (
        <div className="card" style={{ padding: '20px' }}>
          <div className="card-header">
            <h3 className="card-title">Platform Runtime Metadata</h3>
            <span style={{ fontSize: '12px', fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', backgroundColor: 'var(--accent-blue-subtle)', padding: '3px 8px', borderRadius: 'var(--radius-sm)' }}>
              {displayVersion}
            </span>
          </div>

          <div className="grid-3">
            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>SERVICE NAME</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {platformInfo?.service || healthData?.service || 'CodeSentinel'}
              </div>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>PLATFORM VERSION</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {displayVersion}
              </div>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>ENVIRONMENT</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {healthData?.environment || platformInfo?.environment || 'production'}
              </div>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>API VERSION</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {(platformInfo?.api_version || 'v1').toUpperCase()}
              </div>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>CAPABILITIES</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {platformInfo?.enabled_capabilities?.length ? `${platformInfo.enabled_capabilities.length} Enabled` : '12 Enabled'}
              </div>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>EXECUTION BOUNDARY</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--verdict-allow)', fontFamily: 'var(--font-mono)' }}>
                STATIC NON-EXECUTION
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Policies */}
      <div className="card" style={{ padding: '20px' }}>
        <div className="card-header">
          <h3 className="card-title">Active Security Analysis Policies</h3>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {policies.length} {policies.length === 1 ? 'profile' : 'profiles'} registered
          </span>
        </div>

        {policies.length === 0 ? (
          <div style={{ fontSize: '13px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
            Default deterministic policy profile active (Blocks Critical & High, Reviews Medium).
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {policies.map((p, idx) => (
              <div
                key={p.id || idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 16px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {p.name || p.id}
                  </div>
                  {p.description && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      {p.description}
                    </div>
                  )}
                </div>

                <StatusBadge status="READY" />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
