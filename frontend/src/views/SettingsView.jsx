import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  getPlatformInfo,
  getPlatformHealth,
  getPlatformReadiness,
  getPlatformReleaseReadiness,
  getPlatformPolicies,
} from '../services/apiClient';
import StatusBadge from '../components/StatusBadge';
import {
  SettingsIcon,
  ShieldLogo,
  ToolsIcon,
  ReviewsIcon,
} from '../components/dashboard/Icons';

/**
 * Sanitize error messages to avoid displaying local filesystem paths,
 * database paths, environment variables, or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred while loading settings.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

const SETTINGS_TABS = [
  { id: 'application', label: 'Application & System' },
  { id: 'policies', label: 'Security Policies' },
  { id: 'capabilities', label: 'Analysis Capabilities' },
  { id: 'preferences', label: 'UI Preferences' },
  { id: 'diagnostics', label: 'Platform Readiness' },
];

export default function SettingsView() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Active Tab from URL search params or default
  const activeTab = searchParams.get('tab')?.toLowerCase() || 'application';

  const setTab = (tabId) => {
    setSearchParams({ tab: tabId }, { replace: true });
  };

  // Data states from backend
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [platformInfo, setPlatformInfo] = useState(null);
  const [platformHealth, setPlatformHealth] = useState(null);
  const [platformReadiness, setPlatformReadiness] = useState(null);
  const [releaseReadiness, setReleaseReadiness] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [selectedPolicyName, setSelectedPolicyName] = useState('default');

  // Client-side UI Preferences (strictly non-sensitive, stored in localStorage)
  const [uiTheme, setUiTheme] = useState(() => {
    try {
      return localStorage.getItem('cs_pref_theme') || 'light';
    } catch {
      return 'light';
    }
  });

  const [uiDensity, setUiDensity] = useState(() => {
    try {
      return localStorage.getItem('cs_pref_density') || 'comfortable';
    } catch {
      return 'comfortable';
    }
  });

  const [uiLineNums, setUiLineNums] = useState(() => {
    try {
      return localStorage.getItem('cs_pref_linenums') === 'true';
    } catch {
      return true;
    }
  });

  const [prefSaveNotice, setPrefSaveNotice] = useState(null);

  // Load backend configuration & telemetry
  const loadSettingsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [infoRes, healthRes, readinessRes, releaseRes, policiesRes] = await Promise.allSettled([
        getPlatformInfo(),
        getPlatformHealth(),
        getPlatformReadiness(),
        getPlatformReleaseReadiness(),
        getPlatformPolicies(),
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
    } catch (err) {
      setError(sanitizeErrorMessage(err.message || 'Failed to retrieve platform configuration.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettingsData();
  }, []);

  // Save UI Preferences locally
  const handleSavePreferences = (e) => {
    e.preventDefault();
    try {
      localStorage.setItem('cs_pref_theme', uiTheme);
      localStorage.setItem('cs_pref_density', uiDensity);
      localStorage.setItem('cs_pref_linenums', String(uiLineNums));
      setPrefSaveNotice('UI presentation preferences saved locally in this browser.');
      setTimeout(() => setPrefSaveNotice(null), 3000);
    } catch {
      setPrefSaveNotice('Local storage unavailable. Preferences remain active for this session only.');
    }
  };

  // Currently inspected policy
  const activePolicy = useMemo(() => {
    if (!Array.isArray(policies) || policies.length === 0) return null;
    return policies.find((p) => p.name === selectedPolicyName) || policies[0];
  }, [policies, selectedPolicyName]);

  return (
    <div className="cs-settings-workspace-view" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Banner */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <SettingsIcon size={22} color="#6366F1" />
              <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                CodeSentinel Settings &amp; Platform Configuration
              </h1>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
              Inspect authoritative server security policies, engine specifications, release readiness status, and manage client presentation preferences.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Environment: <strong>Production / Verified</strong>
            </span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={loadSettingsData}
              disabled={loading}
              aria-label="Refresh settings and platform metadata"
            >
              ↻ Refresh Settings
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="alert-box alert-error" role="alert">
          <div>{error}</div>
        </div>
      )}

      {/* Settings Section Navigation Tabs */}
      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }} role="tablist" aria-label="Settings Sections">
        {SETTINGS_TABS.map((tab) => {
          const isSelected = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={isSelected}
              onClick={() => setTab(tab.id)}
              style={{
                fontSize: '12.5px',
                fontWeight: 600,
                padding: '8px 14px',
                borderRadius: '6px',
                border: isSelected ? '1px solid #6366F1' : '1px solid var(--border-subtle)',
                background: isSelected ? '#6366F1' : 'var(--bg-card)',
                color: isSelected ? '#FFFFFF' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Loading State */}
      {loading ? (
        <div className="card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Loading platform configuration and policy profiles...
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* TAB 1: Application & System Information */}
          {activeTab === 'application' && (
            <div className="card" style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 4px' }}>
                  Application Baseline Information
                </h2>
                <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
                  Active platform release specification, verified engine versions, and static boundary verification.
                </p>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '14px',
                  marginBottom: '20px',
                }}
              >
                <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-void)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block' }}>
                    Platform Service
                  </span>
                  <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                    {platformInfo?.service || 'CodeSentinel'}
                  </div>
                </div>

                <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-void)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block' }}>
                    Platform Version
                  </span>
                  <div style={{ fontSize: '14px', fontWeight: 700, color: '#6366F1', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                    v{platformInfo?.version || '1.1.0'}
                  </div>
                </div>

                <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-void)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block' }}>
                    API Protocol Version
                  </span>
                  <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                    {platformInfo?.api_version || 'v1'}
                  </div>
                </div>

                <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-void)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block' }}>
                    Backend Health State
                  </span>
                  <div style={{ marginTop: '4px' }}>
                    <StatusBadge status={platformHealth?.status === 'healthy' ? 'ONLINE' : 'REVIEW'} />
                  </div>
                </div>
              </div>

              {/* Security Boundary Notice */}
              <div
                style={{
                  backgroundColor: 'rgba(99, 102, 241, 0.05)',
                  border: '1px solid rgba(99, 102, 241, 0.2)',
                  borderRadius: '6px',
                  padding: '14px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                }}
              >
                <span style={{ fontSize: '18px' }} aria-hidden="true">🛡️</span>
                <div>
                  <strong style={{ fontSize: '12.5px', color: '#4338CA', display: 'block' }}>
                    Deterministic Static Non-Execution Architecture
                  </strong>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0', lineHeight: 1.45 }}>
                    CodeSentinel statically analyzes source AST representations and diff modifications without code execution. Environment variables, database paths, and API keys remain strictly confined to the backend server and are never exposed across client interfaces.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Security Policy Profiles (Read-Only) */}
          {activeTab === 'policies' && (
            <div className="card" style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                  <div>
                    <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 4px' }}>
                      Authoritative Security Policy Profiles
                    </h2>
                    <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
                      Inspect the deterministic policy profiles evaluated by Step 6O security gates.
                    </p>
                  </div>
                  <span
                    style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '3px 8px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(16, 185, 129, 0.1)',
                      color: '#059669',
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                    }}
                  >
                    SERVER-ENFORCED (READ-ONLY)
                  </span>
                </div>
              </div>

              {/* Policy Selector Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Policy Profile:
                </span>
                {policies.map((p) => (
                  <button
                    key={p.name}
                    type="button"
                    onClick={() => setSelectedPolicyName(p.name)}
                    className={`btn btn-sm ${selectedPolicyName === p.name ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ fontSize: '11.5px', padding: '4px 12px' }}
                    aria-pressed={selectedPolicyName === p.name}
                  >
                    {p.name.toUpperCase()}
                  </button>
                ))}
              </div>

              {activePolicy ? (
                <div
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-subtle)',
                    backgroundColor: 'var(--bg-void)',
                  }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
                      gap: '12px',
                      marginBottom: '16px',
                    }}
                  >
                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Severity Threshold</span>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                        {String(activePolicy.severity_threshold).toUpperCase()}
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Max File Limit</span>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                        {activePolicy.max_files} files
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Review Action</span>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: '#F59E0B', marginTop: '2px' }}>
                        {String(activePolicy.review_action).toUpperCase()}
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Block Action</span>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: '#EF4444', marginTop: '2px' }}>
                        {String(activePolicy.block_action).toUpperCase()}
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Block on Critical</span>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: activePolicy.block_on_critical ? '#EF4444' : '#10B981', marginTop: '2px' }}>
                        {activePolicy.block_on_critical ? 'YES (Enforced)' : 'NO'}
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Block on High</span>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: activePolicy.block_on_high ? '#EF4444' : '#10B981', marginTop: '2px' }}>
                        {activePolicy.block_on_high ? 'YES (Enforced)' : 'NO'}
                      </div>
                    </div>
                  </div>

                  <div>
                    <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '8px' }}>
                      Enabled Vulnerability Rules ({activePolicy.enabled_categories?.length || 0}):
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {(activePolicy.enabled_categories || []).map((cat) => (
                        <span
                          key={cat}
                          style={{
                            fontSize: '11px',
                            padding: '3px 8px',
                            borderRadius: '4px',
                            backgroundColor: 'var(--bg-card)',
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
                </div>
              ) : (
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  No policy profile data available.
                </div>
              )}

              <div style={{ marginTop: '16px', padding: '12px', backgroundColor: 'var(--bg-void)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>
                  ℹ️ <strong>Server Authority:</strong> Policy profiles are configured on the backend server and cannot be overridden by client requests. This preserves the immutable integrity of CI/CD security gate decisions.
                </p>
              </div>
            </div>
          )}

          {/* TAB 3: Analysis Capabilities */}
          {activeTab === 'capabilities' && (
            <div className="card" style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 4px' }}>
                  Supported Engine Capabilities
                </h2>
                <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
                  Confirmed analysis pipeline engines and supported execution modes.
                </p>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
                  Enabled Subsystems &amp; Features ({platformInfo?.enabled_capabilities?.length || 0})
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
                  {(platformInfo?.enabled_capabilities || []).map((cap) => (
                    <div
                      key={cap}
                      style={{
                        padding: '10px 12px',
                        backgroundColor: 'var(--bg-void)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                      }}
                    >
                      <span style={{ color: '#10B981', fontWeight: 700 }}>✓</span>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                        {cap}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                  gap: '12px',
                  padding: '14px',
                  backgroundColor: 'var(--bg-void)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                }}
              >
                <div>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Supported Languages</span>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                    {(platformInfo?.supported_languages || ['python']).join(', ').toUpperCase()}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Analysis Modes</span>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                    {(platformInfo?.supported_analysis_modes || ['full', 'incremental']).join(', ').toUpperCase()}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Gate Outcomes</span>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#0284C7', marginTop: '2px' }}>
                    {(platformInfo?.security_gate_outcomes || ['ALLOW', 'REVIEW', 'BLOCK']).join(' | ')}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: UI Preferences (Client-Side Only) */}
          {activeTab === 'preferences' && (
            <div className="card" style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 4px' }}>
                  Client UI Presentation Preferences
                </h2>
                <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
                  Customize non-security visual preferences. These settings are persisted locally in your browser.
                </p>
              </div>

              {prefSaveNotice && (
                <div className="alert-box alert-success" style={{ marginBottom: '16px' }} role="status">
                  <div>{prefSaveNotice}</div>
                </div>
              )}

              <form onSubmit={handleSavePreferences} style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '480px' }}>
                <div>
                  <label htmlFor="pref-theme" className="form-label" style={{ fontSize: '12px' }}>
                    Color Theme Mode
                  </label>
                  <select
                    id="pref-theme"
                    value={uiTheme}
                    onChange={(e) => setUiTheme(e.target.value)}
                    className="form-input"
                    style={{ fontSize: '12px' }}
                  >
                    <option value="light">Light Theme (Default)</option>
                    <option value="dark">Dark Theme</option>
                  </select>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', display: 'block' }}>
                    Controls workspace color scheme contrast.
                  </span>
                </div>

                <div>
                  <label htmlFor="pref-density" className="form-label" style={{ fontSize: '12px' }}>
                    Table &amp; List Display Density
                  </label>
                  <select
                    id="pref-density"
                    value={uiDensity}
                    onChange={(e) => setUiDensity(e.target.value)}
                    className="form-input"
                    style={{ fontSize: '12px' }}
                  >
                    <option value="comfortable">Comfortable (Standard Padding)</option>
                    <option value="compact">Compact (Dense Rows)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <input
                    type="checkbox"
                    id="pref-linenums"
                    checked={uiLineNums}
                    onChange={(e) => setUiLineNums(e.target.checked)}
                    style={{ cursor: 'pointer' }}
                  />
                  <label htmlFor="pref-linenums" style={{ fontSize: '12.5px', color: 'var(--text-primary)', cursor: 'pointer', margin: 0 }}>
                    Display code snippet line numbers in finding inspection cards
                  </label>
                </div>

                <div style={{ paddingTop: '10px' }}>
                  <button type="submit" className="btn btn-primary btn-sm">
                    Save UI Preferences
                  </button>
                </div>
              </form>

              <div style={{ marginTop: '20px', padding: '12px', backgroundColor: 'var(--bg-void)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', margin: 0 }}>
                  🔒 <strong>Privacy Assurance:</strong> UI presentation preferences do not store authentication credentials, API tokens, or source code.
                </p>
              </div>
            </div>
          )}

          {/* TAB 5: Platform Diagnostics & Subsystems */}
          {activeTab === 'diagnostics' && (
            <div className="card" style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                  <div>
                    <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 4px' }}>
                      Subsystem Verification &amp; Release Diagnostics
                    </h2>
                    <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
                      Operational status of all 5A–6W platform layers verified against server diagnostics.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => navigate('/tools')}
                  >
                    Open Full Tools &amp; Probes Workspace →
                  </button>
                </div>
              </div>

              {releaseReadiness?.subsystems ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', marginBottom: '20px' }}>
                  {Object.entries(releaseReadiness.subsystems).map(([key, sub]) => (
                    <div
                      key={key}
                      style={{
                        padding: '12px',
                        borderRadius: '6px',
                        border: '1px solid var(--border-subtle)',
                        backgroundColor: 'var(--bg-void)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '4px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)', textTransform: 'capitalize' }}>
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
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic', marginBottom: '20px' }}>
                  Subsystem readiness data currently unavailable.
                </div>
              )}

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate('/system')}
                >
                  Inspect Low-Level Probes in System →
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate('/tools')}
                >
                  Run Diagnostic Verifier in Tools →
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
