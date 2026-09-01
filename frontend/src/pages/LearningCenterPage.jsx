import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import SeverityBadge from '../components/SeverityBadge';
import ReviewStatusBanner from '../components/ReviewStatusBanner';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';
import CodeViewer from '../components/CodeViewer';
import EvidenceSnippet from '../components/EvidenceSnippet';

export default function LearningCenterPage() {
  const navigate = useNavigate();

  // Initial findings presentation list with interactive false-positive suppression state
  const [findingsList, setFindingsList] = useState([
    {
      finding_id: 'finding_1',
      title: 'Hardcoded Secret Assignment in App Config',
      description: 'Detected hardcoded secret string literal assigned to JWT_SECRET in config initialization.',
      severity: 'critical',
      confidence: 'high',
      category: 'security',
      suppressed: false,
      suppression_reason: null,
      evidence: [
        {
          document_id: 'src/flask/config.py',
          line_start: 42,
          line_end: 42,
          signal_type: 'AST_SECRET_LITERAL',
          signal_name: 'jwt_secret_assignment',
          lines: [
            '# Flask Config Settings',
            'DEBUG = True',
            'JWT_SECRET = "[REDACTED_SECRET]"  # Hardcoded secret literal',
            'SESSION_COOKIE_SECURE = True'
          ]
        }
      ]
    },
    {
      finding_id: 'finding_2',
      title: 'Unsafe Pickle Deserialization Invocations',
      description: 'Legacy session decoder uses pickle.loads on unauthenticated bytes.',
      severity: 'critical',
      confidence: 'high',
      category: 'security',
      suppressed: false,
      suppression_reason: null,
      evidence: [
        {
          document_id: 'src/flask/sessions.py',
          line_start: 108,
          line_end: 108,
          signal_type: 'AST_DESERIALIZATION',
          signal_name: 'pickle_loads_invocation',
          lines: [
            'def load_session(raw_bytes):',
            '    # Legacy session decoder',
            '    return pickle.loads(raw_bytes)  # Unsafe deserialization vector'
          ]
        }
      ]
    },
    {
      finding_id: 'finding_3',
      title: 'Test Dummy Secret in Test Suite Helper',
      description: 'Test mock secret key detected in test/fixtures/mock_auth.py.',
      severity: 'medium',
      confidence: 'medium',
      category: 'security',
      suppressed: true,
      suppression_reason: 'Marked as false positive: Test fixture mock credential',
      evidence: [
        {
          document_id: 'tests/fixtures/mock_auth.py',
          line_start: 15,
          line_end: 15,
          signal_type: 'AST_SECRET_LITERAL',
          signal_name: 'mock_test_credential',
          lines: [
            '# Test Mock Credentials',
            'MOCK_API_KEY = "test_key_12345_mock"  # Test fixture'
          ]
        }
      ]
    },
    {
      finding_id: 'finding_4',
      title: 'Internal Debug Logger Invocations',
      description: 'Verbose debug log statement in development helper script.',
      severity: 'low',
      confidence: 'low',
      category: 'security',
      suppressed: true,
      suppression_reason: 'Marked as false positive: Internal dev script logging',
      evidence: [
        {
          document_id: 'src/flask/cli.py',
          line_start: 92,
          line_end: 92,
          signal_type: 'AST_LOGGER',
          signal_name: 'verbose_debug_print',
          lines: [
            'def debug_dump(ctx):',
            '    print("DEBUG CTX:", ctx)'
          ]
        }
      ]
    }
  ]);

  // Policy tuning preset state
  const [selectedPolicy, setSelectedPolicy] = useState('BALANCED');
  const [filterType, setFilterType] = useState('ALL');
  const [selectedFindingId, setSelectedFindingId] = useState('finding_1');

  // Compute telemetry metrics dynamically from presentation state
  const totalFindings = 17;
  const suppressedCount = findingsList.filter((f) => f.suppressed).length + 1; // 3 in presentation state
  const confirmedCount = totalFindings - suppressedCount;
  const candidateCount = 2;

  // Filtered findings list
  const filteredFindings = findingsList.filter((f) => {
    if (filterType === 'SUPPRESSED') return f.suppressed;
    if (filterType === 'CRITICAL') return f.severity.toUpperCase() === 'CRITICAL';
    if (filterType === 'HIGH') return f.severity.toUpperCase() === 'HIGH';
    if (filterType === 'MEDIUM') return f.severity.toUpperCase() === 'MEDIUM';
    if (filterType === 'LOW') return f.severity.toUpperCase() === 'LOW';
    return true;
  });

  // Active finding object
  const activeFinding =
    findingsList.find((f) => f.finding_id === selectedFindingId) || findingsList[0];

  const activeEvidence = activeFinding?.evidence?.[0];

  // Toggle false-positive suppression status for selected finding
  const handleToggleSuppression = (findingId) => {
    setFindingsList((prev) =>
      prev.map((item) => {
        if (item.finding_id === findingId) {
          const nextSuppressed = !item.suppressed;
          return {
            ...item,
            suppressed: nextSuppressed,
            suppression_reason: nextSuppressed
              ? 'Marked as false positive: Manually tuned policy override'
              : null
          };
        }
        return item;
      })
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Page Context & Header */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                FINDING NORMALIZATION &amp; POLICY TUNING WORKSPACE
              </LabelCaps>
              <StatusPip status="cyan" title="Normalization Engine Operational" />
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              False-Positive Learning Center
            </h1>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-on-surface-variant)' }}>
              Normalize findings, tune false-positive suppression rules, and train deterministic false-positive filters.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="search" onClick={() => navigate('/vulnerability-explorer')}>
              VULNERABILITY EXPLORER
            </SecondaryButton>
            <SecondaryButton icon="psychology" onClick={() => navigate('/ai-analysis')}>
              AI ANALYSIS CENTER
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Normalization Telemetry Bento Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <MetricCard
          label="TOTAL FINDINGS"
          value={totalFindings}
          delta="REPOSITORY AUDIT SCOPE"
          accentColor="cyan"
        />
        <MetricCard
          label="SUPPRESSED FINDINGS"
          value={suppressedCount}
          delta="FALSE POSITIVES TUNED"
          accentColor="amber"
        />
        <MetricCard
          label="CONFIRMED FINDINGS"
          value={confirmedCount}
          delta="ACTIVE SECURITY RISKS"
          accentColor="red"
        />
        <MetricCard
          label="LEARNING CANDIDATES"
          value={candidateCount}
          delta="AUTO-TUNING PATTERNS"
          accentColor="green"
        />
      </div>

      {/* 3. Rule Tuning & Policy Presets Panel */}
      <DataPanel title="SECURITY POLICY RULE PRESET TUNING" status="cyan">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <LabelCaps style={{ fontSize: '10px' }}>POLICY PRESET:</LabelCaps>
            {['STRICT SECURITY', 'BALANCED', 'DEVELOPMENT'].map((policy) => (
              <button
                key={policy}
                onClick={() => setSelectedPolicy(policy)}
                style={{
                  backgroundColor: selectedPolicy === policy ? 'var(--primary-cyan)' : 'var(--bg-void-lowest)',
                  color: selectedPolicy === policy ? 'var(--text-inverse)' : 'var(--text-on-surface-variant)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '6px 14px',
                  cursor: 'pointer'
                }}
              >
                {policy}
              </button>
            ))}
          </div>

          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
            CURRENT POLICY: <strong style={{ color: 'var(--primary-cyan)' }}>{selectedPolicy}</strong> (Suppresses test mocks &amp; internal logs)
          </div>
        </div>
      </DataPanel>

      {/* 4. Master Findings Table & Grounded Evidence Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Left Findings Master List Panel (5 cols) */}
        <div style={{ gridColumn: 'span 5' }}>
          <DataPanel
            title="FINDINGS NORMALIZATION LIST"
            status="amber"
            action={
              <div style={{ display: 'flex', gap: '4px' }}>
                {['ALL', 'CRITICAL', 'HIGH', 'SUPPRESSED'].map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setFilterType(filter)}
                    style={{
                      backgroundColor: filterType === filter ? 'var(--primary-cyan)' : 'var(--bg-void-lowest)',
                      color: filterType === filter ? 'var(--text-inverse)' : 'var(--text-on-surface-variant)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '3px 8px',
                      cursor: 'pointer'
                    }}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            }
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {filteredFindings.map((finding) => {
                const isSelected = finding.finding_id === activeFinding?.finding_id;
                return (
                  <div
                    key={finding.finding_id}
                    onClick={() => setSelectedFindingId(finding.finding_id)}
                    style={{
                      padding: '12px',
                      backgroundColor: isSelected ? 'var(--panel-bg-high)' : 'var(--bg-void-lowest)',
                      border: isSelected ? '1px solid var(--primary-cyan)' : '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      transition: 'all 0.15s ease-in-out'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <LabelCaps style={{ fontSize: '10px' }}>{finding.finding_id}</LabelCaps>
                        {finding.suppressed && (
                          <span style={{
                            backgroundColor: 'rgba(254, 183, 0, 0.15)',
                            color: 'var(--secondary-amber)',
                            border: '1px solid var(--secondary-amber)',
                            fontSize: '9px',
                            fontWeight: 700,
                            padding: '1px 5px',
                            borderRadius: 'var(--radius-xs)',
                            fontFamily: 'var(--font-mono)'
                          }}>
                            SUPPRESSED
                          </span>
                        )}
                      </div>
                      <SeverityBadge severity={finding.severity} />
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-on-surface)' }}>
                      {finding.title}
                    </div>
                    <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                      {finding.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </DataPanel>
        </div>

        {/* Right Grounded Evidence & False-Positive Action Inspector (7 cols) */}
        <div style={{ gridColumn: 'span 7' }}>
          <DataPanel
            title={`FINDING NORMALIZATION INSPECTOR — ${activeFinding?.finding_id || ''}`}
            status="cyan"
            action={<SeverityBadge severity={activeFinding?.severity || 'info'} />}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Finding Title & Description */}
              <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
                  {activeFinding?.title}
                </div>
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-on-surface-variant)', lineHeight: 1.5 }}>
                  {activeFinding?.description}
                </p>
                {activeFinding?.suppressed && (
                  <div style={{ marginTop: '4px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--secondary-amber)' }}>
                    &gt; STATUS: SUPPRESSED ({activeFinding.suppression_reason})
                  </div>
                )}
              </div>

              {/* False-Positive Toggle Action Button Bar */}
              <div style={{ display: 'flex', items: 'center', justifyContent: 'space-between', padding: '12px', backgroundColor: 'var(--panel-bg-high)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <div>
                  <LabelCaps style={{ fontSize: '10px' }}>FALSE-POSITIVE NORMALIZATION ACTION</LabelCaps>
                  <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '2px' }}>
                    Toggling suppression updates deterministic severity &amp; finding counts.
                  </div>
                </div>

                <PrimaryButton
                  icon={activeFinding?.suppressed ? 'undo' : 'do_not_disturb_on'}
                  onClick={() => handleToggleSuppression(activeFinding.finding_id)}
                >
                  {activeFinding?.suppressed ? 'RESTORE AS CONFIRMED FINDING' : 'MARK AS FALSE POSITIVE / SUPPRESS'}
                </PrimaryButton>
              </div>

              {/* Evidence Snippet */}
              {activeEvidence && (
                <EvidenceSnippet
                  documentId={activeEvidence.document_id}
                  lineStart={activeEvidence.line_start}
                  lineEnd={activeEvidence.line_end}
                  signalType={activeEvidence.signal_type}
                  signalName={activeEvidence.signal_name}
                />
              )}

              {/* Code Viewer */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>STATIC SOURCE CODE EVIDENCE</LabelCaps>
                <CodeViewer
                  lines={activeEvidence?.lines || ['# Code snippet not loaded']}
                  startLine={(activeEvidence?.line_start || 40) - 2}
                  highlightRange={{
                    start: activeEvidence?.line_start || 42,
                    end: activeEvidence?.line_end || 42
                  }}
                />
              </div>
            </div>
          </DataPanel>
        </div>

      </div>

    </div>
  );
}
