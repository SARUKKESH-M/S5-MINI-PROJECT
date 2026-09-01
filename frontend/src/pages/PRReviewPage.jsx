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

export default function PRReviewPage() {
  const navigate = useNavigate();

  // Local presentation data structurally aligned with Step 6O Production Report Contract
  const [report] = useState({
    status: 'success',
    review_status: 'block',
    analysis_id: 'repo_ana_demo_pr142',
    repository: {
      owner: 'pallets',
      repository: 'flask',
      branch: 'fix/auth-bypass',
      path: './'
    },
    pr_info: {
      number: 142,
      title: 'Fix authentication bypass in session management',
      author: 'security-team',
      commit: '8f2a1c9'
    },
    summary: {
      total_files: 12,
      analyzed_files: 12,
      skipped_files: 0,
      total_findings: 2,
      critical_count: 1,
      high_count: 1,
      medium_count: 0,
      low_count: 0,
      info_count: 0
    },
    findings: [
      {
        finding_id: 'finding_1',
        title: 'Hardcoded Secret Assignment',
        description: 'Detected hardcoded secret string assignment to JWT_SECRET config key.',
        severity: 'critical',
        confidence: 'high',
        category: 'security',
        evidence: [
          {
            document_id: 'src/flask/config.py',
            line_start: 42,
            line_end: 42,
            signal_type: 'AST_SECRET_LITERAL',
            signal_name: 'jwt_secret_assignment',
            lines: [
              '# Flask Application Configuration',
              'DEBUG = True',
              'JWT_SECRET = "[REDACTED_SECRET]"  # Violates secret security policy',
              'SESSION_COOKIE_SECURE = True'
            ]
          }
        ]
      },
      {
        finding_id: 'finding_2',
        title: 'Unsafe Deserialization in Session Load',
        description: 'Potential untrusted pickle deserialization detected in legacy session loader.',
        severity: 'high',
        confidence: 'medium',
        category: 'security',
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
      }
    ],
    analysis_version: '1.0'
  });

  // Selected finding state for evidence inspection
  const [selectedFindingId, setSelectedFindingId] = useState('finding_1');

  const activeFinding =
    report.findings.find((f) => f.finding_id === selectedFindingId) || report.findings[0];

  const activeEvidence = activeFinding?.evidence?.[0];

  // Security rule evaluation checklist
  const securityRules = [
    { name: 'AST Structural Analysis', status: 'pass', detail: '12 Python source files parsed cleanly' },
    { name: 'Hardcoded Secret Detection', status: 'fail', detail: '1 Critical secret assignment detected in config.py' },
    { name: 'Injection Vector Scanner', status: 'pass', detail: 'Zero SQLi/Command injection patterns found' },
    { name: 'Dynamic Execution Boundary', status: 'pass', detail: 'Verified zero eval/exec/os.system invocations' },
    { name: 'Knowledge Retrieval Grounding', status: 'pass', detail: 'CWE-798 & OWASP A07 grounding matches verified' },
    { name: 'LLM Security Decision Engine', status: 'block', detail: 'Policy Block triggered due to Critical finding' }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. PR Header & Technical Review Context */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                PR #{report.pr_info.number} REVIEW WORKSPACE
              </LabelCaps>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
                Commit: {report.pr_info.commit}
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              {report.pr_info.title}
            </h1>
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface-variant)' }}>
              <span>REPO: <strong>{report.repository.owner}/{report.repository.repository}</strong></span>
              <span>BRANCH: <strong>{report.repository.branch}</strong></span>
              <span>ANALYSIS ID: <strong>{report.analysis_id}</strong></span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="dashboard" onClick={() => navigate('/command-center')}>
              COMMAND CENTER
            </SecondaryButton>
            <SecondaryButton icon="folder_managed" onClick={() => navigate('/repo-intelligence')}>
              REPO INTELLIGENCE
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Step 6O Review Contract Decision Banner */}
      <ReviewStatusBanner
        reviewStatus={report.review_status}
        title="AUTOMATED GATE DECISION: BLOCKED (BLOCK)"
        details={`Policy Violation: ${report.summary.critical_count} Critical finding & ${report.summary.high_count} High finding require remediation before PR merge`}
      />

      {/* 3. Security Rule Policy Summary & Audit Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Security Rule Checklist Panel (7 cols) */}
        <div style={{ gridColumn: 'span 7' }}>
          <DataPanel title="SECURITY POLICY RULES EVALUATION" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {securityRules.map((rule, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <StatusPip
                      status={rule.status === 'pass' ? 'green' : rule.status === 'fail' ? 'red' : 'amber'}
                    />
                    <span style={{ fontWeight: 600, color: 'var(--text-on-surface)' }}>{rule.name}</span>
                  </div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}>{rule.detail}</span>
                </div>
              ))}
            </div>
          </DataPanel>
        </div>

        {/* Quick Review Summary Bento (5 cols) */}
        <div style={{ gridColumn: 'span 5', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <MetricCard
            label="CRITICAL FINDINGS"
            value={report.summary.critical_count}
            delta="BLOCKS MERGE"
            accentColor="red"
          />
          <MetricCard
            label="HIGH FINDINGS"
            value={report.summary.high_count}
            delta="BLOCKS MERGE"
            accentColor="amber"
          />
          <MetricCard
            label="ANALYZED FILES"
            value={`${report.summary.analyzed_files} / ${report.summary.total_files}`}
            delta="100% COVERAGE"
            accentColor="cyan"
          />
          <MetricCard
            label="GROUNDED EVIDENCE"
            value={`${report.summary.total_findings}`}
            delta="100% GROUNDED"
            accentColor="green"
          />
        </div>
      </div>

      {/* 4. Findings & Grounded Evidence Dual Workspace */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Left Findings List Panel (5 cols) */}
        <div style={{ gridColumn: 'span 5' }}>
          <DataPanel title="SECURITY FINDINGS LIST" status="amber">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {report.findings.map((f) => {
                const isSelected = f.finding_id === selectedFindingId;
                return (
                  <div
                    key={f.finding_id}
                    onClick={() => setSelectedFindingId(f.finding_id)}
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
                      <LabelCaps style={{ fontSize: '10px' }}>{f.finding_id}</LabelCaps>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-on-surface)' }}>
                      {f.title}
                    </div>
                    <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                      {f.description}
                    </p>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--primary-cyan)', marginTop: '2px' }}>
                      LOCATION: {f.evidence[0]?.document_id}:L{f.evidence[0]?.line_start}
                    </div>
                  </div>
                );
              })}
            </div>
          </DataPanel>
        </div>

        {/* Right Grounded Evidence & Code Viewer Panel (7 cols) */}
        <div style={{ gridColumn: 'span 7' }}>
          <DataPanel
            title={`GROUNDED EVIDENCE INSPECTOR — ${activeFinding?.finding_id || ''}`}
            status="cyan"
            action={<SeverityBadge severity={activeFinding?.severity || 'info'} />}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* Evidence Metadata Snippet */}
              {activeEvidence && (
                <EvidenceSnippet
                  documentId={activeEvidence.document_id}
                  lineStart={activeEvidence.line_start}
                  lineEnd={activeEvidence.line_end}
                  signalType={activeEvidence.signal_type}
                  signalName={activeEvidence.signal_name}
                />
              )}

              {/* Code Snippet Viewer */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>STATIC SOURCE CODE EVIDENCE</LabelCaps>
                <CodeViewer
                  lines={activeEvidence?.lines || ['# Source snippet not loaded']}
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

      {/* 5. PR Security Gate Actions Footer Panel */}
      <DataPanel status="red" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <LabelCaps style={{ color: 'var(--critical-red)' }}>REMEDIATION REQUIRED BEFORE MERGE</LabelCaps>
            <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--text-dim)' }}>
              1 Critical severity finding violates production deployment policy. Remove secret literal from `src/flask/config.py`.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="download" onClick={() => alert('Exporting Step 6O JSON Report Payload...')}>
              EXPORT REPORT JSON
            </SecondaryButton>
            <PrimaryButton icon="search" onClick={() => navigate('/vulnerability-explorer')}>
              OPEN IN VULNERABILITY EXPLORER
            </PrimaryButton>
          </div>
        </div>
      </DataPanel>

    </div>
  );
}
