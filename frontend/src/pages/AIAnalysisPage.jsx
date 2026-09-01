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

export default function AIAnalysisPage() {
  const navigate = useNavigate();

  // Local presentation data structurally aligned with Step 6O Production Report Contract
  const [report] = useState({
    status: 'success',
    review_status: 'block',
    analysis_id: 'repo_ana_demo_flask',
    repository: {
      owner: 'pallets',
      repository: 'flask',
      branch: 'main',
      path: './'
    },
    summary: {
      total_files: 184,
      analyzed_files: 176,
      skipped_files: 8,
      total_findings: 17,
      critical_count: 2,
      high_count: 5,
      medium_count: 6,
      low_count: 3,
      info_count: 1
    },
    findings: [
      {
        finding_id: 'finding_1',
        title: 'Hardcoded Secret Assignment in App Config',
        description: 'Detected hardcoded secret string literal assigned to JWT_SECRET in config initialization.',
        severity: 'critical',
        confidence: 'high',
        category: 'security',
        ast_analysis: {
          signal_type: 'AST_SECRET_LITERAL',
          signal_name: 'jwt_secret_assignment',
          scope: 'config_init()',
          node_type: 'AssignNode',
          line: 42
        },
        rag_grounding: {
          document_id: 'src/flask/config.py',
          line_start: 42,
          line_end: 42,
          similarity_score: '98.4%',
          cwe_mapping: 'CWE-798: Use of Hard-coded Credentials',
          owasp_category: 'OWASP A07:2021 Identification & Authentication Failures'
        },
        llm_trace: [
          '[AST_ENGINE] Extracted AssignNode targeting key "JWT_SECRET" with literal string value.',
          '[RAG_GROUNDER] Retrieved matching security policy document "CWE-798" (Similarity: 98.4%).',
          '[LLM_ANALYZER] Ingress context confirmed: Secret string assigned without env variable lookup.',
          '[LLM_VERDICT] Rule evaluation: HIGH_RISK secret leakage -> Verdict: CRITICAL (Confidence: HIGH).'
        ],
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
        ast_analysis: {
          signal_type: 'AST_DESERIALIZATION',
          signal_name: 'pickle_loads_invocation',
          scope: 'load_session()',
          node_type: 'CallNode',
          line: 108
        },
        rag_grounding: {
          document_id: 'src/flask/sessions.py',
          line_start: 108,
          line_end: 108,
          similarity_score: '96.2%',
          cwe_mapping: 'CWE-502: Deserialization of Untrusted Data',
          owasp_category: 'OWASP A08:2021 Software and Data Integrity Failures'
        },
        llm_trace: [
          '[AST_ENGINE] Extracted CallNode targeting "pickle.loads" with parameter "raw_bytes".',
          '[RAG_GROUNDER] Retrieved matching security policy document "CWE-502" (Similarity: 96.2%).',
          '[LLM_ANALYZER] Parameter source identified as incoming HTTP session cookie payload.',
          '[LLM_VERDICT] Rule evaluation: Arbitrary Code Execution risk -> Verdict: CRITICAL (Confidence: HIGH).'
        ],
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

  // Active finding selection state
  const [selectedFindingId, setSelectedFindingId] = useState('finding_1');

  const activeFinding =
    report.findings.find((f) => f.finding_id === selectedFindingId) || report.findings[0];

  const activeEvidence = activeFinding?.evidence?.[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Header Context & Finding Dropdown Selector */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                AI SECURITY REASONING &amp; GROUNDING CENTER
              </LabelCaps>
              <StatusPip status="cyan" title="MockLLMProvider Operational" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
                MockLLMProvider v1.0
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              AI Analysis Center
            </h1>
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface-variant)' }}>
              <span>REPO: <strong>{report.repository.owner}/{report.repository.repository}</strong></span>
              <span>BRANCH: <strong>{report.repository.branch}</strong></span>
              <span>ANALYSIS ID: <strong>{report.analysis_id}</strong></span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <LabelCaps style={{ fontSize: '10px' }}>SELECT FINDING:</LabelCaps>
            <select
              value={selectedFindingId}
              onChange={(e) => setSelectedFindingId(e.target.value)}
              style={{
                backgroundColor: 'var(--bg-void-lowest)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-xs)',
                padding: '6px 12px',
                color: 'var(--primary-cyan)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              {report.findings.map((f) => (
                <option key={f.finding_id} value={f.finding_id}>
                  {f.finding_id}: {f.title}
                </option>
              ))}
            </select>
            <SecondaryButton icon="search" onClick={() => navigate('/vulnerability-explorer')}>
              VULNERABILITY EXPLORER
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Step 6O Decision Banner */}
      <ReviewStatusBanner
        reviewStatus={report.review_status}
        title="AI SECURITY VERDICT: BLOCKED (BLOCK)"
        details={`Grounded AI Decision: ${activeFinding?.title} violates high-security production policy`}
      />

      {/* 3. AI Reasoning Pipeline Visualization */}
      <DataPanel title="SECURITY REASONING & GROUNDING PIPELINE" status="cyan">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>code</span>
              <LabelCaps style={{ fontSize: '10px' }}>1. AST SIGNALS</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              {activeFinding?.ast_analysis?.signal_type}
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>saved_search</span>
              <LabelCaps style={{ fontSize: '10px' }}>2. RAG GROUNDING</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              {activeFinding?.rag_grounding?.cwe_mapping.split(':')[0]} ({activeFinding?.rag_grounding?.similarity_score})
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>psychology</span>
              <LabelCaps style={{ fontSize: '10px' }}>3. LLM REASONING</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              Confidence: {activeFinding?.confidence.toUpperCase()}
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--critical-red)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--critical-red)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>gpp_bad</span>
              <LabelCaps style={{ fontSize: '10px' }}>4. VERDICT</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--critical-red)', fontWeight: 700 }}>
              {activeFinding?.severity.toUpperCase()} SEVERITY
            </span>
          </div>

        </div>
      </DataPanel>

      {/* 4. Deep Inspection Grid: AST, RAG, LLM Trace */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* AST & RAG Evidence Context (6 cols) */}
        <div style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* AST Structural Analysis Panel */}
          <DataPanel title="AST STRUCTURAL SIGNAL CONTEXT" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>SIGNAL TYPE</span>
                <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>{activeFinding?.ast_analysis?.signal_type}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>SIGNAL NAME</span>
                <span style={{ color: 'var(--text-on-surface)' }}>{activeFinding?.ast_analysis?.signal_name}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>FUNCTION SCOPE</span>
                <span style={{ color: 'var(--text-on-surface)' }}>{activeFinding?.ast_analysis?.scope}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                <span style={{ color: 'var(--text-dim)' }}>AST NODE TYPE</span>
                <span style={{ color: 'var(--text-on-surface)' }}>{activeFinding?.ast_analysis?.node_type}</span>
              </div>
            </div>
          </DataPanel>

          {/* RAG Knowledge Grounding Panel */}
          <DataPanel title="RAG SECURITY KNOWLEDGE GROUNDING" status="amber">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>MATCHING DOCUMENT</span>
                <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>{activeFinding?.rag_grounding?.document_id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>VECTOR SIMILARITY</span>
                <span style={{ color: 'var(--status-green)', fontWeight: 600 }}>{activeFinding?.rag_grounding?.similarity_score}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>CWE STANDARD</span>
                <span style={{ color: 'var(--secondary-amber)' }}>{activeFinding?.rag_grounding?.cwe_mapping}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                <span style={{ color: 'var(--text-dim)' }}>OWASP CATEGORY</span>
                <span style={{ color: 'var(--text-on-surface-variant)' }}>{activeFinding?.rag_grounding?.owasp_category}</span>
              </div>
            </div>
          </DataPanel>

        </div>

        {/* LLM Reasoning Trace & Finding Verdict (6 cols) */}
        <div style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <DataPanel title="LLM REASONING TRACE LOG" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{
                backgroundColor: 'var(--bg-void-lowest)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '12px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                lineHeight: 1.6,
                color: 'var(--text-on-surface-variant)',
                maxHeight: '260px',
                overflowY: 'auto'
              }}>
                {activeFinding?.llm_trace?.map((log, idx) => (
                  <div key={idx} style={{ marginBottom: '6px' }}>
                    <span style={{ color: 'var(--primary-cyan)', marginRight: '6px' }}>&gt;</span>
                    {log}
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>FINDING SEVERITY VERDICT:</LabelCaps>
                <SeverityBadge severity={activeFinding?.severity || 'info'} />
              </div>
            </div>
          </DataPanel>
        </div>

      </div>

      {/* 5. Grounded Evidence Code Inspector */}
      <DataPanel title={`GROUNDED SOURCE CODE EVIDENCE — ${activeEvidence?.document_id || ''}`} status="cyan">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {activeEvidence && (
            <EvidenceSnippet
              documentId={activeEvidence.document_id}
              lineStart={activeEvidence.line_start}
              lineEnd={activeEvidence.line_end}
              signalType={activeEvidence.signal_type}
              signalName={activeEvidence.signal_name}
            />
          )}

          <CodeViewer
            lines={activeEvidence?.lines || ['# Source snippet not loaded']}
            startLine={(activeEvidence?.line_start || 40) - 2}
            highlightRange={{
              start: activeEvidence?.line_start || 42,
              end: activeEvidence?.line_end || 42
            }}
          />
        </div>
      </DataPanel>

    </div>
  );
}
