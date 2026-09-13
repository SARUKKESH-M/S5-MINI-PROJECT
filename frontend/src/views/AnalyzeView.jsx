import React, { useState, useRef } from 'react';
import CodeEditor from '../components/CodeEditor';
import FindingCard from '../components/FindingCard';
import StatusBadge from '../components/StatusBadge';
import SecurityToast from '../components/SecurityToast';
import { analyzeSourceCode } from '../services/apiClient';

const SAFE_EXAMPLE = `def add(a, b):
    return a + b
`;

const VULNERABLE_EXAMPLE = `import os

def run_cmd(user_input):
    os.system("ping " + user_input)
`;

export default function AnalyzeView() {
  const [sourceCode, setSourceCode] = useState(SAFE_EXAMPLE);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [executionTimeMs, setExecutionTimeMs] = useState(null);
  const [showToast, setShowToast] = useState(false);
  const findingsSectionRef = useRef(null);

  const handleLoadSafe = () => {
    setSourceCode(SAFE_EXAMPLE);
    setError(null);
  };

  const handleLoadVulnerable = () => {
    setSourceCode(VULNERABLE_EXAMPLE);
    setError(null);
  };

  const handleClear = () => {
    setSourceCode('');
    setError(null);
    setAnalysisResult(null);
    setShowToast(false);
  };

  const handleCloseToast = () => {
    setShowToast(false);
  };

  const handleViewFindings = () => {
    if (findingsSectionRef.current) {
      findingsSectionRef.current.scrollIntoView({
        behavior: 'smooth',
        block: 'start',
      });
    }
  };

  const handleAnalyze = async () => {
    if (!sourceCode.trim()) {
      setError('Please provide source code to analyze.');
      return;
    }

    setAnalyzing(true);
    setError(null);
    const start = performance.now();

    try {
      const res = await analyzeSourceCode({
        source_code: sourceCode,
        query: 'security analysis',
      });
      const end = performance.now();
      setExecutionTimeMs(Math.round(end - start));
      if (res?.status === 'error') {
        setError(res.error_message || 'Analysis error returned by backend.');
        setAnalysisResult(null);
        setShowToast(false);
      } else {
        setAnalysisResult(res);
        setShowToast(true);
      }
    } catch (err) {
      setError(err.message || 'Analysis failed. Please ensure the backend is available.');
      setAnalysisResult(null);
      setShowToast(false);
    } finally {
      setAnalyzing(false);
    }
  };

  // Derive security verdict from real backend response
  const summary = analysisResult?.summary || {};
  const findings = Array.isArray(analysisResult?.findings) ? analysisResult.findings : [];
  const rawVerdict = analysisResult?.verdict || analysisResult?.review_status || summary._review_status;
  const verdict = rawVerdict ? String(rawVerdict).toUpperCase() : (
    (summary.critical_count > 0 || summary.high_count > 0) ? 'BLOCK' :
    (summary.medium_count > 0) ? 'REVIEW' : 'ALLOW'
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Direct Source Code Analysis
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Deterministic AST parsing, security rule matching, and automated CI gate evaluation.
            </p>
          </div>

          {/* Preset Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleLoadSafe}
              disabled={analyzing}
              title="Load safe Python code sample"
            >
              ✓ Load Safe Example
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleLoadVulnerable}
              disabled={analyzing}
              title="Load vulnerable command-injection Python sample"
            >
              ⚠ Load Vulnerable Example
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleClear}
              disabled={analyzing}
            >
              ✕ Clear
            </button>
          </div>
        </div>
      </div>

      {/* Main Workspace: Editor on Left/Top, Report on Right/Bottom */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(350px, 1.2fr) minmax(350px, 1fr)', gap: '20px' }}>
        {/* Left Column: Code Editor & Execution Trigger */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <CodeEditor
            value={sourceCode}
            onChange={setSourceCode}
            disabled={analyzing}
            minHeight="420px"
          />

          <button
            type="button"
            className="btn btn-primary"
            onClick={handleAnalyze}
            disabled={analyzing || !sourceCode.trim()}
            style={{ padding: '12px', fontSize: '14px', fontWeight: 600, width: '100%' }}
          >
            {analyzing ? '⏳ Analyzing Source Code via AST Engine...' : '⚡ Analyze Code'}
          </button>

          {error && (
            <div className="alert-box alert-error">
              <div>
                <strong>Analysis Error:</strong> {error}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Real-Time Analysis Report */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {analysisResult ? (
            <div className="card" style={{ padding: '20px' }}>
              {/* Report Header & Verdict */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    ANALYSIS ID: {analysisResult.analysis_id}
                  </div>
                  <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Security Gate Report
                  </h3>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>VERDICT:</span>
                  <StatusBadge status={verdict} size="large" />
                </div>
              </div>

              {/* Severity Metrics Breakdown */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(5, 1fr)',
                  gap: '8px',
                  padding: '12px',
                  backgroundColor: 'var(--bg-void)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  textAlign: 'center',
                  marginBottom: '16px',
                }}
              >
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)' }}>CRIT</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-critical)' }}>{summary.critical_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-high)', fontFamily: 'var(--font-mono)' }}>HIGH</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-high)' }}>{summary.high_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-medium)', fontFamily: 'var(--font-mono)' }}>MED</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-medium)' }}>{summary.medium_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-low)', fontFamily: 'var(--font-mono)' }}>LOW</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-low)' }}>{summary.low_count ?? 0}</strong>
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--sev-info)', fontFamily: 'var(--font-mono)' }}>INFO</div>
                  <strong style={{ fontSize: '15px', color: 'var(--sev-info)' }}>{summary.info_count ?? 0}</strong>
                </div>
              </div>

              {/* Context / Execution Info */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: '11px',
                  color: 'var(--text-dim)',
                  fontFamily: 'var(--font-mono)',
                  marginBottom: '16px',
                }}
              >
                <span>Total Findings: {findings.length}</span>
                {executionTimeMs !== null && <span>Duration: {executionTimeMs} ms</span>}
                <span>Provider: {analysisResult.provider || 'AST Engine'}</span>
              </div>

              {/* Findings List */}
              <div ref={findingsSectionRef}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                  Detailed Security Findings ({findings.length})
                </div>

                {findings.length === 0 ? (
                  <div className="alert-box alert-success" style={{ margin: 0 }}>
                    <div>
                      <strong>No Vulnerabilities Detected:</strong> Source code passed all static security AST rules with a clean bill of health. Gate decision: <code>ALLOW</code>.
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {findings.map((finding, idx) => (
                      <FindingCard key={finding.finding_id || idx} finding={finding} index={idx} />
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="empty-state" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div className="empty-state-icon">🛡️</div>
              <div className="empty-state-title">Awaiting Analysis</div>
              <p className="empty-state-desc">
                Click <strong>"Analyze Code"</strong> to run the static security pipeline on the current code editor contents.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Security Gate Toast Notification */}
      {showToast && analysisResult && (
        <SecurityToast
          key={analysisResult.analysis_id || Date.now()}
          verdict={verdict}
          findingCount={findings.length}
          onViewFindings={handleViewFindings}
          onClose={handleCloseToast}
        />
      )}
    </div>
  );
}
