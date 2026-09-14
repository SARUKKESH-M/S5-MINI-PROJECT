import React, { useState } from 'react';
import { intakeRepository, acquireRepository, analyzeRepository } from '../services/apiClient';
import FindingCard from '../components/FindingCard';
import StatusBadge from '../components/StatusBadge';

export default function RepositoryView() {
  const [repoUrl, setRepoUrl] = useState('https://github.com/SARUKKESH-M/S5-MINI-PROJECT');
  const [branch, setBranch] = useState('main');
  const [subpath, setSubpath] = useState('');

  // Flow stages: 'idle' | 'intaking' | 'intake_done' | 'acquiring' | 'analyzing' | 'completed' | 'error'
  const [stage, setStage] = useState('idle');
  const [currentStep, setCurrentStep] = useState(0); // 0=idle, 1=intake, 2=acquire, 3=analyze, 4=verdict
  const [error, setError] = useState(null);
  const [acquisitionData, setAcquisitionData] = useState(null);
  const [analysisReport, setAnalysisReport] = useState(null);

  // Validate Intake
  const handleValidateIntake = async () => {
    if (!repoUrl.trim()) {
      setError('Please provide a valid GitHub HTTPS repository URL.');
      return;
    }

    setStage('intaking');
    setCurrentStep(1);
    setError(null);
    setAnalysisReport(null);

    try {
      const res = await intakeRepository({
        repository_url: repoUrl.trim(),
        branch: branch.trim() || 'main',
        path: subpath.trim() || '',
      });
      setStage('intake_done');
    } catch (err) {
      setError(err.message || 'Repository intake validation failed.');
      setStage('error');
    }
  };

  // Full Pipeline: Acquire & Analyze
  const handleAcquireAndAnalyze = async () => {
    if (!repoUrl.trim()) {
      setError('Please provide a valid GitHub HTTPS repository URL.');
      return;
    }

    setError(null);
    setAnalysisReport(null);

    try {
      // Step 1: Intake if not done
      setStage('intaking');
      setCurrentStep(1);
      await intakeRepository({
        repository_url: repoUrl.trim(),
        branch: branch.trim() || 'main',
        path: subpath.trim() || '',
      });

      // Step 2: Acquire
      setStage('acquiring');
      setCurrentStep(2);
      const acqRes = await acquireRepository({
        repository_url: repoUrl.trim(),
        branch: branch.trim() || 'main',
        path: subpath.trim() || '',
      });
      setAcquisitionData(acqRes);

      const acqId = acqRes.acquisition_id || acqRes.acquisition?.acquisition_id;
      if (!acqId) {
        throw new Error('Acquisition succeeded but no acquisition_id was returned.');
      }

      // Step 3: Analyze
      setStage('analyzing');
      setCurrentStep(3);
      const repRes = await analyzeRepository({
        acquisition_id: acqId,
        query: 'security analysis',
      });

      // Step 4: Verdict
      setCurrentStep(4);
      setAnalysisReport(repRes);
      setStage('completed');
    } catch (err) {
      setError(err.message || 'Repository acquisition/analysis pipeline failed.');
      setStage('error');
    }
  };

  const steps = [
    { num: 1, label: 'INTAKE' },
    { num: 2, label: 'ACQUIRE' },
    { num: 3, label: 'ANALYZE' },
    { num: 4, label: 'VERDICT' },
  ];

  const summary = analysisReport?.summary || {};
  const findings = Array.isArray(analysisReport?.findings) ? analysisReport.findings : [];
  const verdict = analysisReport?.review_status || summary._review_status || (
    (summary.critical_count > 0 || summary.high_count > 0) ? 'BLOCK' :
    (summary.medium_count > 0) ? 'REVIEW' : 'ALLOW'
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Card */}
      <div className="card" style={{ padding: '20px' }}>
        <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
          Repository Security Intake & Audit
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Clone and inspect multi-file repository workspaces through the static AST security analyzer.
        </p>

        {/* 4-Stage Stepper */}
        <div
          className="stepper-grid"
          style={{
            marginTop: '20px',
            padding: '12px 16px',
            backgroundColor: 'var(--bg-void)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {steps.map((s) => {
            const isActive = currentStep === s.num;
            const isDone = currentStep > s.num || (currentStep === 4 && stage === 'completed');
            return (
              <div key={s.num} style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, overflow: 'hidden' }}>
                <span
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    flexShrink: 0,
                    backgroundColor: isDone
                      ? 'var(--verdict-allow)'
                      : isActive
                      ? 'var(--accent-blue)'
                      : 'var(--bg-surface-elevated)',
                    color: isDone || isActive ? '#000' : 'var(--text-muted)',
                  }}
                >
                  {isDone ? '✓' : s.num}
                </span>
                <span
                  style={{
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 600,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    color: isActive ? 'var(--accent-blue)' : isDone ? 'var(--text-primary)' : 'var(--text-dim)',
                  }}
                >
                  {s.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Input Form & Action Panel */}
      <div className="card" style={{ padding: '20px' }}>
        <div className="repo-form-grid" style={{ marginBottom: '16px' }}>
          <div style={{ minWidth: 0 }}>
            <label className="form-label">GitHub HTTPS Repository URL</label>
            <input
              type="text"
              className="form-input"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              disabled={stage === 'intaking' || stage === 'acquiring' || stage === 'analyzing'}
            />
          </div>

          <div style={{ minWidth: 0 }}>
            <label className="form-label">Target Branch</label>
            <input
              type="text"
              className="form-input"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
              disabled={stage === 'intaking' || stage === 'acquiring' || stage === 'analyzing'}
            />
          </div>

          <div style={{ minWidth: 0 }}>
            <label className="form-label">Subpath (Optional)</label>
            <input
              type="text"
              className="form-input"
              value={subpath}
              onChange={(e) => setSubpath(e.target.value)}
              placeholder="e.g. backend/app"
              disabled={stage === 'intaking' || stage === 'acquiring' || stage === 'analyzing'}
            />
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleAcquireAndAnalyze}
            disabled={stage === 'intaking' || stage === 'acquiring' || stage === 'analyzing'}
          >
            {stage === 'acquiring'
              ? '⏳ Acquiring Workspace...'
              : stage === 'analyzing'
              ? '⏳ Running Multi-File Analysis...'
              : '⚡ Acquire & Analyze'}
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleValidateIntake}
            disabled={stage === 'intaking' || stage === 'acquiring' || stage === 'analyzing'}
          >
            Validate Intake Only
          </button>
        </div>

        {error && (
          <div className="alert-box alert-error" style={{ marginTop: '16px', marginBottom: 0 }}>
            <div>
              <strong>Error:</strong> {error}
            </div>
          </div>
        )}

        {stage === 'intake_done' && (
          <div className="alert-box alert-success" style={{ marginTop: '16px', marginBottom: 0 }}>
            <div>
              <strong>Intake Validated:</strong> Repository reference confirmed. Ready for full acquisition and multi-file scan.
            </div>
          </div>
        )}
      </div>

      {/* Analysis Results View */}
      {analysisReport && (
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                ANALYSIS ID: {analysisReport.analysis_id}
              </div>
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Repository Security Report
              </h3>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>GATE VERDICT:</span>
              <StatusBadge status={verdict} size="large" />
            </div>
          </div>

          {/* Severity Counters */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(5, minmax(0, 1fr))',
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

          {/* Findings */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
              Repository Findings ({findings.length})
            </div>

            {findings.length === 0 ? (
              <div className="alert-box alert-success" style={{ margin: 0 }}>
                <div>
                  <strong>No Vulnerabilities Detected:</strong> Scanned files in the workspace passed all security rules. Gate decision: <code>ALLOW</code>.
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {findings.map((f, idx) => (
                  <FindingCard key={f.finding_id || idx} finding={f} index={idx} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
