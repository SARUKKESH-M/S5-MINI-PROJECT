import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import CodeEditor from '../components/CodeEditor';
import FindingCard from '../components/FindingCard';
import StatusBadge from '../components/StatusBadge';
import SecurityToast from '../components/SecurityToast';
import FindingsFilterBar from '../components/common/FindingsFilterBar';
import FindingPreviewModal from '../components/dashboard/FindingPreviewModal';
import { getFindingTaxonomy } from '../utils/securityTaxonomy';
import {
  acquireRepository,
  analyzeRepository,
  analyzeSourceCode,
} from '../services/apiClient';

const SAFE_EXAMPLE = `def add(a, b):
    return a + b
`;

const VULNERABLE_EXAMPLE = `import os

def run_cmd(user_input):
    os.system("ping " + user_input)
`;

export default function AnalyzeView() {
  const location = useLocation();
  const navigate = useNavigate();

  // Analysis mode: 'repository' (default in Phase 5) or 'code' (direct snippet)
  const [analysisMode, setAnalysisMode] = useState('repository');

  // Repository form fields
  const [repoUrl, setRepoUrl] = useState('https://github.com/SARUKKESH-M/S5-MINI-PROJECT');
  const [branch, setBranch] = useState('main');
  const [subpath, setSubpath] = useState('');
  const [analysisQuery, setAnalysisQuery] = useState('security analysis');

  // Direct source code state
  const [sourceCode, setSourceCode] = useState(SAFE_EXAMPLE);

  // Execution & status state: 'idle' | 'queued' | 'acquiring' | 'analyzing' | 'completed' | 'failed' | 'cancelled' | 'timed-out'
  const [analysisStatus, setAnalysisStatus] = useState('idle');
  const [loadingMessage, setLoadingMessage] = useState('');
  const [error, setError] = useState(null);
  const [errorType, setErrorType] = useState(null); // 'timeout' | 'aborted' | 'network' | 'validation' | 'pipeline'
  const [validationError, setValidationError] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [executionTimeMs, setExecutionTimeMs] = useState(null);
  const [showToast, setShowToast] = useState(false);

  // Findings filter and modal state
  const [findingSearch, setFindingSearch] = useState('');
  const [findingSeverity, setFindingSeverity] = useState('ALL');
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Concurrency & lifecycle refs
  const isSubmittingRef = useRef(false);
  const isMountedRef = useRef(true);
  const abortControllerRef = useRef(null);
  const findingsSectionRef = useRef(null);

  // Mount/unmount lifecycle safety
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (abortControllerRef.current) {
        abortControllerRef.current.abort('Component unmounted');
        abortControllerRef.current = null;
      }
    };
  }, []);

  // Consume navigation state passed from Dashboard or other views
  useEffect(() => {
    if (location.state?.repo || location.state?.repository_url) {
      const r = (location.state.repo || location.state.repository_url).trim();
      const full = r.startsWith('http') ? r : `https://github.com/${r}`;
      setRepoUrl(full);
      if (location.state.branch) {
        setBranch(location.state.branch.trim());
      }
      setAnalysisMode('repository');
    }
  }, [location.state]);

  // Client-side repository validation
  const validateRepositoryInput = (url, targetBranch) => {
    if (!url || !url.trim()) {
      return 'Repository URL is required.';
    }
    const clean = url.trim();
    if (/[\x00;&|$\`<>\"\']/.test(clean)) {
      return 'Repository URL contains prohibited command or injection characters.';
    }
    if (!clean.startsWith('https://') && !clean.startsWith('http://') && !clean.includes('/')) {
      return 'Please enter a valid GitHub HTTPS URL (e.g., https://github.com/owner/repository) or owner/repo identifier.';
    }
    if (targetBranch && /[\x00;&|$\`<>\"\'\s]/.test(targetBranch)) {
      return 'Branch name contains invalid characters or whitespace.';
    }
    return null;
  };

  // User-initiated analysis cancellation
  const handleCancelAnalysis = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Analysis cancelled by user.');
      abortControllerRef.current = null;
    }
    if (isMountedRef.current) {
      setAnalysisStatus('cancelled');
      setError('Analysis was cancelled by the user.');
      setErrorType('aborted');
      setLoadingMessage('');
      isSubmittingRef.current = false;
    }
  };

  // Primary Repository Analysis Flow
  const handleAnalyzeRepository = async (e) => {
    if (e) e.preventDefault();

    // Prevent duplicate concurrent submissions
    if (isSubmittingRef.current) return;

    const valErr = validateRepositoryInput(repoUrl, branch);
    if (valErr) {
      setValidationError(valErr);
      setError(null);
      setErrorType('validation');
      return;
    }

    // Cancel any previous in-flight controller
    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Superseded by new analysis request');
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setValidationError(null);
    setError(null);
    setErrorType(null);
    setAnalysisResult(null);
    setShowToast(false);
    isSubmittingRef.current = true;
    setAnalysisStatus('queued');
    setLoadingMessage('Initializing repository acquisition...');

    const start = performance.now();
    let cleanUrl = repoUrl.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = `https://github.com/${cleanUrl}`;
    }
    const cleanBranch = branch.trim() || 'main';

    try {
      // 1. Acquire repository into isolated workspace
      if (!isMountedRef.current) return;
      setAnalysisStatus('acquiring');
      setLoadingMessage(`Acquiring repository workspace (${cleanBranch})...`);

      const acqRes = await acquireRepository(
        {
          repository_url: cleanUrl,
          branch: cleanBranch,
          path: subpath.trim(),
        },
        { signal: controller.signal }
      );

      if (!isMountedRef.current) return;
      const acqId = acqRes.acquisition_id || acqRes.acquisition?.acquisition_id;
      if (!acqId) {
        throw new Error('Workspace acquisition completed but no acquisition ID was returned.');
      }

      // 2. Execute static AST security analysis
      setAnalysisStatus('analyzing');
      setLoadingMessage('Executing static AST security analysis pipeline...');

      const repRes = await analyzeRepository(
        {
          acquisition_id: acqId,
          query: analysisQuery.trim() || 'security analysis',
        },
        { signal: controller.signal }
      );

      if (!isMountedRef.current) return;
      const end = performance.now();
      setExecutionTimeMs(Math.round(end - start));

      if (repRes?.status === 'error') {
        setError(repRes.error_message || 'Analysis pipeline returned an error.');
        setErrorType('pipeline');
        setAnalysisStatus('failed');
        setAnalysisResult(null);
      } else {
        setAnalysisResult(repRes);
        setAnalysisStatus('completed');
        setShowToast(true);
      }
    } catch (err) {
      if (!isMountedRef.current) return;

      if (err.isAborted || err.name === 'AbortError') {
        setAnalysisStatus('cancelled');
        setError('Analysis was cancelled before completion.');
        setErrorType('aborted');
      } else if (err.isTimeout || err.status === 408) {
        setAnalysisStatus('timed-out');
        setError(err.message || 'Analysis request timed out.');
        setErrorType('timeout');
      } else if (err.isNetworkError || err.status === 0) {
        setAnalysisStatus('failed');
        setError('Network connection failed. Unable to reach CodeSentinel backend.');
        setErrorType('network');
      } else {
        setAnalysisStatus('failed');
        setError(err.message || 'Analysis failed. Please check network connectivity and backend availability.');
        setErrorType('pipeline');
      }
      setAnalysisResult(null);
    } finally {
      if (isMountedRef.current) {
        isSubmittingRef.current = false;
        setLoadingMessage('');
        abortControllerRef.current = null;
      }
    }
  };

  // Direct Source Code Analysis Flow
  const handleAnalyzeCode = async () => {
    if (isSubmittingRef.current) return;

    if (!sourceCode.trim()) {
      setValidationError('Please provide source code to analyze.');
      setErrorType('validation');
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Superseded by new analysis request');
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setValidationError(null);
    setError(null);
    setErrorType(null);
    setAnalysisResult(null);
    setShowToast(false);
    isSubmittingRef.current = true;
    setAnalysisStatus('analyzing');
    setLoadingMessage('Analyzing source code via AST Engine...');

    const start = performance.now();
    try {
      const res = await analyzeSourceCode(
        {
          source_code: sourceCode,
          query: 'security analysis',
        },
        { signal: controller.signal }
      );

      if (!isMountedRef.current) return;
      const end = performance.now();
      setExecutionTimeMs(Math.round(end - start));

      if (res?.status === 'error') {
        setError(res.error_message || 'Analysis error returned by backend.');
        setErrorType('pipeline');
        setAnalysisStatus('failed');
        setAnalysisResult(null);
      } else {
        setAnalysisResult(res);
        setAnalysisStatus('completed');
        setShowToast(true);
      }
    } catch (err) {
      if (!isMountedRef.current) return;

      if (err.isAborted || err.name === 'AbortError') {
        setAnalysisStatus('cancelled');
        setError('Analysis was cancelled before completion.');
        setErrorType('aborted');
      } else if (err.isTimeout || err.status === 408) {
        setAnalysisStatus('timed-out');
        setError(err.message || 'Analysis request timed out.');
        setErrorType('timeout');
      } else if (err.isNetworkError || err.status === 0) {
        setAnalysisStatus('failed');
        setError('Network connection failed. Unable to reach CodeSentinel backend.');
        setErrorType('network');
      } else {
        setAnalysisStatus('failed');
        setError(err.message || 'Analysis failed. Please ensure the backend is available.');
        setErrorType('pipeline');
      }
      setAnalysisResult(null);
    } finally {
      if (isMountedRef.current) {
        isSubmittingRef.current = false;
        setLoadingMessage('');
        abortControllerRef.current = null;
      }
    }
  };

  const handleClear = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Cleared by user');
      abortControllerRef.current = null;
    }
    if (analysisMode === 'repository') {
      setRepoUrl('');
      setBranch('main');
      setSubpath('');
    } else {
      setSourceCode('');
    }
    setError(null);
    setErrorType(null);
    setValidationError(null);
    setAnalysisResult(null);
    setShowToast(false);
    setFindingSearch('');
    setFindingSeverity('ALL');
    setSelectedFinding(null);
    setAnalysisStatus('idle');
    setLoadingMessage('');
    isSubmittingRef.current = false;
  };

  const handleLoadDefaultRepo = () => {
    setRepoUrl('https://github.com/SARUKKESH-M/S5-MINI-PROJECT');
    setBranch('main');
    setSubpath('');
    setValidationError(null);
    setError(null);
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

  // Authoritative Security Gate Evaluation (Directly from backend result)
  const summary = analysisResult?.summary || {};
  const findings = Array.isArray(analysisResult?.findings) ? analysisResult.findings : [];
  const rawVerdict = analysisResult?.review_status || analysisResult?.verdict || summary._review_status;
  const verdict = rawVerdict ? String(rawVerdict).toUpperCase() : (
    (summary.critical_count > 0 || summary.high_count > 0) ? 'BLOCK' :
    (summary.medium_count > 0) ? 'REVIEW' : 'ALLOW'
  );

  // Real backend metrics
  const filesAnalyzed = summary.analyzed_files ?? summary.total_files ?? '—';
  const totalFindings = analysisResult?.finding_count ?? summary.total_findings ?? findings.length;
  const analysisId = analysisResult?.analysis_id ?? null;

  // Memoized client-side finding filters (grounded in actual API properties)
  const filteredFindings = useMemo(() => {
    if (!Array.isArray(findings)) return [];
    return findings.filter((f) => {
      // 1. Severity filter
      if (findingSeverity !== 'ALL') {
        const sev = String(f?.severity || 'info').toUpperCase();
        if (sev !== findingSeverity) return false;
      }
      // 2. Text search filter (grounded in title, category, evidence file path, verified mapped CWE ID)
      if (findingSearch && findingSearch.trim()) {
        const q = findingSearch.trim().toLowerCase();
        const title = String(f?.title || f?.name || '').toLowerCase();
        const cat = String(f?.category || f?.rule_id || '').toLowerCase();
        const rawEv = Array.isArray(f?.evidence) ? f.evidence : [];
        const firstEv = rawEv.length > 0 ? rawEv[0] : null;
        const docId = String(f?.file_path || f?.file || firstEv?.document_id || '').toLowerCase();
        const taxonomy = getFindingTaxonomy(f);
        const cwe = String(taxonomy?.cweId || '').toLowerCase();

        const matches = title.includes(q) || cat.includes(q) || docId.includes(q) || cwe.includes(q);
        if (!matches) return false;
      }
      return true;
    });
  }, [findings, findingSeverity, findingSearch]);

  const isAnalyzing = analysisStatus === 'queued' || analysisStatus === 'acquiring' || analysisStatus === 'analyzing';

  const handleRetry = () => {
    if (analysisMode === 'repository') {
      handleAnalyzeRepository();
    } else {
      handleAnalyzeCode();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header with Mode Switcher */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Security Analysis Workspace
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Deterministic static AST inspection, repository security scanning, and fail-closed gate evaluation.
            </p>
          </div>

          {/* Mode Switcher Tabs */}
          <div className="cs-analyze-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={analysisMode === 'repository'}
              className={`cs-analyze-tab-btn ${analysisMode === 'repository' ? 'active' : ''}`}
              onClick={() => {
                setAnalysisMode('repository');
                setValidationError(null);
              }}
              disabled={isAnalyzing}
            >
              📁 Repository Analysis
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={analysisMode === 'code'}
              className={`cs-analyze-tab-btn ${analysisMode === 'code' ? 'active' : ''}`}
              onClick={() => {
                setAnalysisMode('code');
                setValidationError(null);
              }}
              disabled={isAnalyzing}
            >
              📝 Code Snippet Editor
            </button>
          </div>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div className="cs-analyze-grid-layout">
        {/* Left Column: Form / Editor */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {analysisMode === 'repository' ? (
            /* Repository Analysis Form */
            <form onSubmit={handleAnalyzeRepository} className="card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                  Repository Configuration
                </h3>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleLoadDefaultRepo}
                    disabled={isAnalyzing}
                    title="Load default project repository"
                  >
                    Load Default Repo
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleClear}
                    disabled={isAnalyzing}
                  >
                    Clear
                  </button>
                </div>
              </div>

              {/* Repository URL Input */}
              <div className="cs-form-group">
                <label htmlFor="repo-url-input" className="cs-form-label">
                  GitHub Repository HTTPS URL <span style={{ color: 'var(--sev-critical)' }}>*</span>
                </label>
                <input
                  id="repo-url-input"
                  type="text"
                  className="cs-form-input"
                  placeholder="https://github.com/SARUKKESH-M/S5-MINI-PROJECT"
                  value={repoUrl}
                  onChange={(e) => {
                    setRepoUrl(e.target.value);
                    if (validationError) setValidationError(null);
                  }}
                  disabled={isAnalyzing}
                  autoComplete="off"
                  spellCheck="false"
                  aria-required="true"
                  aria-invalid={Boolean(validationError)}
                  aria-describedby={`repo-url-helper ${validationError ? 'validation-error-banner' : ''}`.trim()}
                />
                <span id="repo-url-helper" className="cs-form-helper">
                  Supports GitHub repository HTTPS clone URLs or owner/repository slugs.
                </span>
              </div>

              {/* Branch & Subpath Row */}
              <div className="cs-form-2col-grid">
                <div className="cs-form-group">
                  <label htmlFor="branch-input" className="cs-form-label">
                    Git Branch
                  </label>
                  <input
                    id="branch-input"
                    type="text"
                    className="cs-form-input"
                    placeholder="main"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    disabled={isAnalyzing}
                    autoComplete="off"
                  />
                </div>

                <div className="cs-form-group">
                  <label htmlFor="subpath-input" className="cs-form-label">
                    Target Subpath (Optional)
                  </label>
                  <input
                    id="subpath-input"
                    type="text"
                    className="cs-form-input"
                    placeholder="e.g. backend or src"
                    value={subpath}
                    onChange={(e) => setSubpath(e.target.value)}
                    disabled={isAnalyzing}
                    autoComplete="off"
                  />
                </div>
              </div>

              {/* Analysis Policy / Query */}
              <div className="cs-form-group">
                <label htmlFor="query-input" className="cs-form-label">
                  Analysis Policy Profile / Query
                </label>
                <input
                  id="query-input"
                  type="text"
                  className="cs-form-input"
                  placeholder="security analysis"
                  value={analysisQuery}
                  onChange={(e) => setAnalysisQuery(e.target.value)}
                  disabled={isAnalyzing}
                />
              </div>

              {/* Action Buttons: Submit and Cancel */}
              <div style={{ display: 'flex', gap: '10px', marginTop: '8px', flexWrap: 'wrap' }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isAnalyzing || !repoUrl.trim()}
                  style={{
                    flex: 1,
                    padding: '12px',
                    fontSize: '14px',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                  }}
                >
                  {isAnalyzing ? (
                    <>
                      <span className="cs-status-indicator-dot" />
                      <span>{loadingMessage || 'Analyzing repository...'}</span>
                    </>
                  ) : (
                    <>
                      <span>⚡</span>
                      <span>Start Security Analysis</span>
                    </>
                  )}
                </button>

                {isAnalyzing && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={handleCancelAnalysis}
                    style={{
                      padding: '12px 18px',
                      color: 'var(--sev-high)',
                      borderColor: 'var(--border-subtle)',
                      fontWeight: 600,
                    }}
                    title="Cancel currently running analysis"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>
          ) : (
            /* Direct Code Snippet Mode */
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setSourceCode(SAFE_EXAMPLE);
                      setError(null);
                    }}
                    disabled={isAnalyzing}
                  >
                    ✓ Load Safe Example
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setSourceCode(VULNERABLE_EXAMPLE);
                      setError(null);
                    }}
                    disabled={isAnalyzing}
                  >
                    ⚠ Load Vulnerable Example
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleClear}
                    disabled={isAnalyzing}
                  >
                    Clear
                  </button>
                </div>
              </div>

              <CodeEditor
                value={sourceCode}
                onChange={setSourceCode}
                disabled={isAnalyzing}
                minHeight="380px"
              />

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleAnalyzeCode}
                  disabled={isAnalyzing || !sourceCode.trim()}
                  style={{ flex: 1, padding: '12px', fontSize: '14px', fontWeight: 600 }}
                >
                  {isAnalyzing ? '⏳ Analyzing Source Code via AST Engine...' : '⚡ Analyze Code'}
                </button>

                {isAnalyzing && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={handleCancelAnalysis}
                    style={{
                      padding: '12px 18px',
                      color: 'var(--sev-high)',
                      borderColor: 'var(--border-subtle)',
                      fontWeight: 600,
                    }}
                    title="Cancel in-flight analysis"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Validation Error Banner */}
          {validationError && (
            <div id="validation-error-banner" className="alert-box alert-error" role="alert" aria-live="assertive">
              <div>
                <strong>Validation Notice:</strong> {validationError}
              </div>
            </div>
          )}

          {/* Execution Error Banner (Left Column) */}
          {error && (
            <div className="alert-box alert-error" role="alert" aria-live="assertive">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                <div>
                  <strong>{errorType === 'timeout' ? 'Analysis Timeout:' : errorType === 'aborted' ? 'Analysis Stopped:' : 'Analysis Notice:'}</strong> {error}
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleRetry}
                  style={{ marginLeft: '12px', flexShrink: 0 }}
                >
                  ↻ Retry
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Real-Time Results & Summary */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {isAnalyzing ? (
            /* Honest Loading State */
            <div
              className="card"
              style={{
                padding: '36px 24px',
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                minHeight: '380px',
              }}
              role="status"
              aria-live="polite"
            >
              <div className="cs-pulse-shield-indicator" style={{ marginBottom: '16px' }}>
                <span className="cs-pulse-ring" />
                <span className="cs-pulse-icon">🛡️</span>
              </div>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
                {analysisStatus === 'queued'
                  ? 'Analysis Request Queued'
                  : analysisStatus === 'acquiring'
                  ? 'Acquiring Workspace'
                  : 'AST Security Analysis in Progress'}
              </h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)', maxWidth: '340px', lineHeight: 1.5, marginBottom: '12px' }}>
                {loadingMessage || 'Executing deterministic security inspection...'}
              </p>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', backgroundColor: 'var(--bg-void)', padding: '6px 12px', borderRadius: '4px', border: '1px solid var(--border-subtle)', marginBottom: '16px' }}>
                Target: {repoUrl ? repoUrl.replace('https://github.com/', '') : 'Direct Code'} ({branch})
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleCancelAnalysis}
                style={{ color: 'var(--sev-high)', borderColor: 'var(--border-subtle)' }}
              >
                ✕ Cancel Analysis
              </button>
            </div>
          ) : analysisResult ? (
            /* Real Backend Result Card */
            <div className="card" style={{ padding: '20px' }}>
              {/* Report Header & Verdict */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    ANALYSIS ID: {analysisId || '—'}
                  </div>
                  <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                    Security Gate Report
                  </h3>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>GATE VERDICT:</span>
                  <StatusBadge status={verdict} size="large" />
                </div>
              </div>

              {/* Execution Metadata Pill Row */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(3, 1fr)',
                  gap: '8px',
                  padding: '10px 14px',
                  backgroundColor: 'var(--bg-void)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  marginBottom: '14px',
                  fontSize: '11.5px',
                  fontFamily: 'var(--font-mono)',
                  textAlign: 'center',
                }}
              >
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>FILES ANALYZED</div>
                  <strong style={{ color: 'var(--text-primary)', fontSize: '13px' }}>{filesAnalyzed}</strong>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>FINDINGS</div>
                  <strong style={{ color: totalFindings > 0 ? 'var(--sev-critical)' : 'var(--verdict-allow)', fontSize: '13px' }}>
                    {totalFindings}
                  </strong>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>DURATION</div>
                  <strong style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                    {executionTimeMs !== null ? `${executionTimeMs}ms` : '—'}
                  </strong>
                </div>
              </div>

              {/* Severity Metrics Breakdown */}
              <div className="cs-severity-breakdown-bar">
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

              {/* Post-Analysis Navigation Actions */}
              <div style={{ display: 'flex', gap: '10px', marginBottom: '16px', flexWrap: 'wrap' }}>
                {analysisId && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{ flex: '1 1 200px', padding: '8px 12px' }}
                    onClick={() => navigate(`/history?id=${analysisId}`, { state: { analysisId } })}
                    title="Inspect complete audit trail record"
                  >
                    <span>View Full Audit in History →</span>
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ padding: '8px 12px' }}
                  onClick={handleClear}
                  title="Reset for new analysis"
                >
                  New Analysis
                </button>
              </div>

              {/* Findings List */}
              <div ref={findingsSectionRef}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                  Detailed Security Findings ({findings.length})
                </div>

                {findings.length > 0 && (
                  <FindingsFilterBar
                    findings={findings}
                    searchQuery={findingSearch}
                    onSearchChange={setFindingSearch}
                    severityFilter={findingSeverity}
                    onSeverityChange={setFindingSeverity}
                    onClearFilters={() => {
                      setFindingSearch('');
                      setFindingSeverity('ALL');
                    }}
                    matchingCount={filteredFindings.length}
                    totalCount={findings.length}
                  />
                )}

                {findings.length === 0 ? (
                  <div className="alert-box alert-success" style={{ margin: 0 }}>
                    <div>
                      <strong>No Vulnerabilities Detected:</strong> Code passed all automated AST security inspections. Gate decision: <code>ALLOW</code>.
                    </div>
                  </div>
                ) : filteredFindings.length === 0 ? (
                  <div
                    className="card"
                    style={{
                      padding: '24px 16px',
                      textAlign: 'center',
                      backgroundColor: 'var(--bg-surface-elevated)',
                      border: '1px solid var(--border-default)',
                    }}
                  >
                    <div style={{ fontSize: '24px', marginBottom: '8px' }}>🔍</div>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                      No Matching Findings
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 12px' }}>
                      No security findings match your active severity or text filters.
                    </p>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setFindingSearch('');
                        setFindingSeverity('ALL');
                      }}
                    >
                      Clear Filters
                    </button>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '420px', overflowY: 'auto' }}>
                    {filteredFindings.map((finding, idx) => (
                      <FindingCard
                        key={finding.finding_id || idx}
                        finding={finding}
                        index={idx}
                        onInspect={(f) => setSelectedFinding(f)}
                      />
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : error || analysisStatus === 'failed' || analysisStatus === 'timed-out' || analysisStatus === 'cancelled' ? (
            /* Actionable Error & Recovery State Card */
            <div
              className="card"
              style={{
                padding: '32px 24px',
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                minHeight: '380px',
              }}
              role="alert"
              aria-live="assertive"
            >
              <div style={{ fontSize: '36px', marginBottom: '12px' }}>
                {analysisStatus === 'cancelled' ? '🛑' : analysisStatus === 'timed-out' ? '⏳' : '⚠️'}
              </div>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
                {analysisStatus === 'cancelled'
                  ? 'Analysis Cancelled'
                  : analysisStatus === 'timed-out'
                  ? 'Analysis Timed Out'
                  : 'Analysis Could Not Be Completed'}
              </h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)', maxWidth: '380px', lineHeight: 1.5, marginBottom: '16px' }}>
                {error || 'An unexpected error interrupted the static analysis pipeline.'}
              </p>

              {/* Recovery Guidance Box */}
              <div
                style={{
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  backgroundColor: 'var(--bg-void)',
                  padding: '12px 16px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  maxWidth: '380px',
                  textAlign: 'left',
                  marginBottom: '20px',
                  lineHeight: 1.5,
                }}
              >
                <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '4px' }}>
                  💡 Recovery Advice:
                </strong>
                {errorType === 'timeout' && (
                  <span>
                    Try specifying a target subpath (e.g., <code>src</code> or <code>backend</code>) to reduce scan surface, or ensure the backend model service is warm.
                  </span>
                )}
                {errorType === 'aborted' && (
                  <span>
                    The operation was safely terminated before completing. No partial reports or corrupted gate decisions were stored.
                  </span>
                )}
                {errorType === 'network' && (
                  <span>
                    Verify that the CodeSentinel backend service is running and accessible at the configured URL. Check network connectivity.
                  </span>
                )}
                {(!errorType || errorType === 'pipeline' || errorType === 'validation') && (
                  <span>
                    Check that the repository exists, is accessible via HTTPS, and that the specified branch is spelled correctly.
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={handleRetry}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  <span>↻</span>
                  <span>Retry Analysis</span>
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleClear}
                >
                  Reset Parameters
                </button>
              </div>
            </div>
          ) : (
            /* Awaiting Analysis Empty State */
            <div className="empty-state" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div className="empty-state-icon">🛡️</div>
              <div className="empty-state-title">Awaiting Analysis</div>
              <p className="empty-state-desc">
                {analysisMode === 'repository' ? (
                  <>Configure repository parameters and click <strong>"Start Security Analysis"</strong> to execute multi-file inspection.</>
                ) : (
                  <>Click <strong>"Analyze Code"</strong> to run the static security pipeline on the current code editor contents.</>
                )}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Finding Detail Inspection Modal */}
      <FindingPreviewModal
        isOpen={Boolean(selectedFinding)}
        onClose={() => setSelectedFinding(null)}
        finding={selectedFinding}
      />

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
