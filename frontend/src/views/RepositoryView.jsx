import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  intakeRepository,
  acquireRepository,
  analyzeRepository,
  getRepositoryAnalytics,
  getAnalyses,
} from '../services/apiClient';
import FindingCard from '../components/FindingCard';
import StatusBadge from '../components/StatusBadge';
import FindingsFilterBar from '../components/common/FindingsFilterBar';
import FindingPreviewModal from '../components/dashboard/FindingPreviewModal';
import { getFindingTaxonomy } from '../utils/securityTaxonomy';
import { CodeFileIcon } from '../components/dashboard/Icons';

/**
 * Sanitize error messages to avoid displaying local filesystem paths,
 * database paths, environment variables, or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred during repository operation.';
  let clean = raw;
  // Strip out Windows drive paths (e.g., C:\Users\...) and Unix paths (/tmp/...)
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  // Strip out any tokens or sensitive patterns
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

/**
 * Extract normalized owner/repository slug from analysis metadata.
 */
function getAnalysisRepoIdentifier(a) {
  if (!a) return '';
  const repoMeta = a.repository || a.summary?._repository;
  if (!repoMeta) return '';
  if (typeof repoMeta === 'string') return repoMeta.toLowerCase();
  const owner = (repoMeta.owner || '').toLowerCase();
  const name = (repoMeta.repository || repoMeta.name || '').toLowerCase();
  if (owner && name) return `${owner}/${name}`;
  return name || owner;
}

export default function RepositoryView() {
  const location = useLocation();
  const navigate = useNavigate();

  // Form inputs
  const [repoUrl, setRepoUrl] = useState('https://github.com/SARUKKESH-M/S5-MINI-PROJECT');
  const [branch, setBranch] = useState('main');
  const [subpath, setSubpath] = useState('');

  // Auto-populate from Dashboard navigation state or header search if provided (Phase 4 compatibility)
  useEffect(() => {
    const rawRepo = location.state?.repo || location.state?.repository_url || location.state?.repoUrl;
    if (rawRepo) {
      const r = String(rawRepo).trim();
      const full = r.startsWith('http') ? r : `https://github.com/${r}`;
      setRepoUrl(full);
      if (location.state.branch) {
        setBranch(String(location.state.branch).trim());
      }
    }
    if (location.state?.query) {
      setRepoSearch(String(location.state.query).trim());
    }
  }, [location.state]);

  // Flow stages: 'idle' | 'intaking' | 'intake_done' | 'acquiring' | 'acquired' | 'analyzing' | 'completed' | 'error' | 'cancelled' | 'timed-out'
  const [stage, setStage] = useState('idle');
  const [currentStep, setCurrentStep] = useState(0); // 0=idle, 1=intake, 2=acquire, 3=analyze, 4=verdict
  const [error, setError] = useState(null);
  const [intakeData, setIntakeData] = useState(null);
  const [acquisitionData, setAcquisitionData] = useState(null);
  const [analysisReport, setAnalysisReport] = useState(null);

  // Finding filters and inspection modal state
  const [findingSearch, setFindingSearch] = useState('');
  const [findingSeverity, setFindingSeverity] = useState('ALL');
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Concurrency & lifecycle refs
  const isSubmittingRef = useRef(false);
  const isMountedRef = useRef(true);
  const abortControllerRef = useRef(null);

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

  // Monitored Repositories & Analytics state
  const [monitoredRepos, setMonitoredRepos] = useState([]);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [reposLoading, setReposLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [repoSearch, setRepoSearch] = useState('');

  // Load monitored repositories and recent analyses from real backend
  const loadRepositoryIntelligence = async () => {
    if (!isMountedRef.current) return;
    setReposLoading(true);
    setLoadError(null);
    try {
      const [analyticsRes, analysesRes] = await Promise.allSettled([
        getRepositoryAnalytics({ timeWindow: '30d' }),
        getAnalyses({ limit: 100 }),
      ]);

      if (!isMountedRef.current) return;

      let hasSuccess = false;
      if (analyticsRes.status === 'fulfilled' && Array.isArray(analyticsRes.value?.repositories)) {
        setMonitoredRepos(analyticsRes.value.repositories);
        hasSuccess = true;
      } else {
        setMonitoredRepos([]);
      }

      if (analysesRes.status === 'fulfilled' && Array.isArray(analysesRes.value?.analyses)) {
        setRecentAnalyses(analysesRes.value.analyses);
        hasSuccess = true;
      } else {
        setRecentAnalyses([]);
      }

      if (!hasSuccess && (analyticsRes.status === 'rejected' || analysesRes.status === 'rejected')) {
        setLoadError('Unable to retrieve monitored repository telemetry from backend. Please verify backend service.');
      }
    } catch (err) {
      if (!isMountedRef.current) return;
      setLoadError(sanitizeErrorMessage(err.message || 'Failed to load repository telemetry.'));
    } finally {
      if (isMountedRef.current) {
        setReposLoading(false);
      }
    }
  };

  useEffect(() => {
    loadRepositoryIntelligence();
  }, []);

  // Strict client-side validation
  const validateInputs = () => {
    const cleanUrl = repoUrl.trim();
    if (!cleanUrl) {
      return { isValid: false, message: 'Repository URL is required.' };
    }

    if (!cleanUrl.startsWith('https://github.com/')) {
      return { isValid: false, message: 'Only GitHub HTTPS repository URLs (https://github.com/owner/repo) are supported.' };
    }

    if (cleanUrl.includes('@')) {
      return { isValid: false, message: 'Embedded credentials in repository URLs are strictly prohibited.' };
    }

    const unsafeCharsRegex = /[\x00;&|$\`<>\"\']/;
    if (unsafeCharsRegex.test(cleanUrl)) {
      return { isValid: false, message: 'Repository URL contains prohibited special characters.' };
    }

    const pathPart = cleanUrl.replace('https://github.com/', '').replace(/\/+$/, '');
    const parts = pathPart.split('/').filter(Boolean);
    if (parts.length < 2) {
      return { isValid: false, message: 'Repository URL must include both owner and repository name (e.g., https://github.com/owner/repo).' };
    }

    if (!branch.trim()) {
      return { isValid: false, message: 'Target branch cannot be blank (defaults to "main").' };
    }

    return { isValid: true, message: null };
  };

  // User-initiated operation cancellation
  const handleCancelOperation = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Operation cancelled by user.');
      abortControllerRef.current = null;
    }
    if (isMountedRef.current) {
      setStage('cancelled');
      setError('Repository operation was cancelled by the user.');
      isSubmittingRef.current = false;
    }
  };

  // Safe retry handler targeting current step
  const handleRetryLastAction = () => {
    if (currentStep === 1) {
      handleValidateIntake();
    } else if (currentStep === 2) {
      handleAcquireWorkspace();
    } else if (currentStep === 3) {
      if (acquisitionData) {
        handleAnalyzeAcquiredWorkspace();
      } else {
        handleAcquireAndAnalyze();
      }
    } else {
      handleAcquireAndAnalyze();
    }
  };

  // 1. Validate Intake Only
  const handleValidateIntake = async () => {
    if (isSubmittingRef.current) return;

    const validation = validateInputs();
    if (!validation.isValid) {
      setError(validation.message);
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Superseded by new operation');
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    isSubmittingRef.current = true;
    setStage('intaking');
    setCurrentStep(1);
    setError(null);
    setAnalysisReport(null);

    try {
      const res = await intakeRepository(
        {
          repository_url: repoUrl.trim(),
          branch: branch.trim() || 'main',
          path: subpath.trim() || '',
        },
        { signal: controller.signal }
      );
      if (!isMountedRef.current) return;
      setIntakeData(res);
      setStage('intake_done');
    } catch (err) {
      if (!isMountedRef.current) return;
      if (err.isAborted || err.name === 'AbortError') {
        setStage('cancelled');
        setError('Intake validation was cancelled.');
      } else if (err.isTimeout || err.status === 408) {
        setStage('timed-out');
        setError('Intake validation timed out.');
      } else {
        setError(sanitizeErrorMessage(err.message || 'Repository intake validation failed.'));
        setStage('error');
      }
    } finally {
      if (isMountedRef.current) {
        isSubmittingRef.current = false;
        abortControllerRef.current = null;
      }
    }
  };

  // 2. Acquire Repository Workspace Only
  const handleAcquireWorkspace = async () => {
    if (isSubmittingRef.current) return;

    const validation = validateInputs();
    if (!validation.isValid) {
      setError(validation.message);
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Superseded by new operation');
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    isSubmittingRef.current = true;
    setError(null);
    setStage('acquiring');
    setCurrentStep(2);

    try {
      const acqRes = await acquireRepository(
        {
          repository_url: repoUrl.trim(),
          branch: branch.trim() || 'main',
          path: subpath.trim() || '',
        },
        { signal: controller.signal }
      );
      if (!isMountedRef.current) return;
      setAcquisitionData(acqRes);
      setStage('acquired');
    } catch (err) {
      if (!isMountedRef.current) return;
      if (err.isAborted || err.name === 'AbortError') {
        setStage('cancelled');
        setError('Workspace acquisition was cancelled.');
      } else if (err.isTimeout || err.status === 408) {
        setStage('timed-out');
        setError('Workspace acquisition timed out.');
      } else {
        setError(sanitizeErrorMessage(err.message || 'Repository acquisition failed.'));
        setStage('error');
      }
    } finally {
      if (isMountedRef.current) {
        isSubmittingRef.current = false;
        abortControllerRef.current = null;
      }
    }
  };

  // 3. Analyze Workspace that has already been acquired
  const handleAnalyzeAcquiredWorkspace = async () => {
    if (isSubmittingRef.current) return;

    const acqId = acquisitionData?.acquisition?.acquisition_id || acquisitionData?.acquisition_id;
    if (!acqId) {
      setError('Acquisition ID is missing. Please acquire repository workspace first.');
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Superseded by new operation');
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    isSubmittingRef.current = true;
    setError(null);
    setAnalysisReport(null);
    setStage('analyzing');
    setCurrentStep(3);

    try {
      const repRes = await analyzeRepository(
        {
          acquisition_id: acqId,
          query: 'security analysis',
        },
        { signal: controller.signal }
      );
      if (!isMountedRef.current) return;
      setCurrentStep(4);
      setAnalysisReport(repRes);
      setStage('completed');
      loadRepositoryIntelligence(); // refresh repository telemetry table
    } catch (err) {
      if (!isMountedRef.current) return;
      if (err.isAborted || err.name === 'AbortError') {
        setStage('cancelled');
        setError('Repository analysis was cancelled.');
      } else if (err.isTimeout || err.status === 408) {
        setStage('timed-out');
        setError('Repository analysis timed out.');
      } else {
        setError(sanitizeErrorMessage(err.message || 'Repository analysis failed.'));
        setStage('error');
      }
    } finally {
      if (isMountedRef.current) {
        isSubmittingRef.current = false;
        abortControllerRef.current = null;
      }
    }
  };

  // 4. Acquire & Analyze Complete Pipeline
  const handleAcquireAndAnalyze = async () => {
    if (isSubmittingRef.current) return;

    const validation = validateInputs();
    if (!validation.isValid) {
      setError(validation.message);
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort('Superseded by new operation');
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    isSubmittingRef.current = true;
    setError(null);
    setAnalysisReport(null);

    try {
      // Step 1: Intake
      setStage('intaking');
      setCurrentStep(1);
      const inRes = await intakeRepository(
        {
          repository_url: repoUrl.trim(),
          branch: branch.trim() || 'main',
          path: subpath.trim() || '',
        },
        { signal: controller.signal }
      );
      if (!isMountedRef.current) return;
      setIntakeData(inRes);

      // Step 2: Acquire
      setStage('acquiring');
      setCurrentStep(2);
      const acqRes = await acquireRepository(
        {
          repository_url: repoUrl.trim(),
          branch: branch.trim() || 'main',
          path: subpath.trim() || '',
        },
        { signal: controller.signal }
      );
      if (!isMountedRef.current) return;
      setAcquisitionData(acqRes);

      const acqId = acqRes.acquisition_id || acqRes.acquisition?.acquisition_id;
      if (!acqId) {
        throw new Error('Acquisition succeeded but no acquisition_id was returned by backend.');
      }

      // Step 3: Analyze
      setStage('analyzing');
      setCurrentStep(3);
      const repRes = await analyzeRepository(
        {
          acquisition_id: acqId,
          query: 'security analysis',
        },
        { signal: controller.signal }
      );
      if (!isMountedRef.current) return;

      // Step 4: Verdict
      setCurrentStep(4);
      setAnalysisReport(repRes);
      setStage('completed');
      loadRepositoryIntelligence(); // refresh table with new analysis
    } catch (err) {
      if (!isMountedRef.current) return;
      if (err.isAborted || err.name === 'AbortError') {
        setStage('cancelled');
        setError('Repository pipeline was cancelled.');
      } else if (err.isTimeout || err.status === 408) {
        setStage('timed-out');
        setError('Repository pipeline timed out.');
      } else {
        setError(sanitizeErrorMessage(err.message || 'Repository acquisition & analysis pipeline failed.'));
        setStage('error');
      }
    } finally {
      if (isMountedRef.current) {
        isSubmittingRef.current = false;
        abortControllerRef.current = null;
      }
    }
  };

  // 5. Navigate to Analyze Studio (Phase 5 handoff)
  const handleNavigateToAnalyze = () => {
    navigate('/analyze', {
      state: {
        repo: repoUrl.trim(),
        repoUrl: repoUrl.trim(),
        repository_url: repoUrl.trim(),
        branch: branch.trim() || 'main',
      },
    });
  };

  // Prevent double submissions on Enter
  const handleInputKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (!isProcessing) {
        handleValidateIntake();
      }
    }
  };

  // Load a monitored repository into form
  const handleSelectMonitoredRepo = (repo) => {
    const id = repo.repository_id;
    if (!id || id === 'default') {
      setRepoUrl('https://github.com/SARUKKESH-M/S5-MINI-PROJECT');
    } else if (id.startsWith('http')) {
      setRepoUrl(id);
    } else {
      setRepoUrl(`https://github.com/${id}`);
    }
    setBranch('main');
    setError(null);
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

  // Monitored repository aggregate insights (Authoritative, strictly from SQLite)
  const repoInsights = useMemo(() => {
    const totalRepos = monitoredRepos.length;
    const totalAnalyses = monitoredRepos.reduce((acc, r) => acc + (r.analysis_count || 0), 0);
    const totalFindings = monitoredRepos.reduce((acc, r) => acc + (r.finding_count || 0), 0);
    const attentionCount = monitoredRepos.filter(
      (r) => (r.critical_count || 0) > 0 || (r.high_count || 0) > 0 || ((r.review_status_distribution?.block || 0) > 0)
    ).length;
    const cleanCount = monitoredRepos.filter(
      (r) => (r.finding_count || 0) === 0 && ((r.review_status_distribution?.block || 0) === 0)
    ).length;
    return { totalRepos, totalAnalyses, totalFindings, attentionCount, cleanCount };
  }, [monitoredRepos]);

  // Filtered monitored repositories for table (supports name, owner/name, or gate verdict)
  const filteredMonitored = useMemo(() => {
    if (!repoSearch.trim()) return monitoredRepos;
    const q = repoSearch.toLowerCase().trim();
    return monitoredRepos.filter((r) => {
      const id = String(r.repository_id || '').toLowerCase();
      const dist = r.review_status_distribution || {};
      const isBlocked = (dist.block ?? 0) > 0 || (r.critical_count ?? 0) > 0;
      const isReview = (dist.review ?? 0) > 0 || (r.medium_count ?? 0) > 0;
      const gate = isBlocked ? 'block' : isReview ? 'review' : 'allow';
      return id.includes(q) || gate.includes(q);
    });
  }, [monitoredRepos, repoSearch]);

  // Find latest analysis matching current repo URL if available
  const currentRepoSlug = useMemo(() => {
    try {
      const clean = repoUrl.replace('https://github.com/', '').replace(/\/+$/, '');
      return clean.toLowerCase();
    } catch {
      return '';
    }
  }, [repoUrl]);

  const latestAnalysisForCurrentRepo = useMemo(() => {
    if (!currentRepoSlug || !Array.isArray(recentAnalyses)) return null;
    return recentAnalyses.find((a) => {
      const rep = a.repository?.repository || a.summary?._repository?.repository || '';
      return rep.toLowerCase().includes(currentRepoSlug) || currentRepoSlug.includes(rep.toLowerCase());
    }) || null;
  }, [recentAnalyses, currentRepoSlug]);

  const isProcessing = stage === 'intaking' || stage === 'acquiring' || stage === 'analyzing';

  return (
    <div className="cs-repo-workspace-view">
      {/* Header Card */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Repository Management & Administration
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
              Configure, validate, acquire, and audit multi-file codebases with the CodeSentinel security engine.
            </p>
          </div>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={loadRepositoryIntelligence}
            disabled={reposLoading}
          >
            ↻ Refresh Repositories
          </button>
        </div>

        {/* 4-Stage Stepper */}
        <div
          className="stepper-grid"
          role="status"
          aria-live="polite"
          style={{
            marginTop: '20px',
            padding: '12px 16px',
            backgroundColor: 'var(--bg-void)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {steps.map((s) => {
            const isFailed = currentStep === s.num && (stage === 'error' || stage === 'cancelled' || stage === 'timed-out');
            const isActive = currentStep === s.num && isProcessing;
            const isDone = (currentStep > s.num) || (currentStep === 4 && stage === 'completed');
            const badgeBg = isFailed
              ? 'var(--sev-critical)'
              : isDone
              ? '#10B981'
              : isActive
              ? '#6366F1'
              : 'var(--bg-surface-elevated)';
            const textColor = isFailed
              ? 'var(--sev-critical)'
              : isActive
              ? '#6366F1'
              : isDone
              ? 'var(--text-primary)'
              : 'var(--text-dim)';

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
                    backgroundColor: badgeBg,
                    color: isDone || isActive || isFailed ? '#FFFFFF' : 'var(--text-muted)',
                  }}
                >
                  {isFailed ? '!' : isDone ? '✓' : s.num}
                </span>
                <span
                  style={{
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 600,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    color: textColor,
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
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 2px' }}>
              Target Repository Configuration
            </h3>
            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
              Specify the repository URL and branch to intake and inspect.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Acquisition Status:
            </span>
            <StatusBadge
              status={
                stage === 'completed'
                  ? 'ONLINE'
                  : stage === 'acquired'
                  ? 'READY'
                  : stage === 'intake_done'
                  ? 'PASSED'
                  : stage === 'cancelled'
                  ? 'REVIEW'
                  : stage === 'timed-out' || stage === 'error'
                  ? 'BLOCK'
                  : isProcessing
                  ? 'REVIEW'
                  : 'INFO'
              }
            />
          </div>
        </div>

        <div className="cs-repo-form-grid" style={{ marginBottom: '16px' }}>
          <div style={{ minWidth: 0 }}>
            <label htmlFor="cs-repo-url-input" className="form-label">
              GitHub HTTPS Repository URL <span style={{ color: 'var(--sev-critical)' }}>*</span>
            </label>
            <input
              id="cs-repo-url-input"
              type="text"
              className="form-input"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              onKeyDown={handleInputKeyDown}
              placeholder="https://github.com/owner/repository"
              disabled={isProcessing}
              aria-required="true"
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'cs-repo-error-banner' : undefined}
            />
          </div>

          <div style={{ minWidth: 0 }}>
            <label htmlFor="cs-branch-input" className="form-label">Target Branch</label>
            <input
              id="cs-branch-input"
              type="text"
              className="form-input"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              onKeyDown={handleInputKeyDown}
              placeholder="main"
              disabled={isProcessing}
            />
          </div>

          <div style={{ minWidth: 0 }}>
            <label htmlFor="cs-subpath-input" className="form-label">Subpath (Optional)</label>
            <input
              id="cs-subpath-input"
              type="text"
              className="form-input"
              value={subpath}
              onChange={(e) => setSubpath(e.target.value)}
              onKeyDown={handleInputKeyDown}
              placeholder="e.g. backend"
              disabled={isProcessing}
            />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="cs-repo-actions-bar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleValidateIntake}
              disabled={isProcessing}
            >
              {stage === 'intaking' ? '⏳ Validating Intake...' : 'Validate Intake Only'}
            </button>

            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleAcquireWorkspace}
              disabled={isProcessing}
            >
              {stage === 'acquiring' ? '⏳ Acquiring Workspace...' : 'Acquire Workspace'}
            </button>

            {stage === 'acquired' && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleAnalyzeAcquiredWorkspace}
                disabled={isProcessing}
              >
                {stage === 'analyzing'
                  ? '⏳ Running Multi-File Analysis...'
                  : '⚡ Analyze Acquired Workspace'}
              </button>
            )}

            <button
              type="button"
              className={stage === 'acquired' ? 'btn btn-secondary' : 'btn btn-primary'}
              onClick={handleAcquireAndAnalyze}
              disabled={isProcessing}
            >
              {stage === 'analyzing' && currentStep === 3
                ? '⏳ Running Multi-File Analysis...'
                : stage === 'acquiring' && currentStep === 2
                ? '⏳ Acquiring & Preparing...'
                : '⚡ Acquire & Analyze'}
            </button>

            {isProcessing && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleCancelOperation}
                style={{ color: 'var(--sev-high)', borderColor: 'var(--border-subtle)', fontWeight: 600 }}
                title="Cancel running operation"
              >
                ✕ Cancel
              </button>
            )}
          </div>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleNavigateToAnalyze}
            disabled={isProcessing}
            title="Open repository in dedicated Analysis Studio"
          >
            Open in Analyze Studio →
          </button>
        </div>

        {/* Actionable Error / Status Banner */}
        {error && (
          <div id="cs-repo-error-banner" className="alert-box alert-error" role="alert" aria-live="assertive" style={{ marginTop: '16px', marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <strong>
                  {stage === 'cancelled' ? 'Operation Cancelled:' : stage === 'timed-out' ? 'Operation Timed Out:' : 'Error:'}
                </strong>{' '}
                {error}
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleRetryLastAction}
                disabled={isProcessing}
                style={{ flexShrink: 0 }}
              >
                ↻ Retry Step
              </button>
            </div>
          </div>
        )}

        {/* Intake Success Metadata */}
        {intakeData && (
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#10B981', marginBottom: '6px' }}>
              ✓ Intake Validated: Repository reference verified and accessible.
            </div>
            <div className="cs-repo-meta-grid">
              <div className="cs-repo-meta-box">
                <span className="cs-repo-meta-label">Discovered Files</span>
                <span className="cs-repo-meta-value">{intakeData.file_count ?? intakeData.source_file_count ?? '—'}</span>
              </div>
              <div className="cs-repo-meta-box">
                <span className="cs-repo-meta-label">Total Source Size</span>
                <span className="cs-repo-meta-value">
                  {intakeData.total_source_bytes
                    ? `${(intakeData.total_source_bytes / 1024).toFixed(1)} KB`
                    : '—'}
                </span>
              </div>
              <div className="cs-repo-meta-box">
                <span className="cs-repo-meta-label">Source Extensions</span>
                <span className="cs-repo-meta-value" style={{ fontSize: '12px' }}>
                  {Array.isArray(intakeData.source_extensions)
                    ? intakeData.source_extensions.join(', ')
                    : '—'}
                </span>
              </div>
              <div className="cs-repo-meta-box">
                <span className="cs-repo-meta-label">Owner / Repo</span>
                <span className="cs-repo-meta-value" style={{ fontSize: '12px' }}>
                  {intakeData.repository?.owner || '—'}/{intakeData.repository?.repository || '—'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Acquisition Metadata (Strictly excludes internal filesystem paths) */}
        {acquisitionData && (
          <div style={{ marginTop: '14px', padding: '12px 14px', backgroundColor: '#F8FAFC', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 700, color: '#64748B', textTransform: 'uppercase' }}>
                  Acquisition ID:
                </span>
                <code style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#0284C7', fontWeight: 600 }}>
                  {acquisitionData.acquisition?.acquisition_id || acquisitionData.acquisition_id || '—'}
                </code>
              </div>
              <span style={{ fontSize: '12px', color: '#10B981', fontWeight: 600 }}>
                ✓ Workspace Isolated & Ready for Inspection
              </span>
            </div>
          </div>
        )}

        {/* Recent Analysis Summary for this repo if exists */}
        {latestAnalysisForCurrentRepo && !analysisReport && (
          <div style={{ marginTop: '16px', padding: '14px 16px', backgroundColor: '#F8FAFC', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <div style={{ fontSize: '11px', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Latest Audit Record For This Repository
                </div>
                <div style={{ fontSize: '13.5px', fontWeight: 600, color: '#0F172A', marginTop: '2px' }}>
                  Analysis ID: <code style={{ color: '#0284C7' }}>{latestAnalysisForCurrentRepo.analysis_id}</code>
                  <span style={{ margin: '0 8px', color: '#CBD5E1' }}>•</span>
                  <span>{latestAnalysisForCurrentRepo.timestamp ? new Date(latestAnalysisForCurrentRepo.timestamp).toLocaleDateString() : 'Recent'}</span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <StatusBadge
                  status={
                    latestAnalysisForCurrentRepo.review_status ||
                    latestAnalysisForCurrentRepo.summary?._review_status ||
                    'ALLOW'
                  }
                />
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate(`/history?id=${latestAnalysisForCurrentRepo.analysis_id}`)}
                >
                  Audit in History →
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Results View if run in RepositoryView */}
      {analysisReport && (
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                ANALYSIS ID: {analysisReport.analysis_id}
              </div>
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', margin: '2px 0 0' }}>
                Multi-File Repository Security Report
              </h3>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>GATE VERDICT:</span>
              <StatusBadge status={verdict} size="large" />
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => navigate(`/history?id=${analysisReport.analysis_id}`)}
              >
                View Full Audit in History →
              </button>
            </div>
          </div>

          {/* Severity Counters */}
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

          {/* Findings List Preview */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
              Repository Findings ({findings.length})
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
                  <strong>No Vulnerabilities Detected:</strong> Scanned files in the workspace passed all security rules. Gate decision: <code>ALLOW</code>.
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
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {filteredFindings.map((f, idx) => (
                  <FindingCard
                    key={f.finding_id || idx}
                    finding={f}
                    index={idx}
                    onInspect={(finding) => setSelectedFinding(finding)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Monitored Repositories & Activity List */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 2px' }}>
              Monitored Repositories & Analytics
            </h3>
            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: 0 }}>
              Repositories tracked across security analyses and audit logs.
            </p>
          </div>

          <input
            type="text"
            className="cs-explorer-search-input"
            style={{ width: '220px' }}
            placeholder="Filter repositories..."
            value={repoSearch}
            onChange={(e) => setRepoSearch(e.target.value)}
          />
        </div>

        {/* Authoritative Repository Posture Overview Chips */}
        {monitoredRepos.length > 0 && (
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '10px',
              marginBottom: '16px',
            }}
          >
            <div className="cs-repo-meta-box">
              <span className="cs-repo-meta-label">Monitored Repos</span>
              <span className="cs-repo-meta-value">{repoInsights.totalRepos}</span>
            </div>
            <div className="cs-repo-meta-box">
              <span className="cs-repo-meta-label">Total Analyses</span>
              <span className="cs-repo-meta-value">{repoInsights.totalAnalyses}</span>
            </div>
            <div
              className="cs-repo-meta-box"
              style={{
                borderColor: repoInsights.attentionCount > 0 ? '#FECACA' : '#E2E8F0',
                backgroundColor: repoInsights.attentionCount > 0 ? '#FEF2F2' : '#F8FAFC',
              }}
            >
              <span
                className="cs-repo-meta-label"
                style={{ color: repoInsights.attentionCount > 0 ? '#DC2626' : '#64748B' }}
              >
                Requires Attention
              </span>
              <span
                className="cs-repo-meta-value"
                style={{ color: repoInsights.attentionCount > 0 ? '#DC2626' : '#0F172A' }}
              >
                {repoInsights.attentionCount}
              </span>
            </div>
            <div className="cs-repo-meta-box" style={{ borderColor: '#D1FAE5', backgroundColor: '#F0FDF4' }}>
              <span className="cs-repo-meta-label" style={{ color: '#059669' }}>Clean Posture</span>
              <span className="cs-repo-meta-value" style={{ color: '#059669' }}>{repoInsights.cleanCount}</span>
            </div>
          </div>
        )}

        {loadError && (
          <div className="alert-box alert-error" style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <strong>Telemetry Notice:</strong> {loadError}
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={loadRepositoryIntelligence}
              >
                ↻ Retry
              </button>
            </div>
          </div>
        )}

        {reposLoading ? (
          <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Loading repository intelligence...
          </div>
        ) : filteredMonitored.length === 0 ? (
          monitoredRepos.length === 0 ? (
            <div className="empty-state" style={{ padding: '30px 20px' }}>
              <div className="empty-state-icon">📁</div>
              <div className="empty-state-title">No Monitored Repositories Yet</div>
              <p className="empty-state-desc">
                Run a repository intake or scan to populate the repository intelligence register.
              </p>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: '30px 20px' }}>
              <div className="empty-state-icon">🔍</div>
              <div className="empty-state-title">No Matching Repositories</div>
              <p className="empty-state-desc">
                No repositories match your filter &ldquo;{repoSearch}&rdquo;.
              </p>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                style={{ marginTop: '10px' }}
                onClick={() => setRepoSearch('')}
              >
                Clear Filter
              </button>
            </div>
          )
        ) : (
          <div className="table-container" style={{ border: '1px solid #E2E8F0', borderRadius: '8px' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Repository Identifier</th>
                  <th>Analyses</th>
                  <th>Finding Posture & Severities</th>
                  <th>Gate Verdict & Breakdown</th>
                  <th>Last Analysis</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredMonitored.map((repo) => {
                  const id = repo.repository_id || 'default';
                  const dist = repo.review_status_distribution || {};
                  const isBlocked = (dist.block ?? 0) > 0 || (repo.critical_count ?? 0) > 0;
                  const isReview = (dist.review ?? 0) > 0 || (repo.medium_count ?? 0) > 0;
                  const gateVerdict = isBlocked ? 'BLOCK' : isReview ? 'REVIEW' : 'ALLOW';
                  const requiresAttention = isBlocked || (repo.high_count ?? 0) > 0;

                  const matchingAnalysis = Array.isArray(recentAnalyses)
                    ? recentAnalyses.find((a) => {
                        const slug = getAnalysisRepoIdentifier(a);
                        const target = String(id).toLowerCase();
                        return slug && (slug.includes(target) || target.includes(slug));
                      })
                    : null;

                  return (
                    <tr key={id}>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#0284C7' }}>
                              {id}
                            </span>
                            {requiresAttention && (
                              <span
                                style={{
                                  fontSize: '10px',
                                  fontWeight: 700,
                                  padding: '1px 6px',
                                  borderRadius: '4px',
                                  backgroundColor: '#FEF2F2',
                                  color: '#DC2626',
                                  border: '1px solid #FECACA',
                                  fontFamily: 'var(--font-mono)',
                                  letterSpacing: '0.3px',
                                }}
                                title="Authoritative condition: Repository has BLOCK analyses or Critical/High findings"
                              >
                                ATTENTION
                              </span>
                            )}
                          </div>
                        </div>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        {repo.analysis_count ?? 0}
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', color: (repo.finding_count ?? 0) > 0 ? '#EF4444' : '#10B981', fontWeight: 700 }}>
                            {repo.finding_count ?? 0} total
                          </span>
                          <div style={{ display: 'flex', gap: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                            <span style={{ color: '#EF4444' }} title="Critical findings count">C:{repo.critical_count ?? 0}</span>
                            <span style={{ color: '#F97316' }} title="High findings count">H:{repo.high_count ?? 0}</span>
                            <span style={{ color: '#F59E0B' }} title="Medium findings count">M:{repo.medium_count ?? 0}</span>
                            <span style={{ color: '#06B6D4' }} title="Low findings count">L:{repo.low_count ?? 0}</span>
                          </div>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          <StatusBadge status={gateVerdict} />
                          <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            B:{dist.block ?? 0} · R:{dist.review ?? 0} · A:{dist.allow ?? 0}
                          </span>
                        </div>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {repo.last_analysis_timestamp
                          ? new Date(repo.last_analysis_timestamp).toLocaleDateString()
                          : '—'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', flexWrap: 'wrap', gap: '4px', justifyContent: 'flex-end' }}>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleSelectMonitoredRepo(repo)}
                            title="Load this repository into the workspace configuration"
                          >
                            Configure
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => {
                              const full = id.startsWith('http') ? id : (id === 'default' ? 'https://github.com/SARUKKESH-M/S5-MINI-PROJECT' : `https://github.com/${id}`);
                              navigate('/analyze', {
                                state: {
                                  repo: full,
                                  repoUrl: full,
                                  repository_url: full,
                                  branch: 'main',
                                },
                              });
                            }}
                            title="Open repository in dedicated Analyze Studio"
                          >
                            Analyze →
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => {
                              if (matchingAnalysis?.analysis_id) {
                                navigate(`/history?id=${encodeURIComponent(matchingAnalysis.analysis_id)}`);
                              } else {
                                navigate('/history');
                              }
                            }}
                            title={matchingAnalysis ? `View analysis ${matchingAnalysis.analysis_id} in history` : 'View audit history'}
                          >
                            History →
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => navigate(`/analytics?repo=${encodeURIComponent(id)}`)}
                            title="Inspect repository risk analytics and trends"
                          >
                            Analytics
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => {
                              if (matchingAnalysis?.analysis_id) {
                                navigate(`/reviews?analysis_id=${encodeURIComponent(matchingAnalysis.analysis_id)}`);
                              } else {
                                navigate('/reviews');
                              }
                            }}
                            title="Review security findings and manage suppressions"
                          >
                            Review
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => navigate(`/pull-requests?repo=${encodeURIComponent(id)}`)}
                            title="View Pull Requests for this repository"
                          >
                            PRs
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Repository Retention & Deletion Policy Notice (Rules 14 & 15: No fake deletion) */}
        <div className="cs-repo-retention-notice" style={{ marginTop: '16px' }}>
          <span style={{ fontSize: '16px' }}>🛡️</span>
          <div>
            <strong>Repository Retention Policy:</strong> Monitored repository records and telemetry are permanently preserved in the SQLite audit store. In accordance with security compliance boundaries, repository deletion is restricted.
          </div>
        </div>
      </div>

      {/* Finding Detail Inspection Modal */}
      <FindingPreviewModal
        isOpen={Boolean(selectedFinding)}
        onClose={() => setSelectedFinding(null)}
        finding={selectedFinding}
      />
    </div>
  );
}
