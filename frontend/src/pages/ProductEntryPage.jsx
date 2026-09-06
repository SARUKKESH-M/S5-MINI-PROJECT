import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';
import {
  intakeRepository,
  acquireRepository,
  analyzeRepository,
  getPlatformMetrics
} from '../services/apiClient';

export default function ProductEntryPage() {
  const navigate = useNavigate();

  // Form input state
  const [repoUrl, setRepoUrl] = useState('https://github.com/pallets/flask');
  const [branch, setBranch] = useState('main');
  const [targetPath, setTargetPath] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Execution flow state: 'idle' | 'intake' | 'acquiring' | 'analyzing' | 'completed' | 'error'
  const [pipelineState, setPipelineState] = useState('idle');
  const [statusMessage, setStatusMessage] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  // Results state
  const [intakeResult, setIntakeResult] = useState(null);
  const [acquisitionResult, setAcquisitionResult] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);

  // Platform Telemetry
  const [telemetry, setTelemetry] = useState({
    totalAudits: 0,
    blockedThreats: 0,
    lastLatencyMs: 0,
    isAvailable: false
  });

  useEffect(() => {
    let isMounted = true;
    getPlatformMetrics()
      .then((m) => {
        if (!isMounted || !m) return;
        setTelemetry({
          totalAudits: m.analysis_requests_total ?? 0,
          blockedThreats: m.decisions_block_total ?? 0,
          lastLatencyMs: m.last_analysis_duration_ms ?? 0,
          isAvailable: true
        });
      })
      .catch(() => {
        // Telemetry failure handled gracefully
      });
    return () => { isMounted = false; };
  }, []);

  // Preset sample repositories
  const sampleRepos = [
    { name: 'pallets/flask', url: 'https://github.com/pallets/flask', branch: 'main' },
    { name: 'psf/requests', url: 'https://github.com/psf/requests', branch: 'main' },
    { name: 'tiangolo/fastapi', url: 'https://github.com/tiangolo/fastapi', branch: 'master' }
  ];

  const handleSelectSample = (sample) => {
    setRepoUrl(sample.url);
    setBranch(sample.branch);
    setStatusMessage(`Loaded preset repository reference: ${sample.name}`);
    setErrorMessage(null);
  };

  // Step 1: Validate Intake Only
  const handleValidateIntake = async (e) => {
    if (e) e.preventDefault();
    if (!repoUrl.trim()) return;

    setPipelineState('intake');
    setStatusMessage('Validating repository reference and discovering source scope...');
    setErrorMessage(null);
    setIntakeResult(null);

    const payload = {
      repository_url: repoUrl.trim(),
      branch: branch.trim() || 'main',
      path: targetPath.trim() || '',
      local_path: localPath.trim() || undefined
    };

    try {
      const res = await intakeRepository(payload);
      setIntakeResult(res);
      setPipelineState('idle');
      setStatusMessage(`Intake verified: ${res.file_count || 0} source file(s) discovered (${res.source_extensions?.join(', ') || 'N/A'}).`);
    } catch (err) {
      setPipelineState('error');
      setErrorMessage(err.message || 'Repository intake validation failed.');
      setStatusMessage(null);
    }
  };

  // Automated 3-Stage Pipeline: Intake -> Acquire -> Analyze
  const handleFullPipeline = async (e) => {
    if (e) e.preventDefault();
    if (!repoUrl.trim()) return;

    setErrorMessage(null);
    setIntakeResult(null);
    setAcquisitionResult(null);
    setAnalysisResult(null);

    const basePayload = {
      repository_url: repoUrl.trim(),
      branch: branch.trim() || 'main',
      path: targetPath.trim() || '',
      local_path: localPath.trim() || undefined
    };

    try {
      // Stage 1: Intake
      setPipelineState('intake');
      setStatusMessage('[1/3] Validating repository intake reference...');
      const intakeRes = await intakeRepository(basePayload);
      setIntakeResult(intakeRes);

      // Stage 2: Acquisition
      setPipelineState('acquiring');
      setStatusMessage('[2/3] Acquiring repository into isolated workspace...');
      const acqRes = await acquireRepository(basePayload);
      setAcquisitionResult(acqRes);

      const acqId = acqRes.acquisition?.acquisition_id;
      if (!acqId) {
        throw new Error('Acquisition succeeded but did not return a valid acquisition_id.');
      }

      // Stage 3: Analysis
      setPipelineState('analyzing');
      setStatusMessage('[3/3] Executing static AST parsing, RAG grounding, and security analysis...');
      const anaRes = await analyzeRepository({
        acquisition_id: acqId,
        query: `Repository Security Analysis: ${intakeRes.repository?.repository || repoUrl}`
      });

      setAnalysisResult(anaRes);
      setPipelineState('completed');
      setStatusMessage(`Analysis completed: ${anaRes.analysis_id} generated. Gate Decision: ${(anaRes.review_status || 'ALLOW').toUpperCase()}`);
    } catch (err) {
      setPipelineState('error');
      setErrorMessage(err.message || 'Repository acquisition & analysis pipeline failed.');
      setStatusMessage(null);
    }
  };

  const isRunning = pipelineState === 'intake' || pipelineState === 'acquiring' || pipelineState === 'analyzing';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1280px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Hero Header Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '24px', alignItems: 'center' }}>
        <div style={{ gridColumn: 'span 5', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <LabelCaps style={{ color: 'var(--primary-cyan)', fontSize: '12px' }}>
              CODESENTINEL DevSecOps PLATFORM
            </LabelCaps>
            <h1 style={{
              margin: '8px 0 0 0',
              fontFamily: 'var(--font-ui)',
              fontSize: '32px',
              fontWeight: 700,
              lineHeight: 1.2,
              letterSpacing: '-0.02em',
              color: 'var(--text-on-surface)'
            }}>
              SECURITY OS<br />
              <span style={{ color: 'var(--primary-cyan)', fontFamily: 'var(--font-mono)', fontSize: '24px' }}>
                INTAKE PIPELINE
              </span>
            </h1>
          </div>
          <p style={{ margin: 0, color: 'var(--text-on-surface-variant)', fontSize: '14px', lineHeight: 1.6 }}>
            Automated repository security analysis pipeline. Executes local workspace intake, secure clone acquisition, static AST parsing, and authoritative Step 6O gate verification.
          </p>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <PrimaryButton icon="rocket_launch" onClick={handleFullPipeline} disabled={isRunning}>
              {isRunning ? 'PIPELINE ACTIVE...' : 'ACQUIRE &amp; ANALYZE REPO'}
            </PrimaryButton>
            <SecondaryButton icon="dashboard" onClick={() => navigate('/command-center')}>
              GLOBAL COMMAND
            </SecondaryButton>
          </div>
        </div>

        {/* Abstract Pipeline SVG Flow Visualization */}
        <div style={{
          gridColumn: 'span 7',
          backgroundColor: 'var(--panel-bg)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-xs)',
          padding: '24px',
          height: '240px',
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          overflow: 'hidden'
        }}>
          {/* Connecting SVG Path */}
          <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
            <path
              d="M 60 120 L 200 120 L 320 60 L 460 60 L 580 120 L 720 120"
              fill="none"
              stroke="var(--border-default)"
              strokeWidth="2"
            />
            <path
              d="M 60 120 L 200 120 L 320 60 L 460 60 L 580 120 L 720 120"
              fill="none"
              stroke={isRunning ? 'var(--secondary-amber)' : 'var(--primary-cyan)'}
              strokeWidth="2"
              strokeDasharray="8 8"
            />
          </svg>

          {/* Node 1: Intake */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', left: '10%' }}>
            <div style={{
              width: '44px',
              height: '44px',
              backgroundColor: 'var(--panel-bg-high)',
              border: `1px solid ${pipelineState === 'intake' ? 'var(--primary-cyan)' : 'var(--border-default)'}`,
              borderRadius: 'var(--radius-xs)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--primary-cyan)'
            }}>
              <span className="material-symbols-outlined">input</span>
            </div>
            <LabelCaps style={{ fontSize: '10px' }}>1. INTAKE</LabelCaps>
          </div>

          {/* Node 2: Acquisition */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', left: '38%', top: '15%' }}>
            <div style={{
              width: '44px',
              height: '44px',
              backgroundColor: 'var(--panel-bg-high)',
              border: `1px solid ${pipelineState === 'acquiring' ? 'var(--secondary-amber)' : 'var(--border-default)'}`,
              borderRadius: 'var(--radius-xs)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--secondary-amber)'
            }}>
              <span className="material-symbols-outlined">download_for_offline</span>
            </div>
            <LabelCaps style={{ fontSize: '10px' }}>2. ACQUIRE</LabelCaps>
          </div>

          {/* Node 3: AST / RAG */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', left: '62%', top: '15%' }}>
            <div style={{
              width: '44px',
              height: '44px',
              backgroundColor: 'var(--panel-bg-high)',
              border: `1px solid ${pipelineState === 'analyzing' ? 'var(--primary-cyan)' : 'var(--border-default)'}`,
              borderRadius: 'var(--radius-xs)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-on-surface-variant)'
            }}>
              <span className="material-symbols-outlined">psychology</span>
            </div>
            <LabelCaps style={{ fontSize: '10px' }}>3. ANALYZE</LabelCaps>
          </div>

          {/* Node 4: Gate Decision */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', right: '10%' }}>
            <div style={{
              width: '44px',
              height: '44px',
              backgroundColor: 'var(--panel-bg-high)',
              border: `1px solid ${analysisResult ? (analysisResult.review_status === 'block' ? 'var(--critical-red)' : 'var(--status-green)') : 'var(--primary-cyan)'}`,
              borderRadius: 'var(--radius-xs)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: analysisResult ? (analysisResult.review_status === 'block' ? 'var(--critical-red)' : 'var(--status-green)') : 'var(--primary-cyan)',
              boxShadow: '0 0 12px rgba(0, 240, 255, 0.25)'
            }}>
              <span className="material-symbols-outlined">verified_user</span>
            </div>
            <LabelCaps style={{ fontSize: '10px', color: 'var(--primary-cyan)' }}>
              {analysisResult ? `GATE: ${analysisResult.review_status?.toUpperCase()}` : '4. GATE'}
            </LabelCaps>
          </div>
        </div>
      </div>

      {/* 2. Main Intake Form Panel */}
      <DataPanel title="REPOSITORY INTAKE &amp; ACQUISITION WORKSPACE" status="cyan">
        <form onSubmit={handleFullPipeline} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <LabelCaps>TARGET GITHUB HTTPS REPOSITORY URL</LabelCaps>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <input
                type="url"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                required
                disabled={isRunning}
                style={{
                  flex: 1,
                  minWidth: '280px',
                  backgroundColor: 'var(--bg-void-lowest)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '10px 14px',
                  color: 'var(--text-on-surface)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '13px',
                  outline: 'none'
                }}
              />
              <div style={{ display: 'flex', gap: '8px' }}>
                <SecondaryButton
                  icon="rule"
                  type="button"
                  onClick={handleValidateIntake}
                  disabled={isRunning}
                >
                  {pipelineState === 'intake' ? 'VALIDATING...' : 'VALIDATE INTAKE'}
                </SecondaryButton>
                <PrimaryButton
                  icon="play_arrow"
                  type="submit"
                  disabled={isRunning}
                >
                  {isRunning ? 'PROCESSING...' : 'ACQUIRE &amp; ANALYZE'}
                </PrimaryButton>
              </div>
            </div>
          </div>

          {/* Branch & Path controls */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <LabelCaps>BRANCH REFERENCE</LabelCaps>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
                disabled={isRunning}
                style={{
                  backgroundColor: 'var(--bg-void-lowest)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '8px 12px',
                  color: 'var(--text-on-surface)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '13px',
                  outline: 'none'
                }}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <LabelCaps>TARGET SUBPATH (OPTIONAL)</LabelCaps>
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="./ or src/"
                disabled={isRunning}
                style={{
                  backgroundColor: 'var(--bg-void-lowest)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '8px 12px',
                  color: 'var(--text-on-surface)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '13px',
                  outline: 'none'
                }}
              />
            </div>
          </div>

          {/* Advanced Local Workspace Toggle */}
          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--primary-cyan)',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                padding: 0
              }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
                {showAdvanced ? 'expand_less' : 'tune'}
              </span>
              {showAdvanced ? 'HIDE ADVANCED SETTINGS' : 'ADVANCED: LOCAL WORKSPACE / OFFLINE OVERRIDE'}
            </button>

            {showAdvanced && (
              <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>LOCAL DIRECTORY PATH OVERRIDE (OPTIONAL)</LabelCaps>
                <input
                  type="text"
                  value={localPath}
                  onChange={(e) => setLocalPath(e.target.value)}
                  placeholder="e.g. scratch or C:/path/to/local/code"
                  disabled={isRunning}
                  style={{
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '8px 12px',
                    color: 'var(--text-on-surface)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    outline: 'none'
                  }}
                />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
                  When provided, CodeSentinel acquires directly from this local filesystem location without cloning over the network.
                </span>
              </div>
            )}
          </div>

          {/* Preset Demo Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '4px', flexWrap: 'wrap' }}>
            <LabelCaps style={{ fontSize: '10px' }}>PRESET DEMO REFERENCES:</LabelCaps>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {sampleRepos.map((sample) => (
                <button
                  key={sample.name}
                  type="button"
                  onClick={() => handleSelectSample(sample)}
                  disabled={isRunning}
                  style={{
                    backgroundColor: 'var(--panel-bg-high)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '4px 10px',
                    color: 'var(--text-on-surface-variant)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease-in-out'
                  }}
                >
                  {sample.name}
                </button>
              ))}
            </div>
          </div>

          {/* Feedback & Status Message */}
          {statusMessage && (
            <div style={{
              padding: '10px 14px',
              backgroundColor: 'rgba(0, 240, 255, 0.08)',
              border: '1px solid var(--primary-cyan)',
              borderRadius: 'var(--radius-xs)',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--primary-cyan)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <StatusPip status={isRunning ? 'amber' : 'cyan'} />
              <span>{statusMessage}</span>
            </div>
          )}

          {/* Error Banner */}
          {errorMessage && (
            <div style={{
              padding: '12px 16px',
              backgroundColor: 'rgba(255, 59, 48, 0.08)',
              border: '1px solid var(--critical-red)',
              borderRadius: 'var(--radius-xs)',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--critical-red)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div>
                <strong>INTAKE ERROR:</strong> {errorMessage}
              </div>
              <button
                type="button"
                onClick={handleFullPipeline}
                style={{
                  backgroundColor: 'transparent',
                  border: '1px solid var(--critical-red)',
                  color: 'var(--critical-red)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '2px 8px',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px'
                }}
              >
                RETRY
              </button>
            </div>
          )}
        </form>
      </DataPanel>

      {/* 3. Real Pipeline Results Presentation */}
      {/* 3A. Intake Discovery Preview */}
      {intakeResult && (
        <DataPanel title="STAGE 1 — DISCOVERED REPOSITORY METADATA (PUBLIC SCOPE)" status="cyan">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <LabelCaps style={{ fontSize: '10px' }}>DISCOVERED FILES</LabelCaps>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', fontWeight: 700, color: 'var(--primary-cyan)', marginTop: '4px' }}>
                  {intakeResult.file_count ?? 0}
                </div>
              </div>

              <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <LabelCaps style={{ fontSize: '10px' }}>TOTAL SOURCE SIZE</LabelCaps>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', fontWeight: 700, color: 'var(--status-green)', marginTop: '4px' }}>
                  {intakeResult.total_source_bytes ? `${(intakeResult.total_source_bytes / 1024).toFixed(1)} KB` : '0 KB'}
                </div>
              </div>

              <div style={{ padding: '10px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <LabelCaps style={{ fontSize: '10px' }}>SOURCE EXTENSIONS</LabelCaps>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-on-surface)', marginTop: '4px' }}>
                  {intakeResult.source_extensions?.join(', ') || 'None'}
                </div>
              </div>
            </div>

            {/* Discovered files preview list */}
            {intakeResult.files && intakeResult.files.length > 0 && (
              <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
                <div style={{ padding: '6px 12px', backgroundColor: 'var(--bg-void-low)', borderBottom: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
                  DISCOVERED FILES PREVIEW (FIRST {Math.min(intakeResult.files.length, 5)} OF {intakeResult.files.length})
                </div>
                {intakeResult.files.slice(0, 5).map((f) => (
                  <div
                    key={f.path}
                    style={{
                      padding: '8px 12px',
                      borderBottom: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px'
                    }}
                  >
                    <span style={{ color: 'var(--text-on-surface)' }}>{f.path}</span>
                    <span style={{ color: 'var(--text-dim)' }}>{f.size_bytes} B ({f.language})</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </DataPanel>
      )}

      {/* 3B. Analysis Result & Direct PR Review Handoff */}
      {analysisResult && (
        <DataPanel
          title="STAGE 3 — REPOSITORY ANALYSIS COMPLETE (STEP 6O CONTRACT)"
          status={analysisResult.review_status === 'block' ? 'red' : 'green'}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <StatusPip status={analysisResult.review_status === 'block' ? 'red' : 'green'} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
                    ANALYSIS ID: {analysisResult.analysis_id}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>
                  Verdict: <strong style={{ color: analysisResult.review_status === 'block' ? 'var(--critical-red)' : 'var(--status-green)' }}>{(analysisResult.review_status || 'ALLOW').toUpperCase()}</strong> — {analysisResult.summary?.total_findings || 0} findings ({analysisResult.summary?.critical_count || 0} Critical)
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <PrimaryButton
                  icon="alt_route"
                  onClick={() => navigate('/pr-review', { state: { analysisId: analysisResult.analysis_id } })}
                >
                  OPEN IN PR REVIEW
                </PrimaryButton>
                <SecondaryButton
                  icon="folder_managed"
                  onClick={() => navigate('/repo-intelligence', { state: { analysisId: analysisResult.analysis_id } })}
                >
                  VIEW INTELLIGENCE
                </SecondaryButton>
              </div>
            </div>
          </div>
        </DataPanel>
      )}

      {/* 4. Real Metrics Bento Grid (from /platform/metrics) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        <MetricCard
          label="AUDITED ANALYSES"
          value={telemetry.isAvailable ? String(telemetry.totalAudits) : 'ONLINE'}
          delta="ANALYSIS RECORDS ACTIVE"
          accentColor="cyan"
        />
        <MetricCard
          label="THREATS BLOCKED"
          value={telemetry.isAvailable ? String(telemetry.blockedThreats) : '0'}
          delta="SECURITY GATE ENFORCEMENT"
          accentColor="red"
        />
        <MetricCard
          label="LAST PIPELINE LATENCY"
          value={telemetry.isAvailable ? `${telemetry.lastLatencyMs} ms` : 'READY'}
          delta="DETERMINISTIC LATENCY"
          accentColor="green"
        />
      </div>

      {/* 5. Security Guarantees & Intake Protocol Panel */}
      <DataPanel title="INTAKE SECURITY GUARANTEES &amp; PROTOCOL BOUNDARIES" status="green">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--status-green)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>gpp_good</span>
              <strong style={{ fontSize: '13px' }}>Static Non-Execution</strong>
            </div>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.5 }}>
              Strict prohibition against code execution (`eval`, `exec`, `os.system`). Target files treated strictly as UTF-8 text.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>folder_zip</span>
              <strong style={{ fontSize: '13px' }}>Isolated Workspace</strong>
            </div>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.5 }}>
              Acquired repositories reside in controlled temporary workspace directories with traversal path validation.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>verified</span>
              <strong style={{ fontSize: '13px' }}>AST + RAG Grounded</strong>
            </div>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.5 }}>
              Every finding must be backed by concrete AST signals and grounded document line ranges before aggregation.
            </p>
          </div>
        </div>
      </DataPanel>
    </div>
  );
}
