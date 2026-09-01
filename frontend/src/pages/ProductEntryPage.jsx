import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';

export default function ProductEntryPage() {
  const navigate = useNavigate();

  // Local interactive UI state
  const [repoUrl, setRepoUrl] = useState('https://github.com/pallets/flask');
  const [branch, setBranch] = useState('main');
  const [targetPath, setTargetPath] = useState('./');
  const [isInitializing, setIsInitializing] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);

  // Preset demo repositories
  const sampleRepos = [
    { name: 'pallets/flask', url: 'https://github.com/pallets/flask' },
    { name: 'psf/requests', url: 'https://github.com/psf/requests' },
    { name: 'tiangolo/fastapi', url: 'https://github.com/tiangolo/fastapi' },
  ];

  const handleSelectSample = (url) => {
    setRepoUrl(url);
    setStatusMessage(`Loaded preset repository: ${url}`);
  };

  const handleInitialize = (e) => {
    e.preventDefault();
    if (!repoUrl.trim()) return;

    setIsInitializing(true);
    setStatusMessage('Validating intake reference & preparing isolation workspace...');

    // Simulate fast local UI feedback before routing to Command Center
    setTimeout(() => {
      setIsInitializing(false);
      navigate('/command-center');
    }, 800);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1280px', margin: '0 auto', width: '100%' }}>
      {/* Hero Header Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '24px', alignItems: 'center' }}>
        <div style={{ gridColumn: 'span 5', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <LabelCaps style={{ color: 'var(--primary-cyan)', fontSize: '12px' }}>
              CODESENTINEL v2.4.1_STABLE
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
                INITIALIZED
              </span>
            </h1>
          </div>
          <p style={{ margin: 0, color: 'var(--text-on-surface-variant)', fontSize: '14px', lineHeight: 1.6 }}>
            Autonomous repository security analysis pipeline. Combining AST parsing, RAG evidence retrieval, and LLM threat verification.
          </p>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <PrimaryButton icon="terminal" onClick={handleInitialize} disabled={isInitializing}>
              {isInitializing ? 'INITIALIZING WORKSPACE...' : 'INITIALIZE SECURITY ENVIRONMENT'}
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
              stroke="var(--primary-cyan)"
              strokeWidth="2"
              strokeDasharray="8 8"
            />
          </svg>

          {/* Node 1: GitHub PR */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', left: '10%' }}>
            <div style={{ width: '44px', height: '44px', backgroundColor: 'var(--panel-bg-high)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-xs)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined">webhook</span>
            </div>
            <LabelCaps style={{ fontSize: '10px' }}>GITHUB PR</LabelCaps>
          </div>

          {/* Node 2: AST / RAG */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', left: '38%', top: '15%' }}>
            <div style={{ width: '44px', height: '44px', backgroundColor: 'var(--panel-bg-high)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-xs)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined">memory</span>
            </div>
            <LabelCaps style={{ fontSize: '10px' }}>AST / RAG</LabelCaps>
          </div>

          {/* Node 3: AI Engine */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', left: '62%', top: '15%' }}>
            <div style={{ width: '44px', height: '44px', backgroundColor: 'var(--panel-bg-high)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-xs)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-on-surface-variant)' }}>
              <span className="material-symbols-outlined">psychology</span>
            </div>
            <LabelCaps style={{ fontSize: '10px' }}>AI ENGINE</LabelCaps>
          </div>

          {/* Node 4: Decision PASS */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 1, position: 'absolute', right: '10%' }}>
            <div style={{ width: '44px', height: '44px', backgroundColor: 'var(--panel-bg-high)', border: '1px solid var(--primary-cyan)', borderRadius: 'var(--radius-xs)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--primary-cyan)', boxShadow: '0 0 12px rgba(0, 240, 255, 0.25)' }}>
              <span className="material-symbols-outlined">security</span>
            </div>
            <LabelCaps style={{ fontSize: '10px', color: 'var(--primary-cyan)' }}>DECISION: PASS</LabelCaps>
          </div>
        </div>
      </div>

      {/* Main Intake Form Panel */}
      <DataPanel title="REPOSITORY INTAKE WORKSPACE" status="cyan">
        <form onSubmit={handleInitialize} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <LabelCaps>TARGET GITHUB HTTPS REPOSITORY URL</LabelCaps>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="url"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                required
                style={{
                  flex: 1,
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
              <PrimaryButton icon="search" type="submit" disabled={isInitializing}>
                ACQUIRE &amp; ANALYZE
              </PrimaryButton>
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
              <LabelCaps>TARGET SUBPATH</LabelCaps>
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="./"
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

          {/* Preset Demo Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '4px' }}>
            <LabelCaps style={{ fontSize: '10px' }}>PRESET DEMO REPOSITORIES:</LabelCaps>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {sampleRepos.map((repo) => (
                <button
                  key={repo.name}
                  type="button"
                  onClick={() => handleSelectSample(repo.url)}
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
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = 'var(--primary-cyan)';
                    e.currentTarget.style.color = 'var(--primary-cyan)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = 'var(--border-subtle)';
                    e.currentTarget.style.color = 'var(--text-on-surface-variant)';
                  }}
                >
                  {repo.name}
                </button>
              ))}
            </div>
          </div>

          {statusMessage && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--primary-cyan)', marginTop: '4px' }}>
              &gt; {statusMessage}
            </div>
          )}
        </form>
      </DataPanel>

      {/* Metrics Bento Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        <MetricCard
          label="NETWORK SCANS"
          value="4.2k"
          delta="PRs Processed / 24H"
          accentColor="cyan"
        />
        <MetricCard
          label="THREATS BLOCKED"
          value="128"
          delta="CRITICAL SEV DETECTED"
          accentColor="red"
        />
        <MetricCard
          label="ENGINE CONFIDENCE"
          value="99.8%"
          delta="GROUNDED EVIDENCE ACCURACY"
          accentColor="amber"
        />
      </div>

      {/* Security Guarantees & Intake Protocol Panel */}
      <DataPanel title="INTAKE SECURITY GUARANTEES & PROTOCOL BOUNDARIES" status="green">
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
