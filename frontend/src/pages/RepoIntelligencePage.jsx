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

export default function RepoIntelligencePage() {
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
    acquisition: {
      acquisition_id: 'acq_workspace_8f91',
      status: 'COMPLETED',
      isolated_dir: 'scratch/repo_workspaces/acq_workspace_8f91',
      acquired_at: '2026-09-01T08:25:00Z'
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
        description: 'Detected hardcoded secret string literal in application configuration.',
        severity: 'critical',
        confidence: 'high',
        category: 'security'
      },
      {
        finding_id: 'finding_2',
        title: 'Unsafe Pickle Deserialization Invocations',
        description: 'Legacy session loading method uses untrusted pickle deserialization.',
        severity: 'critical',
        confidence: 'high',
        category: 'security'
      },
      {
        finding_id: 'finding_3',
        title: 'Missing CSRF Token Protection on Admin Route',
        description: 'State-changing POST handler lacks explicit CSRF token check decorator.',
        severity: 'high',
        confidence: 'medium',
        category: 'security'
      }
    ],
    analysis_version: '1.0'
  });

  // File Inventory presentation list
  const [files] = useState([
    { path: 'src/flask/app.py', size: '24.5 KB', status: 'ANALYZED', ast_signals: 14, findings: 1, type: 'python' },
    { path: 'src/flask/config.py', size: '12.1 KB', status: 'ANALYZED', ast_signals: 8, findings: 1, type: 'python' },
    { path: 'src/flask/sessions.py', size: '18.3 KB', status: 'ANALYZED', ast_signals: 11, findings: 1, type: 'python' },
    { path: 'src/flask/blueprints.py', size: '15.8 KB', status: 'ANALYZED', ast_signals: 6, findings: 0, type: 'python' },
    { path: 'src/flask/cli.py', size: '32.0 KB', status: 'ANALYZED', ast_signals: 19, findings: 0, type: 'python' },
    { path: 'src/flask/helpers.py', size: '9.4 KB', status: 'ANALYZED', ast_signals: 4, findings: 0, type: 'python' },
    { path: 'tests/test_basic.py', size: '8.2 KB', status: 'SKIPPED', ast_signals: 0, findings: 0, type: 'test' },
    { path: 'docs/conf.py', size: '5.1 KB', status: 'SKIPPED', ast_signals: 0, findings: 0, type: 'doc' }
  ]);

  const [selectedFilePath, setSelectedFilePath] = useState('src/flask/config.py');
  const [filterType, setFilterType] = useState('ALL');

  const filteredFiles = files.filter((f) => {
    if (filterType === 'ANALYZED') return f.status === 'ANALYZED';
    if (filterType === 'SKIPPED') return f.status === 'SKIPPED';
    if (filterType === 'FINDINGS') return f.findings > 0;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Repository Technical Header */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                REPOSITORY INTELLIGENCE WORKSPACE
              </LabelCaps>
              <StatusPip status="green" title="Workspace: Acquired & Isolated" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--status-green)' }}>
                {report.acquisition.status}
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              {report.repository.owner}/{report.repository.repository}
            </h1>
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface-variant)' }}>
              <span>BRANCH: <strong>{report.repository.branch}</strong></span>
              <span>ACQUISITION ID: <strong>{report.acquisition.acquisition_id}</strong></span>
              <span>ANALYSIS ID: <strong>{report.analysis_id}</strong></span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="alt_route" onClick={() => navigate('/pr-review')}>
              PR REVIEW
            </SecondaryButton>
            <SecondaryButton icon="search" onClick={() => navigate('/vulnerability-explorer')}>
              VULNERABILITY EXPLORER
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Repository Telemetry Bento Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <MetricCard
          label="TOTAL FILES"
          value={report.summary.total_files}
          delta="DISCOVERED IN REPO"
          accentColor="cyan"
        />
        <MetricCard
          label="ANALYZED FILES"
          value={report.summary.analyzed_files}
          delta="SUPPORTED UTF-8 TEXT"
          accentColor="green"
        />
        <MetricCard
          label="SKIPPED FILES"
          value={report.summary.skipped_files}
          delta="EXCLUDED / UNPOWERED"
          accentColor="dim"
        />
        <MetricCard
          label="TOTAL FINDINGS"
          value={report.summary.total_findings}
          delta={`${report.summary.critical_count} CRITICAL / ${report.summary.high_count} HIGH`}
          accentColor="red"
        />
      </div>

      {/* 3. 5-Stage Repository Analysis Pipeline Visualization */}
      <DataPanel title="REPOSITORY SECURITY ANALYSIS PIPELINE" status="cyan">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
          
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>download</span>
              <LabelCaps style={{ fontSize: '10px' }}>1. ACQUISITION</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              Isolated workspace created
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>find_in_page</span>
              <LabelCaps style={{ fontSize: '10px' }}>2. DISCOVERY</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              176 Python files filtered
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>code</span>
              <LabelCaps style={{ fontSize: '10px' }}>3. AST ENGINE</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              AST signals &amp; imports parsed
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>saved_search</span>
              <LabelCaps style={{ fontSize: '10px' }}>4. RAG GROUNDING</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              ChromaDB retrieval context
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--primary-cyan)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>verified</span>
              <LabelCaps style={{ fontSize: '10px' }}>5. REPORT CONTRACT</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
              Step 6O Findings Formatted
            </span>
          </div>

        </div>
      </DataPanel>

      {/* 4. Repository File Inventory & Findings Overview */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* File Inventory Explorer Table (8 cols) */}
        <div style={{ gridColumn: 'span 8' }}>
          <DataPanel
            title="REPOSITORY FILE INVENTORY & ANALYSIS STATUS"
            status="cyan"
            action={
              <div style={{ display: 'flex', gap: '6px' }}>
                {['ALL', 'ANALYZED', 'SKIPPED', 'FINDINGS'].map((type) => (
                  <button
                    key={type}
                    onClick={() => setFilterType(type)}
                    style={{
                      backgroundColor: filterType === type ? 'var(--primary-cyan)' : 'var(--bg-void-lowest)',
                      color: filterType === type ? 'var(--text-inverse)' : 'var(--text-on-surface-variant)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '3px 8px',
                      cursor: 'pointer'
                    }}
                  >
                    {type}
                  </button>
                ))}
              </div>
            }
          >
            <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
              {/* Header */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 90px 100px 90px 80px',
                gap: '12px',
                padding: '8px 16px',
                backgroundColor: 'var(--bg-void-low)',
                borderBottom: '1px solid var(--border-subtle)',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--text-dim)',
                fontWeight: 700
              }}>
                <div>FILE PATH</div>
                <div>SIZE</div>
                <div>STATUS</div>
                <div>AST SIGNALS</div>
                <div style={{ textAlign: 'right' }}>FINDINGS</div>
              </div>

              {/* File Row Items */}
              {filteredFiles.map((file) => {
                const isSelected = file.path === selectedFilePath;
                return (
                  <div
                    key={file.path}
                    onClick={() => setSelectedFilePath(file.path)}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 90px 100px 90px 80px',
                      gap: '12px',
                      padding: '10px 16px',
                      borderBottom: '1px solid var(--border-subtle)',
                      backgroundColor: isSelected ? 'var(--panel-bg-high)' : 'transparent',
                      borderLeft: isSelected ? '3px solid var(--primary-cyan)' : '3px solid transparent',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      cursor: 'pointer'
                    }}
                  >
                    <div style={{ color: 'var(--text-on-surface)', fontWeight: isSelected ? 600 : 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {file.path}
                    </div>
                    <div style={{ color: 'var(--text-dim)' }}>{file.size}</div>
                    <div>
                      <span style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor: file.status === 'ANALYZED' ? 'rgba(52, 199, 89, 0.1)' : 'rgba(132, 148, 149, 0.1)',
                        color: file.status === 'ANALYZED' ? 'var(--status-green)' : 'var(--text-dim)',
                        border: file.status === 'ANALYZED' ? '1px solid var(--status-green)' : '1px solid var(--border-subtle)'
                      }}>
                        {file.status}
                      </span>
                    </div>
                    <div style={{ color: 'var(--text-on-surface-variant)' }}>{file.ast_signals}</div>
                    <div style={{ textAlign: 'right', fontWeight: 600, color: file.findings > 0 ? 'var(--critical-red)' : 'var(--text-dim)' }}>
                      {file.findings}
                    </div>
                  </div>
                );
              })}
            </div>
          </DataPanel>
        </div>

        {/* Repository Findings Summary Panel (4 cols) */}
        <div style={{ gridColumn: 'span 4' }}>
          <DataPanel title="REPOSITORY FINDINGS SUMMARY" status="amber">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {report.findings.map((finding) => (
                <div
                  key={finding.finding_id}
                  style={{
                    padding: '12px',
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <LabelCaps style={{ fontSize: '10px' }}>{finding.finding_id}</LabelCaps>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text-on-surface)' }}>
                    {finding.title}
                  </div>
                  <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                    {finding.description}
                  </p>
                </div>
              ))}

              <PrimaryButton icon="search" onClick={() => navigate('/vulnerability-explorer')}>
                OPEN VULNERABILITY EXPLORER
              </PrimaryButton>
            </div>
          </DataPanel>
        </div>

      </div>

    </div>
  );
}
