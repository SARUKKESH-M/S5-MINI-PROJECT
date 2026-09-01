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

export default function CommandCenterPage() {
  const navigate = useNavigate();

  // Local presentation data structurally aligned with Step 6O Report Contract
  const [report] = useState({
    status: 'success',
    review_status: 'block',
    analysis_id: 'repo_ana_command_center_demo',
    repository: {
      owner: 'pallets',
      repository: 'flask',
      branch: 'main',
      path: './'
    },
    summary: {
      total_files: 42,
      analyzed_files: 38,
      skipped_files: 4,
      total_findings: 87,
      critical_count: 3,
      high_count: 14,
      medium_count: 42,
      low_count: 28,
      info_count: 0
    },
    analysis_version: '1.0'
  });

  // Presentation live event stream
  const eventStream = [
    { id: 1, time: '14:02:45.102Z', target: 'frontend-ui/PR#442', context: 'Analyzed 4 files for XSS vectors in React components.', verdict: 'CLEAN', severity: 'low' },
    { id: 2, time: '14:02:42.881Z', target: 'auth-service/PR#109', context: 'Detected Hardcoded JWT Secret in src/config.ts', verdict: 'FLAGGED', severity: 'critical' },
    { id: 3, time: '14:02:40.005Z', target: 'payment-api/PR#88', context: 'SQL Injection scan across 12 endpoints. No risks found.', verdict: 'CLEAN', severity: 'low' },
    { id: 4, time: '14:02:35.122Z', target: 'data-pipeline/PR#902', context: 'Dependency check passed. Pandas updated to 2.1.0', verdict: 'CLEAN', severity: 'info' }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      {/* 1. System Health Status Bar (Top Full Width Row) */}
      <DataPanel status="cyan" style={{ padding: '12px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <StatusPip status="cyan" />
            <LabelCaps style={{ fontSize: '11px', color: 'var(--text-on-surface)' }}>
              SYSTEM HEALTH STATUS
            </LabelCaps>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '24px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
            <div>
              <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>FASTAPI</span>
              <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>ONLINE</span>
            </div>
            <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '24px' }}>
              <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>REDIS</span>
              <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>99.9%</span>
            </div>
            <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '24px' }}>
              <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>CELERY</span>
              <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>IDLE_0</span>
            </div>
            <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '24px' }}>
              <span style={{ color: 'var(--text-dim)', marginRight: '6px' }}>MODELS</span>
              <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>READY</span>
            </div>
          </div>
        </div>
      </DataPanel>

      {/* 2. Main Dashboard Content Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Left Column: Global Risk Orbit (8 cols) */}
        <div style={{ gridColumn: 'span 8', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <DataPanel
            title="GLOBAL RISK ORBIT"
            status="cyan"
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
                <span>LATENCY: 12ms</span>
                <StatusPip status="cyan" />
              </div>
            }
            style={{ height: '340px', position: 'relative' }}
          >
            {/* Concentric Orbit Visual Radar Container */}
            <div style={{
              flex: 1,
              position: 'relative',
              backgroundColor: 'var(--bg-void-lowest)',
              borderRadius: 'var(--radius-xs)',
              overflow: 'hidden',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '1px solid var(--border-subtle)'
            }}>
              {/* Concentric Orbit Rings */}
              <div style={{ position: 'absolute', width: '220px', height: '220px', border: '1px solid var(--border-default)', borderRadius: '50%', opacity: 0.3 }} />
              <div style={{ position: 'absolute', width: '340px', height: '340px', border: '1px solid var(--border-default)', borderRadius: '50%', opacity: 0.2 }} />
              <div style={{ position: 'absolute', width: '460px', height: '460px', border: '1px solid var(--border-default)', borderRadius: '50%', opacity: 0.1 }} />

              {/* Center Hub Node */}
              <div style={{
                position: 'relative',
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                border: '1px solid var(--primary-cyan)',
                backgroundColor: 'var(--panel-bg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--primary-cyan)',
                zIndex: 2,
                boxShadow: '0 0 16px rgba(0, 240, 255, 0.2)'
              }}>
                <span className="material-symbols-outlined" style={{ fontSize: '28px' }}>hub</span>
              </div>

              {/* Orbital Risk Nodes */}
              {/* Node 1: Critical Auth Risk */}
              <div style={{ position: 'absolute', top: '22%', left: '28%', display: 'flex', alignItems: 'center', gap: '6px', zIndex: 3 }}>
                <span className="status-pip status-pip-red" style={{ width: '10px', height: '10px' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--critical-red)', backgroundColor: 'var(--panel-bg-high)', padding: '2px 6px', border: '1px solid var(--critical-red)', borderRadius: 'var(--radius-xs)' }}>
                  auth-service (CRITICAL_CVE)
                </span>
              </div>

              {/* Node 2: Medium Payment Risk */}
              <div style={{ position: 'absolute', top: '65%', left: '68%', display: 'flex', alignItems: 'center', gap: '6px', zIndex: 3 }}>
                <span className="status-pip status-pip-amber" style={{ width: '8px', height: '8px' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--secondary-amber)', backgroundColor: 'var(--panel-bg-high)', padding: '2px 6px', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                  payment-api (HIGH_RISK)
                </span>
              </div>

              {/* Node 3: Low Frontend Risk */}
              <div style={{ position: 'absolute', top: '35%', left: '78%', display: 'flex', alignItems: 'center', gap: '6px', zIndex: 3 }}>
                <span className="status-pip status-pip-green" style={{ width: '6px', height: '6px' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-on-surface-variant)' }}>
                  frontend-ui (CLEAN)
                </span>
              </div>

              {/* Monitored Repos Overlay Badge */}
              <div style={{
                position: 'absolute',
                bottom: '12px',
                left: '12px',
                backgroundColor: 'rgba(35, 43, 44, 0.9)',
                border: '1px solid var(--border-default)',
                padding: '6px 12px',
                borderRadius: 'var(--radius-xs)',
                display: 'flex',
                flexDirection: 'column',
                gap: '2px',
                zIndex: 2
              }}>
                <LabelCaps style={{ fontSize: '9px' }}>MONITORED REPOS</LabelCaps>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
                  1,204
                </span>
              </div>
            </div>
          </DataPanel>
        </div>

        {/* Right Column: Telemetry & Vulnerability Distribution (4 cols) */}
        <div style={{ gridColumn: 'span 4', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Critical Telemetry Panel */}
          <DataPanel title="CRITICAL TELEMETRY" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', paddingBottom: '10px', borderBottom: '1px solid var(--border-subtle)' }}>
                <div>
                  <LabelCaps style={{ fontSize: '10px' }}>GLOBAL RISK SCORE</LabelCaps>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px', marginTop: '2px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '32px', fontWeight: 700, color: 'var(--primary-cyan)' }}>
                      24
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)' }}>
                      / 100
                    </span>
                  </div>
                </div>
                <div style={{
                  backgroundColor: 'rgba(0, 240, 255, 0.1)',
                  border: '1px solid var(--primary-cyan)',
                  color: 'var(--primary-cyan)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-xs)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>trending_down</span>
                  -2.4%
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--text-dim)' }}>AI Throughput</span>
                <span style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>845 PRs/hr</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--text-dim)' }}>Avg Review Latency</span>
                <span style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>1.2s</span>
              </div>
            </div>
          </DataPanel>

          {/* Active Vulnerabilities Severity Breakdown Panel */}
          <DataPanel title="ACTIVE VULNERABILITIES" status="amber">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {/* Critical */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="critical" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: '15%', height: '100%', backgroundColor: 'var(--critical-red)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {report.summary.critical_count}
                </span>
              </div>

              {/* High */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="high" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: '45%', height: '100%', backgroundColor: 'var(--secondary-amber)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {report.summary.high_count}
                </span>
              </div>

              {/* Medium */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="medium" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: '80%', height: '100%', backgroundColor: 'var(--primary-cyan)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {report.summary.medium_count}
                </span>
              </div>

              {/* Low */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '70px' }}>
                  <SeverityBadge severity="low" />
                </div>
                <div style={{ flex: 1, height: '6px', backgroundColor: 'var(--panel-bg-high)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                  <div style={{ width: '60%', height: '100%', backgroundColor: 'var(--text-on-surface-variant)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, width: '24px', textAlign: 'right' }}>
                  {report.summary.low_count}
                </span>
              </div>
            </div>
          </DataPanel>

        </div>
      </div>

      {/* 3. Review Contract Banner for Current Analysis */}
      <ReviewStatusBanner
        reviewStatus={report.review_status}
        title="PULL REQUEST REVIEW VERDICT: BLOCKED (BLOCK)"
        details={`Repository: ${report.repository.owner}/${report.repository.repository} (${report.repository.branch}) — ${report.summary.critical_count} Critical findings policy violation`}
      />

      {/* 4. Live Event Stream (AI Verdicts) Table Panel */}
      <DataPanel
        title="LIVE EVENT STREAM (AI VERDICTS)"
        status="cyan"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary-cyan)' }}>
            <StatusPip status="cyan" />
            <span>LISTENING FOR PR WEBHOOKS</span>
          </div>
        }
      >
        <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
          {/* Table Header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '150px 180px 1fr 140px 80px',
            gap: '12px',
            padding: '8px 16px',
            backgroundColor: 'var(--bg-void-low)',
            borderBottom: '1px solid var(--border-subtle)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: 'var(--text-dim)',
            fontWeight: 700
          }}>
            <div>TIMESTAMP</div>
            <div>TARGET REPO</div>
            <div>ANALYSIS CONTEXT</div>
            <div>VERDICT</div>
            <div style={{ textAlign: 'right' }}>ACTION</div>
          </div>

          {/* Table Event Rows */}
          {eventStream.map((evt) => (
            <div
              key={evt.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '150px 180px 1fr 140px 80px',
                gap: '12px',
                padding: '12px 16px',
                borderBottom: '1px solid var(--border-subtle)',
                backgroundColor: evt.verdict === 'FLAGGED' ? 'rgba(255, 59, 48, 0.05)' : 'transparent',
                borderLeft: evt.verdict === 'FLAGGED' ? '3px solid var(--critical-red)' : '3px solid transparent',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                alignItems: 'center'
              }}
            >
              <div style={{ color: 'var(--text-dim)' }}>{evt.time}</div>
              <div style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>{evt.target}</div>
              <div style={{ color: 'var(--text-on-surface-variant)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {evt.context}
              </div>
              <div>
                {evt.verdict === 'FLAGGED' ? (
                  <SeverityBadge severity="critical" />
                ) : (
                  <span style={{
                    backgroundColor: 'rgba(52, 199, 89, 0.1)',
                    color: 'var(--status-green)',
                    border: '1px solid var(--status-green)',
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: 'var(--radius-xs)'
                  }}>
                    CLEAN (ALLOW)
                  </span>
                )}
              </div>
              <div style={{ textAlign: 'right' }}>
                <SecondaryButton
                  icon={evt.verdict === 'FLAGGED' ? 'gavel' : 'visibility'}
                  onClick={() => navigate('/pr-review')}
                  style={{ padding: '4px 8px', fontSize: '11px' }}
                >
                  VIEW
                </SecondaryButton>
              </div>
            </div>
          ))}
        </div>
      </DataPanel>
    </div>
  );
}
