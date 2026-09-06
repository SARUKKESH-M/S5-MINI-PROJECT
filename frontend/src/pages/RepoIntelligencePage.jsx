import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import SeverityBadge from '../components/SeverityBadge';
import ReviewStatusBanner from '../components/ReviewStatusBanner';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';
import {
  getAnalyses,
  getAnalysis,
  getAnalysisFindings
} from '../services/apiClient';

export default function RepoIntelligencePage() {
  const navigate = useNavigate();
  const location = useLocation();

  // Selected analysis and data state
  const [analysesList, setAnalysesList] = useState([]);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [findings, setFindings] = useState([]);

  // Loading & error state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load repository analyses
  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    const loadData = async () => {
      try {
        const res = await getAnalyses({ limit: 25, offset: 0 });
        if (!isMounted) return;

        const list = Array.isArray(res.analyses) ? res.analyses : [];
        setAnalysesList(list);

        if (list.length > 0) {
          const incomingId = location.state?.analysisId;
          const targetId = (incomingId && list.some(a => a.analysis_id === incomingId))
            ? incomingId
            : list[0].analysis_id;

          setSelectedAnalysisId(targetId);

          // Fetch details and findings for target
          const [detailRes, findingsRes] = await Promise.allSettled([
            getAnalysis(targetId),
            getAnalysisFindings(targetId)
          ]);

          if (!isMounted) return;

          if (detailRes.status === 'fulfilled' && detailRes.value?.analysis) {
            setSelectedAnalysis(detailRes.value.analysis);
          } else {
            const fallback = list.find(a => a.analysis_id === targetId);
            setSelectedAnalysis(fallback || null);
          }

          if (findingsRes.status === 'fulfilled' && Array.isArray(findingsRes.value?.findings)) {
            setFindings(findingsRes.value.findings);
          } else {
            setFindings([]);
          }
        } else {
          setSelectedAnalysis(null);
          setFindings([]);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message || 'Failed to load repository intelligence');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadData();

    return () => { isMounted = false; };
  }, [location.state?.analysisId]);

  // Switch selected repository analysis
  const handleSelectAnalysis = async (aid) => {
    if (aid === selectedAnalysisId) return;
    setSelectedAnalysisId(aid);
    setLoading(true);

    try {
      const [detailRes, findingsRes] = await Promise.allSettled([
        getAnalysis(aid),
        getAnalysisFindings(aid)
      ]);

      if (detailRes.status === 'fulfilled' && detailRes.value?.analysis) {
        setSelectedAnalysis(detailRes.value.analysis);
      } else {
        const fallback = analysesList.find(a => a.analysis_id === aid);
        setSelectedAnalysis(fallback || null);
      }

      if (findingsRes.status === 'fulfilled' && Array.isArray(findingsRes.value?.findings)) {
        setFindings(findingsRes.value.findings);
      } else {
        setFindings([]);
      }
    } catch {
      // Handled gracefully
    } finally {
      setLoading(false);
    }
  };

  // Export report JSON handler
  const handleExportJSON = () => {
    if (!selectedAnalysis) return;
    const exportPayload = {
      ...selectedAnalysis,
      findings
    };
    const jsonStr = JSON.stringify(exportPayload, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `codesentinel_${selectedAnalysis.analysis_id || 'repo_report'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Safe metadata extraction
  const summary = selectedAnalysis?.summary || {};
  const totalFiles = summary.total_files ?? summary.analyzed_files ?? 0;
  const analyzedFiles = summary.analyzed_files ?? 0;
  const skippedFiles = summary.skipped_files ?? 0;
  const totalFindings = summary.total_findings ?? findings.length;
  const criticalCount = summary.critical_count ?? findings.filter(f => f.severity === 'critical').length;
  const highCount = summary.high_count ?? findings.filter(f => f.severity === 'high').length;

  const repoMeta = selectedAnalysis?.repository || summary._repository || null;
  const repoName = (repoMeta?.owner && repoMeta?.repository)
    ? `${repoMeta.owner}/${repoMeta.repository}`
    : (selectedAnalysis?.query?.replace('Repository Analysis: ', '') || 'Static Repository Scope');
  const branchName = repoMeta?.branch || 'main';
  const reviewStatus = (selectedAnalysis?.review_status || summary._review_status || (criticalCount > 0 ? 'block' : 'allow')).toLowerCase();

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
              <StatusPip status={reviewStatus === 'block' ? 'red' : 'green'} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--status-green)' }}>
                {selectedAnalysis?.status?.toUpperCase() || 'STANDBY'}
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              {repoName}
            </h1>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface-variant)' }}>
              <span>BRANCH: <strong>{branchName}</strong></span>
              <span>ANALYSIS ID: <strong>{selectedAnalysis?.analysis_id || 'None'}</strong></span>
              {selectedAnalysis?.created_at && (
                <span>AUDITED: <strong>{selectedAnalysis.created_at.substring(0, 19).replace('T', ' ')}Z</strong></span>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <PrimaryButton
              icon="alt_route"
              onClick={() => navigate('/pr-review', { state: { analysisId: selectedAnalysis?.analysis_id } })}
              disabled={!selectedAnalysis}
            >
              PR REVIEW
            </PrimaryButton>
            <SecondaryButton icon="download" onClick={handleExportJSON} disabled={!selectedAnalysis}>
              EXPORT JSON
            </SecondaryButton>
            <SecondaryButton icon="search" onClick={() => navigate('/vulnerability-explorer', { state: { analysisId: selectedAnalysis?.analysis_id } })}>
              EXPLORER
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Repository Selector Bar (if multiple analyses exist) */}
      {analysesList.length > 1 && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          padding: '8px 12px',
          backgroundColor: 'var(--panel-bg)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-xs)'
        }}>
          <LabelCaps style={{ fontSize: '10px', color: 'var(--text-dim)', flexShrink: 0 }}>
            AUDITED REPOSITORIES:
          </LabelCaps>
          {analysesList.map((a) => {
            const isSelected = a.analysis_id === selectedAnalysisId;
            const rInfo = a.summary?._repository;
            const label = (rInfo?.owner && rInfo?.repository)
              ? `${rInfo.owner}/${rInfo.repository}`
              : (a.query?.replace('Repository Analysis: ', '') || a.analysis_id);
            return (
              <button
                key={a.analysis_id}
                type="button"
                onClick={() => handleSelectAnalysis(a.analysis_id)}
                style={{
                  backgroundColor: isSelected ? 'var(--panel-bg-high)' : 'var(--bg-void-lowest)',
                  border: isSelected ? '1px solid var(--primary-cyan)' : '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '4px 10px',
                  color: isSelected ? 'var(--primary-cyan)' : 'var(--text-on-surface-variant)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: isSelected ? 700 : 400,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                  flexShrink: 0
                }}
              >
                {label} ({a.analysis_id})
              </button>
            );
          })}
        </div>
      )}

      {/* 3. Review Status Banner (Authoritative Gate Decision) */}
      <ReviewStatusBanner
        reviewStatus={reviewStatus}
        title={
          reviewStatus === 'block'
            ? 'SECURITY GATE VERDICT: BLOCKED (BLOCK)'
            : reviewStatus === 'review'
            ? 'SECURITY GATE VERDICT: REVIEW NEEDED (REVIEW)'
            : 'SECURITY GATE VERDICT: PASSED (ALLOW)'
        }
        details={
          reviewStatus === 'block'
            ? `Remediation required: ${criticalCount} Critical & ${highCount} High finding(s) require remediation before deployment`
            : `All ${analyzedFiles} analyzed source files satisfy production security policies`
        }
      />

      {/* 4. Repository Telemetry Bento Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <MetricCard
          label="TOTAL FILES"
          value={totalFiles}
          delta="DISCOVERED IN WORKSPACE"
          accentColor="cyan"
        />
        <MetricCard
          label="ANALYZED FILES"
          value={analyzedFiles}
          delta="STATIC AST PARSED"
          accentColor="green"
        />
        <MetricCard
          label="SKIPPED FILES"
          value={skippedFiles}
          delta="EXCLUDED EXTENSIONS"
          accentColor="dim"
        />
        <MetricCard
          label="TOTAL FINDINGS"
          value={totalFindings}
          delta={`${criticalCount} CRITICAL / ${highCount} HIGH`}
          accentColor={criticalCount > 0 ? "critical" : highCount > 0 ? "amber" : "green"}
        />
      </div>

      {/* 5. 5-Stage Repository Analysis Pipeline Visualization */}
      <DataPanel title="REPOSITORY SECURITY ANALYSIS PIPELINE FLOW" status="cyan">
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
              {analyzedFiles} files filtered
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>code</span>
              <LabelCaps style={{ fontSize: '10px' }}>3. AST ENGINE</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              AST signals parsed
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>saved_search</span>
              <LabelCaps style={{ fontSize: '10px' }}>4. RAG GROUNDING</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              Knowledge base retrieval
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

      {/* 6. Findings Overview & Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Findings List (8 cols) */}
        <div style={{ gridColumn: 'span 8' }}>
          <DataPanel title={`REPOSITORY FINDINGS (${findings.length})`} status={criticalCount > 0 ? 'red' : 'green'}>
            {loading ? (
              <div style={{ padding: '24px', textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)' }}>
                Loading repository intelligence...
              </div>
            ) : findings.length === 0 ? (
              <div style={{
                padding: '32px',
                textAlign: 'center',
                backgroundColor: 'var(--bg-void-lowest)',
                border: '1px dashed var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: 'var(--text-dim)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '8px'
              }}>
                <span className="material-symbols-outlined" style={{ fontSize: '32px', color: 'var(--status-green)' }}>
                  verified_user
                </span>
                <strong style={{ color: 'var(--text-on-surface)' }}>NO VULNERABILITIES IDENTIFIED</strong>
                <span>All static security controls passed for this repository audit.</span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {findings.map((f, idx) => (
                  <div
                    key={f.finding_id || idx}
                    style={{
                      padding: '12px 16px',
                      backgroundColor: 'var(--bg-void-lowest)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <LabelCaps style={{ fontSize: '10px' }}>{f.finding_id}</LabelCaps>
                        <strong style={{ fontSize: '13px', color: 'var(--text-on-surface)' }}>{f.title}</strong>
                      </div>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                      {f.description}
                    </p>
                    {f.evidence?.[0] && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--primary-cyan)', marginTop: '2px' }}>
                        LOCATION: {f.evidence[0].document_id}:{f.evidence[0].line_start} ({f.evidence[0].signal_name || f.evidence[0].signal_type})
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </DataPanel>
        </div>

        {/* Action Panel (4 cols) */}
        <div style={{ gridColumn: 'span 4', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <DataPanel title="SECURITY ACTION &amp; WORKFLOWS" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.5 }}>
                Open this repository analysis in the PR Review workspace to inspect grounded AST evidence and code signals line-by-line.
              </p>
              <PrimaryButton
                icon="alt_route"
                onClick={() => navigate('/pr-review', { state: { analysisId: selectedAnalysis?.analysis_id } })}
                disabled={!selectedAnalysis}
              >
                OPEN PR REVIEW WORKSPACE
              </PrimaryButton>
              <SecondaryButton
                icon="input"
                onClick={() => navigate('/')}
              >
                INTAKE ANOTHER REPOSITORY
              </SecondaryButton>
              <SecondaryButton
                icon="dashboard"
                onClick={() => navigate('/command-center')}
              >
                COMMAND CENTER DASHBOARD
              </SecondaryButton>
            </div>
          </DataPanel>
        </div>

      </div>

    </div>
  );
}
