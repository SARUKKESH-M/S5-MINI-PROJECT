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
import CodeViewer from '../components/CodeViewer';
import EvidenceSnippet from '../components/EvidenceSnippet';
import {
  getAnalyses,
  getAnalysis,
  getAnalysisFindings
} from '../services/apiClient';

export default function PRReviewPage() {
  const navigate = useNavigate();
  const location = useLocation();

  // 1. History state (from GET /analyses)
  const [analyses, setAnalyses] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState(null);
  const [totalCount, setTotalCount] = useState(0);

  // 2. Selected analysis state (from GET /analyses/{id})
  const [selectedAnalysisId, setSelectedAnalysisId] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);

  // 3. Findings state (from GET /analyses/{id}/findings)
  const [findings, setFindings] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState(null);
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  // Fetch analysis history list
  const loadAnalysesHistory = async (autoSelectId = null) => {
    setHistoryLoading(true);
    setHistoryError(null);

    try {
      const res = await getAnalyses({ limit: 30, offset: 0 });
      const list = Array.isArray(res.analyses) ? res.analyses : [];
      setAnalyses(list);
      setTotalCount(res.total_count ?? list.length);

      if (list.length > 0) {
        const incomingId = location.state?.analysisId;
        const targetId = autoSelectId || (incomingId && list.some(a => a.analysis_id === incomingId) ? incomingId : (selectedAnalysisId && list.some(a => a.analysis_id === selectedAnalysisId) ? selectedAnalysisId : list[0].analysis_id));
        setSelectedAnalysisId(targetId);
      } else {
        setSelectedAnalysisId(null);
        setSelectedAnalysis(null);
        setFindings([]);
      }
    } catch (err) {
      setHistoryError(err.message || 'Failed to load analysis history');
      setAnalyses([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    loadAnalysesHistory();
  }, []);

  // Fetch selected analysis details and findings when selectedAnalysisId changes
  useEffect(() => {
    if (!selectedAnalysisId) return;

    let isMounted = true;
    setAnalysisLoading(true);
    setFindingsLoading(true);
    setAnalysisError(null);
    setFindingsError(null);

    const fetchAnalysisData = async () => {
      try {
        let analysisObj = null;
        let rawFindings = null;

        try {
          const analysisRes = await getAnalysis(selectedAnalysisId);
          if (analysisRes?.analysis) {
            analysisObj = analysisRes.analysis;
            if (Array.isArray(analysisRes.analysis.findings)) {
              rawFindings = analysisRes.analysis.findings;
            }
          }
        } catch (err) {
          // Graceful fallback to the item in the list if single-fetch fails
          const fallback = analyses.find(a => a.analysis_id === selectedAnalysisId);
          if (fallback) {
            analysisObj = fallback;
            if (Array.isArray(fallback.findings)) {
              rawFindings = fallback.findings;
            }
          } else {
            setAnalysisError(err?.message || 'Failed to load analysis details');
          }
        }

        if (!isMounted) return;

        if (analysisObj) {
          setSelectedAnalysis(analysisObj);
        }

        // If findings were not embedded in the analysis record, fallback to dedicated findings endpoint
        if (rawFindings === null) {
          try {
            const findingsRes = await getAnalysisFindings(selectedAnalysisId);
            rawFindings = Array.isArray(findingsRes?.findings) ? findingsRes.findings : [];
          } catch (fErr) {
            setFindingsError(fErr?.message || 'Findings unavailable');
            rawFindings = [];
          }
        }

        if (!isMounted) return;

        setFindings(rawFindings);
        if (rawFindings.length > 0) {
          setSelectedFindingId(rawFindings[0].finding_id);
        } else {
          setSelectedFindingId(null);
        }
      } catch (err) {
        if (isMounted) {
          setAnalysisError(err.message || 'Error fetching analysis');
        }
      } finally {
        if (isMounted) {
          setAnalysisLoading(false);
          setFindingsLoading(false);
        }
      }
    };

    fetchAnalysisData();

    return () => {
      isMounted = false;
    };
  }, [selectedAnalysisId]);

  // Export report JSON handler (pure client-side blob download, zero server-side mutations)
  const handleExportJSON = () => {
    if (!selectedAnalysis) return;
    const exportData = {
      ...selectedAnalysis,
      findings: findings.length > 0 ? findings : (selectedAnalysis.findings || [])
    };
    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `codesentinel_${selectedAnalysis.analysis_id || 'analysis'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Derive active finding
  const activeFinding = findings.find((f) => f.finding_id === selectedFindingId) || findings[0] || null;
  const activeEvidence = activeFinding?.evidence?.[0] || null;

  // Metadata summary
  const summary = selectedAnalysis?.summary || {};
  const criticalCount = summary.critical_count ?? findings.filter(f => f.severity === 'critical').length;
  const highCount = summary.high_count ?? findings.filter(f => f.severity === 'high').length;
  const totalFindings = summary.total_findings ?? findings.length;
  const analyzedFiles = summary.analyzed_files ?? 0;
  const totalFiles = summary.total_files ?? analyzedFiles;

  // Backend gate review status
  const reviewStatus = (selectedAnalysis?.review_status || summary._review_status || (criticalCount > 0 ? 'block' : highCount > 0 ? 'review' : 'allow')).toLowerCase();
  
  // Repository metadata (safe backend properties)
  const repoMeta = selectedAnalysis?.repository || summary._repository || null;
  const repoString = (repoMeta?.owner && repoMeta?.repository)
    ? `${repoMeta.owner}/${repoMeta.repository}`
    : (selectedAnalysis?.query?.replace('Repository Analysis: ', '') || 'Static Code Target');
  const branchString = repoMeta?.branch || 'main';

  // Dynamic security rules evaluation
  const securityRules = [
    {
      name: 'AST Structural Analysis',
      status: analyzedFiles > 0 ? 'pass' : 'dim',
      detail: analyzedFiles > 0 ? `${analyzedFiles} source files parsed & analyzed` : 'Zero source files analyzed'
    },
    {
      name: 'Critical Security Controls',
      status: criticalCount > 0 ? 'fail' : 'pass',
      detail: criticalCount > 0 ? `${criticalCount} Critical severity finding(s) detected` : 'Zero Critical severity issues identified'
    },
    {
      name: 'High Severity Violations',
      status: highCount > 0 ? 'warn' : 'pass',
      detail: highCount > 0 ? `${highCount} High severity finding(s) require review` : 'Zero High severity violations identified'
    },
    {
      name: 'Knowledge Retrieval Grounding',
      status: findings.length > 0 ? 'pass' : 'pass',
      detail: `${findings.length} findings verified against security knowledge base`
    },
    {
      name: 'LLM Security Gate Engine',
      status: reviewStatus === 'block' ? 'block' : reviewStatus === 'review' ? 'warn' : 'pass',
      detail: `Backend verdict: ${reviewStatus.toUpperCase()} (Authoritative decision)`
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Analysis History Selector Panel (Step 6 & 7) */}
      <DataPanel
        title="AUDITED ANALYSIS HISTORY &amp; REVIEW SELECTION"
        status="cyan"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
              {totalCount} AUDITS RECORDED
            </span>
            <SecondaryButton
              icon="autorenew"
              onClick={() => loadAnalysesHistory()}
              disabled={historyLoading}
              style={{ padding: '3px 8px', fontSize: '11px' }}
            >
              REFRESH
            </SecondaryButton>
          </div>
        }
      >
        {historyLoading && analyses.length === 0 ? (
          <div style={{
            padding: '24px',
            textAlign: 'center',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-dim)'
          }}>
            <span className="material-symbols-outlined rotating" style={{ verticalAlign: 'middle', marginRight: '8px', color: 'var(--primary-cyan)' }}>
              autorenew
            </span>
            Loading analysis history...
          </div>
        ) : historyError ? (
          <div style={{
            padding: '16px',
            backgroundColor: 'rgba(254, 183, 0, 0.08)',
            border: '1px solid var(--secondary-amber)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--secondary-amber)'
          }}>
            History unavailable: {historyError}
          </div>
        ) : analyses.length === 0 ? (
          <div style={{
            padding: '28px',
            textAlign: 'center',
            backgroundColor: 'var(--bg-void-lowest)',
            border: '1px dashed var(--border-subtle)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-dim)'
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: '28px', color: 'var(--primary-cyan)', display: 'block', marginBottom: '6px' }}>
              history
            </span>
            NO ANALYSES RECORDED YET
            <p style={{ margin: '4px 0 0 0', fontSize: '11px' }}>
              Execute an analysis via the Command Center or CLI to populate review history.
            </p>
          </div>
        ) : (
          <div style={{
            display: 'flex',
            gap: '10px',
            overflowX: 'auto',
            paddingBottom: '6px',
            paddingTop: '2px'
          }}>
            {analyses.map((a) => {
              const isSelected = a.analysis_id === selectedAnalysisId;
              const rStatus = (a.summary?._review_status || (a.finding_count > 0 ? 'block' : 'allow')).toLowerCase();
              const isBlock = rStatus === 'block';
              const isReview = rStatus === 'review';
              const pipStatus = isBlock ? 'red' : isReview ? 'amber' : 'green';
              const aRepo = a.summary?._repository;
              const aTarget = (aRepo?.owner && aRepo?.repository)
                ? `${aRepo.owner}/${aRepo.repository}`
                : (a.query?.replace('Repository Analysis: ', '') || a.analysis_id);
              const timeFormatted = a.created_at
                ? (a.created_at.includes('T') ? a.created_at.substring(11, 19) + 'Z' : a.created_at)
                : '';

              return (
                <div
                  key={a.analysis_id}
                  onClick={() => setSelectedAnalysisId(a.analysis_id)}
                  style={{
                    minWidth: '240px',
                    maxWidth: '280px',
                    padding: '10px 12px',
                    backgroundColor: isSelected ? 'var(--panel-bg-high)' : 'var(--bg-void-lowest)',
                    border: isSelected ? '1px solid var(--primary-cyan)' : '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                    flexShrink: 0,
                    transition: 'all 0.15s ease-in-out'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <StatusPip status={pipStatus} />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, color: isSelected ? 'var(--primary-cyan)' : 'var(--text-on-surface)' }}>
                        {a.analysis_id}
                      </span>
                    </div>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '9px',
                      fontWeight: 700,
                      padding: '1px 5px',
                      borderRadius: 'var(--radius-xs)',
                      backgroundColor: isBlock ? 'rgba(255, 59, 48, 0.1)' : isReview ? 'rgba(254, 183, 0, 0.1)' : 'rgba(52, 199, 89, 0.1)',
                      color: isBlock ? 'var(--critical-red)' : isReview ? 'var(--secondary-amber)' : 'var(--status-green)',
                      border: `1px solid ${isBlock ? 'var(--critical-red)' : isReview ? 'var(--secondary-amber)' : 'var(--status-green)'}`
                    }}>
                      {rStatus.toUpperCase()}
                    </span>
                  </div>

                  <div style={{
                    fontFamily: 'var(--font-ui)',
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--text-on-surface)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis'
                  }}>
                    {aTarget}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
                    <span>{a.finding_count || 0} findings</span>
                    <span>{timeFormatted}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </DataPanel>

      {/* 2. Selected Analysis Header & Technical Review Context (Step 8 & 9) */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                AUDITED ANALYSIS WORKSPACE
              </LabelCaps>
              <StatusPip status={reviewStatus === 'allow' ? 'green' : reviewStatus === 'review' ? 'amber' : 'red'} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
                {selectedAnalysis?.analysis_id || 'SELECT AN ANALYSIS'}
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              {selectedAnalysis?.query || 'Security Analysis Audit Report'}
            </h1>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface-variant)' }}>
              <span>TARGET: <strong>{repoString}</strong></span>
              <span>BRANCH: <strong>{branchString}</strong></span>
              {selectedAnalysis?.created_at && (
                <span>AUDITED: <strong>{selectedAnalysis.created_at.substring(0, 19).replace('T', ' ')}Z</strong></span>
              )}
              {selectedAnalysis?.provider && (
                <span>ENGINE: <strong>{selectedAnalysis.provider.toUpperCase()}</strong></span>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="dashboard" onClick={() => navigate('/command-center')}>
              COMMAND CENTER
            </SecondaryButton>
            <SecondaryButton icon="folder_managed" onClick={() => navigate('/repo-intelligence')}>
              REPO INTELLIGENCE
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 3. Step 6O Review Contract Decision Banner (Backend Authoritative) */}
      <ReviewStatusBanner
        reviewStatus={reviewStatus}
        title={
          reviewStatus === 'block'
            ? 'AUTOMATED GATE DECISION: BLOCKED (BLOCK)'
            : reviewStatus === 'review'
            ? 'AUTOMATED GATE DECISION: REVIEW NEEDED (REVIEW)'
            : 'AUTOMATED GATE DECISION: PASSED (ALLOW)'
        }
        details={
          reviewStatus === 'block'
            ? `Policy Block Triggered: ${criticalCount} Critical & ${highCount} High finding(s) require remediation before merge`
            : reviewStatus === 'review'
            ? `Manual Review Required: ${highCount} High finding(s) detected across ${analyzedFiles} analyzed file(s)`
            : `All ${analyzedFiles} analyzed source file(s) pass automated security gate policies`
        }
      />

      {/* 4. Security Rule Policy Summary & Audit Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Security Rule Checklist Panel (7 cols) */}
        <div style={{ gridColumn: 'span 7' }}>
          <DataPanel title="SECURITY POLICY RULES EVALUATION" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {securityRules.map((rule, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <StatusPip
                      status={rule.status === 'pass' ? 'green' : rule.status === 'fail' || rule.status === 'block' ? 'red' : rule.status === 'warn' ? 'amber' : 'dim'}
                    />
                    <span style={{ fontWeight: 600, color: 'var(--text-on-surface)' }}>{rule.name}</span>
                  </div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}>{rule.detail}</span>
                </div>
              ))}
            </div>
          </DataPanel>
        </div>

        {/* Quick Review Summary Bento (5 cols) */}
        <div style={{ gridColumn: 'span 5', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <MetricCard
            label="CRITICAL FINDINGS"
            value={criticalCount}
            delta={criticalCount > 0 ? "BLOCKS MERGE" : "CLEAN"}
            accentColor={criticalCount > 0 ? "critical" : "green"}
          />
          <MetricCard
            label="HIGH FINDINGS"
            value={highCount}
            delta={highCount > 0 ? "REQUIRES REVIEW" : "CLEAN"}
            accentColor={highCount > 0 ? "amber" : "green"}
          />
          <MetricCard
            label="ANALYZED FILES"
            value={`${analyzedFiles} / ${totalFiles}`}
            delta="PARSED & AUDITED"
            accentColor="cyan"
          />
          <MetricCard
            label="GROUNDED FINDINGS"
            value={totalFindings}
            delta={findings.length > 0 ? "ACTIVE EVIDENCE" : "NO ISSUES"}
            accentColor={findings.length > 0 ? "dim" : "green"}
          />
        </div>
      </div>

      {/* 5. Findings & Grounded Evidence Dual Workspace (Steps 10, 11, 12) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Left Findings List Panel (5 cols) */}
        <div style={{ gridColumn: 'span 5' }}>
          <DataPanel
            title={`SECURITY FINDINGS (${findings.length})`}
            status={criticalCount > 0 ? 'red' : highCount > 0 ? 'amber' : 'green'}
          >
            {findingsLoading ? (
              <div style={{
                padding: '24px',
                textAlign: 'center',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: 'var(--text-dim)'
              }}>
                <span className="material-symbols-outlined rotating" style={{ verticalAlign: 'middle', marginRight: '8px', color: 'var(--primary-cyan)' }}>
                  autorenew
                </span>
                Loading findings...
              </div>
            ) : findingsError ? (
              <div style={{
                padding: '16px',
                backgroundColor: 'rgba(254, 183, 0, 0.08)',
                border: '1px solid var(--secondary-amber)',
                borderRadius: 'var(--radius-xs)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: 'var(--secondary-amber)'
              }}>
                Findings error: {findingsError}
              </div>
            ) : findings.length === 0 ? (
              <div style={{
                padding: '32px 16px',
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
                <span style={{ fontWeight: 700, color: 'var(--text-on-surface)' }}>
                  NO FINDINGS RECORDED FOR THIS ANALYSIS
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                  All security controls and static analysis checks passed cleanly.
                </span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {findings.map((f, idx) => {
                  const isSelected = f.finding_id === selectedFindingId;
                  const firstEv = f.evidence?.[0];
                  return (
                    <div
                      key={f.finding_id || idx}
                      onClick={() => setSelectedFindingId(f.finding_id)}
                      style={{
                        padding: '12px',
                        backgroundColor: isSelected ? 'var(--panel-bg-high)' : 'var(--bg-void-lowest)',
                        border: isSelected ? '1px solid var(--primary-cyan)' : '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-xs)',
                        cursor: 'pointer',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                        transition: 'all 0.15s ease-in-out'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <LabelCaps style={{ fontSize: '10px' }}>{f.finding_id || `FINDING_${idx + 1}`}</LabelCaps>
                        <SeverityBadge severity={f.severity || 'info'} />
                      </div>
                      <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-on-surface)' }}>
                        {f.title || 'Untitled Security Risk'}
                      </div>
                      <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                        {f.description || 'No description provided.'}
                      </p>
                      {firstEv?.document_id && (
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--primary-cyan)', marginTop: '2px', wordBreak: 'break-all' }}>
                          LOCATION: {firstEv.document_id}{firstEv.line_start ? `:L${firstEv.line_start}` : ''}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </DataPanel>
        </div>

        {/* Right Grounded Evidence & Code Viewer Panel (7 cols) */}
        <div style={{ gridColumn: 'span 7' }}>
          <DataPanel
            title={`GROUNDED EVIDENCE INSPECTOR — ${activeFinding?.finding_id || 'NO FINDING'}`}
            status={activeFinding?.severity === 'critical' ? 'red' : activeFinding?.severity === 'high' ? 'amber' : 'cyan'}
            action={<SeverityBadge severity={activeFinding?.severity || 'info'} />}
          >
            {activeFinding ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {/* Evidence Metadata Snippet */}
                {activeEvidence ? (
                  <EvidenceSnippet
                    documentId={activeEvidence.document_id}
                    lineStart={activeEvidence.line_start}
                    lineEnd={activeEvidence.line_end}
                    signalType={activeEvidence.signal_type}
                    signalName={activeEvidence.signal_name}
                    analysisId={selectedAnalysisId}
                    findingId={activeFinding?.finding_id}
                    repositoryId={selectedAnalysis?.repository?.repository || selectedAnalysis?.repository?.repo_name}
                    isFalsePositive={activeFinding?.is_false_positive}
                    feedback={activeFinding?.feedback}
                    onFeedbackChange={({ findingId, suppressed }) => {
                      setFindings(prev => prev.map(f => f.finding_id === findingId ? { ...f, is_false_positive: suppressed } : f));
                    }}
                  />
                ) : (
                  <div style={{
                    padding: '12px',
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-xs)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    color: 'var(--text-dim)'
                  }}>
                    No AST evidence signals attached to this finding.
                  </div>
                )}

                {/* Code Snippet Viewer */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <LabelCaps style={{ fontSize: '10px' }}>STATIC SOURCE CODE EVIDENCE</LabelCaps>
                    {activeEvidence?.line_start && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
                        Target Line: {activeEvidence.line_start}
                      </span>
                    )}
                  </div>

                  {activeEvidence?.lines && activeEvidence.lines.length > 0 ? (
                    <CodeViewer
                      lines={activeEvidence.lines}
                      startLine={(activeEvidence.line_start || 1) - 1}
                      highlightRange={{
                        start: activeEvidence.line_start || 1,
                        end: activeEvidence.line_end || activeEvidence.line_start || 1
                      }}
                    />
                  ) : (
                    <div style={{
                      padding: '16px',
                      backgroundColor: 'var(--bg-void-lowest)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      color: 'var(--text-dim)',
                      lineHeight: 1.6
                    }}>
                      <div style={{ color: 'var(--primary-cyan)', marginBottom: '4px' }}>
                        # Source code snippet not embedded in backend report payload
                      </div>
                      <div># Document ID: {activeEvidence?.document_id || 'N/A'}</div>
                      <div># Signal Type: {activeEvidence?.signal_type || 'N/A'}</div>
                      <div># Signal Name: {activeEvidence?.signal_name || 'N/A'}</div>
                      <div># Target Location: Line {activeEvidence?.line_start || 'N/A'}</div>
                      <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
                        Inspect the original file in the repository workspace or run local AST parser for full file context.
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{
                padding: '32px',
                textAlign: 'center',
                backgroundColor: 'var(--bg-void-lowest)',
                border: '1px dashed var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: 'var(--text-dim)'
              }}>
                Select a finding from the left panel to inspect grounded evidence signals.
              </div>
            )}
          </DataPanel>
        </div>
      </div>

      {/* 6. Remediation & Report Export Footer Panel */}
      <DataPanel
        status={reviewStatus === 'block' ? 'red' : reviewStatus === 'review' ? 'amber' : 'green'}
        style={{ padding: '16px 20px' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <LabelCaps style={{ color: reviewStatus === 'block' ? 'var(--critical-red)' : reviewStatus === 'review' ? 'var(--secondary-amber)' : 'var(--status-green)' }}>
              {reviewStatus === 'block'
                ? 'REMEDIATION REQUIRED BEFORE MERGE'
                : reviewStatus === 'review'
                ? 'MANUAL REVIEW RECOMMENDED'
                : 'SECURITY CONTROLS SATISFIED'}
            </LabelCaps>
            <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--text-dim)' }}>
              {reviewStatus === 'block'
                ? `${criticalCount} Critical and ${highCount} High finding(s) violate production deployment security policy.`
                : reviewStatus === 'review'
                ? 'Security audit detected potential vulnerabilities that require manual sign-off.'
                : 'Zero policy blocking findings detected in this analysis audit.'}
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="download" onClick={handleExportJSON} disabled={!selectedAnalysis}>
              EXPORT REPORT JSON
            </SecondaryButton>
            <PrimaryButton icon="search" onClick={() => navigate('/vulnerability-explorer', { state: { analysisId: selectedAnalysis?.analysis_id } })}>
              OPEN IN VULNERABILITY EXPLORER
            </PrimaryButton>
          </div>
        </div>
      </DataPanel>

    </div>
  );
}
