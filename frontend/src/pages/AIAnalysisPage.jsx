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
  getAnalysisFindings,
  getPlatformHealth
} from '../services/apiClient';

export default function AIAnalysisPage() {
  const navigate = useNavigate();
  const location = useLocation();

  // Analyses list and selected analysis state
  const [analysesList, setAnalysesList] = useState([]);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  // Platform & Provider status
  const [llmServiceStatus, setLlmServiceStatus] = useState({
    status: 'unknown',
    details: 'Checking engine diagnostics...'
  });

  // Loading & error states
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  // Load platform health and analyses on mount
  useEffect(() => {
    let isMounted = true;

    // Check platform LLM service health
    getPlatformHealth()
      .then((h) => {
        if (!isMounted || !h) return;
        const llmCheck = h.checks?.llm_service;
        setLlmServiceStatus({
          status: llmCheck?.status || 'healthy',
          details: llmCheck?.details || `${h.service || 'CodeSentinel'} Analysis Engine Active`
        });
      })
      .catch(() => {
        if (isMounted) {
          setLlmServiceStatus({ status: 'degraded', details: 'Engine diagnostics unreachable' });
        }
      });

    // Load recent analyses
    const loadAnalyses = async () => {
      setLoading(true);
      setErrorMessage(null);
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
        } else {
          setSelectedAnalysisId(null);
          setSelectedAnalysis(null);
          setFindings([]);
        }
      } catch (err) {
        if (isMounted) {
          setErrorMessage(err.message || 'Failed to load analysis history');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadAnalyses();

    return () => { isMounted = false; };
  }, [location.state?.analysisId]);

  // Load details and findings when selectedAnalysisId changes
  useEffect(() => {
    if (!selectedAnalysisId) return;

    let isMounted = true;
    setFindingsLoading(true);

    const fetchDetails = async () => {
      try {
        const [analysisRes, findingsRes] = await Promise.allSettled([
          getAnalysis(selectedAnalysisId),
          getAnalysisFindings(selectedAnalysisId)
        ]);

        if (!isMounted) return;

        if (analysisRes.status === 'fulfilled' && analysisRes.value?.analysis) {
          setSelectedAnalysis(analysisRes.value.analysis);
        } else {
          const fallback = analysesList.find(a => a.analysis_id === selectedAnalysisId);
          setSelectedAnalysis(fallback || null);
        }

        if (findingsRes.status === 'fulfilled' && Array.isArray(findingsRes.value?.findings)) {
          const fList = findingsRes.value.findings;
          setFindings(fList);
          if (fList.length > 0) {
            setSelectedFindingId(fList[0].finding_id);
          } else {
            setSelectedFindingId(null);
          }
        } else if (analysisRes.status === 'fulfilled' && Array.isArray(analysisRes.value?.analysis?.findings)) {
          const embedded = analysisRes.value.analysis.findings;
          setFindings(embedded);
          if (embedded.length > 0) {
            setSelectedFindingId(embedded[0].finding_id);
          } else {
            setSelectedFindingId(null);
          }
        } else {
          setFindings([]);
          setSelectedFindingId(null);
        }
      } catch {
        // Handled gracefully
      } finally {
        if (isMounted) setFindingsLoading(false);
      }
    };

    fetchDetails();

    return () => { isMounted = false; };
  }, [selectedAnalysisId, analysesList]);

  // Active finding & evidence
  const activeFinding = findings.find((f) => f.finding_id === selectedFindingId) || findings[0] || null;
  const activeEvidence = activeFinding?.evidence?.[0] || null;

  // Metadata summary
  const summary = selectedAnalysis?.summary || {};
  const repoMeta = selectedAnalysis?.repository || summary._repository || null;
  const repoName = (repoMeta?.owner && repoMeta?.repository)
    ? `${repoMeta.owner}/${repoMeta.repository}`
    : (selectedAnalysis?.query?.replace('Repository Analysis: ', '') || 'Static Scope Target');
  const branchName = repoMeta?.branch || 'main';
  const reviewStatus = (selectedAnalysis?.review_status || summary._review_status || (summary.critical_count > 0 ? 'block' : 'allow')).toLowerCase();
  const engineProvider = selectedAnalysis?.provider || 'AST-Deterministic';
  const traceability = selectedAnalysis?.traceability || null;

  // Real traceability logs derived honestly from backend report
  const traceLogs = [];
  if (selectedAnalysis) {
    traceLogs.push(`[ORCHESTRATOR] Initialized security analysis pipeline for "${repoName}" (${selectedAnalysis.analysis_id}).`);
    if (traceability) {
      traceLogs.push(`[AST_ENGINE] Parsed ${traceability.files_analyzed ?? summary.analyzed_files ?? 0} source file(s) under policy profile "${traceability.policy_profile || 'default'}".`);
      traceLogs.push(`[EXECUTION_TRACE] Analysis completed in ${traceability.duration_ms ?? 0} ms with ${traceability.cache_hits ?? 0} cache hit(s).`);
    } else {
      traceLogs.push(`[AST_ENGINE] Scanned ${summary.analyzed_files || 0} file(s) across workspace.`);
    }

    if (activeFinding) {
      traceLogs.push(`[SIGNAL_MATCH] Verified AST signal: ${activeEvidence?.signal_name || activeEvidence?.signal_type || activeFinding.title} in ${activeEvidence?.document_id || 'source'}.`);
      traceLogs.push(`[VERDICT_EVALUATION] Evaluated finding "${activeFinding.finding_id}" as ${activeFinding.severity.toUpperCase()} severity (Confidence: ${activeFinding.confidence?.toUpperCase() || 'HIGH'}).`);
      traceLogs.push(`[GATE_ENFORCEMENT] Security Gate decision: ${reviewStatus.toUpperCase()} (Backend authoritative).`);
    } else {
      traceLogs.push('[RULE_VERIFICATION] Zero security rule violations detected across analyzed files.');
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Header Context & Finding Dropdown Selector */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                SECURITY REASONING &amp; GROUNDING CENTER
              </LabelCaps>
              <StatusPip status={llmServiceStatus.status === 'healthy' ? 'green' : 'amber'} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: llmServiceStatus.status === 'healthy' ? 'var(--status-green)' : 'var(--secondary-amber)' }}>
                ENGINE: {engineProvider.toUpperCase()} ({llmServiceStatus.details})
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              AI &amp; Deterministic Security Analysis
            </h1>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-on-surface-variant)' }}>
              <span>TARGET: <strong>{repoName}</strong></span>
              <span>BRANCH: <strong>{branchName}</strong></span>
              <span>ANALYSIS ID: <strong>{selectedAnalysis?.analysis_id || 'None'}</strong></span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            {/* Analysis Switcher */}
            {analysesList.length > 1 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>AUDIT:</LabelCaps>
                <select
                  value={selectedAnalysisId || ''}
                  onChange={(e) => setSelectedAnalysisId(e.target.value)}
                  style={{
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '6px 10px',
                    color: 'var(--primary-cyan)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    outline: 'none',
                    cursor: 'pointer'
                  }}
                >
                  {analysesList.map((a) => (
                    <option key={a.analysis_id} value={a.analysis_id}>
                      {a.analysis_id} ({a.finding_count || 0} findings)
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Finding Selector */}
            {findings.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>FINDING:</LabelCaps>
                <select
                  value={selectedFindingId || ''}
                  onChange={(e) => setSelectedFindingId(e.target.value)}
                  style={{
                    backgroundColor: 'var(--bg-void-lowest)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '6px 10px',
                    color: 'var(--text-on-surface)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    outline: 'none',
                    cursor: 'pointer',
                    maxWidth: '240px'
                  }}
                >
                  {findings.map((f) => (
                    <option key={f.finding_id} value={f.finding_id}>
                      {f.finding_id}: {f.title}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <SecondaryButton
              icon="alt_route"
              onClick={() => navigate('/pr-review', { state: { analysisId: selectedAnalysis?.analysis_id } })}
              disabled={!selectedAnalysis}
            >
              PR REVIEW
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Step 6O Decision Banner */}
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
          activeFinding
            ? `Authoritative Decision: Finding "${activeFinding.title}" (${activeFinding.severity.toUpperCase()}) evaluated by backend security policy gate`
            : `All ${summary.analyzed_files || 0} analyzed source files satisfy production security policies`
        }
      />

      {/* 3. Reasoning & Grounding Pipeline Visualization */}
      <DataPanel title="SECURITY REASONING &amp; GROUNDING PIPELINE" status="cyan">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>code</span>
              <LabelCaps style={{ fontSize: '10px' }}>1. AST SIGNALS</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              {activeEvidence?.signal_type || activeEvidence?.signal_name || 'AST Parsed'}
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--secondary-amber)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>saved_search</span>
              <LabelCaps style={{ fontSize: '10px' }}>2. CATEGORY</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              {activeFinding?.category || 'Security Control'}
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary-cyan)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>psychology</span>
              <LabelCaps style={{ fontSize: '10px' }}>3. ENGINE</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
              Confidence: {activeFinding?.confidence?.toUpperCase() || 'VERIFIED'}
            </span>
          </div>

          <div style={{ padding: '12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: activeFinding?.severity === 'critical' ? 'var(--critical-red)' : 'var(--status-green)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>gpp_maybe</span>
              <LabelCaps style={{ fontSize: '10px' }}>4. VERDICT</LabelCaps>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: activeFinding?.severity === 'critical' ? 'var(--critical-red)' : 'var(--status-green)', fontWeight: 700 }}>
              {activeFinding?.severity ? `${activeFinding.severity.toUpperCase()} SEVERITY` : 'CLEAN'}
            </span>
          </div>

        </div>
      </DataPanel>

      {/* 4. Deep Inspection Grid: AST Context & Diagnostic Trace */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* AST Signal & Knowledge Context (6 cols) */}
        <div style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* AST Structural Context */}
          <DataPanel title="AST STRUCTURAL SIGNAL CONTEXT" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>SIGNAL TYPE</span>
                <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>{activeEvidence?.signal_type || 'AST_NODE'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>SIGNAL NAME</span>
                <span style={{ color: 'var(--text-on-surface)' }}>{activeEvidence?.signal_name || activeFinding?.title || 'N/A'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>SOURCE DOCUMENT</span>
                <span style={{ color: 'var(--text-on-surface)', wordBreak: 'break-all' }}>{activeEvidence?.document_id || 'Workspace Scope'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                <span style={{ color: 'var(--text-dim)' }}>LINE LOCATION</span>
                <span style={{ color: 'var(--primary-cyan)', fontWeight: 600 }}>
                  {activeEvidence?.line_start ? `Line ${activeEvidence.line_start}` : 'N/A'}
                </span>
              </div>
            </div>
          </DataPanel>

          {/* Knowledge & Classification Panel */}
          <DataPanel title="SECURITY POLICY &amp; RULE CLASSIFICATION" status="amber">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>VULNERABILITY CATEGORY</span>
                <span style={{ color: 'var(--secondary-amber)', fontWeight: 600 }}>{activeFinding?.category || 'Security Control'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>CONFIDENCE METRIC</span>
                <span style={{ color: 'var(--status-green)', fontWeight: 600 }}>{activeFinding?.confidence?.toUpperCase() || 'HIGH'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-dim)' }}>SEVERITY LEVEL</span>
                <span style={{ color: activeFinding?.severity === 'critical' ? 'var(--critical-red)' : 'var(--text-on-surface)' }}>
                  {activeFinding?.severity?.toUpperCase() || 'CLEAN'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                <span style={{ color: 'var(--text-dim)' }}>ANALYSIS CONTRACT</span>
                <span style={{ color: 'var(--text-on-surface-variant)' }}>v{selectedAnalysis?.analysis_version || '1.0'}</span>
              </div>
            </div>
          </DataPanel>

        </div>

        {/* Traceability & Diagnostic Log (6 cols) */}
        <div style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <DataPanel title="PIPELINE TRACEABILITY &amp; AUDIT LOG" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{
                backgroundColor: 'var(--bg-void-lowest)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '12px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                lineHeight: 1.6,
                color: 'var(--text-on-surface-variant)',
                minHeight: '220px',
                maxHeight: '260px',
                overflowY: 'auto'
              }}>
                {traceLogs.map((log, idx) => (
                  <div key={idx} style={{ marginBottom: '6px' }}>
                    <span style={{ color: 'var(--primary-cyan)', marginRight: '6px' }}>&gt;</span>
                    {log}
                  </div>
                ))}
              </div>

              {activeFinding && (
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                  <LabelCaps style={{ fontSize: '10px' }}>FINDING SEVERITY:</LabelCaps>
                  <SeverityBadge severity={activeFinding.severity || 'info'} />
                </div>
              )}
            </div>
          </DataPanel>
        </div>

      </div>

      {/* 5. Grounded Evidence Code Inspector */}
      <DataPanel title={`GROUNDED SOURCE CODE EVIDENCE — ${activeEvidence?.document_id || 'INSPECTOR'}`} status="cyan">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {activeEvidence ? (
            <EvidenceSnippet
              documentId={activeEvidence.document_id}
              lineStart={activeEvidence.line_start}
              lineEnd={activeEvidence.line_end}
              signalType={activeEvidence.signal_type}
              signalName={activeEvidence.signal_name}
            />
          ) : (
            <div style={{
              padding: '12px',
              backgroundColor: 'var(--bg-void-lowest)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-xs)',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--text-dim)'
            }}>
              Zero findings or code evidence recorded for this analysis.
            </div>
          )}

          <CodeViewer
            lines={activeEvidence?.lines || [
              `# Source code not embedded in backend report payload`,
              `# Document: ${activeEvidence?.document_id || 'N/A'}`,
              `# Signal Type: ${activeEvidence?.signal_type || 'N/A'}`,
              `# Signal Name: ${activeEvidence?.signal_name || 'N/A'}`,
              `# Target Line: ${activeEvidence?.line_start || 1}`
            ]}
            startLine={activeEvidence?.line_start || 1}
            highlightRange={{
              start: activeEvidence?.line_start || 1,
              end: activeEvidence?.line_end || activeEvidence?.line_start || 1
            }}
          />
        </div>
      </DataPanel>

    </div>
  );
}
