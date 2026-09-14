import React from 'react';
import SecurityGateCard from './SecurityGateCard';
import TopFindings from './TopFindings';
import FindingPreview from './FindingPreview';
import ProductionStatus from './ProductionStatus';

export default function LatestAnalysisPanel({
  latestAnalysis = null,
  latestFindings = null,
  findingPreview = null,
  productionStatus = null,
}) {
  const repoName = latestAnalysis?.repo || 'SARUKKESH-M/S5-MINI-PROJECT';
  const branch = latestAnalysis?.branch || 'main';
  const status = latestAnalysis?.status || 'Completed';
  const dateStr = latestAnalysis?.date || 'Sep 14, 2026 · 10:12 AM';
  const filesAnalyzed = latestAnalysis?.filesAnalyzed ?? 123;
  const findingsCount = latestAnalysis?.findingsCount ?? 18;
  const duration = latestAnalysis ? latestAnalysis.duration : '117.74s';
  const reviewStatus = latestAnalysis?.reviewStatus || 'BLOCK';

  return (
    <div className="cs-latest-analysis-panel">
      {/* Panel Top Card */}
      <div className="cs-panel-overview-card">
        <div className="cs-panel-overview-header">
          <div>
            <h3 className="cs-panel-title">Latest Analysis</h3>
            <div className="cs-panel-repo-name">{repoName}</div>
          </div>
          <span className="cs-status-indicator-badge">
            <span className="cs-status-dot-green" />
            <span>{status}</span>
          </span>
        </div>

        <div className="cs-panel-repo-meta">
          <span className="cs-meta-branch">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="6" y1="3" x2="6" y2="15" />
              <circle cx="18" cy="6" r="3" />
              <circle cx="6" cy="18" r="3" />
              <path d="M18 9a9 9 0 0 1-9 9" />
            </svg>
            <span>{branch}</span>
          </span>
          <span className="cs-meta-divider">•</span>
          <span className="cs-meta-date">{dateStr}</span>
        </div>

        {/* 3 Metric Pills */}
        <div className="cs-panel-stat-pills">
          <div className="cs-panel-pill">
            <span className="cs-pill-value">{filesAnalyzed}</span>
            <span className="cs-pill-label">Files Analyzed</span>
          </div>
          <div className="cs-panel-pill">
            <span className="cs-pill-value">{findingsCount}</span>
            <span className="cs-pill-label">Findings</span>
          </div>
          <div className="cs-panel-pill">
            <span className="cs-pill-value">{duration}</span>
            <span className="cs-pill-label">Duration</span>
          </div>
        </div>
      </div>

      {/* Security Gate Card */}
      <SecurityGateCard gate={reviewStatus} />

      {/* Top Findings */}
      <TopFindings findings={latestFindings} />

      {/* Finding Preview */}
      <FindingPreview preview={findingPreview} />

      {/* Production Status */}
      <ProductionStatus status={productionStatus} />
    </div>
  );
}
