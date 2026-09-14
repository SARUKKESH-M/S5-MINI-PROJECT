/**
 * CodeSentinel Dashboard Service
 *
 * Encapsulates Dashboard data retrieval, concurrent orchestration,
 * robust error tolerance via Promise.allSettled, section-specific fallback isolation,
 * and pure data normalization functions.
 *
 * Zero-trust compliant: Never requests or reconstructs raw source code.
 */

import {
  getAnalyticsSummary,
  getRepositoryAnalytics,
  getAnalyses,
  getAnalysis,
  getPlatformHealth,
  getPlatformInfo,
} from './apiClient';

/**
 * Approved Phase 1 Demonstration Baseline Data
 * Used ONLY when specific backend APIs fail, return empty, or are unavailable.
 */
export function createDashboardFallbackData() {
  return {
    dashboardMetrics: {
      repositories: '12',
      analyses: '48',
      findings: '126',
      blocked: '18',
      trendPercentages: {
        repositories: '+20% from last month',
        analyses: '+32% from last month',
        findings: '+12% from last month',
        blocked: '+5% from last month',
      },
    },
    severityBreakdown: [
      { name: 'Critical', value: 8, color: '#EF4444' },
      { name: 'High', value: 24, color: '#F97316' },
      { name: 'Medium', value: 68, color: '#F59E0B' },
      { name: 'Low', value: 18, color: '#3B82F6' },
      { name: 'Info', value: 8, color: '#94A3B8' },
    ],
    totalFindingsCount: 126,
    analysisTrend: [
      { date: 'Sep 7', analyses: 4, findings: 14 },
      { date: 'Sep 8', analyses: 6, findings: 18 },
      { date: 'Sep 9', analyses: 5, findings: 12 },
      { date: 'Sep 10', analyses: 9, findings: 24 },
      { date: 'Sep 11', analyses: 7, findings: 19 },
      { date: 'Sep 12', analyses: 8, findings: 21 },
      { date: 'Sep 13', analyses: 9, findings: 18 },
    ],
    gateDistribution: [
      { name: 'Block', value: 18, color: '#EF4444' },
      { name: 'Review', value: 9, color: '#F59E0B' },
      { name: 'Allow', value: 21, color: '#10B981' },
    ],
    totalGateAnalysesCount: 48,
    recentAnalyses: [
      {
        id: '1',
        repo: 'SARUKKESH-M/S5-MINI-PROJECT',
        branch: 'main',
        status: 'Completed',
        findings: 18,
        gate: 'Block',
        gateType: 'block',
        date: 'Sep 14, 2026',
        time: '10:12 AM',
      },
      {
        id: '2',
        repo: 'microsoft/vscode',
        branch: 'main',
        status: 'Completed',
        findings: 5,
        gate: 'Review',
        gateType: 'review',
        date: 'Sep 13, 2026',
        time: '04:32 PM',
      },
      {
        id: '3',
        repo: 'facebook/react',
        branch: 'main',
        status: 'Completed',
        findings: 2,
        gate: 'Allow',
        gateType: 'allow',
        date: 'Sep 12, 2026',
        time: '11:05 AM',
      },
      {
        id: '4',
        repo: 'vercel/next.js',
        branch: 'canary',
        status: 'Completed',
        findings: 7,
        gate: 'Review',
        gateType: 'review',
        date: 'Sep 11, 2026',
        time: '03:21 PM',
      },
      {
        id: '5',
        repo: 'langchain-ai/langchain',
        branch: 'main',
        status: 'Completed',
        findings: 12,
        gate: 'Block',
        gateType: 'block',
        date: 'Sep 10, 2026',
        time: '09:14 AM',
      },
    ],
    latestAnalysis: {
      id: 'demo-latest',
      repo: 'SARUKKESH-M/S5-MINI-PROJECT',
      branch: 'main',
      status: 'Completed',
      date: 'Sep 14, 2026 · 10:12 AM',
      filesAnalyzed: 123,
      findingsCount: 18,
      duration: '117.74s',
      reviewStatus: 'BLOCK',
      isFallback: true,
    },
    latestFindings: [
      {
        id: '1',
        severity: 'Critical',
        sevKey: 'critical',
        title: 'Command Injection Risk',
        count: 1,
        color: '#EF4444',
      },
      {
        id: '2',
        severity: 'High',
        sevKey: 'high',
        title: 'Potential SQL Injection',
        count: 3,
        color: '#F97316',
      },
      {
        id: '3',
        severity: 'Medium',
        sevKey: 'medium',
        title: 'Path Traversal / Unsafe File Access',
        count: 10,
        color: '#F59E0B',
      },
      {
        id: '4',
        severity: 'Medium',
        sevKey: 'medium',
        title: 'Possible Hardcoded Secret',
        count: 1,
        color: '#F59E0B',
      },
      {
        id: '5',
        severity: 'Medium',
        sevKey: 'medium',
        title: 'Insecure File Handling',
        count: 4,
        color: '#F59E0B',
      },
    ],
    findingPreview: {
      title: 'Command Injection Risk',
      severity: 'Critical',
      sevKey: 'critical',
      fileLocation: 'backend/utils/execute.py:42',
      description: 'User-controlled input can lead to arbitrary command execution on the server.',
      codeSnippet: [
        { lineNum: 40, code: 'def run_command(cmd):', isHighlighted: false },
        { lineNum: 41, code: '    # vulnerable code', isHighlighted: false },
        { lineNum: 42, code: '    os.system(cmd)', isHighlighted: true },
        { lineNum: 43, code: '    return True', isHighlighted: false },
      ],
    },
    productionStatus: {
      isHealthy: true,
      title: 'Production Backend Verified',
      description: 'CodeSentinel v1.1.0 is live and secure.',
    },
  };
}

// ---------------------------------------------------------------------------
// Pure Normalization Helpers
// ---------------------------------------------------------------------------

/**
 * Format UTC ISO 8601 string to { date: "Sep 14, 2026", time: "10:12 AM" }
 */
export function formatDateTime(isoString) {
  if (!isoString) {
    return { date: '—', time: '—', combined: '—' };
  }
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) {
      return { date: '—', time: '—', combined: '—' };
    }
    const dateStr = d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'UTC',
    });
    const timeStr = d.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
      timeZone: 'UTC',
    });
    return {
      date: dateStr,
      time: timeStr,
      combined: `${dateStr} · ${timeStr}`,
    };
  } catch {
    return { date: '—', time: '—', combined: '—' };
  }
}

/**
 * Normalize 4 Key Metric Cards
 */
export function normalizeMetrics(summaryData, repoAnalyticsData, fallback) {
  if (!summaryData && !repoAnalyticsData) {
    return fallback.dashboardMetrics;
  }

  const sData = summaryData?.data || summaryData || {};
  const rData = repoAnalyticsData || {};

  // Total Repositories
  let reposVal = fallback.dashboardMetrics.repositories;
  if (typeof rData.total_repositories === 'number') {
    reposVal = String(rData.total_repositories);
  } else if (Array.isArray(rData.repositories)) {
    reposVal = String(rData.repositories.length);
  }

  // Total Analyses
  let analysesVal = fallback.dashboardMetrics.analyses;
  if (typeof sData.total_analyses === 'number') {
    analysesVal = String(sData.total_analyses);
  }

  // Total Findings
  let findingsVal = fallback.dashboardMetrics.findings;
  if (typeof sData.total_findings === 'number') {
    findingsVal = String(sData.total_findings);
  }

  // Blocked
  let blockedVal = fallback.dashboardMetrics.blocked;
  if (sData.review_status_distribution && typeof sData.review_status_distribution.block === 'number') {
    blockedVal = String(sData.review_status_distribution.block);
  }

  return {
    repositories: reposVal,
    analyses: analysesVal,
    findings: findingsVal,
    blocked: blockedVal,
    trendPercentages: fallback.dashboardMetrics.trendPercentages,
  };
}

/**
 * Normalize Findings by Severity Donut Chart
 */
export function normalizeSeverity(summaryData, fallback) {
  const sData = summaryData?.data || summaryData;
  if (!sData || !sData.severities) {
    return {
      severityBreakdown: fallback.severityBreakdown,
      totalFindingsCount: fallback.totalFindingsCount,
    };
  }

  const sevs = sData.severities;
  const breakdown = [
    { name: 'Critical', value: Number(sevs.critical) || 0, color: '#EF4444' },
    { name: 'High', value: Number(sevs.high) || 0, color: '#F97316' },
    { name: 'Medium', value: Number(sevs.medium) || 0, color: '#F59E0B' },
    { name: 'Low', value: Number(sevs.low) || 0, color: '#3B82F6' },
    { name: 'Info', value: Number(sevs.info) || 0, color: '#94A3B8' },
  ];

  const total = typeof sData.total_findings === 'number'
    ? sData.total_findings
    : breakdown.reduce((acc, cur) => acc + cur.value, 0);

  return {
    severityBreakdown: breakdown,
    totalFindingsCount: total,
  };
}

/**
 * Normalize Security Gate Decisions Donut Chart
 */
export function normalizeGateDistribution(summaryData, fallback) {
  const sData = summaryData?.data || summaryData;
  if (!sData || !sData.review_status_distribution) {
    return {
      gateDistribution: fallback.gateDistribution,
      totalGateAnalysesCount: fallback.totalGateAnalysesCount,
    };
  }

  const dist = sData.review_status_distribution;
  const distribution = [
    { name: 'Block', value: Number(dist.block) || 0, color: '#EF4444' },
    { name: 'Review', value: Number(dist.review) || 0, color: '#F59E0B' },
    { name: 'Allow', value: Number(dist.allow) || 0, color: '#10B981' },
  ];

  const total = typeof sData.total_analyses === 'number'
    ? sData.total_analyses
    : distribution.reduce((acc, cur) => acc + cur.value, 0);

  return {
    gateDistribution: distribution,
    totalGateAnalysesCount: total,
  };
}

/**
 * Normalize Recent Repository Analyses (Table Rows)
 */
export function normalizeRecentAnalyses(analysesData, fallback) {
  const rawList = analysesData?.analyses;
  if (!Array.isArray(rawList) || rawList.length === 0) {
    return fallback.recentAnalyses;
  }

  return rawList.map((item, idx) => {
    const summary = item.summary || {};
    const repoMeta = summary._repository || item.repository;

    let repoName = 'SARUKKESH-M/S5-MINI-PROJECT';
    let branch = 'main';

    if (repoMeta && typeof repoMeta === 'object') {
      const owner = repoMeta.owner || '';
      const rName = repoMeta.repository || repoMeta.name || '';
      if (owner && rName) {
        repoName = `${owner}/${rName}`;
      } else if (rName || owner) {
        repoName = rName || owner;
      }
      if (repoMeta.branch) {
        branch = repoMeta.branch;
      }
    } else if (typeof repoMeta === 'string' && repoMeta.trim()) {
      repoName = repoMeta.trim();
    }

    const reviewStatus = String(summary._review_status || item.review_status || 'block').toLowerCase();
    const gateCapitalized = reviewStatus === 'allow'
      ? 'Allow'
      : reviewStatus === 'review'
      ? 'Review'
      : 'Block';

    const rawStatus = String(item.status || 'completed').toLowerCase();
    const statusFormatted = (rawStatus === 'completed' || rawStatus === 'success') ? 'Completed' : 'Failed';

    const dt = formatDateTime(item.created_at);

    return {
      id: String(item.analysis_id || idx + 1),
      repo: repoName,
      branch: branch || 'main',
      status: statusFormatted,
      findings: typeof item.finding_count === 'number' ? item.finding_count : (Number(summary.total_findings) || 0),
      gate: gateCapitalized,
      gateType: reviewStatus in { allow: 1, review: 1, block: 1 } ? reviewStatus : 'block',
      date: dt.date,
      time: dt.time,
    };
  });
}

/**
 * Normalize Latest Analysis Card
 */
export function normalizeLatestAnalysis(newestAnalysis, detailedReport, fallback) {
  if (!newestAnalysis) {
    return fallback.latestAnalysis;
  }

  const summary = detailedReport?.summary || newestAnalysis.summary || {};
  const repoMeta = detailedReport?.repository || summary._repository || newestAnalysis.repository;

  let repoName = 'SARUKKESH-M/S5-MINI-PROJECT';
  let branch = 'main';

  if (repoMeta && typeof repoMeta === 'object') {
    const owner = repoMeta.owner || '';
    const rName = repoMeta.repository || repoMeta.name || '';
    if (owner && rName) {
      repoName = `${owner}/${rName}`;
    } else if (rName || owner) {
      repoName = rName || owner;
    }
    if (repoMeta.branch) {
      branch = repoMeta.branch;
    }
  } else if (typeof repoMeta === 'string' && repoMeta.trim()) {
    repoName = repoMeta.trim();
  }

  const rawStatus = String(detailedReport?.status || newestAnalysis.status || 'completed').toLowerCase();
  const statusFormatted = (rawStatus === 'completed' || rawStatus === 'success') ? 'Completed' : 'Failed';

  const filesAnalyzed = Number(summary.analyzed_files) || Number(summary.total_files) || 123;
  const findingsCount = typeof newestAnalysis.finding_count === 'number'
    ? newestAnalysis.finding_count
    : (Number(summary.total_findings) || 0);

  const rawGate = String(detailedReport?.review_status || summary._review_status || 'block').toUpperCase();
  const reviewStatus = (rawGate === 'ALLOW' || rawGate === 'REVIEW' || rawGate === 'BLOCK') ? rawGate : 'BLOCK';

  const dt = formatDateTime(newestAnalysis.created_at);

  return {
    id: String(newestAnalysis.analysis_id || 'latest'),
    repo: repoName,
    branch: branch || 'main',
    status: statusFormatted,
    date: dt.combined,
    filesAnalyzed,
    findingsCount,
    // Requirement 11: Real backend data displays "—". Demo duration appears only on fallback.
    duration: '—',
    reviewStatus,
    isFallback: false,
  };
}

/**
 * Normalize Top Findings List
 */
export function normalizeFindings(detailedAnalysis, fallback) {
  const rawFindings = detailedAnalysis?.findings || detailedAnalysis?.analysis?.findings;
  if (!Array.isArray(rawFindings) || rawFindings.length === 0) {
    return fallback.latestFindings;
  }

  const sevColors = {
    critical: '#EF4444',
    high: '#F97316',
    medium: '#F59E0B',
    low: '#3B82F6',
    info: '#94A3B8',
  };

  // Group or take top findings
  return rawFindings.slice(0, 5).map((f, idx) => {
    const sev = String(f.severity || 'medium').toLowerCase();
    const sevCapitalized = sev.charAt(0).toUpperCase() + sev.slice(1);
    const sevKey = sev in sevColors ? sev : 'medium';

    return {
      id: String(f.finding_id || idx + 1),
      severity: sevCapitalized,
      sevKey,
      title: f.title || f.category || 'Security Finding',
      count: 1,
      color: sevColors[sevKey],
      description: f.description || '',
      evidence: f.evidence || [],
    };
  });
}

/**
 * Normalize Finding Preview Card
 */
export function normalizeFindingPreview(findingsList, fallback) {
  if (!Array.isArray(findingsList) || findingsList.length === 0) {
    return fallback.findingPreview;
  }

  // Prioritize critical, then high, then first finding
  const primary = findingsList.find(f => f.sevKey === 'critical')
    || findingsList.find(f => f.sevKey === 'high')
    || findingsList[0];

  let fileLoc = fallback.findingPreview.fileLocation;
  if (Array.isArray(primary.evidence) && primary.evidence.length > 0) {
    const ev = primary.evidence[0];
    if (ev.document_id) {
      fileLoc = ev.document_id;
      if (ev.line_start) {
        fileLoc += `:${ev.line_start}`;
      }
    }
  }

  return {
    title: primary.title || fallback.findingPreview.title,
    severity: primary.severity || fallback.findingPreview.severity,
    sevKey: primary.sevKey || fallback.findingPreview.sevKey,
    fileLocation: fileLoc,
    description: primary.description || fallback.findingPreview.description,
    // Note: Illustrative syntax block remains presentation fallback per Step 13
    codeSnippet: fallback.findingPreview.codeSnippet,
  };
}

/**
 * Normalize 7-day Trend Time Series
 */
export function normalizeTrend(allAnalysesData, fallback) {
  const rawList = allAnalysesData?.analyses;
  if (!Array.isArray(rawList) || rawList.length === 0) {
    return fallback.analysisTrend;
  }

  // Build map of UTC calendar dates
  const dayMap = new Map();

  for (const item of rawList) {
    if (!item.created_at) continue;
    try {
      const d = new Date(item.created_at);
      if (isNaN(d.getTime())) continue;

      // Group key e.g. "Sep 14"
      const dateKey = d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        timeZone: 'UTC',
      });

      const findingCount = typeof item.finding_count === 'number'
        ? item.finding_count
        : (Number(item.summary?.total_findings) || 0);

      if (!dayMap.has(dateKey)) {
        dayMap.set(dateKey, {
          date: dateKey,
          timestamp: d.getTime(),
          analyses: 0,
          findings: 0,
        });
      }

      const entry = dayMap.get(dateKey);
      entry.analyses += 1;
      entry.findings += findingCount;
    } catch {
      // ignore parse error
    }
  }

  // If fewer than 2 distinct calendar days exist in real records,
  // use the approved 7-day demo baseline per Rule 15
  if (dayMap.size < 2) {
    return fallback.analysisTrend;
  }

  // Sort chronologically and take last 7 days
  const sorted = Array.from(dayMap.values())
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(-7)
    .map(entry => ({
      date: entry.date,
      analyses: entry.analyses,
      findings: entry.findings,
    }));

  return sorted.length >= 2 ? sorted : fallback.analysisTrend;
}

/**
 * Normalize Production Status
 */
export function normalizeProductionStatus(healthRes, infoRes, fallback) {
  if (!healthRes) {
    return {
      isHealthy: false,
      title: 'Backend Offline',
      description: 'Unable to connect to CodeSentinel backend.',
    };
  }

  const isHealthy = String(healthRes.status).toLowerCase() === 'healthy';
  const version = infoRes?.version || healthRes?.version || '1.1.0';

  return {
    isHealthy,
    title: isHealthy ? 'Production Backend Verified' : 'Backend Degraded',
    description: isHealthy
      ? `CodeSentinel v${version} is live and secure.`
      : 'Some platform security subsystems are degraded.',
  };
}

// ---------------------------------------------------------------------------
// Central Orchestration Function
// ---------------------------------------------------------------------------

/**
 * Fetches all Dashboard data concurrently via Promise.allSettled and normalizes
 * the response into the exact contract expected by CodeSentinel Dashboard components.
 */
export async function fetchDashboardData() {
  const fallback = createDashboardFallbackData();

  try {
    // 1. Fire independent initial requests concurrently
    const [
      summarySettled,
      repoAnalyticsSettled,
      recentAnalysesSettled,
      trendAnalysesSettled,
      healthSettled,
      infoSettled,
    ] = await Promise.allSettled([
      getAnalyticsSummary({ timeWindow: 'all' }),
      getRepositoryAnalytics({ timeWindow: 'all', limit: 20 }),
      getAnalyses({ limit: 5, offset: 0 }),
      getAnalyses({ limit: 100, offset: 0 }),
      getPlatformHealth(),
      getPlatformInfo(),
    ]);

    const summaryData = summarySettled.status === 'fulfilled' ? summarySettled.value : null;
    const repoAnalyticsData = repoAnalyticsSettled.status === 'fulfilled' ? repoAnalyticsSettled.value : null;
    const recentAnalysesData = recentAnalysesSettled.status === 'fulfilled' ? recentAnalysesSettled.value : null;
    const trendAnalysesData = trendAnalysesSettled.status === 'fulfilled' ? trendAnalysesSettled.value : null;
    const healthData = healthSettled.status === 'fulfilled' ? healthSettled.value : null;
    const infoData = infoSettled.status === 'fulfilled' ? infoSettled.value : null;

    // 2. Fetch detailed analysis for the newest item if available
    let detailedAnalysis = null;
    const newestItem = recentAnalysesData?.analyses?.[0];
    if (newestItem?.analysis_id) {
      try {
        detailedAnalysis = await getAnalysis(newestItem.analysis_id);
      } catch (err) {
        // Soft failure: fallback to summary information without crashing
        console.warn('Could not fetch detailed analysis findings:', err.message);
      }
    }

    // 3. Apply normalization
    const dashboardMetrics = normalizeMetrics(summaryData, repoAnalyticsData, fallback);
    const { severityBreakdown, totalFindingsCount } = normalizeSeverity(summaryData, fallback);
    const { gateDistribution, totalGateAnalysesCount } = normalizeGateDistribution(summaryData, fallback);
    const recentAnalyses = normalizeRecentAnalyses(recentAnalysesData, fallback);
    const latestAnalysis = normalizeLatestAnalysis(newestItem, detailedAnalysis, fallback);
    const latestFindings = normalizeFindings(detailedAnalysis, fallback);
    const findingPreview = normalizeFindingPreview(latestFindings, fallback);
    const analysisTrend = normalizeTrend(trendAnalysesData, fallback);
    const productionStatus = normalizeProductionStatus(healthData, infoData, fallback);

    return {
      dashboardMetrics,
      severityBreakdown,
      totalFindingsCount,
      analysisTrend,
      gateDistribution,
      totalGateAnalysesCount,
      recentAnalyses,
      latestAnalysis,
      latestFindings,
      findingPreview,
      productionStatus,
    };
  } catch (globalErr) {
    console.error('Critical failure in fetchDashboardData:', globalErr);
    return fallback;
  }
}
