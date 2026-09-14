import React from 'react';
import { useNavigate } from 'react-router-dom';
import { RepositoriesIcon, MoreDotsIcon } from './Icons';

const recentAnalysesData = [
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
];

export default function RecentAnalysesTable({ data = recentAnalysesData }) {
  const navigate = useNavigate();
  const rows = Array.isArray(data) && data.length > 0 ? data : recentAnalysesData;

  return (
    <div id="recent-analyses-table" className="cs-table-card">
      <div className="cs-table-card-header">
        <div>
          <h3 className="cs-table-title">Recent Repository Analyses</h3>
          <p className="cs-table-subtitle">Latest automated code inspections across connected repositories</p>
        </div>
        <button
          type="button"
          className="cs-view-all-link"
          onClick={() => navigate('/repositories')}
        >
          <span>View All</span>
          <span className="cs-arrow-icon">→</span>
        </button>
      </div>

      <div className="cs-table-responsive-wrapper">
        <table className="cs-data-table" aria-label="Recent Repository Analyses">
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Branch</th>
              <th scope="col">Status</th>
              <th scope="col">Findings</th>
              <th scope="col">Security Gate</th>
              <th scope="col">Analyzed</th>
              <th scope="col" className="cs-th-actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="cs-table-row">

                <td className="cs-td-repo">
                  <div className="cs-repo-cell">
                    <span className="cs-repo-icon-slot">
                      <RepositoriesIcon size={16} color="#6366F1" />
                    </span>
                    <span className="cs-repo-name" title={row.repo}>
                      {row.repo}
                    </span>
                  </div>
                </td>

                <td className="cs-td-branch">
                  <span className="cs-branch-pill">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="6" y1="3" x2="6" y2="15" />
                      <circle cx="18" cy="6" r="3" />
                      <circle cx="6" cy="18" r="3" />
                      <path d="M18 9a9 9 0 0 1-9 9" />
                    </svg>
                    <span>{row.branch}</span>
                  </span>
                </td>

                <td className="cs-td-status">
                  <span className="cs-status-indicator-badge">
                    <span className="cs-status-dot-green" />
                    <span>{row.status}</span>
                  </span>
                </td>

                <td className="cs-td-findings">
                  <span className="cs-findings-count-pill">{row.findings}</span>
                </td>

                <td className="cs-td-gate">
                  <span className={`cs-gate-badge cs-gate-${row.gateType}`}>
                    {row.gate}
                  </span>
                </td>

                <td className="cs-td-analyzed">
                  <div className="cs-analyzed-datetime">
                    <span className="cs-analyzed-date">{row.date}</span>
                    <span className="cs-analyzed-time">{row.time}</span>
                  </div>
                </td>

                <td className="cs-td-actions">
                  <div className="cs-actions-cell">
                    <button
                      type="button"
                      className="cs-action-view-btn"
                      onClick={() => navigate('/analyze')}
                    >
                      View
                    </button>
                    <button
                      type="button"
                      className="cs-action-menu-btn"
                      title="More actions"
                      aria-label="More actions"
                    >
                      <MoreDotsIcon size={16} color="#94A3B8" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
