import React from 'react';
import { useNavigate } from 'react-router-dom';

const topFindingsList = [
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
];

export default function TopFindings({
  findings = topFindingsList,
  onSelectFinding = null,
  selectedId = null,
}) {
  const navigate = useNavigate();
  const items = Array.isArray(findings) && findings.length > 0 ? findings : topFindingsList;

  return (
    <div className="cs-top-findings-card">
      <div className="cs-top-findings-header">
        <h4 className="cs-card-section-title">Top Findings</h4>
        <button
          type="button"
          className="cs-view-all-link-sm"
          onClick={() => navigate('/history')}
          title="View all findings in audit history"
        >
          <span>View All</span>
          <span className="cs-arrow-icon">→</span>
        </button>
      </div>

      <div className="cs-findings-items-list" role="list">
        {items.map((item) => {
          const isSelected = selectedId && String(selectedId) === String(item.id);
          return (
            <div
              key={item.id}
              className={`cs-finding-row-item ${isSelected ? 'cs-finding-row-selected' : ''}`}
              style={{ borderLeftColor: item.color, cursor: 'pointer' }}
              onClick={() => onSelectFinding?.(item)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelectFinding?.(item);
                }
              }}
              title={`Inspect ${item.title}`}
            >
              <div className="cs-finding-item-info">
                <span className={`cs-severity-pill cs-sev-${item.sevKey}`}>
                  {item.severity}
                </span>
                <span className="cs-finding-item-name" title={item.title}>
                  {item.title}
                </span>
              </div>
              <span className="cs-finding-item-count">{item.count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
