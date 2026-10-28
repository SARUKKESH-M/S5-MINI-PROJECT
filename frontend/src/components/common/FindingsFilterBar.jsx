import React, { useMemo } from 'react';

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SEV_COLORS = {
  CRITICAL: { bg: '#FEF2F2', border: '#FECACA', text: '#DC2626' },
  HIGH: { bg: '#FFF7ED', border: '#FFEDD5', text: '#EA580C' },
  MEDIUM: { bg: '#FEFCE8', border: '#FEF08A', text: '#CA8A04' },
  LOW: { bg: '#ECFEFF', border: '#CFFAFE', text: '#0891B2' },
  INFO: { bg: '#F1F5F9', border: '#E2E8F0', text: '#64748B' },
};

export default function FindingsFilterBar({
  findings = [],
  searchQuery = '',
  onSearchChange,
  severityFilter = 'ALL',
  onSeverityChange,
  onClearFilters,
  matchingCount = 0,
  totalCount = 0,
}) {
  // Compute counts per severity category across the unfiltered finding set
  const counts = useMemo(() => {
    const map = {
      ALL: findings.length,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) {
      const sev = String(f?.severity || 'info').toUpperCase();
      if (map[sev] !== undefined) {
        map[sev] += 1;
      } else {
        map.INFO += 1;
      }
    }
    return map;
  }, [findings]);

  const isFilterActive = severityFilter !== 'ALL' || (typeof searchQuery === 'string' && searchQuery.trim() !== '');

  return (
    <div
      className="findings-filter-bar"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
        padding: '12px 14px',
        backgroundColor: 'var(--bg-surface-elevated)',
        border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-sm)',
        marginBottom: '12px',
      }}
      aria-label="Filter findings"
    >
      {/* Search Input & Action Row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '8px',
        }}
      >
        <div style={{ flex: '1 1 180px', minWidth: '0' }}>
          <input
            type="search"
            className="form-control"
            placeholder="Filter by title, file, category, or CWE..."
            value={searchQuery}
            onChange={(e) => onSearchChange?.(e.target.value)}
            aria-label="Filter findings by text"
            style={{
              width: '100%',
              fontSize: '12px',
              padding: '6px 10px',
              backgroundColor: 'var(--bg-void)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            Showing <strong>{matchingCount}</strong> of <strong>{totalCount}</strong>
          </span>
          {isFilterActive && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onClearFilters}
              style={{ fontSize: '11px', padding: '4px 8px', minHeight: '28px' }}
              aria-label="Clear all finding filters"
            >
              Clear Filters
            </button>
          )}
        </div>
      </div>

      {/* Severity Filter Pills */}
      <div
        role="group"
        aria-label="Filter by severity"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          flexWrap: 'wrap',
        }}
      >
        {SEVERITIES.map((sev) => {
          const isSelected = severityFilter === sev;
          const count = counts[sev] || 0;
          const styleConfig = SEV_COLORS[sev];

          return (
            <button
              key={sev}
              type="button"
              onClick={() => onSeverityChange?.(sev)}
              aria-pressed={isSelected}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                fontSize: '11px',
                fontWeight: isSelected ? 700 : 500,
                fontFamily: 'var(--font-mono)',
                minHeight: '28px',
                padding: '4px 10px',
                borderRadius: '4px',
                border: isSelected
                  ? '1px solid var(--accent-blue)'
                  : '1px solid var(--border-subtle)',
                backgroundColor: isSelected
                  ? 'var(--accent-blue-subtle, rgba(56, 189, 248, 0.15))'
                  : 'var(--bg-void)',
                color: isSelected ? 'var(--text-primary)' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <span>{sev}</span>
              <span
                style={{
                  fontSize: '10px',
                  padding: '1px 4px',
                  borderRadius: '3px',
                  backgroundColor: isSelected
                    ? 'var(--accent-blue)'
                    : styleConfig?.bg || 'var(--border-subtle)',
                  color: isSelected
                    ? '#ffffff'
                    : styleConfig?.text || 'var(--text-dim)',
                  fontWeight: 600,
                }}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
