import React from 'react';

/**
 * SecurityToast - Non-blocking Security Gate notification toast.
 * Renders verdict, summary status, findings count, and navigation actions.
 */
export default function SecurityToast({
  verdict,
  findingCount = 0,
  onViewFindings,
  onClose,
}) {
  const cleanVerdict = String(verdict || 'ALLOW').toUpperCase();

  let borderColor = 'var(--verdict-allow-border)';
  let accentColor = 'var(--verdict-allow)';
  let bgGradient = 'linear-gradient(135deg, rgba(16, 185, 129, 0.14) 0%, rgba(15, 20, 28, 0.96) 100%)';
  let subtitle = 'Security check passed';
  let description = 'No blocking vulnerabilities detected';

  if (cleanVerdict === 'BLOCK') {
    borderColor = 'var(--verdict-block-border)';
    accentColor = 'var(--verdict-block)';
    bgGradient = 'linear-gradient(135deg, rgba(239, 68, 68, 0.16) 0%, rgba(15, 20, 28, 0.96) 100%)';
    subtitle = 'Critical vulnerability detected';
    description = `${findingCount} ${findingCount === 1 ? 'finding requires' : 'findings require'} attention`;
  } else if (cleanVerdict === 'REVIEW') {
    borderColor = 'var(--verdict-review-border)';
    accentColor = 'var(--verdict-review)';
    bgGradient = 'linear-gradient(135deg, rgba(245, 158, 11, 0.16) 0%, rgba(15, 20, 28, 0.96) 100%)';
    subtitle = 'Manual review required';
    description = `${findingCount} ${findingCount === 1 ? 'finding requires' : 'findings require'} attention`;
  }

  const showViewFindings = findingCount > 0 && typeof onViewFindings === 'function';

  return (
    <aside
      role="status"
      aria-live="polite"
      aria-label="Security gate notification"
      style={{
        position: 'fixed',
        bottom: '24px',
        right: '24px',
        width: '360px',
        maxWidth: 'calc(100vw - 48px)',
        backgroundColor: 'var(--bg-surface-elevated)',
        backgroundImage: bgGradient,
        border: `1px solid ${borderColor}`,
        borderLeft: `4px solid ${accentColor}`,
        borderRadius: 'var(--radius-md)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5), 0 2px 8px rgba(0, 0, 0, 0.35)',
        padding: '16px',
        zIndex: 1000,
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
      }}
    >
      {/* Top row: Verdict Header & Close Button */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
        <div>
          <div
            style={{
              fontSize: '12px',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              color: accentColor,
              letterSpacing: '0.8px',
              textTransform: 'uppercase',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span
              style={{
                display: 'inline-block',
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: accentColor,
              }}
            />
            SECURITY GATE: {cleanVerdict}
          </div>
          <div
            style={{
              fontSize: '14px',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginTop: '4px',
            }}
          >
            {subtitle}
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close notification"
          style={{
            color: 'var(--text-muted)',
            fontSize: '18px',
            lineHeight: 1,
            padding: '4px',
            borderRadius: 'var(--radius-sm)',
            cursor: 'pointer',
            transition: 'color 0.15s ease',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
          onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
        >
          ×
        </button>
      </div>

      {/* Description */}
      <div
        style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          lineHeight: 1.4,
        }}
      >
        {description}
      </div>

      {/* Action: View Findings */}
      {showViewFindings && (
        <div style={{ display: 'flex', justifyContent: 'flex-start', marginTop: '2px' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onViewFindings}
            aria-label="View security findings"
            style={{
              fontSize: '11px',
              padding: '5px 12px',
              fontWeight: 600,
              borderColor: borderColor,
              color: 'var(--text-primary)',
            }}
          >
            View Findings
          </button>
        </div>
      )}
    </aside>
  );
}
