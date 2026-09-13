import React from 'react';

export default function StatCard({
  label,
  value,
  subtext,
  badge,
  accent = 'default',
  style = {}
}) {
  let accentBorder = 'var(--border-subtle)';
  if (accent === 'allow') accentBorder = 'var(--verdict-allow-border)';
  if (accent === 'review') accentBorder = 'var(--verdict-review-border)';
  if (accent === 'block') accentBorder = 'var(--verdict-block-border)';
  if (accent === 'blue') accentBorder = 'rgba(56, 189, 248, 0.4)';

  return (
    <div
      className="card"
      style={{
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        borderColor: accentBorder,
        ...style
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <span style={{
          fontSize: '11px',
          fontWeight: 600,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.75px',
          fontFamily: 'var(--font-mono)'
        }}>
          {label}
        </span>
        {badge}
      </div>

      <div style={{
        fontSize: '24px',
        fontWeight: 700,
        color: 'var(--text-primary)',
        fontFamily: 'var(--font-mono)',
        letterSpacing: '-0.5px',
        marginBottom: '6px'
      }}>
        {value}
      </div>

      {subtext && (
        <div style={{
          fontSize: '12px',
          color: 'var(--text-muted)',
          display: 'flex',
          alignItems: 'center',
          gap: '6px'
        }}>
          {subtext}
        </div>
      )}
    </div>
  );
}
