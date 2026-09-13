import React from 'react';
import StatusBadge from './StatusBadge';

export default function HealthCard({ title, status, details, latencyMs = null }) {
  return (
    <div
      className="card"
      style={{
        padding: '16px',
        backgroundColor: 'var(--bg-surface-elevated)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        gap: '10px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span
          style={{
            fontSize: '12px',
            fontWeight: 600,
            color: 'var(--text-secondary)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {title}
        </span>
        <StatusBadge status={status} />
      </div>

      {details && (
        <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.4 }}>
          {details}
        </div>
      )}

      {latencyMs !== null && (
        <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
          LATENCY: {latencyMs} ms
        </div>
      )}
    </div>
  );
}
