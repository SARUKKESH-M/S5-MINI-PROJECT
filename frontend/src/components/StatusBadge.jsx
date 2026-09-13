import React from 'react';

export default function StatusBadge({ status, size = 'normal', type = 'default' }) {
  const clean = String(status || 'unknown').toUpperCase();

  let bg = 'rgba(100, 116, 139, 0.15)';
  let color = '#94a3b8';
  let border = 'rgba(100, 116, 139, 0.3)';

  // Security Gate Verdicts
  if (clean === 'ALLOW' || clean === 'PASSED' || clean === 'HEALTHY' || clean === 'ONLINE' || clean === 'READY') {
    bg = 'rgba(16, 185, 129, 0.12)';
    color = '#10b981';
    border = 'rgba(16, 185, 129, 0.3)';
  } else if (clean === 'REVIEW' || clean === 'DEGRADED' || clean === 'WARNING') {
    bg = 'rgba(245, 158, 11, 0.12)';
    color = '#f59e0b';
    border = 'rgba(245, 158, 11, 0.3)';
  } else if (clean === 'BLOCK' || clean === 'BLOCKED' || clean === 'UNAVAILABLE' || clean === 'CRITICAL' || clean === 'OFFLINE' || clean === 'FAILED') {
    bg = 'rgba(239, 68, 68, 0.12)';
    color = '#ef4444';
    border = 'rgba(239, 68, 68, 0.3)';
  } else if (clean === 'HIGH') {
    bg = 'rgba(249, 115, 22, 0.15)';
    color = '#f97316';
    border = 'rgba(249, 115, 22, 0.3)';
  } else if (clean === 'MEDIUM') {
    bg = 'rgba(245, 158, 11, 0.15)';
    color = '#f59e0b';
    border = 'rgba(245, 158, 11, 0.3)';
  } else if (clean === 'LOW') {
    bg = 'rgba(6, 182, 212, 0.15)';
    color = '#06b6d4';
    border = 'rgba(6, 182, 212, 0.3)';
  } else if (clean === 'INFO') {
    bg = 'rgba(100, 116, 139, 0.15)';
    color = '#94a3b8';
    border = 'rgba(100, 116, 139, 0.3)';
  }

  const isLarge = size === 'large';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        padding: isLarge ? '6px 14px' : '2px 8px',
        borderRadius: '4px',
        fontSize: isLarge ? '13px' : '11px',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        letterSpacing: '0.5px',
        whiteSpace: 'nowrap',
      }}
    >
      <span
        style={{
          width: isLarge ? '8px' : '6px',
          height: isLarge ? '8px' : '6px',
          borderRadius: '50%',
          backgroundColor: color,
          display: 'inline-block',
        }}
      />
      {clean}
    </span>
  );
}
