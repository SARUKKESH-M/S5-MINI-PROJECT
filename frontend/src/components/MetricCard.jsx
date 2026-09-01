import React from 'react';
import LabelCaps from './LabelCaps';

export default function MetricCard({ label, value, delta, accentColor = 'cyan' }) {
  const accentMap = {
    cyan: 'var(--primary-cyan)',
    amber: 'var(--secondary-amber)',
    red: 'var(--critical-red)',
    green: 'var(--status-green)',
    dim: 'var(--border-default)'
  };

  const color = accentMap[accentColor] || accentMap.cyan;

  return (
    <div className="metric-card">
      <div className="metric-card-accent-top" style={{ backgroundColor: color }} />
      <LabelCaps>{label}</LabelCaps>
      <div className="metric-card-value">{value}</div>
      {delta && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
          {delta}
        </div>
      )}
    </div>
  );
}
