import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import LabelCaps from './LabelCaps';

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: '#ff3b30' },
  high: { label: 'High', color: '#feb700' },
  medium: { label: 'Medium', color: '#00f0ff' },
  low: { label: 'Low', color: '#34c759' },
  info: { label: 'Info', color: '#b9cacb' }
};

export default function SeverityDistributionChart({ data = [], loading = false, error = null }) {
  if (loading) {
    return (
      <div style={{
        height: '240px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-dim)'
      }}>
        <span className="material-symbols-outlined rotating" style={{ fontSize: '24px', color: 'var(--primary-cyan)' }}>
          autorenew
        </span>
        <span>LOADING SEVERITY DATA...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        height: '240px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--secondary-amber)'
      }}>
        Severity data unavailable: {error}
      </div>
    );
  }

  // Filter non-zero entries
  const activeData = data.filter(d => (d.value || 0) > 0);
  const totalFindings = activeData.reduce((acc, d) => acc + (d.value || 0), 0);

  if (activeData.length === 0) {
    return (
      <div style={{
        height: '240px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '6px',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-dim)',
        backgroundColor: 'var(--bg-void-lowest)',
        borderRadius: 'var(--radius-xs)',
        border: '1px dashed var(--border-subtle)'
      }}>
        <span className="material-symbols-outlined" style={{ fontSize: '28px', color: 'var(--status-green)' }}>
          verified_user
        </span>
        <span style={{ fontWeight: 600 }}>NO VULNERABILITIES RECORDED</span>
        <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>All analyzed files pass security thresholds</span>
      </div>
    );
  }

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0];
      const pct = totalFindings > 0 ? ((item.value / totalFindings) * 100).toFixed(1) : 0;
      return (
        <div style={{
          backgroundColor: 'var(--panel-bg)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-xs)',
          padding: '8px 12px',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          boxShadow: '0 4px 16px rgba(0,0,0,0.5)'
        }}>
          <div style={{ color: item.payload.color || 'var(--text-on-surface)', fontWeight: 700, marginBottom: '2px' }}>
            {item.name.toUpperCase()} SEVERITY
          </div>
          <div style={{ color: 'var(--text-on-surface)' }}>
            Findings: <span style={{ fontWeight: 700 }}>{item.value}</span> ({pct}%)
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ height: '180px', position: 'relative' }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={activeData}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
            >
              {activeData.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.color || SEVERITY_CONFIG[entry.name.toLowerCase()]?.color || '#00f0ff'}
                  stroke="var(--bg-void)"
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Center Donut Summary */}
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
          pointerEvents: 'none'
        }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '20px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
            {totalFindings}
          </div>
          <LabelCaps style={{ fontSize: '8px', color: 'var(--text-dim)' }}>TOTAL</LabelCaps>
        </div>
      </div>

      {/* Legend Breakdown */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center' }}>
        {activeData.map(d => (
          <div
            key={d.name}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              padding: '2px 8px',
              backgroundColor: 'var(--bg-void-lowest)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-xs)'
            }}
          >
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: d.color }} />
            <span style={{ color: 'var(--text-on-surface-variant)' }}>{d.name.toUpperCase()}:</span>
            <span style={{ color: 'var(--text-on-surface)', fontWeight: 700 }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
