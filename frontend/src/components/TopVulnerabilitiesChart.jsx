import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

export default function TopVulnerabilitiesChart({ data = [], loading = false, error = null }) {
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
        <span>LOADING VULNERABILITY DATA...</span>
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
        Analytics data unavailable: {error}
      </div>
    );
  }

  if (!data || data.length === 0) {
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
        <span className="material-symbols-outlined" style={{ fontSize: '28px', color: 'var(--primary-cyan)' }}>
          security
        </span>
        <span style={{ fontWeight: 600 }}>NO VULNERABILITY PATTERNS DETECTED</span>
        <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Zero security findings across recent analyses</span>
      </div>
    );
  }

  // Format labels to shorten if very long
  const formattedData = data.map(item => ({
    ...item,
    displayName: item.name.length > 24 ? item.name.substring(0, 22) + '…' : item.name
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
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
          <div style={{ color: 'var(--primary-cyan)', fontWeight: 700, marginBottom: '2px' }}>
            {item.name}
          </div>
          <div style={{ color: 'var(--text-on-surface)' }}>
            Occurrences: <span style={{ fontWeight: 700 }}>{item.count}</span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ width: '100%', height: '220px' }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={formattedData}
          layout="vertical"
          margin={{ top: 5, right: 30, left: 10, bottom: 5 }}
        >
          <XAxis
            type="number"
            allowDecimals={false}
            tick={{ fill: 'var(--text-dim)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
            stroke="var(--border-subtle)"
          />
          <YAxis
            type="category"
            dataKey="displayName"
            width={140}
            tick={{ fill: 'var(--text-on-surface-variant)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
            stroke="var(--border-subtle)"
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar
            dataKey="count"
            radius={[0, 4, 4, 0]}
          >
            {formattedData.map((entry, index) => (
              <Cell
                key={`bar-cell-${index}`}
                fill={index === 0 ? 'var(--critical-red)' : index === 1 ? 'var(--secondary-amber)' : 'var(--primary-cyan)'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
