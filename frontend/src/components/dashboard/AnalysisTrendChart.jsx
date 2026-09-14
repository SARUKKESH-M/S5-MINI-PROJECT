import React from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';

const trendData = [
  { date: 'Sep 7', analyses: 4, findings: 14 },
  { date: 'Sep 8', analyses: 6, findings: 18 },
  { date: 'Sep 9', analyses: 5, findings: 12 },
  { date: 'Sep 10', analyses: 9, findings: 24 },
  { date: 'Sep 11', analyses: 7, findings: 19 },
  { date: 'Sep 12', analyses: 8, findings: 21 },
  { date: 'Sep 13', analyses: 9, findings: 18 },
];

export default function AnalysisTrendChart({ data = trendData }) {
  const chartData = Array.isArray(data) && data.length > 0 ? data : trendData;

  return (
    <div className="cs-analytics-card">
      <div className="cs-analytics-card-header">
        <h3 className="cs-analytics-card-title">Analysis Trend</h3>
        <div className="cs-trend-legend-pills">
          <span className="cs-trend-pill">
            <span className="cs-trend-pill-dot" style={{ background: '#6366F1' }} />
            <span>Analyses</span>
          </span>
          <span className="cs-trend-pill">
            <span className="cs-trend-pill-dot" style={{ background: '#F59E0B' }} />
            <span>Findings</span>
          </span>
        </div>
      </div>

      <div className="cs-trend-chart-wrapper">
        <ResponsiveContainer width="100%" height={220}>
          <ComposedChart data={chartData} margin={{ top: 12, right: 12, left: -22, bottom: 0 }}>

            <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
            <XAxis
              dataKey="date"
              tickLine={false}
              axisLine={{ stroke: '#E2E8F0' }}
              tick={{ fill: '#64748B', fontSize: 11 }}
            />
            <YAxis
              tickLine={false}
              axisLine={false}
              tick={{ fill: '#94A3B8', fontSize: 11 }}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="cs-chart-tooltip">
                      <div className="cs-tooltip-date">{label}</div>
                      {payload.map((item, idx) => (
                        <div key={idx} className="cs-tooltip-row">
                          <span className="cs-tooltip-swatch" style={{ background: item.color }} />
                          <span className="cs-tooltip-label">{item.name}:</span>
                          <span className="cs-tooltip-val">{item.value}</span>
                        </div>
                      ))}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar
              dataKey="analyses"
              name="Analyses"
              fill="#6366F1"
              radius={[4, 4, 0, 0]}
              barSize={18}
            />
            <Line
              type="monotone"
              dataKey="findings"
              name="Findings"
              stroke="#F59E0B"
              strokeWidth={2.5}
              dot={{ fill: '#F59E0B', r: 3.5, strokeWidth: 1.5, stroke: '#FFFFFF' }}
              activeDot={{ r: 5 }}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
