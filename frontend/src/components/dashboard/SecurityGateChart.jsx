import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const decisionData = [
  { name: 'Block', value: 18, color: '#EF4444' },
  { name: 'Review', value: 9, color: '#F59E0B' },
  { name: 'Allow', value: 21, color: '#10B981' },
];

export default function SecurityGateChart({ data = decisionData, total = 48 }) {
  const chartData = Array.isArray(data) && data.length > 0 ? data : decisionData;
  const totalCount = typeof total === 'number' ? total : 48;

  return (
    <div className="cs-analytics-card">
      <div className="cs-analytics-card-header">
        <h3 className="cs-analytics-card-title">Security Gate Decisions</h3>
      </div>

      <div className="cs-donut-chart-container">
        <div className="cs-donut-chart-wrapper">
          <ResponsiveContainer width="100%" height={190}>
            <PieChart>
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const itemData = payload[0];
                    return (
                      <div className="cs-chart-tooltip">
                        <span className="cs-tooltip-swatch" style={{ background: itemData.payload.color }} />
                        <span className="cs-tooltip-label">{itemData.name}:</span>
                        <span className="cs-tooltip-val">{itemData.value}</span>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={56}
                outerRadius={78}
                paddingAngle={4}
                dataKey="value"
                strokeWidth={0}
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>

          {/* Centered Donut Label */}
          <div className="cs-donut-center-label">
            <span className="cs-donut-count">{totalCount}</span>
            <span className="cs-donut-caption">Analyses</span>
          </div>
        </div>

        {/* Legend */}
        <div className="cs-chart-legend cs-legend-decisions">
          {chartData.map((item) => (
            <div key={item.name} className="cs-legend-item">
              <div className="cs-legend-left">
                <span className="cs-legend-bullet" style={{ background: item.color }} />
                <span className="cs-legend-name">{item.name}</span>
              </div>
              <span className="cs-legend-value">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
