import React from 'react';
import {
  RepositoriesIcon,
  AnalyzeIcon,
  VulnerabilitiesIcon,
  ShieldAlertIcon,
  TrendingUpIcon,
} from './Icons';

const metricsData = [
  {
    id: 'repositories',
    title: 'Total Repositories',
    value: '12',
    trend: '+20% from last month',
    icon: RepositoriesIcon,
    colorScheme: 'indigo',
  },
  {
    id: 'analyses',
    title: 'Total Analyses',
    value: '48',
    trend: '+32% from last month',
    icon: AnalyzeIcon,
    colorScheme: 'blue',
  },
  {
    id: 'findings',
    title: 'Total Findings',
    value: '126',
    trend: '+12% from last month',
    icon: VulnerabilitiesIcon,
    colorScheme: 'amber',
  },
  {
    id: 'blocked',
    title: 'Blocked',
    value: '18',
    trend: '+5% from last month',
    icon: ShieldAlertIcon,
    colorScheme: 'rose',
  },
];

export default function MetricCardsGrid({ metrics = null }) {
  const cards = metricsData.map((item) => {
    let cardValue = item.value;
    let cardTrend = item.trend;

    if (metrics) {
      if (item.id === 'repositories' && metrics.repositories !== undefined) {
        cardValue = metrics.repositories;
        if (metrics.trendPercentages?.repositories) {
          cardTrend = metrics.trendPercentages.repositories;
        }
      } else if (item.id === 'analyses' && metrics.analyses !== undefined) {
        cardValue = metrics.analyses;
        if (metrics.trendPercentages?.analyses) {
          cardTrend = metrics.trendPercentages.analyses;
        }
      } else if (item.id === 'findings' && metrics.findings !== undefined) {
        cardValue = metrics.findings;
        if (metrics.trendPercentages?.findings) {
          cardTrend = metrics.trendPercentages.findings;
        }
      } else if (item.id === 'blocked' && metrics.blocked !== undefined) {
        cardValue = metrics.blocked;
        if (metrics.trendPercentages?.blocked) {
          cardTrend = metrics.trendPercentages.blocked;
        }
      }
    }

    return { ...item, value: cardValue, trend: cardTrend };
  });

  return (
    <div className="cs-metrics-grid">
      {cards.map((item) => {
        const Icon = item.icon;
        return (
          <div key={item.id} className={`cs-metric-card cs-metric-${item.colorScheme}`}>
            <div className="cs-metric-card-top">
              <span className="cs-metric-title">{item.title}</span>
              <div className={`cs-metric-icon-badge cs-badge-${item.colorScheme}`}>
                <Icon size={18} />
              </div>
            </div>

            <div className="cs-metric-value">{item.value}</div>

            <div className="cs-metric-trend-row">
              <span className="cs-trend-badge">
                <TrendingUpIcon size={13} color="#10B981" />
                <span className="cs-trend-text">{item.trend}</span>
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
