import React from 'react';
import { ShieldCheckIcon } from './Icons';

export default function ProductionStatus({ status = null }) {
  const isHealthy = status?.isHealthy !== false;
  const title = status?.title || (isHealthy ? 'Production Backend Verified' : 'Backend Degraded');
  const desc = status?.description || (isHealthy ? 'CodeSentinel v1.1.0 is live and secure.' : 'Backend connection unavailable.');
  const iconColor = isHealthy ? '#16A34A' : '#EF4444';

  return (
    <div className="cs-panel-production-card">
      <div className="cs-prod-status-icon-badge">
        <ShieldCheckIcon size={20} color={iconColor} />
      </div>
      <div className="cs-prod-status-text-block">
        <div className="cs-prod-status-title">{title}</div>
        <div className="cs-prod-status-desc">{desc}</div>
      </div>
    </div>
  );
}
