import React from 'react';
import { ShieldAlertIcon } from './Icons';

export default function SecurityGateCard({ gate = 'BLOCK' }) {
  const normGate = String(gate || 'BLOCK').toUpperCase();
  const isAllow = normGate === 'ALLOW';
  const isReview = normGate === 'REVIEW';

  const title = `Security Gate: ${normGate}`;
  const desc = isAllow
    ? 'All automated security checks passed. Safe for production deployment.'
    : isReview
    ? 'Security findings require manual team review before deployment.'
    : 'This repository contains security vulnerabilities that must be addressed before deployment.';

  const iconColor = isAllow ? '#16A34A' : isReview ? '#D97706' : '#DC2626';

  return (
    <div className="cs-panel-security-card">
      <div className="cs-panel-gate-header">
        <div className="cs-gate-icon-badge">
          <ShieldAlertIcon size={18} color={iconColor} />
        </div>
        <span className="cs-gate-card-title">{title}</span>
      </div>
      <p className="cs-gate-card-desc">{desc}</p>
    </div>
  );
}
