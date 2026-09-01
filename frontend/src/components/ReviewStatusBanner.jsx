import React from 'react';

export default function ReviewStatusBanner({ reviewStatus = 'allow', title, details }) {
  const normStatus = String(reviewStatus).toLowerCase();
  
  const displayMap = {
    allow: { label: 'PASSED (ALLOW)', icon: 'check_circle', class: 'review-status-allow' },
    block: { label: 'BLOCKED (BLOCK)', icon: 'block', class: 'review-status-block' },
    review: { label: 'REVIEW NEEDED', icon: 'rate_review', class: 'review-status-review' }
  };

  const statusInfo = displayMap[normStatus] || displayMap.allow;

  return (
    <div className={`review-status-banner ${statusInfo.class}`}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>
          {statusInfo.icon}
        </span>
        <span>{title || statusInfo.label}</span>
      </div>
      {details && (
        <span style={{ fontSize: '11px', opacity: 0.8, textTransform: 'none' }}>
          {details}
        </span>
      )}
    </div>
  );
}
