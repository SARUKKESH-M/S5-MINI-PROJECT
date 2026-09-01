import React from 'react';

export default function SeverityBadge({ severity = 'info' }) {
  const normSeverity = String(severity).toLowerCase();
  
  const iconMap = {
    critical: 'gpp_bad',
    high: 'warning',
    medium: 'error_outline',
    low: 'info',
    info: 'help_outline'
  };

  const iconName = iconMap[normSeverity] || 'help_outline';

  return (
    <span className={`severity-badge severity-${normSeverity}`}>
      <span className="material-symbols-outlined" style={{ fontSize: '13px' }}>
        {iconName}
      </span>
      {normSeverity}
    </span>
  );
}
