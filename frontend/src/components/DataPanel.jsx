import React from 'react';
import LabelCaps from './LabelCaps';
import StatusPip from './StatusPip';

export default function DataPanel({ title, status, action, children, style = {} }) {
  return (
    <section className="sentinel-panel" style={style}>
      {(title || action || status) && (
        <div className="sentinel-panel-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {status && <StatusPip status={status} />}
            {title && <LabelCaps>{title}</LabelCaps>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
