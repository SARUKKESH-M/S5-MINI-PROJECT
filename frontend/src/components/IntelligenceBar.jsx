import React from 'react';
import StatusPip from './StatusPip';

export default function IntelligenceBar() {
  return (
    <header className="intelligence-bar">
      {/* CLI Terminal Search Prompt */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, maxWidth: '640px' }}>
        <span style={{ color: 'var(--primary-cyan)', fontWeight: 'bold', fontSize: '15px' }}>&gt;</span>
        <input
          type="text"
          placeholder="SEARCH SECURITY FINDINGS, REPOSITORIES, OR CLI COMMANDS..."
          style={{
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: 'var(--text-on-surface)',
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
            width: '100%'
          }}
          readOnly
        />
      </div>

      {/* Health Indicator & System Version Metadata */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: 'var(--text-on-surface-variant)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <StatusPip status="green" title="Engine Status: Operational" />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>SENTINEL OS v1.0</span>
        </div>
        <div style={{ borderLeft: '1px solid var(--border-subtle)', height: '16px' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)' }}>
          MOCK PROVIDER
        </span>
      </div>
    </header>
  );
}
