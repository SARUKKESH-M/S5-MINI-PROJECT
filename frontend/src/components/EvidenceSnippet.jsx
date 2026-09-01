import React from 'react';
import LabelCaps from './LabelCaps';

export default function EvidenceSnippet({ documentId, lineStart, lineEnd, signalType, signalName, snippetLines = [] }) {
  return (
    <div className="evidence-snippet">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--primary-cyan)' }}>
            description
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600 }}>
            {documentId || 'FILE_PATH_PLACEHOLDER'}
          </span>
        </div>
        <LabelCaps style={{ fontSize: '10px' }}>
          LINES {lineStart || 1}-{lineEnd || 1}
        </LabelCaps>
      </div>

      {(signalType || signalName) && (
        <div style={{ display: 'flex', gap: '12px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
          {signalType && <span>SIGNAL: <strong>{signalType}</strong></span>}
          {signalName && <span>NAME: <strong>{signalName}</strong></span>}
        </div>
      )}

      {snippetLines.length > 0 && (
        <div style={{ marginTop: '4px' }}>
          <pre style={{
            margin: 0,
            padding: '8px 12px',
            backgroundColor: 'var(--bg-void-lowest)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-on-surface)',
            overflowX: 'auto'
          }}>
            {snippetLines.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}
