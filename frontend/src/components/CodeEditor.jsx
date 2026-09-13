import React from 'react';

export default function CodeEditor({
  value,
  onChange,
  placeholder = 'Paste or type Python code here...',
  disabled = false,
  minHeight = '320px',
}) {
  const lineCount = value ? value.split('\n').length : 1;
  const charCount = value ? value.length : 0;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-default)',
        backgroundColor: 'var(--bg-void)',
        overflow: 'hidden',
      }}
    >
      {/* Editor Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 14px',
          backgroundColor: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border-subtle)',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          color: 'var(--text-muted)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#38bdf8' }} />
          <span>source.py</span>
          <span style={{ color: 'var(--text-dim)' }}>|</span>
          <span style={{ color: 'var(--accent-blue)' }}>Python AST Engine</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span>{lineCount} {lineCount === 1 ? 'line' : 'lines'}</span>
          <span>{charCount} chars</span>
        </div>
      </div>

      {/* Editor Area */}
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        spellCheck="false"
        style={{
          width: '100%',
          minHeight: minHeight,
          padding: '14px',
          backgroundColor: 'transparent',
          border: 'none',
          outline: 'none',
          color: '#e2e8f0',
          fontFamily: 'var(--font-mono)',
          fontSize: '13px',
          lineHeight: '1.6',
          resize: 'vertical',
          boxSizing: 'border-box',
          tabSize: 4,
        }}
      />
    </div>
  );
}
