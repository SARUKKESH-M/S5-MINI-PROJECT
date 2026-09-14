import React, { useState } from 'react';
import StatusBadge from './StatusBadge';

export default function FindingCard({ finding, index, onInspect }) {
  const [expanded, setExpanded] = useState(true);

  if (!finding) return null;

  const severity = finding.severity || 'info';
  const title = finding.title || finding.name || 'Security Finding';
  const category = finding.category || finding.rule_id || null;
  const description = finding.description || null;
  const filePath = finding.file_path || finding.file || null;

  // Extract line number from line_number, line, or evidence array
  const firstEvidence = Array.isArray(finding.evidence) && finding.evidence.length > 0 ? finding.evidence[0] : null;
  const lineNumber = finding.line_number ?? finding.line ?? firstEvidence?.line_start ?? null;

  // Extract AST signal from explicit field or evidence object
  const astSignal = finding.ast_signal || (
    firstEvidence?.signal_name
      ? `${firstEvidence.signal_name}${firstEvidence.signal_type ? ` (${firstEvidence.signal_type})` : ''}`
      : null
  );

  // Safely normalize codeSnippet / evidence to string to prevent object rendering crash
  let evidenceDisplay = null;
  if (typeof finding.code_snippet === 'string' && finding.code_snippet.trim()) {
    evidenceDisplay = finding.code_snippet;
  } else if (Array.isArray(finding.evidence) && finding.evidence.length > 0) {
    evidenceDisplay = finding.evidence.map((ev) => {
      if (typeof ev === 'string') return ev;
      if (typeof ev === 'object' && ev !== null) {
        const parts = [];
        if (ev.line_start) {
          parts.push(`Line ${ev.line_start}${ev.line_end && ev.line_end !== ev.line_start ? `-${ev.line_end}` : ''}`);
        }
        if (ev.signal_name) parts.push(`Signal: ${ev.signal_name}`);
        if (ev.signal_type) parts.push(`Type: ${ev.signal_type}`);
        return parts.length > 0 ? parts.join(' | ') : JSON.stringify(ev);
      }
      return String(ev);
    }).join('\n');
  } else if (typeof finding.evidence === 'string' && finding.evidence.trim()) {
    evidenceDisplay = finding.evidence;
  }

  const remediation = finding.remediation || finding.recommendation || null;
  const confidence = finding.confidence !== undefined ? (
    typeof finding.confidence === 'number'
      ? `${Math.round(finding.confidence * 100)}%`
      : String(finding.confidence)
  ) : null;

  return (
    <div
      className="card"
      style={{
        padding: '16px',
        marginBottom: '12px',
        backgroundColor: 'var(--bg-surface-elevated)',
        border: '1px solid var(--border-default)',
      }}
    >
      {/* Finding Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          cursor: 'pointer',
          gap: '12px',
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
            #{index + 1}
          </span>
          <StatusBadge status={severity} />
          <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
            {title}
          </h4>
          {category && (
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--text-muted)',
                backgroundColor: 'var(--bg-void)',
                padding: '2px 6px',
                borderRadius: '3px',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {category}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {confidence && (
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              CONF: {confidence}
            </span>
          )}
          {onInspect && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '11px', padding: '2px 8px', color: '#4F46E5', borderColor: '#C7D2FE' }}
              onClick={(e) => {
                e.stopPropagation();
                onInspect(finding);
              }}
              aria-label={`Inspect details for ${title}`}
            >
              Inspect Details →
            </button>
          )}
          <button
            type="button"
            style={{ color: 'var(--text-muted)', fontSize: '12px', padding: '2px 6px' }}
            aria-label={expanded ? 'Collapse finding' : 'Expand finding'}
          >
            {expanded ? '▲' : '▼'}
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {/* File location */}
          {(filePath || lineNumber) && (
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
              📍 {filePath || '<source>'}{lineNumber ? `:${lineNumber}` : ''}
            </div>
          )}

          {/* Description */}
          {description && (
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {description}
            </p>
          )}

          {/* Code Snippet Evidence */}
          {evidenceDisplay && (
            <div style={{ marginTop: '4px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Code Evidence
              </div>
              <pre
                style={{
                  backgroundColor: 'var(--bg-void)',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  color: '#f43f5e',
                  overflowX: 'auto',
                }}
              >
                <code>{evidenceDisplay}</code>
              </pre>
            </div>
          )}

          {/* AST Signal */}
          {astSignal && (
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              <strong style={{ color: 'var(--text-secondary)' }}>AST Signal:</strong> {astSignal}
            </div>
          )}

          {/* Remediation */}
          {remediation && (
            <div
              style={{
                backgroundColor: 'rgba(56, 189, 248, 0.08)',
                border: '1px solid rgba(56, 189, 248, 0.2)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 14px',
                marginTop: '4px',
              }}
            >
              <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--accent-blue)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Remediation
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                {remediation}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
