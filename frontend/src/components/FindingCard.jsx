import React, { useState } from 'react';
import StatusBadge from './StatusBadge';
import { getFindingTaxonomy, getRemediationGuidance } from '../utils/securityTaxonomy';

const FindingCard = React.memo(function FindingCard({ finding, index, onInspect }) {
  const [expanded, setExpanded] = useState(true);

  if (!finding) return null;

  const severity = finding.severity || 'info';
  const title = finding.title || finding.name || 'Security Finding';
  const category = finding.category || finding.rule_id || null;
  const description = finding.description || null;
  const filePath = finding.file_path || finding.file || null;

  // Grounded taxonomy resolution (memoized via WeakMap in securityTaxonomy)
  const taxonomy = getFindingTaxonomy(finding);

  // Extract primary line number from line_number, line, or evidence array
  const rawEvidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  const firstEvidence = rawEvidence.length > 0 ? rawEvidence[0] : null;
  const lineNumber = finding.line_number ?? finding.line ?? firstEvidence?.line_start ?? null;

  // Extract primary AST signal from explicit field or evidence object
  const astSignal = finding.ast_signal || (
    firstEvidence?.signal_name
      ? `${firstEvidence.signal_name}${firstEvidence.signal_type ? ` (${firstEvidence.signal_type})` : ''}`
      : (firstEvidence?.signal_type || null)
  );

  // Code snippet display if provided
  const codeSnippet = typeof finding.code_snippet === 'string' && finding.code_snippet.trim()
    ? finding.code_snippet.trim()
    : null;

  // Authoritative remediation guidance
  const remediationInfo = getRemediationGuidance(finding);

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
      {/* Finding Header Container (No nested interactive elements) */}
      <div
        className="cs-finding-card-header"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        {/* Semantic Expand/Collapse Button Control */}
        <button
          type="button"
          className="cs-finding-expand-trigger"
          aria-expanded={expanded}
          onClick={() => setExpanded((prev) => !prev)}
          aria-label={`${expanded ? 'Collapse' : 'Expand'} finding: ${title}`}
          style={{
            background: 'transparent',
            border: 'none',
            padding: '4px 6px',
            margin: '-4px -6px',
            textAlign: 'left',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            flexWrap: 'wrap',
            flex: '1 1 auto',
            font: 'inherit',
            color: 'inherit',
            borderRadius: '4px',
          }}
        >
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
            #{index + 1}
          </span>
          <StatusBadge status={severity} />
          <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
            {title}
          </h4>

          {/* Mapped CWE Badge */}
          {taxonomy.cweId && (
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                fontWeight: 600,
                color: '#4F46E5',
                backgroundColor: '#EEF2FF',
                padding: '2px 6px',
                borderRadius: '3px',
                border: '1px solid #C7D2FE',
              }}
              title={taxonomy.cweName || taxonomy.cweId}
            >
              {taxonomy.cweId}
            </span>
          )}

          {/* Mapped OWASP Category Badge */}
          {taxonomy.owasp && (
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '10px',
                color: 'var(--text-muted)',
                backgroundColor: 'var(--bg-void)',
                padding: '2px 6px',
                borderRadius: '3px',
                border: '1px solid var(--border-subtle)',
              }}
              title={taxonomy.owasp}
            >
              {taxonomy.owasp.split('-')[0]}
            </span>
          )}

          {/* Raw Category */}
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

          {/* Expand/Collapse Chevron Indicator */}
          <span
            style={{
              color: 'var(--text-muted)',
              fontSize: '12px',
              padding: '0 4px',
              marginLeft: 'auto',
            }}
            aria-hidden="true"
          >
            {expanded ? '▲' : '▼'}
          </span>
        </button>

        {/* Independent Actions (Sibling controls, WCAG 4.1.2 compliant) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
          {confidence && (
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              CONF: {confidence}
            </span>
          )}
          {onInspect && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '11px', padding: '4px 10px', color: '#4F46E5', borderColor: '#C7D2FE' }}
              onClick={() => onInspect(finding)}
              aria-label={`Inspect details for ${title}`}
            >
              Inspect Details →
            </button>
          )}
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
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              {description}
            </p>
          )}

          {/* Structured AST Evidence Rows */}
          {rawEvidence.length > 0 && (
            <div style={{ marginTop: '4px' }}>
              <div
                style={{
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  marginBottom: '6px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  fontWeight: 600,
                }}
              >
                Supporting AST Evidence ({rawEvidence.length} item{rawEvidence.length > 1 ? 's' : ''})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {rawEvidence.map((ev, evIdx) => {
                  if (typeof ev === 'string') {
                    return (
                      <div
                        key={evIdx}
                        style={{
                          backgroundColor: 'var(--bg-void)',
                          padding: '6px 10px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border-subtle)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11.5px',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {ev}
                      </div>
                    );
                  }
                  if (typeof ev === 'object' && ev !== null) {
                    const lineText = ev.line_start
                      ? `Lines ${ev.line_start}${ev.line_end && ev.line_end !== ev.line_start ? `-${ev.line_end}` : ''}`
                      : null;
                    const docId = ev.document_id || filePath || null;
                    const sink = ev.signal_name || null;
                    const sigType = ev.signal_type || null;

                    return (
                      <div
                        key={evIdx}
                        style={{
                          backgroundColor: 'var(--bg-void)',
                          padding: '8px 12px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border-subtle)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11.5px',
                          display: 'flex',
                          flexWrap: 'wrap',
                          gap: '10px',
                          alignItems: 'center',
                        }}
                      >
                        {docId && (
                          <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>
                            {docId}
                          </span>
                        )}
                        {lineText && (
                          <span style={{ color: 'var(--text-muted)' }}>
                            {lineText}
                          </span>
                        )}
                        {sink && (
                          <span>
                            <strong style={{ color: 'var(--text-secondary)' }}>Trigger Symbol:</strong>{' '}
                            <code style={{ color: '#DC2626', backgroundColor: 'rgba(239, 68, 68, 0.08)', padding: '1px 4px', borderRadius: '2px' }}>
                              {sink}
                            </code>
                          </span>
                        )}
                        {sigType && (
                          <span style={{ color: 'var(--text-dim)', fontSize: '10.5px' }}>
                            ({sigType})
                          </span>
                        )}
                      </div>
                    );
                  }
                  return null;
                })}
              </div>
            </div>
          )}

          {/* Source Code Snippet Evidence (if available in finding) */}
          {codeSnippet && (
            <div style={{ marginTop: '4px' }}>
              <div
                style={{
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  marginBottom: '4px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  fontWeight: 600,
                }}
              >
                Code Snippet
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
                  margin: 0,
                }}
              >
                <code>{codeSnippet}</code>
              </pre>
            </div>
          )}

          {/* AST Signal summary if rawEvidence was empty */}
          {astSignal && rawEvidence.length === 0 && (
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              <strong style={{ color: 'var(--text-secondary)' }}>AST Signal:</strong> {astSignal}
            </div>
          )}

          {/* Authoritative Remediation Guidance */}
          {remediationInfo && (
            <div
              style={{
                backgroundColor: 'rgba(56, 189, 248, 0.08)',
                border: '1px solid rgba(56, 189, 248, 0.2)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 14px',
                marginTop: '4px',
              }}
            >
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: 'var(--accent-blue)',
                  marginBottom: '4px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span>Remediation Guidance</span>
                {!remediationInfo.isSpecific && (
                  <span
                    style={{
                      fontSize: '9.5px',
                      color: 'var(--text-muted)',
                      textTransform: 'none',
                      fontWeight: 500,
                    }}
                  >
                    (General Best Practice)
                  </span>
                )}
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {remediationInfo.text}
              </div>
              {remediationInfo.disclaimer && (
                <div
                  style={{
                    fontSize: '11px',
                    color: 'var(--text-muted)',
                    marginTop: '6px',
                    fontStyle: 'italic',
                  }}
                >
                  ℹ️ {remediationInfo.disclaimer}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
});

export default FindingCard;
