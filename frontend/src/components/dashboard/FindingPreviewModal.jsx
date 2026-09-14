import React, { useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { CodeFileIcon } from './Icons';
import StatusBadge from '../StatusBadge';

export default function FindingPreviewModal({
  isOpen = false,
  onClose,
  finding = null,
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const dialogRef = useRef(null);
  const closeBtnRef = useRef(null);
  const previousFocusRef = useRef(null);

  // Focus trap, Escape key support, and focus restoration
  useEffect(() => {
    if (!isOpen) return;

    // Save previous focus trigger
    previousFocusRef.current = document.activeElement;

    // Focus close button on mount
    const timer = setTimeout(() => {
      closeBtnRef.current?.focus();
    }, 50);

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose?.();
        return;
      }

      if (e.key === 'Tab' && dialogRef.current) {
        const focusable = dialogRef.current.querySelectorAll(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('keydown', handleKeyDown);
      if (previousFocusRef.current && typeof previousFocusRef.current.focus === 'function') {
        previousFocusRef.current.focus();
      }
    };
  }, [isOpen, onClose]);

  if (!isOpen || !finding) return null;

  const title = finding.title || finding.name || 'Security Vulnerability';
  const severity = (finding.severity || 'Medium').toUpperCase();
  const sevKey = (finding.sevKey || finding.severity || 'medium').toLowerCase();
  const category = finding.category || finding.rule_id || null;
  const findingId = finding.finding_id || null;

  // Primary evidence extraction
  const primaryEv = Array.isArray(finding.evidence) && finding.evidence.length > 0 ? finding.evidence[0] : null;
  const rawPath = finding.fileLocation || finding.file_path || finding.file || primaryEv?.document_id || '—';
  const lineStart = finding.line_number ?? finding.line ?? primaryEv?.line_start ?? null;
  const lineEnd = primaryEv?.line_end ?? null;
  const colStart = finding.column ?? primaryEv?.column_start ?? null;

  const fileLocation = finding.fileLocation || (
    rawPath !== '—'
      ? `${rawPath}${lineStart ? `:${lineStart}${lineEnd && lineEnd !== lineStart ? `-${lineEnd}` : ''}${colStart ? `:${colStart}` : ''}` : ''}`
      : '—'
  );

  const confidence = finding.confidence !== undefined ? (
    typeof finding.confidence === 'number'
      ? `${Math.round(finding.confidence * 100)}%`
      : String(finding.confidence)
  ) : null;

  const description = finding.description || 'Potential security issue identified by CodeSentinel automated inspection engine.';

  // AST signals / Evidence details
  const astSignal = finding.ast_signal || (
    primaryEv?.signal_name
      ? `${primaryEv.signal_name}${primaryEv.signal_type ? ` (${primaryEv.signal_type})` : ''}`
      : (primaryEv?.signal_type || null)
  );
  const sinkName = primaryEv?.sink_name || null;
  const scope = primaryEv?.scope || primaryEv?.function_name || null;

  // Safe Code Snippet (Strictly no raw source retrieval)
  let codeSnippetLines = null;
  if (Array.isArray(finding.codeSnippet)) {
    codeSnippetLines = finding.codeSnippet;
  } else if (typeof finding.code_snippet === 'string' && finding.code_snippet.trim()) {
    codeSnippetLines = finding.code_snippet.split('\n').map((line, idx) => ({
      lineNum: lineStart ? Number(lineStart) + idx : idx + 1,
      code: line,
      isHighlighted: idx === 0,
    }));
  } else if (primaryEv && typeof primaryEv.code_snippet === 'string' && primaryEv.code_snippet.trim()) {
    codeSnippetLines = primaryEv.code_snippet.split('\n').map((line, idx) => ({
      lineNum: lineStart ? Number(lineStart) + idx : idx + 1,
      code: line,
      isHighlighted: idx === 0,
    }));
  }

  // Remediation
  const remediation = finding.remediation || finding.recommendation || null;

  const isAlreadyInHistory = location.pathname.startsWith('/history');
  const isAlreadyInReviews = location.pathname.startsWith('/reviews');

  return (
    <div
      className="cs-modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="cs-modal-title"
    >
      <div
        ref={dialogRef}
        className="cs-modal-dialog"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '680px' }}
      >
        {/* Modal Header */}
        <div className="cs-modal-header">
          <div className="cs-modal-header-left" style={{ gap: '10px', flexWrap: 'wrap' }}>
            <h3 id="cs-modal-title" className="cs-modal-title">Finding Inspection</h3>
            <StatusBadge status={severity} />
            {finding.is_false_positive ? (
              <span
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: '#4338CA',
                  backgroundColor: '#EEF2FF',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  border: '1px solid #C7D2FE',
                }}
              >
                ✓ SUPPRESSED
              </span>
            ) : (
              <span
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: '#B91C1C',
                  backgroundColor: '#FEF2F2',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  border: '1px solid #FECACA',
                }}
              >
                ● OPEN
              </span>
            )}
            {category && (
              <span
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  color: '#64748B',
                  backgroundColor: '#F1F5F9',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  border: '1px solid #CBD5E1',
                }}
              >
                {category}
              </span>
            )}
          </div>
          <button
            ref={closeBtnRef}
            type="button"
            className="cs-modal-close-btn"
            onClick={onClose}
            aria-label="Close finding modal"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="cs-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Finding Title & ID */}
          <div>
            <div className="cs-modal-finding-name">{title}</div>
            {findingId && (
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B', marginTop: '2px' }}>
                Finding ID: <code style={{ color: '#475569' }}>{findingId}</code>
              </div>
            )}
          </div>

          {/* Location & Confidence */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '8px',
              padding: '8px 12px',
              backgroundColor: '#F8FAFC',
              borderRadius: '6px',
              border: '1px solid #E2E8F0',
            }}
          >
            <div className="cs-preview-file-loc" style={{ margin: 0 }}>
              <CodeFileIcon size={15} color="#64748B" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, color: '#0284C7' }}>
                {fileLocation}
              </span>
            </div>
            {confidence && (
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                Confidence: <strong style={{ color: '#0F172A' }}>{confidence}</strong>
              </div>
            )}
          </div>

          {/* AST / Evidence Metadata */}
          {(astSignal || sinkName || scope) && (
            <div
              style={{
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                color: '#475569',
                backgroundColor: '#F1F5F9',
                padding: '10px 14px',
                borderRadius: '6px',
                border: '1px solid #CBD5E1',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
            >
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#334155', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Authoritative AST Evidence
              </div>
              {astSignal && <div><strong>Rule / Signal:</strong> {astSignal}</div>}
              {sinkName && <div><strong>Sink Target:</strong> {sinkName}</div>}
              {scope && <div><strong>Scope:</strong> {scope}</div>}
            </div>
          )}

          {/* Code Snippet Box (Zero-Trust Security Compliant: strictly no raw source fetching) */}
          <div className="cs-preview-code-block" style={{ margin: 0 }}>
            <div className="cs-code-block-banner">
              <span>{codeSnippetLines ? 'ILLUSTRATIVE CONTEXT SNIPPET' : 'SOURCE CONTEXT'}</span>
            </div>
            {codeSnippetLines ? (
              codeSnippetLines.map((line, idx) => (
                <div
                  key={idx}
                  className={`cs-code-line ${line.isHighlighted ? 'cs-code-line-highlight' : ''}`}
                >
                  <span className="cs-line-num">{line.lineNum}</span>
                  <span className="cs-code-content">{line.code}</span>
                </div>
              ))
            ) : (
              <div
                style={{
                  padding: '14px 16px',
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)',
                  color: '#94A3B8',
                  fontStyle: 'italic',
                }}
              >
                Source preview unavailable (no code snippet was recorded for this finding. Raw source retrieval is disabled by security policy).
              </div>
            )}
          </div>

          {/* Risk Explanation */}
          <div className="cs-preview-danger-box" style={{ margin: 0 }}>
            <div className="cs-danger-label">Risk Explanation & Impact</div>
            <p className="cs-danger-desc" style={{ margin: 0, fontSize: '13px', lineHeight: 1.5 }}>
              {description}
            </p>
          </div>

          {/* Remediation Guidance */}
          <div
            style={{
              backgroundColor: remediation ? 'rgba(56, 189, 248, 0.08)' : '#F8FAFC',
              border: `1px solid ${remediation ? 'rgba(56, 189, 248, 0.25)' : '#E2E8F0'}`,
              borderRadius: '6px',
              padding: '12px 14px',
            }}
          >
            <div
              style={{
                fontSize: '11px',
                fontWeight: 700,
                color: remediation ? '#0284C7' : '#64748B',
                marginBottom: '4px',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}
            >
              Remediation Guidance
            </div>
            <div style={{ fontSize: '13px', color: remediation ? '#334155' : '#94A3B8', lineHeight: 1.5 }}>
              {remediation || 'No specific remediation guidance was recorded for this rule.'}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="cs-modal-footer">
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onClose}
          >
            Close
          </button>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {!isAlreadyInReviews && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  onClose?.();
                  navigate('/reviews', { state: { analysisId: finding.analysis_id } });
                }}
                style={{ color: '#4F46E5', borderColor: '#C7D2FE' }}
              >
                Security Review →
              </button>
            )}
            {!isAlreadyInHistory && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  onClose?.();
                  navigate('/history');
                }}
              >
                Audit in History
              </button>
            )}
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                onClose?.();
                navigate('/analyze');
              }}
            >
              Inspect in Analyze
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
