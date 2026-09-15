import React, { useEffect, useRef } from 'react';
import StatusBadge from '../StatusBadge';

/**
 * SecurityCriticalModal
 * Informational / Review modal for inspecting critical security events (e.g., BLOCK verdict).
 * Strictly preserves Step 6O backend gate authority; never provides override controls.
 */
export default function SecurityCriticalModal({
  isOpen = false,
  onClose,
  title = 'Critical Security Notice',
  verdict = 'BLOCK',
  reason,
  criticalCount = 0,
  details = [],
  actionLabel = 'Acknowledge & Close',
  onAction,
}) {
  const closeBtnRef = useRef(null);
  const modalRef = useRef(null);
  const previousFocusRef = useRef(null);

  useEffect(() => {
    if (!isOpen) return;

    previousFocusRef.current = document.activeElement;

    const timer = setTimeout(() => {
      closeBtnRef.current?.focus();
    }, 40);

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }

      if (e.key === 'Tab' && modalRef.current) {
        const focusable = modalRef.current.querySelectorAll(
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

  if (!isOpen) return null;

  const isBlock = String(verdict).toUpperCase() === 'BLOCK';

  return (
    <div
      className="cs-modal-backdrop"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.75)',
        backdropFilter: 'blur(4px)',
        zIndex: 1100,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
      }}
      onClick={onClose}
      role="presentation"
    >
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-modal-title"
        aria-describedby="security-modal-desc"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '540px',
          maxWidth: '100%',
          backgroundColor: 'var(--bg-card, #FFFFFF)',
          borderRadius: '8px',
          border: `1.5px solid ${isBlock ? '#EF4444' : '#F59E0B'}`,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.35)',
          padding: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '24px' }} aria-hidden="true">
              {isBlock ? '⛔' : '⚠️'}
            </span>
            <h2
              id="security-modal-title"
              style={{
                fontSize: '18px',
                fontWeight: 700,
                color: isBlock ? '#EF4444' : 'var(--text-primary)',
                margin: 0,
              }}
            >
              {title}
            </h2>
          </div>

          <StatusBadge status={verdict} size="large" />
        </div>

        <div
          id="security-modal-desc"
          style={{
            fontSize: '13px',
            color: 'var(--text-primary)',
            lineHeight: 1.5,
            marginBottom: '16px',
          }}
        >
          {reason || (
            isBlock
              ? 'Authoritative Step 6O Security Gate has issued a BLOCK verdict. High-severity security hazards must be resolved prior to production release.'
              : 'Security analysis identified issues requiring formal review before merging.'
          )}
        </div>

        {criticalCount > 0 && (
          <div
            style={{
              padding: '10px 14px',
              backgroundColor: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              borderRadius: '6px',
              marginBottom: '16px',
              fontSize: '12px',
              fontWeight: 600,
              color: '#991B1B',
            }}
          >
            {criticalCount} blocking {criticalCount === 1 ? 'finding' : 'findings'} detected by static AST deterministic verification.
          </div>
        )}

        {Array.isArray(details) && details.length > 0 && (
          <div style={{ marginBottom: '18px', maxHeight: '180px', overflowY: 'auto' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
              Identified Hazards:
            </span>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-primary)' }}>
              {details.map((item, idx) => (
                <li key={idx} style={{ marginBottom: '4px' }}>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div
          style={{
            padding: '10px 12px',
            backgroundColor: 'var(--bg-void, #F8FAFC)',
            borderRadius: '6px',
            border: '1px solid var(--border-subtle, #E2E8F0)',
            marginBottom: '20px',
            fontSize: '11px',
            color: 'var(--text-muted)',
            fontStyle: 'italic',
          }}
        >
          🔒 <strong>Fail-Closed Gate Enforcement:</strong> Gate verdicts are authoritative server decisions computed deterministically. The frontend cannot override or force-approve a blocked status.
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
          <button
            ref={closeBtnRef}
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => {
              if (typeof onAction === 'function') onAction();
              onClose();
            }}
          >
            {actionLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
