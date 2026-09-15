import React, { useEffect, useRef } from 'react';

/**
 * Reusable accessible Confirmation Dialog for consequential or destructive operations.
 * Traps focus, handles Escape key, and protects against accidental double submission.
 */
export default function ConfirmDialog({
  isOpen = false,
  title = 'Confirm Action',
  message = 'Are you sure you want to proceed with this action?',
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  isDestructive = true,
  isProcessing = false,
  onConfirm,
  onCancel,
}) {
  const dialogRef = useRef(null);
  const cancelBtnRef = useRef(null);
  const confirmBtnRef = useRef(null);
  const previousFocusRef = useRef(null);

  useEffect(() => {
    if (!isOpen) return;

    // Save previous active element for focus restoration
    previousFocusRef.current = document.activeElement;

    // Focus cancel button by default to prevent accidental trigger of destructive action
    const timer = setTimeout(() => {
      cancelBtnRef.current?.focus();
    }, 40);

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (!isProcessing && typeof onCancel === 'function') {
          onCancel();
        }
        return;
      }

      // Modal focus trap between cancel and confirm
      if (e.key === 'Tab' && dialogRef.current) {
        const focusable = dialogRef.current.querySelectorAll(
          'button:not([disabled]), [tabindex]:not([tabindex="-1"])'
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
  }, [isOpen, isProcessing, onCancel]);

  if (!isOpen) return null;

  return (
    <div
      className="cs-modal-backdrop"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(3px)',
        zIndex: 1100,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
      }}
      onClick={() => {
        if (!isProcessing && typeof onCancel === 'function') onCancel();
      }}
      role="presentation"
    >
      <div
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-desc"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '440px',
          maxWidth: '100%',
          backgroundColor: 'var(--bg-card, #FFFFFF)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle, #E2E8F0)',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.1)',
          padding: '22px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
          <span style={{ fontSize: '22px' }} aria-hidden="true">
            {isDestructive ? '⚠️' : 'ℹ️'}
          </span>
          <h3
            id="confirm-dialog-title"
            style={{
              fontSize: '16px',
              fontWeight: 700,
              color: isDestructive ? '#EF4444' : 'var(--text-primary)',
              margin: 0,
            }}
          >
            {title}
          </h3>
        </div>

        <p
          id="confirm-dialog-desc"
          style={{
            fontSize: '13px',
            color: 'var(--text-muted)',
            lineHeight: 1.45,
            margin: '0 0 20px',
          }}
        >
          {message}
        </p>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '10px' }}>
          <button
            ref={cancelBtnRef}
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onCancel}
            disabled={isProcessing}
          >
            {cancelLabel}
          </button>

          <button
            ref={confirmBtnRef}
            type="button"
            className={`btn btn-sm ${isDestructive ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            disabled={isProcessing}
            style={isDestructive ? { backgroundColor: '#EF4444', borderColor: '#DC2626', color: '#FFFFFF' } : {}}
          >
            {isProcessing ? 'Processing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
