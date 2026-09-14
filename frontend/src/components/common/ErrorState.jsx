import React from 'react';

/**
 * Sanitize error message to prevent leakage of filesystem paths or tokens.
 */
function sanitizeErrorMessage(raw) {
  if (!raw || typeof raw !== 'string') return 'An unexpected error occurred. Please try again.';
  let clean = raw;
  clean = clean.replace(/[a-zA-Z]:\\[^:\s\n\r"']+/g, '[workspace]');
  clean = clean.replace(/\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+/g, '[workspace]');
  clean = clean.replace(/(?:ghp_[a-zA-Z0-9]{20,}|token\s*=\s*['"]?[a-zA-Z0-9._-]+)/gi, '[REDACTED]');
  return clean;
}

/**
 * Reusable ErrorState component.
 * Displays sanitized, accessible error alerts with optional retry capability.
 */
export default function ErrorState({
  title = 'Unable to Complete Request',
  error,
  onRetry,
  retryLabel = 'Try Again',
  secondaryActionText,
  onSecondaryAction,
  style = {},
  className = '',
}) {
  const displayError = typeof error === 'string'
    ? sanitizeErrorMessage(error)
    : (error?.message ? sanitizeErrorMessage(error.message) : 'An unexpected error occurred.');

  return (
    <div
      className={`cs-error-state-card ${className}`}
      role="alert"
      style={{
        padding: '24px',
        backgroundColor: 'rgba(239, 68, 68, 0.05)',
        border: '1px solid rgba(239, 68, 68, 0.2)',
        borderRadius: '8px',
        textAlign: 'center',
        ...style,
      }}
    >
      <div style={{ fontSize: '28px', marginBottom: '8px' }} aria-hidden="true">
        ⚠️
      </div>

      <div style={{ fontSize: '14px', fontWeight: 700, color: '#DC2626', marginBottom: '6px' }}>
        {title}
      </div>

      <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', maxWidth: '420px', margin: '0 auto 16px', lineHeight: 1.4 }}>
        {displayError}
      </p>

      {(onRetry || onSecondaryAction) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'center', flexWrap: 'wrap' }}>
          {typeof onRetry === 'function' && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onRetry}
            >
              ↻ {retryLabel}
            </button>
          )}

          {typeof onSecondaryAction === 'function' && secondaryActionText && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onSecondaryAction}
            >
              {secondaryActionText}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
