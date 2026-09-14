import React from 'react';

/**
 * Reusable, accessible EmptyState component.
 * Provides clear information on what is empty, why, and what action to take next.
 */
export default function EmptyState({
  icon = '📭',
  title = 'No Data Available',
  description = 'There are no records matching the current view or filter criteria.',
  actionText,
  onAction,
  secondaryActionText,
  onSecondaryAction,
  style = {},
  className = '',
}) {
  return (
    <div
      className={`cs-empty-state-card ${className}`}
      style={{
        padding: '36px 20px',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        ...style,
      }}
    >
      <div
        className="cs-empty-state-icon"
        style={{ fontSize: '32px', marginBottom: '10px', lineHeight: 1 }}
        aria-hidden="true"
      >
        {icon}
      </div>

      <div
        className="cs-empty-state-title"
        style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}
      >
        {title}
      </div>

      {description && (
        <p
          className="cs-empty-state-desc"
          style={{
            fontSize: '12.5px',
            color: 'var(--text-muted)',
            maxWidth: '380px',
            margin: '0 auto 16px',
            lineHeight: 1.45,
          }}
        >
          {description}
        </p>
      )}

      {(actionText || secondaryActionText) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
          {actionText && typeof onAction === 'function' && (
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={onAction}
            >
              {actionText}
            </button>
          )}

          {secondaryActionText && typeof onSecondaryAction === 'function' && (
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
