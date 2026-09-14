import React from 'react';

/**
 * Reusable LoadingState component.
 * Displays honest, non-fabricated loading feedback without fake percentage bars.
 */
export default function LoadingState({
  message = 'Loading data...',
  subtext,
  minHeight = '160px',
  style = {},
  className = '',
}) {
  return (
    <div
      className={`cs-loading-state-container ${className}`}
      role="status"
      aria-live="polite"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight,
        padding: '24px',
        textAlign: 'center',
        ...style,
      }}
    >
      <div
        className="cs-loading-spinner"
        style={{
          width: '28px',
          height: '28px',
          border: '3px solid rgba(99, 102, 241, 0.2)',
          borderTopColor: '#6366F1',
          borderRadius: '50%',
          animation: 'cs-spin 0.8s linear infinite',
          marginBottom: '12px',
        }}
        aria-hidden="true"
      />

      <div
        style={{
          fontSize: '13px',
          fontWeight: 600,
          color: 'var(--text-primary)',
          fontFamily: 'var(--font-mono)',
        }}
      >
        {message}
      </div>

      {subtext && (
        <div
          style={{
            fontSize: '11.5px',
            color: 'var(--text-muted)',
            marginTop: '4px',
            maxWidth: '320px',
          }}
        >
          {subtext}
        </div>
      )}
    </div>
  );
}
