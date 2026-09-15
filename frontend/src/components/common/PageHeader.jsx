import React from 'react';
import Breadcrumbs from './Breadcrumbs';

/**
 * Standardized, accessible PageHeader component.
 * Provides consistent typography, spacing, actions, and breadcrumbs across workspaces.
 */
export default function PageHeader({
  title,
  description,
  icon,
  breadcrumbs,
  primaryAction,
  secondaryAction,
  badge,
  children,
  className = '',
  style = {},
}) {
  return (
    <div className={`card cs-page-header ${className}`} style={{ padding: '20px', marginBottom: '20px', ...style }}>
      {/* Optional Breadcrumb Navigation */}
      {breadcrumbs && <Breadcrumbs items={breadcrumbs} />}

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ flex: '1 1 280px', minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
            {icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{icon}</span>}
            <h1 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', margin: 0, wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
              {title}
            </h1>
            {badge && <span style={{ display: 'inline-flex' }}>{badge}</span>}
          </div>

          {description && (
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0, lineHeight: 1.45, wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
              {description}
            </p>
          )}
        </div>

        {(primaryAction || secondaryAction) && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {secondaryAction}
            {primaryAction}
          </div>
        )}
      </div>

      {children && <div style={{ marginTop: '16px' }}>{children}</div>}
    </div>
  );
}
