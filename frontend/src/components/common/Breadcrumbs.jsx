import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const ROUTE_LABELS = {
  '': 'Dashboard',
  'dashboard': 'Dashboard',
  'analyze': 'Analysis Studio',
  'repositories': 'Repositories',
  'pull-requests': 'Pull Requests',
  'reviews': 'Security Review',
  'analytics': 'Analytics',
  'history': 'Audit History',
  'tools': 'Tools',
  'settings': 'Settings',
  'system': 'System Diagnostics',
};

/**
 * Reusable, accessible Breadcrumbs navigation component.
 */
export default function Breadcrumbs({ items, className = '' }) {
  const location = useLocation();

  // If explicit items not provided, derive from pathname
  const breadcrumbItems = React.useMemo(() => {
    if (Array.isArray(items) && items.length > 0) return items;

    const segments = location.pathname.split('/').filter(Boolean);
    const list = [{ label: 'Dashboard', path: '/' }];

    let currentPath = '';
    segments.forEach((seg, idx) => {
      currentPath += `/${seg}`;
      const isLast = idx === segments.length - 1;
      const label = ROUTE_LABELS[seg.toLowerCase()] || decodeURIComponent(seg);
      list.push({
        label,
        path: isLast ? null : currentPath,
        active: isLast,
      });
    });

    return list;
  }, [items, location.pathname]);

  if (breadcrumbItems.length <= 1) return null;

  return (
    <nav aria-label="Breadcrumb" className={`cs-breadcrumbs ${className}`} style={{ marginBottom: '12px' }}>
      <ol
        style={{
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '6px',
          listStyle: 'none',
          padding: 0,
          margin: 0,
          fontSize: '12px',
        }}
      >
        {breadcrumbItems.map((item, idx) => {
          const isLast = idx === breadcrumbItems.length - 1;

          return (
            <li
              key={item.path || idx}
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
              aria-current={isLast ? 'page' : undefined}
            >
              {idx > 0 && (
                <span
                  className="cs-breadcrumb-separator"
                  style={{ color: 'var(--text-dim)', fontSize: '11px', userSelect: 'none' }}
                  aria-hidden="true"
                >
                  /
                </span>
              )}

              {isLast || !item.path ? (
                <span
                  style={{
                    color: isLast ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontWeight: isLast ? 600 : 400,
                  }}
                >
                  {item.label}
                </span>
              ) : (
                <Link
                  to={item.path}
                  style={{
                    color: 'var(--text-muted)',
                    textDecoration: 'none',
                    transition: 'color 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = '#6366F1')}
                  onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
                >
                  {item.label}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
