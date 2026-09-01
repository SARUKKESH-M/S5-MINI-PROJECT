import React from 'react';
import { NavLink } from 'react-router-dom';

export default function SecurityCommandRail() {
  const navItems = [
    { path: '/', icon: 'shield', label: 'Product Entry' },
    { path: '/command-center', icon: 'dashboard', label: 'Security Command Center' },
    { path: '/pr-review', icon: 'alt_route', label: 'PR Security Review Workspace' },
    { path: '/repo-intelligence', icon: 'folder_managed', label: 'Repository Intelligence' },
    { path: '/vulnerability-explorer', icon: 'search', label: 'Vulnerability Explorer' },
    { path: '/ai-analysis', icon: 'psychology', label: 'AI Analysis Center' },
    { path: '/learning-center', icon: 'tune', label: 'False-Positive Learning Center' },
    { path: '/system-health', icon: 'monitor_heart', label: 'System Health & Infrastructure' },
  ];

  return (
    <aside className="command-rail" title="Security Command Rail">
      {/* Brand Sentinel Logo */}
      <div style={{ marginBottom: '24px', color: 'var(--primary-cyan)', display: 'flex', justifyContent: 'center' }}>
        <span className="material-symbols-outlined" style={{ fontSize: '28px' }}>
          security
        </span>
      </div>

      {/* Navigation Items for All 8 Views */}
      <nav style={{ display: 'flex', flexDirection: 'column', width: '100%', alignItems: 'center' }}>
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `command-rail-item ${isActive ? 'active' : ''}`
            }
            title={item.label}
          >
            <span className="material-symbols-outlined" style={{ fontSize: '22px' }}>
              {item.icon}
            </span>
          </NavLink>
        ))}
      </nav>

      {/* System Active Indicator Pip */}
      <div style={{ marginTop: 'auto', marginBottom: '16px' }} title="Sentinel Engine Active">
        <span className="status-pip status-pip-cyan" />
      </div>
    </aside>
  );
}
