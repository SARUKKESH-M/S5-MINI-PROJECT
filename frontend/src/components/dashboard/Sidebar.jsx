import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  ShieldLogo,
  DashboardIcon,
  AnalyzeIcon,
  RepositoriesIcon,
  PullRequestsIcon,
  VulnerabilitiesIcon,
  ReviewsIcon,
  DevelopersIcon,
  AnalyticsIcon,
  FalsePositivesIcon,
  ToolsIcon,
  SettingsIcon,
  SunIcon,
  MoonIcon,
} from './Icons';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon, path: '/' },
  { id: 'analyze', label: 'Analyze', icon: AnalyzeIcon, path: '/analyze' },
  { id: 'repositories', label: 'Repositories', icon: RepositoriesIcon, path: '/repositories' },
  { id: 'pull-requests', label: 'Pull Requests', icon: PullRequestsIcon, path: '/pull-requests' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: VulnerabilitiesIcon, path: '#' },
  { id: 'reviews', label: 'Reviews', icon: ReviewsIcon, path: '/reviews' },
  { id: 'developers', label: 'Developers', icon: DevelopersIcon, path: '#' },
  { id: 'analytics', label: 'Analytics', icon: AnalyticsIcon, path: '/analytics' },
  { id: 'false-positives', label: 'False Positives', icon: FalsePositivesIcon, path: '#' },
  { id: 'tools', label: 'Tools', icon: ToolsIcon, path: '#' },
  { id: 'settings', label: 'Settings', icon: SettingsIcon, path: '#' },
];

export default function Sidebar() {
  const [themeMode, setThemeMode] = useState('light');
  const location = useLocation();

  return (
    <aside className="cs-sidebar" aria-label="Sidebar Navigation">
      {/* Brand Header */}
      <div className="cs-sidebar-brand">
        <div className="cs-brand-logo-container">
          <ShieldLogo size={30} />
        </div>
        <div className="cs-brand-meta">
          <div className="cs-brand-name">CodeSentinel</div>
          <div className="cs-brand-tagline">Secure Code. Safer Tomorrow.</div>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="cs-sidebar-nav" aria-label="Primary Navigation">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isSelected = item.id === 'dashboard'
            ? isDashboardRoute
            : (item.path !== '#' && (location.pathname === item.path || location.pathname.startsWith(`${item.path}/`)));

          return (
            <div key={item.id} className="cs-nav-item-wrapper">
              {item.path !== '#' ? (
                <NavLink
                  to={item.path}
                  className={() => `cs-sidebar-link ${isSelected ? 'active' : ''}`}
                  aria-current={isSelected ? 'page' : undefined}
                >
                  <span className="cs-nav-icon">
                    <Icon size={17} />
                  </span>
                  <span className="cs-nav-label">{item.label}</span>
                </NavLink>
              ) : (
                <button
                  type="button"
                  className="cs-sidebar-link cs-sidebar-btn-link"
                  title={`${item.label} (Later Phase)`}
                  aria-label={item.label}
                >
                  <span className="cs-nav-icon">
                    <Icon size={17} />
                  </span>
                  <span className="cs-nav-label">{item.label}</span>
                </button>
              )}
            </div>
          );
        })}
      </nav>

      {/* Bottom Footer Section */}
      <div className="cs-sidebar-footer">
        {/* Light / Dark Mode Toggle */}
        <div className="cs-theme-toggle-container">
          <button
            type="button"
            className={`cs-theme-toggle-btn ${themeMode === 'light' ? 'active' : ''}`}
            onClick={() => setThemeMode('light')}
            aria-label="Light mode"
            title="Light mode"
          >
            <SunIcon size={14} />
            <span>Light</span>
          </button>
          <button
            type="button"
            className={`cs-theme-toggle-btn ${themeMode === 'dark' ? 'active' : ''}`}
            onClick={() => setThemeMode('dark')}
            aria-label="Dark mode"
            title="Dark mode"
          >
            <MoonIcon size={14} />
            <span>Dark</span>
          </button>
        </div>

        {/* System Status Details */}
        <NavLink
          to="/system"
          className={({ isActive }) => `cs-sidebar-system-info cs-sidebar-system-link ${isActive ? 'active' : ''}`}
          title="Inspect System Status & Diagnostics"
          aria-label="System Diagnostics"
        >
          <div className="cs-system-header">
            <span className="cs-system-title">CodeSentinel</span>
            <span className="cs-system-version">v1.1.0</span>
          </div>
          <div className="cs-system-status-row">
            <span className="cs-status-indicator-dot" />
            <span className="cs-status-text">Production</span>
          </div>
        </NavLink>
      </div>
    </aside>
  );
}
