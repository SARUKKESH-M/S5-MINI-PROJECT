import React, { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useSidebar } from './SidebarContext';
import { getPlatformHealth } from '../../services/apiClient';
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
  HistoryIcon,
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
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: VulnerabilitiesIcon, path: '/vulnerabilities' },
  { id: 'reviews', label: 'Reviews', icon: ReviewsIcon, path: '/reviews' },
  { id: 'developers', label: 'Developers', icon: DevelopersIcon, path: '/developers' },
  { id: 'analytics', label: 'Analytics', icon: AnalyticsIcon, path: '/analytics' },
  { id: 'history', label: 'Audit History', icon: HistoryIcon, path: '/history' },
  { id: 'false-positives', label: 'False Positives', icon: FalsePositivesIcon, path: '/false-positives' },
  { id: 'tools', label: 'Tools', icon: ToolsIcon, path: '/tools' },
  { id: 'settings', label: 'Settings', icon: SettingsIcon, path: '/settings' },
];

export default function Sidebar() {
  const { isOpen, closeSidebar } = useSidebar();
  const [themeMode, setThemeMode] = useState(() => {
    try {
      return localStorage.getItem('cs_pref_theme') || 'light';
    } catch {
      return 'light';
    }
  });

  const [healthStatus, setHealthStatus] = useState({
    status: 'checking',
    version: '1.1.0',
    label: 'Checking status...',
  });

  const location = useLocation();
  const isDashboardRoute = location.pathname === '/' || location.pathname === '/dashboard';

  // Apply theme to DOM and dispatch notification for synchronization
  const applyTheme = (mode) => {
    setThemeMode(mode);
    try {
      localStorage.setItem('cs_pref_theme', mode);
    } catch {
      // Ignore localStorage failure
    }
    document.documentElement.setAttribute('data-theme', mode);
    window.dispatchEvent(new CustomEvent('cs-theme-changed', { detail: mode }));
  };

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', themeMode);

    const handleExternalThemeChange = (e) => {
      if (e.detail && (e.detail === 'light' || e.detail === 'dark')) {
        setThemeMode(e.detail);
      }
    };
    window.addEventListener('cs-theme-changed', handleExternalThemeChange);
    return () => window.removeEventListener('cs-theme-changed', handleExternalThemeChange);
  }, [themeMode]);

  // Fetch real platform health telemetry with 30s polling
  useEffect(() => {
    let isMounted = true;
    async function checkHealth() {
      try {
        const res = await getPlatformHealth();
        if (!isMounted) return;
        const ver = res?.version || '1.1.0';
        if (res?.status === 'healthy' || res?.status === 'ok') {
          setHealthStatus({ status: 'healthy', version: ver, label: 'Operational' });
        } else if (res?.status) {
          setHealthStatus({ status: 'degraded', version: ver, label: 'Degraded' });
        } else {
          setHealthStatus({ status: 'unavailable', version: ver, label: 'Unavailable' });
        }
      } catch {
        if (isMounted) {
          setHealthStatus({ status: 'offline', version: '1.1.0', label: 'Backend Offline' });
        }
      }
    }

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Handle escape key to close mobile drawer & body scroll locking
  useEffect(() => {
    if (!isOpen) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        closeSidebar();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, closeSidebar]);

  return (
    <>
      {/* Mobile Drawer Backdrop Overlay */}
      {isOpen && (
        <div
          className="cs-sidebar-backdrop"
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}

      <aside
        className={`cs-sidebar ${isOpen ? 'cs-sidebar-open' : ''}`}
        aria-label="Sidebar Navigation"
        aria-modal={isOpen ? 'true' : undefined}
      >
        {/* Brand Header */}
        <div className="cs-sidebar-brand">
          <div className="cs-brand-logo-container">
            <ShieldLogo size={30} />
          </div>
          <div className="cs-brand-meta">
            <div className="cs-brand-name">CodeSentinel</div>
            <div className="cs-brand-tagline">Secure Code. Safer Tomorrow.</div>
          </div>
          <button
            type="button"
            className="cs-sidebar-mobile-close"
            onClick={closeSidebar}
            aria-label="Close navigation sidebar"
          >
            ✕
          </button>
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
                    onClick={closeSidebar}
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
                    aria-label={`${item.label} (Available in later phase)`}
                    aria-disabled="true"
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
              onClick={() => applyTheme('light')}
              aria-label="Light mode"
              title="Light mode"
            >
              <SunIcon size={14} />
              <span>Light</span>
            </button>
            <button
              type="button"
              className={`cs-theme-toggle-btn ${themeMode === 'dark' ? 'active' : ''}`}
              onClick={() => applyTheme('dark')}
              aria-label="Dark mode"
              title="Dark mode"
            >
              <MoonIcon size={14} />
              <span>Dark</span>
            </button>
          </div>

          {/* System Status Details with Live Telemetry */}
          <NavLink
            to="/system"
            className={({ isActive }) => `cs-sidebar-system-info cs-sidebar-system-link ${isActive ? 'active' : ''}`}
            title="Inspect System Status & Diagnostics"
            aria-label="System Diagnostics"
            onClick={closeSidebar}
          >
            <div className="cs-system-header">
              <span className="cs-system-title">CodeSentinel</span>
              <span className="cs-system-version">v{healthStatus.version}</span>
            </div>
            <div className="cs-system-status-row">
              <span
                className={`cs-status-indicator-dot cs-health-${healthStatus.status}`}
                style={{
                  backgroundColor:
                    healthStatus.status === 'healthy'
                      ? '#10B981'
                      : healthStatus.status === 'degraded'
                      ? '#F59E0B'
                      : healthStatus.status === 'checking'
                      ? '#64748B'
                      : '#EF4444',
                }}
                aria-hidden="true"
              />
              <span className="cs-status-text">{healthStatus.label}</span>
            </div>
          </NavLink>
        </div>
      </aside>
    </>
  );
}
