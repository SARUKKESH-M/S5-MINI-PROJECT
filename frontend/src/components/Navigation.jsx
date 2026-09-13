import React, { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { getHealth } from '../services/apiClient';
import StatusBadge from './StatusBadge';

export default function Navigation() {
  const [backendStatus, setBackendStatus] = useState('checking');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    let isMounted = true;
    const checkConnection = async () => {
      try {
        const res = await getHealth();
        if (isMounted) {
          if (res?.status === 'ok' || res?.status === 'healthy') {
            setBackendStatus('ONLINE');
          } else {
            setBackendStatus('READY');
          }
        }
      } catch {
        if (isMounted) {
          setBackendStatus('OFFLINE');
        }
      }
    };

    checkConnection();
    const timer = setInterval(checkConnection, 30000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  // Close mobile menu on route navigation
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  const navItems = [
    { label: 'Dashboard', path: '/' },
    { label: 'Analyze', path: '/analyze' },
    { label: 'Repositories', path: '/repositories' },
    { label: 'History', path: '/history' },
    { label: 'System', path: '/system' },
  ];

  return (
    <header className="site-header">
      <div className="header-inner">
        {/* Brand */}
        <div className="brand-section">
          <NavLink to="/" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo">CS</div>
            <div className="brand-title">
              CODESENTINEL
              <span className="brand-version">v1.1.0</span>
            </div>
          </NavLink>
        </div>

        {/* Navigation Menu */}
        <nav className={`nav-menu ${mobileMenuOpen ? 'open' : ''}`}>
          {navItems.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Backend Connectivity Status */}
        <div className="header-status">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              BACKEND:
            </span>
            <StatusBadge status={backendStatus} />
          </div>

          <button
            type="button"
            className="mobile-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>
        </div>
      </div>
    </header>
  );
}
