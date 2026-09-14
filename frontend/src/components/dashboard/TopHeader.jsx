import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { SearchIcon, BellIcon, GitHubIcon, ChevronDownIcon } from './Icons';

export default function TopHeader() {
  const navigate = useNavigate();
  const searchInputRef = useRef(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  // Keyboard shortcut: Ctrl+K or Cmd+K focuses search
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Click outside to close popovers
  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (!e.target.closest('.cs-header-actions')) {
        setShowNotifications(false);
        setShowProfileMenu(false);
      }
    };
    window.addEventListener('click', handleOutsideClick);
    return () => window.removeEventListener('click', handleOutsideClick);
  }, []);

  const handleSearchSubmit = (e) => {
    if (e.key === 'Enter' && searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      if (q.includes('/') || q.includes('repo')) {
        navigate('/repositories', { state: { query: searchQuery.trim() } });
      } else {
        navigate('/history', { state: { query: searchQuery.trim() } });
      }
      setSearchQuery('');
    }
  };

  return (
    <header className="cs-top-header">
      {/* Left Search Bar */}
      <div className="cs-header-search-wrapper">
        <span className="cs-search-icon-slot">
          <SearchIcon size={17} color="#64748B" />
        </span>
        <input
          ref={searchInputRef}
          type="text"
          className="cs-header-search-input"
          placeholder="Search repositories, findings, PRs... (Press ⌘K)"
          aria-label="Search repositories, findings, PRs"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={handleSearchSubmit}
        />
        <div
          className="cs-search-shortcut-badge"
          onClick={() => searchInputRef.current?.focus()}
          title="Press Ctrl+K or ⌘K to focus"
        >
          <span>⌘K</span>
        </div>
      </div>

      {/* Right Controls & User Profile */}
      <div className="cs-header-actions">
        {/* Notification Bell with Dropdown */}
        <div style={{ position: 'relative' }}>
          <button
            type="button"
            className={`cs-header-icon-btn ${showNotifications ? 'active' : ''}`}
            title="Notifications"
            aria-label="Notifications"
            onClick={(e) => {
              e.stopPropagation();
              setShowNotifications(!showNotifications);
              setShowProfileMenu(false);
            }}
          >
            <BellIcon size={19} color="#475569" />
            <span className="cs-notification-badge-dot" />
          </button>

          {showNotifications && (
            <div
              className="cs-notifications-popover"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="cs-popover-header">
                <span>System Notifications</span>
                <span className="cs-badge-pill-online">Active</span>
              </div>
              <div className="cs-notifications-list">
                <div className="cs-notification-item">
                  <span className="cs-status-dot-green" />
                  <div>
                    <div className="cs-notif-title">Backend v1.1.0 Healthy</div>
                    <div className="cs-notif-time">All security subsystems online</div>
                  </div>
                </div>
                <div className="cs-notification-item">
                  <span className="cs-status-dot-green" />
                  <div>
                    <div className="cs-notif-title">Security Gate Active</div>
                    <div className="cs-notif-time">Fail-closed gate enforcement enabled</div>
                  </div>
                </div>
              </div>
              <div className="cs-popover-footer">
                <button
                  type="button"
                  className="cs-popover-footer-btn"
                  onClick={() => {
                    setShowNotifications(false);
                    navigate('/system');
                  }}
                >
                  View System Diagnostics →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* GitHub Link Icon */}
        <a
          href="https://github.com/SARUKKESH-M/S5-MINI-PROJECT"
          target="_blank"
          rel="noopener noreferrer"
          className="cs-header-icon-btn"
          title="GitHub Repository"
          aria-label="GitHub Repository"
        >
          <GitHubIcon size={19} color="#475569" />
        </a>

        {/* Vertical Divider */}
        <div className="cs-header-divider" />

        {/* User Profile Menu */}
        <div style={{ position: 'relative' }}>
          <div
            className="cs-user-profile-menu"
            style={{ cursor: 'pointer' }}
            onClick={(e) => {
              e.stopPropagation();
              setShowProfileMenu(!showProfileMenu);
              setShowNotifications(false);
            }}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setShowProfileMenu(!showProfileMenu);
              }
            }}
            title="User Profile & Settings"
          >
            <div className="cs-user-avatar">
              <span>SM</span>
            </div>
            <div className="cs-user-info">
              <div className="cs-user-name">Sharu Mani</div>
              <div className="cs-user-role">Developer</div>
            </div>
            <ChevronDownIcon size={14} color="#64748B" />
          </div>

          {showProfileMenu && (
            <div
              className="cs-profile-dropdown"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="cs-dropdown-user-header">
                <strong>Sharu Mani</strong>
                <span style={{ fontSize: '11px', color: '#64748B' }}>admin@codesentinel.dev</span>
              </div>
              <div className="cs-dropdown-divider" />
              <button
                type="button"
                className="cs-dropdown-item"
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/repositories');
                }}
              >
                Repositories
              </button>
              <button
                type="button"
                className="cs-dropdown-item"
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/history');
                }}
              >
                Audit History
              </button>
              <button
                type="button"
                className="cs-dropdown-item"
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/system');
                }}
              >
                System Diagnostics
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
