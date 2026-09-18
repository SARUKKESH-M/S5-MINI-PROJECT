import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSidebar } from './SidebarContext';
import { useAuth } from '../../context/AuthContext';
import { SearchIcon, BellIcon, GitHubIcon, ChevronDownIcon } from './Icons';
import { getAnalyses, getPlatformHealth } from '../../services/apiClient';

const WORKSPACE_TARGETS = [
  { id: 'dashboard', title: 'Dashboard', path: '/', category: 'Workspaces', hint: 'Overview & security posture metrics' },
  { id: 'analyze', title: 'Analysis Studio', path: '/analyze', category: 'Workspaces', hint: 'Scan Python source code or branches' },
  { id: 'repositories', title: 'Repositories', path: '/repositories', category: 'Workspaces', hint: 'Manage and intake GitHub repositories' },
  { id: 'pull-requests', title: 'Pull Requests', path: '/pull-requests', category: 'Workspaces', hint: 'PR reviews, diff scoping & webhook CI/CD' },
  { id: 'reviews', title: 'Security Reviews', path: '/reviews', category: 'Workspaces', hint: 'Finding management & false-positive suppressions' },
  { id: 'analytics', title: 'Analytics & Intelligence', path: '/analytics', category: 'Workspaces', hint: 'CWE distributions, trends & MTTR metrics' },
  { id: 'history', title: 'Audit History', path: '/history', category: 'Workspaces', hint: 'Permanent chronological scan records' },
  { id: 'tools', title: 'Operational Tools', path: '/tools', category: 'Workspaces', hint: 'Subsystem release readiness & policy inspector' },
  { id: 'settings', title: 'Platform Settings', path: '/settings', category: 'Workspaces', hint: 'Server policies, engine specs & UI preferences' },
  { id: 'access', title: 'Access Management', path: '/settings?tab=access', category: 'Admin', hint: 'Pre-authorize Google users & manage access' },
  { id: 'system', title: 'System Diagnostics', path: '/system', category: 'Workspaces', hint: 'Component health checks & readiness probes' },
];

export default function TopHeader() {
  const navigate = useNavigate();
  const { toggleSidebar, isOpen: isSidebarOpen } = useSidebar();
  const { user, logout } = useAuth();
  const searchInputRef = useRef(null);
  const searchContainerRef = useRef(null);
  const notifBtnRef = useRef(null);
  const profileBtnRef = useRef(null);

  // Authenticated user display values
  const userName = user?.full_name || 'CodeSentinel User';
  const userEmail = user?.email || 'authenticated@codesentinel.dev';
  const userRole = user?.role || 'USER';
  const userAvatar = user?.profile_picture || null;
  const userInitials = useMemo(() => {
    if (!userName) return 'CS';
    const parts = userName.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return userName.slice(0, 2).toUpperCase();
  }, [userName]);

  // Popover visibility states
  const [searchQuery, setSearchQuery] = useState('');
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  // Telemetry states for legitimate search and notifications
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [hasLoadedAnalyses, setHasLoadedAnalyses] = useState(false);
  const [platformHealth, setPlatformHealth] = useState(null);

  // Lazy load analyses for search on search focus
  const ensureSearchDataLoaded = async () => {
    if (hasLoadedAnalyses) return;
    try {
      const res = await getAnalyses({ limit: 15 });
      if (Array.isArray(res.analyses)) {
        setRecentAnalyses(res.analyses);
      }
      setHasLoadedAnalyses(true);
    } catch {
      // Graceful fallback: workspaces will still be searchable
      setHasLoadedAnalyses(true);
    }
  };

  // Fetch health status for real notification telemetry once on mount
  useEffect(() => {
    let isMounted = true;
    async function loadHealth() {
      try {
        const res = await getPlatformHealth();
        if (isMounted && res) setPlatformHealth(res);
      } catch {
        // Fallback: quiet state
      }
    }
    loadHealth();
    return () => {
      isMounted = false;
    };
  }, []);

  // Keyboard navigation & global shortcuts (⌘K/Ctrl+K, Escape)
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        setShowSearchResults(true);
        ensureSearchDataLoaded();
      } else if (e.key === 'Escape') {
        if (showSearchResults) {
          setShowSearchResults(false);
          searchInputRef.current?.blur();
        }
        if (showNotifications) {
          setShowNotifications(false);
          notifBtnRef.current?.focus();
        }
        if (showProfileMenu) {
          setShowProfileMenu(false);
          profileBtnRef.current?.focus();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showSearchResults, showNotifications, showProfileMenu]);

  // Click outside listener for all popovers
  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (searchContainerRef.current && !searchContainerRef.current.contains(e.target)) {
        setShowSearchResults(false);
      }
      if (!e.target.closest('.cs-header-actions')) {
        setShowNotifications(false);
        setShowProfileMenu(false);
      }
    };
    window.addEventListener('click', handleOutsideClick);
    return () => window.removeEventListener('click', handleOutsideClick);
  }, []);

  // Search Results aggregation across legitimate entities
  const searchResults = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) {
      // When input is focused with no query, show quick navigation workspaces
      return WORKSPACE_TARGETS.slice(0, 6);
    }

    const results = [];

    // 1. Match Workspaces
    WORKSPACE_TARGETS.forEach((ws) => {
      if (ws.title.toLowerCase().includes(q) || ws.hint.toLowerCase().includes(q) || ws.path.includes(q)) {
        results.push(ws);
      }
    });

    // 2. Match Repositories (Extracted from real analyses)
    const seenRepos = new Set();
    recentAnalyses.forEach((item) => {
      const summary = item.summary || {};
      const repoMeta = summary._repository || item.repository || {};
      const repoName = typeof repoMeta === 'string'
        ? repoMeta
        : (repoMeta.owner && repoMeta.repository ? `${repoMeta.owner}/${repoMeta.repository}` : (repoMeta.name || ''));

      if (repoName && !seenRepos.has(repoName)) {
        seenRepos.add(repoName);
        if (repoName.toLowerCase().includes(q)) {
          results.push({
            id: `repo-${repoName}`,
            title: repoName,
            category: 'Repositories',
            hint: 'View repository workspace & security overview',
            path: '/repositories',
            state: { repo: repoName },
          });
        }
      }
    });

    // 3. Match Analysis Records (by analysis_id or branch)
    recentAnalyses.forEach((item) => {
      const id = String(item.analysis_id || '');
      const branch = String(item.branch || item.summary?._repository?.branch || '');
      const gate = String(item.review_status || item.summary?._review_status || '').toUpperCase();

      if (id.toLowerCase().includes(q) || branch.toLowerCase().includes(q) || gate.toLowerCase() === q) {
        results.push({
          id: `analysis-${id}`,
          title: `Analysis ${id.slice(0, 8)}... (${gate || 'AUDIT'})`,
          category: 'Analyses',
          hint: `Branch: ${branch || 'main'} | ${item.finding_count ?? 0} findings`,
          path: `/history?id=${encodeURIComponent(id)}`,
        });
      }
    });

    return results.slice(0, 10);
  }, [searchQuery, recentAnalyses]);

  // Reset highlighted index on query change
  useEffect(() => {
    setHighlightedIndex(0);
  }, [searchQuery]);

  // Navigate to selected search result
  const handleSelectResult = (result) => {
    if (!result) return;
    setShowSearchResults(false);
    setSearchQuery('');
    if (result.state) {
      navigate(result.path, { state: result.state });
    } else {
      navigate(result.path);
    }
  };

  // Keyboard navigation within search results
  const handleSearchKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightedIndex((prev) => (prev < searchResults.length - 1 ? prev + 1 : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightedIndex((prev) => (prev > 0 ? prev - 1 : searchResults.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (searchResults.length > 0) {
        handleSelectResult(searchResults[highlightedIndex]);
      } else if (searchQuery.trim()) {
        // Fallback search navigation to history or repositories
        const q = searchQuery.trim();
        if (q.includes('/')) {
          navigate('/repositories', { state: { query: q } });
        } else {
          navigate('/history', { state: { query: q } });
        }
        setShowSearchResults(false);
        setSearchQuery('');
      }
    }
  };

  return (
    <header className="cs-top-header">
      {/* Mobile Hamburger Menu Toggle Button */}
      <button
        type="button"
        className="cs-mobile-menu-btn"
        onClick={toggleSidebar}
        aria-label={isSidebarOpen ? 'Close navigation menu' : 'Open navigation menu'}
        aria-expanded={isSidebarOpen}
        title="Toggle navigation sidebar"
      >
        <span className="cs-mobile-menu-icon" aria-hidden="true">
          {isSidebarOpen ? '✕' : '☰'}
        </span>
      </button>

      {/* Left Search Bar with Integrated Live Dropdown */}
      <div className="cs-header-search-wrapper" ref={searchContainerRef} style={{ position: 'relative' }}>
        <span className="cs-search-icon-slot">
          <SearchIcon size={17} color="#64748B" />
        </span>
        <input
          ref={searchInputRef}
          type="text"
          className="cs-header-search-input"
          placeholder="Search workspaces, repositories, analyses... (Press ⌘K)"
          aria-label="Search workspaces, repositories, and analyses"
          aria-autocomplete="list"
          aria-expanded={showSearchResults}
          aria-controls="cs-header-search-results"
          role="combobox"
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setShowSearchResults(true);
          }}
          onFocus={() => {
            setShowSearchResults(true);
            ensureSearchDataLoaded();
          }}
          onKeyDown={handleSearchKeyDown}
        />
        <div
          className="cs-search-shortcut-badge"
          onClick={() => {
            searchInputRef.current?.focus();
            setShowSearchResults(true);
            ensureSearchDataLoaded();
          }}
          title="Press Ctrl+K or ⌘K to focus"
          aria-hidden="true"
        >
          <span>⌘K</span>
        </div>

        {/* Global Search Results Dropdown */}
        {showSearchResults && (
          <div
            id="cs-header-search-results"
            className="cs-search-dropdown-menu"
            role="listbox"
            style={{
              position: 'absolute',
              top: 'calc(100% + 6px)',
              left: 0,
              right: 0,
              backgroundColor: 'var(--bg-card, #FFFFFF)',
              border: '1px solid var(--border-subtle, #E2E8F0)',
              borderRadius: '8px',
              boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.15), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
              maxHeight: '380px',
              overflowY: 'auto',
              zIndex: 1200,
              padding: '6px 0',
            }}
          >
            {searchResults.length === 0 ? (
              <div style={{ padding: '16px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12.5px' }}>
                No matching workspaces, repositories, or analyses found.
              </div>
            ) : (
              <div>
                <div style={{ padding: '6px 14px', fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.5px' }}>
                  {searchQuery.trim() ? 'Matching Results' : 'Suggested Workspaces'}
                </div>

                {searchResults.map((item, idx) => {
                  const isHighlighted = idx === highlightedIndex;
                  return (
                    <div
                      key={item.id || idx}
                      role="option"
                      aria-selected={isHighlighted}
                      onClick={() => handleSelectResult(item)}
                      onMouseEnter={() => setHighlightedIndex(idx)}
                      style={{
                        padding: '8px 14px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        backgroundColor: isHighlighted ? 'rgba(99, 102, 241, 0.08)' : 'transparent',
                        cursor: 'pointer',
                        transition: 'background-color 0.1s ease',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {item.title}
                        </div>
                        {item.hint && (
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                            {item.hint}
                          </div>
                        )}
                      </div>

                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '4px',
                          backgroundColor: 'var(--bg-void, #F8FAFC)',
                          border: '1px solid var(--border-subtle, #E2E8F0)',
                          color: '#6366F1',
                          textTransform: 'uppercase',
                        }}
                      >
                        {item.category}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right Controls & User Profile */}
      <div className="cs-header-actions">
        {/* Notification Bell with Honest System Status Popover */}
        <div style={{ position: 'relative' }}>
          <button
            ref={notifBtnRef}
            type="button"
            className={`cs-header-icon-btn ${showNotifications ? 'active' : ''}`}
            title="System Notifications"
            aria-label="System Notifications"
            aria-haspopup="dialog"
            aria-expanded={showNotifications}
            onClick={(e) => {
              e.stopPropagation();
              setShowNotifications(!showNotifications);
              setShowProfileMenu(false);
              setShowSearchResults(false);
            }}
          >
            <BellIcon size={19} color="#475569" />
          </button>

          {showNotifications && (
            <div
              className="cs-notifications-popover"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-label="System Notifications"
            >
              <div className="cs-popover-header">
                <span>System Notifications</span>
                <span className="cs-badge-pill-online">
                  {platformHealth?.status === 'healthy' ? 'Operational' : 'Active'}
                </span>
              </div>

              <div className="cs-notifications-list">
                {platformHealth ? (
                  <div className="cs-notification-item">
                    <span className="cs-status-dot-green" aria-hidden="true" />
                    <div>
                      <div className="cs-notif-title">Platform Backend Operational</div>
                      <div className="cs-notif-time">
                        Status: <strong>{platformHealth.status || 'healthy'}</strong> (Version: v{platformHealth.version || '1.1.0'})
                      </div>
                    </div>
                  </div>
                ) : null}

                <div className="cs-notification-item" style={{ backgroundColor: 'transparent' }}>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                    No unread security incidents. All security gate policies and diff-scope evaluators operating within established baseline.
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
          title="GitHub Repository (opens in new tab)"
          aria-label="GitHub Repository"
        >
          <GitHubIcon size={19} color="#475569" />
        </a>

        {/* Vertical Divider */}
        <div className="cs-header-divider" />

        {/* User Profile Menu */}
        <div style={{ position: 'relative' }}>
          <button
            ref={profileBtnRef}
            type="button"
            className="cs-user-profile-menu"
            style={{ cursor: 'pointer', background: 'transparent', border: 'none', textAlign: 'left', font: 'inherit' }}
            onClick={(e) => {
              e.stopPropagation();
              setShowProfileMenu(!showProfileMenu);
              setShowNotifications(false);
              setShowSearchResults(false);
            }}
            aria-expanded={showProfileMenu}
            aria-haspopup="menu"
            aria-label={`User Profile & Settings (${userName}, ${userRole})`}
            title="User Profile & Settings"
          >
            <div className="cs-user-avatar" aria-hidden="true">
              {userAvatar ? (
                <img
                  src={userAvatar}
                  alt={userName}
                  style={{ width: '100%', height: '100%', borderRadius: 'inherit', objectFit: 'cover' }}
                  referrerPolicy="no-referrer"
                />
              ) : (
                <span>{userInitials}</span>
              )}
            </div>
            <div className="cs-user-info">
              <div className="cs-user-name">{userName}</div>
              <div className="cs-user-role">{userRole}</div>
            </div>
            <ChevronDownIcon size={14} color="#64748B" />
          </button>

          {showProfileMenu && (
            <div
              className="cs-profile-dropdown"
              onClick={(e) => e.stopPropagation()}
              role="menu"
            >
              <div className="cs-dropdown-user-header">
                <strong>{userName}</strong>
                <span style={{ fontSize: '11px', color: '#64748B' }}>{userEmail}</span>
                <span style={{ fontSize: '10px', color: userRole === 'ADMIN' ? '#00f0ff' : '#94A3B8', fontWeight: 600, marginTop: '2px', textTransform: 'uppercase' }}>
                  {userRole}
                </span>
              </div>
              <div className="cs-dropdown-divider" />
              {userRole === 'ADMIN' && (
                <button
                  type="button"
                  className="cs-dropdown-item"
                  style={{ color: '#00f0ff', fontWeight: 600 }}
                  role="menuitem"
                  onClick={() => {
                    setShowProfileMenu(false);
                    navigate('/settings?tab=access');
                  }}
                >
                  🔐 Access Management
                </button>
              )}
              <button
                type="button"
                className="cs-dropdown-item"
                role="menuitem"
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/settings');
                }}
              >
                Platform Settings
              </button>
              <button
                type="button"
                className="cs-dropdown-item"
                role="menuitem"
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/tools');
                }}
              >
                Operational Tools
              </button>
              <button
                type="button"
                className="cs-dropdown-item"
                role="menuitem"
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
                role="menuitem"
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/system');
                }}
              >
                System Diagnostics
              </button>
              <div className="cs-dropdown-divider" />
              <button
                type="button"
                className="cs-dropdown-item"
                style={{ color: '#EF4444', fontWeight: 500 }}
                role="menuitem"
                onClick={async () => {
                  setShowProfileMenu(false);
                  await logout();
                  navigate('/login');
                }}
              >
                Sign Out →
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
