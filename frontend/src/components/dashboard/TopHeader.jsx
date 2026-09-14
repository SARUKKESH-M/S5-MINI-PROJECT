import React from 'react';
import { SearchIcon, BellIcon, GitHubIcon, ChevronDownIcon } from './Icons';

export default function TopHeader() {
  return (
    <header className="cs-top-header">
      {/* Left Search Bar */}
      <div className="cs-header-search-wrapper">
        <span className="cs-search-icon-slot">
          <SearchIcon size={17} color="#64748B" />
        </span>
        <input
          type="text"
          className="cs-header-search-input"
          placeholder="Search repositories, findings, PRs..."
          aria-label="Search repositories, findings, PRs"
        />
        <div className="cs-search-shortcut-badge">
          <span>⌘K</span>
        </div>
      </div>

      {/* Right Controls & User Profile */}
      <div className="cs-header-actions">
        {/* Notification Bell with Red Dot */}
        <button type="button" className="cs-header-icon-btn" title="Notifications" aria-label="Notifications">
          <BellIcon size={19} color="#475569" />
          <span className="cs-notification-badge-dot" />
        </button>

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

        {/* User Profile */}
        <div className="cs-user-profile-menu">
          <div className="cs-user-avatar">
            <span>SM</span>
          </div>
          <div className="cs-user-info">
            <div className="cs-user-name">Sharu Mani</div>
            <div className="cs-user-role">Developer</div>
          </div>
          <ChevronDownIcon size={14} color="#64748B" />
        </div>
      </div>
    </header>
  );
}
