import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldLogo } from './Icons';

export default function Footer() {
  return (
    <footer className="cs-dashboard-footer" aria-label="Dashboard Footer">
      <div className="cs-footer-left">
        <div className="cs-footer-brand">
          <ShieldLogo size={20} />
          <span className="cs-footer-brand-name">CodeSentinel</span>
        </div>
        <span className="cs-footer-divider">|</span>
        <span className="cs-footer-tagline">Secure Code. Safer Tomorrow.</span>
      </div>

      <div className="cs-footer-center">
        <Link to="/system" className="cs-footer-link">System Diagnostics</Link>
        <Link to="/tools" className="cs-footer-link">Operational Tools</Link>
        <Link to="/history" className="cs-footer-link">Audit History</Link>
        <a
          href="https://github.com/SARUKKESH-M/S5-MINI-PROJECT"
          target="_blank"
          rel="noopener noreferrer"
          className="cs-footer-link"
        >
          GitHub
        </a>
      </div>

      <div className="cs-footer-right">
        <span className="cs-footer-version-tag">
          <span className="cs-status-dot-green" />
          <span>v1.1.0 · Production</span>
        </span>
      </div>
    </footer>
  );
}
