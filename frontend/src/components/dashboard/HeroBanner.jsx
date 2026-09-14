import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function HeroBanner() {
  const navigate = useNavigate();

  return (
    <section className="cs-hero-banner">
      {/* Background glow layers */}
      <div className="cs-hero-glow-sphere cs-hero-glow-1" />
      <div className="cs-hero-glow-sphere cs-hero-glow-2" />

      {/* Left Text & Actions */}
      <div className="cs-hero-content">
        <div className="cs-hero-badge">
          <span className="cs-hero-badge-dot" />
          <span>Next-Generation Deterministic & Advisory Security Engine</span>
        </div>
        <h1 className="cs-hero-title">AI-Powered Code Security Analysis</h1>
        <p className="cs-hero-subtitle">
          Detect vulnerabilities. Enforce security. Build safer software.
        </p>

        <div className="cs-hero-actions">
          <button
            type="button"
            className="cs-hero-btn cs-hero-btn-primary"
            onClick={() => navigate('/analyze')}
          >
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="5 3 19 12 5 21 5 3" />
            </svg>
            <span>Analyze Repository</span>
          </button>
          <button
            type="button"
            className="cs-hero-btn cs-hero-btn-secondary"
            onClick={() => {
              const el = document.getElementById('recent-analyses-table');
              if (el) el.scrollIntoView({ behavior: 'smooth' });
            }}
          >
            <span>View Demo</span>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="5" y1="12" x2="19" y2="12" />
              <polyline points="12 5 19 12 12 19" />
            </svg>
          </button>
        </div>
      </div>

      {/* Right Cyber Security Graphic */}
      <div className="cs-hero-visual-container">
        <div className="cs-hero-shield-graphic">
          <svg width="220" height="220" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="shieldBorderGrad" x1="0" y1="0" x2="200" y2="200" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#818CF8" stopOpacity="0.9" />
                <stop offset="50%" stopColor="#6366F1" stopOpacity="0.6" />
                <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.8" />
              </linearGradient>
              <linearGradient id="shieldFillGrad" x1="40" y1="20" x2="160" y2="180" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#1E1B4B" stopOpacity="0.75" />
                <stop offset="100%" stopColor="#0F172A" stopOpacity="0.85" />
              </linearGradient>
              <radialGradient id="haloGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#6366F1" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#6366F1" stopOpacity="0" />
              </radialGradient>
            </defs>

            {/* Glowing background halo */}
            <circle cx="100" cy="100" r="90" fill="url(#haloGlow)" />

            {/* Subtle rotating cyber circles */}
            <circle cx="100" cy="100" r="76" stroke="#4F46E5" strokeWidth="1.5" strokeDasharray="6 4" strokeOpacity="0.5" />
            <circle cx="100" cy="100" r="64" stroke="#38BDF8" strokeWidth="1" strokeDasharray="3 3" strokeOpacity="0.4" />

            {/* Central Main Shield */}
            <path
              d="M100 32L54 52V98C54 136 73.5 166 100 176C126.5 166 146 136 146 98V52L100 32Z"
              fill="url(#shieldFillGrad)"
              stroke="url(#shieldBorderGrad)"
              strokeWidth="2.5"
            />

            {/* Inner Shield Accent */}
            <path
              d="M100 46L66 62V98C66 128 80.5 152 100 160C119.5 152 134 128 134 98V62L100 46Z"
              fill="none"
              stroke="#6366F1"
              strokeWidth="1.2"
              strokeOpacity="0.4"
            />

            {/* Security Lock / Code Node */}
            <rect x="86" y="94" width="28" height="24" rx="4" fill="#6366F1" fillOpacity="0.3" stroke="#818CF8" strokeWidth="2" />
            <path d="M92 94V87C92 82.58 95.58 79 100 79C104.42 79 108 82.58 108 87V94" stroke="#38BDF8" strokeWidth="2" strokeLinecap="round" />
            <circle cx="100" cy="104" r="2.5" fill="#FFFFFF" />
            <line x1="100" y1="106.5" x2="100" y2="111" stroke="#FFFFFF" strokeWidth="2" strokeLinecap="round" />

            {/* Circuit Nodes */}
            <circle cx="48" cy="98" r="3" fill="#38BDF8" />
            <line x1="48" y1="98" x2="60" y2="98" stroke="#38BDF8" strokeWidth="1.5" />
            <circle cx="152" cy="98" r="3" fill="#818CF8" />
            <line x1="140" y1="98" x2="152" y2="98" stroke="#818CF8" strokeWidth="1.5" />

            {/* Top scanning radar spark */}
            <circle cx="100" cy="32" r="3" fill="#A5B4FC" />
          </svg>
        </div>
      </div>
    </section>
  );
}
