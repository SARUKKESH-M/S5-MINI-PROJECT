import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import '../styles/auth.css';

// Official Google "G" SVG Icon
function GoogleIcon() {
  return (
    <svg className="cs-google-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
      />
      <path
        fill="#EA4335"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
      />
    </svg>
  );
}

// CodeSentinel Shield Icon
function ShieldIcon() {
  return (
    <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--primary-cyan)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

export default function LoginView() {
  const { user, isAuthenticated, loading: authLoading, authError, clearAuthError, login } = useAuth();
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState(null);
  const [showDevOptions, setShowDevOptions] = useState(false);
  const [customToken, setCustomToken] = useState('');
  const googleBtnContainerRef = useRef(null);

  const navigate = useNavigate();
  const location = useLocation();

  // Determine redirect destination from router state or default to /dashboard
  const destination = location.state?.from?.pathname || '/';

  // If already authenticated, redirect immediately to target workspace
  useEffect(() => {
    if (isAuthenticated && !authLoading) {
      navigate(destination, { replace: true });
    }
  }, [isAuthenticated, authLoading, navigate, destination]);

  // Check if Google Client ID is configured
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

  // Initialize Google Identity Services (GIS) if available
  useEffect(() => {
    if (!googleClientId || !window.google?.accounts?.id || isAuthenticated) return;

    try {
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: async (response) => {
          if (response?.credential) {
            setSubmitting(true);
            setLocalError(null);
            try {
              await login(response.credential);
              navigate(destination, { replace: true });
            } catch (err) {
              setLocalError(err);
            } finally {
              setSubmitting(false);
            }
          }
        },
      });

      if (googleBtnContainerRef.current) {
        window.google.accounts.id.renderButton(googleBtnContainerRef.current, {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'continue_with',
          shape: 'rectangular',
        });
      }
    } catch (e) {
      console.warn('Google Identity Services initialization skipped:', e);
    }
  }, [googleClientId, isAuthenticated, login, navigate, destination]);

  // Primary Google Login Action handler
  const handleGoogleClick = async () => {
    if (submitting || authLoading) return;
    setLocalError(null);
    clearAuthError();

    // If GIS is present, trigger standard Google prompt
    if (window.google?.accounts?.id && googleClientId) {
      window.google.accounts.id.prompt();
      return;
    }

    // Otherwise, in development / test / offline mode, use the pre-authorized admin demo identity
    setSubmitting(true);
    try {
      const demoToken = `mock:{"sub":"admin-google-sub","email":"admin@codesentinel.dev","name":"Admin Security Lead","picture":""}`;
      await login(demoToken);
      navigate(destination, { replace: true });
    } catch (err) {
      setLocalError(err);
    } finally {
      setSubmitting(false);
    }
  };

  // Handler for custom / mock token testing
  const handleCustomTokenSubmit = async (e) => {
    e.preventDefault();
    if (!customToken.trim() || submitting) return;
    setSubmitting(true);
    setLocalError(null);
    clearAuthError();

    try {
      await login(customToken.trim());
      navigate(destination, { replace: true });
    } catch (err) {
      setLocalError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const activeError = localError || authError;

  return (
    <div className="cs-auth-page">
      <main className="cs-auth-card" role="main" aria-labelledby="login-title">
        {/* Branding Emblem */}
        <div className="cs-auth-emblem-wrap">
          <div className="cs-auth-emblem">
            <ShieldIcon />
          </div>
        </div>

        {/* Title and System Badge */}
        <h1 id="login-title" className="cs-auth-title">
          Code<span>Sentinel</span>
        </h1>

        <div className="cs-auth-badge">
          <span className="cs-auth-badge-dot" aria-hidden="true" />
          AI Security Operating System
        </div>

        <p className="cs-auth-subtitle">
          Continuous AST taint analysis, AI security review, and autonomous PR gatekeeper.
        </p>

        {/* Error / Unauthorized / Disabled Alerts */}
        {activeError && (
          <div
            className={`cs-auth-alert ${
              activeError.type === 'DISABLED'
                ? 'cs-auth-alert-disabled'
                : activeError.type === 'UNAUTHORIZED'
                ? 'cs-auth-alert-unauthorized'
                : 'cs-auth-alert-error'
            }`}
            role="alert"
            aria-live="polite"
          >
            <div className="cs-auth-alert-icon" aria-hidden="true">
              {activeError.type === 'DISABLED' ? '🚫' : activeError.type === 'UNAUTHORIZED' ? '🛡️' : '⚠'}
            </div>
            <div className="cs-auth-alert-content">
              <strong>{activeError.title || 'Authentication Failed'}</strong>
              <div>{activeError.message}</div>
            </div>
            <button
              type="button"
              className="cs-auth-alert-dismiss"
              onClick={() => {
                setLocalError(null);
                clearAuthError();
              }}
              aria-label="Dismiss error message"
            >
              ×
            </button>
          </div>
        )}

        {/* Primary Action Box */}
        <div className="cs-auth-action-box">
          {/* GIS rendered container if GIS is active */}
          <div ref={googleBtnContainerRef} style={{ width: '100%' }} />

          {/* Standard accessible Continue with Google button */}
          {(!googleClientId || !window.google?.accounts?.id) && (
            <button
              type="button"
              className="cs-google-btn"
              onClick={handleGoogleClick}
              disabled={submitting || authLoading}
              aria-label="Continue with Google"
            >
              {submitting ? (
                <div className="cs-auth-spinner" aria-hidden="true" />
              ) : (
                <GoogleIcon />
              )}
              <span>{submitting ? 'Verifying Credentials...' : 'Continue with Google'}</span>
            </button>
          )}

          {/* Dev / Test Controls Toggle */}
          <div className="cs-auth-dev-toggle">
            <button
              type="button"
              className="cs-auth-dev-btn"
              onClick={() => setShowDevOptions(!showDevOptions)}
              aria-expanded={showDevOptions}
            >
              ⚙ {showDevOptions ? 'Hide Identity Emulator' : 'Identity Emulator & Test Accounts'}
            </button>

            {showDevOptions && (
              <div style={{ marginTop: '12px', textAlign: 'left', width: '100%' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '8px' }}>
                  Quick test profiles (Phase A4 / A5 contract verification):
                </div>

                <div style={{ display: 'flex', gap: '6px', flexDirection: 'column', marginBottom: '10px' }}>
                  <button
                    type="button"
                    className="cs-auth-dev-btn"
                    style={{ textAlign: 'left', justifyContent: 'flex-start' }}
                    onClick={async () => {
                      setSubmitting(true);
                      setLocalError(null);
                      try {
                        await login(`mock:{"sub":"admin-google-sub","email":"admin@codesentinel.dev","name":"Admin User","picture":""}`);
                        navigate(destination, { replace: true });
                      } catch (err) {
                        setLocalError(err);
                      } finally {
                        setSubmitting(false);
                      }
                    }}
                  >
                    🔑 Sign in as Pre-Authorized ADMIN
                  </button>

                  <button
                    type="button"
                    className="cs-auth-dev-btn"
                    style={{ textAlign: 'left', justifyContent: 'flex-start' }}
                    onClick={async () => {
                      setSubmitting(true);
                      setLocalError(null);
                      try {
                        await login(`mock:{"sub":"stranger-sub","email":"stranger@example.com","name":"Unknown User","picture":""}`);
                        navigate(destination, { replace: true });
                      } catch (err) {
                        setLocalError(err);
                      } finally {
                        setSubmitting(false);
                      }
                    }}
                  >
                    🚫 Test Unauthorized Account (Expect 403)
                  </button>
                </div>

                <form onSubmit={handleCustomTokenSubmit} style={{ display: 'flex', gap: '6px' }}>
                  <input
                    type="text"
                    value={customToken}
                    onChange={(e) => setCustomToken(e.target.value)}
                    placeholder="Custom token or mock JSON..."
                    style={{
                      flex: 1,
                      padding: '6px 8px',
                      background: 'var(--panel-bg-high)',
                      border: '1px solid var(--border-default)',
                      color: 'var(--text-on-surface)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      borderRadius: 'var(--radius-xs)',
                    }}
                  />
                  <button
                    type="submit"
                    className="cs-auth-dev-btn"
                    style={{ width: 'auto', padding: '6px 12px' }}
                    disabled={!customToken.trim() || submitting}
                  >
                    Test
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>

        {/* Security & Access Policy Notice */}
        <div className="cs-auth-footer">
          <div>Protected by CodeSentinel Access Boundary.</div>
          <div>Pre-authorized enterprise Google Workspace identity required.</div>
        </div>
      </main>
    </div>
  );
}
