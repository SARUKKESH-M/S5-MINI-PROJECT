import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { fetchCurrentUser, loginWithGoogle, logoutUser } from '../services/apiClient';

const INITIAL_GATE_DEADLINE_MS = Number(import.meta.env?.VITE_AUTH_GATE_DEADLINE_MS) || 3500;
const SESSION_CHECK_TIMEOUT_MS = Number(import.meta.env?.VITE_SESSION_TIMEOUT_MS) || 15000;

const AuthContext = createContext({
  user: null,
  loading: true,
  sessionPending: true,
  isAuthenticated: false,
  authError: null,
  clearAuthError: () => {},
  login: async () => {},
  logout: async () => {},
  refreshUser: async () => {},
});

export const useAuth = () => useContext(AuthContext);

/**
 * Classify 403 / 401 error details to provide high-clarity error feedback
 */
function parseAuthError(err) {
  const status = err.status || 0;
  const detail = String(err.message || err.data?.detail || '');

  if (status === 403) {
    const isDisabled = detail.toLowerCase().includes('disabled') || detail.toLowerCase().includes('deactivated');
    return {
      status: 403,
      type: isDisabled ? 'DISABLED' : 'UNAUTHORIZED',
      title: isDisabled ? 'Account Suspended' : 'Access Denied',
      message: isDisabled
        ? 'Your CodeSentinel account has been deactivated. Please contact your organization security administrator.'
        : 'Your Google account is not pre-authorized to access CodeSentinel. Access must be granted by an administrator.',
      detail,
    };
  }

  if (status === 401) {
    return {
      status: 401,
      type: 'UNAUTHENTICATED',
      title: 'Authentication Required',
      message: 'Your session has expired or is invalid. Please sign in to continue.',
      detail,
    };
  }

  if (status === 0 || err.isTimeout) {
    return {
      status: err.status || 0,
      type: 'NETWORK_ERROR',
      title: 'Connection Error',
      message: err.isTimeout
        ? 'Session verification request timed out. Please check your backend connection.'
        : 'Unable to communicate with CodeSentinel security service. Ensure backend is running.',
      detail,
    };
  }

  return {
    status,
    type: 'SERVER_ERROR',
    title: 'Authentication Error',
    message: detail || 'An unexpected authentication error occurred.',
    detail,
  };
}

export function AuthProvider({ children, gateDeadlineMs = INITIAL_GATE_DEADLINE_MS }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sessionPending, setSessionPending] = useState(true);
  const [authError, setAuthError] = useState(null);
  const authSeqRef = useRef(0);

  const clearAuthError = useCallback(() => {
    setAuthError(null);
  }, []);

  /**
   * Refreshes current user state from the authoritative backend session
   */
  const refreshUser = useCallback(async () => {
    const seq = ++authSeqRef.current;
    try {
      const raw = await fetchCurrentUser({ timeout: SESSION_CHECK_TIMEOUT_MS });
      const userData = raw?.user || raw;
      if (authSeqRef.current === seq) {
        setUser(userData);
        setAuthError(null);
      }
      return userData;
    } catch (err) {
      if (authSeqRef.current === seq) {
        setUser(null);
        if (err.status !== 401 && !err.isTimeout && !err.isAborted) {
          setAuthError(parseAuthError(err));
        }
      }
      return null;
    }
  }, []);

  /**
   * Initial session check on application boot with fast gate deadline and race-safe background resolution
   */
  useEffect(() => {
    let isMounted = true;
    const seq = ++authSeqRef.current;

    // Safety deadline: unblock gate UI after gateDeadlineMs so user is never frozen
    const deadlineTimer = setTimeout(() => {
      if (isMounted && authSeqRef.current === seq) {
        setLoading(false);
      }
    }, gateDeadlineMs);

    async function checkInitialSession() {
      try {
        const raw = await fetchCurrentUser({ timeout: SESSION_CHECK_TIMEOUT_MS });
        const userData = raw?.user || raw;
        if (isMounted && authSeqRef.current === seq) {
          setUser(userData);
          setAuthError(null);
        }
      } catch (err) {
        if (isMounted && authSeqRef.current === seq) {
          setUser(null);
          // Only show error banner if explicit access-denied/disabled status
          if (err.status === 403) {
            setAuthError(parseAuthError(err));
          }
        }
      } finally {
        clearTimeout(deadlineTimer);
        if (isMounted && authSeqRef.current === seq) {
          setLoading(false);
          setSessionPending(false);
        }
      }
    }

    checkInitialSession();

    return () => {
      isMounted = false;
      clearTimeout(deadlineTimer);
    };
  }, [gateDeadlineMs]);

  /**
   * Listen for global session invalidation events emitted by apiClient
   */
  useEffect(() => {
    const handleSessionExpired = () => {
      authSeqRef.current++;
      setUser(null);
      setSessionPending(false);
      setAuthError({
        status: 401,
        type: 'UNAUTHENTICATED',
        title: 'Session Expired',
        message: 'Your CodeSentinel session has expired. Please sign in again.',
      });
    };

    const handleAccessDenied = (e) => {
      const detail = e.detail?.message || '';
      const isDisabled = detail.toLowerCase().includes('disabled') || detail.toLowerCase().includes('deactivated');
      if (isDisabled) {
        authSeqRef.current++;
        setUser(null);
        setSessionPending(false);
        setAuthError({
          status: 403,
          type: 'DISABLED',
          title: 'Account Suspended',
          message: 'Your CodeSentinel account has been deactivated. Please contact your organization security administrator.',
          detail,
        });
      }
    };

    window.addEventListener('codesentinel:session-expired', handleSessionExpired);
    window.addEventListener('codesentinel:access-denied', handleAccessDenied);

    return () => {
      window.removeEventListener('codesentinel:session-expired', handleSessionExpired);
      window.removeEventListener('codesentinel:access-denied', handleAccessDenied);
    };
  }, []);

  /**
   * Re-verify session on tab refocus after inactivity (heartbeat sync)
   */
  useEffect(() => {
    let lastChecked = Date.now();

    const handleVisibilityOrFocus = async () => {
      if (document.visibilityState === 'visible' && Date.now() - lastChecked > 60000) {
        lastChecked = Date.now();
        if (user) {
          const seq = ++authSeqRef.current;
          try {
            const raw = await fetchCurrentUser({ timeout: SESSION_CHECK_TIMEOUT_MS });
            const freshUser = raw?.user || raw;
            if (authSeqRef.current === seq) {
              setUser(freshUser);
            }
          } catch (err) {
            if (authSeqRef.current === seq) {
              if (err.status === 401 || err.status === 403) {
                setUser(null);
                setAuthError(parseAuthError(err));
              }
            }
          }
        }
      }
    };

    window.addEventListener('focus', handleVisibilityOrFocus);
    document.addEventListener('visibilitychange', handleVisibilityOrFocus);

    return () => {
      window.removeEventListener('focus', handleVisibilityOrFocus);
      document.removeEventListener('visibilitychange', handleVisibilityOrFocus);
    };
  }, [user]);

  /**
   * Authenticates with Google ID token and creates an authoritative session
   */
  const login = useCallback(async (idToken) => {
    const seq = ++authSeqRef.current;
    setLoading(true);
    setAuthError(null);
    try {
      await loginWithGoogle(idToken);
      const raw = await fetchCurrentUser();
      const currentUser = raw?.user || raw;
      if (authSeqRef.current === seq) {
        setUser(currentUser);
        setAuthError(null);
        setSessionPending(false);
      }
      return currentUser;
    } catch (err) {
      if (authSeqRef.current === seq) {
        setUser(null);
        const parsed = parseAuthError(err);
        setAuthError(parsed);
        throw parsed;
      }
    } finally {
      if (authSeqRef.current === seq) {
        setSessionPending(false);
        setLoading(false);
      }
    }
  }, []);

  /**
   * Revokes session on backend and clears local user state
   */
  const logout = useCallback(async () => {
    const seq = ++authSeqRef.current;
    setLoading(true);
    try {
      await logoutUser();
    } catch (err) {
      console.warn('Backend logout encountered error, clearing local state:', err);
    } finally {
      if (authSeqRef.current === seq) {
        setUser(null);
        setAuthError(null);
        setSessionPending(false);
        setLoading(false);
      }
    }
  }, []);

  const value = {
    user,
    loading,
    sessionPending,
    isAuthenticated: Boolean(user && user.status === 'ACTIVE'),
    authError,
    clearAuthError,
    login,
    logout,
    refreshUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
