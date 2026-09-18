import React from 'react';
import { Navigate, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import '../styles/auth.css';

/**
 * Centered Security Gate Loading Indicator
 */
function AuthGateLoading() {
  return (
    <div className="cs-auth-gate-loading" role="status" aria-live="polite">
      <div className="cs-gate-radar" aria-hidden="true" />
      <div>Verifying CodeSentinel security session...</div>
    </div>
  );
}

/**
 * Route protection gate ensuring only authenticated users with active status
 * can access internal CodeSentinel workspaces.
 */
export default function ProtectedRoute({ children, requiredRole = null }) {
  const { isAuthenticated, loading, user } = useAuth();
  const location = useLocation();

  if (loading) {
    return <AuthGateLoading />;
  }

  if (!isAuthenticated) {
    // Preserve attempted destination for seamless redirect after login
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user?.role !== requiredRole) {
    return (
      <div className="card" style={{ maxWidth: '600px', margin: '60px auto', padding: '32px', textAlign: 'center' }}>
        <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔒</div>
        <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
          Access Denied
        </h2>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '24px' }}>
          This area requires <strong>{requiredRole}</strong> privileges. Your current role is <strong>{user?.role || 'USER'}</strong>.
        </p>
        <a href="#/dashboard" className="btn btn-primary">
          Return to Dashboard
        </a>
      </div>
    );
  }

  return children ? children : <Outlet />;
}
