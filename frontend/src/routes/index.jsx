import React, { lazy, Suspense } from 'react';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom';

import DashboardView from '../views/DashboardView';
import LoginView from '../views/LoginView';
import ProtectedRoute from './ProtectedRoute';
import Sidebar from '../components/dashboard/Sidebar';
import TopHeader from '../components/dashboard/TopHeader';
import Breadcrumbs from '../components/common/Breadcrumbs';

// Route-level code splitting: landing dashboard remains eager, workspaces are loaded on demand
const AnalyzeView = lazy(() => import('../views/AnalyzeView'));
const RepositoryView = lazy(() => import('../views/RepositoryView'));
const HistoryView = lazy(() => import('../views/HistoryView'));
const PullRequestsView = lazy(() => import('../views/PullRequestsView'));
const VulnerabilitiesView = lazy(() => import('../views/VulnerabilitiesView'));
const DevelopersView = lazy(() => import('../views/DevelopersView'));
const SecurityReviewView = lazy(() => import('../views/SecurityReviewView'));
const AnalyticsView = lazy(() => import('../views/AnalyticsView'));
const FalsePositivesView = lazy(() => import('../views/FalsePositivesView'));
const SystemView = lazy(() => import('../views/SystemView'));
const ToolsView = lazy(() => import('../views/ToolsView'));
const SettingsView = lazy(() => import('../views/SettingsView'));

function RouteLoading() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '260px',
        padding: '32px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
      }}
      role="status"
      aria-live="polite"
    >
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: '24px', marginBottom: '8px' }}>⏳</div>
        <div>Loading workspace...</div>
      </div>
    </div>
  );
}

function PageLayout({ children }) {
  return (
    <div className="cs-main-content-workspace">
      <TopHeader />
      <main id="main-content" tabIndex={-1} className="cs-page-workspace">
        <Breadcrumbs />
        <Suspense fallback={<RouteLoading />}>
          {children}
        </Suspense>
      </main>
    </div>
  );
}

function WorkspaceLayout() {
  return (
    <div className="cs-app-layout">
      <Sidebar />
      <Outlet />
    </div>
  );
}

export default function AppRoutes() {
  return (
    <Routes>
      {/* Public Login Route */}
      <Route path="/login" element={<LoginView />} />

      {/* Protected Application Workspace Routes */}
      <Route element={<ProtectedRoute><WorkspaceLayout /></ProtectedRoute>}>
        <Route path="/" element={<DashboardView />} />
        <Route path="/dashboard" element={<DashboardView />} />
      <Route
        path="/analyze"
        element={
          <PageLayout>
            <AnalyzeView />
          </PageLayout>
        }
      />
      <Route
        path="/repositories"
        element={
          <PageLayout>
            <RepositoryView />
          </PageLayout>
        }
      />
      <Route
        path="/pull-requests"
        element={
          <PageLayout>
            <PullRequestsView />
          </PageLayout>
        }
      />
      <Route
        path="/history"
        element={
          <PageLayout>
            <HistoryView />
          </PageLayout>
        }
      />
      <Route
        path="/vulnerabilities"
        element={
          <PageLayout>
            <VulnerabilitiesView />
          </PageLayout>
        }
      />
      <Route
        path="/reviews"
        element={
          <PageLayout>
            <SecurityReviewView />
          </PageLayout>
        }
      />
      <Route
        path="/developers"
        element={
          <PageLayout>
            <DevelopersView />
          </PageLayout>
        }
      />
      <Route path="/review" element={<Navigate to="/reviews" replace />} />
      <Route path="/security-review" element={<Navigate to="/reviews" replace />} />
      <Route
        path="/analytics"
        element={
          <PageLayout>
            <AnalyticsView />
          </PageLayout>
        }
      />
      <Route
        path="/false-positives"
        element={
          <PageLayout>
            <FalsePositivesView />
          </PageLayout>
        }
      />
      <Route
        path="/system"
        element={
          <PageLayout>
            <SystemView />
          </PageLayout>
        }
      />
      <Route
        path="/tools"
        element={
          <PageLayout>
            <ToolsView />
          </PageLayout>
        }
      />
      <Route
        path="/settings"
        element={
          <PageLayout>
            <SettingsView />
          </PageLayout>
        }
      />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
