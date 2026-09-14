import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';

import DashboardView from '../views/DashboardView';
import AnalyzeView from '../views/AnalyzeView';
import RepositoryView from '../views/RepositoryView';
import HistoryView from '../views/HistoryView';
import PullRequestsView from '../views/PullRequestsView';
import SecurityReviewView from '../views/SecurityReviewView';
import AnalyticsView from '../views/AnalyticsView';
import SystemView from '../views/SystemView';
import TopHeader from '../components/dashboard/TopHeader';

function PageLayout({ children }) {
  return (
    <div className="cs-main-content-workspace">
      <TopHeader />
      <main className="cs-page-workspace" style={{ padding: '24px 32px', flex: 1, overflowY: 'auto' }}>
        {children}
      </main>
    </div>
  );
}

export default function AppRoutes() {
  return (
    <Routes>
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
        path="/reviews"
        element={
          <PageLayout>
            <SecurityReviewView />
          </PageLayout>
        }
      />
      <Route path="/review" element={<Navigate to="/reviews" replace />} />
      <Route
        path="/analytics"
        element={
          <PageLayout>
            <AnalyticsView />
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
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
