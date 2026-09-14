import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';

import DashboardView from '../views/DashboardView';
import AnalyzeView from '../views/AnalyzeView';
import RepositoryView from '../views/RepositoryView';
import HistoryView from '../views/HistoryView';
import SystemView from '../views/SystemView';

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<DashboardView />} />
      <Route path="/dashboard" element={<DashboardView />} />
      <Route path="/analyze" element={<AnalyzeView />} />
      <Route path="/repositories" element={<RepositoryView />} />
      <Route path="/history" element={<HistoryView />} />
      <Route path="/system" element={<SystemView />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
