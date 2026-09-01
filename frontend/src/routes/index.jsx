import React from 'react';
import { Routes, Route } from 'react-router-dom';
import ApplicationLayout from '../layouts/ApplicationLayout';

import ProductEntryPage from '../pages/ProductEntryPage';
import CommandCenterPage from '../pages/CommandCenterPage';
import PRReviewPage from '../pages/PRReviewPage';
import RepoIntelligencePage from '../pages/RepoIntelligencePage';
import VulnerabilityExplorerPage from '../pages/VulnerabilityExplorerPage';
import AIAnalysisPage from '../pages/AIAnalysisPage';
import LearningCenterPage from '../pages/LearningCenterPage';
import SystemHealthPage from '../pages/SystemHealthPage';

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<ApplicationLayout />}>
        <Route index element={<ProductEntryPage />} />
        <Route path="command-center" element={<CommandCenterPage />} />
        <Route path="pr-review" element={<PRReviewPage />} />
        <Route path="repo-intelligence" element={<RepoIntelligencePage />} />
        <Route path="vulnerability-explorer" element={<VulnerabilityExplorerPage />} />
        <Route path="ai-analysis" element={<AIAnalysisPage />} />
        <Route path="learning-center" element={<LearningCenterPage />} />
        <Route path="system-health" element={<SystemHealthPage />} />
        <Route path="*" element={<ProductEntryPage />} />
      </Route>
    </Routes>
  );
}
