import React, { useState, useEffect } from 'react';
import TopHeader from '../components/dashboard/TopHeader';
import HeroBanner from '../components/dashboard/HeroBanner';
import MetricCardsGrid from '../components/dashboard/MetricCard';
import SeverityChart from '../components/dashboard/SeverityChart';
import AnalysisTrendChart from '../components/dashboard/AnalysisTrendChart';
import SecurityGateChart from '../components/dashboard/SecurityGateChart';
import RecentAnalysesTable from '../components/dashboard/RecentAnalysesTable';
import LatestAnalysisPanel from '../components/dashboard/LatestAnalysisPanel';
import Footer from '../components/dashboard/Footer';
import { fetchDashboardData, createDashboardFallbackData } from '../services/dashboardService';

export default function DashboardView() {
  const [dashboardData, setDashboardData] = useState(() => createDashboardFallbackData());
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;

    async function loadData() {
      try {
        const data = await fetchDashboardData();
        if (isMounted && data) {
          setDashboardData(data);
        }
      } catch (err) {
        console.warn('Dashboard data fetch encountered an issue, retaining baseline:', err);
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    loadData();

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <div className="cs-main-content-workspace">
      {/* Top Header */}
      <TopHeader />

      {/* Main Workspace Scroll Area */}
      <main id="main-content" tabIndex={-1} className="cs-dashboard-workspace">
        {/* Hero Section */}
        <HeroBanner />

        {/* 4 Metric Cards */}
        <MetricCardsGrid metrics={dashboardData.dashboardMetrics} />

        {/* 3 Analytics Cards */}
        <section className="cs-analytics-grid" aria-label="Analytics Overview">
          <SeverityChart
            data={dashboardData.severityBreakdown}
            total={dashboardData.totalFindingsCount}
          />
          <AnalysisTrendChart data={dashboardData.analysisTrend} />
          <SecurityGateChart
            data={dashboardData.gateDistribution}
            total={dashboardData.totalGateAnalysesCount}
          />
        </section>

        {/* Main 2-Column Section: Table + Latest Analysis Panel */}
        <section className="cs-main-columns-grid" aria-label="Recent Analyses and Details">
          <RecentAnalysesTable data={dashboardData.recentAnalyses} />
          <LatestAnalysisPanel
            latestAnalysis={dashboardData.latestAnalysis}
            latestFindings={dashboardData.latestFindings}
            findingPreview={dashboardData.findingPreview}
            productionStatus={dashboardData.productionStatus}
          />
        </section>

        {/* Footer */}
        <Footer />
      </main>
    </div>
  );
}
