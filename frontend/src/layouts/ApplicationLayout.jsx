import React from 'react';
import { Outlet } from 'react-router-dom';
import SecurityCommandRail from '../components/SecurityCommandRail';
import IntelligenceBar from '../components/IntelligenceBar';

export default function ApplicationLayout() {
  return (
    <div className="app-container">
      {/* 64px Left Rail */}
      <SecurityCommandRail />

      {/* Main Viewport */}
      <div className="main-viewport">
        {/* 48px Top Intelligence Bar */}
        <IntelligenceBar />

        {/* Viewport Content for Active Route */}
        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
