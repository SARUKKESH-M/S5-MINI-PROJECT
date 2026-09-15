import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import Sidebar from './components/dashboard/Sidebar';
import AppRoutes from './routes';
import { ToastProvider } from './components/common/ToastContext';
import { SidebarProvider } from './components/dashboard/SidebarContext';
import './styles/index.css';
import './styles/dashboard.css';

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <ToastProvider>
        <SidebarProvider>
          <a href="#main-content" className="cs-skip-link">Skip to main content</a>
          <div className="cs-app-layout">
            <Sidebar />
            <AppRoutes />
          </div>
        </SidebarProvider>
      </ToastProvider>
    </BrowserRouter>
  );
}
