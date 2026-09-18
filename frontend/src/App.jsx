import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import AppRoutes from './routes';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './components/common/ToastContext';
import { SidebarProvider } from './components/dashboard/SidebarContext';
import './styles/index.css';
import './styles/dashboard.css';

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <ToastProvider>
          <SidebarProvider>
            <a href="#main-content" className="cs-skip-link">Skip to main content</a>
            <AppRoutes />
          </SidebarProvider>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
