import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import Sidebar from './components/dashboard/Sidebar';
import AppRoutes from './routes';
import './styles/index.css';
import './styles/dashboard.css';

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <div className="cs-app-layout">
        <Sidebar />
        <AppRoutes />
      </div>
    </BrowserRouter>
  );
}
