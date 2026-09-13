import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import Navigation from './components/Navigation';
import AppRoutes from './routes';
import './styles/index.css';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Navigation />
        <main className="main-container">
          <AppRoutes />
        </main>
      </div>
    </BrowserRouter>
  );
}
