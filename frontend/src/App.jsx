import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import AppRoutes from './routes';
import './styles/index.css';

export default function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}
