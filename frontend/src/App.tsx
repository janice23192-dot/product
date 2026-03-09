import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Investigations from './pages/Investigations';
import ThreatHunting from './pages/ThreatHunting';
import Settings from './pages/Settings';

/**
 * Main application component.
 * Routes to all major pages per the UI design spec.
 */
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="investigations" element={<Investigations />} />
        <Route path="hunting" element={<ThreatHunting />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
