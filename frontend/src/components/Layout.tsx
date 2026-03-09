import React, { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';

/** Navigation items for the sidebar. Req 4.1 */
const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/alerts', label: 'Alerts', icon: '🔔' },
  { path: '/investigations', label: 'Investigations', icon: '🔍' },
  { path: '/hunting', label: 'Threat Hunting', icon: '🎯' },
  { path: '/settings', label: 'Settings', icon: '⚙️' },
];

/**
 * Main layout with collapsible sidebar (60px collapsed, 240px expanded),
 * top bar, and content area. Req 4.1, 6.5.
 */
export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const location = useLocation();

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside
        className={`flex-shrink-0 bg-surface-800 border-r border-surface-100 transition-all duration-200 ${
          sidebarOpen ? 'w-60' : 'w-[60px]'
        }`}
      >
        {/* Logo */}
        <div className="h-14 flex items-center px-4 border-b border-surface-100">
          <span className="text-primary font-bold text-lg">
            {sidebarOpen ? 'SIP' : 'S'}
          </span>
          {sidebarOpen && <span className="ml-2 text-sm text-gray-400">Security Intelligence</span>}
        </div>

        {/* Nav items */}
        <nav className="mt-4 space-y-1 px-2">
          {NAV_ITEMS.map((item) => {
            const active = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center px-3 py-2 rounded text-sm transition-colors ${
                  active
                    ? 'bg-surface-300 text-primary'
                    : 'text-gray-400 hover:text-white hover:bg-surface-200'
                }`}
              >
                <span className="text-lg">{item.icon}</span>
                {sidebarOpen && <span className="ml-3">{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Toggle */}
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="absolute bottom-4 left-4 text-gray-400 hover:text-white text-xs"
        >
          {sidebarOpen ? '<< Collapse' : '>>'}
        </button>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar. Req 17.1 */}
        <header className="h-14 bg-surface-800 border-b border-surface-100 flex items-center justify-between px-6">
          <div className="flex items-center gap-4">
            <input
              type="text"
              placeholder="Search events, entities, IOCs..."
              className="bg-surface-200 text-white px-4 py-1.5 rounded w-96 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div className="flex items-center gap-4">
            <span className="bg-severity-critical text-white text-xs px-2 py-1 rounded-full">3 Critical</span>
            <span className="text-gray-400 text-sm">analyst@sip.io</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
