import React, { useState } from 'react';

/**
 * Alert dashboard with live feed, filters, and actions.
 * Req 17.1-17.12, 36.1-36.4.
 */
export default function Alerts() {
  const [filter, setFilter] = useState('all');

  const mockAlerts = [
    { id: 'ALT-001', title: 'Brute force attack detected', severity: 95, status: 'new', source: 'Auth Logs', time: '2m ago', entities: ['192.168.1.100', 'admin'] },
    { id: 'ALT-002', title: 'Malicious domain communication', severity: 82, status: 'new', source: 'DNS Logs', time: '5m ago', entities: ['evil-domain.com'] },
    { id: 'ALT-003', title: 'Unusual data transfer volume', severity: 68, status: 'acknowledged', source: 'NetFlow', time: '12m ago', entities: ['10.0.0.50'] },
    { id: 'ALT-004', title: 'Failed MFA bypass attempt', severity: 75, status: 'investigating', source: 'Auth Logs', time: '18m ago', entities: ['user@company.com'] },
    { id: 'ALT-005', title: 'Suspicious PowerShell execution', severity: 60, status: 'new', source: 'EDR', time: '25m ago', entities: ['DESKTOP-ABC123'] },
  ];

  const getSeverityColor = (severity: number) => {
    if (severity >= 80) return 'severity-critical';
    if (severity >= 60) return 'severity-high';
    if (severity >= 40) return 'severity-medium';
    if (severity >= 20) return 'severity-low';
    return 'severity-info';
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Alerts</h1>
        <div className="flex gap-2">
          {['all', 'new', 'acknowledged', 'investigating'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded text-sm capitalize ${
                filter === f ? 'bg-primary text-black' : 'bg-surface-200 text-gray-400'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        {mockAlerts
          .filter((a) => filter === 'all' || a.status === filter)
          .map((alert) => (
            <div key={alert.id} className="card flex items-center gap-4 hover:border-primary/30 cursor-pointer transition-colors">
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center text-lg font-bold ${getSeverityColor(alert.severity)} bg-surface-200`}>
                {alert.severity}
              </div>
              <div className="flex-1">
                <div className="font-medium">{alert.title}</div>
                <div className="text-xs text-gray-400 mt-1">
                  {alert.id} | {alert.source} | {alert.time}
                </div>
              </div>
              <div className="flex gap-2">
                {alert.entities.map((e, i) => (
                  <span key={i} className="bg-surface-200 text-xs px-2 py-1 rounded text-primary">
                    {e}
                  </span>
                ))}
              </div>
              <span className={`text-xs px-2 py-1 rounded capitalize ${
                alert.status === 'new' ? 'bg-severity-high/20 text-severity-high' :
                alert.status === 'acknowledged' ? 'bg-severity-medium/20 text-severity-medium' :
                'bg-severity-info/20 text-severity-info'
              }`}>
                {alert.status}
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}
