import React from 'react';

/**
 * Investigation workspace with case management, evidence panel,
 * graph visualization, timeline, and query builder.
 * Req 4.1-4.10, 19.1-19.14, 37.1-37.6.
 */
export default function Investigations() {
  const mockCases = [
    { id: 'CASE-001', title: 'APT29 Suspected Intrusion', severity: 90, status: 'investigating', assignee: 'analyst1', evidence: 12, created: '2024-01-15' },
    { id: 'CASE-002', title: 'Insider Data Exfiltration', severity: 75, status: 'open', assignee: 'analyst2', evidence: 5, created: '2024-01-16' },
    { id: 'CASE-003', title: 'Phishing Campaign Analysis', severity: 60, status: 'investigating', assignee: 'analyst1', evidence: 8, created: '2024-01-17' },
    { id: 'CASE-004', title: 'Ransomware Indicator Found', severity: 85, status: 'contained', assignee: 'analyst3', evidence: 15, created: '2024-01-18' },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Investigations</h1>
        <button className="btn-primary">New Case</button>
      </div>

      {/* Cases List. Req 19.1 */}
      <div className="grid gap-4">
        {mockCases.map((c) => (
          <div key={c.id} className="card hover:border-primary/30 cursor-pointer transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-400">{c.id}</span>
                  <h3 className="font-medium">{c.title}</h3>
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  Assigned to {c.assignee} | {c.evidence} evidence items | Created {c.created}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-sm font-bold ${
                  c.severity >= 80 ? 'severity-critical' : c.severity >= 60 ? 'severity-high' : 'severity-medium'
                }`}>
                  Sev: {c.severity}
                </span>
                <span className={`text-xs px-2 py-1 rounded capitalize ${
                  c.status === 'investigating' ? 'bg-severity-info/20 text-severity-info' :
                  c.status === 'contained' ? 'bg-severity-medium/20 text-severity-medium' :
                  'bg-surface-200 text-gray-400'
                }`}>
                  {c.status}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Investigation Workspace placeholder. Req 4.3-4.10 */}
      <div className="mt-8 card">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Investigation Workspace</h3>
        <div className="grid grid-cols-2 gap-4 h-64">
          <div className="bg-surface-200 rounded-lg flex items-center justify-center text-gray-400">
            Entity Relationship Graph (D3.js) - Req 4.3
          </div>
          <div className="bg-surface-200 rounded-lg flex items-center justify-center text-gray-400">
            Event Timeline - Req 4.4
          </div>
        </div>
      </div>
    </div>
  );
}
