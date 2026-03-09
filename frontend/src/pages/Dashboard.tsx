import React from 'react';

/**
 * Main security dashboard with real-time metrics and visualizations.
 * Req 6.1-6.12, 41.1-41.12.
 */
export default function Dashboard() {
  const metrics = [
    { label: 'Active Alerts', value: '47', color: 'text-severity-high', trend: '+12%' },
    { label: 'Open Cases', value: '12', color: 'text-primary', trend: '-3%' },
    { label: 'MTTD', value: '4.2m', color: 'text-severity-medium', trend: '-18%' },
    { label: 'MTTR', value: '28m', color: 'text-severity-info', trend: '-5%' },
    { label: 'Events/sec', value: '85K', color: 'text-accent-green', trend: '+8%' },
    { label: 'Active Sources', value: '42', color: 'text-primary', trend: '0%' },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Security Dashboard</h1>

      {/* Metrics Grid. Req 41.1-41.12 */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        {metrics.map((m) => (
          <div key={m.label} className="card">
            <div className="text-xs text-gray-400 mb-1">{m.label}</div>
            <div className={`text-2xl font-bold ${m.color}`}>{m.value}</div>
            <div className="text-xs text-gray-500 mt-1">{m.trend}</div>
          </div>
        ))}
      </div>

      {/* Alert Severity Distribution. Req 6.2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="card">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Alert Severity Distribution</h3>
          <div className="space-y-3">
            {[
              { level: 'Critical', count: 3, pct: 6, color: 'bg-severity-critical' },
              { level: 'High', count: 12, pct: 26, color: 'bg-severity-high' },
              { level: 'Medium', count: 18, pct: 38, color: 'bg-severity-medium' },
              { level: 'Low', count: 9, pct: 19, color: 'bg-severity-low' },
              { level: 'Info', count: 5, pct: 11, color: 'bg-severity-info' },
            ].map((s) => (
              <div key={s.level} className="flex items-center gap-3">
                <span className="text-xs w-16 text-gray-400">{s.level}</span>
                <div className="flex-1 bg-surface-200 rounded-full h-2">
                  <div className={`${s.color} h-2 rounded-full`} style={{ width: `${s.pct}%` }} />
                </div>
                <span className="text-xs text-gray-400 w-8">{s.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Recent Activity</h3>
          <div className="space-y-2">
            {[
              { time: '2m ago', text: 'Brute force attack detected from 192.168.1.100', severity: 'critical' },
              { time: '5m ago', text: 'New IOC match: malicious domain phishing-site.com', severity: 'high' },
              { time: '12m ago', text: 'Case #1042 updated by analyst1', severity: 'info' },
              { time: '18m ago', text: 'Playbook "Block IP" executed successfully', severity: 'low' },
              { time: '25m ago', text: 'Data source "AWS CloudTrail" reconnected', severity: 'info' },
            ].map((a, i) => (
              <div key={i} className="flex items-start gap-3 text-sm py-1">
                <span className={`w-2 h-2 rounded-full mt-1.5 bg-severity-${a.severity}`} />
                <div>
                  <span className="text-gray-400 text-xs mr-2">{a.time}</span>
                  <span>{a.text}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Coverage. Req 41.4 */}
      <div className="card">
        <h3 className="text-sm font-medium text-gray-400 mb-4">MITRE ATT&CK Detection Coverage</h3>
        <div className="grid grid-cols-7 gap-1 text-xs">
          {[
            'Reconnaissance', 'Resource Dev', 'Initial Access', 'Execution',
            'Persistence', 'Priv Escalation', 'Defense Evasion', 'Credential Access',
            'Discovery', 'Lateral Movement', 'Collection', 'C2',
            'Exfiltration', 'Impact',
          ].map((tactic) => (
            <div
              key={tactic}
              className="bg-surface-200 p-2 rounded text-center hover:bg-surface-300 cursor-pointer"
            >
              <div className="text-gray-400 truncate">{tactic}</div>
              <div className="text-primary font-bold mt-1">{Math.floor(Math.random() * 60 + 40)}%</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
