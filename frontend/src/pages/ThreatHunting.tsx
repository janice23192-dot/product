import React from 'react';

/**
 * Threat hunting workspace with hypothesis-driven workflows,
 * query libraries, and hunting notebooks. Req 23.1-23.12, 39.1-39.3.
 */
export default function ThreatHunting() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Threat Hunting</h1>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* MITRE ATT&CK Query Library. Req 23.2 */}
        <div className="card">
          <h3 className="text-sm font-medium text-gray-400 mb-4">MITRE ATT&CK Hunting Queries</h3>
          <div className="space-y-2">
            {[
              { technique: 'T1059', name: 'Command & Scripting', count: 12 },
              { technique: 'T1071', name: 'Application Layer Protocol', count: 8 },
              { technique: 'T1021', name: 'Remote Services', count: 6 },
              { technique: 'T1053', name: 'Scheduled Task/Job', count: 5 },
              { technique: 'T1078', name: 'Valid Accounts', count: 10 },
            ].map((q) => (
              <div key={q.technique} className="flex items-center justify-between py-2 px-3 rounded bg-surface-200 hover:bg-surface-300 cursor-pointer">
                <div>
                  <span className="text-primary text-xs mr-2">{q.technique}</span>
                  <span className="text-sm">{q.name}</span>
                </div>
                <span className="text-xs text-gray-400">{q.count} queries</span>
              </div>
            ))}
          </div>
        </div>

        {/* Active Hunts. Req 23.5 */}
        <div className="card col-span-2">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Active Hunting Sessions</h3>
          <div className="space-y-3">
            {[
              { id: 'HUNT-001', hypothesis: 'Lateral movement via RDP', status: 'active', findings: 2 },
              { id: 'HUNT-002', hypothesis: 'DNS tunneling exfiltration', status: 'active', findings: 0 },
              { id: 'HUNT-003', hypothesis: 'Credential harvesting via phishing', status: 'completed', findings: 5 },
            ].map((h) => (
              <div key={h.id} className="bg-surface-200 p-3 rounded hover:bg-surface-300 cursor-pointer">
                <div className="flex justify-between">
                  <span className="font-medium text-sm">{h.hypothesis}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    h.status === 'active' ? 'bg-accent-green/20 text-accent-green' : 'bg-gray-600/20 text-gray-400'
                  }`}>{h.status}</span>
                </div>
                <div className="text-xs text-gray-400 mt-1">{h.id} | {h.findings} findings</div>
              </div>
            ))}
          </div>

          {/* Query Builder. Req 5.1 */}
          <div className="mt-6">
            <h4 className="text-sm text-gray-400 mb-2">Hunting Query</h4>
            <textarea
              className="w-full bg-surface-900 text-primary font-mono text-sm p-3 rounded border border-surface-100 focus:outline-none focus:ring-1 focus:ring-primary"
              rows={4}
              placeholder='source_type:"authentication" AND result:"failure" AND severity:>50 | stats count by username | where count > 10'
            />
            <button className="btn-primary mt-2 text-sm">Run Query</button>
          </div>
        </div>
      </div>
    </div>
  );
}
