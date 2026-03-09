import React from 'react';

/**
 * Settings and administration page covering user management,
 * data sources, detection rules, playbooks, and system configuration.
 * Req 41.1-41.5.
 */
export default function Settings() {
  const sections = [
    { id: 'users', label: 'User Management', desc: 'Manage users, roles, and permissions. Req 10.1-10.12' },
    { id: 'sources', label: 'Data Sources', desc: 'Configure and monitor data source connections. Req 1.1-1.10' },
    { id: 'rules', label: 'Detection Rules', desc: 'Create and manage threat detection rules. Req 2.1-2.10' },
    { id: 'playbooks', label: 'Playbooks', desc: 'Design and manage automated response playbooks. Req 9.1-9.10' },
    { id: 'retention', label: 'Data Retention', desc: 'Configure retention policies and archival. Req 12.1-12.12' },
    { id: 'notifications', label: 'Notifications', desc: 'Configure alert notification channels. Req 17.4' },
    { id: 'threat-intel', label: 'Threat Intelligence', desc: 'Manage threat intelligence feeds. Req 7.1-7.10' },
    { id: 'system', label: 'System Configuration', desc: 'Platform-wide configuration settings. Req 29.1-29.12' },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Settings & Administration</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sections.map((s) => (
          <div key={s.id} className="card hover:border-primary/30 cursor-pointer transition-colors">
            <h3 className="font-medium text-white">{s.label}</h3>
            <p className="text-sm text-gray-400 mt-1">{s.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
