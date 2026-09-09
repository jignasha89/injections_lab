'use client';

import { Database, Server, Scan, Zap } from 'lucide-react';
import ParseTreeGraphic from '@/components/shared/ParseTreeGraphic';
import Link from 'next/link';

export default function SettingsPage() {
  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12">
      {/* Header */}
      <div className="border-b border-border-strong pb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-text-primary flex items-center gap-3">
          Settings
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          System telemetry and scanner configuration
        </p>
      </div>

      <div className="max-w-2xl space-y-8">
        {/* Connection status */}
        <section className="space-y-4">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-widest flex items-center gap-2">
            <Database className="w-4 h-4 text-text-secondary" /> Database &amp; API driver
          </h2>

          <div className="cyber-card divide-y divide-border-strong overflow-hidden">
            <div className="flex justify-between items-center px-5 py-4">
              <span className="text-sm text-text-secondary">Database driver</span>
              <span className="text-sm text-text-primary font-mono font-medium">MongoDB Mongoose / MemoryDB</span>
            </div>
            <div className="flex justify-between items-center px-5 py-4">
              <span className="text-sm text-text-secondary">API endpoint</span>
              <span className="text-sm text-text-primary font-mono font-medium">http://localhost:5000/api</span>
            </div>
            <div className="flex justify-between items-center px-5 py-4">
              <span className="text-sm text-text-secondary">Rules engine</span>
              <span className="text-sm text-text-primary font-mono font-medium">v1.0 (55 rules)</span>
            </div>
            <div className="flex justify-between items-center px-5 py-4 bg-bg-base/50">
              <span className="text-sm text-text-secondary">Status</span>
              <span className="text-sm text-severity-low font-medium flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-severity-low animate-pulse" /> Active &amp; connected
              </span>
            </div>
          </div>
        </section>

        {/* Infrastructure */}
        <section className="space-y-4">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-widest flex items-center gap-2">
            <Server className="w-4 h-4 text-text-secondary" /> Platform infrastructure
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="cyber-card p-5 space-y-2">
              <div className="flex items-center gap-2">
                <Scan className="w-4 h-4 text-brand-primary" />
                <span className="text-text-primary font-medium text-sm">Passive scanner mode</span>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">Structural query parsing enabled. No active exploit payloads transmitted.</p>
            </div>
            <div className="cyber-card p-5 space-y-2">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-brand-primary" />
                <span className="text-text-primary font-medium text-sm">Report generation</span>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">Executive PDF report and structured CSV data exporter active.</p>
            </div>
          </div>
        </section>

        {/* Additional configuration — fills viewport */}
        <section className="space-y-4">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-widest flex items-center gap-2">
            <Zap className="w-4 h-4 text-text-secondary" /> Scanner rules
          </h2>
          <div className="cyber-card empty-state">
            <div className="empty-state-icon">
              <ParseTreeGraphic active={false} scale={1.2} />
            </div>
            <p className="empty-state-title">No custom rules configured</p>
            <p className="empty-state-desc">
              The built-in 55-rule engine covers all major injection families. Custom rules will appear here.
            </p>
            <Link href="/scanner" className="btn-cyber-primary px-5 py-2.5 text-xs font-semibold mt-2">
              View scanner
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}
