'use client';

import { useState } from 'react';
import CompactGlobe from '@/components/dashboard/CompactGlobe';
import { CheckCircle, Globe, Table } from 'lucide-react';

export interface ScanResultRow {
  id: number;
  type: string;
  parameter: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'Confirmed' | 'Pending' | 'Testing';
  count?: number;
}

export interface CenterPanelProps {
  scanResults: ScanResultRow[];
  globeWidth?: number;
  globeHeight?: number;
}

export default function CenterPanel({ 
  scanResults,
  globeWidth = 500,
  globeHeight = 400
}: CenterPanelProps) {
  const [activeTab, setActiveTab] = useState<'observatory' | 'results'>('observatory');

  return (
    <div className="rounded-2xl bg-[#070b1e]/90 border border-[#00d4ff]/35 p-6 shadow-[0_0_25px_rgba(0,212,255,0.12)] font-mono">
      {/* Tab Bar Header */}
      <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-4 mb-6">
        <div className="flex gap-2 bg-[#040714] p-1 rounded-xl border border-[#00d4ff]/30">
          <button
            type="button"
            onClick={() => setActiveTab('observatory')}
            className={`px-4 py-2 rounded-lg text-xs font-mono font-bold uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'observatory'
                ? 'bg-[#00d4ff] text-[#0a0e27] shadow-[0_0_14px_rgba(0,212,255,0.5)]'
                : 'text-[#a0aec0] hover:text-white'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>THREAT OBSERVATORY</span>
          </button>
          
          <button
            type="button"
            onClick={() => setActiveTab('results')}
            className={`px-4 py-2 rounded-lg text-xs font-mono font-bold uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'results'
                ? 'bg-[#00d4ff] text-[#0a0e27] shadow-[0_0_14px_rgba(0,212,255,0.5)]'
                : 'text-[#a0aec0] hover:text-white'
            }`}
          >
            <Table className="w-3.5 h-3.5" />
            <span>SCAN RESULTS</span>
          </button>
        </div>

        <span className="hidden sm:flex text-xs font-mono text-[#00ff00] items-center gap-1.5 font-bold">
          <span className="w-2 h-2 rounded-full bg-[#00ff00] animate-ping" />
          LIVE STREAM
        </span>
      </div>

      {/* TAB 1: THREAT OBSERVATORY (3D Globe 500x400px) */}
      {activeTab === 'observatory' && (
        <div className="space-y-4 flex flex-col items-center justify-center min-h-[420px]">
          <div 
            className="w-full rounded-xl overflow-hidden relative border border-[#00d4ff]/20 bg-transparent flex items-center justify-center"
            style={{ maxWidth: `${globeWidth}px`, height: `${globeHeight}px` }}
          >
            <CompactGlobe width={globeWidth} height={globeHeight} className="mx-auto" />
          </div>
          <p className="text-xs text-[#a0aec0] font-mono text-center">
            Regional Threat Telemetry: USA (7,943), UK (7,943), CHINA (31,216), INDIA (8,415), UAE (5,248), BRAZIL (9,277)
          </p>
        </div>
      )}

      {/* TAB 2: SCAN RESULTS (Vulnerability Findings Table: Type | Parameter | Risk | Status | Count) */}
      {activeTab === 'results' && (
        <div className="overflow-x-auto min-h-[420px]">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#00d4ff]/30 bg-[#040714] text-[#00d4ff]">
                <th className="p-3 font-bold uppercase tracking-wider">Type</th>
                <th className="p-3 font-bold uppercase tracking-wider">Parameter</th>
                <th className="p-3 font-bold uppercase tracking-wider">Risk</th>
                <th className="p-3 font-bold uppercase tracking-wider">Status</th>
                <th className="p-3 font-bold uppercase tracking-wider text-right">Count</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#00d4ff]/10 text-slate-200">
              {scanResults.map((row) => {
                let riskStyle = 'bg-[#ffb800]/20 text-[#ffb800] border-[#ffb800]/40';
                if (row.risk === 'CRITICAL') {
                  riskStyle = 'bg-[#ff0051]/20 text-[#ff0051] border-[#ff0051]/50 shadow-[0_0_8px_rgba(255,0,81,0.35)]';
                } else if (row.risk === 'HIGH') {
                  riskStyle = 'bg-[#ff9500]/20 text-[#ff9500] border-[#ff9500]/40';
                } else if (row.risk === 'MEDIUM') {
                  riskStyle = 'bg-[#ffb800]/20 text-[#ffb800] border-[#ffb800]/40';
                }

                return (
                  <tr 
                    key={row.id} 
                    className="hover:bg-[#00d4ff]/10 transition-colors odd:bg-[#040714]/40 even:bg-[#070b1e]/60"
                  >
                    <td className="p-3 font-bold text-white">{row.type}</td>
                    <td className="p-3 text-cyan-300 font-mono">{row.parameter}</td>
                    <td className="p-3">
                      <span className={`px-2.5 py-0.5 rounded border text-[10px] font-bold uppercase ${riskStyle}`}>
                        {row.risk}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className="text-[#00ff00] font-bold flex items-center gap-1">
                        <CheckCircle className="w-3.5 h-3.5 text-[#00ff00]" /> {row.status}
                      </span>
                    </td>
                    <td className="p-3 text-right font-bold text-cyan-400 font-mono">
                      {row.count || Math.floor(Math.random() * 12) + 1}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
