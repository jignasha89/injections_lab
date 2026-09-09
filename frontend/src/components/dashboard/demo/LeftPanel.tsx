'use client';

import { Search, Play, RefreshCw, Zap } from 'lucide-react';

export interface VulnStats {
  sqli: number;
  xss: number;
  cmdi: number;
  ldap: number;
}

export interface LeftPanelProps {
  targetUrl: string;
  onUrlChange: (url: string) => void;
  onStartScan: () => void;
  isScanning: boolean;
  stats: VulnStats;
}

export default function LeftPanel({
  targetUrl,
  onUrlChange,
  onStartScan,
  isScanning,
  stats
}: LeftPanelProps) {
  return (
    <div className="p-6 rounded-2xl bg-[#070b1e]/90 border border-[#00d4ff]/35 shadow-[0_0_25px_rgba(0,212,255,0.12)] hover:border-[#00d4ff]/60 transition-all font-mono">
      {/* Title */}
      <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-4 mb-6">
        <h2 className="text-base font-bold text-[#00d4ff] uppercase tracking-widest flex items-center gap-2">
          <Search className="w-4.5 h-4.5 text-[#00d4ff]" /> INJECTION SCANNER
        </h2>
        <span className="text-[10px] font-mono text-[#00d4ff] px-2 py-0.5 rounded bg-[#00d4ff]/10 border border-[#00d4ff]/30 uppercase font-bold">
          v2.4 Engine
        </span>
      </div>

      {/* URL Input Section */}
      <div className="space-y-4">
        <div>
          <label 
            htmlFor="target-url-input" 
            className="block text-xs font-mono font-bold text-[#a0aec0] uppercase tracking-wider mb-2"
          >
            Target URL
          </label>
          <div className="relative">
            <input
              id="target-url-input"
              type="text"
              value={targetUrl}
              onChange={(e) => onUrlChange(e.target.value)}
              placeholder="https://example.com?id=1&search=test"
              className="w-full h-[44px] px-4 rounded-[4px] bg-[#040714] border border-[#00d4ff]/30 text-xs md:text-sm text-white font-mono placeholder:text-text-secondary/30 focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff]/50 transition-all outline-none"
            />
          </div>
        </div>

        {/* SCAN NOW Button */}
        <button
          type="button"
          onClick={onStartScan}
          disabled={isScanning}
          className="w-full h-[44px] rounded-[4px] bg-[#00d4ff] hover:bg-[#33ddff] text-[#0a0e27] font-mono font-extrabold text-sm uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(0,212,255,0.4)] hover:shadow-[0_0_30px_rgba(0,212,255,0.75)] hover:scale-[1.01] active:scale-[0.99] flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-[#0a0e27]" />
              <span>SCANNING TARGET...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current text-[#0a0e27]" />
              <span>SCAN NOW</span>
            </>
          )}
        </button>
      </div>

      {/* Vulnerability Stats 2x2 Grid (Margin-top: 24px) */}
      <div className="mt-6 pt-6 border-t border-[#00d4ff]/20">
        <span className="text-xs font-mono font-bold text-[#a0aec0] uppercase tracking-wider block mb-4">
          Vulnerability Stats
        </span>

        <div className="grid grid-cols-2 gap-3">
          {/* 1. SQL Injection */}
          <div className="p-[12px] rounded-[4px] bg-[#ff0051]/15 border border-[#ff0051] text-[#ff0051] shadow-[0_0_12px_rgba(255,0,81,0.2)] hover:scale-[1.02] transition-transform">
            <span className="text-[28px] font-bold font-mono block leading-none drop-shadow-[0_0_8px_rgba(255,0,81,0.6)]">
              {stats.sqli}
            </span>
            <span className="text-[11px] font-mono uppercase font-semibold text-slate-200 mt-1.5 block">
              SQL Injection
            </span>
          </div>

          {/* 2. XSS Attacks */}
          <div className="p-[12px] rounded-[4px] bg-[#ff9500]/15 border border-[#ff9500] text-[#ff9500] shadow-[0_0_12px_rgba(255,149,0,0.2)] hover:scale-[1.02] transition-transform">
            <span className="text-[28px] font-bold font-mono block leading-none drop-shadow-[0_0_8px_rgba(255,149,0,0.6)]">
              {stats.xss}
            </span>
            <span className="text-[11px] font-mono uppercase font-semibold text-slate-200 mt-1.5 block">
              XSS Attacks
            </span>
          </div>

          {/* 3. Command Injection */}
          <div className="p-[12px] rounded-[4px] bg-[#ff0051]/15 border border-[#ff0051] text-[#ff0051] shadow-[0_0_12px_rgba(255,0,81,0.2)] hover:scale-[1.02] transition-transform">
            <span className="text-[28px] font-bold font-mono block leading-none drop-shadow-[0_0_8px_rgba(255,0,81,0.6)]">
              {stats.cmdi}
            </span>
            <span className="text-[11px] font-mono uppercase font-semibold text-slate-200 mt-1.5 block">
              Command Injection
            </span>
          </div>

          {/* 4. LDAP Injection */}
          <div className="p-[12px] rounded-[4px] bg-[#ff9500]/15 border border-[#ff9500] text-[#ff9500] shadow-[0_0_12px_rgba(255,149,0,0.2)] hover:scale-[1.02] transition-transform">
            <span className="text-[28px] font-bold font-mono block leading-none drop-shadow-[0_0_8px_rgba(255,149,0,0.6)]">
              {stats.ldap}
            </span>
            <span className="text-[11px] font-mono uppercase font-semibold text-slate-200 mt-1.5 block">
              LDAP Injection
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
