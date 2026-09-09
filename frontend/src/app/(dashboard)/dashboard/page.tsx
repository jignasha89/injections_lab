'use client';

import { useState, useEffect, useRef } from 'react';
import { Terminal, Radio, Target } from 'lucide-react';
import GlobeVisualization from '@/components/dashboard/GlobeVisualization';
import Link from 'next/link';

const MOCK_LOGS = [
  "Initializing payload evasion engine...",
  "WAF evasion required for target constraints.",
  "Loading NoSQL injection vector (ID: 412).",
  "Bypass payload verified against filters.",
  "Syncing telemetry with command center.",
  "Executing blind SQLi on /api/graphql.",
  "Rate limit detected, throttling execution.",
  "Template injection payload successful.",
  "Exfiltrating data fragment...",
  "Session token identified in response."
];

export default function DashboardPage() {
  const [logs, setLogs] = useState<{id: number, text: string}[]>([]);
  const logsContainerRef = useRef<HTMLDivElement>(null);
  const logCounter = useRef(0);



  useEffect(() => {
    // Helper to generate a random log
    const createLog = (id: number) => {
      const nextLog = MOCK_LOGS[Math.floor(Math.random() * MOCK_LOGS.length)];
      
      const rand = Math.random();
      let level = '[INFO]';
      if (rand > 0.9) level = '[CRITICAL]';
      else if (rand > 0.75) level = '[HIGH]';
      else if (rand > 0.5) level = '[MEDIUM]';
      else if (rand > 0.3) level = '[LOW]';
      
      const time = new Date(Date.now() - (20 - id) * 1000).toLocaleTimeString('en-US', { hour12: false });
      return { id, text: `${time} ${level} ${nextLog}` };
    };

    // Pre-fill terminal so it doesn't look empty
    const initialLogs = Array.from({ length: 20 }).map((_, i) => {
      logCounter.current += 1;
      return createLog(logCounter.current);
    });
    setLogs(initialLogs);

    // Continuous fast stream
    const interval = setInterval(() => {
      logCounter.current += 1;
      const newLog = createLog(logCounter.current);
      newLog.text = newLog.text.replace(/:\d\d /, `:${new Date().getSeconds().toString().padStart(2, '0')} `); // Update to real current time
      
      setLogs(prev => {
        const newLogs = [...prev, newLog];
        return newLogs.slice(-25); // Keep last 25 logs for scrolling
      });
    }, 800);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (logsContainerRef.current) {
      logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
    }
  }, [logs]);



  return (
    <div className="absolute inset-0 p-6 lg:p-8 flex flex-col font-sans text-text-primary overflow-hidden">
      <div className="w-full h-full flex flex-col">

      {/* Header */}
      <div className="flex items-center justify-between pb-4 shrink-0 bg-gradient-to-r from-[#0d1222] via-[#090d18] to-purple-950/20 p-5 rounded-2xl border border-indigo-500/30 mb-5 shadow-[0_0_20px_rgba(99,102,241,0.15)] hover:border-cyan-400/40 hover:shadow-[0_0_25px_rgba(6,182,212,0.2)] hover:-translate-y-0.5 transition-all duration-300">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3 text-white">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse drop-shadow-[0_0_8px_#06b6d4]" />
            Threat Observatory
          </h1>
          <p className="text-[13px] text-slate-300 mt-1 font-medium">
            InjectionLab enterprise security assessment command center
          </p>
        </div>
        <Link href="/scanner" className="btn-cyber-primary px-5 py-2.5 text-sm flex items-center gap-2 shadow-[0_0_18px_rgba(99,102,241,0.4)] hover:shadow-[0_0_26px_rgba(6,182,212,0.6)] transition-all">
          <Target className="w-4 h-4" /> Deploy Assessment
        </Link>
      </div>

      {/* Main: Globe Left | Panels Right */}
      <div className="flex flex-1 gap-6 lg:gap-8 min-h-0 h-full w-full">

        {/* ── Globe Column ── */}
        <div className="relative flex-[1.5] shrink-0 rounded-2xl overflow-hidden border border-indigo-500/30 bg-gradient-to-b from-[#0a0e1a] via-[#060812] to-[#030408] shadow-[0_0_25px_rgba(99,102,241,0.15)] hover:border-purple-500/40 transition-all duration-300">
          {/* Status badge */}
          <div className="absolute top-4 left-4 z-10 flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0d1222]/90 backdrop-blur border border-cyan-400/40 text-[10px] font-mono text-cyan-200 uppercase tracking-widest shadow-[0_0_12px_rgba(6,182,212,0.25)] font-bold">
              <span className="relative flex h-3 w-3 items-center justify-center">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400 shadow-[0_0_12px_#06b6d4]"></span>
              </span>
              Live Telemetry
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#060812]/80 backdrop-blur border border-slate-700/60 text-[9px] font-bold text-slate-300 uppercase tracking-widest shadow-sm">
              Simulated
            </div>
          </div>
          <GlobeVisualization />
        </div>

        {/* ── Middle Column (Traffic Interceptor) ── */}
        <div className="flex-1 xl:flex-[1.2] shrink-0 flex flex-col gap-4 h-full relative overflow-hidden rounded-2xl border border-indigo-500/30 bg-gradient-to-b from-[#0a0e1a] via-[#060812] to-[#030408] p-6 shadow-[0_0_25px_rgba(99,102,241,0.15)] hover:border-cyan-400/40 hover:shadow-[0_0_30px_rgba(6,182,212,0.2)] hover:-translate-y-0.5 transition-all duration-300">
          <div className="flex items-center justify-between mb-2 shrink-0 relative z-20 border-b border-indigo-500/25 pb-3">
            <h3 className="text-[11px] font-bold text-cyan-300 uppercase tracking-widest flex items-center gap-2">
              <Radio className="w-4 h-4 text-amber-400 animate-pulse drop-shadow-[0_0_8px_#f59e0b]" /> Live Interceptor
            </h3>
            <span className="text-[9.5px] font-mono text-amber-300 px-2.5 py-1 rounded-md bg-amber-500/15 border border-amber-500/40 shadow-[0_0_10px_rgba(245,158,11,0.25)] font-bold animate-pulse">Active Proxy</span>
          </div>
          <div className="flex-1 overflow-hidden relative">
            <div className="absolute inset-0 overflow-y-auto [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none] font-mono text-[11px] text-slate-100 space-y-3 pb-6 flex flex-col-reverse">
              {logs.slice(0, 15).map((log) => (
                <div key={`traffic-${log.id}`} className="p-3 bg-[#0c101c] border border-cyan-500/30 rounded-xl shadow-md opacity-100 hover:bg-[#12182a] hover:border-cyan-400/60 hover:shadow-[0_0_15px_rgba(6,182,212,0.2)] transition-all">
                  <div className="text-[10px] text-cyan-300 mb-1.5 flex justify-between font-bold tracking-wide">
                    <span>TCP/IP {8000 + (log.id % 100)} &rarr; TARGET:443</span>
                    <span className={log.text.includes('[CRITICAL]') ? 'text-red-400 bg-red-950/70 px-2 py-0.5 rounded border border-red-500/50 font-bold' : 'text-emerald-400 bg-emerald-950/70 px-2 py-0.5 rounded border border-emerald-500/50 font-bold'}>
                      {log.text.includes('[CRITICAL]') ? 'BLOCKED' : '200 OK'}
                    </span>
                  </div>
                  <div className="break-all leading-relaxed text-slate-100">
                    <span className="text-emerald-400 font-extrabold text-[11.5px]">POST</span> <span className="text-white font-bold text-[11px]">/api/v1/execute</span> <span className="text-slate-200 font-semibold text-[11px]">HTTP/1.1</span><br/>
                    <span className="text-slate-200 font-semibold text-[11px]">Host: target.local</span><br/>
                    <span className="text-slate-200 font-semibold text-[11px]">Content-Length: {84 + log.id}</span>
                    <div className="text-[10px] text-cyan-200 mt-2 font-mono bg-[#050812] p-2 rounded-lg border border-slate-700/80 font-bold tracking-wider">
                      {Array.from({length: 16}).map((_, i) => Math.floor((Math.random() * log.id * 123) % 256).toString(16).padStart(2,'0')).join(' ')}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="absolute bottom-0 left-0 w-full h-12 bg-gradient-to-t from-[#030408] to-transparent pointer-events-none" />
            <div className="absolute top-0 left-0 w-full h-4 bg-gradient-to-b from-[#0a0e1a] to-transparent pointer-events-none" />
          </div>
        </div>

        {/* ── Right Panels Column ── */}
        <div className="flex-1 flex flex-col gap-6 overflow-y-auto h-full min-w-0 custom-scrollbar pr-1">

          {/* Active Payload Telemetry (Terminal) */}
          <div className="h-1/2 rounded-2xl border border-indigo-500/30 bg-gradient-to-br from-[#0a0e1a] via-[#060812] to-[#030408] p-6 flex flex-col relative overflow-hidden shadow-[0_0_25px_rgba(99,102,241,0.15)] hover:border-purple-400/40 hover:shadow-[0_0_30px_rgba(168,85,247,0.2)] hover:-translate-y-0.5 transition-all duration-300">
            <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-b from-transparent to-[#030408]/80 pointer-events-none z-10" />
            <div className="flex items-center justify-between mb-3 shrink-0 relative z-20 border-b border-indigo-500/25 pb-3">
              <h3 className="text-[11px] font-bold text-purple-300 uppercase tracking-widest flex items-center gap-2">
                <Terminal className="w-4 h-4 text-purple-400" /> Active Payload Telemetry
              </h3>
              <span className="relative flex h-3 w-3 items-center justify-center">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-purple-400 shadow-[0_0_12px_#c084fc]"></span>
              </span>
            </div>
            <div ref={logsContainerRef} className="flex-1 overflow-y-auto [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none] font-mono text-[11.5px] sm:text-[12px] leading-relaxed text-slate-100 space-y-2 relative z-0 pb-6 pr-2 font-medium">
              {logs.map((log) => (
                <div 
                  key={log.id} 
                  className="p-1 rounded hover:bg-slate-800/50 transition-colors"
                  style={{ 
                    animation: 'fadeInUp 0.3s ease forwards',
                    color: log.text.includes('[CRITICAL]') ? '#FF4D4D' :
                           log.text.includes('[HIGH]') ? '#FFA116' :
                           log.text.includes('[MEDIUM]') ? '#FFD700' :
                           log.text.includes('[LOW]') ? '#00E676' :
                           log.text.includes('[INFO]') ? '#38BDF8' : '#F1F5F9',
                    fontWeight: log.text.includes('[CRITICAL]') ? '700' :
                                log.text.includes('[HIGH]') ? '600' : '500'
                  }}
                >
                  {log.text}
                </div>
              ))}
            </div>
          </div>

          {/* Payload Distribution Chart */}
          <div className="h-1/2 rounded-2xl border border-indigo-500/30 bg-gradient-to-br from-[#0a0e1a] via-[#060812] to-[#030408] p-6 flex flex-col relative overflow-hidden shadow-[0_0_25px_rgba(99,102,241,0.15)] hover:border-cyan-400/40 hover:shadow-[0_0_30px_rgba(6,182,212,0.2)] hover:-translate-y-0.5 transition-all duration-300">
            <div className="flex items-center justify-between mb-4 shrink-0 relative z-20 border-b border-indigo-500/25 pb-3">
              <h3 className="text-[11px] font-bold text-white uppercase tracking-widest flex items-center gap-2">
                <Target className="w-4 h-4 text-cyan-400" /> Payload Distribution
              </h3>
              <span className="text-[11px] font-mono px-2.5 py-1 rounded-md bg-indigo-500/20 border border-indigo-400/40 text-cyan-300 font-bold shadow-sm">55 Active Families</span>
            </div>
            
            <div className="flex-1 flex flex-col justify-between text-xs space-y-3.5 pb-1">
              {/* Stat Row 1 */}
              <div className="group p-2.5 rounded-xl hover:bg-indigo-950/30 hover:shadow-[0_0_18px_rgba(99,102,241,0.2)] hover:border hover:border-indigo-400/40 transition-all duration-200 cursor-pointer">
                <div className="flex justify-between font-mono text-[11px] mb-1.5">
                  <span className="text-slate-100 font-semibold group-hover:text-cyan-300 transition-colors">Blind SQL Injection (Time-Based)</span>
                  <span className="text-cyan-400 font-bold">24%</span>
                </div>
                <div className="w-full bg-[#141a2e] rounded-full h-3 overflow-hidden p-0.5 border border-slate-700/60 shadow-inner">
                  <div className="bg-gradient-to-r from-indigo-500 via-purple-500 to-cyan-400 h-2 rounded-full shadow-[0_0_12px_rgba(99,102,241,0.7)] group-hover:scale-x-[1.02] origin-left transition-all duration-200" style={{ width: '24%' }}></div>
                </div>
              </div>

              {/* Stat Row 2 */}
              <div className="group p-2.5 rounded-xl hover:bg-amber-950/30 hover:shadow-[0_0_18px_rgba(245,158,11,0.2)] hover:border hover:border-amber-400/40 transition-all duration-200 cursor-pointer">
                <div className="flex justify-between font-mono text-[11px] mb-1.5">
                  <span className="text-slate-100 font-semibold group-hover:text-amber-300 transition-colors">Cross-Site Scripting (Reflected)</span>
                  <span className="text-amber-400 font-bold">18%</span>
                </div>
                <div className="w-full bg-[#141a2e] rounded-full h-3 overflow-hidden p-0.5 border border-slate-700/60 shadow-inner">
                  <div className="bg-gradient-to-r from-amber-500 via-yellow-400 to-orange-300 h-2 rounded-full shadow-[0_0_12px_rgba(245,158,11,0.7)] group-hover:scale-x-[1.02] origin-left transition-all duration-200" style={{ width: '18%' }}></div>
                </div>
              </div>

              {/* Stat Row 3 */}
              <div className="group p-2.5 rounded-xl hover:bg-red-950/30 hover:shadow-[0_0_18px_rgba(239,68,68,0.2)] hover:border hover:border-red-400/40 transition-all duration-200 cursor-pointer">
                <div className="flex justify-between font-mono text-[11px] mb-1.5">
                  <span className="text-slate-100 font-semibold group-hover:text-red-300 transition-colors">Server-Side Template Injection</span>
                  <span className="text-red-400 font-bold">15%</span>
                </div>
                <div className="w-full bg-[#141a2e] rounded-full h-3 overflow-hidden p-0.5 border border-slate-700/60 shadow-inner">
                  <div className="bg-gradient-to-r from-red-500 via-orange-500 to-amber-400 h-2 rounded-full shadow-[0_0_12px_rgba(239,68,68,0.7)] group-hover:scale-x-[1.02] origin-left transition-all duration-200" style={{ width: '15%' }}></div>
                </div>
              </div>

              {/* Stat Row 4 */}
              <div className="group p-2.5 rounded-xl hover:bg-emerald-950/30 hover:shadow-[0_0_18px_rgba(16,185,129,0.2)] hover:border hover:border-emerald-400/40 transition-all duration-200 cursor-pointer">
                <div className="flex justify-between font-mono text-[11px] mb-1.5">
                  <span className="text-slate-100 font-semibold group-hover:text-emerald-300 transition-colors">Path Traversal & LFI</span>
                  <span className="text-emerald-400 font-bold">12%</span>
                </div>
                <div className="w-full bg-[#141a2e] rounded-full h-3 overflow-hidden p-0.5 border border-slate-700/60 shadow-inner">
                  <div className="bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-300 h-2 rounded-full shadow-[0_0_12px_rgba(16,185,129,0.7)] group-hover:scale-x-[1.02] origin-left transition-all duration-200" style={{ width: '12%' }}></div>
                </div>
              </div>

              {/* Stat Row 5 */}
              <div className="group p-2.5 rounded-xl hover:bg-slate-800/40 hover:shadow-[0_0_18px_rgba(148,163,184,0.2)] hover:border hover:border-slate-500/40 transition-all duration-200 cursor-pointer">
                <div className="flex justify-between font-mono text-[11px] mb-1.5">
                  <span className="text-slate-100 font-semibold group-hover:text-slate-200 transition-colors">Other Injection Vectors (31 Families)</span>
                  <span className="text-slate-300 font-bold">31%</span>
                </div>
                <div className="w-full bg-[#141a2e] rounded-full h-3 overflow-hidden p-0.5 border border-slate-700/60 shadow-inner">
                  <div className="bg-gradient-to-r from-slate-500 via-zinc-400 to-slate-300 h-2 rounded-full shadow-[0_0_8px_rgba(148,163,184,0.5)] group-hover:scale-x-[1.02] origin-left transition-all duration-200" style={{ width: '31%' }}></div>
                </div>
              </div>
            </div>
          </div>

        </div>
        </div>
      </div>
    </div>
  );
}
