'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { Target, Radio, Activity, ShieldAlert, Cpu, Terminal } from 'lucide-react';
import CompactGlobe from '@/components/dashboard/CompactGlobe';

export interface InterceptorPayload {
  id: number;
  time: string;
  tcpPort: string;
  targetPort: string;
  method: string;
  path: string;
  host: string;
  contentLength: number;
  hexData: string;
  status: string;
}

const INITIAL_PAYLOADS: InterceptorPayload[] = [
  {
    id: 1,
    time: '14:32:45',
    tcpPort: '@053',
    targetPort: '443',
    method: 'POST',
    path: '/api/v1/execute',
    host: 'target.local',
    contentLength: 1038,
    hexData: '30 51 a5 b2 13 1b 84 19 fc 53 63 51 c4 cf 3f 23 e2',
    status: '200 OK'
  },
  {
    id: 2,
    time: '14:32:40',
    tcpPort: '@052',
    targetPort: '443',
    method: 'POST',
    path: '/api/v1/execute',
    host: 'target.local',
    contentLength: 1036,
    hexData: '84 22 bc 37 5e b0 37 d9 23 e7 5d 29 c1 c4 7e 04',
    status: '200 OK'
  },
  {
    id: 3,
    time: '14:32:35',
    tcpPort: '@051',
    targetPort: '443',
    method: 'POST',
    path: '/api/v1/graphql',
    host: 'target.local',
    contentLength: 1104,
    hexData: '7b 22 71 75 65 72 79 22 3a 20 22 7b 20 75 73 65 72 73',
    status: '200 OK'
  },
  {
    id: 4,
    time: '14:32:30',
    tcpPort: '@050',
    targetPort: '443',
    method: 'POST',
    path: '/api/v1/auth/login',
    host: 'target.local',
    contentLength: 984,
    hexData: '27 20 4f 52 20 27 31 27 3d 27 31 20 2d 2d 20 41 44',
    status: '200 OK'
  }
];

export interface InjectionStatItem {
  id: string;
  name: string;
  percent: number;
  color: string;
  barColor: string;
}

export default function DashboardPage() {
  // Payloads Interceptor Stream
  const [payloads, setPayloads] = useState<InterceptorPayload[]>(INITIAL_PAYLOADS);
  const interceptorRef = useRef<HTMLDivElement>(null);

  // Injection Statistics State
  const [stats, setStats] = useState<InjectionStatItem[]>([
    { id: 'sqli', name: 'Blind SQL Injection (Time-Based)', percent: 24, color: '#00d4ff', barColor: 'from-[#3b82f6] to-[#00d4ff]' },
    { id: 'xss', name: 'Cross-Site Scripting (Reflected)', percent: 19, color: '#ff9500', barColor: 'bg-[#ff9500]' },
    { id: 'ssti', name: 'Server-Side Template Injection', percent: 15, color: '#ff0051', barColor: 'bg-[#ff0051]' },
    { id: 'cmdi', name: 'OS Command Execution', percent: 14, color: '#7c3aed', barColor: 'bg-[#7c3aed]' },
    { id: 'nosql', name: 'NoSQL Query Tampering', percent: 12, color: '#ec4899', barColor: 'bg-[#ec4899]' },
    { id: 'ldap', name: 'LDAP / XPath Fuzzing', percent: 10, color: '#ffb800', barColor: 'bg-[#ffb800]' },
    { id: 'traversal', name: 'Path Traversal / SSRF', percent: 6, color: '#00ff00', barColor: 'bg-[#00ff00]' },
  ]);

  // Stream new live payloads every 5 seconds
  useEffect(() => {
    const hexSamples = [
      'a9 4f 12 c8 7b 3a 90 f4 1c d2 8e 5e 33 b1 70 e9',
      '55 b8 e1 09 4c 9a 21 df 67 89 12 c3 45 f6 78 90',
      '7b 22 69 64 22 3a 20 22 27 20 4f 52 20 31 3d 31',
      '3c 73 63 72 69 70 74 3e 61 6c 65 72 74 28 31 29'
    ];
    const pathSamples = [
      '/api/v1/execute',
      '/api/v1/graphql',
      '/api/v2/auth/login',
      '/api/v1/user/search'
    ];

    let portCounter = 54;

    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
      portCounter += 1;

      const newEntry: InterceptorPayload = {
        id: Date.now(),
        time: timeStr,
        tcpPort: `@0${portCounter}`,
        targetPort: '443',
        method: 'POST',
        path: pathSamples[Math.floor(Math.random() * pathSamples.length)],
        host: 'target.local',
        contentLength: Math.floor(Math.random() * 200) + 950,
        hexData: hexSamples[Math.floor(Math.random() * hexSamples.length)],
        status: '200 OK'
      };

      setPayloads(prev => [newEntry, ...prev.slice(0, 15)]);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // Update Injection Statistics percentages every 4 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => {
        const delta = (Math.random() - 0.5) * 2;
        const newStats = prev.map(item => {
          if (item.id === 'sqli') {
            const nextP = Math.min(30, Math.max(20, Math.round(item.percent + delta)));
            return { ...item, percent: nextP };
          }
          if (item.id === 'xss') {
            const nextP = Math.min(25, Math.max(15, Math.round(item.percent - delta * 0.5)));
            return { ...item, percent: nextP };
          }
          return item;
        });
        return newStats;
      });
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0e27] font-mono text-white flex flex-col selection:bg-[#00d4ff]/30 p-6 md:p-8">
      
      {/* ── TOP HEADER (Height: 80px) ── */}
      <header className="h-[80px] border-b border-[#00d4ff]/30 pb-4 mb-6 flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white flex items-center gap-3 font-mono">
            <Radio className="w-6 h-6 text-[#00d4ff] animate-pulse drop-shadow-[0_0_10px_#00d4ff]" />
            Threat Observatory
          </h1>
          <p className="text-xs md:text-sm text-[#a0aec0] font-mono mt-1">
            InjectionLab enterprise security assessment command center
          </p>
        </div>

        {/* Deploy Assessment Button (Gradient Purple -> Blue) */}
        <Link
          href="/scanner"
          className="px-6 py-3 rounded-xl bg-gradient-to-r from-[#7c3aed] to-[#3b82f6] hover:from-[#8b5cf6] hover:to-[#60a5fa] text-white font-mono font-extrabold text-sm uppercase tracking-wider flex items-center gap-2 shadow-[0_0_20px_rgba(124,58,237,0.45)] hover:shadow-[0_0_30px_rgba(59,130,246,0.65)] hover:scale-[1.02] active:scale-[0.98] transition-all"
        >
          <Target className="w-5 h-5 text-white" />
          <span>Deploy Assessment</span>
        </Link>
      </header>

      {/* ── MAIN CONTENT: 3-COLUMN LAYOUT (35% | 35% | 30%) ── */}
      <main className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 items-start">

        {/* ── LEFT COLUMN (35% width / 4.2 cols -> lg:col-span-4) ── */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-6 rounded-lg bg-[#0f1535]/50 border border-[#00d4ff]/30 shadow-[0_0_20px_rgba(0,212,255,0.1)] hover:border-[#00d4ff]/50 transition-all">
            
            {/* Header */}
            <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-3 mb-4">
              <h2 className="text-sm font-bold text-[#00d4ff] uppercase tracking-wider flex items-center gap-2 font-mono">
                <Activity className="w-4 h-4 text-[#00d4ff]" /> LIVE TELEMETRY
              </h2>
              <span className="px-2.5 py-0.5 rounded bg-[#00d4ff]/15 border border-[#00d4ff]/40 text-[#00d4ff] text-[10px] font-bold uppercase tracking-wider shadow-[0_0_8px_rgba(0,212,255,0.3)] animate-pulse">
                SIMULATED
              </span>
            </div>

            {/* 3D Globe (450px x 400px Container) */}
            <div className="w-full h-[400px] rounded-lg border border-[#00d4ff]/20 bg-[#070b1e]/90 flex items-center justify-center relative overflow-hidden p-2">
              <CompactGlobe width={450} height={400} className="mx-auto" />
            </div>

            <p className="text-[11px] text-[#a0aec0] font-mono mt-3 text-center">
              Rotating Earth Telemetry • GERMANY, UK, JAPAN, CHINA, INDIA, VIETNAM, SOUTH KOREA, SINGAPORE
            </p>
          </div>
        </div>

        {/* ── MIDDLE COLUMN (35% width / 4.2 cols -> lg:col-span-4) ── */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-6 rounded-lg bg-[#0f1535]/50 border border-[#00d4ff]/30 shadow-[0_0_20px_rgba(0,212,255,0.1)] hover:border-[#00d4ff]/50 transition-all">
            
            {/* Header */}
            <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-3 mb-4">
              <h2 className="text-sm font-bold text-[#00d4ff] uppercase tracking-wider flex items-center gap-2 font-mono">
                <Terminal className="w-4 h-4 text-[#00d4ff]" /> LIVE INTERCEPTOR
              </h2>
              <span className="px-2.5 py-0.5 rounded bg-[#ff9500]/15 border border-[#ff9500]/40 text-[#ff9500] text-[10px] font-bold uppercase tracking-wider shadow-[0_0_8px_rgba(255,149,0,0.3)] animate-pulse">
                Active Proxy
              </span>
            </div>

            {/* Scrollable Payload Interceptor Stream */}
            <div 
              ref={interceptorRef}
              className="h-[430px] overflow-y-auto space-y-3 pr-1.5 scrollbar-thin scrollbar-thumb-[#00d4ff]/30"
            >
              {payloads.map((entry) => (
                <div 
                  key={entry.id}
                  className="p-3 rounded-md bg-[#070b1e] border border-[#00d4ff]/20 text-[11px] font-mono space-y-1.5 hover:border-[#00d4ff]/50 transition-colors"
                >
                  <div className="flex items-center justify-between border-b border-[#00d4ff]/10 pb-1">
                    <span className="text-[#00d4ff] font-bold">
                      TCP/IP {entry.tcpPort} → TARGET:{entry.targetPort}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[#00ff00]/15 border border-[#00ff00]/40 text-[#00ff00] font-bold text-[9px]">
                      {entry.status}
                    </span>
                  </div>

                  <div className="text-slate-200">
                    <span className="text-amber-400 font-bold">{entry.method}</span> {entry.path} <span className="text-[#a0aec0]">HTTP/1.1</span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-[#a0aec0]">
                    <span>Host: {entry.host}</span>
                    <span>Content-Length: {entry.contentLength}</span>
                  </div>

                  <div className="p-2 rounded bg-[#040714] border border-[#00d4ff]/15 text-[#a0aec0] text-[10px] break-all font-mono">
                    {entry.hexData}
                  </div>
                </div>
              ))}
            </div>

          </div>
        </div>

        {/* ── RIGHT COLUMN (30% width / 3.6 cols -> lg:col-span-4) ── */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-6 rounded-lg bg-[#0f1535]/50 border border-[#00d4ff]/30 shadow-[0_0_20px_rgba(0,212,255,0.1)] hover:border-[#00d4ff]/50 transition-all font-mono">
            
            {/* Header */}
            <div className="border-b border-[#00d4ff]/20 pb-3 mb-4">
              <h2 className="text-sm font-bold text-[#00d4ff] uppercase tracking-wider flex items-center gap-2 font-mono">
                <Cpu className="w-4 h-4 text-[#00d4ff]" /> ACTIVE PAYLOAD TELEMETRY
              </h2>
            </div>

            {/* Injection Statistics Progress Bars */}
            <div className="space-y-4 mb-6">
              {stats.map((item) => (
                <div key={item.id} className="space-y-1.5">
                  <div className="flex items-center justify-between text-[13px]">
                    <span className="text-white font-bold">{item.name}</span>
                    <span className="font-bold text-[12px]" style={{ color: item.color }}>
                      {item.percent}%
                    </span>
                  </div>

                  {/* 6px height progress bar */}
                  <div className="w-full h-[6px] rounded-full bg-[#040714] border border-[#00d4ff]/20 overflow-hidden p-[0.5px]">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ease-out bg-gradient-to-r ${item.barColor}`}
                      style={{ width: `${item.percent}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* Bottom Section: PAYLOAD DISTRIBUTION */}
            <div className="pt-4 border-t border-[#00d4ff]/20">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-[#00d4ff] uppercase tracking-wider">
                  PAYLOAD DISTRIBUTION
                </span>
                <span className="px-2.5 py-0.5 rounded bg-[#7c3aed]/20 border border-[#7c3aed]/50 text-[#c084fc] text-[10px] font-bold uppercase tracking-wider">
                  55 Active Families
                </span>
              </div>

              {/* Multi-Segment Color Breakdown Bar */}
              <div className="w-full h-3 rounded-full bg-[#040714] border border-[#00d4ff]/20 overflow-hidden flex p-[1px] mb-2">
                <div className="h-full bg-[#00d4ff] transition-all" style={{ width: `${stats.find(s=>s.id==='sqli')?.percent || 24}%` }} title="SQLi" />
                <div className="h-full bg-[#ff9500] transition-all" style={{ width: `${stats.find(s=>s.id==='xss')?.percent || 19}%` }} title="XSS" />
                <div className="h-full bg-[#ff0051] transition-all" style={{ width: `${stats.find(s=>s.id==='ssti')?.percent || 15}%` }} title="SSTI" />
                <div className="h-full bg-[#7c3aed] transition-all" style={{ width: `${stats.find(s=>s.id==='cmdi')?.percent || 14}%` }} title="CmdI" />
                <div className="h-full bg-[#ec4899] transition-all" style={{ width: `${stats.find(s=>s.id==='nosql')?.percent || 12}%` }} title="NoSQL" />
                <div className="h-full bg-[#ffb800] transition-all" style={{ width: `${stats.find(s=>s.id==='ldap')?.percent || 10}%` }} title="LDAP" />
                <div className="h-full bg-[#00ff00] transition-all" style={{ width: `${stats.find(s=>s.id==='traversal')?.percent || 6}%` }} title="Path" />
              </div>

              <div className="flex items-center justify-between text-[10px] text-[#a0aec0] font-mono">
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#00d4ff]" /> SQLi (24%)</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#ff9500]" /> XSS (19%)</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#ff0051]" /> SSTI (15%)</span>
              </div>
            </div>

          </div>
        </div>

      </main>

    </div>
  );
}
