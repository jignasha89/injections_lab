'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import Header from '@/components/dashboard/demo/Header';
import LeftPanel, { VulnStats } from '@/components/dashboard/demo/LeftPanel';
import CenterPanel, { ScanResultRow } from '@/components/dashboard/demo/CenterPanel';
import RightPanel, { EventLogItem } from '@/components/dashboard/demo/RightPanel';
import BottomPanel from '@/components/dashboard/demo/BottomPanel';

// Mock Initial Findings Data
const INITIAL_DEMO_RESULTS: ScanResultRow[] = [
  { id: 1, type: 'SQL Injection', parameter: 'id=', risk: 'HIGH', status: 'Confirmed', count: 24 },
  { id: 2, type: 'XSS Injection', parameter: 'search=', risk: 'MEDIUM', status: 'Pending', count: 15 },
  { id: 3, type: 'Command Injection', parameter: 'cmd=', risk: 'CRITICAL', status: 'Confirmed', count: 8 },
  { id: 4, type: 'LDAP Injection', parameter: 'user=', risk: 'MEDIUM', status: 'Confirmed', count: 5 },
  { id: 5, type: 'Path Traversal', parameter: 'file=', risk: 'HIGH', status: 'Confirmed', count: 7 },
  { id: 6, type: 'SSRF Vector', parameter: 'url=', risk: 'CRITICAL', status: 'Confirmed', count: 4 },
];

export default function InjectionLabDemoPage() {
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const audioCtxRef = useRef<AudioContext | null>(null);

  const playBeep = useCallback((freq = 880, duration = 0.08) => {
    if (!soundEnabled) return;
    try {
      if (!audioCtxRef.current) {
        audioCtxRef.current = new (window.AudioContext || (window as any).webkitAudioContext)();
      }
      const ctx = audioCtxRef.current;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.05, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch {
      // Audio context fallback gracefully ignored
    }
  }, [soundEnabled]);

  const [targetUrl, setTargetUrl] = useState<string>('https://example.com?id=1&search=test');
  const [isScanning, setIsScanning] = useState<boolean>(false);

  // Exact 2x2 Vuln Stats (SQL INJECTION: 24, XSS ATTACKS: 15, COMMAND INJECTION: 8, LDAP INJECTION: 5)
  const [stats, setStats] = useState<VulnStats>({
    sqli: 24,
    xss: 15,
    cmdi: 8,
    ldap: 5
  });

  const [scanResults, setScanResults] = useState<ScanResultRow[]>(INITIAL_DEMO_RESULTS);

  const [eventLogs, setEventLogs] = useState<EventLogItem[]>([
    { id: 1, time: '14:32:45', text: 'Scan Started', status: 'INITIATED', type: 'info' },
    { id: 2, time: '14:32:48', text: 'URL Crawled: example.com', status: 'COMPLETED', type: 'success' },
    { id: 3, time: '14:33:12', text: 'Parameter Detected: id=', status: 'FOUND', type: 'warning' },
    { id: 4, time: '14:33:15', text: 'SQL Injection Tested', status: 'VULNERABLE', type: 'critical' },
    { id: 5, time: '14:33:42', text: 'XSS Test Completed', status: 'VULNERABLE', type: 'critical' },
  ]);

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString('en-US', { hour12: false });

      const sampleEvents: Array<{ text: string; status: string; type: EventLogItem['type'] }> = [
        { text: 'Parameter Detected: search=', status: 'FOUND', type: 'warning' },
        { text: 'Command Injection Tested on cmd=', status: 'VULNERABLE', type: 'critical' },
        { text: 'LDAP Injection Probe Verified', status: 'CONFIRMED', type: 'success' },
        { text: 'WAF Evasion Pattern Executed', status: 'ACTIVE', type: 'info' },
        { text: 'Header Injection Matrix Passed', status: 'PASSED', type: 'info' }
      ];

      const randomEv = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
      setEventLogs(prev => [
        ...prev.slice(-20),
        { id: Date.now(), time: timeStr, text: randomEv.text, status: randomEv.status, type: randomEv.type }
      ]);
    }, 2800);

    return () => clearInterval(interval);
  }, []);

  const handleStartScan = useCallback(() => {
    if (isScanning) return;
    setIsScanning(true);
    playBeep(1046, 0.12);

    const now = new Date();
    const t = now.toLocaleTimeString('en-US', { hour12: false });

    setEventLogs(prev => [
      ...prev,
      { id: Date.now(), time: t, text: `Triggered Full Assessment on ${targetUrl}`, status: 'EXECUTION', type: 'critical' }
    ]);

    setTimeout(() => {
      playBeep(880, 0.08);
      setEventLogs(prev => [
        ...prev,
        { id: Date.now(), time: new Date().toLocaleTimeString('en-US', { hour12: false }), text: 'Crawling Endpoint & Extracting Parameters', status: 'COMPLETED', type: 'info' }
      ]);
    }, 1500);

    setTimeout(() => {
      playBeep(1318, 0.1);
      setStats(prev => ({ ...prev, sqli: prev.sqli + 1, xss: prev.xss + 1 }));
      setScanResults(prev => [
        { id: Date.now(), type: 'SQL Injection', parameter: 'id=', risk: 'CRITICAL', status: 'Confirmed', count: 25 },
        ...prev
      ]);
    }, 3200);

    setTimeout(() => {
      playBeep(1567, 0.2);
      setIsScanning(false);
      setEventLogs(prev => [
        ...prev,
        { id: Date.now(), time: new Date().toLocaleTimeString('en-US', { hour12: false }), text: 'Assessment Completed — Telemetry Synced', status: 'FINISHED', type: 'success' }
      ]);
    }, 5500);
  }, [isScanning, targetUrl, playBeep]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#0a0e27] via-[#0c1130] to-[#0f1535] text-white font-mono relative overflow-x-hidden selection:bg-[#00d4ff]/30">
      
      {/* Scanline Overlay */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-20 bg-[linear-gradient(to_bottom,transparent_0px,rgba(0,212,255,0.1)_1px,transparent_2px)] bg-[size:100%_4px]" />
      
      <div className="relative z-10 flex flex-col min-h-screen">
        
        {/* HEADER COMPONENT */}
        <Header
          soundEnabled={soundEnabled}
          onToggleSound={() => setSoundEnabled(prev => !prev)}
          systemStatus={isScanning ? "Deep Assessment Running..." : "All Systems Operational"}
        />

        {/* MAIN CONTENT GRID (3-Column Layout: Col 1: 25%, Col 2: 50%, Col 3: 25%) */}
        <main className="flex-1 p-6 md:p-8 grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-8 items-start">
          
          {/* COLUMN 1: LEFT PANEL (25% width / 3 cols) */}
          <div className="lg:col-span-3">
            <LeftPanel
              targetUrl={targetUrl}
              onUrlChange={setTargetUrl}
              onStartScan={handleStartScan}
              isScanning={isScanning}
              stats={stats}
            />
          </div>

          {/* COLUMN 2: CENTER PANEL (50% width / 6 cols) */}
          <div className="lg:col-span-6">
            <CenterPanel 
              scanResults={scanResults} 
              globeWidth={500} 
              globeHeight={400} 
            />
          </div>

          {/* COLUMN 3: RIGHT PANEL (25% width / 3 cols) */}
          <div className="lg:col-span-3">
            <RightPanel eventLogs={eventLogs} />
          </div>

        </main>

        {/* BOTTOM SECTION: DETAILED RESULTS PANEL */}
        <BottomPanel />

      </div>
    </div>
  );
}
