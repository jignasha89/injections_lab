'use client';

import { useState, useEffect } from 'react';
import { Activity, Volume2, VolumeX, ShieldCheck } from 'lucide-react';

export interface HeaderProps {
  soundEnabled: boolean;
  onToggleSound: () => void;
  systemStatus?: string;
}

export default function Header({
  soundEnabled,
  onToggleSound,
  systemStatus = 'All Systems Operational'
}: HeaderProps) {
  const [timeStr, setTimeStr] = useState<string>('00:00:00');

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setTimeStr(now.toLocaleTimeString('en-US', { hour12: false }));
    };
    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-[80px] border-b border-[#00d4ff]/30 px-6 md:px-8 flex items-center justify-between bg-[#080c21]/90 backdrop-blur-md shrink-0 shadow-[0_4px_25px_rgba(0,212,255,0.1)] z-20">
      {/* Left: Logo & Title */}
      <div className="flex items-center gap-4">
        <div className="w-11 h-11 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/40 flex items-center justify-center text-[#00d4ff] shadow-[0_0_20px_rgba(0,212,255,0.35)]">
          <Activity className="w-6 h-6 animate-pulse" />
        </div>
        <div>
          <h1 className="text-2xl md:text-[28px] font-bold text-[#00d4ff] tracking-tight font-mono leading-none drop-shadow-[0_0_12px_rgba(0,212,255,0.6)]">
            InjectionLab Demo
          </h1>
          <p className="text-xs text-[#a0aec0] font-mono mt-1 tracking-wider uppercase">
            Enterprise Security Assessment Command Center
          </p>
        </div>
      </div>

      {/* Right: Status Indicators & Time */}
      <div className="flex items-center gap-4 md:gap-6">
        {/* Audio Beep Sound Toggle */}
        <button
          onClick={onToggleSound}
          title={soundEnabled ? "Mute Scan Audio Beeps" : "Enable Scan Audio Beeps"}
          className={`p-2 rounded-lg border transition-all ${
            soundEnabled
              ? 'bg-[#00d4ff]/15 border-[#00d4ff]/50 text-[#00d4ff] shadow-[0_0_12px_rgba(0,212,255,0.3)]'
              : 'bg-[#040714] border-slate-700 text-slate-400 hover:text-white'
          }`}
        >
          {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
        </button>

        {/* System Status */}
        <div className="hidden lg:flex flex-col items-end">
          <div className="flex items-center gap-2 text-xs text-[#00ff00] font-bold font-mono">
            <span className="w-2 h-2 rounded-full bg-[#00ff00] animate-ping" />
            <span>{systemStatus}</span>
          </div>
          <span className="text-[10px] text-[#a0aec0] uppercase tracking-wider font-mono">
            Security Telemetry Node #01
          </span>
        </div>

        {/* Live Mode Badge */}
        <div className="px-3.5 py-1 rounded-full bg-[#00ff00]/15 border border-[#00ff00]/50 text-[#00ff00] text-xs font-bold font-mono tracking-widest uppercase shadow-[0_0_14px_rgba(0,255,0,0.3)] animate-pulse flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#00ff00]" />
          LIVE MODE
        </div>

        {/* Time Display */}
        <div className="px-4 py-1.5 rounded-lg bg-[#040714] border border-[#00d4ff]/30 text-[#00d4ff] font-mono font-bold text-base md:text-lg shadow-inner tracking-widest">
          {timeStr}
        </div>
      </div>
    </header>
  );
}
