'use client';

import React from 'react';
import { useScannerStore } from '@/store/scannerStore';
import { Activity } from 'lucide-react';
import { motion } from 'framer-motion';

export interface AssessmentEngineProgressProps {
  className?: string;
}

export default function AssessmentEngineProgress({ className = '' }: AssessmentEngineProgressProps) {
  const {
    scanState = 'idle',
    progressPercent = 0,
    currentPhase = 1,
    activityMessage = ''
  } = useScannerStore();

  const isScanning = scanState === 'running' || scanState === 'stopping';

  const getStageName = (phase: number) => {
    switch (phase) {
      case 1: return 'Stage 01 • Reconnaissance';
      case 2: return 'Stage 02 • Surface Mapping';
      case 3: return 'Stage 03 • Exploitation Testing';
      case 4: return 'Stage 04 • Threat Validation';
      default: return 'Stage 01 • Reconnaissance';
    }
  };

  return (
    <div 
      className={`w-full max-w-[900px] mx-auto p-[32px] rounded-[12px] bg-gradient-to-b from-[#0a0e27] to-[#0f1535] border border-[#00d4ff]/30 shadow-[0_0_35px_rgba(0,212,255,0.15)] text-white font-sans ${className}`}
    >
      {/* SECTION 1: HEADER */}
      <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-[20px] mb-[24px]">
        {/* Left: Title Section */}
        <div className="flex items-center gap-[12px]">
          <div className="w-[36px] h-[36px] rounded-lg bg-[#00d4ff]/10 border border-[#00d4ff]/30 flex items-center justify-center text-[#00d4ff]">
            <Activity className={`w-5 h-5 ${isScanning ? 'animate-spin' : ''}`} />
          </div>
          <div>
            <h2 className="text-[18px] font-[700] tracking-[0.05em] uppercase text-white leading-tight">
              ASSESSMENT ENGINE PROGRESS
            </h2>
            <p className="text-[12px] text-[#a0aec0] mt-[2px] font-medium">
              Real-time vulnerability inspection pipeline
            </p>
          </div>
        </div>

        {/* Right: Status Badge */}
        <div>
          <span 
            className={`px-[16px] py-[6px] rounded-full text-[12px] font-[600] tracking-[0.08em] uppercase border transition-all ${
              scanState === 'running'
                ? 'bg-[#00d4ff]/15 text-[#00d4ff] border-[#00d4ff]/60 shadow-[0_0_14px_rgba(0,212,255,0.4)] animate-pulse'
                : scanState === 'completed'
                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/60 shadow-[0_0_14px_rgba(16,185,129,0.4)]'
                : 'bg-[#00d4ff]/10 text-[#00d4ff] border-[#00d4ff]/40 shadow-[0_0_10px_rgba(0,212,255,0.2)]'
            }`}
          >
            {scanState === 'running' ? 'SCAN IN PROGRESS' : scanState === 'completed' ? 'SCAN COMPLETE' : 'STANDBY'}
          </span>
        </div>
      </div>

      {/* SECTION 2: PROGRESS TRACKING BOX */}
      <div className="p-[24px] rounded-[8px] bg-[rgba(0,0,0,0.3)] border border-[#00d4ff]/20 space-y-[20px]">
        
        {/* Current Stage Row */}
        <div className="flex items-center justify-between">
          <div className="text-[14px]">
            <span className="text-[#a0aec0] font-mono mr-[8px]">Current Stage:</span>
            <span className="text-[#00d4ff] font-[600] text-[15px]">
              {scanState === 'completed' ? '100% • Scan Complete' : getStageName(currentPhase)}
            </span>
          </div>

          <div className="text-[24px] font-[700] text-[#00d4ff] font-mono drop-shadow-[0_0_10px_rgba(0,212,255,0.6)]">
            {progressPercent}%
          </div>
        </div>

        {/* Progress Bar Container */}
        <div className="space-y-[12px]">
          <div className="w-full h-[6px] bg-[rgba(0,212,255,0.1)] border border-[#00d4ff]/30 rounded-[3px] overflow-hidden relative p-[1px]">
            {/* Stage segment dividers */}
            <div className="absolute top-0 bottom-0 left-[20%] w-[1.5px] bg-[#00d4ff]/40 z-20 pointer-events-none" />
            <div className="absolute top-0 bottom-0 left-[45%] w-[1.5px] bg-[#00d4ff]/40 z-20 pointer-events-none" />
            <div className="absolute top-0 bottom-0 left-[80%] w-[1.5px] bg-[#00d4ff]/40 z-20 pointer-events-none" />

            {/* Active Progress Fill */}
            <div
              className="h-full rounded-[2px] bg-gradient-to-r from-[#00d4ff] via-[#6366f1] to-[#a855f7] transition-all duration-500 ease-out relative shadow-[0_0_18px_#00d4ff]"
              style={{ width: `${progressPercent}%` }}
            >
              <div className="absolute right-0 top-0 bottom-0 w-[6px] bg-cyan-200 rounded-full blur-[2px]" />
            </div>
          </div>

          {/* Stage Badges Row */}
          <div className="grid grid-cols-4 gap-[8px] text-[11px] font-mono">
            {/* Stage 01 Badge */}
            <div 
              className={`px-[10px] py-[6px] rounded-[6px] border text-center transition-all ${
                currentPhase === 1 || scanState === 'completed'
                  ? 'bg-[#00d4ff]/15 text-[#00d4ff] border-[#00d4ff]/60 font-[700] shadow-[0_0_12px_rgba(0,212,255,0.3)]'
                  : 'bg-[rgba(255,255,255,0.03)] text-[#a0aec0] border-[rgba(255,255,255,0.08)]'
              }`}
            >
              Stage 01 (0%-20%)
            </div>

            {/* Stage 02 Badge */}
            <div 
              className={`px-[10px] py-[6px] rounded-[6px] border text-center transition-all ${
                currentPhase === 2
                  ? 'bg-[#6366f1]/20 text-[#818cf8] border-[#6366f1]/60 font-[700] shadow-[0_0_12px_rgba(99,102,241,0.3)]'
                  : 'bg-[rgba(255,255,255,0.03)] text-[#a0aec0] border-[rgba(255,255,255,0.08)]'
              }`}
            >
              Stage 02 (20%-45%)
            </div>

            {/* Stage 03 Badge */}
            <div 
              className={`px-[10px] py-[6px] rounded-[6px] border text-center transition-all ${
                currentPhase === 3
                  ? 'bg-[#a855f7]/20 text-[#c084fc] border-[#a855f7]/60 font-[700] shadow-[0_0_12px_rgba(168,85,247,0.3)]'
                  : 'bg-[rgba(255,255,255,0.03)] text-[#a0aec0] border-[rgba(255,255,255,0.08)]'
              }`}
            >
              Stage 03 (45%-80%)
            </div>

            {/* Stage 04 Badge */}
            <div 
              className={`px-[10px] py-[6px] rounded-[6px] border text-center transition-all ${
                currentPhase === 4 || scanState === 'completed'
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/60 font-[700] shadow-[0_0_12px_rgba(16,185,129,0.3)]'
                  : 'bg-[rgba(255,255,255,0.03)] text-[#a0aec0] border-[rgba(255,255,255,0.08)]'
              }`}
            >
              Stage 04 (80%-100%)
            </div>
          </div>
        </div>

        {/* 4 Stages Detailed List */}
        <div className="space-y-[10px] pt-[8px]">
          {/* Stage 01 Item */}
          <div className={`p-[12px] rounded-[8px] border transition-all ${
            currentPhase === 1 && isScanning 
              ? 'bg-[#00d4ff]/10 border-[#00d4ff]/50 shadow-[0_0_16px_rgba(0,212,255,0.2)]' 
              : currentPhase > 1 || scanState === 'completed'
              ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
              : 'bg-[rgba(255,255,255,0.02)] border-[rgba(255,255,255,0.06)]'
          }`}>
            <div className="flex items-center justify-between text-[13px]">
              <div className="flex items-center gap-[10px]">
                <div className={`w-[24px] h-[24px] rounded-full flex items-center justify-center font-mono text-[11px] font-[700] ${
                  currentPhase > 1 || scanState === 'completed'
                    ? 'bg-emerald-500/20 border border-emerald-400 text-emerald-300'
                    : 'bg-[#00d4ff]/20 border border-[#00d4ff] text-[#00d4ff]'
                }`}>
                  {currentPhase > 1 || scanState === 'completed' ? '✓' : '1'}
                </div>
                <div>
                  <span className="font-[700] text-white">Stage 01 • Reconnaissance (0% → 20%)</span>
                  <p className="text-[11px] text-[#a0aec0] mt-[1px]">Crawling & discovering pages/internal links</p>
                </div>
              </div>
              <span className="text-[10px] font-mono uppercase font-[700] px-[8px] py-[2px] rounded border border-[#00d4ff]/40 text-[#00d4ff]">
                {currentPhase === 1 && isScanning ? 'Active' : currentPhase > 1 || scanState === 'completed' ? '✓ Complete' : 'Pending'}
              </span>
            </div>
          </div>

          {/* Stage 02 Item */}
          <div className={`p-[12px] rounded-[8px] border transition-all ${
            currentPhase === 2 && isScanning 
              ? 'bg-[#6366f1]/15 border-[#6366f1]/50 shadow-[0_0_16px_rgba(99,102,241,0.2)]' 
              : currentPhase > 2 || scanState === 'completed'
              ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
              : 'bg-[rgba(255,255,255,0.02)] border-[rgba(255,255,255,0.06)]'
          }`}>
            <div className="flex items-center justify-between text-[13px]">
              <div className="flex items-center gap-[10px]">
                <div className={`w-[24px] h-[24px] rounded-full flex items-center justify-center font-mono text-[11px] font-[700] ${
                  currentPhase > 2 || scanState === 'completed'
                    ? 'bg-emerald-500/20 border border-emerald-400 text-emerald-300'
                    : currentPhase === 2
                    ? 'bg-[#6366f1]/20 border border-[#6366f1] text-[#818cf8]'
                    : 'bg-white/5 border border-white/20 text-[#a0aec0]'
                }`}>
                  {currentPhase > 2 || scanState === 'completed' ? '✓' : '2'}
                </div>
                <div>
                  <span className="font-[700] text-white">Stage 02 • Surface Mapping (20% → 45%)</span>
                  <p className="text-[11px] text-[#a0aec0] mt-[1px]">Detecting URL params, GET/POST params & forms</p>
                </div>
              </div>
              <span className="text-[10px] font-mono uppercase font-[700] px-[8px] py-[2px] rounded border border-white/20 text-[#a0aec0]">
                {currentPhase === 2 && isScanning ? 'Active' : currentPhase > 2 || scanState === 'completed' ? '✓ Complete' : 'Pending'}
              </span>
            </div>
          </div>

          {/* Stage 03 Item */}
          <div className={`p-[12px] rounded-[8px] border transition-all ${
            currentPhase === 3 && isScanning 
              ? 'bg-[#a855f7]/15 border-[#a855f7]/50 shadow-[0_0_16px_rgba(168,85,247,0.2)]' 
              : currentPhase > 3 || scanState === 'completed'
              ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
              : 'bg-[rgba(255,255,255,0.02)] border-[rgba(255,255,255,0.06)]'
          }`}>
            <div className="flex items-center justify-between text-[13px]">
              <div className="flex items-center gap-[10px]">
                <div className={`w-[24px] h-[24px] rounded-full flex items-center justify-center font-mono text-[11px] font-[700] ${
                  currentPhase > 3 || scanState === 'completed'
                    ? 'bg-emerald-500/20 border border-emerald-400 text-emerald-300'
                    : currentPhase === 3
                    ? 'bg-[#a855f7]/20 border border-[#a855f7] text-[#c084fc]'
                    : 'bg-white/5 border border-white/20 text-[#a0aec0]'
                }`}>
                  {currentPhase > 3 || scanState === 'completed' ? '✓' : '3'}
                </div>
                <div>
                  <span className="font-[700] text-white">Stage 03 • Exploitation Testing (45% → 80%)</span>
                  <p className="text-[11px] text-[#a0aec0] mt-[1px]">Testing parameters against injection vectors</p>
                </div>
              </div>
              <span className="text-[10px] font-mono uppercase font-[700] px-[8px] py-[2px] rounded border border-white/20 text-[#a0aec0]">
                {currentPhase === 3 && isScanning ? 'Active' : currentPhase > 3 || scanState === 'completed' ? '✓ Complete' : 'Pending'}
              </span>
            </div>
          </div>

          {/* Stage 04 Item */}
          <div className={`p-[12px] rounded-[8px] border transition-all ${
            currentPhase === 4 && isScanning 
              ? 'bg-emerald-500/15 border-emerald-500/50 shadow-[0_0_16px_rgba(16,185,129,0.2)]' 
              : scanState === 'completed'
              ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
              : 'bg-[rgba(255,255,255,0.02)] border-[rgba(255,255,255,0.06)]'
          }`}>
            <div className="flex items-center justify-between text-[13px]">
              <div className="flex items-center gap-[10px]">
                <div className={`w-[24px] h-[24px] rounded-full flex items-center justify-center font-mono text-[11px] font-[700] ${
                  scanState === 'completed'
                    ? 'bg-emerald-500/20 border border-emerald-400 text-emerald-300'
                    : currentPhase === 4
                    ? 'bg-emerald-500/20 border border-emerald-400 text-emerald-300'
                    : 'bg-white/5 border border-white/20 text-[#a0aec0]'
                }`}>
                  {scanState === 'completed' ? '✓' : '4'}
                </div>
                <div>
                  <span className="font-[700] text-white">Stage 04 • Threat Validation (80% → 100%)</span>
                  <p className="text-[11px] text-[#a0aec0] mt-[1px]">Validating results & removing false positives</p>
                </div>
              </div>
              <span className="text-[10px] font-mono uppercase font-[700] px-[8px] py-[2px] rounded border border-white/20 text-[#a0aec0]">
                {scanState === 'completed' ? '✓ Complete' : currentPhase === 4 && isScanning ? 'Active' : 'Pending'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Console Activity Footer */}
      <div className="mt-[20px] p-[12px] rounded-[8px] bg-[#050714] border border-[#00d4ff]/25 font-mono text-[12px] text-[#00d4ff] flex items-center gap-[10px]">
        <div className="w-[8px] h-[8px] rounded-full bg-[#00d4ff] animate-pulse shrink-0 drop-shadow-[0_0_8px_#00d4ff]" />
        <div className="truncate flex-1 flex items-center">
          <span className="text-[#a0aec0] text-[11px] uppercase mr-[8px] font-bold">TELEMETRY:</span>
          <span className="text-white truncate">{activityMessage || (isScanning ? 'Streaming engine telemetry...' : 'Awaiting target configuration to start assessment...')}</span>
          <span className="inline-block w-[6px] h-[12px] bg-[#00d4ff] ml-[6px] animate-pulse shrink-0" />
        </div>
      </div>
    </div>
  );
}
