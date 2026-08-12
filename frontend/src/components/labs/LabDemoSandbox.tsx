'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Info,
  Sliders,
  Code2,
  Lock,
  Unlock,
} from 'lucide-react';
import { getInjectionSpec, TestPayload } from '@/data/injectionRegistry';

interface SandboxProps {
  slug: string;
  title: string;
  category?: string;
}

export default function LabDemoSandbox({ slug, title, category }: SandboxProps) {
  const spec = getInjectionSpec(slug, title, category);

  const [isSecureMode, setIsSecureMode] = useState<boolean>(false);
  const [selectedTestCase, setSelectedTestCase] = useState<TestPayload | null>(
    spec.testCases[0] || null
  );
  const [customInput, setCustomInput] = useState<string>(
    spec.testCases[0]?.payload || ''
  );
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [verdict, setVerdict] = useState<'VULNERABLE' | 'DEFENDED_SECURE' | 'BENIGN_SAFE' | null>(
    null
  );
  const [details, setDetails] = useState<{
    sinkType: string;
    reason: string;
    mitigationApplied: string;
    outputSnapshot?: string;
  } | null>(null);

  // Auto-run baseline simulation on mount or mode change
  useEffect(() => {
    runSimulation(selectedTestCase?.payload || spec.testCases[0]?.payload || '', isSecureMode);
  }, [slug, isSecureMode]);

  const runSimulation = (inputVal: string, secure: boolean) => {
    const matchedPreset = spec.testCases.find((tc) => tc.payload === inputVal);

    if (matchedPreset) {
      const logs = secure ? matchedPreset.secureLogs : matchedPreset.vulnerableLogs;
      setConsoleLogs(logs);
      if (matchedPreset.type === 'Benign/Safe') {
        setVerdict('BENIGN_SAFE');
      } else {
        setVerdict(secure ? 'DEFENDED_SECURE' : 'VULNERABLE');
      }
      setDetails({
        sinkType: secure ? 'Hardened / Sanitized Application Layer' : 'Vulnerable Direct Execution Sink',
        reason: secure ? matchedPreset.expectedSecureBehavior : matchedPreset.expectedVulnerableBehavior,
        mitigationApplied: matchedPreset.secureMitigation,
        outputSnapshot: secure ? matchedPreset.expectedSecureBehavior : matchedPreset.vulnerableIndicator,
      });
    } else {
      // Dynamic custom input evaluation
      const result = spec.simulateCustomInput(inputVal, secure);
      setConsoleLogs(result.logs);
      setVerdict(result.verdict);
      setDetails(result.details);
    }
  };

  const handleSelectPreset = (tc: TestPayload) => {
    setSelectedTestCase(tc);
    setCustomInput(tc.payload);
    runSimulation(tc.payload, isSecureMode);
  };

  const handleExecute = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    runSimulation(customInput, isSecureMode);
  };

  const handleReset = () => {
    const defaultTC = spec.testCases[0];
    setSelectedTestCase(defaultTC);
    setCustomInput(defaultTC?.payload || '');
    setIsSecureMode(false);
    runSimulation(defaultTC?.payload || '', false);
  };

  return (
    <div className="space-y-6 text-slate-800">
      {/* Top Configuration & Mode Bar */}
      <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-100 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-full font-bold bg-blue-50 text-blue-700 border border-blue-200">
                {spec.cwe}
              </span>
              <span className="text-[10px] font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-full font-bold bg-slate-100 text-slate-700">
                {spec.owasp}
              </span>
            </div>
            <h3 className="text-base font-extrabold text-slate-900 mt-1 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-blue-600" /> Interactive Execution Sandbox
            </h3>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-2xl border border-slate-200">
            <button
              onClick={() => setIsSecureMode(false)}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 ${
                !isSecureMode
                  ? 'bg-red-600 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Unlock className="w-3.5 h-3.5" /> Vulnerable Mode
            </button>
            <button
              onClick={() => setIsSecureMode(true)}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 ${
                isSecureMode
                  ? 'bg-green-600 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Lock className="w-3.5 h-3.5" /> Secure Defense Mode
            </button>
          </div>
        </div>

        {/* Curated Test Case Presets */}
        <div>
          <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2.5">
            Curated Educational Test Cases (Standards-Referenced)
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {spec.testCases.map((tc) => {
              const isSelected = selectedTestCase?.id === tc.id && customInput === tc.payload;
              return (
                <button
                  key={tc.id}
                  onClick={() => handleSelectPreset(tc)}
                  className={`p-3 rounded-2xl text-left border transition-all text-xs flex flex-col justify-between gap-1.5 ${
                    isSelected
                      ? 'bg-blue-50/80 border-blue-500 ring-2 ring-blue-500/20 text-blue-900 shadow-sm'
                      : 'bg-slate-50/60 border-slate-200/80 hover:bg-slate-100 hover:border-slate-300 text-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span
                      className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${
                        tc.type === 'Baseline'
                          ? 'bg-rose-100 text-rose-700'
                          : tc.type === 'Encoded/Obfuscated'
                          ? 'bg-amber-100 text-amber-700'
                          : tc.type === 'Boundary/Edge'
                          ? 'bg-purple-100 text-purple-700'
                          : 'bg-emerald-100 text-emerald-700'
                      }`}
                    >
                      {tc.type}
                    </span>
                    {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-blue-600" />}
                  </div>
                  <p className="font-bold text-slate-900 line-clamp-1">{tc.label}</p>
                  <code className="text-[10px] font-mono text-slate-500 bg-white/80 px-1.5 py-0.5 rounded border border-slate-200/50 truncate block">
                    {tc.payload}
                  </code>
                </button>
              );
            })}
          </div>
        </div>

        {/* Input & Execution Bar */}
        <form onSubmit={handleExecute} className="space-y-3">
          <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-wider">
            Active Input Payload
          </label>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <input
                type="text"
                value={customInput}
                onChange={(e) => {
                  setCustomInput(e.target.value);
                  setSelectedTestCase(null);
                }}
                placeholder="Enter custom payload or string to test..."
                className="w-full bg-slate-50 border border-slate-300 text-slate-900 rounded-2xl px-4 py-3 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
              />
            </div>
            <div className="flex gap-2">
              <button
                type="submit"
                className="px-6 py-3 bg-slate-900 hover:bg-slate-800 active:scale-95 text-white text-xs font-bold rounded-2xl transition-all flex items-center justify-center gap-2 shadow-sm shrink-0"
              >
                <Play className="w-3.5 h-3.5 fill-current" /> Run Test
              </button>
              <button
                type="button"
                onClick={handleReset}
                title="Reset Sandbox"
                className="p-3 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-2xl border border-slate-200 transition-all shrink-0"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Output & Execution Trace Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Terminal Trace Box */}
        <div className="bg-[#090a0f] rounded-3xl border border-zinc-800 p-6 flex flex-col justify-between shadow-2xl">
          <div>
            <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3 mb-4">
              <div className="flex items-center gap-2 text-zinc-400 font-mono text-xs">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span className="font-bold uppercase tracking-wider text-zinc-300">
                  Execution Trace
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400">
                {consoleLogs.length} events
              </span>
            </div>

            <div className="space-y-2 font-mono text-[11px] leading-relaxed max-h-[300px] overflow-y-auto pr-1 select-text scrollbar-thin scrollbar-thumb-zinc-800">
              <AnimatePresence>
                {consoleLogs.map((log, index) => {
                  let color = 'text-zinc-300';
                  if (log.includes('[VULNERABLE]') || log.includes('[CRITICAL]') || log.includes('[ERROR]')) {
                    color = 'text-rose-400 font-bold';
                  } else if (log.includes('[SECURE]') || log.includes('[PASS]') || log.includes('[DEFENSE]')) {
                    color = 'text-emerald-400 font-bold';
                  } else if (log.includes('[WARN]') || log.includes('[BLOCK]')) {
                    color = 'text-amber-400';
                  } else if (log.includes('[INIT]') || log.includes('[INPUT]')) {
                    color = 'text-cyan-300';
                  } else if (log.includes('[SINK]') || log.includes('[COMMAND-OUTPUT]')) {
                    color = 'text-purple-300';
                  }

                  return (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.15, delay: index * 0.03 }}
                      className={`p-1.5 rounded bg-zinc-950/60 border border-zinc-800/50 ${color}`}
                    >
                      {log}
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[10px] font-mono text-zinc-500">
            <span>Sink: {details?.sinkType || 'Execution Stream'}</span>
            <span>Mode: {isSecureMode ? 'DEFENSE ACTIVE' : 'VULNERABLE DEMO'}</span>
          </div>
        </div>

        {/* Diagnostic Assessment Card */}
        <div className="space-y-4">
          {/* Verdict Banner */}
          {verdict === 'VULNERABLE' && (
            <div className="p-5 rounded-3xl bg-rose-50 border border-rose-200 text-rose-900 shadow-sm flex items-start gap-4">
              <ShieldAlert className="w-7 h-7 text-rose-600 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-200/60 text-rose-800">
                  Exploit Triggered
                </span>
                <h4 className="font-extrabold text-sm text-rose-950">
                  VULNERABILITY CONFIRMED
                </h4>
                <p className="text-xs text-rose-800/90 leading-relaxed">
                  The payload bypassed application boundary controls and executed inside the vulnerable sink.
                </p>
              </div>
            </div>
          )}

          {verdict === 'DEFENDED_SECURE' && (
            <div className="p-5 rounded-3xl bg-emerald-50 border border-emerald-200 text-emerald-900 shadow-sm flex items-start gap-4">
              <ShieldCheck className="w-7 h-7 text-emerald-600 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-200/60 text-emerald-800">
                  Defense Verified
                </span>
                <h4 className="font-extrabold text-sm text-emerald-950">
                  ATTACK NEUTRALIZED SAFELY
                </h4>
                <p className="text-xs text-emerald-800/90 leading-relaxed">
                  The security control intercepted and neutralized the injection attempt without executing malicious logic.
                </p>
              </div>
            </div>
          )}

          {verdict === 'BENIGN_SAFE' && (
            <div className="p-5 rounded-3xl bg-blue-50 border border-blue-200 text-blue-900 shadow-sm flex items-start gap-4">
              <CheckCircle2 className="w-7 h-7 text-blue-600 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-200/60 text-blue-800">
                  Baseline Verified
                </span>
                <h4 className="font-extrabold text-sm text-blue-950">
                  CLEAN / BENIGN INPUT
                </h4>
                <p className="text-xs text-blue-800/90 leading-relaxed">
                  Legitimate user input executed properly through standard data channels. Zero false positives.
                </p>
              </div>
            </div>
          )}

          {/* Details Breakdown */}
          {details && (
            <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
              <h4 className="text-xs font-bold tracking-wider text-slate-800 uppercase flex items-center gap-1.5">
                <Info className="w-4 h-4 text-blue-600" /> Educational Analysis &amp; Mitigation
              </h4>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    Root Cause / Behavior:
                  </span>
                  <p className="font-medium text-slate-700 mt-0.5 leading-relaxed">
                    {details.reason}
                  </p>
                </div>

                <div>
                  <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    Recommended Secure Mitigation:
                  </span>
                  <p className="font-semibold text-emerald-700 mt-0.5 bg-emerald-50/60 p-2 rounded-xl border border-emerald-100">
                    {details.mitigationApplied}
                  </p>
                </div>

                {details.outputSnapshot && (
                  <div>
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                      Sink Output Snapshot:
                    </span>
                    <pre className="mt-1 p-2.5 rounded-xl bg-slate-900 text-cyan-300 font-mono text-[10px] overflow-x-auto">
                      {details.outputSnapshot}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
