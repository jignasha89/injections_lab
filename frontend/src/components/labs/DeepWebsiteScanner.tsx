'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe,
  Shield,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  Terminal,
  ChevronDown,
  ChevronUp,
  FileCode,
  Lock,
  Zap,
  Activity,
  Code2,
  ExternalLink,
  Layers,
} from 'lucide-react';

export interface ScanFinding {
  inputPointTested: string;
  payloadUsed: string;
  vulnerabilityType: string;
  confidence: 'Low' | 'Medium' | 'High' | 'Confirmed';
  evidence: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvss?: number;
  cwe?: string;
  owasp?: string;
  recommendation: string;
}

export interface SecurityHeaderResult {
  header: string;
  present: boolean;
  value?: string;
  status: 'pass' | 'fail' | 'warn';
  recommendation?: string;
}

export interface DiscoveredForm {
  action: string;
  method: 'GET' | 'POST';
  enctype?: string;
  isFileUpload: boolean;
  inputs: { name: string; type: string; value: string }[];
}

export interface DiscoveredLinkParam {
  href: string;
  param: string;
  value: string;
}

export interface LiveScanResponse {
  targetUrl: string;
  normalizedUrl: string;
  scanTimestamp: string;
  scanMode: 'passive' | 'active';
  statusCode: number;
  responseTimeMs: number;
  serverBanner?: string;
  headers: Record<string, SecurityHeaderResult>;
  discoveredEndpoints: {
    forms: DiscoveredForm[];
    linksWithParams: DiscoveredLinkParam[];
    scriptApiEndpoints: string[];
  };
  findings: ScanFinding[];
  summary: {
    totalPages: number;
    formsCount: number;
    paramsCount: number;
    scriptEndpointsCount: number;
    totalFindings: number;
    riskScore: number;
    highestSeverity: string;
    headersCompliance: {
      passed: number;
      failed: number;
      warned: number;
      total: number;
    };
  };
}

const SEVERITY_COLORS: Record<string, { badge: string; border: string }> = {
  Critical: {
    badge: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
    border: 'border-rose-500/30',
  },
  High: {
    badge: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
    border: 'border-orange-500/30',
  },
  Medium: {
    badge: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
    border: 'border-amber-500/30',
  },
  Low: {
    badge: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
    border: 'border-cyan-500/30',
  },
  Info: {
    badge: 'bg-zinc-800 text-zinc-300 border-zinc-700',
    border: 'border-zinc-800',
  },
};

const CONFIDENCE_COLORS: Record<string, string> = {
  Confirmed: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  High: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
  Medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  Low: 'text-zinc-400 bg-zinc-800 border-zinc-700',
};

export default function DeepWebsiteScanner() {
  const [url, setUrl] = useState('');
  const [scanMode, setScanMode] = useState<'passive' | 'active'>('passive');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LiveScanResponse | null>(null);
  const [error, setError] = useState('');
  const [showEndpoints, setShowEndpoints] = useState(false);
  const [showHeaders, setShowHeaders] = useState(false);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const presets = [
    { label: 'Local Mock Sandbox', url: 'http://localhost:3001' },
    { label: 'Local API Users', url: 'http://localhost:3000/api/users?id=1&name=admin' },
    { label: 'Local Search Form', url: 'http://localhost:3001/search?q=test' },
  ];

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setResult(null);

    if (!url.trim()) {
      setError('Please provide a target URL.');
      return;
    }

    if (!authorized) {
      setError('You must confirm authorization before initiating a scan.');
      return;
    }

    setLoading(true);

    try {
      const response = await api.post<LiveScanResponse>('/scan', {
        url: url.trim(),
        authorized: true,
        scanMode,
        config: {
          rateLimitMs: 500,
        },
      });

      setResult(response.data);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error?: string } } };
      setError(
        axiosErr.response?.data?.error || 'Target scan failed. Please verify that the target URL is accessible.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-[#0c0d14] rounded-2xl border border-zinc-800/80 shadow-2xl p-6 space-y-6">
      {/* Header & Mode Badge */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                Deep Website Scanner
                <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 uppercase font-semibold">
                  Live HTML + Differential Engine
                </span>
              </h3>
              <p className="text-zinc-400 text-xs font-mono mt-0.5">
                Inspect live web pages for form fields, API endpoints, missing security headers, and differential injection anomalies.
              </p>
            </div>
          </div>
        </div>

        {/* Mode Selector */}
        <div className="flex items-center bg-[#050508] p-1 rounded-xl border border-zinc-800">
          <button
            type="button"
            onClick={() => setScanMode('passive')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
              scanMode === 'passive'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(0,240,255,0.15)]'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Passive Inspection (Default)
          </button>
          <button
            type="button"
            onClick={() => setScanMode('active')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
              scanMode === 'active'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.15)]'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Active Differential Probe
          </button>
        </div>
      </div>

      {/* Mandatory Disclaimer Banner */}
      <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300/90 text-xs font-mono leading-relaxed">
        <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-amber-300">Authorized Educational Testing Only:</strong> You may strictly only scan URLs, applications, or domains that you own or have explicit, documented permission to test.
        </div>
      </div>

      {/* Scan Input Form */}
      <form onSubmit={handleScan} className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="relative md:col-span-8">
            <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              placeholder="e.g. http://localhost:3001 or http://localhost:3000/api/users?id=1"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl text-xs font-mono bg-[#050508] border border-zinc-800 text-zinc-100 placeholder-zinc-600 focus:bg-[#0a0b12] focus:border-cyan-500/50 focus:outline-none transition"
            />
          </div>

          <div className="md:col-span-4 flex gap-2">
            <button
              type="submit"
              disabled={loading || (scanMode === 'active' && !authorized)}
              className={`w-full py-2.5 px-4 rounded-xl text-xs font-mono font-bold transition-all flex items-center justify-center gap-2 ${
                loading || (scanMode === 'active' && !authorized)
                  ? 'opacity-50 cursor-not-allowed bg-zinc-800 text-zinc-400'
                  : scanMode === 'active'
                  ? 'bg-amber-500 hover:bg-amber-400 text-black shadow-[0_0_15px_rgba(245,158,11,0.25)]'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-black shadow-[0_0_15px_rgba(0,240,255,0.25)]'
              }`}
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-t-black border-r-transparent border-l-transparent border-b-black rounded-full animate-spin" />
                  <span>{scanMode === 'active' ? 'Probing Target...' : 'Fetching & Parsing...'}</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>{scanMode === 'active' ? 'Run Active Probe' : 'Run Passive Scan'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Presets & Authorization Checkbox */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
          {/* Presets */}
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-zinc-400">
            <span className="text-zinc-600">Quick Targets:</span>
            {presets.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => setUrl(p.url)}
                className="px-2 py-0.5 rounded-md bg-zinc-900 border border-zinc-800 hover:border-cyan-500/40 hover:text-cyan-300 transition"
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Permission Checkbox */}
          <label className="flex items-center gap-2 text-xs font-mono text-zinc-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="h-3.5 w-3.5 rounded border-zinc-700 bg-zinc-900 text-cyan-500 focus:ring-cyan-500/40"
            />
            <span>I have authorized permission to audit this target</span>
          </label>
        </div>
      </form>

      {/* Error Message */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Scan Results View */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-5 pt-2"
        >
          {/* Summary Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="bg-[#050508] p-3 rounded-xl border border-zinc-800">
              <span className="text-[10px] font-mono text-zinc-500 block uppercase">HTTP Status</span>
              <span className="text-sm font-mono font-bold text-emerald-400">
                {result.statusCode} OK
              </span>
            </div>

            <div className="bg-[#050508] p-3 rounded-xl border border-zinc-800">
              <span className="text-[10px] font-mono text-zinc-500 block uppercase">Latency</span>
              <span className="text-sm font-mono font-bold text-cyan-400">
                {result.responseTimeMs} ms
              </span>
            </div>

            <div className="bg-[#050508] p-3 rounded-xl border border-zinc-800">
              <span className="text-[10px] font-mono text-zinc-500 block uppercase">Forms Extracted</span>
              <span className="text-sm font-mono font-bold text-white">
                {result.summary.formsCount}
              </span>
            </div>

            <div className="bg-[#050508] p-3 rounded-xl border border-zinc-800">
              <span className="text-[10px] font-mono text-zinc-500 block uppercase">Script APIs</span>
              <span className="text-sm font-mono font-bold text-purple-400">
                {result.summary.scriptEndpointsCount}
              </span>
            </div>

            <div className="bg-[#050508] p-3 rounded-xl border border-zinc-800">
              <span className="text-[10px] font-mono text-zinc-500 block uppercase">Risk Rating</span>
              <span
                className={`text-sm font-mono font-bold ${
                  result.summary.highestSeverity === 'Critical'
                    ? 'text-rose-400'
                    : result.summary.highestSeverity === 'High'
                    ? 'text-orange-400'
                    : result.summary.highestSeverity === 'Medium'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {result.summary.highestSeverity} ({result.summary.riskScore}/10)
              </span>
            </div>

            <div className="bg-[#050508] p-3 rounded-xl border border-zinc-800">
              <span className="text-[10px] font-mono text-zinc-500 block uppercase">Findings</span>
              <span className="text-sm font-mono font-bold text-amber-300">
                {result.findings.length}
              </span>
            </div>
          </div>

          {/* Toggleable Drawer: Security Headers */}
          <div className="border border-zinc-800/80 rounded-xl overflow-hidden bg-[#050508]">
            <button
              type="button"
              onClick={() => setShowHeaders(!showHeaders)}
              className="w-full px-4 py-3 flex items-center justify-between text-xs font-mono text-zinc-300 hover:text-white hover:bg-zinc-900/50 transition"
            >
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span className="font-bold">HTTP Security Headers Audit</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400">
                  {result.summary.headersCompliance.passed}/{result.summary.headersCompliance.total} Passed
                </span>
              </div>
              {showHeaders ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
            </button>

            <AnimatePresence>
              {showHeaders && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="px-4 pb-4 space-y-2 border-t border-zinc-800/80 pt-3"
                >
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {Object.entries(result.headers).map(([hKey, hVal]) => (
                      <div
                        key={hKey}
                        className="p-2.5 rounded-lg bg-zinc-900/60 border border-zinc-800 flex items-start justify-between gap-2"
                      >
                        <div>
                          <span className="text-xs font-mono font-bold text-white block">{hKey}</span>
                          <span className="text-[10px] font-mono text-zinc-400 leading-tight block mt-0.5">
                            {hVal.recommendation}
                          </span>
                        </div>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded-md uppercase font-bold shrink-0 ${
                            hVal.status === 'pass'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : hVal.status === 'warn'
                              ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                              : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                          }`}
                        >
                          {hVal.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Toggleable Drawer: Discovered Endpoints */}
          <div className="border border-zinc-800/80 rounded-xl overflow-hidden bg-[#050508]">
            <button
              type="button"
              onClick={() => setShowEndpoints(!showEndpoints)}
              className="w-full px-4 py-3 flex items-center justify-between text-xs font-mono text-zinc-300 hover:text-white hover:bg-zinc-900/50 transition"
            >
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-purple-400" />
                <span className="font-bold">Discovered Attack Surface</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400">
                  {result.discoveredEndpoints.forms.length} Forms, {result.discoveredEndpoints.linksWithParams.length} Links, {result.discoveredEndpoints.scriptApiEndpoints.length} APIs
                </span>
              </div>
              {showEndpoints ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
            </button>

            <AnimatePresence>
              {showEndpoints && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="px-4 pb-4 space-y-3 border-t border-zinc-800/80 pt-3 text-xs font-mono"
                >
                  {/* Forms */}
                  <div>
                    <h5 className="text-[10px] uppercase font-bold text-zinc-400 mb-1.5">HTML Forms</h5>
                    <div className="space-y-1.5">
                      {result.discoveredEndpoints.forms.map((form, fIdx) => (
                        <div key={fIdx} className="p-2 rounded-lg bg-zinc-900/60 border border-zinc-800 text-[11px]">
                          <div className="flex items-center gap-2">
                            <span className="text-cyan-400 font-bold">{form.method}</span>
                            <span className="text-zinc-200">{form.action}</span>
                            {form.isFileUpload && (
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">File Upload</span>
                            )}
                          </div>
                          <div className="text-zinc-400 text-[10px] mt-1">
                            Inputs: {form.inputs.map((inp) => `${inp.name} (${inp.type})`).join(', ') || 'None'}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Script APIs */}
                  {result.discoveredEndpoints.scriptApiEndpoints.length > 0 && (
                    <div>
                      <h5 className="text-[10px] uppercase font-bold text-zinc-400 mb-1.5">Discovered Script APIs</h5>
                      <div className="flex flex-wrap gap-1.5">
                        {result.discoveredEndpoints.scriptApiEndpoints.map((apiPath, aIdx) => (
                          <span key={aIdx} className="px-2 py-1 rounded bg-zinc-900 border border-zinc-800 text-purple-300 text-[11px]">
                            {apiPath}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Diagnostic Findings List */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center justify-between">
              <span>Security Diagnostic Findings ({result.findings.length})</span>
              <span className="text-[10px] text-zinc-500 font-normal">Click a card to inspect evidence & recommendation</span>
            </h4>

            {result.findings.length === 0 ? (
              <div className="p-6 rounded-xl bg-[#050508] border border-zinc-800 text-center font-mono text-xs text-zinc-400">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                No vulnerabilities detected in this target inspection mode.
              </div>
            ) : (
              <div className="space-y-2.5">
                {result.findings.map((f, idx) => {
                  const isExpanded = expandedIndex === idx;
                  const sevStyle = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.Info;

                  return (
                    <div
                      key={idx}
                      onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                      className={`p-4 rounded-xl bg-[#050508] border transition-all cursor-pointer hover:border-zinc-700 ${sevStyle.border}`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border font-bold uppercase ${sevStyle.badge}`}>
                            {f.severity}
                          </span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold ${CONFIDENCE_COLORS[f.confidence] || CONFIDENCE_COLORS.Low}`}>
                            {f.confidence} Confidence
                          </span>
                          <span className="text-xs font-mono font-bold text-white">{f.vulnerabilityType}</span>
                        </div>
                        <div className="flex items-center gap-2 text-zinc-500 text-xs font-mono">
                          <span>{f.owasp || 'A03:2021'}</span>
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </div>

                      <div className="mt-2 text-xs font-mono text-zinc-400">
                        <span className="text-zinc-500">Input Point: </span>
                        <code className="text-cyan-300">{f.inputPointTested}</code>
                      </div>

                      {/* Expanded Details */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-4 pt-3 border-t border-zinc-800/80 space-y-3 text-xs font-mono"
                          >
                            {/* Payload */}
                            {f.payloadUsed && f.payloadUsed !== 'N/A' && (
                              <div>
                                <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-1">
                                  Test Payload Injected
                                </span>
                                <pre className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 text-rose-300 overflow-x-auto text-[11px]">
                                  {f.payloadUsed}
                                </pre>
                              </div>
                            )}

                            {/* Evidence */}
                            <div>
                              <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-1">
                                Diagnostic Evidence / Differential Signature
                              </span>
                              <div className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 text-amber-300 text-[11px] leading-relaxed">
                                {f.evidence}
                              </div>
                            </div>

                            {/* Recommendation */}
                            <div>
                              <span className="text-[10px] uppercase font-bold text-emerald-400 block mb-1">
                                🛡️ Remediation Recommendation
                              </span>
                              <p className="text-zinc-300 text-[11px] leading-relaxed">
                                {f.recommendation}
                              </p>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </motion.div>
      )}
    </div>
  );
}
