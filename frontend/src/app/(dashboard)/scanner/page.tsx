'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { motion } from 'framer-motion';
import { 
  Scan, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Server, 
  HelpCircle, 
  Save, 
  ChevronDown, 
  ChevronUp, 
  Globe 
} from 'lucide-react';
import Link from 'next/link';

interface Finding {
  type: string;
  location: string;
  parameter?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  recommendation: string;
}

interface ScanResult {
  targetUrl: string;
  parameters: string[];
  pathSegments: string[];
  potentialInjectionPoints: {
    type: string;
    location: string;
    risk: string;
  }[];
  findings: Finding[];
  techStackClues: string[];
  summary: {
    totalPages: number;
    injectionPoints: number;
    parameters: number;
    riskScore: number;
    owaspCoverage: string[];
  };
}

export default function ScannerPage() {
  const [url, setUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);

  // Preset vulnerable urls for user convenience
  const presets = [
    { name: 'Vulnerable Portal', url: 'http://localhost:3000/labs/crlf-injection?redirect=https://safe.com' },
    { name: 'SMTP Injection Lab', url: 'http://localhost:3000/labs/smtp-injection?to=admin@myapp.com' },
    { name: 'Log4Shell Simulator', url: 'http://localhost:3000/labs/log4shell?ua=jndi:ldap://test' },
  ];

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setResult(null);
    setSaveSuccess(false);

    if (!authorized) {
      setError('You must confirm authorized permission to inspect the target.');
      return;
    }

    setLoading(true);

    try {
      const res = await api.post('/scanner/analyze', { url, authorized });
      setResult(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.error || 'Target analysis failed. Verify URL structure.');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveReport = async () => {
    if (!result) return;
    setSaving(true);
    setSaveSuccess(false);

    try {
      await api.post('/reports/generate', {
        title: `Safe Inspection - ${new URL(result.targetUrl).hostname}`,
        targetUrl: result.targetUrl,
        scanType: 'url',
        summary: result.summary,
        findings: result.findings,
        techStack: result.techStackClues,
      });
      setSaveSuccess(true);
    } catch (err) {
      console.error(err);
      setError('Failed to save report to server logs.');
    } finally {
      setSaving(false);
    }
  };

  const toggleFinding = (index: number) => {
    setExpandedFinding(expandedFinding === index ? null : index);
  };

  return (
    <div className="space-y-10 animate-in fade-in duration-500 text-slate-800">
      {/* Page Header */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Target Inspector</h2>
        <p className="text-slate-600 text-base mt-1.5 font-semibold">
          Perform safe, structural, and educational analysis of routes to identify parameters, forms, and vulnerability mappings.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* URL Scanner Setup Card */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-6">
            <h3 className="text-base font-bold tracking-wider text-slate-800 uppercase border-b border-slate-100 pb-2">
              Configure Target
            </h3>

            <form onSubmit={handleScan} className="space-y-5">
              <div>
                <label className="block text-xs font-bold text-slate-600 uppercase tracking-wider mb-2">
                  Target Endpoint URL
                </label>
                <div className="relative">
                  <input
                    type="url"
                    required
                    placeholder="https://example.com/login"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="w-full pl-10 pr-4 py-3.5 rounded-2xl text-sm bg-slate-50 border border-slate-200 text-slate-955 placeholder-slate-450 focus:bg-white focus:border-blue-600 focus:ring-2 focus:ring-blue-100 focus:outline-none transition-colors"
                  />
                  <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4.5 h-4.5 text-slate-400" />
                </div>
              </div>

              {/* Consent Toggle */}
              <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 flex items-start gap-3 shadow-inner">
                <input
                  type="checkbox"
                  id="authorized"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-1 h-5 w-5 rounded-md border-slate-300 text-blue-600 focus:ring-blue-500 focus:ring-2"
                />
                <label htmlFor="authorized" className="text-xs font-bold text-slate-655 text-slate-600 cursor-pointer select-none leading-relaxed">
                  I confirm that I have explicit authorization to audit and inspect this target website or application.
                </label>
              </div>

              {error && <p className="text-xs font-bold text-red-600">{error}</p>}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-4 rounded-2xl text-sm font-bold bg-slate-950 text-white shadow-md hover:bg-slate-900 active:scale-[0.98] transition-all disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <div className="w-4.5 h-4.5 border-2 border-t-white border-r-transparent border-l-transparent border-b-white rounded-full animate-spin" />
                    Analyzing Target...
                  </>
                ) : (
                  <>
                    <Scan className="w-4.5 h-4.5" />
                    Execute Safe Scan
                  </>
                )}
              </button>
            </form>

            <div className="border-t border-slate-200 pt-4">
              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">
                Built-in Demo Presets
              </h4>
              <div className="space-y-2.5">
                {presets.map((preset) => (
                  <button
                    key={preset.name}
                    onClick={() => {
                      setUrl(preset.url);
                      setAuthorized(true);
                    }}
                    className="w-full text-left px-4 py-3.5 rounded-2xl bg-slate-50 hover:bg-blue-50 border border-slate-200 hover:border-blue-300 transition-all text-xs flex justify-between items-center shadow-sm"
                  >
                    <span className="font-bold text-slate-800">{preset.name}</span>
                    <span className="font-mono text-[10px] text-slate-500 truncate max-w-[155px] font-bold">{preset.url}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Educational Disclaimer Panel */}
          <div className="p-4 rounded-2xl bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-2 shadow-sm">
            <div className="flex items-center gap-2 font-bold text-amber-800">
              <ShieldAlert className="w-5 h-5 shrink-0" />
              <span>SAFETY NOTICE</span>
            </div>
            <p className="font-semibold leading-relaxed">
              This tool performs passive analysis by parsing path variables and parameters. It does NOT send malicious payloads or run exploits. It exists to map routing points to educational CWE modules.
            </p>
          </div>
        </div>

        {/* Results Screen */}
        <div className="lg:col-span-2">
          {!result && !loading && (
            <div className="bg-white rounded-3xl p-12 text-center border border-slate-200 shadow-sm flex flex-col items-center justify-center min-h-[400px]">
              <div className="p-4.5 rounded-2xl bg-blue-50 border border-blue-100 text-blue-600 mb-4 shadow-sm">
                <Scan className="w-8 h-8 animate-pulse" />
              </div>
              <h3 className="font-bold text-lg text-slate-900">No Target Inspected</h3>
              <p className="text-sm text-slate-500 mt-2 max-w-sm font-bold leading-relaxed">
                Enter an authorized URL or choose a demo lab configuration to map structural vulnerabilities.
              </p>
            </div>
          )}

          {loading && (
            <div className="bg-white rounded-3xl p-12 text-center border border-slate-200 shadow-sm flex flex-col items-center justify-center min-h-[400px]">
              <div className="w-12 h-12 border-4 border-t-blue-600 border-r-transparent border-l-transparent border-b-slate-950 rounded-full animate-spin mb-4" />
              <h3 className="font-bold text-lg text-slate-900">Performing Analysis...</h3>
              <p className="text-sm text-slate-500 mt-2 font-bold leading-relaxed">
                Extracting cookies, parsing header mappings, and cataloging potential injection risks.
              </p>
            </div>
          )}

          {result && (
            <div className="space-y-6">
              {/* Scan Overview */}
              <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-100 pb-4 mb-4">
                  <div>
                    <h3 className="font-extrabold text-lg text-slate-900">Scan Assessment</h3>
                    <p className="text-xs md:text-sm text-slate-500 font-mono mt-1 font-bold">{result.targetUrl}</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={handleSaveReport}
                      disabled={saving || saveSuccess}
                      className="px-4.5 py-3 rounded-2xl text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-200 transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-sm"
                    >
                      <Save className="w-4 h-4" />
                      {saving ? 'Saving...' : saveSuccess ? 'Saved' : 'Save Report'}
                    </button>
                  </div>
                </div>

                {saveSuccess && (
                  <div className="mb-4 p-3.5 rounded-2xl bg-green-50 border border-green-200 text-xs text-green-700 flex items-center gap-2 font-bold animate-in fade-in duration-300 shadow-sm">
                    <CheckCircle className="w-4.5 h-4.5 shrink-0 text-green-600" />
                    <span>Report has been successfully logged to your security archive.</span>
                  </div>
                )}

                {/* Score Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                    <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Risk Score</p>
                    <p className="text-xl font-bold font-mono text-red-600 mt-1">{result.summary.riskScore} / 10</p>
                  </div>
                  <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                    <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Findings Found</p>
                    <p className="text-xl font-bold font-mono text-blue-600 mt-1">{result.summary.injectionPoints}</p>
                  </div>
                  <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                    <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Parameters</p>
                    <p className="text-xl font-bold font-mono text-slate-900 mt-1">{result.summary.parameters}</p>
                  </div>
                  <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                    <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">OWASP Covered</p>
                    <p className="text-xl font-bold font-mono text-slate-900 mt-1">{result.summary.owaspCoverage.length}</p>
                  </div>
                </div>

                {/* Tech Stack */}
                {result.techStackClues.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-slate-100">
                    <p className="text-xs text-slate-600 font-bold mb-2 flex items-center gap-1.5">
                      <Server className="w-4 h-4 text-blue-600" /> Tech Stack Clues:
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {result.techStackClues.map((t) => (
                        <span key={t} className="px-3 py-1.5 rounded-2xl bg-slate-50 border border-slate-200 text-xs font-bold text-slate-700">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Finding Cards */}
              <div className="space-y-4">
                <h4 className="text-sm md:text-base font-bold tracking-wider text-slate-800 uppercase">
                  Identified Finding Details
                </h4>

                {result.findings.map((finding, idx) => {
                  const isExpanded = expandedFinding === idx;
                  const sevColors = {
                    Critical: 'text-red-700 border-red-200 bg-red-50',
                    High: 'text-amber-700 border-amber-200 bg-amber-50',
                    Medium: 'text-yellow-800 border-yellow-200 bg-yellow-50',
                    Low: 'text-blue-700 border-blue-200 bg-blue-50',
                    Info: 'text-slate-700 border-slate-200 bg-slate-50',
                  };

                  return (
                    <div key={idx} className="bg-white rounded-3xl border border-slate-200 overflow-hidden shadow-sm hover:border-slate-300 transition-all">
                      <button
                        onClick={() => toggleFinding(idx)}
                        className="w-full px-5 py-4.5 flex items-center justify-between text-left hover:bg-slate-50 transition-all gap-4"
                      >
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-2.5">
                            <span className={`text-[10px] px-2.5 py-0.5 rounded-full border font-bold ${sevColors[finding.severity]}`}>
                              {finding.severity}
                            </span>
                            <span className="text-sm md:text-base font-bold text-slate-900">{finding.type}</span>
                          </div>
                          <p className="text-xs text-slate-500 font-mono truncate max-w-lg font-bold">{finding.location}</p>
                        </div>
                        {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
                      </button>

                      {isExpanded && (
                        <div className="px-5 pb-5 pt-2 border-t border-slate-100 space-y-4 text-xs md:text-sm animate-in fade-in duration-300">
                          <div>
                            <span className="text-xs font-bold text-slate-655 text-slate-500 uppercase tracking-wider block mb-1">
                              Threat Description
                            </span>
                            <p className="text-slate-700 font-semibold leading-relaxed">{finding.description}</p>
                          </div>

                          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                            <div>
                              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-0.5">
                                CVSS Score
                              </span>
                              <span className="font-mono text-red-600 font-bold">{finding.cvss} / 10</span>
                            </div>
                            <div>
                              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-0.5">
                                CWE Reference
                              </span>
                              <span className="font-mono text-blue-600 font-bold">{finding.cwe}</span>
                            </div>
                            <div>
                              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-0.5">
                                OWASP Mapping
                              </span>
                              <span className="font-mono text-slate-900 font-bold">{finding.owasp}</span>
                            </div>
                          </div>

                          <div className="p-4 bg-green-50 rounded-3xl border border-green-200">
                            <span className="text-xs text-green-800 font-bold flex items-center gap-1.5 mb-2">
                              <AlertTriangle className="w-4 h-4 text-green-600" /> Secure Mitigation
                            </span>
                            <p className="text-xs md:text-sm text-green-900 font-semibold leading-relaxed">{finding.recommendation}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
