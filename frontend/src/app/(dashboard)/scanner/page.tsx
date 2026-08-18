'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import {
  Scan,
  ShieldAlert,
  CheckCircle,
  Server,
  Save,
  ChevronDown,
  ChevronUp,
  Globe,
  Code2,
  Shield,
  Eye,
  BookOpen,
} from 'lucide-react';

interface Finding {
  type: string;
  injectionFamily: string;
  location: string;
  parameter?: string;
  paramValue?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  confidence: 'Confirmed' | 'Likely' | 'Possible' | 'Low';
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  evidence: string;
  evidenceSignals?: string[];
  pocPayload: string;
  recommendation: string;
}

interface ScanResult {
  targetUrl: string;
  scanTimestamp: string;
  parameters: string[];
  paramValues: Record<string, string>;
  pathSegments: string[];
  domain: string;
  techStackClues: string[];
  wafDetected?: boolean;
  wafVendor?: string | null;
  wafEvidence?: string | null;
  wafNotice?: string | null;
  potentialInjectionPoints: {
    type: string;
    location: string;
    risk: string;
    reason: string;
  }[];
  findings: Finding[];
  summary: {
    totalPages: number;
    injectionPoints: number;
    parameters: number;
    riskScore: number;
    highestSeverity: string;
    owaspCoverage: string[];
    familiesTested: string[];
    injectionFamilyCounts: Record<string, number>;
  };
}

const SEV_STYLES: Record<string, string> = {
  Critical: 'text-rose-400 border-rose-500/40 bg-rose-500/10',
  High: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  Medium: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  Low: 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10',
  Info: 'text-zinc-400 border-zinc-700/60 bg-zinc-800/50',
};

const CONFIDENCE_STYLES: Record<string, string> = {
  Confirmed: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  Likely: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
  Possible: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  Low: 'text-zinc-400 bg-zinc-800 border-zinc-700',
};

const FAMILY_COLORS: Record<string, string> = {
  'SQL/NoSQL Injection': 'text-rose-300',
  'Client-Side / XSS': 'text-amber-300',
  'Server-Side / Code Execution': 'text-purple-300',
  'Protocol / Header / Log / AI Injection': 'text-cyan-300',
};

export default function ScannerPage() {
  const [url, setUrl] = useState('');
  const [scanMode, setScanMode] = useState<'heuristic' | 'active'>('active');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [filterFamily, setFilterFamily] = useState<string>('All');

  const presets = [
    {
      name: 'Local Sandbox / DVWA',
      url: 'http://localhost:3000/api/users?id=1&name=admin',
      tag: 'Localhost Target',
    },
    {
      name: 'PHP Admin Portal',
      url: 'http://vuln-app.test/admin/login.php?username=admin&password=test&redirect=/dashboard',
      tag: 'SQLi + Auth',
    },
    {
      name: 'Search + Redirect',
      url: 'https://example.com/search?q=test&redirect=https://safe.com&id=1&page=home',
      tag: 'XSS + Redirect',
    },
    {
      name: 'File Include Portal',
      url: 'http://vuln.test/index.php?file=contact&template=home&page=about&lang=en',
      tag: 'LFI + SSTI',
    },
    {
      name: 'REST API Endpoint',
      url: 'https://api.target.com/api/v1/users?id=5&sort=name&filter=active&token=abc123',
      tag: 'NoSQL + HPP',
    },
    {
      name: 'AI Chat Interface',
      url: 'https://ai-app.test/api/chat?prompt=hello&model=gpt4&url=https://source.com',
      tag: 'Prompt Injection',
    },
  ];

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setResult(null);
    setSaveSuccess(false);
    setExpandedFinding(null);
    setFilterFamily('All');

    if (!authorized) {
      setError('You must confirm authorized permission to inspect the target.');
      return;
    }

    setLoading(true);
    try {
      const res = await api.post('/scan', {
        url,
        authorized: true,
        scanMode: scanMode === 'active' ? 'active' : 'passive',
        config: { rateLimitMs: 250, timeoutMs: 10000 },
      });

      const data = res.data;
      const rawFindings = data.findings || [];

      // Determine injection family for categorization and filters
      const mappedFindings: Finding[] = rawFindings.map((f: {
        vulnerabilityType: string;
        inputPointTested: string;
        payloadUsed: string;
        severity: Finding['severity'];
        confidence: Finding['confidence'];
        cvss?: number;
        cwe?: string;
        owasp?: string;
        evidence: string;
        evidenceSignals?: string[];
        recommendation: string;
      }) => {
        const vType = (f.vulnerabilityType || '').toLowerCase();
        let family = 'Protocol / Header / Log / AI Injection';
        if (vType.includes('sql') || vType.includes('quote') || vType.includes('tautology')) {
          family = 'SQL/NoSQL Injection';
        } else if (vType.includes('xss') || vType.includes('script') || vType.includes('canary')) {
          family = 'Client-Side / XSS';
        } else if (vType.includes('template') || vType.includes('ssti') || vType.includes('command') || vType.includes('echo')) {
          family = 'Server-Side / Code Execution';
        }

        return {
          type: f.vulnerabilityType,
          injectionFamily: family,
          location: f.inputPointTested,
          parameter: f.inputPointTested,
          paramValue: f.payloadUsed,
          severity: f.severity || 'Medium',
          confidence: f.confidence || 'Medium',
          cvss: f.cvss || 7.5,
          cwe: f.cwe || 'CWE-89',
          owasp: f.owasp || 'A03:2021',
          description: f.evidence || f.vulnerabilityType,
          evidence: f.evidence,
          evidenceSignals: f.evidenceSignals || [],
          pocPayload: f.payloadUsed,
          recommendation: f.recommendation,
        };
      });

      const familyCounts: Record<string, number> = {};
      for (const f of mappedFindings) {
        familyCounts[f.injectionFamily] = (familyCounts[f.injectionFamily] || 0) + 1;
      }

      // Extract target URL parameters and link parameters
      const targetParams: string[] = [];
      const targetParamValues: Record<string, string> = {};
      try {
        const u = new URL(data.normalizedUrl || url);
        u.searchParams.forEach((v, k) => {
          targetParams.push(k);
          targetParamValues[k] = v;
        });
      } catch {}

      const linkParams = (data.discoveredEndpoints?.linksWithParams || []).map((l: { param: string }) => l.param);
      const combinedParams = Array.from(new Set([...targetParams, ...linkParams]));

      const urlPoints = targetParams.map((p) => ({
        type: 'URL Query Parameter',
        location: `GET ${data.normalizedUrl || url} [${p}]`,
        risk: 'High',
        reason: `Target query parameter "${p}" exposed in URL string.`,
      }));

      const formPoints = (data.discoveredEndpoints?.forms || []).map((form: { method: string; action: string; inputs: { name: string }[] }) => ({
        type: 'HTML Form',
        location: `${form.method} ${form.action}`,
        risk: 'High',
        reason: `Discovered form with input fields: ${form.inputs.map((i) => i.name).join(', ')}`,
      }));

      setResult({
        targetUrl: data.targetUrl || url,
        scanTimestamp: data.scanTimestamp || new Date().toISOString(),
        parameters: combinedParams,
        paramValues: targetParamValues,
        pathSegments: [],
        domain: new URL(data.normalizedUrl || url).hostname,
        techStackClues: data.serverBanner ? [`Server: ${data.serverBanner}`] : ['Live Target Audited'],
        wafDetected: data.wafDetected,
        wafVendor: data.wafVendor,
        wafEvidence: data.wafEvidence,
        wafNotice: data.wafNotice,
        potentialInjectionPoints: [...urlPoints, ...formPoints],
        findings: mappedFindings,
        summary: {
          totalPages: 1,
          injectionPoints: urlPoints.length + (data.discoveredEndpoints?.forms?.length || 0) + (data.discoveredEndpoints?.linksWithParams?.length || 0),
          parameters: data.summary?.paramsCount || combinedParams.length,
          riskScore: data.summary?.riskScore || 0,
          highestSeverity: data.summary?.highestSeverity || 'Info',
          owaspCoverage: ['A03:2021-Injection', 'A05:2021-Security Misconfiguration'],
          familiesTested: ['SQL/NoSQL Injection', 'Client-Side / XSS', 'Server-Side / Code Execution', 'Protocol / Header / Log / AI Injection'],
          injectionFamilyCounts: familyCounts,
        },
      });
    } catch (err: unknown) {
      console.error(err);
      const errorObj = err as { response?: { data?: { error?: string } } };
      setError(errorObj.response?.data?.error || 'Target analysis failed. Verify URL structure.');
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
        title: `${scanMode === 'active' ? 'Active Differential' : 'Heuristic'} Scan — ${result.domain}`,
        targetUrl: result.targetUrl,
        scanType: 'url',
        summary: result.summary,
        findings: result.findings,
        techStack: result.techStackClues,
      });
      setSaveSuccess(true);
    } catch (err) {
      console.error(err);
      setError('Failed to save report.');
    } finally {
      setSaving(false);
    }
  };

  const filteredFindings = result?.findings.filter(
    (f) => filterFamily === 'All' || f.injectionFamily === filterFamily
  ) ?? [];

  const families = result
    ? ['All', ...Object.keys(result.summary.injectionFamilyCounts)]
    : ['All'];

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-zinc-100 font-sans">
      {/* Page Header */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
          Injection Scanner{' '}
          <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">
            78 Injection Modules
          </span>
        </h2>
        <p className="text-zinc-400 text-sm mt-1.5 font-mono">
          Comprehensive analyzer supporting Heuristic URL parsing and Deep Active Differential Probing against authorized targets.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* ── Left: Config ── */}
        <div className="lg:col-span-1 space-y-5">
          {/* Scan Form */}
          <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-zinc-800/80 pb-2">
              <h3 className="text-xs font-mono font-bold tracking-wider text-cyan-400 uppercase">
                Configure Target
              </h3>
              <span className="text-[10px] font-mono text-zinc-400">
                Mode: {scanMode === 'active' ? 'Active Deep Scan' : 'Heuristic Scan'}
              </span>
            </div>

            {/* Mode Switcher */}
            <div className="grid grid-cols-2 gap-2 bg-[#050508] p-1 rounded-xl border border-zinc-800">
              <button
                type="button"
                onClick={() => setScanMode('active')}
                className={`py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all ${
                  scanMode === 'active'
                    ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-300'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                Deep Active Scan
              </button>
              <button
                type="button"
                onClick={() => setScanMode('heuristic')}
                className={`py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all ${
                  scanMode === 'heuristic'
                    ? 'bg-purple-500/20 border border-purple-500/50 text-purple-300'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                Heuristic Scan
              </button>
            </div>

            {scanMode === 'active' ? (
              <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-[11px] text-cyan-300/90 font-mono leading-relaxed">
                Deep Active Scan fetches live HTML, parses forms and URL parameters, tests SQLi / XSS / SSTI / Command Injection vectors, and audits security headers.
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-purple-500/10 border border-purple-500/30 text-[11px] text-purple-300/90 font-mono leading-relaxed">
                Heuristic Mode analyzes target URL structure and response security headers passively without input fuzzing.
              </div>
            )}

            <form onSubmit={handleScan} className="space-y-4">
              <div>
                <label className="block text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider mb-2">
                  Target URL
                </label>
                <div className="relative">
                  <input
                    type="url"
                    required
                    placeholder="https://example.com/search?q=test or http://testfire.net/login.jsp"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="w-full pl-9 pr-4 py-2.5 rounded-xl text-xs font-mono bg-[#050508] border border-zinc-800 text-zinc-100 placeholder-zinc-600 focus:bg-[#0a0b12] focus:border-cyan-500/50 focus:outline-none transition"
                  />
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-[#050508] border border-zinc-800 flex items-start gap-2.5">
                <input
                  type="checkbox"
                  id="authorized"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 text-cyan-500 focus:ring-cyan-500/40"
                />
                <label htmlFor="authorized" className="text-xs text-zinc-300 cursor-pointer select-none leading-relaxed">
                  I confirm I have authorized permission to test this target endpoint.
                </label>
              </div>

              {error && <p className="text-xs font-mono font-bold text-rose-400">{error}</p>}

              <button
                type="submit"
                disabled={loading}
                className={`w-full py-3 rounded-xl text-xs font-mono font-bold transition-all disabled:opacity-50 flex items-center justify-center gap-2 ${
                  scanMode === 'active'
                    ? 'bg-amber-500 hover:bg-amber-400 text-black shadow-[0_0_20px_rgba(245,158,11,0.25)]'
                    : 'bg-cyan-500 hover:bg-cyan-400 text-black shadow-[0_0_20px_rgba(0,240,255,0.25)]'
                }`}
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-t-black border-r-transparent border-l-transparent border-b-black rounded-full animate-spin" />
                    {scanMode === 'active' ? 'Extracting & Probing Forms...' : 'Analyzing Parameters...'}
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4" />
                    {scanMode === 'active' ? 'Run Active Differential Probe' : 'Run Heuristic Scan'}
                  </>
                )}
              </button>
            </form>

            {/* Presets */}
            <div className="border-t border-zinc-800/80 pt-4">
              <h4 className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider mb-2.5">
                Demo Targets
              </h4>
              <div className="space-y-2">
                {presets.map((preset) => (
                  <button
                    key={preset.name}
                    onClick={() => { setUrl(preset.url); setAuthorized(true); }}
                    className="w-full text-left px-3 py-2.5 rounded-xl bg-[#050508] hover:bg-zinc-900/60 border border-zinc-800 transition-all"
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="font-mono font-bold text-xs text-zinc-200">{preset.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{preset.tag}</span>
                    </div>
                    <p className="text-[10px] font-mono text-zinc-600 truncate">{preset.url}</p>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Warning Card */}
          <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 space-y-2">
            <div className="flex items-center gap-2 font-mono font-bold">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
              <span>AUTHORIZED EDUCATIONAL AUDIT ONLY</span>
            </div>
            <p className="text-zinc-300 text-[11px] leading-relaxed">
              {scanMode === 'active'
                ? 'Deep Active mode transmits safe, non-destructive test probes (SQLi, XSS, SSTI, Command Canaries) to discover parameter and form-level vulnerabilities on authorized targets.'
                : 'Heuristic mode evaluates target URL parameters and HTTP response security headers passively without input probing.'}
            </p>
          </div>
        </div>

        {/* ── Right: Results ── */}
        <div className="lg:col-span-2">
          {!result && !loading && (
            <div className="bg-[#0c0d14] rounded-2xl p-12 text-center border border-zinc-800/80 flex flex-col items-center justify-center min-h-[420px]">
              <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-4">
                <Scan className="w-8 h-8 animate-pulse" />
              </div>
              <h3 className="font-mono font-bold text-base text-white">No Scan Running</h3>
              <p className="text-xs text-zinc-400 mt-2 max-w-sm leading-relaxed">
                Enter a URL with query parameters (e.g. <span className="text-cyan-400 font-mono">?id=1&user=admin</span>) to detect injection vulnerabilities across 78 attack categories.
              </p>
              <div className="mt-6 grid grid-cols-2 gap-2 text-[11px] font-mono text-zinc-500 max-w-xs">
                {['SQL Injection', 'XSS Variants', 'Command Injection', 'SSRF', 'SSTI', 'Prompt Injection', 'Path Traversal', 'Log4Shell'].map(t => (
                  <span key={t} className="px-2 py-1 rounded bg-zinc-900 border border-zinc-800 text-center">{t}</span>
                ))}
              </div>
            </div>
          )}

          {loading && (
            <div className="bg-[#0c0d14] rounded-2xl p-12 text-center border border-zinc-800/80 flex flex-col items-center justify-center min-h-[420px]">
              <div className="w-12 h-12 border-4 border-t-cyan-400 border-r-transparent border-l-transparent border-b-rose-500 rounded-full animate-spin mb-4" />
              <h3 className="font-mono font-bold text-base text-white">Running 78-Module Scan...</h3>
              <p className="text-xs text-zinc-400 mt-2 font-mono">
                Mapping parameters → Running injection pattern rules → Building report
              </p>
            </div>
          )}

          {result && (
            <div className="space-y-5">
              {/* WAF Detection Alert Banner */}
              {result.wafDetected && (
                <div className="p-4 rounded-2xl bg-amber-500/15 border border-amber-500/40 text-amber-300 space-y-1.5 font-mono shadow-[0_0_25px_rgba(245,158,11,0.15)]">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-bold text-xs">
                      <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>WEB APPLICATION FIREWALL (WAF) DETECTED: {result.wafVendor || 'Active WAF'}</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-200">
                      WAF Active
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-300 leading-relaxed font-sans">
                    {result.wafNotice || 'A Web Application Firewall was detected. Results may under-report real vulnerabilities, as the WAF may be blocking or altering probe payloads.'}
                  </p>
                  {result.wafEvidence && (
                    <p className="text-[10px] text-zinc-400 font-mono">
                      Signature: {result.wafEvidence}
                    </p>
                  )}
                </div>
              )}

              {/* Summary Bar */}
              <div className="bg-[#0c0d14] p-5 rounded-2xl border border-zinc-800/80 space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
                  <div>
                    <h3 className="font-mono font-bold text-base text-white">Scan Report</h3>
                    <p className="text-xs text-cyan-400 font-mono mt-0.5 truncate max-w-sm">{result.targetUrl}</p>
                    <p className="text-[10px] text-zinc-600 font-mono mt-0.5">{new Date(result.scanTimestamp).toLocaleString()}</p>
                  </div>
                  <button
                    onClick={handleSaveReport}
                    disabled={saving || saveSuccess}
                    className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-all flex items-center gap-1.5 disabled:opacity-50 shrink-0"
                  >
                    <Save className="w-4 h-4" />
                    {saving ? 'Saving...' : saveSuccess ? '✓ Saved' : 'Save Report'}
                  </button>
                </div>

                {saveSuccess && (
                  <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2 font-mono">
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                    Report saved to your security archive.
                  </div>
                )}

                {/* Stats Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
                  <div className="p-3.5 bg-[#050508] rounded-xl border border-zinc-800">
                    <p className="text-[10px] text-zinc-500 uppercase">Risk Score</p>
                    <p className={`text-xl font-bold mt-1 ${result.summary.riskScore >= 9 ? 'text-rose-400' : result.summary.riskScore >= 7 ? 'text-orange-400' : result.summary.riskScore >= 5 ? 'text-yellow-400' : 'text-cyan-400'}`}>
                      {result.summary.riskScore} <span className="text-sm text-zinc-500">/ 10</span>
                    </p>
                  </div>
                  <div className="p-3.5 bg-[#050508] rounded-xl border border-zinc-800">
                    <p className="text-[10px] text-zinc-500 uppercase">Findings</p>
                    <p className="text-xl font-bold text-rose-400 mt-1">{result.summary.injectionPoints}</p>
                  </div>
                  <div className="p-3.5 bg-[#050508] rounded-xl border border-zinc-800">
                    <p className="text-[10px] text-zinc-500 uppercase">Parameters</p>
                    <p className="text-xl font-bold text-white mt-1">{result.summary.parameters}</p>
                  </div>
                  <div className="p-3.5 bg-[#050508] rounded-xl border border-zinc-800">
                    <p className="text-[10px] text-zinc-500 uppercase">OWASP</p>
                    <p className="text-xl font-bold text-purple-400 mt-1">{result.summary.owaspCoverage.length}</p>
                  </div>
                </div>

                {/* Highest Severity */}
                <div className="flex flex-wrap items-center gap-3">
                  <span className={`text-xs font-mono font-bold px-3 py-1 rounded-full border ${SEV_STYLES[result.summary.highestSeverity] || SEV_STYLES['Info']}`}>
                    ⚠ Highest: {result.summary.highestSeverity}
                  </span>
                  {result.summary.owaspCoverage.map((o) => (
                    <span key={o} className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">{o}</span>
                  ))}
                </div>

                {/* Tech Stack */}
                {result.techStackClues.length > 0 && (
                  <div className="pt-2 border-t border-zinc-800/80">
                    <p className="text-xs text-zinc-400 font-mono mb-2 flex items-center gap-1.5">
                      <Server className="w-4 h-4 text-cyan-400" /> Tech Stack Fingerprint:
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {result.techStackClues.map((t) => (
                        <span key={t} className="px-2.5 py-1 rounded-lg bg-zinc-900 border border-zinc-700 text-xs font-mono text-cyan-300">{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Family Breakdown */}
                {Object.keys(result.summary.injectionFamilyCounts).length > 0 && (
                  <div className="pt-2 border-t border-zinc-800/80">
                    <p className="text-xs text-zinc-400 font-mono mb-2">Findings by Category:</p>
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(result.summary.injectionFamilyCounts).map(([family, count]) => (
                        <div key={family} className="flex items-center justify-between px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-800">
                          <span className={`text-[11px] font-mono ${FAMILY_COLORS[family] || 'text-zinc-300'}`}>{family}</span>
                          <span className="text-xs font-mono font-bold text-white">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Findings Filter */}
              <div className="flex gap-2 flex-wrap">
                {families.map((fam) => (
                  <button
                    key={fam}
                    onClick={() => setFilterFamily(fam)}
                    className={`px-3 py-1.5 rounded-lg text-[11px] font-mono font-bold border transition-all ${filterFamily === fam
                      ? 'bg-cyan-500 text-black border-cyan-400'
                      : 'bg-zinc-900 text-zinc-400 border-zinc-800 hover:border-cyan-500/40'
                    }`}
                  >
                    {fam === 'All' ? `All (${result.findings.length})` : `${fam.split(' / ')[0]} (${result.summary.injectionFamilyCounts[fam] || 0})`}
                  </button>
                ))}
              </div>

              {/* Finding Cards */}
              <div className="space-y-3">
                {filteredFindings.length === 0 && (
                  <div className="text-center py-8 text-zinc-500 text-sm font-mono">
                    No findings in this category.
                  </div>
                )}
                {filteredFindings.map((finding, idx) => {
                  const isExpanded = expandedFinding === idx;
                  return (
                    <div key={idx} className="bg-[#0c0d14] rounded-2xl border border-zinc-800/80 overflow-hidden">
                      <button
                        onClick={() => setExpandedFinding(isExpanded ? null : idx)}
                        className="w-full px-5 py-4 flex items-center justify-between text-left hover:bg-zinc-900/40 transition-all gap-4"
                      >
                        <div className="space-y-1.5 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${SEV_STYLES[finding.severity]}`}>
                              {finding.severity}
                            </span>
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${CONFIDENCE_STYLES[finding.confidence]}`}>
                              {finding.confidence}
                            </span>
                            <span className="text-sm font-mono font-bold text-white">{finding.type}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <p className="text-[11px] text-zinc-500 font-mono truncate">{finding.location}</p>
                            <span className={`text-[10px] font-mono shrink-0 ${FAMILY_COLORS[finding.injectionFamily] || 'text-zinc-400'}`}>
                              {finding.injectionFamily}
                            </span>
                          </div>
                        </div>
                        {isExpanded ? <ChevronUp className="w-4 h-4 text-zinc-400 shrink-0" /> : <ChevronDown className="w-4 h-4 text-zinc-400 shrink-0" />}
                      </button>

                      {isExpanded && (
                        <div className="px-5 pb-5 pt-3 border-t border-zinc-800/60 space-y-4 text-xs animate-in fade-in duration-200">
                          {/* Description */}
                          <div>
                            <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                              <BookOpen className="w-3 h-3" /> Threat Description
                            </span>
                            <p className="text-zinc-300 leading-relaxed">{finding.description}</p>
                          </div>

                          {/* Evidence */}
                          <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800">
                            <span className="text-[10px] font-mono font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                              <Eye className="w-3 h-3" /> Detection Evidence
                            </span>
                            <p className="text-zinc-300 font-mono text-[11px] leading-relaxed">{finding.evidence}</p>
                          </div>

                          {/* Corroborating Signals */}
                          {finding.evidenceSignals && finding.evidenceSignals.length > 0 && (
                            <div className="p-3 bg-zinc-900/40 rounded-xl border border-zinc-800 space-y-1.5">
                              <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                                <CheckCircle className="w-3 h-3" /> Corroborating Signals ({finding.evidenceSignals.length})
                              </span>
                              <div className="flex flex-wrap gap-1.5 mt-1">
                                {finding.evidenceSignals.map((sig, idx) => (
                                  <span
                                    key={idx}
                                    className="px-2 py-0.5 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-[10px] font-mono text-cyan-300"
                                  >
                                    ✓ {sig}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* PoC Payload */}
                          <div>
                            <span className="text-[10px] font-mono font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                              <Code2 className="w-3 h-3" /> Safe PoC Payload (Educational)
                            </span>
                            <div className="p-3 bg-[#050508] rounded-xl border border-rose-500/20 font-mono text-[11px] text-rose-300 break-all">
                              {finding.pocPayload}
                            </div>
                          </div>

                          {/* Scores */}
                          <div className="grid grid-cols-3 gap-3 font-mono">
                            <div className="p-3 bg-[#050508] rounded-xl border border-zinc-800">
                              <span className="text-[10px] text-zinc-500 block">CVSS Score</span>
                              <span className="text-rose-400 font-bold text-sm">{finding.cvss} / 10</span>
                            </div>
                            <div className="p-3 bg-[#050508] rounded-xl border border-zinc-800">
                              <span className="text-[10px] text-zinc-500 block">CWE</span>
                              <span className="text-cyan-400 font-bold text-sm">{finding.cwe}</span>
                            </div>
                            <div className="p-3 bg-[#050508] rounded-xl border border-zinc-800">
                              <span className="text-[10px] text-zinc-500 block">OWASP</span>
                              <span className="text-purple-400 font-bold text-sm">{finding.owasp}</span>
                            </div>
                          </div>

                          {/* Recommendation */}
                          <div className="p-3.5 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
                            <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                              <Shield className="w-3 h-3" /> Recommended Fix
                            </span>
                            <p className="text-zinc-300 leading-relaxed">{finding.recommendation}</p>
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
