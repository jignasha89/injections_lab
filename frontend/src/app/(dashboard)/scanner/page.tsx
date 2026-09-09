'use client';

import { useState, useRef, useEffect } from 'react';
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
  AlertCircle,
  XCircle,
  Crosshair,
  Activity,
  AlertTriangle,
  Info,
  Play
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import { useScannerStore, Finding } from '@/store/scannerStore';
import AssessmentEngineProgress from '@/components/dashboard/AssessmentEngineProgress';

const getSeverityBadgeClass = (severity: string) => {
  switch (severity) {
    case 'Critical': return 'severity-critical';
    case 'High': return 'severity-high';
    case 'Medium': return 'severity-medium';
    case 'Low': return 'severity-low';
    case 'Info':
    default: return 'severity-info';
  }
};

const getConfidenceBadgeClass = (confidence: string) => {
  switch (confidence) {
    case 'Confirmed': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'Likely': return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'Possible': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    default: return 'bg-surface-base border-border-strong text-text-secondary';
  }
};

const getFamilySeverity = (findings: Finding[]) => {
  if (findings.some(f => f.severity === 'Critical')) return 'Critical';
  if (findings.some(f => f.severity === 'High')) return 'High';
  if (findings.some(f => f.severity === 'Medium')) return 'Medium';
  if (findings.some(f => f.severity === 'Low')) return 'Low';
  return 'Info';
};

const getSeverityTextColor = (severity: string) => {
  switch (severity) {
    case 'Critical': return 'text-severity-critical';
    case 'High': return 'text-severity-high';
    case 'Medium': return 'text-severity-medium';
    case 'Low': return 'text-severity-low';
    case 'Info':
    default: return 'text-severity-info';
  }
};

const FamilySeverityIcon = ({ severity, className }: { severity: string; className: string }) => {
  switch (severity) {
    case 'Critical': return <XCircle className={className} />;
    case 'High': return <AlertTriangle className={className} />;
    case 'Medium': return <AlertCircle className={className} />;
    case 'Low': return <Shield className={className} />;
    case 'Info':
    default: return <Info className={className} />;
  }
};

function parseEvidence(evidenceStr: string | undefined): any {
  if (!evidenceStr) return null;
  try {
    const parsed = JSON.parse(evidenceStr);
    if (typeof parsed === 'object' && parsed !== null) return parsed;
    return null;
  } catch {
    return null;
  }
}

export default function ScannerPage() {
  const [timeStr, setTimeStr] = useState<string>('00:00:00');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toLocaleTimeString('en-US', { hour12: false }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const { 
    url, setUrl, authorized, setAuthorized, loading, result, error, setError, 
    startScan, stopScan, resetScan, reset, scanState
  } = useScannerStore();

  const isScanning = scanState === 'running' || scanState === 'stopping';
  const isScanFinished = scanState === 'stopped' || scanState === 'completed';

  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [expandedFamily, setExpandedFamily] = useState<string | null>(null);
  const [filterFamily, setFilterFamily] = useState<string>('All');

  const [urlTouched, setUrlTouched] = useState(false);
  const [urlError, setUrlError] = useState('');
  const formRef = useRef<HTMLFormElement>(null);

  const validateUrl = (value: string): string => {
    if (!value.trim()) return 'An endpoint URL is required to begin analysis.';
    try {
      new URL(value);
      return '';
    } catch {
      return 'Enter a valid URL starting with http:// or https://';
    }
  };

  const handleUrlChange = (value: string) => {
    setUrl(value);
    if (urlTouched) {
      setUrlError(validateUrl(value));
    }
  };

  const handleUrlBlur = () => {
    setUrlTouched(true);
    setUrlError(validateUrl(url));
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveSuccess(false);
    setExpandedFinding(null);
    setFilterFamily('All');

    const validationError = validateUrl(url);
    if (validationError) {
      setUrlTouched(true);
      setUrlError(validationError);
      return;
    }

    await startScan();
  };

  const handleSaveReport = async () => {
    if (!result) return;
    setSaving(true);
    setSaveSuccess(false);
    try {
      await api.post('/reports/generate', {
        title: `Assessment — ${result.domain}`,
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

  const groupedFindings = filteredFindings.reduce((acc, f) => {
    const family = f.injectionFamily;
    if (!acc[family]) acc[family] = [];
    acc[family].push(f);
    return acc;
  }, {} as Record<string, Finding[]>);

  const families = result
    ? ['All', ...Object.keys(result.summary.injectionFamilyCounts)]
    : ['All'];

  // ─── STATE 1: CONFIGURATION (2-COLUMN LAYOUT 40/60) ───
  if (!result) {
    return (
      <div className="min-h-screen bg-[#0a0e27] font-mono text-white selection:bg-[#00d4ff]/30 flex flex-col">
        
        {/* Full-Width Header (Height: 60px) */}
        <header className="h-[60px] border-b border-[#00d4ff]/30 px-6 md:px-8 flex items-center justify-between bg-[#080c21]/90 shrink-0">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-[#00d4ff] animate-pulse" />
            <h1 className="text-base md:text-lg font-bold text-[#00d4ff] uppercase tracking-wider font-mono">
              InjectionLab Demo
            </h1>
          </div>

          <div className="px-4 py-1 rounded bg-[#040714] border border-[#00d4ff]/30 text-[#00d4ff] font-mono font-bold text-sm md:text-base">
            {timeStr}
          </div>
        </header>

        {/* 2-Column Main View */}
        <main className="flex-1 p-6 md:p-8 max-w-[1600px] w-full mx-auto">
          {/* Page Heading */}
          <div className="mb-6 border-b border-[#00d4ff]/20 pb-4">
            <h2 className="text-xl font-bold text-[#00d4ff] uppercase tracking-wider flex items-center gap-2">
              <Scan className="w-5 h-5 text-[#00d4ff]" /> INJECTION SCANNER
            </h2>
            <p className="text-xs text-[#a0aec0] font-mono mt-1">
              Configure target endpoint for deep structural vulnerability inspection
            </p>
          </div>

        {/* 2-Column Layout (LEFT 40%, RIGHT 60%) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-8 items-start">
          
          {/* LEFT COLUMN (40% width / 5 cols) */}
          <div className="lg:col-span-5 space-y-6">
            <div className="p-6 rounded-2xl bg-[#070b1e]/90 border border-[#00d4ff]/35 shadow-[0_0_25px_rgba(0,212,255,0.12)]">
              
              {/* Header */}
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/40 flex items-center justify-center text-[#00d4ff] shadow-[0_0_12px_rgba(0,212,255,0.3)]">
                  <Scan className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white tracking-tight font-mono">
                    Active Assessment
                  </h2>
                  <span className="text-[10px] text-[#00d4ff] font-mono uppercase tracking-wider font-bold">55 Rules Enabled</span>
                </div>
              </div>

              <p className="text-xs text-[#a0aec0] leading-relaxed mb-6 font-mono">
                Configure a target endpoint for deep structural inspection. InjectionLab will perform automated fuzzing across 55+ known vulnerability patterns.
              </p>

              {/* Form */}
              <form ref={formRef} onSubmit={handleScan} noValidate className="space-y-6">
                <div>
                  <label htmlFor="target-url" className="block text-xs font-bold text-[#a0aec0] uppercase tracking-wider mb-2 font-mono">
                    TARGET URL
                  </label>
                  <div className="relative">
                    <input
                      id="target-url"
                      type="text"
                      placeholder="https://example.com?id=1&search=test"
                      value={url}
                      onChange={(e) => handleUrlChange(e.target.value)}
                      onBlur={handleUrlBlur}
                      disabled={isScanning || loading}
                      className={`w-full h-[44px] px-4 rounded-md bg-[#040714] border text-xs md:text-sm text-white font-mono placeholder:text-[#a0aec0]/40 transition-all outline-none ${
                        urlTouched && urlError ? 'border-red-500 focus:ring-1 focus:ring-red-500' : 'border-[#00d4ff]/30 focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff]/50'
                      }`}
                    />
                  </div>
                  {urlTouched && urlError && (
                    <div className="mt-2 flex items-center gap-2 text-xs font-medium text-red-400 font-mono">
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>{urlError}</span>
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-[#00d4ff]/20">
                  <div className="flex items-start gap-3 mb-6">
                    <input
                      type="checkbox"
                      id="authorized"
                      checked={authorized}
                      onChange={(e) => setAuthorized(e.target.checked)}
                      disabled={isScanning || loading}
                      className="mt-1 h-4 w-4 rounded border-[#00d4ff]/40 bg-transparent text-[#00d4ff] focus:ring-[#00d4ff]/40 accent-[#00d4ff] cursor-pointer shrink-0"
                    />
                    <label htmlFor="authorized" className="text-xs text-[#a0aec0] font-mono cursor-pointer select-none leading-relaxed">
                      I confirm authorization to inspect this target and understand that structural parameter analysis will be performed.
                    </label>
                  </div>

                  {/* START SCAN button (Gradient purple -> cyan, 100% width) */}
                  {(scanState === 'idle' || isScanFinished) && (
                    <button
                      type="submit"
                      disabled={loading}
                      onClick={(e) => {
                        if (isScanFinished) {
                          e.preventDefault();
                          resetScan();
                          setUrlTouched(false);
                          setUrlError('');
                          setSaveSuccess(false);
                          setTimeout(() => {
                            formRef.current?.requestSubmit();
                          }, 50);
                        }
                      }}
                      className="w-full h-[46px] rounded-lg bg-gradient-to-r from-[#818cf8] via-[#6366f1] to-[#00d4ff] hover:from-[#a5b4fc] hover:to-[#33ddff] text-white font-mono font-extrabold text-sm uppercase tracking-widest transition-all shadow-[0_0_25px_rgba(0,212,255,0.4)] hover:shadow-[0_0_35px_rgba(0,212,255,0.7)] hover:scale-[1.01] active:scale-[0.99] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                    >
                      <Play className="w-4 h-4 fill-current text-white" />
                      <span>START SCAN</span>
                    </button>
                  )}

                  {scanState === 'running' && (
                    <button
                      type="button"
                      onClick={() => stopScan()}
                      className="w-full h-[46px] rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/50 font-mono font-extrabold text-sm uppercase tracking-widest transition-all shadow-lg flex items-center justify-center gap-2 cursor-pointer"
                    >
                      <XCircle className="w-4 h-4" /> STOP SCAN
                    </button>
                  )}
                </div>

                {error && (
                  <div className="p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    {error}
                  </div>
                )}
              </form>
            </div>
          </div>

          {/* RIGHT COLUMN (60% width / 7 cols) */}
          <div className="lg:col-span-7">
            <AssessmentEngineProgress className="w-full" />
          </div>

        </div>
        </main>
      </div>
    );
  }

  // ─── STATE 2: SCAN RESULTS VIEW ───
  return (
    <div className="max-w-[1600px] mx-auto p-6 md:p-8 space-y-8 font-mono text-white pb-16">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-[#00d4ff]/20">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3 font-mono">
            <Shield className="w-6 h-6 text-[#00d4ff]" />
            Assessment Complete
          </h1>
          <p className="text-xs font-mono text-[#a0aec0] mt-2">
            Target: <span className="text-[#00d4ff]">{result.targetUrl}</span>
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => {
              reset();
              setUrlTouched(false);
              setUrlError('');
            }}
            className="px-4 py-2 rounded-lg bg-[#070b1e] border border-[#00d4ff]/30 text-xs font-mono font-bold text-[#a0aec0] hover:text-white hover:border-[#00d4ff] transition-all"
          >
            New Scan
          </button>
          <button
            onClick={handleSaveReport}
            disabled={saving || saveSuccess}
            className="px-5 py-2 rounded-lg bg-[#00d4ff] text-[#0a0e27] text-xs font-mono font-extrabold uppercase tracking-wider flex items-center gap-2 shadow-[0_0_20px_rgba(0,212,255,0.4)] hover:bg-[#33ddff] disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Saving…' : saveSuccess ? '✓ Saved' : 'Save Report'}
          </button>
        </div>
      </div>

      {saveSuccess && (
        <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center gap-2">
          <CheckCircle className="w-4 h-4 shrink-0" />
          Report successfully saved to Workspace.
        </div>
      )}

      {/* Primary Results Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-6 rounded-xl bg-[#070b1e] border-l-4 border-l-red-500 border border-[#00d4ff]/20">
          <p className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest mb-2">Risk Score</p>
          <p className="text-4xl font-extrabold font-mono text-red-500">
            {result.summary.riskScore} <span className="text-sm text-[#a0aec0]">/ 10</span>
          </p>
        </div>
        <div className="p-6 rounded-xl bg-[#070b1e] border border-[#00d4ff]/20">
          <p className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest mb-2">Unique Findings</p>
          <p className="text-4xl font-extrabold font-mono text-white">{result.summary.injectionPoints}</p>
        </div>
        <div className="p-6 rounded-xl bg-[#070b1e] border border-[#00d4ff]/20">
          <p className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest mb-2">Parameters Analyzed</p>
          <p className="text-4xl font-extrabold font-mono text-white">{result.summary.parameters}</p>
        </div>
        <div className="p-6 rounded-xl bg-[#070b1e] border border-[#00d4ff]/20">
          <p className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest mb-2">OWASP Coverage</p>
          <p className="text-4xl font-extrabold font-mono text-white">{result.summary.owaspCoverage.length}</p>
        </div>
      </div>

      {/* Tech stack */}
      {result.techStackClues && result.techStackClues.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <span className="text-xs text-[#a0aec0] font-bold uppercase tracking-widest flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-[#00d4ff]" /> Intelligence:
          </span>
          {result.techStackClues.map((t) => (
            <span key={t} className="px-2.5 py-1 bg-[#070b1e] border border-[#00d4ff]/30 text-[11px] font-mono text-[#00d4ff] rounded">
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Detailed Findings Section */}
      <div className="space-y-6 pt-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#00d4ff]/20 pb-4">
          <h2 className="text-lg font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-[#00d4ff]" /> Detailed Findings ({result.findings.length})
          </h2>

          {/* Family Filter Tabs */}
          <div className="flex gap-2 flex-wrap">
            {families.map((fam) => (
              <button
                key={fam}
                onClick={() => setFilterFamily(fam)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all border ${
                  filterFamily === fam
                    ? 'bg-[#00d4ff]/15 text-[#00d4ff] border-[#00d4ff]'
                    : 'bg-[#070b1e] text-[#a0aec0] border-[#00d4ff]/20 hover:text-white hover:border-[#00d4ff]/50'
                }`}
              >
                {fam === 'All' ? `All (${result.findings.length})` : `${fam.split(' / ')[0]} (${result.summary.injectionFamilyCounts[fam] || 0})`}
              </button>
            ))}
          </div>
        </div>

        {/* Grouped Findings Accordion */}
        <div className="space-y-4">
          {Object.entries(groupedFindings).map(([family, familyFindings], familyIdx) => {
            const isFamilyExpanded = expandedFamily === family || (expandedFamily === null && familyIdx === 0);
            const familySeverity = getFamilySeverity(familyFindings);
            const textColorClass = getSeverityTextColor(familySeverity);

            return (
              <div key={family} className="rounded-xl bg-[#070b1e] border border-[#00d4ff]/25 overflow-hidden">
                <button
                  onClick={() => setExpandedFamily(isFamilyExpanded ? '' : family)}
                  className="w-full px-6 py-4 bg-[#080d24] flex items-center justify-between transition-colors border-b border-[#00d4ff]/20 hover:bg-[#0c1334]"
                >
                  <h3 className={`text-sm font-bold uppercase tracking-wider flex items-center gap-3 ${textColorClass}`}>
                    <FamilySeverityIcon severity={familySeverity} className="w-5 h-5" /> {family}
                  </h3>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-[#00d4ff] bg-[#00d4ff]/10 px-2.5 py-1 rounded border border-[#00d4ff]/30">
                      {familyFindings.length} Finding{familyFindings.length !== 1 ? 's' : ''}
                    </span>
                    {isFamilyExpanded ? <ChevronUp className="w-5 h-5 text-[#a0aec0]" /> : <ChevronDown className="w-5 h-5 text-[#a0aec0]" />}
                  </div>
                </button>

                <AnimatePresence>
                  {isFamilyExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="p-6 space-y-4"
                    >
                      {familyFindings.map((finding, idx) => {
                        const globalId = `${family}-${idx}`;
                        const isExpanded = expandedFinding === globalId;

                        return (
                          <div key={idx} className="rounded-lg bg-[#0a0f2c] border border-[#00d4ff]/20 overflow-hidden">
                            <button
                              onClick={() => setExpandedFinding(isExpanded ? null : globalId)}
                              className="w-full px-5 py-4 flex items-center justify-between text-left hover:bg-[#0e163d] transition-colors gap-4"
                              aria-expanded={isExpanded}
                            >
                              <div className="space-y-1.5 min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className={`severity-badge ${getSeverityBadgeClass(finding.severity)}`}>
                                    {finding.severity}
                                  </span>
                                  {finding.confidence && (
                                    <span className={`text-[10px] font-mono px-2 py-0.5 border rounded ${getConfidenceBadgeClass(finding.confidence)}`}>
                                      {finding.confidence}
                                    </span>
                                  )}
                                  <span className="text-sm font-bold text-white">
                                    {finding.type}
                                  </span>
                                  <span className="text-[10px] px-2 py-0.5 rounded border border-[#00d4ff]/30 text-[#00d4ff] font-mono">
                                    {finding.cwe}
                                  </span>
                                  <span className="text-[10px] px-2 py-0.5 rounded border border-[#00d4ff]/30 text-[#a0aec0] font-mono">
                                    {finding.owasp}
                                  </span>
                                </div>
                                <p className="text-xs text-[#a0aec0] font-mono truncate">
                                  {finding.location}
                                </p>
                              </div>
                              <div className="flex items-center gap-3 shrink-0">
                                <span className="text-xs font-mono font-bold text-[#00d4ff]">CVSS: {finding.cvss}</span>
                                {isExpanded ? <ChevronUp className="w-4 h-4 text-[#a0aec0]" /> : <ChevronDown className="w-4 h-4 text-[#a0aec0]" />}
                              </div>
                            </button>

                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: 'auto', opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  className="p-5 border-t border-[#00d4ff]/20 space-y-4 bg-[#070b1e]/95"
                                >
                                  {/* Parameter & Location */}
                                  {finding.parameter && (
                                    <div>
                                      <span className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest block mb-1 flex items-center gap-1.5">
                                        <Crosshair className="w-3 h-3 text-[#00d4ff]" /> Tested Parameter
                                      </span>
                                      <div className="p-3 rounded bg-[#040714] border border-[#00d4ff]/20 font-mono text-sm text-[#00d4ff] break-all">
                                        {finding.parameter}
                                        {finding.paramValue && (
                                          <span className="text-xs text-[#a0aec0] block mt-1">Value: {finding.paramValue}</span>
                                        )}
                                      </div>
                                    </div>
                                  )}

                                  {/* Evidence / Detection Signals */}
                                  <div>
                                    <span className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest block mb-1 flex items-center gap-1.5">
                                      <Eye className="w-3 h-3 text-[#00d4ff]" /> Detection Evidence
                                    </span>
                                    <div className="p-3 rounded bg-[#040714] border border-[#00d4ff]/20 font-mono text-xs text-[#e2e8f0] whitespace-pre-wrap break-all leading-relaxed">
                                      {finding.evidence}
                                    </div>
                                  </div>

                                  {/* PoC Payload */}
                                  {finding.pocPayload && (
                                    <div>
                                      <span className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest block mb-1 flex items-center gap-1.5">
                                        <Code2 className="w-3 h-3 text-[#00d4ff]" /> Proof of Concept (PoC)
                                      </span>
                                      <div className="p-3 rounded bg-[#040714] border border-[#00d4ff]/20 font-mono text-xs text-amber-400 break-all">
                                        {finding.pocPayload}
                                      </div>
                                    </div>
                                  )}

                                  {/* Business Impact */}
                                  <div>
                                    <span className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest block mb-1 flex items-center gap-1.5">
                                      <BookOpen className="w-3 h-3 text-[#00d4ff]" /> Business Impact
                                    </span>
                                    <p className="text-xs text-[#cbd5e1] leading-relaxed font-sans">
                                      {finding.severity === 'Critical' || finding.severity === 'High'
                                        ? 'This flaw allows an attacker to manipulate backend queries, bypass authentication, or infer sensitive database contents through conditional differential logic. Immediate remediation is required.'
                                        : 'This issue exposes structural or behavioral application logic that can be chained by an attacker. Remediate to enforce defense-in-depth.'}
                                    </p>
                                  </div>

                                  {/* Technical Details */}
                                  <div>
                                    <span className="text-[10px] font-mono font-bold text-[#a0aec0] uppercase tracking-widest block mb-1 flex items-center gap-1.5">
                                      <Eye className="w-3 h-3 text-[#00d4ff]" /> Technical Details
                                    </span>
                                    <p className="text-xs text-[#cbd5e1] leading-relaxed font-sans">{finding.description}</p>
                                  </div>

                                  {/* Remediation */}
                                  <div className="p-4 rounded-lg bg-[#00d4ff]/5 border border-[#00d4ff]/30">
                                    <span className="text-[10px] font-mono font-bold text-[#00d4ff] uppercase tracking-widest block mb-1 flex items-center gap-1.5">
                                      <Shield className="w-3 h-3" /> Remediation Guidance
                                    </span>
                                    <p className="text-xs text-[#e2e8f0] leading-relaxed font-sans">{finding.recommendation}</p>
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        );
                      })}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
