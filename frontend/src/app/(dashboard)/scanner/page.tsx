'use client';

import { useState, useRef, useEffect } from 'react';
import { api } from '@/lib/api';
import ParseTreeGraphic from '@/components/shared/ParseTreeGraphic';
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
  RotateCcw,
  Crosshair,
  Activity,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import { useScannerStore, ScanResult, Finding } from '@/store/scannerStore';

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

/** Parse structured evidence from JSON string */
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
  const { url, setUrl, authorized, setAuthorized, loading, result, error, setError, startScan, stopScan, resetScan, reset, scanState, liveLogs } = useScannerStore();

  const isScanning = scanState === 'running' || scanState === 'stopping';
  const isScanFinished = scanState === 'stopped' || scanState === 'completed';

  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [expandedFamily, setExpandedFamily] = useState<string | null>(null);
  const [filterFamily, setFilterFamily] = useState<string>('All');

  const getLogColorClass = (tool: string, level: string) => {
    if (level === 'error') return 'text-severity-critical';
    if (level === 'warn') return 'text-amber-400';
    if (['crawler', 'deepcrawl', 'surface_mapper'].includes(tool)) return 'text-emerald-400';
    if (['executor', 'sqlmap', 'nuclei', 'ffuf', 'payload_orchestrator'].includes(tool)) return 'text-severity-critical';
    if (['response_analyzer', 'orchestrator'].includes(tool)) return 'text-blue-400';
    return 'text-brand-primary';
  };

  /* Custom inline validation state */
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

    /* Custom validation — prevent native tooltip */
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

  const liveLogsEndRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    liveLogsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [liveLogs]);

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

  // ─── STATE 1: CONFIGURATION (EMPTY OR LOADING) ───
  if (!result) {
    return (
      <div className="max-w-[1600px] mx-auto pt-8 pb-24 text-text-primary font-sans flex flex-col xl:flex-row gap-8 items-start">
        
        {/* Left Column: Form */}
        <div className="w-full xl:w-5/12 space-y-8">
          <div className="space-y-4">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-surface-base border border-border-strong mb-2">
              <Scan className="w-6 h-6 text-brand-primary" />
            </div>
            <h1 className="text-3xl font-semibold tracking-tight text-text-primary">
              Active Assessment
            </h1>
            <p className="text-sm text-text-secondary leading-relaxed">
              Configure a target endpoint for deep inspection. Injection Lab will perform a structural analysis across 55+ known vulnerability patterns.
            </p>
          </div>

          <div className="cyber-card p-6 md:p-8 shadow-2xl">
            <form ref={formRef} onSubmit={handleScan} noValidate className="space-y-6">
              <div>
                <label htmlFor="target-url" className="block text-xs font-semibold text-text-secondary uppercase tracking-widest mb-3">
                  Target URL
                </label>
                <div className="relative group">
                  <input
                    id="target-url"
                    type="text"
                    placeholder="http://testfire.net/"
                    value={url}
                    onChange={(e) => handleUrlChange(e.target.value)}
                    onBlur={handleUrlBlur}
                    disabled={isScanning || loading}
                    className={`cyber-input font-mono w-full pl-12 pr-4 py-4 text-sm md:text-base text-text-primary placeholder:text-text-secondary/30 transition-all ${urlTouched && urlError ? 'border-severity-critical focus:border-severity-critical focus:ring-severity-critical/20' : 'focus:border-border-focus'} ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                  />
                  <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary group-focus-within:text-brand-primary transition-colors" />
                </div>
                {urlTouched && urlError && (
                  <div className="mt-2 flex items-center gap-2 text-xs font-medium text-severity-critical">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{urlError}</span>
                  </div>
                )}
              </div>

              <div className="flex flex-col gap-4 pt-4 border-t border-border-subtle">
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    id="authorized"
                    checked={authorized}
                    onChange={(e) => setAuthorized(e.target.checked)}
                    disabled={isScanning || loading}
                    className="mt-1 h-4 w-4 rounded border-border-strong bg-transparent text-brand-primary focus:ring-brand-primary/40 accent-[var(--color-brand-primary)] cursor-pointer"
                  />
                  <label htmlFor="authorized" className="text-xs text-text-secondary cursor-pointer select-none leading-relaxed">
                    I confirm authorization to inspect this target and understand that structural parameter analysis will be performed.
                  </label>
                </div>

                <div className="flex gap-2 w-full mt-4">
                  {/* START SCAN button - shown when idle or after scan finishes */}
                  {(scanState === 'idle' || isScanFinished) && (
                    <button
                      type="submit"
                      disabled={loading}
                      onClick={(e) => {
                        if (isScanFinished) {
                          // Reset before starting a new scan
                          e.preventDefault();
                          resetScan();
                          setUrlTouched(false);
                          setUrlError('');
                          setSaveSuccess(false);
                          // Let the form submit on next tick after reset
                          setTimeout(() => {
                            formRef.current?.requestSubmit();
                          }, 50);
                        }
                      }}
                      className="btn-cyber-primary py-3.5 text-sm font-semibold flex items-center justify-center gap-2 flex-1 shadow-lg disabled:opacity-50 transition-all"
                    >
                      <Shield className="w-4 h-4" />
                      Start Scan
                    </button>
                  )}
                  
                  {/* STOP SCAN button - shown when scan is running */}
                  {scanState === 'running' && (
                    <button
                      type="button"
                      onClick={() => stopScan()}
                      className="py-3.5 text-sm font-semibold flex items-center justify-center gap-2 flex-1 shadow-lg bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/50 rounded-md transition-all"
                    >
                      <XCircle className="w-4 h-4" /> Stop Scan
                    </button>
                  )}

                  {/* STOPPING indicator */}
                  {scanState === 'stopping' && (
                    <button
                      type="button"
                      disabled
                      className="py-3.5 text-sm font-semibold flex items-center justify-center gap-2 flex-1 shadow-lg bg-amber-500/10 text-amber-400/60 border border-amber-500/30 rounded-md cursor-not-allowed"
                    >
                      <Activity className="w-4 h-4 animate-pulse" /> Stopping...
                    </button>
                  )}
                </div>
              </div>
              
              {error && (
                <div className="p-3 bg-severity-critical/10 border border-severity-critical/20 text-severity-critical text-xs font-medium flex items-center gap-2">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  {error}
                </div>
              )}
            </form>
          </div>
        </div>

        {/* Right Column: Live Request Box */}
        <div className="w-full xl:w-7/12 cyber-card p-0 flex flex-col h-[600px] overflow-hidden bg-[#0A0A0E] border-border-strong">
          <div className="p-4 border-b border-border-strong flex items-center justify-between bg-surface-base">
            <h3 className="text-sm font-semibold flex items-center gap-2 text-text-primary uppercase tracking-widest">
              <Server className="w-4 h-4 text-brand-primary" /> Live Engine Logs
            </h3>
            {scanState === 'running' && (
              <div className="flex items-center gap-2 text-[10px] font-mono font-bold text-brand-primary tracking-widest uppercase">
                <div className="w-2 h-2 rounded-full bg-brand-primary animate-pulse" /> Streaming
              </div>
            )}
            {scanState === 'stopping' && (
              <div className="flex items-center gap-2 text-[10px] font-mono font-bold text-amber-400 tracking-widest uppercase">
                <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" /> Stopping
              </div>
            )}
            {scanState === 'stopped' && (
              <div className="flex items-center gap-2 text-[10px] font-mono font-bold text-red-400 tracking-widest uppercase">
                <div className="w-2 h-2 rounded-full bg-red-400" /> Stopped
              </div>
            )}
          </div>
          <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed">
            {liveLogs.length === 0 ? (
              <div className="text-text-secondary h-full flex flex-col items-center justify-center gap-4">
                <div className="w-12 h-12 rounded-full border border-border-strong flex items-center justify-center bg-surface-base">
                  <Code2 className="w-5 h-5 text-text-secondary" />
                </div>
                <p>Waiting for scan to initialize...</p>
              </div>
            ) : (
              <div className="space-y-2">
                {liveLogs.map((log, i) => (
                  <div key={i} className="flex gap-4 border-b border-border-subtle/30 pb-2 break-all">
                    <span className="text-text-secondary shrink-0 select-none">{log.timestamp}</span>
                    <span className={`shrink-0 uppercase w-12 font-bold select-none ${getLogColorClass(log.tool, log.level)}`}>
                      [{log.level}]
                    </span>
                    <span className="text-text-primary whitespace-pre-wrap">{log.message}</span>
                  </div>
                ))}
                <div ref={liveLogsEndRef} />
              </div>
            )}
          </div>
        </div>

      </div>
    );
  }

  // ─── STATE 2: RESULTS VIEW ───
  return (
    <div className="max-w-[1600px] mx-auto space-y-8 text-text-primary font-sans pb-16">
      
      {/* Condensed Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 section-divider">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-text-primary flex items-center gap-3">
            <Shield className="w-6 h-6 text-brand-primary" />
            Assessment Complete
          </h1>
          <p className="text-sm font-mono text-text-secondary mt-2">
            Target: <span className="text-text-primary">{result.targetUrl}</span>
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => {
              reset();
              setUrlTouched(false);
              setUrlError('');
            }}
            className="text-xs font-semibold text-text-secondary hover:text-text-primary transition-colors"
          >
            New Scan
          </button>
          <button
            onClick={handleSaveReport}
            disabled={saving || saveSuccess}
            className="btn-cyber-primary px-5 py-2.5 text-xs font-semibold flex items-center gap-2 disabled:opacity-50 shrink-0"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Saving…' : saveSuccess ? '✓ Saved' : 'Save Report'}
          </button>
        </div>
      </div>

      {saveSuccess && (
        <div className="p-4 bg-severity-low/10 text-severity-low border border-severity-low/20 text-sm font-medium flex items-center gap-2">
          <CheckCircle className="w-4 h-4 shrink-0" />
          Report successfully saved to Workspace.
        </div>
      )}

      {/* Primary Results Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-6 bg-surface-base border-l-4 border-l-severity-critical">
          <p className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest mb-2">Risk Score</p>
          <p className={`stat-hero text-4xl ${result.summary.riskScore >= 7 ? 'text-severity-critical' : result.summary.riskScore >= 4 ? 'text-severity-medium' : 'text-severity-low'}`}>
            {result.summary.riskScore} <span className="text-lg text-text-secondary font-sans">/ 10</span>
          </p>
        </div>
        <div className="p-6 bg-surface-hover">
          <p className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest mb-2">Unique Findings</p>
          <p className="stat-hero text-4xl text-text-primary">{result.summary.injectionPoints}</p>
        </div>
        <div className="p-6 bg-surface-hover">
          <p className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest mb-2">Parameters Analyzed</p>
          <p className="stat-hero text-4xl text-text-primary">{result.summary.parameters}</p>
        </div>
        <div className="p-6 bg-surface-hover">
          <p className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest mb-2">OWASP Coverage</p>
          <p className="stat-hero text-4xl text-text-primary">{result.summary.owaspCoverage.length}</p>
        </div>
      </div>

      {/* Tech stack */}
      {result.techStackClues.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 pt-4">
          <span className="text-xs text-text-secondary font-medium uppercase tracking-widest flex items-center gap-2">
            <Server className="w-3.5 h-3.5" /> Intelligence:
          </span>
          {result.techStackClues.map((t) => (
            <span key={t} className="px-2 py-1 bg-surface-hover border border-border-subtle text-[11px] font-mono text-text-secondary">{t}</span>
          ))}
        </div>
      )}

              {/* Family filter */}
              <div className="flex gap-2 flex-wrap">
                {families.map((fam) => (
                  <button
                    key={fam}
                    onClick={() => setFilterFamily(fam)}
                    className={`px-3.5 py-2 rounded-md text-xs font-medium border transition-all ${filterFamily === fam
                      ? 'bg-brand-primary/10 text-brand-primary border-brand-primary/20 '
                      : 'bg-transparent text-text-secondary border-border-subtle hover:bg-surface-base hover:text-text-primary'
                    }`}
                  >
                    {fam === 'All' ? `All (${result.findings.length})` : `${fam.split(' / ')[0]} (${result.summary.injectionFamilyCounts[fam] || 0})`}
                  </button>
                ))}
              </div>

              {/* Finding Groupings — grouped by family only */}
              <div className="space-y-6 mt-6">
                {Object.entries(groupedFindings).map(([family, familyFindings], familyIdx) => {
                  const isFamilyExpanded = expandedFamily === family || (expandedFamily === null && familyIdx === 0);
                  const familySeverity = getFamilySeverity(familyFindings);
                  const textColorClass = getSeverityTextColor(familySeverity);
                  
                  return (
                  <div key={family} className="cyber-card overflow-hidden !p-0">
                    <button
                      onClick={() => setExpandedFamily(isFamilyExpanded ? '' : family)}
                      className="w-full px-6 py-5 bg-surface-hover flex items-center justify-between transition-colors border-b border-border-strong"
                    >
                      <h3 className={`text-sm font-bold uppercase tracking-widest flex items-center gap-3 ${textColorClass}`}>
                        <FamilySeverityIcon severity={familySeverity} className="w-5 h-5" /> {family}
                      </h3>
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-semibold text-text-secondary bg-surface-base px-2 py-1 rounded-md border border-border-strong">{familyFindings.length} Finding{familyFindings.length !== 1 ? 's' : ''}</span>
                        {isFamilyExpanded ? <ChevronUp className="w-5 h-5 text-text-secondary" /> : <ChevronDown className="w-5 h-5 text-text-secondary" />}
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
                            const evidence = parseEvidence(finding.evidence);

                            return (
                              <div key={idx} className="cyber-card overflow-hidden">
                                <button
                                  onClick={() => setExpandedFinding(isExpanded ? null : globalId)}
                                  className="w-full px-5 py-4 flex items-center justify-between text-left hover:bg-bg-base/50 transition-colors gap-4"
                                  aria-expanded={isExpanded}
                                >
                                  <div className="space-y-1.5 min-w-0">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className={`severity-badge ${getSeverityBadgeClass(finding.severity)}`}>
                                        {finding.severity}
                                      </span>
                                      <span className={`text-[10px] font-mono px-2 py-0.5 border rounded ${getConfidenceBadgeClass(finding.confidence)}`}>
                                        {finding.confidence}
                                      </span>
                                      <span className="text-sm font-semibold text-text-primary">
                                        {finding.parameter ? `Param: ${finding.parameter}` : family}
                                      </span>
                                    </div>
                                    <p className="text-[11px] font-mono text-text-secondary truncate">{finding.location}</p>
                                  </div>
                                  {isExpanded ? <ChevronUp className="w-4 h-4 text-text-secondary shrink-0" /> : <ChevronDown className="w-4 h-4 text-text-secondary shrink-0" />}
                                </button>

                                <AnimatePresence>
                                  {isExpanded && (
                                    <motion.div 
                                      initial={{ opacity: 0, height: 0 }}
                                      animate={{ opacity: 1, height: 'auto' }}
                                      exit={{ opacity: 0, height: 0 }}
                                      className="px-5 pb-5 pt-4 border-t border-border-strong space-y-5 text-xs"
                                    >
                                      {/* Metadata badges */}
                                      <div className="flex flex-wrap gap-2">
                                        <span className="font-mono text-[10px] px-2.5 py-1 rounded-md inner-cell text-text-secondary">CVSS {finding.cvss}</span>
                                        <span className="font-mono text-[10px] px-2.5 py-1 rounded-md inner-cell text-text-secondary">{finding.cwe}</span>
                                        <span className="font-mono text-[10px] px-2.5 py-1 rounded-md inner-cell text-text-secondary">{finding.owasp}</span>
                                        {evidence?.http_method && (
                                          <span className="font-mono text-[10px] px-2.5 py-1 rounded-md inner-cell text-text-secondary">{evidence.http_method}</span>
                                        )}
                                        {evidence?.parameter_location && (
                                          <span className="font-mono text-[10px] px-2.5 py-1 rounded-md inner-cell text-text-secondary capitalize">{evidence.parameter_location}</span>
                                        )}
                                      </div>

                                      {/* Parameter & Location */}
                                      {finding.parameter && (
                                        <div>
                                          <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest block mb-2">
                                            <Crosshair className="w-3 h-3 inline mr-1" />
                                            Tested Parameter
                                          </span>
                                          <div className="inner-cell p-3 space-y-1">
                                            <p className="text-sm font-mono text-brand-primary break-all">
                                              {finding.parameter}
                                              {evidence?.parameter_location && (
                                                <span className="text-text-secondary ml-2 text-[10px] capitalize">({evidence.parameter_location})</span>
                                              )}
                                            </p>
                                          </div>
                                        </div>
                                      )}

                                      {/* Successful Payload / Tested Value */}
                                      {evidence?.tested_value && (
                                        <div>
                                          <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-1.5 mb-2">
                                            <Code2 className="w-3 h-3" /> Successful Test Payload
                                          </span>
                                          <div className="inner-cell p-3 font-mono text-[11px] text-text-primary break-all">
                                            {evidence.tested_value}
                                          </div>
                                        </div>
                                      )}

                                      {/* Evidence / Detection Signals */}
                                      {evidence?.reasons && evidence.reasons.length > 0 && (
                                        <div className="inner-cell p-4 font-mono">
                                          <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest block mb-2">
                                            <Eye className="w-3 h-3 inline mr-1" />
                                            Detection Evidence
                                          </span>
                                          <div className="space-y-1">
                                            {evidence.reasons.map((reason: string, ri: number) => (
                                              <p key={ri} className="text-text-primary text-[11px] leading-relaxed">
                                                • {reason.replace(/_/g, ' ')}
                                              </p>
                                            ))}
                                          </div>
                                          {evidence.status_code > 0 && (
                                            <p className="text-text-secondary text-[10px] mt-2">Response: HTTP {evidence.status_code} ({evidence.response_time}s)</p>
                                          )}
                                        </div>
                                      )}

                                      {/* Subtypes detected */}
                                      {evidence?.subtypes_detected && evidence.subtypes_detected.length > 1 && (
                                        <div>
                                          <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest block mb-2">
                                            Subtypes Confirmed
                                          </span>
                                          <div className="flex flex-wrap gap-1.5">
                                            {evidence.subtypes_detected.map((st: string, si: number) => (
                                              <span key={si} className="px-2 py-0.5 bg-surface-hover border border-border-subtle text-[10px] font-mono text-text-secondary rounded">
                                                {st}
                                              </span>
                                            ))}
                                          </div>
                                        </div>
                                      )}

                                      {/* Business impact */}
                                      <div>
                                        <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-1.5 mb-2">
                                          <BookOpen className="w-3 h-3" /> Business impact
                                        </span>
                                        <p className="text-text-primary leading-relaxed font-sans">
                                          {finding.severity === 'Critical' || finding.severity === 'High'
                                            ? 'This flaw could let an attacker compromise sensitive data, take over accounts, or access underlying systems. Immediate remediation is required.'
                                            : 'This issue could help an attacker gather system information or chain with other vulnerabilities. Address it to maintain defense in depth.'}
                                        </p>
                                      </div>

                                      {/* Technical details */}
                                      <div>
                                        <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-1.5 mb-2">
                                          <Eye className="w-3 h-3" /> Technical details
                                        </span>
                                        <p className="text-text-primary leading-relaxed font-sans">{finding.description}</p>
                                      </div>

                                      {/* Successful Tests summary (collapsed) */}
                                      {evidence?.successful_tests && evidence.successful_tests.length > 1 && (
                                        <details className="inner-cell p-3">
                                          <summary className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest cursor-pointer select-none">
                                            Additional Tests Performed ({evidence.successful_tests.length})
                                          </summary>
                                          <div className="mt-3 space-y-2">
                                            {evidence.successful_tests.map((test: any, ti: number) => (
                                              <div key={ti} className="text-[10px] font-mono text-text-secondary border-b border-border-subtle/30 pb-2">
                                                <span className="text-text-primary">{test.subtype}</span>
                                                <span className="mx-1">→</span>
                                                <span className="break-all">{test.payload?.substring(0, 150)}{test.payload?.length > 150 ? '…' : ''}</span>
                                                {test.status_code > 0 && <span className="ml-2 text-text-secondary">(HTTP {test.status_code})</span>}
                                              </div>
                                            ))}
                                          </div>
                                        </details>
                                      )}

                                      {/* PoC payload (fallback for passive findings) */}
                                      {!evidence?.tested_value && finding.pocPayload && (
                                        <div>
                                          <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-1.5 mb-2">
                                            <Code2 className="w-3 h-3" /> PoC payload
                                          </span>
                                          <div className="inner-cell p-3 font-mono text-[11px] text-text-primary break-all">
                                            {finding.pocPayload}
                                          </div>
                                        </div>
                                      )}

                                      {/* Remediation */}
                                      <div className="p-4 rounded-md bg-surface-base border border-border-strong">
                                        <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-1.5 mb-2">
                                          <Shield className="w-3 h-3" /> Remediation
                                        </span>
                                        <p className="text-text-primary leading-relaxed font-sans">{finding.recommendation}</p>
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
  );
}
