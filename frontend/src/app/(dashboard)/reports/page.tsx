'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { generatePDF, generateCSV } from '@/lib/reportGenerator';
import ParseTreeGraphic from '@/components/shared/ParseTreeGraphic';
import { 
  FileText, 
  Trash2, 
  Download, 
  ShieldCheck, 
  ArrowLeft,
  ChevronRight,
  Globe,
  Calendar,
  FileSpreadsheet,
  AlertTriangle,
  Activity,
  Clock,
  ShieldAlert,
  BookOpen,
  Eye,
  Code2,
  Shield,
  CheckCircle2,
  Maximize2,
  X,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Layers,
  Terminal
} from 'lucide-react';

interface Finding {
  type: string;
  injectionFamily: string;
  location: string;
  parameter?: string;
  paramValue?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  confidence?: string;
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  evidence?: string;
  pocPayload?: string;
  recommendation: string;
  simpleSummary?: string;
  simpleExplanation?: string;
  simpleFix?: string[];
  screenshot?: string;
  screenshotCaption?: string;
}

interface Report {
  _id: string;
  title: string;
  targetUrl: string;
  scanType: 'url' | 'demo';
  summary: {
    totalPages: number;
    injectionPoints: number;
    forms: number;
    headers: number;
    parameters: number;
    cookies: number;
    jsonInputs: number;
    riskScore: number;
    highestSeverity?: string;
    owaspCoverage: string[];
    overallRiskRating?: string;
    plainSummary?: string;
  };
  findings: Finding[];
  techStack: string[];
  createdAt: string;
}

function getRiskRatingInfo(rating?: string, score: number = 0, findings: Finding[] = []) {
  let effectiveRating = rating;
  if (!effectiveRating) {
    const hasCrit = findings.some(f => f.severity === 'Critical');
    const hasHigh = findings.some(f => f.severity === 'High');
    if (score >= 8.5 || hasCrit) effectiveRating = 'Critical';
    else if (score >= 6.0 || hasHigh) effectiveRating = 'High';
    else if (score >= 3.5) effectiveRating = 'Medium';
    else effectiveRating = 'Low';
  }

  switch (effectiveRating.toLowerCase()) {
    case 'critical':
      return {
        label: 'Critical Risk',
        badgeClass: 'bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.25)]',
        accentColor: '#ef4444',
        barColor: 'bg-red-500',
        desc: 'Immediate action required. Vulnerabilities present severe risk of unauthorized database access, code execution, or data theft.',
      };
    case 'high':
      return {
        label: 'High Risk',
        badgeClass: 'bg-orange-500/20 text-orange-400 border-orange-500/50 shadow-[0_0_15px_rgba(249,115,22,0.25)]',
        accentColor: '#f97316',
        barColor: 'bg-orange-500',
        desc: 'Significant security weak spots identified. Remediation should be scheduled in the current sprint to protect visitors and user data.',
      };
    case 'medium':
      return {
        label: 'Medium Risk',
        badgeClass: 'bg-amber-500/20 text-amber-400 border-amber-500/50 shadow-[0_0_15px_rgba(245,158,11,0.25)]',
        accentColor: '#f59e0b',
        barColor: 'bg-amber-500',
        desc: 'Moderate concerns identified that could be chained with other flaws. Schedule remediation in upcoming updates.',
      };
    case 'low':
    default:
      return {
        label: 'Low Risk',
        badgeClass: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.25)]',
        accentColor: '#10b981',
        barColor: 'bg-emerald-500',
        desc: 'Only minor or informational observations noted. Continue standard security monitoring and good hygiene.',
      };
  }
}

function getFallbackPlainDetails(f: Finding) {
  const type = (f.type || '').toLowerCase();
  const param = f.parameter || 'input parameter';

  if (type.includes('sql') || type.includes('injection')) {
    return {
      simpleSummary: `We found a weak spot in the "${param}" field that could let an attacker steal or tamper with stored database records.`,
      simpleExplanation: `What this means: The website sends user input directly into database queries without validating it. An attacker could enter special database symbols to trick the website into revealing confidential user records or passwords.`,
      simpleFix: [
        'Ask your developer to use "Prepared Statements" (parameterized queries) for all database calls.',
        `Ensure "${param}" only accepts expected characters (e.g. letters and numbers).`,
        'Never assemble SQL statements by concatenating user input strings.'
      ],
      caption: `Proof of concept showing how a test query triggered unauthorized database processing via "${param}".`
    };
  }

  if (type.includes('xss') || type.includes('cross-site')) {
    return {
      simpleSummary: `Malicious browser code can be entered through "${param}" to hijack visitor sessions or steal login cookies.`,
      simpleExplanation: `What this means: Data entered into "${param}" is reflected back into the web page without escaping. An attacker could craft a link containing hidden script code; when clicked, the code runs in the visitor's browser.`,
      simpleFix: [
        'Turn on HTML output encoding so symbols like "<" or ">" are displayed as safe text.',
        'Configure a Content Security Policy (CSP) header to restrict script execution.',
        'Mark authentication cookies as "HttpOnly" so scripts cannot access them.'
      ],
      caption: `Proof of concept showing test code reflecting in the browser from "${param}".`
    };
  }

  return {
    simpleSummary: `Input entered into "${param}" is not verified thoroughly, which could expose internal website behavior.`,
    simpleExplanation: `What this means: The website accepts unexpected characters in "${param}". An attacker could exploit this discrepancy to bypass validation filters or chain with other vulnerabilities.`,
    simpleFix: [
      `Validate that "${param}" matches strictly expected formats and lengths.`,
      'Apply context-appropriate output sanitization before displaying this value.',
      'Ensure software libraries and framework components are updated to their latest security patches.'
    ],
    caption: `Proof of concept showing anomalous application response for parameter "${param}".`
  };
}

function ReportsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const reportId = searchParams.get('id');

  const [reports, setReports] = useState<Report[]>([]);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [exportingPDF, setExportingPDF] = useState(false);
  const [exportingCSV, setExportingCSV] = useState(false);

  // UI States
  const [zoomScreenshot, setZoomScreenshot] = useState<{ src: string; title: string; caption?: string } | null>(null);
  const [openTechDetails, setOpenTechDetails] = useState<Record<string, boolean>>({});
  const [showAppendix, setShowAppendix] = useState(false);

  useEffect(() => {
    fetchReports();
  }, []);

  useEffect(() => {
    if (reportId) {
      fetchReportDetail(reportId);
    } else {
      setSelectedReport(null);
    }
  }, [reportId]);

  const fetchReports = async () => {
    try {
      const res = await api.get('/reports?view=reports');
      setReports(res.data.reports || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const fetchReportDetail = async (id: string) => {
    setLoadingDetail(true);
    try {
      const res = await api.get(`/reports/${id}`);
      setSelectedReport(res.data.report);
    } catch (err) {
      console.error(err);
      router.push('/reports');
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this report?')) return;
    try {
      await api.delete(`/reports/${id}?view=reports`);
      fetchReports();
      if (selectedReport?._id === id) {
        router.push('/reports');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const exportCSV = () => {
    if (!selectedReport) return;
    setExportingCSV(true);
    try {
      generateCSV(selectedReport as any);
    } catch (err) {
      console.error('CSV Export Error:', err);
      alert('Failed to generate CSV file.');
    } finally {
      setExportingCSV(false);
    }
  };

  const exportPDF = async () => {
    if (!selectedReport) return;
    setExportingPDF(true);
    try {
      generatePDF(selectedReport as any);
    } catch (err) {
      console.error('PDF Export Error:', err);
      alert('Failed to export PDF report.');
    } finally {
      setExportingPDF(false);
    }
  };

  const toggleTechDetails = (idx: string) => {
    setOpenTechDetails(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

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

  const getConfidenceBadgeClass = (confidence?: string) => {
    switch (confidence) {
      case 'Confirmed': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'Likely': return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      case 'Possible': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      default: return 'bg-surface-base border-border-strong text-text-secondary';
    }
  };

  const riskInfo = selectedReport ? getRiskRatingInfo(
    selectedReport.summary?.overallRiskRating,
    selectedReport.summary?.riskScore,
    selectedReport.findings
  ) : null;

  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-16 max-w-[1500px] mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-border-strong pb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-text-primary flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-brand-primary" />
            Security Audit Reports
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Easy-to-understand vulnerability summaries with developer technical details and verified proof-of-concept evidence.
          </p>
        </div>

        {selectedReport && (
          <button
            onClick={() => router.push('/reports')}
            className="btn-cyber-secondary px-4 py-2 text-xs font-medium flex items-center gap-2 self-start sm:self-auto"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to reports
          </button>
        )}
      </div>

      {/* Detail View Mode */}
      {selectedReport ? (
        <div className="space-y-6">
          {/* Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-4 cyber-card p-5">
            <div className="flex items-center gap-2.5 text-sm text-text-primary font-medium">
              <ShieldCheck className="w-4 h-4 text-brand-primary" />
              <span>Assessment results finalized and decrypted</span>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={exportCSV}
                disabled={exportingCSV}
                className="btn-cyber-secondary px-4 py-2 text-xs font-medium flex items-center gap-2 disabled:opacity-50"
              >
                <FileSpreadsheet className="w-3.5 h-3.5" />
                {exportingCSV ? 'Generating CSV…' : 'Export CSV'}
              </button>
              <button
                onClick={exportPDF}
                disabled={exportingPDF}
                className="btn-cyber-primary px-4 py-2 text-xs font-medium flex items-center gap-2 disabled:opacity-50"
              >
                <Download className="w-3.5 h-3.5" />
                {exportingPDF ? 'Generating PDF…' : 'Download PDF report'}
              </button>
            </div>
          </div>

          {loadingDetail ? (
            <div className="cyber-card p-12 flex flex-col items-center justify-center min-h-[300px]">
              <div className="w-8 h-8 border-2 border-brand-primary border-t-transparent rounded-full animate-spin mb-4" />
              <p className="text-sm font-medium text-text-primary">Retrieving assessment data…</p>
            </div>
          ) : (
            <div className="space-y-8">
              
              {/* ────────────────────────────────────────────────────────── */}
              {/* 1. PLAIN-LANGUAGE EXECUTIVE SUMMARY & RISK BADGE (TOP)    */}
              {/* ────────────────────────────────────────────────────────── */}
              <div className="rounded-2xl bg-gradient-to-br from-[#0c1228] via-[#090d1f] to-[#050814] border border-[#00d4ff]/30 p-6 md:p-8 shadow-[0_10px_35px_rgba(0,0,0,0.5)] space-y-6">
                
                {/* Header Row: Title + Risk Badge */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-white/10">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-[#00d4ff]" />
                      <span className="text-[11px] font-mono uppercase tracking-widest text-[#00d4ff] font-bold">
                        Executive Plain-Language Overview
                      </span>
                    </div>
                    <h2 className="text-2xl font-bold text-white tracking-tight">
                      {selectedReport.title}
                    </h2>
                    <p className="text-sm text-slate-300 flex items-center gap-2">
                      <Globe className="w-4 h-4 text-[#00d4ff]" /> Target Website: 
                      <span className="font-mono text-[#00d4ff] font-medium">{selectedReport.targetUrl}</span>
                    </p>
                  </div>

                  {/* Overall Risk Score Badge */}
                  {riskInfo && (
                    <div className="flex items-center gap-4 bg-black/40 border border-white/10 rounded-2xl p-4 lg:p-5">
                      <div className="text-right">
                        <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 block font-bold">
                          Overall Risk Rating
                        </span>
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-extrabold uppercase tracking-wider border mt-1 ${riskInfo.badgeClass}`}>
                          <span className="w-2 h-2 rounded-full animate-ping" style={{ backgroundColor: riskInfo.accentColor }} />
                          {riskInfo.label}
                        </span>
                      </div>
                      <div className="h-12 w-px bg-white/10" />
                      <div className="text-center">
                        <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 block font-bold">
                          Risk Score
                        </span>
                        <span className="text-3xl font-extrabold font-mono text-white">
                          {selectedReport.summary.riskScore.toFixed(1)}
                          <span className="text-xs text-slate-400 font-normal"> / 10</span>
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Plain-Language Narrative Summary */}
                <div className="rounded-xl bg-white/[0.03] border border-white/10 p-5 md:p-6 space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-white">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    <span>What You Need to Know (In Simple Terms)</span>
                  </div>
                  <p className="text-sm text-slate-200 leading-relaxed font-sans">
                    {selectedReport.summary?.plainSummary || (
                      `We completed an automated security review of ${selectedReport.targetUrl} and detected ${selectedReport.findings.length} security weak spot(s). If exploited, an attacker could attempt to manipulate input parameters, steal session tokens, or access backend records. Review the action checklist below and share these findings with your development team to reinforce your defenses.`
                    )}
                  </p>
                </div>

                {/* Quick Glance Metrics */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                    <span className="text-[10px] font-mono uppercase text-slate-400 block">Total Weak Spots</span>
                    <span className="text-2xl font-bold font-mono text-white mt-1 block">
                      {selectedReport.findings.length}
                    </span>
                  </div>
                  <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                    <span className="text-[10px] font-mono uppercase text-red-400 block">Critical Findings</span>
                    <span className="text-2xl font-bold font-mono text-red-400 mt-1 block">
                      {selectedReport.findings.filter(f => f.severity === 'Critical').length}
                    </span>
                  </div>
                  <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                    <span className="text-[10px] font-mono uppercase text-orange-400 block">High Priority</span>
                    <span className="text-2xl font-bold font-mono text-orange-400 mt-1 block">
                      {selectedReport.findings.filter(f => f.severity === 'High').length}
                    </span>
                  </div>
                  <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                    <span className="text-[10px] font-mono uppercase text-[#00d4ff] block">Tested Inputs</span>
                    <span className="text-2xl font-bold font-mono text-[#00d4ff] mt-1 block">
                      {selectedReport.summary.parameters || selectedReport.summary.injectionPoints || selectedReport.findings.length}
                    </span>
                  </div>
                </div>

              </div>

              {/* ────────────────────────────────────────────────────────── */}
              {/* 2. FINDINGS LIST (DUAL EXPLANATION + SCREENSHOT + FIX)     */}
              {/* ────────────────────────────────────────────────────────── */}
              <div className="space-y-6">
                <div className="flex items-center justify-between border-b border-border-strong pb-3">
                  <div className="flex items-center gap-2.5">
                    <AlertTriangle className="w-5 h-5 text-brand-primary" />
                    <h3 className="text-base font-bold text-text-primary uppercase tracking-wider font-mono">
                      Identified Findings & Remediation ({selectedReport.findings.length})
                    </h3>
                  </div>
                  <span className="text-xs text-text-secondary font-mono">
                    Dual Non-Technical & Technical Breakdown
                  </span>
                </div>

                {selectedReport.findings.length === 0 ? (
                  <div className="cyber-card p-8 text-center text-text-secondary">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                    <p className="text-sm font-semibold text-text-primary">No vulnerabilities detected</p>
                    <p className="text-xs mt-1">The tested parameters did not exhibit signs of injection weaknesses.</p>
                  </div>
                ) : (
                  selectedReport.findings.map((f, idx) => {
                    const fallback = getFallbackPlainDetails(f);
                    const simpleSummary = f.simpleSummary || fallback.simpleSummary;
                    const simpleExplanation = f.simpleExplanation || fallback.simpleExplanation;
                    const simpleFixes = f.simpleFix && f.simpleFix.length > 0 ? f.simpleFix : fallback.simpleFix;
                    const caption = f.screenshotCaption || fallback.caption;
                    const cardKey = `f-${idx}`;
                    const isTechOpen = openTechDetails[cardKey] ?? false;

                    return (
                      <div 
                        key={cardKey} 
                        className="cyber-card p-6 md:p-7 border border-white/10 hover:border-[#00d4ff]/40 transition-all rounded-2xl space-y-6 bg-[#070b1a]"
                      >
                        {/* Finding Header */}
                        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-white/10">
                          <div className="flex items-center gap-3 flex-wrap">
                            <span className={`severity-badge ${getSeverityBadgeClass(f.severity)} text-xs font-mono font-bold uppercase px-3 py-1`}>
                              {f.severity}
                            </span>
                            {f.confidence && (
                              <span className={`text-[10px] font-mono px-2 py-0.5 border rounded ${getConfidenceBadgeClass(f.confidence)}`}>
                                {f.confidence}
                              </span>
                            )}
                            <h4 className="text-base font-bold text-white tracking-tight">
                              {f.type} {f.parameter ? `in "${f.parameter}"` : ''}
                            </h4>
                          </div>

                          <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                            {f.cwe && (
                              <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10">
                                {f.cwe}
                              </span>
                            )}
                            {f.owasp && (
                              <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10">
                                {f.owasp}
                              </span>
                            )}
                            <span className="font-bold text-white bg-white/10 px-2 py-0.5 rounded">
                              CVSS: {f.cvss || 7.5}
                            </span>
                          </div>
                        </div>

                        {/* ── PART A: IN SIMPLE TERMS (NON-TECHNICAL AUDIENCE) ── */}
                        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                          
                          {/* Non-Technical Summary & What It Means (7 cols) */}
                          <div className="lg:col-span-7 space-y-4">
                            
                            <div className="p-5 rounded-xl bg-gradient-to-br from-[#0e172e] to-[#090d1f] border border-[#00d4ff]/25 space-y-3">
                              <div className="flex items-center gap-2 text-xs font-bold text-[#00d4ff] uppercase tracking-wider font-mono">
                                <BookOpen className="w-4 h-4" /> In Simple Terms
                              </div>
                              <p className="text-sm font-semibold text-white leading-relaxed">
                                {simpleSummary}
                              </p>
                              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                                {simpleExplanation}
                              </p>
                            </div>

                            {/* Plain Action Checklist: How to Fix This */}
                            <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
                              <div className="flex items-center gap-2 text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">
                                <CheckCircle2 className="w-4 h-4" /> How to Fix This (Action Checklist)
                              </div>
                              <ul className="space-y-2">
                                {simpleFixes.map((step, sIdx) => (
                                  <li key={sIdx} className="flex items-start gap-2.5 text-xs text-slate-200">
                                    <span className="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                                      {sIdx + 1}
                                    </span>
                                    <span>{step}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>

                          </div>

                          {/* ── PART B: PROOF-OF-CONCEPT SCREENSHOT (5 cols) ── */}
                          <div className="lg:col-span-5 flex flex-col">
                            <div className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center justify-between">
                              <span className="flex items-center gap-1.5">
                                <Eye className="w-3.5 h-3.5 text-[#00d4ff]" /> Proof of Concept Evidence
                              </span>
                              {f.screenshot && (
                                <button
                                  onClick={() => setZoomScreenshot({ src: f.screenshot!, title: `${f.type} - Proof of Concept`, caption })}
                                  className="text-[10px] text-[#00d4ff] hover:underline flex items-center gap-1"
                                >
                                  <Maximize2 className="w-3 h-3" /> Zoom
                                </button>
                              )}
                            </div>

                            {f.screenshot ? (
                              <div className="rounded-xl overflow-hidden border border-white/15 bg-black/60 shadow-lg flex-1 flex flex-col">
                                {/* Chrome Bar */}
                                <div className="bg-[#0b0f1e] px-3 py-2 border-b border-white/10 flex items-center gap-2">
                                  <div className="flex gap-1.5">
                                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                                    <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                                  </div>
                                  <span className="text-[10px] font-mono text-slate-400 truncate ml-2">
                                    {selectedReport.targetUrl}
                                  </span>
                                </div>

                                {/* Thumbnail Image (Click to Zoom) */}
                                <div 
                                  className="relative group cursor-pointer overflow-hidden bg-[#04060f] flex items-center justify-center p-2"
                                  onClick={() => setZoomScreenshot({ src: f.screenshot!, title: `${f.type} - Proof of Concept`, caption })}
                                >
                                  <img 
                                    src={f.screenshot} 
                                    alt={caption} 
                                    className="w-full h-auto object-contain max-h-[190px] rounded group-hover:scale-[1.02] transition-transform duration-300"
                                  />
                                  <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                    <span className="px-3 py-1.5 rounded-lg bg-black/80 border border-white/20 text-white text-xs font-mono flex items-center gap-1.5 shadow-xl">
                                      <Maximize2 className="w-3.5 h-3.5 text-[#00d4ff]" /> Click to Inspect
                                    </span>
                                  </div>
                                </div>

                                {/* Plain-Language Caption */}
                                <div className="p-3 bg-[#080c1d] border-t border-white/10 text-[11px] text-slate-300 leading-relaxed font-sans">
                                  <span className="font-bold text-[#00d4ff] font-mono">Proof: </span>
                                  {caption}
                                </div>
                              </div>
                            ) : (
                              <div className="p-6 rounded-xl border border-dashed border-white/15 bg-black/30 text-center flex-1 flex flex-col items-center justify-center space-y-2">
                                <Terminal className="w-8 h-8 text-slate-500" />
                                <span className="text-xs text-slate-400 font-mono">Automated payload response logged</span>
                                <span className="text-[11px] text-slate-500 font-sans">{caption}</span>
                              </div>
                            )}
                          </div>

                        </div>

                        {/* ── PART C: COLLAPSIBLE TECHNICAL DETAILS (FOR DEVELOPERS) ── */}
                        <div className="border-t border-white/10 pt-4">
                          <button
                            type="button"
                            onClick={() => toggleTechDetails(cardKey)}
                            className="flex items-center justify-between w-full py-2 text-xs font-mono font-bold text-slate-400 hover:text-white transition-colors"
                          >
                            <span className="flex items-center gap-2">
                              <Code2 className="w-4 h-4 text-[#00d4ff]" />
                              Technical Details for Developers (Payloads, Endpoints & Raw Evidence)
                            </span>
                            {isTechOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>

                          {isTechOpen && (
                            <div className="mt-4 p-5 rounded-xl bg-black/50 border border-white/10 space-y-4 font-mono text-xs animate-in fade-in duration-200">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                  <span className="text-[10px] text-slate-400 uppercase block mb-1">Target Endpoint</span>
                                  <p className="p-2.5 rounded bg-[#04060f] border border-white/10 text-white break-all">{f.location}</p>
                                </div>
                                {f.parameter && (
                                  <div>
                                    <span className="text-[10px] text-slate-400 uppercase block mb-1">Affected Parameter</span>
                                    <p className="p-2.5 rounded bg-[#04060f] border border-white/10 text-[#00d4ff] break-all">{f.parameter}{f.paramValue ? ` = ${f.paramValue}` : ''}</p>
                                  </div>
                                )}
                              </div>

                              {f.pocPayload && (
                                <div>
                                  <span className="text-[10px] text-amber-400 uppercase block mb-1">Injected Test Vector (Payload)</span>
                                  <pre className="p-3 rounded bg-[#04060f] border border-amber-500/20 text-amber-300 whitespace-pre-wrap break-all">{f.pocPayload}</pre>
                                </div>
                              )}

                              {f.evidence && (
                                <div>
                                  <span className="text-[10px] text-slate-400 uppercase block mb-1">Detection Signals / Evidence</span>
                                  <pre className="p-3 rounded bg-[#04060f] border border-white/10 text-slate-300 whitespace-pre-wrap break-all max-h-[160px] overflow-y-auto">{f.evidence}</pre>
                                </div>
                              )}

                              {f.description && (
                                <div>
                                  <span className="text-[10px] text-slate-400 uppercase block mb-1">Vulnerability Mechanics</span>
                                  <p className="text-slate-300 font-sans leading-relaxed">{f.description}</p>
                                </div>
                              )}

                              {f.recommendation && (
                                <div className="p-3.5 rounded bg-brand-primary/5 border border-brand-primary/20">
                                  <span className="text-[10px] text-brand-primary uppercase block mb-1 font-bold">Standard Engineering Remediation</span>
                                  <p className="text-slate-200 font-sans leading-relaxed">{f.recommendation}</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>

                      </div>
                    );
                  })
                )}
              </div>

              {/* ────────────────────────────────────────────────────────── */}
              {/* 3. COLLAPSIBLE FULL TECHNICAL APPENDIX                    */}
              {/* ────────────────────────────────────────────────────────── */}
              <div className="cyber-card p-6 rounded-2xl border border-white/10 bg-[#060918]">
                <button
                  type="button"
                  onClick={() => setShowAppendix(!showAppendix)}
                  className="flex items-center justify-between w-full text-left"
                >
                  <div className="flex items-center gap-3">
                    <Layers className="w-5 h-5 text-brand-primary" />
                    <div>
                      <h4 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                        Full Technical Appendix & Host Matrix
                      </h4>
                      <p className="text-xs text-text-secondary mt-0.5">
                        Raw parameters, OWASP Top 10 coverage matrix, detected technologies, and scope metadata.
                      </p>
                    </div>
                  </div>
                  {showAppendix ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>

                {showAppendix && (
                  <div className="mt-6 pt-6 border-t border-white/10 space-y-6 font-mono text-xs">
                    
                    {/* Matrix Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="inner-cell p-4">
                        <span className="text-[10px] text-text-secondary uppercase">Pages Inspected</span>
                        <p className="text-lg font-bold text-white mt-1">{selectedReport.summary.totalPages || 1}</p>
                      </div>
                      <div className="inner-cell p-4">
                        <span className="text-[10px] text-text-secondary uppercase">Forms Identified</span>
                        <p className="text-lg font-bold text-white mt-1">{selectedReport.summary.forms || 0}</p>
                      </div>
                      <div className="inner-cell p-4">
                        <span className="text-[10px] text-text-secondary uppercase">HTTP Headers Inspected</span>
                        <p className="text-lg font-bold text-white mt-1">{selectedReport.summary.headers || 0}</p>
                      </div>
                      <div className="inner-cell p-4">
                        <span className="text-[10px] text-text-secondary uppercase">OWASP Categories</span>
                        <p className="text-lg font-bold text-white mt-1">{selectedReport.summary.owaspCoverage.length}</p>
                      </div>
                    </div>

                    {/* OWASP Coverage Badges */}
                    {selectedReport.summary.owaspCoverage.length > 0 && (
                      <div>
                        <span className="text-[10px] text-text-secondary uppercase block mb-2 font-bold">
                          Covered OWASP Categories
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {selectedReport.summary.owaspCoverage.map((cat, i) => (
                            <span key={i} className="px-2.5 py-1 rounded bg-white/5 border border-white/10 text-text-primary text-[11px]">
                              {cat}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Detected Tech Stack */}
                    {selectedReport.techStack && selectedReport.techStack.length > 0 && (
                      <div>
                        <span className="text-[10px] text-text-secondary uppercase block mb-2 font-bold">
                          Identified Host & Application Components
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {selectedReport.techStack.map((tech, i) => (
                            <span key={i} className="px-2.5 py-1 rounded bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] text-[11px]">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Scope & Authorization Note */}
                    <div className="p-4 rounded bg-white/[0.02] border border-white/5 text-[11px] text-slate-400 font-sans leading-relaxed">
                      <strong className="text-white font-mono">Scope & Methodology: </strong> 
                      This report details automated structural injection tests performed under verified operator consent. Fuzzing was conducted against user input points using harmless heuristic payloads designed to test input sanitization and response differentials without service disruption.
                    </div>

                  </div>
                )}
              </div>

            </div>
          )}
        </div>
      ) : (
        /* History Archive List Mode */
        <div className="space-y-4">
          {loading ? (
            <div className="cyber-card empty-state">
              <div className="w-8 h-8 border-2 border-brand-primary border-t-transparent rounded-full animate-spin mb-4" />
              <p className="empty-state-title">Loading history…</p>
            </div>
          ) : reports.length === 0 ? (
            <div className="cyber-card empty-state">
              <div className="empty-state-icon">
                <ParseTreeGraphic active={false} scale={1.2} />
              </div>
              <p className="empty-state-title">No saved reports</p>
              <p className="empty-state-desc">Run a scan to generate your first security assessment report.</p>
              <button onClick={() => router.push('/scanner')} className="btn-cyber-primary px-5 py-2.5 text-xs font-semibold mt-2">
                Run scan
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {reports.map((report) => {
                const reportRisk = getRiskRatingInfo(
                  report.summary?.overallRiskRating,
                  report.summary?.riskScore
                );
                return (
                  <div
                    key={report._id}
                    onClick={() => router.push(`/reports?id=${report._id}`)}
                    className="cyber-card p-6 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group hover:border-[#00d4ff]/50 transition-all"
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <h3 className="text-sm font-semibold text-text-primary group-hover:text-brand-primary transition-colors">
                          {report.title}
                        </h3>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold uppercase ${reportRisk.badgeClass}`}>
                          {reportRisk.label}
                        </span>
                        <span className="text-[9px] font-mono px-2 py-0.5 rounded-md inner-cell text-text-secondary capitalize">
                          {report.scanType}
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-text-secondary">{report.targetUrl}</p>
                      <p className="text-[10px] font-medium text-text-secondary flex items-center gap-1.5">
                        <Clock className="w-3 h-3" /> {new Date(report.createdAt).toLocaleString()}
                      </p>
                    </div>

                    <div className="flex items-center gap-6 text-xs">
                      <div>
                        <span className="text-[10px] text-text-secondary block uppercase font-medium mb-0.5">Findings</span>
                        <span className="font-mono font-semibold text-text-primary">{report.summary.injectionPoints}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-text-secondary block uppercase font-medium mb-0.5">Score</span>
                        <span className={`font-mono font-bold ${report.summary.riskScore >= 7 ? 'text-severity-critical' : report.summary.riskScore >= 4 ? 'text-severity-medium' : 'text-severity-low'}`}>
                          {report.summary.riskScore.toFixed(1)}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 pl-4 border-l border-border-strong">
                        <button
                          onClick={(e) => handleDelete(report._id, e)}
                          className="p-2 rounded-md text-text-secondary hover:text-severity-critical hover:bg-severity-critical/10 transition-colors"
                          aria-label="Delete report"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                        <ChevronRight className="w-4 h-4 text-text-secondary group-hover:text-brand-primary transition-colors" />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ────────────────────────────────────────────────────────── */}
      {/* 4. LIGHTBOX MODAL FOR SCREENSHOT ZOOM                     */}
      {/* ────────────────────────────────────────────────────────── */}
      {zoomScreenshot && (
        <div 
          className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md flex items-center justify-center p-4 sm:p-6 animate-in fade-in duration-200"
          onClick={() => setZoomScreenshot(null)}
        >
          <div 
            className="relative max-w-5xl w-full bg-[#0b0f1e] border border-white/20 rounded-2xl overflow-hidden shadow-2xl space-y-4 p-6"
            onClick={e => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2">
                <Eye className="w-5 h-5 text-[#00d4ff]" />
                <h3 className="text-base font-bold text-white font-mono">{zoomScreenshot.title}</h3>
              </div>
              <button
                onClick={() => setZoomScreenshot(null)}
                className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Image View */}
            <div className="bg-[#04060f] rounded-xl p-2 flex items-center justify-center border border-white/10 max-h-[70vh] overflow-auto">
              <img 
                src={zoomScreenshot.src} 
                alt={zoomScreenshot.title} 
                className="max-w-full h-auto object-contain rounded-lg"
              />
            </div>

            {/* Modal Caption */}
            {zoomScreenshot.caption && (
              <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/10 text-xs text-slate-300 font-sans leading-relaxed">
                <strong className="text-[#00d4ff] font-mono">Verified Evidence: </strong>
                {zoomScreenshot.caption}
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}

export default function ReportsPage() {
  return (
    <Suspense fallback={
      <div className="cyber-card empty-state">
        <div className="w-8 h-8 border-2 border-brand-primary border-t-transparent rounded-full animate-spin mb-4" />
        <p className="empty-state-title">Loading reports…</p>
      </div>
    }>
      <ReportsContent />
    </Suspense>
  );
}
