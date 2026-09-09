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
  Shield
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
  };
  findings: Finding[];
  techStack: string[];
  createdAt: string;
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

  const groupedFindings = selectedReport?.findings.reduce((acc, f) => {
    const family = f.injectionFamily || 'Unknown';
    const subtype = f.type.includes(' - ') ? f.type.split(' - ')[1].trim() : f.type;
    if (!acc[family]) acc[family] = {};
    if (!acc[family][subtype]) acc[family][subtype] = [];
    acc[family][subtype].push(f);
    return acc;
  }, {} as Record<string, Record<string, Finding[]>>) || {};

  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-border-strong pb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-text-primary">
            Audit reports
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Historical security assessments and finding details
          </p>
        </div>

        {selectedReport && (
          <button
            onClick={() => router.push('/reports')}
            className="btn-cyber-secondary px-4 py-2 text-xs font-medium flex items-center gap-2 self-start sm:self-auto"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to list
          </button>
        )}
      </div>

      {/* Detail View Mode */}
      {selectedReport ? (
        <div className="space-y-5">
          {/* Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-4 cyber-card p-5">
            <div className="flex items-center gap-2.5 text-sm text-text-primary font-medium">
              <ShieldCheck className="w-4 h-4 text-brand-primary" />
              <span>Assessment results ready for export</span>
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
            <div className="cyber-card p-6 md:p-8 space-y-8">
              {/* Report Header */}
              <div className="border-b border-border-strong pb-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldAlert className="w-4 h-4 text-brand-primary" />
                    <span className="text-[10px] font-semibold text-brand-primary uppercase tracking-widest">Injection Lab Assessment</span>
                  </div>
                  <h3 className="text-xl font-semibold text-text-primary mt-1">{selectedReport.title}</h3>
                  <p className="text-sm text-text-secondary mt-1 flex items-center gap-2">
                    <Globe className="w-3.5 h-3.5 text-text-secondary" /> Target: <span className="text-text-primary font-mono">{selectedReport.targetUrl}</span>
                  </p>
                </div>
                <div className="text-left md:text-right text-sm text-text-secondary space-y-1.5">
                  <p className="px-2 py-1 rounded bg-surface-base border border-border-subtle font-mono font-medium text-text-primary inline-block text-[11px]">
                    ID: #{selectedReport._id.slice(-8).toUpperCase()}
                  </p>
                  <p className="flex items-center gap-1.5 md:justify-end text-xs">
                    <Calendar className="w-3.5 h-3.5" /> {new Date(selectedReport.createdAt).toLocaleString()}
                  </p>
                </div>
              </div>

              {/* 1. Executive Summary & Host Matrix */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-text-primary uppercase tracking-widest flex items-center gap-2 border-b border-border-strong pb-3">
                  <Activity className="w-3.5 h-3.5 text-text-secondary" /> 1. Executive summary
                </h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="inner-cell p-4">
                    <p className="text-[10px] font-medium text-text-secondary uppercase tracking-wider">Risk index</p>
                    <p className={`stat-hero text-2xl mt-2 ${selectedReport.summary.riskScore >= 7 ? 'text-severity-critical' : selectedReport.summary.riskScore >= 4 ? 'text-severity-medium' : 'text-severity-low'}`}>
                      {selectedReport.summary.riskScore} <span className="text-xs text-text-secondary font-normal font-sans">/ 10.0</span>
                    </p>
                  </div>
                  <div className="inner-cell p-4">
                    <p className="text-[10px] font-medium text-text-secondary uppercase tracking-wider">Vulnerabilities</p>
                    <p className="stat-hero text-2xl text-text-primary mt-2">{selectedReport.findings.length}</p>
                  </div>
                  <div className="inner-cell p-4">
                    <p className="text-[10px] font-medium text-text-secondary uppercase tracking-wider">Parameters tested</p>
                    <p className="stat-hero text-2xl text-text-primary mt-2">{selectedReport.summary.parameters}</p>
                  </div>
                  <div className="inner-cell p-4">
                    <p className="text-[10px] font-medium text-text-secondary uppercase tracking-wider">OWASP coverage</p>
                    <p className="stat-hero text-2xl text-text-primary mt-2">{selectedReport.summary.owaspCoverage.length}</p>
                  </div>
                </div>
              </div>

              {/* 2. Detailed Vulnerabilities Section */}
              <div className="space-y-8 pt-4">
                <h4 className="text-xs font-semibold tracking-widest text-text-primary uppercase flex items-center gap-2 border-b border-border-strong pb-3">
                  <AlertTriangle className="w-3.5 h-3.5 text-text-secondary" /> 2. Detailed findings ({selectedReport.findings.length})
                </h4>

                {Object.entries(groupedFindings).map(([family, subtypes]) => (
                  <div key={family} className="space-y-4">
                    <h3 className="text-sm font-bold text-brand-primary uppercase tracking-widest border-b border-border-strong pb-2 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4" /> {family}
                    </h3>
                    
                    {Object.entries(subtypes).map(([subtype, groupFindings], subtypeIdx) => (
                      <div key={subtype} className="space-y-3 pl-0 md:pl-4 md:border-l-2 border-border-strong">
                        <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-widest pt-2">
                          {subtypeIdx + 1}. {subtype} ({groupFindings.length})
                        </h4>
                        
                        <div className="space-y-3">
                          {groupFindings.map((f, i) => (
                            <div key={i} className="cyber-card p-6 space-y-4">
                              {/* Vulnerability Header */}
                              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-border-strong pb-4">
                                <div className="flex items-center gap-2.5 flex-wrap">
                                  <span className={`severity-badge ${getSeverityBadgeClass(f.severity)}`}>
                                    {f.severity}
                                  </span>
                                  {f.confidence && (
                                    <span className={`text-[10px] font-mono px-2 py-0.5 border rounded ${getConfidenceBadgeClass(f.confidence)}`}>
                                      {f.confidence}
                                    </span>
                                  )}
                                  <span className="text-sm font-semibold text-text-primary">{f.parameter ? `Param: ${f.parameter}` : subtype}</span>
                                  <span className="text-[9px] px-1.5 py-0.5 rounded border border-border-subtle text-text-secondary font-mono ml-2">
                                    {f.cwe}
                                  </span>
                                  <span className="text-[9px] px-1.5 py-0.5 rounded border border-border-subtle text-text-secondary font-mono">
                                    {f.owasp}
                                  </span>
                                </div>
                                <span className="stat-hero text-xs text-text-secondary">CVSS: {f.cvss}</span>
                              </div>

                              {/* Target Endpoint & Params */}
                              <div className="space-y-3">
                                <div>
                                  <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider block mb-1">Target endpoint:</span>
                                  <p className="text-xs font-mono text-text-primary inner-cell p-3 break-all">{f.location}</p>
                                </div>
                                
                                {f.parameter && (
                                  <div>
                                    <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider block mb-1">Query parameter:</span>
                                    <p className="text-xs font-mono text-brand-primary inner-cell p-3 break-all">{f.parameter}{f.paramValue ? ` = ${f.paramValue}` : ''}</p>
                                  </div>
                                )}
                              </div>

                              {/* Detailed Analysis */}
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                                {/* Layman / Business Impact */}
                                <div>
                                  <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                                    <BookOpen className="w-3 h-3" /> Business impact
                                  </span>
                                  <p className="text-[13px] text-text-primary leading-relaxed font-sans">
                                    {f.severity === 'Critical' || f.severity === 'High' 
                                      ? "This is a severe flaw that could allow an attacker to compromise sensitive data, take over user accounts, or gain unauthorized access to the system. Immediate attention is required to prevent significant business disruption or data breaches."
                                      : "This issue could be leveraged by an attacker to gather information about the system or perform lower-level exploits. It should be addressed to maintain a strong security posture."}
                                  </p>
                                </div>
                                
                                {/* Technical Details */}
                                <div>
                                  <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                                    <Eye className="w-3 h-3" /> Technical details
                                  </span>
                                  <p className="text-[13px] text-text-primary leading-relaxed font-sans">{f.description}</p>
                                </div>
                              </div>

                              {/* PoC Payload */}
                              {f.pocPayload && (
                                <div className="mt-3">
                                  <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                                    <Code2 className="w-3 h-3" /> PoC payload
                                  </span>
                                  <div className="inner-cell p-3 font-mono text-[11px] text-text-primary break-all">
                                    {f.pocPayload}
                                  </div>
                                </div>
                              )}
                              
                              {/* Remediation */}
                              <div className="mt-3 pt-4 border-t border-border-strong">
                                <span className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                                  <Shield className="w-3 h-3" /> Recommended fix
                                </span>
                                <p className="text-[13px] text-text-primary leading-relaxed font-sans">{f.recommendation}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ))}
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
              {reports.map((report) => (
                <div
                  key={report._id}
                  onClick={() => router.push(`/reports?id=${report._id}`)}
                  className="cyber-card p-6 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2.5">
                      <h3 className="text-sm font-semibold text-text-primary group-hover:text-brand-primary transition-colors">
                        {report.title}
                      </h3>
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
                      <span className="text-[10px] text-text-secondary block uppercase font-medium mb-0.5">Risk</span>
                      <span className={`font-mono font-semibold ${report.summary.riskScore >= 7 ? 'text-severity-critical' : report.summary.riskScore >= 4 ? 'text-severity-medium' : 'text-severity-low'}`}>
                        {report.summary.riskScore}
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
              ))}
            </div>
          )}
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
