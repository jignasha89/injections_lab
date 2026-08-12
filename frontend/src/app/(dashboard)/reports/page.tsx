'use client';

import { useState, useEffect, useRef } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import { 
  FileText, 
  Trash2, 
  Download, 
  ShieldCheck, 
  ArrowLeft,
  ChevronRight,
  Globe,
  Calendar
} from 'lucide-react';

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

interface Report {
  _id: string;
  title: string;
  targetUrl: string;
  scanType: 'url' | 'demo';
  labSlug?: string;
  summary: {
    totalPages: number;
    injectionPoints: number;
    forms: number;
    headers: number;
    parameters: number;
    cookies: number;
    jsonInputs: number;
    riskScore: number;
    owaspCoverage: string[];
  };
  findings: Finding[];
  techStack: string[];
  createdAt: string;
}

export default function ReportsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const reportId = searchParams.get('id');

  const [reports, setReports] = useState<Report[]>([]);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [exporting, setExporting] = useState(false);

  const pdfRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let ignore = false;
    async function loadReports() {
      try {
        const res = await api.get('/reports');
        if (!ignore) {
          setReports(res.data.reports || []);
        }
      } catch (err) {
        console.error(err);
      } finally {
        if (!ignore) setLoading(false);
      }
    }
    loadReports();
    return () => {
      ignore = true;
    };
  }, []);

  useEffect(() => {
    if (!reportId) return;
    let ignore = false;
    async function loadDetail() {
      try {
        const res = await api.get(`/reports/${reportId}`);
        if (!ignore) {
          setSelectedReport(res.data.report);
        }
      } catch (err) {
        console.error(err);
        if (!ignore) router.push('/reports');
      } finally {
        if (!ignore) setLoadingDetail(false);
      }
    }
    loadDetail();
    return () => {
      ignore = true;
    };
  }, [reportId, router]);

  const refreshReports = async () => {
    try {
      const res = await api.get('/reports');
      setReports(res.data.reports || []);
    } catch (err) {
      console.error(err);
    }
  };

  const displayedReport = reportId ? selectedReport : null;

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this report?')) return;
    try {
      await api.delete(`/reports/${id}`);
      refreshReports();
      if (displayedReport?._id === id) {
        router.push('/reports');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const exportPDF = async () => {
    if (!pdfRef.current || !displayedReport) return;
    setExporting(true);

    try {
      const element = pdfRef.current;
      const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#0c0d14',
      });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const imgWidth = 210;
      const pageHeight = 295;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }

      pdf.save(`InjectionLab-Audit-${displayedReport._id.slice(-8)}.pdf`);
    } catch (err) {
      console.error('Failed to export PDF:', err);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-zinc-100 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
            Security Audit Archive <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">PDF Reports</span>
          </h2>
          <p className="text-zinc-400 text-sm mt-1.5 font-mono">
            Review archived target scan evaluations, export executive PDF reports, and trace vulnerability histories.
          </p>
        </div>

        {displayedReport && (
          <button
            onClick={() => router.push('/reports')}
            className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700 transition-all flex items-center gap-1.5 self-start sm:self-auto"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Archive List
          </button>
        )}
      </div>

      {/* Detail View Mode */}
      {displayedReport ? (
        <div className="space-y-6">
          {/* Action Bar */}
          <div className="flex justify-end gap-3">
            <button
              onClick={exportPDF}
              disabled={exporting}
              className="px-4 py-2.5 rounded-xl text-xs font-mono font-bold bg-cyan-500 text-black hover:bg-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.2)] transition-all flex items-center gap-2 disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              {exporting ? 'Generating PDF...' : 'Download Official PDF Report'}
            </button>
          </div>

          {loadingDetail ? (
            <p className="text-xs font-mono text-zinc-500 text-center py-8">Loading audit detail sheet...</p>
          ) : (
            <div ref={pdfRef} className="bg-[#0c0d14] p-8 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-6 text-zinc-100">
              {/* Report Header */}
              <div className="border-b border-zinc-800 pb-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                  <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest">InjectionLab Audit Report</span>
                  <h3 className="text-2xl font-extrabold text-white font-mono mt-1">{displayedReport.title}</h3>
                  <p className="text-xs text-zinc-400 font-mono mt-1 flex items-center gap-1">
                    <Globe className="w-3.5 h-3.5 text-cyan-400" /> {displayedReport.targetUrl}
                  </p>
                </div>
                <div className="text-left md:text-right font-mono text-xs text-zinc-400">
                  <p>REPORT ID: #{displayedReport._id.slice(-8)}</p>
                  <p className="mt-1 flex items-center gap-1 md:justify-end">
                    <Calendar className="w-3.5 h-3.5 text-zinc-500" /> {new Date(displayedReport.createdAt).toLocaleDateString()}
                  </p>
                </div>
              </div>

              {/* Summary Metrics */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
                <div className="p-4 bg-[#050508] rounded-xl border border-zinc-800">
                  <p className="text-[10px] text-zinc-500 uppercase">Risk Score</p>
                  <p className="text-xl font-bold text-rose-400 mt-1">{displayedReport.summary.riskScore} / 10</p>
                </div>
                <div className="p-4 bg-[#050508] rounded-xl border border-zinc-800">
                  <p className="text-[10px] text-zinc-500 uppercase">Vulnerability Flags</p>
                  <p className="text-xl font-bold text-cyan-400 mt-1">{displayedReport.summary.injectionPoints}</p>
                </div>
                <div className="p-4 bg-[#050508] rounded-xl border border-zinc-800">
                  <p className="text-[10px] text-zinc-500 uppercase">Parameters</p>
                  <p className="text-xl font-bold text-white mt-1">{displayedReport.summary.parameters}</p>
                </div>
                <div className="p-4 bg-[#050508] rounded-xl border border-zinc-800">
                  <p className="text-[10px] text-zinc-500 uppercase">OWASP Categories</p>
                  <p className="text-xl font-bold text-purple-400 mt-1">{displayedReport.summary.owaspCoverage.length}</p>
                </div>
              </div>

              {/* Detailed Findings */}
              <div className="space-y-4 pt-4 border-t border-zinc-800">
                <h4 className="text-xs font-mono font-bold tracking-wider text-zinc-300 uppercase">
                  Cataloged Vulnerabilities ({displayedReport.findings.length})
                </h4>

                {displayedReport.findings.map((f, i) => (
                  <div key={i} className="p-4 rounded-xl bg-[#050508] border border-zinc-800 space-y-3 font-sans">
                    <div className="flex justify-between items-start gap-4">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="text-xs font-bold text-white">{f.type}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 font-bold">
                          {f.severity}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-cyan-400">
                          {f.cwe}
                        </span>
                      </div>
                      <span className="font-mono text-xs text-rose-400 font-bold">CVSS {f.cvss}</span>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed">{f.description}</p>
                    <p className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Fix: {f.recommendation}
                    </p>
                  </div>
                ))}
              </div>

              {/* Tech Stack */}
              {displayedReport.techStack.length > 0 && (
                <div className="pt-4 border-t border-zinc-800 space-y-2">
                  <h4 className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">
                    Detected Tech Stack Clues
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {displayedReport.techStack.map((tech) => (
                      <span key={tech} className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 text-xs font-mono text-cyan-300">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Footer */}
              <div className="pt-6 border-t border-zinc-800 text-[10px] font-mono text-zinc-500 flex justify-between">
                <span>InjectionLab Educational Platform</span>
                <span>CONFIDENTIAL AUDIT DOCUMENT</span>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Archive List Mode */
        <div className="space-y-4">
          {loading ? (
            <p className="text-xs font-mono text-zinc-500 text-center py-8">Fetching audit history...</p>
          ) : reports.length === 0 ? (
            <div className="bg-[#0c0d14] p-12 rounded-2xl border border-zinc-800 text-center space-y-3">
              <FileText className="w-8 h-8 text-zinc-500 mx-auto animate-pulse" />
              <p className="text-xs font-mono text-zinc-400">No archived reports saved yet.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {reports.map((report) => (
                <div
                  key={report._id}
                  onClick={() => router.push(`/reports?id=${report._id}`)}
                  className="bg-[#0c0d14] p-5 rounded-2xl border border-zinc-800/80 hover:border-cyan-500/40 transition-all cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 font-mono">
                      <h3 className="text-base font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {report.title}
                      </h3>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-400 capitalize">
                        {report.scanType}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-zinc-400">{report.targetUrl}</p>
                    <p className="text-[10px] font-mono text-zinc-500">
                      {new Date(report.createdAt).toLocaleString()}
                    </p>
                  </div>

                  <div className="flex items-center gap-6 font-mono text-xs">
                    <div>
                      <span className="text-[10px] text-zinc-500 block">FINDINGS</span>
                      <span className="text-cyan-400 font-bold">{report.summary.injectionPoints}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-500 block">RISK SCORE</span>
                      <span className="text-rose-400 font-bold">{report.summary.riskScore}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => handleDelete(report._id, e)}
                        className="p-2 rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-rose-400 hover:border-rose-500/30 transition-all"
                        aria-label="Delete report"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                      <ChevronRight className="w-5 h-5 text-zinc-500 group-hover:text-cyan-400 transition-colors" />
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
