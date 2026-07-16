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
  Eye, 
  AlertTriangle, 
  ShieldCheck, 
  Calendar, 
  Globe, 
  ArrowLeft,
  ChevronRight,
  TrendingUp
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
      const res = await api.get('/reports');
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
      await api.delete(`/reports/${id}`);
      fetchReports();
      if (selectedReport?._id === id) {
        router.push('/reports');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const exportPDF = async () => {
    if (!pdfRef.current || !selectedReport) return;
    setExporting(true);

    try {
      const element = pdfRef.current;
      const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#ffffff',
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

      const filename = `${selectedReport.title.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_audit_report.pdf`;
      pdf.save(filename);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-10 animate-in fade-in duration-500 text-slate-800">
      {/* Detail View */}
      {selectedReport ? (
        <div className="space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4">
            <button
              onClick={() => router.push('/reports')}
              className="px-4.5 py-3 rounded-xl text-xs font-bold bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 transition-all flex items-center gap-1.5 shadow-sm"
            >
              <ArrowLeft className="w-4 h-4" /> Back to History
            </button>
            <button
              onClick={exportPDF}
              disabled={exporting}
              className="px-4.5 py-3 rounded-xl text-xs font-bold bg-slate-950 text-white hover:bg-slate-900 active:scale-95 transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-md"
            >
              <Download className="w-4 h-4" />
              {exporting ? 'Generating PDF...' : 'Download PDF Report'}
            </button>
          </div>

          {loadingDetail ? (
            <p className="text-sm text-slate-500 text-center py-12 font-semibold">Loading audit details...</p>
          ) : (
            <div ref={pdfRef} className="bg-white p-8 md:p-10 rounded-3xl border border-slate-200 space-y-8 text-slate-800 max-w-4xl mx-auto shadow-md">
              {/* Header Title */}
              <div className="border-b border-slate-200 pb-6 flex flex-col md:flex-row justify-between gap-4 items-start">
                <div>
                  <span className="text-[10px] uppercase font-bold tracking-widest text-blue-600">SECURITY AUDIT SHEETS</span>
                  <h2 className="text-3xl font-extrabold text-slate-900 mt-1">{selectedReport.title}</h2>
                  <p className="text-xs md:text-sm text-slate-600 mt-2 font-mono flex items-center gap-1 font-bold">
                    <Globe className="w-3.5 h-3.5 text-slate-500" /> {selectedReport.targetUrl}
                  </p>
                </div>
                <div className="text-right">
                  <div className="flex items-center gap-1.5 text-xs text-slate-700 bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 font-bold shadow-sm">
                    <Calendar className="w-3.5 h-3.5 text-slate-500" />
                    <span>{new Date(selectedReport.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>

              {/* Assessment Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-5 bg-slate-50 border border-slate-200 rounded-2xl text-center shadow-sm">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider font-extrabold">Assessment Score</p>
                  <p className="text-3xl font-black font-mono text-red-600 mt-2">{selectedReport.summary.riskScore}</p>
                </div>
                <div className="p-5 bg-slate-50 border border-slate-200 rounded-2xl text-center shadow-sm">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider font-extrabold">Total Findings</p>
                  <p className="text-3xl font-black font-mono text-blue-600 mt-2">{selectedReport.findings.length}</p>
                </div>
                <div className="p-5 bg-slate-50 border border-slate-200 rounded-2xl text-center shadow-sm">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider font-extrabold">Parameters</p>
                  <p className="text-3xl font-black font-mono text-slate-900 mt-2">{selectedReport.summary.parameters}</p>
                </div>
                <div className="p-5 bg-slate-50 border border-slate-200 rounded-2xl text-center shadow-sm">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider font-extrabold">OWASP Coverage</p>
                  <p className="text-3xl font-black font-mono text-slate-900 mt-2">{selectedReport.summary.owaspCoverage.length}</p>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-3">
                <h3 className="text-sm md:text-base font-bold tracking-wider text-slate-900 uppercase border-l-4 border-blue-600 pl-3">
                  Executive Summary
                </h3>
                <p className="text-sm text-slate-600 leading-relaxed font-semibold">
                  A passive security inspection was performed on the target route. The analysis identified structural parameters, form values, cookies, and header contexts used in data flows. We mapped matching vulnerability risks to OWASP security metrics and listed non-destructive diagnostic guidance and mitigations below.
                </p>
              </div>

              {/* Findings Section */}
              <div className="space-y-6">
                <h3 className="text-sm md:text-base font-bold tracking-wider text-slate-900 uppercase border-l-4 border-blue-600 pl-3">
                  Identified Threats and Vulnerabilities
                </h3>

                {selectedReport.findings.length === 0 ? (
                  <p className="text-sm text-slate-500 italic font-bold">No vulnerability risks identified.</p>
                ) : (
                  <div className="space-y-6">
                    {selectedReport.findings.map((f, i) => (
                      <div key={i} className="p-6 rounded-3xl bg-white border border-slate-200 space-y-4 shadow-sm">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-100 pb-3">
                          <div className="flex items-center gap-2.5">
                            <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 px-2.5 py-1 rounded-xl border border-blue-200 shadow-sm">
                              #{i + 1}
                            </span>
                            <h4 className="text-sm md:text-base font-bold text-slate-900">{f.type}</h4>
                          </div>
                          <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-red-50 border border-red-200 text-red-700 font-extrabold">
                            CVSS {f.cvss} / Severity: {f.severity}
                          </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono font-bold">
                          <div>
                            <span className="text-slate-500 block mb-0.5">LOCATION:</span>
                            <span className="text-slate-800 break-all">{f.location}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block mb-0.5">CWE MAPPING:</span>
                            <span className="text-blue-600">{f.cwe}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block mb-0.5">OWASP METRIC:</span>
                            <span className="text-slate-900">{f.owasp}</span>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <span className="text-[10px] text-slate-500 uppercase tracking-widest font-extrabold block">Vulnerability Description</span>
                          <p className="text-xs md:text-sm text-slate-600 leading-relaxed font-semibold">{f.description}</p>
                        </div>

                        <div className="p-4 bg-green-50 border border-green-200 rounded-2xl shadow-inner space-y-1">
                          <span className="text-[10px] text-green-800 font-extrabold uppercase tracking-wider flex items-center gap-1.5">
                            <ShieldCheck className="w-4.5 h-4.5 text-green-600" /> Secure Coding Recommendation
                          </span>
                          <p className="text-xs md:text-sm text-green-950 font-bold leading-relaxed">{f.recommendation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Technology Stack Detected */}
              {selectedReport.techStack.length > 0 && (
                <div className="space-y-3 border-t border-slate-200 pt-6">
                  <h3 className="text-xs md:text-sm font-bold tracking-wider text-slate-700 uppercase">
                    Detected Technologies Stack
                  </h3>
                  <div className="flex flex-wrap gap-2.5">
                    {selectedReport.techStack.map((tech) => (
                      <span key={tech} className="px-3.5 py-1.5 rounded-xl text-xs font-mono font-bold bg-blue-50 border border-blue-200 text-blue-700">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* PDF Footer Disclaimer */}
              <div className="border-t border-slate-200 pt-6 text-[10px] text-slate-500 text-center uppercase tracking-widest font-bold leading-relaxed">
                <p>This report is for authorized educational and threat modeling use only.</p>
                <p className="mt-1">Generated via InjectionLab — Learn. Detect. Fix.</p>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* History Index View */
        <div className="space-y-6 text-slate-800">
          <div>
            <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Audit Archives</h2>
            <p className="text-slate-600 text-sm mt-1.5 font-semibold">
              View generated reports, study security logs, and export executive assessment summaries in PDF formats.
            </p>
          </div>

          {loading ? (
            <p className="text-sm text-slate-500 text-center py-12 font-semibold">Loading archives...</p>
          ) : reports.length === 0 ? (
            <div className="bg-white p-12 rounded-3xl border border-slate-200 text-center flex flex-col items-center justify-center min-h-[300px] shadow-sm">
              <FileText className="w-8 h-8 text-slate-400 mb-4 animate-pulse" />
              <h3 className="font-bold text-base text-slate-800">No reports recorded</h3>
              <p className="text-xs text-slate-500 mt-2 max-w-sm font-semibold">
                Run security scans inside the Target Inspector or complete demo labs to generate vulnerability records.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {reports.map((report) => (
                <div
                  key={report._id}
                  onClick={() => router.push(`/reports?id=${report._id}`)}
                  className="bg-white p-6 rounded-3xl border border-slate-200 hover:border-blue-400 transition-all cursor-pointer flex flex-col justify-between group shadow-sm hover:shadow-md"
                >
                  <div>
                    <div className="flex justify-between items-start gap-4">
                      <span className="text-[10px] px-2.5 py-1 rounded-full bg-slate-50 border border-slate-200 text-slate-700 font-mono font-bold capitalize">
                        {report.scanType} Mode
                      </span>
                      <span className="text-xs font-bold text-slate-500">
                        {new Date(report.createdAt).toLocaleDateString()}
                      </span>
                    </div>

                    <h3 className="font-extrabold text-base md:text-lg text-slate-900 mt-4 group-hover:text-blue-600 transition-colors truncate">
                      {report.title}
                    </h3>
                    <p className="text-xs md:text-sm text-slate-500 font-mono mt-1 truncate max-w-xs font-semibold">{report.targetUrl}</p>

                    <div className="grid grid-cols-3 gap-2 mt-6 font-mono text-xs border-t border-slate-100 pt-4 font-bold">
                      <div>
                        <span className="text-[10px] text-slate-500 block mb-0.5">RISK SCORE:</span>
                        <span className="text-red-600 font-bold">{report.summary.riskScore}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 block mb-0.5">FINDINGS:</span>
                        <span className="text-blue-600 font-bold">{report.summary.injectionPoints}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 block mb-0.5">PARAMS:</span>
                        <span className="text-slate-900 font-bold">{report.summary.parameters}</span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 flex justify-between items-center gap-4">
                    <button className="text-xs md:text-sm text-blue-600 font-bold group-hover:underline flex items-center gap-1">
                      Open Audit Sheet <ChevronRight className="w-4 h-4" />
                    </button>
                    <button
                      onClick={(e) => handleDelete(report._id, e)}
                      className="p-2 rounded-xl hover:bg-red-50 text-slate-400 hover:text-red-600 border border-transparent hover:border-red-100 transition-all shadow-sm"
                      aria-label="Delete report"
                    >
                      <Trash2 className="w-4.5 h-4.5" />
                    </button>
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
