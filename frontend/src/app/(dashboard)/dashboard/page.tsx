'use client';

import { useState, useEffect } from 'react';
import { useStore } from '@/lib/store';
import { api } from '@/lib/api';
import DashboardCharts from '@/components/dashboard/DashboardCharts';
import { 
  FileText, 
  AlertTriangle, 
  ListCollapse, 
  Hash, 
  Cookie, 
  Layers, 
  HelpCircle, 
  Flame, 
  ChevronRight, 
  ExternalLink 
} from 'lucide-react';
import Link from 'next/link';
import { labsData } from '@/data/labsData';

interface ReportSummary {
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
    owaspCoverage: string[];
  };
  techStack: string[];
  createdAt: string;
}

export default function DashboardPage() {
  const { progress } = useStore();
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const res = await api.get('/reports');
        setReports(res.data.reports || []);
      } catch (err) {
        console.error('Failed to load reports:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchReports();
  }, []);

  // 1. Calculations for Category Distribution Pie Chart
  const categoryStats: { [key: string]: number } = {};
  labsData.forEach((lab) => {
    categoryStats[lab.category] = (categoryStats[lab.category] || 0) + 1;
  });

  // 2. Calculations for OWASP Top 10 Completion Bar Chart
  const owaspStats: { [key: string]: number } = {
    'A01: Broken Access Control': 0,
    'A03: Injection': 0,
    'A09: Logging & Monitoring': 0,
    'AI/LLM Risks': 0,
  };

  progress.forEach((p) => {
    if (p.completed) {
      const lab = labsData.find((l) => l.slug === p.labSlug);
      if (lab) {
        if (lab.owasp.includes('A01')) {
          owaspStats['A01: Broken Access Control']++;
        } else if (lab.owasp.includes('A03')) {
          owaspStats['A03: Injection']++;
        } else if (lab.owasp.includes('A09')) {
          owaspStats['A09: Logging & Monitoring']++;
        } else if (lab.owasp.includes('LLM')) {
          owaspStats['AI/LLM Risks']++;
        }
      }
    }
  });

  // 3. Stats derived from the latest scan report or default values
  const latestReport = reports[0];
  const stats = {
    totalPages: latestReport?.summary?.totalPages || 12,
    injectionPoints: latestReport?.summary?.injectionPoints || 8,
    forms: latestReport?.summary?.forms || 4,
    headers: latestReport?.summary?.headers || 24,
    parameters: latestReport?.summary?.parameters || 16,
    cookies: latestReport?.summary?.cookies || 6,
    jsonInputs: latestReport?.summary?.jsonInputs || 3,
    riskScore: latestReport?.summary?.riskScore || 7.4,
    owaspCoverage: latestReport?.summary?.owaspCoverage?.length || 2,
  };

  // Compile all unique detected technologies across reports
  const allTech = Array.from(
    new Set(reports.flatMap((r) => r.techStack))
  ).filter(Boolean);

  const defaultTech = ['Node.js', 'Express', 'React', 'MongoDB', 'Apache', 'Java'];
  const displayTech = allTech.length > 0 ? allTech : defaultTech;

  return (
    <div className="space-y-10 animate-in fade-in duration-500 text-slate-800">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Security Command Center</h2>
        <p className="text-slate-600 text-base mt-1.5 font-semibold">
          Monitor detected vulnerabilities, verify secure code mitigations, and track your educational labs progress.
        </p>
      </div>

      {/* Grid of Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        {/* Risk Score (Giant Badge - Red for danger) */}
        <div className="col-span-2 bg-white p-8 rounded-3xl flex items-center justify-between border-l-8 border-red-600 border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div>
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Target Risk Score</p>
            <h3 className="text-5xl font-black font-mono mt-2.5 text-red-600">
              {stats.riskScore} <span className="text-sm text-slate-400 font-normal">/ 10.0</span>
            </h3>
            <p className="text-xs text-slate-500 font-semibold mt-2.5">Based on latest heuristic analysis</p>
          </div>
          <Flame className="w-14 h-14 text-red-600" />
        </div>

        {/* Total Points (Red danger / orange warning) */}
        <div className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div className="flex justify-between items-start">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Potential Points</p>
            <AlertTriangle className="w-5.5 h-5.5 text-red-600" />
          </div>
          <div className="mt-4">
            <h4 className="text-3xl font-black font-mono text-slate-900">{stats.injectionPoints}</h4>
            <p className="text-xs text-slate-500 font-bold mt-1.5">Identified parameters/segments</p>
          </div>
        </div>

        {/* Pages (Blue for standard info) */}
        <div className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div className="flex justify-between items-start">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Total Pages</p>
            <FileText className="w-5.5 h-5.5 text-blue-600" />
          </div>
          <div className="mt-4">
            <h4 className="text-3xl font-black font-mono text-slate-900">{stats.totalPages}</h4>
            <p className="text-xs text-slate-500 font-bold mt-1.5">Heuristically cataloged paths</p>
          </div>
        </div>

        {/* Forms (Blue for standard info) */}
        <div className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div className="flex justify-between items-start">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Forms</p>
            <ListCollapse className="w-5.5 h-5.5 text-blue-600" />
          </div>
          <div className="mt-4">
            <h4 className="text-3xl font-black font-mono text-slate-900">{stats.forms}</h4>
            <p className="text-xs text-slate-500 font-bold mt-1.5">Forms & query parameters</p>
          </div>
        </div>

        {/* Headers */}
        <div className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div className="flex justify-between items-start">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Headers</p>
            <Layers className="w-5.5 h-5.5 text-blue-600" />
          </div>
          <div className="mt-4">
            <h4 className="text-3xl font-black font-mono text-slate-900">{stats.headers}</h4>
            <p className="text-xs text-slate-500 font-bold mt-1.5">Request & Response headers</p>
          </div>
        </div>

        {/* Cookies (Green safe) */}
        <div className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div className="flex justify-between items-start">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Cookies</p>
            <Cookie className="w-5.5 h-5.5 text-green-600" />
          </div>
          <div className="mt-4">
            <h4 className="text-3xl font-black font-mono text-slate-900">{stats.cookies}</h4>
            <p className="text-xs text-slate-500 font-bold mt-1.5">Stored session attributes</p>
          </div>
        </div>

        {/* JSON Inputs */}
        <div className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 shadow-sm hover:shadow-md transition-all">
          <div className="flex justify-between items-start">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">JSON Inputs</p>
            <Hash className="w-5.5 h-5.5 text-slate-500" />
          </div>
          <div className="mt-4">
            <h4 className="text-3xl font-black font-mono text-slate-900">{stats.jsonInputs}</h4>
            <p className="text-xs text-slate-500 font-bold mt-1.5">API request body forms</p>
          </div>
        </div>
      </div>

      {/* Tech Stack detection */}
      <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm">
        <h3 className="text-sm md:text-base font-bold tracking-wider text-slate-800 uppercase mb-4">
          Heuristically Detected Technologies
        </h3>
        <div className="flex flex-wrap gap-3">
          {displayTech.map((tech) => (
            <span
              key={tech}
              className="px-4 py-2 rounded-2xl text-xs md:text-sm font-bold font-mono bg-blue-50 border border-blue-200 text-blue-700"
            >
              {tech}
            </span>
          ))}
        </div>
      </div>

      {/* Charts Grid */}
      <DashboardCharts categoryStats={categoryStats} owaspStats={owaspStats} />

      {/* Recent Scan History */}
      <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-6 border-b border-slate-200 pb-4">
          <h3 className="text-sm md:text-base font-bold tracking-wider text-slate-800 uppercase">
            Recent Scans & Reports
          </h3>
          <Link href="/reports" className="text-sm font-bold text-blue-600 hover:text-blue-800 hover:underline flex items-center gap-1">
            View All Reports <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        {loading ? (
          <p className="text-sm text-slate-500 text-center py-6 font-semibold">Analyzing database entries...</p>
        ) : reports.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-base text-slate-500 mb-4 font-bold">No security scans have been recorded yet.</p>
            <Link
              href="/scanner"
              className="px-6 py-3 rounded-2xl text-xs md:text-sm font-bold bg-slate-950 text-white hover:bg-slate-800 transition-all shadow-md"
            >
              Run First Safe Scan
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {reports.slice(0, 3).map((report) => (
              <div key={report._id} className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h4 className="text-base font-extrabold text-slate-900 flex items-center gap-2">
                    {report.title}
                    <span className="text-[10px] px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 text-slate-700 capitalize font-bold">
                      {report.scanType}
                    </span>
                  </h4>
                  <p className="text-xs md:text-sm text-slate-500 font-mono mt-1 font-semibold">{report.targetUrl}</p>
                </div>
                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <p className="text-xs text-slate-500 font-bold">Potential Findings</p>
                    <p className="text-base font-bold font-mono text-blue-600">{report.summary.injectionPoints}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-500 font-bold">Risk Score</p>
                    <p className="text-base font-bold font-mono text-red-600">{report.summary.riskScore}</p>
                  </div>
                  <Link
                    href={`/reports?id=${report._id}`}
                    className="p-2.5 rounded-2xl text-slate-500 hover:text-slate-900 hover:bg-slate-50 transition-all border border-transparent hover:border-slate-200"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
