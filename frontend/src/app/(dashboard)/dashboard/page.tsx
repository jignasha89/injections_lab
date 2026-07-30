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
  Flame,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
  UserCheck
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

  // Category Distribution
  const categoryStats: { [key: string]: number } = {};
  labsData.forEach((lab) => {
    categoryStats[lab.category] = (categoryStats[lab.category] || 0) + 1;
  });

  // OWASP Top 10 Completion Bar Chart
  const owaspStats: { [key: string]: number } = {
    'A01: Access Control': 0,
    'A03: Injection': 0,
    'A09: Logging': 0,
    'AI/LLM Risks': 0,
  };

  progress.forEach((p) => {
    if (p.completed) {
      const lab = labsData.find((l) => l.slug === p.labSlug);
      if (lab) {
        if (lab.owasp.includes('A01')) owaspStats['A01: Access Control']++;
        else if (lab.owasp.includes('A03')) owaspStats['A03: Injection']++;
        else if (lab.owasp.includes('A09')) owaspStats['A09: Logging']++;
        else if (lab.owasp.includes('LLM')) owaspStats['AI/LLM Risks']++;
      }
    }
  });

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
  };

  const allTech = Array.from(new Set(reports.flatMap((r) => r.techStack))).filter(Boolean);
  const defaultTech = ['Node.js', 'Express', 'React', 'MongoDB', 'Apache', 'Java'];
  const displayTech = allTech.length > 0 ? allTech : defaultTech;

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-zinc-100">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div className="flex items-center gap-4">
          <div className="p-1 rounded-2xl bg-black/40 border border-cyan-500/40 shadow-[0_0_30px_rgba(0,240,255,0.3)] shrink-0">
            <img
              src="/logo.png"
              alt="InjectionLab Logo"
              className="w-18 h-18 object-contain dark-logo scale-105"
            />
          </div>
          <div>
            <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white flex items-center gap-2 font-mono">
              Injection<span className="text-cyan-400">Lab</span>
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">v1.0</span>
            </h2>
            <p className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest mt-0.5">
              Learn • Test • Secure
            </p>
          </div>
        </div>
        <p className="text-xs text-zinc-400 font-mono text-left sm:text-right max-w-xs leading-relaxed">
          Real-time vulnerability monitor &amp; 55-vector attack catalog
        </p>
      </div>

      {/* Grid of Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
        {/* Risk Score */}
        <div className="col-span-2 bg-[#0c0d14] p-6 rounded-2xl flex items-center justify-between border border-rose-500/40 shadow-[0_0_20px_rgba(255,42,95,0.1)]">
          <div>
            <p className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider">Latest Audit Risk Score</p>
            <h3 className="text-4xl font-extrabold font-mono mt-2 text-rose-400">
              {stats.riskScore} <span className="text-xs text-zinc-500 font-normal">/ 10.0</span>
            </h3>
            <p className="text-xs text-zinc-400 font-mono mt-2">Heuristic risk index across active targets</p>
          </div>
          <Flame className="w-12 h-12 text-rose-500 animate-pulse" />
        </div>

        {/* Injection Points */}
        <div className="bg-[#0c0d14] p-5 rounded-2xl flex flex-col justify-between border border-zinc-800/80 shadow-xl">
          <div className="flex justify-between items-start">
            <p className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">Injection Points</p>
            <AlertTriangle className="w-4.5 h-4.5 text-amber-400" />
          </div>
          <div className="mt-3">
            <h4 className="text-2xl font-bold font-mono text-white">{stats.injectionPoints}</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-1">Cataloged inputs</p>
          </div>
        </div>

        {/* Total Cataloged Labs */}
        <div className="bg-[#0c0d14] p-5 rounded-2xl flex flex-col justify-between border border-zinc-800/80 shadow-xl">
          <div className="flex justify-between items-start">
            <p className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">Total Attack Types</p>
            <ShieldCheck className="w-4.5 h-4.5 text-cyan-400" />
          </div>
          <div className="mt-3">
            <h4 className="text-2xl font-bold font-mono text-cyan-400">55</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-1">4 Attack Families</p>
          </div>
        </div>

        {/* Forms */}
        <div className="bg-[#0c0d14] p-5 rounded-2xl flex flex-col justify-between border border-zinc-800/80 shadow-xl">
          <div className="flex justify-between items-start">
            <p className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">Form Endpoints</p>
            <ListCollapse className="w-4.5 h-4.5 text-cyan-400" />
          </div>
          <div className="mt-3">
            <h4 className="text-2xl font-bold font-mono text-white">{stats.forms}</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-1">Inspected forms</p>
          </div>
        </div>

        {/* Headers */}
        <div className="bg-[#0c0d14] p-5 rounded-2xl flex flex-col justify-between border border-zinc-800/80 shadow-xl">
          <div className="flex justify-between items-start">
            <p className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">HTTP Headers</p>
            <Layers className="w-4.5 h-4.5 text-purple-400" />
          </div>
          <div className="mt-3">
            <h4 className="text-2xl font-bold font-mono text-white">{stats.headers}</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-1">Request vectors</p>
          </div>
        </div>

        {/* Cookies */}
        <div className="bg-[#0c0d14] p-5 rounded-2xl flex flex-col justify-between border border-zinc-800/80 shadow-xl">
          <div className="flex justify-between items-start">
            <p className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">Cookies</p>
            <Cookie className="w-4.5 h-4.5 text-emerald-400" />
          </div>
          <div className="mt-3">
            <h4 className="text-2xl font-bold font-mono text-white">{stats.cookies}</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-1">Session tokens</p>
          </div>
        </div>

        {/* JSON Inputs */}
        <div className="bg-[#0c0d14] p-5 rounded-2xl flex flex-col justify-between border border-zinc-800/80 shadow-xl">
          <div className="flex justify-between items-start">
            <p className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">JSON Bodies</p>
            <Hash className="w-4.5 h-4.5 text-cyan-400" />
          </div>
          <div className="mt-3">
            <h4 className="text-2xl font-bold font-mono text-white">{stats.jsonInputs}</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-1">REST API fields</p>
          </div>
        </div>
      </div>

      {/* Team Information Section */}
      <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
        <h3 className="text-xs font-mono font-bold tracking-wider text-zinc-300 uppercase flex items-center gap-2 border-b border-zinc-800/80 pb-3">
          <UserCheck className="w-4 h-4 text-cyan-400" /> Project Team Information
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-300 flex items-center justify-between">
            <span className="text-zinc-400 font-bold">Project Developer:</span>
            <span className="text-sm font-extrabold text-white">Jignasha</span>
          </div>

          <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center justify-between">
            <span className="text-zinc-400 font-bold">Team Members:</span>
            <span className="text-sm font-extrabold text-white">Dwij, Yashi</span>
          </div>
        </div>
      </div>

      {/* Tech Stack detection */}
      <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl">
        <h3 className="text-xs font-mono font-bold tracking-wider text-zinc-300 uppercase mb-3">
          Heuristically Cataloged Server Technologies
        </h3>
        <div className="flex flex-wrap gap-2">
          {displayTech.map((tech) => (
            <span
              key={tech}
              className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-zinc-900 border border-zinc-700 text-cyan-300"
            >
              {tech}
            </span>
          ))}
        </div>
      </div>

      {/* Recent Scan History */}
      <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <h3 className="text-xs font-mono font-bold tracking-wider text-zinc-300 uppercase">
            Recent Audit Reports
          </h3>
          <Link href="/reports" className="text-xs font-mono font-bold text-cyan-400 hover:underline flex items-center gap-1">
            View Archives <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        {loading ? (
          <p className="text-xs font-mono text-zinc-500 text-center py-4">Reading database records...</p>
        ) : reports.length === 0 ? (
          <div className="text-center py-6">
            <p className="text-xs text-zinc-400 mb-3 font-mono">No security scans recorded yet.</p>
            <Link
              href="/scanner"
              className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-500 text-black hover:bg-cyan-400 transition-all"
            >
              Run First Target Scan
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/80">
            {reports.slice(0, 3).map((report) => (
              <div key={report._id} className="py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div>
                  <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                    {report.title}
                    <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-400 capitalize">
                      {report.scanType}
                    </span>
                  </h4>
                  <p className="text-xs text-zinc-500 font-mono mt-0.5">{report.targetUrl}</p>
                </div>
                <div className="flex items-center gap-5 font-mono text-xs">
                  <div>
                    <span className="text-[10px] text-zinc-500 block">FINDINGS:</span>
                    <span className="text-cyan-400 font-bold">{report.summary.injectionPoints}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 block">RISK SCORE:</span>
                    <span className="text-rose-400 font-bold">{report.summary.riskScore}</span>
                  </div>
                  <Link
                    href={`/reports?id=${report._id}`}
                    className="p-2 rounded-xl text-zinc-400 hover:text-white hover:bg-zinc-800 border border-transparent hover:border-zinc-700"
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

