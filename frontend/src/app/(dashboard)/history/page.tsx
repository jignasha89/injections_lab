'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import ParseTreeGraphic from '@/components/shared/ParseTreeGraphic';
import { 
  History, 
  Trash2, 
  ChevronRight,
  Globe,
  Clock
} from 'lucide-react';

interface Report {
  _id: string;
  title: string;
  targetUrl: string;
  scanType: 'url' | 'demo';
  summary: {
    injectionPoints: number;
    riskScore: number;
  };
  createdAt: string;
}

export default function HistoryPage() {
  const router = useRouter();
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await api.get('/reports?view=history');
      setReports(res.data.reports || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this historical scan?')) return;
    try {
      await api.delete(`/reports/${id}?view=history`);
      fetchHistory();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-border-strong pb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-text-primary flex items-center gap-3">
            <History className="w-6 h-6 text-brand-primary" />
            Scan History
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            A complete log of all your past security tests.
          </p>
        </div>
      </div>

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
            <p className="empty-state-title">No scan history</p>
            <p className="empty-state-desc">Run a scan to generate your first test record.</p>
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
                className="cyber-card p-6 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group hover:border-brand-primary/40 transition-colors"
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
                    <span className="font-mono font-semibold text-text-primary">{report.summary?.injectionPoints || 0}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-text-secondary block uppercase font-medium mb-0.5">Risk</span>
                    <span className={`font-mono font-semibold ${report.summary?.riskScore >= 7 ? 'text-severity-critical' : report.summary?.riskScore >= 4 ? 'text-severity-medium' : 'text-severity-low'}`}>
                      {report.summary?.riskScore || 0}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 pl-4 border-l border-border-strong">
                    <button
                      onClick={(e) => handleDelete(report._id, e)}
                      className="p-2 rounded-md text-text-secondary hover:text-severity-critical hover:bg-severity-critical/10 transition-colors"
                      aria-label="Delete record"
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
    </div>
  );
}
