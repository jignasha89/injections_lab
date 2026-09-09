'use client';

import { useState } from 'react';
import { labsData } from '@/data/labsData';
import { 
  BookOpen, 
  Terminal, 
  ShieldAlert, 
  Search,
  ShieldCheck,
  Activity,
  ArrowRight
} from 'lucide-react';
import Link from 'next/link';
import { clsx } from 'clsx';

export default function InjectionDetailsPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLabId, setSelectedLabId] = useState(labsData[0]?.id || 1);

  const filteredLabs = labsData.filter((lab) =>
    lab.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    lab.category.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const selectedLab = labsData.find(l => l.id === selectedLabId) || labsData[0];

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 border-red-500/20 bg-red-500/10';
      case 'High': return 'text-orange-400 border-orange-500/20 bg-orange-500/10';
      case 'Medium': return 'text-amber-400 border-amber-500/20 bg-amber-500/10';
      default: return 'text-blue-400 border-blue-500/20 bg-blue-500/10';
    }
  };

  return (
    <div className="h-[calc(100vh-8rem)] p-6 lg:p-8 flex flex-col md:flex-row gap-6 font-sans">
      {/* Sidebar / List View */}
      <div className="w-full md:w-80 flex flex-col gap-4 bg-surface-base border border-border-subtle rounded-xl overflow-hidden shrink-0">
        <div className="p-4 border-b border-border-subtle bg-bg-base/50">
          <h2 className="text-base font-bold text-text-primary mb-3 tracking-tight">Injection Catalog (55)</h2>
          <div className="relative">
            <input
              type="text"
              placeholder="Search injection types..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2.5 rounded-lg text-sm bg-bg-base border border-border-subtle text-text-primary placeholder-text-secondary focus:bg-surface-hover focus:border-brand-primary focus:outline-none transition-colors font-mono font-medium"
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredLabs.length === 0 ? (
            <p className="text-sm text-text-secondary text-center py-4 font-medium">No results found.</p>
          ) : (
            filteredLabs.map(lab => (
              <button
                key={lab.id}
                onClick={() => setSelectedLabId(lab.id)}
                className={clsx(
                  "w-full text-left px-3.5 py-3 rounded-lg text-sm transition-colors flex flex-col gap-1.5 border",
                  selectedLabId === lab.id
                    ? "bg-brand-primary/10 border-brand-primary/40 text-brand-primary font-bold shadow-[0_0_12px_rgba(99,102,241,0.2)]"
                    : "bg-transparent border-transparent text-text-secondary hover:bg-surface-hover hover:text-text-primary font-medium"
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm text-text-primary line-clamp-1">{lab.title}</span>
                </div>
                <div className="flex items-center justify-between mt-0.5">
                  <span className="font-mono text-xs uppercase font-bold tracking-wider text-text-secondary opacity-90 truncate">{lab.category}</span>
                  <span className={clsx("text-xs font-bold px-2 py-0.5 rounded border shrink-0", getSeverityBadge(lab.severity))}>
                    {lab.severity}
                  </span>
                </div>
              </button>
            ))
          )}
        </div>
      </div>

      {/* Detailed Reading View */}
      {selectedLab && (
        <div className="flex-1 bg-surface-base border border-border-subtle rounded-xl overflow-y-auto">
          {/* Header */}
          <div className="p-6 md:p-8 border-b border-border-subtle bg-gradient-to-b from-bg-base to-transparent relative overflow-hidden">
            <div className="absolute top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-brand-primary/5 rounded-full blur-[80px]" />
            <div className="relative z-10 flex flex-col gap-4">
              <div className="flex flex-wrap gap-2.5 items-center">
                <span className="text-xs md:text-sm font-mono font-bold px-3 py-1 rounded-md bg-bg-base border border-border-subtle text-text-secondary shadow-sm">
                  CWE: {selectedLab.cwe}
                </span>
                <span className={clsx("text-xs md:text-sm font-mono font-bold px-3 py-1 rounded-md border shadow-sm", getSeverityBadge(selectedLab.severity))}>
                  CVSS: {selectedLab.cvss}
                </span>
                <span className="text-xs md:text-sm font-mono font-bold px-3 py-1 rounded-md bg-bg-base border border-border-subtle text-text-secondary truncate max-w-[280px] shadow-sm">
                  {selectedLab.owasp}
                </span>
              </div>
              
              <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-text-primary leading-tight">{selectedLab.title}</h1>
              <p className="text-base md:text-lg text-text-secondary font-sans leading-relaxed max-w-4xl font-medium">
                {selectedLab.shortDescription}
              </p>

              <div className="pt-2">
                <Link
                  href={`/labs/${selectedLab.slug}`}
                  className="inline-flex items-center gap-2 px-5 py-2.5 bg-brand-primary hover:bg-brand-primary/90 text-white text-sm font-bold rounded-lg transition-colors shadow-[0_0_16px_rgba(99,102,241,0.4)]"
                >
                  Open Interactive Lab <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          </div>

          {/* Content Grid */}
          <div className="p-6 md:p-8 space-y-8">
            
            {/* Theory */}
            <div className="space-y-3">
              <h3 className="text-base md:text-lg font-extrabold text-text-primary uppercase tracking-wider flex items-center gap-2.5 border-b border-border-subtle pb-2.5">
                <BookOpen className="w-5 h-5 text-brand-primary" /> Theoretical Overview
              </h3>
              <p className="text-base text-slate-200 leading-loose whitespace-pre-line bg-bg-base p-5 rounded-xl border border-border-subtle font-normal">
                {selectedLab.theory}
              </p>
            </div>

            {/* Mechanics */}
            <div className="space-y-3">
              <h3 className="text-base md:text-lg font-extrabold text-text-primary uppercase tracking-wider flex items-center gap-2.5 border-b border-border-subtle pb-2.5">
                <Terminal className="w-5 h-5 text-orange-400" /> Attack Mechanics
              </h3>
              <p className="text-base text-slate-200 leading-relaxed whitespace-pre-line bg-bg-base p-5 rounded-xl border border-border-subtle font-mono text-sm md:text-base font-medium">
                {selectedLab.howItWorks}
              </p>
            </div>

            {/* Impact */}
            <div className="space-y-3">
              <h3 className="text-base md:text-lg font-extrabold text-text-primary uppercase tracking-wider flex items-center gap-2.5 border-b border-border-subtle pb-2.5">
                <ShieldAlert className="w-5 h-5 text-red-400" /> Business Impact
              </h3>
              <p className="text-base text-slate-200 leading-loose whitespace-pre-line bg-bg-base p-5 rounded-xl border border-border-subtle border-l-4 border-l-red-500/60 font-normal">
                {selectedLab.impact}
              </p>
            </div>

            {/* Real World */}
            <div className="space-y-3">
              <h3 className="text-base md:text-lg font-extrabold text-text-primary uppercase tracking-wider flex items-center gap-2.5 border-b border-border-subtle pb-2.5">
                <Activity className="w-5 h-5 text-purple-400" /> Real-World Context
              </h3>
              <div className="bg-bg-base p-5 rounded-xl border border-border-subtle space-y-2">
                <p className="text-base font-bold text-text-primary">
                  {selectedLab.realWorldCVE.id} ({selectedLab.realWorldCVE.year})
                </p>
                <p className="text-base text-slate-200 leading-relaxed font-normal">
                  {selectedLab.realWorldCVE.description}
                </p>
              </div>
            </div>

            {/* Mitigation */}
            <div className="space-y-3">
              <h3 className="text-base md:text-lg font-extrabold text-text-primary uppercase tracking-wider flex items-center gap-2.5 border-b border-border-subtle pb-2.5">
                <ShieldCheck className="w-5 h-5 text-emerald-400" /> Secure Development Guidelines
              </h3>
              <ul className="bg-bg-base p-5 rounded-xl border border-border-subtle space-y-3.5">
                {selectedLab.mitigation.map((mit, i) => (
                  <li key={i} className="flex items-start gap-3.5 text-base text-slate-200 leading-relaxed font-medium">
                    <span className="text-emerald-400 font-extrabold text-lg mt-0.5">•</span>
                    <span>{mit}</span>
                  </li>
                ))}
              </ul>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
