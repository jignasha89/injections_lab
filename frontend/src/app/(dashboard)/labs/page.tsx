'use client';

import { useState } from 'react';
import { useStore } from '@/lib/store';
import { labsData } from '@/data/labsData';
import Link from 'next/link';
import { 
  CheckCircle, 
  Bookmark, 
  Search, 
  Play,
  ShieldAlert,
  Sparkles,
  ChevronRight
} from 'lucide-react';
import { motion } from 'framer-motion';

export default function LabsIndexPage() {
  const { progress, toggleBookmark } = useStore();
  const [filterCategory, setFilterCategory] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const categories = ['All', ...Array.from(new Set(labsData.map((lab) => lab.category)))];

  // Filtering logic
  const filteredLabs = labsData.filter((lab) => {
    const matchesCategory = filterCategory === 'All' || lab.category === filterCategory;
    const matchesSearch = 
      lab.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lab.shortDescription.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lab.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lab.slug.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'glow-badge-rose';
      case 'High':
        return 'glow-badge-amber';
      case 'Medium':
        return 'glow-badge-amber';
      case 'Low':
      default:
        return 'glow-badge-cyan';
    }
  };

  return (
    <div className="space-y-8 p-6 lg:p-8 text-slate-100 font-sans pb-10">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-6">
        <div>
          <h2 className="text-2xl md:text-3xl font-extrabold tracking-tight text-text-primary flex items-center gap-3">
            Vulnerability Labs Sandboxes <span className="text-xs font-mono font-bold px-3 py-1 rounded-full glow-badge-cyan">55 Live Sandboxes</span>
          </h2>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Interactive injection attack simulation modules categorized across 4 domain specializations
          </p>
        </div>
      </div>

      {/* Filter and Search Section */}
      <div className="cyber-card p-5 space-y-4">
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
          {/* Category Selector Buttons */}
          <div className="flex flex-wrap gap-2 w-full md:w-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`px-3.5 py-1.5 rounded-md text-xs font-semibold transition-all ${
                  filterCategory === cat
                    ? 'btn-cyber-primary text-text-primary shadow-[0_0_15px_rgba(6,182,212,0.4)]'
                    : 'bg-white/5 text-text-secondary border border-white/10 hover:text-text-primary hover:bg-white/10'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Search Input Box */}
          <div className="relative w-full md:w-80">
            <input
              type="text"
              placeholder="Search 55 labs, CWEs, titles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-md text-xs bg-bg-base border border-white/10 text-text-primary placeholder-slate-500 focus:border-brand-primary/20 focus:outline-none transition-all "
            />
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-brand-primary" />
          </div>
        </div>
      </div>

      {/* Grid of 55 Labs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredLabs.map((lab, idx) => {
          const userProg = progress.find((p) => p.labSlug === lab.slug);
          const isCompleted = userProg?.completed || false;
          const isBookmarked = userProg?.bookmarked || false;

          return (
            <motion.div
              key={lab.slug}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2, delay: Math.min(idx * 0.015, 0.25) }}
              className="cyber-card p-6 flex flex-col justify-between group relative overflow-hidden"
            >
              <div>
                {/* Meta Header */}
                <div className="flex justify-between items-start gap-2 mb-3">
                  <div className="flex items-center gap-2 flex-wrap font-mono">
                    <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-md ${getSeverityBadgeClass(lab.severity)}`}>
                      {lab.severity}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-text-secondary font-bold">
                      {lab.cwe}
                    </span>
                  </div>

                  <div className="flex gap-1.5">
                    {/* Bookmark Toggle */}
                    <button
                      onClick={() => toggleBookmark(lab.slug)}
                      className={`p-1.5 rounded-lg border transition-all ${
                        isBookmarked ? 'bg-cyan-500/20 border-brand-primary/20 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.3)]' : 'bg-white/5 border-white/10 text-slate-500 hover:text-slate-200'
                      }`}
                      aria-label="Bookmark lab"
                    >
                      <Bookmark className="w-3.5 h-3.5 fill-current" />
                    </button>

                    {/* Completion Icon */}
                    {isCompleted && (
                      <span className="p-1.5 rounded-lg glow-badge-emerald" title="Completed">
                        <CheckCircle className="w-3.5 h-3.5" />
                      </span>
                    )}
                  </div>
                </div>

                {/* Content */}
                <h3 className="font-bold text-base text-text-primary group-hover:text-cyan-300 transition-colors font-sans flex items-center justify-between">
                  <span>#{lab.id} {lab.title}</span>
                </h3>
                <p className="text-xs text-text-secondary mt-2 line-clamp-3 leading-relaxed font-sans">
                  {lab.shortDescription}
                </p>

                {/* Tags & CVSS */}
                <div className="mt-4 flex flex-wrap gap-2 text-[10px] font-mono">
                  <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
                    CVSS: {lab.cvss}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300 truncate max-w-[130px]">
                    {lab.family}
                  </span>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-5 pt-4 border-t border-white/10">
                <Link
                  href={`/labs/${lab.slug}`}
                  className="w-full py-2.5 rounded-md text-xs font-semibold bg-white/5 hover:bg-surface-hover text-cyan-300 hover:text-text-primary border border-white/10 hover:border-transparent transition-all duration-200 flex items-center justify-center gap-2 group-"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Launch Lab Sandbox
                  <ChevronRight className="w-3.5 h-3.5 opacity-60 group-hover:translate-x-1 transition-transform" />
                </Link>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
