'use client';

import { useState } from 'react';
import { useStore } from '@/lib/store';
import { labsData } from '@/data/labsData';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { 
  FlaskConical, 
  CheckCircle, 
  Bookmark, 
  Search, 
  Play,
  User,
  ShieldCheck,
  Cpu,
  Code2,
  Terminal,
  Bot
} from 'lucide-react';

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

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-zinc-100">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
            Vulnerability Labs <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">55 Interactive Sandboxes</span>
          </h2>
          <p className="text-zinc-400 text-sm mt-1.5 font-mono">
            Explore 55 injection attack simulation modules categorized across 4 core vulnerability domains.
          </p>
        </div>
      </div>

      {/* Filter and Search Section */}
      <div className="space-y-4 bg-[#0c0d14] p-5 rounded-2xl border border-zinc-800/80 shadow-2xl">
        {/* Category & Search Row */}
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
          <div className="flex flex-wrap gap-2 w-full md:w-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`px-3 py-1 rounded-lg text-xs font-mono transition-all border ${
                  filterCategory === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/60 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                    : 'bg-zinc-900/60 text-zinc-400 border-zinc-800 hover:bg-zinc-800 hover:text-white'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full md:w-80">
            <input
              type="text"
              placeholder="Filter 55 lab titles, CWEs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-xl text-xs font-mono bg-[#050508] border border-zinc-800 text-zinc-100 placeholder-zinc-500 focus:bg-[#0a0b12] focus:border-cyan-500/50 focus:outline-none"
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
          </div>
        </div>
      </div>

      {/* Grid of 55 Labs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredLabs.map((lab, idx) => {
          const userProg = progress.find((p) => p.labSlug === lab.slug);
          const isCompleted = userProg?.completed || false;
          const isBookmarked = userProg?.bookmarked || false;

          const sevColors = {
            Critical: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
            High: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
            Medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
            Low: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
          };

          return (
            <motion.div
              key={lab.slug}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2, delay: Math.min(idx * 0.02, 0.3) }}
              className="bg-[#0c0d14] p-6 rounded-2xl flex flex-col justify-between border border-zinc-800/80 hover:border-cyan-500/40 hover:shadow-[0_0_20px_rgba(0,240,255,0.08)] transition-all group relative overflow-hidden"
            >
              <div>
                {/* Meta Header */}
                <div className="flex justify-between items-start gap-2 mb-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-md font-bold border ${sevColors[lab.severity]}`}>
                      {lab.severity}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-md font-bold border bg-zinc-900 border-zinc-800 text-zinc-400">
                      {lab.cwe}
                    </span>
                  </div>

                  <div className="flex gap-1.5">
                    {/* Bookmark Toggle */}
                    <button
                      onClick={() => toggleBookmark(lab.slug)}
                      className={`p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 transition-all ${
                        isBookmarked ? 'text-cyan-400 border-cyan-500/40' : 'text-zinc-500 hover:text-zinc-300'
                      }`}
                      aria-label="Bookmark lab"
                    >
                      <Bookmark className="w-3.5 h-3.5 fill-current" />
                    </button>

                    {/* Completion Icon */}
                    {isCompleted && (
                      <span className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                        <CheckCircle className="w-3.5 h-3.5" />
                      </span>
                    )}
                  </div>
                </div>

                {/* Content */}
                <h3 className="font-bold text-base text-white group-hover:text-cyan-400 transition-colors font-mono">
                  #{lab.id} {lab.title}
                </h3>
                <p className="text-xs text-zinc-400 mt-2 line-clamp-3 leading-relaxed font-sans">
                  {lab.shortDescription}
                </p>

                {/* Tags & CWE */}
                <div className="mt-4 flex flex-wrap gap-1.5 font-mono text-[10px]">
                  <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                    {lab.cwe}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                    CVSS: {lab.cvss}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 truncate max-w-[120px]">
                    {lab.family}
                  </span>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-5 pt-3.5 border-t border-zinc-800/80">
                <Link
                  href={`/labs/${lab.slug}`}
                  className="w-full py-2.5 rounded-xl text-xs font-mono font-bold bg-zinc-900 hover:bg-cyan-500 hover:text-black group-hover:bg-cyan-500 group-hover:text-black text-cyan-300 border border-zinc-800 group-hover:border-cyan-400 transition-all flex items-center justify-center gap-2 shadow-sm"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Launch Sandbox
                </Link>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}

