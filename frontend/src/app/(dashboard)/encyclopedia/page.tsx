'use client';

import { useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { labsData } from '@/data/labsData';
import { useStore } from '@/lib/store';
import { BookOpen, Search, Bookmark, ChevronRight, User } from 'lucide-react';

export default function EncyclopediaPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialSearch = searchParams.get('search') || '';

  const { progress, toggleBookmark } = useStore();
  const [searchQuery, setSearchQuery] = useState(initialSearch);
  const [filterSeverity, setFilterSeverity] = useState('All');

  useEffect(() => {
    setSearchQuery(searchParams.get('search') || '');
  }, [searchParams]);

  const severities = ['All', 'Critical', 'High', 'Medium', 'Low'];

  const filteredItems = labsData.filter((item) => {
    const matchesSearch = 
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.shortDescription.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.family.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesSeverity = filterSeverity === 'All' || item.severity === filterSeverity;
    
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-zinc-100">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
          Injection Encyclopedia <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">55 Types</span>
        </h2>
        <p className="text-zinc-400 text-sm mt-1.5 font-mono">
          Comprehensive threat catalog containing classifications, CWE mappings, and CVSS scores.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="space-y-4 bg-[#0c0d14] p-5 rounded-2xl border border-zinc-800/80 shadow-2xl">
        {/* Severity & Search Row */}
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
          <div className="flex flex-wrap gap-2 w-full md:w-auto">
            {severities.map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-3 py-1 rounded-lg text-xs font-mono transition-all border ${
                  filterSeverity === sev
                    ? 'bg-zinc-800 text-white border-zinc-700'
                    : 'bg-transparent text-zinc-400 border-transparent hover:bg-zinc-900 hover:text-zinc-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full md:w-80">
            <input
              type="text"
              placeholder="Search 55 injection types..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-xl text-xs font-mono bg-[#050508] border border-zinc-800 text-zinc-100 placeholder-zinc-500 focus:bg-[#0a0b12] focus:border-cyan-500/50 focus:outline-none"
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
          </div>
        </div>
      </div>

      {/* Encyclopedia List */}
      <div className="space-y-4">
        {filteredItems.length === 0 ? (
          <div className="bg-[#0c0d14] p-12 rounded-2xl border border-zinc-800/80 text-center">
            <BookOpen className="w-8 h-8 text-zinc-500 mb-3 mx-auto animate-pulse" />
            <p className="text-xs font-mono text-zinc-400">No matching encyclopedia entries found.</p>
          </div>
        ) : (
          filteredItems.map((item) => {
            const userProg = progress.find((p) => p.labSlug === item.slug);
            const isBookmarked = userProg?.bookmarked || false;

            const sevColors = {
              Critical: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
              High: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
              Medium: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
              Low: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
            };

            return (
              <div
                key={item.slug}
                className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 hover:border-cyan-500/40 transition-all flex flex-col md:flex-row gap-5 justify-between items-start"
              >
                <div className="space-y-3 flex-1">
                  <div className="flex flex-wrap items-center gap-2 font-mono">
                    <span className="text-xs text-zinc-500 font-bold">#{item.id}</span>
                    <h3 className="text-base font-bold text-white font-mono">{item.title}</h3>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${sevColors[item.severity]}`}>
                      {item.severity}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                      {item.family}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                      {item.cwe}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                      CVSS: {item.cvss}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-300 leading-relaxed font-sans max-w-3xl">
                    {item.shortDescription}
                  </p>

                  <div className="p-3.5 bg-[#050508] border border-zinc-800/80 rounded-xl space-y-1">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block">Theoretical Background</span>
                    <p className="text-xs text-zinc-400 leading-relaxed whitespace-pre-line line-clamp-2 font-sans">
                      {item.theory}
                    </p>
                  </div>
                </div>

                <div className="flex md:flex-col gap-2 shrink-0 w-full md:w-auto items-center md:items-end justify-between">
                  <button
                    onClick={() => toggleBookmark(item.slug)}
                    className={`p-2 rounded-xl border transition-all ${
                      isBookmarked
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400'
                        : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-white'
                    }`}
                    aria-label="Bookmark entry"
                  >
                    <Bookmark className="w-4 h-4 fill-current" />
                  </button>

                  <button
                    onClick={() => router.push(`/labs/${item.slug}`)}
                    className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-black transition-all flex items-center gap-1.5"
                  >
                    Launch Lab <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

