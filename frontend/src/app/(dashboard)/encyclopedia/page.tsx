'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { labsData } from '@/data/labsData';
import { useStore } from '@/lib/store';
import { BookOpen, Search, Bookmark, ChevronRight } from 'lucide-react';

function EncyclopediaContent() {
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

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'text-red-400 border-red-500/20 bg-red-500/10';
      case 'High':
        return 'text-orange-400 border-orange-500/20 bg-orange-500/10';
      case 'Medium':
        return 'text-amber-400 border-amber-500/20 bg-amber-500/10';
      default:
        return 'text-blue-400 border-blue-500/20 bg-blue-500/10';
    }
  };

  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12">
      {/* Title */}
      <div className="border-b border-border-subtle pb-4">
        <h2 className="text-xl md:text-2xl font-semibold tracking-tight text-[#e2e8f0] flex items-center gap-3">
          Injection Threat Encyclopedia <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-semibold">55 Vector Catalog</span>
        </h2>
        <p className="text-xs text-[#94a3b8] mt-1">
          Comprehensive threat intelligence dictionary containing CWE mappings, CVSS scores, and theoretical vector breakdowns
        </p>
      </div>

      {/* Filter Bar */}
      <div className="bg-surface-base p-4 rounded-md border border-border-subtle ">
        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="flex flex-wrap gap-1.5 w-full md:w-auto">
            {severities.map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
                  filterSeverity === sev
                    ? 'bg-blue-600 text-text-primary border-blue-600'
                    : 'bg-[#161b27] text-[#94a3b8] border-border-subtle hover:text-[#e2e8f0]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full md:w-72">
            <input
              type="text"
              placeholder="Search 55 threat entries..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 rounded-lg text-xs bg-[#0d1017] border border-border-subtle text-[#e2e8f0] placeholder-[#475569] focus:bg-surface-base focus:border-blue-600 focus:outline-none transition-colors font-mono"
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#475569]" />
          </div>
        </div>
      </div>

      {/* Encyclopedia List */}
      <div className="space-y-3">
        {filteredItems.length === 0 ? (
          <div className="bg-surface-base p-10 rounded-md border border-border-subtle text-center">
            <BookOpen className="w-6 h-6 text-[#475569] mb-2 mx-auto" />
            <p className="text-xs text-[#94a3b8]">No matching threat encyclopedia entries found.</p>
          </div>
        ) : (
          filteredItems.map((item) => {
            const userProg = progress.find((p) => p.labSlug === item.slug);
            const isBookmarked = userProg?.bookmarked || false;

            return (
              <div
                key={item.slug}
                className="bg-surface-base p-5 rounded-md border border-border-subtle hover:border-blue-600/40 transition-colors flex flex-col md:flex-row gap-4 justify-between items-start"
              >
                <div className="space-y-2.5 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono text-[#475569]">#{item.id}</span>
                    <h3 className="text-sm font-semibold text-[#e2e8f0]">{item.title}</h3>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-medium border ${getSeverityBadge(item.severity)}`}>
                      {item.severity}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161b27] border border-border-subtle text-[#94a3b8]">
                      {item.family}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161b27] border border-border-subtle text-[#94a3b8]">
                      {item.cwe}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161b27] border border-border-subtle text-[#94a3b8]">
                      CVSS {item.cvss}
                    </span>
                  </div>

                  <p className="text-xs text-[#94a3b8] leading-relaxed font-sans max-w-3xl">
                    {item.shortDescription}
                  </p>

                  <div className="p-3 bg-[#0d1017] border border-border-subtle rounded-lg space-y-1">
                    <span className="text-[10px] font-semibold text-blue-400 uppercase tracking-wider block">Theoretical Vector Mechanism</span>
                    <p className="text-xs text-[#94a3b8] leading-relaxed line-clamp-2 font-sans">
                      {item.theory}
                    </p>
                  </div>
                </div>

                <div className="flex md:flex-col gap-2 shrink-0 w-full md:w-auto items-center md:items-end justify-between">
                  <button
                    onClick={() => toggleBookmark(item.slug)}
                    className={`p-2 rounded-lg border transition-colors ${
                      isBookmarked
                        ? 'bg-blue-600/10 border-blue-600/30 text-blue-400'
                        : 'bg-[#161b27] border-border-subtle text-[#475569] hover:text-[#94a3b8]'
                    }`}
                    aria-label="Bookmark entry"
                  >
                    <Bookmark className="w-3.5 h-3.5 fill-current" />
                  </button>

                  <button
                    onClick={() => router.push(`/labs/${item.slug}`)}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-text-primary transition-colors flex items-center gap-1 "
                  >
                    Launch Lab <ChevronRight className="w-3.5 h-3.5" />
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

export default function EncyclopediaPage() {
  return (
    <Suspense fallback={<div className="text-xs text-[#94a3b8] p-4 font-mono">Loading encyclopedia...</div>}>
      <EncyclopediaContent />
    </Suspense>
  );
}
