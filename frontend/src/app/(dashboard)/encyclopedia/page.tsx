'use client';

import { useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { labsData, LabData } from '@/data/labsData';
import { useStore } from '@/lib/store';
import { BookOpen, Search, Bookmark, ChevronRight, AlertTriangle, ExternalLink } from 'lucide-react';

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

  // Filter logic
  const filteredItems = labsData.filter((item) => {
    const matchesSearch = 
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.shortDescription.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.cwe.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesSeverity = filterSeverity === 'All' || item.severity === filterSeverity;
    
    return matchesSearch && matchesSeverity;
  });

  const severities = ['All', 'Critical', 'High', 'Medium', 'Low'];

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-slate-800">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Injection Encyclopedia</h2>
        <p className="text-slate-600 text-sm mt-1">
          A-Z catalog containing threat classifications, threat metrics, CWE numbers, and secure coding references.
        </p>
      </div>

      {/* Filter Options */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="flex flex-wrap gap-2.5 w-full md:w-auto">
          {severities.map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-4.5 py-3 rounded-xl text-xs font-bold border transition-all ${
                filterSeverity === sev
                  ? 'bg-slate-950 text-white border-slate-950 shadow-sm'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-80">
          <input
            type="text"
            placeholder="Search encyclopedia entries..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-3 rounded-xl text-sm bg-slate-50 border border-slate-200 text-slate-950 focus:bg-white focus:border-blue-600 focus:outline-none"
          />
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        </div>
      </div>

      {/* Encyclopedia List */}
      <div className="space-y-6">
        {filteredItems.length === 0 ? (
          <div className="bg-white p-12 rounded-3xl border border-slate-200 text-center shadow-sm">
            <BookOpen className="w-8 h-8 text-slate-400 mb-4 mx-auto animate-pulse" />
            <p className="text-sm text-slate-500 font-semibold">No matching encyclopedia entries found.</p>
          </div>
        ) : (
          filteredItems.map((item) => {
            const userProg = progress.find((p) => p.labSlug === item.slug);
            const isBookmarked = userProg?.bookmarked || false;

            const sevColors = {
              Critical: 'text-red-700 border-red-200 bg-red-50',
              High: 'text-amber-700 border-amber-200 bg-amber-50',
              Medium: 'text-yellow-800 border-yellow-200 bg-yellow-50',
              Low: 'text-blue-700 border-blue-200 bg-blue-50',
            };

            return (
              <div
                key={item.slug}
                className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm hover:border-blue-400 transition-all flex flex-col md:flex-row gap-6 justify-between items-start"
              >
                <div className="space-y-4 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="text-lg font-bold text-slate-900">{item.title}</h3>
                    <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold border ${sevColors[item.severity]}`}>
                      {item.severity}
                    </span>
                    <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">
                      CWE: {item.cwe}
                    </span>
                    <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">
                      CVSS: {item.cvss}
                    </span>
                    <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">
                      OWASP: {item.owasp}
                    </span>
                  </div>

                  <p className="text-xs md:text-sm text-slate-600 leading-relaxed font-semibold max-w-3xl">
                    {item.shortDescription}
                  </p>

                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold block mb-1">Theoretical Background</span>
                    <p className="text-xs md:text-sm text-slate-700 leading-relaxed whitespace-pre-line line-clamp-2 font-semibold">
                      {item.theory}
                    </p>
                  </div>
                </div>

                <div className="flex md:flex-col gap-3 shrink-0 w-full md:w-auto items-center md:items-end justify-between">
                  <button
                    onClick={() => toggleBookmark(item.slug)}
                    className={`p-2.5 rounded-xl border transition-all shadow-sm ${
                      isBookmarked
                        ? 'bg-blue-50 border-blue-200 text-blue-600'
                        : 'bg-slate-50 border-slate-200 text-slate-500 hover:text-slate-800'
                    }`}
                    aria-label="Bookmark entry"
                  >
                    <Bookmark className="w-4.5 h-4.5 fill-current" />
                  </button>

                  <button
                    onClick={() => router.push(`/labs/${item.slug}`)}
                    className="px-4.5 py-3 rounded-xl text-xs font-bold bg-slate-950 hover:bg-slate-900 text-white active:scale-95 transition-all flex items-center gap-1.5 shadow-sm"
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
