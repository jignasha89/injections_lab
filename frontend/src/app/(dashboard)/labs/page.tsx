'use client';

import { useState } from 'react';
import { useStore } from '@/lib/store';
import { labsData } from '@/data/labsData';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { 
  FlaskConical, 
  CheckCircle, 
  HelpCircle, 
  Bookmark, 
  Search, 
  Flame, 
  Play 
} from 'lucide-react';

export default function LabsIndexPage() {
  const { progress, toggleBookmark } = useStore();
  const [filterCategory, setFilterCategory] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');

  // Extract categories
  const categories = ['All', ...Array.from(new Set(labsData.map((lab) => lab.category)))];

  // Filtering logic
  const filteredLabs = labsData.filter((lab) => {
    const matchesCategory = filterCategory === 'All' || lab.category === filterCategory;
    const matchesSearch = 
      lab.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lab.shortDescription.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-10 animate-in fade-in duration-500 text-slate-800">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Vulnerability Labs</h2>
          <p className="text-slate-600 text-base mt-1.5 font-semibold">
            Choose from 13 educational simulation sandboxes. Toggle vulnerable code vs secure filters.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
        {/* Category Filters */}
        <div className="flex flex-wrap gap-2.5 w-full md:w-auto">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilterCategory(cat)}
              className={`px-4.5 py-3 rounded-xl text-xs font-bold border transition-all ${
                filterCategory === cat
                  ? 'bg-slate-950 text-white border-slate-950 shadow-sm'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Local Lab Search */}
        <div className="relative w-full md:w-80">
          <input
            type="text"
            placeholder="Search active labs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-3 rounded-xl text-sm bg-slate-50 border border-slate-200 text-slate-955 focus:bg-white focus:border-blue-600 focus:outline-none"
          />
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        </div>
      </div>

      {/* Grid of Labs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredLabs.map((lab, idx) => {
          const userProg = progress.find((p) => p.labSlug === lab.slug);
          const isCompleted = userProg?.completed || false;
          const isBookmarked = userProg?.bookmarked || false;

          const sevColors = {
            Critical: 'text-red-700 bg-red-50 border-red-200',
            High: 'text-amber-700 bg-amber-50 border-amber-200',
            Medium: 'text-yellow-800 bg-yellow-50 border-yellow-200',
            Low: 'text-blue-700 bg-blue-50 border-blue-200',
          };

          return (
            <motion.div
              key={lab.slug}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: idx * 0.05 }}
              className="bg-white p-6 rounded-3xl flex flex-col justify-between border border-slate-200 hover:border-blue-400 hover:shadow-md transition-all group relative overflow-hidden"
            >
              <div>
                {/* Icons & State */}
                <div className="flex justify-between items-start gap-4 mb-4">
                  <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold border ${sevColors[lab.severity]}`}>
                    {lab.severity}
                  </span>
                  <div className="flex gap-2">
                    {/* Bookmark Toggle */}
                    <button
                      onClick={() => toggleBookmark(lab.slug)}
                      className={`p-1.5 rounded-xl bg-slate-50 border border-slate-200 transition-all shadow-sm ${
                        isBookmarked ? 'text-blue-600' : 'text-slate-400 hover:text-slate-700'
                      }`}
                      aria-label="Bookmark lab"
                    >
                      <Bookmark className="w-3.5 h-3.5 fill-current" />
                    </button>

                    {/* Completion Icon */}
                    {isCompleted && (
                      <span className="p-1 rounded-xl bg-green-50 border border-green-200 text-green-600 shadow-sm">
                        <CheckCircle className="w-4 h-4" />
                      </span>
                    )}
                  </div>
                </div>

                {/* Content */}
                <h3 className="font-extrabold text-base md:text-lg text-slate-900 group-hover:text-blue-600 transition-colors">
                  {lab.title}
                </h3>
                <p className="text-xs md:text-sm text-slate-600 mt-2 line-clamp-3 leading-relaxed font-semibold">
                  {lab.shortDescription}
                </p>

                {/* Details Meta */}
                <div className="mt-4 flex flex-wrap gap-1.5 font-bold">
                  <span className="text-[9px] font-mono px-2.5 py-1 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">
                    CWE: {lab.cwe}
                  </span>
                  <span className="text-[9px] font-mono px-2.5 py-1 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">
                    CVSS: {lab.cvss}
                  </span>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-6 pt-4 border-t border-slate-100">
                <Link
                  href={`/labs/${lab.slug}`}
                  className="w-full py-3 rounded-xl text-xs md:text-sm font-bold bg-slate-50 hover:bg-slate-950 group-hover:bg-slate-950 text-slate-800 hover:text-white border border-slate-200 hover:border-slate-950 transition-all flex items-center justify-center gap-1.5 shadow-sm"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Launch Lab Sandbox
                </Link>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
