'use client';

import { useState } from 'react';
import { useStore } from '@/lib/store';
import { Search, Bookmark, Trophy, AlertTriangle, X, Menu } from 'lucide-react';
import { useRouter } from 'next/navigation';

interface NavbarProps {
  onToggleSidebar?: () => void;
}

export default function Navbar({ onToggleSidebar }: NavbarProps) {
  const router = useRouter();
  const { progress, achievements } = useStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [showBookmarks, setShowBookmarks] = useState(false);

  // Calculate learning progress
  const totalLabs = 13;
  const completedLabs = progress.filter((p) => p.completed).length;
  const percentage = Math.round((completedLabs / totalLabs) * 100);

  // Get bookmarked labs
  const bookmarks = progress.filter((p) => p.bookmarked);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      router.push(`/encyclopedia?search=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-40 px-4 md:px-6 py-4 flex flex-col gap-3 shadow-sm">
      {/* Banner */}
      <div className="flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-2xl px-3.5 py-2.5 text-xs text-amber-800">
        <AlertTriangle className="w-5 h-5 shrink-0 text-amber-600" />
        <span className="font-bold tracking-wide">EDUCATION DISCLAIMER:</span>
        <span className="truncate font-semibold">This tool is intended only for authorized security testing and educational demonstrations.</span>
      </div>

      <div className="flex items-center justify-between gap-4">
        {/* Left Side: Hamburger (Mobile) + Search */}
        <div className="flex items-center gap-3 flex-1">
          {/* Hamburger button */}
          <button 
            onClick={onToggleSidebar}
            className="lg:hidden p-2.5 rounded-2xl text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 shadow-sm"
            aria-label="Toggle Menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Search Form */}
          <form onSubmit={handleSearch} className="relative w-full max-w-xs md:max-w-md">
            <input
              type="text"
              placeholder="Search encyclopedia, labs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-2xl text-sm bg-slate-50 border border-slate-200 text-slate-955 placeholder-slate-500 focus:bg-white focus:border-blue-600 focus:outline-none transition-colors"
            />
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          </form>
        </div>

        {/* Right Side: Action Widgets */}
        <div className="flex items-center gap-3 md:gap-6">
          {/* Progress Tracker */}
          <div className="hidden sm:flex items-center gap-3">
            <span className="text-xs font-bold text-slate-500">Progress:</span>
            <div className="w-20 md:w-32 h-3.5 rounded-full bg-slate-100 overflow-hidden relative border border-slate-200">
              <div
                className="h-full bg-blue-600 rounded-full transition-all duration-500"
                style={{ width: `${percentage}%` }}
              />
            </div>
            <span className="text-xs font-mono font-extrabold text-blue-600">{percentage}%</span>
          </div>

          {/* Bookmarks Toggle */}
          <div className="relative">
            <button
              onClick={() => setShowBookmarks(!showBookmarks)}
              className="relative p-2.5 rounded-2xl text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 transition-all shadow-sm"
            >
              <Bookmark className="w-4.5 h-4.5" />
              {bookmarks.length > 0 && (
                <span className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-blue-600 text-[10px] font-extrabold text-white flex items-center justify-center border border-white">
                  {bookmarks.length}
                </span>
              )}
            </button>

            {showBookmarks && (
              <div className="absolute right-0 mt-3 w-64 bg-white rounded-2xl shadow-xl p-4 border border-slate-200 animate-in fade-in slide-in-from-top-2 duration-200 z-50">
                <div className="flex items-center justify-between mb-3 border-b border-slate-200 pb-2">
                  <h3 className="font-bold text-sm text-blue-600">Bookmarks</h3>
                  <button onClick={() => setShowBookmarks(false)} className="text-slate-400 hover:text-slate-700">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                {bookmarks.length === 0 ? (
                  <p className="text-xs text-slate-500 text-center py-4">No bookmarked labs</p>
                ) : (
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {bookmarks.map((b) => (
                      <button
                        key={b.labSlug}
                        onClick={() => {
                          router.push(`/labs/${b.labSlug}`);
                          setShowBookmarks(false);
                        }}
                        className="w-full text-left px-2.5 py-2 rounded-2xl text-xs text-slate-700 hover:bg-slate-100 hover:text-slate-900 truncate font-semibold"
                      >
                        {b.labSlug.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Achievements badge count */}
          <div className="flex items-center gap-1.5 p-2 rounded-2xl bg-blue-50 border border-blue-100 text-blue-600 shadow-sm font-bold">
            <Trophy className="w-4.5 h-4.5 text-blue-600" />
            <span className="text-xs font-mono font-extrabold">{achievements.length}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
