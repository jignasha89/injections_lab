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

  // Calculate learning progress across 55 total labs
  const totalLabs = 55;
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
    <header className="bg-[#08090e] border-b border-zinc-800/80 sticky top-0 z-40 px-4 md:px-6 py-3 flex flex-col gap-2.5 shadow-2xl backdrop-blur-md">
      {/* Banner */}
      <div className="flex items-center gap-2 bg-amber-500/10 border border-amber-500/30 rounded-xl px-3 py-1.5 text-xs text-amber-300">
        <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
        <span className="font-bold tracking-wide font-mono">AUTHORIZATION ONLY:</span>
        <span className="truncate text-zinc-300">This platform runs 55 injection demos strictly for institute educational audits & research.</span>
      </div>

      <div className="flex items-center justify-between gap-4">
        {/* Left Side: Hamburger (Mobile) + Search */}
        <div className="flex items-center gap-3 flex-1">
          <button 
            onClick={onToggleSidebar}
            className="lg:hidden p-2 rounded-xl text-zinc-400 hover:text-white hover:bg-zinc-800/60 border border-zinc-800"
            aria-label="Toggle Menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Mobile Brand Logo */}
          <div className="flex lg:hidden items-center gap-2">
            <img 
              src="/logo.png" 
              alt="InjectionLab Logo" 
              className="w-10 h-10 object-contain dark-logo scale-105"
            />
            <span className="font-extrabold text-sm font-mono text-white hidden sm:inline">
              Injection<span className="text-cyan-400">Lab</span>
            </span>
          </div>

          {/* Search Form */}
          <form onSubmit={handleSearch} className="relative w-full max-w-xs md:max-w-md">
            <input
              type="text"
              placeholder="Search 55 injection types, CWEs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-xl text-xs font-mono bg-[#0e1017] border border-zinc-800 text-zinc-100 placeholder-zinc-500 focus:bg-[#121520] focus:border-cyan-500/50 focus:outline-none transition-colors"
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
          </form>
        </div>

        {/* Right Side: Action Widgets */}
        <div className="flex items-center gap-3 md:gap-5">
          {/* Progress Tracker */}
          <div className="hidden sm:flex items-center gap-2.5">
            <span className="text-xs font-mono text-zinc-400">Labs Done:</span>
            <div className="w-20 md:w-28 h-2.5 rounded-full bg-zinc-800/80 overflow-hidden relative border border-zinc-700/50">
              <div
                className="h-full bg-cyan-400 rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(0,240,255,0.5)]"
                style={{ width: `${percentage}%` }}
              />
            </div>
            <span className="text-xs font-mono font-bold text-cyan-400">{completedLabs}/55 ({percentage}%)</span>
          </div>

          {/* Bookmarks Toggle */}
          <div className="relative">
            <button
              onClick={() => setShowBookmarks(!showBookmarks)}
              className="relative p-2 rounded-xl text-zinc-400 hover:text-white hover:bg-zinc-800/60 border border-zinc-800 transition-all"
            >
              <Bookmark className="w-4 h-4" />
              {bookmarks.length > 0 && (
                <span className="absolute -top-1 -right-1 w-4.5 h-4.5 rounded-full bg-cyan-500 text-[9px] font-mono font-bold text-black flex items-center justify-center border border-black">
                  {bookmarks.length}
                </span>
              )}
            </button>

            {showBookmarks && (
              <div className="absolute right-0 mt-3 w-64 bg-[#0d0e15] rounded-xl shadow-2xl p-4 border border-zinc-800 z-50">
                <div className="flex items-center justify-between mb-3 border-b border-zinc-800 pb-2">
                  <h3 className="font-bold text-xs font-mono text-cyan-400">Bookmarked Modules</h3>
                  <button onClick={() => setShowBookmarks(false)} className="text-zinc-400 hover:text-white">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                {bookmarks.length === 0 ? (
                  <p className="text-xs text-zinc-500 text-center py-3 font-mono">No bookmarks saved</p>
                ) : (
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {bookmarks.map((b) => (
                      <button
                        key={b.labSlug}
                        onClick={() => {
                          router.push(`/labs/${b.labSlug}`);
                          setShowBookmarks(false);
                        }}
                        className="w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-mono text-zinc-300 hover:bg-zinc-800/80 hover:text-cyan-300 truncate"
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
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-300 font-mono font-bold text-xs">
            <Trophy className="w-4 h-4 text-purple-400" />
            <span>{achievements.length} Badges</span>
          </div>
        </div>
      </div>
    </header>
  );
}

