'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useStore } from '@/lib/store';
import Sidebar from '@/components/layout/Sidebar';
import Navbar from '@/components/layout/Navbar';
import { api } from '@/lib/api';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const { token, setAuth, setProgress, setAchievements, setNotes } = useStore();
  const [loading, setLoading] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  useEffect(() => {
    if (!token) {
      router.push('/login');
      return;
    }

    const loadUserData = async () => {
      try {
        const [meRes, progRes, notesRes] = await Promise.all([
          api.get('/auth/me'),
          api.get('/user/progress'),
          api.get('/user/notes')
        ]);
        
        setAuth(token, meRes.data.user);
        setProgress(progRes.data.progress || []);
        setAchievements(progRes.data.achievements || []);
        setNotes(notesRes.data.notes || []);
        setLoading(false);
      } catch (err) {
        console.error('Failed to sync user session:', err);
        setLoading(false);
      }
    };

    loadUserData();
  }, [token, router, setAuth, setProgress, setAchievements, setNotes]);

  if (loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-[#050508] text-cyan-400 font-mono">
        <div className="flex flex-col items-center gap-4 p-8 rounded-2xl bg-[#0a0b10] border border-zinc-800 shadow-[0_0_30px_rgba(0,240,255,0.15)]">
          <div className="w-10 h-10 border-4 border-t-cyan-400 border-r-transparent border-l-transparent border-b-purple-500 rounded-full animate-spin" />
          <p className="text-xs tracking-widest uppercase animate-pulse text-zinc-300">Initializing InjectionLab Environment...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-[#050508] text-zinc-100 font-sans selection:bg-cyan-500 selection:text-black">
      {/* Mobile Sidebar Overlay Backdrop */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/70 z-40 lg:hidden backdrop-blur-md transition-opacity duration-300"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}
      
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
      
      <div className="flex-1 flex flex-col min-w-0 bg-[#050508]">
        <Navbar onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 p-4 md:p-8 overflow-y-auto max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  );
}

