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
    // 1. Client-side authentication check
    if (!token) {
      router.push('/login');
      return;
    }

    // 2. Load user stats, progress, achievements, notes from backend
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
        // If API fails, fall back to offline/localStorage but proceed
        setLoading(false);
      }
    };

    loadUserData();
  }, [token, router, setAuth, setProgress, setAchievements, setNotes]);

  if (loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-cyber-bg text-cyber-accent">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-t-cyber-accent border-r-transparent border-l-transparent border-b-cyber-purple rounded-full animate-spin" />
          <p className="text-sm font-mono tracking-widest uppercase animate-pulse">Initializing Lab Environment...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-cyber-bg text-slate-800">
      {/* Mobile Sidebar Overlay Backdrop */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/40 z-40 lg:hidden backdrop-blur-sm transition-opacity duration-300"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}
      
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
      
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 p-6 md:p-10 overflow-y-auto max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  );
}
