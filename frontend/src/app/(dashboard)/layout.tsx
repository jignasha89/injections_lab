'use client';

import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useStore } from '@/lib/store';
import Sidebar from '@/components/layout/Sidebar';
import Navbar from '@/components/layout/Navbar';
import { api } from '@/lib/api';
import { Toaster } from 'sonner';


export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
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
      <div className="flex h-screen w-screen items-center justify-center bg-bg-base text-text-primary">
        <div className="flex flex-col items-center gap-3 p-6 rounded-lg bg-surface-base border border-border-strong">
          <div className="w-8 h-8 border-2 border-brand-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-xs font-medium text-text-secondary">Initializing…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-bg-base text-text-primary font-sans">
      <Toaster 
        theme="dark" 
        position="bottom-right"
        toastOptions={{
          style: {
            background: 'var(--color-surface-hover)',
            border: '1px solid var(--color-border-strong)',
            color: 'var(--color-text-primary)',
          }
        }}
      />
      
      {/* Mobile sidebar overlay */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/60 z-40 lg:hidden backdrop-blur-sm transition-opacity duration-200"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}
      
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
      
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 w-full relative">
          <div className="h-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
