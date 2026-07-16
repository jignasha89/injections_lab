'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useStore } from '@/lib/store';

export default function RootPage() {
  const router = useRouter();
  const { token } = useStore();

  useEffect(() => {
    if (token) {
      router.push('/dashboard');
    } else {
      router.push('/login');
    }
  }, [token, router]);

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-cyber-bg text-cyber-accent">
      <div className="flex flex-col items-center gap-3">
        <div className="w-8 h-8 border-4 border-t-cyber-accent border-r-transparent border-l-transparent border-b-cyber-purple rounded-full animate-spin" />
        <p className="text-[10px] font-mono tracking-widest uppercase animate-pulse">Routing secure session...</p>
      </div>
    </div>
  );
}
