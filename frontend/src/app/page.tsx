'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useStore } from '@/lib/store';
import { motion } from 'framer-motion';

export default function RootPage() {
  const router = useRouter();
  const { token } = useStore();

  useEffect(() => {
    const timeout = setTimeout(() => {
      if (token) {
        router.push('/dashboard');
      } else {
        router.push('/login');
      }
    }, 500);
    return () => clearTimeout(timeout);
  }, [token, router]);

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-bg-base text-text-primary font-sans relative overflow-hidden">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col items-center gap-4 p-8 rounded-lg cyber-card relative z-10 text-center"
      >
        <div className="w-10 h-10 border-2 border-brand-primary border-t-transparent rounded-full animate-spin" />
        <div className="flex flex-col items-center gap-1">
          <p className="text-sm font-semibold tracking-tight text-text-primary">
            Injection<span className="text-brand-primary">Lab</span>
          </p>
          <p className="text-[10px] font-mono text-text-secondary">
            Establishing connection…
          </p>
        </div>
      </motion.div>
    </div>
  );
}
