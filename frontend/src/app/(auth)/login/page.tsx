'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { useStore } from '@/lib/store';
import { api } from '@/lib/api';
import { motion } from 'framer-motion';
import { Eye, EyeOff, AlertCircle } from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();
  const { token, setAuth } = useStore();
  const [email, setEmail] = useState('open@gmail.com');
  const [password, setPassword] = useState('open@123');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (token) {
      router.push('/dashboard');
    }
  }, [token, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await api.post('/auth/login', { email, password });
      setAuth(res.data.accessToken, res.data.user);
      router.push('/dashboard');
    } catch (err: unknown) {
      console.error(err);
      const errorObj = err as { response?: { data?: { error?: string } } };
      setError(errorObj.response?.data?.error || 'Invalid credentials or connection error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050508] p-4 relative overflow-hidden text-zinc-100 font-sans">
      {/* Background Cyber Gradients */}
      <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-[140px] pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md bg-[#0c0d14] p-8 rounded-2xl shadow-2xl border border-zinc-800/80 relative z-10 space-y-6"
      >
        {/* Header */}
        <div className="flex flex-col items-center gap-2">
          <div className="p-1 rounded-3xl bg-black/40 border border-cyan-500/40 shadow-[0_0_35px_rgba(0,240,255,0.3)]">
            <Image 
              src="/logo.png" 
              alt="InjectionLab Logo" 
              width={80}
              height={80}
              className="w-20 h-20 object-contain dark-logo scale-105"
            />
          </div>
          <h2 className="text-2xl font-extrabold tracking-tight text-white font-mono mt-1 flex items-center gap-1.5">
            Injection<span className="text-cyan-400">Lab</span>
          </h2>
          <p className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest text-center">
            Learn • Test • Secure
          </p>
          <span className="text-[10px] font-mono text-zinc-400 bg-zinc-900 border border-zinc-800 px-2.5 py-0.5 rounded-full mt-1">
            78 Attack Vectors • Interactive Security Platform
          </span>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-xs text-rose-300 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <p>{error}</p>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 font-mono">
          <div>
            <label className="block text-[10px] font-bold text-zinc-400 uppercase tracking-wider mb-1.5">
              Email Address
            </label>
            <input
              type="email"
              required
              placeholder="e.g., student@injectionlab.local"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl text-xs bg-[#050508] border border-zinc-800 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div>
            <label className="block text-[10px] font-bold text-zinc-400 uppercase tracking-wider mb-1.5">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-3.5 pr-10 py-2.5 rounded-xl text-xs bg-[#050508] border border-zinc-800 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-cyan-500/50"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="flex gap-2 text-[10px]">
            <button
              type="button"
              onClick={() => { setEmail('open@gmail.com'); setPassword('open@123'); }}
              className="flex-1 py-1.5 px-2 rounded-lg bg-zinc-900 border border-cyan-500/30 text-cyan-300 font-bold hover:bg-zinc-800 transition"
            >
              🌐 Public View (open@gmail.com)
            </button>
            <button
              type="button"
              onClick={() => { setEmail('admin@injectionlab.local'); setPassword('admin12345'); }}
              className="flex-1 py-1.5 px-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition"
            >
              🔒 Admin (admin@injectionlab.local)
            </button>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-black shadow-[0_0_15px_rgba(0,240,255,0.25)] transition-all disabled:opacity-50"
          >
            {loading ? 'Authenticating Security Token...' : 'Authorize Session'}
          </button>
        </form>

        {/* Footer */}
        <div className="text-center text-xs text-zinc-400 font-mono">
          <span>New student? </span>
          <Link href="/register" className="text-cyan-400 hover:underline font-bold">
            Create Lab Account
          </Link>
          <div className="mt-4 pt-3 border-t border-zinc-800/80 text-[10px] text-zinc-500 uppercase tracking-widest">
            AUTHORIZED DEMO ENVIRONMENT
          </div>
        </div>
      </motion.div>
    </div>
  );
}

