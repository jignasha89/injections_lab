'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useStore } from '@/lib/store';
import { api } from '@/lib/api';
import { Eye, EyeOff, AlertCircle, ArrowRight } from 'lucide-react';
import { motion } from 'framer-motion';
import ParseTreeGraphic from '@/components/shared/ParseTreeGraphic';

export default function RegisterPage() {
  const router = useRouter();
  const { token, setAuth } = useStore();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
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

    if (password.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    setLoading(true);

    try {
      const res = await api.post('/auth/register', { username, email, password });
      setAuth(res.data.accessToken, res.data.user);
      router.push('/dashboard');
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.error || 'Registration failed. Try a different username/email.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative font-sans overflow-hidden bg-bg-base text-text-primary">
      <motion.div 
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="w-full max-w-md cyber-card p-6 sm:p-8 relative z-10 overflow-visible"
      >
        {/* Header */}
        <div className="w-full flex flex-col items-center justify-center gap-2 mb-6 text-center">
          <div className="w-full max-w-[320px] h-auto flex items-center justify-center p-1">
            <img 
              src="/assets/logo_transparent.png" 
              alt="InjectionLab Logo" 
              className="w-full h-auto max-h-[220px] object-contain drop-shadow-[0_0_25px_rgba(6,182,212,0.45)] hover:scale-[1.02] transition-transform duration-300" 
            />
          </div>
          <div className="mt-1">
            <h1 className="text-xl font-bold tracking-tight text-white font-sans">
              Create Account
            </h1>
            <p className="text-[11px] text-cyan-300 font-mono tracking-widest uppercase font-bold mt-1">
              Join InjectionLab Security Platform
            </p>
          </div>
        </div>

        {error && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mb-5 p-3 rounded-md bg-severity-critical/10 border border-severity-critical/20 text-severity-critical flex items-start gap-2 text-xs"
          >
            <AlertCircle className="w-4 h-4 shrink-0" />
            <p className="leading-tight font-medium">{error}</p>
          </motion.div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Username
            </label>
            <input
              type="text"
              required
              minLength={3}
              maxLength={30}
              placeholder="sec_analyst"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="cyber-input w-full px-3.5 py-2.5 text-sm"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Email address
            </label>
            <input
              type="email"
              required
              placeholder="assessor@injectionlab.local"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="cyber-input w-full px-3.5 py-2.5 text-sm"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                required
                minLength={8}
                placeholder="Min. 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="cyber-input w-full pl-3.5 pr-10 py-2.5 text-sm"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-secondary hover:text-text-primary transition-colors"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="btn-cyber-primary w-full py-2.5 text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? 'Creating account…' : 'Create account'}
              {!loading && <ArrowRight className="w-4 h-4" />}
            </button>
          </div>
        </form>

        {/* Footer */}
        <div className="mt-6 text-center text-xs text-text-secondary border-t border-border-subtle pt-4">
          <span>Already registered? </span>
          <Link href="/login" className="text-brand-primary hover:text-brand-primary-hover font-medium transition-colors">
            Sign in
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
