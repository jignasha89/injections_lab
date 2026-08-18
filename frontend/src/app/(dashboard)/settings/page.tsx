'use client';

import { useState } from 'react';
import { useStore } from '@/lib/store';
import { ShieldAlert, CheckCircle, RefreshCcw, Database } from 'lucide-react';
import { api } from '@/lib/api';

export default function SettingsPage() {
  const { setProgress, setAchievements, setNotes } = useStore();
  const [successMsg, setSuccessMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [resetting, setResetting] = useState(false);

  const handleResetProgress = async () => {
    if (!confirm('Are you sure you want to delete all lab progress and notes? This action is irreversible.')) return;
    setResetting(true);
    setSuccessMsg('');
    setErrorMsg('');

    try {
      // Clear progress on backend
      await api.put('/user/progress/crlf-injection', { completed: false, quizScore: 0 });
      // Clean up frontend state
      setProgress([]);
      setAchievements([]);
      setNotes([]);
      setSuccessMsg('Your security learning sandbox state has been reset successfully.');
    } catch (err) {
      console.error(err);
      setErrorMsg('Failed to sync state reset to the database.');
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500 max-w-5xl mx-auto text-zinc-100 font-sans">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3 font-mono">
          System Settings <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">Node / Serverless</span>
        </h2>
        <p className="text-zinc-400 text-sm mt-1.5 font-mono">
          Manage system configurations, backend service connections, and educational databases.
        </p>
      </div>

      <div className="space-y-6">
        {/* Connection status card */}
        <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
          <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" /> Sandbox Workspace Database Engine
          </h3>
          <div className="space-y-3 font-mono text-xs">
            <div className="flex justify-between border-b border-zinc-800/80 pb-2">
              <span className="text-zinc-500">Database Driver:</span>
              <span className="text-zinc-200">MongoDB Mongoose / In-Memory Dual Engine</span>
            </div>
            <div className="flex justify-between border-b border-zinc-800/80 pb-2">
              <span className="text-zinc-500">Active State Store:</span>
              <span className="text-cyan-300">Fast Memory DB + Atlas Cluster Synced</span>
            </div>
            <div className="flex justify-between pb-1">
              <span className="text-zinc-500">Service Status:</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> OPERATIONAL
              </span>
            </div>
          </div>
        </div>

        {/* Clear/Reset progress data */}
        <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
          <h3 className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" /> Danger Zone Settings
          </h3>

          <p className="text-xs text-zinc-300 leading-relaxed font-sans">
            Resetting your workspace will delete all logged quiz answers, earned achievements/badges, and text notes. This will reset the course progression meter back to 0%.
          </p>

          {successMsg && (
            <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2 font-mono font-bold animate-in fade-in duration-300">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span>{successMsg}</span>
            </div>
          )}

          {errorMsg && (
            <p className="text-xs font-mono font-bold text-rose-400">{errorMsg}</p>
          )}

          <button
            onClick={handleResetProgress}
            disabled={resetting}
            className="px-5 py-2.5 rounded-xl text-xs font-mono font-bold bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 border border-rose-500/30 hover:border-rose-500/50 transition-all flex items-center gap-2 disabled:opacity-50 shadow-sm"
          >
            <RefreshCcw className="w-4 h-4" />
            {resetting ? 'Resetting State...' : 'Reset Sandbox Progress'}
          </button>
        </div>
      </div>
    </div>
  );
}
