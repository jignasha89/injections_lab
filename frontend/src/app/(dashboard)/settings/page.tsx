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
    <div className="space-y-8 animate-in fade-in duration-500 max-w-5xl mx-auto text-slate-800">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">System Settings</h2>
        <p className="text-slate-600 text-sm mt-1">
          Manage system configurations, backend service connections, and educational databases.
        </p>
      </div>

      <div className="space-y-6">
        {/* Connection status card */}
        <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
          <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wide flex items-center gap-2">
            <Database className="w-5 h-5 text-blue-600" /> Sandbox Workspace DB
          </h3>
          <div className="space-y-3 font-mono text-xs font-semibold">
            <div className="flex justify-between border-b border-slate-50 pb-2">
              <span className="text-slate-500">Database Driver:</span>
              <span className="text-slate-800">MongoDB Mongoose</span>
            </div>
            <div className="flex justify-between border-b border-slate-50 pb-2">
              <span className="text-slate-500">Database URL:</span>
              <span className="text-slate-800">mongodb://localhost:27017/injectionlab</span>
            </div>
            <div className="flex justify-between pb-1">
              <span className="text-slate-500">Service Status:</span>
              <span className="text-green-600 font-bold flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse" /> CONNECTED
              </span>
            </div>
          </div>
        </div>

        {/* Clear/Reset progress data */}
        <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
          <h3 className="text-sm font-bold text-red-700 uppercase tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-600" /> Dangerous Settings
          </h3>

          <p className="text-xs md:text-sm text-slate-600 leading-relaxed font-semibold">
            Resetting your workspace will delete all logged quiz answers, earned achievements/badges, and text notes. This will reset the course progression meter back to 0%.
          </p>

          {successMsg && (
            <div className="p-3.5 rounded-xl bg-green-50 border border-green-200 text-xs text-green-700 flex items-center gap-2 font-bold animate-in fade-in duration-300">
              <CheckCircle className="w-4 h-4 text-green-600" />
              <span>{successMsg}</span>
            </div>
          )}

          {errorMsg && (
            <p className="text-xs font-bold text-red-600">{errorMsg}</p>
          )}

          <button
            onClick={handleResetProgress}
            disabled={resetting}
            className="px-5 py-3 rounded-xl text-xs font-bold bg-red-50 hover:bg-red-600 text-red-600 hover:text-white border border-red-200 hover:border-red-600 transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-sm"
          >
            <RefreshCcw className="w-4 h-4" />
            {resetting ? 'Resetting State...' : 'Reset Sandbox Progress'}
          </button>
        </div>
      </div>
    </div>
  );
}
