'use client';

import { useStore } from '@/lib/store';
import { 
  Mail, Calendar, ShieldCheck, Key, 
  Settings, Lock, Smartphone, Globe, 
  Cpu, ChevronRight 
} from 'lucide-react';

export default function ProfilePage() {
  const { user } = useStore();

  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12 max-w-[1300px] mx-auto w-full">
      {/* Title */}
      <div className="border-b border-border-strong pb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-text-primary">
          Profile Settings
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Manage your account identity, security, and application preferences.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* LEFT COLUMN: Identity & Security */}
        <div className="lg:col-span-4 space-y-6">
          
          {/* Profile Card */}
          <div className="cyber-card p-6 flex flex-col items-center text-center space-y-4 shadow-xl">
             <div className="w-24 h-24 rounded-full bg-surface-base border-2 border-border-strong text-text-primary flex items-center justify-center text-4xl font-mono shadow-inner relative overflow-hidden group">
                <div className="absolute inset-0 bg-brand-primary/10 opacity-0 group-hover:opacity-100 transition-opacity" />
                {user?.username?.[0]?.toUpperCase() || 'A'}
             </div>
             <div>
               <h2 className="text-xl font-semibold text-text-primary">{user?.username || 'Assessor'}</h2>
               <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-brand-primary/10 text-brand-primary text-[10px] font-mono font-semibold uppercase tracking-widest mt-3 border border-brand-primary/20">
                 <ShieldCheck className="w-3.5 h-3.5" /> {user?.role || 'Security'} Assessor
               </span>
             </div>
             
             <div className="w-full pt-5 mt-2 border-t border-border-subtle space-y-3.5 text-sm text-text-secondary text-left">
               <div className="flex justify-between items-center">
                 <span className="flex items-center gap-2.5 font-medium"><Mail className="w-4 h-4" /> Email</span>
                 <span className="text-text-primary truncate max-w-[150px]">{user?.email || 'assessor@injectionlab.local'}</span>
               </div>
               <div className="flex justify-between items-center">
                 <span className="flex items-center gap-2.5 font-medium"><Calendar className="w-4 h-4" /> Joined</span>
                 <span className="text-text-primary">October 2023</span>
               </div>
               <div className="flex justify-between items-center">
                 <span className="flex items-center gap-2.5 font-medium"><Globe className="w-4 h-4" /> Last IP</span>
                 <span className="text-text-primary font-mono text-xs">192.168.1.105</span>
               </div>
             </div>
          </div>

          {/* Account Security */}
          {/*
          <div className="cyber-card p-0 overflow-hidden shadow-lg">
             <div className="p-4 border-b border-border-strong bg-surface-hover/30 flex items-center gap-2.5">
               <Lock className="w-4 h-4 text-brand-primary" />
               <h3 className="text-sm font-semibold text-text-primary uppercase tracking-widest">Account Security</h3>
             </div>
             <div className="divide-y divide-border-subtle text-sm">
               <button className="w-full flex items-center justify-between p-4 hover:bg-surface-hover transition-colors group">
                  <div className="flex items-center gap-3">
                    <Key className="w-4 h-4 text-text-secondary group-hover:text-text-primary transition-colors" />
                    <span className="text-text-primary font-medium">Change Password</span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-text-secondary group-hover:translate-x-1 transition-transform" />
               </button>
               <button className="w-full flex items-center justify-between p-4 hover:bg-surface-hover transition-colors group">
                  <div className="flex items-center gap-3">
                    <Smartphone className="w-4 h-4 text-text-secondary group-hover:text-text-primary transition-colors" />
                    <div className="text-left leading-tight">
                      <span className="text-text-primary font-medium block">Two-Factor Auth</span>
                      <span className="text-[11px] text-severity-medium mt-0.5 block">Not configured</span>
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-text-secondary group-hover:translate-x-1 transition-transform" />
               </button>
             </div>
          </div>
          */}
        </div>

        {/* RIGHT COLUMN: Settings & Details */}
        {/*
        <div className="lg:col-span-8 space-y-6">
          
          {/* Workspace Privileges *\/}
          <section>
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-2 mb-4">
              <Cpu className="w-4 h-4" /> Workspace Privileges
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
               <div className="cyber-card p-5 border-l-2 border-l-brand-primary hover:border-brand-primary/50 transition-colors">
                  <h3 className="text-sm font-bold text-text-primary mb-1">Active Scans</h3>
                  <p className="text-xs text-text-secondary mb-4 leading-relaxed">Your role allows initiating active verification payloads against lab targets.</p>
                  <span className="text-[10px] font-mono bg-surface-base px-2 py-1 rounded text-text-primary border border-border-subtle">Authorized</span>
               </div>
               <div className="cyber-card p-5 border-l-2 border-l-emerald-500 hover:border-emerald-500/50 transition-colors">
                  <h3 className="text-sm font-bold text-text-primary mb-1">Export Limits</h3>
                  <p className="text-xs text-text-secondary mb-4 leading-relaxed">You have full capabilities to export unlimited PDF and CSV assessment reports.</p>
                  <span className="text-[10px] font-mono bg-surface-base px-2 py-1 rounded text-text-primary border border-border-subtle">Unlimited</span>
               </div>
            </div>
          </section>

          {/* Application Preferences *\/}
          <section>
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-2 mb-4 mt-8">
              <Settings className="w-4 h-4" /> Application Preferences
            </h2>
            <div className="cyber-card divide-y divide-border-strong overflow-hidden shadow-lg">
               
               <div className="p-5 flex items-center justify-between hover:bg-surface-hover/30 transition-colors">
                  <div className="space-y-1">
                     <h3 className="text-sm font-medium text-text-primary">Email Notifications</h3>
                     <p className="text-xs text-text-secondary">Receive alerts when long-running background scans complete.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" defaultChecked className="sr-only peer" />
                    <div className="w-9 h-5 bg-surface-base peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-text-primary after:border-border-subtle after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-brand-primary border border-border-strong"></div>
                  </label>
               </div>

               <div className="p-5 flex items-center justify-between hover:bg-surface-hover/30 transition-colors">
                  <div className="space-y-1">
                     <h3 className="text-sm font-medium text-text-primary">Sound Effects</h3>
                     <p className="text-xs text-text-secondary">Play an audible chime when a high severity finding is successfully verified.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" />
                    <div className="w-9 h-5 bg-surface-base peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-text-primary after:border-border-subtle after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-brand-primary border border-border-strong"></div>
                  </label>
               </div>

               <div className="p-5 flex items-center justify-between hover:bg-surface-hover/30 transition-colors">
                  <div className="space-y-1">
                     <h3 className="text-sm font-medium text-text-primary">High Contrast Mode</h3>
                     <p className="text-xs text-text-secondary">Increase contrast for better readability of terminal live logs and evidence payloads.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" />
                    <div className="w-9 h-5 bg-surface-base peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-text-primary after:border-border-subtle after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-brand-primary border border-border-strong"></div>
                  </label>
               </div>

            </div>
          </section>

          {/* API Access *\/}
          <section>
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-widest flex items-center gap-2 mb-4 mt-8">
              <Key className="w-4 h-4" /> API Integrations
            </h2>
            <div className="cyber-card p-6 shadow-lg">
               <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                 <div>
                   <h3 className="text-sm font-medium text-text-primary mb-1">Developer API Keys</h3>
                   <p className="text-xs text-text-secondary max-w-lg leading-relaxed">
                     Generate API keys to interact with the Injection Lab engine programmatically via CI/CD pipelines or automated assessment tooling.
                   </p>
                 </div>
                 <div className="w-12 h-12 rounded-lg bg-surface-base border border-border-strong flex items-center justify-center shrink-0">
                   <Cpu className="w-5 h-5 text-brand-primary" />
                 </div>
               </div>
               
               <div className="mt-6 space-y-4">
                 <div className="bg-surface-base border border-border-strong p-3.5 rounded flex items-center justify-between">
                   <div className="flex items-center gap-3">
                     <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                     <code className="text-[13px] font-mono text-text-secondary tracking-widest">sk_prod_••••••••••••••••••••••••</code>
                   </div>
                   <button className="text-xs font-semibold text-text-secondary hover:text-severity-critical transition-colors">Revoke</button>
                 </div>
                 
                 <button className="btn-cyber-primary px-5 py-2.5 text-xs font-semibold w-full sm:w-auto shadow-md">
                   Generate New Key
                 </button>
               </div>
            </div>
          </section>

        </div>
        */}
      </div>
    </div>
  );
}
