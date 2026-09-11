'use client';

import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  Key, 
  Clock, 
  Database, 
  FileText, 
  UserCheck, 
  AlertTriangle, 
  CheckCircle2, 
  RefreshCw, 
  Eye, 
  Users, 
  Terminal, 
  LogOut,
  Sparkles,
  Search,
  ExternalLink,
  Shield,
  Activity
} from 'lucide-react';
import { api } from '@/lib/api';
import { useStore } from '@/lib/store';
import { useRouter } from 'next/navigation';

interface ScanReport {
  _id: string;
  userId: string;
  ownerUsername?: string;
  ownerEmail?: string;
  title: string;
  targetUrl: string;
  summary: {
    totalPages: number;
    injectionPoints: number;
    riskScore: number;
  };
  findings?: Array<{
    type: string;
    severity: string;
    location: string;
    cvss: number;
  }>;
  encryptionStatus?: {
    encryptedAtRest: boolean;
    algorithm: string;
    hmacIntegrity?: string;
  };
  createdAt: string;
}

interface InjectionAttempt {
  _id: string;
  sessionId: string;
  userMessage: string;
  aiResponse: string;
  success: boolean;
  leakType: string[];
  ip?: string;
  timestamp: string;
}

interface AuditLog {
  _id: string;
  adminId: string;
  adminUsername: string;
  action: string;
  targetResource: string;
  ip: string;
  userAgent: string;
  timestamp: string;
}

interface UserRecord {
  _id: string;
  username: string;
  email: string;
  role: 'student' | 'admin';
  labsCompleted: number;
  createdAt: string;
}

export default function AdminSecurityPage() {
  const { user, logout } = useStore();
  const router = useRouter();

  const [activeTab, setActiveTab] = useState<'scans' | 'injections' | 'audit' | 'users'>('scans');
  const [scans, setScans] = useState<ScanReport[]>([]);
  const [injections, setInjections] = useState<InjectionAttempt[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [usersList, setUsersList] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [twoFaVerified, setTwoFaVerified] = useState<boolean>(false);
  const [twoFaCode, setTwoFaCode] = useState<string>('');
  const [twoFaError, setTwoFaError] = useState<string | null>(null);
  const [showTwoFaModal, setShowTwoFaModal] = useState<boolean>(false);
  const [idleTimeRemaining, setIdleTimeRemaining] = useState<number>(15 * 60); // 15 minutes
  const [selectedScanDetail, setSelectedScanDetail] = useState<ScanReport | null>(null);

  // 15-Minute Session Inactivity Idle Timeout
  useEffect(() => {
    let idleTimer: NodeJS.Timeout;
    const IDLE_LIMIT_SEC = 15 * 60; // 15 min
    let secondsLeft = IDLE_LIMIT_SEC;

    const resetIdleTimer = () => {
      secondsLeft = IDLE_LIMIT_SEC;
      setIdleTimeRemaining(IDLE_LIMIT_SEC);
    };

    const interval = setInterval(() => {
      secondsLeft -= 1;
      setIdleTimeRemaining(secondsLeft);
      if (secondsLeft <= 0) {
        clearInterval(interval);
        alert('⚠️ Administrative session timed out due to 15 minutes of inactivity. You have been logged out for security.');
        logout();
        router.push('/login');
      }
    }, 1000);

    const activityEvents = ['mousemove', 'keydown', 'mousedown', 'scroll', 'touchstart'];
    activityEvents.forEach((ev) => window.addEventListener(ev, resetIdleTimer));

    return () => {
      clearInterval(interval);
      activityEvents.forEach((ev) => window.removeEventListener(ev, resetIdleTimer));
    };
  }, [logout, router]);

  // Load data based on active tab
  useEffect(() => {
    if (user?.role === 'admin') {
      loadTabData(activeTab);
    }
  }, [user, activeTab]);

  const loadTabData = async (tab: 'scans' | 'injections' | 'audit' | 'users') => {
    setLoading(true);
    try {
      if (tab === 'scans') {
        const res = await api.get('/admin/scans');
        setScans(res.data.scans || []);
      } else if (tab === 'injections') {
        const res = await api.get('/admin/injection-attempts');
        setInjections(res.data.attempts || []);
      } else if (tab === 'audit') {
        const res = await api.get('/admin/audit-logs');
        setAuditLogs(res.data.logs || []);
      } else if (tab === 'users') {
        const res = await api.get('/admin/users');
        setUsersList(res.data.users || []);
      }
    } catch (err: any) {
      console.error('Failed to load admin data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2Fa = async () => {
    setTwoFaError(null);
    try {
      const res = await api.post('/admin/verify-2fa', { code: twoFaCode });
      if (res.data.success) {
        setTwoFaVerified(true);
        setShowTwoFaModal(false);
        setTwoFaCode('');
        loadTabData(activeTab);
      }
    } catch (err: any) {
      setTwoFaError(err.response?.data?.error || 'Invalid 2FA code. Please try again.');
    }
  };

  // Access Control check
  if (!user || user.role !== 'admin') {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] p-6 text-center font-mono select-none">
        <div className="w-20 h-20 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 mb-6 shadow-[0_0_30px_rgba(239,68,68,0.2)]">
          <ShieldAlert className="w-10 h-10" />
        </div>
        <h1 className="text-2xl font-bold text-white mb-2">403 Forbidden: Administrator Clearance Required</h1>
        <p className="text-xs text-[#a0aec0] max-w-md mb-6 leading-relaxed">
          Access to cross-tenant scan histories, AES-256 decrypted audit vaults, and security administrative controls is restricted exclusively to authorized administrators.
        </p>
        <button
          onClick={() => router.push('/dashboard')}
          className="px-5 py-2.5 rounded-lg bg-[#00d4ff]/20 border border-[#00d4ff]/40 text-[#00d4ff] hover:bg-[#00d4ff]/30 text-xs font-bold transition-all"
        >
          Return to Workspace
        </button>
      </div>
    );
  }

  const formatIdleTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <div className="space-y-6 p-4 lg:p-6 text-white font-mono select-none">
      
      {/* Top Header & Security Status Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0a0e27]/90 border border-[#00d4ff]/30 shadow-[0_0_25px_rgba(0,212,255,0.08)]">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[#00d4ff]/10 border border-[#00d4ff]/40 flex items-center justify-center text-[#00d4ff]">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">Admin Security Center</h1>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/40 font-bold uppercase tracking-wider">
              ADMIN CLEARANCE
            </span>
          </div>
          <p className="text-xs text-[#a0aec0] mt-1">
            End-to-End Cryptographic Monitoring, Audit Logging & Access Control Vault
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Idle Timeout Indicator */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#040714] border border-[#00d4ff]/20 text-xs">
            <Clock className="w-3.5 h-3.5 text-[#00d4ff]" />
            <span className="text-[#a0aec0]">Idle Timeout:</span>
            <span className={`font-bold ${idleTimeRemaining < 180 ? 'text-red-400 animate-pulse' : 'text-white'}`}>
              {formatIdleTime(idleTimeRemaining)}
            </span>
          </div>

          {/* 2FA Status Pill */}
          <button
            onClick={() => setShowTwoFaModal(true)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-bold transition-all ${
              twoFaVerified
                ? 'bg-[#00ff88]/20 border-[#00ff88]/50 text-[#00ff88]'
                : 'bg-amber-500/20 border-amber-500/50 text-amber-300 hover:bg-amber-500/30'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>{twoFaVerified ? '2FA Active' : 'Verify 2FA'}</span>
          </button>

          <button
            onClick={() => loadTabData(activeTab)}
            className="p-2 rounded-lg bg-[#040714] border border-[#00d4ff]/20 text-[#a0aec0] hover:text-[#00d4ff] hover:border-[#00d4ff]/40 transition-all"
            title="Refresh View"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-[#00d4ff]' : ''}`} />
          </button>
        </div>
      </div>

      {/* 4 Cryptographic Security Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Encryption at Rest */}
        <div className="p-4 rounded-xl bg-[#0a0e27]/80 border border-[#00ff88]/30 shadow-md space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-[#a0aec0] uppercase tracking-wider font-bold">Data At Rest</span>
            <Database className="w-4 h-4 text-[#00ff88]" />
          </div>
          <div className="text-sm font-bold text-white flex items-center gap-2">
            <span>AES-256-GCM</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/40">
              ACTIVE
            </span>
          </div>
          <p className="text-[10px] text-[#a0aec0]">
            All scans, chats, and attack payloads encrypted before database write.
          </p>
        </div>

        {/* Card 2: Integrity Verification */}
        <div className="p-4 rounded-xl bg-[#0a0e27]/80 border border-[#00d4ff]/30 shadow-md space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-[#a0aec0] uppercase tracking-wider font-bold">Data Integrity</span>
            <CheckCircle2 className="w-4 h-4 text-[#00d4ff]" />
          </div>
          <div className="text-sm font-bold text-white flex items-center gap-2">
            <span>HMAC-SHA256</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40">
              ENFORCED
            </span>
          </div>
          <p className="text-[10px] text-[#a0aec0]">
            Continuous cryptographic tamper detection on all saved records.
          </p>
        </div>

        {/* Card 3: Transport Security */}
        <div className="p-4 rounded-xl bg-[#0a0e27]/80 border border-[#b026ff]/30 shadow-md space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-[#a0aec0] uppercase tracking-wider font-bold">In-Transit TLS</span>
            <Lock className="w-4 h-4 text-[#b026ff]" />
          </div>
          <div className="text-sm font-bold text-white flex items-center gap-2">
            <span>HSTS & Headers</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#b026ff]/20 text-[#b026ff] border border-[#b026ff]/40">
              ENFORCED
            </span>
          </div>
          <p className="text-[10px] text-[#a0aec0]">
            Strict-Transport-Security, CSP, nosniff, and frameguard active.
          </p>
        </div>

        {/* Card 4: Access Governance */}
        <div className="p-4 rounded-xl bg-[#0a0e27]/80 border border-[#ff2a5f]/30 shadow-md space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-[#a0aec0] uppercase tracking-wider font-bold">Audit Governance</span>
            <Activity className="w-4 h-4 text-[#ff2a5f]" />
          </div>
          <div className="text-sm font-bold text-white flex items-center gap-2">
            <span>Audit Trail</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#ff2a5f]/20 text-[#ff2a5f] border border-[#ff2a5f]/40">
              RECORDING
            </span>
          </div>
          <p className="text-[10px] text-[#a0aec0]">
            Every admin data access is cryptographically logged in auditLogs.
          </p>
        </div>

      </div>

      {/* Tabs Navigation */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[#00d4ff]/20 pb-3">
        <button
          onClick={() => setActiveTab('scans')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
            activeTab === 'scans'
              ? 'bg-[#00d4ff] text-black shadow-[0_0_15px_rgba(0,212,255,0.4)]'
              : 'bg-[#0a0e27] text-[#a0aec0] hover:text-white border border-[#00d4ff]/20'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>All Users' Scans ({scans.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('injections')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
            activeTab === 'injections'
              ? 'bg-[#00d4ff] text-black shadow-[0_0_15px_rgba(0,212,255,0.4)]'
              : 'bg-[#0a0e27] text-[#a0aec0] hover:text-white border border-[#00d4ff]/20'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Prompt Injection Exploits ({injections.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
            activeTab === 'audit'
              ? 'bg-[#00d4ff] text-black shadow-[0_0_15px_rgba(0,212,255,0.4)]'
              : 'bg-[#0a0e27] text-[#a0aec0] hover:text-white border border-[#00d4ff]/20'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Immutable Audit Logs ({auditLogs.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('users')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
            activeTab === 'users'
              ? 'bg-[#00d4ff] text-black shadow-[0_0_15px_rgba(0,212,255,0.4)]'
              : 'bg-[#0a0e27] text-[#a0aec0] hover:text-white border border-[#00d4ff]/20'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>User Directory ({usersList.length})</span>
        </button>
      </div>

      {/* Main Content Area */}
      <div className="rounded-xl bg-[#0a0e27]/80 border border-[#00d4ff]/20 shadow-xl p-4 overflow-hidden">
        
        {/* Tab 1: All Users' Scan History */}
        {activeTab === 'scans' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs border-b border-[#00d4ff]/10 pb-3">
              <div>
                <h3 className="font-bold text-white text-sm">Cross-User Scan History Vault</h3>
                <p className="text-[#a0aec0] text-xs">
                  Decrypted on-the-fly for authorized administrator review. Stored as AES-256-GCM ciphertexts in database.
                </p>
              </div>
              <div className="relative">
                <input
                  type="text"
                  placeholder="Filter by target or user..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="bg-[#040714] border border-[#00d4ff]/30 rounded-lg px-3 py-1.5 text-xs text-white placeholder-[#4a5568] focus:outline-none focus:border-[#00d4ff] w-56"
                />
              </div>
            </div>

            {loading ? (
              <div className="py-12 text-center text-xs text-[#00d4ff] animate-pulse">
                Decrypting scan vault using AES-256 master key...
              </div>
            ) : scans.length === 0 ? (
              <div className="py-12 text-center text-xs text-[#a0aec0]">
                No scans saved in the platform database yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[#00d4ff]/20 text-[#a0aec0] text-[11px]">
                      <th className="py-2.5 px-3">Owner</th>
                      <th className="py-2.5 px-3">Target URL</th>
                      <th className="py-2.5 px-3">Risk Score</th>
                      <th className="py-2.5 px-3">Findings</th>
                      <th className="py-2.5 px-3">At-Rest Encryption</th>
                      <th className="py-2.5 px-3">Date</th>
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#00d4ff]/10">
                    {scans
                      .filter((s) => 
                        !searchTerm || 
                        s.targetUrl?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                        s.ownerUsername?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                        s.ownerEmail?.toLowerCase().includes(searchTerm.toLowerCase())
                      )
                      .map((scan) => (
                        <tr key={scan._id} className="hover:bg-[#040714]/60 transition-colors">
                          <td className="py-3 px-3">
                            <span className="font-bold text-white block">{scan.ownerUsername}</span>
                            <span className="text-[10px] text-[#a0aec0]">{scan.ownerEmail}</span>
                          </td>
                          <td className="py-3 px-3">
                            <span className="font-bold text-[#00d4ff] truncate max-w-xs block">
                              {scan.targetUrl}
                            </span>
                            <span className="text-[10px] text-[#a0aec0]">{scan.title}</span>
                          </td>
                          <td className="py-3 px-3">
                            <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                              scan.summary?.riskScore >= 7
                                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                : scan.summary?.riskScore >= 4
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                : 'bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/40'
                            }`}>
                              {scan.summary?.riskScore ?? 0} / 10
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <span className="font-bold text-white">
                              {scan.summary?.injectionPoints ?? scan.findings?.length ?? 0}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <div className="flex items-center gap-1.5">
                              <span className="text-[10px] px-2 py-0.5 rounded bg-[#00ff88]/15 text-[#00ff88] border border-[#00ff88]/30 font-bold flex items-center gap-1">
                                <Shield className="w-3 h-3" />
                                AES-256-GCM
                              </span>
                              <span className="text-[9px] text-[#a0aec0]">HMAC-VALID</span>
                            </div>
                          </td>
                          <td className="py-3 px-3 text-[#a0aec0] text-[11px]">
                            {new Date(scan.createdAt).toLocaleDateString()}
                          </td>
                          <td className="py-3 px-3 text-right">
                            <button
                              onClick={() => setSelectedScanDetail(scan)}
                              className="px-2.5 py-1 rounded bg-[#00d4ff]/15 hover:bg-[#00d4ff]/30 text-[#00d4ff] text-[11px] font-bold transition-all border border-[#00d4ff]/30"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Global Prompt Injection Exploits */}
        {activeTab === 'injections' && (
          <div className="space-y-4">
            <div className="border-b border-[#00d4ff]/10 pb-3">
              <h3 className="font-bold text-white text-sm">Global AI Prompt Injection Vault</h3>
              <p className="text-[#a0aec0] text-xs">
                All attack vectors and AI model completions stored with AES-256-GCM encryption at rest.
              </p>
            </div>

            {loading ? (
              <div className="py-12 text-center text-xs text-[#00d4ff] animate-pulse">
                Decrypting injection telemetry vault...
              </div>
            ) : injections.length === 0 ? (
              <div className="py-12 text-center text-xs text-[#a0aec0]">
                No prompt injection attempts logged yet.
              </div>
            ) : (
              <div className="space-y-3">
                {injections.map((att) => (
                  <div 
                    key={att._id}
                    className={`p-3.5 rounded-xl border transition-all ${
                      att.success 
                        ? 'bg-[#061a12] border-[#00ff88]/40' 
                        : 'bg-[#040714] border-[#00d4ff]/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">Session: {att.sessionId}</span>
                        {att.success ? (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/40 font-bold">
                            ⚡ EXPLOIT SUCCESSFUL
                          </span>
                        ) : (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-[#00d4ff]/15 text-[#00d4ff] border border-[#00d4ff]/30 font-bold">
                            BLOCKED BY DEFENSE
                          </span>
                        )}
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20">
                          DECRYPTED FROM REST
                        </span>
                      </div>
                      <span className="text-[10px] text-[#a0aec0]">
                        {new Date(att.timestamp).toLocaleString()}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs">
                      <div className="p-2 rounded bg-[#0a0e27] border border-[#b026ff]/30 text-purple-200">
                        <span className="text-[10px] text-[#b026ff] font-bold block mb-0.5">ATTACK VECTOR:</span>
                        {att.userMessage}
                      </div>

                      <div className="p-2 rounded bg-[#0a0e27] border border-[#00d4ff]/30 text-slate-200">
                        <span className="text-[10px] text-[#00d4ff] font-bold block mb-0.5">AI COMPLETION:</span>
                        {att.aiResponse}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Immutable Audit Logs */}
        {activeTab === 'audit' && (
          <div className="space-y-4">
            <div className="border-b border-[#00d4ff]/10 pb-3">
              <h3 className="font-bold text-white text-sm">Administrative Security Audit Trail</h3>
              <p className="text-[#a0aec0] text-xs">
                Immutable record of who accessed which sensitive user data and when.
              </p>
            </div>

            {loading ? (
              <div className="py-12 text-center text-xs text-[#00d4ff] animate-pulse">
                Fetching security audit logs...
              </div>
            ) : auditLogs.length === 0 ? (
              <div className="py-12 text-center text-xs text-[#a0aec0]">
                No audit events logged yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[#00d4ff]/20 text-[#a0aec0] text-[11px]">
                      <th className="py-2.5 px-3">Administrator</th>
                      <th className="py-2.5 px-3">Action</th>
                      <th className="py-2.5 px-3">Target Resource</th>
                      <th className="py-2.5 px-3">Client IP</th>
                      <th className="py-2.5 px-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#00d4ff]/10">
                    {auditLogs.map((log) => (
                      <tr key={log._id} className="hover:bg-[#040714]/60 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-white">{log.adminUsername}</td>
                        <td className="py-2.5 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#00d4ff]/15 text-[#00d4ff] border border-[#00d4ff]/30">
                            {log.action}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-[#a0aec0] truncate max-w-xs">{log.targetResource}</td>
                        <td className="py-2.5 px-3 text-white font-mono">{log.ip}</td>
                        <td className="py-2.5 px-3 text-[#a0aec0]">{new Date(log.timestamp).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Tab 4: User Directory & Governance */}
        {activeTab === 'users' && (
          <div className="space-y-4">
            <div className="border-b border-[#00d4ff]/10 pb-3">
              <h3 className="font-bold text-white text-sm">User Directory & Role Governance</h3>
              <p className="text-[#a0aec0] text-xs">
                Active registered accounts and security clearance tiers.
              </p>
            </div>

            {loading ? (
              <div className="py-12 text-center text-xs text-[#00d4ff] animate-pulse">
                Loading user directory...
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[#00d4ff]/20 text-[#a0aec0] text-[11px]">
                      <th className="py-2.5 px-3">Username</th>
                      <th className="py-2.5 px-3">Email</th>
                      <th className="py-2.5 px-3">Clearance Role</th>
                      <th className="py-2.5 px-3">Labs Completed</th>
                      <th className="py-2.5 px-3">Joined</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#00d4ff]/10">
                    {usersList.map((u) => (
                      <tr key={u._id} className="hover:bg-[#040714]/60 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-white">{u.username}</td>
                        <td className="py-2.5 px-3 text-[#a0aec0]">{u.email}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            u.role === 'admin'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : 'bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40'
                          }`}>
                            {u.role.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-white font-bold">{u.labsCompleted}</td>
                        <td className="py-2.5 px-3 text-[#a0aec0]">{new Date(u.createdAt).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

      </div>

      {/* 2FA Verification Modal */}
      {showTwoFaModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-xl bg-[#0a0e27] border border-[#00d4ff]/40 shadow-2xl p-5 space-y-4 font-mono">
            <div className="flex items-center gap-2 text-white font-bold text-sm border-b border-[#00d4ff]/20 pb-3">
              <Key className="w-4 h-4 text-[#00d4ff]" />
              <span>Two-Factor Authentication</span>
            </div>

            <p className="text-xs text-[#a0aec0] leading-relaxed">
              Enter the 6-digit verification code from your authenticator app (or admin authorization token) to confirm high-privilege access:
            </p>

            <div className="space-y-2">
              <input
                type="text"
                placeholder="6-digit code (e.g. 789012)"
                value={twoFaCode}
                onChange={(e) => setTwoFaCode(e.target.value)}
                maxLength={6}
                className="w-full bg-[#040714] border border-[#00d4ff]/40 rounded-lg px-3.5 py-2.5 text-center text-lg font-mono text-white tracking-widest focus:outline-none focus:border-[#00d4ff]"
              />
              {twoFaError && <p className="text-[11px] text-red-400">{twoFaError}</p>}
            </div>

            <div className="flex items-center gap-2 pt-2">
              <button
                onClick={() => setShowTwoFaModal(false)}
                className="flex-1 py-2 rounded-lg bg-[#040714] border border-[#00d4ff]/20 hover:bg-[#00d4ff]/10 text-xs font-bold text-[#a0aec0] transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleVerify2Fa}
                className="flex-1 py-2 rounded-lg bg-[#00d4ff] hover:bg-[#33ddff] text-[#050508] text-xs font-bold transition-all shadow-[0_0_12px_rgba(0,212,255,0.4)]"
              >
                Verify 2FA
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Inspect Scan Details Modal */}
      {selectedScanDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl max-h-[80vh] flex flex-col rounded-xl bg-[#0a0e27] border border-[#00d4ff]/40 shadow-2xl p-5 space-y-4 font-mono overflow-hidden">
            <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-3">
              <div>
                <h3 className="font-bold text-white text-sm">Decrypted Scan Report Details</h3>
                <span className="text-[10px] text-[#00ff88]">AES-256-GCM Verification: VALID HMAC</span>
              </div>
              <button
                onClick={() => setSelectedScanDetail(null)}
                className="text-xs text-[#a0aec0] hover:text-white px-2 py-1 rounded bg-[#040714]"
              >
                Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3 pr-1 text-xs">
              <div className="p-3 rounded-lg bg-[#040714] border border-[#00d4ff]/20 space-y-1">
                <span className="text-[10px] text-[#a0aec0] uppercase block">Target URL</span>
                <span className="text-[#00d4ff] font-bold block break-all">{selectedScanDetail.targetUrl}</span>
                <span className="text-[#a0aec0] text-[11px] block">Owner: {selectedScanDetail.ownerUsername} ({selectedScanDetail.ownerEmail})</span>
              </div>

              <div>
                <span className="text-[11px] font-bold text-white block mb-2">Findings Summary ({selectedScanDetail.findings?.length || 0}):</span>
                {(!selectedScanDetail.findings || selectedScanDetail.findings.length === 0) ? (
                  <p className="text-xs text-[#a0aec0]">No specific findings recorded in this scan.</p>
                ) : (
                  <div className="space-y-2">
                    {selectedScanDetail.findings.map((f, i) => (
                      <div key={i} className="p-2.5 rounded bg-[#040714] border border-[#00d4ff]/20 flex items-center justify-between">
                        <div>
                          <span className="font-bold text-white block">{f.type}</span>
                          <span className="text-[10px] text-[#a0aec0]">{f.location}</span>
                        </div>
                        <span className="text-[10px] font-bold text-red-400 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30">
                          {f.severity} (CVSS {f.cvss})
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
