'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { useStore } from '@/lib/store';
import { labsData, LabData } from '@/data/labsData';
import LabCodeComparison from '@/components/labs/LabCodeComparison';
import { 
  ArrowLeft, 
  BookOpen, 
  FlaskConical, 
  Code2, 
  ShieldCheck, 
  HelpCircle, 
  Bookmark, 
  Award,
  Terminal
} from 'lucide-react';
import Link from 'next/link';

export default function LabDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { progress, toggleBookmark } = useStore();
  const slug = params.slug as string;

  const [lab, setLab] = useState<LabData | null>(null);
  const [activeTab, setActiveTab] = useState<'theory' | 'sandbox' | 'code' | 'quiz' | 'interview'>('theory');
  const [localNote, setLocalNote] = useState('');
  const [savingNote, setSavingNote] = useState(false);

  useEffect(() => {
    const foundLab = labsData.find((l) => l.slug === slug);
    if (!foundLab) {
      router.push('/labs');
      return;
    }
    setLab(foundLab);

    const fetchNote = async () => {
      try {
        const res = await api.get('/user/notes');
        const noteObj = res.data.notes?.find((n: any) => n.labSlug === slug);
        if (noteObj) setLocalNote(noteObj.content);
      } catch (err) {
        console.error('Failed to load notes:', err);
      }
    };
    fetchNote();
  }, [slug, router]);

  if (!lab) {
    return (
      <div className="flex h-64 items-center justify-center bg-[#0b0d11] text-[#94a3b8]">
        <div className="flex flex-col items-center gap-3 p-6 rounded-md bg-surface-base border border-border-subtle">
          <div className="w-6 h-6 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs font-medium">Mounting Virtual Sandbox...</p>
        </div>
      </div>
    );
  }

  const userProg = progress.find((p) => p.labSlug === slug);
  const isCompleted = userProg?.completed || false;
  const isBookmarked = userProg?.bookmarked || false;

  const saveNote = async () => {
    setSavingNote(true);
    try {
      await api.post('/user/notes', { labSlug: slug, content: localNote });
    } catch (err) {
      console.error(err);
    } finally {
      setSavingNote(false);
    }
  };

  const tabs = [
    { id: 'theory', name: 'Theory & Architecture', icon: BookOpen },
    { id: 'code', name: 'Vulnerable vs Secure Code', icon: Code2 },
  ];

  return (
    <div className="space-y-8 p-6 lg:p-8 text-slate-100 font-sans pb-16">
      {/* Back & Breadcrumb Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-border-subtle pb-4 gap-4">
        <div className="flex items-center gap-3">
          <Link
            href="/labs"
            className="p-2 rounded-lg bg-surface-base border border-border-subtle text-[#94a3b8] hover:text-[#e2e8f0] transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] uppercase font-semibold text-blue-400">{lab.category}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161b27] border border-border-subtle text-[#94a3b8]">
                {lab.cwe}
              </span>
            </div>
            <h2 className="text-xl md:text-2xl font-semibold text-[#e2e8f0] flex items-center gap-2 mt-0.5">
              #{lab.id} {lab.title}
              {isCompleted && (
                <span className="text-[11px] px-2.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-medium flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" /> Completed
                </span>
              )}
            </h2>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => toggleBookmark(lab.slug)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors flex items-center gap-1.5 ${
              isBookmarked
                ? 'bg-blue-600/10 border-blue-600/30 text-blue-400'
                : 'bg-surface-base border-border-subtle text-[#94a3b8] hover:text-[#e2e8f0]'
            }`}
          >
            <Bookmark className="w-3.5 h-3.5 fill-current" />
            {isBookmarked ? 'Bookmarked' : 'Bookmark'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-border-subtle gap-1 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2.5 rounded-t-lg text-xs font-medium transition-colors flex items-center gap-2 border-b-2 shrink-0 ${
                isActive
                  ? 'border-blue-600 text-blue-400 bg-surface-base'
                  : 'border-transparent text-[#94a3b8] hover:text-[#e2e8f0] hover:bg-surface-base/50'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.name}
            </button>
          );
        })}
      </div>

      {/* Workspace Display */}
      <div className="min-h-[480px]">
        {activeTab === 'theory' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Side: Educational details */}
            <div className="lg:col-span-2 space-y-5">
              {/* Theory text */}
              <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-2">
                <h3 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider flex items-center gap-2 border-b border-border-subtle pb-2">
                  <BookOpen className="w-4 h-4 text-blue-500" /> Theoretical Overview
                </h3>
                <p className="text-xs md:text-sm text-[#94a3b8] leading-relaxed font-sans whitespace-pre-line">{lab.theory}</p>
              </div>

              {/* How it works */}
              <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-2">
                <h3 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider flex items-center gap-2 border-b border-border-subtle pb-2">
                  <Terminal className="w-4 h-4 text-blue-500" /> Attack Mechanics &amp; Execution Vector
                </h3>
                <p className="text-xs md:text-sm text-[#94a3b8] leading-relaxed font-sans whitespace-pre-line">{lab.howItWorks}</p>
              </div>

              {/* Impact */}
              <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-2">
                <h3 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider flex items-center gap-2 border-b border-border-subtle pb-2">
                  <Award className="w-4 h-4 text-red-400" /> Severity &amp; Potential Business Impact
                </h3>
                <p className="text-xs md:text-sm text-[#94a3b8] leading-relaxed font-sans whitespace-pre-line">{lab.impact}</p>
              </div>
            </div>

            {/* Right Side: Meta statistics card, Notes */}
            <div className="lg:col-span-1 space-y-5">
              {/* Metrics info panel */}
              <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-3">
                <h4 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider border-b border-border-subtle pb-2">
                  Threat Intelligence Classification
                </h4>
                <div className="space-y-2.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">Assigned Engineer:</span>
                    <span className="text-[#e2e8f0] font-medium">{lab.teamMember}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">CWE Identifier:</span>
                    <span className="text-blue-400 font-mono font-medium">{lab.cwe}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">CVSS v3.1 Score:</span>
                    <span className="text-red-400 font-mono font-semibold">{lab.cvss} / 10.0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">OWASP Top 10:</span>
                    <span className="text-[#e2e8f0] font-medium">{lab.owasp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">CVE Reference:</span>
                    <span className="text-blue-400 font-mono font-medium">{lab.realWorldCVE.id}</span>
                  </div>
                </div>
                <div className="bg-[#0d1017] border border-border-subtle rounded-lg p-3 text-xs text-[#94a3b8] italic leading-relaxed">
                  &ldquo;{lab.realWorldCVE.description}&rdquo;
                </div>
              </div>

              {/* Notebook */}
              <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-2">
                <h4 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider flex items-center justify-between">
                  <span>Assessor Notes</span>
                  <button
                    onClick={saveNote}
                    disabled={savingNote}
                    className="text-[11px] text-blue-400 hover:text-blue-300 font-medium"
                  >
                    {savingNote ? 'saving...' : 'Save Note'}
                  </button>
                </h4>
                <textarea
                  value={localNote}
                  onChange={(e) => setLocalNote(e.target.value)}
                  placeholder="Record assessment notes, test payloads, or remediation observations..."
                  className="w-full h-32 p-3 bg-[#0d1017] border border-border-subtle rounded-lg text-xs font-mono text-[#e2e8f0] placeholder-[#475569] focus:outline-none focus:border-blue-600 resize-none"
                />
              </div>
            </div>
          </div>
        )}



        {activeTab === 'code' && (
          <div className="space-y-5">
            <LabCodeComparison
              vulnerable={lab.codeExample.vulnerable}
              secure={lab.codeExample.secure}
              language={lab.codeExample.language}
            />

            {/* Mitigation rules */}
            <div className="bg-emerald-500/5 border border-emerald-500/20 p-5 rounded-md space-y-2.5">
              <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Secure Development Guidelines
              </h3>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-[#94a3b8] leading-relaxed font-sans">
                {lab.mitigation.map((mit, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">•</span>
                    <span>{mit}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
