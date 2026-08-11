'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { useStore } from '@/lib/store';
import { labsData, LabData } from '@/data/labsData';
import LabDemoSandbox from '@/components/labs/LabDemoSandbox';
import LabCodeComparison from '@/components/labs/LabCodeComparison';
import LabQuiz from '@/components/labs/LabQuiz';
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
      <div className="flex h-screen items-center justify-center bg-[#050508] text-cyan-400 font-mono">
        <p className="text-xs tracking-widest uppercase animate-pulse">Mounting Virtual Sandbox...</p>
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
    { id: 'sandbox', name: 'Interactive Demo', icon: FlaskConical },
    { id: 'code', name: 'Vulnerable vs Secure Code', icon: Code2 },
    { id: 'quiz', name: 'Assessment Quiz', icon: Award },
    { id: 'interview', name: 'Interview Prep', icon: HelpCircle },
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-500 text-zinc-100 font-sans">
      {/* Back & Breadcrumb Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-zinc-800/80 pb-4 gap-4">
        <div className="flex items-center gap-3">
          <Link
            href="/labs"
            className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white hover:border-zinc-700 transition-all"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-mono font-bold tracking-widest text-cyan-400">{lab.category}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold border bg-zinc-900 border-zinc-800 text-zinc-400">
                {lab.cwe}
              </span>
            </div>
            <h2 className="text-2xl md:text-3xl font-extrabold text-white font-mono flex items-center gap-2 mt-1">
              #{lab.id} {lab.title}
              {isCompleted && (
                <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono font-bold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" /> Completed
                </span>
              )}
            </h2>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => toggleBookmark(lab.slug)}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-bold border transition-all flex items-center gap-1.5 ${
              isBookmarked
                ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400'
                : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-white'
            }`}
          >
            <Bookmark className="w-4 h-4 fill-current" />
            {isBookmarked ? 'Bookmarked' : 'Bookmark'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-zinc-800/80 gap-2 overflow-x-auto pb-1">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2.5 rounded-t-xl text-xs font-mono font-bold transition-all flex items-center gap-2 border-b-2 shrink-0 ${
                isActive
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10'
                  : 'border-transparent text-zinc-400 hover:text-white hover:bg-zinc-900/50'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.name}
            </button>
          );
        })}
      </div>

      {/* Workspace Display */}
      <div className="min-h-[500px]">
        {activeTab === 'theory' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Side: Educational details */}
            <div className="lg:col-span-2 space-y-6">
              {/* Theory text */}
              <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-3">
                <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-cyan-400" /> Theory Overview
                </h3>
                <p className="text-xs md:text-sm text-zinc-300 leading-relaxed font-sans whitespace-pre-line">{lab.theory}</p>
              </div>

              {/* How it works */}
              <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-3">
                <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" /> Threat Vector & Mechanics
                </h3>
                <p className="text-xs md:text-sm text-zinc-300 leading-relaxed font-sans whitespace-pre-line">{lab.howItWorks}</p>
              </div>

              {/* Impact */}
              <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-3">
                <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Award className="w-4 h-4 text-rose-400" /> Severity & Impact
                </h3>
                <p className="text-xs md:text-sm text-zinc-300 leading-relaxed font-sans whitespace-pre-line">{lab.impact}</p>
              </div>
            </div>

            {/* Right Side: Meta statistics card, Notes */}
            <div className="lg:col-span-1 space-y-6">
              {/* Metrics info panel */}
              <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
                <h4 className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-wider border-b border-zinc-800 pb-2">
                  Threat Classification
                </h4>
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex justify-between">
                    <span className="text-zinc-500">CWE Reference:</span>
                    <span className="text-cyan-400 font-bold">{lab.cwe}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">CVSS Severity:</span>
                    <span className="text-rose-400 font-bold">{lab.cvss} / 10</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">OWASP Mapping:</span>
                    <span className="text-cyan-400 font-bold">{lab.owasp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">CVE Example:</span>
                    <span className="text-white font-bold">{lab.realWorldCVE.id}</span>
                  </div>
                </div>
                <div className="bg-[#050508] border border-zinc-800 rounded-xl p-3.5 text-xs text-zinc-400 italic leading-relaxed">
                  &ldquo;{lab.realWorldCVE.description}&rdquo;
                </div>
              </div>

              {/* Scratch Notebook */}
              <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-3">
                <h4 className="text-xs font-mono font-bold text-zinc-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Student Notes</span>
                  <button
                    onClick={saveNote}
                    disabled={savingNote}
                    className="text-[10px] text-cyan-400 hover:underline font-mono"
                  >
                    {savingNote ? 'saving...' : '[save note]'}
                  </button>
                </h4>
                <textarea
                  value={localNote}
                  onChange={(e) => setLocalNote(e.target.value)}
                  placeholder="Record insights, test payloads, or custom snippets for this lab..."
                  className="w-full h-32 p-3 bg-[#050508] border border-zinc-800 rounded-xl text-xs font-mono text-zinc-100 focus:outline-none focus:border-cyan-500/50 resize-none"
                />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'sandbox' && (
          <LabDemoSandbox slug={lab.slug} title={lab.title} />
        )}

        {activeTab === 'code' && (
          <div className="space-y-6">
            <LabCodeComparison
              vulnerable={lab.codeExample.vulnerable}
              secure={lab.codeExample.secure}
              language={lab.codeExample.language}
            />

            {/* Mitigation rules */}
            <div className="bg-emerald-500/10 border border-emerald-500/30 p-6 rounded-2xl space-y-3">
              <h3 className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Secure Coding Defense Rules
              </h3>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-zinc-300 leading-relaxed font-sans">
                {lab.mitigation.map((mit, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-emerald-400 font-mono">•</span>
                    <span>{mit}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {activeTab === 'quiz' && (
          <LabQuiz slug={lab.slug} quiz={lab.quiz} />
        )}

        {activeTab === 'interview' && (
          <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-5">
            <h3 className="text-xs font-mono font-bold tracking-wider text-zinc-300 uppercase border-b border-zinc-800 pb-3">
              Technical Defense Questions (Viva / Interview Prep)
            </h3>

            <div className="space-y-4">
              {lab.interviewQuestions.map((iq, i) => (
                <div key={i} className="p-4 rounded-xl bg-[#050508] border border-zinc-800 space-y-2">
                  <h4 className="text-xs font-mono font-bold text-cyan-400">
                    Q: {iq.question}
                  </h4>
                  <p className="text-xs text-zinc-300 leading-relaxed pl-3 border-l-2 border-zinc-700 font-sans">
                    {iq.answer}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

