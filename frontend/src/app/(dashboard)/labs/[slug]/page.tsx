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
  Terminal,
  Trophy,
  History,
  FileText
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

    // Load saved note if any
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
      <div className="flex h-screen items-center justify-center bg-white text-slate-800">
        <p className="font-mono text-sm uppercase animate-pulse">Mounting Virtual Sandbox...</p>
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
    <div className="space-y-6 animate-in fade-in duration-500 max-w-none text-slate-800">
      {/* Back & Breadcrumb */}
      <div className="flex items-center justify-between border-b border-slate-200 pb-4">
        <div className="flex items-center gap-3">
          <Link
            href="/labs"
            className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-all shadow-sm"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-widest text-blue-600">{lab.category}</span>
            <h2 className="text-3xl font-extrabold text-slate-900 flex items-center gap-2">
              {lab.title}
              {isCompleted && (
                <span className="text-[10px] px-2.5 py-1 rounded-full bg-green-50 border border-green-200 text-green-700 font-bold flex items-center gap-1">
                  <ShieldCheck className="w-4 h-4" /> Completed
                </span>
              )}
            </h2>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => toggleBookmark(lab.slug)}
            className={`px-4.5 py-3 rounded-xl text-xs md:text-sm font-bold border transition-all flex items-center gap-1.5 shadow-sm ${
              isBookmarked
                ? 'bg-blue-50 border-blue-200 text-blue-600'
                : 'bg-slate-50 border-slate-200 text-slate-600 hover:text-slate-900'
            }`}
          >
            <Bookmark className="w-4 h-4 fill-current" />
            {isBookmarked ? 'Bookmarked' : 'Bookmark'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200 gap-2.5 overflow-x-auto pb-1">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4.5 py-3 rounded-t-xl text-xs md:text-sm font-bold transition-all flex items-center gap-2 border-b-2 shrink-0 ${
                isActive
                  ? 'border-blue-600 text-blue-600 bg-blue-50/40'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Icon className="w-4.5 h-4.5" />
              {tab.name}
            </button>
          );
        })}
      </div>

      {/* Workspace Display */}
      <div className="min-h-[500px]">
        {activeTab === 'theory' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Side: Educational details */}
            <div className="lg:col-span-2 space-y-6">
              {/* Theory text */}
              <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-4">
                <h3 className="text-base md:text-lg font-bold text-slate-900 flex items-center gap-2">
                  <BookOpen className="w-5.5 h-5.5 text-blue-600" /> Theory Overview
                </h3>
                <p className="text-sm md:text-base text-slate-700 leading-relaxed font-semibold whitespace-pre-line">{lab.theory}</p>
              </div>

              {/* How it works */}
              <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-4">
                <h3 className="text-base md:text-lg font-bold text-slate-900 flex items-center gap-2">
                  <Terminal className="w-5.5 h-5.5 text-blue-600" /> Threat Vector & Mechanics
                </h3>
                <p className="text-sm md:text-base text-slate-700 leading-relaxed font-semibold whitespace-pre-line">{lab.howItWorks}</p>
              </div>

              {/* Impact */}
              <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-4">
                <h3 className="text-base md:text-lg font-bold text-slate-900 flex items-center gap-2">
                  <Award className="w-5.5 h-5.5 text-red-600" /> Severity & Impact
                </h3>
                <p className="text-sm md:text-base text-slate-700 leading-relaxed font-semibold whitespace-pre-line">{lab.impact}</p>
              </div>
            </div>

            {/* Right Side: Meta statistics card, Notes */}
            <div className="lg:col-span-1 space-y-6">
              {/* Metrics info panel */}
              <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
                <h4 className="text-xs md:text-sm font-bold text-slate-700 uppercase tracking-wide border-b border-slate-100 pb-2">
                  Threat Classification
                </h4>
                <div className="space-y-3.5 font-mono text-xs md:text-sm font-semibold">
                  <div className="flex justify-between">
                    <span className="text-slate-500">CWE Reference:</span>
                    <span className="text-blue-600 font-bold">{lab.cwe}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">CVSS Severity:</span>
                    <span className="text-red-600 font-bold">{lab.cvss} / 10</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">OWASP Mapping:</span>
                    <span className="text-blue-600 font-bold">{lab.owasp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">CVE Example:</span>
                    <span className="text-slate-800 underline font-bold flex items-center gap-1">
                      {lab.realWorldCVE.id}
                    </span>
                  </div>
                </div>
                <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 text-xs md:text-sm text-slate-655 text-slate-600 italic font-semibold leading-relaxed">
                  &ldquo;{lab.realWorldCVE.description}&rdquo;
                </div>
              </div>

              {/* Scratch Notebook */}
              <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-3">
                <h4 className="text-xs md:text-sm font-bold text-slate-700 uppercase tracking-wide flex items-center justify-between">
                  <span>Student Notes</span>
                  <button
                    onClick={saveNote}
                    disabled={savingNote}
                    className="text-[10px] text-blue-600 hover:text-blue-800 hover:underline lowercase font-mono font-bold"
                  >
                    {savingNote ? 'saving...' : '[save note]'}
                  </button>
                </h4>
                <textarea
                  value={localNote}
                  onChange={(e) => setLocalNote(e.target.value)}
                  placeholder="Record insights, test payloads, or custom snippets for this lab..."
                  className="w-full h-36 p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs md:text-sm font-semibold text-slate-900 focus:bg-white focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100 resize-none"
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

            {/* Mitigation rules checkbox allowlist */}
            <div className="bg-green-50 border border-green-200 p-8 rounded-3xl shadow-sm space-y-4">
              <h3 className="text-sm md:text-base font-bold text-green-800 uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-5.5 h-5.5 text-green-600" /> Secure Coding Defense Standard
              </h3>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-4 list-disc text-xs md:text-sm text-green-950 font-bold leading-relaxed">
                {lab.mitigation.map((mit, i) => (
                  <li key={i}>{mit}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {activeTab === 'quiz' && (
          <LabQuiz slug={lab.slug} quiz={lab.quiz} />
        )}

        {activeTab === 'interview' && (
          <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-6">
            <h3 className="text-sm md:text-base font-bold tracking-wider text-slate-800 uppercase border-b border-slate-100 pb-3">
              Technical Interview Question Prep
            </h3>

            <div className="space-y-4">
              {lab.interviewQuestions.map((iq, i) => (
                <div key={i} className="p-4.5 rounded-2xl bg-slate-50 border border-slate-200 space-y-2.5">
                  <h4 className="text-xs md:text-sm font-bold text-blue-600 uppercase tracking-wider">
                    Q: {iq.question}
                  </h4>
                  <p className="text-xs md:text-sm text-slate-700 leading-relaxed pl-4 border-l-4 border-slate-300 font-semibold">
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
