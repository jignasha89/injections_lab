'use client';

import { useState, useRef } from 'react';
import { useStore } from '@/lib/store';
import { Mail, Calendar, Download, Award } from 'lucide-react';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';

export default function ProfilePage() {
  const { user, progress, achievements } = useStore();
  const [exportingCert, setExportingCert] = useState(false);
  const certRef = useRef<HTMLDivElement>(null);

  const completedCount = progress.filter((p) => p.completed).length;
  const totalLabs = 13;
  const progressPercent = Math.round((completedCount / totalLabs) * 100);

  // Available achievements dictionary
  const achievementDict: { [key: string]: { name: string; desc: string; icon: string } } = {
    first_lab: { name: 'First Contact', desc: 'Successfully completed first injection sandbox module.', icon: '🎯' },
    five_labs: { name: 'Vulnerability Analyst', desc: 'Mastered remediation of 5 target labs.', icon: '🛡️' },
    all_labs: { name: 'Elite Guardian', desc: 'Cleaned all 13 vulnerable sandboxes successfully.', icon: '🏆' },
  };

  const handleDownloadCertificate = async () => {
    if (!certRef.current || completedCount === 0) return;
    setExportingCert(true);

    try {
      const element = certRef.current;
      const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#ffffff',
      });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('l', 'mm', 'a4'); // Landscape format for certificates
      const imgWidth = 297;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;

      pdf.addImage(imgData, 'PNG', 0, 0, imgWidth, imgHeight);
      pdf.save(`${user?.username.toLowerCase()}_injectionlab_certificate.pdf`);
    } catch (err) {
      console.error('Certificate rendering failed:', err);
    } finally {
      setExportingCert(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500 max-w-5xl mx-auto text-zinc-100 font-sans">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3 font-mono">
          Student Profile <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">Authorized Account</span>
        </h2>
        <p className="text-zinc-400 text-sm mt-1.5 font-mono">
          Review learning stats, unlocked cyber achievements, and download course certificates.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* User Card */}
        <div className="md:col-span-1 bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-6 flex flex-col items-center text-center">
          <div className="w-20 h-20 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-3xl font-extrabold shadow-[0_0_20px_rgba(0,240,255,0.2)] font-mono">
            {user?.username ? user.username[0].toUpperCase() : 'U'}
          </div>
          <div>
            <h3 className="text-lg font-bold text-white font-mono">{user?.username}</h3>
            <p className="text-xs text-cyan-400 font-mono capitalize mt-0.5">{user?.role} Account</p>
          </div>

          <div className="w-full border-t border-zinc-800/80 pt-4 space-y-3.5 text-left text-xs font-mono">
            <div className="flex items-center gap-2 text-zinc-300">
              <Mail className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="truncate">{user?.email}</span>
            </div>
            <div className="flex items-center gap-2 text-zinc-300">
              <Calendar className="w-4 h-4 text-zinc-500 shrink-0" />
              <span>Joined August 2026</span>
            </div>
          </div>
        </div>

        {/* Stats Column */}
        <div className="md:col-span-2 space-y-6">
          {/* Progress overview */}
          <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4 font-mono">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
              Lab Mastery Tracker
            </h3>
            <div className="flex items-center gap-4">
              <div className="w-full h-3 rounded-full bg-[#050508] border border-zinc-800 overflow-hidden relative">
                <div
                  className="h-full bg-cyan-400 rounded-full transition-all duration-500 shadow-[0_0_10px_rgba(0,240,255,0.5)]"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
              <span className="text-sm font-extrabold text-cyan-400 shrink-0">
                {completedCount} / {totalLabs}
              </span>
            </div>
            <p className="text-xs text-zinc-400 font-sans">
              Complete all 13 security simulation modules to earn the Cyber Defense Certificate.
            </p>
          </div>

          {/* Certificate Generation */}
          {completedCount > 0 && (
            <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                  <Award className="w-4 h-4 text-emerald-400" /> Course Certificate Unlocked
                </h3>
                <button
                  onClick={handleDownloadCertificate}
                  disabled={exportingCert}
                  className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-emerald-500 hover:bg-emerald-400 text-black active:scale-95 transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.25)]"
                >
                  <Download className="w-4 h-4" />
                  {exportingCert ? 'Generating...' : 'Download Certificate'}
                </button>
              </div>

              {/* Hidden/Visually scaled Certificate layout in A4 Landscape */}
              <div className="border border-zinc-800 p-4 rounded-xl bg-[#050508]">
                <div 
                  ref={certRef} 
                  className="bg-white p-8 border-4 border-double border-blue-600 rounded-2xl text-center space-y-6 max-w-lg mx-auto text-slate-800"
                >
                  <div className="flex justify-center">
                    <Award className="w-10 h-10 text-blue-600" />
                  </div>
                  <div className="space-y-1">
                    <h2 className="text-xl font-bold tracking-widest text-slate-900 uppercase font-serif">Certificate of Completion</h2>
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold font-mono">InjectionLab Security Workspace</p>
                  </div>
                  <div className="space-y-2 font-sans">
                    <p className="text-[11px] text-slate-500 italic font-semibold">This is to certify that student</p>
                    <p className="text-base font-black text-blue-600 font-mono">{user?.username}</p>
                    <p className="text-[11px] text-slate-600 font-semibold max-w-xs mx-auto leading-relaxed">
                      has successfully completed practical lab training mapping and mitigating {completedCount} injection vectors.
                    </p>
                  </div>
                  <div className="border-t border-slate-200 pt-4 flex justify-between items-center text-[8px] text-slate-500 font-mono font-semibold">
                    <span>DATE: {new Date().toLocaleDateString()}</span>
                    <span>VERIFY: injectionlab-cert-ok</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Unlocked Achievements list */}
          <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
            <h3 className="text-xs font-mono font-bold text-zinc-300 uppercase tracking-wider">
              Badges & Achievements ({achievements.length})
            </h3>
            {achievements.length === 0 ? (
              <p className="text-xs text-zinc-500 italic font-mono">No achievements unlocked yet. Finish your first lab to start.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {achievements.map((ach) => {
                  const details = achievementDict[ach.id] || { name: ach.id, desc: 'Unlocked badge', icon: '🎯' };
                  return (
                    <div
                      key={ach.id}
                      className="p-4 bg-[#050508] border border-zinc-800 rounded-xl flex items-start gap-3.5 shadow-sm"
                    >
                      <span className="text-2xl shrink-0 mt-0.5">{details.icon}</span>
                      <div>
                        <h4 className="text-xs font-mono font-bold text-white">{details.name}</h4>
                        <p className="text-[11px] text-zinc-400 mt-1 leading-relaxed font-sans">
                          {details.desc}
                        </p>
                        <span className="text-[9px] text-cyan-400 font-mono font-bold mt-1.5 block">
                          Earned {new Date(ach.earnedAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
