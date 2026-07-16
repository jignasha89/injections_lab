'use client';

import { useState, useRef } from 'react';
import { useStore } from '@/lib/store';
import { Trophy, ShieldCheck, Mail, User as UserIcon, Calendar, Download, Award } from 'lucide-react';
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
    <div className="space-y-8 animate-in fade-in duration-500 max-w-5xl mx-auto text-slate-800">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Student Profile</h2>
        <p className="text-slate-600 text-sm mt-1">
          Review learning stats, unlocked cyber achievements, and download course certificates.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* User Card */}
        <div className="md:col-span-1 bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-6 flex flex-col items-center text-center">
          <div className="w-20 h-20 rounded-full bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 text-3xl font-extrabold shadow-sm">
            {user?.username[0].toUpperCase()}
          </div>
          <div>
            <h3 className="text-lg font-bold text-slate-900">{user?.username}</h3>
            <p className="text-xs text-slate-500 font-semibold capitalize">{user?.role} Account</p>
          </div>

          <div className="w-full border-t border-slate-100 pt-4 space-y-3.5 text-left text-xs font-semibold">
            <div className="flex items-center gap-2 text-slate-600">
              <Mail className="w-4.5 h-4.5 text-slate-500" />
              <span className="truncate">{user?.email}</span>
            </div>
            <div className="flex items-center gap-2 text-slate-600">
              <Calendar className="w-4.5 h-4.5 text-slate-500" />
              <span>Joined July 2026</span>
            </div>
          </div>
        </div>

        {/* Stats Column */}
        <div className="md:col-span-2 space-y-6">
          {/* Progress overview */}
          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wide">
              Lab Mastery Tracker
            </h3>
            <div className="flex items-center gap-4">
              <div className="w-full h-3.5 rounded-full bg-slate-100 border border-slate-200 overflow-hidden relative">
                <div
                  className="h-full bg-blue-600 rounded-full transition-all duration-500"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
              <span className="text-sm font-mono font-extrabold text-blue-600 shrink-0">
                {completedCount} / {totalLabs}
              </span>
            </div>
            <p className="text-xs text-slate-600 font-semibold">
              Complete all 13 security simulation modules to earn the Cyber Defense Certificate.
            </p>
          </div>

          {/* Certificate Generation */}
          {completedCount > 0 && (
            <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-green-700 uppercase tracking-wide">
                  Course Certificate
                </h3>
                <button
                  onClick={handleDownloadCertificate}
                  disabled={exportingCert}
                  className="px-4 py-2.5 rounded-xl text-xs font-bold bg-green-600 hover:bg-green-700 text-white active:scale-95 transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-sm"
                >
                  <Download className="w-4 h-4" />
                  {exportingCert ? 'Generating...' : 'Download Certificate'}
                </button>
              </div>

              {/* Hidden/Visually scaled Certificate layout in A4 Landscape */}
              <div className="border border-slate-200 p-4 rounded-2xl bg-slate-50">
                <div 
                  ref={certRef} 
                  className="bg-white p-8 border-4 border-double border-blue-600 rounded-2xl text-center space-y-6 max-w-lg mx-auto"
                >
                  <div className="flex justify-center">
                    <Award className="w-10 h-10 text-blue-600" />
                  </div>
                  <div className="space-y-1">
                    <h2 className="text-xl font-bold tracking-widest text-slate-900 uppercase">Certificate of Completion</h2>
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">InjectionLab Security Workspace</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-[11px] text-slate-500 italic font-semibold">This is to certify that student</p>
                    <p className="text-base font-black text-blue-600">{user?.username}</p>
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
          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wide">
              Badges & Achievements ({achievements.length})
            </h3>
            {achievements.length === 0 ? (
              <p className="text-xs text-slate-500 italic font-semibold">No achievements unlocked yet. Finish your first lab to start.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {achievements.map((ach) => {
                  const details = achievementDict[ach.id] || { name: ach.id, desc: 'Unlocked badge', icon: '🎯' };
                  return (
                    <div
                      key={ach.id}
                      className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex items-start gap-3.5 shadow-sm"
                    >
                      <span className="text-2xl shrink-0 mt-0.5">{details.icon}</span>
                      <div>
                        <h4 className="text-xs font-bold text-slate-900">{details.name}</h4>
                        <p className="text-[10px] text-slate-600 font-semibold mt-1 leading-relaxed">
                          {details.desc}
                        </p>
                        <span className="text-[9px] text-slate-400 font-mono font-bold mt-1.5 block">
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
