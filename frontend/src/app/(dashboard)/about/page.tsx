'use client';

import { ShieldCheck, Flame, BookOpen, User, FileText, Globe, ExternalLink } from 'lucide-react';

export default function AboutPage() {
  return (
    <div className="space-y-8 animate-in fade-in duration-500 max-w-5xl mx-auto text-slate-800">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">About InjectionLab</h2>
        <p className="text-slate-600 text-sm mt-1">
          Learn, detect, and mitigate critical software injection threats.
        </p>
      </div>

      {/* Main Panel */}
      <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-6">
        <div className="flex items-center gap-4 border-b border-slate-100 pb-6">
          <div className="p-3.5 rounded-2xl bg-blue-50 border border-blue-200 text-blue-600 shadow-sm">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-slate-900">Version 1.0.0 (Educational Release)</h3>
            <p className="text-xs text-slate-500 font-semibold">Intentionally vulnerable local playground environment.</p>
          </div>
        </div>

        <div className="space-y-4 text-xs md:text-sm text-slate-700 leading-relaxed font-semibold">
          <p>
            InjectionLab is an interactive, full-stack educational portal designed for developers and security analysts to master detection and remediation of input validation errors. The system replicates real-world interfaces found in vulnerability suites like PortSwigger Web Security Academy.
          </p>
          <p>
            The project maps threats across 13 specialized lab challenges covering traditional HTTP Header CRLF exploits, legacy file inclusion methods, and modern Large Language Model (LLM) prompt injection vectors.
          </p>
        </div>

        {/* Guidelines section */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-slate-100 pt-6">
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
              <BookOpen className="w-4.5 h-4.5 text-blue-600" /> Educational Blueprint
            </h4>
            <p className="text-xs text-slate-600 leading-relaxed font-semibold">
              Every lab presents full documentation explaining threat mechanisms, side-by-side Monaco code comparisons, and dynamic parameter trace sandboxes.
            </p>
          </div>

          <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
              <Flame className="w-4.5 h-4.5 text-red-600" /> Authorized Usage Only
            </h4>
            <p className="text-xs text-slate-600 leading-relaxed font-semibold">
              This environment is strictly intended for local authorized security learning, classroom training, and academic audits. Never perform attacks on third-party systems.
            </p>
          </div>
        </div>
      </div>

      {/* OWASP & references */}
      <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
        <h3 className="text-sm font-bold tracking-wider text-slate-700 uppercase">
          Reference Material Mappings
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-bold">
          <a
            href="https://owasp.org/www-project-top-ten/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3 bg-slate-50 border border-slate-200 hover:border-blue-400 hover:bg-blue-50/10 rounded-xl flex items-center justify-between group transition-all"
          >
            <span className="text-slate-800 group-hover:text-blue-600">OWASP Top 10</span>
            <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-blue-600" />
          </a>
          <a
            href="https://cwe.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3 bg-slate-50 border border-slate-200 hover:border-blue-400 hover:bg-blue-50/10 rounded-xl flex items-center justify-between group transition-all"
          >
            <span className="text-slate-800 group-hover:text-blue-600">Mitre CWE</span>
            <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-blue-600" />
          </a>
          <a
            href="https://github.com/OWASP/GooseShop"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3 bg-slate-50 border border-slate-200 hover:border-blue-400 hover:bg-blue-50/10 rounded-xl flex items-center justify-between group transition-all"
          >
            <span className="text-slate-800 group-hover:text-blue-600">OWASP Code Project</span>
            <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-blue-600" />
          </a>
        </div>
      </div>
    </div>
  );
}
