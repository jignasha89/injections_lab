'use client';

import { ShieldCheck, Flame, BookOpen, ExternalLink, Cpu, Code2, Terminal, Bot } from 'lucide-react';
import Image from 'next/image';

export default function AboutPage() {
  const domains = [
    {
      title: 'Database & Query Injection',
      assigned: 14,
      color: 'from-blue-500/20 to-cyan-500/20 border-cyan-500/40 text-cyan-400',
      icon: Cpu,
      description: 'Error-based, Union, Blind & Out-of-band SQLi, MongoDB, NoSQL, ORM, XPath & GraphQL injections.'
    },
    {
      title: 'Client-Side & Browser Injection',
      assigned: 14,
      color: 'from-emerald-500/20 to-teal-500/20 border-emerald-500/40 text-emerald-400',
      icon: Code2,
      description: 'Reflected/Stored/DOM XSS, HTMLi, CSS, CSTI, HTTP Parameter Pollution, Formula & WebSockets.'
    },
    {
      title: 'Server-Side & Code Execution Injection',
      assigned: 14,
      color: 'from-amber-500/20 to-orange-500/20 border-amber-500/40 text-amber-400',
      icon: Terminal,
      description: 'Classic OS CMDi, PHP/Py/JS Code Injection, SSTI, XXE, LDAP Authentication Bypass & LaTeX.'
    },
    {
      title: 'Protocol, Header, Log & AI Injection',
      assigned: 13,
      color: 'from-purple-500/20 to-pink-500/20 border-purple-500/40 text-purple-400',
      icon: Bot,
      description: 'CRLF, HTTP Header/Response Splitting, Log4Shell JNDI, SMTP/IMAP, Path Traversal & Prompt Injection.'
    }
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-500 max-w-5xl mx-auto text-zinc-100">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div className="flex items-center gap-4">
          <div className="p-1 rounded-2xl bg-black/40 border border-cyan-500/40 shadow-[0_0_30px_rgba(0,240,255,0.3)] shrink-0">
            <Image 
              src="/logo.png" 
              alt="InjectionLab Logo" 
              width={72}
              height={72}
              className="w-18 h-18 object-contain dark-logo scale-105"
            />
          </div>
          <div>
            <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white flex items-center gap-2 font-mono">
              About Injection<span className="text-cyan-400">Lab</span>
            </h2>
            <p className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest mt-0.5">
              Learn • Test • Secure
            </p>
          </div>
        </div>
      </div>

      {/* Main Overview Panel */}
      <div className="bg-[#0c0d14] p-8 rounded-3xl border border-zinc-800/80 shadow-2xl space-y-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-zinc-800/80 pb-6">
          <div className="flex items-center gap-4">
            <div className="p-3.5 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_20px_rgba(0,240,255,0.15)]">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white font-mono">InjectionLab v1.0.0 (GUI + CLI)</h3>
              <p className="text-xs text-zinc-400">Cybersecurity Institute Defense Project</p>
            </div>
          </div>
          <div className="px-4 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-xs font-bold">
            78 Attack Vectors Cataloged
          </div>
        </div>

        <div className="space-y-4 text-xs md:text-sm text-zinc-300 leading-relaxed font-sans">
          <p>
            <strong className="text-white">InjectionLab</strong> is an interactive web security demonstration tool that cataloged <span className="text-cyan-400 font-mono font-bold">78 distinct injection attack vectors</span> across 7 core technical domains. Designed for execution on both <span className="text-emerald-400 font-mono">Windows</span> and <span className="text-purple-400 font-mono font-bold">Kali Linux</span>.
          </p>
          <p>
            Every vulnerability entry features a complete 5-question viva/defense breakdown (Definition Q1, Attack Mechanics Q2, Live Demo Q3, Secure Remediation Q4, and Real-world CVE Q5) paired with side-by-side vulnerable vs secure code implementations.
          </p>
        </div>

        {/* Dual Operating Modes & Security Policy */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-zinc-800/80 pt-6">
          <div className="p-4 rounded-2xl bg-[#07080d] border border-zinc-800 space-y-2">
            <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-cyan-400" /> Live Scan Mode
            </h4>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Safe, non-destructive heuristic URL scanner designed to identify injectable parameters, header split risks, and input points on target applications without executing destructive payloads.
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-[#07080d] border border-zinc-800 space-y-2">
            <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wider font-mono flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" /> Lab Mode (Docker Sandboxed)
            </h4>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Self-contained simulation sandboxes for all 78 injection types including high-risk vectors (Log4Shell, OS CMDi, SSTI, Prompt Injection, Java Deserialization, YAML/Pickle RCE) safely isolated from host networks.
            </p>
          </div>
        </div>
      </div>

      {/* DOMAIN CLASSIFICATIONS SECTION AT BOTTOM */}
      <div className="bg-[#0c0d14] p-8 rounded-3xl border border-zinc-800/80 shadow-2xl space-y-6">
        <div className="border-b border-zinc-800/80 pb-4 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
              Technical Domains & Attack Classifications
            </h3>
            <p className="text-xs text-zinc-400 mt-1">
              All 78 injection attack types categorized across 7 domain areas
            </p>
          </div>
          <span className="px-3 py-1 rounded-full bg-zinc-800 text-xs font-mono font-bold text-cyan-400 border border-zinc-700">
            7 Domains • 78 Types Total
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {domains.map((domain) => {
            const Icon = domain.icon;
            return (
              <div
                key={domain.title}
                className={`p-5 rounded-2xl bg-gradient-to-br ${domain.color} border space-y-3 backdrop-blur-sm transition-all hover:scale-[1.01]`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-xl bg-black/40 border border-white/10 text-white">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-base font-extrabold text-white font-mono">{domain.title}</h4>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded-lg bg-black/50 text-xs font-mono font-bold text-white border border-white/10">
                    {domain.assigned} Types
                  </span>
                </div>
                <p className="text-xs text-zinc-300 leading-relaxed font-mono">
                  {domain.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* References & Standards */}
      <div className="bg-[#0c0d14] p-6 rounded-3xl border border-zinc-800/80 shadow-2xl space-y-4">
        <h3 className="text-xs font-bold tracking-wider text-zinc-400 uppercase font-mono">
          Security Industry Reference Standards
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <a
            href="https://owasp.org/www-project-top-ten/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 bg-[#07080d] border border-zinc-800 hover:border-cyan-500/50 hover:bg-cyan-500/5 rounded-xl flex items-center justify-between group transition-all text-zinc-300 hover:text-white"
          >
            <span>OWASP Top 10 (2021)</span>
            <ExternalLink className="w-4 h-4 text-zinc-500 group-hover:text-cyan-400" />
          </a>
          <a
            href="https://cwe.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 bg-[#07080d] border border-zinc-800 hover:border-cyan-500/50 hover:bg-cyan-500/5 rounded-xl flex items-center justify-between group transition-all text-zinc-300 hover:text-white"
          >
            <span>MITRE CWE Catalog</span>
            <ExternalLink className="w-4 h-4 text-zinc-500 group-hover:text-cyan-400" />
          </a>
          <a
            href="https://owasp.org/www-project-top-10-for-large-language-model-applications/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 bg-[#07080d] border border-zinc-800 hover:border-cyan-500/50 hover:bg-cyan-500/5 rounded-xl flex items-center justify-between group transition-all text-zinc-300 hover:text-white"
          >
            <span>OWASP Top 10 for LLM</span>
            <ExternalLink className="w-4 h-4 text-zinc-500 group-hover:text-cyan-400" />
          </a>
        </div>
      </div>
    </div>
  );
}
