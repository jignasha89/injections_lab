'use client';

import { ShieldCheck, Flame, BookOpen, ExternalLink, Cpu, Code2, Terminal, Bot } from 'lucide-react';

export default function AboutPage() {
  const domains = [
    {
      title: 'Database & Query Injection',
      assigned: 14,
      borderColor: 'border-l-blue-500',
      icon: Cpu,
      description: 'Error-based, Union, Blind & Out-of-band SQLi, MongoDB, NoSQL, ORM, XPath & GraphQL injections.'
    },
    {
      title: 'Client-Side & Browser Injection',
      assigned: 14,
      borderColor: 'border-l-emerald-500',
      icon: Code2,
      description: 'Reflected/Stored/DOM XSS, HTMLi, CSS, CSTI, HTTP Parameter Pollution, Formula & WebSockets.'
    },
    {
      title: 'Server-Side & Code Execution',
      assigned: 14,
      borderColor: 'border-l-amber-500',
      icon: Terminal,
      description: 'Classic OS CMDi, PHP/Py/JS Code Injection, SSTI, XXE, LDAP Authentication Bypass & LaTeX.'
    },
    {
      title: 'Protocol, Header, Log & AI Injection',
      assigned: 13,
      borderColor: 'border-l-purple-500',
      icon: Bot,
      description: 'CRLF, HTTP Header/Response Splitting, Log4Shell JNDI, SMTP/IMAP, Path Traversal & Prompt Injection.'
    }
  ];

  return (
    <div className="space-y-8 p-6 lg:p-8 text-[#e2e8f0] font-sans pb-16">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border-subtle pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-md bg-surface-base border border-border-subtle p-1.5 flex items-center justify-center shrink-0">
            <img 
              src="/logo.png" 
              alt="InjectionLab Logo" 
              className="w-full h-full object-contain"
            />
          </div>
          <div>
            <h2 className="text-xl md:text-2xl font-semibold tracking-tight text-[#e2e8f0] flex items-center gap-1.5 font-sans">
              About Injection<span className="text-blue-500 font-bold">Lab</span>
            </h2>
            <p className="text-xs text-[#94a3b8]">
              Educational Cyber Vulnerability Assessment &amp; Defense Platform
            </p>
          </div>
        </div>
      </div>

      {/* Main Overview Panel */}
      <div className="bg-surface-base p-6 rounded-md border border-border-subtle  space-y-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-border-subtle pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-[#161b27] border border-border-subtle text-blue-500">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#e2e8f0]">InjectionLab v1.0.0 Architecture</h3>
              <p className="text-xs text-[#94a3b8]">Full-Stack Security Audit &amp; Interactive Defense Suite</p>
            </div>
          </div>
          <span className="px-3 py-1 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono text-xs font-semibold">
            55 Attack Vectors Cataloged
          </span>
        </div>

        <div className="space-y-3 text-xs md:text-sm text-[#94a3b8] leading-relaxed font-sans">
          <p>
            <strong className="text-[#e2e8f0]">InjectionLab</strong> is a comprehensive web security platform cataloging <span className="text-blue-400 font-mono font-semibold">55 distinct injection attack vectors</span> across 4 core technical domains. Designed for execution on both <span className="text-[#e2e8f0] font-medium">Windows</span> and <span className="text-[#e2e8f0] font-medium">Kali Linux</span> environments.
          </p>
          <p>
            Every vulnerability entry features a 5-question defense breakdown (Definition, Attack Mechanics, Live Demo, Secure Remediation, and Real-world CVE Examples) paired with side-by-side vulnerable vs secure code implementations.
          </p>
        </div>

        {/* Dual Operating Modes & Security Policy */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-border-subtle pt-5">
          <div className="p-4 rounded-lg bg-[#0d1017] border border-border-subtle space-y-1">
            <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-blue-400" /> Passive Assessment Engine
            </h4>
            <p className="text-xs text-[#94a3b8] leading-relaxed">
              Safe heuristic URL parameter scanner designed to identify injectable inputs, header risks, and payload delivery points without transmitting destructive code.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-[#0d1017] border border-border-subtle space-y-1">
            <h4 className="text-xs font-semibold text-red-400 uppercase tracking-wider flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" /> Interactive Simulation Sandboxes
            </h4>
            <p className="text-xs text-[#94a3b8] leading-relaxed">
              Self-contained demonstration environments for all 55 injection types including high-risk vectors (Log4Shell, OS CMDi, SSTI, Prompt Injection).
            </p>
          </div>
        </div>
      </div>

      {/* DOMAIN CLASSIFICATIONS SECTION */}
      <div className="bg-surface-base p-6 rounded-md border border-border-subtle  space-y-4">
        <div className="border-b border-border-subtle pb-3 flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider">
              Technical Domains &amp; Attack Vector Classifications
            </h3>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Categorization across 4 technical domain specializations
            </p>
          </div>
          <span className="px-2.5 py-1 rounded bg-[#161b27] text-xs font-mono text-[#94a3b8] border border-border-subtle">
            4 Domains • 55 Vectors
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {domains.map((domain) => {
            const Icon = domain.icon;
            return (
              <div
                key={domain.title}
                className={`p-4 rounded-lg bg-[#0d1017] border border-border-subtle ${domain.borderColor} border-l-4 space-y-2`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4 text-[#e2e8f0]" />
                    <h4 className="text-xs font-semibold text-[#e2e8f0]">{domain.title}</h4>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-[#161b27] text-[10px] font-mono text-[#94a3b8] border border-border-subtle">
                    {domain.assigned} Vectors
                  </span>
                </div>
                <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
                  {domain.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Industry Standards */}
      <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-3">
        <h3 className="text-xs font-semibold tracking-wider text-[#e2e8f0] uppercase">
          Industry Reference Standards &amp; Mappings
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-sans">
          <a
            href="https://owasp.org/www-project-top-ten/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3 bg-[#0d1017] border border-border-subtle hover:border-blue-600/40 rounded-lg flex items-center justify-between group transition-colors text-[#94a3b8] hover:text-[#e2e8f0]"
          >
            <span>OWASP Top 10 (2021)</span>
            <ExternalLink className="w-3.5 h-3.5 text-[#475569] group-hover:text-blue-400" />
          </a>
          <a
            href="https://cwe.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3 bg-[#0d1017] border border-border-subtle hover:border-blue-600/40 rounded-lg flex items-center justify-between group transition-colors text-[#94a3b8] hover:text-[#e2e8f0]"
          >
            <span>MITRE CWE Knowledge Base</span>
            <ExternalLink className="w-3.5 h-3.5 text-[#475569] group-hover:text-blue-400" />
          </a>
          <a
            href="https://owasp.org/www-project-top-10-for-large-language-model-applications/"
            target="_blank"
            rel="noopener noreferrer"
            className="p-3 bg-[#0d1017] border border-border-subtle hover:border-blue-600/40 rounded-lg flex items-center justify-between group transition-colors text-[#94a3b8] hover:text-[#e2e8f0]"
          >
            <span>OWASP Top 10 for LLM</span>
            <ExternalLink className="w-3.5 h-3.5 text-[#475569] group-hover:text-blue-400" />
          </a>
        </div>
      </div>
    </div>
  );
}
