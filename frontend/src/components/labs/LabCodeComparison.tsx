'use client';

import { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Copy, Check, Code } from 'lucide-react';

interface CodeComparisonProps {
  vulnerable: string;
  secure: string;
  language: string;
}

export default function LabCodeComparison({ vulnerable, secure, language }: CodeComparisonProps) {
  const [copiedVulnerable, setCopiedVulnerable] = useState(false);
  const [copiedSecure, setCopiedSecure] = useState(false);

  const handleCopy = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Convert language keys for Monaco Editor compat
  const monacoLanguage = language === 'javascript' ? 'javascript' : language === 'python' ? 'python' : language === 'java' ? 'java' : language === 'php' ? 'php' : 'javascript';

  const editorOptions = {
    readOnly: true,
    minimap: { enabled: false },
    fontSize: 12,
    lineNumbers: 'on' as const,
    scrollBeyondLastLine: false,
    theme: 'vs-light',
    domReadOnly: true,
    cursorBlinking: 'solid' as const,
    contextmenu: false,
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 text-slate-800">
      {/* Vulnerable Editor */}
      <div className="bg-white rounded-3xl border border-red-200 overflow-hidden flex flex-col h-[420px] shadow-sm">
        <div className="bg-red-50 border-b border-red-100 px-5 py-3 flex items-center justify-between">
          <span className="text-xs font-bold text-red-700 uppercase tracking-wider flex items-center gap-1.5">
            <Code className="w-4.5 h-4.5 text-red-700" /> Vulnerable Implementation ({language})
          </span>
          <button
            onClick={() => handleCopy(vulnerable, setCopiedVulnerable)}
            className="p-1.5 rounded-xl hover:bg-red-100 text-red-700 transition-all"
            aria-label="Copy vulnerable code"
          >
            {copiedVulnerable ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
        <div className="flex-1 relative border-t border-slate-100">
          <Editor
            height="100%"
            language={monacoLanguage}
            value={vulnerable}
            options={editorOptions}
            theme="vs-light"
          />
        </div>
      </div>

      {/* Secure Editor */}
      <div className="bg-white rounded-3xl border border-green-200 overflow-hidden flex flex-col h-[420px] shadow-sm">
        <div className="bg-green-50 border-b border-green-100 px-5 py-3 flex items-center justify-between">
          <span className="text-xs font-bold text-green-700 uppercase tracking-wider flex items-center gap-1.5">
            <Code className="w-4.5 h-4.5 text-green-700" /> Secure Mitigation ({language})
          </span>
          <button
            onClick={() => handleCopy(secure, setCopiedSecure)}
            className="p-1.5 rounded-xl hover:bg-green-100 text-green-700 transition-all"
            aria-label="Copy secure code"
          >
            {copiedSecure ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
        <div className="flex-1 relative border-t border-slate-100">
          <Editor
            height="100%"
            language={monacoLanguage}
            value={secure}
            options={editorOptions}
            theme="vs-light"
          />
        </div>
      </div>
    </div>
  );
}
