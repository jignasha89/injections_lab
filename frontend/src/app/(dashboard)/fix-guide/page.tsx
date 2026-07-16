'use client';

import { useState } from 'react';
import { labsData } from '@/data/labsData';
import { useStore } from '@/lib/store';
import { ShieldCheck, HelpCircle, FileCode, CheckCircle, ArrowRight, BookOpen } from 'lucide-react';

export default function FixGuidePage() {
  const [selectedLabSlug, setSelectedLabSlug] = useState(labsData[0].slug);
  const [activeLang, setActiveLang] = useState<'nodejs' | 'python' | 'java' | 'php'>('nodejs');

  const selectedLab = labsData.find((l) => l.slug === selectedLabSlug) || labsData[0];

  const languages = [
    { id: 'nodejs', name: 'Node.js (Express)' },
    { id: 'python', name: 'Python (Flask/Django)' },
    { id: 'java', name: 'Java (Spring Boot)' },
    { id: 'php', name: 'PHP (Vanilla/Laravel)' },
  ];

  // Map framework-specific code snippets
  const getFrameworkSnippets = (slug: string) => {
    switch (slug) {
      case 'crlf-injection':
        return {
          nodejs: `// Node.js Express fix
res.setHeader('Location', url.replace(/[\\r\\n]/g, ''));`,
          python: `# Python Flask fix
import re
safe_url = re.sub(r'[\\r\\n]', '', user_url)
return redirect(safe_url)`,
          java: `// Java Spring Boot fix
String safeUrl = userUrl.replaceAll("[\\r\\n]", "");
response.setHeader("Location", safeUrl);`,
          php: `// PHP fix
$safeUrl = str_replace(array("\\r", "\\n"), '', $userUrl);
header("Location: " . $safeUrl);`
        };
      case 'path-traversal':
        return {
          nodejs: `// Node.js path resolving
const resolvedPath = path.resolve(BASE_DIR, filename);
if (!resolvedPath.startsWith(BASE_DIR + path.sep)) {
  throw new Error("Traversal attempt detected");
}`,
          python: `# Python os path check
import os
resolved = os.path.abspath(os.path.join(BASE_DIR, filename))
if not resolved.startswith(BASE_DIR):
    raise PermissionError("Access Denied")`,
          java: `// Java File path check
File file = new File(BASE_DIR, filename);
String resolved = file.getCanonicalPath();
if (!resolved.startsWith(new File(BASE_DIR).getCanonicalPath())) {
    throw new SecurityException("Access Denied");
}`,
          php: `// PHP realpath check
$resolved = realpath($BASE_DIR . '/' . $filename);
if ($resolved === false || strpos($resolved, $BASE_DIR) !== 0) {
    die("Access Denied");
}`
        };
      default:
        return {
          nodejs: `// Node.js general check\nconst safe = encodeURIComponent(input);`,
          python: `# Python general check\nimport html\nsafe = html.escape(input)`,
          java: `// Java general check\nString safe = org.owasp.encoder.Encode.forHtml(input);`,
          php: `// PHP general check\n$safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');`
        };
    }
  };

  const snippets = getFrameworkSnippets(selectedLabSlug);

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-slate-800">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-slate-900">Remediation Guide</h2>
        <p className="text-slate-600 text-sm mt-1">
          Review secure coding standards, framework-specific code fixes, and developer mitigation manuals.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Lab Selector Sidebar */}
        <div className="lg:col-span-1 space-y-3">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 mb-2">
            Vulnerabilities
          </h3>
          <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
            {labsData.map((lab) => (
              <button
                key={lab.slug}
                onClick={() => setSelectedLabSlug(lab.slug)}
                className={`w-full text-left px-4 py-3 rounded-xl text-xs font-bold transition-all border ${
                  selectedLabSlug === lab.slug
                    ? 'bg-blue-50 border-blue-600 text-blue-600 shadow-sm'
                    : 'bg-slate-50 border-slate-200 text-slate-655 text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                {lab.title}
              </button>
            ))}
          </div>
        </div>

        {/* Detailed Fix Sheet */}
        <div className="lg:col-span-3 space-y-6">
          {/* Overview */}
          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
            <h3 className="font-bold text-lg text-slate-900 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-blue-600" /> Mitigating {selectedLab.title}
            </h3>
            <p className="text-xs md:text-sm text-slate-600 leading-relaxed font-semibold">
              {selectedLab.shortDescription}
            </p>

            <div className="border-t border-slate-100 pt-4 space-y-3">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wide">
                Why This Happens:
              </h4>
              <p className="text-xs md:text-sm text-slate-600 leading-relaxed whitespace-pre-line font-semibold">
                {selectedLab.howItWorks}
              </p>
            </div>
          </div>

          {/* Code Fix Switcher */}
          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
            <h3 className="font-bold text-sm text-slate-800 uppercase tracking-wide flex items-center gap-2">
              <FileCode className="w-5 h-5 text-blue-600" /> Framework Reference Implementations
            </h3>

            {/* Language Tabs */}
            <div className="flex border-b border-slate-100 gap-2 pb-1 overflow-x-auto">
              {languages.map((lang) => (
                <button
                  key={lang.id}
                  onClick={() => setActiveLang(lang.id as any)}
                  className={`px-4 py-2.5 text-xs font-bold shrink-0 border-b-2 transition-all ${
                    activeLang === lang.id
                      ? 'border-blue-600 text-blue-600 bg-blue-50/40'
                      : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                  }`}
                >
                  {lang.name}
                </button>
              ))}
            </div>

            {/* Snippet box */}
            <div className="relative bg-slate-955 border border-slate-900 rounded-2xl p-5 font-mono text-xs text-slate-100 min-h-32 shadow-inner">
              <pre className="whitespace-pre overflow-x-auto leading-relaxed">
                {activeLang === 'nodejs' ? snippets.nodejs : activeLang === 'python' ? snippets.python : activeLang === 'java' ? snippets.java : snippets.php}
              </pre>
            </div>
          </div>

          {/* Secure checklist */}
          <div className="bg-green-50 border border-green-200 p-6 rounded-3xl space-y-4">
            <h3 className="font-bold text-sm text-green-800 uppercase tracking-wide flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-green-600" /> Secure Coding Defense Manual
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-4 list-disc text-xs md:text-sm text-green-950 font-bold leading-relaxed">
              {selectedLab.mitigation.map((m, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <CheckCircle className="w-5 h-5 text-green-600 shrink-0 mt-0.5" />
                  <span>{m}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
