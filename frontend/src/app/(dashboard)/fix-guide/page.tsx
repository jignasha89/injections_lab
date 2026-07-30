'use client';

import { useState } from 'react';
import { labsData } from '@/data/labsData';
import { ShieldCheck, FileCode, CheckCircle, BookOpen } from 'lucide-react';

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

  const getFrameworkSnippets = (slug: string) => {
    switch (slug) {
      case 'crlf-injection':
        return {
          nodejs: `// Node.js Express fix\nres.setHeader('Location', url.replace(/[\\r\\n]/g, ''));`,
          python: `# Python Flask fix\nimport re\nsafe_url = re.sub(r'[\\r\\n]', '', user_url)\nreturn redirect(safe_url)`,
          java: `// Java Spring Boot fix\nString safeUrl = userUrl.replaceAll("[\\r\\n]", "");\nresponse.setHeader("Location", safeUrl);`,
          php: `// PHP fix\n$safeUrl = str_replace(array("\\r", "\\n"), '', $userUrl);\nheader("Location: " . $safeUrl);`
        };
      case 'path-traversal-directory-traversal':
        return {
          nodejs: `// Node.js path resolving\nconst resolvedPath = path.resolve(BASE_DIR, filename);\nif (!resolvedPath.startsWith(BASE_DIR + path.sep)) {\n  throw new Error("Traversal attempt detected");\n}`,
          python: `# Python os path check\nimport os\nresolved = os.path.abspath(os.path.join(BASE_DIR, filename))\nif not resolved.startswith(BASE_DIR):\n    raise PermissionError("Access Denied")`,
          java: `// Java File path check\nFile file = new File(BASE_DIR, filename);\nString resolved = file.getCanonicalPath();\nif (!resolved.startsWith(new File(BASE_DIR).getCanonicalPath())) {\n    throw new SecurityException("Access Denied");\n}`,
          php: `// PHP realpath check\n$resolved = realpath($BASE_DIR . '/' . $filename);\nif ($resolved === false || strpos($resolved, $BASE_DIR) !== 0) {\n    die("Access Denied");\n}`
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
    <div className="space-y-8 animate-in fade-in duration-500 text-zinc-100 font-sans">
      {/* Title */}
      <div>
        <h2 className="text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
          Remediation Guide <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">55 Attack Fixes</span>
        </h2>
        <p className="text-zinc-400 text-sm mt-1.5 font-mono">
          Review secure coding standards, framework-specific code fixes, and developer defense manuals.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Lab Selector Sidebar */}
        <div className="lg:col-span-1 space-y-3">
          <h3 className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-wider px-2 mb-2">
            Cataloged Attacks ({labsData.length})
          </h3>
          <div className="space-y-1 max-h-[550px] overflow-y-auto pr-1">
            {labsData.map((lab) => (
              <button
                key={lab.slug}
                onClick={() => setSelectedLabSlug(lab.slug)}
                className={`w-full text-left px-3.5 py-2.5 rounded-xl text-xs font-mono transition-all border ${
                  selectedLabSlug === lab.slug
                    ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300 shadow-[0_0_12px_rgba(0,240,255,0.15)] font-bold'
                    : 'bg-[#0c0d14] border-zinc-800 text-zinc-400 hover:text-white hover:bg-zinc-900'
                }`}
              >
                #{lab.id} {lab.title}
              </button>
            ))}
          </div>
        </div>

        {/* Detailed Fix Sheet */}
        <div className="lg:col-span-3 space-y-6">
          {/* Overview */}
          <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
            <h3 className="font-mono font-bold text-base text-white flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-cyan-400" /> Mitigating #{selectedLab.id} {selectedLab.title}
            </h3>
            <p className="text-xs text-zinc-300 leading-relaxed font-sans">
              {selectedLab.shortDescription}
            </p>

            <div className="border-t border-zinc-800/80 pt-4 space-y-2">
              <h4 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                Vulnerability Mechanics:
              </h4>
              <p className="text-xs text-zinc-400 leading-relaxed whitespace-pre-line font-sans">
                {selectedLab.howItWorks}
              </p>
            </div>
          </div>

          {/* Code Fix Switcher */}
          <div className="bg-[#0c0d14] p-6 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-4">
            <h3 className="font-mono font-bold text-xs text-zinc-300 uppercase tracking-wider flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" /> Framework Reference Fix Implementations
            </h3>

            {/* Language Tabs */}
            <div className="flex border-b border-zinc-800 gap-2 pb-1 overflow-x-auto">
              {languages.map((lang) => (
                <button
                  key={lang.id}
                  onClick={() => setActiveLang(lang.id as any)}
                  className={`px-4 py-2 text-xs font-mono font-bold shrink-0 border-b-2 transition-all ${
                    activeLang === lang.id
                      ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10'
                      : 'border-transparent text-zinc-400 hover:text-white hover:bg-zinc-900'
                  }`}
                >
                  {lang.name}
                </button>
              ))}
            </div>

            {/* Snippet box */}
            <div className="relative bg-[#050508] border border-zinc-800 rounded-xl p-4 font-mono text-xs text-cyan-300 min-h-32 shadow-inner">
              <pre className="whitespace-pre overflow-x-auto leading-relaxed">
                {activeLang === 'nodejs' ? snippets.nodejs : activeLang === 'python' ? snippets.python : activeLang === 'java' ? snippets.java : snippets.php}
              </pre>
            </div>
          </div>

          {/* Secure checklist */}
          <div className="bg-emerald-500/10 border border-emerald-500/30 p-6 rounded-2xl space-y-3">
            <h3 className="font-mono font-bold text-xs text-emerald-400 uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Secure Coding Defense Manual
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-zinc-300 font-sans leading-relaxed">
              {selectedLab.mitigation.map((m, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
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

