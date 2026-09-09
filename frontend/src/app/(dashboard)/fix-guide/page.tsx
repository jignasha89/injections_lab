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
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12">
      {/* Title */}
      <div className="border-b border-border-subtle pb-4">
        <h2 className="text-xl md:text-2xl font-semibold tracking-tight text-[#e2e8f0] flex items-center gap-3">
          Remediation &amp; Defense Manual <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-semibold">55 Attack Fixes</span>
        </h2>
        <p className="text-xs text-[#94a3b8] mt-1">
          Framework-specific secure code reference snippets, input validation rules, and defensive architecture
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Lab Selector Sidebar */}
        <div className="lg:col-span-1 space-y-2">
          <h3 className="text-xs font-semibold text-[#94a3b8] uppercase tracking-wider px-1 mb-2">
            Cataloged Vectors ({labsData.length})
          </h3>
          <div className="space-y-1 max-h-[520px] overflow-y-auto pr-1">
            {labsData.map((lab) => (
              <button
                key={lab.slug}
                onClick={() => setSelectedLabSlug(lab.slug)}
                className={`w-full text-left px-3 py-2 rounded-lg text-xs font-sans transition-colors relative ${
                  selectedLabSlug === lab.slug
                    ? 'bg-surface-base text-[#e2e8f0] font-semibold'
                    : 'bg-transparent text-[#94a3b8] hover:text-[#e2e8f0] hover:bg-surface-base/50'
                }`}
              >
                {selectedLabSlug === lab.slug && (
                  <div className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-blue-600 rounded-r-full" />
                )}
                #{lab.id} {lab.title}
              </button>
            ))}
          </div>
        </div>

        {/* Detailed Fix Sheet */}
        <div className="lg:col-span-3 space-y-5">
          {/* Overview */}
          <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-3">
            <h3 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider flex items-center gap-2 border-b border-border-subtle pb-2">
              <BookOpen className="w-4 h-4 text-blue-500" /> Remediation for #{selectedLab.id} {selectedLab.title}
            </h3>
            <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
              {selectedLab.shortDescription}
            </p>

            <div className="pt-2 space-y-1">
              <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
                Vulnerability Execution Mechanism:
              </h4>
              <p className="text-xs text-[#94a3b8] leading-relaxed whitespace-pre-line font-sans">
                {selectedLab.howItWorks}
              </p>
            </div>
          </div>

          {/* Code Fix Switcher */}
          <div className="bg-surface-base p-5 rounded-md border border-border-subtle  space-y-3">
            <h3 className="text-xs font-semibold text-[#e2e8f0] uppercase tracking-wider flex items-center gap-2">
              <FileCode className="w-4 h-4 text-blue-500" /> Framework Secure Implementation Code
            </h3>

            {/* Language Tabs */}
            <div className="flex border-b border-border-subtle gap-1 pb-1 overflow-x-auto">
              {languages.map((lang) => (
                <button
                  key={lang.id}
                  onClick={() => setActiveLang(lang.id as any)}
                  className={`px-3 py-1.5 text-xs font-medium shrink-0 border-b-2 transition-colors ${
                    activeLang === lang.id
                      ? 'border-blue-600 text-blue-400 bg-[#161b27]'
                      : 'border-transparent text-[#94a3b8] hover:text-[#e2e8f0]'
                  }`}
                >
                  {lang.name}
                </button>
              ))}
            </div>

            {/* Snippet box */}
            <div className="bg-[#0d1017] border border-border-subtle rounded-lg p-4 font-mono text-xs text-blue-300 min-h-28  overflow-x-auto">
              <pre className="whitespace-pre leading-relaxed">
                {activeLang === 'nodejs' ? snippets.nodejs : activeLang === 'python' ? snippets.python : activeLang === 'java' ? snippets.java : snippets.php}
              </pre>
            </div>
          </div>

          {/* Secure checklist */}
          <div className="bg-emerald-500/5 border border-emerald-500/20 p-5 rounded-md space-y-2.5">
            <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Defense &amp; Mitigation Checklist
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-[#94a3b8] font-sans leading-relaxed">
              {selectedLab.mitigation.map((m, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
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
