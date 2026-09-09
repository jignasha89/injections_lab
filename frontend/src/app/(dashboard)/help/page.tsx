'use client';

import { 
  HelpCircle, 
  Search, 
  ShieldCheck, 
  Activity, 
  FileText,
  TerminalSquare,
  Cpu
} from 'lucide-react';

export default function HelpPage() {
  return (
    <div className="space-y-8 p-6 lg:p-8 text-text-primary font-sans pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-border-strong pb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-text-primary flex items-center gap-3">
            <HelpCircle className="w-6 h-6 text-brand-primary" />
            Documentation & Help
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Learn how the new 55-Type Injection Lab scanner works and how to interpret your results.
          </p>
        </div>
      </div>

      <div className="space-y-6">
        
        {/* Section 1: Overview */}
        <section className="cyber-card p-6 md:p-8">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-surface-hover rounded-lg border border-border-strong text-brand-primary">
              <TerminalSquare className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-text-primary mb-2">What is Injection Lab?</h2>
              <p className="text-sm text-text-secondary leading-relaxed mb-4">
                Injection Lab is an educational vulnerability assessment tool designed to help you understand, detect, and remediate various injection flaws. It is powered by an industry-leading, high-accuracy scanning engine that actively analyzes web applications for <strong>55 distinct injection families</strong>.
              </p>
              <p className="text-sm text-text-secondary leading-relaxed mb-4">
                Our engine covers everything from classic Error-Based SQLi, XSS, and Path Traversal, to advanced Time-Based Blind SQLi, Server-Side Template Injection (SSTI), XPath Injection, and WAF Bypasses.
              </p>
            </div>
          </div>
        </section>

        {/* Section 2: Architecture */}
        <section className="cyber-card p-6 md:p-8">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-surface-hover rounded-lg border border-border-strong text-brand-primary">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-text-primary mb-2">Dual-Engine Architecture</h2>
              <p className="text-sm text-text-secondary leading-relaxed mb-4">
                Injection Lab runs on a powerful, hybridized backend system:
              </p>
              <ul className="list-disc pl-5 text-sm text-text-secondary space-y-2">
                <li><strong className="text-text-primary">Python FastAPI Engine (Port 8000):</strong> The core brain of the scanner. Built with Python for lightning-fast execution, it contains over 1,300 lines of heuristic logic, differential timing checks, and 55 unique JSON payload configurations. It runs in a highly optimized memory-only mode.</li>
                <li><strong className="text-text-primary">Node.js / Express API (Port 5000):</strong> The nervous system. It orchestrates user history, PDF report generation, and MongoDB persistence. It communicates with the Python engine in real-time via WebSockets to stream live scan progress back to your UI.</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Section 3: How Scanning Works */}
        <section className="cyber-card p-6 md:p-8">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-surface-hover rounded-lg border border-border-strong text-brand-primary">
              <Search className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-text-primary mb-2">Heuristic & Differential Targeting</h2>
              <p className="text-sm text-text-secondary leading-relaxed mb-4">
                Unlike traditional scanners that blindly fire every payload causing massive noise, our engine uses <strong>contextual targeting and differential analysis</strong>.
              </p>
              <ul className="list-disc pl-5 text-sm text-text-secondary space-y-2">
                <li><strong className="text-text-primary">Parameter Inference:</strong> The scanner analyzes parameter names (e.g., <code className="text-brand-primary">?login=</code>, <code className="text-brand-primary">?file=</code>) to infer their purpose and injects context-specific payloads.</li>
                <li><strong className="text-text-primary">Differential Timing:</strong> For Blind Injection (like SQLi or Command Injection), the engine injects deliberate time-delay commands (like <code className="text-brand-primary">sleep(5)</code>) and measures the exact execution latency against baseline ping responses to guarantee an accurate positive.</li>
                <li><strong className="text-text-primary">DOM & Error Parsing:</strong> It parses error codes, structural DOM deviations, and specific regex patterns to detect reflected and error-based flaws without false positives.</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Section 4: Step-by-Step Guide */}
        <section className="cyber-card p-6 md:p-8">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-surface-hover rounded-lg border border-border-strong text-brand-primary">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-text-primary mb-2">Step-by-Step Guide</h2>
              
              <h3 className="text-md font-semibold text-text-primary mt-4 mb-2">How to Run a Scan</h3>
              <ol className="list-decimal pl-5 text-sm text-text-secondary space-y-2 mb-6">
                <li>Ensure both backend servers are running via <code className="text-brand-primary">npm run dev</code>.</li>
                <li>Navigate to the <strong className="text-text-primary">Scanner</strong> page using the sidebar navigation.</li>
                <li>Enter the Target URL of the application you want to test.</li>
                <li>Click the <strong className="text-text-primary">Start Audit</strong> button. Watch the live WebSocket terminal feed as the Python engine executes its attack modules!</li>
              </ol>

              <h3 className="text-md font-semibold text-text-primary mb-2">How to Save & Export Reports</h3>
              <ol className="list-decimal pl-5 text-sm text-text-secondary space-y-2">
                <li>Once a scan completes, the findings (mapped to CVSS and CWE scores) are automatically saved to MongoDB and appear in the <strong className="text-text-primary">History</strong> page.</li>
                <li>Navigate to the <strong className="text-text-primary">History</strong> page and click on any past test to view its detailed audit report.</li>
                <li>In the top right corner of the report, you will find <strong className="text-text-primary">Export CSV</strong> and <strong className="text-text-primary">Download PDF report</strong> buttons.</li>
              </ol>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}

