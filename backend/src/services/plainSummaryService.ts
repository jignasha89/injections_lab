/**
 * Plain-Language Heuristics Service
 * ────────────────────────────────
 * Translates technical vulnerability data into plain, non-technical language
 * so non-technical stakeholders (executives, site owners, product managers)
 * understand their security posture at a glance without reading technical jargon.
 */

export interface PlainFindingDetails {
  simpleSummary: string;
  simpleExplanation: string;
  simpleFix: string[];
  screenshotCaption: string;
}

export type RiskRating = 'Critical' | 'High' | 'Medium' | 'Low';

/**
 * Calculates a friendly risk rating from risk score or finding severities
 */
export function calculateOverallRiskRating(riskScore: number, findings: Array<{ severity: string }>): {
  rating: RiskRating;
  color: 'red' | 'orange' | 'yellow' | 'green';
  badgeClass: string;
} {
  const hasCritical = findings.some((f) => f.severity === 'Critical');
  const hasHigh = findings.some((f) => f.severity === 'High');
  const hasMedium = findings.some((f) => f.severity === 'Medium');

  if (hasCritical || riskScore >= 7.5) {
    return { rating: 'Critical', color: 'red', badgeClass: 'bg-red-500/20 text-red-400 border-red-500/40' };
  }
  if (hasHigh || riskScore >= 5.0) {
    return { rating: 'High', color: 'orange', badgeClass: 'bg-orange-500/20 text-orange-400 border-orange-500/40' };
  }
  if (hasMedium || riskScore >= 2.5) {
    return { rating: 'Medium', color: 'yellow', badgeClass: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' };
  }
  return { rating: 'Low', color: 'green', badgeClass: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' };
}

/**
 * Generates an executive summary paragraph written in everyday language
 */
export function generatePlainLanguageSummary(
  targetUrl: string,
  findings: Array<{ type: string; severity: string; parameter?: string }>,
  riskScore: number
): string {
  if (!findings || findings.length === 0) {
    return `Great news! Our security scan of ${targetUrl} did not find any critical weaknesses or injection vulnerabilities. Your website is currently following good security practices for the tested pages.`;
  }

  const { rating } = calculateOverallRiskRating(riskScore, findings);
  const criticalCount = findings.filter((f) => f.severity === 'Critical').length;
  const highCount = findings.filter((f) => f.severity === 'High').length;
  const totalCount = findings.length;

  const topVulnerabilities = findings.slice(0, 3).map((f) => {
    const t = f.type.toLowerCase();
    if (t.includes('sql')) return "database injection flaws where attackers could access stored records";
    if (t.includes('xss') || t.includes('cross-site')) return "browser script weaknesses where visitor sessions could be stolen";
    if (t.includes('command') || t.includes('code')) return "server control flaws where an attacker could run unauthorized commands";
    if (t.includes('traversal') || t.includes('file')) return "file storage weaknesses where internal server files could be viewed";
    if (t.includes('template') || t.includes('ssti')) return "server template weaknesses";
    if (t.includes('header') || t.includes('crlf')) return "response header weaknesses";
    return f.type;
  });

  const uniqueTop = Array.from(new Set(topVulnerabilities)).join(', and ');

  if (rating === 'Critical' || rating === 'High') {
    return `Attention needed: We completed a security audit of ${targetUrl} and identified ${totalCount} security weak spot${totalCount > 1 ? 's' : ''} (${criticalCount} Critical, ${highCount} High). Most notably, we discovered ${uniqueTop}. If an attacker finds these weak spots, they could potentially view private user data, bypass login screens, or disrupt your website. We recommend sharing the action steps below with your web development team to patch these issues promptly.`;
  }

  return `We audited ${targetUrl} and discovered ${totalCount} moderate security issue${totalCount > 1 ? 's' : ''}. While your core services remain functional, addressing these items will harden your website against unauthorized tampering and improve overall visitor safety.`;
}

/**
 * Produces plain-language details, explanations, and fix checklists for any finding
 */
export function getPlainFindingDetails(finding: {
  type: string;
  injectionFamily?: string;
  parameter?: string;
  location?: string;
  pocPayload?: string;
}): PlainFindingDetails {
  const typeLower = (finding.type || '').toLowerCase();
  const familyLower = (finding.injectionFamily || '').toLowerCase();
  const param = finding.parameter || 'an input field';

  // 1. SQL / NoSQL Database Injections
  if (typeLower.includes('sql') && !typeLower.includes('nosql')) {
    return {
      simpleSummary: `We found a weak spot in the "${param}" input that could let an attacker steal or tamper with your database records.`,
      simpleExplanation: `What this means: Your website accepts data from visitors through "${param}" and sends it directly to your database without checking if it's safe. An attacker can type special database instructions into this field, tricking your database into revealing confidential data — such as customer names, passwords, or payment records — without needing a password.`,
      simpleFix: [
        'Ask your web developer to use "Prepared Statements" (parameterized queries) for all database requests.',
        `Ensure the "${param}" field only accepts valid letters or numbers, rejecting unexpected symbols like quotes or semicolons.`,
        'Never assemble database commands by gluing user-typed text together.',
      ],
      screenshotCaption: `Proof of concept showing how a test database query was triggered through the "${param}" parameter, demonstrating that the database processed unauthorized commands.`,
    };
  }

  if (typeLower.includes('nosql')) {
    return {
      simpleSummary: `Attackers could bypass login screens or access private data by manipulating the "${param}" field.`,
      simpleExplanation: `What this means: The website uses a modern NoSQL database, but doesn't verify the structure of what users enter into "${param}". A hacker can submit special query symbols that trick the website into logging them in as an administrator without knowing the password.`,
      simpleFix: [
        `Enforce strict validation so "${param}" only accepts regular text strings, not objects or special symbols like "$gt" or "$ne".`,
        'Use the database driver\'s built-in schema verification to check all incoming user data.',
        'Apply least-privilege permissions so the database account cannot run administrative commands.',
      ],
      screenshotCaption: `Proof of concept showing how a special NoSQL query operator was accepted by "${param}", causing the database to return records without authorization.`,
    };
  }

  // 2. Cross-Site Scripting (XSS)
  if (typeLower.includes('xss') || typeLower.includes('cross-site scripting')) {
    return {
      simpleSummary: `Malicious code can be injected through "${param}" to hijack your visitors' accounts or steal login cookies.`,
      simpleExplanation: `What this means: When someone types something into "${param}", the website shows it back on the screen without cleaning it up. An attacker could sneak hidden computer code into a link or comment. When your real customers click that link, the attacker's code runs in their browser and can steal their login session or pretend to be them.`,
      simpleFix: [
        'Ask your developer to turn on "HTML Encoding" so any symbols like <script> or " are turned into harmless plain text on the screen.',
        'Add a Content Security Policy (CSP) header to stop unauthorized browser scripts from running.',
        'Mark all login cookies as "HttpOnly" so scripts cannot read or steal them.',
      ],
      screenshotCaption: `Proof of concept showing test script code echoing back in the browser response from "${param}", demonstrating that untrusted browser code could execute.`,
    };
  }

  // 3. Command Injection / Code Execution
  if (typeLower.includes('command') || typeLower.includes('code execution') || typeLower.includes('rce')) {
    return {
      simpleSummary: `High severity: An attacker could take over your hosting server by injecting commands into "${param}".`,
      simpleExplanation: `What this means: Your website runs backend operating system commands using data submitted to "${param}". A skilled attacker can attach extra computer commands (like downloading malware or reading private server files). This could give them full control over your web server.`,
      simpleFix: [
        'Ask your developer to avoid calling system command-line tools with user-submitted data.',
        'Use built-in programming language functions instead of operating system shell commands.',
        `Strictly whitelist what "${param}" is allowed to contain (e.g., only numbers or pre-approved filenames).`,
      ],
      screenshotCaption: `Proof of concept showing server response indicating that system-level commands were interpreted from input supplied to "${param}".`,
    };
  }

  // 4. Path Traversal / File Disclosure
  if (typeLower.includes('traversal') || typeLower.includes('file inclusion') || typeLower.includes('lfi')) {
    return {
      simpleSummary: `Attackers could view private files stored on your server by altering the "${param}" parameter.`,
      simpleExplanation: `What this means: The website looks up files based on the name entered into "${param}". By entering special folder tricks (like "../"), an attacker can navigate outside the intended folder and read internal server configuration files, passwords, or secret keys.`,
      simpleFix: [
        `Do not allow "${param}" to take raw file paths or symbols like ".." and "/".`,
        'Store files using a fixed ID or lookup table rather than direct filenames from users.',
        'Lock the web server process so it can only read from a single designated public directory.',
      ],
      screenshotCaption: `Proof of concept showing navigation symbols (../) processed by the file loader at "${param}", disclosing server path structure.`,
    };
  }

  // 5. Server-Side Template Injection (SSTI)
  if (typeLower.includes('template') || typeLower.includes('ssti')) {
    return {
      simpleSummary: `A flaw in your website template engine allows visitors to run unauthorized calculations and server code.`,
      simpleExplanation: `What this means: Your website uses a template design engine to build web pages. When text from "${param}" is inserted into the template, the server executes expressions found inside it. An attacker can use this to execute commands on the server.`,
      simpleFix: [
        'Pass user input as variables to the template rather than embedding raw text directly into template code.',
        'Turn on template sandboxing mode to block access to system commands.',
        `Clean and validate "${param}" to reject mathematical or template syntax like "{{", "\${", or "<%".`,
      ],
      screenshotCaption: `Proof of concept demonstrating that a test mathematical expression (e.g., {{7*7}}) was evaluated by the template engine into 49.`,
    };
  }

  // 6. SSRF (Server-Side Request Forgery)
  if (typeLower.includes('ssrf') || typeLower.includes('request forgery')) {
    return {
      simpleSummary: `Your web server can be tricked into attacking your private internal network or cloud services.`,
      simpleExplanation: `What this means: Your server downloads content from web addresses specified in "${param}". An attacker can supply an internal address (like your company database or cloud metadata service), making your server act as a proxy to attack systems not visible from the public internet.`,
      simpleFix: [
        'Only allow the server to fetch URLs from a strict whitelist of trusted partner domains.',
        'Block the server from making requests to local internal IP addresses (like 127.0.0.1, 10.x, 192.168.x).',
        'Disable automatic redirects in the web client processing these requests.',
      ],
      screenshotCaption: `Proof of concept showing server initiating outbound connectivity based on user-supplied URL parameter "${param}".`,
    };
  }

  // 7. Generic / Header / Other Injection
  return {
    simpleSummary: `We found an unexpected input handling weakness in "${param}" that should be reviewed.`,
    simpleExplanation: `What this means: The website accepts input through "${param}" without validating it thoroughly. While it may not immediately compromise the server, attackers look for these discrepancies to chain with other flaws or confuse browser security filters.`,
    simpleFix: [
      `Review what kind of data "${param}" is supposed to receive, and reject anything that doesn't match.`,
      'Ensure proper output escaping before displaying user input back to other visitors.',
      'Keep your web server software and third-party frameworks up to date.',
    ],
    screenshotCaption: `Proof of concept showing test payload response indicating improper input handling in "${param}".`,
  };
}

/**
 * Enriches an entire findings list with non-technical summaries, explanations, fixes, and captions
 */
export function enrichFindingsWithPlainLanguage(findings: any[]): any[] {
  if (!findings || !Array.isArray(findings)) return [];

  return findings.map((f) => {
    const plain = getPlainFindingDetails(f);
    return {
      ...f,
      simpleSummary: f.simpleSummary || plain.simpleSummary,
      simpleExplanation: f.simpleExplanation || plain.simpleExplanation,
      simpleFix: f.simpleFix && f.simpleFix.length > 0 ? f.simpleFix : plain.simpleFix,
      screenshotCaption: f.screenshotCaption || plain.screenshotCaption,
    };
  });
}
