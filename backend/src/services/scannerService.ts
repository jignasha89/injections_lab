/**
 * Scanner Service
 * Performs HEURISTIC/STRUCTURAL analysis of URLs for educational purposes.
 * No real HTTP requests are made to target systems.
 * This is for demonstrating injection concepts only.
 */

interface ScanFinding {
  type: string;
  location: string;
  parameter?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  recommendation: string;
}

interface ScanResult {
  targetUrl: string;
  parameters: string[];
  pathSegments: string[];
  potentialInjectionPoints: {
    type: string;
    location: string;
    risk: string;
  }[];
  findings: ScanFinding[];
  techStackClues: string[];
  summary: {
    totalPages: number;
    injectionPoints: number;
    parameters: number;
    riskScore: number;
    owaspCoverage: string[];
  };
}

const INJECTION_PATTERNS: { pattern: RegExp; type: string; severity: ScanFinding['severity']; cvss: number; cwe: string; owasp: string; description: string; recommendation: string }[] = [
  {
    pattern: /(\?|&)(redirect|url|return|next|goto|dest|destination|continue|forward|target)=/i,
    type: 'Open Redirect / Host Header Injection',
    severity: 'High',
    cvss: 7.4,
    cwe: 'CWE-601',
    owasp: 'A03:2021',
    description: 'URL parameter may be used for redirect, potentially enabling Host Header Injection or Open Redirect attacks.',
    recommendation: 'Validate and whitelist all redirect targets. Never trust user-supplied redirect URLs.',
  },
  {
    pattern: /(\?|&)(file|path|dir|folder|document|page|include|template)=/i,
    type: 'Path Traversal',
    severity: 'Critical',
    cvss: 9.1,
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    description: 'File or path parameter detected. Could be vulnerable to Path Traversal (../../etc/passwd) or Null Byte injection.',
    recommendation: 'Use allowlists for file paths. Canonicalize paths and reject directory traversal sequences.',
  },
  {
    pattern: /(\?|&)(email|to|from|cc|bcc|subject|recipient)=/i,
    type: 'Email Header Injection / SMTP Injection',
    severity: 'High',
    cvss: 7.5,
    cwe: 'CWE-93',
    owasp: 'A03:2021',
    description: 'Email-related parameter detected. Could be vulnerable to Email Header Injection or SMTP Injection via CRLF sequences.',
    recommendation: 'Sanitize all email inputs. Reject CRLF characters. Use parameterized email APIs.',
  },
  {
    pattern: /(\?|&)(log|logger|debug|trace|msg|message|event)=/i,
    type: 'Log Injection',
    severity: 'Medium',
    cvss: 5.3,
    cwe: 'CWE-117',
    owasp: 'A09:2021',
    description: 'Logging parameter detected. Could be vulnerable to Log Injection or Log4Shell-style attacks.',
    recommendation: 'Sanitize log inputs. Use structured logging. Never log raw user-supplied data.',
  },
  {
    pattern: /(\?|&)(q|search|query|find|keyword|term|s)=/i,
    type: 'CRLF Injection / HTTP Header Injection',
    severity: 'Medium',
    cvss: 6.1,
    cwe: 'CWE-113',
    owasp: 'A03:2021',
    description: 'Search/query parameter detected. Could be vulnerable to CRLF Injection if value is reflected in HTTP headers.',
    recommendation: 'Strip or encode CR (\\r) and LF (\\n) characters from all user inputs used in HTTP headers.',
  },
  {
    pattern: /(\?|&)(prompt|input|ai|llm|gpt|chat|message|ask)=/i,
    type: 'Direct Prompt Injection',
    severity: 'High',
    cvss: 7.2,
    cwe: 'CWE-77',
    owasp: 'A03:2021',
    description: 'AI/prompt-related parameter detected. Could be vulnerable to Direct or Indirect Prompt Injection attacks.',
    recommendation: 'Implement prompt guards, output validation, and privilege separation for AI-integrated components.',
  },
  {
    pattern: /(\?|&)(imap|mailbox|folder|uid|seq)=/i,
    type: 'IMAP Injection',
    severity: 'High',
    cvss: 7.0,
    cwe: 'CWE-93',
    owasp: 'A03:2021',
    description: 'IMAP-related parameter detected. Could be vulnerable to IMAP command injection.',
    recommendation: 'Use IMAP client libraries that handle command escaping. Never interpolate raw user input into IMAP commands.',
  },
];

const TECH_CLUES: { pattern: RegExp; tech: string }[] = [
  { pattern: /\.php(\?|$)/i, tech: 'PHP' },
  { pattern: /\.asp(\?|$)/i, tech: 'ASP.NET' },
  { pattern: /\.aspx(\?|$)/i, tech: 'ASP.NET' },
  { pattern: /\.jsp(\?|$)/i, tech: 'Java/JSP' },
  { pattern: /\.do(\?|$)/i, tech: 'Java/Struts' },
  { pattern: /\/api\//i, tech: 'REST API' },
  { pattern: /\/graphql/i, tech: 'GraphQL' },
  { pattern: /wordpress|wp-content|wp-admin/i, tech: 'WordPress' },
  { pattern: /django|python/i, tech: 'Python/Django' },
  { pattern: /laravel/i, tech: 'Laravel' },
  { pattern: /rails|ruby/i, tech: 'Ruby on Rails' },
];

export function analyzeUrl(rawUrl: string): ScanResult {
  const url = new URL(rawUrl);
  const parameters: string[] = [];
  url.searchParams.forEach((_val, key) => parameters.push(key));

  const pathSegments = url.pathname.split('/').filter(Boolean);

  // Detect potential injection points from parameters
  const potentialInjectionPoints = parameters.map((param) => ({
    type: 'Query Parameter',
    location: `?${param}=`,
    risk: param.match(/file|path|dir|redirect|url/i) ? 'High' : 'Medium',
  }));

  // Add path segments as potential points
  pathSegments.forEach((seg) => {
    if (seg.match(/\d+/) || seg.length > 20) {
      potentialInjectionPoints.push({ type: 'Path Parameter', location: `/${seg}`, risk: 'Low' });
    }
  });

  // Run injection pattern detection
  const findings: ScanFinding[] = [];
  for (const { pattern, type, severity, cvss, cwe, owasp, description, recommendation } of INJECTION_PATTERNS) {
    if (pattern.test(rawUrl)) {
      const matchParam = rawUrl.match(pattern)?.[2] || '';
      findings.push({ type, location: `Query parameter: ${matchParam}`, parameter: matchParam, severity, cvss, cwe, owasp, description, recommendation });
    }
  }

  // Add header-based findings (always present - educational)
  findings.push({
    type: 'HTTP Header Injection (Potential)',
    location: 'HTTP Headers',
    severity: 'Medium',
    cvss: 5.4,
    cwe: 'CWE-113',
    owasp: 'A03:2021',
    description: 'HTTP headers such as X-Forwarded-For, Referer, and User-Agent may be logged or reflected. Ensure server-side validation strips CRLF sequences.',
    recommendation: 'Validate and sanitize all HTTP header values. Strip \\r and \\n characters.',
  });

  // Detect tech stack clues
  const techStackClues: string[] = [];
  for (const { pattern, tech } of TECH_CLUES) {
    if (pattern.test(rawUrl) && !techStackClues.includes(tech)) {
      techStackClues.push(tech);
    }
  }

  const owaspCoverage = [...new Set(findings.map((f) => f.owasp))];
  const riskScore = Math.min(
    10,
    findings.reduce((acc, f) => acc + f.cvss, 0) / Math.max(findings.length, 1)
  );

  return {
    targetUrl: rawUrl,
    parameters,
    pathSegments,
    potentialInjectionPoints,
    findings,
    techStackClues,
    summary: {
      totalPages: 1,
      injectionPoints: findings.length,
      parameters: parameters.length,
      riskScore: Math.round(riskScore * 10) / 10,
      owaspCoverage,
    },
  };
}
