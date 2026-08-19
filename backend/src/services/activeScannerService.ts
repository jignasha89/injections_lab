/**
 * InjectionLab Active Scanner Service
 * Safe differential testing engine for self-hosted / local educational targets (DVWA, Juice Shop, WebGoat, bWAPP, localhost).
 * Extracts forms and URL parameters, executes baseline vs probe comparisons, and scores confidence.
 */

import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { ScanFinding, ScanResult } from './scannerService';

export interface ActiveScanConfig {
  maxPages?: number;
  timeoutMs?: number;
  rateLimitMs?: number;
  userAgent?: string;
  cookies?: string;
  customHeaders?: Record<string, string>;
}

export interface ExtractedInput {
  name: string;
  type: string;
  defaultValue: string;
  location: 'Query Parameter' | 'Form Field' | 'HTTP Header';
  formAction?: string;
  formMethod?: 'GET' | 'POST';
}

/**
 * Validates that the target is strictly on a local/self-hosted educational environment.
 */
export function isLocalOrPrivateTarget(hostname: string): boolean {
  const cleanHost = hostname.toLowerCase();

  // Localhost & loopback
  if (
    cleanHost === 'localhost' ||
    cleanHost === '127.0.0.1' ||
    cleanHost === '::1' ||
    cleanHost === '0.0.0.0' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local')
  ) {
    return true;
  }

  // Private IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = cleanHost.match(ipv4Regex);
  if (match) {
    const octet1 = parseInt(match[1], 10);
    const octet2 = parseInt(match[2], 10);

    if (octet1 === 10) return true; // 10.0.0.0/8
    if (octet1 === 172 && octet2 >= 16 && octet2 <= 31) return true; // 172.16.0.0/12
    if (octet1 === 192 && octet2 === 168) return true; // 192.168.0.0/16
  }

  return false;
}

// ─────────────────────────────────────────────────────────────
// PROBE DEFINITIONS & SIGNATURES
// ─────────────────────────────────────────────────────────────

interface DifferentialProbe {
  category: string;
  family: string;
  cwe: string;
  owasp: string;
  cvss: number;
  severity: ScanFinding['severity'];
  payload: string;
  description: string;
  recommendation: string;
  isVulnerable: (baselineText: string, probeText: string, probeHeaders: Record<string, string>) => {
    vulnerable: boolean;
    confidence: ScanFinding['confidence'];
    evidence: string;
  };
}

const DB_ERROR_PATTERNS = [
  // MySQL / MariaDB
  /SQL syntax.*MySQL/i,
  /you have an error in your sql syntax/i,
  /check the manual that corresponds to your (mysql|mariadb)/i,
  /Warning.*mysql_/i,
  /Warning.*mysqli_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /com\.mysql\.jdbc/i,
  /mysqli_query/i,
  /mysql_fetch_/i,
  /mysql_num_rows/i,
  /MariaDB server version for the right syntax/i,
  /SQLSTATE\[42000\]: Syntax error/i,
  /SQLSTATE\[HY000\]/i,

  // PostgreSQL
  /PostgreSQL.*ERROR/i,
  /Warning.*\Wpg_/i,
  /valid PostgreSQL result/i,
  /Npgsql\./i,
  /org\.postgresql\.util\.PSQLException/i,
  /ERROR:\s+syntax error at or near/i,
  /pg_query\(\)/i,
  /pg_exec\(\)/i,
  /PG::SyntaxError/i,
  /unterminated quoted string at or near/i,
  /psycopg2\.errors\./i,

  // Microsoft SQL Server
  /Driver.*SQL[\-\_\ ]*Server/i,
  /OLE DB.*SQL Server/i,
  /\bSQLServer JDBC Driver\b/i,
  /Unclosed quotation mark after the character string/i,
  /Microsoft OLE DB Provider for ODBC Drivers/i,
  /System\.Data\.SqlClient\.SqlException/i,
  /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
  /\[Microsoft\]\[ODBC Driver \d+ for SQL Server\]/i,
  /Line \d+: Incorrect syntax near/i,
  /Msg \d+, Level \d+, State \d+/i,

  // SQLite
  /SQLite\/JDBCDriver/i,
  /SQLite\.Exception/i,
  /System\.Data\.SQLite\.SQLiteException/i,
  /unrecognized token:/i,
  /operational error: near/i,
  /near ".*": syntax error/i,
  /incomplete input/i,
  /SQLite3::query\(\)/i,

  // Oracle
  /\bORA-[0-9]{5}\b/i,
  /Oracle error/i,
  /Oracle.*Driver/i,
  /SQL command not properly ended/i,
  /quoted string not properly terminated/i,
  /PL\/SQL: ORA-/i,
  /oracle\.jdbc\./i,

  // IBM DB2
  /CLI0150E/i,
  /DB2 SQL error:/i,
  /\[IBM\]\[CLI Driver\]\[DB2\//i,
  /SQLSTATE=42601/i,

  // Microsoft Access
  /Syntax error in query expression/i,
  /Data type mismatch in criteria expression/i,
  /\[Microsoft\]\[ODBC Microsoft Access Driver\]/i,

  // Generic / Hibernate / ORMs
  /org\.hibernate\.QueryException/i,
  /org\.hibernate\.exception\.SQLGrammarException/i,
  /SQLSTATE\[[0-9A-Z]{5}\]/i,
  /syntax error in query/i,
  /unhandled sql exception/i,
  /SequelizeDatabaseError/i,
  /TypeORMError/i,
];

const DIFFERENTIAL_PROBES: DifferentialProbe[] = [
  {
    category: 'Error-Based SQL Injection',
    family: 'SQL/NoSQL Injection',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    cvss: 9.8,
    severity: 'Critical',
    payload: "' OR '1'='1' --",
    description: 'The parameter is unsafely concatenated into a database SQL query, producing database syntax errors or expanding result sets.',
    recommendation: 'Use parameterized queries / prepared statements for all database queries.',
    isVulnerable: (baseline, probe) => {
      for (const pattern of DB_ERROR_PATTERNS) {
        if (pattern.test(probe) && !pattern.test(baseline)) {
          return {
            vulnerable: true,
            confidence: 'Confirmed',
            evidence: `Database syntax error signature detected in response: "${probe.match(pattern)?.[0]}"`,
          };
        }
      }
      return { vulnerable: false, confidence: 'Low', evidence: '' };
    },
  },
  {
    category: 'Reflected Cross-Site Scripting (XSS)',
    family: 'Client-Side / XSS',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    cvss: 8.2,
    severity: 'High',
    payload: '<injlab_xss_probe_99>',
    description: 'The parameter is reflected unencoded directly into the HTML response body, allowing arbitrary script execution in client browsers.',
    recommendation: 'Implement context-aware HTML entity encoding and strict Content Security Policy (CSP).',
    isVulnerable: (baseline, probe) => {
      if (probe.includes('<injlab_xss_probe_99>') && !baseline.includes('<injlab_xss_probe_99>')) {
        return {
          vulnerable: true,
          confidence: 'Confirmed',
          evidence: 'Unencoded HTML probe tag reflected directly into response body: "<injlab_xss_probe_99>"',
        };
      }
      return { vulnerable: false, confidence: 'Low', evidence: '' };
    },
  },
  {
    category: 'Server-Side Template Injection (SSTI)',
    family: 'Server-Side / Code Execution',
    cwe: 'CWE-1336',
    owasp: 'A03:2021',
    cvss: 9.8,
    severity: 'Critical',
    payload: '{{77*77}}',
    description: 'The template engine evaluated user input as executable expression syntax (77 * 77 = 5929).',
    recommendation: 'Never pass user input into dynamic template compilation methods. Use static templates with variable context binding.',
    isVulnerable: (baseline, probe) => {
      if (probe.includes('5929') && !baseline.includes('5929') && !probe.includes('{{77*77}}')) {
        return {
          vulnerable: true,
          confidence: 'Confirmed',
          evidence: 'Mathematical expression evaluated server-side: {{77*77}} resulted in computed output "5929".',
        };
      }
      return { vulnerable: false, confidence: 'Low', evidence: '' };
    },
  },
  {
    category: 'OS Command Injection',
    family: 'Server-Side / Code Execution',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    cvss: 9.8,
    severity: 'Critical',
    payload: '127.0.0.1; echo injlab_cmd_probe_active',
    description: 'Operating system command shell metacharacters allowed executing chained system commands.',
    recommendation: 'Avoid shell execution. Use execFile with strict argument arrays and regex format validation.',
    isVulnerable: (baseline, probe) => {
      if (probe.includes('injlab_cmd_probe_active') && !baseline.includes('injlab_cmd_probe_active')) {
        return {
          vulnerable: true,
          confidence: 'Confirmed',
          evidence: 'Arbitrary shell echo output reflected in response stream: "injlab_cmd_probe_active"',
        };
      }
      return { vulnerable: false, confidence: 'Low', evidence: '' };
    },
  },
  {
    category: 'CRLF / HTTP Header Injection',
    family: 'Protocol / Header / Log / AI Injection',
    cwe: 'CWE-113',
    owasp: 'A03:2021',
    cvss: 7.5,
    severity: 'High',
    payload: 'normal%0d%0aX-InjLab-Header: InjectedValue99',
    description: 'Carriage Return + Line Feed characters allowed injecting unauthorized HTTP response headers.',
    recommendation: 'Strip \\r and \\n characters before writing values into HTTP response headers.',
    isVulnerable: (baseline, probe, headers) => {
      const lowerHeaders = Object.keys(headers).reduce<Record<string, string>>((acc, key) => {
        acc[key.toLowerCase()] = String(headers[key]);
        return acc;
      }, {});

      if (lowerHeaders['x-injlab-header'] === 'InjectedValue99') {
        return {
          vulnerable: true,
          confidence: 'Confirmed',
          evidence: 'Injected custom HTTP header was reflected into response stream: "X-InjLab-Header: InjectedValue99"',
        };
      }
      return { vulnerable: false, confidence: 'Low', evidence: '' };
    },
  },
];

// ─────────────────────────────────────────────────────────────
// ACTIVE SCAN ENGINE
// ─────────────────────────────────────────────────────────────

export async function runActiveScan(
  targetUrl: string,
  config: ActiveScanConfig = {}
): Promise<ScanResult> {
  const parsedUrl = new URL(targetUrl);
  const hostname = parsedUrl.hostname;

  // 1. Safety Check: Verify local/sandbox target
  if (!isLocalOrPrivateTarget(hostname)) {
    throw new Error(
      `Safety Boundary Enforcement: Active probe scanning is strictly restricted to local or self-hosted educational targets (localhost, 127.0.0.1, private IP ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). For remote/public targets, please use Heuristic Mode.`
    );
  }

  const timeoutMs = Math.min(config.timeoutMs || 5000, 10000);
  const requestHeaders = {
    'User-Agent': config.userAgent || 'InjectionLab-SecurityScanner/2.0 (Educational Safe Probe)',
    ...(config.customHeaders || {}),
    ...(config.cookies ? { Cookie: config.cookies } : {}),
  };

  const client = axios.create({
    timeout: timeoutMs,
    headers: requestHeaders,
    maxRedirects: 3,
    validateStatus: () => true, // capture all status codes (400, 500, etc.)
  });

  // 2. Fetch Target Webpage
  let rootResponse: AxiosResponse;
  try {
    rootResponse = await client.get(targetUrl);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Connection failed';
    throw new Error(`Failed to connect to local target "${targetUrl}": ${msg}`);
  }

  const htmlBody = typeof rootResponse.data === 'string' ? rootResponse.data : JSON.stringify(rootResponse.data);
  const $ = cheerio.load(htmlBody);

  // 3. Extract All Input Points (URL Query Params + HTML Forms)
  const inputInventory: ExtractedInput[] = [];
  const parameters: string[] = [];
  const paramValues: Record<string, string> = {};

  // A. URL Parameters
  parsedUrl.searchParams.forEach((val, key) => {
    parameters.push(key);
    paramValues[key] = val;
    inputInventory.push({
      name: key,
      type: 'url_query',
      defaultValue: val || '1',
      location: 'Query Parameter',
    });
  });

  // B. HTML Forms & Fields
  $('form').each((_, formElem) => {
    const form = $(formElem);
    const rawAction = form.attr('action') || '';
    const formAction = rawAction ? new URL(rawAction, targetUrl).toString() : targetUrl;
    const formMethod = (form.attr('method') || 'GET').toUpperCase() as 'GET' | 'POST';

    form.find('input, textarea, select').each((_, fieldElem) => {
      const field = $(fieldElem);
      const name = field.attr('name');
      const type = field.attr('type') || fieldElem.tagName.toLowerCase();
      const val = field.attr('value') || '';

      if (name && !inputInventory.some((i) => i.name === name && i.location === 'Form Field')) {
        inputInventory.push({
          name,
          type,
          defaultValue: val || 'test',
          location: 'Form Field',
          formAction,
          formMethod,
        });
        if (!parameters.includes(name)) {
          parameters.push(name);
          paramValues[name] = val;
        }
      }
    });
  });

  const potentialInjectionPoints: ScanResult['potentialInjectionPoints'] = inputInventory.map((inp) => ({
    type: inp.location,
    location: inp.location === 'Form Field' ? `${inp.formMethod} ${inp.formAction} [${inp.name}]` : `?${inp.name}=${inp.defaultValue}`,
    risk: /^(id|_id|[a-z]+_id|user(name)?|login|email|pass(word)?|search|q|query|cmd|exec|file|path|url|token|auth|key)$/i.test(inp.name) || /^\d+$/.test(inp.defaultValue) ? 'High' : 'Medium',
    reason: `Discovered user-controlled ${inp.location} (${inp.name}) on target page`,
  }));

  // 4. Execute Differential Testing per Input Point
  const findings: ScanFinding[] = [];
  const delayMs = config.rateLimitMs || 100;

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  for (const input of inputInventory) {
    // Send Safe Baseline Request
    const baselineVal = 'safe_baseline_token_123';
    let baselineText = '';

    try {
      if (input.location === 'Form Field' && input.formMethod === 'POST') {
        const formData: Record<string, string> = { [input.name]: baselineVal };
        const bRes = await client.post(input.formAction || targetUrl, formData);
        baselineText = typeof bRes.data === 'string' ? bRes.data : JSON.stringify(bRes.data);
      } else {
        const testUrl = new URL(input.formAction || targetUrl);
        testUrl.searchParams.set(input.name, baselineVal);
        const bRes = await client.get(testUrl.toString());
        baselineText = typeof bRes.data === 'string' ? bRes.data : JSON.stringify(bRes.data);
      }
    } catch {
      continue;
    }

    await sleep(delayMs);

    // Send Probes
    for (const probe of DIFFERENTIAL_PROBES) {
      try {
        let probeText = '';
        let probeHeaders: Record<string, string> = {};

        if (input.location === 'Form Field' && input.formMethod === 'POST') {
          const formData: Record<string, string> = { [input.name]: probe.payload };
          const pRes = await client.post(input.formAction || targetUrl, formData);
          probeText = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
          probeHeaders = pRes.headers as Record<string, string>;
        } else {
          const testUrl = new URL(input.formAction || targetUrl);
          testUrl.searchParams.set(input.name, probe.payload);
          const pRes = await client.get(testUrl.toString());
          probeText = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
          probeHeaders = pRes.headers as Record<string, string>;
        }

        const evaluation = probe.isVulnerable(baselineText, probeText, probeHeaders);

        if (evaluation.vulnerable) {
          findings.push({
            type: probe.category,
            injectionFamily: probe.family,
            location: input.location === 'Form Field' ? `${input.formMethod} ${input.formAction} [${input.name}]` : `?${input.name}=`,
            parameter: input.name,
            paramValue: probe.payload,
            severity: probe.severity,
            confidence: evaluation.confidence,
            cvss: probe.cvss,
            cwe: probe.cwe,
            owasp: probe.owasp,
            description: probe.description,
            evidence: evaluation.evidence,
            pocPayload: probe.payload,
            recommendation: probe.recommendation,
          });
        }
      } catch {
        // Continue testing other probes
      }

      await sleep(delayMs);
    }
  }

  // 5. Calculate Metrics
  const SEVERITY_ORDER: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  findings.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));

  const owaspCoverage = [...new Set(findings.map((f) => f.owasp))];
  const familiesTested = [...new Set(DIFFERENTIAL_PROBES.map((p) => p.family))];
  const injectionFamilyCounts: Record<string, number> = {};
  for (const f of findings) {
    injectionFamilyCounts[f.injectionFamily] = (injectionFamilyCounts[f.injectionFamily] || 0) + 1;
  }

  const highestSeverity = findings.reduce((best, f) => {
    return (SEVERITY_ORDER[f.severity] || 0) > (SEVERITY_ORDER[best] || 0) ? f.severity : best;
  }, 'Info' as string);

  const riskScore = findings.length > 0
    ? Math.min(10, findings.reduce((acc, f) => acc + f.cvss, 0) / findings.length)
    : 0;

  return {
    targetUrl,
    scanTimestamp: new Date().toISOString(),
    parameters,
    paramValues,
    pathSegments: parsedUrl.pathname.split('/').filter(Boolean),
    domain: hostname,
    techStackClues: ['Active Inspection Verified', rootResponse.headers['server'] ? `Server: ${rootResponse.headers['server']}` : 'HTTP Target'],
    potentialInjectionPoints,
    findings,
    summary: {
      totalPages: 1,
      injectionPoints: potentialInjectionPoints.length,
      parameters: parameters.length,
      riskScore: Math.round(riskScore * 10) / 10,
      highestSeverity,
      owaspCoverage,
      familiesTested,
      injectionFamilyCounts,
    },
  };
}
