/**
 * InjectionLab Deep Website Scanner Service
 * Fetches live web pages, parses HTML forms and scripts using Cheerio,
 * audits HTTP security headers, and performs differential benign probe testing.
 */

import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import payloadConfig from '../config/payloads.json';

export interface LiveScanConfig {
  scanMode?: 'passive' | 'active';
  timeoutMs?: number;
  rateLimitMs?: number;
  userAgent?: string;
  cookies?: string;
  customHeaders?: Record<string, string>;
  maxRedirects?: number;
}

export interface SecurityHeaderResult {
  header: string;
  present: boolean;
  value?: string;
  status: 'pass' | 'fail' | 'warn';
  recommendation?: string;
}

export interface FormInputField {
  name: string;
  type: string;
  value: string;
}

export interface DiscoveredForm {
  action: string;
  method: 'GET' | 'POST';
  enctype?: string;
  isFileUpload: boolean;
  inputs: FormInputField[];
}

export interface DiscoveredLinkParam {
  href: string;
  param: string;
  value: string;
}

export interface ScanFindingResult {
  inputPointTested: string;
  payloadUsed: string;
  vulnerabilityType: string;
  confidence: 'Low' | 'Medium' | 'High' | 'Confirmed';
  evidence: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvss?: number;
  cwe?: string;
  owasp?: string;
  recommendation: string;
}

export interface DeepScanResult {
  targetUrl: string;
  normalizedUrl: string;
  scanTimestamp: string;
  scanMode: 'passive' | 'active';
  statusCode: number;
  responseTimeMs: number;
  serverBanner?: string;
  headers: Record<string, SecurityHeaderResult>;
  discoveredEndpoints: {
    forms: DiscoveredForm[];
    linksWithParams: DiscoveredLinkParam[];
    scriptApiEndpoints: string[];
  };
  findings: ScanFindingResult[];
  summary: {
    totalPages: number;
    formsCount: number;
    paramsCount: number;
    scriptEndpointsCount: number;
    totalFindings: number;
    riskScore: number;
    highestSeverity: string;
    headersCompliance: {
      passed: number;
      failed: number;
      warned: number;
      total: number;
    };
  };
  auditLog: {
    timestamp: string;
    target: string;
    mode: string;
    authorized: boolean;
    isLocalTarget: boolean;
  };
}

// ─────────────────────────────────────────────────────────────
// DATABASE ERROR SIGNATURES
// ─────────────────────────────────────────────────────────────
const DB_ERROR_PATTERNS = [
  // MySQL / MariaDB
  { db: 'MySQL', pattern: /SQL syntax.*MySQL/i },
  { db: 'MySQL', pattern: /you have an error in your sql syntax/i },
  { db: 'MySQL', pattern: /check the manual that corresponds to your (mysql|mariadb)/i },
  { db: 'MySQL', pattern: /Warning.*mysql_/i },
  { db: 'MySQL', pattern: /valid MySQL result/i },
  { db: 'MySQL', pattern: /MySqlClient\./i },
  { db: 'MySQL', pattern: /com\.mysql\.jdbc/i },
  { db: 'MySQL', pattern: /mysqli_query/i },
  { db: 'MySQL', pattern: /mysql_fetch_/i },
  { db: 'MySQL', pattern: /mysql_num_rows/i },
  // PostgreSQL
  { db: 'PostgreSQL', pattern: /PostgreSQL.*ERROR/i },
  { db: 'PostgreSQL', pattern: /Warning.*\Wpg_/i },
  { db: 'PostgreSQL', pattern: /valid PostgreSQL result/i },
  { db: 'PostgreSQL', pattern: /Npgsql\./i },
  { db: 'PostgreSQL', pattern: /org\.postgresql\.util\.PSQLException/i },
  { db: 'PostgreSQL', pattern: /ERROR:\s+syntax error at or near/i },
  { db: 'PostgreSQL', pattern: /pg_query\(\)/i },
  // Microsoft SQL Server
  { db: 'MSSQL', pattern: /Driver.*SQL[\-\_\ ]*Server/i },
  { db: 'MSSQL', pattern: /OLE DB.*SQL Server/i },
  { db: 'MSSQL', pattern: /\bSQLServer JDBC Driver\b/i },
  { db: 'MSSQL', pattern: /Unclosed quotation mark after the character string/i },
  { db: 'MSSQL', pattern: /Microsoft OLE DB Provider for ODBC Drivers/i },
  { db: 'MSSQL', pattern: /System\.Data\.SqlClient\.SqlException/i },
  // SQLite
  { db: 'SQLite', pattern: /SQLite\/JDBCDriver/i },
  { db: 'SQLite', pattern: /SQLite\.Exception/i },
  { db: 'SQLite', pattern: /System\.Data\.SQLite\.SQLiteException/i },
  { db: 'SQLite', pattern: /unrecognized token:/i },
  { db: 'SQLite', pattern: /operational error: near/i },
  // Oracle
  { db: 'Oracle', pattern: /ORA-[0-9]{5}/i },
  { db: 'Oracle', pattern: /Oracle error/i },
  { db: 'Oracle', pattern: /Oracle.*Driver/i },
  { db: 'Oracle', pattern: /SQL command not properly ended/i },
  // Generic / Hibernate
  { db: 'Generic SQL', pattern: /org\.hibernate\.QueryException/i },
  { db: 'Generic SQL', pattern: /SQLSTATE\[\d+\]/i },
  { db: 'Generic SQL', pattern: /syntax error in query/i },
  { db: 'Generic SQL', pattern: /unhandled sql exception/i },
];

/**
 * Checks if target hostname is localhost or private IP range
 */
export function isLocalOrPrivateTarget(hostname: string): boolean {
  const cleanHost = hostname.toLowerCase();

  if (
    cleanHost === 'localhost' ||
    cleanHost === '127.0.0.1' ||
    cleanHost === '::1' ||
    cleanHost === '0.0.0.0' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.test') ||
    cleanHost.endsWith('.example')
  ) {
    return true;
  }

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

/**
 * Audit Logger for Security Scans
 */
function logScanAudit(event: {
  timestamp: string;
  target: string;
  mode: string;
  authorized: boolean;
  isLocal: boolean;
  clientIp?: string;
}) {
  const prefix = event.isLocal ? '🔒 [LOCAL AUDIT]' : '🌐 [REMOTE AUDIT]';
  console.log(
    `${prefix} [${event.timestamp}] Target: ${event.target} | Mode: ${event.mode.toUpperCase()} | Authorized: ${event.authorized} | ClientIP: ${event.clientIp || 'unknown'}`
  );
  if (!event.isLocal && event.mode === 'active') {
    console.warn(
      `⚠️ [SECURITY NOTICE] Active scan performed against non-localhost target: ${event.target}. Verified authorization required.`
    );
  }
}

/**
 * Analyze HTTP Response Headers for Security Best Practices
 */
export function analyzeSecurityHeaders(
  headers: Record<string, unknown>,
  isHttps: boolean
): Record<string, SecurityHeaderResult> {
  const normHeaders: Record<string, string> = {};
  for (const [key, val] of Object.entries(headers)) {
    normHeaders[key.toLowerCase()] = String(val);
  }

  const results: Record<string, SecurityHeaderResult> = {};

  // 1. Content-Security-Policy
  const csp = normHeaders['content-security-policy'];
  if (csp) {
    const hasUnsafe = csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'");
    results['Content-Security-Policy'] = {
      header: 'Content-Security-Policy',
      present: true,
      value: csp,
      status: hasUnsafe ? 'warn' : 'pass',
      recommendation: hasUnsafe
        ? "Avoid 'unsafe-inline' or 'unsafe-eval' in CSP directives. Use nonce-based or hash-based script authentication."
        : 'Content-Security-Policy is present and configured.',
    };
  } else {
    results['Content-Security-Policy'] = {
      header: 'Content-Security-Policy',
      present: false,
      status: 'fail',
      recommendation:
        'Implement Content-Security-Policy (CSP) to restrict sources of executable scripts, objects, and styles.',
    };
  }

  // 2. X-Frame-Options
  const xfo = normHeaders['x-frame-options'];
  if (xfo) {
    const valid = ['deny', 'sameorigin'].includes(xfo.toLowerCase());
    results['X-Frame-Options'] = {
      header: 'X-Frame-Options',
      present: true,
      value: xfo,
      status: valid ? 'pass' : 'warn',
      recommendation: valid
        ? 'X-Frame-Options is properly configured.'
        : "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent Clickjacking.",
    };
  } else {
    results['X-Frame-Options'] = {
      header: 'X-Frame-Options',
      present: false,
      status: 'fail',
      recommendation:
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to protect users from UI redressing and clickjacking.",
    };
  }

  // 3. X-Content-Type-Options
  const xcto = normHeaders['x-content-type-options'];
  if (xcto && xcto.toLowerCase().includes('nosniff')) {
    results['X-Content-Type-Options'] = {
      header: 'X-Content-Type-Options',
      present: true,
      value: xcto,
      status: 'pass',
      recommendation: 'X-Content-Type-Options: nosniff is enabled.',
    };
  } else {
    results['X-Content-Type-Options'] = {
      header: 'X-Content-Type-Options',
      present: Boolean(xcto),
      value: xcto,
      status: 'fail',
      recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type confusion attacks.",
    };
  }

  // 4. Strict-Transport-Security (HSTS)
  const hsts = normHeaders['strict-transport-security'];
  if (hsts) {
    results['Strict-Transport-Security'] = {
      header: 'Strict-Transport-Security',
      present: true,
      value: hsts,
      status: 'pass',
      recommendation: 'Strict-Transport-Security (HSTS) is enabled.',
    };
  } else {
    results['Strict-Transport-Security'] = {
      header: 'Strict-Transport-Security',
      present: false,
      status: isHttps ? 'fail' : 'warn',
      recommendation: isHttps
        ? "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS connections."
        : 'HSTS requires an HTTPS endpoint to be enforced.',
    };
  }

  // 5. Referrer-Policy
  const refPolicy = normHeaders['referrer-policy'];
  if (refPolicy) {
    results['Referrer-Policy'] = {
      header: 'Referrer-Policy',
      present: true,
      value: refPolicy,
      status: 'pass',
      recommendation: 'Referrer-Policy is configured.',
    };
  } else {
    results['Referrer-Policy'] = {
      header: 'Referrer-Policy',
      present: false,
      status: 'warn',
      recommendation:
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to avoid leaking sensitive query params to 3rd parties.",
    };
  }

  // 6. Permissions-Policy
  const permPolicy = normHeaders['permissions-policy'];
  if (permPolicy) {
    results['Permissions-Policy'] = {
      header: 'Permissions-Policy',
      present: true,
      value: permPolicy,
      status: 'pass',
      recommendation: 'Permissions-Policy is configured.',
    };
  } else {
    results['Permissions-Policy'] = {
      header: 'Permissions-Policy',
      present: false,
      status: 'warn',
      recommendation:
        "Add 'Permissions-Policy' to explicitly restrict access to browser features (camera, microphone, geolocation).",
    };
  }

  return results;
}

/**
 * Parse HTML content with Cheerio to extract forms, link query params, and script API routes
 */
export function parseHtmlContent(
  html: string,
  targetUrl: string
): {
  forms: DiscoveredForm[];
  linksWithParams: DiscoveredLinkParam[];
  scriptApiEndpoints: string[];
} {
  const $ = cheerio.load(html);
  const forms: DiscoveredForm[] = [];
  const linksWithParams: DiscoveredLinkParam[] = [];
  const scriptApiEndpoints = new Set<string>();

  // 1. Extract Forms & Inputs
  $('form').each((_, formElem) => {
    const form = $(formElem);
    const rawAction = form.attr('action') || '';
    let formAction = targetUrl;
    try {
      formAction = rawAction ? new URL(rawAction, targetUrl).toString() : targetUrl;
    } catch {
      formAction = targetUrl;
    }

    const method = (form.attr('method') || 'GET').toUpperCase() as 'GET' | 'POST';
    const enctype = form.attr('enctype') || 'application/x-www-form-urlencoded';
    let isFileUpload = enctype.toLowerCase().includes('multipart/form-data');

    const inputs: FormInputField[] = [];

    form.find('input, textarea, select').each((_, fieldElem) => {
      const field = $(fieldElem);
      const name = field.attr('name');
      const type = (field.attr('type') || fieldElem.tagName.toLowerCase()).toLowerCase();
      const value = field.attr('value') || '';

      if (type === 'file') {
        isFileUpload = true;
      }

      if (name) {
        inputs.push({ name, type, value });
      }
    });

    forms.push({
      action: formAction,
      method: method === 'POST' ? 'POST' : 'GET',
      enctype,
      isFileUpload,
      inputs,
    });
  });

  // 2. Extract Link Query Parameters
  $('a[href]').each((_, aElem) => {
    const href = $(aElem).attr('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;

    try {
      const resolved = new URL(href, targetUrl);
      resolved.searchParams.forEach((val, key) => {
        if (!linksWithParams.some((l) => l.href === resolved.pathname && l.param === key)) {
          linksWithParams.push({
            href: resolved.pathname,
            param: key,
            value: val,
          });
        }
      });
    } catch {
      // Ignore invalid URL strings
    }
  });

  // 3. Extract API endpoints from inline <script> tags & HTML content
  $('script').each((_, scriptElem) => {
    const scriptContent = $(scriptElem).html() || '';
    if (!scriptContent) return;

    // Match fetch/axios/ajax calls
    const fetchRegex = /(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?|\$\.(?:ajax|get|post))\s*\(\s*['"`]([a-zA-Z0-9_\-\/\.\?=&]+)['"`]/g;
    let match: RegExpExecArray | null;
    while ((match = fetchRegex.exec(scriptContent)) !== null) {
      if (match[1] && (match[1].startsWith('/') || match[1].startsWith('http') || match[1].includes('api'))) {
        scriptApiEndpoints.add(match[1]);
      }
    }

    // Match common API path literal strings: /api/..., /v1/..., /auth/..., etc.
    const pathRegex = /['"`](\/(?:api|v[0-9]+|auth|users|admin|graphql|login|search|data|items|download)[a-zA-Z0-9_\-\/\.\?=&]*)['"`]/g;
    while ((match = pathRegex.exec(scriptContent)) !== null) {
      if (match[1]) {
        scriptApiEndpoints.add(match[1]);
      }
    }
  });

  return {
    forms,
    linksWithParams,
    scriptApiEndpoints: Array.from(scriptApiEndpoints),
  };
}

/**
 * Executes a Deep Scan on the given URL
 */
export async function executeLiveScan(
  rawUrl: string,
  authorized: boolean,
  config: LiveScanConfig = {},
  clientIp?: string
): Promise<DeepScanResult> {
  const timestamp = new Date().toISOString();

  // 1. URL Format Validation
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('Target URL string is required.');
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl.startsWith('http') ? rawUrl : `http://${rawUrl}`);
  } catch {
    throw new Error(`Invalid URL format: "${rawUrl}". Please provide a valid HTTP/HTTPS URL.`);
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS protocols are supported.');
  }

  const normalizedUrl = parsedUrl.toString();
  const hostname = parsedUrl.hostname;
  const isLocal = isLocalOrPrivateTarget(hostname);

  // 2. Global / Config Mode resolution
  const configuredMode = (process.env.SCAN_MODE?.toLowerCase() || 'passive') as 'passive' | 'active';
  const requestedMode = config.scanMode?.toLowerCase() === 'active' ? 'active' : 'passive';
  const effectiveMode: 'passive' | 'active' = requestedMode === 'active' && authorized ? 'active' : 'passive';

  // 3. Permissions Enforcement
  if (!authorized) {
    throw new Error(
      'Authorization confirmation required. You must explicitly confirm ownership or permission to scan this target.'
    );
  }

  // 4. Audit Logging
  logScanAudit({
    timestamp,
    target: normalizedUrl,
    mode: effectiveMode,
    authorized,
    isLocal,
    clientIp,
  });

  // 5. Fetch Target Webpage
  const timeoutMs = Math.min(Math.max(config.timeoutMs || 10000, 1000), 30000); // 10s default, max 30s
  const requestHeaders = {
    'User-Agent': config.userAgent || 'InjectionLab-DeepScanner/2.0 (Authorized Security Audit; Educational)',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    ...(config.customHeaders || {}),
    ...(config.cookies ? { Cookie: config.cookies } : {}),
  };

  const httpClient = axios.create({
    timeout: timeoutMs,
    headers: requestHeaders,
    maxRedirects: config.maxRedirects || 5,
    validateStatus: () => true, // Capture all HTTP status codes (200, 401, 403, 500, etc.)
  });

  const probeHttpClient = axios.create({
    timeout: timeoutMs,
    headers: requestHeaders,
    maxRedirects: 0,
    validateStatus: () => true,
  });

  const startTime = Date.now();
  let rootResponse: AxiosResponse;

  try {
    rootResponse = await httpClient.get(normalizedUrl);
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Network request failed';
    throw new Error(`Failed to fetch target URL "${normalizedUrl}": ${errorMsg}`);
  }

  const responseTimeMs = Date.now() - startTime;
  const rawHtml = typeof rootResponse.data === 'string' ? rootResponse.data : JSON.stringify(rootResponse.data);
  const responseHeaders = rootResponse.headers as Record<string, unknown>;

  // 6. Security Header Auditing
  const securityHeaders = analyzeSecurityHeaders(responseHeaders, parsedUrl.protocol === 'https:');

  // 7. Parse HTML Structure
  const discovered = parseHtmlContent(rawHtml, normalizedUrl);

  // 8. Generate Passive / Baseline Findings
  const findings: ScanFindingResult[] = [];

  // Check for Missing Security Headers in Findings
  for (const [headerName, hResult] of Object.entries(securityHeaders)) {
    if (hResult.status === 'fail') {
      findings.push({
        inputPointTested: `HTTP Response Header: ${headerName}`,
        payloadUsed: 'N/A (Passive Header Inspection)',
        vulnerabilityType: `Missing Security Header (${headerName})`,
        confidence: 'Confirmed',
        evidence: `Header "${headerName}" is missing from server HTTP response headers.`,
        severity: headerName === 'Content-Security-Policy' || headerName === 'X-Frame-Options' ? 'Medium' : 'Low',
        cvss: headerName === 'Content-Security-Policy' ? 5.3 : 4.0,
        cwe: headerName === 'X-Frame-Options' ? 'CWE-1021' : 'CWE-693',
        owasp: 'A05:2021-Security Misconfiguration',
        recommendation: hResult.recommendation || `Implement ${headerName} header.`,
      });
    }
  }

  // 9. Differential Testing (Active Mode)
  if (effectiveMode === 'active') {
    const rateLimitDelay = config.rateLimitMs || 500; // 500ms rate limit delay
    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

    // Compile list of inputs to test
    interface TestInputTarget {
      name: string;
      location: 'URL Parameter' | 'Form Field';
      method: 'GET' | 'POST';
      actionUrl: string;
      defaultValue: string;
      formAllInputs?: Record<string, string>;
    }

    const testTargets: TestInputTarget[] = [];

    // A. URL Query Parameters from target URL
    parsedUrl.searchParams.forEach((val, key) => {
      testTargets.push({
        name: key,
        location: 'URL Parameter',
        method: 'GET',
        actionUrl: normalizedUrl,
        defaultValue: val || '1',
      });
    });

    // B. URL parameters from discovered page links
    for (const link of discovered.linksWithParams) {
      if (!testTargets.some((t) => t.name === link.param && t.location === 'URL Parameter')) {
        let actionUrl = normalizedUrl;
        try {
          actionUrl = new URL(link.href, normalizedUrl).toString();
        } catch {
          actionUrl = normalizedUrl;
        }
        testTargets.push({
          name: link.param,
          location: 'URL Parameter',
          method: 'GET',
          actionUrl,
          defaultValue: link.value || '1',
        });
      }
    }

    // C. Form Fields (Only GET & POST, skipping file uploads)
    for (const form of discovered.forms) {
      if (form.isFileUpload) continue; // Skip file uploads as requested

      const formDefaults: Record<string, string> = {};
      for (const input of form.inputs) {
        if (input.name) {
          formDefaults[input.name] = input.value || (input.type === 'password' ? 'test123' : 'test');
        }
      }

      for (const input of form.inputs) {
        if (!input.name || ['submit', 'button', 'reset', 'image'].includes(input.type)) continue;

        testTargets.push({
          name: input.name,
          location: 'Form Field',
          method: form.method,
          actionUrl: form.action,
          defaultValue: input.value || 'test',
          formAllInputs: formDefaults,
        });
      }
    }

    // Iterate through input targets
    for (const input of testTargets) {
      // 1. Safe Baseline Request
      const baselineVal = 'injlab_safe_baseline_token';
      let baselineText = '';
      let baselineStatus = 200;
      let baselineDuration = 0;
      let baselineHeaders: Record<string, unknown> = {};

      try {
        const bStart = Date.now();
        if (input.method === 'POST') {
          const formData: Record<string, string> = {
            ...(input.formAllInputs || {}),
            [input.name]: baselineVal,
          };
          const formBody = new URLSearchParams(formData).toString();
          const bRes = await probeHttpClient.post(input.actionUrl, formBody, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
          baselineText = typeof bRes.data === 'string' ? bRes.data : JSON.stringify(bRes.data);
          baselineStatus = bRes.status;
          baselineHeaders = bRes.headers || {};
        } else {
          const testUrl = new URL(input.actionUrl);
          testUrl.searchParams.set(input.name, baselineVal);
          const bRes = await probeHttpClient.get(testUrl.toString());
          baselineText = typeof bRes.data === 'string' ? bRes.data : JSON.stringify(bRes.data);
          baselineStatus = bRes.status;
          baselineHeaders = bRes.headers || {};
        }
        baselineDuration = Date.now() - bStart;
      } catch {
        continue;
      }

      await sleep(rateLimitDelay);

      // 2. Iterate through categorized payloads
      const categories = Object.keys(payloadConfig) as (keyof typeof payloadConfig)[];

      for (const category of categories) {
        const payloads = payloadConfig[category] as Array<{
          id: string;
          name: string;
          payload: string;
          detectionType: string;
          expectedMatch?: string;
          expectedDelayMs?: number;
          cwe?: string;
          owasp?: string;
          cvss?: number;
          severity?: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
          description?: string;
          recommendation?: string;
        }>;

        for (const p of payloads) {
          try {
            let probeText = '';
            let probeStatus = 200;
            let probeDuration = 0;
            let probeHeaders: Record<string, unknown> = {};

            const pStart = Date.now();
            if (input.method === 'POST') {
              const formData: Record<string, string> = {
                ...(input.formAllInputs || {}),
                [input.name]: p.payload,
              };
              const formBody = new URLSearchParams(formData).toString();
              const pRes = await probeHttpClient.post(input.actionUrl, formBody, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              });
              probeText = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
              probeStatus = pRes.status;
              probeHeaders = pRes.headers || {};
            } else {
              const testUrl = new URL(input.actionUrl);
              testUrl.searchParams.set(input.name, p.payload);
              const pRes = await probeHttpClient.get(testUrl.toString());
              probeText = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
              probeStatus = pRes.status;
              probeHeaders = pRes.headers || {};
            }
            probeDuration = Date.now() - pStart;

            let isVulnerable = false;
            let evidence = '';
            let confidence: 'Low' | 'Medium' | 'High' | 'Confirmed' = 'Medium';

            // Check A: Database Error Signatures (SQLi)
            if (p.detectionType === 'error_match') {
              for (const { db, pattern } of DB_ERROR_PATTERNS) {
                if (pattern.test(probeText) && !pattern.test(baselineText)) {
                  isVulnerable = true;
                  confidence = 'Confirmed';
                  const match = probeText.match(pattern)?.[0] || 'Database syntax error';
                  evidence = `${db} error signature detected in response body: "${match}"`;
                  break;
                }
              }

              // Check A2: Boolean Tautology & Authentication Bypass
              if (!isVulnerable && (p.payload.includes('OR') || p.payload.includes('--') || p.payload.includes("'"))) {
                const failPatterns = /login failed|invalid username|invalid credentials|authentication failed|failed to login|incorrect password/i;
                const successPatterns = /sign off|logout|account history|welcome|dashboard|main\.jsp|user account|my account|admin portal/i;

                const baselineLocation = String(baselineHeaders['location'] || '').toLowerCase();
                const probeLocation = String(probeHeaders['location'] || '').toLowerCase();

                const hadFailure = failPatterns.test(baselineText) || baselineStatus === 401 || baselineStatus === 403 || baselineLocation.includes('login') || baselineLocation.includes('fail');
                const bypassedFailure = !failPatterns.test(probeText) && (probeStatus === 200 || probeStatus === 302);
                const hasSuccessToken = successPatterns.test(probeText) && !successPatterns.test(baselineText);
                const hasSuccessRedirect = probeLocation.length > 0 && !probeLocation.includes('login') && !probeLocation.includes('fail') &&
                  (probeLocation.includes('main') || probeLocation.includes('account') || probeLocation.includes('dashboard') || probeLocation.includes('admin') || probeLocation.includes('home') || probeLocation.includes('bank'));

                if (hasSuccessRedirect || (hadFailure && (bypassedFailure || hasSuccessToken))) {
                  isVulnerable = true;
                  confidence = 'Confirmed';
                  evidence = hasSuccessRedirect
                    ? `SQL injection authentication bypass detected: Probe payload "${p.payload}" triggered redirect to authenticated destination "${probeHeaders['location']}".`
                    : `SQL boolean tautology bypassed application logic. Baseline returned authentication failure, but probe payload "${p.payload}" resulted in successful state alteration.`;
                }
              }

              // Check A3: 500 Internal Server Error Anomaly on single quote
              if (!isVulnerable && p.payload === "'" && baselineStatus < 500 && probeStatus >= 500) {
                isVulnerable = true;
                confidence = 'High';
                evidence = `Unescaped single quote triggered HTTP ${probeStatus} Internal Server Error, indicating unhandled database query syntax exception.`;
              }
            }

            // Check B: Reflected Payload (XSS, Command Injection Canary)
            if (p.detectionType === 'reflection' && p.expectedMatch) {
              if (probeText.includes(p.expectedMatch) && !baselineText.includes(p.expectedMatch)) {
                isVulnerable = true;
                confidence = 'Confirmed';
                evidence = `Unencoded probe string reflected in response body: "${p.expectedMatch}"`;
              }
            }

            // Check C: Mathematical / Expression Evaluation (SSTI)
            if (p.detectionType === 'eval_match' && p.expectedMatch) {
              if (
                probeText.includes(p.expectedMatch) &&
                !baselineText.includes(p.expectedMatch) &&
                !probeText.includes(p.payload)
              ) {
                isVulnerable = true;
                confidence = 'Confirmed';
                evidence = `Dynamic template evaluation detected: expression "${p.payload}" resulted in computed string "${p.expectedMatch}"`;
              }
            }

            // Check D: Timing Anomaly (Time-based Blind SQLi)
            if (p.detectionType === 'time_delay' && p.expectedDelayMs) {
              const expectedDelay = p.expectedDelayMs;
              if (probeDuration >= expectedDelay * 0.8 && probeDuration > baselineDuration + 1500) {
                isVulnerable = true;
                confidence = 'High';
                evidence = `Response time anomaly: baseline response took ${baselineDuration}ms, probe took ${probeDuration}ms (~${expectedDelay}ms expected delay).`;
              }
            }

            if (isVulnerable) {
              findings.push({
                inputPointTested: `${input.method} ${input.actionUrl} [${input.name}] (${input.location})`,
                payloadUsed: p.payload,
                vulnerabilityType: p.name,
                confidence,
                evidence,
                severity: p.severity || 'High',
                cvss: p.cvss || 8.0,
                cwe: p.cwe || 'CWE-89',
                owasp: p.owasp || 'A03:2021-Injection',
                recommendation: p.recommendation || 'Sanitize and parameterize all input points.',
              });
            }
          } catch {
            // Continue testing remaining probes
          }

          await sleep(rateLimitDelay);
        }
      }
    }
  }

  // 10. Summary Calculation
  const headerValues = Object.values(securityHeaders);
  const passedHeaders = headerValues.filter((h) => h.status === 'pass').length;
  const failedHeaders = headerValues.filter((h) => h.status === 'fail').length;
  const warnedHeaders = headerValues.filter((h) => h.status === 'warn').length;

  const SEVERITY_SCORES: Record<string, number> = { Critical: 10, High: 8, Medium: 5, Low: 2, Info: 0 };
  const highestSeverity = findings.reduce((highest, f) => {
    return (SEVERITY_SCORES[f.severity] || 0) > (SEVERITY_SCORES[highest] || 0) ? f.severity : highest;
  }, 'Info' as string);

  const riskScore =
    findings.length > 0
      ? Math.min(10, findings.reduce((sum, f) => sum + (f.cvss || 5.0), 0) / findings.length)
      : 0;

  const totalParams =
    parsedUrl.searchParams.size +
    discovered.linksWithParams.length +
    discovered.forms.reduce((acc, f) => acc + f.inputs.length, 0);

  return {
    targetUrl: rawUrl,
    normalizedUrl,
    scanTimestamp: timestamp,
    scanMode: effectiveMode,
    statusCode: rootResponse.status,
    responseTimeMs,
    serverBanner: (responseHeaders['server'] as string) || undefined,
    headers: securityHeaders,
    discoveredEndpoints: discovered,
    findings,
    summary: {
      totalPages: 1,
      formsCount: discovered.forms.length,
      paramsCount: totalParams,
      scriptEndpointsCount: discovered.scriptApiEndpoints.length,
      totalFindings: findings.length,
      riskScore: Math.round(riskScore * 10) / 10,
      highestSeverity,
      headersCompliance: {
        passed: passedHeaders,
        failed: failedHeaders,
        warned: warnedHeaders,
        total: headerValues.length,
      },
    },
    auditLog: {
      timestamp,
      target: normalizedUrl,
      mode: effectiveMode,
      authorized,
      isLocalTarget: isLocal,
    },
  };
}
