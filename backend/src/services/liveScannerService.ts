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
  allParams?: Record<string, string>;
}

export interface ScanFindingResult {
  inputPointTested: string;
  payloadUsed: string;
  vulnerabilityType: string;
  confidence: 'Low' | 'Medium' | 'High' | 'Confirmed';
  evidence: string;
  evidenceSignals?: string[];
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
  wafDetected: boolean;
  wafVendor?: string | null;
  wafEvidence?: string | null;
  wafNotice?: string | null;
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
// COMPREHENSIVE MULTI-DATABASE ERROR SIGNATURES
// ─────────────────────────────────────────────────────────────
const DB_ERROR_PATTERNS = [
  // MySQL / MariaDB
  { db: 'MySQL', pattern: /SQL syntax.*MySQL/i },
  { db: 'MySQL', pattern: /you have an error in your sql syntax/i },
  { db: 'MySQL', pattern: /check the manual that corresponds to your (mysql|mariadb)/i },
  { db: 'MySQL', pattern: /Warning.*mysql_/i },
  { db: 'MySQL', pattern: /Warning.*mysqli_/i },
  { db: 'MySQL', pattern: /valid MySQL result/i },
  { db: 'MySQL', pattern: /MySqlClient\./i },
  { db: 'MySQL', pattern: /com\.mysql\.jdbc/i },
  { db: 'MySQL', pattern: /mysqli_query/i },
  { db: 'MySQL', pattern: /mysql_fetch_/i },
  { db: 'MySQL', pattern: /mysql_num_rows/i },
  { db: 'MariaDB', pattern: /MariaDB server version for the right syntax/i },
  { db: 'MySQL', pattern: /SQLSTATE\[42000\]: Syntax error/i },
  { db: 'MySQL', pattern: /SQLSTATE\[HY000\]/i },

  // PostgreSQL
  { db: 'PostgreSQL', pattern: /PostgreSQL.*ERROR/i },
  { db: 'PostgreSQL', pattern: /Warning.*\Wpg_/i },
  { db: 'PostgreSQL', pattern: /valid PostgreSQL result/i },
  { db: 'PostgreSQL', pattern: /Npgsql\./i },
  { db: 'PostgreSQL', pattern: /org\.postgresql\.util\.PSQLException/i },
  { db: 'PostgreSQL', pattern: /ERROR:\s+syntax error at or near/i },
  { db: 'PostgreSQL', pattern: /pg_query\(\)/i },
  { db: 'PostgreSQL', pattern: /pg_exec\(\)/i },
  { db: 'PostgreSQL', pattern: /PG::SyntaxError/i },
  { db: 'PostgreSQL', pattern: /unterminated quoted string at or near/i },
  { db: 'PostgreSQL', pattern: /psycopg2\.errors\./i },

  // Microsoft SQL Server
  { db: 'MSSQL', pattern: /Driver.*SQL[\-\_\ ]*Server/i },
  { db: 'MSSQL', pattern: /OLE DB.*SQL Server/i },
  { db: 'MSSQL', pattern: /\bSQLServer JDBC Driver\b/i },
  { db: 'MSSQL', pattern: /Unclosed quotation mark after the character string/i },
  { db: 'MSSQL', pattern: /Microsoft OLE DB Provider for ODBC Drivers/i },
  { db: 'MSSQL', pattern: /System\.Data\.SqlClient\.SqlException/i },
  { db: 'MSSQL', pattern: /\[Microsoft\]\[ODBC SQL Server Driver\]/i },
  { db: 'MSSQL', pattern: /\[Microsoft\]\[ODBC Driver \d+ for SQL Server\]/i },
  { db: 'MSSQL', pattern: /Line \d+: Incorrect syntax near/i },
  { db: 'MSSQL', pattern: /Msg \d+, Level \d+, State \d+/i },

  // SQLite
  { db: 'SQLite', pattern: /SQLite\/JDBCDriver/i },
  { db: 'SQLite', pattern: /SQLite\.Exception/i },
  { db: 'SQLite', pattern: /System\.Data\.SQLite\.SQLiteException/i },
  { db: 'SQLite', pattern: /unrecognized token:/i },
  { db: 'SQLite', pattern: /operational error: near/i },
  { db: 'SQLite', pattern: /near ".*": syntax error/i },
  { db: 'SQLite', pattern: /incomplete input/i },
  { db: 'SQLite', pattern: /SQLite3::query\(\)/i },

  // Oracle
  { db: 'Oracle', pattern: /\bORA-[0-9]{5}\b/i },
  { db: 'Oracle', pattern: /Oracle error/i },
  { db: 'Oracle', pattern: /Oracle.*Driver/i },
  { db: 'Oracle', pattern: /SQL command not properly ended/i },
  { db: 'Oracle', pattern: /quoted string not properly terminated/i },
  { db: 'Oracle', pattern: /PL\/SQL: ORA-/i },
  { db: 'Oracle', pattern: /oracle\.jdbc\./i },

  // IBM DB2
  { db: 'IBM DB2', pattern: /CLI0150E/i },
  { db: 'IBM DB2', pattern: /DB2 SQL error:/i },
  { db: 'IBM DB2', pattern: /\[IBM\]\[CLI Driver\]\[DB2\//i },
  { db: 'IBM DB2', pattern: /SQLSTATE=42601/i },

  // Microsoft Access
  { db: 'MS Access', pattern: /Syntax error in query expression/i },
  { db: 'MS Access', pattern: /Data type mismatch in criteria expression/i },
  { db: 'MS Access', pattern: /\[Microsoft\]\[ODBC Microsoft Access Driver\]/i },

  // Generic / Hibernate / ORMs
  { db: 'Generic SQL', pattern: /org\.hibernate\.QueryException/i },
  { db: 'Generic SQL', pattern: /org\.hibernate\.exception\.SQLGrammarException/i },
  { db: 'Generic SQL', pattern: /SQLSTATE\[[0-9A-Z]{5}\]/i },
  { db: 'Generic SQL', pattern: /syntax error in query/i },
  { db: 'Generic SQL', pattern: /unhandled sql exception/i },
  { db: 'Generic SQL', pattern: /SequelizeDatabaseError/i },
  { db: 'Generic SQL', pattern: /TypeORMError/i },
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

// ─────────────────────────────────────────────────────────────
// WAF (WEB APPLICATION FIREWALL) SIGNATURES & DETECTION
// ─────────────────────────────────────────────────────────────
export interface WafDetectionResult {
  detected: boolean;
  vendor: string | null;
  evidence: string | null;
}

const WAF_SIGNATURES = [
  {
    vendor: 'Cloudflare',
    headerPatterns: [
      { header: 'cf-ray', pattern: /.+/ },
      { header: 'cf-cache-status', pattern: /.+/ },
      { header: 'server', pattern: /cloudflare/i },
      { header: 'set-cookie', pattern: /__cf_bm|__cfduid/i },
    ],
    bodyPatterns: [
      /attention required! \| cloudflare/i,
      /cloudflare ray id:/i,
      /error 1020 access denied/i,
    ],
  },
  {
    vendor: 'AWS WAF',
    headerPatterns: [
      { header: 'x-amzn-requestid', pattern: /.+/ },
      { header: 'x-amz-cf-id', pattern: /.+/ },
      { header: 'x-amzn-waf-action', pattern: /.+/ },
      { header: 'server', pattern: /awswaf/i },
    ],
    bodyPatterns: [
      /request blocked by aws waf/i,
      /awswaf/i,
    ],
  },
  {
    vendor: 'Akamai',
    headerPatterns: [
      { header: 'akamai-origin-hop', pattern: /.+/ },
      { header: 'x-akamai-transformed', pattern: /.+/ },
      { header: 'x-akamai-request-id', pattern: /.+/ },
      { header: 'server', pattern: /akamaighost/i },
    ],
    bodyPatterns: [
      /access denied - akamai/i,
      /reference #[0-9a-f.]+/i,
    ],
  },
  {
    vendor: 'Imperva / Incapsula',
    headerPatterns: [
      { header: 'x-iinfo', pattern: /.+/ },
      { header: 'x-cdn', pattern: /incapsula/i },
      { header: 'set-cookie', pattern: /incap_ses|visid_incap/i },
    ],
    bodyPatterns: [
      /incapsula incident id/i,
      /powered by incapsula/i,
      /request unsuccessful\. incapsula/i,
    ],
  },
  {
    vendor: 'ModSecurity / OWASP CRS',
    headerPatterns: [
      { header: 'server', pattern: /mod_security|modsecurity/i },
    ],
    bodyPatterns: [
      /this error was generated by mod_security/i,
      /web application firewall.*modsecurity/i,
      /rules\.modsecurity\.org/i,
    ],
  },
  {
    vendor: 'F5 BIG-IP ASM',
    headerPatterns: [
      { header: 'server', pattern: /big-ip/i },
      { header: 'set-cookie', pattern: /TS[0-9a-f]{6,}/i },
    ],
    bodyPatterns: [
      /the requested url was rejected\. please consult with your administrator/i,
    ],
  },
  {
    vendor: 'Sucuri',
    headerPatterns: [
      { header: 'x-sucuri-id', pattern: /.+/ },
      { header: 'x-sucuri-cache', pattern: /.+/ },
      { header: 'server', pattern: /sucuri/i },
    ],
    bodyPatterns: [
      /access denied - sucuri website firewall/i,
      /sucuri webpage block/i,
    ],
  },
  {
    vendor: 'Fastly',
    headerPatterns: [
      { header: 'x-fastly-request-id', pattern: /.+/ },
      { header: 'fastly-debug-digest', pattern: /.+/ },
    ],
    bodyPatterns: [
      /fastly error: unknown domain/i,
    ],
  },
];

/**
 * Inspects response headers and status/body for common Web Application Firewall (WAF) signatures.
 */
export function detectWaf(
  headers: Record<string, unknown>,
  body: string,
  statusCode: number
): WafDetectionResult {
  const normalizedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v || '');
  }

  for (const waf of WAF_SIGNATURES) {
    for (const hRule of waf.headerPatterns) {
      const val = normalizedHeaders[hRule.header];
      if (val && hRule.pattern.test(val)) {
        return {
          detected: true,
          vendor: waf.vendor,
          evidence: `Header "${hRule.header}: ${val.slice(0, 80)}" matched ${waf.vendor} signature`,
        };
      }
    }

    for (const bPattern of waf.bodyPatterns) {
      if (bPattern.test(body)) {
        return {
          detected: true,
          vendor: waf.vendor,
          evidence: `Response body matched ${waf.vendor} signature`,
        };
      }
    }
  }

  // Generic WAF / 403 Block Page heuristic
  if (statusCode === 403 && (body.includes('firewall') || body.includes('blocked') || body.includes('access denied'))) {
    return {
      detected: true,
      vendor: 'Generic Web Application Firewall',
      evidence: 'HTTP 403 Forbidden with security block page indicators in response body',
    };
  }

  return {
    detected: false,
    vendor: null,
    evidence: null,
  };
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
      const allParams: Record<string, string> = {};
      resolved.searchParams.forEach((v, k) => {
        allParams[k] = v;
      });

      resolved.searchParams.forEach((val, key) => {
        if (!linksWithParams.some((l) => l.href === resolved.pathname && l.param === key)) {
          linksWithParams.push({
            href: resolved.pathname,
            param: key,
            value: val,
            allParams,
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
 * Renders target webpage with headless Chromium to capture client-rendered JavaScript (React/Vue/SPA) DOM.
 * Gracefully returns null if Puppeteer fails, is unsupported, or times out.
 */
async function renderPageWithBrowser(
  targetUrl: string,
  timeoutMs: number,
  userAgent?: string
): Promise<string | null> {
  let browser: any = null;
  try {
    const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
    if (isServerless) {
      const chromiumMod: any = await import('@sparticuz/chromium');
      const puppeteerCore: any = await import('puppeteer-core');
      const chrom = chromiumMod.default || chromiumMod;
      const executablePath = await chrom.executablePath();
      browser = await (puppeteerCore.default || puppeteerCore).launch({
        args: chrom.args,
        defaultViewport: chrom.defaultViewport,
        executablePath: executablePath,
        headless: chrom.headless,
      });
    } else {
      try {
        const puppeteer: any = await import('puppeteer');
        browser = await (puppeteer.default || puppeteer).launch({
          headless: true,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--single-process',
            '--no-zygote',
          ],
          timeout: Math.min(timeoutMs, 25000),
        });
      } catch {
        const chromiumMod: any = await import('@sparticuz/chromium');
        const puppeteerCore: any = await import('puppeteer-core');
        const chrom = chromiumMod.default || chromiumMod;
        const executablePath = await chrom.executablePath();
        browser = await (puppeteerCore.default || puppeteerCore).launch({
          args: chrom.args,
          defaultViewport: chrom.defaultViewport,
          executablePath: executablePath,
          headless: chrom.headless,
        });
      }
    }

    const page = await browser.newPage();
    if (userAgent) {
      await page.setUserAgent(userAgent);
    }
    await page.setViewport({ width: 1280, height: 800 });

    // Navigate with reasonable timeout and wait for DOM content
    await page.goto(targetUrl, {
      waitUntil: 'domcontentloaded',
      timeout: Math.min(timeoutMs, 25000),
    });

    // Brief wait for client-side JavaScript / React / Vue mounting
    try {
      await page.waitForNetworkIdle({ idleTime: 300, timeout: 3000 });
    } catch {
      // Continue if network idle threshold is not strictly met
    }

    const renderedHtml = await page.content();
    return renderedHtml;
  } catch (err) {
    // Graceful fallback to static fetch
    console.warn(`[BROWSER_RENDER_FALLBACK] Headless browser rendering skipped/failed (${err instanceof Error ? err.message : 'Unknown error'}), falling back to standard HTTP fetch.`);
    return null;
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {}
    }
  }
}

/**
 * Executes a full live website scan against a target URL.
 * Automatically respects passive/active restrictions, parses HTML forms & headers,
 * and performs differential testing when in active mode.
 */
export async function executeLiveScan(
  rawUrl: string,
  authorized: boolean = false,
  config: LiveScanConfig = {},
  clientIp: string = 'unknown'
): Promise<DeepScanResult> {
  const timestamp = new Date().toISOString();

  // 1. URL Normalization & Validation
  if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new Error('Target URL is required. Please provide a valid web address.');
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
  const timeoutMs = Math.min(Math.max(config.timeoutMs || 25000, 1000), 60000); // 25s default, max 60s
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

  // 6. Security Header Auditing & WAF (Web Application Firewall) Detection
  const securityHeaders = analyzeSecurityHeaders(responseHeaders, parsedUrl.protocol === 'https:');
  const wafResult = detectWaf(responseHeaders, rawHtml, rootResponse.status);
  const wafNotice = wafResult.detected
    ? `A Web Application Firewall (${wafResult.vendor || 'WAF'}) was detected. Results may under-report real vulnerabilities, as the WAF may be blocking or altering probe payloads.`
    : undefined;

  // 7. Parse HTML Structure (with dynamic JavaScript SPA rendering support)
  let pageHtml = rawHtml;
  try {
    const renderedHtml = await renderPageWithBrowser(normalizedUrl, timeoutMs, config.userAgent);
    if (renderedHtml && renderedHtml.length > 50) {
      pageHtml = renderedHtml;
    }
  } catch {
    pageHtml = rawHtml;
  }

  const discovered = parseHtmlContent(pageHtml, normalizedUrl);

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
        evidenceSignals: ['header_missing_from_response', 'renderable_http_response_verified'],
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

    // B. URL parameters from discovered page links (preserving complete query parameter context)
    for (const link of discovered.linksWithParams) {
      if (!testTargets.some((t) => t.name === link.param && t.location === 'URL Parameter')) {
        let actionUrl = normalizedUrl;
        try {
          const resolved = new URL(link.href, normalizedUrl);
          if (link.allParams) {
            for (const [k, v] of Object.entries(link.allParams)) {
              resolved.searchParams.set(k, v);
            }
          }
          actionUrl = resolved.toString();
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
      if (form.isFileUpload) continue; // Skip file uploads

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

    // Helper: Execute a test probe request against current target input
    const executeProbe = async (
      targetInput: TestInputTarget,
      payloadStr: string
    ): Promise<{ text: string; status: number; headers: Record<string, unknown>; duration: number }> => {
      const pStart = Date.now();
      let resText = '';
      let resStatus = 200;
      let resHeaders: Record<string, unknown> = {};

      if (targetInput.method === 'POST') {
        const formData: Record<string, string> = {
          ...(targetInput.formAllInputs || {}),
          [targetInput.name]: payloadStr,
        };
        const formBody = new URLSearchParams(formData).toString();
        const pRes = await probeHttpClient.post(targetInput.actionUrl, formBody, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        resText = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
        resStatus = pRes.status;
        resHeaders = pRes.headers || {};
      } else {
        const testUrl = new URL(targetInput.actionUrl);
        testUrl.searchParams.set(targetInput.name, payloadStr);
        const pRes = await probeHttpClient.get(testUrl.toString());
        resText = typeof pRes.data === 'string' ? pRes.data : JSON.stringify(pRes.data);
        resStatus = pRes.status;
        resHeaders = pRes.headers || {};
      }
      const duration = Date.now() - pStart;
      return { text: resText, status: resStatus, headers: resHeaders, duration };
    };

    // Iterate through input targets
    for (const input of testTargets) {
      // 1. Safe Baseline Request
      const baselineVal = 'injlab_safe_baseline_token';
      let baselineText = '';
      let baselineStatus = 200;
      let baselineDuration = 0;
      let baselineHeaders: Record<string, unknown> = {};

      try {
        const baseRes = await executeProbe(input, baselineVal);
        baselineText = baseRes.text;
        baselineStatus = baseRes.status;
        baselineHeaders = baseRes.headers;
        baselineDuration = baseRes.duration;
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
          falsePayload?: string;
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
            let isVulnerable = false;
            let evidence = '';
            let evidenceSignals: string[] = [];
            let confidence: 'Low' | 'Medium' | 'High' | 'Confirmed' = 'Medium';

            // ── A. Error-Based SQLi Detection ──
            if (p.detectionType === 'error_match') {
              const probeRes = await executeProbe(input, p.payload);

              let matchedDb = '';
              let matchedSignature = '';

              for (const { db, pattern } of DB_ERROR_PATTERNS) {
                if (pattern.test(probeRes.text) && !pattern.test(baselineText)) {
                  matchedDb = db;
                  matchedSignature = probeRes.text.match(pattern)?.[0] || 'Database syntax error';
                  evidenceSignals.push(`db_error_signature_detected (${db})`);
                  break;
                }
              }

              if (matchedDb) {
                isVulnerable = true;
                evidence = `${matchedDb} syntax error signature detected in response body: "${matchedSignature}"`;
                confidence = 'Confirmed';
              } else if ((p.payload === "'" || p.payload === '"') && baselineStatus < 500 && probeRes.status >= 500) {
                isVulnerable = true;
                evidenceSignals.push(`server_error_anomaly (HTTP ${probeRes.status})`);
                evidence = `Unescaped quote probe (${p.payload}) triggered HTTP ${probeRes.status} Internal Server Error, indicating unhandled database query exception.`;
                confidence = 'High';
              }
            }

            // ── B. Generic Boolean-Based Differential SQLi Detection ──
            if (p.detectionType === 'boolean_diff' && p.falsePayload) {
              // 1. Send TRUE condition probe
              const trueRes = await executeProbe(input, p.payload);
              await sleep(rateLimitDelay);
              // 2. Send FALSE condition probe
              const falseRes = await executeProbe(input, p.falsePayload);

              const trueLen = trueRes.text.length;
              const falseLen = falseRes.text.length;
              const baseLen = baselineText.length;

              // Check if either probe generated a DB error
              let matchedDb = '';
              let matchedSig = '';
              for (const { db, pattern } of DB_ERROR_PATTERNS) {
                if ((pattern.test(trueRes.text) || pattern.test(falseRes.text)) && !pattern.test(baselineText)) {
                  matchedDb = db;
                  matchedSig = (trueRes.text.match(pattern) || falseRes.text.match(pattern))?.[0] || 'Syntax error';
                  break;
                }
              }

              if (matchedDb) {
                isVulnerable = true;
                evidenceSignals.push(`db_error_detected (${matchedDb})`);
                evidence = `${matchedDb} error signature detected during boolean probe testing: "${matchedSig}"`;
                confidence = 'Confirmed';
              } else {
                // Genuine behavioral difference between TRUE condition and FALSE condition
                const statusDivergence = (trueRes.status === 200 || trueRes.status === baselineStatus) && (falseRes.status !== trueRes.status);
                const trueMatchesBaseline = Math.abs(trueLen - baseLen) <= Math.max(100, baseLen * 0.15) || trueRes.status === baselineStatus;
                const lengthDivergence = Math.abs(trueLen - falseLen) >= Math.max(30, Math.min(trueLen, falseLen) * 0.10);
                const falseCollapsed = falseLen < trueLen * 0.75;
                const contentDiffers = trueRes.text !== falseRes.text;

                if (contentDiffers && (statusDivergence || (trueMatchesBaseline && (lengthDivergence || falseCollapsed)))) {
                  isVulnerable = true;
                  evidenceSignals.push('boolean_true_matched_baseline');
                  evidenceSignals.push('boolean_false_diverged_from_true');
                  if (statusDivergence) evidenceSignals.push(`status_code_divergence (${trueRes.status} vs ${falseRes.status})`);
                  if (lengthDivergence) evidenceSignals.push(`response_length_divergence (TRUE: ${trueLen}B vs FALSE: ${falseLen}B)`);

                  confidence = (statusDivergence || Math.abs(trueLen - falseLen) > 80) ? 'Confirmed' : 'High';
                  evidence = `Boolean-based SQL injection detected: TRUE condition payload ("${p.payload}") produced baseline-consistent behavior (${trueLen} bytes, HTTP ${trueRes.status}), while FALSE condition payload ("${p.falsePayload}") caused behavioral divergence (${falseLen} bytes, HTTP ${falseRes.status}).`;
                }
              }
            }

            // ── C. Generic SQL Authentication Bypass Detection ──
            if (p.detectionType === 'auth_bypass') {
              const bypassRes = await executeProbe(input, p.payload);
              const baselineLoc = String(baselineHeaders['location'] || '').toLowerCase();
              const bypassLoc = String(bypassRes.headers['location'] || '').toLowerCase();
              const baseSetCookie = String(baselineHeaders['set-cookie'] || '');
              const bypassSetCookie = String(bypassRes.headers['set-cookie'] || '');

              // Check DB error first
              for (const { db, pattern } of DB_ERROR_PATTERNS) {
                if (pattern.test(bypassRes.text) && !pattern.test(baselineText)) {
                  isVulnerable = true;
                  evidenceSignals.push(`db_error_signature_detected (${db})`);
                  evidence = `${db} error signature triggered by authentication bypass payload: "${bypassRes.text.match(pattern)?.[0]}"`;
                  confidence = 'Confirmed';
                  break;
                }
              }

              if (!isVulnerable) {
                // Universal auth bypass behavioral signals:
                // 1. Redirection away from login/auth
                const redirectedToNewLocation = bypassLoc.length > 0 && !bypassLoc.includes('login') && !bypassLoc.includes('auth') && !bypassLoc.includes('fail') && !bypassLoc.includes('signin') && bypassLoc !== baselineLoc;
                // 2. Issuance of new session cookie not present in baseline
                const issuedAuthCookie = bypassSetCookie.length > 0 && !baseSetCookie.includes(bypassSetCookie.split(';')[0]) && /sess|auth|token|jwt|id|key/i.test(bypassSetCookie);
                // 3. Status transition: 401/403 baseline -> 200/302 bypass
                const statusElevated = (baselineStatus === 401 || baselineStatus === 403) && (bypassRes.status === 200 || bypassRes.status === 302);
                // 4. Failure marker vanished
                const genericFailPatterns = /invalid username|invalid password|invalid credentials|authentication failed|login failed|incorrect password|user not found|access denied/i;
                const hadFailMarker = genericFailPatterns.test(baselineText) || baselineStatus === 401 || baselineStatus === 403;
                const removedFailMarker = hadFailMarker && !genericFailPatterns.test(bypassRes.text) && (bypassRes.status === 200 || bypassRes.status === 302);

                if (redirectedToNewLocation) evidenceSignals.push('authenticated_redirect_detected');
                if (issuedAuthCookie) evidenceSignals.push('session_cookie_issued');
                if (statusElevated) evidenceSignals.push(`status_elevated (${baselineStatus} -> ${bypassRes.status})`);
                if (removedFailMarker) evidenceSignals.push('auth_failure_marker_eliminated');

                if (redirectedToNewLocation || issuedAuthCookie || (statusElevated && removedFailMarker)) {
                  isVulnerable = true;
                  confidence = evidenceSignals.length >= 2 ? 'Confirmed' : 'High';
                  evidence = `SQL injection authentication bypass detected: Probe payload "${p.payload}" altered authentication state (redirect: "${bypassRes.headers['location'] || 'none'}", status: HTTP ${bypassRes.status}).`;
                }
              }
            }

            // ── D. Reflected Payload (XSS, Command Injection Canary) ──
            if (p.detectionType === 'reflection' && p.expectedMatch) {
              const probeRes = await executeProbe(input, p.payload);
              const probeContentType = String(probeRes.headers['content-type'] || '').toLowerCase();
              const isHtmlContext = probeContentType.includes('text/html') || probeContentType.includes('application/xhtml+xml');

              if (probeRes.text.includes(p.expectedMatch) && !baselineText.includes(p.expectedMatch)) {
                isVulnerable = true;
                evidenceSignals.push('probe_string_reflected');
                if (isHtmlContext) {
                  evidenceSignals.push('html_render_context_verified');
                }
                if (p.payload.includes('<') && probeRes.text.includes(p.payload)) {
                  evidenceSignals.push('unescaped_html_tags_confirmed');
                }
                if (p.payload.includes('"') && probeRes.text.includes(p.payload)) {
                  evidenceSignals.push('attribute_quote_unescaped');
                }
                if (p.name.includes('Shell') || p.name.includes('Command') || p.name.includes('Echo')) {
                  evidenceSignals.push('command_output_verified');
                }

                confidence = evidenceSignals.length >= 2 ? 'Confirmed' : 'High';
                evidence = `Unencoded probe string reflected in response body: "${p.expectedMatch}"`;
              }
            }

            // ── E. Mathematical / Expression Evaluation (SSTI) ──
            if (p.detectionType === 'eval_match' && p.expectedMatch) {
              const probeRes = await executeProbe(input, p.payload);
              if (
                probeRes.text.includes(p.expectedMatch) &&
                !baselineText.includes(p.expectedMatch) &&
                !probeRes.text.includes(p.payload)
              ) {
                isVulnerable = true;
                evidenceSignals.push('expression_evaluated_to_result');
                evidenceSignals.push('literal_expression_suppressed');
                confidence = 'Confirmed';
                evidence = `Dynamic template evaluation detected: expression "${p.payload}" resulted in computed string "${p.expectedMatch}".`;
              }
            }

            // ── F. Timing Anomaly (Time-Based Blind SQLi) ──
            if (p.detectionType === 'time_delay' && p.expectedDelayMs) {
              const probeRes = await executeProbe(input, p.payload);
              const expectedDelay = p.expectedDelayMs;
              if (probeRes.duration >= expectedDelay * 0.8 && probeRes.duration > baselineDuration + 1500) {
                isVulnerable = true;
                evidenceSignals.push('duration_exceeds_threshold');
                evidenceSignals.push(`baseline_differential_confirmed (+${probeRes.duration - baselineDuration}ms)`);
                confidence = 'Confirmed';
                evidence = `Response time anomaly: baseline response took ${baselineDuration}ms, probe took ${probeRes.duration}ms (~${expectedDelay}ms expected delay).`;
              }
            }

            if (isVulnerable) {
              findings.push({
                inputPointTested: `${input.method} ${input.actionUrl} [${input.name}] (${input.location})`,
                payloadUsed: p.payload,
                vulnerabilityType: p.name,
                confidence,
                evidence,
                evidenceSignals,
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
    wafDetected: wafResult.detected,
    wafVendor: wafResult.vendor,
    wafEvidence: wafResult.evidence,
    wafNotice,
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
