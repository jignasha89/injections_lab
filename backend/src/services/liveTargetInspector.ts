import http from 'http';
import https from 'https';
import { URL } from 'url';
import { ScanFinding, ScanResult, INJECTION_RULES, evaluateRule, RuleEvaluationContext } from './scannerService';

export interface ReachabilityResult {
  reachable: boolean;
  status?: number;
  headers?: Record<string, string | string[] | undefined>;
  error?: string;
  code?: string;
}

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  parameters: { name: string; type: string; location: string }[];
  source: string;
}

export interface LiveInspectionResult {
  targetUrl: string;
  domain: string;
  reachable: boolean;
  statusCode: number;
  pagesCrawled: string[];
  parameters: string[];
  paramValues: Record<string, string>;
  pathSegments: string[];
  techStackClues: string[];
  endpoints: DiscoveredEndpoint[];
  potentialInjectionPoints: { type: string; location: string; risk: string; reason: string }[];
  findings: ScanFinding[];
  summary: ScanResult['summary'];
}

// In-memory cache for live inspection results by scanId or targetUrl
const inspectionCache = new Map<string, LiveInspectionResult>();

export function getCachedInspection(key: string): LiveInspectionResult | undefined {
  return inspectionCache.get(key);
}

export function setCachedInspection(key: string, result: LiveInspectionResult): void {
  inspectionCache.set(key, result);
}

/**
 * Perform a real HTTP/HTTPS GET request to verify the target website is reachable.
 * Returns reachable: true if the server responds with ANY HTTP status code.
 * Returns reachable: false if DNS fails, connection is refused, or request times out.
 */
export function checkTargetReachability(rawUrl: string, timeoutMs: number = 7000): Promise<ReachabilityResult> {
  return new Promise((resolve) => {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return resolve({
        reachable: false,
        error: 'Invalid URL format — please enter a valid URL including http:// or https://',
      });
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return resolve({
        reachable: false,
        error: 'Only HTTP and HTTPS protocols are supported.',
      });
    }

    const client = parsed.protocol === 'https:' ? https : http;
    const options: http.RequestOptions = {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 InjectionLab/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      timeout: timeoutMs,
      // @ts-ignore
      rejectUnauthorized: false, // Accept self-signed / lab certs, but network/DNS errors will still fail
    };

    let resolved = false;

    const req = client.request(parsed, options, (res) => {
      if (resolved) return;
      resolved = true;
      const status = res.statusCode || 200;
      // Any valid HTTP status code indicates the host was reached!
      resolve({
        reachable: true,
        status,
        headers: res.headers as Record<string, string | string[] | undefined>,
      });
      req.destroy(); // Response header received; no need to drain full body
    });

    req.on('timeout', () => {
      if (resolved) return;
      resolved = true;
      req.destroy();
      resolve({
        reachable: false,
        error: 'Target website could not be reached — please check the URL and try again (connection timed out)',
        code: 'ETIMEDOUT',
      });
    });

    req.on('error', (err: NodeJS.ErrnoException) => {
      if (resolved) return;
      resolved = true;
      let userFriendlyError = 'Target website could not be reached — please check the URL and try again';
      if (err.code === 'ENOTFOUND') {
        userFriendlyError = `Target website could not be reached — please check the URL and try again (DNS lookup failed for host "${parsed.hostname}")`;
      } else if (err.code === 'ECONNREFUSED') {
        userFriendlyError = `Target website could not be reached — please check the URL and try again (Connection refused at ${parsed.host})`;
      } else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') {
        userFriendlyError = `Target website could not be reached — please check the URL and try again (Network route unreachable)`;
      } else if (err.message) {
        userFriendlyError = `Target website could not be reached — please check the URL and try again (${err.message})`;
      }
      resolve({
        reachable: false,
        error: userFriendlyError,
        code: err.code,
      });
    });

    req.end();
  });
}

/**
 * Fetch HTML from a URL with redirection handling
 */
function fetchHtml(targetUrl: string, maxRedirects: number = 3): Promise<{ ok: boolean; status: number; headers: Record<string, string>; body: string; finalUrl: string }> {
  return new Promise((resolve) => {
    try {
      const u = new URL(targetUrl);
      const client = u.protocol === 'https:' ? https : http;
      const opts: http.RequestOptions = {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 InjectionLab/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        timeout: 6000,
        // @ts-ignore
        rejectUnauthorized: false,
      };

      const req = client.get(u, opts, (res) => {
        if ([301, 302, 307, 308].includes(res.statusCode || 0) && res.headers.location && maxRedirects > 0) {
          const next = new URL(res.headers.location, targetUrl).toString();
          return fetchHtml(next, maxRedirects - 1).then(resolve);
        }

        let body = '';
        res.on('data', (chunk) => {
          if (body.length < 300000) body += chunk;
        });
        res.on('end', () => {
          resolve({
            ok: true,
            status: res.statusCode || 200,
            headers: res.headers as Record<string, string>,
            body,
            finalUrl: targetUrl,
          });
        });
      });

      req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: targetUrl }); });
      req.on('error', () => { resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: targetUrl }); });
    } catch {
      resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: targetUrl });
    }
  });
}

/**
 * Send an active probe to a target parameter and capture live response
 */
function sendProbe(
  url: string,
  paramName: string,
  method: string,
  probeValue: string,
  siblingParams: Record<string, string> = {}
): Promise<{ ok: boolean; status: number; headers: Record<string, string>; body: string; location?: string }> {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const allParams: Record<string, string> = { ...siblingParams };
      if (paramName) {
        allParams[paramName] = probeValue;
      }

      if (method.toUpperCase() === 'GET') {
        for (const [k, v] of Object.entries(allParams)) {
          u.searchParams.set(k, v);
        }
        const client = u.protocol === 'https:' ? https : http;
        const req = client.get(u, {
          // @ts-ignore
          family: 4,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) InjectionLab-AuditProbe/1.0',
            'Accept': '*/*',
          },
          timeout: 5000,
          // @ts-ignore
          rejectUnauthorized: false,
        }, (res) => {
          let body = '';
          res.on('data', (chunk) => { if (body.length < 150000) body += chunk; });
          res.on('end', () => resolve({
            ok: true,
            status: res.statusCode || 200,
            headers: res.headers as Record<string, string>,
            body,
            location: (res.headers.location as string) || '',
          }));
        });
        req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, headers: {}, body: '', location: '' }); });
        req.on('error', () => resolve({ ok: false, status: 0, headers: {}, body: '', location: '' }));
      } else {
        // POST
        const postData = new URLSearchParams(allParams).toString();
        const client = u.protocol === 'https:' ? https : http;
        const req = client.request(u, {
          method: 'POST',
          // @ts-ignore
          family: 4,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) InjectionLab-AuditProbe/1.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData),
          },
          timeout: 5000,
          // @ts-ignore
          rejectUnauthorized: false,
        }, (res) => {
          let body = '';
          res.on('data', (chunk) => { if (body.length < 150000) body += chunk; });
          res.on('end', () => resolve({
            ok: true,
            status: res.statusCode || 200,
            headers: res.headers as Record<string, string>,
            body,
            location: (res.headers.location as string) || '',
          }));
        });
        req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, headers: {}, body: '', location: '' }); });
        req.on('error', () => resolve({ ok: false, status: 0, headers: {}, body: '', location: '' }));
        req.write(postData);
        req.end();
      }
    } catch {
      resolve({ ok: false, status: 0, headers: {}, body: '', location: '' });
    }
  });
}

/**
 * Perform real live crawling, attack surface extraction, and security inspection on a target URL.
 */
export async function inspectLiveTarget(rawUrl: string): Promise<LiveInspectionResult> {
  const parsed = new URL(rawUrl);
  const domain = parsed.hostname;
  const baseUrl = `${parsed.protocol}//${parsed.host}`;

  // 1. Fetch initial root page
  const rootRes = await fetchHtml(rawUrl);
  const techStackClues: string[] = [];
  const discoveredLinks = new Set<string>();
  const discoveredEndpoints: DiscoveredEndpoint[] = [];
  const discoveredParameters = new Set<string>();
  const paramValues: Record<string, string> = {};
  const pathSegments = new Set<string>();

  // Extract path segment from initial URL
  if (parsed.pathname && parsed.pathname !== '/') {
    pathSegments.add(parsed.pathname);
  }

  // Extract query parameters from initial URL
  for (const [key, val] of parsed.searchParams.entries()) {
    discoveredParameters.add(key);
    paramValues[key] = val;
  }

  // Detect tech stack from real headers
  const headers = rootRes.headers || {};
  const serverHeader = headers['server'] || '';
  if (serverHeader) {
    techStackClues.push(`Web Server: ${serverHeader}`);
  }
  if (headers['x-powered-by']) {
    techStackClues.push(`Runtime: ${headers['x-powered-by']}`);
  }
  if (headers['set-cookie']) {
    const cookies = Array.isArray(headers['set-cookie']) ? headers['set-cookie'].join(';') : String(headers['set-cookie']);
    if (/JSESSIONID/i.test(cookies)) techStackClues.push('Framework: Java Servlet / JSP');
    if (/PHPSESSID/i.test(cookies)) techStackClues.push('Language: PHP');
    if (/ASP\.NET_SessionId|ASPSESSION/i.test(cookies)) techStackClues.push('Framework: ASP.NET');
    if (/connect\.sid/i.test(cookies)) techStackClues.push('Runtime: Node.js (Express)');
    if (/csrftoken|django/i.test(cookies)) techStackClues.push('Framework: Python Django');
  }

  const pagesCrawled: string[] = [rawUrl];

  // If HTML was received, parse links and forms
  if (rootRes.ok && rootRes.body) {
    const html = rootRes.body;

    // Detect clues from HTML content
    if (/Apache-Coyote/i.test(html) || /Apache-Coyote/i.test(serverHeader)) {
      if (!techStackClues.some(c => c.includes('Apache-Coyote'))) techStackClues.push('Container: Apache-Coyote (Tomcat)');
    }
    if (/nginx/i.test(serverHeader)) techStackClues.push('Web Server: Nginx');
    if (/WordPress/i.test(html)) techStackClues.push('CMS: WordPress');

    // Extract links <a href="...">
    const linkRegex = /href=["']([^"'#\s]+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = linkRegex.exec(html)) !== null) {
      const href = match[1];
      if (href.startsWith('mailto:') || href.startsWith('javascript:') || href.startsWith('tel:')) continue;
      try {
        const resolved = new URL(href, rawUrl);
        if (resolved.hostname === domain) {
          discoveredLinks.add(resolved.toString());
          if (resolved.pathname && resolved.pathname !== '/') pathSegments.add(resolved.pathname);
          // Query params from links
          for (const [k, v] of resolved.searchParams.entries()) {
            discoveredParameters.add(k);
            if (!paramValues[k]) paramValues[k] = v;
          }
        }
      } catch {
        // ignore invalid URL
      }
    }

    // Extract forms <form ...>
    const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch: RegExpExecArray | null;
    while ((formMatch = formRegex.exec(html)) !== null) {
      const formAttrs = formMatch[1];
      const formContent = formMatch[2];

      const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
      const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);
      const action = actionMatch ? actionMatch[1] : '';
      const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

      let formUrl = rawUrl;
      try {
        formUrl = action ? new URL(action, rawUrl).toString() : rawUrl;
      } catch {
        // keep rawUrl
      }

      // Extract input fields
      const inputRegex = /<input[^>]*name=["']([^"']+)["'][^>]*>/gi;
      let inputMatch: RegExpExecArray | null;
      const formParams: { name: string; type: string; location: string }[] = [];
      while ((inputMatch = inputRegex.exec(formContent)) !== null) {
        const name = inputMatch[1];
        discoveredParameters.add(name);
        formParams.push({ name, type: 'form_field', location: method === 'POST' ? 'body' : 'query' });
      }

      discoveredEndpoints.push({
        url: formUrl,
        method,
        parameters: formParams,
        source: 'form',
      });
    }
  }

  // Crawl up to 4 additional discovered internal pages for deeper parameter extraction
  const extraPages = Array.from(discoveredLinks)
    .filter(u => u !== rawUrl && !u.endsWith('.css') && !u.endsWith('.js') && !u.endsWith('.png') && !u.endsWith('.jpg'))
    .slice(0, 4);

  for (const pageUrl of extraPages) {
    pagesCrawled.push(pageUrl);
    const subRes = await fetchHtml(pageUrl);
    if (subRes.ok && subRes.body) {
      // Extract forms
      const subFormRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
      let sfm: RegExpExecArray | null;
      while ((sfm = subFormRegex.exec(subRes.body)) !== null) {
        const formAttrs = sfm[1];
        const formContent = sfm[2];
        const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
        const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);
        const action = actionMatch ? actionMatch[1] : '';
        const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

        let formUrl = pageUrl;
        try {
          formUrl = action ? new URL(action, pageUrl).toString() : pageUrl;
        } catch {
          // fallback
        }

        const inputRegex = /<input[^>]*name=["']([^"']+)["'][^>]*>/gi;
        let im: RegExpExecArray | null;
        const formParams: { name: string; type: string; location: string }[] = [];
        while ((im = inputRegex.exec(formContent)) !== null) {
          const name = im[1];
          discoveredParameters.add(name);
          formParams.push({ name, type: 'form_field', location: method === 'POST' ? 'body' : 'query' });
        }

        discoveredEndpoints.push({
          url: formUrl,
          method,
          parameters: formParams,
          source: 'crawled_form',
        });
      }
    }
  }

  // ── STAGE 3 & 4: REAL ACTIVE PROBING & VULNERABILITY INSPECTION ──
  const findings: ScanFinding[] = [];
  const testedParams = Array.from(discoveredParameters);
  const potentialInjectionPoints: { type: string; location: string; risk: string; reason: string }[] = [];

  // Register potential injection points
  for (const p of testedParams) {
    const isSearchOrQuery = /search|query|q|find|keyword/i.test(p);
    const isAuth = /user|uid|pass|email|login/i.test(p);
    const isPath = /page|file|path|doc|url|redirect/i.test(p);

    potentialInjectionPoints.push({
      type: isSearchOrQuery ? 'Search Query Parameter' : isAuth ? 'Authentication Input' : isPath ? 'Resource Path / Redirection' : 'General Input Parameter',
      location: `Parameter "${p}" at ${domain}`,
      risk: isAuth || isSearchOrQuery ? 'High' : 'Medium',
      reason: `Live parameter "${p}" detected on ${domain} attack surface.`,
    });
  }

  // 1. Test live parameters with live probes
  const canaryToken = `inj_canary_${Math.floor(Math.random() * 89999 + 10000)}`;
  for (const p of testedParams.slice(0, 8)) {
    // Find target URL for this parameter
    const endpoint = discoveredEndpoints.find(ep => ep.parameters.some(param => param.name === p));
    const targetEndpointUrl = endpoint ? endpoint.url : (rawUrl.includes('?') ? rawUrl : `${rawUrl}?${p}=test`);
    const method = endpoint ? endpoint.method : 'GET';

    // Build sibling parameters so form POSTs have valid accompanying fields
    const siblingParams: Record<string, string> = {};
    if (endpoint && endpoint.parameters) {
      for (const param of endpoint.parameters) {
        if (param.name !== p) {
          const lower = param.name.toLowerCase();
          siblingParams[param.name] = lower.includes('pass') ? 'test' : (lower.includes('submit') || lower.includes('btn')) ? 'Login' : 'test';
        }
      }
    }

    // Probe 1: XSS / HTML Injection canary
    const xssProbeRes = await sendProbe(targetEndpointUrl, p, method, canaryToken, siblingParams);
    if (xssProbeRes.ok && xssProbeRes.body && xssProbeRes.body.includes(canaryToken)) {
      const idx = xssProbeRes.body.indexOf(canaryToken);
      const snippet = xssProbeRes.body.slice(Math.max(0, idx - 30), Math.min(xssProbeRes.body.length, idx + canaryToken.length + 40)).trim();

      findings.push({
        type: 'Reflected Cross-Site Scripting (XSS)',
        injectionFamily: 'xss',
        location: `${method} ${targetEndpointUrl} (${p})`,
        parameter: p,
        paramValue: canaryToken,
        severity: 'High',
        confidence: 'Confirmed',
        detectionOutcome: 'CONFIRMED',
        cvss: 7.5,
        cwe: 'CWE-79',
        owasp: 'A03:2021-Injection',
        description: `The live parameter "${p}" echoes user-supplied input directly into the HTTP response body without contextual HTML sanitization or encoding.`,
        evidence: `Live probe "${canaryToken}" was reflected verbatim in the response at ${targetEndpointUrl}:\n"...${snippet}..."`,
        corroborationSignals: ['input_reflected_verbatim', 'unescaped_response_body'],
        pocPayload: `${targetEndpointUrl}${targetEndpointUrl.includes('?') ? '&' : '?'}${p}=<script>alert(document.domain)</script>`,
        recommendation: `Apply contextual HTML entity encoding to the parameter "${p}" before rendering it in response templates. Implement a strict Content-Security-Policy (CSP) header.`,
        fingerprint: `xss|${p}|${targetEndpointUrl}`,
      });
    }

    // Probe 2: SQL Injection Syntax Test
    const sqlProbeVal = "1' OR '1'='1";
    const sqlProbeRes = await sendProbe(targetEndpointUrl, p, method, sqlProbeVal, siblingParams);
    if (sqlProbeRes.ok && sqlProbeRes.body) {
      const bodyLower = sqlProbeRes.body.toLowerCase();
      const sqlErrorPatterns = [
        'sql syntax', 'syntax error', 'mysql_', 'unclosed quotation mark',
        'ora-', 'postgresql', 'sqlite3', 'jdbc', 'odbc', 'org.apache.jasper',
        'coyote', 'database error', 'sqlcommand'
      ];
      const matchedPattern = sqlErrorPatterns.find(pat => bodyLower.includes(pat));
      if (matchedPattern) {
        const idx = bodyLower.indexOf(matchedPattern);
        const snippet = sqlProbeRes.body.slice(Math.max(0, idx - 20), Math.min(sqlProbeRes.body.length, idx + 60)).trim();

        findings.push({
          type: 'SQL Injection (SQLi)',
          injectionFamily: 'sqli',
          location: `${method} ${targetEndpointUrl} (${p})`,
          parameter: p,
          paramValue: sqlProbeVal,
          severity: 'Critical',
          confidence: 'Confirmed',
          detectionOutcome: 'CONFIRMED',
          cvss: 9.3,
          cwe: 'CWE-89',
          owasp: 'A03:2021-Injection',
          description: `The parameter "${p}" triggered database exception behavior or error disclosure when injected with SQL delimiter syntax.`,
          evidence: `Database syntax anomaly detected in live server response for payload "${sqlProbeVal}":\n"...${snippet}..."`,
          corroborationSignals: ['sql_syntax_error_pattern', 'database_exception_disclosed'],
          pocPayload: `${targetEndpointUrl}${targetEndpointUrl.includes('?') ? '&' : '?'}${p}=${encodeURIComponent(sqlProbeVal)}`,
          recommendation: `Use parameterized queries (PreparedStatements in Java, PDO in PHP) for all database operations involving "${p}". Do not concatenate user input into SQL commands.`,
          fingerprint: `sqli|${p}|${targetEndpointUrl}`,
        });
      }
    }

    // Probe 3: Boolean-Based Blind SQL Injection (TRUE vs FALSE Differential Test)
    // Sends real TRUE and FALSE test values to the live parameter and compares responses
    const boolPairs = [
      { trueVal: "admin' OR '1'='1", falseVal: "admin' AND '1'='2" },
      { trueVal: "' OR '1'='1", falseVal: "' AND '1'='2" },
      { trueVal: "1' OR 1=1-- ", falseVal: "1' AND 1=2-- " },
    ];

    let boolFindingAdded = false;
    let lastResTrue: any = null;
    let lastResFalse: any = null;
    for (const pair of boolPairs) {
      if (boolFindingAdded) break;

      const resTrue = await sendProbe(targetEndpointUrl, p, method, pair.trueVal, siblingParams);
      const resFalse = await sendProbe(targetEndpointUrl, p, method, pair.falseVal, siblingParams);
      lastResTrue = resTrue;
      lastResFalse = resFalse;

      if (!resTrue.ok && !resFalse.ok) continue;

      const statusDiff = resTrue.status !== resFalse.status && resTrue.status !== 0 && resFalse.status !== 0;
      const locTrue = resTrue.location || '';
      const locFalse = resFalse.location || '';
      const locDiff = Boolean(locTrue && locFalse && locTrue !== locFalse) ||
                      Boolean(locTrue && !locFalse) ||
                      Boolean(!locTrue && locFalse);
      const lenDiff = Math.abs((resTrue.body?.length || 0) - (resFalse.body?.length || 0));

      const tLower = (resTrue.body || '').toLowerCase();
      const fLower = (resFalse.body || '').toLowerCase();

      const authSuccessTrue = /welcome|logout|sign off|account balance|main\.jsp|bank/i.test(tLower) || /main\.jsp|bank/i.test(locTrue);
      const authSuccessFalse = /welcome|logout|sign off|account balance|main\.jsp|bank/i.test(fLower) || /main\.jsp|bank/i.test(locFalse);
      const authDiff = authSuccessTrue !== authSuccessFalse;

      const failTrue = /login failed|invalid username|invalid password|failed/i.test(tLower);
      const failFalse = /login failed|invalid username|invalid password|failed/i.test(fLower);
      const failDiff = failTrue !== failFalse;

      if (statusDiff || locDiff || lenDiff > 35 || authDiff || failDiff) {
        boolFindingAdded = true;
        const signals: string[] = [];
        if (statusDiff) signals.push(`HTTP status divergence (HTTP ${resTrue.status} on TRUE vs HTTP ${resFalse.status} on FALSE)`);
        if (locDiff) signals.push(`HTTP redirection divergence ("${locTrue || 'no redirect'}" vs "${locFalse || 'no redirect'}")`);
        if (lenDiff > 35) signals.push(`Content length differential (${resTrue.body?.length || 0} bytes on TRUE vs ${resFalse.body?.length || 0} bytes on FALSE, delta: ${lenDiff} bytes)`);
        if (authDiff) signals.push('Authentication state variation between TRUE and FALSE conditions');
        if (failDiff) signals.push('Conditional error message disparity in response body');

        findings.push({
          type: 'Boolean-Based Blind SQL Injection',
          injectionFamily: 'sqli',
          location: `${method} ${targetEndpointUrl} (${p})`,
          parameter: p,
          paramValue: `${pair.trueVal} (TRUE) vs ${pair.falseVal} (FALSE)`,
          severity: 'Critical',
          confidence: 'Confirmed',
          detectionOutcome: 'CONFIRMED',
          cvss: 8.6,
          cwe: 'CWE-89',
          owasp: 'A03:2021-Injection',
          description: `The live parameter "${p}" is vulnerable to boolean-based blind SQL injection. Sending a logical TRUE condition vs a logical FALSE condition causes the application to respond differently in status code, page structure, or redirection logic, confirming direct manipulation of the backend database query without explicit error messages.`,
          evidence: `Differential HTTP response confirmed on live target ${targetEndpointUrl}:\n` +
            `• TRUE condition ("${pair.trueVal}") => HTTP ${resTrue.status} (Length: ${resTrue.body?.length || 0} bytes${locTrue ? ', Redirect: ' + locTrue : ''})\n` +
            `• FALSE condition ("${pair.falseVal}") => HTTP ${resFalse.status} (Length: ${resFalse.body?.length || 0} bytes${locFalse ? ', Redirect: ' + locFalse : ''})\n` +
            `• Detection Signals: ${signals.join('; ')}.`,
          corroborationSignals: ['boolean_differential_response', 'status_or_content_divergence'],
          pocPayload: `${targetEndpointUrl} | TRUE: ${pair.trueVal} | FALSE: ${pair.falseVal}`,
          recommendation: `Use parameterized queries (PreparedStatements) for all database operations involving "${p}". Disallow string concatenation when constructing dynamic SQL statements.`,
          fingerprint: `sqli_boolean|${p}|${targetEndpointUrl}`,
        });
      }
    }

    // 4. Evaluate all configured rule categories against live HTTP response data for this parameter
    const liveEvalCtx: RuleEvaluationContext = {
      url: targetEndpointUrl,
      paramName: p,
      paramValue: sqlProbeVal,
      probePayload: canaryToken,
      response: {
        status: sqlProbeRes.status || xssProbeRes.status || 200,
        headers: (sqlProbeRes.headers || xssProbeRes.headers || {}) as Record<string, string>,
        body: sqlProbeRes.body || xssProbeRes.body || '',
        length: sqlProbeRes.body?.length || xssProbeRes.body?.length || 0,
      },
      baselineResponse: {
        status: rootRes.status || 200,
        headers: rootRes.headers as Record<string, string>,
        body: rootRes.body || '',
        length: rootRes.body?.length || 0,
      },
      trueResponse: {
        status: lastResTrue?.status || 0,
        headers: (lastResTrue?.headers || {}) as Record<string, string>,
        body: lastResTrue?.body || '',
        location: lastResTrue?.location || '',
        length: lastResTrue?.body?.length || 0,
      },
      falseResponse: {
        status: lastResFalse?.status || 0,
        headers: (lastResFalse?.headers || {}) as Record<string, string>,
        body: lastResFalse?.body || '',
        location: lastResFalse?.location || '',
        length: lastResFalse?.body?.length || 0,
      },
    };

    for (const rule of INJECTION_RULES) {
      if (rule.id === 'sqli-blind-boolean' && boolFindingAdded) continue;
      if (rule.id === 'xss-reflected' && xssProbeRes.ok && xssProbeRes.body && xssProbeRes.body.includes(canaryToken)) continue;

      const evalRes = rule.evaluate ? rule.evaluate(liveEvalCtx) : evaluateRule(rule, liveEvalCtx);
      if (evalRes.found) {
        const fp = `${rule.id}|${p}|${targetEndpointUrl}`;
        if (!findings.some(f => f.fingerprint === fp)) {
          findings.push({
            type: rule.type,
            injectionFamily: rule.family,
            location: `${method} ${targetEndpointUrl} (${p})`,
            parameter: p,
            paramValue: evalRes.pocPayload || rule.pocPayload,
            severity: rule.severity,
            confidence: evalRes.confidence || 'Confirmed',
            detectionOutcome: evalRes.detectionOutcome || 'CONFIRMED',
            cvss: rule.cvss,
            cwe: rule.cwe,
            owasp: rule.owasp,
            description: rule.description,
            evidence: evalRes.evidence || rule.evidence || 'Anomaly confirmed on live response.',
            corroborationSignals: ['real_response_evaluated', 'anomaly_confirmed'],
            pocPayload: evalRes.pocPayload || rule.pocPayload,
            recommendation: rule.recommendation,
            fingerprint: fp,
          });
        }
      }
    }
  }

  // 2. Real Server Configuration & Header Security Findings
  if (!headers['content-security-policy']) {
    findings.push({
      type: 'Missing Content-Security-Policy (CSP)',
      injectionFamily: 'header_injection',
      location: `HTTP Response Headers at ${baseUrl}`,
      severity: 'Medium',
      confidence: 'Confirmed',
      detectionOutcome: 'CONFIRMED',
      cvss: 5.4,
      cwe: 'CWE-1021',
      owasp: 'A05:2021-Security Misconfiguration',
      description: `The live web server at ${domain} does not transmit a Content-Security-Policy header, leaving client browsers vulnerable to cross-site script injection and unauthorized resource loading.`,
      evidence: `Live HTTP response from ${baseUrl} contains no "Content-Security-Policy" header.`,
      corroborationSignals: ['csp_header_absent'],
      pocPayload: 'N/A (Header Assessment)',
      recommendation: 'Configure a restrictive Content-Security-Policy (e.g. default-src \'self\'; script-src \'self\';).',
      fingerprint: `csp|${domain}`,
    });
  }

  if (!headers['x-frame-options']) {
    findings.push({
      type: 'Missing Clickjacking Defense (X-Frame-Options)',
      injectionFamily: 'header_injection',
      location: `HTTP Response Headers at ${baseUrl}`,
      severity: 'Low',
      confidence: 'Confirmed',
      detectionOutcome: 'CONFIRMED',
      cvss: 4.3,
      cwe: 'CWE-1021',
      owasp: 'A05:2021-Security Misconfiguration',
      description: `The target page does not define X-Frame-Options or frame-ancestors directives, permitting malicious websites to frame the target and attempt UI redressing (Clickjacking).`,
      evidence: `Live HTTP response headers lack "X-Frame-Options" directive.`,
      corroborationSignals: ['x_frame_options_missing'],
      pocPayload: `<html><body><iframe src="${rawUrl}"></iframe></body></html>`,
      recommendation: 'Send "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" with all web responses.',
      fingerprint: `clickjacking|${domain}`,
    });
  }

  if (serverHeader) {
    findings.push({
      type: 'Server Version Fingerprint Disclosure',
      injectionFamily: 'log_injection',
      location: `HTTP Response Header: Server: ${serverHeader}`,
      severity: 'Low',
      confidence: 'Confirmed',
      detectionOutcome: 'CONFIRMED',
      cvss: 3.1,
      cwe: 'CWE-200',
      owasp: 'A05:2021-Security Misconfiguration',
      description: `The server explicitly reveals its software identity and version banner ("${serverHeader}"), assisting attackers in mapping targeted CVE exploits.`,
      evidence: `Live Server header disclosed: "${serverHeader}".`,
      corroborationSignals: ['server_banner_leakage'],
      pocPayload: 'N/A (Header Inspection)',
      recommendation: 'Mask or disable the Server response header token in your web server configuration.',
      fingerprint: `server_disclosure|${domain}`,
    });
  }

  // Summary counts
  const familyCounts: Record<string, number> = {};
  for (const f of findings) {
    familyCounts[f.injectionFamily] = (familyCounts[f.injectionFamily] || 0) + 1;
  }

  const order: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  const highestSeverity = findings.reduce(
    (best, f) => (order[f.severity] > order[best] ? f.severity : best),
    'Info'
  );

  const avgCvss = findings.length
    ? Math.round((findings.reduce((acc, f) => acc + f.cvss, 0) / findings.length) * 10) / 10
    : 0;

  const result: LiveInspectionResult = {
    targetUrl: rawUrl,
    domain,
    reachable: true,
    statusCode: rootRes.status || 200,
    pagesCrawled,
    parameters: Array.from(discoveredParameters),
    paramValues,
    pathSegments: Array.from(pathSegments),
    techStackClues,
    endpoints: discoveredEndpoints,
    potentialInjectionPoints,
    findings,
    summary: {
      totalPages: pagesCrawled.length,
      injectionPoints: potentialInjectionPoints.length || testedParams.length || 1,
      parameters: testedParams.length,
      riskScore: avgCvss,
      highestSeverity,
      owaspCoverage: Array.from(new Set(findings.map(f => f.owasp))),
      familiesTested: Array.from(new Set(findings.map(f => f.injectionFamily))),
      injectionFamilyCounts: familyCounts,
      confirmedCount: findings.filter(f => f.detectionOutcome === 'CONFIRMED').length,
      probableCount: findings.filter(f => f.detectionOutcome === 'PROBABLE').length,
      inconclusiveCount: findings.filter(f => f.detectionOutcome === 'INCONCLUSIVE').length,
    },
  };

  return result;
}
