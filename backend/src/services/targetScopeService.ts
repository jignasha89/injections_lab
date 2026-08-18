/**
 * Target Scope and Authorization Management Service
 * Enforces safety boundaries, URL normalization, scope validation, and rate-limiting configurations
 * for educational security testing.
 */

export interface ScanScopeConfig {
  maxDepth: number;          // Maximum crawl depth (default: 2, max: 5)
  maxPages: number;          // Maximum total pages/endpoints to inspect (default: 10, max: 50)
  requestTimeoutMs: number;  // Per-request timeout in ms (default: 5000)
  rateLimitMs: number;       // Delay between requests in ms (default: 200)
  allowSubdomains: boolean;  // Whether to allow subdomains of the target domain (default: false)
  allowedDomains: string[];  // Whitelist of allowed domains/hosts
  requireAuthorization: boolean; // Enforce explicit user authorization confirmation
}

export interface ValidatedTarget {
  rawUrl: string;
  normalizedUrl: string;
  origin: string;
  hostname: string;
  protocol: string;
  port: string;
  pathname: string;
  scope: ScanScopeConfig;
  isAllowed: boolean;
  validationError?: string;
}

export const DEFAULT_SCAN_SCOPE: ScanScopeConfig = {
  maxDepth: 2,
  maxPages: 10,
  requestTimeoutMs: 25000,
  rateLimitMs: 200,
  allowSubdomains: false,
  allowedDomains: [],
  requireAuthorization: true,
};

/**
 * Normalizes a URL string by standardizing protocol, hostname casing, stripping fragments,
 * and canonicalizing default ports and paths.
 */
export function normalizeUrl(inputUrl: string): string {
  if (!inputUrl || typeof inputUrl !== 'string') {
    throw new Error('Invalid URL: Input must be a non-empty string');
  }

  let raw = inputUrl.trim();
  if (!/^https?:\/\//i.test(raw)) {
    raw = `http://${raw}`;
  }

  const parsed = new URL(raw);

  // Standardize hostname to lowercase
  parsed.hostname = parsed.hostname.toLowerCase();

  // Strip URL hash / fragment
  parsed.hash = '';

  // Remove default ports (80 for http, 443 for https)
  if ((parsed.protocol === 'http:' && parsed.port === '80') ||
      (parsed.protocol === 'https:' && parsed.port === '443')) {
    parsed.port = '';
  }

  // Remove trailing slashes on root path
  if (parsed.pathname === '/') {
    parsed.pathname = '/';
  }

  return parsed.toString();
}

/**
 * Validates target URL and initializes its scope configuration.
 */
export function validateAndInitTarget(
  inputUrl: string,
  authorized: boolean,
  customScope?: Partial<ScanScopeConfig>
): ValidatedTarget {
  if (!authorized) {
    return {
      rawUrl: inputUrl,
      normalizedUrl: '',
      origin: '',
      hostname: '',
      protocol: '',
      port: '',
      pathname: '',
      scope: { ...DEFAULT_SCAN_SCOPE, ...customScope },
      isAllowed: false,
      validationError: 'Authorization confirmation required: You must verify authorized ownership or permission before scanning.',
    };
  }

  try {
    const normalized = normalizeUrl(inputUrl);
    const parsed = new URL(normalized);

    // Only allow HTTP/HTTPS protocols
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        rawUrl: inputUrl,
        normalizedUrl: normalized,
        origin: '',
        hostname: '',
        protocol: parsed.protocol,
        port: '',
        pathname: '',
        scope: { ...DEFAULT_SCAN_SCOPE, ...customScope },
        isAllowed: false,
        validationError: `Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.`,
      };
    }

    // Disallow local link-local / multicast / internal sensitive ranges if necessary, but allow localhost for dev
    const hostname = parsed.hostname;

    const mergedScope: ScanScopeConfig = {
      ...DEFAULT_SCAN_SCOPE,
      ...customScope,
      // Clamp bounds to prevent runaway crawling
      maxDepth: Math.min(Math.max(1, customScope?.maxDepth ?? DEFAULT_SCAN_SCOPE.maxDepth), 5),
      maxPages: Math.min(Math.max(1, customScope?.maxPages ?? DEFAULT_SCAN_SCOPE.maxPages), 50),
      requestTimeoutMs: Math.min(Math.max(1000, customScope?.requestTimeoutMs ?? DEFAULT_SCAN_SCOPE.requestTimeoutMs), 60000),
      rateLimitMs: Math.min(Math.max(50, customScope?.rateLimitMs ?? DEFAULT_SCAN_SCOPE.rateLimitMs), 5000),
      allowedDomains: customScope?.allowedDomains?.length
        ? customScope.allowedDomains.map((d) => d.toLowerCase())
        : [hostname],
    };

    return {
      rawUrl: inputUrl,
      normalizedUrl: normalized,
      origin: parsed.origin,
      hostname,
      protocol: parsed.protocol,
      port: parsed.port,
      pathname: parsed.pathname,
      scope: mergedScope,
      isAllowed: true,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Invalid URL structure';
    return {
      rawUrl: inputUrl,
      normalizedUrl: '',
      origin: '',
      hostname: '',
      protocol: '',
      port: '',
      pathname: '',
      scope: { ...DEFAULT_SCAN_SCOPE, ...customScope },
      isAllowed: false,
      validationError: `Target URL validation failed: ${message}`,
    };
  }
}

/**
 * Checks whether a candidate URL or redirect destination is strictly within the allowed scan scope.
 */
export function isUrlInScope(candidateUrl: string, baseTarget: ValidatedTarget): boolean {
  if (!baseTarget.isAllowed) return false;

  try {
    const normalizedCandidate = normalizeUrl(candidateUrl);
    const parsedCandidate = new URL(normalizedCandidate);
    const candidateHost = parsedCandidate.hostname.toLowerCase();

    // 1. Direct hostname match
    if (candidateHost === baseTarget.hostname.toLowerCase()) {
      return true;
    }

    // 2. Explicit allowed domains list
    if (baseTarget.scope.allowedDomains.includes(candidateHost)) {
      return true;
    }

    // 3. Subdomain allowance (if enabled in scope)
    if (baseTarget.scope.allowSubdomains && candidateHost.endsWith(`.${baseTarget.hostname.toLowerCase()}`)) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}
