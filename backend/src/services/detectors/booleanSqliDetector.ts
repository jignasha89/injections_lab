/**
 * InjectionLab - Modular Boolean-Based Differential SQL Injection Detector
 * Performs dynamic HTML normalization, dynamic noise filtering (timestamps, CSRF nonces, session IDs),
 * percentage-based length divergence calculation, and baseline asymmetry validation.
 */

export interface BooleanDiffResult {
  isVulnerable: boolean;
  confidence: 'Confirmed' | 'Likely' | 'Needs manual review';
  evidence: string;
  evidenceSignals: string[];
}

/**
 * Normalizes HTML response content by stripping dynamic tokens (MD5/SHA nonces, UUIDs, ISO/Unix timestamps, CSRF tokens, session IDs, request IDs)
 * and collapsing excess whitespace.
 */
export function normalizeHtmlForComparison(html: string): string {
  if (!html) return '';
  return html
    .replace(/\b[0-9a-fA-F]{32,64}\b/g, '') // MD5 / SHA hashes
    .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '') // UUIDs
    .replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, '') // ISO Timestamps
    .replace(/\b\d{10,13}\b/g, '') // Unix timestamps in ms/sec
    .replace(/\b(csrf|_token|nonce|session_?id|auth_?token|req_?id|request_?id|time|timestamp|clock)=["'][^"']+["']/gi, '') // CSRF & Token attributes
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Evaluates whether a TRUE condition probe payload and a FALSE condition probe payload demonstrate
 * genuine Boolean-Based SQL Injection behavior against a baseline response.
 */
export function evaluateBooleanDifferential(
  baseLen: number,
  baseStatus: number,
  trueLen: number,
  trueStatus: number,
  falseLen: number,
  falseStatus: number,
  trueText: string,
  falseText: string,
  baselineText: string,
  payload: string,
  falsePayload: string
): BooleanDiffResult {
  const evidenceSignals: string[] = [];

  const normTrue = normalizeHtmlForComparison(trueText);
  const normFalse = normalizeHtmlForComparison(falseText);
  const normBase = normalizeHtmlForComparison(baselineText);

  // 1. Core Text & Structure Divergence
  const contentDiffers = normTrue !== normFalse;

  // Safeguard: Check if the text divergence is strictly due to the literal probe strings being reflected in the HTML response
  const normTrueStripped = normTrue.split(payload).join('').split(encodeURIComponent(payload)).join('').trim();
  const normFalseStripped = normFalse.split(falsePayload).join('').split(encodeURIComponent(falsePayload)).join('').trim();
  const isReflectionOnly = normTrueStripped === normFalseStripped && trueStatus === falseStatus;

  // If the ONLY difference between TRUE and FALSE probes is that the probe payload string was echoed back in the page body, it is NOT SQLi
  if (isReflectionOnly && trueStatus === baseStatus) {
    return { isVulnerable: false, confidence: 'Needs manual review', evidence: '', evidenceSignals: [] };
  }

  // 2. HTTP Status Code Divergence (e.g. TRUE: 200 vs FALSE: 500 / 404 / 302)
  const statusDivergence = (trueStatus === 200 || trueStatus === baseStatus) && (falseStatus !== trueStatus);

  // 3. Percentage Length Divergence (filtering out small dynamic timestamp/token noise)
  const minLen = Math.min(trueLen, falseLen);
  const absLenDiff = Math.abs(trueLen - falseLen);
  const pctDiff = minLen > 0 ? absLenDiff / minLen : 1.0;
  const significantLengthDivergence = absLenDiff >= 30 || pctDiff >= 0.08;

  // 4. Baseline Asymmetry Proximity
  const trueMatchesBase = Math.abs(trueLen - baseLen) <= Math.max(150, baseLen * 0.15) || trueStatus === baseStatus;
  const falseMatchesBase = Math.abs(falseLen - baseLen) <= Math.max(150, baseLen * 0.15) || falseStatus === baseStatus;

  // Genuine boolean vulnerability requires structural content difference AND NOT reflection-only AND
  // (status divergence OR significant length divergence OR baseline asymmetry)
  const isVulnerable = contentDiffers && !isReflectionOnly && (
    statusDivergence ||
    (significantLengthDivergence && (trueMatchesBase || falseMatchesBase)) ||
    (trueMatchesBase && !falseMatchesBase) ||
    (!trueMatchesBase && falseMatchesBase)
  );

  if (isVulnerable) {
    evidenceSignals.push('boolean_true_false_divergence_confirmed');
    if (trueMatchesBase) evidenceSignals.push('boolean_true_matched_baseline');
    if (falseMatchesBase) evidenceSignals.push('boolean_false_matched_baseline');
    if (statusDivergence) evidenceSignals.push(`status_code_divergence (${trueStatus} vs ${falseStatus})`);
    if (significantLengthDivergence) evidenceSignals.push(`response_length_divergence (TRUE: ${trueLen}B vs FALSE: ${falseLen}B)`);

    // Two-tier confidence: Confirmed requires 2+ distinct evidence signals (e.g. divergence + baseline match / status diff)
    const confidence: 'Confirmed' | 'Likely' | 'Needs manual review' = evidenceSignals.length >= 2 ? 'Confirmed' : 'Likely';
    const evidence = `Boolean-based SQL injection detected: TRUE condition payload ("${payload}") produced baseline-consistent behavior (${trueLen} bytes, HTTP ${trueStatus}), while FALSE condition payload ("${falsePayload}") caused behavioral divergence (${falseLen} bytes, HTTP ${falseStatus}).`;

    return { isVulnerable: true, confidence, evidence, evidenceSignals };
  }

  return { isVulnerable: false, confidence: 'Needs manual review', evidence: '', evidenceSignals: [] };
}
