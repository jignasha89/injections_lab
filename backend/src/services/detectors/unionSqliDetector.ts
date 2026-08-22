/**
 * InjectionLab - Modular UNION-Based SQL Injection Detector Helper
 * Detects dynamic column projection reflection, NULL-column expansion,
 * database error signatures during UNION queries, and structural HTML divergence.
 */

import { DB_ERROR_PATTERNS } from '../liveScannerService';

export interface UnionDiffResult {
  isVulnerable: boolean;
  confidence: 'Confirmed' | 'High' | 'Medium' | 'Low';
  evidence: string;
  evidenceSignals: string[];
}

/**
 * Evaluates whether a UNION SELECT probe response demonstrates UNION-based SQL Injection behavior.
 */
export function evaluateUnionSqli(
  baselineText: string,
  probeText: string,
  probeStatus: number,
  baselineStatus: number,
  expectedMatch: string | undefined,
  payload: string
): UnionDiffResult {
  const evidenceSignals: string[] = [];

  // 1. Database Error Pattern Detection during UNION query
  for (const { db, pattern } of DB_ERROR_PATTERNS) {
    if (pattern.test(probeText) && !pattern.test(baselineText)) {
      evidenceSignals.push(`db_error_signature_detected (${db})`);
      return {
        isVulnerable: true,
        confidence: 'Confirmed',
        evidence: `${db} error signature triggered by UNION probe: "${probeText.match(pattern)?.[0]}"`,
        evidenceSignals,
      };
    }
  }

  // 2. Projected Literal String Match (e.g. 'injlab_union_canary_v1' injected via UNION SELECT)
  if (expectedMatch && probeText.includes(expectedMatch) && !baselineText.includes(expectedMatch)) {
    evidenceSignals.push('union_canary_string_reflected');
    evidenceSignals.push('query_column_projection_verified');

    const confidence = probeStatus === baselineStatus || probeStatus === 200 ? 'Confirmed' : 'High';
    const evidence = `UNION-based SQL injection detected: Payload "${payload}" projected custom canary string ("${expectedMatch}") into the HTTP response body.`;

    return {
      isVulnerable: true,
      confidence,
      evidence,
      evidenceSignals,
    };
  }

  // 3. Significant Structural / Column-Select Divergence
  const probeLen = probeText.length;
  const baseLen = baselineText.length;
  const lengthRatio = baseLen > 0 ? probeLen / baseLen : 1;

  if (payload.toUpperCase().includes('UNION SELECT') && lengthRatio > 1.35 && probeStatus === 200) {
    evidenceSignals.push('union_resultset_expansion_detected');
    evidenceSignals.push(`response_length_boost (+${probeLen - baseLen}B)`);

    return {
      isVulnerable: true,
      confidence: 'High',
      evidence: `UNION SELECT payload ("${payload}") expanded query result set from ${baseLen}B to ${probeLen}B.`,
      evidenceSignals,
    };
  }

  return {
    isVulnerable: false,
    confidence: 'Low',
    evidence: '',
    evidenceSignals: [],
  };
}
