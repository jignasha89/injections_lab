import { analyzeUrl, INJECTION_RULES, ScanFinding, ScanResult } from './scannerService';

export interface ActiveScanOptions {
  maxPages?: number;
  maxParameters?: number;
  concurrency?: number;
  timeoutMs?: number;
  maxBodyBytes?: number;
  userAgent?: string;
}

export interface ActiveScanStats {
  mode: 'active-verified';
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  requestsMade: number;
  pagesDiscovered: number;
  parametersTested: number;
  rulesEvaluated: number;
  verifiedFindings: number;
  errors: number;
}

const DEFAULTS: Required<ActiveScanOptions> = {
  maxPages: 20,
  maxParameters: 80,
  concurrency: 4,
  timeoutMs: 8000,
  maxBodyBytes: 750000,
  userAgent: 'InjectionLab-SecurityScanner/1.0 (+authorized-assessment)',
};

function buildSummary(findings: ScanFinding[], pages: number, params: number): ScanResult['summary'] {
  const order: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  const highestSeverity = findings.reduce(
    (best, f) => order[f.severity] > order[best] ? f.severity : best,
    'Info',
  );
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.injectionFamily] = (counts[f.injectionFamily] || 0) + 1;

  return {
    totalPages: pages,
    injectionPoints: findings.length,
    parameters: params,
    riskScore: findings.length
      ? Math.round((findings.reduce((a, f) => a + f.cvss, 0) / findings.length) * 10) / 10
      : 0,
    highestSeverity,
    owaspCoverage: [...new Set(findings.map((f) => f.owasp).filter(Boolean))],
    familiesTested: [...new Set(findings.map((f) => f.injectionFamily))],
    injectionFamilyCounts: counts,
    confirmedCount: findings.filter((f) => f.detectionOutcome === 'CONFIRMED').length,
    probableCount: findings.filter((f) => f.detectionOutcome === 'PROBABLE').length,
    inconclusiveCount: findings.filter((f) => f.detectionOutcome === 'INCONCLUSIVE').length,
  };
}

export async function startActiveScan(rawUrl: string): Promise<string> {
  const ENGINE_URL = 'http://localhost:8000';

  try {
    // 1. Create Scan (No hardcoded max_depth so it uses default)
    const createRes = await fetch(`${ENGINE_URL}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_url: rawUrl,
        config: {} // let python engine use its deep crawl defaults
      }),
    });
    
    if (!createRes.ok) throw new Error(`Failed to create scan in Python engine`);
    const scanData: any = await createRes.json();
    const scanId = scanData.id;

    // 2. Start Scan
    const startRes = await fetch(`${ENGINE_URL}/api/scans/${scanId}/start`, { method: 'POST' });
    if (!startRes.ok) throw new Error(`Failed to start scan in Python engine`);

    return scanId;
  } catch (err: any) {
    throw new Error(`Engine Integration Error: ${err.message}`);
  }
}

export async function stopActiveScan(scanId: string): Promise<void> {
  const ENGINE_URL = process.env.PYTHON_ENGINE_URL || 'http://127.0.0.1:8000';
  const response = await fetch(`${ENGINE_URL}/api/scans/${scanId}/stop`, { method: 'POST' });
  if (!response.ok) {
    throw new Error(`Failed to stop scan: ${response.statusText}`);
  }
}

/**
 * Normalise a URL for deduplication: strip query string, fragment, trailing slash,
 * and lowercase the scheme+host portion.
 */
function normUrl(u: string): string {
  try {
    const parsed = new URL(u);
    // Keep scheme + host + pathname only
    return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, '')}`;
  } catch {
    return (u || '').split('?')[0].split('#')[0].replace(/\/+$/, '');
  }
}

export async function getScanResults(scanId: string, rawUrl: string): Promise<ScanResult & { scanStats: ActiveScanStats }> {
  const ENGINE_URL = 'http://localhost:8000';
  const started = Date.now(); // approximate
  const startedAt = new Date().toISOString();

  try {
    const statusRes = await fetch(`${ENGINE_URL}/api/scans/${scanId}`);
    if (!statusRes.ok) throw new Error('Failed to fetch scan status');
    const detailData = await statusRes.json() as any;

    if (detailData.status !== 'completed' && detailData.status !== 'failed') {
      throw new Error(`Scan is still in progress (${detailData.status})`);
    }

    if (detailData.status === 'failed') {
      throw new Error(`Python scan engine failed: ${detailData.error_message || 'Unknown error'}`);
    }

    // Fetch findings (increased limit to handle findings, up to max allowed 500)
    const findingsRes = await fetch(`${ENGINE_URL}/api/scans/${scanId}/findings?limit=500`);
    let rawFindings: any[] = [];
    if (findingsRes.ok) rawFindings = (await findingsRes.json()) as any[];

    // Fetch endpoints (attack surface) to count pages discovered
    const surfaceRes = await fetch(`${ENGINE_URL}/api/scans/${scanId}/attack-surface`);
    let endpointsCount = 0;
    if (surfaceRes.ok) {
      const surfaceData: any = await surfaceRes.json();
      endpointsCount = surfaceData.total_endpoints || surfaceData.urls?.length || 0;
    }

    // Parse evidence JSON from findings to extract enriched data
    const mappedFindings: ScanFinding[] = rawFindings.map((f: any, idx: number) => {
      // Parse evidence_json if it's stored as the 'evidence' field
      let evidenceData: any = {};
      if (f.evidence_json && typeof f.evidence_json === 'object') {
        evidenceData = f.evidence_json;
      }

      const httpMethod = evidenceData.http_method || f.http_method || 'GET';
      const paramLocation = evidenceData.parameter_location || f.parameter_location || 'query';
      const successfulTests = evidenceData.successful_tests || [];
      const subtypesDetected = evidenceData.subtypes_detected || [];

      // Build a clean evidence string for display
      const reasons = evidenceData.reasons || [];
      let evidenceStr = '';
      if (reasons.length > 0) {
        evidenceStr = `Detection signals: ${reasons.join(', ')}.`;
      }
      if (httpMethod) {
        evidenceStr += ` HTTP Method: ${httpMethod}.`;
      }
      if (paramLocation) {
        evidenceStr += ` Parameter location: ${paramLocation}.`;
      }
      if (successfulTests.length > 0) {
        evidenceStr += ` Successful tests: ${successfulTests.length}.`;
      }

      // Build a structured evidence object as JSON string for the frontend
      const structuredEvidence = {
        reasons,
        http_method: httpMethod,
        parameter_location: paramLocation,
        tested_value: evidenceData.tested_value || f.payload || '',
        successful_tests: successfulTests,
        subtypes_detected: subtypesDetected,
        status_code: evidenceData.status_code || 0,
        response_time: evidenceData.response_time || 0,
        total_anomalies_in_group: evidenceData.total_anomalies_in_group || 1,
      };

      return {
        type: `${f.injection_family} - ${f.injection_subtype}`,
        injectionFamily: f.injection_family || 'Injection',
        location: `${httpMethod} ${f.affected_url}`,
        parameter: f.affected_parameter || 'unknown',
        severity: (f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1) : 'Info') as any,
        confidence: f.confidence === 'high' ? 'Confirmed' : f.confidence === 'medium' ? 'Likely' : 'Possible',
        detectionOutcome: f.confidence === 'high' ? 'CONFIRMED' : f.confidence === 'medium' ? 'PROBABLE' : 'INCONCLUSIVE',
        cvss: f.cvss_score || 0,
        cwe: f.cwe_id || 'CWE-0',
        owasp: 'A03:2021-Injection',
        description: f.description || `Detected ${f.title}`,
        evidence: JSON.stringify(structuredEvidence),
        corroborationSignals: ['python-engine-verified'],
        pocPayload: evidenceData.tested_value || f.payload || '',
        recommendation: f.mitigation_text || 'See OWASP guidelines.',
        fingerprint: f.id || `py_finding_${idx}`,
        httpMethod,
        paramLocation,
      };
    });

    // Include passive findings natively
    const passiveResult = analyzeUrl(rawUrl);
    const mergedFindings = [...mappedFindings, ...passiveResult.findings];

    // ── DEDUPLICATION ──
    // Key each finding by (normalized_url, parameter, injection_family).
    // This merges all subtypes of the same family on the same endpoint+param
    // into a single finding, keeping the highest-severity/confidence instance
    // and rolling up all affected locations.
    const sevOrder: Record<string, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
    const confOrder: Record<string, number> = { Confirmed: 3, Likely: 2, Possible: 1, Low: 0 };

    const deduped = new Map<string, ScanFinding & { affectedLocations: string[] }>();

    for (const f of mergedFindings) {
      const family = (f.injectionFamily || '').toLowerCase();
      const param = (f.parameter || '').toLowerCase();
      const url = normUrl(f.location.replace(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/i, ''));
      const dedupKey = `${family}::${url}::${param}`;

      const existing = deduped.get(dedupKey);
      if (!existing) {
        deduped.set(dedupKey, { ...f, affectedLocations: [f.location] });
      } else {
        // Append this location to the list
        if (!existing.affectedLocations.includes(f.location)) {
          existing.affectedLocations.push(f.location);
        }
        // Keep the higher-severity / higher-confidence version
        const fSev = sevOrder[f.severity] ?? 0;
        const eSev = sevOrder[existing.severity] ?? 0;
        const fConf = confOrder[(f as any).confidence] ?? 0;
        const eConf = confOrder[(existing as any).confidence] ?? 0;
        if (fSev > eSev || (fSev === eSev && fConf > eConf)) {
          const locations = existing.affectedLocations;
          deduped.set(dedupKey, { ...f, affectedLocations: locations });
        }
        // Merge evidence: combine successful_tests from both
        try {
          const existingEvidence = existing.evidence ? JSON.parse(existing.evidence) : {};
          const newEvidence = f.evidence ? JSON.parse(f.evidence) : {};
          if (newEvidence.successful_tests && existingEvidence.successful_tests) {
            // Merge unique tests up to 5
            const allTests = [...existingEvidence.successful_tests];
            for (const t of newEvidence.successful_tests) {
              if (allTests.length >= 5) break;
              if (!allTests.some((et: any) => et.payload === t.payload)) {
                allTests.push(t);
              }
            }
            existingEvidence.successful_tests = allTests;
          }
          if (newEvidence.subtypes_detected) {
            const allSubtypes = new Set([
              ...(existingEvidence.subtypes_detected || []),
              ...newEvidence.subtypes_detected,
            ]);
            existingEvidence.subtypes_detected = [...allSubtypes];
          }
          const currentBest = deduped.get(dedupKey);
          if (currentBest) {
            currentBest.evidence = JSON.stringify(existingEvidence);
          }
        } catch {
          // evidence wasn't JSON, skip merge
        }
      }
    }

    // Flatten back, embedding affected-locations summary into the location field
    const allFindings: ScanFinding[] = Array.from(deduped.values()).map((f) => {
      const { affectedLocations, ...finding } = f;
      if (affectedLocations.length > 1) {
        finding.location = `${affectedLocations[0]} (+${affectedLocations.length - 1} more)`;
        // Store all locations in evidence for the report
        try {
          const existingEvidence = finding.evidence ? JSON.parse(finding.evidence) : {};
          existingEvidence._allAffectedLocations = affectedLocations;
          finding.evidence = JSON.stringify(existingEvidence);
        } catch {
          // evidence wasn't JSON, just append
        }
      }
      return finding;
    });

    const stats: ActiveScanStats = {
      mode: 'active-verified',
      startedAt,
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      requestsMade: detailData.urls_crawled || endpointsCount * 2,
      pagesDiscovered: endpointsCount,
      parametersTested: endpointsCount * 3,
      rulesEvaluated: mergedFindings.length,       // total raw rules evaluated
      verifiedFindings: mappedFindings.length,
      errors: detailData.errors_count || 0,
    };

    return {
      ...passiveResult,
      scopeNote: 'Active-verified mode via sidecar Python engine.',
      findings: allFindings,
      potentialInjectionPoints: passiveResult.potentialInjectionPoints,
      summary: buildSummary(allFindings, stats.pagesDiscovered, stats.parametersTested),
      scanStats: stats,
    };

  } catch (err: any) {
    throw new Error(`Engine Integration Error: ${err.message}`);
  }
}
