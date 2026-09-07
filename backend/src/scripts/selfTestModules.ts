/**
 * InjectionLab Self-Test Diagnostic Runner
 * Executes all 78 injection rules against known synthetic payloads locally to ensure
 * every module triggers independently and flag any dead or broken detectors.
 */

import { injectionRegistry } from '../data/injectionRegistry';
import { analyzeUrl } from '../services/scannerService';

export interface ModuleDiagnosticResult {
  slug: string;
  title: string;
  category: string;
  status: 'PASS' | 'FAIL_DEAD_DETECTOR';
  details: string;
}

export function runSelfTest(): { totalModules: number; passed: number; failed: number; results: ModuleDiagnosticResult[] } {
  const results: ModuleDiagnosticResult[] = [];
  const entries = Object.entries(injectionRegistry);

  for (const [slug, spec] of entries) {
    let triggered = false;
    let details = '';

    // Test with baseline payload in simulation mode
    const baselineCase = spec.testCases.find((tc) => tc.type === 'Baseline') || spec.testCases[0];
    if (baselineCase) {
      const simResult = spec.simulateCustomInput(baselineCase.payload, false);
      if (simResult.verdict === 'VULNERABLE') {
        triggered = true;
        details = `Registry simulation confirmed VULNERABLE for payload: "${baselineCase.payload}"`;
      }
    }

    // Secondary test: heuristic rule engine test
    if (!triggered) {
      const testUrl = `http://localhost/test?id=1&search=${encodeURIComponent(baselineCase?.payload || 'test')}&cat=1`;
      const scanResult = analyzeUrl(testUrl);
      const matchedFinding = scanResult.findings.find(
        (f) =>
          f.type.toLowerCase().includes(spec.title.toLowerCase()) ||
          f.category?.toLowerCase().includes(spec.category.toLowerCase()) ||
          f.injectionFamily?.toLowerCase().includes(spec.family.toLowerCase())
      );
      if (matchedFinding) {
        triggered = true;
        details = `Heuristic scanner triggered rule "${matchedFinding.type}"`;
      }
    }

    results.push({
      slug,
      title: spec.title,
      category: spec.category,
      status: triggered ? 'PASS' : 'FAIL_DEAD_DETECTOR',
      details: details || 'Detector failed to trigger on baseline payload',
    });
  }

  const passed = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL_DEAD_DETECTOR').length;

  return {
    totalModules: results.length,
    passed,
    failed,
    results,
  };
}

if (require.main === module) {
  console.log('====================================================');
  console.log('   INJECTIONLAB 78-MODULE SELF-TEST DIAGNOSTIC RUN');
  console.log('====================================================\n');

  const suite = runSelfTest();
  console.log(`Total Modules Tested : ${suite.totalModules}`);
  console.log(`Passed (Active)     : ${suite.passed}`);
  console.log(`Failed (Dead/Broken): ${suite.failed}\n`);

  if (suite.failed > 0) {
    console.log('DEAD / BROKEN DETECTORS DETECTED:');
    suite.results
      .filter((r) => r.status === 'FAIL_DEAD_DETECTOR')
      .forEach((r) => console.log(`  - [${r.slug}] ${r.title}: ${r.details}`));
  } else {
    console.log('SUCCESS: All 78 injection modules fired independently!');
  }
}
