/**
 * InjectionLab Multi-Target Regression Test Suite
 * Automatically verifies that the live scanner engine accurately detects
 * vulnerability classes across ALL authorized test targets in a single run.
 */

import { executeLiveScan, DeepScanResult } from '../services/liveScannerService';
import http from 'http';
import https from 'https';

interface TargetTestCase {
  name: string;
  url: string;
  expectedVulnTypes: string[]; // e.g. ['SQL', 'XSS', 'SSTI']
  expectedParams?: string[];   // e.g. ['uid', 'passw', 'cat', 'q']
  isRemote?: boolean;
  description: string;
}

const REGRESSION_TARGETS: TargetTestCase[] = [
  {
    name: 'Altoro Mutual (testfire.net) - Auth Bypass / Login SQLi',
    url: 'http://testfire.net/login.jsp',
    expectedVulnTypes: ['SQL', 'Authentication Bypass'],
    expectedParams: ['uid', 'passw'],
    isRemote: true,
    description: 'Verifies SQL injection authentication bypass on login forms (uid/passw).',
  },
  {
    name: 'Acunetix TestPHP (vulnweb.com) - Product Catalog SQLi',
    url: 'http://testphp.vulnweb.com/listproducts.php?cat=1',
    expectedVulnTypes: ['SQL'],
    expectedParams: ['cat'],
    isRemote: true,
    description: 'Verifies boolean and error-based SQL injection on GET query parameter (cat).',
  },
  {
    name: 'Mock Target Vulnweb Catalog (localhost:3001/listproducts.php?cat=1)',
    url: 'http://localhost:3001/listproducts.php?cat=1',
    expectedVulnTypes: ['SQL'],
    expectedParams: ['cat'],
    description: 'Verifies boolean and error-based SQL injection on GET query parameters.',
  },
  {
    name: 'InjectionLab Mock Sandbox (Local Target)',
    url: 'http://localhost:3001',
    expectedVulnTypes: ['SQL', 'XSS', 'Template'],
    description: 'Verifies local multi-vulnerability detection across SQLi, XSS, and SSTI.',
  },
  {
    name: 'DVWA / Localhost Environment (if running on port 3000)',
    url: 'http://localhost:3000',
    expectedVulnTypes: ['SQL', 'XSS'],
    description: 'Verifies detection against self-hosted DVWA / sandbox container.',
  },
];

// ANSI Colors for output formatting
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

async function checkUrlReachable(targetUrl: string, timeoutMs = 4000): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(targetUrl);
      const protocol = parsed.protocol === 'https:' ? https : http;
      const req = protocol.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method: 'GET',
          timeout: timeoutMs,
          headers: { 'User-Agent': 'InjectionLab-HealthCheck/1.0' },
        },
        (res) => {
          resolve(Boolean(res.statusCode && res.statusCode < 500));
        }
      );
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      req.end();
    } catch {
      resolve(false);
    }
  });
}

export async function runRegressionSuite(): Promise<{ total: number; passed: number; failed: number; skipped: number }> {
  console.log(`\n${BOLD}${CYAN}==============================================================${RESET}`);
  console.log(`${BOLD}${CYAN}   INJECTIONLAB MULTI-TARGET SCANNER REGRESSION SUITE        ${RESET}`);
  console.log(`${BOLD}${CYAN}==============================================================${RESET}\n`);

  let passedCount = 0;
  let failedCount = 0;
  let skippedCount = 0;

  for (let i = 0; i < REGRESSION_TARGETS.length; i++) {
    const testCase = REGRESSION_TARGETS[i];
    console.log(`\n${BOLD}[${i + 1}/${REGRESSION_TARGETS.length}] Testing Target:${RESET} ${CYAN}${testCase.name}${RESET}`);
    console.log(`    URL: ${testCase.url}`);
    console.log(`    Goal: ${testCase.description}`);

    // Pre-check target connectivity
    const isUp = await checkUrlReachable(testCase.url);
    if (!isUp) {
      console.log(`    ${YELLOW}⚠️ Target host unreachable / offline. Skipping target.${RESET}`);
      skippedCount++;
      continue;
    }

    const startTime = Date.now();
    let scanResult: DeepScanResult | null = null;
    let scanError: string | null = null;

    try {
      scanResult = await executeLiveScan(testCase.url, true, {
        scanMode: 'active',
        timeoutMs: 25000,
        rateLimitMs: 150,
      });
    } catch (err) {
      scanError = err instanceof Error ? err.message : String(err);
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    if (scanError || !scanResult) {
      console.log(`    ${RED}❌ SCAN ERROR (${duration}s): ${scanError}${RESET}`);
      failedCount++;
      continue;
    }

    // Evaluate Findings against Expected Vulnerabilities
    const findings = scanResult.findings;
    console.log(`    Response: HTTP ${scanResult.statusCode} | Time: ${duration}s | Total Findings: ${findings.length}`);

    const foundExpectedTypes = testCase.expectedVulnTypes.every((expectedType) => {
      return findings.some(
        (f) =>
          f.vulnerabilityType.toLowerCase().includes(expectedType.toLowerCase()) ||
          (f.owasp && f.owasp.toLowerCase().includes(expectedType.toLowerCase())) ||
          (f.evidence && f.evidence.toLowerCase().includes(expectedType.toLowerCase()))
      );
    });

    // Check if expected parameters were flagged
    let foundExpectedParams = true;
    if (testCase.expectedParams && testCase.expectedParams.length > 0) {
      foundExpectedParams = testCase.expectedParams.some((expectedParam) => {
        return findings.some((f) =>
          f.inputPointTested.toLowerCase().includes(`[${expectedParam.toLowerCase()}]`) ||
          f.inputPointTested.toLowerCase().includes(`?${expectedParam.toLowerCase()}=`) ||
          f.inputPointTested.toLowerCase().includes(`=${expectedParam.toLowerCase()}`) ||
          f.inputPointTested.toLowerCase().includes(expectedParam.toLowerCase())
        );
      });
    }

    console.log(`    Findings Breakdown:`);
    for (const f of findings) {
      const sigIcon = f.severity === 'Critical' ? '🔴' : f.severity === 'High' ? '🟠' : '🟡';
      console.log(`      ${sigIcon} [${f.confidence}] ${f.vulnerabilityType} on ${f.inputPointTested}`);
      console.log(`         ↳ Evidence: ${f.evidence.slice(0, 120)}...`);
    }

    const isTestPassed = foundExpectedTypes && foundExpectedParams && findings.length > 0;

    if (isTestPassed) {
      console.log(`    ${GREEN}${BOLD}✔ RESULT: PASS${RESET} (Identified expected vulnerability classes generic behavior)`);
      passedCount++;
    } else {
      console.log(`    ${RED}${BOLD}✖ RESULT: FAIL${RESET} (Expected: ${testCase.expectedVulnTypes.join(', ')}${testCase.expectedParams ? ` on params ${testCase.expectedParams.join(', ')}` : ''})`);
      failedCount++;
    }
  }

  console.log(`\n${BOLD}==============================================================${RESET}`);
  console.log(`${BOLD}REGRESSION SUMMARY:${RESET}`);
  console.log(`  Total Targets : ${REGRESSION_TARGETS.length}`);
  console.log(`  ${GREEN}Passed        : ${passedCount}${RESET}`);
  console.log(`  ${RED}Failed        : ${failedCount}${RESET}`);
  console.log(`  ${YELLOW}Skipped       : ${skippedCount}${RESET}`);
  console.log(`${BOLD}==============================================================${RESET}\n`);

  return {
    total: REGRESSION_TARGETS.length,
    passed: passedCount,
    failed: failedCount,
    skipped: skippedCount,
  };
}

// Allow direct CLI execution: ts-node src/scripts/regressionTest.ts
if (require.main === module) {
  runRegressionSuite()
    .then((results) => {
      if (results.failed > 0) {
        process.exit(1);
      } else {
        process.exit(0);
      }
    })
    .catch((err) => {
      console.error('Fatal error running regression suite:', err);
      process.exit(1);
    });
}
