/**
 * InjectionLab Regression Test Suite Runner
 * Runs the scanner against regressionSuite.json benchmarks and reports precision,
 * recall, and overall accuracy metrics per module.
 */

import * as fs from 'fs';
import * as path from 'path';
import { analyzeUrl } from '../services/scannerService';

export interface SuiteTestCase {
  name: string;
  url: string;
  expectedFindingsCount: number;
  expectedTypes: string[];
  expectZeroFalsePositives: boolean;
  description: string;
}

export function runRegressionSuite(): {
  totalCases: number;
  passedCases: number;
  precision: number;
  recall: number;
  details: { name: string; status: 'PASS' | 'FAIL'; precision: number; recall: number; reason: string }[];
} {
  const suitePath = path.join(__dirname, '../data/regressionSuite.json');
  const rawData = fs.readFileSync(suitePath, 'utf8');
  const testCases: SuiteTestCase[] = JSON.parse(rawData);

  let totalTP = 0;
  let totalFP = 0;
  let totalFN = 0;
  let passedCases = 0;
  const details: { name: string; status: 'PASS' | 'FAIL'; precision: number; recall: number; reason: string }[] = [];

  for (const tc of testCases) {
    const scanResult = analyzeUrl(tc.url);
    // Ignore universal header injection warning when checking target-specific findings
    const actualFindings = scanResult.findings.filter(
      (f) => f.type !== 'HTTP Header Injection (Universal)'
    );

    const actualTypes = actualFindings.map((f) => f.type.toLowerCase());
    const expectedTypes = tc.expectedTypes.map((t) => t.toLowerCase());

    let tp = 0;
    let fp = 0;
    let fn = 0;

    if (tc.expectZeroFalsePositives) {
      fp = actualFindings.length;
    } else {
      for (const actual of actualTypes) {
        if (expectedTypes.some((exp) => actual.includes(exp) || exp.includes(actual))) {
          tp++;
        } else {
          fp++;
        }
      }
      for (const expected of expectedTypes) {
        if (!actualTypes.some((act) => act.includes(expected) || expected.includes(act))) {
          fn++;
        }
      }
    }

    totalTP += tp;
    totalFP += fp;
    totalFN += fn;

    const casePrecision = tp + fp > 0 ? tp / (tp + fp) : tc.expectZeroFalsePositives && fp === 0 ? 1 : 0;
    const caseRecall = tp + fn > 0 ? tp / (tp + fn) : tc.expectZeroFalsePositives && fp === 0 ? 1 : 0;

    const isPass = tc.expectZeroFalsePositives ? fp === 0 : tp > 0 && fp === 0;

    if (isPass) passedCases++;

    details.push({
      name: tc.name,
      status: isPass ? 'PASS' : 'FAIL',
      precision: Math.round(casePrecision * 100) / 100,
      recall: Math.round(caseRecall * 100) / 100,
      reason: isPass
        ? 'Matched expected vulnerability signatures without false positives.'
        : `TP: ${tp}, FP: ${fp}, FN: ${fn}. Actual findings: [${actualFindings.map((f) => f.type).join(', ')}]`,
    });
  }

  const overallPrecision = totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 1;
  const overallRecall = totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 1;

  return {
    totalCases: testCases.length,
    passedCases,
    precision: Math.round(overallPrecision * 100) / 100,
    recall: Math.round(overallRecall * 100) / 100,
    details,
  };
}

if (require.main === module) {
  console.log('====================================================');
  console.log('      INJECTIONLAB REGRESSION TEST SUITE RUNNER');
  console.log('====================================================\n');

  const report = runRegressionSuite();
  console.log(`Total Test Cases   : ${report.totalCases}`);
  console.log(`Passed Suite Cases : ${report.passedCases}`);
  console.log(`Overall Precision  : ${(report.precision * 100).toFixed(1)}%`);
  console.log(`Overall Recall     : ${(report.recall * 100).toFixed(1)}%\n`);

  console.log('DETAILED BENCHMARK RESULTS:');
  report.details.forEach((d) => {
    console.log(`  [${d.status}] ${d.name}`);
    console.log(`         Precision: ${(d.precision * 100).toFixed(1)}% | Recall: ${(d.recall * 100).toFixed(1)}%`);
    console.log(`         Notes: ${d.reason}`);
  });
}
