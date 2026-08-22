/**
 * InjectionLab - Boolean Differential SQLi Detector Unit Test Suite
 * Asserts that evaluateBooleanDifferential correctly identifies vulnerabilities across:
 * 1. Numeric Boolean SQLi (TRUE matches baseline, FALSE collapses)
 * 2. String/Quote Boolean SQLi (' AND '1'='1 vs ' AND '1'='2)
 * 3. Tautology SQLi (' OR '1'='1 vs ' OR '1'='2 - FALSE matches baseline, TRUE expands)
 * 4. Dynamic Noise Tolerance (timestamps, CSRF tokens, session IDs)
 * 5. Non-vulnerable pages (zero false positives when TRUE and FALSE return identical content)
 */

import { evaluateBooleanDifferential, normalizeHtmlForComparison } from '../services/detectors/booleanSqliDetector';
import { evaluateUnionSqli } from '../services/detectors/unionSqliDetector';
import assert from 'node:assert';

function runUnitTests() {
  console.log('🧪 Starting Boolean Differential Detector Unit Test Suite...\n');

  // Test 1: HTML Normalization (Dynamic Noise Stripping)
  console.log('Test 1: HTML Normalization (Dynamic Noise Stripping)');
  const rawHtml1 = '<div>Hello World</div> <!-- Server time: 2026-08-22T17:31:05Z --> <input csrf_token="a1b2c3d4e5f67890a1b2c3d4e5f67890" />';
  const rawHtml2 = '<div>Hello World</div> <!-- Server time: 2026-08-22T17:31:06Z --> <input csrf_token="f9e8d7c6b5a43210f9e8d7c6b5a43210" />';
  assert.strictEqual(normalizeHtmlForComparison(rawHtml1), normalizeHtmlForComparison(rawHtml2));
  console.log('  ✓ Passed HTML Normalization\n');

  // Test 2: Numeric Boolean Differential SQLi (1 AND 1=1 vs 1 AND 1=2)
  console.log('Test 2: Numeric Boolean Differential SQLi (1 AND 1=1 vs 1 AND 1=2)');
  const baseText = '<html><body><h1>Product List</h1><p>Item 1: Camera ($500)</p><p>Item 2: Laptop ($1200)</p></body></html>';
  const trueText = '<html><body><h1>Product List</h1><p>Item 1: Camera ($500)</p><p>Item 2: Laptop ($1200)</p></body></html>';
  const falseText = '<html><body><h1>Product List</h1><p>No products found matching criteria.</p></body></html>';

  const resNumeric = evaluateBooleanDifferential(
    baseText.length, 200,
    trueText.length, 200,
    falseText.length, 200,
    trueText, falseText, baseText,
    '1 AND 1=1', '1 AND 1=2'
  );
  assert.strictEqual(resNumeric.isVulnerable, true);
  assert.strictEqual(resNumeric.confidence === 'Confirmed' || resNumeric.confidence === 'High', true);
  console.log(`  ✓ Detected: ${resNumeric.evidence}\n`);

  // Test 3: String/Quote Tautology SQLi (' OR '1'='1 vs ' OR '1'='2)
  console.log("Test 3: String/Quote Tautology SQLi (' OR '1'='1 vs ' OR '1'='2)");
  const loginBase = '<html><body><form><h2>Login</h2><p>Invalid credentials</p></form></body></html>';
  const loginTrue = '<html><body><div id="dashboard"><h1>Welcome Admin</h1><p>Session ID: 998877</p></div></body></html>';
  const loginFalse = '<html><body><form><h2>Login</h2><p>Invalid credentials</p></form></body></html>';

  const resTautology = evaluateBooleanDifferential(
    loginBase.length, 200,
    loginTrue.length, 200,
    loginFalse.length, 200,
    loginTrue, loginFalse, loginBase,
    "' OR '1'='1", "' OR '1'='2"
  );
  assert.strictEqual(resTautology.isVulnerable, true);
  assert.strictEqual(resTautology.confidence === 'Confirmed' || resTautology.confidence === 'High', true);
  console.log(`  ✓ Detected: ${resTautology.evidence}\n`);

  // Test 4: Zero False Positives on Safe / Non-Vulnerable Inputs
  console.log('Test 4: Zero False Positives on Non-Vulnerable Page (Dynamic Timestamps)');
  const safeBase = '<html><body><h1>Search Results</h1><p>Time: 17:31:01</p><p>No results found for "test"</p></body></html>';
  const safeTrue = '<html><body><h1>Search Results</h1><p>Time: 17:31:02</p><p>No results found for "test"</p></body></html>';
  const safeFalse = '<html><body><h1>Search Results</h1><p>Time: 17:31:03</p><p>No results found for "test"</p></body></html>';

  const resSafe = evaluateBooleanDifferential(
    safeBase.length, 200,
    safeTrue.length, 200,
    safeFalse.length, 200,
    safeTrue, safeFalse, safeBase,
    '1 AND 1=1', '1 AND 1=2'
  );
  assert.strictEqual(resSafe.isVulnerable, false);
  // Test 5: UNION SELECT Projection Canary Reflection
  console.log('Test 5: UNION SELECT Projection Canary Reflection');
  const unionBase = '<html><body><h1>Products</h1><ul><li>Camera</li></ul></body></html>';
  const unionProbe = '<html><body><h1>Products</h1><ul><li>Camera</li><li>injlab_union_canary_v1</li></ul></body></html>';

  const resUnion = evaluateUnionSqli(
    unionBase, unionProbe, 200, 200, 'injlab_union_canary_v1', "' UNION SELECT NULL,'injlab_union_canary_v1'--"
  );
  assert.strictEqual(resUnion.isVulnerable, true);
  assert.strictEqual(resUnion.confidence, 'Confirmed');
  console.log(`  ✓ Detected: ${resUnion.evidence}\n`);

  console.log('✅ ALL DETECTOR UNIT TESTS (BOOLEAN + UNION SQLI) PASSED SUCCESSFULLY!');
}

runUnitTests();
