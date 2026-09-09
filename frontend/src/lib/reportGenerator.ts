/**
 * reportGenerator.ts
 * ══════════════════
 * Professional security assessment report generation — PDF and CSV exports.
 * Produces Nessus/Burp-caliber engagement deliverables with:
 *   - 10-section document structure
 *   - Dual Vulnerability / Mitigation sides per finding
 *   - MITRE ATT&CK Enterprise mappings
 *   - CVSS v3.1 vectors
 *   - Light-background print-ready layout
 */

import { jsPDF } from 'jspdf';

/* ═══════════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════════ */

interface Finding {
  type: string;
  injectionFamily: string;
  location: string;
  parameter?: string;
  paramValue?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  confidence?: string;
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  evidence?: string;
  pocPayload?: string;
  recommendation: string;
  httpMethod?: string;
  paramLocation?: string;
}

/** Normalise URL for dedup: strip query/fragment/trailing-slash */
function normUrlForDedup(loc: string): string {
  const cleaned = (loc || '')
    .replace(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/i, '')
    .split('?')[0]
    .split('#')[0]
    .replace(/\/+$/, '');
  try {
    const u = new URL(cleaned);
    return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
  } catch {
    return cleaned;
  }
}

/** Build a dedup key: family + normalised_url + parameter */
function findingDedupKey(f: Finding): string {
  const family = (f.injectionFamily || '').toLowerCase();
  const url = normUrlForDedup(f.location);
  const param = (f.parameter || '').toLowerCase();
  return `${family}::${url}::${param}`;
}

interface ReportSummary {
  totalPages: number;
  injectionPoints: number;
  forms?: number;
  headers?: number;
  parameters: number;
  cookies?: number;
  jsonInputs?: number;
  riskScore: number;
  highestSeverity?: string;
  owaspCoverage: string[];
}

interface Report {
  _id: string;
  title: string;
  targetUrl: string;
  scanType: 'url' | 'demo';
  summary: ReportSummary;
  findings: Finding[];
  techStack: string[];
  createdAt: string;
}

interface AttackMapping {
  tactic: string;
  tacticId: string;
  techniqueId: string;
  techniqueName: string;
}

interface EnrichedFinding extends Finding {
  findingId: string;
  cvssVector: string;
  owaspFull: string;
  cweFull: string;
  businessRisk: string;
  technicalDescription: string;
  rootCause: string;
  remediationSteps: string;
  remediationPriority: string;
  attackMappings: AttackMapping[];
  refs: { label: string; url: string }[];
}

/* ═══════════════════════════════════════════════════════════════
   LOOKUP MAPS
   ═══════════════════════════════════════════════════════════════ */

const OWASP_NAMES: Record<string, string> = {
  'A01:2021': 'A01:2021 – Broken Access Control',
  'A02:2021': 'A02:2021 – Cryptographic Failures',
  'A03:2021': 'A03:2021 – Injection',
  'A04:2021': 'A04:2021 – Insecure Design',
  'A05:2021': 'A05:2021 – Security Misconfiguration',
  'A06:2021': 'A06:2021 – Vulnerable and Outdated Components',
  'A07:2021': 'A07:2021 – Identification and Authentication Failures',
  'A08:2021': 'A08:2021 – Software and Data Integrity Failures',
  'A09:2021': 'A09:2021 – Security Logging and Monitoring Failures',
  'A10:2021': 'A10:2021 – Server-Side Request Forgery (SSRF)',
};

const OWASP_URLS: Record<string, string> = {
  'A01:2021': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  'A02:2021': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  'A03:2021': 'https://owasp.org/Top10/A03_2021-Injection/',
  'A04:2021': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  'A05:2021': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  'A06:2021': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  'A07:2021': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  'A08:2021': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  'A09:2021': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  'A10:2021': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/',
};

const CWE_NAMES: Record<string, string> = {
  'CWE-74': 'CWE-74: Improper Neutralization of Special Elements in Output',
  'CWE-78': 'CWE-78: OS Command Injection',
  'CWE-79': 'CWE-79: Cross-site Scripting (XSS)',
  'CWE-89': 'CWE-89: SQL Injection',
  'CWE-90': 'CWE-90: LDAP Injection',
  'CWE-91': 'CWE-91: XML Injection',
  'CWE-93': 'CWE-93: CRLF Injection',
  'CWE-94': 'CWE-94: Code Injection',
  'CWE-113': 'CWE-113: HTTP Response Splitting',
  'CWE-116': 'CWE-116: Improper Encoding or Escaping of Output',
  'CWE-117': 'CWE-117: Improper Output Neutralization for Logs',
  'CWE-611': 'CWE-611: XML External Entity Reference (XXE)',
  'CWE-918': 'CWE-918: Server-Side Request Forgery (SSRF)',
  'CWE-943': 'CWE-943: Improper Neutralization in Data Query Logic',
};

/* ═══════════════════════════════════════════════════════════════
   CATEGORY DETECTION
   ═══════════════════════════════════════════════════════════════ */

type VulnCategory = 'sqli' | 'nosqli' | 'xss' | 'ssti' | 'cmdi' | 'ssrf' | 'xxe' | 'email' | 'log' | 'header' | 'ldap' | 'xpath' | 'generic';

function detectCategory(type: string, family: string): VulnCategory {
  const t = (type || '').toLowerCase();
  const f = (family || '').toLowerCase();
  if (t.includes('sql') && !t.includes('nosql')) return 'sqli';
  if (t.includes('nosql')) return 'nosqli';
  if (t.includes('xss') || t.includes('cross-site scripting')) return 'xss';
  if (t.includes('ssti') || t.includes('template injection')) return 'ssti';
  if (t.includes('command injection') || t.includes('os injection') || t.includes('remote code')) return 'cmdi';
  if (t.includes('ssrf') || t.includes('server-side request forgery')) return 'ssrf';
  if (t.includes('xxe') || t.includes('xml external entity')) return 'xxe';
  if (t.includes('email header') || t.includes('email injection')) return 'email';
  if (t.includes('log injection') || t.includes('log forging')) return 'log';
  if (t.includes('http header injection') || t.includes('crlf') || t.includes('response splitting')) return 'header';
  if (t.includes('ldap')) return 'ldap';
  if (t.includes('xpath')) return 'xpath';
  if (t.includes('xml injection')) return 'xxe';
  // Fallback to family
  if (f.includes('sql') && !f.includes('nosql')) return 'sqli';
  if (f.includes('nosql')) return 'nosqli';
  if (f.includes('xss') || f.includes('cross-site')) return 'xss';
  if (f.includes('code execution') || f.includes('server-side')) return 'ssti';
  if (f.includes('command')) return 'cmdi';
  if (f.includes('ssrf')) return 'ssrf';
  if (f.includes('xxe') || f.includes('xml')) return 'xxe';
  return 'generic';
}

/* ═══════════════════════════════════════════════════════════════
   ATT&CK MAPPING
   ═══════════════════════════════════════════════════════════════ */

function getAttackMappings(cat: VulnCategory): AttackMapping[] {
  // T1190 — Exploit Public-Facing Application — applies to every injection finding
  const base: AttackMapping = { tactic: 'Initial Access', tacticId: 'TA0001', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application' };
  const outcome: Record<VulnCategory, AttackMapping> = {
    sqli:    { tactic: 'Collection', tacticId: 'TA0009', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories' },
    nosqli:  { tactic: 'Defense Evasion', tacticId: 'TA0005', techniqueId: 'T1078', techniqueName: 'Valid Accounts' },
    xss:     { tactic: 'Credential Access', tacticId: 'TA0006', techniqueId: 'T1539', techniqueName: 'Steal Web Session Cookie' },
    ssti:    { tactic: 'Execution', tacticId: 'TA0002', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter' },
    cmdi:    { tactic: 'Execution', tacticId: 'TA0002', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter' },
    ssrf:    { tactic: 'Credential Access', tacticId: 'TA0006', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials' },
    xxe:     { tactic: 'Collection', tacticId: 'TA0009', techniqueId: 'T1005', techniqueName: 'Data from Local System' },
    email:   { tactic: 'Initial Access', tacticId: 'TA0001', techniqueId: 'T1566', techniqueName: 'Phishing' },
    log:     { tactic: 'Defense Evasion', tacticId: 'TA0005', techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
    header:  { tactic: 'Credential Access', tacticId: 'TA0006', techniqueId: 'T1557', techniqueName: 'Adversary-in-the-Middle' },
    ldap:    { tactic: 'Defense Evasion', tacticId: 'TA0005', techniqueId: 'T1078', techniqueName: 'Valid Accounts' },
    xpath:   { tactic: 'Collection', tacticId: 'TA0009', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories' },
    generic: { tactic: 'Collection', tacticId: 'TA0009', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories' },
  };
  return [base, outcome[cat]];
}

/* ═══════════════════════════════════════════════════════════════
   FINDING ENRICHMENT
   ═══════════════════════════════════════════════════════════════ */

function enrichFinding(f: Finding, index: number): EnrichedFinding {
  const findingId = `INJ-${String(index + 1).padStart(3, '0')}`;
  const cat = detectCategory(f.type, f.injectionFamily);
  const param = f.parameter || 'the affected parameter';
  const endpoint = (f.location || '').split('?')[0];

  // ── CVSS Vectors ──────────────────────────────────────────
  const vectors: Record<VulnCategory, Record<string, string>> = {
    sqli:    { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    nosqli:  { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    xss:     { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N' },
    ssti:    { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    cmdi:    { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', Medium: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N' },
    ssrf:    { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    xxe:     { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    email:   { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N' },
    log:     { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N' },
    header:  { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N' },
    ldap:    { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    xpath:   { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    generic: { Critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', High: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', Medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N', Low: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N' },
  };
  const cvssVector = vectors[cat]?.[f.severity] || vectors[cat]?.Critical || vectors.generic.Critical;

  // ── OWASP / CWE full names ────────────────────────────────
  const owaspFull = OWASP_NAMES[(f.owasp || '').trim()] || (f.owasp || 'Unknown');
  const cweKey = (f.cwe || '').split(' ')[0].trim();
  const cweFull = CWE_NAMES[cweKey] || (f.cwe || 'Unknown');

  // ── Business Risk (plain language, zero jargon) ───────────
  const businessRisks: Record<VulnCategory, string> = {
    sqli: 'An attacker could steal your entire customer database — names, emails, passwords, payment details — everything stored in the system. This kind of breach typically triggers mandatory regulatory notifications, significant fines under data protection laws, and lasting damage to customer trust.',
    nosqli: 'An attacker could bypass login screens entirely and access other users\' accounts without knowing their passwords. This means unauthorized access to private data and the ability to perform actions as other users, potentially exposing confidential business information.',
    xss: 'An attacker could hijack user sessions and impersonate legitimate users, including administrators. Victims would see no sign of compromise until unauthorized actions — potentially including financial transactions or data theft — were taken in their name.',
    ssti: 'An attacker could execute arbitrary code on the server, effectively taking full control of the application and its hosting infrastructure. This could lead to complete data theft, service disruption, and the use of your servers to attack others.',
    cmdi: 'An attacker could take complete control of the server, gaining the ability to access any file, install malware, or use the server as a launching point to attack other internal systems. This represents a total compromise of the hosting infrastructure.',
    ssrf: 'An attacker could use your server to reach internal systems that are normally hidden from the internet — databases, admin panels, or cloud credentials. This turns your own server into a tool for attacking your internal network.',
    xxe: 'An attacker could read sensitive files from the server, such as configuration files containing database passwords or API keys. They could also map your internal network to identify further targets for attack.',
    email: 'An attacker could use your application to send spam or phishing emails that appear to originate from your organization. This damages your email reputation, risks your domain being blacklisted, and could target your own customers with convincing scam messages.',
    log: 'An attacker could inject fake entries into your application logs, making it appear that different users performed actions they did not. This undermines your audit trail and could allow malicious activity to go undetected during forensic investigation.',
    header: 'An attacker could manipulate HTTP responses sent to other users, potentially redirecting them to malicious websites or injecting harmful content into legitimate pages. This could lead to credential theft and session compromise.',
    ldap: 'An attacker could bypass directory-based authentication and access organizational accounts or sensitive directory information without proper authorization, potentially gaining administrative access to internal systems.',
    xpath: 'An attacker could extract sensitive information from XML data stores by manipulating query logic, gaining access to records and data they should not be able to see.',
    generic: 'This vulnerability could allow an unauthorized person to access or manipulate application functionality in unintended ways, potentially exposing sensitive information or disrupting business operations.',
  };

  // ── Root Cause ────────────────────────────────────────────
  const rootCauses: Record<VulnCategory, string> = {
    sqli: 'Dynamic construction of SQL queries using unsanitized user input instead of parameterized queries (prepared statements).',
    nosqli: 'User-controlled objects or strings passed directly into NoSQL query filters without type checking or sanitization.',
    xss: 'The application renders untrusted user data into HTML output without context-aware encoding, allowing script injection.',
    ssti: 'User input is passed directly into a server-side template rendering engine (e.g., Jinja2, Twig, Velocity), enabling template expression evaluation.',
    cmdi: 'User input is concatenated directly into OS shell commands without sanitization, allowing shell metacharacter injection.',
    ssrf: 'The server fetches remote resources using user-supplied URLs without validating against a strict allowlist of permitted destinations.',
    xxe: 'The XML parser is configured to resolve external entities and DTDs by default, allowing attacker-controlled entity definitions.',
    email: 'Email header fields (To, CC, Subject) are constructed using user input without rejecting CRLF sequences.',
    log: 'User input is written directly to application log files without stripping or encoding newline and carriage-return characters.',
    header: 'HTTP response headers are constructed using user input without sanitizing CRLF sequences, enabling response splitting.',
    ldap: 'User input is concatenated directly into LDAP query filters without escaping special LDAP characters.',
    xpath: 'User input is concatenated into XPath query expressions without proper escaping or parameterization.',
    generic: 'Insufficient validation, sanitization, or encoding of user-supplied input before it is processed by the application.',
  };

  // ── Remediation Steps (endpoint-specific) ─────────────────
  const remediations: Record<VulnCategory, string> = {
    sqli: `1. Replace the dynamic SQL query at ${endpoint} with a parameterized/prepared statement.\n2. Bind the "${param}" value using the database driver's parameter binding API — never concatenate.\n3. Apply strict input validation on "${param}" to reject unexpected characters before the query layer.\n4. Configure the database account with least-privilege permissions (no DDL/DBA rights).`,
    nosqli: `1. At ${endpoint}, enforce strict type checking on "${param}" — reject objects, accept only the expected primitive type.\n2. Use the database driver's query builder with explicit field-value bindings instead of raw query objects.\n3. Strip or reject any MongoDB operator prefixes ($gt, $ne, $regex) from "${param}" input.\n4. Add schema validation at the application layer before database interaction.`,
    xss: `1. Apply context-aware output encoding when rendering "${param}" at ${endpoint} — HTML-entity-encode for body, JS-encode for script contexts, URL-encode for href attributes.\n2. Deploy a strict Content-Security-Policy header (script-src 'self') to mitigate any missed encoding.\n3. Set HttpOnly and Secure flags on all session cookies.\n4. Use a templating engine with auto-escaping enabled by default.`,
    ssti: `1. Never pass user input from "${param}" directly to template render functions at ${endpoint}.\n2. Use a sandboxed template environment (e.g., Jinja2 SandboxedEnvironment, Pebble strict mode).\n3. Validate and sanitize "${param}" input before any template processing — reject template syntax characters.\n4. Separate user data from template code: pass data as context variables, never as inline expressions.`,
    cmdi: `1. Eliminate the system shell call at ${endpoint} entirely — use language-native APIs (e.g., fs, child_process with array args) instead.\n2. If shell execution is unavoidable, use a strict allowlist of permitted values for "${param}" — never pass raw input.\n3. Reject shell metacharacters (;, |, &, $, \`, \\n) from "${param}" input via input validation.\n4. Run the application process under a minimal-privilege OS user account.`,
    ssrf: `1. Implement a strict URL allowlist at ${endpoint} — only permit outbound requests to known, trusted domains.\n2. Block all requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1, localhost).\n3. Disable HTTP redirects in the server-side HTTP client processing "${param}".\n4. Use a dedicated egress proxy with DNS-rebinding protection for all outbound requests.`,
    xxe: `1. Disable external entity resolution and DTD processing in the XML parser handling "${param}" at ${endpoint}.\n2. For Java: set XMLConstants.FEATURE_SECURE_PROCESSING. For Python: use defusedxml. For .NET: set DtdProcessing.Prohibit.\n3. Validate XML input against a strict schema (XSD) before processing.\n4. Consider switching from XML to JSON where the API contract permits.`,
    email: `1. Reject any CRLF characters (\\r, \\n, %0d, %0a) in the "${param}" field at ${endpoint} before any mail operation.\n2. Validate email addresses using strict RFC 5321 patterns — reject anything that doesn't match.\n3. Use a dedicated email library (e.g., Nodemailer, javax.mail) that handles header escaping automatically.\n4. Implement rate limiting and logging on the email-sending endpoint.`,
    log: `1. Sanitize "${param}" at ${endpoint} by stripping or encoding CRLF characters before writing to any log output.\n2. Switch to structured logging (JSON format) which naturally escapes control characters.\n3. Implement SIEM correlation rules to detect anomalous log patterns (e.g., unexpected admin-level log entries).\n4. Apply output encoding appropriate for the log sink format.`,
    header: `1. Strip all CRLF sequences (\\r\\n, \\r, \\n) from "${param}" input before it is used in any HTTP response header at ${endpoint}.\n2. Use your framework's built-in response-header API (e.g., res.setHeader in Express) which typically handles encoding.\n3. Reject non-printable characters from user input used in response construction.\n4. Validate that "${param}" conforms to expected format before including in the response.`,
    ldap: `1. Escape LDAP special characters (*, (, ), \\, NUL) in "${param}" before constructing queries at ${endpoint}.\n2. Use parameterized LDAP search filters (framework-supported) instead of string concatenation.\n3. Validate "${param}" against a strict allowlist of expected characters.\n4. Apply least-privilege LDAP bind credentials for the application.`,
    xpath: `1. Use parameterized XPath queries (XPath variables) at ${endpoint} instead of string concatenation with "${param}".\n2. Validate "${param}" input against a strict whitelist of expected values and characters.\n3. Escape XPath special characters (' " [ ] / @) in user input before query construction.\n4. Limit XPath query permissions to read-only where possible.`,
    generic: `1. Apply strict input validation at ${endpoint} for the "${param}" parameter — use an allowlist of expected characters and formats.\n2. Apply context-appropriate output encoding when the value is rendered or processed downstream.\n3. Follow the principle of least privilege for all data access and processing operations.\n4. Perform a targeted code review of the input handling path for this parameter.`,
  };

  const remediationPriority = f.severity === 'Critical' ? 'Immediate (Sprint 0)'
    : f.severity === 'High' ? 'High Priority (Current Sprint)'
    : f.severity === 'Medium' ? 'Planned (Next Sprint)'
    : f.severity === 'Low' ? 'Backlog (Hardening)'
    : 'Informational';

  // ── ATT&CK ────────────────────────────────────────────────
  const attackMappings = getAttackMappings(cat);

  // ── References ────────────────────────────────────────────
  const refs: { label: string; url: string }[] = [];
  const cweNum = cweKey.replace('CWE-', '');
  refs.push({ label: cweFull || cweKey, url: `https://cwe.mitre.org/data/definitions/${cweNum}.html` });
  refs.push({ label: owaspFull, url: OWASP_URLS[f.owasp.trim()] || 'https://owasp.org/Top10/' });
  for (const am of attackMappings) {
    refs.push({ label: `${am.techniqueId}: ${am.techniqueName}`, url: `https://attack.mitre.org/techniques/${am.techniqueId.replace('.', '/')}/` });
  }

  return {
    ...f,
    findingId,
    cvssVector,
    owaspFull,
    cweFull,
    businessRisk: businessRisks[cat],
    technicalDescription: f.description,
    rootCause: rootCauses[cat],
    remediationSteps: remediations[cat],
    remediationPriority,
    attackMappings,
    refs,
  };
}

/* ═══════════════════════════════════════════════════════════════
   CSV GENERATION
   ═══════════════════════════════════════════════════════════════ */

export function generateCSV(report: Report): void {
  const headers = [
    'Finding ID', 'Title', 'Severity', 'CVSS Score', 'CVSS Vector', 'CWE',
    'OWASP Category', 'ATT&CK Tactic(s)', 'ATT&CK Technique ID(s)',
    'Affected Endpoint', 'Status', 'Remediation Summary',
  ];

  const esc = (s: string | undefined | null): string => {
    if (!s) return '""';
    return `"${String(s).replace(/"/g, '""')}"`;
  };

  // Deduplicate findings for CSV — key by (family, url, parameter)
  const rawFindings = report.findings || [];
  const csvSevRank: Record<string, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
  const csvDedupMap = new Map<string, Finding>();
  for (const f of rawFindings) {
    const key = findingDedupKey(f);
    const existing = csvDedupMap.get(key);
    if (!existing || (csvSevRank[f.severity] ?? 0) > (csvSevRank[existing.severity] ?? 0)) {
      csvDedupMap.set(key, f);
    }
  }
  const csvUniqueFindings = Array.from(csvDedupMap.values());

  const rows = csvUniqueFindings.map((f, i) => {
    const e = enrichFinding(f, i);
    return [
      esc(e.findingId), esc(e.type), esc(e.severity), esc(String(e.cvss)),
      esc(e.cvssVector), esc(e.cwe), esc(e.owaspFull),
      esc(e.attackMappings.map(m => m.tactic).join('; ')),
      esc(e.attackMappings.map(m => m.techniqueId).join('; ')),
      esc(e.location), esc('Open'),
      esc(e.remediationSteps.replace(/\n/g, ' ')),
    ];
  });

  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `InjectionLab_Findings_${(report.targetUrl || 'unknown').replace(/[^a-z0-9]/gi, '_').toLowerCase()}_${new Date().toISOString().split('T')[0]}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ═══════════════════════════════════════════════════════════════
   PDF GENERATION
   ═══════════════════════════════════════════════════════════════ */

export function generatePDF(report: Report): void {
  const doc = new jsPDF({ orientation: 'p', unit: 'pt', format: 'a4' });
  const PW = doc.internal.pageSize.getWidth();   // ~595
  const PH = doc.internal.pageSize.getHeight();  // ~842
  const M = 50;
  const CW = PW - 2 * M;                        // ~495

  /* ── Colors (RGB tuples) ── */
  type C3 = [number, number, number];
  const INK: C3   = [26, 29, 35];       // #1A1D23
  const SEC: C3   = [100, 116, 139];    // #64748B
  const ACC: C3   = [15, 118, 110];     // #0F766E (Darker teal for visibility)
  const LNK: C3   = [37, 99, 235];      // #2563EB (Standard link blue)
  const PBG: C3   = [250, 250, 248];    // #FAFAF8
  const BDR: C3   = [226, 232, 240];    // #E2E8F0
  const CBG: C3   = [241, 245, 249];    // #F1F5F9
  const WHT: C3   = [255, 255, 255];

  const SEV: Record<string, C3> = {
    Critical: [220, 38, 38],   // #DC2626
    High:     [234, 88, 12],   // #EA580C
    Medium:   [217, 119, 6],   // #D97706
    Low:      [101, 163, 13],  // #65A30D
    Info:     [100, 116, 139], // #64748B
  };

  /* ── State ── */
  let y = 0;
  let pageNum = 0;
  const reportId = `IL-${(report._id || 'UNKNOWN').slice(-8).toUpperCase()}`;
  const assessDate = new Date(report.createdAt || Date.now()).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  /* ── Deduplicate findings before enrichment — key by (family, url, parameter) ── */
  const rawFindings = report.findings || [];
  const sevRank: Record<string, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
  const dedupMap = new Map<string, Finding>();
  for (const f of rawFindings) {
    const key = findingDedupKey(f);
    const existing = dedupMap.get(key);
    if (!existing || (sevRank[f.severity] ?? 0) > (sevRank[existing.severity] ?? 0)) {
      dedupMap.set(key, f);
    }
  }
  const uniqueFindings = Array.from(dedupMap.values());

  /* ── Enrich findings ── */
  const enriched = uniqueFindings.map((f, i) => enrichFinding(f, i));
  const sorted = [...enriched].sort((a, b) => b.cvss - a.cvss);
  const critCount = enriched.filter(f => f.severity === 'Critical').length;
  const highCount = enriched.filter(f => f.severity === 'High').length;
  const medCount  = enriched.filter(f => f.severity === 'Medium').length;
  const lowCount  = enriched.filter(f => f.severity === 'Low').length;
  const infoCount = enriched.filter(f => f.severity === 'Info').length;
  const total = enriched.length;

  /* ══════════════════════ HELPERS ══════════════════════ */

  const fillBg = () => { doc.setFillColor(...PBG); doc.rect(0, 0, PW, PH, 'F'); };

  const drawChrome = () => {
    doc.setFontSize(7); doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
    doc.text('CONFIDENTIAL', M, 26);
    doc.text(reportId, PW - M, 26, { align: 'right' } as any);
    doc.setDrawColor(...BDR); doc.setLineWidth(0.5);
    doc.line(M, 32, PW - M, 32);
    doc.line(M, PH - 32, PW - M, PH - 32);
    doc.text(`Page ${pageNum}`, PW - M, PH - 20, { align: 'right' } as any);
    doc.text('Injection Lab \u2014 Security Assessment Report', M, PH - 20);
  };

  const newPage = () => {
    doc.addPage(); pageNum++; fillBg(); drawChrome(); y = 60;
  };

  const chk = (need: number) => { if (y + need > PH - 46) newPage(); };

  const safeText = (str: string | undefined | null) => {
    if (!str) return '';
    return String(str)
      .replace(/≤/g, '<=')
      .replace(/≥/g, '>=')
      .replace(/[—–]/g, '-')
      .replace(/[‘’]/g, "'")
      .replace(/[“”]/g, '"')
      .replace(/→/g, '->')
      .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, '');
  };

  /** Write wrapped text, returns nothing — mutates y */
  const wt = (txt: string, x: number, sz: number, font: string, style: string, col: C3, maxW?: number) => {
    doc.setFontSize(sz); doc.setFont(font, style); doc.setTextColor(...col);
    const lines: string[] = doc.splitTextToSize(safeText(txt), maxW ?? CW - (x - M));
    const lh = sz * 1.5;
    for (const ln of lines) { chk(lh); doc.text(ln, x, y); y += lh; }
  };

  const secHead = (title: string) => {
    chk(50); y += 20;
    doc.setFillColor(...ACC); doc.rect(M, y - 14, 3, 18, 'F');
    doc.setFontSize(16); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(title, M + 12, y);
    y += 12;
    doc.setDrawColor(...BDR); doc.setLineWidth(0.5); doc.line(M, y, PW - M, y);
    y += 18;
  };

  const subHead = (title: string) => {
    chk(24); y += 10;
    doc.setFontSize(10.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(title, M, y); y += 18;
  };

  const drawBadge = (sev: string, bx: number, by: number): number => {
    const c = SEV[sev] || SEV.Info;
    const t = sev.toUpperCase();
    doc.setFontSize(7); doc.setFont('helvetica', 'bold');
    const tw = doc.getTextWidth(t);
    const pw = tw + 10;
    doc.setFillColor(...c); doc.rect(bx, by - 8, pw, 11, 'F');
    doc.setTextColor(255, 255, 255); doc.text(t, bx + 5, by);
    return pw;
  };

  const drawGauge = (score: number, sev: string, gx: number, gy: number, gw: number = 170) => {
    doc.setFillColor(...BDR); doc.rect(gx, gy, gw, 8, 'F');
    const fw = Math.max(0, (score / 10) * gw);
    if (fw > 0) { doc.setFillColor(...(SEV[sev] || SEV.Info)); doc.rect(gx, gy, fw, 8, 'F'); }
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(`${score.toFixed(1)} / 10`, gx + gw + 6, gy + 7);
  };

  const drawAggBar = (by: number) => {
    if (total === 0) return;
    let bx = M;
    const segs: { count: number; color: C3; label: string }[] = [
      { count: critCount, color: SEV.Critical, label: 'Critical' },
      { count: highCount, color: SEV.High, label: 'High' },
      { count: medCount, color: SEV.Medium, label: 'Medium' },
      { count: lowCount, color: SEV.Low, label: 'Low' },
      { count: infoCount, color: SEV.Info, label: 'Info' },
    ];
    for (const s of segs) {
      if (s.count === 0) continue;
      const sw = (s.count / total) * CW;
      doc.setFillColor(...s.color); doc.rect(bx, by, sw, 22, 'F');
      if (sw > 30) {
        doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(255, 255, 255);
        doc.text(String(s.count), bx + sw / 2, by + 14, { align: 'center' } as any);
      }
      bx += sw;
    }
    doc.setDrawColor(...BDR); doc.setLineWidth(0.5); doc.rect(M, by, CW, 22, 'S');
  };

  /* ══════════════════════════════════════════════════════
     SECTION 1 — COVER PAGE
     ══════════════════════════════════════════════════════ */
  fillBg();
  doc.setFillColor(...ACC); doc.rect(0, 0, PW, 5, 'F');

  doc.setFontSize(12); doc.setFont('helvetica', 'bold'); doc.setTextColor(...ACC);
  doc.text('INJECTION LAB', M, 68);
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
  doc.text('Automated Security Assessment Platform', M, 83);

  doc.setDrawColor(...ACC); doc.setLineWidth(1.5); doc.line(M, 104, M + 55, 104);

  doc.setFontSize(28); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
  doc.text(doc.splitTextToSize('Vulnerability Assessment Report', CW), M, 145);

  let cy = 200;
  const coverField = (label: string, value: string) => {
    doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
    doc.text(label.toUpperCase(), M, cy); cy += 14;
    doc.setFontSize(11); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(value, CW)[0], M, cy); cy += 26;
  };
  coverField('Assessment Target', report.targetUrl || 'Unknown Target');
  coverField('Assessment Date', assessDate);
  coverField('Report ID', reportId);
  coverField('Status', 'Completed');
  coverField('Classification', 'CONFIDENTIAL');

  doc.setFillColor(...ACC); doc.rect(0, PH - 5, PW, 5, 'F');
  doc.setFontSize(7.5); doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
  doc.text(doc.splitTextToSize('This document contains confidential security assessment findings. Distribution is restricted to authorized personnel only.', CW), M, PH - 44);

  /* ══════════════════════════════════════════════════════
     SECTION 2 — DOCUMENT CONTROL
     ══════════════════════════════════════════════════════ */
  newPage();
  secHead('1. Document Control');

  const dcRows = [
    ['Report Title', report.title], ['Report ID', reportId], ['Version', '1.0'],
    ['Date Issued', assessDate], ['Assessor', 'Injection Lab Automated Scanner v2.4'],
    ['Classification', 'CONFIDENTIAL'], ['Status', 'Final'], ['Target', report.targetUrl || 'Unknown Target'],
  ];
  const rh = 24;
  for (const [label, val] of dcRows) {
    chk(rh);
    doc.setFillColor(...CBG); doc.rect(M, y, 150, rh, 'F');
    doc.setDrawColor(...BDR); doc.setLineWidth(0.3); doc.rect(M, y, CW, rh, 'S');
    doc.setFontSize(8.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text(label, M + 6, y + 16);
    doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(val, CW - 168)[0], M + 156, y + 16);
    y += rh;
  }
  y += 16;

  /* ══════════════════════════════════════════════════════
     SECTION 3 — EXECUTIVE SUMMARY
     ══════════════════════════════════════════════════════ */
  secHead('2. Executive Summary');
  const posture = (report.summary?.riskScore || 0) >= 7 ? 'Critical' : (report.summary?.riskScore || 0) >= 4 ? 'Elevated' : 'Moderate';
  wt(`This report presents the results of an authorized security assessment performed against ${report.targetUrl || 'the target'} on ${assessDate}. The assessment identified ${total} security finding${total !== 1 ? 's' : ''} across the tested attack surface. The overall security posture is assessed as ${posture} Risk.`, M, 10.5, 'helvetica', 'normal', INK);
  y += 8;

  if (total > 0) {
    const top3 = sorted.slice(0, 3);
    subHead('Top Priorities');
    for (let i = 0; i < top3.length; i++) {
      wt(`${i + 1}. ${top3[i].type} (${top3[i].severity}, CVSS ${top3[i].cvss}) at ${top3[i].location.split('?')[0]}`, M + 8, 10, 'helvetica', 'normal', INK);
      y += 2;
    }
    y += 8;
  }

  subHead('Severity Distribution');
  drawAggBar(y); y += 32;

  // Legend
  let lx = M;
  doc.setFontSize(7.5);
  const sevLabels: [string, number][] = [['Critical', critCount], ['High', highCount], ['Medium', medCount], ['Low', lowCount], ['Info', infoCount]];
  for (const [label, count] of sevLabels) {
    doc.setFillColor(...(SEV[label] || SEV.Info)); doc.rect(lx, y, 7, 7, 'F');
    doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
    doc.text(`${label}: ${count}`, lx + 10, y + 6);
    lx += 92;
  }
  y += 20;

  /* ══════════════════════════════════════════════════════
     SECTION 4 — SCOPE & METHODOLOGY
     ══════════════════════════════════════════════════════ */
  secHead('3. Scope & Methodology');
  subHead('Scope');
  wt(`Testing was restricted to ${report.targetUrl || 'the target'}. Only endpoints and parameters identified by the scanner were evaluated. Internal infrastructure, multi-step business-logic flaws, and authenticated endpoints beyond the tested surface were out of scope.`, M, 10.5, 'helvetica', 'normal', INK);
  y += 8;
  subHead('Authorization');
  wt('This assessment was performed under explicit authorization confirmed by the operator before scanner execution. The scanner requires authorization acknowledgment before initiating any analysis. All testing used non-destructive, heuristic-based detection methods that do not modify application state or cause denial of service.', M, 10.5, 'helvetica', 'normal', INK);
  y += 8;
  subHead('Methodology');
  wt('The methodology aligns with the OWASP Testing Guide v4.2 and employs 55 distinct injection detection profiles across major families (SQLi, XSS, SSTI, SSRF, Command Injection, XXE, and others). Findings are classified using CVSS v3.1 Base Scores and mapped to the OWASP Top 10 2021, CWE, and MITRE ATT&CK Enterprise Framework.', M, 10.5, 'helvetica', 'normal', INK);
  y += 8;

  /* ══════════════════════════════════════════════════════
     SECTION 5 — RISK RATING METHODOLOGY
     ══════════════════════════════════════════════════════ */
  secHead('4. Risk Rating Methodology');
  wt('Each finding is assigned a severity rating based on its CVSS v3.1 Base Score. CVSS evaluates exploitability (attack vector, complexity, privileges required, user interaction) and impact (confidentiality, integrity, availability) on a 0\u201310 scale. The severity thresholds used in this report are:', M, 10.5, 'helvetica', 'normal', INK);
  y += 8;

  const sevDefs: [string, string, string][] = [
    ['Critical (9.0\u201310.0)', 'Immediate exploitation risk with severe business impact. Remediate within 24\u201348 hours.', 'Critical'],
    ['High (7.0\u20138.9)', 'Significant risk of data compromise or system access. Remediate within the current sprint.', 'High'],
    ['Medium (4.0\u20136.9)', 'Moderate risk requiring user interaction or specific conditions. Plan remediation.', 'Medium'],
    ['Low (0.1\u20133.9)', 'Limited impact under constrained conditions. Address during hardening cycles.', 'Low'],
    ['Informational (0.0)', 'Best-practice deviation with no directly exploitable impact.', 'Info'],
  ];
  for (const [label, desc, sev] of sevDefs) {
    chk(30);
    doc.setFillColor(...(SEV[sev] || SEV.Info)); doc.rect(M, y - 8, 3, 13, 'F');
    doc.setFontSize(9.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(label, M + 10, y); y += 13;
    wt(desc, M + 10, 9, 'helvetica', 'normal', SEC); y += 4;
  }
  y += 8;

  /* ══════════════════════════════════════════════════════
     SECTION 6 — FINDINGS SUMMARY TABLE
     ══════════════════════════════════════════════════════ */
  secHead('5. Findings Summary');
  if (total === 0) {
    wt('No vulnerabilities were identified during this assessment.', M, 10.5, 'helvetica', 'normal', INK);
  } else {
    const cols = [44, 136, 50, 34, 62, 130, 39]; // sum ≈ 495
    const hdrs = ['ID', 'Title', 'Severity', 'CVSS', 'OWASP', 'Endpoint', 'Status'];

    chk(rh);
    doc.setFillColor(...CBG); doc.rect(M, y, CW, rh, 'F');
    doc.setDrawColor(...BDR); doc.setLineWidth(0.3); doc.rect(M, y, CW, rh, 'S');
    doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    let hx = M;
    hdrs.forEach((h, i) => { doc.text(h, hx + 4, y + 16); hx += cols[i]; });
    y += rh;

    for (const ef of sorted) {
      chk(rh);
      doc.setDrawColor(...BDR); doc.setLineWidth(0.2); doc.line(M, y + rh, PW - M, y + rh);
      let rx = M;
      doc.setFontSize(7.5);
      doc.setFont('courier', 'normal'); doc.setTextColor(...INK);
      doc.text(ef.findingId, rx + 4, y + 16); rx += cols[0];
      doc.setFont('helvetica', 'normal');
      doc.text(doc.splitTextToSize(ef.type, cols[1] - 8)[0], rx + 4, y + 16); rx += cols[1];
      doc.setFont('helvetica', 'bold'); doc.setTextColor(...(SEV[ef.severity] || SEV.Info));
      doc.text(ef.severity, rx + 4, y + 16); rx += cols[2];
      doc.setFont('courier', 'bold'); doc.setTextColor(...INK);
      doc.text(String(ef.cvss), rx + 4, y + 16); rx += cols[3];
      doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
      doc.text(doc.splitTextToSize(ef.owasp, cols[4] - 8)[0], rx + 4, y + 16); rx += cols[4];
      doc.setFont('courier', 'normal'); doc.setTextColor(...INK);
      doc.text(doc.splitTextToSize(ef.location.split('?')[0], cols[5] - 8)[0], rx + 4, y + 16); rx += cols[5];
      doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
      doc.text('Open', rx + 4, y + 16);
      y += rh;
    }
  }
  y += 12;

  /* ══════════════════════════════════════════════════════
     SECTION 7 — DETAILED FINDINGS
     ══════════════════════════════════════════════════════ */
  secHead('6. Detailed Findings');

  for (const ef of sorted) {
    // ─── Finding header bar ───
    chk(190);
    y += 10;
    doc.setFillColor(...INK); doc.rect(M, y, CW, 28, 'F');
    doc.setFontSize(11); doc.setFont('helvetica', 'bold'); doc.setTextColor(255, 255, 255);
    const titleTxt = `${ef.findingId}: ${ef.type}`;
    doc.text(doc.splitTextToSize(titleTxt, CW - 85)[0], M + 10, y + 18);
    drawBadge(ef.severity, PW - M - 65, y + 18);
    y += 40;

    // ═══ VULNERABILITY SIDE ═══
    doc.setFillColor(...ACC); doc.rect(M, y, CW, 1.5, 'F'); y += 14;
    doc.setFontSize(9); doc.setFont('helvetica', 'bold'); doc.setTextColor(...ACC);
    doc.text('VULNERABILITY', M, y); y += 18;

    // Metadata box
    chk(66);
    doc.setFillColor(...CBG); doc.rect(M, y, CW, 60, 'F');
    doc.setDrawColor(...BDR); doc.setLineWidth(0.3); doc.rect(M, y, CW, 60, 'S');

    const halfW = CW / 2;
    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text('ENDPOINT', M + 8, y + 13);
    doc.setFontSize(8); doc.setFont('courier', 'normal'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(ef.location, halfW - 16)[0], M + 8, y + 25);

    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text('PARAMETER', M + halfW, y + 13);
    doc.setFontSize(8); doc.setFont('courier', 'normal'); doc.setTextColor(...INK);
    doc.text(ef.parameter || 'N/A', M + halfW, y + 25);

    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text('CVSS v3.1', M + 8, y + 42);
    doc.setFontSize(8); doc.setFont('courier', 'bold'); doc.setTextColor(...INK);
    doc.text(`${ef.cvss}`, M + 55, y + 42);
    doc.setFont('courier', 'normal'); doc.setTextColor(...SEC);
    doc.text(ef.cvssVector, M + 78, y + 42);

    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text('CWE', M + halfW, y + 42);
    doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(ef.cwe, halfW - 30)[0], M + halfW + 25, y + 42);

    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text('OWASP', M + 8, y + 54);
    doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(ef.owaspFull, CW - 50)[0], M + 42, y + 54);

    y += 70;

    // Risk gauge
    chk(18);
    doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text('RISK SCORE', M, y + 6);
    drawGauge(ef.cvss, ef.severity, M + 65, y, 170);
    y += 18;

    // Business Risk
    subHead('Business Risk');
    wt(ef.businessRisk, M, 10, 'helvetica', 'normal', INK);
    y += 6;

    // Technical Description
    subHead('Technical Description');
    wt(ef.technicalDescription, M, 10, 'helvetica', 'normal', INK);
    y += 6;

    // Proof of Concept — with structured evidence
    if (ef.pocPayload || ef.evidence) {
      subHead('Proof of Concept');
      const parts: string[] = [];
      // Try to parse structured evidence from JSON
      let structuredEv: any = null;
      try {
        if (ef.evidence) structuredEv = JSON.parse(ef.evidence);
      } catch { /* not JSON, use as string */ }

      if (structuredEv && typeof structuredEv === 'object') {
        if (structuredEv.http_method) parts.push(`Method: ${structuredEv.http_method}`);
        if (ef.parameter) parts.push(`Parameter: ${ef.parameter} (${structuredEv.parameter_location || 'query'})`);
        if (structuredEv.reasons && structuredEv.reasons.length > 0) {
          parts.push(`Detection: ${structuredEv.reasons.join(', ')}`);
        }
        if (structuredEv.tested_value) {
          parts.push(`\nSuccessful Payload:\n${structuredEv.tested_value}`);
        }
        if (structuredEv.status_code) {
          parts.push(`Response: HTTP ${structuredEv.status_code}`);
        }
      } else {
        if (ef.evidence) parts.push(`Signal: ${ef.evidence}`);
        if (ef.parameter) parts.push(`Parameter: ${ef.parameter}${ef.paramValue ? ` = ${ef.paramValue}` : ''}`);
      }
      if (!structuredEv?.tested_value && ef.pocPayload) {
        parts.push(`\nPayload:\n${ef.pocPayload}`);
      }
      const pocStr = safeText(parts.join('\n'));
      const pocLines: string[] = doc.splitTextToSize(pocStr, CW - 20);
      const pocH = pocLines.length * 11 + 18;

      chk(pocH);
      doc.setFillColor(245, 245, 242); doc.rect(M, y, CW, pocH, 'F');
      doc.setDrawColor(...BDR); doc.rect(M, y, CW, pocH, 'S');
      doc.setFillColor(...ACC); doc.rect(M, y, 3, pocH, 'F');
      doc.setFontSize(8.5); doc.setFont('courier', 'normal'); doc.setTextColor(...INK);
      doc.text(pocLines, M + 12, y + 13);
      y += pocH + 8;
    }

    // ═══ MITIGATION SIDE ═══
    chk(40);
    y += 6;
    doc.setDrawColor(...ACC); doc.setLineWidth(1); doc.line(M, y, PW - M, y);
    doc.setLineWidth(0.5); y += 14;
    doc.setFontSize(9); doc.setFont('helvetica', 'bold'); doc.setTextColor(...ACC);
    doc.text('MITIGATION', M, y); y += 18;

    // Remediation
    subHead('Remediation Steps');
    wt(ef.remediationSteps, M, 10, 'helvetica', 'normal', INK);
    y += 4;
    doc.setFontSize(8.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...SEC);
    doc.text(`Priority: ${ef.remediationPriority}`, M, y); y += 14;

    // ATT&CK Mapping
    subHead('MITRE ATT\u0026CK Mapping');
    for (const am of ef.attackMappings) {
      chk(26);
      doc.setFontSize(8.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
      doc.text(`${am.tacticId} ${am.tactic}`, M, y); y += 12;
      doc.setFontSize(8); doc.setFont('courier', 'normal'); doc.setTextColor(...ACC);
      doc.text(`  -> ${am.techniqueId}: ${am.techniqueName}`, M, y); y += 14;
    }
    y += 4;

    // References
    subHead('References');
    for (const ref of ef.refs) {
      chk(22);
      doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
      doc.text(`\u2022 ${ref.label}`, M + 4, y); y += 10;
      doc.setFontSize(7); doc.setFont('courier', 'normal'); doc.setTextColor(...LNK);
      doc.text(ref.url, M + 10, y); y += 12;
    }
    y += 10;

    // Finding separator
    if (sorted.indexOf(ef) < sorted.length - 1) {
      doc.setDrawColor(...BDR); doc.setLineWidth(0.3); doc.line(M, y, PW - M, y); y += 4;
    }
  }

  /* ══════════════════════════════════════════════════════
     SECTION 8 — ATT&CK COVERAGE SUMMARY
     ══════════════════════════════════════════════════════ */
  newPage();
  secHead('7. ATT\u0026CK Coverage Summary');
  wt('The table below summarises all MITRE ATT\u0026CK Enterprise tactics and techniques observed across the findings in this assessment, providing an attacker-chain perspective.', M, 10.5, 'helvetica', 'normal', INK);
  y += 8;

  // Build coverage map
  const atkMap = new Map<string, { tactic: string; tacticId: string; techniqueId: string; techniqueName: string; findings: string[] }>();
  for (const ef of enriched) {
    for (const am of ef.attackMappings) {
      const key = `${am.tacticId}|${am.techniqueId}`;
      if (!atkMap.has(key)) atkMap.set(key, { ...am, findings: [] });
      atkMap.get(key)!.findings.push(ef.findingId);
    }
  }
  const atkRows = Array.from(atkMap.values()).sort((a, b) => a.tacticId.localeCompare(b.tacticId));

  // Table
  const atCols = [115, 72, 175, 133]; // sum ≈ 495
  const atHdrs = ['Tactic', 'Technique ID', 'Technique Name', 'Finding(s)'];
  chk(rh);
  doc.setFillColor(...CBG); doc.rect(M, y, CW, rh, 'F');
  doc.setDrawColor(...BDR); doc.setLineWidth(0.3); doc.rect(M, y, CW, rh, 'S');
  doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
  let ax = M;
  atHdrs.forEach((h, i) => { doc.text(h, ax + 5, y + 16); ax += atCols[i]; });
  y += rh;

  for (const ar of atkRows) {
    chk(rh);
    doc.setDrawColor(...BDR); doc.setLineWidth(0.2); doc.line(M, y + rh, PW - M, y + rh);
    ax = M;
    doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(`${ar.tacticId} ${ar.tactic}`, atCols[0] - 10)[0], ax + 5, y + 16); ax += atCols[0];
    doc.setFont('courier', 'normal');
    doc.text(ar.techniqueId, ax + 5, y + 16); ax += atCols[1];
    doc.setFont('helvetica', 'normal');
    doc.text(doc.splitTextToSize(ar.techniqueName, atCols[2] - 10)[0], ax + 5, y + 16); ax += atCols[2];
    doc.setFont('courier', 'normal'); doc.setTextColor(...ACC);
    doc.text(doc.splitTextToSize(ar.findings.join(', '), atCols[3] - 10)[0], ax + 5, y + 16);
    y += rh;
  }
  y += 16;

  /* ══════════════════════════════════════════════════════
     SECTION 9 — REMEDIATION ROADMAP
     ══════════════════════════════════════════════════════ */
  secHead('8. Remediation Roadmap');
  wt('All findings resequenced by remediation priority for engineering planning.', M, 10.5, 'helvetica', 'normal', INK);
  y += 8;

  const rrCols = [88, 48, 125, 52, 182]; // sum ≈ 495
  const rrHdrs = ['Priority', 'ID', 'Title', 'Severity', 'Primary Remediation'];
  chk(rh);
  doc.setFillColor(...CBG); doc.rect(M, y, CW, rh, 'F');
  doc.setDrawColor(...BDR); doc.setLineWidth(0.3); doc.rect(M, y, CW, rh, 'S');
  doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
  let rrx = M;
  rrHdrs.forEach((h, i) => { doc.text(h, rrx + 4, y + 16); rrx += rrCols[i]; });
  y += rh;

  for (const ef of sorted) {
    const firstStep = (ef.remediationSteps.split('\n')[0] || '').replace(/^1\.\s*/, '');
    const stepLines: string[] = doc.splitTextToSize(firstStep, rrCols[4] - 10);
    const rowH = Math.max(rh, stepLines.length * 10 + 10);
    chk(rowH);
    doc.setDrawColor(...BDR); doc.setLineWidth(0.2); doc.line(M, y + rowH, PW - M, y + rowH);
    rrx = M;
    doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(doc.splitTextToSize(ef.remediationPriority, rrCols[0] - 8)[0], rrx + 4, y + 16); rrx += rrCols[0];
    doc.setFont('courier', 'normal');
    doc.text(ef.findingId, rrx + 4, y + 16); rrx += rrCols[1];
    doc.setFont('helvetica', 'normal');
    doc.text(doc.splitTextToSize(ef.type, rrCols[2] - 8)[0], rrx + 4, y + 16); rrx += rrCols[2];
    doc.setFont('helvetica', 'bold'); doc.setTextColor(...(SEV[ef.severity] || SEV.Info));
    doc.text(ef.severity, rrx + 4, y + 16); rrx += rrCols[3];
    doc.setFont('helvetica', 'normal'); doc.setTextColor(...INK);
    doc.text(stepLines, rrx + 4, y + 16);
    y += rowH;
  }
  y += 16;

  /* ══════════════════════════════════════════════════════
     SECTION 10 — GLOSSARY
     ══════════════════════════════════════════════════════ */
  secHead('9. Appendix \u2014 Glossary');

  const glossary: [string, string][] = [
    ['CVSS', 'Common Vulnerability Scoring System \u2014 a standardised framework for rating vulnerability severity on a 0\u201310 scale.'],
    ['CWE', 'Common Weakness Enumeration \u2014 a community-developed catalogue of software and hardware weakness types.'],
    ['OWASP', 'Open Worldwide Application Security Project \u2014 a nonprofit that publishes security guidelines including the widely-referenced Top 10 list.'],
    ['MITRE ATT&CK', 'A knowledge base of adversary tactics and techniques based on real-world observations, used to classify attacker behaviour.'],
    ['SQL Injection (SQLi)', 'An attack where malicious SQL is inserted into application queries, allowing database contents to be read, modified, or deleted.'],
    ['Cross-Site Scripting (XSS)', 'An attack where malicious scripts are injected into web pages viewed by other users, enabling session theft or page defacement.'],
    ['Server-Side Template Injection (SSTI)', 'An attack where template-engine syntax is injected into server-side templates, potentially leading to remote code execution.'],
    ['Server-Side Request Forgery (SSRF)', 'An attack where the server is tricked into making requests to internal resources not intended to be externally accessible.'],
    ['XML External Entity (XXE)', 'An attack against XML parsers that resolve external entities, allowing local-file disclosure or internal-network scanning.'],
    ['Command Injection', 'An attack where OS commands are injected through application inputs, giving the attacker control over the server.'],
    ['CRLF Injection', 'An attack that injects carriage-return / line-feed characters to manipulate HTTP headers or log files.'],
    ['NoSQL Injection', 'An attack against NoSQL databases where query operators are injected to bypass authentication or extract data.'],
    ['Log Injection', 'An attack where fake log entries are inserted to cover tracks, confuse security analysts, or forge audit trails.'],
    ['Parameterized Query', 'A database query technique where user input is bound as parameters rather than concatenated, preventing SQL injection.'],
    ['CVSS Vector', 'A text string encoding the specific attack characteristics (vector, complexity, impact) used to calculate a CVSS score.'],
  ];

  for (const [term, def] of glossary) {
    chk(32);
    doc.setFontSize(10); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
    doc.text(term, M, y); y += 12;
    wt(def, M + 8, 9, 'helvetica', 'normal', SEC);
    y += 6;
  }

  /* ══════════════════════════════════════════════════════
     SECTION 11 — END OF REPORT
     ══════════════════════════════════════════════════════ */
  newPage();
  doc.setFillColor(...ACC); doc.rect(0, 0, PW, 5, 'F');
  
  y = PH / 2 - 40;
  doc.setFontSize(24); doc.setFont('helvetica', 'bold'); doc.setTextColor(...INK);
  doc.text('END OF REPORT', PW / 2, y, { align: 'center' } as any);
  
  y += 24;
  doc.setFontSize(10); doc.setFont('helvetica', 'normal'); doc.setTextColor(...SEC);
  doc.text('Injection Lab - Automated Security Assessment Platform', PW / 2, y, { align: 'center' } as any);
  
  doc.setFillColor(...ACC); doc.rect(0, PH - 5, PW, 5, 'F');

  /* ── Save ── */
  doc.save(`InjectionLab_Assessment_${(report.targetUrl || 'unknown').replace(/[^a-z0-9]/gi, '_').toLowerCase()}_${new Date().toISOString().split('T')[0]}.pdf`);
}
