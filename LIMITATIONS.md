# InjectionLab Scanner — Capabilities & Known Limitations

This document outlines what the InjectionLab scanner is designed to do well, alongside known technical boundaries and scenarios where manual verification or specialized tooling is required.

---

## 🎯 Scanner Strengths & Core Capabilities

1. **Generic Behavioral Differential Testing**
   - **Boolean-Based SQL Injection:** Evaluates true vs. false condition payloads (`1 AND 1=1` vs `1 AND 1=2`) to detect response state alterations, status divergences, and content size shifts without relying on site-specific strings.
   - **Generic Auth Bypass Detection:** Identifies authentication bypass through universal HTTP behaviors (authenticated redirects, session cookie issuance, status code elevation) across arbitrary login forms.

2. **Broad Multi-Database Error Library**
   - Contains signatures for 35+ database engines, drivers, and ORMs including MySQL, MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, IBM DB2, Microsoft Access, Hibernate, Sequelize, and TypeORM.
   - Detects unhandled 500 server anomalies triggered by unescaped quotation syntax probes.

3. **Contextual Canary Reflection (XSS & Command Injection)**
   - Uses distinct canary tags (`<injlab_xss_canary_probe>`) and attribute break-outs (`" injlab-probe-attr="1`) to verify unescaped reflection within renderable HTML contexts.
   - Utilizes safe shell echo probes (`; echo injlab_cmd_probe_success`) to confirm OS command execution without causing destructive system changes.

4. **Template Engine Evaluation (SSTI)**
   - Employs mathematical expressions (`{{77*77}}` -> `5929`) to confirm dynamic server-side template evaluation while distinguishing computed outputs from literal reflections.

5. **Security Header Auditing & WAF Fingerprinting**
   - Evaluates HTTP response security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
   - Identifies active Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5 ASM, Sucuri, Fastly) to alert auditors of potential payload filtering.

6. **Client-Side SPA DOM Extraction**
   - Leverages headless Chromium (Puppeteer) with static HTTP fetch fallback to parse dynamically mounted React, Vue, and Angular forms and links.

---

## ⚠️ Known Limitations & Boundaries

1. **Web Application Firewalls (WAF) & Rate Limiters**
   - **Impact:** Aggressive WAFs (e.g. Cloudflare Under Attack Mode, AWS WAF bot controls) or IP-level rate limiters may intercept, alter, or block probe traffic (returning 403 Forbidden or CAPTCHA challenges).
   - **Expectation:** When a WAF is active, the scanner flags its presence and notes that real vulnerabilities may be masked.

2. **Out-of-Band (OOB) Vulnerabilities**
   - **Impact:** Blind injection vulnerabilities that yield zero in-band response difference and require external callback listeners (DNS/HTTP interaction like Burp Collaborator or interactsh) cannot be confirmed by in-band differential probing alone.

3. **Multi-Step Workflows & Dynamic Anti-CSRF Nonces**
   - **Impact:** Forms requiring fresh per-request CSRF tokens, multi-factor authentication (MFA), CAPTCHAs, or strict multi-step wizard state sequences will reject automated differential requests.

4. **Second-Order Injections**
   - **Impact:** Vulnerabilities where a payload is stored (e.g., in a database profile or log) and only activated later when viewed by an administrator on an internal dashboard are outside the scope of single-phase DAST scanning.

5. **Complex Single-Page Application Interactions**
   - **Impact:** While Puppeteer discovers initial DOM elements, single-page applications that require complex multi-click user journeys or client-side encrypted payloads (e.g., custom WebCrypto envelopes) require manual penetration testing.

---

## 🛡️ Recommended Usage Guidelines

- Always ensure explicit written authorization before scanning any target.
- Use passive heuristic mode for initial reconnaissance on production targets.
- Supplement automated active scanning with manual code review and specialized interactive testing for mission-critical applications.
