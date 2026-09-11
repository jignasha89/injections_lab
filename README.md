# 🛡️ InjectionLab — Full-Stack Educational Security Platform

**InjectionLab** is a full-stack web security education platform built for cybersecurity academic institutions. It demonstrates **55 distinct injection attack types** mapped across 4 team member specialized domains, providing interactive payload sandboxes, structural target URL inspections, framework remediation guides, quiz assessments, and official PDF audit reports.

---

## 👩‍💻 Project Ownership & Team Structure

- **Platform Owner**: **Jignasha Panchal** (`jignasha89@gmail.com`)

### 👥 Team Member Topic Division (55 Total Injection Types)
1. **Dwij (14 Attack Types)**: Database & Query Injection (SQLi, NoSQLi, Blind SQLi, GraphQL, XPath, ORM, LDAPs, Command/DB, etc.)
2. **Mohit (14 Attack Types)**: Client-Side & Browser Injection (DOM XSS, Stored XSS, Reflected XSS, HTMLi, Client Template, CSP Bypass, Prototype Pollution, etc.)
3. **Yashi (14 Attack Types)**: Server-Side & Code Execution Injection (RCE, SSTI, Deserialization, XXE, Command Injection, OS Command, Code Eval, File Inclusion, etc.)
4. **Jignasha (13 Attack Types)**: Protocol, Header, Log & AI Injection (CRLF, Log4Shell, SMTP, Header Split, Prompt Injection, Host Header, Log Tampering, SSRF, etc.)

---

## 🎨 Design Aesthetic
- **Theme**: Dark Obsidian Hacker Aesthetic (`#050508` dark background, `#f8fafc` crisp white typography)
- **Accents**: Neon Cyan (`#00f0ff`), Emerald Green (`#00ff88`), Electric Purple (`#b026ff`), Cyber Rose (`#ff2a5f`)
- **Features**: Glassmorphic panels, real-time diagnostic output terminals, live CVSS metrics, interactive quiz badges, PDF generation.

---

## 🚀 Launching on Windows

### Prerequisites
- Node.js (v18+)
- npm (v9+)

### 1. Backend Setup
```powershell
cd backend
npm install
npm run dev
```
*Note: If MongoDB is not running locally, backend automatically enables `USE_MEMORY_DB=true` mode and runs seamlessly on `http://localhost:5000`.*

### 2. Frontend Setup
```powershell
cd frontend
npm install
cmd /c "npm run dev"
```
*Open your browser at `http://localhost:3000`.*

---

## 🐧 Launching on Kali Linux

### Prerequisites
```bash
sudo apt update
sudo apt install -y nodejs npm git
```

### 1. Backend Setup
```bash
cd backend
npm install
npm run dev
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
*Open browser at `http://localhost:3000` or inspect targets via CLI curl.*

---

## 🔑 Default Credentials
- **Admin Email**: `ipgroot@gmail.com`
- **Password**: `IpGroot@22`

---

## 🛠️ Tech Stack
- **Frontend**: Next.js 16 (App Router), React 19, Tailwind CSS v4, Zustand State Management, Lucide Icons, jsPDF & html2canvas.
- **Backend**: Node.js Express, TypeScript, In-Memory DB Mode & MongoDB Mongoose models, JWT Authentication, CORS.

---

## 🔒 Security, Cryptography & Encryption Architecture

InjectionLab implements comprehensive, defense-in-depth cryptographic security across the client, server, database, and administrative panel. **All saved data is encrypted in transit (TLS 1.3 / AES-256-GCM) and at rest (AES-256-GCM with HMAC integrity validation), and access is strictly restricted to authenticated and authorized users.**

### 1. Transport Layer Security & Security Headers
- **HTTPS Enforcement**: In production and cloud deployments, all incoming HTTP requests are automatically redirected to HTTPS via a 301 Permanent Redirect.
- **Strict HTTP Security Headers**: Configured across both Express and Next.js:
  - `Strict-Transport-Security`: `max-age=31536000; includeSubDomains; preload`
  - `Content-Security-Policy`: Restricts unauthorized origins, scripts, and frame embedding.
  - `X-Content-Type-Options: nosniff` (prevents MIME-type confusion attacks).
  - `X-Frame-Options: DENY` (prevents clickjacking).
  - `Referrer-Policy: strict-origin-when-cross-origin`.

### 2. Client ↔ Server In-Transit Payload Encryption
- Sensitive scan requests, responses, and session payloads are encrypted over the wire using **AES-256-GCM** with an ephemeral per-session key.
- A secure key exchange handshake (`POST /api/security/handshake`) issues a cryptographically random session key stored only in client memory for the session lifetime.
- Both client (Web Crypto API) and server (Node.js `crypto`) authenticate ciphertext using a 128-bit GCM authentication tag.

### 3. Encryption at Rest (AES-256-GCM + HMAC Integrity)
- **Zero Plaintext Storage**: Every scan result, target URL, vulnerability finding, chat board transcript, and prompt injection attempt saved to MongoDB (collections: `reports`, `chatSessions`, `injectionAttempts`, `auditLogs`) or memory DB is encrypted with **AES-256-GCM** before being written.
- **Master Encryption Key (`DB_ENCRYPTION_KEY`)**: Stored exclusively as an isolated environment variable, never stored alongside data or exposed to client-side bundles.
- **HMAC-SHA256 Tamper Detection**: Each encrypted container (`enc:v1:<iv>:<tag>:<hmac>:<ciphertext>`) is signed with an HMAC-SHA256 digest derived via HKDF. Any tampering with stored database records is detected before decryption, causing immediate rejection and security alerting.
- **Decrypt-on-Demand**: Stored records are decrypted only at the exact moment of authorized retrieval (user viewing their own history, or an authorized administrator viewing the admin panel).

### 4. Admin Panel Access Control & Audit Vault
- **Role-Based Access Control (RBAC)**: Only accounts with the `admin` role can view all users' scan history, inspect global prompt injection logs, and access administrative telemetry. Regular students can only view their own reports.
- **Immutable Audit Logging**: Every administrative access to sensitive user data (`VIEW_ALL_SCANS`, `VIEW_SCAN_DETAIL`, `EXPORT_REPORT`, etc.) is recorded in the `auditLogs` collection with administrator username, IP address, user-agent, target resource, and timestamp.
- **15-Minute Session Inactivity Timeout**: The admin panel actively tracks user idle time; after 15 minutes of inactivity, the session is terminated and the administrator is logged out automatically.
- **Two-Factor Authentication (2FA)**: High-privilege administrative operations can be verified with a 6-digit TOTP token.

### 5. Key Management & Key Rotation Procedure
- **Environment Variable Isolation**: Keep `DB_ENCRYPTION_KEY`, `OPENAI_API_KEY`, `JWT_SECRET`, and `ADMIN_JWT_SECRET` as separate variables in your deployment environment (e.g. Vercel, Docker). Never reuse or commit them.
- **Generating a New Master Key**:
  ```bash
  # Generate a cryptographically secure 256-bit key (64 hex characters)
  openssl rand -hex 32
  ```
- **Key Rotation Process**:
  1. Generate a new 256-bit master key (`DB_ENCRYPTION_KEY_NEW`).
  2. Run the database migration script to read existing records with `DB_ENCRYPTION_KEY`, decrypt each container, and re-encrypt with `DB_ENCRYPTION_KEY_NEW`.
  3. Promote `DB_ENCRYPTION_KEY_NEW` to `DB_ENCRYPTION_KEY` in environment variables.
  4. Restart the backend service.

