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
- **Student Email**: `jignasha89@gmail.com`
- **Password**: `jignasha@893`

---

## 🛠️ Tech Stack
- **Frontend**: Next.js 16 (App Router), React 19, Tailwind CSS v4, Zustand State Management, Lucide Icons, jsPDF & html2canvas.
- **Backend**: Node.js Express, TypeScript, In-Memory DB Mode & MongoDB Mongoose models, JWT Authentication, CORS.
