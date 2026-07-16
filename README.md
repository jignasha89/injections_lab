# InjectionLab — Cybersecurity Education Platform

**Tagline**: Learn. Detect. Fix.

InjectionLab is an educational cybersecurity training platform that simulates common input injection flaws and showcases developer mitigation mechanisms. The application combines interactive sandboxes, technical interview preparations, code editor highlights, and audit report downloads.

---

## Technical Architecture Overview

The system runs a decoupled Client-Server architecture:
1. **Frontend**: Next.js 14 App Router, TailwindCSS v4, Zustand, Framer Motion animations, and Monaco Code Editor comparisons.
2. **Backend**: Express Node.js API with custom security middleware (Helmet, Rate Limits).
3. **Database**: MongoDB Mongoose database storing user states, progress cards, and scan archives.

---

## Project Structure

```
d:\injection checker software\
├── frontend/                    # Next.js 14 Client
│   ├── src/
│   │   ├── app/                 # Routes
│   │   ├── components/          # Sandbox, Quiz, Code Compare, Layouts
│   │   ├── lib/                 # Store, Axios API Client
│   │   └── data/                # Labs educational data
│   └── package.json
│
├── backend/                     # Express Server
│   ├── src/
│   │   ├── models/              # Mongoose schemas (User, Report)
│   │   ├── routes/              # API router (Auth, Labs, Scanner, Reports, User)
│   │   ├── services/            # Passive scanner heuristic services
│   │   ├── data/                # Static 13 labs syllabus data
│   │   └── scripts/             # DB Seeding script
│   └── package.json
│
├── docker-compose.yml           # Local multi-container compose file
└── README.md                    # Technical documentation
```

---

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) v18+ and `npm` installed.
- [MongoDB](https://www.mongodb.com/) running locally on `mongodb://localhost:27017/` (or via Docker).

### Option A: Local Desktop Setup

1. **Clone & Install Backend**:
   ```bash
   cd backend
   npm install
   ```
2. **Configure Environment Variables**:
   Create a `.env` file in the `backend/` folder (a default `.env` is already configured for localhost):
   ```env
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/injectionlab
   JWT_SECRET=injectionlab_super_secret_jwt_key_2024_change_in_production
   JWT_REFRESH_SECRET=injectionlab_refresh_secret_2024_change_in_production
   JWT_EXPIRES_IN=15m
   JWT_REFRESH_EXPIRES_IN=7d
   NODE_ENV=development
   FRONTEND_URL=http://localhost:3000
   ```
3. **Seed Database**:
   ```bash
   npm run seed
   ```
   *Seeds the database with default accounts:*
   - **Student Account**: `student@injectionlab.local` / `student12345`
   - **Admin Account**: `admin@injectionlab.local` / `admin12345`
4. **Start Backend**:
   ```bash
   npm run dev
   ```

5. **Start Frontend**:
   Navigate to the `frontend` directory in a new terminal window:
   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```
   *Frontend is now listening on `http://localhost:3000`.*

---

### Option B: Docker Compose Setup

Run the following command in the root workspace directory to build and spawn all services (DB, server, client) instantly:
```bash
docker-compose up --build
```
*Port mappings:*
- **Frontend App**: `http://localhost:3000`
- **Backend API**: `http://localhost:5000/api`
- **MongoDB Port**: `http://localhost:27017`

---

## 13 Injection Lab Modules

Dedicated guides, animations, and sandboxes are built for:
1. **CRLF Injection** — Line feeds (%0D%0A) inside header writers.
2. **HTTP Response Splitting** — Splitting response packages to poison caches.
3. **HTTP Header Injection** — Injecting raw Set-Cookie variables.
4. **Host Header Injection** — Poisoning password reset mail links.
5. **Log Injection** — Forging entry parameters in system text loggers.
6. **Log4Shell** — Explaining JNDI LDAP lookup codes.
7. **Email Header Injection** — Injecting CC/BCC lines in mail objects.
8. **SMTP Injection** — SMTP protocol command overrides.
9. **IMAP Injection** — Command selector injections in mail boxes.
10. **Path Traversal** — Crawling outside allowed folders via `../`.
11. **Null Byte Injection** — String truncation via `%00` filters.
12. **Direct Prompt Injection** — Prompt bypass in Large Language Models.
13. **Indirect Prompt Injection** — External data poisonings inside AI agents.

---

## API Specifications

### Authentication Routes
- `POST /api/auth/register` — Create new student workspace credentials.
- `POST /api/auth/login` — Sign in and claim JWT authorization tokens.
- `POST /api/auth/refresh` — Refresh access token pairs.
- `GET /api/auth/me` — Verify token context.

### Labs & Progress Routes
- `GET /api/labs` — List catalog threat categories.
- `GET /api/labs/:slug` — Retrieve full CVE description, Monaco example lines, and quiz objects.
- `POST /api/labs/:slug/quiz/submit` — Submit quiz scorecards.
- `PUT /api/user/progress/:labSlug` — Update completion flags.

### Inspector/Scanner Routes
- `POST /api/scanner/analyze` — Passively analyze query structures and endpoints.
- `POST /api/reports/generate` — Save inspection sheets to MongoDB records.
- `GET /api/reports` — List saved report archives.
- `DELETE /api/reports/:id` — Delete individual reports.

---

## OWASP Secure Coding Principles Implemented
- **Input Sanitization**: Block lists and regex sanitizations for CRLF and JNDI lookups.
- **Output Encoding**: Safe rendering of reflected tags.
- **Path Normalization**: Canonical resolution via `path.resolve()` and domain boundaries checks.
- **Privilege Separation**: Clear boundaries for system prompts in LLM calls.
- **Secure Sessions**: SameSite, HttpOnly, and Secure cookie configs.
