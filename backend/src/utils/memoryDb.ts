import bcrypt from 'bcryptjs';
import { labsData } from '../data/labsData';

// User structure
interface MemoryProgress {
  labSlug: string;
  completed: boolean;
  quizScore: number;
  completedAt?: Date;
  bookmarked: boolean;
}

interface MemoryNote {
  labSlug: string;
  content: string;
  updatedAt: Date;
}

interface MemoryAchievement {
  id: string;
  earnedAt: Date;
}

interface MemoryUser {
  _id: string;
  username: string;
  email: string;
  passwordHash: string;
  role: 'student' | 'admin';
  progress: MemoryProgress[];
  achievements: MemoryAchievement[];
  notes: MemoryNote[];
  createdAt: Date;
}

// Report structure
interface MemoryFinding {
  type: string;
  location: string;
  parameter?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  recommendation: string;
}

interface MemoryReport {
  _id: string;
  userId: string;
  title: string;
  targetUrl: string;
  scanType: 'url' | 'demo';
  labSlug?: string;
  summary: {
    totalPages: number;
    injectionPoints: number;
    forms: number;
    headers: number;
    parameters: number;
    cookies: number;
    jsonInputs: number;
    riskScore: number;
    owaspCoverage: string[];
  };
  findings: MemoryFinding[];
  techStack: string[];
  createdAt: Date;
}

// In-Memory Database store
export const usersStore: MemoryUser[] = [
  // Admin user
  {
    _id: 'admin_mem_id',
    username: 'admin',
    email: 'admin@injectionlab.local',
    passwordHash: bcrypt.hashSync('admin12345', 12),
    role: 'admin',
    progress: [],
    achievements: [{ id: 'first_lab', earnedAt: new Date() }],
    notes: [],
    createdAt: new Date(),
  },
  // Default student user
  {
    _id: 'student_mem_id',
    username: 'student',
    email: 'student@injectionlab.local',
    passwordHash: bcrypt.hashSync('student@123', 12),
    role: 'student',
    progress: labsData.map((lab, i) => ({
      labSlug: lab.slug,
      completed: i < 3,
      quizScore: i < 3 ? 80 + i * 10 : 0,
      completedAt: i < 3 ? new Date(Date.now() - (3 - i) * 24 * 60 * 60 * 1000) : undefined,
      bookmarked: i === 4,
    })),
    achievements: [{ id: 'first_lab', earnedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000) }],
    notes: [
      {
        labSlug: 'crlf-injection',
        content: 'CRLF injection occurs when Carriage Return (\\r) and Line Feed (\\n) sequences are unchecked in headers.',
        updatedAt: new Date(),
      },
    ],
    createdAt: new Date(),
  },
  // ── Public Demo Account (safe to share with anyone) ──
  {
    _id: 'public_demo_id',
    username: 'InjectionLab Demo',
    email: 'open@gmail.com',
    passwordHash: bcrypt.hashSync('open@123', 12),
    role: 'student',
    progress: labsData.map((lab, i) => ({
      labSlug: lab.slug,
      completed: i < 5,
      quizScore: i < 5 ? 70 + i * 5 : 0,
      completedAt: i < 5 ? new Date(Date.now() - (5 - i) * 24 * 60 * 60 * 1000) : undefined,
      bookmarked: i === 1 || i === 7,
    })),
    achievements: [{ id: 'first_lab', earnedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000) }],
    notes: [
      {
        labSlug: 'sql-injection-classic',
        content: 'Classic SQLi: try \' OR \'1\'=\'1\'-- in any login field to bypass authentication.',
        updatedAt: new Date(),
      },
    ],
    createdAt: new Date(),
  },
];

export const reportsStore: MemoryReport[] = [
  {
    _id: 'report_mem_1',
    userId: 'student_mem_id',
    title: 'Demo Vulnerable Application Scan',
    targetUrl: 'http://demo.testfire.net/bank/login.aspx',
    scanType: 'url',
    summary: {
      totalPages: 4,
      injectionPoints: 3,
      forms: 2,
      headers: 15,
      parameters: 5,
      cookies: 3,
      jsonInputs: 1,
      riskScore: 7.2,
      owaspCoverage: ['A03:2021', 'A01:2021'],
    },
    findings: [
      {
        type: 'Path Traversal',
        location: 'Query parameter: file',
        parameter: 'file',
        severity: 'Critical',
        cvss: 9.1,
        cwe: 'CWE-22',
        owasp: 'A01:2021',
        description: 'The parameter "file" appears to accept path patterns and could be vulnerable to Path Traversal.',
        recommendation: 'Verify resolved path prefix directory matching uploads folder.',
      },
    ],
    techStack: ['ASP.NET', 'IIS Server'],
    createdAt: new Date(),
  },
];
