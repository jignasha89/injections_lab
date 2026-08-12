import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from '../models/User';
import Report from '../models/Report';
import { labsData } from '../data/labsData';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/injectionlab';

async function seed() {
  try {
    console.log('Connecting to database...');
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');

    // 1. Clear Existing Data
    console.log('Cleaning collection: Users...');
    await User.deleteMany({});
    console.log('Cleaning collection: Reports...');
    await Report.deleteMany({});

    // 2. Create Default Admin/Student Users
    console.log('Creating default users...');
    const admin = new User({
      username: 'admin',
      email: 'admin@injectionlab.local',
      passwordHash: 'admin12345', // pre-save hook hashes this
      role: 'admin',
      progress: [],
      achievements: [
        { id: 'first_lab', earnedAt: new Date() }
      ],
      notes: []
    });

    const student = new User({
      username: 'student',
      email: 'student@injectionlab.local',
      passwordHash: 'student@123', // pre-save hook hashes this
      role: 'student',
      progress: labsData.map((lab, i) => ({
        labSlug: lab.slug,
        completed: i < 3, // Complete first 3 labs for demonstration
        quizScore: i < 3 ? 80 + i * 10 : 0,
        completedAt: i < 3 ? new Date(Date.now() - (3 - i) * 24 * 60 * 60 * 1000) : undefined,
        bookmarked: i === 4
      })),
      achievements: [
        { id: 'first_lab', earnedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000) }
      ],
      notes: [
        {
          labSlug: 'crlf-injection',
          content: 'CRLF injection occurs when Carriage Return (\\r) and Line Feed (\\n) sequences are unchecked in headers.',
          updatedAt: new Date()
        }
      ]
    });

    const demoUser = new User({
      username: 'InjectionLab Demo',
      email: 'open@gmail.com',
      passwordHash: 'open@123', // pre-save hook hashes this
      role: 'student',
      progress: labsData.map((lab, i) => ({
        labSlug: lab.slug,
        completed: i < 5,
        quizScore: i < 5 ? 70 + i * 5 : 0,
        completedAt: i < 5 ? new Date(Date.now() - (5 - i) * 24 * 60 * 60 * 1000) : undefined,
        bookmarked: i === 1 || i === 7,
      })),
      achievements: [
        { id: 'first_lab', earnedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000) }
      ],
      notes: [
        {
          labSlug: 'error-based-sqli',
          content: 'Error-based SQLi: Force the DB to leak versions or tables inside error output.',
          updatedAt: new Date(),
        },
      ],
    });

    await admin.save();
    await student.save();
    await demoUser.save();
    console.log('Users created:');
    console.log('- admin@injectionlab.local / admin12345 (Admin)');
    console.log('- student@injectionlab.local / student@123 (Student)');
    console.log('- open@gmail.com / open@123 (Demo Public)');

    // 3. Create Sample Scan Reports
    console.log('Creating sample scan reports...');
    const report1 = new Report({
      userId: student._id,
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
        owaspCoverage: ['A03:2021', 'A01:2021']
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
          description: 'The parameter "file" appears to accept path patterns and could be vulnerable to Path Traversal, allowing remote attackers to view arbitrary system files.',
          recommendation: 'Verify that the input is properly canonicalized using path.resolve() and starts with the allowed root directory. Better yet, map files to random IDs stored in the database.'
        },
        {
          type: 'CRLF Injection / HTTP Header Injection',
          location: 'Query parameter: q',
          parameter: 'q',
          severity: 'Medium',
          cvss: 6.1,
          cwe: 'CWE-113',
          owasp: 'A03:2021',
          description: 'Search parameter "q" was reflected into the response without removing CR/LF sequences. This may allow attackers to inject custom headers or perform response splitting.',
          recommendation: 'Sanitize the parameter by removing or escaping carriage return (\\r) and line feed (\\n) characters before writing it to headers.'
        }
      ],
      techStack: ['ASP.NET', 'IIS Server', 'Windows Server']
    });

    const report2 = new Report({
      userId: student._id,
      title: 'Built-in Lab Simulation - Log4Shell',
      targetUrl: 'http://localhost:3000/labs/log4shell',
      scanType: 'demo',
      labSlug: 'log4shell',
      summary: {
        totalPages: 1,
        injectionPoints: 1,
        forms: 1,
        headers: 8,
        parameters: 2,
        cookies: 1,
        jsonInputs: 1,
        riskScore: 10.0,
        owaspCoverage: ['A03:2021']
      },
      findings: [
        {
          type: 'Log4Shell (CVE-2021-44228)',
          location: 'HTTP Header: User-Agent',
          parameter: 'User-Agent',
          severity: 'Critical',
          cvss: 10.0,
          cwe: 'CWE-917',
          owasp: 'A03:2021',
          description: 'An educational simulation of the critical Log4Shell vulnerability in Apache Log4j. User input logged without sanitization triggers Remote Code Execution.',
          recommendation: 'Update Apache Log4j to 2.17.1+. Apply formatMsgNoLookups JVM option as immediate mitigation. Ensure outbound firewall blocks port 389/1099 from the server.'
        }
      ],
      techStack: ['Java', 'Spring Boot', 'Apache Log4j']
    });

    await report1.save();
    await report2.save();
    console.log('Sample reports created successfully');

    console.log('Database seeding completed successfully! 🎉');
    process.exit(0);
  } catch (error) {
    console.error('Database seeding failed:', error);
    process.exit(1);
  }
}

seed();
