import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';

import authRoutes from './routes/auth';
import labRoutes from './routes/labs';
import scannerRoutes from './routes/scanner';
import reportRoutes from './routes/reports';
import userRoutes from './routes/user';
import chatRoutes from './routes/chat';
import securityRoutes from './routes/security';
import adminRoutes from './routes/admin';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/injectionlab';

// HTTPS Enforcement Middleware (for production deployments)
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === 'production' &&
    req.headers['x-forwarded-proto'] &&
    req.headers['x-forwarded-proto'] !== 'https'
  ) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// Comprehensive Security Headers via Helmet
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
        connectSrc: ["'self'", 'http:', 'https:', 'ws:', 'wss:'],
        fontSrc: ["'self'", 'data:', 'https:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', limiter);

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/labs', labRoutes);
app.use('/api/scanner', scannerRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/user', userRoutes);
app.use('/api/chat', chatRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/admin', adminRoutes);

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    message: 'InjectionLab API is running',
    timestamp: new Date().toISOString(),
    disclaimer: 'This platform is for authorized educational use only.',
  });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

let pythonEngine: ChildProcess | null = null;
function startPythonEngine() {
  const engineDir = path.join(__dirname, '..', 'python_engine');
  console.log(`🐍 Starting Python Scanner Engine from ${engineDir}...`);
  
  const pythonCmd = process.platform === 'win32' 
    ? path.join(engineDir, 'venv', 'Scripts', 'python.exe')
    : path.join(engineDir, 'venv', 'bin', 'python');
  pythonEngine = spawn(pythonCmd, ['-m', 'uvicorn', 'backend.main:socket_app', '--port', '8000'], {
    cwd: engineDir,
    stdio: 'pipe',
  });
  
  pythonEngine.stdout?.on('data', (data) => console.log(`[Python] ${data.toString().trim()}`));
  pythonEngine.stderr?.on('data', (data) => console.error(`[Python ERR] ${data.toString().trim()}`));
  
  pythonEngine.on('close', (code) => {
    console.log(`🐍 Python Engine exited with code ${code}`);
  });
}

function cleanup() {
  if (pythonEngine && !pythonEngine.killed) {
    console.log('🐍 Stopping Python Scanner Engine...');
    pythonEngine.kill();
  }
}
process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('SIGTERM', () => { cleanup(); process.exit(0); });
process.on('exit', cleanup);

if (process.env.NODE_ENV !== 'test') {
  startPythonEngine();
  if (process.env.USE_MEMORY_DB === 'true') {
    console.log('ℹ️ Starting in-memory database mode directly.');
    app.listen(PORT, () => {
      console.log(`🚀 InjectionLab API running on port ${PORT} [IN-MEMORY MODE]`);
      console.log(`⚠️  For authorized educational use only.`);
    });
  } else {
    // Connect to MongoDB and start server
    mongoose
      .connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 })
      .then(() => {
        console.log('✅ Connected to MongoDB');
        app.listen(PORT, () => {
          console.log(`🚀 InjectionLab API running on port ${PORT}`);
          console.log(`⚠️  For authorized educational use only.`);
        });
      })
      .catch((err) => {
        console.warn('⚠️ MongoDB connection error. Falling back to IN-MEMORY DATABASE mode.');
        process.env.USE_MEMORY_DB = 'true';
        app.listen(PORT, () => {
          console.log(`🚀 InjectionLab API running on port ${PORT} [IN-MEMORY FALLBACK]`);
          console.log(`⚠️  For authorized educational use only.`);
        });
      });
  }
}

export default app;

