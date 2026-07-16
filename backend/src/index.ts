import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

import authRoutes from './routes/auth';
import labRoutes from './routes/labs';
import scannerRoutes from './routes/scanner';
import reportRoutes from './routes/reports';
import userRoutes from './routes/user';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/injectionlab';

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,
}));

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

// Connect to MongoDB and start server
mongoose
  .connect(MONGODB_URI)
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

export default app;
