import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import User from '../models/User';
import { authenticate, AuthRequest } from '../middleware/auth';
import { usersStore } from '../utils/memoryDb';
import bcrypt from 'bcryptjs';

const router = Router();

const generateTokens = (userId: string, role: string) => {
  const accessToken = jwt.sign(
    { userId, role },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: process.env.JWT_EXPIRES_IN || '15m' } as jwt.SignOptions
  );
  const refreshToken = jwt.sign(
    { userId, role },
    process.env.JWT_REFRESH_SECRET || 'refresh_secret',
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' } as jwt.SignOptions
  );
  return { accessToken, refreshToken };
};

// POST /api/auth/register
router.post(
  '/register',
  [
    body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 chars'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  ],
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { username, email, password } = req.body;

    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const existing = usersStore.find((u) => u.email === email || u.username === username);
      if (existing) {
        res.status(409).json({ error: 'Username or email already in use' });
        return;
      }

      const newUser = {
        _id: 'user_mem_' + Math.random().toString(36).substring(2, 9),
        username,
        email,
        passwordHash: bcrypt.hashSync(password, 12),
        role: 'student' as const,
        progress: [],
        achievements: [],
        notes: [],
        createdAt: new Date(),
      };
      usersStore.push(newUser);

      const { accessToken, refreshToken } = generateTokens(newUser._id, newUser.role);

      res.status(201).json({
        message: 'Account created successfully (Memory DB Mode)',
        accessToken,
        refreshToken,
        user: { id: newUser._id, username: newUser.username, email: newUser.email, role: newUser.role },
      });
      return;
    }

    try {
      const existing = await User.findOne({ $or: [{ email }, { username }] });
      if (existing) {
        res.status(409).json({ error: 'Username or email already in use' });
        return;
      }

      const user = new User({ username, email, passwordHash: password });
      await user.save();

      const { accessToken, refreshToken } = generateTokens(user._id.toString(), user.role);

      res.status(201).json({
        message: 'Account created successfully',
        accessToken,
        refreshToken,
        user: { id: user._id, username: user.username, email: user.email, role: user.role },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// POST /api/auth/login
router.post(
  '/login',
  [
    body('email').trim().notEmpty().withMessage('Username or Email is required'),
    body('password').notEmpty(),
  ],
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { email, password } = req.body;

    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const user = usersStore.find((u) => u.email === email || u.username === email);
      if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const { accessToken, refreshToken } = generateTokens(user._id, user.role);

      res.json({
        accessToken,
        refreshToken,
        user: { id: user._id, username: user.username, email: user.email, role: user.role },
      });
      return;
    }

    try {
      const user = await User.findOne({ $or: [{ email }, { username: email }] });
      if (!user || !(await user.comparePassword(password))) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const { accessToken, refreshToken } = generateTokens(user._id.toString(), user.role);

      res.json({
        accessToken,
        refreshToken,
        user: { id: user._id, username: user.username, email: user.email, role: user.role },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// POST /api/auth/refresh
router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    res.status(400).json({ error: 'Refresh token required' });
    return;
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || 'refresh_secret') as {
      userId: string;
      role: string;
    };
    const { accessToken, refreshToken: newRefresh } = generateTokens(decoded.userId, decoded.role);
    res.json({ accessToken, refreshToken: newRefresh });
  } catch {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// GET /api/auth/me
router.get('/me', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const user = usersStore.find((u) => u._id === req.userId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      const { passwordHash, ...safeUser } = user;
      res.json({ user: safeUser });
      return;
    }

    const user = await User.findById(req.userId).select('-passwordHash');
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.json({ user });
  } catch {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

export default router;
