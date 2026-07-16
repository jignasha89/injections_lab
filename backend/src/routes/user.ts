import { Router, Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import User from '../models/User';
import { usersStore } from '../utils/memoryDb';

const router = Router();

// GET /api/user/progress
router.get('/progress', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const user = usersStore.find((u) => u._id === req.userId);
      res.json({ progress: user?.progress || [], achievements: user?.achievements || [] });
      return;
    }

    const user = await User.findById(req.userId).select('progress achievements');
    res.json({ progress: user?.progress || [], achievements: user?.achievements || [] });
  } catch {
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// PUT /api/user/progress/:labSlug
router.put('/progress/:labSlug', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { completed, quizScore, bookmarked } = req.body;
  try {
    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const user = usersStore.find((u) => u._id === req.userId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const existing = user.progress.find((p) => p.labSlug === req.params.labSlug);
      if (existing) {
        if (completed !== undefined) existing.completed = completed;
        if (quizScore !== undefined) existing.quizScore = Math.max(existing.quizScore, quizScore);
        if (bookmarked !== undefined) existing.bookmarked = bookmarked;
        if (completed) existing.completedAt = new Date();
      } else {
        user.progress.push({
          labSlug: req.params.labSlug,
          completed: completed || false,
          quizScore: quizScore || 0,
          bookmarked: bookmarked || false,
          completedAt: completed ? new Date() : undefined,
        });
      }

      // Auto-award achievements
      const completedCount = user.progress.filter((p) => p.completed).length;
      const achievements = user.achievements.map((a) => a.id);
      if (completedCount >= 1 && !achievements.includes('first_lab')) {
        user.achievements.push({ id: 'first_lab', earnedAt: new Date() });
      }
      if (completedCount >= 5 && !achievements.includes('five_labs')) {
        user.achievements.push({ id: 'five_labs', earnedAt: new Date() });
      }
      if (completedCount >= 13 && !achievements.includes('all_labs')) {
        user.achievements.push({ id: 'all_labs', earnedAt: new Date() });
      }

      res.json({ progress: user.progress, achievements: user.achievements });
      return;
    }

    const user = await User.findById(req.userId);
    if (!user) { res.status(404).json({ error: 'User not found' }); return; }

    const existing = user.progress.find((p) => p.labSlug === req.params.labSlug);
    if (existing) {
      if (completed !== undefined) existing.completed = completed;
      if (quizScore !== undefined) existing.quizScore = Math.max(existing.quizScore, quizScore);
      if (bookmarked !== undefined) existing.bookmarked = bookmarked;
      if (completed) existing.completedAt = new Date();
    } else {
      user.progress.push({
        labSlug: req.params.labSlug,
        completed: completed || false,
        quizScore: quizScore || 0,
        bookmarked: bookmarked || false,
        completedAt: completed ? new Date() : undefined,
      });
    }

    // Auto-award achievements
    const completedCount = user.progress.filter((p) => p.completed).length;
    const achievements = user.achievements.map((a) => a.id);
    if (completedCount >= 1 && !achievements.includes('first_lab')) {
      user.achievements.push({ id: 'first_lab', earnedAt: new Date() });
    }
    if (completedCount >= 5 && !achievements.includes('five_labs')) {
      user.achievements.push({ id: 'five_labs', earnedAt: new Date() });
    }
    if (completedCount >= 13 && !achievements.includes('all_labs')) {
      user.achievements.push({ id: 'all_labs', earnedAt: new Date() });
    }

    await user.save();
    res.json({ progress: user.progress, achievements: user.achievements });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update progress' });
  }
});

// GET /api/user/notes
router.get('/notes', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const user = usersStore.find((u) => u._id === req.userId);
      res.json({ notes: user?.notes || [] });
      return;
    }

    const user = await User.findById(req.userId).select('notes');
    res.json({ notes: user?.notes || [] });
  } catch {
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// POST /api/user/notes
router.post('/notes', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { labSlug, content } = req.body;
  try {
    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const user = usersStore.find((u) => u._id === req.userId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const existing = user.notes.find((n) => n.labSlug === labSlug);
      if (existing) {
        existing.content = content;
        existing.updatedAt = new Date();
      } else {
        user.notes.push({ labSlug, content, updatedAt: new Date() });
      }
      res.json({ notes: user.notes });
      return;
    }

    const user = await User.findById(req.userId);
    if (!user) { res.status(404).json({ error: 'User not found' }); return; }

    const existing = user.notes.find((n) => n.labSlug === labSlug);
    if (existing) {
      existing.content = content;
      existing.updatedAt = new Date();
    } else {
      user.notes.push({ labSlug, content, updatedAt: new Date() });
    }
    await user.save();
    res.json({ notes: user.notes });
  } catch {
    res.status(500).json({ error: 'Failed to save note' });
  }
});

export default router;
