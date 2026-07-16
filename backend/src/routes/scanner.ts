import { Router, Request, Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import { analyzeUrl } from '../services/scannerService';

const router = Router();

// POST /api/scanner/analyze
// Performs HEURISTIC analysis only - no real HTTP requests to user targets
router.post('/analyze', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { url, authorized } = req.body;

  if (!authorized) {
    res.status(403).json({
      error: 'Authorization confirmation required.',
      message: 'You must confirm you are authorized to test this target.',
    });
    return;
  }

  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Valid URL required' });
    return;
  }

  try {
    new URL(url); // Validate URL format
  } catch {
    res.status(400).json({ error: 'Invalid URL format' });
    return;
  }

  try {
    const result = analyzeUrl(url);
    res.json({
      disclaimer: 'This is a heuristic/structural analysis for educational purposes only. No real requests were made to the target.',
      ...result,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

export default router;
