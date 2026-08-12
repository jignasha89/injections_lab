import { Router, Response } from 'express';
import { optionalAuthenticate, AuthRequest } from '../middleware/auth';
import { analyzeUrl } from '../services/scannerService';
import { validateAndInitTarget, ScanScopeConfig } from '../services/targetScopeService';

const router = Router();

// POST /api/scanner/analyze
// Performs structured analysis within authorized scope
router.post('/analyze', optionalAuthenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { url, authorized, scope } = req.body as { url: string; authorized: boolean; scope?: Partial<ScanScopeConfig> };

  const targetValidation = validateAndInitTarget(url, authorized, scope);

  if (!targetValidation.isAllowed) {
    res.status(400).json({
      error: targetValidation.validationError || 'Invalid target configuration.',
      message: targetValidation.validationError,
    });
    return;
  }

  try {
    const result = analyzeUrl(targetValidation.normalizedUrl);
    res.json({
      disclaimer: 'This is a heuristic/structural analysis for educational purposes only.',
      targetScope: targetValidation.scope,
      normalizedTarget: targetValidation.normalizedUrl,
      ...result,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

export default router;
