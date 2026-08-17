import { Router, Response } from 'express';
import { optionalAuthenticate, AuthRequest } from '../middleware/auth';
import { analyzeUrl } from '../services/scannerService';
import { validateAndInitTarget, ScanScopeConfig } from '../services/targetScopeService';
import { runActiveScan, ActiveScanConfig } from '../services/activeScannerService';

const router = Router();

// POST /api/scanner/analyze
// Performs structured heuristic analysis within authorized scope (safe for all URLs)
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
      scanMode: 'Heuristic',
      ...result,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// POST /api/scanner/active
// Performs active differential testing against localhost / self-hosted educational targets (DVWA, Juice Shop, etc.)
router.post('/active', optionalAuthenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { url, authorized, config } = req.body as {
    url: string;
    authorized: boolean;
    config?: ActiveScanConfig;
  };

  if (!authorized) {
    res.status(400).json({
      error: 'Authorization confirmation required.',
      message: 'You must confirm authorized ownership or permission before scanning.',
    });
    return;
  }

  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Valid URL required' });
    return;
  }

  try {
    const result = await runActiveScan(url, config);
    res.json({
      disclaimer: 'Active differential test completed on authorized local sandbox target.',
      scanMode: 'Active Differential Probe',
      ...result,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Active scan execution failed';
    res.status(400).json({ error: message });
  }
});

// POST /api/scanner/scan
// Performs live website crawl, HTML form/script parsing, header audit, and safe differential testing
router.post('/scan', optionalAuthenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { url, authorized, scanMode, config } = req.body;
  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Target URL is required.' });
    return;
  }
  if (!authorized) {
    res.status(400).json({ error: 'Authorization confirmation required.' });
    return;
  }
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  try {
    const { executeLiveScan } = await import('../services/liveScannerService');
    const result = await executeLiveScan(url, authorized, { ...(config || {}), scanMode }, clientIp);
    res.json({
      disclaimer: 'Live scan completed for authorized educational testing.',
      ...result,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    res.status(400).json({ error: message });
  }
});

export default router;

