import { Router, Request, Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import { analyzeUrl } from '../services/scannerService';
import { startActiveScan, getScanResults, stopActiveScan } from '../services/activeScannerService';

const router = Router();

function allowedHosts(): Set<string> {
  return new Set(
    (process.env.SCAN_ALLOWED_HOSTS || 'localhost,127.0.0.1,::1')
      .split(',')
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean),
  );
}

function isAuthorizedTarget(rawUrl: string): boolean {
  try {
    const u = new URL(rawUrl);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const hosts = allowedHosts();
    if (hosts.has('*')) return true;
    const host = u.hostname.toLowerCase();
    return hosts.has(host) || hosts.has(u.host.toLowerCase());
  } catch {
    return false;
  }
}

// POST /api/scanner/analyze
// Active, evidence-first assessment for explicitly allowlisted lab targets.
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

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    res.status(400).json({ error: 'Invalid URL format' });
    return;
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    res.status(400).json({ error: 'Only HTTP(S) targets are supported' });
    return;
  }

  // This is the second, server-side gate. A UI checkbox alone can never
  // authorize an active assessment.
  if (!isAuthorizedTarget(url)) {
    res.status(403).json({
      error: 'Target is not allowlisted for active assessment.',
      message: 'Add the exact lab hostname to SCAN_ALLOWED_HOSTS before scanning.',
    });
    return;
  }

  try {
    const scanId = await startActiveScan(url);
    res.json({ scanId, targetUrl: url });
  } catch (err) {
    console.error('Scanner error:', err);
    res.status(500).json({
      error: err instanceof Error ? `Analysis failed: ${err.message}` : 'Analysis failed',
      message: err instanceof Error ? err.message : 'Unknown scanner error',
    });
  }
});

// GET /api/scanner/results/:scanId
router.get('/results/:scanId', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { scanId } = req.params;
  const url = req.query.url as string;

  if (!scanId || !url) {
    res.status(400).json({ error: 'Valid scanId and url required' });
    return;
  }

  try {
    const result = await getScanResults(scanId, url);
    res.json({
      disclaimer: 'Active-verified mode. Only explicitly allowlisted targets may be assessed. Verification uses non-destructive canary probes and response evidence.',
      ...result,
    });
  } catch (err) {
    console.error('Scanner error:', err);
    res.status(500).json({
      error: err instanceof Error ? `Analysis failed: ${err.message}` : 'Analysis failed',
      message: err instanceof Error ? err.message : 'Unknown scanner error',
    });
  }
});

// Explicit passive endpoint retained for compatibility/testing.
router.post('/analyze/passive', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Valid URL required' });
    return;
  }
  try {
    new URL(url);
    res.json({
      disclaimer: 'Passive analysis only. No target requests were made.',
      ...analyzeUrl(url),
    });
  } catch {
    res.status(400).json({ error: 'Invalid URL format' });
  }
});

// Scan control routes — only Stop is supported
router.post('/:scanId/stop', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    await stopActiveScan(req.params.scanId);
    res.json({ message: 'Scan stopped' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
