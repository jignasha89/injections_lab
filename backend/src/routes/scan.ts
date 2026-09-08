import { Router, Response } from 'express';
import { optionalAuthenticate, AuthRequest } from '../middleware/auth';
import { executeLiveScan, LiveScanConfig } from '../services/liveScannerService';

const router = Router();

/**
 * POST /api/scan
 * Deep Live Website Scanner endpoint.
 * Fetches target website, parses forms/scripts, evaluates security headers,
 * and performs safe differential injection testing in active mode.
 */
router.post('/', optionalAuthenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { url, authorized, scanMode, config } = req.body as {
    url?: string;
    authorized?: boolean;
    scanMode?: 'passive' | 'active';
    config?: LiveScanConfig;
  };

  console.log(`[SCAN_DIAGNOSTIC] [API_RECV] Received POST /api/scan request for URL: "${url}", authorized=${authorized}, scanMode=${scanMode || 'default'}`);

  // 1. Validate Input Parameters
  if (!url || typeof url !== 'string') {
    console.error('[SCAN_DIAGNOSTIC] [API_REJECT] Missing or invalid url in request body.');
    res.status(400).json({
      error: 'Target URL is required and must be a valid string.',
      field: 'url',
    });
    return;
  }

  // 2. Validate Ownership / Permission Confirmation
  if (!authorized) {
    console.error('[SCAN_DIAGNOSTIC] [API_REJECT] Authorization confirmation is false.');
    res.status(400).json({
      error: 'Authorization confirmation required.',
      message: 'You must confirm that you own or have explicit permission to test this target before scanning.',
      field: 'authorized',
    });
    return;
  }

  // 3. Extract Client IP for Audit Trail
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  try {
    const scanConfig: LiveScanConfig = {
      ...(config || {}),
      scanMode: scanMode || config?.scanMode,
    };

    console.log(`[SCAN_DIAGNOSTIC] [EXEC_START] Dispatching executeLiveScan for target "${url}"...`);
    const result = await executeLiveScan(url, authorized, scanConfig, clientIp);
    console.log(`[SCAN_DIAGNOSTIC] [EXEC_SUCCESS] executeLiveScan completed for target "${url}". Total findings: ${result.findings.length}, Risk score: ${result.summary.riskScore}`);

    res.json({
      disclaimer: 'This live scan is for educational and authorized defensive auditing purposes only.',
      ...result,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Deep scan execution failed';
    console.error(`[SCAN_DIAGNOSTIC] [EXEC_FAIL] Deep scan failed for target "${url}":`, message);
    res.status(400).json({
      error: message,
      targetUrl: url,
    });
  }
});

export default router;
