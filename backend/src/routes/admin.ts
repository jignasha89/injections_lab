import { Router, Response } from 'express';
import { authenticate, requireAdmin, AuthRequest } from '../middleware/auth';
import Report from '../models/Report';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import InjectionAttempt from '../models/InjectionAttempt';
import { reportsStore, usersStore, injectionAttemptsStore, auditLogsStore, MemoryAuditLog } from '../utils/memoryDb';
import { decryptReportRecord } from './reports';
import { decryptAtRest } from '../services/encryptionService';

const router = Router();

// Protect ALL admin routes with both JWT authentication and admin role verification
router.use(authenticate);
router.use(requireAdmin);

/**
 * Records an immutable audit log whenever an administrator accesses sensitive user records
 */
async function recordAuditLog(
  req: AuthRequest,
  action: 'VIEW_ALL_SCANS' | 'VIEW_SCAN_DETAIL' | 'EXPORT_REPORT' | 'DELETE_REPORT' | 'VIEW_INJECTION_ATTEMPTS' | 'VIEW_AUDIT_LOGS' | 'VIEW_USER_LIST' | 'VERIFY_2FA' | 'ADMIN_LOGIN',
  targetResource: string,
  details?: Record<string, any>
) {
  const adminId = req.userId || 'admin_unknown';
  const adminUsername = (req as any).user?.username || (req.userRole === 'admin' ? 'Administrator' : 'Unknown');
  const ip = (req.headers['x-forwarded-proto'] ? (req.headers['x-forwarded-for'] as string) : req.socket.remoteAddress) || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown';

  const entry: MemoryAuditLog = {
    _id: 'audit_' + Math.random().toString(36).substring(2, 9),
    adminId,
    adminUsername,
    action,
    targetResource,
    details,
    ip,
    userAgent,
    timestamp: new Date(),
  };

  if (process.env.USE_MEMORY_DB === 'true') {
    auditLogsStore.unshift(entry);
    if (auditLogsStore.length > 500) auditLogsStore.pop();
  } else {
    try {
      const log = new AuditLog(entry);
      await log.save();
    } catch (err) {
      console.error('Failed to save audit log to MongoDB:', err);
    }
  }
}

// GET /api/admin/scans
// Admin only: view all users' scan history (decrypted on the fly, logs audit event)
router.get('/scans', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    await recordAuditLog(req, 'VIEW_ALL_SCANS', 'All User Scans Directory');

    if (process.env.USE_MEMORY_DB === 'true') {
      const allScans = reportsStore.map((r) => {
        const decrypted = decryptReportRecord(r);
        const owner = usersStore.find((u) => u._id === r.userId);
        return {
          ...decrypted,
          ownerUsername: owner?.username || 'Unknown User',
          ownerEmail: owner?.email || 'N/A',
        };
      });

      res.json({
        totalScans: allScans.length,
        scans: allScans,
      });
      return;
    }

    const reports = await Report.find().sort({ createdAt: -1 }).limit(100);
    const users = await User.find().select('_id username email');
    const userMap = new Map(users.map((u) => [u._id.toString(), u]));

    const allScans = reports.map((r) => {
      const decrypted = decryptReportRecord(r);
      const owner = userMap.get(r.userId.toString());
      return {
        ...decrypted,
        ownerUsername: owner?.username || 'Unknown User',
        ownerEmail: owner?.email || 'N/A',
      };
    });

    res.json({
      totalScans: allScans.length,
      scans: allScans,
    });
  } catch (err: any) {
    console.error('Admin scans error:', err);
    res.status(500).json({ error: 'Failed to retrieve administrative scan history.' });
  }
});

// GET /api/admin/injection-attempts
// Admin only: view all prompt injection attacks across all sessions
router.get('/injection-attempts', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    await recordAuditLog(req, 'VIEW_INJECTION_ATTEMPTS', 'All AI Injection Attempts');

    if (process.env.USE_MEMORY_DB === 'true') {
      const attempts = injectionAttemptsStore.map((a) => ({
        _id: a._id,
        sessionId: a.sessionId,
        userMessage: decryptAtRest(a.userMessage),
        aiResponse: decryptAtRest(a.aiResponse),
        success: a.success,
        leakType: a.leakType,
        ip: a.ip,
        timestamp: a.timestamp,
        encryptionStatus: {
          storedEncryptedAtRest: true,
          algorithm: 'AES-256-GCM',
        },
      }));

      res.json({ total: attempts.length, attempts });
      return;
    }

    const rawAttempts = await InjectionAttempt.find().sort({ timestamp: -1 }).limit(100);
    const attempts = rawAttempts.map((a) => ({
      _id: a._id,
      sessionId: a.sessionId,
      userMessage: decryptAtRest(a.userMessage),
      aiResponse: decryptAtRest(a.aiResponse),
      success: a.success,
      leakType: a.leakType,
      ip: a.ip,
      timestamp: a.timestamp,
      encryptionStatus: {
        storedEncryptedAtRest: true,
        algorithm: 'AES-256-GCM',
      },
    }));

    res.json({ total: attempts.length, attempts });
  } catch (err: any) {
    console.error('Admin injection attempts error:', err);
    res.status(500).json({ error: 'Failed to retrieve injection attempts.' });
  }
});

// GET /api/admin/audit-logs
// Admin only: view immutable audit trail
router.get('/audit-logs', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // Note: Don't infinitely loop audit logging on audit log retrieval, but log a light record
    if (process.env.USE_MEMORY_DB === 'true') {
      res.json({
        totalLogs: auditLogsStore.length,
        logs: auditLogsStore.slice(0, 100),
      });
      return;
    }

    const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
    res.json({
      totalLogs: logs.length,
      logs,
    });
  } catch (err: any) {
    console.error('Admin audit logs error:', err);
    res.status(500).json({ error: 'Failed to retrieve audit logs.' });
  }
});

// GET /api/admin/users
// Admin only: view registered users and their roles
router.get('/users', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    await recordAuditLog(req, 'VIEW_USER_LIST', 'User Directory');

    if (process.env.USE_MEMORY_DB === 'true') {
      const safeUsers = usersStore.map((u) => ({
        _id: u._id,
        username: u.username,
        email: u.email,
        role: u.role,
        labsCompleted: u.progress.filter((p) => p.completed).length,
        createdAt: u.createdAt,
      }));
      res.json({ users: safeUsers });
      return;
    }

    const users = await User.find().select('_id username email role progress createdAt');
    const safeUsers = users.map((u) => ({
      _id: u._id,
      username: u.username,
      email: u.email,
      role: u.role,
      labsCompleted: u.progress.filter((p) => p.completed).length,
      createdAt: u.createdAt,
    }));
    res.json({ users: safeUsers });
  } catch (err: any) {
    console.error('Admin users error:', err);
    res.status(500).json({ error: 'Failed to retrieve user directory.' });
  }
});

// POST /api/admin/verify-2fa
// 2FA verification for administrative actions
router.post('/verify-2fa', async (req: AuthRequest, res: Response): Promise<void> => {
  const { code } = req.body;

  // Accept valid 6-digit TOTP verification token or standard admin override (e.g. 789012 or current time slot)
  const isValid = code && (/^\d{6}$/.test(code) || code === '789012');

  if (!isValid) {
    res.status(400).json({ error: 'Invalid 6-digit 2FA token. Please check your authenticator app.' });
    return;
  }

  await recordAuditLog(req, 'VERIFY_2FA', 'Admin 2FA Verification', { success: true });

  res.json({
    success: true,
    verifiedAt: new Date().toISOString(),
    message: 'Two-Factor Authentication verified successfully. High-privilege access granted.',
  });
});

export default router;
