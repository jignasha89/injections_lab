import { Router, Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import Report from '../models/Report';
import { reportsStore } from '../utils/memoryDb';

const router = Router();

// GET /api/reports
router.get('/', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const view = req.query.view as string;

    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      let userReports = reportsStore.filter((r) => r.userId === req.userId);
      if (view === 'reports') {
        userReports = userReports.filter((r) => !r.isHiddenFromReports);
      } else if (view === 'history') {
        userReports = userReports.filter((r) => !r.isHiddenFromHistory);
      }
      const safeReports = userReports.map(({ findings, ...rest }) => rest);
      res.json({ reports: safeReports });
      return;
    }

    const query: any = { userId: req.userId };
    if (view === 'reports') {
      query.isHiddenFromReports = { $ne: true };
    } else if (view === 'history') {
      query.isHiddenFromHistory = { $ne: true };
    }

    const reports = await Report.find(query)
      .select('-findings')
      .sort({ createdAt: -1 })
      .limit(50);
    res.json({ reports });
  } catch {
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// POST /api/reports/generate
router.post('/generate', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { title, targetUrl, scanType, labSlug, summary, findings, techStack } = req.body;

    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const report = {
        _id: 'report_mem_' + Math.random().toString(36).substring(2, 9),
        userId: req.userId || 'student_mem_id',
        title,
        targetUrl,
        scanType,
        labSlug,
        summary,
        findings,
        techStack,
        createdAt: new Date(),
      };
      reportsStore.push(report);
      res.status(201).json({ report });
      return;
    }

    const report = new Report({
      userId: req.userId,
      title,
      targetUrl,
      scanType,
      labSlug,
      summary,
      findings,
      techStack,
    });
    await report.save();
    res.status(201).json({ report });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// GET /api/reports/:id
router.get('/:id', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const report = reportsStore.find((r) => r._id === req.params.id && r.userId === req.userId);
      if (!report) {
        res.status(404).json({ error: 'Report not found' });
        return;
      }
      res.json({ report });
      return;
    }

    const report = await Report.findOne({ _id: req.params.id, userId: req.userId });
    if (!report) {
      res.status(404).json({ error: 'Report not found' });
      return;
    }
    res.json({ report });
  } catch {
    res.status(500).json({ error: 'Failed to fetch report' });
  }
});

// DELETE /api/reports/:id
router.delete('/:id', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const view = req.query.view as string;

    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const index = reportsStore.findIndex((r) => r._id === req.params.id && r.userId === req.userId);
      if (index === -1) {
        res.status(404).json({ error: 'Report not found' });
        return;
      }
      
      const report = reportsStore[index];
      if (view === 'reports') report.isHiddenFromReports = true;
      else if (view === 'history') report.isHiddenFromHistory = true;
      else {
        report.isHiddenFromReports = true;
        report.isHiddenFromHistory = true;
      }

      if (report.isHiddenFromReports && report.isHiddenFromHistory) {
        reportsStore.splice(index, 1);
      }
      res.json({ message: 'Report deleted' });
      return;
    }

    const report = await Report.findOne({ _id: req.params.id, userId: req.userId });
    if (!report) {
      res.status(404).json({ error: 'Report not found' });
      return;
    }

    if (view === 'reports') report.isHiddenFromReports = true;
    else if (view === 'history') report.isHiddenFromHistory = true;
    else {
      report.isHiddenFromReports = true;
      report.isHiddenFromHistory = true;
    }

    if (report.isHiddenFromReports && report.isHiddenFromHistory) {
      await Report.findByIdAndDelete(report._id);
    } else {
      await report.save();
    }
    res.json({ message: 'Report deleted' });
  } catch {
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

export default router;
