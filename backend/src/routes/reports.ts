import { Router, Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import Report from '../models/Report';
import { reportsStore } from '../utils/memoryDb';
import { encryptAtRest, decryptAtRest, verifyHMACIntegrity } from '../services/encryptionService';
import {
  enrichFindingsWithPlainLanguage,
  calculateOverallRiskRating,
  generatePlainLanguageSummary,
} from '../services/plainSummaryService';
import { enrichFindingsWithScreenshots } from '../services/screenshotService';

const router = Router();

/**
 * Helper to decrypt a report on-the-fly for authorized viewer and ensure plain-language summaries
 */
export function decryptReportRecord(rawReport: any): any {
  if (!rawReport) return rawReport;
  const reportObj = typeof rawReport.toObject === 'function' ? rawReport.toObject() : { ...rawReport };

  let targetUrl = reportObj.targetUrl;
  let summary = reportObj.summary || {};
  let findings = reportObj.findings || [];
  let techStack = reportObj.techStack || [];
  let isIntegrityValid = true;

  if (reportObj.encryptedPayload) {
    try {
      isIntegrityValid = verifyHMACIntegrity(reportObj.encryptedPayload);
      const decrypted = decryptAtRest<any>(reportObj.encryptedPayload);
      targetUrl = decrypted.targetUrl || targetUrl;
      summary = decrypted.summary || summary;
      findings = decrypted.findings || findings;
      techStack = decrypted.techStack || techStack;
    } catch (err: any) {
      console.error('Failed to decrypt report at rest:', err.message);
    }
  }

  // Ensure findings and summary have plain-language explanations
  const enrichedFindings = enrichFindingsWithPlainLanguage(findings);
  const riskScore = summary?.riskScore || 0;
  const { rating: overallRiskRating } = calculateOverallRiskRating(riskScore, enrichedFindings);
  const plainSummary = summary?.plainSummary || generatePlainLanguageSummary(targetUrl, enrichedFindings, riskScore);

  const enrichedSummary = {
    ...summary,
    overallRiskRating: summary?.overallRiskRating || overallRiskRating,
    plainSummary,
  };

  return {
    ...reportObj,
    targetUrl,
    summary: enrichedSummary,
    findings: enrichedFindings,
    techStack,
    encryptionStatus: {
      encryptedAtRest: Boolean(reportObj.encryptedPayload),
      algorithm: reportObj.encryptedPayload ? 'AES-256-GCM' : 'PLAINTEXT',
      hmacIntegrity: reportObj.encryptedPayload ? (isIntegrityValid ? 'VALID' : 'FAILED') : 'N/A',
    },
  };
}

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
      
      const decryptedReports = userReports.map((r) => {
        const dec = decryptReportRecord(r);
        const { findings, ...rest } = dec;
        return rest;
      });

      res.json({ reports: decryptedReports });
      return;
    }

    const query: any = { userId: req.userId };
    if (view === 'reports') {
      query.isHiddenFromReports = { $ne: true };
    } else if (view === 'history') {
      query.isHiddenFromHistory = { $ne: true };
    }

    const reports = await Report.find(query)
      .sort({ createdAt: -1 })
      .limit(50);

    const decryptedReports = reports.map((r) => {
      const dec = decryptReportRecord(r);
      const { findings, ...rest } = dec;
      return rest;
    });

    res.json({ reports: decryptedReports });
  } catch {
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// POST /api/reports/generate
router.post('/generate', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { title, targetUrl, scanType, labSlug, summary, findings, techStack } = req.body;
    const rawFindings = findings || [];
    const plainFindings = enrichFindingsWithPlainLanguage(rawFindings);
    const enrichedFindings = await enrichFindingsWithScreenshots(plainFindings, targetUrl);
    const riskScore = summary?.riskScore || 0;
    const { rating: overallRiskRating } = calculateOverallRiskRating(riskScore, enrichedFindings);
    const plainSummary = summary?.plainSummary || generatePlainLanguageSummary(targetUrl, enrichedFindings, riskScore);

    const enrichedSummary = {
      ...(summary || {}),
      totalPages: summary?.totalPages || 1,
      injectionPoints: summary?.injectionPoints || enrichedFindings.length,
      forms: summary?.forms || 0,
      headers: summary?.headers || 0,
      parameters: summary?.parameters || 0,
      cookies: summary?.cookies || 0,
      jsonInputs: summary?.jsonInputs || 0,
      riskScore,
      owaspCoverage: summary?.owaspCoverage || [],
      overallRiskRating,
      plainSummary,
    };

    // Encrypt sensitive scan results before saving to database
    const sensitivePayload = {
      targetUrl,
      summary: enrichedSummary,
      findings: enrichedFindings,
      techStack: techStack || [],
    };
    const encryptedPayload = encryptAtRest(sensitivePayload);

    // In-memory Database Fallback
    if (process.env.USE_MEMORY_DB === 'true') {
      const report = {
        _id: 'report_mem_' + Math.random().toString(36).substring(2, 9),
        userId: req.userId || 'student_mem_id',
        title,
        targetUrl: `[AES-256-GCM ENCRYPTED]`,
        scanType,
        labSlug,
        summary: enrichedSummary,
        findings: [], // Redacted at rest in memory
        techStack: [], // Redacted at rest in memory
        isEncrypted: true,
        encryptedPayload,
        createdAt: new Date(),
      };
      reportsStore.push(report);

      // Return decrypted representation to the authorized client
      res.status(201).json({ report: decryptReportRecord(report) });
      return;
    }

    const report = new Report({
      userId: req.userId,
      title,
      targetUrl: `[AES-256-GCM ENCRYPTED]`,
      scanType,
      labSlug,
      summary: enrichedSummary,
      findings: [], // Redacted at rest in MongoDB
      techStack: [], // Redacted at rest in MongoDB
      isEncrypted: true,
      encryptedPayload,
    });
    await report.save();

    res.status(201).json({ report: decryptReportRecord(report) });
  } catch (err) {
    console.error('Error generating encrypted report:', err);
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
      res.json({ report: decryptReportRecord(report) });
      return;
    }

    const report = await Report.findOne({ _id: req.params.id, userId: req.userId });
    if (!report) {
      res.status(404).json({ error: 'Report not found' });
      return;
    }
    res.json({ report: decryptReportRecord(report) });
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
