import { Router, Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import { labsData } from '../data/labsData';

const router = Router();

// GET /api/labs - list all labs
router.get('/', (_req, res: Response) => {
  const list = labsData.map(({ slug, title, category, severity, cvss, cwe, owasp, shortDescription, tags }) => ({
    slug, title, category, severity, cvss, cwe, owasp, shortDescription, tags,
  }));
  res.json({ labs: list });
});

// GET /api/labs/:slug - get full lab data
router.get('/:slug', (req, res: Response) => {
  const lab = labsData.find((l) => l.slug === req.params.slug);
  if (!lab) {
    res.status(404).json({ error: 'Lab not found' });
    return;
  }
  res.json({ lab });
});

// POST /api/labs/:slug/quiz/submit
router.post('/:slug/quiz/submit', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  const { answers } = req.body;
  const lab = labsData.find((l) => l.slug === req.params.slug);
  if (!lab) {
    res.status(404).json({ error: 'Lab not found' });
    return;
  }

  let score = 0;
  const results = lab.quiz.map((q, i) => {
    const correct = q.correctIndex === answers[i];
    if (correct) score++;
    return { questionIndex: i, correct, correctIndex: q.correctIndex };
  });

  const percentage = Math.round((score / lab.quiz.length) * 100);

  res.json({ score, total: lab.quiz.length, percentage, results });
});

export default router;
