import { Router } from 'express';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/dashboard/stats
 * BUG FIX: Dashboard tiles showed empty/blank instead of 0 when there
 * were no requests. The store.getDashboardStats() now always returns
 * numeric 0 values, never null/undefined.
 */
router.get('/stats', (req: AuthRequest, res) => {
  const stats = store.getDashboardStats(req.orgId!);
  res.json(stats);
});

router.get('/activity', (req: AuthRequest, res) => {
  res.json({ events: [] });
});

export default router;
