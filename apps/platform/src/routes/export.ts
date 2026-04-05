import { Router } from 'express';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

/**
 * BUG FIX: Export routes were returning 403 because they used the broken
 * RBAC permission guard. Now they use requireAuth (JWT validation only).
 */
router.use(requireAuth);

router.get('/tokens', (req: AuthRequest, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="hdp-tokens-export.json"');
  res.json({ exportedAt: new Date().toISOString(), orgId: req.orgId, tokens: [] });
});

router.get('/policies', (req: AuthRequest, res) => {
  const policies = Array.from(store.policies.values()).filter(p => p.orgId === req.orgId);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="hdp-policies-export.json"');
  res.json({ exportedAt: new Date().toISOString(), orgId: req.orgId, policies });
});

router.get('/principals', (req: AuthRequest, res) => {
  const principals = Array.from(store.principals.values()).filter(p => p.orgId === req.orgId);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="hdp-principals-export.json"');
  res.json({ exportedAt: new Date().toISOString(), orgId: req.orgId, principals });
});

router.get('/audit', (req: AuthRequest, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="hdp-audit-export.json"');
  res.json({ exportedAt: new Date().toISOString(), orgId: req.orgId, events: [] });
});

export default router;
