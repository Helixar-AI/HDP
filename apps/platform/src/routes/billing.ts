import { Router } from 'express';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/billing/plans
 * BUG FIX: Was returning an empty array because the plans data was
 * never seeded. Plans are now defined in the store and always returned.
 */
router.get('/plans', (req: AuthRequest, res) => {
  const plans = store.getPlans();
  const currentPlan = store.getOrgPlan(req.orgId!);

  const plansWithCurrent = plans.map(p => ({
    ...p,
    current: p.id === currentPlan?.id,
  }));

  res.json(plansWithCurrent);
});

router.get('/current', (req: AuthRequest, res) => {
  const plan = store.getOrgPlan(req.orgId!);
  if (!plan) {
    res.status(404).json({ error: 'No plan found' });
    return;
  }
  res.json({ ...plan, current: true });
});

router.post('/subscribe', (req: AuthRequest, res) => {
  const { planId } = req.body;
  const plans = store.getPlans();
  const plan = plans.find(p => p.id === planId);

  if (!plan) {
    res.status(400).json({ error: 'Invalid plan' });
    return;
  }

  store.orgPlans.set(req.orgId!, planId);
  res.json({ message: `Subscribed to ${plan.name} plan`, plan: { ...plan, current: true } });
});

export default router;
