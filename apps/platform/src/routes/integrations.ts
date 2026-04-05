import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

router.get('/siem', (req: AuthRequest, res) => {
  const config = Array.from(store.siemConfigs.values()).find(c => c.orgId === req.orgId);
  if (!config) {
    res.json({ endpoint: '', format: 'json', enabled: false });
    return;
  }
  res.json(config);
});

/**
 * PUT /api/integrations/siem
 * BUG FIX: This endpoint was missing entirely. The SIEM integration page
 * let users enter an endpoint URL but had no save button because there
 * was no backend route to persist the configuration.
 */
router.put('/siem', (req: AuthRequest, res) => {
  const { endpoint, format, enabled } = req.body;

  if (!endpoint) {
    res.status(400).json({ error: 'SIEM endpoint URL is required' });
    return;
  }

  const existing = Array.from(store.siemConfigs.values()).find(c => c.orgId === req.orgId);
  const config = {
    id: existing?.id || uuid(),
    endpoint,
    format: format || 'json',
    enabled: enabled ?? true,
    orgId: req.orgId!,
    updatedAt: new Date().toISOString(),
  };

  store.siemConfigs.set(config.id, config);
  res.json(config);
});

router.delete('/siem', (req: AuthRequest, res) => {
  const config = Array.from(store.siemConfigs.values()).find(c => c.orgId === req.orgId);
  if (config) {
    store.siemConfigs.delete(config.id);
  }
  res.status(204).send();
});

export default router;
