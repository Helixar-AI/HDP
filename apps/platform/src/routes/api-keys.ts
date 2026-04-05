import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import crypto from 'crypto';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

router.get('/', (req: AuthRequest, res) => {
  const keys = Array.from(store.apiKeys.values())
    .filter(k => k.orgId === req.orgId)
    .map(k => ({ ...k, keyHash: undefined }));
  res.json(keys);
});

/**
 * POST /api/api-keys
 * NOTE: Principal selection is now optional since principals can be
 * created via POST /api/principals (which was previously missing).
 */
router.post('/', (req: AuthRequest, res) => {
  const { name, principalId } = req.body;
  if (!name) {
    res.status(400).json({ error: 'API key name is required' });
    return;
  }

  const rawKey = `hdp_${crypto.randomBytes(32).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.slice(0, 11) + '...';

  const apiKey = {
    id: uuid(),
    name,
    keyHash,
    keyPrefix,
    principalId: principalId || '',
    orgId: req.orgId!,
    lastUsed: null,
    createdAt: new Date().toISOString(),
  };

  store.apiKeys.set(apiKey.id, apiKey);
  // Return the raw key only on creation — it's never shown again
  res.status(201).json({ ...apiKey, key: rawKey, keyHash: undefined });
});

router.delete('/:id', (req: AuthRequest, res) => {
  const key = store.apiKeys.get(req.params.id);
  if (!key || key.orgId !== req.orgId) {
    res.status(404).json({ error: 'API key not found' });
    return;
  }
  store.apiKeys.delete(key.id);
  res.status(204).send();
});

export default router;
