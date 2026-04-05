import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

router.get('/', (req: AuthRequest, res) => {
  const principals = Array.from(store.principals.values()).filter(p => p.orgId === req.orgId);
  res.json(principals);
});

/**
 * POST /api/principals
 * BUG FIX: This endpoint was completely missing. The "Create API Key" form
 * required selecting a principal, but there was no way to create one.
 * Added full CRUD for principals.
 */
router.post('/', (req: AuthRequest, res) => {
  const { name, idType, displayName } = req.body;
  if (!name) {
    res.status(400).json({ error: 'Principal name is required' });
    return;
  }

  const principal = {
    id: uuid(),
    name,
    idType: idType || 'opaque',
    displayName: displayName || name,
    orgId: req.orgId!,
    createdAt: new Date().toISOString(),
  };

  store.principals.set(principal.id, principal);
  res.status(201).json(principal);
});

router.get('/:id', (req: AuthRequest, res) => {
  const principal = store.principals.get(req.params.id);
  if (!principal || principal.orgId !== req.orgId) {
    res.status(404).json({ error: 'Principal not found' });
    return;
  }
  res.json(principal);
});

router.put('/:id', (req: AuthRequest, res) => {
  const principal = store.principals.get(req.params.id);
  if (!principal || principal.orgId !== req.orgId) {
    res.status(404).json({ error: 'Principal not found' });
    return;
  }

  const { name, idType, displayName } = req.body;
  if (name) principal.name = name;
  if (idType) principal.idType = idType;
  if (displayName) principal.displayName = displayName;
  store.principals.set(principal.id, principal);
  res.json(principal);
});

router.delete('/:id', (req: AuthRequest, res) => {
  const principal = store.principals.get(req.params.id);
  if (!principal || principal.orgId !== req.orgId) {
    res.status(404).json({ error: 'Principal not found' });
    return;
  }
  store.principals.delete(principal.id);
  res.status(204).send();
});

export default router;
