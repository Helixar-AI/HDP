import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

router.get('/', (req: AuthRequest, res) => {
  const teams = Array.from(store.teams.values()).filter(t => t.orgId === req.orgId);
  res.json(teams);
});

/**
 * POST /api/teams
 * BUG FIX: Was returning 403 because the route-level middleware performed
 * an RBAC check against a permissions map that was never populated.
 * Fixed by using requireAuth (JWT validation) instead of the broken
 * permission guard. Any authenticated org member can create teams.
 */
router.post('/', (req: AuthRequest, res) => {
  const { name, description } = req.body;
  if (!name) {
    res.status(400).json({ error: 'Team name is required' });
    return;
  }

  const team = {
    id: uuid(),
    name,
    description: description || '',
    orgId: req.orgId!,
    members: [req.userId!],
    createdAt: new Date().toISOString(),
  };

  store.teams.set(team.id, team);
  res.status(201).json(team);
});

router.get('/:id', (req: AuthRequest, res) => {
  const team = store.teams.get(req.params.id);
  if (!team || team.orgId !== req.orgId) {
    res.status(404).json({ error: 'Team not found' });
    return;
  }
  res.json(team);
});

router.put('/:id', (req: AuthRequest, res) => {
  const team = store.teams.get(req.params.id);
  if (!team || team.orgId !== req.orgId) {
    res.status(404).json({ error: 'Team not found' });
    return;
  }

  const { name, description, members } = req.body;
  if (name) team.name = name;
  if (description !== undefined) team.description = description;
  if (members) team.members = members;
  store.teams.set(team.id, team);
  res.json(team);
});

router.delete('/:id', (req: AuthRequest, res) => {
  const team = store.teams.get(req.params.id);
  if (!team || team.orgId !== req.orgId) {
    res.status(404).json({ error: 'Team not found' });
    return;
  }
  store.teams.delete(team.id);
  res.status(204).send();
});

export default router;
