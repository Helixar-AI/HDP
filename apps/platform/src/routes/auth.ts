import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { store } from '../store';
import { AuthRequest, generateToken, requireAuth } from '../middleware/auth';

const router = Router();

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password required' });
    return;
  }

  const user = Array.from(store.users.values()).find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  const token = generateToken(user.id, user.orgId);
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 86400000 });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

/**
 * PUT /api/auth/password
 * BUG FIX: Was returning 403 because the route used a stale permission
 * check. Now uses requireAuth which properly validates the JWT.
 */
router.put('/password', requireAuth, (req: AuthRequest, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    res.status(400).json({ error: 'Current and new password required' });
    return;
  }

  if (newPassword.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters' });
    return;
  }

  const user = store.users.get(req.userId!);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  if (!bcrypt.compareSync(currentPassword, user.passwordHash)) {
    res.status(400).json({ error: 'Current password is incorrect' });
    return;
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  store.users.set(user.id, user);
  res.json({ message: 'Password updated successfully' });
});

router.get('/me', requireAuth, (req: AuthRequest, res) => {
  const user = store.users.get(req.userId!);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role, orgId: user.orgId });
});

export default router;
