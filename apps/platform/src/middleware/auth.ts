import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { store } from '../store';

const JWT_SECRET = process.env.JWT_SECRET || 'hdp-platform-dev-secret';

export interface AuthRequest extends Request {
  userId?: string;
  orgId?: string;
}

export function generateToken(userId: string, orgId: string): string {
  return jwt.sign({ userId, orgId }, JWT_SECRET, { expiresIn: '24h' });
}

/**
 * Auth middleware — validates JWT and attaches userId + orgId to req.
 *
 * BUG FIX: The previous implementation returned 403 for all authenticated
 * users because it checked a stale RBAC permission map that was never
 * populated after login. Now it simply validates the JWT and confirms
 * the user exists — route-level guards handle specific permission checks.
 */
export function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  const cookieToken = req.cookies?.token;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : cookieToken;

  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; orgId: string };
    const user = store.users.get(decoded.userId);

    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    req.userId = decoded.userId;
    req.orgId = decoded.orgId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction): void {
  if (!req.userId) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const user = store.users.get(req.userId);
  if (!user || user.role !== 'admin') {
    res.status(403).json({ error: 'Admin access required' });
    return;
  }

  next();
}
