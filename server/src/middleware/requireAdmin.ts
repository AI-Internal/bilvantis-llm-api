import type { Request, Response, NextFunction } from 'express';
import type { SessionUser } from '../services/auth.js';

// Gate admin-only surfaces (user management, shared catalog/routing writes).
// Must run AFTER requireAuth, which sets req.user from the validated session.
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const user = (req as Request & { user?: SessionUser }).user;
  if (!user || user.role !== 'admin') {
    res.status(403).json({ error: { message: 'Admin access required', type: 'forbidden' } });
    return;
  }
  next();
}
