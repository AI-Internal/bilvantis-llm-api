import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import type { SessionUser } from '../services/auth.js';
import {
  listUsers,
  getUser,
  createUser,
  deleteUser,
  regenerateProxyKey,
} from '../services/auth.js';

// Admin-only team management. Mounted at /api/users behind requireAuth +
// requireAdmin, so req.user is always a validated admin here.
export const usersRouter = Router();

function currentUser(req: Request): SessionUser {
  return (req as Request & { user?: SessionUser }).user!;
}

const createSchema = z.object({
  email: z.string().email('A valid email is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  role: z.enum(['admin', 'member']).optional(),
});

// List all users (no secrets — proxy keys are never returned here).
usersRouter.get('/', (_req: Request, res: Response) => {
  res.json({ users: listUsers() });
});

// Create a teammate. Returns the new user's one-time proxy key so the admin can
// hand it over; it is not shown again in the list.
usersRouter.post('/', (req: Request, res: Response) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map((e) => e.message).join(', '), type: 'invalid_request_error' } });
    return;
  }
  try {
    const user = createUser(parsed.data.email, parsed.data.password, parsed.data.role ?? 'member');
    res.status(201).json({ user: getUser(user.userId) });
  } catch (err: any) {
    if (err?.code === 'email_taken') {
      res.status(409).json({ error: { message: 'An account with that email already exists', type: 'invalid_request_error' } });
      return;
    }
    throw err;
  }
});

// Rotate a user's proxy key (admin can reset a teammate's credential).
usersRouter.post('/:id/proxy-key', (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || !getUser(id)) {
    res.status(404).json({ error: { message: 'User not found', type: 'invalid_request_error' } });
    return;
  }
  res.json({ proxyKey: regenerateProxyKey(id) });
});

// Delete a user. Blocks removing yourself and removing the last admin.
usersRouter.delete('/:id', (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (id === currentUser(req).userId) {
    res.status(400).json({ error: { message: 'You cannot delete your own account', type: 'invalid_request_error' } });
    return;
  }
  try {
    deleteUser(id);
    res.json({ success: true });
  } catch (err: any) {
    if (err?.code === 'not_found') {
      res.status(404).json({ error: { message: 'User not found', type: 'invalid_request_error' } });
      return;
    }
    if (err?.code === 'last_admin') {
      res.status(400).json({ error: { message: 'Cannot delete the last admin', type: 'invalid_request_error' } });
      return;
    }
    throw err;
  }
});
