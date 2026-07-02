import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  userCount,
  createUser,
  verifyCredentials,
  createSession,
  validateSession,
  deleteSession,
  isAllowedEmailDomain,
  allowedEmailDomains,
} from '../services/auth.js';

export const authRouter = Router();

// Shared 400 for a disallowed signup domain. Returns true when the email was
// rejected (caller should stop), false when it's fine to proceed.
function rejectDisallowedDomain(email: string, res: Response): boolean {
  if (isAllowedEmailDomain(email)) return false;
  const list = allowedEmailDomains();
  res.status(400).json({
    error: {
      message: list.includes('*')
        ? 'Email domain not allowed.'
        : `Email must be a ${list.map((d) => '@' + d).join(', ')} address.`,
      type: 'invalid_request_error',
    },
  });
  return true;
}

// Dashboard auth (#35). These routes are mounted BEFORE requireAuth, so
// /status, /setup and /login are reachable without a session (bootstrap);
// /logout and /me validate the token themselves.

const credentialsSchema = z.object({
  email: z.string().email('A valid email is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

// ── Brute-force throttle ──────────────────────────────────────────────────
// Simple in-memory per-email limiter. A local single-user tool doesn't need a
// distributed store; this just blunts online password guessing.
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const attempts = new Map<string, { count: number; lockedUntil: number }>();

function isLockedOut(email: string): boolean {
  const a = attempts.get(email.toLowerCase());
  return !!a && a.lockedUntil > Date.now();
}
function recordFailure(email: string): void {
  const key = email.toLowerCase();
  const a = attempts.get(key) ?? { count: 0, lockedUntil: 0 };
  a.count++;
  if (a.count >= MAX_ATTEMPTS) {
    a.lockedUntil = Date.now() + LOCKOUT_MS;
    a.count = 0;
  }
  attempts.set(key, a);
}
function clearFailures(email: string): void {
  attempts.delete(email.toLowerCase());
}

function bearer(req: Request): string | undefined {
  return req.headers.authorization?.replace(/^Bearer\s+/i, '')
    ?? (req.headers['x-dashboard-token'] as string | undefined);
}

// Has the dashboard been set up yet, and is this caller authenticated?
authRouter.get('/status', (req: Request, res: Response) => {
  const session = validateSession(bearer(req));
  res.json({
    needsSetup: userCount() === 0,
    authenticated: !!session,
    email: session?.email ?? null,
    role: session?.role ?? null,
    // Lets the auth page show which email domains registration accepts.
    allowedEmailDomains: allowedEmailDomains(),
  });
});

// First-run account creation. Only allowed while there are zero users, so it
// can't be used to add accounts once the dashboard is claimed.
authRouter.post('/setup', (req: Request, res: Response) => {
  if (userCount() > 0) {
    res.status(409).json({ error: { message: 'Setup already completed. Use login instead.', type: 'setup_complete' } });
    return;
  }
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  if (rejectDisallowedDomain(parsed.data.email, res)) return;
  const user = createUser(parsed.data.email, parsed.data.password);
  const token = createSession(user.userId);
  res.status(201).json({ token, email: user.email, role: user.role });
});

// Open self-service signup. Unlike /setup this stays available after the first
// account exists — the auth page offers a Register ⇄ Login toggle. createUser
// makes the very first account the admin and every later one a member, so the
// first person to register still becomes the owner.
authRouter.post('/register', (req: Request, res: Response) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  if (rejectDisallowedDomain(parsed.data.email, res)) return;
  try {
    const user = createUser(parsed.data.email, parsed.data.password);
    const token = createSession(user.userId);
    res.status(201).json({ token, email: user.email, role: user.role });
  } catch (err: any) {
    if (err?.code === 'email_taken') {
      res.status(409).json({ error: { message: 'An account with that email already exists', type: 'email_taken' } });
      return;
    }
    throw err;
  }
});

authRouter.post('/login', (req: Request, res: Response) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  const { email, password } = parsed.data;

  if (isLockedOut(email)) {
    res.status(429).json({ error: { message: 'Too many failed attempts. Try again later.', type: 'rate_limit_error' } });
    return;
  }

  const user = verifyCredentials(email, password);
  if (!user) {
    recordFailure(email);
    // Same message whether the email exists or not — don't leak which.
    res.status(401).json({ error: { message: 'Invalid email or password', type: 'authentication_error' } });
    return;
  }

  clearFailures(email);
  const token = createSession(user.userId);
  res.json({ token, email: user.email, role: user.role });
});

authRouter.post('/logout', (req: Request, res: Response) => {
  deleteSession(bearer(req));
  res.json({ success: true });
});

authRouter.get('/me', (req: Request, res: Response) => {
  const session = validateSession(bearer(req));
  if (!session) {
    res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
    return;
  }
  res.json({ email: session.email, role: session.role });
});
