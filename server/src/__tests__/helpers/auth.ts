import { createUser, createSession, getProxyKey } from '../../services/auth.js';
import { getDb } from '../../db/index.js';

// Dashboard /api/* routes are gated by requireAuth (#35). Tests mint a session
// token once (after initDb) and attach it to gated requests.

export function mintDashboardToken(email = 'test@example.com'): string {
  // Multi-tenant: mint a session for the FIRST user (creating one if none). This
  // keeps the dashboard session, the /v1 proxy key (getUnifiedApiKey), and the
  // api_keys default-owner trigger all pointing at the same single test user, so
  // keys added via the dashboard route are the same ones /v1 routes through.
  const db = getDb();
  const existing = db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get() as { id: number } | undefined;
  const userId = existing ? existing.id : createUser(email, 'password123').userId;
  return createSession(userId);
}

// Ensure a single default user exists — the "first user" that the proxy-key
// compat accessor (getUnifiedApiKey) and the api_keys default-owner trigger key
// off. Idempotent: returns the existing first user after a DB reset. Call once
// (e.g. in beforeAll after initDb) in /v1 and key-scoped tests.
export function ensureTestUser(): { userId: number; proxyKey: string } {
  const db = getDb();
  let row = db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get() as { id: number } | undefined;
  if (!row) {
    const u = createUser('proxy@example.com', 'password123');
    row = { id: u.userId };
  }
  return { userId: row.id, proxyKey: getProxyKey(row.id) ?? '' };
}

// Gated = under /api/ but not the public bootstrap routes (/api/auth/*, /api/ping).
export function isGatedApiPath(path: string): boolean {
  return path.startsWith('/api/') && !path.startsWith('/api/auth') && path !== '/api/ping';
}
